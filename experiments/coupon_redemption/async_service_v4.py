"""Current-boot bounded issuance jobs; durable state never restarts an effect."""
import json
import base64
import multiprocessing
import os
import re
import signal
import time

from .service_v4 import DsmackCouponServiceV4
from .spike import Store, RedemptionError
from .transport import _unique_object, _reject_constant, _finite_float

PENDING = {'state': 'in_progress', 'automatic_retry_allowed': False,
           'deposit_release_authorized': False}


class AsyncCouponServiceV4(DsmackCouponServiceV4):
    def __init__(self, *args, max_active_jobs=2, job_deadline_seconds=3600, **kwargs):
        self.provider_binding = dict(kwargs['provider_binding'])
        super().__init__(*args, **kwargs)
        if (type(max_active_jobs) is not int or not 1 <= max_active_jobs <= 8
                or type(job_deadline_seconds) is not int or not 30 <= job_deadline_seconds <= 7200):
            raise RedemptionError('invalid bounded issuance job profile')
        self.max_jobs, self.job_deadline = max_active_jobs, job_deadline_seconds
        self.jobs = {}
        self.db_path = self.store.db.execute('PRAGMA database_list').fetchone()['file']
        self.context = multiprocessing.get_context('fork')

    def _active(self, digest):
        job = self.jobs.get(digest)
        if job is not None and not job.is_alive():
            job.join()
            del self.jobs[digest]
            return False
        return job is not None

    def _claim(self, coupon, peer, public, accepted_hash):
        grant, stored, offer, row = self._load(coupon)
        digest = grant['digest']
        if row['state'] != 'ready':
            winner = self.store.db.execute('SELECT * FROM service_v4_claims WHERE digest=?', (digest,)).fetchone()
            if (winner is None or winner['peer'] != peer or winner['delivery_key'] != public
                    or winner['offer_hash'] != accepted_hash or accepted_hash != stored['offer_hash']):
                raise RedemptionError('coupon bound to another claimant')
            if row['state'] == 'issuing' and self._active(digest):
                return dict(PENDING)
            # Delivered same-key replay is the only effect-free completion.
            return super()._claim(coupon, peer, public, accepted_hash)
        for existing in list(self.jobs):
            self._active(existing)
        if len(self.jobs) >= self.max_jobs:
            raise RedemptionError('issuance jobs at capacity')
        reserved = self.context.Event()
        job = self.context.Process(target=self._run_job,
            args=(coupon, peer, public, accepted_hash, reserved), daemon=False)
        job.start()
        self.jobs[digest] = job
        # Wait only for the committed reservation, not chain/provider progress.
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and job.is_alive() and not reserved.wait(0.02):
            pass
        if reserved.is_set():
            return dict(PENDING)
        # A failed or stalled reservation never permits creating a replacement.
        # Stalled child is terminated and reaped before the handler returns.
        self._stop_job(digest)
        raise RedemptionError('claim reservation failed')

    def _run_job(self, coupon, peer, public, accepted_hash, reserved):
        # Child owns a fresh connection. It neither writes worker stdout nor
        # leaves a retained job command/nonce from which startup could replay.
        for fd in (0, 1, 2):
            replacement = os.open(os.devnull, os.O_RDWR)
            os.dup2(replacement, fd)
            if replacement > 2:
                os.close(replacement)
        self.store.close()
        store = Store(self.db_path)
        last = ['guard_entered', None, None]
        def progress(stage, method=None, error=None):
            store.note_issuance(store.digest(coupon), stage, method, error)
            last[:] = [stage, method, error]
        store.effect_observer = progress
        def deadline(_signal, _frame):
            raise TimeoutError('issuance job deadline')
        signal.signal(signal.SIGALRM, deadline)
        signal.signal(signal.SIGTERM, deadline)
        signal.alarm(self.job_deadline)
        original_authorizer = self.issuance_authorizer
        def authorize(*arguments):
            reserved.set()  # Store.redeem committed winner+issuing already.
            progress('guard_entered')
            if original_authorizer is None:
                raise RedemptionError('issuance authorization unavailable')
            if hasattr(original_authorizer, 'progress'):
                original_authorizer.progress = progress
            if hasattr(original_authorizer, 'rpc_diagnostics'):
                original_authorizer.rpc_diagnostics = lambda stage, detail: store.note_guard_rpc(
                    store.digest(coupon), stage, detail)
            original_authorizer(*arguments)
        try:
            service = DsmackCouponServiceV4(store, self.provider, self.signing_key,
                sponsor_subject=self.sponsor, observer_subject=self.observer,
                issuer_peer_id=self.issuer_peer, provider_binding=self.provider_binding,
                issuer_binding=self.issuer_binding, issuance_authorizer=authorize)
            service._claim(coupon, peer, public, accepted_hash)
        except Exception as error:
            # Static private metadata only; never exception text or authority.
            category = getattr(error, 'category', None) or last[2]
            if category is None:
                category = ('timeout' if isinstance(error, TimeoutError) else
                            'provider_error' if last[0] == 'provider_post_started' else
                            'validation_failed' if isinstance(error, RedemptionError) else 'internal_error')
            try:
                progress(last[0], last[1], category)
            except Exception:
                pass  # Diagnostic failure cannot restart an effect.
        finally:
            signal.alarm(0)
            store.close()

    def dispatch(self, frame, principal, *, local_peer, remote_peer):
        request = None
        try:
            request = json.loads(frame, object_pairs_hook=_unique_object,
                                 parse_constant=_reject_constant, parse_float=_finite_float)
            if type(request) is dict and request.get('op') == 'status':
                grant, stored, _offer, row = self._load(request['coupon'])
                fields = {'id', 'op', 'coupon'}
                operator = any(role in principal.roles and principal.subject == grant[role]
                               for role in ('sponsor', 'observer'))
                if set(request) == fields | {'recipient_key', 'offer_hash'}:
                    public = base64.b64decode(request['recipient_key'], validate=True)
                    if len(public) != 32 or request['offer_hash'] != stored['offer_hash']:
                        raise RedemptionError('invalid status commitment')
                    if row['state'] != 'ready':
                        winner = self.store.db.execute('SELECT * FROM service_v4_claims WHERE digest=?', (grant['digest'],)).fetchone()
                        if (winner is None or winner['peer'] != remote_peer or winner['delivery_key'] != public
                                or winner['offer_hash'] != request['offer_hash']):
                            raise RedemptionError('status bound to another claimant')
                    request = {key: request[key] for key in fields}
                    frame = json.dumps(request, separators=(',', ':')).encode()
                elif set(request) != fields or (row['state'] != 'ready' and not operator):
                    raise RedemptionError('winning status commitments required')
        except Exception:
            # Malformed or unauthorized status stays generic and non-enumerating:
            # only a syntactically valid request ID is preserved for correlation,
            # and the base dispatcher still refuses the substituted operation
            # without revealing account or state.
            identifier = request.get('id') if type(request) is dict else None
            if type(identifier) is not str or not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', identifier):
                identifier = None
            fallback = json.dumps({'id': identifier, 'op': 'invalid'}, separators=(',', ':')).encode()
            return super().dispatch(fallback, principal,
                local_peer=local_peer, remote_peer=remote_peer)
        encoded = super().dispatch(frame, principal, local_peer=local_peer, remote_peer=remote_peer)
        # Base dispatch has already validated exact frames and status authority.
        response = json.loads(encoded)
        if response.get('ok') is True and response['result'].get('state') == 'reconciliation_required':
            request = json.loads(frame)
            digest = self.store.digest(request['coupon'])
            row = self.store.db.execute('SELECT state FROM coupons WHERE digest=?', (digest,)).fetchone()
            if row['state'] == 'issuing' and self._active(digest):
                response['result']['state'] = 'in_progress'
                return json.dumps(response, separators=(',', ':')).encode()
        return encoded

    def _stop_job(self, digest):
        job = self.jobs.pop(digest, None)
        if job is None:
            return
        if job.is_alive():
            job.terminate()
        job.join(timeout=2)
        if job.is_alive():
            job.kill()
            job.join(timeout=2)
        if job.is_alive():
            raise RedemptionError('issuance job did not exit')

    def close_jobs(self):
        for digest in list(self.jobs):
            self._stop_job(digest)
