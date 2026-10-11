"""Submit once, then prove finalized consumption before a provider effect.

RPC is a transaction courier, never the finality authority. No nonce, signed
transaction, or permission is written to state. A fresh object owns one attempt.
"""
import hashlib
import http.client
import json
import multiprocessing
import os
import re
import secrets
import selectors
import signal
import subprocess
import time
import urllib.request
import urllib.error

from .offer_v4 import peer_hash
from .spike import RedemptionError
from .transport import _unique_object, _reject_constant

DOMAIN = b'dsmack-coupon-issuance-attempt-v1'
UPSTREAM = '2af9b41887e069144ee56cd710f3ddca195473f8'
PROFILE = 'helios-ethereum-sepolia-finalized-experiment'
BASE_PROFILE = 'base-mainnet-rpc-safe-debug-v1'
BASE_RPC = 'https://mainnet.base.org'
BASE_CONFIRMATION = {'version': 1, 'profile': BASE_PROFILE, 'block_tag': 'safe',
    'rpc_url': BASE_RPC, 'trust': 'configured-rpc', 'l1_finality_verified': False,
    'reorg_action': 'quarantine-no-retry'}
BASE_FIELDS = {'version', 'trust_profile', 'chain_id', 'execution_rpc', 'guard_address',
    'guard_code_hash', 'issuer_address', 'issuance_policy_hash', 'max_safe_age_seconds', 'timeout_seconds'}
FINALITY_FIELDS = {'version', 'trust_profile', 'chain_id', 'genesis_validators_root', 'bootstrap_checkpoint',
                   'consensus_rpc', 'execution_rpc', 'guard_address', 'guard_code_hash', 'issuer_address',
                   'issuance_policy_hash', 'max_finalized_age_seconds', 'timeout_seconds'}


def validate_finality_profile(profile):
    """Exact checker profile schema, mirroring the reviewed binary's own pins.

    Unknown fields, noncanonical commitments, non-HTTPS endpoints (loopback
    excepted) and out-of-bound lifetimes are refused before any credential,
    signature or network use. Raises ValueError; callers wrap in RedemptionError.
    """
    from urllib.parse import urlsplit
    if type(profile) is dict and profile.get('trust_profile') == BASE_PROFILE:
        if (set(profile) != BASE_FIELDS or type(profile['version']) is not int or profile['version'] != 1
                or type(profile['chain_id']) is not int or profile['chain_id'] != 8453
                or profile['execution_rpc'] != BASE_RPC
                or type(profile['max_safe_age_seconds']) is not int
                or not 60 <= profile['max_safe_age_seconds'] <= 7200
                or type(profile['timeout_seconds']) is not int or not 1 <= profile['timeout_seconds'] <= 300):
            raise ValueError()
        for name in ('guard_code_hash', 'issuance_policy_hash'):
            if (type(profile[name]) is not str or not re.fullmatch(r'0x[0-9a-f]{64}', profile[name])
                    or profile[name] == '0x' + '00' * 32): raise ValueError()
        for name in ('guard_address', 'issuer_address'):
            if (type(profile[name]) is not str or not re.fullmatch(r'0x[0-9a-f]{40}', profile[name])
                    or profile[name] == '0x' + '00' * 20): raise ValueError()
        return profile
    if (type(profile) is not dict or set(profile) != FINALITY_FIELDS
            or profile['version'] != 1 or profile['trust_profile'] != PROFILE
            or type(profile['chain_id']) is not int or profile['chain_id'] != 11155111):
        raise ValueError()
    for field in ('genesis_validators_root', 'bootstrap_checkpoint', 'guard_code_hash', 'issuance_policy_hash'):
        if (type(profile[field]) is not str or not re.fullmatch(r'0x[0-9a-f]{64}', profile[field])
                or profile[field] == '0x' + '00' * 32):
            raise ValueError()
    for field in ('guard_address', 'issuer_address'):
        if (type(profile[field]) is not str or not re.fullmatch(r'0x[0-9a-f]{40}', profile[field])
                or profile[field] == '0x' + '00' * 20):
            raise ValueError()
    for field in ('consensus_rpc', 'execution_rpc'):
        if type(profile[field]) is not str or not 0 < len(profile[field]) < 512:
            raise ValueError()
        parsed = urlsplit(profile[field])
        if (parsed.username or parsed.password or parsed.fragment or not parsed.hostname
                or any(ord(character) < 33 or ord(character) > 126 for character in profile[field])):
            raise ValueError()
        if not (parsed.scheme == 'https'
                or (parsed.scheme == 'http' and parsed.hostname in ('127.0.0.1', 'localhost', '::1'))):
            raise ValueError()
    if (type(profile['max_finalized_age_seconds']) is not int
            or not 60 <= profile['max_finalized_age_seconds'] <= 7200
            or type(profile['timeout_seconds']) is not int or not 1 <= profile['timeout_seconds'] <= 300):
        raise ValueError()
    return profile


def raw32(value):
    if type(value) is not str or not re.fullmatch(r'(?:0x)?[0-9a-f]{64}', value):
        raise RedemptionError('invalid guard commitment')
    result = bytes.fromhex(value.removeprefix('0x'))
    if result == bytes(32):
        raise RedemptionError('invalid guard commitment')
    return result


def address(value):
    if type(value) is not str or not re.fullmatch(r'0x[0-9a-f]{40}', value):
        raise RedemptionError('invalid guard authority')
    result = bytes.fromhex(value[2:])
    if result == bytes(20):
        raise RedemptionError('invalid guard authority')
    return result


def keccak(data):
    # Ethereum Keccak-256, deliberately not hashlib.sha3_256.
    from eth_hash.auto import keccak as digest
    return digest(data)


def recipient_commitment(peer, delivery_key):
    if type(delivery_key) is not bytes or len(delivery_key) != 32:
        raise RedemptionError('invalid delivery binding')
    return hashlib.sha256(b'dsmack-coupon-guard-recipient-v1\0' +
                          bytes.fromhex(peer_hash(peer)) + hashlib.sha256(delivery_key).digest()).digest()


def commitment(profile, intent):
    words = [keccak(DOMAIN), profile['chain_id'].to_bytes(32, 'big'),
             address(profile['guard_address']).rjust(32, b'\0'),
             address(profile['issuer_address']).rjust(32, b'\0'),
             raw32(profile['issuance_policy_hash'])]
    words += [raw32(intent[k]) for k in ('coupon_digest', 'recipient_commitment',
                                       'accepted_offer_hash', 'process_nonce')]
    return keccak(b''.join(words))


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        raise RedemptionError('guard transport refused redirect')


class GuardRPC:
    """Bounded courier. One sendRawTransaction call, including ambiguous errors."""
    def __init__(self, url):
        from urllib.parse import urlsplit
        parsed = urlsplit(url)
        if (parsed.scheme != 'https' or not parsed.hostname or parsed.username
                or parsed.password or parsed.fragment):
            raise RedemptionError('HTTPS guard courier required')
        self.url = url
        self.opener = urllib.request.build_opener(NoRedirect)
        self.observer = None
        self.diagnostic_observer = None
        self._attempts = {}
        self._response_failures = {}

    def call(self, method, params, *, timeout=15):
        started = time.monotonic()
        self._attempts[method] = self._attempts.get(method, 0) + 1
        status = code = count = partial_count = exception_class = None
        if self.observer is not None:
            self.observer(method, None)
        request = urllib.request.Request(self.url,
            json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode(),
            {'Content-Type': 'application/json', 'User-Agent': 'dsmack-coupon-guard/1'}, method='POST')
        try:
            with self.opener.open(request, timeout=timeout) as response:
                status = getattr(response, 'status', None)
                data = response.read(65537)
                count = len(data)
            if len(data) > 65536:
                category = 'response_oversized'
                raise GuardResponseRefused(category)
            try:
                result = json.loads(data, object_pairs_hook=_unique_object, parse_constant=_reject_constant)
            except (json.JSONDecodeError, UnicodeDecodeError):
                raise GuardResponseRefused('response_decode') from None
            if (type(result) is not dict or result.get('jsonrpc') != '2.0'
                    or type(result.get('id')) is not int or result['id'] != 1):
                raise ValueError()
            if set(result) == {'jsonrpc', 'id', 'result'}:
                self._response_failures[method] = 0
                return result['result']
            error = result.get('error')
            if (set(result) != {'jsonrpc', 'id', 'error'} or type(error) is not dict
                    or set(error) != {'code', 'message'} or type(error['code']) is not int
                    or type(error['message']) is not str):
                raise ValueError()
            # Geth's receipt index can lag submission. Only this exact documented
            # read response is temporary; sends and all other RPC errors remain
            # terminal. Neither provider text nor data is retained or surfaced.
            category = ('receipt_indexing' if method == 'eth_getTransactionReceipt'
                        and error['code'] == -32000
                        and error['message'] == 'transaction indexing is in progress'
                        else 'rpc_error')
            code = error['code']
        except http.client.IncompleteRead as error:
            # A truncated/malformed chunk frame is not a JSON envelope. Never
            # parse or retain its partial body, or repeat an ambiguous send.
            category = 'response_read'
            exception_class = 'IncompleteRead'
            if type(error.partial) is bytes and len(error.partial) <= 65537:
                partial_count = len(error.partial)
        except GuardResponseRefused as error:
            category = error.category
        except urllib.error.HTTPError as error:
            status = error.code
            category = 'http_retryable' if error.code in (429, 502, 503, 504) else 'http_terminal'
            error.close()
        except (urllib.error.URLError, TimeoutError, OSError):
            category = 'network_unavailable'
        except RedemptionError:
            category = 'redirect_refused'
        except Exception:
            category = 'invalid_response'
        if category in ('response_decode', 'response_read'):
            self._response_failures[method] = self._response_failures.get(method, 0) + 1
        else:
            self._response_failures[method] = 0
        if self.diagnostic_observer is not None:
            self.diagnostic_observer({'method': method, 'category': 'response_envelope' if category == 'invalid_response' else category,
                'http_status': status if type(status) is int and 100 <= status <= 599 else None,
                'rpc_code': code if type(code) is int and -2147483648 <= code <= 2147483647 else None,
                'response_bytes': count, 'response_partial_bytes': partial_count,
                'exception_class': exception_class,
                'attempt': self._attempts[method],
                'elapsed_ms': max(0, int((time.monotonic() - started) * 1000))})
        if self.observer is not None:
            self.observer(method, category)
        if method in SAFE_READ_METHODS and (category in ('http_retryable', 'network_unavailable', 'receipt_indexing')
                or category in ('response_decode', 'response_read') and self._response_failures[method] <= 2):
            raise GuardReadUnavailable(category) from None
        refusal = RedemptionError('guard transaction outcome unavailable')
        refusal.category = category  # Static private diagnostic, never raw RPC text.
        raise refusal from None


SAFE_READ_METHODS = frozenset(('eth_chainId', 'eth_getTransactionReceipt',
    'eth_getTransactionByHash', 'eth_getBlockByNumber', 'eth_getCode', 'eth_call', 'eth_getStorageAt'))


class GuardResponseRefused(Exception):
    def __init__(self, category):
        self.category = category


class GuardReadUnavailable(RedemptionError):
    """Temporary transport/receipt-index read only, never binding/submission."""
    def __init__(self, category):
        self.category = category
        super().__init__('guard read temporarily unavailable')


def run_checker(binary, config_path, intent, timeout):
    """Current intent only on a pipe; bounded output, kill and reap on failure."""
    payload = json.dumps(intent, separators=(',', ':')).encode() + b'\n'
    parent_pid = os.getpid()
    def parent_death():
        # Linux package profile. Checker has no subprocesses; bridge's existing
        # process-group cleanup remains the outer lifecycle boundary.
        import ctypes
        if ctypes.CDLL(None).prctl(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != parent_pid:
            os._exit(1)
    proc = subprocess.Popen([binary, '--config', str(config_path)], stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'}, close_fds=True, preexec_fn=parent_death)
    selector = selectors.DefaultSelector()
    output = bytearray()
    deadline = time.monotonic() + timeout
    try:
        # Exact intent is < 1 KiB, below the anonymous pipe's minimum capacity.
        proc.stdin.write(payload)
        proc.stdin.close()
        for stream in (proc.stdout, proc.stderr):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ)
        total = 0
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError()
            for key, _ in selector.select(min(remaining, 0.5)):
                chunk = os.read(key.fd, 4096)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                total += len(chunk)
                if total > 8192:
                    raise ValueError()
                if key.fileobj is proc.stdout:
                    output.extend(chunk)
        if proc.wait(timeout=max(0.01, deadline - time.monotonic())) != 0:
            raise ValueError()
        return json.loads(output, object_pairs_hook=_unique_object, parse_constant=_reject_constant)
    except Exception:
        raise RedemptionError('authenticated guard state unavailable') from None
    finally:
        selector.close()
        if proc.poll() is None:
            proc.kill()
        proc.wait(timeout=5)
        for stream in (proc.stdout, proc.stderr):
            stream.close()


class FinalizedIssuanceGuard:
    def __init__(self, *, profile, profile_path, binary, private_key, gas_price_wei,
                 deadline_seconds=3600, poll_seconds=15, rpc=None):
        from eth_keys import keys
        self.profile = dict(profile)
        try:
            validate_finality_profile(self.profile)
        except ValueError:
            raise RedemptionError('unsupported guard profile') from None
        if (type(gas_price_wei) is not int or not 0 < gas_price_wei < 2**64
                or not 30 <= deadline_seconds <= 7200 or not 1 <= poll_seconds <= 60):
            raise RedemptionError('unsupported guard profile')
        self.key = keys.PrivateKey(private_key)
        if self.key.public_key.to_canonical_address() != address(profile['issuer_address']):
            raise RedemptionError('guard signer differs from pinned authority')
        self.profile_path, self.binary = profile_path, binary
        self.gas_price, self.deadline, self.poll = gas_price_wei, deadline_seconds, poll_seconds
        self.rpc = rpc or GuardRPC(profile['execution_rpc'])
        # Shared by forked jobs in this boot only. Reserve before submission,
        # including unknown outcomes, so siblings cannot replace each other's tx.
        self.nonce_lock = multiprocessing.Lock()
        self.next_nonce = multiprocessing.Value('Q', 0, lock=False)

    def _send(self, intent):
        with self.nonce_lock:
            return self._send_locked(intent)

    def _send_locked(self, intent):
        import rlp
        raw_nonce = self.rpc.call('eth_getTransactionCount', [self.profile['issuer_address'], 'pending'])
        if type(raw_nonce) is not str or not re.fullmatch(r'0x[0-9a-f]{1,16}', raw_nonce):
            raise RedemptionError('guard transaction nonce unavailable')
        selector = keccak(b'consume(bytes32,(bytes32,bytes32,bytes32))')[:4]
        data = selector + b''.join(raw32(intent[k]) for k in
            ('coupon_digest', 'recipient_commitment', 'accepted_offer_hash', 'process_nonce'))
        # Fixed bounded legacy EIP-155 transaction. Fee policy is explicitly
        # configured; untrusted gas estimation cannot widen the spending budget.
        nonce = max(int(raw_nonce, 16), self.next_nonce.value)
        if nonce >= 2**64 - 1:
            raise RedemptionError('guard transaction nonce unavailable')
        self.next_nonce.value = nonce + 1
        fields = [nonce, self.gas_price, 150000,
                  address(self.profile['guard_address']), 0, data]
        chain = self.profile['chain_id']
        signature = self.key.sign_msg_hash(keccak(rlp.encode(fields + [chain, 0, 0])))
        transaction = rlp.encode(fields + [signature.v + 35 + chain * 2, signature.r, signature.s])
        expected = '0x' + keccak(transaction).hex()
        result = self.rpc.call('eth_sendRawTransaction', ['0x' + transaction.hex()])
        if result != expected:
            raise RedemptionError('guard transaction outcome unavailable')
        return expected

    def __call__(self, digest, peer, delivery_key, accepted_hash, issuer):
        if issuer['issuance_policy_sha256'] != self.profile['issuance_policy_hash'].removeprefix('0x'):
            raise RedemptionError('guard policy mismatch')
        intent = {'version': 1, 'coupon_digest': '0x' + digest,
                  'recipient_commitment': '0x' + recipient_commitment(peer, delivery_key).hex(),
                  'accepted_offer_hash': '0x' + accepted_hash, 'process_nonce': '0x' + secrets.token_bytes(32).hex()}
        expected = '0x' + commitment(self.profile, intent).hex()
        deadline = time.monotonic() + self.deadline
        self._send(intent)  # Exactly once. Unknown outcome never authorizes POST.
        while time.monotonic() < deadline:
            try:
                from .peer_worker import _private_file
                from .staging_approval import canonical
                if _private_file(self.profile_path) != canonical(self.profile):
                    raise RedemptionError('authenticated checker profile mismatch')
                result = run_checker(self.binary, self.profile_path, intent,
                    min(self.profile['timeout_seconds'] + 5, deadline - time.monotonic()))
                self._validate(result, digest, expected)
                # This return grants one permission only to the interrupted-free
                # caller's next provider POST. No receipt or nonce is persisted.
                return
            except RedemptionError:
                remaining = deadline - time.monotonic()
                if remaining > 0:
                    time.sleep(min(self.poll, remaining))
        raise RedemptionError('finalized guard deadline exceeded')

    def _validate(self, result, digest, expected):
        fields = {'version', 'trust_profile', 'upstream_sha', 'chain_id', 'genesis_validators_root',
                  'bootstrap_checkpoint', 'finalized_block', 'verified_at_ms', 'freshness_basis', 'guard'}
        guard = {'address': self.profile['guard_address'], 'code_hash': self.profile['guard_code_hash'],
                 'issuer': self.profile['issuer_address'], 'policy_hash': self.profile['issuance_policy_hash'],
                 'coupon_digest': '0x' + digest, 'consumed_commitment': expected}
        if (type(result) is not dict or set(result) != fields or result['version'] != 1
                or result['trust_profile'] != PROFILE or result['upstream_sha'] != UPSTREAM
                or result['chain_id'] != self.profile['chain_id']
                or result['genesis_validators_root'] != self.profile['genesis_validators_root']
                or result['bootstrap_checkpoint'] != self.profile['bootstrap_checkpoint']
                or result['freshness_basis'] != 'local-system-time-assumed' or result['guard'] != guard):
            raise RedemptionError('finalized guard binding mismatch')
        block = result['finalized_block']
        now = int(time.time())
        if (type(block) is not dict or set(block) != {'hash', 'number', 'timestamp', 'state_root', 'receipts_root'}
                or type(block['timestamp']) is not int or block['timestamp'] > now
                or now - block['timestamp'] > self.profile['max_finalized_age_seconds']
                or type(result['verified_at_ms']) is not int
                or abs(int(time.time() * 1000) - result['verified_at_ms']) > 10000):
            raise RedemptionError('finalized guard freshness mismatch')


class _NotSafeYet(Exception):
    pass


def _quantity(value):
    if type(value) is not str or not re.fullmatch(r'0x(?:0|[1-9a-f][0-9a-f]{0,15})', value):
        raise RedemptionError('invalid Base guard quantity')
    return int(value, 16)


class BaseSafeIssuanceGuard(FinalizedIssuanceGuard):
    """Explicit single-RPC debug trust, not an authenticated L1 finality proof.

    Only this uninterrupted object's fresh submitted attempt may authorize its
    next provider POST. Receipts, disk snapshots and historical checks cannot
    rebuild that permission. A reorg/mismatch quarantines; no resubmission.
    """
    def __init__(self, **kwargs):
        if kwargs['profile'].get('trust_profile') != BASE_PROFILE:
            raise RedemptionError('unsupported Base guard profile')
        super().__init__(**kwargs)
        self.progress = None
        self.rpc_diagnostics = None

    def _progress(self, stage, method=None, error=None):
        self._current_stage = stage
        if self.progress is not None:
            self.progress(stage, method, error)

    def _safe(self, intent, transaction_hash, deadline):
        attempt_deadline = min(deadline, time.monotonic() + self.profile['timeout_seconds'])
        def call(method, params):
            remaining = attempt_deadline - time.monotonic()
            if remaining <= 0:
                raise RedemptionError('Base safe read deadline exceeded')
            if isinstance(self.rpc, GuardRPC):
                result = self.rpc.call(method, params, timeout=min(15, remaining))
            else:
                result = self.rpc.call(method, params)  # Protected fixture injection only.
            if time.monotonic() >= attempt_deadline:
                raise RedemptionError('Base safe read deadline exceeded')
            return result
        if call('eth_chainId', []) != hex(8453):
            raise RedemptionError('Base guard chain mismatch')
        receipt = call('eth_getTransactionReceipt', [transaction_hash])
        if receipt is None:
            raise _NotSafeYet()
        def receipt_refused(category):
            self._progress('guard_read', 'eth_getTransactionReceipt', category)
            refusal = RedemptionError('Base guard receipt mismatch')
            refusal.category = category
            raise refusal
        if type(receipt) is not dict:
            receipt_refused('receipt_invalid')
        if receipt.get('transactionHash') != transaction_hash:
            receipt_refused('receipt_hash_mismatch')
        if (receipt.get('from') != self.profile['issuer_address']
                or receipt.get('to') != self.profile['guard_address']):
            receipt_refused('receipt_authority_mismatch')
        if receipt.get('status') != '0x1':
            receipt_refused('receipt_reverted' if receipt.get('status') == '0x0' else 'receipt_status_invalid')
        try:
            mined_number = _quantity(receipt.get('blockNumber'))
        except (ValueError, RedemptionError):
            receipt_refused('receipt_quantity_invalid')
        # base/base 749fe75d4c92d94ccb4375d6f6ba39bcb8ad4299 pending
        # receipts carry numeric block_number and B256::ZERO block_hash.
        # This exact DATA sentinel is only a wait, never canonical inclusion
        # or permission. The caller retains its original hash and deadline.
        if receipt.get('blockHash') == '0x' + '00' * 32:
            self._progress('guard_read', 'eth_getTransactionReceipt', 'receipt_preconfirmed')
            raise _NotSafeYet()
        try:
            raw32(receipt.get('blockHash'))
        except (ValueError, RedemptionError):
            receipt_refused('receipt_hash_invalid')
        transaction = call('eth_getTransactionByHash', [transaction_hash])
        calldata = keccak(b'consume(bytes32,(bytes32,bytes32,bytes32))')[:4] + b''.join(
            raw32(intent[k]) for k in ('coupon_digest', 'recipient_commitment', 'accepted_offer_hash', 'process_nonce'))
        if (type(transaction) is not dict or transaction.get('hash') != transaction_hash
                or transaction.get('from') != self.profile['issuer_address']
                or transaction.get('to') != self.profile['guard_address']
                or transaction.get('input') != '0x' + calldata.hex()
                or transaction.get('value') != '0x0' or _quantity(transaction.get('chainId')) != 8453
                or transaction.get('blockHash') != receipt['blockHash']
                or transaction.get('blockNumber') != receipt['blockNumber']):
            raise RedemptionError('Base guard transaction mismatch')
        block = call('eth_getBlockByNumber', ['safe', False])
        if type(block) is not dict:
            raise RedemptionError('Base safe block unavailable')
        safe_number = _quantity(block.get('number'))
        safe_hash = block.get('hash'); raw32(safe_hash)
        timestamp = _quantity(block.get('timestamp'))
        now = int(time.time())
        if timestamp > now or now - timestamp > self.profile['max_safe_age_seconds']:
            raise RedemptionError('Base safe block stale')
        if safe_number < mined_number:
            raise _NotSafeYet()
        canonical_receipt = call('eth_getBlockByNumber', [receipt['blockNumber'], False])
        if type(canonical_receipt) is not dict or canonical_receipt.get('hash') != receipt['blockHash']:
            raise RedemptionError('Base guard receipt reorg')
        frozen = {'blockHash': safe_hash, 'requireCanonical': True}
        code = call('eth_getCode', [self.profile['guard_address'], frozen])
        if (type(code) is not str or not re.fullmatch(r'0x(?:[0-9a-f]{2})+', code)
                or '0x' + keccak(bytes.fromhex(code[2:])).hex() != self.profile['guard_code_hash']):
            raise RedemptionError('Base guard code mismatch')
        def read(method):
            return call('eth_call', [{'to': self.profile['guard_address'],
                'data': '0x' + keccak(method)[:4].hex()}, frozen])
        if (read(b'issuer()') != '0x' + address(self.profile['issuer_address']).rjust(32, b'\0').hex()
                or read(b'policyHash()') != self.profile['issuance_policy_hash']):
            raise RedemptionError('Base guard authority mismatch')
        slot = '0x' + keccak(raw32(intent['coupon_digest']) + bytes(32)).hex()
        consumed = call('eth_getStorageAt', [self.profile['guard_address'], slot, frozen])
        if consumed != '0x' + commitment(self.profile, intent).hex():
            raise RedemptionError('Base guard consumed intent mismatch')
        current_safe = call('eth_getBlockByNumber', ['safe', False])
        if type(current_safe) is not dict:
            raise RedemptionError('Base safe head unavailable')
        current_number = _quantity(current_safe.get('number'))
        current_hash = current_safe.get('hash'); raw32(current_hash)
        if current_number < safe_number:
            raise RedemptionError('Base safe head downgraded')
        if current_number == safe_number and current_hash != safe_hash:
            raise RedemptionError('Base safe head reorg')
        canonical_safe = call('eth_getBlockByNumber', [block['number'], False])
        if type(canonical_safe) is not dict or canonical_safe.get('hash') != safe_hash:
            raise RedemptionError('Base safe block reorg')
        now = int(time.time())
        if timestamp > now or now - timestamp > self.profile['max_safe_age_seconds']:
            raise RedemptionError('Base safe block stale')
        return {'trust_profile': BASE_PROFILE, 'block_hash': safe_hash,
                'block_number': safe_number, 'l1_finality_verified': False}

    def __call__(self, digest, peer, delivery_key, accepted_hash, issuer):
        self._progress('guard_entered')
        if isinstance(self.rpc, GuardRPC):
            self.rpc.observer = lambda method, error: self._progress(self._current_stage, method, error)
            self.rpc.diagnostic_observer = (None if self.rpc_diagnostics is None else
                lambda detail: self.rpc_diagnostics(self._current_stage, detail))
        if issuer['issuance_policy_sha256'] != self.profile['issuance_policy_hash'].removeprefix('0x'):
            raise RedemptionError('guard policy mismatch')
        from .peer_worker import _private_file
        from .staging_approval import canonical
        if _private_file(self.profile_path) != canonical(self.profile):
            raise RedemptionError('Base guard profile mismatch')
        if self.rpc.call('eth_chainId', []) != hex(8453):
            raise RedemptionError('Base guard chain mismatch')
        intent = {'version': 1, 'coupon_digest': '0x' + digest,
                  'recipient_commitment': '0x' + recipient_commitment(peer, delivery_key).hex(),
                  'accepted_offer_hash': '0x' + accepted_hash, 'process_nonce': '0x' + secrets.token_bytes(32).hex()}
        deadline = time.monotonic() + self.deadline
        self._progress('guard_submit_started')
        transaction_hash = self._send(intent)  # One submission only; ambiguity quarantines.
        self._progress('guard_submitted')
        while time.monotonic() < deadline:
            try:
                if _private_file(self.profile_path) != canonical(self.profile):
                    raise RedemptionError('Base guard profile mismatch')
                self._progress('guard_read')
                self._safe(intent, transaction_hash, deadline)
                if time.monotonic() >= deadline:
                    raise RedemptionError('Base safe guard deadline exceeded')
                # Memory-only permission; no persistence or provider retry.
                self._progress('guard_confirmed')
                return
            except (_NotSafeYet, GuardReadUnavailable):
                remaining = deadline - time.monotonic()
                if remaining > 0:
                    time.sleep(min(self.poll, remaining))
        raise RedemptionError('Base safe guard deadline exceeded')
