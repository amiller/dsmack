"""Adapter to native owner's external-client stdout/stdin lifecycle protocol.
Never connects to the socket; never deletes uncertain same-UID paths.
"""
import os,selectors,subprocess,time,json
from pathlib import Path
import approved_run as ar
class Helper:
    def __init__(self,config,logs,timeout=12):
        self.config=config;self.logs=Path(logs);self.timeout=timeout;self.proc=None;self.err=None
        self.report={'started':False,'ready':False,'quiescence':'unconfirmed','garbage_collection':'deferred','cleanup_errors':[]}
    def start(self):
        c=self.config
        ar.need(not os.path.lexists(c['run_dir']),'helper run directory must be fresh')
        self.err=open(self.logs/'helper.stderr','xb')
        self.proc=subprocess.Popen([c['launcher']['path'],c['gvproxy']['path'],c['run_dir']],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=self.err)
        self.report['started']=True;self.report['pid']=self.proc.pid
        sel=None;data=b'';consumed=0;failure=None
        try:
            sel=selectors.DefaultSelector();sel.register(self.proc.stdout,selectors.EVENT_READ)
            deadline=time.monotonic()+self.timeout
            while time.monotonic()<deadline:
                if sel.select(min(.1,max(0,deadline-time.monotonic()))):
                    b=os.read(self.proc.stdout.fileno(),4096)
                    consumed+=len(b);data=(data+b)[:4096]
                    ar.need(consumed<=4096,'helper readiness oversize')
                    if b'\n' in data: break
                    ar.need(b,'helper died before readiness')
                ar.need(self.proc.poll() is None,'helper died before readiness')
            ar.need(data==os.fsencode(str(Path(c['run_dir'])/'net.sock'))+b'\n','helper readiness missing/mismatched')
            ar.need(self.proc.poll() is None,'helper died at readiness')
            self.report['ready']=True
        except BaseException as exc:
            failure=exc;self.report['readiness_error']=str(exc)
            raise
        finally:
            self.report['readiness_stdout_bytes_consumed']=consumed
            self.report['readiness_stdout_truncated']=consumed>len(data)
            try:
                with open(self.logs/'helper.stdout','xb') as out:
                    out.write(data);out.flush();os.fsync(out.fileno())
                self.report['readiness_stdout_persisted']=True
            except OSError as exc:
                self.report['ready']=False
                self.report['readiness_stdout_persisted']=False
                self.report['cleanup_errors'].append('readiness stdout persistence: '+str(exc))
                if failure is None:
                    self.report['readiness_error']=str(exc)
                    raise
            finally:
                if sel is not None: sel.close()
    # Pinned, machine-readable native terminal-status contract. `stop` trusts ONLY
    # an exact match of this typed record (one newline-terminated JSON line on the
    # native owner's stdout lifecycle channel) to declare quiescence. Retained
    # filesystem residue with confirmed process/FD quiescence is an ordinary
    # success (deferred host GC); it is NOT inferred from any path observation and
    # NOT from human error text. Everything else refuses: unconfirmed reap, a
    # residual pid, non-quiescent/kill-unconfirmed outcome, any teardown fault,
    # an observe-error/unassessed retention, a malformed/duplicate/truncated/
    # missing/multiple record, a spoofed/mismatched schema, or a status/exit-code
    # mismatch (contract success but nonzero exit, or zero exit without the
    # contract). See HELPER-SHUTDOWN-STATUS-CONTRACT.md.
    STATUS_SCHEMA='gvproxy-launcher/helper-shutdown-status@1'
    QUIESCENT_OUTCOMES=('graceful','already-exited','killed')
    SAFE_RETENTION=('removed','retained-deferred')
    STATUS_CAP=4096
    def _read_status_line(self):
        # Bounded read of EXACTLY one newline-terminated status line FOLLOWED BY
        # EOF. Never stats the run dir. Reads until the owner closes its stdout
        # (bounded by STATUS_CAP and the owner timeout); it does NOT stop at the
        # first newline, so any byte that arrives in a LATER read after the record
        # is still seen and refused. Refuses missing/truncated/oversize, every
        # trailing byte (multiple / fragmented late records), an absent EOF
        # (record present but stdout never closed within the timeout), and
        # non-UTF-8 input.
        fd=self.proc.stdout
        if fd is None: return None,'no stdout channel'
        buf=b'';eof=False;sel=selectors.DefaultSelector()
        try:
            sel.register(fd,selectors.EVENT_READ)
            deadline=time.monotonic()+self.timeout
            while time.monotonic()<deadline:
                if sel.select(min(.1,max(0,deadline-time.monotonic()))):
                    # Read at most one byte past the cap so a record exactly at the
                    # cap plus any trailing byte is still detected as oversize.
                    b=os.read(fd.fileno(),self.STATUS_CAP+1-len(buf))
                    if not b:
                        eof=True;break               # owner closed stdout => EOF
                    buf+=b
                    if len(buf)>self.STATUS_CAP: return None,'status oversize'
            if not eof:
                # Preserve owner timeout handling: a record with no following EOF
                # (stdout held open) is refused, never accepted on the newline.
                return None,'status read timed out (no EOF after record)'
        except OSError as exc:
            return None,'status read error: '+str(exc)
        finally:
            sel.close()
        if b'\n' not in buf: return None,'status truncated/missing'
        nl=buf.index(b'\n')
        # Exactly one record: the sole newline must terminate the buffer with no
        # trailing byte (a second record, a fragment, or any late data refuses).
        if nl!=len(buf)-1: return None,'trailing bytes after status (multiple records)'
        try: return buf[:nl].decode('utf-8'),None
        except UnicodeDecodeError: return None,'status not utf-8'
    def _consume_safe_success(self,raw,read_err,rc):
        # Decide the pinned safe-success contract from the TYPED record alone.
        if read_err is not None: return False,read_err
        if raw is None: return False,'missing status'
        def pairs(items):
            o={}
            for k,v in items:
                if k in o: raise ValueError('duplicate key: '+k)
                o[k]=v
            return o
        try: rec=json.loads(raw,object_pairs_hook=pairs)
        except ValueError as exc: return False,'malformed status: '+str(exc)
        if not isinstance(rec,dict) or set(rec)!={'schema','phase','process','retention','errors'}:
            return False,'status keys mismatch'
        if rec['schema']!=self.STATUS_SCHEMA: return False,'schema mismatch'
        if rec['phase']!='shutdown': return False,'phase mismatch'
        p=rec['process']
        if not isinstance(p,dict) or set(p)!={'quiescence','child_reaped','residual_pid','outcome'}:
            return False,'process keys mismatch'
        if p['quiescence']!='confirmed': return False,'quiescence not confirmed'
        if p['child_reaped'] is not True: return False,'child reap not confirmed'
        if p['residual_pid'] is not None: return False,'residual pid present'
        if p['outcome'] not in self.QUIESCENT_OUTCOMES: return False,'non-quiescent outcome'
        if rec['retention'] not in self.SAFE_RETENTION: return False,'unsafe retention: '+repr(rec['retention'])
        if not isinstance(rec['errors'],list) or rec['errors']: return False,'teardown faults present'
        # Corroborate the typed success contract with the exit code LAST: a
        # well-formed success record paired with a nonzero exit is a mismatch and
        # is refused (arbitrary nonzero never grants success).
        if rc!=0: return False,'exit/status mismatch: rc='+repr(rc)
        return True,rec['retention']
    def stop(self):
        if self.proc is None:
            if self.err is not None: self.err.close()
            return self.report
        try:
            if self.proc.poll() is None:
                try: self.proc.stdin.write(b'stop\n');self.proc.stdin.flush()
                except OSError as e: self.report['cleanup_errors'].append(str(e))
            # Read the native owner's single pinned terminal status BEFORE reaping.
            status_raw,status_err=self._read_status_line()
            try: rc=self.proc.wait(timeout=self.timeout)
            except subprocess.TimeoutExpired:
                self.report['cleanup_errors'].append('native supervisor did not finish; child reap unconfirmed')
                # Preserve the native supervisor as the residual child's owner.
                # Killing it could orphan gvproxy and defeat its reap latch.
                self.report['residual_owner_pid']=self.proc.pid
                rc=None
            self.report['returncode']=rc
            ok,detail=self._consume_safe_success(status_raw,status_err,rc)
            if ok and not self.report['cleanup_errors']:
                self.report['quiescence']='native-confirmed'
                self.report['native_retention']=detail
            else: self.report['cleanup_errors'].append('native shutdown not safe-success: '+detail)
        finally:
            for stream in (self.proc.stdin,self.proc.stdout,self.err):
                try: stream.close()
                except OSError as exc:
                    self.report['cleanup_errors'].append('descriptor close: '+str(exc))
                    self.report['quiescence']='unconfirmed'
            (self.logs/'helper-status.json').write_text(json.dumps(self.report,sort_keys=True))
        return self.report
