"""First upgrade transfers controllers while keeping the existing guests alive."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest

from pool_handoff import LegacyHandoff, ExistingProcess


class HandoffTests(unittest.TestCase):
    def test_handoff_resumes_on_rejection_and_commit_keeps_guest_and_transport(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); (root/'guests').mkdir()
            (root/'pool_mac_run.py').write_text('import time; time.sleep(120)\n')
            (root/'pool.py').write_text('''import json,subprocess,sys,time
from pathlib import Path
root=Path(sys.argv[1]); run=root/'guests/run-one'; run.mkdir()
driver=subprocess.Popen([sys.executable,str(root/'pool_mac_run.py'),str(run)])
(run/'compose-manifest.json').write_text(json.dumps(dict(docker_compose_file=json.dumps(dict(services=dict(node=dict(environment=dict(ADMIT_SECONDS='3120'))))))))
(root/'guests/pool.jsonl').write_text(json.dumps(dict(event='launch',run=str(run),driver_pid=driver.pid,slot_id=0))+'\\n'+json.dumps(dict(event='ready',run=str(run),relay_peer='guest'))+'\\n')
(root/'guests/directory.json').write_text(json.dumps(dict(slots=[dict(slot_id=0,relay_peer='guest',started_at=int(time.time()),attestation=dict(relay_peer='guest'))])))
(root/'driver.pid').write_text(str(driver.pid))
time.sleep(120)
''')
            (root/'mac-pool.py').write_text('''import subprocess,sys,time
from pathlib import Path
root=Path(sys.argv[sys.argv.index('--state')+1])
pool=subprocess.Popen([sys.executable,str(root/'pool.py'),str(root)])
transport=subprocess.Popen([sys.executable,'-c','import time; time.sleep(120)'],start_new_session=True)
(root/'controllers.json').write_text(__import__('json').dumps(dict(pool=pool.pid,transport=transport.pid)))
time.sleep(120)
''')
            launcher=subprocess.Popen([sys.executable,str(root/'mac-pool.py'),'--state',str(root)])
            owned=[launcher.pid]
            try:
                deadline=time.monotonic()+5
                while not (root/'driver.pid').exists():
                    self.assertIsNone(launcher.poll())
                    self.assertLess(time.monotonic(),deadline)
                    time.sleep(.01)
                controllers=json.loads((root/'controllers.json').read_bytes())
                driver=int((root/'driver.pid').read_text())
                owned.extend([controllers['pool'],controllers['transport'],driver])
                handoff=LegacyHandoff(launcher.pid,root)
                self.assertEqual(handoff.pool.pid,controllers['pool'])
                self.assertEqual([p.pid for p in handoff.transports],[controllers['transport']])
                handoff.resume()
                self.assertIsNone(ExistingProcess(driver).poll())
                handoff=LegacyHandoff(launcher.pid,root)
                handoff.commit()
                launcher.wait(timeout=5)
                self.assertEqual(launcher.returncode,-signal.SIGKILL)
                self.assertIsNone(ExistingProcess(driver).poll())
                self.assertIsNone(ExistingProcess(controllers['transport']).poll())
            finally:
                for pid in reversed(owned):
                    try:os.kill(pid,signal.SIGKILL)
                    except ProcessLookupError:pass
                launcher.wait(timeout=5)


if __name__ == '__main__':
    unittest.main()
