import http.server,json,subprocess,sys,tempfile,threading,unittest
from pathlib import Path
HERE=Path(__file__).parent
ROOT_SHA='4de4686cb585a54375a9ab859aa533e8a81255d9d2c9a76b96d0ae9006ecc0df'
TASK={'slug':'board-search','payout_wei':'1000','chain_id':84532,'runtime':{'trust_key_sha256':ROOT_SHA,'key_id':'k','sequence':3,'profile_id':'p','release_inventory_sha256':'a'*64,'assets':[{'name':n,'url':'https://github.com/x','bytes':1<<20,'sha256':'b'*64}for n in ('inventory','signature','archive')]}}

class Doctor(unittest.TestCase):
    def test_reads_only_task_and_reports_each_check(self):
        seen=[]
        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                seen.append(('GET',self.path));b=json.dumps(TASK).encode();self.send_response(200);self.send_header('Content-Length',str(len(b)));self.end_headers();self.wfile.write(b)
            def do_POST(self):seen.append(('POST',self.path));self.send_response(500);self.end_headers()
            def log_message(self,*a):pass
        srv=http.server.ThreadingHTTPServer(('127.0.0.1',0),H);threading.Thread(target=srv.serve_forever,daemon=True).start()
        with tempfile.TemporaryDirectory(prefix='.d-',dir=Path.home())as t:
            t=Path(t);t.chmod(0o700);node=t/'node';node.write_text('#!/bin/sh\necho v22.1.0\n');node.chmod(0o700);key=t/'key.pem';key.write_bytes(b'not the maintainer key');key.chmod(0o600)
            r=subprocess.run([sys.executable,'-I',str(HERE/'doctor.py'),'--api',f'http://127.0.0.1:{srv.server_port}','--allow-loopback','--home',str(t/'h'),'--node',str(node),'--public-key',str(key),'--json'],capture_output=True,text=True,timeout=60)
            srv.shutdown();out=json.loads(r.stdout);status={c['check']:c['status']for c in out['checks']}
            self.assertEqual(r.returncode,1);self.assertFalse(out['ready'])
            self.assertEqual((status['node'],status['public_key'],status['paths'],status['task_runtime'],status['release_approval']),('fail','fail','ok','ok','unknown'),out['checks'])
            self.assertIn('disk',status);self.assertEqual(out['task']['payout_wei'],'1000')
            self.assertEqual(seen,[('GET','/api/task')]);self.assertFalse((t/'h').exists())
