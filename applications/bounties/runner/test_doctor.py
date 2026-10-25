import hashlib,http.server,json,os,shutil,subprocess,sys,tempfile,threading,unittest
from unittest import mock
from pathlib import Path
HERE=Path(__file__).parent;NODE=str(Path(shutil.which('node')).resolve())
s=HERE/'doctor.py';D={'__name__':'arcade_doctor','__file__':str(s)};exec(compile(s.read_bytes(),str(s),'exec'),D);S=D['S']
APP={'attestation_category':6,'bundle_id':'dev.dsmack.provider','cdhash_full':'1'*64,'certificate_sha256':'2'*64,'entitlements_sha256':'3'*64,'notarization_evidence_sha256':'4'*64,'team_id':'T'}
# Sign a tiny synthetic release with a fresh key through the same canonical encoder the CLI checks.
SIGN="""import {generateKeyPairSync,sign} from 'node:crypto';import {writeFileSync} from 'node:fs';import {canonical} from '%s';
const [out,issued,expires,app]=process.argv.slice(1);const {publicKey,privateKey}=generateKeyPairSync('ed25519');
const v={schema:'dsmack-alpha-release/2',key_id:'k',release_id:'r',channel:'alpha',sequence:3,issued_at:issued,expires_at:expires,platform:{os:'darwin',arch:'arm64',minimum_version:'27.0'},app:JSON.parse(app),
files:[{path:'profiles/p.json',bytes:5000,sha256:'5'.repeat(64),mode:384},{path:'a.bin',bytes:7000,sha256:'6'.repeat(64),mode:448}],profiles:[{profile_id:'p',descriptor_path:'profiles/p.json',descriptor_sha256:'5'.repeat(64)}],
provenance_sha256:'7'.repeat(64),verification_policy:'dsmack-developer-id-signing/1',archive:{format:'tar+gzip',bytes:9000,sha256:'8'.repeat(64)}};
const raw=Buffer.from(canonical(v));writeFileSync(out+'/inventory',raw);writeFileSync(out+'/signature',sign(null,Buffer.concat([Buffer.from(v.schema+'\\0'),raw]),privateKey));writeFileSync(out+'/key.pem',publicKey.export({type:'spki',format:'pem'}));"""%(HERE.parents[1]/'pilot-client/alpha-release.mjs')

def fixture(t,expires='2099-01-01T00:00:00.000Z'):
    f=t/'f';f.mkdir(mode=0o700);subprocess.run([NODE,'--input-type=module','-e',SIGN,str(f),'2020-01-01T00:00:00.000Z',expires,json.dumps(APP)],check=True)
    for n in ('inventory','signature','key.pem'):(f/n).chmod(0o600)
    runtime={'trust_key_sha256':hashlib.sha256((f/'key.pem').read_bytes()).hexdigest(),'key_id':'k','sequence':3,'profile_id':'p','release_inventory_sha256':hashlib.sha256((f/'inventory').read_bytes()).hexdigest(),
             'assets':[{'name':'inventory','url':'https://github.com/i','bytes':(f/'inventory').stat().st_size,'sha256':'0'*64},{'name':'signature','url':'https://github.com/s','bytes':64,'sha256':'0'*64},{'name':'archive','url':'https://github.com/a','bytes':9000,'sha256':'8'*64}]}
    return f,runtime

def serve(task,seen):
    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append(('GET',self.path));b=json.dumps(task).encode();self.send_response(200);self.send_header('Content-Length',str(len(b)));self.end_headers();self.wfile.write(b)
        def do_POST(self):seen.append(('POST',self.path));self.send_response(500);self.end_headers()
        def log_message(self,*a):pass
    srv=http.server.ThreadingHTTPServer(('127.0.0.1',0),H);threading.Thread(target=srv.serve_forever,daemon=True).start();return srv

class Doctor(unittest.TestCase):
    def setUp(self):self.tmp=tempfile.TemporaryDirectory(prefix='.d-',dir=Path.home());self.t=Path(self.tmp.name);self.t.chmod(0o700)
    def tearDown(self):self.tmp.cleanup()
    def copy(self,f,fetched):
        def fetch(d,path):fetched.append(d['name']);shutil.copyfile(f/d['name'],path)
        return fetch

    def test_reads_only_task_and_skips_release_without_node_and_key(self):
        seen=[];_,runtime=fixture(self.t);srv=serve({'slug':'b','payout_wei':'1000','runtime':runtime},seen)
        node=self.t/'node';node.write_text('#!/bin/sh\necho v22.1.0\n');node.chmod(0o700);key=self.t/'key.pem';key.write_bytes(b'not the maintainer key');key.chmod(0o600)
        r=subprocess.run([sys.executable,'-I',str(s),'--api',f'http://127.0.0.1:{srv.server_port}','--allow-loopback','--home',str(self.t/'h h'),'--node',str(node),'--public-key',str(key),'--json'],capture_output=True,text=True,timeout=60);srv.shutdown()
        out=json.loads(r.stdout);status={c['check']:c['status']for c in out['checks']}
        self.assertEqual(r.returncode,1);self.assertEqual((status['node'],status['public_key'],status['paths'],status['release']),('fail','fail','ok','fail'),out['checks'])
        self.assertEqual(out['task']['payout_wei'],'1000');self.assertEqual(seen,[('GET','/api/task')]);self.assertFalse((self.t/'h h').exists())

    def test_release_authenticates_metadata_only_and_budgets_expanded_bytes(self):
        f,runtime=fixture(self.t);fetched=[]
        v,row=D['release'](NODE,str(f/'key.pem'),runtime,str(self.t/'h'),self.copy(f,fetched))
        self.assertEqual((row[0],fetched,v['sequence']),('ok',['inventory','signature'],3));self.assertEqual([n for _,_,n in S['disk_need'](self.t/'h',self.t/'h'/'s',v)],[5000+7000+9000+(12<<30)])
        self.assertEqual(sorted(os.listdir(self.t)),['f'])
        runtime['release_inventory_sha256']='9'*64
        with self.assertRaisesRegex(ValueError,'not the task runtime'):D['release'](NODE,str(f/'key.pem'),runtime,str(self.t/'h'),self.copy(f,[]))
        fetched=[];runtime['assets'][0]['bytes']=2<<30
        with self.assertRaisesRegex(ValueError,'size caps'):D['release'](NODE,str(f/'key.pem'),runtime,str(self.t/'h'),self.copy(f,fetched))
        self.assertEqual(fetched,[])

    def test_symlinked_node_names_its_resolved_path(self):
        node=self.t/'node';node.write_text('#!/bin/sh\necho v24.0.0\n');node.chmod(0o700);(self.t/'link').symlink_to(node)
        with self.assertRaisesRegex(ValueError,'not a symlink: '+str(node)):S['node_version'](str(self.t/'link'))

    def test_setup_refuses_expired_release_before_archive_or_state(self):
        f,runtime=fixture(self.t,'2021-01-01T00:00:00.000Z');fetched=[];srv=serve({'runtime':runtime,'app_policy_sha256':'0'*64},[])
        node=self.t/'node';shutil.copyfile(NODE,node);node.chmod(0o700)
        argv=['setup.py','--api',f'http://127.0.0.1:{srv.server_port}','--allow-loopback','--home',str(self.t/'h'),'--node',str(node),'--public-key',str(f/'key.pem')]
        try:
            with mock.patch.dict(S,{'ROOT_SHA':runtime['trust_key_sha256'],'download':self.copy(f,fetched)}),mock.patch.object(sys,'argv',argv),self.assertRaisesRegex(ValueError,'Release not current'):S['main']()
        finally:srv.shutdown()
        self.assertEqual(fetched,['inventory','signature']);self.assertEqual(sorted(os.listdir(self.t)),['f','node'])
