// Initial trust: invoke this inspected CLI with a public maintainer key selected
// outside the release archive. This snapshots prerequisites; it installs no code.
import {createPublicKey,createHash,verify} from 'node:crypto';
import {mkdirSync,lstatSync,realpathSync,readFileSync,openSync,closeSync,fstatSync,fsyncSync,writeSync,copyFileSync,chmodSync,constants as C} from 'node:fs';
import {resolve,dirname,join} from 'node:path';import {fileURLToPath} from 'node:url';
function need(v,m){if(!v)throw Error(m);}
function protect(path){need(realpathSync(path)===path,'Symlink ancestry');for(let p=path;;p=dirname(p)){const s=lstatSync(p);need(s.isDirectory()&&[0,process.getuid()].includes(s.uid)&&!(s.mode&0o022),'Unsafe bootstrap parent');if(p===dirname(p))break;}}
function durable(path,b,mode=0o600){const fd=openSync(path,C.O_WRONLY|C.O_CREAT|C.O_EXCL|C.O_NOFOLLOW,mode);try{let n=0;while(n<b.length)n+=writeSync(fd,b,n,b.length-n);fsyncSync(fd);}finally{closeSync(fd);}}
function pin(path){const b=readFileSync(path);return {path,bytes:b.length,sha256:createHash('sha256').update(b).digest('hex')};}
try{
 need(!Object.keys(process.env).some(k=>k.startsWith('NODE_')||k.startsWith('DYLD_')),'Clear NODE_* and DYLD_* bootstrap injection environment');
 const a={};for(let i=2;i<process.argv.length;i+=2){const k=process.argv[i]?.slice(2);need(['trust-key','key-id','channel','min-sequence','out'].includes(k)&&process.argv[i]===`--${k}`&&a[k]===undefined&&process.argv[i+1],'Arguments');a[k]=process.argv[i+1];}
 for(const k of ['trust-key','key-id','channel','min-sequence','out'])need(a[k]!==undefined,'Missing '+k);
 need(/^(0|[1-9][0-9]*)$/.test(a['min-sequence'])&&Number.isSafeInteger(Number(a['min-sequence'])),'Sequence');
 const keyfd=openSync(a['trust-key'],C.O_RDONLY|C.O_NOFOLLOW|C.O_NONBLOCK);let key;try{const s=fstatSync(keyfd);need(s.isFile()&&s.nlink===1&&s.size<=4096,'Bounded regular public key');key=readFileSync(keyfd);}finally{closeSync(keyfd);}need(key.length<=4096&&key.toString().startsWith('-----BEGIN PUBLIC KEY-----')&&createPublicKey(key).asymmetricKeyType==='ed25519','External Ed25519 PUBLIC key required');
 verify(null,Buffer.from('dsmack-bootstrap-algorithm-probe'),createPublicKey(key),Buffer.alloc(64));
 const objects=[...new Set(process.report.getReport().sharedObjects.map(p=>p===process.execPath?'<node-executable>':p))].sort();need(objects.length<=512&&objects.every(p=>typeof p==='string'&&p.length<=4096),'Bounded runtime dependencies');
 const dependencies=[];for(const load_path of objects){if(load_path==='<node-executable>'||load_path.startsWith('/System/Library/')||load_path.startsWith('/usr/lib/')||load_path.startsWith('/lib/')||load_path.startsWith('/lib64/')||/^linux-vdso\.so\./.test(load_path))continue;need(load_path.startsWith('/'),'Absolute native dependency');const path=realpathSync(load_path);need(load_path===path,'Native dependency aliases refused');protect(dirname(load_path));protect(dirname(path));const st=lstatSync(path);need(st.isFile()&&st.nlink===1&&[0,process.getuid()].includes(st.uid)&&!(st.mode&0o022),'Protected native dependency');dependencies.push({load_path,...pin(path)});}
 const out=resolve(a.out);protect(dirname(out));need(!lstatExists(out),'Fresh bootstrap destination required');mkdirSync(out,{mode:0o700});
 const source=dirname(fileURLToPath(import.meta.url));const sources={};
 for(const name of ['alpha-release-cli.mjs','alpha-release.mjs','alpha-profile.mjs','alpha_stage.py']){const b=readFileSync(join(source,name));need(b.length<=262144,'Bootstrap source bound');durable(join(out,name),b);if(name.endsWith('.mjs'))sources[name]=pin(join(out,name));}
 durable(join(out,'root.pem'),key);let node;
 if(process.platform==='darwin'){node=realpathSync(process.execPath);protect(dirname(node));const st=lstatSync(node);need(st.isFile()&&[0,process.getuid()].includes(st.uid)&&!(st.mode&0o022),'Protected existing Node prerequisite');}
 else{node=join(out,'node');copyFileSync(realpathSync(process.execPath),node,C.COPYFILE_EXCL);chmodSync(node,0o700);const fd=openSync(node,C.O_RDONLY);try{fsyncSync(fd);}finally{closeSync(fd);}}
 const config={schema:'dsmack-alpha-bootstrap/2',node:pin(node),sources,trust_key:pin(join(out,'root.pem')),key_id:a['key-id'],channel:a.channel,min_sequence:Number(a['min-sequence']),runtime:{node_version:process.version,node_arch:process.arch,node_platform:process.platform,shared_objects:objects},runtime_dependencies:dependencies};durable(join(out,'bootstrap.json'),Buffer.from(JSON.stringify(config)+'\n'));
 for(const p of [out,dirname(out)]){const fd=openSync(p,C.O_RDONLY|C.O_DIRECTORY|C.O_NOFOLLOW);try{fsyncSync(fd);}finally{closeSync(fd);}}
 console.log(JSON.stringify({schema:'dsmack-alpha-bootstrap-result/1',bootstrap:join(out,'bootstrap.json'),installer:join(out,'alpha_stage.py'),node_version:process.version,trust_key_sha256:config.trust_key.sha256,launch_ready:false}));
}catch(e){console.error('Bootstrap refused: '+e.message);process.exitCode=1;}
function lstatExists(p){try{lstatSync(p);return true;}catch(e){if(e.code==='ENOENT')return false;throw e;}}
