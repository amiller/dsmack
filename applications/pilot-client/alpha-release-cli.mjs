import {readFileSync,openSync,closeSync,fstatSync,constants as C} from 'node:fs';
import {authenticateInventory,verifyStagedFiles,canonical,authenticateWorkload} from './alpha-release.mjs';
import {selectProfile} from './alpha-profile.mjs';
function read(path,max){const fd=openSync(path,C.O_RDONLY|C.O_NOFOLLOW|C.O_NONBLOCK);try{const s=fstatSync(fd);if(!s.isFile()||s.nlink!==1||s.size>max)throw Error('Public input shape');return readFileSync(fd);}finally{closeSync(fd);}}
try{
 const a={};const allowed=['inventory','signature','trust-key','key-id','channel','min-sequence','root','profile','workload-admission','workload-signature'];
 for(let i=2;i<process.argv.length;i+=2){const k=process.argv[i]?.slice(2);if(process.argv[i]!==`--${k}`||!allowed.includes(k)||a[k]!==undefined||!process.argv[i+1])throw Error('Arguments');a[k]=process.argv[i+1];}
 for(const k of allowed.slice(0,6))if(a[k]===undefined)throw Error('Missing '+k);
 if(!/^(0|[1-9][0-9]*)$/.test(a['min-sequence']))throw Error('Sequence');
 const authenticated=authenticateInventory(read(a.inventory,262144),read(a.signature,64),{publicKey:read(a['trust-key'],4096),keyId:a['key-id'],channel:a.channel,minSequence:Number(a['min-sequence'])});
 if(a.root)verifyStagedFiles(a.root,authenticated);
 if(a.profile&&!a.root)throw Error('Profile requires checked stage');
 const profile=a.profile?selectProfile(a.root,authenticated.inventory,a.profile):null;
 if(!!a['workload-admission']!==!!a['workload-signature']||a['workload-admission']&&!profile)throw Error('Workload requires both signature and selected profile');
 const workload=a['workload-admission']?authenticateWorkload(read(a['workload-admission'],65536),read(a['workload-signature'],64),authenticated,profile,{publicKey:read(a['trust-key'],4096)}):null;
 console.log(canonical({schema:'dsmack-alpha-authentication-result/3',workload,runtime:{node_version:process.version,node_arch:process.arch,node_platform:process.platform,shared_objects:[...new Set(process.report.getReport().sharedObjects.map(p=>p===process.execPath?'<node-executable>':p))].sort()},inventory_sha256:authenticated.inventory_sha256,inventory:authenticated.inventory,staged_files_checked:!!a.root,profile,launch_ready:false}));
}catch(e){console.error('Release admission refused: '+e.message);process.exitCode=1;}
