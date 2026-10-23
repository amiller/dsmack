// Independent read-only consumer of an already authenticated application archive.
// Native receipt/report bytes remain untouched; this creates a logical namespace.
import { exact, need, sha } from '../bounty-demo/core.mjs';
import { document, encoded, same } from './original-report.mjs';
export const OUTPUT_BUNDLE={schema:'dsmack-flat-result-ustar/1',artifact:'result-files',manifest:'output-manifest.json',duplicates:{'stage-checks':'checks.json','public-input-audit':'public-input-audit.json'}};
const zero=b=>b.every(x=>x===0),name=x=>typeof x==='string'&&/^[a-z][a-z0-9.-]{0,79}$/.test(x);
export function validateOutputBundle(selection){if(selection===null)return;exact(selection,['schema','artifact','manifest','duplicates']);same(selection,OUTPUT_BUNDLE,'selected output bundle protocol');}
function text(b){const n=b.indexOf(0);need(n>=0&&zero(b.subarray(n)),'result USTAR string termination');need(b.subarray(0,n).every(x=>x<128),'result USTAR ASCII');return b.subarray(0,n).toString('ascii');}
function octal(b){need(/^[0-7]+\0$/.test(b.toString('ascii')),'result USTAR octal');const n=parseInt(b.subarray(0,-1).toString('ascii'),8);need(Number.isSafeInteger(n),'result USTAR safe integer');return n;}
export function parseOutputBundle(raw){
 need(Buffer.isBuffer(raw)&&raw.length>=1024&&raw.length<=16*1024*1024&&raw.length%512===0,'bounded raw result USTAR required');
 const members=Object.create(null);let offset=0,last='';
 while(offset+512<=raw.length&&!zero(raw.subarray(offset,offset+512))){
  need(Object.keys(members).length<256,'result member count');const h=raw.subarray(offset,offset+512);need(h.every(x=>x<128),'ASCII result USTAR header');
  need(h.subarray(257,265).equals(Buffer.from('ustar\0'+'00'))&&h[156]===48,'regular USTAR result member required');
  need(zero(h.subarray(157,257))&&zero(h.subarray(265,329))&&zero(h.subarray(345)),'result USTAR metadata/links/prefix/reserved');
  const checksum=h.subarray(148,156).toString('ascii'),copy=Buffer.from(h);copy.fill(32,148,156);
  need(/^[0-7]{6}\0 $/.test(checksum)&&parseInt(checksum,8)===copy.reduce((a,b)=>a+b,0),'result USTAR checksum');
  const n=text(h.subarray(0,100));need(name(n)&&n>last&&!Object.hasOwn(members,n),'ordered unique flat result member');last=n;
  need(octal(h.subarray(100,108))===0o644&&octal(h.subarray(108,116))===0&&octal(h.subarray(116,124))===0&&octal(h.subarray(136,148))===0,'result USTAR mode/owner/time');
  need(octal(h.subarray(329,337))===0&&octal(h.subarray(337,345))===0,'result USTAR device metadata');
  const size=octal(h.subarray(124,136));need(size<=16*1024*1024,'result file bound');offset+=512;
  const end=offset+Math.ceil(size/512)*512;need(end<=raw.length&&zero(raw.subarray(offset+size,end)),'result content/padding');
  members[n]=raw.subarray(offset,offset+size);offset=end;
 }
 need(raw.length===offset+1024&&zero(raw.subarray(offset)),'exact result USTAR terminators');
 need(Object.hasOwn(members,'output-manifest.json'),'internal output manifest required');
 const manifestBytes=members['output-manifest.json'],manifest=document(manifestBytes,262144);exact(manifest,['schema','files']);same(manifest.schema,'dsmack-bounty-output-manifest/1','internal manifest domain');
 need(Array.isArray(manifest.files)&&manifest.files.length>0&&manifest.files.length<=255,'logical result count');
 const files={};let previous='';
 for(const f of manifest.files){
  exact(f,['name','size','sha256']);need(name(f.name)&&!['output-manifest.json','result-files','result-files.tar'].includes(f.name)&&f.name>previous,'logical manifest name/order/self exclusion');previous=f.name;
  need(Number.isSafeInteger(f.size)&&f.size>=0&&typeof f.sha256==='string'&&/^[a-f0-9]{64}$/.test(f.sha256),'logical result descriptor');
  const b=members[f.name];need(Buffer.isBuffer(b)&&b.length===f.size&&sha(b)===f.sha256,'logical result bytes');files[f.name]=b;
 }
 same(Object.keys(members).sort(),[...Object.keys(files),'output-manifest.json'].sort(),'closed result membership');
 // Preserve and independently reconstruct the original application manifest.
 need(manifestBytes.equals(encoded({schema:manifest.schema,files:Object.keys(files).sort().map(n=>({name:n,size:files[n].length,sha256:sha(files[n])}))})),'result manifest reconstruction');
 return {files,manifestBytes};
}
export function expandOutputBundle(nativeOutputs,selection,mapping){
 validateOutputBundle(selection);need(selection!==null,'bundle selection required');
 same(Object.keys(nativeOutputs).filter(k=>k.startsWith('artifact:')).sort(),['artifact:result-files','artifact:stage-checks','artifact:public-input-audit'].sort(),'closed native bundle artifacts');
 const parsed=parseOutputBundle(nativeOutputs['artifact:result-files']);
 same(Object.keys(mapping).sort(),Object.keys(parsed.files).sort(),'closed logical application map');
 for(const [logical,member] of Object.entries(mapping))same(logical,member,'logical bundle member identity');
 for(const [native,logical] of Object.entries(selection.duplicates)){
  need(Buffer.isBuffer(parsed.files[logical])&&Buffer.isBuffer(nativeOutputs['artifact:'+native])&&parsed.files[logical].equals(nativeOutputs['artifact:'+native]),'native/logical duplicate bytes mismatch');
 }
 return parsed;
}
