// NEW bounded source-delivery restriction; no archive extraction or execution.
import { need, sha } from '../bounty-demo/core.mjs';
import { document, same } from './original-report.mjs';
import { treeIdentity } from './projection.mjs';
const zero=b=>b.every(x=>x===0);
function text(raw){const i=raw.indexOf(0);need(i>=0&&zero(raw.subarray(i)),'USTAR string termination');const value=raw.subarray(0,i).toString('ascii');need(Buffer.from(value,'ascii').equals(raw.subarray(0,i)),'USTAR ASCII');return value;}
function octal(raw){need(/^[0-7]+\0$/.test(raw.toString('ascii')),'USTAR octal');const n=parseInt(raw.subarray(0,-1).toString('ascii'),8);need(Number.isSafeInteger(n),'USTAR safe integer');return n;}
export function verifySourceDelivery(bundleBytes,candidateManifestBytes,candidate) {
  need(Buffer.isBuffer(bundleBytes)&&bundleBytes.length>=1024&&bundleBytes.length<=32*1024*1024&&bundleBytes.length%512===0,'bounded raw USTAR bundle required');
  same(treeIdentity(candidateManifestBytes),candidate,'delivered candidate manifest');
  const entries=document(candidateManifestBytes,4*1024*1024);let offset=0;
  for(const entry of entries){
    const head=bundleBytes.subarray(offset,offset+512);need(head.length===512&&!zero(head),'missing USTAR member');
    need(head.subarray(257,265).equals(Buffer.from('ustar\0'+'00')),'USTAR format');
    const check=Buffer.from(head);check.fill(32,148,156);
    const checksum=head.subarray(148,156).toString('ascii');need(/^[0-7]{6}\0 $/.test(checksum)&&parseInt(checksum,8)===check.reduce((a,b)=>a+b,0),'USTAR checksum');
    need([0,48].includes(head[156])&&zero(head.subarray(157,257)),'USTAR regular file only');
    need(zero(head.subarray(500)),'USTAR reserved bytes');
    const prefix=text(head.subarray(345,500)),name=text(head.subarray(0,100));
    same(prefix?prefix+'/'+name:name,entry.path,'USTAR source path/order');
    same(octal(head.subarray(100,108)),entry.mode,'USTAR source mode');
    same(octal(head.subarray(124,136)),entry.bytes,'USTAR source size');
    offset+=512;need(offset+entry.bytes<=bundleBytes.length,'truncated USTAR content');
    same(sha(bundleBytes.subarray(offset,offset+entry.bytes)),entry.sha256,'USTAR source bytes');
    const end=offset+Math.ceil(entry.bytes/512)*512;need(zero(bundleBytes.subarray(offset+entry.bytes,end)),'USTAR padding');offset=end;
  }
  need(bundleBytes.length===offset+1024&&zero(bundleBytes.subarray(offset)),'exact USTAR terminator/membership');
}
