import test from 'node:test';
import assert from 'node:assert/strict';
import {canonical,sha} from '../bounty-demo/core.mjs';
import {treeIdentity} from './projection.mjs';
import {verifySourceRelation} from './source-relation.mjs';
const raw=x=>Buffer.from(canonical(x));
const entry=(path,content,mode=420)=>({path,mode,bytes:Buffer.byteLength(content),sha256:sha(Buffer.from(content))});
function fixture(change) {
  const base=[entry('apps/board/index.html','base'),entry('apps/board/logic.js','logic'),entry('package.json','{}')];
  const candidate=structuredClone(base);candidate[0]=entry(base[0].path,'candidate');
  change?.(base,candidate);
  const baseManifestBytes=raw(base),candidateManifestBytes=raw(candidate);
  const expectedBase=treeIdentity(baseManifestBytes),expectedCandidate=treeIdentity(candidateManifestBytes);
  const record={schema:'dsmack-bounty-admission-transform/2',operation:'allowlisted-existing-file-replacement',
    base_tree_manifest_sha256:expectedBase,candidate_tree_manifest_sha256:expectedCandidate,
    allowed_paths:['apps/board/index.html','apps/board/logic.js','apps/board/ui.js'],
    changed_files:['apps/board/index.html']};
  const args={baseManifestBytes,candidateManifestBytes,expectedBase,expectedCandidate};
  return {record,args};
}
function run(f) {const transformBytes=raw(f.record);return verifySourceRelation({...f.args,transformBytes,expectedTransform:sha(transformBytes)});}
test('actual full manifest relation and independently pinned identities pass',()=>{
  const result=run(fixture());assert.deepEqual(result.changed_files,['apps/board/index.html']);assert.ok(Object.isFrozen(result.changed_files));
});
test('digest substitution and self-consistent wrong transform record refuse',()=>{
  const f=fixture();f.args.expectedCandidate='0'.repeat(64);assert.throws(()=>run(f),/candidate tree/);
  const g=fixture();g.record.base_tree_manifest_sha256='0'.repeat(64);assert.throws(()=>run(g),/transform base/);
});
test('outside allowlist, additions/deletions and executable modes refuse',()=>{
  for(const mutate of [
    (_,c)=>c[2]=entry('package.json','malicious'),
    (_,c)=>c.push(entry('z.js','added')),
    (_,c)=>c.pop(),
    (_,c)=>c[0].mode=493,
  ]) assert.throws(()=>run(fixture(mutate)));
});
test('actual omitted changes, broadened allowlist and no-op refuse',()=>{
  const f=fixture((_,c)=>c[1]=entry('apps/board/logic.js','changed'));assert.throws(()=>run(f),/complete actual/);
  const g=fixture();g.record.allowed_paths.push('package.json');assert.throws(()=>run(g),/fixed board/);
  const h=fixture((b,c)=>c.splice(0,c.length,...b));assert.throws(()=>run(h),/nonempty actual/);
});
test('legacy upstream assertions and extra claimed audit flags refuse',()=>{
  for(const field of ['upstream_commit','upstream_git_tree','verified']) {
    const f=fixture();f.record[field]=true;assert.throws(()=>run(f));
  }
  const f=fixture();f.record.schema='dsmack-bounty-admission-transform/1';assert.throws(()=>run(f),/version/);
});
test('noncanonical or duplicate-key record and wrong selected digest refuse',()=>{
  const f=fixture(),transformBytes=Buffer.from(JSON.stringify(f.record,null,2));
  assert.throws(()=>verifySourceRelation({...f.args,transformBytes,expectedTransform:sha(transformBytes)}),/canonical/);
  assert.throws(()=>verifySourceRelation({...f.args,transformBytes:raw(f.record),expectedTransform:'0'.repeat(64)}),/digest/);
});
