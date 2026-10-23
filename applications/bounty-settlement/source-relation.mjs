// NEW transform/2: a content relation, not upstream Git provenance.
// Call only after BOTH full source bundles have authenticated against these
// manifests. A worker's transform declaration does not establish that premise.
import {canonical, exact, need, sha} from '../bounty-demo/core.mjs';
import {treeIdentity} from './projection.mjs';

const PATHS = Object.freeze([
  'apps/board/index.html', 'apps/board/logic.js', 'apps/board/ui.js',
]);
const bytes = value => Buffer.from(canonical(value));
const same = (a,b,label) => need(canonical(a) === canonical(b),label);

export function verifySourceRelation({baseManifestBytes, candidateManifestBytes,
  transformBytes, expectedBase, expectedCandidate, expectedTransform}) {
  // treeIdentity validates canonical encoding, exact entry fields, sorted
  // membership, file-only modes, traversal and ancestor conflicts.
  same(treeIdentity(baseManifestBytes),expectedBase,'independent base tree');
  same(treeIdentity(candidateManifestBytes),expectedCandidate,'independent candidate tree');
  need(Buffer.isBuffer(transformBytes) && transformBytes.length > 0 &&
    transformBytes.length <= 131072,'bounded transform');
  same(sha(transformBytes),expectedTransform,'independent transform digest');
  const record=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(transformBytes));
  need(bytes(record).equals(transformBytes),'canonical transform');
  exact(record,['schema','operation','base_tree_manifest_sha256',
    'candidate_tree_manifest_sha256','allowed_paths','changed_files']);
  same(record.schema,'dsmack-bounty-admission-transform/2','transform version');
  same(record.operation,'allowlisted-existing-file-replacement','transform operation');
  same(record.base_tree_manifest_sha256,expectedBase,'transform base');
  same(record.candidate_tree_manifest_sha256,expectedCandidate,'transform candidate');
  same(record.allowed_paths,PATHS,'fixed board allowlist');
  const base=JSON.parse(baseManifestBytes), candidate=JSON.parse(candidateManifestBytes);
  need(base.length > 0,'nonempty source tree');
  same(base.map(e=>e.path),candidate.map(e=>e.path),'no added/deleted source files');
  const changed=[];
  for(let i=0;i<base.length;i++) {
    const before=base[i], after=candidate[i];
    same(before.mode,after.mode,'no source mode changes');
    if(before.bytes !== after.bytes || before.sha256 !== after.sha256) {
      need(PATHS.includes(before.path),'change outside fixed board allowlist');
      changed.push(before.path);
    }
  }
  need(changed.length > 0,'nonempty actual source change');
  same(record.changed_files,changed,'complete actual source changes');
  return Object.freeze({schema:record.schema,base_sha256:expectedBase,
    candidate_sha256:expectedCandidate,transform_sha256:expectedTransform,
    changed_files:Object.freeze([...changed])});
}
