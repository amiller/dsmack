// The same HTTP verdict route, with genuine closed acceptance enforced before
// the existing certificate gate. No caller-selected paths or trust configuration.
import { createApplication } from '../bounty-demo/server.mjs';
import { need } from '../bounty-demo/core.mjs';
import { AcceptanceAdapter } from './acceptance-adapter.mjs';
export function createAcceptanceApplication({store,operatorToken,admissions,reportKeys,loadInput,...options}) {
  need(typeof loadInput==='function','trusted original-evidence source required');
  need(!Object.hasOwn(options,'verdictAdmission'),'acceptance gate cannot be overridden');
  const adapter=new AcceptanceAdapter({store,admissions,reportKeys});
  return createApplication({...options,store,operatorToken,verdictAdmission:async(id,cert)=>adapter.admit(id,await loadInput(id),cert)});
}
