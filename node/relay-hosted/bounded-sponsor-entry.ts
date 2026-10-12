// Operator entry: configuration is supplied in the reviewed source bundle, never
// taken from public HTTP bodies. Phase changes require a container restart.
import relayHandler from './server.ts';
import {QualificationSponsorPolicy,type QualificationBudget,type SponsorPolicy} from './sponsor-policy.ts';
import {PublicPilotSponsorPolicy,type PilotBudget} from './pilot-sponsor-policy.ts';
import {nativeSponsorChecks,pilotAccountAddress,pilotAccountEligibleForFirstClaim,type MeasuredAdmission} from './sponsor-chain-checks.ts';
type Context={env:Record<string,string>,dataDir:string};
type Config=({phase:'qualification',budget:QualificationBudget}|{phase:'public-pilot',budget:PilotBudget})&{measured?:MeasuredAdmission};
let singleton:Promise<SponsorPolicy>|undefined;let singleDataDir:string|undefined;
const abi=JSON.parse(await Deno.readTextFile(new URL('./abi.json',import.meta.url)));
const badges=JSON.parse(await Deno.readTextFile(new URL('./badge-abi.json',import.meta.url)));
async function policy(ctx:Context){
 if(singleDataDir!==undefined&&singleDataDir!==ctx.dataDir)throw Error('sponsorship writer changed');singleDataDir=ctx.dataDir;
 singleton??=(async()=>{const c=JSON.parse(await Deno.readTextFile(new URL('./native-sponsor-plan.json',import.meta.url))) as Config;
  if(c.phase==='qualification')return new QualificationSponsorPolicy(c.budget,ctx.dataDir+'/native-qualification-budget.json',abi,nativeSponsorChecks(240000000000000n,c.measured));
  if(c.phase==='public-pilot'){const deps=nativeSponsorChecks(0n,c.measured);return new PublicPilotSponsorPolicy(c.budget,ctx.dataDir+'/native-public-pilot-budget.json',{...abi,factory:badges.factory,badges:badges.badges},{...deps,verifyHello:deps.verifyHello!,accountAddress:pilotAccountAddress,accountEligibleForFirstClaim:pilotAccountEligibleForFirstClaim});}
  throw Error('bounded native sponsorship configuration absent');
 })();return await singleton;
}
export default async function handler(request:Request,ctx:Context){
 try{
  if(Object.keys(ctx.env).sort().join(',')!=='PRIVATE_KEY,RPC_URL,SPONSOR_WRITES_PAUSED')throw Error('stored native environment names changed');
  // Owner maintenance delegates a paused context. This instance is retired by
  // the final isolated-container restart; it is never switched in place.
  const paused=ctx.env.SPONSOR_WRITES_PAUSED==='true';
  if(paused&&request.method==='POST'&&/\/(?:nft|ios)\/send\/release-nft-seed\/?$/.test(new URL(request.url).pathname))return Response.json({error:'native key release paused; retry after operator cutover'},{status:503});
  const sponsorPolicy=paused?undefined:await policy(ctx);
  return relayHandler(request,{...ctx,env:{...ctx.env,NATIVE_DIRECTORY_ENABLED:'true'},sponsorPolicy});
 }catch{return Response.json({error:'bounded native sponsorship unavailable; operator reconciliation required'},{status:503});}
}
