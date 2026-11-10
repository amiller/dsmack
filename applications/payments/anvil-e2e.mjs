// Local chain only: forge build --root contracts, anvil --chain-id 84532 --port 18545
// deno run -A applications/payments/anvil-e2e.mjs
import assert from "node:assert/strict";
import { ContractFactory, JsonRpcProvider, Wallet } from "npm:ethers@6.17.0";
import { Payments } from "../relay-broker/payments.mjs";
import { Inference } from "../relay-broker/inference.mjs";
import { AgentSessions } from "../relay-broker/agent.mjs";
import { canonical, signingKey } from "../relay-broker/grants.mjs";
import { Receipt, receiptDomain, receiptSigner, claimDomain, Claim, verifyTypedData } from "./schema.mjs";
const provider = new JsonRpcProvider("http://127.0.0.1:18545", 84532, {cacheTimeout:-1});
const owner=await provider.getSigner(0), user=await provider.getSigner(1), operator=await provider.getSigner(2);
const userAddress=(await user.getAddress()).toLowerCase(), operatorAddress=await operator.getAddress();
const deploy=async(path,args=[])=>{
 const artifact=JSON.parse(await Deno.readTextFile(path));
 const c=await new ContractFactory(artifact.abi,artifact.bytecode.object,owner).deploy(...args);
 await c.waitForDeployment();return c;
};
const usdc=await deploy("contracts/out/UsageEscrow.t.sol/MockUSDC.json");
const rail=await deploy("contracts/out/UsageEscrow.sol/UsageEscrow.json",[await usdc.getAddress(),await owner.getAddress()]);
const brokerKey=Wallet.createRandom(), guest=Wallet.createRandom();
await (await rail.registerBroker(brokerKey.address)).wait();
await (await usdc.mint(userAddress,1000000)).wait();
await (await usdc.connect(user).approve(await rail.getAddress(),1000000)).wait();
await (await rail.connect(user).deposit(1000000)).wait();
let now=Number((await provider.getBlock("latest")).timestamp);
const payments=new Payments({cfg:{escrow:await rail.getAddress(),inferenceOperator:operatorAddress},key:brokerKey,
 now:()=>now,save:async()=>{},chain:{snapshot:async()=>({call:async(name,args)=>await rail[name](...args)})}});
const inference=new Inference({payments,cfg:{model:"fixture"},now:()=>now,
 provider:{apiKey:"local",costs:async()=>({requests:[{requestId:"inference-local",costNanoUsd:"100000"}]})}});
const signed=async(action,extra={})=>{
 const body={action,wallet:userAddress,nonce:crypto.randomUUID().replaceAll("-",""),issuedAt:now,...extra};
 return {...body,sig:await user.signMessage(canonical(body))};
};
const initial=await inference.credit(await signed("credit"));
assert.equal(initial.grantedNanoUsd,"1000000000");
await inference.credit(await signed("credit"));
assert.equal(inference.summary(userAddress).grantedNanoUsd,"1000000000");
const peer="12D3KooWPXeq29kZzJxDgCA92X16PSiM5Bv1XxAshJ8wJzYv9k6x";
const node={kind:"compute",relay_peer:peer,admit_until:now+3600,
 payments:{receiptSigner:guest.address,operator:operatorAddress},attestation:{nodeBinding:{binding:{receiptSigner:guest.address}}}};
const broker={payments,inference,key:await signingKey("12".repeat(32)),cfg:{},now:()=>now,live:()=>[node]};
const sessions=new AgentSessions(broker,async()=>[{publisher:"local-mac",online:true,received_at:now,updated_at:now,
 slots:[{slot_id:0,state:"ready",relay_peer:peer}]}]);
const session=await sessions.open(await signed("agent-open",{conversationId:"local",client_peer:peer,node_peer:peer}));
const receipt={purchaseId:BigInt("0x"+session.sessionId).toString(),sequence:1,unit:1,used:"5",endedAt:now,finalReceipt:true};
const envelope={receipt,signature:await guest.signTypedData(receiptDomain(await rail.getAddress()),{Receipt},receipt)};
await sessions.receipt(envelope);await sessions.receipt(envelope);
assert.equal(inference.summary(userAddress).spentNanoUsd,"900000");
assert.equal(receiptSigner(await rail.getAddress(),envelope),guest.address);
// Billing ID/cost evidence comes from the provider boundary exercised by inference.test.mjs.
payments.state.inferenceCredit[userAddress].pending="local";
payments.state.inferenceRequests={local:{status:"responded",inferenceId:"inference-local",reservedNanoUsd:"100000",usedTokens:"7"}};
await inference.usage(await signed("usage"));
assert.equal(inference.summary(userAddress).spentNanoUsd,"1000000");
const week=Math.floor(now/604800);
await provider.send("evm_increaseTime",[604800]);await provider.send("evm_mine",[]);
now=Number((await provider.getBlock("latest")).timestamp);
const authorization=await payments.weeklyClaim(userAddress,operatorAddress,week);
assert.equal(authorization.claim.cumulativeOwed,"1000");
assert.equal(verifyTypedData(claimDomain(await rail.getAddress(),userAddress),{Claim},authorization.claim,authorization.signature),brokerKey.address);
await (await rail.claim(userAddress,authorization.claim,authorization.signature)).wait();
assert.equal(await usdc.balanceOf(operatorAddress),1000n);
await assert.rejects(rail.claim(userAddress,authorization.claim,authorization.signature));
const excessive={operator:operatorAddress,cumulativeOwed:"1000001",period:week};
const excessiveSig=await brokerKey.signTypedData(claimDomain(await rail.getAddress(),userAddress),{Claim},excessive);
await assert.rejects(rail.claim(userAddress,excessive,excessiveSig));
await (await rail.connect(user).requestExit()).wait();
await assert.rejects(inference.prepare(await signed("prepare",{attestationNonce:"cd".repeat(32)})),e=>e.code==="ACCOUNT_EXITING");
await assert.rejects(rail.connect(user).withdraw());
await provider.send("evm_increaseTime",[14*86400]);await provider.send("evm_mine",[]);
await (await rail.connect(user).withdraw()).wait();
assert.equal(await usdc.balanceOf(userAddress),999000n);
assert.equal(await rail.balance(userAddress),0n);
console.log(JSON.stringify({chainId:84532,rail:await rail.getAddress(),depositUsdcUnits:"1000000",debitNanoUsd:"1000000",claimUsdcUnits:"1000",escapeUsdcUnits:"999000",receipt:"dsmack.receipt/5"}));
provider.destroy();
