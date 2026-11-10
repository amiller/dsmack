import assert from "node:assert/strict";
import { test } from "node:test";
import { Earnings } from "./chain.mjs";
import { abi } from "../payments/schema.mjs";

test("cumulative claims become incremental USDC payouts per user and a failed read retries the whole chunk",async()=>{
 const address="0x"+"11".repeat(20),user="0x"+"22".repeat(20),other="0x"+"33".repeat(20);
 const e=new Earnings({rpc:"http://127.0.0.1:1",chainId:84532,escrow:address,deploymentBlock:0});
 e.provider.destroy();e.checked=true;
 const log=(who,total,index)=>({...abi.encodeEventLog(abi.getEvent("Claimed"),[who,address,total,30]),
  blockNumber:index,transactionHash:"0x"+String(index).repeat(64)});
 let fail=true;
 e.provider={getLogs:async()=>[log(user,1000,1),log(user,2000,2),log(other,500,3)],
  getBlock:async block=>{if(block===2&&fail)throw Error("RPC unavailable");return {number:100,timestamp:2000000000}}};
 await assert.rejects(e.read(),/RPC unavailable/);
 assert.equal(e.events.length,0);assert.equal(e.cumulative.size,0);assert.equal(e.nextBlock,0);
 fail=false;
 const events=await e.read();
 assert.deepEqual(events.map(e=>e.operatorCredit),["1000","1000","500"]);
 assert.equal(e.nextBlock,101);
 assert.deepEqual(await e.read(),events);
});
