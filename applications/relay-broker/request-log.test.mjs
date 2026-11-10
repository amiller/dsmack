import assert from "node:assert/strict";
import { test } from "node:test";
import { handleRequest } from "./server.ts";
import { InferenceError } from "./inference.mjs";
import { NearError, NearProvider } from "./near.mjs";

async function capture(operation) {
  const original = console.error, lines = [];
  console.error = line => lines.push(JSON.parse(line));
  try { await operation(lines); } finally { console.error = original; }
}
const nonce = "1234abcd" + "ef".repeat(12);
const bytes = value => new TextEncoder().encode(value).byteLength;

test("a refused signed request logs its prefix and exact UTF-8 bytes without private fields", async () => {
  await capture(async lines => {
    const payload = JSON.stringify({nonce, wallet:"wallet-private-marker", body:"prompt-private-marker 中文"});
    const broker = {cfg:{},inference:{prepare(){throw new InferenceError("BUYER_SIGNATURE", "response-private-marker", 403);}}};
    const response = await handleRequest(new Request("https://broker.example/inference/prepare", {method:"POST",body:payload}), broker);
    const raw = await response.text();
    assert.equal(response.headers.get("x-request-ref"), "1234abcd");
    assert.equal(lines.length, 1);
    assert.equal(lines[0].event, "broker_failure");
    assert.equal(lines[0].code, "BUYER_SIGNATURE");
    assert.equal(lines[0].http_status, 403);
    assert.equal(lines[0].ref, "1234abcd");
    assert.equal(lines[0].request_bytes, bytes(payload));
    assert.equal(lines[0].response_bytes, bytes(raw));
    assert(lines[0].duration_ms >= 0);
    assert(!JSON.stringify(lines).includes("private-marker"));
    assert(!JSON.stringify(lines).includes(nonce));
  });
});

test("unexpected broker failures log once without exposing an exception message", async () => {
  await capture(async lines => {
    const failure = Error("secret-key-private-marker"), broker = {cfg:{},inference:{prepare(){throw failure;}}};
    await assert.rejects(handleRequest(new Request("https://broker.example/inference/prepare", {
      method:"POST",body:JSON.stringify({nonce}),
    }),broker), error=>error===failure);
    assert.equal(lines.length,1);
    assert.equal(lines[0].code,"INTERNAL_ERROR");
    assert.equal(lines[0].ref,"1234abcd");
    assert.equal(lines[0].http_status,500);
    assert(!JSON.stringify(lines).includes("private-marker"));
  });
});

const model = "test/model";
const attestation = fetchEncrypted => ({evidence:{model,verified:true,expires_at:Date.now()/1000+60},transport:{fetchEncrypted}});
const chat = (provider, transport) => provider.chatEncrypted({nonce, key:"key-private-marker",model,
  body:{prompt:"body-private-marker 中文"},headers:{secret:"header-private-marker"},attestation:attestation(transport)});

test("NEAR success and refusal log byte counts and upstream status without response contents", async () => {
  await capture(async lines => {
    const provider = new NearProvider(), payload = "data: 中文\n\n", refusal = "response-private-marker 😀";
    const response = await chat(provider, ()=>new Response(payload,{headers:{"content-type":"text/event-stream"}}));
    assert.equal(await response.text(),payload);
    assert.equal(lines.length,1);
    assert.equal(lines[0].code,"OK");
    assert.equal(lines[0].http_status,200);
    assert.equal(lines[0].request_bytes,bytes(JSON.stringify({prompt:"body-private-marker 中文"})));
    assert.equal(lines[0].response_bytes,bytes(payload));
    await assert.rejects(chat(provider,()=>new Response(refusal,{status:429})),error=>error.code==="PROVIDER_HTTP_429");
    assert.equal(lines.length,2);
    assert.equal(lines[1].http_status,429);
    assert.equal(lines[1].response_bytes,bytes(refusal));
    assert.equal(lines[1].ref,"1234abcd");
    assert(!JSON.stringify(lines).includes("private-marker"));
    assert(!JSON.stringify(lines).includes(nonce));
  });
});

test("NEAR transport failure and stream cancellation each log exactly once", async () => {
  await capture(async lines => {
    const provider = new NearProvider();
    await assert.rejects(chat(provider,()=>{throw Error("secret-key-private-marker");}),error=>error.code==="NEAR_ATTESTATION_TRANSPORT");
    assert.equal(lines.length,1);
    assert.equal(lines[0].http_status,null);
    const response=await chat(provider,()=>new Response(new ReadableStream({pull(c){c.enqueue(new Uint8Array([1,2,3]));}}),{headers:{"content-type":"text/event-stream"}}));
    await response.body.cancel();
    assert.equal(lines.length,2);
    assert.equal(lines[1].code,"REQUEST_CANCELLED");
    assert(!JSON.stringify(lines).includes("private-marker"));
  });
});

test("an interrupted NEAR stream logs the bytes read before the failure once", async () => {
  await capture(async lines => {
    let sent=false;
    const response=await chat(new NearProvider(),()=>new Response(new ReadableStream({pull(c){
      if(sent)throw Error("response-private-marker");
      sent=true;c.enqueue(new Uint8Array([1,2,3]));
    }}),{headers:{"content-type":"text/event-stream"}}));
    await assert.rejects(response.arrayBuffer(), error => error.code === "PROVIDER_TRANSPORT");
    assert.equal(lines.length,1);
    assert.equal(lines[0].code,"PROVIDER_TRANSPORT");
    assert.equal(lines[0].response_bytes,3);
    assert(!JSON.stringify(lines).includes("private-marker"));
  });
});


test("the broker sends NEAR HTTP diagnostics to the client and its request log", async () => {
  await capture(async lines => {
    const broker = { cfg: {}, inference: { prepare() { throw new NearError("PROVIDER_HTTP_402_INSUFFICIENT_CREDIT"); } } };
    const response = await handleRequest(new Request("https://broker.example/inference/prepare", {
      method: "POST", body: JSON.stringify({ nonce }),
    }), broker);
    assert.equal(response.status, 502);
    assert.equal((await response.json()).error.code, "PROVIDER_HTTP_402_INSUFFICIENT_CREDIT");
    assert.equal(lines[0].code, "PROVIDER_HTTP_402_INSUFFICIENT_CREDIT");
  });
});
