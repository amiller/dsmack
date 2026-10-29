import {
  cat,
  checkAssertion,
  decodeAttestation,
  hex,
  open,
  rpcChain,
  seal,
  sha256,
  unhex,
} from "../../../dstack-compat/secret-release/policy.mjs";
import { bytesEqual, decodeCbor, require } from "./encoding.mjs";
import { APP_ID, verifyEnrollment } from "./enrollment.mjs";
import {
  domain,
  Grant,
  NodeBinding,
  paymentBinding,
  Receipt,
  verifyTypedData,
} from "./payments.mjs";
export { hex, unhex };
const enc = new TextEncoder(),
  dec = new TextDecoder("utf-8", { fatal: true }),
  subtle = crypto.subtle;
export const REGISTRY = "0xF7Bbd6DbB5708D3470940dcC19E2b2c75706ee8E";
export const ATTEST = "0xFF8393e6D4c3dF89e826A5BF14829733B953c948";
export const CANARY = "0xdC66c90291973167126a3c4455D5A6064634f3B1";
const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const eq = (a, b) => bytesEqual(a, b),
  hash = async (raw) => hex(await sha256(raw));
export function canonical(value) {
  function sorted(v) {
    if (v === null || typeof v === "string" || typeof v === "boolean") return v;
    if (typeof v === "number") {
      require(Number.isSafeInteger(v), "canonical integer");
      return v;
    }
    if (Array.isArray(v)) return v.map(sorted);
    require(v && typeof v === "object", "canonical value");
    return Object.fromEntries(
      Object.keys(v).sort().map((k) => [k, sorted(v[k])]),
    );
  }
  return enc.encode(JSON.stringify(sorted(value)));
}
export function peerBytes(peer) {
  require(
    typeof peer === "string" && peer.length >= 32 && peer.length <= 100,
    "PeerId",
  );
  let n = 0n;
  for (const c of peer) {
    const d = alphabet.indexOf(c);
    require(d >= 0, "PeerId base58");
    n = n * 58n + BigInt(d);
  }
  let s = n.toString(16);
  if (s.length % 2) s = "0" + s;
  const b = cat(new Uint8Array(peer.match(/^1*/)[0].length), unhex(s));
  require(
    (b.length === 38 && hex(b.slice(0, 6)) === "002408011220") ||
      (b.length === 34 && hex(b.slice(0, 2)) === "1220"),
    "PeerId multihash",
  );
  return b;
}
function peerString(raw) {
  let n = BigInt("0x" + hex(raw)), s = "";
  while (n) {
    s = alphabet[Number(n % 58n)] + s;
    n /= 58n;
  }
  for (const b of raw) {
    if (b !== 0) break;
    s = "1" + s;
  }
  return s;
}
export async function createClient() {
  const key = await subtle.generateKey({ name: "Ed25519" }, false, [
    "sign",
    "verify",
  ]);
  const pub = new Uint8Array(await subtle.exportKey("raw", key.publicKey));
  return {
    peer: peerString(cat(unhex("002408011220"), pub)),
    privateKey: key.privateKey,
  };
}
export async function signBrokerRequest(client, body) {
  require(client.peer === body.client_peer, "request client peer");
  return {
    ...body,
    sig: hex(
      new Uint8Array(
        await subtle.sign("Ed25519", client.privateKey, canonical(body)),
      ),
    ),
  };
}
async function verifyEd(key, signature, body) {
  const pub = await subtle.importKey(
    "raw",
    unhex(key),
    { name: "Ed25519" },
    false,
    ["verify"],
  );
  require(
    await subtle.verify("Ed25519", pub, unhex(signature), canonical(body)),
    "Ed25519 signature",
  );
}
async function rpc(rpcUrl, method, params) {
  const v = await jsonRequest(rpcUrl, {
    jsonrpc: "2.0",
    id: 1,
    method,
    params,
  });
  require(!v.error && typeof v.result === "string", "RPC response");
  return v.result;
}
export async function jsonRequest(url, body, signal, max = 48 << 20) {
  const response = await fetch(url, {
    method: body === undefined ? "GET" : "POST",
    headers: { "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
    redirect: "error",
    signal,
  });
  const reader = response.body.getReader(), chunks = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.length;
    require(size <= max, "HTTP response size");
    chunks.push(value);
  }
  const value = JSON.parse(dec.decode(cat(...chunks)));
  if (!response.ok) throw new Error(value.error ?? "HTTP " + response.status);
  return value;
}
async function assertion(proof, policy, enrollment, minCounter = 0) {
  const a = await decodeAttestation(unhex(proof)),
    obj = decodeCbor(a.assertion),
    auth = obj.get("authenticatorData");
  require(eq(a.key_id, enrollment.kid), "node key is not enrolled Apple key");
  require(
    eq(auth.slice(0, 32), await sha256(enc.encode(APP_ID))),
    "assertion app ID",
  );
  const ext = decodeCbor(auth.slice(37));
  require(
    hex(ext.get("apple_cd_hash_hash_01")) === policy.cdhash,
    "assertion build",
  );
  const counter = new DataView(auth.buffer, auth.byteOffset).getUint32(33);
  require(counter > minCounter, "assertion counter replay");
  const chain = policy.chain ??
      rpcChain(policy.rpc, policy.attest ?? ATTEST, policy.canary ?? CANARY),
    key = await chain.key(a.key_id);
  require(
    eq(cat(key.x, key.y), enrollment.point.slice(1)),
    "chain enrollment key mismatch",
  );
  require(await chain.category() === 3, "chain validation category");
  await checkAssertion(a, chain, Date.now());
  require(
    hex(a.caller) === await hash(enc.encode("node")),
    "Attest caller is not node",
  );
  require(
    hex(a.manifest_sha256) === policy.manifestHash &&
      hex(a.os_image_hash) === policy.image,
    "node measurements",
  );
  return { ...a, counter };
}
// policy.manifest is the exact approved manifest bytes, selected independently of discovery.
export async function verifyNode(registration, policy) {
  require(
    policy.manifest instanceof Uint8Array &&
      /^[0-9a-f]{64}$/.test(policy.cdhash) &&
      /^[0-9a-f]{64}$/.test(policy.brokerKey),
    "node policy",
  );
  const manifest = JSON.parse(dec.decode(policy.manifest)),
    compose = JSON.parse(manifest.docker_compose_file),
    service = compose.services.node;
  require(
    service?.entrypoint?.join() === "/usr/local/bin/dsmack-compute" &&
      service.command?.[0] === "serve" &&
      service.command[4] === policy.brokerKey &&
      service.command[5] === policy.cdhash,
    "compose broker key/build",
  );
  const provider = service.environment?.INFERENCE_PROVIDER
    ? JSON.parse(service.environment.INFERENCE_PROVIDER)
    : null;
  const configuredModel = provider?.model ?? service.environment?.MODEL;
  if (policy.model !== undefined) {
    require(configuredModel === policy.model, "compose model");
  }
  const resolved = {
    ...policy,
    manifestHash: await hash(policy.manifest),
    image: manifest.base_vm.os_image_hash,
    model: policy.model ?? configuredModel ?? "claude-opus-4-8",
    provider,
  };
  require(
    registration.kind === "compute" && registration.cdhash === policy.cdhash &&
      registration.manifest_sha256 === resolved.manifestHash &&
      registration.os_image_hash === resolved.image,
    "node registration measurements",
  );
  require(
    registration.relay_maddr.endsWith(
      "/p2p-circuit/p2p/" + registration.relay_peer,
    ),
    "node circuit target",
  );
  const peer = peerBytes(registration.relay_peer),
    secret = unhex(registration.secret_key),
    receipt = unhex(registration.receipt_key);
  require(secret.length === 64 && receipt.length === 32, "node key lengths");
  await subtle.importKey(
    "raw",
    cat(Uint8Array.of(4), secret),
    { name: "ECDH", namedCurve: "P-256" },
    false,
    [],
  );
  if (!policy.chain) {
    require(
      await rpc(policy.rpc, "eth_chainId", []) === "0x14a34",
      "Base Sepolia required",
    );
    const registry = await rpc(policy.rpc, "eth_call", [{
      to: policy.attest ?? ATTEST,
      data: "0xb4eb10ce",
    }, "latest"]);
    require(
      ("0x" + registry.slice(-40)).toLowerCase() ===
        (policy.registry ?? REGISTRY).toLowerCase(),
      "CDRegistry address",
    );
  }
  const enrollment = await verifyEnrollment(policy.enrollment, policy.cdhash);
  const enrollmentMode = policy.enrollmentMode ?? "on-chain";
  require(
    ["on-chain", "apple-root"].includes(enrollmentMode),
    "enrollment mode",
  );
  if (enrollmentMode === "apple-root") {
    const base = policy.chain ??
      rpcChain(policy.rpc, policy.attest ?? ATTEST, policy.canary ?? CANARY);
    resolved.chain = {
      ...base,
      key: async (kid) => {
        require(eq(kid, enrollment.kid), "unknown Apple enrollment");
        return {
          x: enrollment.point.slice(1, 33),
          y: enrollment.point.slice(33),
          expires: enrollment.expires / 1000,
          counter: 0,
          enrolled: true,
        };
      },
    };
  }
  const a = await assertion(
    registration.proof ?? registration.attestation,
    resolved,
    enrollment,
  );
  let expected = cat(
    await sha256(
      cat(enc.encode("dsmack-compute-node/1"), peer, secret, receipt),
    ),
    new Uint8Array(32),
  );
  if (registration.payments) {
    const p = registration.payments;
    require(
      policy.challenge && p.challenge === policy.challenge &&
        /^[0-9a-f]{64}$/.test(p.challenge),
      "fresh node challenge",
    );
    require(
      p.enrollmentKeyId.toLowerCase() === "0x" + hex(enrollment.kid) &&
        p.runId.toLowerCase() === "0x" + hex(a.run),
      "payment run/key",
    );
    require(
      p.grantSigner.toLowerCase() === policy.grantSigner?.toLowerCase(),
      "payment grant signer",
    );
    require(p.runExpires > Math.floor(Date.now() / 1000), "node run expired");
    const chain = policy.chain ??
      rpcChain(policy.rpc, policy.attest ?? ATTEST, policy.canary ?? CANARY);
    require(
      p.buildId.toLowerCase() === "0x" + hex(await chain.buildId()),
      "payment build",
    );
    expected = cat(
      unhex(
        paymentBinding(
          p,
          registration.relay_peer,
          resolved.manifestHash,
          resolved.image,
        ).slice(2),
      ),
      await sha256(cat(expected, unhex(p.challenge))),
    );
  }
  require(eq(a.report_data, expected), "node PeerId/secret/receipt binding");
  return {
    registration,
    policy: resolved,
    enrollment,
    enrollmentMode,
    attestation: a,
    run: hex(a.run),
    head: hex(a.head),
    counter: a.counter,
  };
}
function terms(grant) {
  return grant.grant
    ? {
      id: String(grant.grant.purchaseId),
      seconds: Number(grant.grant.amount),
    }
    : { id: grant.grant_id, seconds: grant.seconds };
}
async function checkGrant(node, grant, clientPeer) {
  const r = node.registration, now = Math.floor(Date.now() / 1000);
  if (grant.grant) {
    const g = grant.grant, p = r.payments;
    require(p, "paid grant for unpaid node");
    require(
      verifyTypedData(domain(p.escrow), { Grant }, g, grant.signature)
        .toLowerCase() === node.policy.grantSigner.toLowerCase(),
      "paid grant signature",
    );
    const b = grant.nodeBinding?.binding;
    require(
      b &&
        verifyTypedData(
            domain(p.escrow),
            { NodeBinding },
            b,
            grant.nodeBinding.signature,
          ).toLowerCase() === node.policy.grantSigner.toLowerCase(),
      "broker run binding",
    );
    require(
      g.node === p.node && g.runId === p.runId &&
        g.buyerKey === "0x" + hex(peerBytes(clientPeer).slice(6)) &&
        Number(g.unit) === 1,
      "paid grant target",
    );
    require(
      g.issuedAt <= now && now < g.serviceUntil &&
        g.serviceUntil <= Math.min(g.issuedAt + 600, p.runExpires) &&
        Number.isSafeInteger(Number(g.amount)) && Number(g.amount) > 0,
      "paid grant lifetime/budget",
    );
    require(
      g.destinationPolicyHash === node.policy.destinationPolicyHash,
      "paid destination policy",
    );
    require(
      b.node === p.node && b.runId === p.runId &&
        b.operator.toLowerCase() === p.operator.toLowerCase() &&
        b.receiptSigner.toLowerCase() === p.receiptSigner.toLowerCase() &&
        b.composeHash === "0x" + r.manifest_sha256 &&
        b.imageHash === "0x" + r.os_image_hash && g.serviceUntil <= b.expires,
      "paid run binding fields",
    );
  } else {
    const { sig, ...body } = grant;
    await verifyEd(node.policy.brokerKey, sig, body);
    require(
      Object.keys(body).sort().join() ===
          "client_peer,expires_at,grant_id,relay_peer,seconds,unit,v" &&
        body.client_peer === clientPeer && body.relay_peer === r.relay_peer &&
        body.unit === "seconds" && body.v === 1 &&
        Number.isInteger(body.seconds) && body.seconds > 0 &&
        body.seconds <= 1800 && body.expires_at > now &&
        /^[0-9a-f]{32}$/.test(body.grant_id),
      "grant fields/expiry",
    );
  }
}
export async function sealJob(
  node,
  {
    grant,
    jobId = hex(crypto.getRandomValues(new Uint8Array(16))),
    credential,
    repoTar,
    prompt,
    client,
  },
) {
  require(
    /^[0-9a-f]{32}$/.test(jobId) && repoTar instanceof Uint8Array &&
      repoTar.length <= 16 << 20 && typeof prompt === "string",
    "job inputs",
  );
  await checkGrant(node, grant, client.peer);
  const pair = await subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" },
      false,
      ["deriveBits"],
    ),
    pub = new Uint8Array(await subtle.exportKey("raw", pair.publicKey)).slice(
      1,
    );
  let binary = "";
  for (let i = 0; i < repoTar.length; i += 8192) {
    binary += String.fromCharCode(...repoTar.subarray(i, i + 8192));
  }
  const plain = {
    job_id: jobId,
    grant_id: terms(grant).id,
    credential,
    repo_tar: btoa(binary),
    prompt,
    output_pub: hex(pub),
  };
  const sealed = await seal(
    unhex(node.registration.secret_key),
    canonical(plain),
    jobId,
  );
  return {
    node,
    client,
    grant,
    jobId,
    sealed,
    outputKey: { priv: pair.privateKey, pub },
  };
}
export async function submitJob(brokerUrl, job, { signal } = {}) {
  await checkGrant(job.node, job.grant, job.client.peer);
  const signed = {
    bundle_sha256: await hash(canonical(job.sealed)),
    client_peer: job.client.peer,
    grant_sha256: await hash(canonical(job.grant)),
    job_id: job.jobId,
    node_peer: job.node.registration.relay_peer,
  };
  const signature = hex(
    new Uint8Array(
      await subtle.sign("Ed25519", job.client.privateKey, canonical(signed)),
    ),
  );
  return {
    result: jsonRequest(brokerUrl.replace(/\/$/, "") + "/sandbox/jobs", {
      node_peer: signed.node_peer,
      job_id: job.jobId,
      grant: job.grant,
      sealed: job.sealed,
      client_peer: job.client.peer,
      signature,
    }, signal),
  };
}
export async function receive(handle) {
  return handle.result;
}
export async function verifyJobAttestation(node, result, job) {
  require(result.status === "complete", "node job did not complete");
  const s = result.statement, t = terms(job.grant);
  require(
    Object.keys(s).sort().join() ===
        "bundle_sha256,grant_id,job_id,outputs,seconds_used" &&
      s.job_id === job.jobId && s.grant_id === t.id,
    "job statement fields/IDs",
  );
  require(
    s.bundle_sha256 === await hash(canonical(job.sealed)),
    "input bundle digest",
  );
  require(
    Number.isInteger(s.seconds_used) && s.seconds_used > 0 &&
      s.seconds_used <= t.seconds,
    "result seconds",
  );
  const a = await assertion(
    result.attestation,
    node.policy,
    node.enrollment,
    node.counter,
  );
  require(
    hex(a.run) === node.run && hex(a.head) === node.head,
    "job came from another node run",
  );
  require(
    eq(a.report_data, cat(await sha256(canonical(s)), new Uint8Array(32))),
    "job statement attestation binding",
  );
  return { ...a, statement: s };
}
export async function verifyReceipt(node, result, job) {
  const checked = await verifyJobAttestation(node, result, job),
    { sig, ...body } = result.receipt;
  await verifyEd(node.registration.receipt_key, sig, body);
  const expected = {
    client_peer: job.client.peer,
    node_peer: node.registration.relay_peer,
    run: node.run,
    report_sha256: await hash(canonical(result.statement)),
    grant_id: terms(job.grant).id,
    job_id: job.jobId,
    seconds_used: result.statement.seconds_used,
  };
  require(
    eq(canonical(body), canonical(expected)),
    "receipt does not bind job",
  );
  if (job.grant.grant) {
    const e = result.payment_receipt, p = node.registration.payments;
    require(
      e &&
        verifyTypedData(domain(p.escrow), { Receipt }, e.receipt, e.signature)
            .toLowerCase() === p.receiptSigner.toLowerCase(),
      "paid usage receipt signer",
    );
    require(
      String(e.receipt.purchaseId) === terms(job.grant).id &&
        Number(e.receipt.used) >= result.statement.seconds_used &&
        Number(e.receipt.used) <= terms(job.grant).seconds &&
        e.receipt.finalReceipt === true && e.receipt.sequence > 0 &&
        e.receipt.endedAt <= Math.floor(Date.now() / 1000) + 30,
      "paid usage receipt bounds",
    );
  }
  return { ...body, counter: checked.counter };
}
export async function openOutputs(job, result) {
  await verifyReceipt(job.node, result, job);
  require(
    Object.keys(result.outputs).sort().join() === "patch,transcript,verdict" &&
      Object.keys(result.statement.outputs).sort().join() ===
        "patch,transcript,verdict",
    "output names",
  );
  const outputs = {};
  for (const [name, box] of Object.entries(result.outputs)) {
    require(
      Object.keys(box).sort().join() === "ct,epk,iv" &&
        /^[0-9a-f]{128}$/.test(box.epk) && /^[0-9a-f]{24}$/.test(box.iv) &&
        typeof box.ct === "string" && box.ct.length >= 32,
      "sealed output fields",
    );
    outputs[name] = await open(job.outputKey, box, job.jobId + "/" + name);
    require(
      await hash(outputs[name]) === result.statement.outputs[name],
      "plaintext output digest",
    );
  }
  verifyTurnOutputs(job.node, outputs);
  return outputs;
}

// Match the worker's transcript and verdict checks before exposing a patch.
export function verifyTurnOutputs(node, outputs) {
  const events = dec.decode(outputs.transcript).trimEnd().split("\n").map(
    (line) => JSON.parse(line),
  );
  const verdict = JSON.parse(dec.decode(outputs.verdict)),
    provider = node.policy.provider;
  const core = events.filter((e) => e.type !== "gateway_event"),
    assistants = core.filter((e) => e.type === "assistant");
  let summary, turns, model;
  if (provider) {
    model = provider.model;
    require(
      core.length > 0 && core.length === assistants.length &&
        assistants.every((e) => e.model === model),
      "provider transcript model",
    );
    require(
      assistants.every((e) =>
        (e.message.tool_calls ?? []).every((c) =>
          ["list_files", "read_file", "write_file"].includes(c.function.name)
        )
      ),
      "provider tool outside allowlist",
    );
    const last = assistants.at(-1);
    require(!last.message.tool_calls?.length, "provider turn unfinished");
    summary = last.message.content ?? "";
    turns = assistants.length;
  } else {
    model = node.policy.model;
    const init = core.filter((e) =>
      e.type === "system" && e.subtype === "init"
    );
    require(
      init.length === 1 && init[0].model === model && assistants.length > 0 &&
        assistants.every((e) => e.message.model === model),
      "requested/observed model mismatch",
    );
    require(
      assistants.every((e) =>
        e.message.content.filter((b) => b.type === "tool_use").every((b) =>
          ["Read", "Grep", "Glob", "Edit", "Write"].includes(b.name)
        )
      ),
      "tool outside allowlist",
    );
    const last = core.at(-1);
    require(
      last.type === "result" && last.subtype === "success" &&
        last.is_error === false,
      "CLI result not success",
    );
    summary = last.result;
    turns = last.num_turns;
  }
  const expected = {
    answer: null,
    summary: [...summary].slice(0, 1000).join(""),
    num_turns: turns,
    observed_models: [model],
    ...(provider ? { provider: "delegated-openai" } : {}),
  };
  require(eq(canonical(verdict), canonical(expected)), "turn verdict mismatch");
  return verdict;
}
