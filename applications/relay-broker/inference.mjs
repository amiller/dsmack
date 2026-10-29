import {
  domain,
  json,
  keccak256,
  NodeBinding,
  Receipt,
} from "../payments/schema.mjs";
import { grantBytes } from "./grants.mjs";
import { peerBytes } from "./attestation.mjs";
import { hex, unhex } from "../../dstack-compat/secret-release/policy.mjs";

export class InferenceError extends Error {
  constructor(code, message, status = 400) {
    super(message);
    this.code = code;
    this.status = status;
  }
}
const check = (ok, code, message, status) => {
  if (!ok) throw new InferenceError(code, message, status);
};
const integer = (v) => /^(0|[1-9][0-9]*)$/.test(String(v));
const enc = new TextEncoder();
export const PRIVACY =
  "NEAR TEE model via broker CVM; broker handles plaintext";

// All allocation mutations use the payments queue and the same durable file:
// a token purchase cannot simultaneously authorize a Mac grant or another key.
export class Inference {
  constructor(
    { payments, cfg, provider, now = () => Math.floor(Date.now() / 1000) },
  ) {
    Object.assign(this, { payments, cfg, provider, now });
    check(
      payments && cfg && /^0x[0-9a-fA-F]{64}$/.test(cfg.node) &&
        typeof cfg.model === "string" && cfg.model.length > 0 &&
        Number.isSafeInteger(cfg.requestTokenCeiling) &&
        cfg.requestTokenCeiling > 0 &&
        integer(cfg.maxNanoUsdPerToken) && BigInt(cfg.maxNanoUsdPerToken) > 0n,
      "BAD_REQUEST",
      "inference class, model and integer tariff configuration required",
    );
    this.sealingKey = crypto.subtle.digest(
      "SHA-256",
      enc.encode(
        "dsmack-inference-key/1:" + payments.key.privateKey,
      ),
    ).then((v) =>
      crypto.subtle.importKey("raw", v, "AES-GCM", false, [
        "encrypt",
        "decrypt",
      ])
    );
  }
  async store(a) {
    const p = this.payments;
    const next = {
      ...p.state,
      inference: { ...p.state.inference, [a.purchaseId]: a },
    };
    await p.save(next);
    p.state = next;
    return a;
  }
  async recover() {
    // Dispatch is durably marked "sent" before the provider sees any prompt.
    // Only a pre-dispatch reservation is safe to clear after process restart.
    return await this.payments.serial(async () => {
      for (const a of Object.values(this.payments.state.inference ?? {})) {
        if (a.pending?.stage === "attesting") {
          await this.store({ ...a, pending: null });
        }
      }
    });
  }
  allocation(id) {
    const a = this.payments.state.inference?.[id];
    check(
      a,
      "CREDIT_NOT_CONFIRMED",
      "mint an allocation from confirmed token credit first",
      402,
    );
    return a;
  }
  async authorized(r, action, fn) {
    return await this.payments.serial(async () => {
      check(
        r?.action === action && /^[1-9][0-9]*$/.test(r.purchaseId) &&
          /^0x[0-9a-fA-F]{64}$/.test(r.txHash) &&
          /^[0-9a-f]{32}$/.test(r.nonce),
        "BAD_REQUEST",
        "signed inference request fields required",
      );
      check(
        Number.isSafeInteger(r.issuedAt) &&
          Math.abs(this.now() - r.issuedAt) <= 120,
        "REQUEST_EXPIRED",
        "request must be signed within 120 seconds",
        403,
      );
      let pub;
      try {
        pub = peerBytes(r.client_peer);
      } catch { /* checked below */ }
      check(
        pub?.length === 38 && hex(pub.slice(0, 6)) === "002408011220",
        "BUYER_SIGNATURE",
        "inline Ed25519 buyer identity required",
        403,
      );
      const { sig, ...fields } = r;
      const key = await crypto.subtle.importKey(
        "raw",
        pub.slice(6),
        "Ed25519",
        false,
        ["verify"],
      );
      check(
        typeof sig === "string" && /^[0-9a-f]{128}$/.test(sig) &&
          await crypto.subtle.verify(
            "Ed25519",
            key,
            unhex(sig),
            grantBytes(fields),
          ),
        "BUYER_SIGNATURE",
        "buyer signature does not verify",
        403,
      );
      const c = this.payments.state.confirmed?.[r.purchaseId];
      check(
        c && c.txHash === r.txHash,
        "CREDIT_NOT_CONFIRMED",
        "purchase must be finalized by /payments/confirm",
        402,
      );
      check(
        c.purchase.buyerKey.toLowerCase() === "0x" + hex(pub.slice(6)),
        "BUYER_SIGNATURE",
        "buyer does not control this purchase",
        403,
      );
      check(
        Number(c.purchase.unit) === 2 &&
          c.purchase.node.toLowerCase() === this.cfg.node.toLowerCase(),
        "WRONG_UNIT",
        "purchase must be for the configured token class",
      );
      const p = this.payments;
      const nonces = p.state.inferenceNonces?.[r.purchaseId] ?? {};
      check(
        !Object.hasOwn(nonces, r.nonce),
        "REQUEST_REPLAY",
        "request nonce already used",
        409,
      );
      const retained = Object.fromEntries(
        Object.entries(nonces).filter(([, at]) => at >= this.now() - 240),
      );
      const next = {
        ...p.state,
        inferenceNonces: {
          ...p.state.inferenceNonces,
          [r.purchaseId]: { ...retained, [r.nonce]: r.issuedAt },
        },
      };
      await p.save(next);
      p.state = next;
      return await fn(c);
    });
  }
  summary(a) {
    return {
      purchaseId: a.purchaseId,
      mode: "broker-proxy",
      provider: "near",
      model: a.model,
      keyId: a.keyId,
      status: a.status,
      amountTokens: a.purchase.amount,
      usedTokens: a.usedTokens,
      reservedTokens: a.pending ? String(this.cfg.requestTokenCeiling) : "0",
      remainingTokens: (BigInt(a.purchase.amount) - BigInt(a.usedTokens) -
        (a.pending ? BigInt(this.cfg.requestTokenCeiling) : 0n)).toString(),
      capNanoUsd: a.capNanoUsd,
      costNanoUsd: a.costNanoUsd,
      expiresAt: a.purchase.expires,
      activeAt: a.activeAt,
    };
  }
  status() {
    return {
      mode: "broker-proxy",
      provider: "near",
      model: this.cfg.model,
      providerConfigured: Boolean(this.provider?.apiKey),
      delegationConfigured: Boolean(
        this.provider && this.provider.canMint !== false,
      ),
      tokenEscrowConfigured: this.cfg.tokenEscrowReady !== false,
      privacy: PRIVACY,
    };
  }
  async quote() {
    check(
      this.cfg.tokenEscrowReady !== false,
      "TOKEN_ESCROW_NOT_CONFIGURED",
      "existing escrow serves sandbox credit; tokens require a separately deployed Sepolia escrow",
      503,
    );
    const s = await this.payments.chain.snapshot();
    const node = await s.call("getNode", [this.cfg.node]);
    check(
      Number(node.unit) === 2,
      "WRONG_UNIT",
      "configured escrow class does not support tokens",
    );
    return {
      mode: "broker-proxy",
      provider: "near",
      model: this.cfg.model,
      unit: "tokens",
      unitId: 2,
      chainId: 84532,
      escrow: this.payments.cfg.escrow,
      codeHash: this.payments.cfg.codeHash,
      node: this.cfg.node,
      priceWei: String(await s.call("quote", [this.cfg.node])),
      floorPriceWei: String(node.floorPrice),
      maxTokens: "10000000",
      requestTokenCeiling: this.cfg.requestTokenCeiling,
      maxNanoUsdPerToken: String(this.cfg.maxNanoUsdPerToken),
      finalizedBlock: s.block.hash,
      configured: Boolean(this.provider && this.provider.canMint !== false),
    };
  }
  async seal(key, id) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: enc.encode(id) },
      await this.sealingKey,
      enc.encode(key),
    );
    return { iv: hex(iv), ciphertext: hex(new Uint8Array(ciphertext)) };
  }
  async unseal(a) {
    return new TextDecoder().decode(
      await crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: unhex(a.sealedKey.iv),
          additionalData: enc.encode(a.purchaseId),
        },
        await this.sealingKey,
        unhex(a.sealedKey.ciphertext),
      ),
    );
  }
  configured() {
    check(
      this.provider && this.provider.canMint !== false,
      "PROVIDER_NOT_CONFIGURED",
      "Andrew must provision NEAR management and reporting credentials",
      503,
    );
  }
  mint(r) {
    return this.authorized(r, "mint", async () => {
      this.configured();
      const old = this.payments.state.inference?.[r.purchaseId];
      if (old) {
        check(
          old.status !== "minting",
          "MINT_AMBIGUOUS",
          "inspect/revoke the named provider key before replacement",
          409,
        );
        return this.summary(old);
      }
      check(
        !this.payments.state.grants[r.purchaseId],
        "WRONG_UNIT",
        "purchase already allocated to a service",
      );
      const p = this.payments, s = await p.chain.snapshot();
      const purchase = await p.chain.purchase(s, r.purchaseId, r.txHash);
      check(
        Number(purchase.unit) === 2 &&
          purchase.node.toLowerCase() === this.cfg.node.toLowerCase() &&
          Number(purchase.expires) > this.now() + 15,
        "CREDIT_EXHAUSTED",
        "token purchase unavailable or expired",
        402,
      );
      const n = await s.call("getNode", [purchase.node]);
      check(
        Number(n.unit) === 2 &&
          purchase.operator.toLowerCase() === n.operator.toLowerCase() &&
          (await s.call("brokerSigner")).toLowerCase() ===
            p.key.address.toLowerCase(),
        "BAD_REQUEST",
        "inference class or broker binding differs from finalized escrow",
      );
      const capNanoUsd =
        (BigInt(purchase.amount) * BigInt(this.cfg.maxNanoUsdPerToken))
          .toString();
      check(
        BigInt(capNanoUsd) <= BigInt(Number.MAX_SAFE_INTEGER),
        "BAD_REQUEST",
        "provider cap exceeds safe integer schema",
      );
      const a = {
        purchaseId: r.purchaseId,
        txHash: r.txHash,
        status: "minting",
        model: this.cfg.model,
        name: `dsmack-${p.cfg.escrow.toLowerCase()}-${r.purchaseId}`,
        capNanoUsd,
        purchase: JSON.parse(
          json(purchase.toObject ? purchase.toObject() : purchase),
        ),
        node: {
          operator: n.operator,
          composeHash: n.composeHash,
          imageHash: n.imageHash,
        },
        usedTokens: "0",
        costNanoUsd: "0",
        createdAt: this.now(),
        requests: [],
        usage: null,
      };
      // Persist intent first: timeouts and failed saves never trigger another mint.
      await this.store(a);
      const result = await this.provider.mint({
        name: a.name,
        capNanoUsd,
        expiresAt: new Date(Number(purchase.expires) * 1000).toISOString(),
      });
      check(
        result.id && result.key,
        "MINT_AMBIGUOUS",
        "provider key creation response incomplete",
        409,
      );
      await this.store({
        ...a,
        status: "active",
        keyId: result.id,
        sealedKey: await this.seal(result.key, a.purchaseId),
        activeAt: this.now() + 10,
      });
      return this.summary(this.allocation(r.purchaseId));
    });
  }
  async refresh(a) {
    this.configured();
    check(
      a.keyId,
      "MINT_AMBIGUOUS",
      "provider key creation needs reconciliation",
      409,
    );
    const usage = await this.provider.usage({
      keyId: a.keyId,
      model: a.model,
      from: new Date(a.createdAt * 1000).toISOString(),
      to: new Date(this.now() * 1000).toISOString(),
    });
    check(
      integer(usage.totalTokens) && integer(usage.costNanoUsd),
      "USAGE_MISMATCH",
      "provider totals must be nonnegative integers",
      502,
    );
    const tokens = BigInt(usage.totalTokens), cost = BigInt(usage.costNanoUsd);
    check(
      tokens >= BigInt(a.usedTokens) && cost >= BigInt(a.costNanoUsd) &&
        tokens <= BigInt(a.purchase.amount) && cost <= BigInt(a.capNanoUsd),
      "USAGE_MISMATCH",
      "provider usage regressed or exceeded purchased credit",
      502,
    );
    const ids = new Set(usage.rows.map((row) => row.inference?.inference_id));
    const expected = a.requests.map((r) => r.inferenceId);
    check(
      usage.rows.length === expected.length &&
        expected.every((id) => id && ids.has(id)),
      "USAGE_PENDING",
      "wait for every admitted request's attributed provider usage row",
      409,
    );
    if (a.pending) {
      check(
        a.pending.inferenceId && ids.has(a.pending.inferenceId),
        "USAGE_PENDING",
        "latest request is not yet present in provider usage",
        409,
      );
    }
    const changed = a.usedTokens !== String(usage.totalTokens) ||
      a.costNanoUsd !== String(usage.costNanoUsd);
    return await this.store({
      ...a,
      pending: null,
      usedTokens: String(usage.totalTokens),
      costNanoUsd: String(usage.costNanoUsd),
      usage,
      charge: changed ? null : a.charge,
    });
  }
  usage(r) {
    return this.authorized(r, "usage", async () => {
      const a = await this.refresh(this.allocation(r.purchaseId));
      return {
        ...this.summary(a),
        usage: a.usage,
        attestation: a.attestation ?? null,
      };
    });
  }
  async charge(a, finalReceipt) {
    check(
      !a.pending,
      "USAGE_PENDING",
      "unreconciled request prevents settlement",
      409,
    );
    if (!a.charge || a.charge.receipt.finalReceipt !== finalReceipt) {
      const p = this.payments;
      const nodeBinding = a.nodeBinding ??
        {
          binding: {
            node: a.purchase.node,
            operator: a.node.operator,
            receiptSigner: p.key.address,
            composeHash: a.node.composeHash,
            imageHash: a.node.imageHash,
            runId: keccak256(enc.encode(a.name)),
            expires: Number(a.purchase.expires),
          },
        };
      if (!nodeBinding.signature) {
        nodeBinding.signature = await p.key.signTypedData(
          domain(p.cfg.escrow),
          { NodeBinding },
          nodeBinding.binding,
        );
      }
      const receipt = {
        purchaseId: a.purchaseId,
        sequence: (a.sequence ?? 0) + 1,
        used: a.usedTokens,
        endedAt: Math.min(this.now(), Number(a.purchase.expires)),
        finalReceipt,
      };
      const signature = await p.key.signTypedData(domain(p.cfg.escrow), {
        Receipt,
      }, receipt);
      a = await this.store({
        ...a,
        sequence: receipt.sequence,
        nodeBinding,
        charge: { receipt, signature, nodeBinding },
      });
    }
    const used = BigInt(a.usedTokens),
      price = BigInt(a.purchase.price),
      floor = BigInt(a.purchase.floorPrice);
    return {
      allocation: this.summary(a),
      ...a.charge,
      chargeWei: String(used * price),
      operatorWei: String(used * floor),
      premiumWei: String(used * (price - floor)),
      refundableWei: String((BigInt(a.purchase.amount) - used) * price),
    };
  }
  charges(r) {
    return this.authorized(r, "charges", async () => {
      const a = this.allocation(r.purchaseId);
      return await this.charge(
        a.status === "closed" ? a : await this.refresh(a),
        a.status === "closed",
      );
    });
  }
  close(r) {
    return this.authorized(r, "close", async () => {
      let a = this.allocation(r.purchaseId);
      if (a.status === "closed") return await this.charge(a, true);
      check(
        !a.pending,
        "REQUEST_IN_FLIGHT",
        "reconcile the admitted request before closing",
        409,
      );
      this.configured();
      check(
        a.keyId,
        "MINT_AMBIGUOUS",
        "provider key creation needs reconciliation",
        409,
      );
      // The secret was never delivered; admission stops before revocation.
      a = await this.store({ ...a, status: "closing" });
      if (!a.revokedAt) {
        await this.provider.revoke(a.keyId);
        a = await this.store({ ...a, revokedAt: this.now() });
      }
      a = await this.refresh(a);
      a = await this.store({ ...a, status: "closed" });
      return await this.charge(a, true);
    });
  }
  async chat(r) {
    const a = await this.authorized(r, "chat", async () => {
      this.configured();
      const a = this.allocation(r.purchaseId);
      check(
        a.status === "active",
        "ALLOCATION_CLOSED",
        "allocation is not active",
        409,
      );
      check(
        !a.pending,
        "REQUEST_IN_FLIGHT",
        "reconcile previous request before sending another",
        409,
      );
      check(
        this.now() >= a.activeAt,
        "PROVIDER_UNAVAILABLE",
        "delegated key activation may take ten seconds",
        502,
      );
      check(
        this.now() + 30 < Number(a.purchase.expires) &&
          BigInt(a.purchase.amount) - BigInt(a.usedTokens) >=
            BigInt(this.cfg.requestTokenCeiling),
        "CREDIT_EXHAUSTED",
        "remaining credit cannot reserve the model's maximum request",
        402,
      );
      check(
        Array.isArray(r.messages) && r.messages.length > 0 &&
          r.messages.length <= 256 &&
          r.messages.every((m) =>
            m && ["system", "user", "assistant"].includes(m.role) &&
            typeof m.content === "string" && Object.keys(m).every((k) =>
              ["role", "content"].includes(k)
            )
          ) &&
          enc.encode(JSON.stringify(r.messages)).length <= 100000 &&
          Number.isSafeInteger(r.max_tokens) && r.max_tokens > 0 &&
          r.max_tokens <= this.cfg.requestTokenCeiling,
        "BAD_REQUEST",
        "bounded text messages and max_tokens required",
      );
      return await this.store({
        ...a,
        pending: { nonce: r.nonce, stage: "attesting" },
      });
    });
    let attestation;
    const key = await this.unseal(a);
    try {
      const nonce = hex(
        new Uint8Array(
          await crypto.subtle.digest(
            "SHA-256",
            enc.encode(
              "dsmack-near-attestation/1:" + r.purchaseId + ":" + r.txHash +
                ":" + r.nonce,
            ),
          ),
        ),
      );
      attestation = await this.provider.attest({ key, model: a.model, nonce });
      check(
        attestation.evidence,
        "ATTESTATION_INVALID",
        "verified provider evidence required",
        502,
      );
    } catch (e) {
      await this.payments.serial(() =>
        this.store({ ...this.allocation(a.purchaseId), pending: null })
      );
      throw e;
    }
    try {
      await this.payments.serial(async () => {
        const current = this.allocation(a.purchaseId);
        check(
          current.status === "active",
          "ALLOCATION_CLOSED",
          "allocation closed during attestation",
          409,
        );
        await this.store({
          ...current,
          attestation: attestation.evidence,
          pending: { ...current.pending, stage: "sent" },
        });
      });
      const response = await this.provider.chat({
        key,
        model: a.model,
        messages: r.messages,
        max_tokens: r.max_tokens,
        attestation,
      });
      check(
        response.ok && response.body,
        "PROVIDER_UNAVAILABLE",
        "provider did not return a completion stream",
        502,
      );
      const inferenceId = response.headers.get("inference-id");
      check(
        inferenceId,
        "USAGE_PENDING",
        "provider omitted billing correlation header; reconcile before retry",
        409,
      );
      await this.payments.serial(async () => {
        const current = this.allocation(a.purchaseId);
        await this.store({
          ...current,
          requests: [...current.requests, { inferenceId }],
          pending: { ...current.pending, inferenceId },
        });
      });
      const evidence = attestation.evidence;
      const stream = new ReadableStream({
        async start(controller) {
          controller.enqueue(
            enc.encode(
              `event: attestation\ndata: ${JSON.stringify(evidence)}\n\n`,
            ),
          );
          try {
            for await (const chunk of response.body) controller.enqueue(chunk);
          } catch {
            try {
              controller.enqueue(
                enc.encode(
                  'event: error\ndata: {"error":{"code":"PROVIDER_UNAVAILABLE","message":"stream interrupted; reconcile usage before retry"}}\n\n',
                ),
              );
            } catch { /* client disconnected */ }
          } finally {
            attestation.transport?.close?.();
            try {
              controller.close();
            } catch { /* client disconnected */ }
          }
        },
      });
      return new Response(stream, {
        headers: {
          "content-type": "text/event-stream",
          "cache-control": "no-store",
        },
      });
    } catch (e) {
      attestation.transport?.close?.();
      throw e;
    }
  }
}
