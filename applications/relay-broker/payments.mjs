import {
  binding,
  domain,
  Grant,
  json,
  NodeBinding,
  receiptSigner,
  require,
  runNode,
} from "../payments/schema.mjs";
import { Quorum } from "../payments/quorum.mjs";
import { admissionChain } from "../payments/admission.mjs";
import { peerBytes, verifyRelay, withEnrollment } from "./attestation.mjs";
import { grantBytes } from "./grants.mjs";
import { hex, unhex } from "../../dstack-compat/secret-release/policy.mjs";

export class Payments {
  constructor(
    {
      cfg,
      key,
      state = { grants: {}, receipts: {} },
      save,
      now = () => Math.floor(Date.now() / 1000),
      quorum = undefined,
    },
  ) {
    this.cfg = cfg;
    this.key = key;
    this.state = state;
    this.save = save;
    this.now = now;
    this.chain = quorum ?? new Quorum(cfg);
    this.pending = Promise.resolve();
    this.challenges = new Map();
  }
  serial(fn) {
    const p = this.pending.then(fn);
    this.pending = p.catch(() => {});
    return p;
  }
  challenge() {
    const now = this.now();
    for (const [k, until] of this.challenges) {
      if (until < now) this.challenges.delete(k);
    }
    require(this.challenges.size < 1024, "too many admission challenges");
    const challenge = hex(crypto.getRandomValues(new Uint8Array(32)));
    this.challenges.set(challenge, now + 60);
    return { challenge };
  }
  async register(r, cfg) {
    this.brokerCfg = cfg;
    const s = await this.chain.snapshot();
    const checked = await verifyRelay(
      r,
      cfg,
      withEnrollment(
        await admissionChain(s, { ...cfg, ...this.cfg }),
        cfg.enrollments,
      ),
      this.now(),
    );
    const p = r.payments;
    require(
      p && p.grantSigner.toLowerCase() === this.key.address.toLowerCase() &&
        p.destinationPolicyHash === this.cfg.destinationPolicyHash,
      "node must pin this coordinator grant signer",
    );
    require(
      p && p.escrow.toLowerCase() === this.cfg.escrow.toLowerCase(),
      "payment escrow mismatch",
    );
    require(
      (this.challenges.get(p.challenge) ?? 0) > this.now(),
      "fresh broker admission challenge required",
    );
    require(
      p.enrollmentKeyId.toLowerCase() === "0x" + checked.key_id &&
        runNode(p.enrollmentKeyId, p.runNonce) === p.runId,
      "payment node/enrollment/run binding",
    );
    // buildId is compared with CDRegistry at the same finalized block by verifyRelay.
    require(
      checked.build_id === p.buildId.slice(2).toLowerCase(),
      "registered payment build mismatch",
    );
    const n = await s.call("getNode", [p.node]);
    require(
      n.operator.toLowerCase() === p.operator.toLowerCase() &&
        Number(n.unit) === (r.kind === "compute" ? 1 : 0),
      "class operator/unit mismatch",
    );
    require(
      n.composeHash === "0x" + r.manifest_sha256 &&
        n.imageHash === "0x" + r.os_image_hash,
      "class measurements mismatch",
    );
    require(p.runExpires > this.now(), "run expired");
    require(
      (await s.call("brokerSigner")).toLowerCase() ===
        this.key.address.toLowerCase(),
      "on-chain broker signer mismatch",
    );
    return await this.serial(async () => {
      let envelope = this.state.bindings?.[p.runId];
      if (!envelope) {
        const value = {
          node: p.node,
          operator: p.operator,
          receiptSigner: p.receiptSigner,
          composeHash: "0x" + r.manifest_sha256,
          imageHash: "0x" + r.os_image_hash,
          runId: p.runId,
          expires: Math.min(p.runExpires, this.now() + 600),
        };
        envelope = {
          binding: value,
          signature: await this.key.signTypedData(domain(this.cfg.escrow), {
            NodeBinding,
          }, value),
        };
        const next = {
          ...this.state,
          bindings: { ...this.state.bindings, [p.runId]: envelope },
        };
        await this.save(next);
        this.state = next;
      }
      require(
        envelope.binding.receiptSigner.toLowerCase() ===
            p.receiptSigner.toLowerCase() &&
          envelope.binding.node === p.node &&
          envelope.binding.expires > this.now(),
        "run binding changed or expired",
      );
      this.challenges.delete(p.challenge);
      return { ...checked, block: s.block.hash, nodeBinding: envelope };
    });
  }
  async classes() {
    const s = await this.chain.snapshot();
    return await Promise.all(
      this.cfg.classes.map(async (node) => ({
        node,
        ...(await s.call("getNode", [node])).toObject(),
        price: (await s.call("quote", [node])).toString(),
        finalizedBlock: s.block.hash,
      })),
    );
  }
  async list(relays) {
    return relays.filter((r) =>
      r.payments && r.attestation.nodeBinding?.binding.expires > this.now()
    );
  }
  async checkNode(node, s) {
    await verifyRelay(
      { ...node, attestation: node.proof },
      this.brokerCfg,
      withEnrollment(
        await admissionChain(s, { ...this.brokerCfg, ...this.cfg }),
        this.brokerCfg.enrollments,
      ),
      this.now(),
    );
  }
  grant(r, relays) {
    return this.serial(async () => {
      const pub = peerBytes(r.client_peer);
      require(pub.length === 38, "inline Ed25519 buyer key required");
      const key = await crypto.subtle.importKey(
        "raw",
        pub.slice(6),
        "Ed25519",
        false,
        ["verify"],
      );
      const fields = {
        client_peer: r.client_peer,
        purchaseId: r.purchaseId,
        txHash: r.txHash,
        runId: r.runId,
      };
      require(
        typeof r.sig === "string" && /^[0-9a-f]{128}$/.test(r.sig) &&
          await crypto.subtle.verify(
            "Ed25519",
            key,
            unhex(r.sig),
            grantBytes(fields),
          ),
        "buyer grant request signature",
      );
      const s = await this.chain.snapshot(),
        p = await this.chain.purchase(s, r.purchaseId, r.txHash);
      require(
        p.buyerKey === "0x" + hex(pub.slice(6)),
        "purchase buyerKey does not control this PeerId",
      );
      const node = relays.find((n) =>
        n.payments?.node === p.node && n.payments.runId === r.runId
      );
      require(node, "payment node is not live");
      await this.checkNode(node, s);
      const nodeBinding = node.attestation.nodeBinding;
      require(nodeBinding?.binding.expires > this.now(), "run binding expired");
      const existing = this.state.grants[r.purchaseId];
      if (existing) {
        require(
          existing.txHash === r.txHash &&
            existing.envelope.grant.buyerKey === p.buyerKey,
          "purchase terms changed",
        );
        require(
          existing.envelope.grant.serviceUntil > this.now(),
          "grant expired",
        );
        return existing.envelope;
      }
      const issuedAt = Math.max(this.now(), Number(p.boughtAt));
      const serviceUntil = Math.min(
        issuedAt + 600,
        Number(p.expires),
        nodeBinding.binding.expires,
      );
      require(issuedAt < serviceUntil, "purchase expired before activation");
      const grant = {
        purchaseId: r.purchaseId,
        node: p.node,
        runId: node.payments.runId,
        buyerKey: p.buyerKey,
        unit: Number(p.unit),
        amount: p.amount.toString(),
        issuedAt,
        serviceUntil,
        destinationPolicyHash: this.cfg.destinationPolicyHash,
      };
      const envelope = {
        grant,
        nodeBinding,
        signature: await this.key.signTypedData(domain(this.cfg.escrow), {
          Grant,
        }, grant),
      };
      const purchase = Object.fromEntries(
        ["amount", "boughtAt", "expires"].map(
          (k) => [k, String(p[k])],
        ),
      );
      purchase.receiptSigner = nodeBinding.binding.receiptSigner;
      purchase.nodeBinding = nodeBinding;
      const next = {
        ...this.state,
        grants: {
          ...this.state.grants,
          [r.purchaseId]: { envelope, txHash: r.txHash, purchase },
        },
      };
      await this.save(next);
      this.state = next;
      return envelope;
    });
  }
  collect(envelope) {
    return this.serial(async () => {
      const signer = receiptSigner(this.cfg.escrow, envelope),
        r = envelope.receipt;
      // These terms were obtained with the finalized purchase and never mutate.
      // Reusing them keeps one-second receipt checkpoints off the RPC hot path.
      const cached = this.state.grants[r.purchaseId]?.purchase;
      require(cached, "confirmed grant required before receipt");
      const p = cached;
      require(
        signer.toLowerCase() === p.receiptSigner.toLowerCase(),
        "registered guest receipt signer required",
      );
      require(
        BigInt(r.used) <= BigInt(p.amount) && r.endedAt >= Number(p.boughtAt) &&
          r.endedAt <= Number(p.expires) && r.endedAt <= this.now(),
        "receipt bounds",
      );
      const old = this.state.receipts[r.purchaseId];
      if (old && Object.keys(r).every((k) => r[k] === old.receipt[k])) {
        return { stored: true };
      }
      require(
        !old ||
          (!old.receipt.finalReceipt && r.sequence > old.receipt.sequence &&
            BigInt(r.used) >= BigInt(old.receipt.used) &&
            r.endedAt >= old.receipt.endedAt),
        "receipt regressed or already final",
      );
      const next = {
        ...this.state,
        receipts: {
          ...this.state.receipts,
          [r.purchaseId]: { ...envelope, nodeBinding: p.nodeBinding },
        },
      };
      await this.save(next);
      this.state = next;
      return { stored: true };
    });
  }
}
