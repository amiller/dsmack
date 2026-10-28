import {
  binding,
  domain,
  Grant,
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
        runNode(p.enrollmentKeyId, p.runNonce) === p.node,
      "payment node/enrollment/run binding",
    );
    const n = await s.call("getNode", [p.node]);
    require(
      n.runExpires > this.now() &&
        Number(n.unit) === (r.kind === "compute" ? 1 : 0),
      "registered run expired or wrong unit",
    );
    for (const k of ["operator", "receiptSigner", "runExpires"]) {
      require(
        String(n[k]).toLowerCase() === String(p[k]).toLowerCase(),
        "registered payment " + k,
      );
    }
    require(
      n.attestationHash ===
        binding(p, r.relay_peer, r.manifest_sha256, r.os_image_hash),
      "payment attestation hash mismatch",
    );
    // buildId is compared with CDRegistry at the same finalized block by verifyRelay.
    require(
      checked.build_id === p.buildId.slice(2).toLowerCase(),
      "registered payment build mismatch",
    );
    this.challenges.delete(p.challenge);
    return { ...checked, block: s.block.hash };
  }
  async list(relays) {
    const s = await this.chain.snapshot(), out = [];
    for (const r of relays.filter((r) => r.payments)) {
      const n = await s.call("getNode", [r.payments.node]);
      if (n.runExpires <= this.now()) continue;
      out.push({
        ...r,
        price: (await s.call("quote", [r.payments.node])).toString(),
        floorPrice: n.floorPrice.toString(),
        target: n.target.toString(),
        unit: Number(n.unit),
        finalizedBlock: s.block.hash,
      });
    }
    return out;
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
      const node = relays.find((n) => n.payments?.node === p.node);
      require(node, "payment node is not live");
      await this.checkNode(node, s);
      const n = await s.call("getNode", [p.node]);
      require(
        n.attestationHash ===
          binding(
            node.payments,
            node.relay_peer,
            node.manifest_sha256,
            node.os_image_hash,
          ),
        "node binding changed",
      );
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
        Number(n.runExpires),
      );
      require(issuedAt < serviceUntil, "purchase expired before activation");
      const grant = {
        purchaseId: r.purchaseId,
        node: p.node,
        buyerKey: p.buyerKey,
        unit: Number(p.unit),
        amount: p.amount.toString(),
        issuedAt,
        serviceUntil,
        destinationPolicyHash: this.cfg.destinationPolicyHash,
      };
      const envelope = {
        grant,
        signature: await this.key.signTypedData(domain(this.cfg.escrow), {
          Grant,
        }, grant),
      };
      const purchase = Object.fromEntries(
        ["receiptSigner", "amount", "boughtAt", "expires"].map(
          (k) => [k, String(p[k])],
        ),
      );
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
      const p = cached ??
        await (await this.chain.snapshot()).call("getPurchase", [r.purchaseId]);
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
        receipts: { ...this.state.receipts, [r.purchaseId]: envelope },
      };
      await this.save(next);
      this.state = next;
      return { stored: true };
    });
  }
}
