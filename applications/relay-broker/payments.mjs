import {
  domain,
  claimDomain,
  Claim,
  NodeBinding,
  require,
  runNode,
} from "../payments/schema.mjs";
import { Quorum } from "../payments/quorum.mjs";
import { admissionChain } from "../payments/admission.mjs";
import { verifyRelay, withEnrollment } from "./attestation.mjs";
import { hex } from "../../dstack-compat/secret-release/policy.mjs";

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
    return await this.bindRun(r, checked, s.block.hash);
  }
  async bindRun(r, checked, block) {
    const p = r.payments;
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
          expires: p.runExpires,
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
      return { ...checked, block, nodeBinding: envelope };
    });
  }
  async classes() {
    const s = await this.chain.snapshot();
    return await Promise.all(this.cfg.classes.map(async node => ({ node,
      ...(await s.call("getNode", [node])).toObject(),
      priceNanoUsdPerSecond: this.cfg.prices?.S1?.nanoUsdPerSecond ?? "15000",
      minimumSeconds: 60,
      finalizedBlock: s.block.hash,
    })));
  }
  async list(relays) {
    return relays.filter(r => r.payments && r.attestation.nodeBinding?.binding.expires > this.now());
  }
  // Called after wallet authentication. A lifetime deposit counter prevents replayed top-ups.
  async syncBalance(wallet) {
    if (!this.cfg.escrow) return;
    const snapshot = await this.chain.snapshot();
    const deposited = BigInt(await snapshot.call("deposits", [wallet])) * 1000n;
    const exiting = Number(await snapshot.call("exitRequestedAt", [wallet]));
    await this.serial(async () => {
      const state = this.state, old = state.inferenceCredit?.[wallet];
      const previous = BigInt(old?.depositedNanoUsd ?? "0");
      require(deposited >= previous, "deposit counter regressed");
      if (!old && deposited === 0n) return;
      const account = old ?? { grantedNanoUsd: "0", spentNanoUsd: "0", usedTokens: "0", pending: null, nonces: {} };
      require(!account.exitRequestedAt || exiting === account.exitRequestedAt, "exit counter regressed");
      const next = { ...state, inferenceCredit: { ...state.inferenceCredit, [wallet]: { ...account,
        depositedNanoUsd: String(deposited), exitRequestedAt: exiting,
        grantedNanoUsd: String(BigInt(account.grantedNanoUsd) + deposited - previous),
      } } };
      await this.save(next); this.state = next;
    });
  }
  async weeklyClaim(wallet, operator, period = Math.floor(this.now() / 604800) - 1) {
    require(/^0x[0-9a-fA-F]{40}$/.test(wallet) && /^0x[0-9a-fA-F]{40}$/.test(operator), "claim addresses");
    require(Number.isSafeInteger(period) && period >= 0 && period < Math.floor(this.now() / 604800), "completed week required");
    wallet = wallet.toLowerCase(); operator = operator.toLowerCase();
    return this.serial(async () => {
      const cumulative = Object.entries(this.state.operatorAccruals?.[wallet]?.[operator] ?? {})
        .filter(([week]) => Number(week) <= period).reduce((n, [, amount]) => n + BigInt(amount), 0n);
      const claim = { operator, cumulativeOwed: String(cumulative / 1000n), period };
      require(BigInt(claim.cumulativeOwed) > 0n, "no funded usage");
      const signature = await this.key.signTypedData(claimDomain(this.cfg.escrow, wallet), { Claim }, claim);
      return { user: wallet, claim, signature };
    });
  }
}

// Pure ledger update used in the same durable transaction as the debit. Gifted credit
// remains sponsor credit; only deposited USDC can fund this user's operator claims.
export function accrue(state, wallet, operator, charge, now) {
  const account = state.inferenceCredit[wallet];
  const funded = BigInt(account.depositedNanoUsd ?? "0") - BigInt(account.prepaidSpentNanoUsd ?? "0");
  const amount = charge < funded ? charge : funded;
  if (amount === 0n) return {};
  require(/^0x[0-9a-fA-F]{40}$/.test(operator ?? ""), "funded debit requires an operator");
  operator = operator.toLowerCase();
  const week = Math.floor(now / 604800), totals = state.operatorAccruals?.[wallet]?.[operator] ?? {};
  return {
    prepaidSpentNanoUsd: String(BigInt(account.prepaidSpentNanoUsd ?? "0") + amount),
    operatorAccruals: { ...state.operatorAccruals, [wallet]: { ...state.operatorAccruals?.[wallet],
      [operator]: { ...totals, [week]: String(BigInt(totals[week] ?? "0") + amount) } } },
  };
}
