import {
  abi,
  binding,
  Contract,
  formatEther,
  grantSigner,
  json,
  parseEther,
  receiptSigner,
  require,
  runNode,
  Wallet,
} from "./schema.mjs";
import { confirmedTransactions, Quorum } from "./quorum.mjs";
import { admissionChain } from "./admission.mjs";
import { sender, settle } from "./submit.mjs";
import { withEnrollment } from "../relay-broker/attestation.mjs";

export async function inspect(cfg, node) {
  const chain = new Quorum(cfg), s = await chain.snapshot();
  const p = node.payments, n = await s.call("getNode", [p.node]);
  require(
    p.escrow.toLowerCase() === cfg.escrow.toLowerCase() &&
      runNode(p.enrollmentKeyId, p.runNonce) === p.node,
    "node payment domain",
  );
  require(
    n.attestationHash ===
      binding(p, node.relay_peer, node.manifest_sha256, node.os_image_hash),
    "on-chain node attestation binding",
  );
  for (const k of ["operator", "receiptSigner", "runExpires"]) {
    require(
      String(n[k]).toLowerCase() === String(p[k]).toLowerCase(),
      "node " + k + " mismatch",
    );
  }
  require(
    n.runExpires > Math.floor(Date.now() / 1000) && Number(n.unit) === 1,
    "compute node expired or wrong unit",
  );
  const admission = withEnrollment(
    await admissionChain(s, cfg),
    cfg.enrollments,
  );
  // Return finalized chain reads to the Python Apple assertion verifier.
  const kid = Uint8Array.from(
    p.enrollmentKeyId.slice(2).match(/../g),
    (b) => parseInt(b, 16),
  );
  const cd = Uint8Array.from(node.cdhash.match(/../g), (b) => parseInt(b, 16));
  const image = Uint8Array.from(
    node.os_image_hash.match(/../g),
    (b) => parseInt(b, 16),
  );
  const build = await admission.buildId();
  require(
    "0x" +
        Array.from(build, (b) => b.toString(16).padStart(2, "0")).join("") ===
      p.buildId,
    "node buildId mismatch",
  );
  const registeredKey = await admission.key(kid);
  registeredKey.x = Array.from(registeredKey.x);
  registeredKey.y = Array.from(registeredKey.y);
  const bytes = (b) =>
    Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
  return {
    node: n.toObject(),
    price: (await s.call("quote", [p.node])).toString(),
    binding: binding(
      p,
      node.relay_peer,
      node.manifest_sha256,
      node.os_image_hash,
    ),
    finalizedBlock: s.block.hash,
    approval: {
      key: registeredKey,
      category: await admission.category(),
      rpIdHash: bytes(await admission.rpIdHash(cd)),
      burnedImage: await admission.burnedImage(image),
      burnedBuild: await admission.burnedBuild(build),
    },
  };
}
async function privateJSON(path, value) {
  await Deno.writeTextFile(path, json(value), { mode: 0o600, createNew: true });
}
async function main() {
  const [command, configPath, statePath, ...args] = Deno.args;
  const cfg = JSON.parse(await Deno.readTextFile(configPath));
  if (command === "inspect") {
    const node = JSON.parse(await Deno.readTextFile(statePath));
    console.log(json(await inspect(cfg, node)));
    return;
  }
  if (command === "check-grant") {
    const envelope = JSON.parse(await Deno.readTextFile(statePath));
    require(
      grantSigner(cfg.escrow, envelope).toLowerCase() ===
        cfg.grantSigner.toLowerCase(),
      "grant signer",
    );
    console.log(json(envelope.grant));
    return;
  }
  require(args.includes("--send"), "transaction commands require --send");
  if (command === "buy") {
    const [fundingPath, nodePath, buyerKey, amount] = args;
    const node = JSON.parse(await Deno.readTextFile(nodePath)),
      checked = await inspect(cfg, node);
    require(
      /^[1-9][0-9]*$/.test(amount) && BigInt(amount) <= 600n,
      "seconds 1..600",
    );
    const payer = Wallet.createRandom();
    // Preserve this buyer before sending anything so refund/withdraw remains recoverable.
    await privateJSON(statePath, {
      payerKey: payer.privateKey,
      payer: payer.address,
      node: node.payments.node,
      buyerKey,
      amount,
      unit: 1,
    });
    const { provider, wallet: funding } = await sender(cfg, fundingPath);
    const paid = BigInt(checked.price) * BigInt(amount);
    const gas = cfg.buyerGasWei
      ? BigInt(cfg.buyerGasWei)
      : parseEther("0.0001");
    const fundingTx = await funding.sendTransaction({
      to: payer.address,
      value: paid + gas,
    });
    await fundingTx.wait();
    const buyer = payer.connect(provider),
      c = new Contract(cfg.escrow, abi, buyer);
    const tx = await c.buy(node.payments.node, 1, amount, buyerKey, {
      value: paid,
    });
    const mined = await tx.wait();
    const event = mined.logs.map((l) => {
      try {
        return abi.parseLog(l);
      } catch {
        return null;
      }
    }).find((e) => e?.name === "Purchase");
    require(event, "buy has no Purchase event");
    const state = {
      payerKey: payer.privateKey,
      payer: payer.address,
      node: node.payments.node,
      buyerKey,
      amount,
      unit: 1,
      purchaseId: event.args.purchaseId.toString(),
      txHash: tx.hash,
      paidWei: paid.toString(),
      operator: checked.node.operator,
      floorPrice: checked.node.floorPrice.toString(),
    };
    await Deno.writeTextFile(statePath, json(state), { mode: 0o600 });
    console.log(
      json({
        purchaseId: state.purchaseId,
        txHash: state.txHash,
        paidWei: state.paidWei,
      }),
    );
    return;
  }
  const state = JSON.parse(await Deno.readTextFile(statePath));
  const { provider, contract, wallet } = await sender(cfg, args[0]);
  if (command === "finish") {
    const envelope = JSON.parse(await Deno.readTextFile(args[1]));
    require(
      envelope.receipt.purchaseId === state.purchaseId,
      "receipt purchase mismatch",
    );
    const s = await new Quorum(cfg).snapshot(),
      p = await s.call("getPurchase", [state.purchaseId]);
    require(
      receiptSigner(cfg.escrow, envelope).toLowerCase() ===
        p.receiptSigner.toLowerCase(),
      "receipt signer mismatch",
    );
    const settlement = await settle(cfg, contract, [envelope]);
    const buyer = new Wallet(state.payerKey, provider),
      bc = new Contract(cfg.escrow, abi, buyer);
    const used = BigInt(envelope.receipt.used),
      settled = used * p.floorPrice,
      premium = used * (p.price - p.floorPrice),
      refund = (p.amount - used) * p.price;
    let withdrawal = null;
    if (refund > 0n) withdrawal = (await (await bc.withdraw()).wait()).hash;
    let operatorWithdrawal = null;
    if (
      state.operator.toLowerCase() === wallet.address.toLowerCase() &&
      settled > 0n
    ) operatorWithdrawal = (await (await contract.withdraw()).wait()).hash;
    await privateJSON(statePath + ".transactions.json", {
      settlement,
      refundWithdrawal: withdrawal,
      operatorWithdrawal,
    });
    const confirmation = await confirmedTransactions(
      cfg,
      [settlement, withdrawal, operatorWithdrawal].filter(Boolean),
    );
    const summary = {
      finalizedBlock: confirmation.block.hash,
      operatorWithdrawal,
      purchaseId: state.purchaseId,
      used: used.toString(),
      paidETH: formatEther(state.paidWei),
      settledToOperatorETH: formatEther(settled),
      lockedPremiumETH: formatEther(premium),
      refundedETH: formatEther(refund),
      operator: state.operator,
      settlement,
      refundWithdrawal: withdrawal,
    };
    await privateJSON(statePath + ".summary.json", summary);
    console.log(json(summary));
  } else if (command === "refund") {
    const tx = await contract.refund(state.purchaseId);
    await tx.wait();
    console.log(json({ refund: tx.hash }));
  } else throw new Error("unknown command");
}

if (import.meta.main) await main();
