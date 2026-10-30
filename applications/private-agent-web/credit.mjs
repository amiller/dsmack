import { store } from "./wallet-store.mjs";
export { store } from "./wallet-store.mjs";
import {
  Contract,
  formatEther,
  JsonRpcProvider,
  keccak256,
  verifyTypedData,
  Wallet,
} from "ethers";
import { abi, domain, NodeBinding, Receipt } from "../payments/schema.mjs";
import { canonical, hex, peerBytes } from "@sandbox";
export { formatEther };
export const require = (ok, message) => {
  if (!ok) throw new Error(message);
};
export async function signed(client, body) {
  return {
    ...body,
    sig: hex(
      new Uint8Array(
        await crypto.subtle.sign(
          "Ed25519",
          client.privateKey,
          new TextEncoder().encode(
            JSON.stringify(
              Object.fromEntries(
                Object.keys(body).sort().map((k) => [k, body[k]]),
              ),
            ),
          ),
        ),
      ),
    ),
  };
}
export async function walletBody(credit, action, fields = {}) {
  require(
    credit.signer && credit.address,
    "Create or connect a wallet to receive starter chat credit.",
  );
  const body = {
    action,
    wallet: credit.address,
    nonce: hex(crypto.getRandomValues(new Uint8Array(16))),
    issuedAt: Math.floor(Date.now() / 1000),
    ...fields,
  };
  const message = JSON.stringify(
    Object.fromEntries(Object.keys(body).sort().map((key) => [key, body[key]])),
  );
  return { ...body, sig: await credit.signer.signMessage(message) };
}
export function formatNanoUsd(value) {
  const amount = BigInt(value);
  require(amount >= 0n, "Chat credit cannot be negative.");
  return "$" + (amount / 1000000000n) + "." +
    ((amount % 1000000000n) / 1000n).toString().padStart(6, "0");
}
export class Credit {
  constructor(cfg, client, changed) {
    this.cfg = cfg;
    this.client = client;
    this.changed = changed;
    this.rpc = new JsonRpcProvider(cfg.rpc, 84532, { staticNetwork: true });
    this.purchases = [];
    this.chatCredit = undefined;
  }
  async init() {
    this.purchases = (await store("purchases")) || [];
    const key = await store("burner");
    if (key) {
      this.signer = new Wallet(key, this.rpc);
      this.address = this.signer.address;
    }
    return this;
  }
  async save() {
    await store("purchases", this.purchases);
    this.changed();
  }
  async burner() {
    require(
      !this.address,
      "A wallet is already active. Use a separate browser profile for another wallet.",
    );
    const wallet = Wallet.createRandom().connect(this.rpc);
    await store("burner", wallet.privateKey);
    this.signer = wallet;
    this.address = wallet.address;
    this.changed();
  }
  async contract() {
    require(this.signer, "Create or connect a wallet first.");
    require(
      BigInt(await this.rpc.send("eth_chainId", [])) === 84532n,
      "RPC is not Base Sepolia.",
    );
    require(
      keccak256(await this.rpc.getCode(this.cfg.escrow)) === this.cfg.codeHash,
      "Escrow code hash does not match the deployment pin.",
    );
    return new Contract(this.cfg.escrow, abi, this.signer);
  }
  async checkBroker(api) {
    const [key, payments] = await Promise.all([
      api("/key"),
      api("/payments/key"),
    ]);
    require(
      key.public_key === this.cfg.brokerKey,
      "Wrong broker key. No data was sent.",
    );
    require(
      payments.chainId === 84532 &&
        payments.escrow?.toLowerCase() === this.cfg.escrow.toLowerCase() &&
        payments.codeHash === this.cfg.codeHash &&
        payments.address?.toLowerCase() === this.cfg.grantSigner.toLowerCase(),
      "Broker payment identity or escrow does not match the deployment pins.",
    );
  }
  selected(unit) {
    return this.purchases.find((p) =>
      p.unit === unit && p.status === "confirmed" && !p.closed &&
      p.payer?.toLowerCase() === this.address?.toLowerCase()
    );
  }
  forSpend(unit, minimum = 1n) {
    return this.purchases.find((p) =>
      p.unit === unit && p.status === "confirmed" && !p.closed && !p.receipt &&
      !p.uncertain && !p.needsReconcile &&
      p.payer?.toLowerCase() === this.address?.toLowerCase() &&
      BigInt(p.amount) - BigInt(p.used || 0) >= BigInt(minimum)
    ) || this.selected(unit);
  }
  async buy(quote, amount) {
    require(quote, "This credit service is unavailable.");
    require(/^[1-9][0-9]*$/.test(amount), "Enter a positive whole amount.");
    require(
      quote.unit === 1 && BigInt(amount) <= 600n,
      "Amount exceeds the purchase limit.",
    );
    const c = await this.contract(), price = await c.quote(quote.node);
    require(
      price === BigInt(quote.price),
      "Price changed. Refresh the quote before buying.",
    );
    const tx = await c.buy(
      quote.node,
      quote.unit,
      amount,
      "0x" + hex(peerBytes(this.client.peer).slice(6)),
      { value: price * BigInt(amount) },
    );
    const p = {
      unit: quote.unit,
      node: quote.node,
      amount,
      used: "0",
      paidWei: (price * BigInt(amount)).toString(),
      priceWei: price.toString(),
      payer: this.address,
      txHash: tx.hash,
      status: "pending",
    };
    this.purchases.push(p);
    await this.save();
    await this.mined(p);
    return p;
  }
  async mined(p) {
    const r = await this.rpc.getTransactionReceipt(p.txHash);
    if (!r) return;
    require(r.status === 1, "Credit purchase reverted on chain.");
    const e = r.logs.map((l) => {
      try {
        return abi.parseLog(l);
      } catch {
        return null;
      }
    }).find((e) => e?.name === "Purchase");
    require(e, "Credit transaction has no Purchase event.");
    p.purchaseId = e.args.purchaseId.toString();
    p.expires = Number(e.args.expires);
    await this.save();
  }
  async confirm(api, p) {
    if (!p.purchaseId) await this.mined(p);
    require(p.purchaseId, "Purchase is awaiting an on-chain receipt.");
    const r = await api(
      "/payments/confirm",
      await signed(this.client, {
        client_peer: this.client.peer,
        purchaseId: p.purchaseId,
        txHash: p.txHash,
      }),
    );
    require(
      r.purchaseId === p.purchaseId &&
        /^0x[0-9a-f]{64}$/.test(r.finalizedBlock),
      "Broker did not return a finalized purchase confirmation.",
    );
    p.status = "confirmed";
    p.finalizedBlock = r.finalizedBlock;
    await this.save();
  }
  checkReceipt(envelope, p) {
    require(
      String(envelope.receipt.purchaseId) === p.purchaseId,
      "Refund receipt is for a different purchase.",
    );
    require(
      verifyTypedData(
        domain(this.cfg.escrow),
        { NodeBinding },
        envelope.nodeBinding.binding,
        envelope.nodeBinding.signature,
      ).toLowerCase() === this.cfg.grantSigner.toLowerCase(),
      "Refund broker binding signature is invalid.",
    );
    require(
      verifyTypedData(
        domain(this.cfg.escrow),
        { Receipt },
        envelope.receipt,
        envelope.signature,
      ).toLowerCase() ===
        envelope.nodeBinding.binding.receiptSigner.toLowerCase(),
      "Refund receipt signature is invalid.",
    );
    const b = envelope.nodeBinding.binding;
    require(
      b.node === p.node && BigInt(envelope.receipt.used) <= BigInt(p.amount) &&
        envelope.receipt.finalReceipt,
      "Refund receipt exceeds purchased credit or is not final.",
    );
    return envelope;
  }
  async settle(envelope, p) {
    this.checkReceipt(envelope, p);
    const c = await this.contract();
    const tx = await c.settle(
      [envelope.receipt],
      [envelope.signature],
      b,
      envelope.nodeBinding.signature,
    );
    p.settlementHash = tx.hash;
    await this.save();
    await tx.wait();
    p.closed = true;
    p.used = String(envelope.receipt.used);
    await this.save();
  }
  async withdraw() {
    const c = await this.contract();
    const value = await c.credits(this.address);
    require(
      value > 0n,
      "No withdrawable credit. Close usage and settle, or wait until the escrow refund period ends.",
    );
    const tx = await c.withdraw();
    await tx.wait();
    return tx.hash;
  }
}
