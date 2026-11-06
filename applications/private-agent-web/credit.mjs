import { store } from "./wallet-store.mjs";
export { store } from "./wallet-store.mjs";
import {
  Contract,
  formatEther,
  JsonRpcProvider,
  keccak256,
  parseUnits,
  Wallet,
} from "ethers";
import { abi } from "../payments/schema.mjs";
import { hex } from "@sandbox";
export { formatEther };
export const require = (ok, message) => {
  if (!ok) throw new Error(message);
};
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
    this.rpc = new JsonRpcProvider(cfg.rpc, 84532, { staticNetwork: true, cacheTimeout: -1 });
    this.chatCredit = undefined;
  }
  async init() {
    const key = await store("burner");
    if (key) {
      this.signer = new Wallet(key, this.rpc);
      this.address = this.signer.address;
    }
    return this;
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
  async deposit(amount) {
    require(typeof amount === "string" && /^(0|[1-9][0-9]*)(\.[0-9]{1,6})?$/.test(amount), "Enter a USDC amount with up to six decimal places.");
    const units = parseUnits(amount, 6);
    require(units > 0n, "Deposit must be positive.");
    const c = await this.contract();
    const token = new Contract(await c.token(), ["function approve(address,uint256) returns(bool)"], this.signer);
    await (await token.approve(this.cfg.escrow, units)).wait();
    const tx = await c.deposit(units); await tx.wait();
    return tx.hash;
  }
  async closeAccount() {
    const c = await this.contract(), exit = Number(await c.exitRequestedAt(this.address));
    if (!exit) {
      const tx = await c.requestExit(); await tx.wait();
      return "Account closing. Withdraw remaining USDC after 14 days; new spending is stopped.";
    }
    const ready = (exit + 14 * 86400) * 1000;
    require(Number((await this.rpc.getBlock("latest")).timestamp) * 1000 >= ready, "USDC withdrawal opens " + new Date(ready).toLocaleString() + ".");
    const tx = await c.withdraw(); await tx.wait();
    return "Remaining USDC withdrawn.";
  }
}
