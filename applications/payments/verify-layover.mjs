// Live check of the Layover escrow: deposit, accept terms, accrue one guest-attested lease statement,
// claim it, and show an over-cap claim reverting. Sends transactions only with --send.
// deno run -A applications/payments/verify-layover.mjs CONFIG BUYER_KEY BROKER_URL STATEMENT_JSON CAP --send
import { Contract, Claim, claimDomain, json, require, verifyTypedData } from "./schema.mjs";
import { sender } from "./submit.mjs";

const [config, keyPath, brokerUrl, statementPath, cap, flag] = Deno.args;
require(flag === "--send" && /^[1-9][0-9]*$/.test(cap ?? ""),
  "usage: verify-layover.mjs CONFIG BUYER_KEY BROKER_URL STATEMENT_JSON CAP --send");
const cfg = JSON.parse(await Deno.readTextFile(config));
const body = JSON.parse(await Deno.readTextFile(statementPath)), st = body.statement;
const { contract, wallet } = await sender(cfg, keyPath, false);
const broker = brokerUrl.replace(/\/$/, ""), buyer = wallet.address;
const get = async (path, init) => {
  const r = await fetch(broker + path, { redirect: "error", signal: AbortSignal.timeout(60000), ...init });
  const text = await r.text();
  require(r.ok, `${path}: HTTP ${r.status} ${text.slice(0, 300)}`);
  return JSON.parse(text);
};
const step = (name, value) => console.log(json({ step: name, ...value }));

require(st.buyer_wallet.toLowerCase() === buyer.toLowerCase(), "BUYER_KEY is not the statement's buyer_wallet");
require(st.escrow.toLowerCase() === cfg.escrow.toLowerCase(), "statement names another escrow");
require(BigInt(st.owed) <= BigInt(cap), "CAP must cover the statement's owed");
const signer = (await get("/payments/key")).address;
require(signer.toLowerCase() === (await contract.brokerSigner()).toLowerCase(), "broker key is not the escrow's brokerSigner");

if (await contract.balance(buyer) + await contract.claimed(buyer, st.terms_hash) < BigInt(cap)) {
  const token = new Contract(await contract.token(), ["function approve(address,uint256) returns(bool)"], wallet);
  await (await token.approve(cfg.escrow, cap)).wait();
  step("deposit", { transaction: (await (await contract.deposit(cap)).wait()).hash, amount: cap });
}
const accepted = await contract.terms(buyer, st.terms_hash);
if (BigInt(accepted.operator) === 0n) {
  step("acceptTerms", { transaction: (await (await contract.acceptTerms(st.terms_hash, st.operator, cap)).wait()).hash, cap });
} else require(accepted.operator.toLowerCase() === st.operator.toLowerCase() && accepted.cap === BigInt(cap),
  "these terms were already accepted with another operator or cap");

step("lease-statement", await get("/payments/lease-statement",
  { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) }));
const envelope = await get(`/payments/claim?user=${buyer}&terms=${st.terms_hash}`);
require(verifyTypedData(claimDomain(cfg.escrow, buyer), { Claim }, envelope.claim, envelope.signature) === signer, "claim signer");
const before = await contract.claimed(buyer, st.terms_hash);
if (BigInt(envelope.claim.cumulativeOwed) > before) {
  step("claim", { transaction: (await (await contract.claim(buyer, envelope.claim, envelope.signature)).wait()).hash,
    cumulativeOwed: envelope.claim.cumulativeOwed });
}
const over = { ...envelope.claim, cumulativeOwed: String(BigInt(cap) + 1n) };
const reverted = await contract.claim.staticCall(buyer, over, "0x" + "00".repeat(65)).then(() => null, e => e.reason);
require(reverted === "terms cap", "over-cap claim did not revert with terms cap: " + reverted);
step("over-cap", { reverted, command: `cast call ${cfg.escrow} 'claim(address,(address,bytes32,uint256,uint64),bytes)' ${buyer} '(${over.operator},${over.termsHash},${over.cumulativeOwed},${over.period})' 0x${"00".repeat(65)} --rpc-url ${cfg.rpcs[0]}` });
