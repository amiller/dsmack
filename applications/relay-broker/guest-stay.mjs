import { Interface, keccak256, toUtf8Bytes, verifyTypedData, zeroPadValue } from "npm:ethers@6.17.0";
import { InferenceError } from "./inference.mjs";
import { canonical } from "./grants.mjs";

export const GUEST_ESCROW = "0xca184cfc10f55b67f8afb42029d768ec6e6f36ad";
export const LAYC = "0x9e851bf5e3b613aaa09853a07d1132f49c90b515";
const need = (ok, message) => { if (!ok) throw new InferenceError("GUEST_ESCROW", message, 403); };
const abi = new Interface([
 "function terms(address,bytes32) view returns (address operator,uint256 cap,uint64 closedAt,bool released)",
 "function balance(address) view returns (uint256)",
 "function exposure(address) view returns (uint256)",
 "function totalClaimed(address,bytes32) view returns (uint256)",
 "function guestKeys(address) view returns (address operator,bytes32 workload,bytes32 kid,bytes32 cdhash)",
 "function approved(bytes32) view returns (bool)",
]);
const claimTypes = { Claim: [{ name: "operator", type: "address" }, { name: "termsHash", type: "bytes32" }, { name: "cumulativeOwed", type: "uint256" }] };
export const guestDomain = buyer => ({ name: "LayoverGuestEscrow", version: "1", chainId: 84532,
 verifyingContract: GUEST_ESCROW, salt: zeroPadValue(buyer, 32) });

export function couchTerms(accepted, wallet, node, placement, conversationId) {
 need(accepted && typeof accepted.terms === "string" && accepted.terms.length <= 8192 &&
   /^0x[0-9a-f]{64}$/.test(accepted.termsHash), "canonical accepted terms required");
 need(keccak256(toUtf8Bytes(accepted.terms)) === accepted.termsHash, "accepted terms hash mismatch");
 const t = JSON.parse(accepted.terms);
 need(t.kind === "layover-terms/1" && t.mode === "couch" && t.chain_id === 84532 &&
   t.escrow === GUEST_ESCROW && t.token === LAYC && t.unit === "LAYC" && t.decimals === 6 &&
   t.thread === conversationId && t.publisher === placement.publisher.toLowerCase() && t.slot_id === placement.slot_id &&
   t.operator === node.payments.operator.toLowerCase() && Number.isSafeInteger(t.minutes) && t.minutes >= 1 && t.minutes <= 60 &&
   Number.isSafeInteger(t.rate_layc_per_second) && t.rate_layc_per_second > 0 && t.minimum_seconds === 60 &&
   t.cap === String(BigInt(t.rate_layc_per_second) * BigInt(t.minutes * 60)), "accepted terms do not match this couch");
 return { buyer: wallet, terms: accepted.terms, termsHash: accepted.termsHash };
}

// All reads share the broker's verified block. Pin GuestEscrow code separately
// because the existing reader pins UsageEscrow for legacy inference traffic.
export async function fundedGuestStay(b, escrow, node) {
 const s = await b.payments.chain.snapshot();
 const code = await s.read("eth_getCode", [GUEST_ESCROW, s.tag]);
 need(b.cfg.agent?.guestEscrowCodeHash && keccak256(code) === b.cfg.agent.guestEscrowCodeHash,
   "GuestEscrow deployed code mismatch");
 const read = async (fn, args) => abi.decodeFunctionResult(fn,
   await s.read("eth_call", [{ to: GUEST_ESCROW, data: abi.encodeFunctionData(fn, args) }, s.tag]));
 const t = JSON.parse(escrow.terms);
 const [accepted, balance, exposure, claimed, key] = await Promise.all([
   read("terms", [escrow.buyer, escrow.termsHash]), read("balance", [escrow.buyer]), read("exposure", [escrow.buyer]),
   read("totalClaimed", [escrow.buyer, escrow.termsHash]), read("guestKeys", [node.payments.receiptSigner]),
 ]);
 need(accepted.operator.toLowerCase() === t.operator && accepted.cap === BigInt(t.cap) && accepted.closedAt === 0n &&
   !accepted.released && balance[0] >= exposure[0] && exposure[0] >= BigInt(t.cap) && claimed[0] === 0n,
   "couch terms are not open and fully funded");
 if (key.operator === "0x0000000000000000000000000000000000000000")
   throw new InferenceError("GUEST_KEY_PENDING", "guest key registration is not in the broker's verified block yet", 409, 2);
 need(key.operator.toLowerCase() === t.operator && (await read("approved", [key.workload]))[0],
   "attested guest key is not registered under an approved workload");
 return s.block;
}

export async function verifyGuestCheckpoint(r, session) {
 const { controlSignature, ...body } = r;
 need(typeof controlSignature === "string" && /^[0-9a-f]{128}$/.test(controlSignature), "guest control signature required");
 const pub = Uint8Array.from(session.node.receipt_key.match(/../g), h => parseInt(h, 16));
 const key = await crypto.subtle.importKey("raw", pub, "Ed25519", false, ["verify"]);
 const signature = Uint8Array.from(controlSignature.match(/../g), h => parseInt(h, 16));
 need(await crypto.subtle.verify("Ed25519", key, signature, new TextEncoder().encode(canonical(body))), "guest control signature mismatch");
 const c = r.claim, t = JSON.parse(session.escrow.terms);
 need(c && c.escrow.toLowerCase() === GUEST_ESCROW && c.buyer.toLowerCase() === session.wallet &&
   c.operator.toLowerCase() === t.operator && c.terms_hash === session.escrow.termsHash &&
   c.key.toLowerCase() === session.node.payments.receiptSigner.toLowerCase() && /^(0|[1-9][0-9]*)$/.test(c.cumulative_owed),
   "claim does not bind this stay");
 need(Number.isSafeInteger(r.guestSeconds) && r.guestSeconds >= session.guestSeconds &&
   r.guestSeconds <= session.grant.seconds && typeof r.final === "boolean" &&
   Number.isSafeInteger(r.sequence) && r.sequence > (session.checkpoint?.sequence ?? 0), "guest checkpoint regressed or exceeds grant");
 const billed = r.guestSeconds > 0 ? Math.max(60, r.guestSeconds) : 0;
 need(BigInt(c.cumulative_owed) === BigInt(billed) * BigInt(t.rate_layc_per_second) && BigInt(c.cumulative_owed) <= BigInt(t.cap),
   "guest claim exceeds accepted charge");
 const signer = verifyTypedData(guestDomain(session.wallet), claimTypes,
   { operator: t.operator, termsHash: c.terms_hash, cumulativeOwed: c.cumulative_owed }, c.signature);
 need(signer.toLowerCase() === session.node.payments.receiptSigner.toLowerCase(), "claim is not signed by the attested guest");
}
