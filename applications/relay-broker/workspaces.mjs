import { verifyMessage } from "../payments/schema.mjs";
import { canonical } from "./grants.mjs";
import { canonicalFleet } from "./fleet.mjs";
import { InferenceError } from "./inference.mjs";
import { unhex } from "../../dstack-compat/secret-release/policy.mjs";

export const workspaceChunkBytes = 512 * 1024;
export const maxEncryptedSnapshotBytes = 272 * 1024 * 1024;
const zero = "0".repeat(64), hash = v => typeof v === "string" && /^[0-9a-f]{64}$/.test(v);
const need = (ok, code, message, status = 400) => { if (!ok) throw new InferenceError(code, message, status); };
const fields = { head: [], history: ["afterVersion"], begin: ["version", "previousHash", "hash", "size", "mac"],
  chunk: ["uploadId", "offset", "data"], commit: ["uploadId"], read: ["version", "hash", "offset", "length", "mac"] };
const same = (a, b) => a && b && ["workspaceId", "version", "previousHash", "hash", "size"].every(k => a[k] === b[k]);
const random = () => crypto.randomUUID().replaceAll("-", "");

/** Ciphertext lives on the Mac/IPFS; this database contains only owner-scoped pointers.
 * begin({workspaceId,version,previousHash,hash,size,mac?}) -> {uploadId,offset,committed?,head?}
 * chunk({workspaceId,uploadId,offset,data}) -> {offset}; commit({workspaceId,uploadId}) -> {head}
 * read({workspaceId,version,hash,offset,length?,mac?}) -> {head,data,offset,nextOffset,source,ipfsFetched}
 * head({workspaceId}) -> {head,pending?}; history({workspaceId,afterVersion?}) -> {heads} */
export class Workspaces {
  /** @param {any} options */
  constructor({ broker, cfg = {}, state = {}, save, store, now = () => Math.floor(Date.now() / 1000) }) {
    Object.assign(this, { broker, cfg, state, save, now });
    this.pending = Promise.resolve();
    this.store = store ?? this.remote.bind(this);
  }
  serial(fn) { const result = this.pending.then(fn); this.pending = result.catch(() => {}); return result; }
  async persist(key, value) {
    const next = { ...this.state, [key]: value }; await this.save(next); this.state = next;
  }
  async remote(mac, action, body) {
    const url = this.cfg.stores?.[mac];
    need(url, "WORKSPACE_STORE_UNAVAILABLE", "snapshot Mac is not configured", 503);
    const unsigned = { action, issuedAt: this.now(), nonce: random(), ...body };
    const sig = await this.broker.payments.key.signMessage("dsmack-workspace-store/1\n" + canonicalFleet(unsigned));
    const response = await fetch(url.replace(/\/$/, "") + "/" + action, { method: "POST", redirect: "error",
      headers: { "content-type": "application/json" }, body: JSON.stringify({ ...unsigned, sig }), signal: AbortSignal.timeout(120000) });
    const chunks = []; let length = 0;
    for await (const chunk of response.body) {
      length += chunk.byteLength;
      need(length <= 1024 * 1024, "WORKSPACE_STORE_RESPONSE", "snapshot store response exceeds limit", 502);
      chunks.push(chunk);
    }
    const raw = new Uint8Array(length); let offset = 0;
    for (const chunk of chunks) { raw.set(chunk, offset); offset += chunk.byteLength; }
    let value; try { value = JSON.parse(new TextDecoder().decode(raw)); } catch { throw new InferenceError("WORKSPACE_STORE_RESPONSE", "snapshot store returned invalid JSON", 502); }
    need(response.ok, value.error?.code ?? "WORKSPACE_STORE_UNAVAILABLE", value.error?.message ?? "snapshot store refused request", response.status);
    return value;
  }
  async authorize(op, r) {
    need(fields[op] && r.action === "workspace-" + op && typeof r.workspaceId === "string" &&
      /^[A-Za-z0-9_-]{1,128}$/.test(r.workspaceId), "WORKSPACE_REQUEST", "workspace ID and action required");
    const guest = r.sessionId !== undefined;
    const allowed = ["action", "workspaceId", "issuedAt", "sig", ...fields[op],
      ...(guest ? ["sessionId", "node_peer"] : ["wallet", "nonce"])];
    need(Object.keys(r).every(k => allowed.includes(k)), "WORKSPACE_REQUEST", "unexpected workspace request field");
    need(Number.isSafeInteger(r.issuedAt) && Math.abs(this.now() - r.issuedAt) <= 120,
      "WORKSPACE_REQUEST_EXPIRED", "workspace request must be signed within 120 seconds", 403);
    const { sig, ...unsigned } = r;
    if (guest) {
      const session = this.broker.payments.state.agentSessions?.[r.sessionId];
      need(session && session.node.relay_peer === r.node_peer && session.conversationId === r.workspaceId && !session.final,
        "WORKSPACE_GUEST", "guest stay does not own this conversation", 403);
      need(/^[0-9a-f]{128}$/.test(sig), "WORKSPACE_SIGNATURE", "guest signature required", 403);
      const key = await crypto.subtle.importKey("raw", unhex(session.node.receipt_key), "Ed25519", false, ["verify"]);
      need(await crypto.subtle.verify("Ed25519", key, unhex(sig), new TextEncoder().encode(canonical(unsigned))),
        "WORKSPACE_SIGNATURE", "attested guest signature does not verify", 403);
      return { wallet: session.wallet, mac: session.placement?.publisher };
    }
    need(/^0x[0-9a-fA-F]{40}$/.test(r.wallet) && /^[0-9a-f]{32}$/.test(r.nonce), "WORKSPACE_SIGNATURE", "signed wallet request required", 403);
    let signer; try { signer = verifyMessage(canonical(unsigned), sig).toLowerCase(); } catch { /* refused below */ }
    need(signer === r.wallet.toLowerCase(), "WORKSPACE_SIGNATURE", "workspace wallet signature does not verify", 403);
    const stay = Object.values(this.broker.payments.state.agentSessions ?? {}).find(s => s.wallet === signer &&
      s.conversationId === r.workspaceId && !s.final);
    return { wallet: signer, mac: stay?.placement?.publisher };
  }
  async snapshotOwner(ref) {
    for (const record of Object.values(this.state)) {
      const head = record.history?.at(-1)?.head;
      if (head?.workspaceId === ref.workspaceId && head.version === ref.version && head.hash === ref.hash) return head.mac;
    }
  }
  async finalize(key, record, pending, head) {
    need(same(head, pending.head) && typeof head.cid === "string" && /^b[a-z2-7]{20,120}$/.test(head.cid),
      "WORKSPACE_STORE_RESPONSE", "store snapshot differs from pending upload", 502);
    const prior = record.history.at(-1)?.head;
    if (prior?.version === head.version && prior.hash === head.hash) return prior;
    need(head.version === (prior?.version ?? 0) + 1 && head.previousHash === (prior?.hash ?? zero),
      "WORKSPACE_CONFLICT", "workspace head changed before snapshot commit", 409);
    const next = { ...record, pending: null, history: [...record.history, { head: { ...head, mac: pending.head.mac },
      uploadId: pending.uploadId, usedAt: this.now() }] };
    await this.persist(key, next); return next.history.at(-1).head;
  }
  async call(op, r) {
    const auth = await this.authorize(op, r), key = auth.wallet + ":" + r.workspaceId;
    return this.serial(async () => {
      let record = this.state[key] ?? { history: [], pending: null };
      const current = record.history.at(-1)?.head ?? null;
      if (op === "head") return { head: current, ...(record.pending ? { pending: record.pending } : {}) };
      if (op === "history") {
        need(r.afterVersion === undefined || Number.isSafeInteger(r.afterVersion) && r.afterVersion >= 0,
          "WORKSPACE_REQUEST", "history counter must be nonnegative");
        return { heads: record.history.filter(v => v.head.version > (r.afterVersion ?? 0)).map(v => v.head) };
      }
      if (op === "begin") {
        need(Number.isSafeInteger(r.version) && r.version > 0 && hash(r.previousHash) && hash(r.hash) &&
          Number.isSafeInteger(r.size) && r.size >= 29 && r.size <= maxEncryptedSnapshotBytes,
          "WORKSPACE_REQUEST", "snapshot version, parent, ciphertext hash and bounded size required");
        const mac = auth.mac ?? r.mac ?? current?.mac;
        need(typeof mac === "string" && this.cfg.stores?.[mac], "WORKSPACE_STORE_UNAVAILABLE", "snapshot Mac is not configured", 503);
        const head = { workspaceId: r.workspaceId, version: r.version, previousHash: r.previousHash, hash: r.hash, size: r.size, cid: null, mac };
        if (same(current, head)) return { committed: true, head: current, uploadId: null, offset: current.size };
        need(r.version === (current?.version ?? 0) + 1 && r.previousHash === (current?.hash ?? zero),
          "WORKSPACE_CONFLICT", "snapshot must extend the current workspace version and hash", 409);
        if (record.pending) {
          const old = record.pending, status = await this.store(old.head.mac, "begin", { wallet: auth.wallet, uploadId: old.uploadId, head: old.head });
          if (status.committed) {
            const committed = await this.finalize(key, record, old, status.head);
            need(same(committed, head), "WORKSPACE_CONFLICT", "a prior snapshot committed; refresh the workspace head", 409);
            return { committed: true, head: committed, uploadId: null, offset: committed.size };
          }
          if (same(old.head, head)) {
            need(Number.isSafeInteger(status.offset) && status.offset >= 0 && status.offset <= head.size, "WORKSPACE_STORE_RESPONSE", "invalid stored upload offset", 502);
            const pending = { ...old, offset: status.offset }; await this.persist(key, { ...record, pending });
            return { uploadId: old.uploadId, offset: pending.offset };
          }
        }
        const uploadId = random(), result = await this.store(mac, "begin", { wallet: auth.wallet, uploadId, head });
        need(Number.isSafeInteger(result.offset) && result.offset >= 0 && result.offset <= head.size,
          "WORKSPACE_STORE_RESPONSE", "invalid stored upload offset", 502);
        const pending = { uploadId, head, offset: result.offset };
        await this.persist(key, { ...record, pending });
        if (result.committed) return { committed: true, head: await this.finalize(key, record, pending, result.head), uploadId: null, offset: head.size };
        return { uploadId, offset: pending.offset };
      }
      if (op === "read") {
        need(Number.isSafeInteger(r.version) && hash(r.hash) && Number.isSafeInteger(r.offset) && r.offset >= 0 &&
          (r.length === undefined || Number.isSafeInteger(r.length) && r.length > 0 && r.length <= workspaceChunkBytes),
          "WORKSPACE_REQUEST", "snapshot version, hash and bounded range required");
        const saved = record.history.find(v => v.head.version === r.version && v.head.hash === r.hash);
        need(saved, "WORKSPACE_NOT_FOUND", "saved snapshot version/hash not found", 404);
        need(r.offset <= saved.head.size, "WORKSPACE_REQUEST", "ciphertext range starts beyond snapshot size");
        const mac = auth.mac ?? r.mac ?? saved.head.mac;
        const result = await this.store(mac, "read", { wallet: auth.wallet, head: saved.head, offset: r.offset, length: r.length ?? workspaceChunkBytes });
        need(same(result.head, saved.head) && result.head.cid === saved.head.cid, "WORKSPACE_STORE_RESPONSE", "store returned a different snapshot", 502);
        need(typeof result.data === "string" && result.data.length <= 4 * Math.ceil(workspaceChunkBytes / 3) &&
          result.data.length % 4 === 0 && /^[A-Za-z0-9+/]*={0,2}$/.test(result.data), "WORKSPACE_STORE_RESPONSE", "invalid ciphertext read chunk", 502);
        const count = atob(result.data).length;
        need(result.offset === r.offset && result.nextOffset === r.offset + count && result.nextOffset <= saved.head.size &&
          count <= (r.length ?? workspaceChunkBytes) && (count > 0 || r.offset === saved.head.size),
          "WORKSPACE_STORE_RESPONSE", "ciphertext read did not advance within the requested range", 502);
        await this.persist(key, { ...record, history: record.history.map(v => v === saved ? { ...v, usedAt: this.now() } : v) });
        return { ...result, head: saved.head };
      }
      need(typeof r.uploadId === "string" && /^[0-9a-f]{32}$/.test(r.uploadId), "WORKSPACE_REQUEST", "pending upload ID required");
      if (op === "commit") {
        const existing = record.history.find(v => v.uploadId === r.uploadId);
        if (existing) return { head: existing.head };
      }
      const pending = record.pending;
      need(pending?.uploadId === r.uploadId, "WORKSPACE_CONFLICT", "upload is no longer the pending workspace snapshot", 409);
      if (op === "chunk") {
        need(Number.isSafeInteger(r.offset) && r.offset >= 0 && typeof r.data === "string" &&
          r.data.length <= 4 * Math.ceil(workspaceChunkBytes / 3) && r.data.length % 4 === 0 && /^[A-Za-z0-9+/]*={0,2}$/.test(r.data),
          "WORKSPACE_REQUEST", "bounded standard base64 ciphertext chunk required");
        const bytes = Uint8Array.from(atob(r.data), c => c.charCodeAt(0));
        need(bytes.length > 0 && bytes.length <= workspaceChunkBytes && r.offset + bytes.length <= pending.head.size,
          "WORKSPACE_REQUEST", "chunk exceeds encrypted snapshot size");
        const result = await this.store(pending.head.mac, "chunk", { wallet: auth.wallet, uploadId: r.uploadId, offset: r.offset, data: r.data });
        need(Number.isSafeInteger(result.offset) && result.offset >= r.offset + bytes.length && result.offset <= pending.head.size,
          "WORKSPACE_STORE_RESPONSE", "invalid stored chunk offset", 502);
        await this.persist(key, { ...record, pending: { ...pending, offset: result.offset } }); return { offset: result.offset };
      }
      const result = await this.store(pending.head.mac, "commit", { wallet: auth.wallet, uploadId: r.uploadId });
      return { head: await this.finalize(key, record, pending, result.head) };
    });
  }
}
