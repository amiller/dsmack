import { seal, hex, unhex } from "../../dstack-compat/secret-release/policy.mjs";
import { store } from "./wallet-store.mjs";

const utf8 = new TextEncoder();
const require = (value, message) => { if (!value) throw Error(message); };
const GENESIS = "0".repeat(64);
const CHUNK = 512 * 1024;
const MAX_BYTES = 224 * 1024 * 1024;
const fields = ["workspaceId", "version", "previousHash", "hash", "size"];
const same = (a, b) => fields.every(field => a?.[field] === b?.[field]);
const decode = value => Uint8Array.from(atob(value.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));
export function checkWorkspaceHead(head, workspaceId) {
  require(head?.workspaceId === workspaceId && Number.isSafeInteger(head.version) && head.version > 0 &&
    /^[0-9a-f]{64}$/.test(head.previousHash) && /^[0-9a-f]{64}$/.test(head.hash) &&
    Number.isSafeInteger(head.size) && head.size >= 29 && head.size <= MAX_BYTES, "Invalid saved workspace head.");
  return head;
}
// Session message conflicts must never discard a newer workspace checkpoint.
export function newestWorkspace(left, right) {
  if (!left) return right;
  if (!right) return left;
  checkWorkspaceHead(left, left.workspaceId); checkWorkspaceHead(right, left.workspaceId);
  require(left.version !== right.version || same(left, right), "Conflicting workspace version refused.");
  return left.version >= right.version ? left : right;
}
export async function workspaceKey(dataKey, workspaceId) {
  const key = await crypto.subtle.importKey("raw", decode(dataKey), "HKDF", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256",
    salt: utf8.encode(workspaceId), info: utf8.encode("dsmack/workspace/v1") }, key, 256));
}
export async function authenticateSnapshot(bytes, head, key) {
  checkWorkspaceHead(head, head.workspaceId);
  require(bytes.length === head.size && hex(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes))) === head.hash,
    "Saved workspace ciphertext hash mismatch.");
  const imported = await crypto.subtle.importKey("raw", key, "AES-GCM", false, ["decrypt"]);
  // Authenticate the untrusted pointer before trusting its version or releasing
  // a key to a guest. Extraction and git fsck happen inside the verified guest.
  await crypto.subtle.decrypt({ name: "AES-GCM", iv: bytes.subarray(0, 12),
    additionalData: utf8.encode(JSON.stringify([head.workspaceId, head.version, head.previousHash])) }, imported, bytes.subarray(12));
}

export class SavedWorkspace {
  constructor({ workspaceId, request, credit, dataKey, head, persist, changed = () => {}, floorStore = store }) {
    Object.assign(this, { workspaceId, credit, dataKey, head, persist, changed, floorStore });
    this.request = (operation, fields = {}) => request(operation, { workspaceId, ...fields });
    this.queue = Promise.resolve();
  }
  serial(fn) {
    const result = this.queue.then(fn); this.queue = result.catch(() => {}); return result;
  }
  async init() {
    require(this.credit.address && this.dataKey(), "Unlock your synced data key before opening a workspace.");
    this.floorKey = "workspace-head:" + this.credit.address.toLowerCase() + ":" + this.workspaceId;
    this.head = newestWorkspace(this.head, await this.floorStore(this.floorKey));
    this.key ??= await workspaceKey(this.dataKey(), this.workspaceId);
  }
  async accept(head) {
    checkWorkspaceHead(head, this.workspaceId);
    this.head = newestWorkspace(this.head, head);
    await this.floorStore(this.floorKey, this.head);
    await this.persist(this.head);
    this.changed({ state: "saved", head: this.head });
  }
  async download(head) {
    checkWorkspaceHead(head, this.workspaceId);
    const bytes = new Uint8Array(head.size);
    let source, ipfsFetched = false;
    for (let offset = 0; offset < bytes.length;) {
      const result = await this.request("read", { version: head.version, hash: head.hash, offset, length: CHUNK });
      require(same(result.head, head) && result.offset === offset, "Saved workspace changed during download.");
      const chunk = decode(result.data);
      require(chunk.length > 0 && chunk.length <= CHUNK && offset + chunk.length <= bytes.length && result.nextOffset === offset + chunk.length,
        "Invalid saved workspace chunk.");
      bytes.set(chunk, offset); offset += chunk.length;
      source = result.source; ipfsFetched ||= !!result.ipfsFetched;
    }
    await authenticateSnapshot(bytes, head, this.key);
    this.lastDownload = { source, ipfsFetched, size: head.size };
    return bytes;
  }
  async latest() {
    await this.init();
    const { head } = await this.request("head");
    if (!head) { require(!this.head, "Saved workspace head disappeared; rollback refused."); return null; }
    checkWorkspaceHead(head, this.workspaceId);
    if (this.head) {
      require(head.version >= this.head.version, "Older saved workspace version refused.");
      if (head.version === this.head.version) { require(same(head, this.head), "Saved workspace hash changed; rollback refused."); return this.head; }
    }
    // A save completed after the tab closed. Its authenticated parent chain
    // must extend the newest checkpoint held in the encrypted synced session.
    const { heads } = await this.request("history", { afterVersion: this.head?.version ?? 0 });
    let previous = this.head?.hash ?? GENESIS, version = this.head?.version ?? 0;
    for (const item of heads) {
      checkWorkspaceHead(item, this.workspaceId);
      if (item.version > head.version) break;
      require(item.version === version + 1 && item.previousHash === previous, "Saved workspace history has a gap or fork.");
      previous = item.hash; version = item.version;
    }
    require(version === head.version && previous === head.hash, "Saved workspace history does not reach its head.");
    this.downloaded = { head, bytes: await this.download(head) };
    await this.accept(head);
    return head;
  }
  async control(client, operation, fields = {}) {
    const result = await client.callTool({ name: "dsmack_workspace", arguments: { operation, ...fields } }, { timeout: 150000 });
    require(!result.isError, "Workspace " + operation + " failed: " + JSON.stringify(result.content));
    return result.structuredContent ?? JSON.parse(result.content.find(item => item.type === "text").text);
  }
  async bind(client, registration, lease) {
    const head = this.head ?? null;
    const sealed = await seal(unhex(registration.secret_key), utf8.encode(JSON.stringify({ workspaceId: this.workspaceId, key: hex(this.key), head })), lease.sessionId + "/workspace");
    this.changed({ state: head ? "restoring" : "opening", head });
    await this.control(client, "bind", { sealed });
    if (head) {
      const local = this.downloaded && same(this.downloaded.head, head) &&
        lease.placement?.publisher === head.mac;
      const bytes = local ? this.downloaded.bytes : await this.download(head);
      for (let offset = 0; offset < bytes.length; offset += CHUNK) {
        let text = ""; const chunk = bytes.subarray(offset, offset + CHUNK);
        for (let at = 0; at < chunk.length; at += 8192) text += String.fromCharCode(...chunk.subarray(at, at + 8192));
        await this.control(client, "write", { offset, data: btoa(text) });
      }
      await this.control(client, "restore", { head });
    }
    this.downloaded = null;
    this.bound = true;
    this.changed({ state: head ? "restored" : "ready", head, download: this.lastDownload });
    return !!head;
  }
  save(client, lease) { return this.serial(async () => {
    require(this.bound, "Open a workspace before saving.");
    this.changed({ state: "saving", head: this.head });
    const candidate = await this.control(client, "seal");
    checkWorkspaceHead(candidate, this.workspaceId);
    require(same(candidate, this.head) || (candidate.version === (this.head?.version ?? 0) + 1 && candidate.previousHash === (this.head?.hash ?? GENESIS)),
      "Guest sealed a conflicting workspace version.");
    const begun = await this.request("begin", { version: candidate.version, previousHash: candidate.previousHash,
      hash: candidate.hash, size: candidate.size, ...(lease.placement?.publisher ? { mac: lease.placement.publisher } : {}) });
    let committed = begun.committed ? begun.head : null;
    if (!committed) {
      for (let offset = begun.offset; offset < candidate.size;) {
        const part = await this.control(client, "read", { offset, length: CHUNK });
        const count = decode(part.data).length;
        require(part.offset === offset && count > 0 && count <= CHUNK && offset + count <= candidate.size, "Invalid guest snapshot chunk.");
        const uploaded = await this.request("chunk", { uploadId: begun.uploadId, offset, data: part.data });
        require(uploaded.offset === offset + count, "Workspace upload offset mismatch.");
        offset = uploaded.offset;
      }
      committed = (await this.request("commit", { uploadId: begun.uploadId })).head;
    }
    require(same(committed, candidate), "Stored workspace differs from the guest's seal.");
    await this.accept(committed);
    await this.control(client, "commit", { head: committed });
    return committed;
  }); }
}
