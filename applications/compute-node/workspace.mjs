import { createCipheriv, createDecipheriv, createHash, createSecretKey, randomBytes } from "node:crypto";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { fileURLToPath } from "node:url";

export const WORKSPACE_CHUNK_BYTES = 512 * 1024;
export const MAX_SNAPSHOT_BYTES = 224 * 1024 * 1024;
const GENESIS = "0".repeat(64);
const helper = fileURLToPath(new URL("./workspace-tar.py", import.meta.url));
const need = (value, message) => { if (!value) throw Error(message); };
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const fields = ["workspaceId", "version", "previousHash", "hash", "size"];
const sameHead = (left, right) => fields.every(field => left?.[field] === right?.[field]);
const aad = (head) => Buffer.from(JSON.stringify([head.workspaceId, head.version, head.previousHash]));
function checkHead(head, workspaceId) {
  need(head?.workspaceId === workspaceId && Number.isSafeInteger(head.version) && head.version > 0 &&
    /^[0-9a-f]{64}$/.test(head.previousHash) && /^[0-9a-f]{64}$/.test(head.hash) &&
    Number.isSafeInteger(head.size) && head.size >= 29 && head.size <= MAX_SNAPSHOT_BYTES,
  "Invalid saved workspace head");
}
function tar(mode, root) {
  const child = spawn("python3", [helper, mode, root], { stdio: ["pipe", "pipe", "pipe"] });
  let errorText = "";
  child.stderr.on("data", bytes => { if (errorText.length < 16384) errorText += bytes.toString(); });
  const done = new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("close", code => code === 0 ? resolve() : reject(Error(errorText.trim() || "Workspace archive failed")));
  });
  done.catch(() => {});
  child.stdin.on("error", () => {});
  const timer = setTimeout(() => child.kill("SIGKILL"), 120000);
  done.finally(() => clearTimeout(timer)).catch(() => {});
  return { child, done };
}

// One controller and queue belong to the guest, rather than to an MCP stream.
// The trusted peer can finish a save through a new local stream after a tab exits.
export class WorkspaceSnapshots {
  constructor(root) { this.root = root; this.queue = Promise.resolve(); this.incoming = []; this.received = 0; }
  serial(operation) {
    const result = this.queue.then(operation);
    this.queue = result.catch(() => {});
    return result;
  }
  async call(args) {
    if (args.operation === "bind") {
      need(typeof args.workspaceId === "string" && args.workspaceId.length > 0 && args.workspaceId.length <= 128 &&
        typeof args.key === "string" && /^[0-9a-f]{64}$/.test(args.key), "Workspace binding required");
      if (args.head) checkHead(args.head, args.workspaceId);
      const key = Buffer.from(args.key, "hex"), keyHash = digest(key);
      if (this.key) {
        key.fill(0);
        need(this.workspaceId === args.workspaceId && this.keyHash === keyHash &&
          ((!this.head && !args.head) || sameHead(this.head, args.head)), "Guest is already bound to a different workspace head");
      } else {
        this.workspaceId = args.workspaceId; this.key = createSecretKey(key); key.fill(0); this.keyHash = keyHash;
        this.head = args.head ? { ...args.head } : null; this.restored = !this.head;
      }
      return { workspaceId: this.workspaceId, head: this.head, restored: this.restored };
    }
    need(this.key, "Bind a workspace before saving or restoring");
    if (args.operation === "seal") {
      need(this.restored, "Restore the saved workspace before sealing");
      if (this.sealed) return this.sealed.head;
      const head = { workspaceId: this.workspaceId, version: (this.head?.version ?? 0) + 1,
        previousHash: this.head?.hash ?? GENESIS };
      const nonce = randomBytes(12), cipher = createCipheriv("aes-256-gcm", this.key, nonce);
      cipher.setAAD(aad(head));
      const chunks = [nonce]; let size = nonce.length;
      const { child, done } = tar("pack", this.root);
      child.stdin.end();
      try {
        for await (const bytes of child.stdout) {
          const encrypted = cipher.update(bytes); chunks.push(encrypted); size += encrypted.length;
          need(size + 16 <= MAX_SNAPSHOT_BYTES, "Encrypted workspace exceeds the snapshot size limit");
        }
        await done;
        chunks.push(cipher.final(), cipher.getAuthTag());
      } catch (error) { child.kill("SIGKILL"); await done.catch(() => {}); throw error; }
      const bytes = Buffer.concat(chunks);
      Object.assign(head, { hash: digest(bytes), size: bytes.length });
      this.sealed = { head, bytes };
      return { ...head };
    }
    if (args.operation === "read") {
      need(this.sealed, "Seal a workspace before reading ciphertext");
      const length = args.length ?? WORKSPACE_CHUNK_BYTES;
      need(Number.isSafeInteger(args.offset) && args.offset >= 0 && args.offset <= this.sealed.bytes.length &&
        Number.isSafeInteger(length) && length > 0 && length <= WORKSPACE_CHUNK_BYTES, "Invalid snapshot chunk range");
      const end = Math.min(args.offset + length, this.sealed.bytes.length);
      return { offset: args.offset, data: this.sealed.bytes.subarray(args.offset, end).toString("base64"), eof: end === this.sealed.bytes.length };
    }
    if (args.operation === "commit") {
      need(this.sealed && sameHead(args.head, this.sealed.head), "Committed workspace differs from the pending seal");
      this.head = { ...args.head }; this.sealed = null;
      return { head: this.head, committed: true };
    }
    if (args.operation === "write") {
      need(this.head && !this.restored, "This guest has no saved workspace awaiting restore");
      need(args.offset === this.received && typeof args.data === "string" &&
        args.data.length <= Math.ceil(WORKSPACE_CHUNK_BYTES / 3) * 4 &&
        /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(args.data), "Invalid snapshot upload chunk");
      const bytes = Buffer.from(args.data, "base64");
      need(bytes.length > 0 && bytes.length <= WORKSPACE_CHUNK_BYTES && this.received + bytes.length <= this.head.size,
        "Snapshot upload exceeds the saved workspace size");
      this.incoming.push(bytes); this.received += bytes.length;
      return { offset: args.offset, size: this.received };
    }
    if (args.operation === "restore") {
      need(this.head && !this.restored && (!args.head || sameHead(args.head, this.head)), "Workspace rollback or head mismatch refused");
      need(this.received === this.head.size, "Saved workspace ciphertext is incomplete");
      const bytes = Buffer.concat(this.incoming);
      need(digest(bytes) === this.head.hash, "Saved workspace ciphertext hash mismatch");
      const decryptor = () => {
        const cipher = createDecipheriv("aes-256-gcm", this.key, bytes.subarray(0, 12));
        cipher.setAAD(aad(this.head)); cipher.setAuthTag(bytes.subarray(-16)); return cipher;
      };
      // Authenticate before any tar member is parsed or extracted. A second pass
      // streams plaintext to the helper without staging another archive on tmpfs.
      let cipher = decryptor();
      for (let at = 12; at < bytes.length - 16; at += 65536) cipher.update(bytes.subarray(at, Math.min(at + 65536, bytes.length - 16)));
      cipher.final();
      cipher = decryptor();
      const { child, done } = tar("restore", this.root);
      child.stdout.resume();
      try {
        for (let at = 12; at < bytes.length - 16; at += 65536) {
          const plain = cipher.update(bytes.subarray(at, Math.min(at + 65536, bytes.length - 16)));
          if (!child.stdin.write(plain)) await Promise.race([once(child.stdin, "drain"), done.then(() => { throw Error("Workspace restore ended before its input"); })]);
        }
        child.stdin.end(cipher.final()); await done;
      } catch (error) { child.kill("SIGKILL"); await done.catch(() => {}); throw error; }
      this.incoming = []; this.received = 0; this.restored = true;
      return { workspaceId: this.workspaceId, version: this.head.version, hash: this.head.hash, restored: true };
    }
    throw Error("Unknown workspace operation");
  }
}
