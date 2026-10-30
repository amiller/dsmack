import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, writeFile, access, rm, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { createCipheriv, createHash, randomBytes } from "node:crypto";
import { WorkspaceSnapshots, WORKSPACE_CHUNK_BYTES } from "./workspace.mjs";
const exec = promisify(execFile);
const workspaceId = "snapshot-boundary-test", key = "ab".repeat(32), genesis = "0".repeat(64);

async function workspace(t) {
  const root = await mkdtemp(resolve(tmpdir(), "dsmack-workspace-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(resolve(root, ".tmp"));
  await exec("git", ["init", "-q"], { cwd: root });
  await exec("git", ["-c", "user.name=Test", "-c", "user.email=test@invalid", "commit", "--allow-empty", "-qm", "Initial workspace"], { cwd: root });
  return root;
}
async function readSnapshot(controller) {
  const chunks = [];
  for (let offset = 0;;) {
    const result = await controller.call({ operation: "read", offset, length: WORKSPACE_CHUNK_BYTES });
    const bytes = Buffer.from(result.data, "base64"); chunks.push(bytes); offset += bytes.length;
    if (result.eof) return Buffer.concat(chunks);
  }
}
async function upload(controller, bytes) {
  for (let offset = 0; offset < bytes.length; offset += WORKSPACE_CHUNK_BYTES)
    await controller.call({ operation: "write", offset, data: bytes.subarray(offset, offset + WORKSPACE_CHUNK_BYTES).toString("base64") });
}

test("encrypted saves restore git, tracked build sources and untracked secrets without dependencies or build output", async t => {
  const root = await workspace(t), next = await workspace(t);
  await mkdir(resolve(root, "src/build"), { recursive: true });
  await writeFile(resolve(root, "src/build/helper.py"), "print('source')\n");
  await exec("git", ["add", "src/build/helper.py"], { cwd: root });
  await exec("git", ["-c", "user.name=Test", "-c", "user.email=test@invalid", "commit", "-qm", "Track build source"], { cwd: root });
  await writeFile(resolve(root, "src/build/generated.bin"), "generated");
  await writeFile(resolve(root, ".env"), "PRIVATE_TEST_VALUE=survives\n");
  await writeFile(resolve(root, "random.bin"), randomBytes(800000));
  for (const name of ["node_modules", ".cache", "dist", "artifacts", "state"]) {
    await mkdir(resolve(root, name), { recursive: true });
    await writeFile(resolve(root, name, "discard"), name);
  }
  const first = new WorkspaceSnapshots(root);
  await first.call({ operation: "bind", workspaceId, key, head: null });
  const head = await first.call({ operation: "seal" });
  assert.equal(head.version, 1); assert.equal(head.previousHash, genesis);
  assert.deepEqual(await first.call({ operation: "seal" }), head, "Retry must retain the pending seal");
  const bytes = await readSnapshot(first);
  assert.equal(bytes.length, head.size);
  assert.equal(createHash("sha256").update(bytes).digest("hex"), head.hash);
  assert(!bytes.includes(Buffer.from("PRIVATE_TEST_VALUE")), "Snapshot must be ciphertext");
  await assert.rejects(first.call({ operation: "commit", head: { ...head, hash: genesis } }), /differs/);
  const committed = { ...head, cid: "test-cid", mac: "test-mac" };
  await first.call({ operation: "commit", head: committed });
  const second = new WorkspaceSnapshots(next);
  await second.call({ operation: "bind", workspaceId, key, head: committed });
  await assert.rejects(second.call({ operation: "seal" }), /Restore/);
  await upload(second, bytes);
  await assert.rejects(second.call({ operation: "restore", head: { ...head, version: head.version - 1 } }), /rollback/);
  await second.call({ operation: "restore" });
  assert.equal(await readFile(resolve(next, ".env"), "utf8"), "PRIVATE_TEST_VALUE=survives\n");
  assert.equal(await readFile(resolve(next, "src/build/helper.py"), "utf8"), "print('source')\n");
  assert.deepEqual(await readFile(resolve(next, "random.bin")), await readFile(resolve(root, "random.bin")));
  for (const name of ["node_modules", ".cache", "dist", "artifacts/discard", "state/discard", "src/build/generated.bin"])
    await assert.rejects(access(resolve(next, name)), { code: "ENOENT" });
  await exec("git", ["fsck", "--full"], { cwd: next });
  const later = await second.call({ operation: "seal" });
  assert.equal(later.version, 2); assert.equal(later.previousHash, head.hash);
});

test("restore authenticates workspace metadata and ciphertext before installing files", async t => {
  const root = await workspace(t), next = await workspace(t);
  await writeFile(resolve(root, "restored.txt"), "authenticated");
  await writeFile(resolve(next, "untouched.txt"), "original");
  const first = new WorkspaceSnapshots(root);
  await first.call({ operation: "bind", workspaceId, key, head: null });
  const head = await first.call({ operation: "seal" }), bytes = await readSnapshot(first);
  const changed = new WorkspaceSnapshots(next), wrong = { ...head, version: head.version + 1 };
  await changed.call({ operation: "bind", workspaceId, key, head: wrong });
  await upload(changed, bytes);
  await assert.rejects(changed.call({ operation: "restore" }));
  assert.equal(await readFile(resolve(next, "untouched.txt"), "utf8"), "original");
  await assert.rejects(access(resolve(next, "restored.txt")), { code: "ENOENT" });
  const corrupted = new WorkspaceSnapshots(next);
  await corrupted.call({ operation: "bind", workspaceId, key, head });
  const altered = Buffer.from(bytes); altered[20] ^= 1;
  await upload(corrupted, altered);
  await assert.rejects(corrupted.call({ operation: "restore" }), /hash mismatch/);
});

test("restore rejects archive links that would overwrite paths through another member", async t => {
  const root = await workspace(t), outside = await workspace(t);
  await writeFile(resolve(outside, "sentinel"), "untouched");
  const script = "import io,sys,tarfile; t=tarfile.open(fileobj=sys.stdout.buffer,mode='w|gz'); a=tarfile.TarInfo('link'); a.type=tarfile.SYMTYPE; a.linkname=sys.argv[1]; t.addfile(a); b=tarfile.TarInfo('link/sentinel'); b.size=9; t.addfile(b,io.BytesIO(b'overwrite')); t.close()";
  const { stdout: archive } = await exec("python3", ["-c", script, outside], { encoding: "buffer" });
  const nonce = randomBytes(12), cipher = createCipheriv("aes-256-gcm", Buffer.from(key, "hex"), nonce);
  cipher.setAAD(Buffer.from(JSON.stringify([workspaceId, 1, genesis])));
  const bytes = Buffer.concat([nonce, cipher.update(archive), cipher.final(), cipher.getAuthTag()]);
  const head = { workspaceId, version: 1, previousHash: genesis, hash: createHash("sha256").update(bytes).digest("hex"), size: bytes.length };
  const controller = new WorkspaceSnapshots(root);
  await controller.call({ operation: "bind", workspaceId, key, head }); await upload(controller, bytes);
  await assert.rejects(controller.call({ operation: "restore" }), /symlink/);
  assert.equal(await readFile(resolve(outside, "sentinel"), "utf8"), "untouched");
});
