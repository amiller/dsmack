// Interactive verifier process: challenge out, one bounded evidence bundle in.
// Peer/key arguments must come from the caller's authenticated connection.
import fs from "node:fs";
import { createDstackIssuerVerifier } from "./dstack_issuer.mjs";
let verifier, timer;
try {
  const args = process.argv.slice(2), values = {};
  for (let i = 0; i < args.length; i += 2) {
    const name = args[i], value = args[i + 1];
    if (!["--policy", "--expected-policy-sha256", "--peer", "--issuer-public-key"].includes(name)
        || !value || Object.hasOwn(values, name)) throw new Error();
    values[name] = value;
  }
  if (Object.keys(values).length !== 4) throw new Error();
  const fd = fs.openSync(values["--policy"], fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
  let bytes;
  try {
    if (!fs.fstatSync(fd).isFile()) throw new Error();
    const buffer = Buffer.alloc(131073), count = fs.readSync(fd, buffer, 0, buffer.length, null);
    if (count > 131072) throw new Error();
    bytes = buffer.subarray(0, count);
  } finally { fs.closeSync(fd); }
  const policy = JSON.parse(bytes.toString("utf8"));
  verifier = createDstackIssuerVerifier({ policy, expectedPolicySha256: values["--expected-policy-sha256"] });
  const challenge = verifier.challenge({ remotePeer: values["--peer"], issuerPublicKeyHex: values["--issuer-public-key"] });
  process.stdout.write(`${JSON.stringify({ binding: challenge })}\n`);
  timer = setTimeout(() => { verifier.close(); process.stdin.destroy(new Error()); }, policy.challenge_ttl_ms); timer.unref();
  const chunks = []; let count = 0;
  for await (const chunk of process.stdin) {
    count += chunk.length;
    if (count > 2 * 1024 * 1024) throw new Error();
    chunks.push(chunk);
  }
  const result = await verifier.verify(JSON.parse(Buffer.concat(chunks).toString("utf8")), { remotePeer: values["--peer"] });
  process.stdout.write(`${JSON.stringify(result)}\n`);
} catch {
  process.stderr.write("Issuer identity verification refused; no private-issuance authorization was established.\n");
  process.exitCode = 1;
} finally { clearTimeout(timer); verifier?.close(); }
