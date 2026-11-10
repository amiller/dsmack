// Register immutable class measurements and the broker before any VM starts.
import { json, require } from "./schema.mjs";
import { sender } from "./submit.mjs";
import { confirmedTransactions, ChainReader } from "./chain-reader.mjs";
const [config, key, manifestPath] = Deno.args;
require(manifestPath, "usage: register-class.mjs CONFIG FUNDING_KEY MANIFEST");
const cfg = JSON.parse(await Deno.readTextFile(config));
const raw = await Deno.readFile(manifestPath),
  manifest = JSON.parse(new TextDecoder().decode(raw));
const measured = JSON.parse(
  JSON.parse(manifest.docker_compose_file).services.node.environment
    .PAYMENTS_CONFIG,
);
require(
  measured.escrow.toLowerCase() === cfg.escrow.toLowerCase() &&
    cfg.classes.includes(measured.node),
  "class configuration",
);
// A class names code and an operator, never a Mac's App Attest key: the broker admits each run only if the key that
// signed it is enrolled on AppleAttestRegistry and has a MacLink to this operator, so rotating a key keeps the class.
require(!("enrollmentKeyId" in measured), "manifest pins an App Attest key; repack without enrollmentKeyId");
const operator = measured.operator;
const s = await new ChainReader(cfg).snapshot(),
  { wallet, contract } = await sender(cfg, key);
require(
  (await s.call("owner")).toLowerCase() === wallet.address.toLowerCase(),
  "class owner",
);
const hashes = [];
const broker = await s.call("brokerSigner");
if (broker === "0x0000000000000000000000000000000000000000") {
  const tx = await contract.registerBroker(cfg.grantSigner);
  console.log(json({ kind: "registerBroker", hash: tx.hash }));
  hashes.push(tx.hash);
  await tx.wait();
} else {require(
    broker.toLowerCase() === cfg.grantSigner.toLowerCase(),
    "immutable broker differs",
  );}
const composeHash = "0x" +
  Array.from(
    new Uint8Array(await crypto.subtle.digest("SHA-256", raw)),
    (b) => b.toString(16).padStart(2, "0"),
  ).join("");
const imageHash = manifest.base_vm.os_image_hash;
require(/^(0x)?[0-9a-f]{64}$/.test(imageHash), "base image hash");
const tx = await contract.registerNode(
  measured.node,
  operator,
  1,
  composeHash,
  "0x" + imageHash.replace(/^0x/, ""),
);
console.log(json({ kind: "registerNode", hash: tx.hash }));
hashes.push(tx.hash);
await tx.wait();
await confirmedTransactions(cfg, hashes);
