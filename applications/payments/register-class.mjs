// Register immutable class measurements and the broker before any VM starts.
import { json, require } from "./schema.mjs";
import { sender } from "./submit.mjs";
import { confirmedTransactions, Quorum } from "./quorum.mjs";
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
const s = await new Quorum(cfg).snapshot(),
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
  measured.operator,
  1,
  10000000000n,
  30,
  composeHash,
  "0x" + imageHash.replace(/^0x/, ""),
);
console.log(json({ kind: "registerNode", hash: tx.hash }));
hashes.push(tx.hash);
await tx.wait();
await confirmedTransactions(cfg, hashes);
