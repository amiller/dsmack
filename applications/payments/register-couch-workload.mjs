// Approve the released couch measurements on GuestEscrow using its owner key.
import { Contract, JsonRpcProvider, Wallet, keccak256, toUtf8Bytes } from "npm:ethers@6.17.0";
const [keyPath, manifestPath, rpc = "https://sepolia.base.org"] = Deno.args;
if (!keyPath || !manifestPath) throw new Error("usage: register-couch-workload.mjs OWNER_KEY MANIFEST [RPC]");
const raw = await Deno.readFile(manifestPath), manifest = JSON.parse(new TextDecoder().decode(raw));
const provider = new JsonRpcProvider(rpc, 84532, { staticNetwork: true });
const escrow = "0xca184cfc10f55b67f8afb42029d768ec6e6f36ad";
try {
 const wallet = new Wallet((await Deno.readTextFile(keyPath)).trim(), provider);
 const c = new Contract(escrow, ["function owner() view returns(address)",
   "function workloadId(bytes32,bytes32,bytes32) pure returns(bytes32)",
   "function approved(bytes32) view returns(bool)", "function setWorkload(bytes32,bytes32,bytes32,bool)"], wallet);
 if ((await c.owner()).toLowerCase() !== wallet.address.toLowerCase()) throw new Error("GuestEscrow owner key required");
 const code = await provider.getCode(escrow);
 if (code === "0x") throw new Error("GuestEscrow has no deployed code");
 const image = "0x" + manifest.base_vm.os_image_hash.replace(/^0x/, "");
 const compose = JSON.parse(manifest.docker_compose_file);
 if (!compose.services.node) throw new Error("couch manifest has no node service");
 const hash = "0x" + [...new Uint8Array(await crypto.subtle.digest("SHA-256", raw))].map(v => v.toString(16).padStart(2,"0")).join("");
 const caller = "0x" + [...new Uint8Array(await crypto.subtle.digest("SHA-256", toUtf8Bytes("node")))].map(v => v.toString(16).padStart(2,"0")).join("");
 const workload = await c.workloadId(image, hash, caller);
 let txHash = null;
 if (!await c.approved(workload)) {
   const tx = await c.setWorkload(image, hash, caller, true);
   txHash = tx.hash;
   console.log(JSON.stringify({ action: "setWorkload", hash: txHash }));
   if ((await tx.wait()).status !== 1) throw new Error("workload approval failed: " + txHash);
 }
 console.log(JSON.stringify({ escrow, workload, image, manifest: hash, caller, codeHash: keccak256(code), txHash }));
} finally { provider.destroy(); }
