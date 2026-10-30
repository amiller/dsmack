import { createLibp2p } from "libp2p";
import { webSockets } from "@libp2p/websockets";
import { webRTC } from "@libp2p/webrtc";
import { circuitRelayTransport } from "@libp2p/circuit-relay-v2";
import { noise } from "@chainsafe/libp2p-noise";
import { yamux } from "@chainsafe/libp2p-yamux";
import { identify } from "@libp2p/identify";
import { multiaddr } from "@multiformats/multiaddr";
import QRCode from "qrcode";

const protocol = "/dsmack/device-link/1.0.0";
const enc = new TextEncoder(), dec = new TextDecoder("utf-8", { fatal: true });
const stableOrigin = "https://private-agent.dstack.soc1024.com";
const bytes = (v) => Uint8Array.from(atob(v.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
const base64 = (v) => btoa(String.fromCharCode(...new Uint8Array(v))).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
const random = () => base64(crypto.getRandomValues(new Uint8Array(16)));
const check = (ok, message) => { if (!ok) throw Error(message); };
const approve = (confirm, code) => confirm ? confirm(code) : window.confirm(`Compare this code on both devices: ${code}\nAllow this device to access your wallet and chats?`);

async function ephemeral() {
  const key = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
  return { privateKey: key.privateKey, publicKey: base64(await crypto.subtle.exportKey("raw", key.publicKey)) };
}
async function secret(privateKey, publicKey, context) {
  check(typeof publicKey === "string" && bytes(publicKey).length === 65, "Device link public key");
  const key = await crypto.subtle.importKey("raw", bytes(publicKey), { name: "ECDH", namedCurve: "P-256" }, false, []);
  const bits = await crypto.subtle.deriveBits({ name: "ECDH", public: key }, privateKey, 256);
  const hkdf = await crypto.subtle.importKey("raw", bits, "HKDF", false, ["deriveBits"]);
  const material = await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: enc.encode(context), info: enc.encode(protocol) }, hkdf, 256);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", material));
  const code = (new DataView(digest.buffer).getUint32(0) % 1000000).toString().padStart(6, "0");
  return { key: await crypto.subtle.importKey("raw", material, "AES-GCM", false, ["encrypt", "decrypt"]), code: code.slice(0, 3) + " " + code.slice(3) };
}
async function seal(key, value, context) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: enc.encode(context) }, key, enc.encode(JSON.stringify(value)));
  return { iv: base64(iv), cipher: base64(cipher) };
}
async function open(key, value, context) {
  check(value && typeof value.iv === "string" && typeof value.cipher === "string" && bytes(value.iv).length === 12 && value.cipher.length < 12000, "Device link ciphertext");
  return JSON.parse(dec.decode(await crypto.subtle.decrypt({ name: "AES-GCM", iv: bytes(value.iv), additionalData: enc.encode(context) }, key, bytes(value.cipher))));
}
function bundle(value) {
  check(value?.v === 1 && typeof value.dk === "string" && bytes(value.dk).length === 32 && /^0x[0-9a-f]{64}$/i.test(value.walletKey), "Device link key bundle");
  return value;
}
function reader(stream) {
  const iterator = stream[Symbol.asyncIterator](), decoder = new TextDecoder("utf-8", { fatal: true });
  let pending = "";
  return async () => {
    for (;;) {
      const end = pending.indexOf("\n");
      if (end !== -1) {
        const message = pending.slice(0, end); pending = pending.slice(end + 1);
        return JSON.parse(message);
      }
      const part = await iterator.next();
      check(!part.done, "Device link closed before completion");
      pending += decoder.decode(part.value.subarray(), { stream: true });
      check(pending.length <= 16384, "Device link message too large");
    }
  };
}
const send = (stream, value) => stream.send(enc.encode(JSON.stringify(value) + "\n"));
async function node(listen) {
  let encrypter;
  const peer = await createLibp2p({
    addresses: { listen: listen ? ["/p2p-circuit", "/webrtc"] : [] },
    transports: [webSockets(), circuitRelayTransport(), webRTC()],
    connectionEncrypters: [(components) => { encrypter = noise()(components); return encrypter; }], streamMuxers: [yamux()],
    services: { identify: identify() },
  });
  return { peer, encrypter };
}
function transport(connection) {
  const address = connection.remoteAddr.toString();
  check(address.includes("/webrtc/"), "Device linking requires WebRTC");
  return { transport: address, encryption: "/noise", nativeEncryption: connection.encryption };
}
export async function discoverLinkRelay(tunnelsUrl) {
  const response = await fetch(tunnelsUrl, { redirect: "error", signal: AbortSignal.timeout(10000) });
  check(response.ok, "Link relay discovery HTTP " + response.status);
  const entries = await response.json();
  check(Array.isArray(entries) && entries.length <= 32, "Link relay discovery entries");
  const entry = entries.find((value) => value.expiresAt > Date.now() / 1000);
  check(entry, "No active link relay");
  const url = new URL(entry.url);
  check(url.protocol === "wss:" && /^[a-z0-9-]+\.trycloudflare\.com$/.test(url.hostname) && !url.port && !url.username && !url.password && url.pathname === "/" && !url.search && !url.hash && /^12D3KooW[1-9A-HJ-NP-Za-km-z]{44}$/.test(entry.relayPeer), "Link relay discovery address");
  return `/dns4/${url.hostname}/tcp/443/wss/p2p/${entry.relayPeer}`;
}
export async function createDeviceLinkReceiver({ relayAddress, onCode = () => {}, onBundle, onStatus = () => {}, confirm } = {}) {
  check(typeof onBundle === "function", "Device link requires key importer");
  const { peer, encrypter } = await node(true), pair = await ephemeral();
  let resolve, reject, claimed = false, finished = false, timer;
  const completed = new Promise((yes, no) => { resolve = yes; reject = no; });
  // The caller may attach its completion handler after painting the QR.
  completed.catch(() => {});
  const close = async () => { clearTimeout(timer); window.removeEventListener("pagehide", leaving); await peer.stop(); if (!finished) { finished = true; reject(Error("Device link cancelled")); } };
  const leaving = () => { void close(); };
  window.addEventListener("pagehide", leaving, { once: true });
  try {
    onStatus("Connecting to the relay…");
    await peer.dial(multiaddr(relayAddress), { signal: AbortSignal.timeout(15000) });
    const address = await new Promise((yes, no) => {
      const deadline = Date.now() + 20000;
      const poll = () => {
        const found = peer.getMultiaddrs().find((a) => a.toString().includes("/p2p-circuit/webrtc/"));
        if (found) yes(found.toString());
        else if (Date.now() > deadline) no(Error("Relay did not reserve a WebRTC address"));
        else setTimeout(poll, 100);
      }; poll();
    });
    const qr = JSON.stringify({ v: 1, address, publicKey: pair.publicKey, nonce: random(), expires: Date.now() + 5 * 60 * 1000 });
    await peer.handle(protocol, async (stream, connection) => {
      try {
        check(!claimed && !finished, "Device link already used"); claimed = true;
        const evidence = transport(connection);
        const secured = await encrypter.secureInbound(stream, { remotePeer: connection.remotePeer, signal: AbortSignal.timeout(30000) });
        const encrypted = secured.connection, read = reader(encrypted), hello = await read();
        check(hello?.v === 1 && hello.nonce === JSON.parse(qr).nonce, "Device link invitation mismatch");
        const context = qr + "\n" + hello.publicKey;
        const shared = await secret(pair.privateKey, hello.publicKey, context);
        onCode(shared.code); onStatus("Compare the code on both devices.");
        check(await approve(confirm, shared.code), "Device link declined");
        send(encrypted, { ready: true });
        const message = await read(), imported = bundle(await open(shared.key, message.box, context));
        await onBundle(imported);
        send(encrypted, { received: true }); await encrypted.close();
        finished = true; clearTimeout(timer); window.removeEventListener("pagehide", leaving); resolve({ code: shared.code, ...evidence });
        onStatus("Device linked."); await peer.stop();
      } catch (error) {
        stream.abort(error); finished = true; clearTimeout(timer); window.removeEventListener("pagehide", leaving); reject(error); onStatus(error.message); await peer.stop();
      }
    }, { maxInboundStreams: 1 });
    timer = setTimeout(() => { if (!finished) { finished = true; reject(Error("Device link expired")); onStatus("Device link expired. Create a new QR code."); peer.stop(); } }, 5 * 60 * 1000);
    onStatus("Scan this QR code with your existing device.");
    return { qr, qrDataUrl: await QRCode.toDataURL(qr, { errorCorrectionLevel: "M", margin: 2, width: 360 }), completed, close };
  } catch (error) { window.removeEventListener("pagehide", leaving); await peer.stop(); throw error; }
}
export async function sendDeviceLink(qr, keys, { onCode = () => {}, onStatus = () => {}, confirm } = {}) {
  check(typeof qr === "string" && qr.length <= 4096, "Device link QR size");
  const invitation = JSON.parse(qr);
  check(invitation.v === 1 && invitation.expires > Date.now() && invitation.expires <= Date.now() + 5 * 60 * 1000 && typeof invitation.nonce === "string" && /^[A-Za-z0-9_-]{22}$/.test(invitation.nonce), "Device link invitation expired or invalid");
  check(typeof invitation.address === "string" && invitation.address.includes("/p2p-circuit/webrtc/p2p/"), "Device link WebRTC address");
  bundle(keys);
  const { peer, encrypter } = await node(false), pair = await ephemeral();
  try {
    onStatus("Connecting directly to your new device…");
    const connection = await peer.dial(multiaddr(invitation.address), { signal: AbortSignal.timeout(30000) });
    const evidence = transport(connection);
    const stream = await connection.newStream(protocol, { signal: AbortSignal.timeout(30000) });
    const secured = await encrypter.secureOutbound(stream, { remotePeer: connection.remotePeer, signal: AbortSignal.timeout(30000) });
    const encrypted = secured.connection, read = reader(encrypted), context = qr + "\n" + pair.publicKey;
    const shared = await secret(pair.privateKey, invitation.publicKey, context);
    send(encrypted, { v: 1, nonce: invitation.nonce, publicKey: pair.publicKey });
    onCode(shared.code); onStatus("Compare the code on both devices.");
    check(await approve(confirm, shared.code), "Device link declined");
    check((await read()).ready === true, "New device did not approve linking");
    send(encrypted, { box: await seal(shared.key, keys, context) });
    check((await read()).received === true, "New device did not import keys");
    await encrypted.close(); onStatus("Device linked.");
    return { code: shared.code, ...evidence };
  } finally { await peer.stop(); }
}

export async function requestOriginMigration(oldUrl, { confirm, onCode = () => {}, onStatus = () => {}, timeout = 120000 } = {}) {
  const target = new URL(oldUrl);
  check(target.protocol === "https:" && target.origin !== location.origin, "Choose the exact HTTPS origin of your existing device");
  const pair = await ephemeral(), nonce = random();
  target.hash = "dsmack-migrate=" + encodeURIComponent(JSON.stringify({ origin: location.origin, nonce, publicKey: pair.publicKey }));
  const popup = window.open(target.href, "dsmack-origin-migration", "popup,width=720,height=720");
  check(popup, "Allow popups to link your existing browser origin");
  return new Promise((resolve, reject) => {
    let shared, context, publicKey, confirming = false, approved = false;
    const stop = () => { clearTimeout(timer); window.removeEventListener("message", receive); };
    const timer = setTimeout(() => { stop(); reject(Error("Origin migration expired")); }, timeout);
    const receive = async (event) => {
      if (event.origin !== target.origin || event.source !== popup || event.data?.nonce !== nonce) return;
      try {
        if (event.data.type === "dsmack-migrate-hello" && !confirming) {
          confirming = true; publicKey = event.data.publicKey;
          context = target.origin + "\n" + location.origin + "\n" + nonce + "\n" + pair.publicKey + "\n" + publicKey;
          shared = await secret(pair.privateKey, publicKey, context);
          onCode(shared.code); onStatus("Compare the code with your existing origin.");
          check(await approve(confirm, shared.code), "Origin migration declined");
          approved = true; popup.postMessage({ type: "dsmack-migrate-ready", nonce }, target.origin);
        } else if (event.data.type === "dsmack-migrate-bundle" && shared && approved) {
          check(event.data.publicKey === publicKey, "Origin migration sender key changed");
          const keys = bundle(await open(shared.key, event.data.box, context));
          stop(); popup.postMessage({ type: "dsmack-migrate-received", nonce }, target.origin); resolve(keys);
        }
      } catch (error) { stop(); reject(error); }
    };
    window.addEventListener("message", receive);
  });
}
export async function serveOriginMigration({ getBundle, confirm, onCode = () => {}, onStatus = () => {}, allowedOrigin = stableOrigin } = {}) {
  if (!location.hash.startsWith("#dsmack-migrate=")) return false;
  const request = JSON.parse(decodeURIComponent(location.hash.slice("#dsmack-migrate=".length)));
  check(window.opener && request.origin === allowedOrigin && /^[A-Za-z0-9_-]{22}$/.test(request.nonce), "Origin migration requester");
  const pair = await ephemeral();
  const context = location.origin + "\n" + request.origin + "\n" + request.nonce + "\n" + request.publicKey + "\n" + pair.publicKey;
  const shared = await secret(pair.privateKey, request.publicKey, context);
  let receive;
  const ready = new Promise((resolve, reject) => {
    const timer = setTimeout(() => { window.removeEventListener("message", receive); reject(Error("Origin migration expired")); }, 120000);
    receive = (event) => {
      if (event.source !== window.opener || event.origin !== request.origin || event.data?.nonce !== request.nonce || event.data.type !== "dsmack-migrate-ready") return;
      clearTimeout(timer); window.removeEventListener("message", receive); resolve();
    };
    window.addEventListener("message", receive);
  });
  ready.catch(() => {});
  window.opener.postMessage({ type: "dsmack-migrate-hello", nonce: request.nonce, publicKey: pair.publicKey }, request.origin);
  onCode(shared.code); onStatus("Compare the code with the new origin.");
  check(await approve(confirm, shared.code), "Origin migration declined");
  await ready;
  const box = await seal(shared.key, bundle(await getBundle()), context);
  window.opener.postMessage({ type: "dsmack-migrate-bundle", nonce: request.nonce, publicKey: pair.publicKey, box }, request.origin);
  return true;
}
