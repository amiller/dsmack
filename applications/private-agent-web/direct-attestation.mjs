import { multiaddr } from "@multiformats/multiaddr";
import { tunnel, address } from "../browser-p2p/tunnels.mjs";

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });
const MAX_ATTESTATION = 150000;
function require(ok, message) { if (!ok) throw new Error(message); }

// The only pre-verification payload is a random public challenge. Repository
// bytes and MCP admission stay in GuestSession after verifyNode succeeds.
export async function fetchDirectAttestation({ peer, selected, challenge, policy, signal }) {
  require(/^[0-9a-f]{64}$/.test(challenge), "Guest attestation needs a fresh 32-byte challenge.");
  const manifest = JSON.parse(decoder.decode(policy.manifest));
  const relayPeer = JSON.parse(manifest.docker_compose_file).services.node.command[1].split("/").at(-1);
  const entries = (selected.tunnels || []).map(tunnel).filter(entry =>
    entry.relayPeer === relayPeer && entry.guestPeer === selected.relay_peer &&
    entry.expiresAt * 1000 > Date.now()).sort((a, b) => b.expiresAt - a.expiresAt);
  require(entries.length, "Chain directory has no live tunnel for this guest and its approved relay.");
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(new Error("Direct guest attestation timed out.")), 30000);
  const abort = () => controller.abort(signal.reason);
  if (signal?.aborted) abort(); else signal?.addEventListener("abort", abort, { once: true });
  let connection, stream;
  const abortStream = () => stream?.abort(controller.signal.reason);
  controller.signal.addEventListener("abort", abortStream, { once: true });
  try {
    controller.signal.throwIfAborted();
    connection = await peer.dial(multiaddr(address(entries[0])), { signal: controller.signal });
    require(connection.remotePeer.toString() === selected.relay_peer,
      "Direct Noise peer differs from the chain directory guest.");
    stream = await connection.newStream("/dsmack/payments-attest/1", {
      signal: controller.signal, runOnLimitedConnection: true,
    });
    stream.inactivityTimeout = 30000;
    controller.signal.throwIfAborted();
    const payload = encoder.encode(JSON.stringify({ challenge }));
    const frame = new Uint8Array(payload.length + 4);
    new DataView(frame.buffer).setUint32(0, payload.length);
    frame.set(payload, 4);
    if (!stream.send(frame)) await stream.onDrain({ signal: controller.signal });
    const registration = await readDirectAttestation(stream);
    controller.signal.throwIfAborted();
    require(registration.relay_peer === selected.relay_peer,
      "Direct guest attestation identifies another Noise peer.");
    require(registration.payments?.challenge === challenge,
      "Direct guest returned a stale attestation challenge.");
    return { registration, connection, entries };
  } catch (error) {
    await connection?.close().catch(() => {});
    throw error;
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener("abort", abort);
    controller.signal.removeEventListener("abort", abortStream);
    if (stream && stream.status !== "closed" && stream.status !== "aborted") {
      stream.abort(new Error("Direct attestation complete."));
    }
  }
}

export async function readDirectAttestation(stream) {
  const chunks = [];
  let length = 0;
  for await (const value of stream) {
    const chunk = value instanceof Uint8Array ? value : value.subarray();
    length += chunk.length;
    require(length <= MAX_ATTESTATION, "Direct guest attestation exceeds the response limit.");
    chunks.push(chunk);
  }
  const raw = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) { raw.set(chunk, offset); offset += chunk.length; }
  return JSON.parse(decoder.decode(raw));
}
