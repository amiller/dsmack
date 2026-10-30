const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });
const magic = new Uint8Array([0x44, 0x53, 0x59, 0x4e]); // DSYN
const header = new Uint8Array([...magic, 1, 1]); // format v1, gzip
export const MAX_SYNC_PLAIN_BYTES = 16 * 1024 * 1024;

export async function encodeSyncJson(value) {
  const json = JSON.stringify(value);
  if (typeof json !== "string") throw new Error("Chat sync value must be JSON.");
  const plain = encoder.encode(json);
  if (plain.length > MAX_SYNC_PLAIN_BYTES) throw new Error("Chat sync JSON exceeds 16 MiB.");
  if (typeof CompressionStream === "undefined") return plain;
  const compressed = new Uint8Array(await new Response(new Blob([plain]).stream().pipeThrough(new CompressionStream("gzip"))).arrayBuffer());
  if (compressed.length + header.length >= plain.length) return plain;
  const result = new Uint8Array(header.length + compressed.length);
  result.set(header); result.set(compressed, header.length);
  return result;
}

export async function decodeSyncJson(input) {
  const bytes = new Uint8Array(input);
  let plain = bytes;
  if (magic.every((byte, index) => bytes[index] === byte)) {
    if (bytes[4] !== 1 || bytes[5] !== 1) throw new Error("Unsupported chat sync compression format.");
    const reader = new Blob([bytes.subarray(header.length)]).stream().pipeThrough(new DecompressionStream("gzip")).getReader();
    const chunks = [];
    let length = 0;
    try {
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        length += value.length;
        if (length > MAX_SYNC_PLAIN_BYTES) throw new Error("Decoded chat sync JSON exceeds 16 MiB.");
        chunks.push(value);
      }
    } catch (error) { await reader.cancel().catch(() => {}); throw error; }
    finally { reader.releaseLock(); }
    plain = new Uint8Array(length);
    let offset = 0;
    for (const chunk of chunks) { plain.set(chunk, offset); offset += chunk.length; }
  }
  if (plain.length > MAX_SYNC_PLAIN_BYTES) throw new Error("Decoded chat sync JSON exceeds 16 MiB.");
  return JSON.parse(decoder.decode(plain));
}
