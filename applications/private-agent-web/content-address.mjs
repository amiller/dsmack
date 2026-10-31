export const decodeBase64Url = value => Uint8Array.from(atob(value.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));
export function encodeBase64Url(bytes) {
  let text = "";
  for (let at = 0; at < bytes.length; at += 8192) text += String.fromCharCode(...bytes.subarray(at, at + 8192));
  return btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
export async function cidFor(bytes) {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  let bits = 0, value = 0, out = "b";
  for (const byte of [1, 0x55, 0x12, 0x20, ...digest]) {
    value = (value << 8) | byte; bits += 8;
    while (bits >= 5) { bits -= 5; out += "abcdefghijklmnopqrstuvwxyz234567"[(value >>> bits) & 31]; }
  }
  if (bits) out += "abcdefghijklmnopqrstuvwxyz234567"[(value << (5 - bits)) & 31];
  return out;
}
