export const nonceRef = nonce => typeof nonce === "string" && /^[0-9a-f]{32}$/.test(nonce) ? nonce.slice(0, 8) : null;
export const errorCode = code => typeof code === "string" && /^[A-Z][A-Z0-9_]{0,63}$/.test(code) ? code : "REQUEST_REFUSED";

// Construct the closed record here: never spread a request, error or provider
// object into a log. Byte counts are payload bytes, excluding HTTP/TLS framing.
export function requestLog(event, { ref, code, status, started, requestBytes, responseBytes }) {
  console.error(JSON.stringify({ event, time: new Date().toISOString(),
    ref, code: errorCode(code), http_status: status,
    duration_ms: Math.round((performance.now() - started) * 1000) / 1000,
    request_bytes: requestBytes, response_bytes: responseBytes }));
}
