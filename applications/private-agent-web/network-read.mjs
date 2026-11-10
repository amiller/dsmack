export const networkFailure = error => !error?.status &&
  (error?.name === "TypeError" || /failed to fetch|network error|load failed/i.test(error?.message || ""));

// Only callers performing reads use this. Signed requests and commands never do.
export async function readWithRetry(read, signal) {
  try { return await read(); }
  catch (error) {
    if (signal?.aborted || !networkFailure(error)) throw error;
    return await read();
  }
}

export function pause(milliseconds, signal) {
  return new Promise((resolve, reject) => {
    const aborted = () => { clearTimeout(timer); reject(signal.reason); };
    const timer = setTimeout(() => { signal?.removeEventListener("abort", aborted); resolve(); }, milliseconds);
    if (signal?.aborted) aborted();
    else signal?.addEventListener("abort", aborted, { once: true });
  });
}
