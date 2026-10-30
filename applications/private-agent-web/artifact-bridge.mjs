import manifest from "./bridge/Manifest.json" with { type: "json" };

const fail = (code, message) => { throw Object.assign(new Error(message), { code }); };
const object = value => value !== null && typeof value === "object" && !Array.isArray(value);
const key = value => typeof value === "string" && value.length > 0 && value.length <= 256;
const requestId = value => typeof value === "string" && /^[a-zA-Z0-9_-]{1,128}$/.test(value);

// Pi stringifies this function into the generated document. All authority stays
// in the host provider's scope closure; the SDK supplies no artifact identifier.
export function dsmackRuntime(sandboxId) {
  const contract = window.__dsmackManifest;
  delete window.__dsmackManifest;
  const pending = new Map();
  let snapshot, readyPromise;
  class BridgeError extends Error {
    constructor(code, message, retryable = false) {
      super(message); this.name = "DsmackBridgeError"; this.code = code; this.retryable = retryable;
    }
  }
  addEventListener("message", event => {
    if (event.source !== parent || event.origin !== "null") return;
    const data = event.data;
    if (!data || data.type !== "dsmack-response" || data.sandboxId !== sandboxId || data.version !== 1) return;
    const entry = pending.get(data.requestId);
    if (!entry) return;
    pending.delete(data.requestId); clearTimeout(entry.timer);
    if (data.ok === true) entry.resolve(data.result);
    else entry.reject(new BridgeError(contract.errors.includes(data.error?.code) ? data.error.code : "HOST_ERROR",
      data.error?.message || "Host request failed", Boolean(data.error?.retryable)));
  });
  function invoke(method, params = {}) {
    if (parent === window) return Promise.reject(new BridgeError("NOT_AVAILABLE", "Open this app in Dsmack to use host capabilities."));
    const requestId = Array.from(crypto.getRandomValues(new Uint8Array(16)), byte => byte.toString(16).padStart(2, "0")).join("");
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        pending.delete(requestId);
        reject(new BridgeError("TIMEOUT", "Host request timed out", true));
      }, method === "agent.complete" ? 120000 : 15000);
      pending.set(requestId, { resolve, reject, timer });
      try { parent.postMessage({ type: "dsmack-request", sandboxId, version: 1, requestId, method, params }, "*"); }
      catch { pending.delete(requestId); clearTimeout(timer); reject(new BridgeError("INVALID_ARGS", "Method parameters must be serializable.")); }
    });
  }
  const getCapabilities = async () => {
    const value = await invoke("runtime.getCapabilities");
    for (const capability of Object.values(value.capabilities)) Object.freeze(capability);
    Object.freeze(value.capabilities); snapshot = Object.freeze(value); return snapshot;
  };
  const sdk = Object.freeze({
    version: 1, BridgeError,
    ready: () => readyPromise ||= getCapabilities().catch(error => { readyPromise = undefined; throw error; }),
    capabilities: Object.freeze({ has: method => Boolean(snapshot?.capabilities[method]?.available) }),
    runtime: Object.freeze({ getCapabilities }),
    storage: Object.freeze({ get: key => invoke("storage.get", { key }), put: (key, value) => invoke("storage.put", { key, value }), list: () => invoke("storage.list") }),
    agent: Object.freeze({ complete: params => invoke("agent.complete", params) }),
    credit: Object.freeze({ balance: () => invoke("credit.balance") }),
    diagnostics: Object.freeze({ log: message => invoke("diagnostics.log", { message }) }),
  });
  Object.defineProperty(window, "dsmack", { value: sdk, writable: false, configurable: false });
}

export class ArtifactBridge {
  constructor({ scope, state, models, credit, diagnostics }) {
    Object.assign(this, { scope, state, models, credit, diagnostics });
  }
  getData() { return { __dsmackManifest: manifest }; }
  getRuntime() { return dsmackRuntime; }
  async handleMessage(message, respond) {
    if (message.type === "execution-complete" || message.type === "execution-error") {
      if (message.type === "execution-error") this.diagnostics?.(String(message.error?.message || "App execution failed"));
      respond({ success: true }); return;
    }
    if (message.type !== "dsmack-request") return;
    const response = { type: "dsmack-response", version: 1, requestId: message.requestId };
    try {
      if (!requestId(message.requestId)) fail("INVALID_ARGS", "A valid requestId is required.");
      if (message.version !== 1) fail("UNSUPPORTED_VERSION", "Bridge version 1 is required.");
      const method = manifest.methods.find(item => item.name === message.method);
      if (!method) fail("METHOD_NOT_FOUND", "Unknown Dsmack method.");
      const params = message.params;
      if (!object(params)) fail("INVALID_ARGS", "Method params must be an object.");
      if (Object.keys(params).some(name => !Object.hasOwn(method.parameters, name))) fail("INVALID_ARGS", "Unknown method parameter.");
      for (const [name, field] of Object.entries(method.parameters)) {
        if (field.required && !Object.hasOwn(params, name)) fail("INVALID_ARGS", `Missing parameter: ${name}`);
      }
      let result;
      switch (message.method) {
        case "runtime.getCapabilities":
          result = { bridgeVersion: 1, capabilities: Object.fromEntries(manifest.methods.map(item => [item.name, {
            supported: true, available: item.name.startsWith("storage.") ? Boolean(this.state) : item.name === "agent.complete" ? Boolean(this.models) : true,
          }])) }; break;
        case "storage.get": case "storage.put": case "storage.list": {
          if (!this.state) fail("NOT_AVAILABLE", "Artifact storage is unavailable.");
          if (message.method !== "storage.list" && !key(params.key)) fail("INVALID_ARGS", "Storage key must contain 1–256 characters.");
          if (message.method === "storage.get") result = (await this.state.get(this.scope, params.key)) ?? null;
          if (message.method === "storage.list") result = await this.state.list(this.scope);
          if (message.method === "storage.put") {
            let serialized;
            try { serialized = JSON.stringify(params.value); } catch { fail("INVALID_ARGS", "Storage value must be JSON."); }
            if (serialized === undefined || serialized.length > 256 * 1024) fail("INVALID_ARGS", "Storage value must be JSON below 256 KiB.");
            const value = JSON.parse(serialized);
            await this.state.put(this.scope, params.key, value); result = value;
          }
          break;
        }
        case "agent.complete":
          if (!this.models) fail("NOT_AVAILABLE", "Artifact model calls are unavailable.");
          if (!Array.isArray(params.messages) || !params.messages.length || params.messages.length > 32 ||
            params.messages.some(item => !object(item) || !["user", "assistant"].includes(item.role) || typeof item.content !== "string" ||
              Object.keys(item).some(name => !["role", "content"].includes(name))) ||
            params.messages.reduce((bytes, item) => bytes + new TextEncoder().encode(item.content).length, 0) > 32768 ||
            (params.maxTokens !== undefined && (!Number.isSafeInteger(params.maxTokens) || params.maxTokens < 64))) fail("INVALID_ARGS", "Provide 1–32 user/assistant text messages below 32 KiB and optional integer maxTokens of at least 64.");
          result = await this.models.complete(this.scope, params); break;
        case "credit.balance": {
          const credit = this.credit?.chatCredit;
          result = { wallet: this.credit?.address || null, remainingNanoUsd: credit?.remainingNanoUsd || "0",
            spentNanoUsd: credit?.spentNanoUsd || "0", pending: Boolean(credit?.pendingInferenceId) }; break;
        }
        case "diagnostics.log":
          if (typeof params.message !== "string" || params.message.length > 8192) fail("INVALID_ARGS", "Log message must be a string below 8 KiB.");
          this.diagnostics?.(params.message); result = null; break;
      }
      respond({ ...response, ok: true, result });
    } catch (error) {
      respond({ ...response, ok: false, error: { code: manifest.errors.includes(error.code) ? error.code : "HOST_ERROR",
        message: String(error.message || error), retryable: Boolean(error.retryable) } });
    }
  }
}
