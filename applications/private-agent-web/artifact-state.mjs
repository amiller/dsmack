const utf8 = new TextEncoder();
const b64 = (value) => btoa(Array.from(new Uint8Array(value), byte => String.fromCharCode(byte)).join(''))
  .replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
const unb64 = (value) => Uint8Array.from(atob(value.replaceAll('-', '+').replaceAll('_', '/')), c => c.charCodeAt(0));
const context = (scope) => utf8.encode(JSON.stringify(['dsmack/artifact-state', 1, scope]));
const empty = () => ({ values: {}, budget: { limitNanoUsd: null, spentNanoUsd: '0', reservedNanoUsd: '0' } });

export class ArtifactState {
  #material;
  #getRecord;
  #saveRecord;
  #pending = new Map();

  constructor({ dataKey, getRecord, saveRecord }) {
    this.#material = crypto.subtle.importKey('raw', unb64(dataKey), 'HKDF', false, ['deriveKey']);
    this.#getRecord = getRecord;
    this.#saveRecord = saveRecord;
  }

  async #key(scope) {
    return crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256',
      salt: utf8.encode('dsmack/artifact-state/v1'), info: context(scope) },
    await this.#material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  }

  async #load(scope) {
    const envelope = await this.#getRecord(scope);
    if (envelope === undefined) return empty();
    if (envelope?.v !== 1) throw new Error('Unsupported artifact state envelope');
    const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(envelope.iv),
      additionalData: context(scope) }, await this.#key(scope), unb64(envelope.ciphertext));
    return JSON.parse(new TextDecoder().decode(plaintext));
  }

  async read(scope) {
    await this.#pending.get(scope);
    return this.#load(scope);
  }

  update(scope, mutator) {
    const prior = this.#pending.get(scope) || Promise.resolve();
    const operation = prior.catch(() => {}).then(async () => {
      const state = await this.#load(scope);
      await mutator(state);
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv,
        additionalData: context(scope) }, await this.#key(scope), utf8.encode(JSON.stringify(state)));
      await this.#saveRecord(scope, { v: 1, iv: b64(iv), ciphertext: b64(ciphertext) });
      return state;
    });
    this.#pending.set(scope, operation);
    const clear = () => { if (this.#pending.get(scope) === operation) this.#pending.delete(scope); };
    operation.then(clear, clear);
    return operation;
  }

  async get(scope, key) {
    const { values } = await this.read(scope);
    return Object.hasOwn(values, key) ? values[key] : undefined;
  }

  async put(scope, key, value) {
    await this.update(scope, state => {
      Object.defineProperty(state.values, key, { value, writable: true, enumerable: true, configurable: true });
    });
    return value;
  }

  async list(scope) {
    return Object.keys((await this.read(scope)).values);
  }
}
