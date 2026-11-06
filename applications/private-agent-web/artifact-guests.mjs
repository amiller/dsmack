const failure = (code, message) => Object.assign(new Error(message), { code });
const check = (ok, code, message) => { if (!ok) throw failure(code, message); };
export const ephemeralWorkspace = () => ({ latest: async () => null, bind: async () => false, save: async () => null });
const publicStatus = value => ({ active: !!value?.active, usageUnresolved: !!value?.usageUnresolved,
  guestSeconds: Number(value?.guestSeconds || 0), rateNanoUsdPerSecond: value?.rateNanoUsdPerSecond || null });
function abortable(operation, signal) {
  if (signal.aborted) return Promise.reject(signal.reason);
  return new Promise((resolve, reject) => {
    const aborted = () => reject(signal.reason);
    signal.addEventListener('abort', aborted, { once: true });
    Promise.resolve(operation).then(resolve, reject).finally(() => signal.removeEventListener('abort', aborted));
  });
}
export class ArtifactGuests {
  constructor({ credit, api, authorize, createSession, confirm, persist, evidence, changed = () => {}, mainHeld = () => false, initial = [], cleanupTimeoutMs = 15000 }) {
    Object.assign(this, { credit, api, authorize, createSession, confirm, persist, evidence, changed, mainHeld, cleanupTimeoutMs });
    this.wallet = credit.address?.toLowerCase();
    this.records = new Map(initial.map(record => [record.id, structuredClone(record)]));
    this.sessions = new Map(); this.credits = new Map(); this.ending = new Map(); this.active = null;
  }
  get pending() { return [...this.records.values()].filter(record => record.sessionId && record.state !== 'released'); }
  get busy() { return !!this.active || this.pending.length > 0; }
  cancel(scope, requestId, owner) {
    const active = this.active;
    if (active && active.record.scope === scope && active.record.id === requestId && (owner === undefined || owner === active.owner)) {
      active.controller.abort(failure('USER_CANCELLED', 'Guest command cancelled. Execution is not retried.'));
    }
  }
  cancelOwner(owner) { if (this.active?.owner === owner) this.cancel(this.active.record.scope, this.active.record.id, owner); }
  dispose() { if (this.active) this.active.controller.abort(failure('USER_CANCELLED', 'The requesting app closed.')); }
  async save(record) { this.records.set(record.id, record); await this.persist(structuredClone(record)); this.changed(structuredClone(record)); }
  fixedCredit(wallet) { return Object.assign(Object.create(this.credit), { address: wallet, signer: this.credit.signer, chatCredit: this.credit.chatCredit }); }
  session(record, fixedCredit, savedLease) {
    const options = { conversationId: record.conversationId, credit: fixedCredit, repository: () => new Map(), workspace: ephemeralWorkspace(), savedLease,
      changed: status => {
        record.status = publicStatus(status);
        if (status.node) record.registration = structuredClone(status.node);
        const session = this.sessions.get(record.id);
        if (session) session.statusSnapshot = status;
        this.changed(structuredClone(record));
      },
      api: async (path, body, options) => {
        if (path === '/agent/open') check(this.credit.address?.toLowerCase() === record.wallet, 'PERMISSION_DENIED', 'The confirmed viewer wallet changed.');
        const response = await this.api(path, body, options);
        if (path === '/agent/open') {
          record.sessionId = response.sessionId; record.state = 'claimed';
          try {
            await this.save(record);
            if (record.cancelled) throw failure("USER_CANCELLED", "The app closed while its guest claim was opening.");
          }
          catch (error) {
            try {
              const ended = await this.api('/agent/end', await this.authorize(fixedCredit, 'agent-end', { sessionId: record.sessionId }));
              record.status = publicStatus(ended); record.state = ended.active || ended.usageUnresolved ? 'release-pending' : 'released';
            } catch { record.state = 'release-pending'; }
            await this.save(record).catch(() => {});
            throw error;
          }
        }
        return response;
      },
    };
    const session = this.createSession(options); this.sessions.set(record.id, session); this.credits.set(record.id, fixedCredit); return session;
  }
  async settle(record, session) {
    if (session.statusSnapshot) record.status = publicStatus(session.statusSnapshot);
    record.state = !session.lease && !record.status?.usageUnresolved ? 'released' : 'release-pending';
    await this.save(record);
    if (record.state === 'released') { this.sessions.delete(record.id); this.credits.delete(record.id); }
    return record;
  }
  async cleanup(record, session) {
    // /agent/open may already have returned while durable persistence is still
    // awaited, before GuestSession can assign its lease. Release that known ID.
    if (!session.lease && record.sessionId) {
      try {
        const result = await this.api('/agent/end', await this.authorize(this.credits.get(record.id), 'agent-end', { sessionId: record.sessionId }));
        record.status = publicStatus(result);
        record.state = result.active || result.usageUnresolved ? 'release-pending' : 'released';
        await this.save(record);
      } catch (error) { record.state = 'release-pending'; record.error = error.message; await this.save(record).catch(() => {}); }
      return record;
    }
    record.state = 'release-pending'; await this.save(record).catch(() => {});
    let ending = this.ending.get(record.id);
    if (!ending) {
      ending = Promise.resolve().then(() => session.end()).then(() => this.settle(record, session));
      this.ending.set(record.id, ending);
      const clear = () => { if (this.ending.get(record.id) === ending) this.ending.delete(record.id); };
      ending.then(clear, clear);
    }
    let timer;
    try { await Promise.race([ending, new Promise((_, reject) => { timer = setTimeout(() => reject(Error('Guest release is still pending.')), this.cleanupTimeoutMs); })]); }
    catch (error) { record.state = 'release-pending'; record.error = error.message; await this.save(record).catch(() => {}); }
    finally { clearTimeout(timer); }
    return record;
  }
  async run(scope, { command, timeoutSeconds = 60 } = {}, { requestId = crypto.randomUUID(), owner, filename = 'app.html', signal } = {}) {
    check(typeof command === 'string' && command.trim() && new TextEncoder().encode(command).length <= 32768,
      'INVALID_ARGS', 'Guest command must contain 1–32768 UTF-8 bytes.');
    check(Number.isInteger(timeoutSeconds) && timeoutSeconds >= 1 && timeoutSeconds <= 120, 'INVALID_ARGS', 'Guest timeout must be 1–120 seconds.');
    check(!this.busy && !this.mainHeld(), 'NOT_AVAILABLE', 'Finish the held guest stay or task cleanup before starting an app command.');
    check(!this.records.has(requestId), 'INVALID_ARGS', 'This guest request was already handled; it cannot be replayed.');
    const wallet = this.credit.address?.toLowerCase();
    check(wallet && this.credit.signer, 'NOT_AVAILABLE', 'Choose the viewer wallet first.');
    check(wallet === this.wallet, 'PERMISSION_DENIED', 'Reopen the app after changing the viewer wallet.');
    const record = { id: requestId, scope, filename, wallet, conversationId: 'artifact-' + crypto.randomUUID(), command, timeoutSeconds, state: 'confirming' };
    const controller = new AbortController(), abort = () => controller.abort(signal.reason);
    if (signal?.aborted) abort(); else signal?.addEventListener('abort', abort, { once: true });
    const deadline = setTimeout(() => controller.abort(failure('TIMEOUT', 'Guest command deadline reached. Execution is not retried.')), 270000);
    this.active = { record, controller, owner };
    let session, result, error;
    try {
      const approved = await abortable(this.confirm({ ...record, credit: this.credit.chatCredit?.remainingNanoUsd || '0' }, controller.signal), controller.signal);
      check(approved, 'USER_CANCELLED', 'Guest command was not approved.');
      check(!controller.signal.aborted, 'USER_CANCELLED', 'Guest command cancelled.');
      check(this.credit.address?.toLowerCase() === wallet, 'PERMISSION_DENIED', 'The confirmed viewer wallet changed.');
      check(!this.mainHeld(), 'NOT_AVAILABLE', 'A chat guest is held; end that stay first.');
      record.state = "opening"; this.changed(structuredClone(record));
      session = this.session(record, this.fixedCredit(wallet));
      const client = await abortable(session.ensure(controller.signal), controller.signal);
      check(this.credit.address?.toLowerCase() === wallet, 'PERMISSION_DENIED', 'The confirmed viewer wallet changed.');
      check(!controller.signal.aborted, "USER_CANCELLED", "Guest command cancelled.");
      record.state = 'running'; record.registration = structuredClone(session.node?.registration || record.registration || {}); await this.save(record);
      check(!controller.signal.aborted, "USER_CANCELLED", "Guest command cancelled.");
      const response = await client.callTool({ name: 'bash', arguments: { command, timeout: timeoutSeconds } }, {
        signal: controller.signal, timeout: timeoutSeconds * 1000 + 15000,
        onprogress: progress => this.changed({ ...record, progress: String(progress.message || '').slice(0, 4096) }),
      });
      result = { text: (response.content || []).filter(part => part.type === 'text').map(part => part.text).join('\n'), isError: !!response.isError };
      record.result = result;
      session.lastActivity = Date.now(); await session.status();
    } catch (caught) { error = controller.signal.aborted ? controller.signal.reason : caught; record.error = error.message; record.cancelled = controller.signal.aborted; }
    finally {
      clearTimeout(deadline); signal?.removeEventListener('abort', abort);
      if (record.sessionId && record.state !== 'released' && session) await this.cleanup(record, session);
      if (!record.sessionId) { record.state = "cancelled"; this.changed(structuredClone(record)); }
      this.active = null;
      if (record.sessionId) {
        const evidence = { ...structuredClone(record), type: 'guest-run', provenance: 'untrusted_artifact' };
        await this.evidence?.(evidence);
      }
    }
    if (error) throw error.code ? error : failure('HOST_ERROR', error.message);
    check(record.state === 'released', 'NOT_AVAILABLE', 'Task output was received, but its owned guest release is still pending. Finish releasing it before another run.');
    return { ...result, guest: { sessionId: record.sessionId, nodePeer: record.registration?.relay_peer || null, ...record.status },
      evidence: { ...structuredClone(record), type: 'guest-run', provenance: 'untrusted_artifact' } };
  }
  recover(record) { return this.finish(record); }
  async finish(record) {
    check(record.wallet === this.credit.address?.toLowerCase(), 'PERMISSION_DENIED', 'Recover the original viewer wallet to release this task guest.');
    check(!this.active, 'NOT_AVAILABLE', 'A guest command is still finishing.');
    const owned = this.records.get(record.id);
    check(owned && owned.sessionId === record.sessionId, 'INVALID_ARGS', 'Unknown owned task lease.');
    if (owned.state === 'released') return owned;
    let session = this.sessions.get(owned.id);
    if (!session) {
      session = this.session(owned, this.fixedCredit(owned.wallet), { active: true, wallet: owned.wallet,
        conversationId: owned.conversationId, sessionId: owned.sessionId, node: owned.registration });
      await session.restore();
    }
    return this.cleanup(owned, session);
  }
}
