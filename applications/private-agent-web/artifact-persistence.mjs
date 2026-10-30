import { newestWorkspace } from "./workspaces.mjs";

// All session saves merge the latest workspace and encrypted artifact envelopes. The session
// lock prevents a stale chat or another tab from overwriting a reserved budget.
export function createSessionPersistence({ storage, save, locks = globalThis.navigator?.locks }) {
  const pending = new Map();
  return (session, agent, artifact) => {
    const persist = async () => {
      const stored = await storage.sessions.get(session.id);
      const head = newestWorkspace(session.dsmack.workspace, stored?.dsmack?.workspace);
      if (head) session.dsmack.workspace = head;
      const previous = session.dsmack.artifactState;
      session.dsmack.artifactState = { ...previous, ...stored?.dsmack?.artifactState };
      if (artifact) session.dsmack.artifactState[artifact.scope] = artifact.envelope;
      try { return await save(storage, session, agent); }
      catch (error) { session.dsmack.artifactState = previous; throw error; }
    };
    const operation = (pending.get(session.id) || Promise.resolve()).catch(() => {}).then(() =>
      locks ? locks.request(`dsmack:session:${session.id}`, persist) : persist());
    pending.set(session.id, operation);
    const clear = () => { if (pending.get(session.id) === operation) pending.delete(session.id); };
    operation.then(clear, clear);
    return operation;
  };
}
