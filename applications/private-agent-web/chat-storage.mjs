import { AppStorage, setAppStorage } from "@pi-components/storage/app-storage.js";
import { IndexedDBStorageBackend } from "@pi-components/storage/backends/indexeddb-storage-backend.js";
import { SettingsStore } from "@pi-components/storage/stores/settings-store.js";
import { ProviderKeysStore } from "@pi-components/storage/stores/provider-keys-store.js";
import { SessionsStore } from "@pi-components/storage/stores/sessions-store.js";
import { CustomProvidersStore } from "@pi-components/storage/stores/custom-providers-store.js";

export function createChatStorage() {
  const settings = new SettingsStore(), providerKeys = new ProviderKeysStore(),
    sessions = new SessionsStore(), customProviders = new CustomProvidersStore();
  const stores = [settings, providerKeys, sessions, customProviders];
  const backend = new IndexedDBStorageBackend({
    dbName: "dsmack-private-agent-chats",
    version: 1,
    stores: [...stores.map((store) => store.getConfig()), SessionsStore.getMetadataConfig()],
  });
  for (const store of stores) store.setBackend(backend);
  const storage = new AppStorage(settings, providerKeys, sessions, customProviders, backend);
  setAppStorage(storage);
  return storage;
}

const text = (message) => typeof message.content === "string"
  ? message.content
  : message.content.filter((part) => part.type === "text").map((part) => part.text).join("\n");

export async function saveChat(storage, session, agent) {
  const messages = structuredClone(agent.state.messages);
  const title = text(messages.find((m) => m.role === "user") || { content: "New chat" }).slice(0, 80);
  const data = structuredClone({
    ...session, title, messages,
    model: agent.state.model,
    thinkingLevel: agent.state.thinkingLevel,
    lastModified: new Date().toISOString(),
  });
  const usage = {
    input: 0, output: 0, cacheRead: 0, cacheWrite: 0, totalTokens: 0,
    cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
  };
  for (const message of messages.filter((m) => m.role === "assistant")) {
    for (const key of ["input", "output", "cacheRead", "cacheWrite", "totalTokens"]) usage[key] += message.usage[key];
    for (const key of Object.keys(usage.cost)) usage.cost[key] += message.usage.cost[key];
  }
  await storage.sessions.save(data, {
    id: data.id, title, createdAt: data.createdAt, lastModified: data.lastModified,
    messageCount: messages.length, usage, thinkingLevel: data.thinkingLevel,
    preview: messages.map(text).join("\n").slice(0, 2048),
  });
  return data;
}
