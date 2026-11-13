export function macFor(network, node) {
  const registration = node?.registration || node;
  const publisher = registration?.mac || registration?.placement?.publisher ||
    registration?.scheduler?.mac || node?.placement?.publisher || node?.placement?.mac || node?.mac || registration?.publisher;
  return network?.macs.find(mac => mac.publisher.toLowerCase() === publisher?.toLowerCase());
}

const adjectives = ["amber", "brisk", "calm", "dusky", "eager", "fern", "gilded", "hazel", "ivory", "jolly", "keen", "lunar", "misty", "noble", "olive", "plucky", "quiet", "russet", "sunny", "tawny", "umber", "velvet", "windy", "zesty", "coral", "dapper", "frosty", "golden", "mossy", "rosy", "sable", "tidal"];
const animals = ["otter", "heron", "lynx", "badger", "finch", "gecko", "ibis", "koala", "lemur", "marten", "newt", "ocelot", "puffin", "quail", "raven", "stoat", "tapir", "urchin", "vole", "walrus", "yak", "zebra", "bison", "crane", "dingo", "egret", "ferret", "gopher", "hare", "jackal", "magpie", "panda"];

// A name people can tell apart, from the key the Mac signs its heartbeats with.
export function macName(publisher) {
  const n = BigInt(publisher);
  return `${adjectives[Number(n % 32n)]}-${animals[Number((n >> 5n) % 32n)]}`;
}

export function macHardware(mac) {
  const chip = mac.chip === "Unknown" ? "" : mac.chip?.replace(/^Apple\s+/i, "");
  return [macName(mac.publisher), chip].filter(Boolean).join(", ");
}

export function sandboxLabel(mac) {
  const region = mac?.region?.name;
  const hardware = mac ? macHardware(mac) : "";
  const description = hardware && region ? `${hardware} in ${region}` : hardware || region;
  return "Dsmack sandbox" + (description ? " · " + description : "");
}

export function networkSummary(network) {
  if (!network?.totals) return "Dsmack network ↗";
  const { macs_online: online, ready_slots: free, standby_slots: standby } = network.totals;
  return `Dsmack network: ${online} Mac${online === 1 ? "" : "s"} online, ${free} free slot${free === 1 ? "" : "s"}` +
    (standby ? `, ${standby} more on demand` : "") + " ↗";
}
