export function macFor(network, node) {
  const registration = node?.registration || node;
  const publisher = registration?.mac || registration?.placement?.publisher ||
    registration?.scheduler?.mac || node?.placement?.publisher || node?.placement?.mac || node?.mac || registration?.publisher;
  return network?.macs.find(mac => mac.publisher.toLowerCase() === publisher?.toLowerCase());
}

export function sandboxLabel(mac) {
  const chip = mac?.chip === "Unknown" ? "" : mac?.chip?.replace(/^Apple\s+/i, "");
  const region = mac?.region?.name;
  const description = chip && region ? `${chip} in ${region}` : chip || region;
  return "Dsmack sandbox" + (description ? " · " + description : "");
}

export function networkSummary(network) {
  if (!network?.totals) return "Dsmack network ↗";
  const { macs_online: online, ready_slots: free } = network.totals;
  return `Dsmack network: ${online} Mac${online === 1 ? "" : "s"} online, ${free} free slot${free === 1 ? "" : "s"} ↗`;
}
