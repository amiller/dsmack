// Placement is a speed/capacity hint. Browsers still verify the selected guest.
export function rankNodes(nodes, fleet, available, { now = Math.floor(Date.now() / 1000), snapshotOwner } = {}) {
  const placement = new Map();
  for (const mac of fleet) {
    if (!mac.online || now - mac.received_at >= 60 || now - mac.updated_at >= 60) continue;
    const ready = mac.slots.filter(slot => slot.state === "ready" && nodes.some(node =>
      node.relay_peer === slot.relay_peer && available(node) && node.admit_until >= now + 30));
    const freeSlots = new Set(ready.map(slot => slot.slot_id)).size;
    for (const slot of mac.slots) if (slot.relay_peer) placement.set(slot.relay_peer, {
      mac: mac.publisher, freeSlots, snapshotLocal: mac.publisher === snapshotOwner,
      ready: ready.includes(slot),
    });
  }
  return nodes.map(node => {
    const at = placement.get(node.relay_peer);
    return { ...node, available: !!at?.ready && available(node), mac: at?.mac,
      scheduler: { mac: at?.mac, freeSlots: at?.freeSlots ?? 0, snapshotLocal: !!at?.snapshotLocal } };
  }).sort((a, b) => Number(b.available) - Number(a.available) ||
    Number(b.scheduler.snapshotLocal) - Number(a.scheduler.snapshotLocal) ||
    b.scheduler.freeSlots - a.scheduler.freeSlots || b.admit_until - a.admit_until);
}

export function busyRetrySeconds(nodes, sessions, now = Math.floor(Date.now() / 1000)) {
  // A signed stay expires at this deadline even if its browser disappears.
  // Heartbeats arrive every 15 seconds, so retry within that period while
  // unoccupied guests are booting or their previous registration is stale.
  const ends = Object.values(sessions ?? {}).filter(s => !s.final && s.grant.expires_at > now)
    .map(s => s.grant.expires_at);
  const draining = nodes.map(n => n.payments?.runExpires).filter(v => v > now);
  return Math.max(1, Math.min(15, ...ends.concat(draining).map(until => Math.ceil(until - now))));
}
