// Placement is a speed/capacity hint. Browsers still verify the selected guest.
/** @param {any[]} nodes @param {any[]} fleet
 * @param {(node: any, placement: {publisher: string, slot_id: number}) => boolean} available
 * @param {{now?: number, snapshotOwner?: string}} options */
export function rankNodes(nodes, fleet, available, { now = Math.floor(Date.now() / 1000), snapshotOwner } = {}) {
  const placement = new Map(), byPeer = new Map(nodes.map(node => [node.relay_peer, node]));
  for (const mac of fleet) {
    if (!mac.online || now - mac.received_at >= 60 || now - mac.updated_at >= 60) continue;
    const slots = new Map();
    for (const slot of mac.slots) {
      if (!slots.has(slot.slot_id)) slots.set(slot.slot_id, []);
      slots.get(slot.slot_id).push(slot);
    }
    const ready = new Map();
    for (const [slotId, guests] of slots) {
      const at = { publisher: mac.publisher, slot_id: slotId };
      // A replacement can be warm while its predecessor still owns this slot.
      // Neither a draining predecessor nor a missing old heartbeat peer frees
      // the persisted logical slot held by an active guest stay.
      if (guests.some(slot => slot.state === "busy" ||
        (byPeer.has(slot.relay_peer) && !available(byPeer.get(slot.relay_peer), at)))) continue;
      const eligible = guests.filter(slot => slot.state === "ready" &&
        byPeer.get(slot.relay_peer)?.admit_until >= now + 30)
        .sort((a, b) => byPeer.get(b.relay_peer).admit_until - byPeer.get(a.relay_peer).admit_until);
      if (eligible.length) ready.set(slotId, eligible[0].relay_peer);
    }
    for (const slot of mac.slots) if (slot.relay_peer) placement.set(slot.relay_peer, {
      mac: mac.publisher, slotId: slot.slot_id, freeSlots: ready.size, snapshotLocal: mac.publisher === snapshotOwner,
      ready: ready.get(slot.slot_id) === slot.relay_peer,
    });
  }
  return nodes.map(node => {
    const at = placement.get(node.relay_peer);
    return { ...node, available: !!at?.ready, mac: at?.mac,
      placement: at ? { publisher: at.mac, slot_id: at.slotId } : undefined,
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
