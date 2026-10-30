export const sameAddress = (a, b) => typeof a === "string" && typeof b === "string" && a.toLowerCase() === b.toLowerCase();
export function running(mac) {
  return new Set(mac.slots.filter(s => ["attesting", "ready", "busy", "draining"].includes(s.state)).map(s => s.slot_id)).size;
}
export function summarize(events, macs, operator, now = Date.now() / 1000) {
  const owned = events.filter(e => sameAddress(e.operator, operator));
  const latest = new Map();
  for (const event of owned) {
    const prior = latest.get(event.purchaseId);
    if (!prior || event.sequence > prior.sequence) latest.set(event.purchaseId, event);
  }
  const total = rows => rows.reduce((sum, e) => sum + BigInt(e.operatorCredit), 0n);
  const day = Math.floor(now / 86400), daily = Array.from({ length: 7 }, (_, i) => ({ day: day - 6 + i, earned: 0n }));
  for (const e of owned) {
    const i = Math.floor(e.timestamp / 86400) - day + 6;
    if (i >= 0 && i < 7) daily[i].earned += BigInt(e.operatorCredit);
  }
  const stats = rows => ({
    all: total(rows), week: total(rows.filter(e => e.timestamp >= now - 7 * 86400)),
    jobs24h: new Set(rows.filter(e => e.timestamp >= now - 86400).map(e => e.purchaseId)).size,
    jobs: [...latest.values()].filter(e => rows.some(row => row.purchaseId === e.purchaseId)).sort((a, b) => b.timestamp - a.timestamp),
  });
  return {
    ...stats(owned), daily,
    macs: macs.filter(m => sameAddress(m.operator, operator)).map(mac => {
      const classes = new Set([...(mac.classes || []), ...mac.slots.map(s => s.node_id).filter(Boolean)].map(c => c.toLowerCase()));
      const runs = new Set(mac.slots.map(s => s.run_id?.toLowerCase()).filter(Boolean));
      return { ...mac, running: running(mac), chain: stats(owned.filter(e => classes.has(e.node.toLowerCase()) || runs.has(e.runId.toLowerCase()))) };
    }),
  };
}
