export const sameAddress = (a, b) => typeof a === "string" && typeof b === "string" && a.toLowerCase() === b.toLowerCase();
export function running(mac) {
  return new Set(mac.slots.filter(s => ["attesting", "ready", "busy", "draining"].includes(s.state)).map(s => s.slot_id)).size;
}
export function summarize(events, macs, operator, now = Date.now() / 1000) {
  const owned = events.filter(e => sameAddress(e.operator, operator));
  const total = rows => rows.reduce((sum, e) => sum + BigInt(e.operatorCredit), 0n);
  const day = Math.floor(now / 86400), daily = Array.from({ length: 7 }, (_, i) => ({ day: day - 6 + i, earned: 0n }));
  for (const e of owned) {
    const i = Math.floor(e.timestamp / 86400) - day + 6;
    if (i >= 0 && i < 7) daily[i].earned += BigInt(e.operatorCredit);
  }
  return {
    all: total(owned), week: total(owned.filter(e => e.timestamp >= now - 7 * 86400)), daily,
    macs: macs.filter(m => sameAddress(m.operator, operator)).map(mac => ({ ...mac, running: running(mac) })),
  };
}
