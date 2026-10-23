import test from 'node:test'
import assert from 'node:assert/strict'
import * as L from '../logic.js'

const DT = 1 / 60
const flat = (gates = []) => ({ spacing: 10, terrain: Array(2000).fill(0), gates })
const run = (s, input, seconds) => {
  for (let i = 0; i < Math.round(seconds / DT); i++) s = L.step(s, input, DT)
  return s
}
const speed = s => Math.hypot(s.vx, s.vy)

test('seeded rng is deterministic and in [0,1)', () => {
  const a = L.mulberry32(42), b = L.mulberry32(42)
  const xs = Array.from({ length: 1000 }, a)
  assert.deepEqual(xs, Array.from({ length: 1000 }, b))
  assert.ok(xs.every(x => x >= 0 && x < 1))
  assert.notDeepEqual(xs.slice(0, 5), Array.from({ length: 5 }, L.mulberry32(43)))
})

test('levels are pure data from the seed', () => {
  assert.deepEqual(L.makeLevel(7), L.makeLevel(7))
  assert.notDeepEqual(L.makeLevel(7).terrain, L.makeLevel(8).terrain)
  assert.deepEqual(JSON.parse(JSON.stringify(L.makeLevel(7))), L.makeLevel(7))
})

test('generated gates clear the terrain and are ordered', () => {
  for (let seed = 1; seed <= 50; seed++) {
    const level = L.makeLevel(seed)
    assert.equal(level.gates.length, 12)
    level.gates.forEach((g, i) => {
      assert.ok(g.y - g.gap / 2 >= L.terrainAt(level, g.x) + 20, `seed ${seed} gate ${i}`)
      if (i) assert.ok(g.x > level.gates[i - 1].x)
    })
    assert.ok(level.terrain.every(h => h > 0 && h < 100))
  }
})

test('terrainAt interpolates linearly and clamps at the ends', () => {
  const level = { spacing: 10, terrain: [0, 10, 30] }
  assert.equal(L.terrainAt(level, 5), 5)
  assert.equal(L.terrainAt(level, 15), 20)
  assert.equal(L.terrainAt(level, -50), 0)
  assert.equal(L.terrainAt(level, 999), 30)
})

test('trim balances forces in level flight at cruise', () => {
  const s = L.initialState(flat())
  const f = L.forces(s)
  assert.ok(Math.abs(f.ax) < 1e-9 && Math.abs(f.ay) < 1e-9)
  assert.ok(s.throttle > 0 && s.throttle < 1)
})

test('level flight at cruise holds altitude and speed for a minute', () => {
  const s = run(L.initialState(flat()), {}, 60)
  assert.equal(s.status, 'flying')
  assert.ok(Math.abs(s.y - 120) < 1e-6)
  assert.ok(Math.abs(speed(s) - L.CRUISE) < 1e-6)
})

test('a speed disturbance damps out instead of diverging', () => {
  const s0 = { ...L.initialState(flat(), { y: 300 }), vx: 46 }
  const late = run(s0, {}, 50)
  const swing = s => {
    let lo = Infinity, hi = -Infinity
    for (let i = 0; i < 600; i++) { s = L.step(s, {}, DT); lo = Math.min(lo, s.y); hi = Math.max(hi, s.y) }
    return hi - lo
  }
  assert.ok(swing(late) < swing(s0) / 4)
  assert.ok(Math.abs(speed(run(late, {}, 30)) - L.CRUISE) < 1)
  assert.ok(Math.abs(late.y - 300) < 20)
})

test('lift is linear below the critical angle and collapses past it', () => {
  assert.equal(L.cl(0.1), 2 * L.cl(0.05))
  assert.ok(L.cl(L.ALPHA_STALL + 0.01) < 0.5 * L.cl(L.ALPHA_STALL - 0.01))
  assert.equal(L.cl(-0.4), -L.cl(0.4))
})

test('pulling up hard at low speed stalls and the plane sinks', () => {
  let s = { ...L.initialState(flat(), { y: 300, speed: 22 }), throttle: 0 }
  s = run(s, { pitch: 1 }, 0.5)
  assert.ok(s.stalled)
  const y0 = s.y
  s = run(s, {}, 2)
  assert.ok(s.stalled)
  assert.ok(s.y < y0 - 5 && s.vy < 0)
})

test('the same pitch-up at cruise speed climbs without stalling', () => {
  let s = L.initialState(flat(), { y: 300 })
  s = run(s, { pitch: 1 }, 0.1)
  assert.ok(!s.stalled)
  s = run(s, {}, 1)
  assert.ok(s.y > 300 && s.vy > 0)
})

test('throttle accelerates and stays within [0, 1]', () => {
  const s = run(L.initialState(flat(), { y: 300 }), { throttle: 1 }, 5)
  assert.equal(s.throttle, 1)
  assert.ok(speed(s) > L.CRUISE + 1)
  assert.equal(run(s, { throttle: -1 }, 5).throttle, 0)
})

test('flying through a gate scores, missing it does not', () => {
  const hit = run(L.initialState(flat([{ x: 200, y: 120, gap: 30 }])), {}, 6)
  assert.equal(hit.score, 1)
  assert.deepEqual(hit.results, [true])
  assert.equal(hit.status, 'finished')
  const miss = run(L.initialState(flat([{ x: 200, y: 160, gap: 30 }, { x: 400, y: 120, gap: 30 }])), {}, 12)
  assert.equal(miss.score, 1)
  assert.deepEqual(miss.results, [false, true])
  assert.equal(miss.next, 2)
})

test('hitting the terrain crashes and freezes the state', () => {
  const s = run(run(L.initialState(flat()), { pitch: -1 }, 0.5), {}, 10)
  assert.equal(s.status, 'crashed')
  assert.equal(L.step(s, { throttle: 1 }, DT), s)
})

test('same seed and inputs give identical flights', () => {
  const inputs = Array.from({ length: 1200 }, (_, i) => ({ pitch: [0, 1, 0, -1][(i >> 6) % 4], throttle: i % 300 < 100 ? 1 : 0 }))
  const fly = () => inputs.reduce((s, inp) => L.step(s, inp, DT), L.initialState(L.makeLevel(99)))
  assert.deepEqual(fly(), fly())
})

test('hands-off flight through a generated level is deterministic and ends', () => {
  const fly = () => run(L.initialState(L.makeLevel(7)), {}, 120)
  const s = fly()
  assert.notEqual(s.status, 'flying')
  assert.deepEqual(s, fly())
})
