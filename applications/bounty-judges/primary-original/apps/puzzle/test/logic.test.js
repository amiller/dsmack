import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { parse, move, undo, play, isWon, moves, pushes, render, interior } from '../logic.js'

const levels = JSON.parse(readFileSync(new URL('../levels.json', import.meta.url)))
const solutions = {
  'First Push': 'rRR',
  'Corner': 'DrdLuuullddR',
  'Two Lanes': 'lLLLrrrddLLL',
  'Pillar': 'rruulDrdLLLrruullDlDRRRurD',
  'Storeroom': 'URdrUluLLDDldR',
  'Warehouse': 'RurrddddlDRuuuuLLLrdRDrddlLdllURlU',
}

test('parse reads walls, goals, boxes and player', () => {
  const s = parse(['#####', '#@$.#', '#####'])
  assert.equal(s.w, 5)
  assert.equal(s.h, 3)
  assert.equal(s.player, 6)
  assert.deepEqual(s.boxes, [7])
  assert.deepEqual([...s.goals], [8])
  assert.equal(s.walls.size, 12)
  assert.equal(moves(s), 0)
})

test('parse handles + and * and ragged rows', () => {
  const s = parse(['####', '#+*#', '#$ #', '###'])
  assert.equal(s.w, 4)
  assert.equal(s.player, 5)
  assert.deepEqual([...s.goals].sort(), [5, 6])
  assert.deepEqual(s.boxes, [6, 9])
})

test('parse rejects malformed levels', () => {
  assert.throws(() => parse(['#$.#']), /no player/)
  assert.throws(() => parse(['#@@$..#']), /more than one player/)
  assert.throws(() => parse(['#@$$.#']), /2 boxes but 1 goals/)
  assert.throws(() => parse(['#@x$.#']), /bad tile 'x'/)
})

test('render round-trips every level', () => {
  for (const lv of levels) assert.deepEqual(render(parse(lv.map)), lv.map.map(r => r.trimEnd()), lv.name)
})

test('walking moves the player and counts moves', () => {
  const s = move(parse(['#####', '#@ .#', '#$  #', '#####']), 'r')
  assert.deepEqual(render(s), ['#####', '# @.#', '#$  #', '#####'])
  assert.equal(moves(s), 1)
  assert.equal(pushes(s), 0)
})

test('walls block movement and return the same state', () => {
  const s = parse(['#####', '#@$.#', '#####'])
  for (const d of 'udl') assert.equal(move(s, d), s)
})

test('moves off the map edge are blocked', () => {
  const s = parse(['@$.'])
  assert.equal(move(s, 'l'), s)
  assert.equal(move(s, 'u'), s)
})

test('pushing moves a box and counts a push', () => {
  const s = move(parse(['######', '#@$ .#', '######']), 'r')
  assert.deepEqual(render(s), ['######', '# @$.#', '######'])
  assert.equal(pushes(s), 1)
  assert.deepEqual(s.history, ['R'])
})

test('cannot push a box into a wall', () => {
  const s = parse(['#####', '# @$#', '#.  #', '#####'])
  assert.equal(move(s, 'r'), s)
})

test('cannot push two boxes', () => {
  const s = parse(['#######', '#@$$..#', '#######'])
  assert.equal(move(s, 'r'), s)
})

test('cannot push a box off the edge of an open map', () => {
  const s = parse(['.@$'])
  assert.equal(move(s, 'r'), s)
})

test('move rejects unknown directions', () => {
  assert.throws(() => move(parse(['@$.']), 'x'), /bad direction/)
})

test('move does not mutate the previous state', () => {
  const s = parse(['######', '#@$ .#', '######'])
  const before = render(s)
  play(s, 'rr')
  assert.deepEqual(render(s), before)
  assert.equal(moves(s), 0)
})

test('win detection', () => {
  assert.equal(isWon(parse(['#@*#'])), true)
  const s = parse(['#@$.#'])
  assert.equal(isWon(s), false)
  assert.equal(isWon(move(s, 'r')), true)
})

test('play throws on a blocked move', () => {
  assert.throws(() => play(parse(['#@$.#']), 'l'), /blocked move 'l' at step 0/)
})

for (const lv of levels) {
  test(`level "${lv.name}" is won by its known solution`, () => {
    const sol = solutions[lv.name]
    assert.ok(sol, `no solution recorded for ${lv.name}`)
    const s0 = parse(lv.map)
    assert.equal(isWon(s0), false)
    const won = play(s0, sol)
    assert.equal(isWon(won), true)
    assert.equal(moves(won), sol.length)
    assert.equal(pushes(won), [...sol].filter(c => c === c.toUpperCase()).length)
    assert.equal(won.history.join(''), sol)
    assert.equal(isWon(undo(won)), false)
  })
}

test('every level has a recorded solution', () => {
  assert.deepEqual(levels.map(l => l.name).sort(), Object.keys(solutions).sort())
})

test('undo reverses walks and pushes exactly', () => {
  for (const lv of levels) {
    const states = [parse(lv.map)]
    for (const c of solutions[lv.name]) states.push(move(states.at(-1), c.toLowerCase()))
    let s = states.at(-1)
    for (let i = states.length - 2; i >= 0; i--) {
      s = undo(s)
      assert.deepEqual(render(s), render(states[i]), `${lv.name} step ${i}`)
      assert.equal(moves(s), i)
    }
  }
})

test('undo at the start is a no-op', () => {
  const s = parse(['#@$.#'])
  assert.equal(undo(s), s)
})

test('blocked moves are not recorded in history', () => {
  const s = parse(['#####', '#@$.#', '#####'])
  assert.equal(moves(move(move(s, 'u'), 'l')), 0)
})

test('interior excludes the empty outside of a level', () => {
  const s = parse([' ###', '##@#', '#$.#', '####'])
  assert.deepEqual([...interior(s)].sort((a, b) => a - b), [6, 9, 10])
})
