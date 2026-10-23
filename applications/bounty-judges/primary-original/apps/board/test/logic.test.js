import { test } from 'node:test'
import assert from 'node:assert/strict'
import { applyAction, emptyBoard, validate, neighbour, findCard } from '../logic.js'

const run = (actions, board = emptyBoard()) => actions.reduce(applyAction, board)
const texts = (board, col) => board.columns[col].map(c => c.text)

test('add appends cards with sequential ids and trimmed text', () => {
  const b = run([{ type: 'add', column: 'todo', text: ' a ' }, { type: 'add', column: 'todo', text: 'b' }, { type: 'add', column: 'done', text: 'c' }])
  assert.deepEqual(b.columns.todo, [{ id: 'c1', text: 'a' }, { id: 'c2', text: 'b' }])
  assert.deepEqual(b.columns.done, [{ id: 'c3', text: 'c' }])
  assert.equal(b.nextId, 4)
})

test('add rejects empty text and unknown columns', () => {
  assert.throws(() => run([{ type: 'add', column: 'todo', text: '   ' }]), /non-empty/)
  assert.throws(() => run([{ type: 'add', column: 'later', text: 'x' }]), /no column later/)
})

test('applyAction does not mutate its input', () => {
  const b = run([{ type: 'add', column: 'todo', text: 'a' }])
  const snapshot = structuredClone(b)
  run([{ type: 'edit', id: 'c1', text: 'z' }, { type: 'move', id: 'c1', to: 'done' }, { type: 'add', column: 'todo', text: 'q' }], b)
  assert.deepEqual(b, snapshot)
})

test('edit changes text in place and keeps position', () => {
  const b = run([{ type: 'add', column: 'todo', text: 'a' }, { type: 'add', column: 'todo', text: 'b' }, { type: 'edit', id: 'c1', text: 'A' }])
  assert.deepEqual(texts(b, 'todo'), ['A', 'b'])
  assert.throws(() => applyAction(b, { type: 'edit', id: 'c9', text: 'x' }), /no card c9/)
  assert.throws(() => applyAction(b, { type: 'edit', id: 'c1', text: '' }), /non-empty/)
})

test('delete removes the card and never reuses its id', () => {
  const b = run([{ type: 'add', column: 'todo', text: 'a' }, { type: 'delete', id: 'c1' }, { type: 'add', column: 'todo', text: 'b' }])
  assert.deepEqual(b.columns.todo, [{ id: 'c2', text: 'b' }])
  assert.throws(() => applyAction(b, { type: 'delete', id: 'c1' }), /no card c1/)
})

test('move appends to target column by default', () => {
  const b = run([
    { type: 'add', column: 'todo', text: 'a' }, { type: 'add', column: 'doing', text: 'b' },
    { type: 'move', id: 'c1', to: 'doing' },
  ])
  assert.deepEqual(texts(b, 'todo'), [])
  assert.deepEqual(texts(b, 'doing'), ['b', 'a'])
})

test('move with index reorders within and across columns', () => {
  const base = run(['a', 'b', 'c'].map(text => ({ type: 'add', column: 'todo', text })))
  assert.deepEqual(texts(applyAction(base, { type: 'move', id: 'c3', to: 'todo', index: 0 }), 'todo'), ['c', 'a', 'b'])
  assert.deepEqual(texts(applyAction(base, { type: 'move', id: 'c1', to: 'todo', index: 2 }), 'todo'), ['b', 'c', 'a'])
  const across = run([{ type: 'add', column: 'done', text: 'x' }, { type: 'move', id: 'c2', to: 'done', index: 0 }], base)
  assert.deepEqual(texts(across, 'done'), ['b', 'x'])
  assert.throws(() => applyAction(base, { type: 'move', id: 'c1', to: 'todo', index: 3 }), /bad index/)
  assert.throws(() => applyAction(base, { type: 'move', id: 'c1', to: 'nowhere' }), /no column/)
})

test('neighbour steps across columns and stops at the edges', () => {
  assert.equal(neighbour('todo', 1), 'doing')
  assert.equal(neighbour('done', -1), 'doing')
  assert.equal(neighbour('todo', -1), undefined)
  assert.equal(neighbour('done', 1), undefined)
})

test('findCard reports column and index', () => {
  const b = run([{ type: 'add', column: 'doing', text: 'a' }, { type: 'add', column: 'doing', text: 'b' }])
  assert.deepEqual(findCard(b, 'c2'), { col: 'doing', index: 1, card: { id: 'c2', text: 'b' } })
})

test('unknown action types throw', () => {
  assert.throws(() => applyAction(emptyBoard(), { type: 'archive' }), /unknown action archive/)
})

test('export/import round-trips through JSON', () => {
  const b = run([{ type: 'add', column: 'todo', text: 'a' }, { type: 'add', column: 'done', text: 'b' }, { type: 'move', id: 'c1', to: 'doing' }])
  const imported = applyAction(emptyBoard(), { type: 'import', board: JSON.parse(JSON.stringify(b)) })
  assert.deepEqual(imported, b)
  assert.equal(applyAction(imported, { type: 'add', column: 'todo', text: 'c' }).columns.todo[0].id, 'c3')
})

const valid = () => ({ nextId: 3, columns: { todo: [{ id: 'c1', text: 'a' }], doing: [], done: [{ id: 'c2', text: 'b' }] } })

test('validate accepts a well-formed board', () => {
  assert.deepEqual(validate(valid()), valid())
  assert.deepEqual(validate(emptyBoard()), emptyBoard())
})

const invalid = {
  'null': null,
  'array': [],
  'missing nextId': (({ nextId, ...b }) => b)(valid()),
  'zero nextId': { ...valid(), nextId: 0 },
  'fractional nextId': { ...valid(), nextId: 2.5 },
  'missing column': { nextId: 3, columns: { todo: [], doing: [] } },
  'extra column': { nextId: 3, columns: { ...valid().columns, later: [] } },
  'column not array': { nextId: 3, columns: { ...valid().columns, doing: {} } },
  'card missing text': { nextId: 3, columns: { ...valid().columns, doing: [{ id: 'c9' }] } },
  'card extra field': { nextId: 3, columns: { ...valid().columns, todo: [{ id: 'c1', text: 'a', due: 1 }] } },
  'empty text': { nextId: 3, columns: { ...valid().columns, todo: [{ id: 'c1', text: ' ' }] } },
  'non-string text': { nextId: 3, columns: { ...valid().columns, todo: [{ id: 'c1', text: 5 }] } },
  'malformed id': { nextId: 3, columns: { ...valid().columns, todo: [{ id: 'x1', text: 'a' }] } },
  'id not below nextId': { ...valid(), nextId: 2 },
  'duplicate id': { nextId: 3, columns: { ...valid().columns, doing: [{ id: 'c1', text: 'dup' }] } },
}

for (const [name, board] of Object.entries(invalid)) {
  test(`validate rejects: ${name}`, () => {
    assert.throws(() => validate(board), /invalid board/)
    assert.throws(() => applyAction(emptyBoard(), { type: 'import', board }), /invalid board/)
  })
}
