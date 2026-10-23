export const COLUMNS = [['todo', 'To do'], ['doing', 'Doing'], ['done', 'Done']]
const IDS = COLUMNS.map(([id]) => id)

export const emptyBoard = () => ({ nextId: 1, columns: { todo: [], doing: [], done: [] } })

export function findCard(board, id) {
  for (const col of IDS) {
    const index = board.columns[col].findIndex(c => c.id === id)
    if (index >= 0) return { col, index, card: board.columns[col][index] }
  }
  throw new Error(`no card ${id}`)
}

function cleanText(text) {
  if (typeof text !== 'string' || !text.trim()) throw new Error('card text must be non-empty')
  return text.trim()
}

function column(id) {
  if (!IDS.includes(id)) throw new Error(`no column ${id}`)
  return id
}

const clone = board => ({ nextId: board.nextId, columns: Object.fromEntries(IDS.map(c => [c, board.columns[c].map(card => ({ ...card }))])) })

export function applyAction(board, action) {
  const next = clone(board)
  const cols = next.columns
  switch (action.type) {
    case 'add':
      cols[column(action.column)].push({ id: `c${next.nextId++}`, text: cleanText(action.text) })
      return next
    case 'edit':
      findCard(next, action.id).card.text = cleanText(action.text)
      return next
    case 'delete': {
      const { col, index } = findCard(next, action.id)
      cols[col].splice(index, 1)
      return next
    }
    // index is the position in the target column after the card is removed from its source.
    case 'move': {
      const { col, index, card } = findCard(next, action.id)
      const to = column(action.to)
      cols[col].splice(index, 1)
      const at = action.index ?? cols[to].length
      if (!Number.isInteger(at) || at < 0 || at > cols[to].length) throw new Error(`bad index ${at}`)
      cols[to].splice(at, 0, card)
      return next
    }
    case 'import':
      return clone(validate(action.board))
    default:
      throw new Error(`unknown action ${action.type}`)
  }
}

// Column to the left/right of col (delta -1/+1), undefined at the edges.
export const neighbour = (col, delta) => IDS[IDS.indexOf(column(col)) + delta]

export function validate(board) {
  const fail = msg => { throw new Error(`invalid board: ${msg}`) }
  if (!board || typeof board !== 'object' || Array.isArray(board)) fail('not an object')
  if (!Number.isInteger(board.nextId) || board.nextId < 1) fail('nextId must be a positive integer')
  const cols = board.columns
  if (!cols || typeof cols !== 'object' || Object.keys(cols).sort().join() !== [...IDS].sort().join()) fail(`columns must be exactly ${IDS.join(', ')}`)
  const seen = new Set()
  for (const col of IDS) {
    if (!Array.isArray(cols[col])) fail(`column ${col} is not an array`)
    for (const card of cols[col]) {
      if (!card || typeof card !== 'object' || Object.keys(card).sort().join() !== 'id,text') fail('card must have exactly id and text')
      const m = /^c(\d+)$/.exec(card.id)
      if (!m || Number(m[1]) >= board.nextId) fail(`bad card id ${card.id}`)
      if (seen.has(card.id)) fail(`duplicate card id ${card.id}`)
      seen.add(card.id)
      if (typeof card.text !== 'string' || !card.text.trim()) fail(`card ${card.id} has empty text`)
    }
  }
  return board
}

// Search returns ordered IDs; it never changes the persisted board.
export function filterBoard(board, query) {
  const needle = query.trim().toLowerCase()
  return Object.fromEntries(COLUMNS.map(([column]) => [column, board.columns[column]
    .filter(card => card.text.toLowerCase().includes(needle)).map(card => card.id)]))
}
