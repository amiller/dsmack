// Trusted grammar shared by generator admission and browser execution. No eval.
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';

export const LIMITS = Object.freeze({suiteBytes:262144, tests:16, steps:64,
  totalSteps:512, selector:240, text:4096, actionMs:5000, assertionMs:1500,
  wallMs:180000, fileBytes:16*1024*1024, totalBytes:64*1024*1024});
export const FIXTURE = '/apps/board/';
export function requireThat(ok, message) { if (!ok) throw new Error(message); }
export function keys(value, wanted) {
  requireThat(value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).sort().join('\0') === [...wanted].sort().join('\0'), 'unexpected fields');
}
export function canonical(value) {
  if (Array.isArray(value)) return '['+value.map(canonical).join(',')+']';
  if (value !== null && typeof value === 'object') return '{'+Object.keys(value).sort()
    .map(key=>JSON.stringify(key)+':'+canonical(value[key])).join(',')+'}';
  requireThat(value === null || typeof value === 'string' || typeof value === 'boolean'
    || Number.isSafeInteger(value), 'invalid JSON scalar');
  // Reject unpaired UTF-16 surrogates, which Python cannot encode as UTF-8.
  if (typeof value === 'string') requireThat(value.isWellFormed(), 'invalid Unicode');
  return JSON.stringify(value);
}
export const sha = bytes => createHash('sha256').update(bytes).digest('hex');
export function decode(bytes) {
  requireThat(bytes.length > 0 && bytes.length <= LIMITS.suiteBytes, 'suite byte bound');
  return new TextDecoder('utf-8', {fatal:true}).decode(bytes);
}
function text(value, max=LIMITS.text) {
  requireThat(typeof value === 'string' && value.length <= max && value.isWellFormed(), 'text bound');
}
// Deliberately small CSS subset. No selector engines, pseudo selectors, escapes,
// commas, URL syntax, regular expressions, or Playwright's >> / text= grammar.
const atom = '(?:[a-zA-Z][a-zA-Z0-9-]*|\\*)?';
const qualifier = '(?:[.#][a-zA-Z_][a-zA-Z0-9_-]*|\\[[a-zA-Z_][a-zA-Z0-9_-]*(?:="[a-zA-Z0-9 _.-]*")?\\])';
const compound = `(?:${atom}(?:${qualifier})+|[a-zA-Z][a-zA-Z0-9-]*|\\*)`;
const css = new RegExp(`^${compound}(?:(?: | > )${compound}){0,7}$`);
export function selector(value) {
  text(value, LIMITS.selector);
  requireThat(value.length > 0 && css.test(value), 'unsupported CSS selector');
}
export function validateSuite(suite) {
  keys(suite, ['schema','tests']);
  requireThat(suite.schema === 'dsmack-bounty-browser-suite/1', 'suite schema');
  requireThat(Array.isArray(suite.tests) && suite.tests.length > 0 && suite.tests.length <= LIMITS.tests, 'test count');
  let previous = '', total = 0;
  for (const test of suite.tests) {
    keys(test, ['id','steps']);
    requireThat(typeof test.id === 'string' && /^[a-z][a-z0-9-]{0,63}$/.test(test.id)
      && test.id > previous, 'sorted unique test IDs');
    previous = test.id;
    requireThat(Array.isArray(test.steps) && test.steps.length >= 2 && test.steps.length <= LIMITS.steps, 'step count');
    total += test.steps.length;
    requireThat(total <= LIMITS.totalSteps, 'total step count');
    requireThat(test.steps[0]?.op === 'navigate', 'first step must navigate');
    let assertions = 0;
    for (const step of test.steps) {
      requireThat(step && typeof step.op === 'string', 'step operation');
      switch (step.op) {
        case 'navigate': keys(step, ['op','path']); requireThat(step.path === FIXTURE, 'fixture path'); break;
        case 'reload': keys(step, ['op']); break;
        case 'click': keys(step, ['op','selector']); selector(step.selector); break;
        case 'fill': keys(step, ['op','selector','value']); selector(step.selector); text(step.value); break;
        case 'assert_count':
          keys(step, ['op','selector','value']); selector(step.selector);
          requireThat(Number.isSafeInteger(step.value) && step.value >= 0 && step.value <= 1000, 'count bound'); assertions++; break;
        case 'assert_text': case 'assert_value':
          keys(step, ['op','selector','value']); selector(step.selector); text(step.value); assertions++; break;
        case 'assert_attribute':
          keys(step, ['op','selector','name','value']); selector(step.selector); text(step.value);
          requireThat(typeof step.name === 'string' && /^(?:data-[a-z0-9-]+|aria-[a-z0-9-]+|title|disabled)$/.test(step.name), 'attribute name'); assertions++; break;
        case 'assert_visible':
          keys(step, ['op','selector','value']); selector(step.selector);
          requireThat(typeof step.value === 'boolean', 'visibility boolean'); assertions++; break;
        default: throw new Error('unsupported operation');
      }
    }
    requireThat(assertions > 0, 'test needs behavioral assertion');
  }
  return suite;
}
export function parseSuite(bytes, strict=true) {
  const raw = decode(bytes), suite = validateSuite(JSON.parse(raw));
  // Canonical equality also rejects duplicate object keys, floats and alternate
  // encodings. The normalization CLI is only for provider output, never CI input.
  requireThat(!strict || raw === canonical(suite), 'noncanonical suite');
  return suite;
}
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    const bytes = readFileSync(0);
    // Provider JSON must also have no duplicate keys: require canonical input.
    const suite = parseSuite(bytes);
    process.stdout.write(canonical(suite));
  } catch (error) { process.stderr.write(String(error.message)+'\n'); process.exitCode=2; }
}
