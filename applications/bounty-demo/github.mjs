import { createHmac, timingSafeEqual, sign, createPrivateKey } from 'node:crypto';

const REPO = /^(?!.*\/\.{1,2}$)[A-Za-z0-9][A-Za-z0-9-]{0,38}\/[A-Za-z0-9_.-]{1,100}$/;
const integer = n => Number.isSafeInteger(n) && n > 0;
const need = (ok, code) => { if (!ok) throw new Error(code); };
const bounded = (s, max) => typeof s === 'string' && s.length > 0 && s.length <= max;
export function verifyWebhook(rawBody, signature, secret) {
  if (!Buffer.isBuffer(rawBody) || rawBody.length > 1048576 || !bounded(secret, 4096) || typeof signature !== 'string' || !/^sha256=[a-f0-9]{64}$/.test(signature)) return false;
  return timingSafeEqual(createHmac('sha256', secret).update(rawBody).digest(), Buffer.from(signature.slice(7), 'hex'));
}
export function createAppJwt({ appId, privateKey, now = Date.now() }) {
  need((typeof appId === 'string' || integer(appId)) && /^[A-Za-z0-9_.-]{1,100}$/.test(String(appId)), 'invalid_app_id');
  need(Number.isSafeInteger(now) && now >= 60000, 'invalid_time');
  const key = createPrivateKey(privateKey);
  need(key.asymmetricKeyType === 'rsa' && key.asymmetricKeyDetails.modulusLength >= 2048, 'invalid_rsa_key');
  const t = Math.floor(now / 1000);
  const parts = [{ alg: 'RS256', typ: 'JWT' }, { iat: t - 60, exp: t + 540, iss: String(appId) }].map(x => Buffer.from(JSON.stringify(x)).toString('base64url'));
  const input = parts.join('.');
  return `${input}.${sign('RSA-SHA256', Buffer.from(input), key).toString('base64url')}`;
}
export function normalizeWebhook(event, payload, { allowedRepositories = [] } = {}) {
  if (!payload || typeof payload !== 'object') return null;
  const repo = payload.repository?.full_name;
  if (!REPO.test(repo ?? '') || !allowedRepositories.includes(repo)) return null;
  const installationId = payload.installation?.id;
  if (!integer(installationId)) return null;
  if (event === 'issues' && ['opened', 'edited', 'closed', 'reopened', 'labeled', 'unlabeled'].includes(payload.action) && integer(payload.issue?.number))
    return { type: 'issue', action: payload.action, repo, installation_id: installationId, issue_number: payload.issue.number };
  if (event === 'check_run' && ['created', 'completed', 'rerequested'].includes(payload.action) && integer(payload.check_run?.id) && /^[a-f0-9]{40}$/.test(payload.check_run?.head_sha ?? ''))
    return { type: 'check_run', action: payload.action, repo, installation_id: installationId, check_run_id: payload.check_run.id, head_sha: payload.check_run.head_sha };
  return null;
}

export class GitHubAppClient {
  #appId; #privateKey; #installations; #fetch; #now;
  constructor({ appId, privateKey, installations, fetch: fetchImpl = globalThis.fetch, now = Date.now }) {
    need(Array.isArray(installations) && installations.length > 0 && typeof fetchImpl === 'function', 'invalid_configuration');
    this.#installations = new Map();
    for (const x of installations) {
      need(REPO.test(x.repo ?? '') && integer(x.installationId) && !this.#installations.has(x.repo), 'invalid_installation_scope');
      this.#installations.set(x.repo, x.installationId);
    }
    this.#appId = appId; this.#privateKey = privateKey; this.#fetch = fetchImpl; this.#now = now;
  }
  async #request(method, path, token, body) {
    let response;
    try {
      response = await this.#fetch(`https://api.github.com${path}`, { method, redirect: 'error', signal: AbortSignal.timeout(15000), headers: { Accept: 'application/vnd.github+json', Authorization: `Bearer ${token}`, 'X-GitHub-Api-Version': '2026-03-10', 'User-Agent': 'dsmack-bounty-demo', ...(body ? { 'Content-Type': 'application/json' } : {}) }, ...(body ? { body: JSON.stringify(body) } : {}) });
    } catch { throw new Error('github_transport_error'); }
    // Never retry a write automatically: an ambiguous response may have committed it.
    if (!response.ok) throw new Error(`github_http_${Number.isInteger(response.status) ? response.status : 0}`);
    try {
      const reader = response.body.getReader(); const chunks = []; let size = 0;
      for (;;) { const { done, value } = await reader.read(); if (done) break; size += value.length; if (size > 1048576) { await reader.cancel(); throw new Error(); } chunks.push(value); }
      return JSON.parse(Buffer.concat(chunks).toString('utf8'));
    } catch { throw new Error('github_invalid_response'); }
  }
  async #token(repo) {
    need(this.#installations.has(repo), 'repository_not_allowed');
    const installation = this.#installations.get(repo);
    const jwt = createAppJwt({ appId: this.#appId, privateKey: this.#privateKey, now: this.#now() });
    const data = await this.#request('POST', `/app/installations/${installation}/access_tokens`, jwt, { repositories: [repo.split('/')[1]], permissions: { issues: 'read', contents: 'read', checks: 'write' } });
    need(bounded(data.token, 4096) && Number.isFinite(Date.parse(data.expires_at)) && Date.parse(data.expires_at) > this.#now() + 60000, 'invalid_installation_token');
    return data.token;
  }
  async readIssue(repo, issueNumber) {
    need(integer(issueNumber), 'invalid_issue_number');
    const token = await this.#token(repo);
    return this.#request('GET', `/repos/${repo}/issues/${issueNumber}`, token);
  }
  async createCheckRun(repo, input) {
    need(input && /^[a-f0-9]{40}$/.test(input.head_sha ?? ''), 'invalid_head_sha');
    return this.#writeCheck(repo, null, input);
  }
  async updateCheckRun(repo, checkRunId, input) {
    need(integer(checkRunId), 'invalid_check_id');
    return this.#writeCheck(repo, checkRunId, input);
  }
  async #writeCheck(repo, id, input) {
    need(input && typeof input === 'object' && Object.keys(input).every(k => ['name', 'head_sha', 'status', 'conclusion', 'output', 'external_id'].includes(k)), 'invalid_check_fields');
    need(bounded(input.name, 100), 'invalid_check_name');
    need(['queued', 'in_progress', 'completed'].includes(input.status), 'invalid_check_status');
    need(input.status === 'completed' ? ['success', 'failure', 'neutral', 'cancelled', 'timed_out', 'action_required', 'skipped'].includes(input.conclusion) : input.conclusion === undefined, 'invalid_check_conclusion');
    if (input.external_id !== undefined) need(bounded(input.external_id, 200), 'invalid_external_id');
    if (input.output !== undefined) need(input.output && Object.keys(input.output).every(k => ['title', 'summary'].includes(k)) && bounded(input.output.title, 200) && bounded(input.output.summary, 10000), 'invalid_check_output');
    if (input.head_sha !== undefined) need(/^[a-f0-9]{40}$/.test(input.head_sha), 'invalid_head_sha');
    const token = await this.#token(repo);
    return this.#request(id ? 'PATCH' : 'POST', `/repos/${repo}/check-runs${id ? `/${id}` : ''}`, token, input);
  }
}
