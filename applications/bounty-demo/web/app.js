/* Same-origin pilot client. Tokens are deliberately held only in this closure. */
(() => {
  'use strict';
  const $ = (id) => document.getElementById(id);
  const states = new Set(['open', 'claimed', 'running', 'submitted', 'verified', 'failed']);
  const phases = ['launch', 'boot', 'pull', 'agent', 'review', 'verify', 'done'];
  const phaseLabels = {launch: 'launch requested', boot: 'guest booting', pull: 'image setup', agent: 'harness ready', review: 'review activity', verify: 'verification activity', done: 'guest stopped'};
  const capabilities = new Map();
  let operatorToken = '';
  let selectedId = null;
  let detail = null;
  let detailKey = '';
  let displayedTaskId = null;
  let tasks = [];
  let refreshing = false;
  let detailRequest = 0;
  let lastDetailCheck = null;
  let detailUnavailable = false;
  let chainPending = false;
  let annotations = {};
  let showRetired = false;
  const node = (tag, text, cls) => {
    const n = document.createElement(tag);
    if (text !== undefined && text !== null) n.textContent = String(text);
    if (cls) n.className = cls;
    return n;
  };
  function button(text, callback, cls = 'button') {
    const b = node('button', text, cls);
    b.type = 'button';
    b.addEventListener('click', callback);
    return b;
  }
  function badge(value, extra = '') {
    return node('span', value || 'Unknown', `badge ${states.has(value) ? value : extra}`);
  }
  function notice(message, error = false) {
    $('notice').textContent = message;
    $('notice').className = error ? 'notice error' : 'notice';
    $('notice').hidden = false;
  }
  function message(error) { return error instanceof Error ? error.message : 'The request failed. Please try again.'; }
  async function api(path, {method = 'GET', body, token, signal} = {}) {
    const headers = {Accept: 'application/json'};
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    if (token) headers.Authorization = `Bearer ${token}`;
    const response = await fetch(path, {method, headers, body: body === undefined ? undefined : JSON.stringify(body), cache: 'no-store', credentials: 'omit', redirect: 'error', signal});
    let data;
    try { data = await response.json(); } catch { throw new Error('The service returned an unreadable response. Check that the application server is running.'); }
    if (!response.ok) {
      const help = response.status === 401 || response.status === 403 ? ' Check your operator token or attempt capability.' : '';
      throw new Error(`${typeof data.error === 'string' ? data.error : `Request rejected (${response.status})`}${help}`);
    }
    return data;
  }
  function timestamp(value) {
    const date = new Date(typeof value === 'number' ? value * 1000 : value);
    return Number.isNaN(date.getTime()) ? 'Time unavailable' : date.toLocaleString();
  }
  function fact(list, label, value) {
    const pair = node('div');
    pair.append(node('dt', label), node('dd', value === undefined || value === null || value === '' ? 'Not provided' : value));
    list.append(pair);
  }
  function panel(title, description) {
    const p = node('section', null, 'panel');
    const h = node('div', null, 'panel-head');
    const copy = node('div');
    copy.append(node('h3', title));
    if (description) copy.append(node('p', description));
    h.append(copy); p.append(h);
    return p;
  }
  function field(form, title, name, options = {}) {
    const label = node('label', title, options.full ? 'full' : '');
    const input = node('input'); input.name = name; input.required = true;
    input.type = options.type || 'text'; input.autocomplete = 'off'; input.spellcheck = false;
    if (options.placeholder) input.placeholder = options.placeholder;
    if (options.pattern) input.pattern = options.pattern;
    if (options.maxLength) input.maxLength = options.maxLength;
    label.append(input); form.append(label); return input;
  }
  function formError(form, error) {
    let target = form.querySelector('.form-error');
    if (!target) { target = node('p', null, 'form-error'); target.setAttribute('role', 'alert'); form.append(target); }
    target.textContent = message(error); target.hidden = false;
  }
  async function submitForm(form, operation) {
    const submit = form.querySelector('[type="submit"]');
    if (submit) submit.disabled = true;
    const error = form.querySelector('.form-error'); if (error) error.hidden = true;
    try { await operation(); } catch (e) { formError(form, e); }
    finally { if (submit) submit.disabled = false; }
  }
  function showCreate() {
    $('advanced-setup').open = true;
    $('create-error').hidden = true;
    if (!$('task-dialog').open) $('task-dialog').showModal();
  }
  async function loadBoard() {
    const data = await api('/api/tasks');
    if (!Array.isArray(data.tasks)) throw new Error('The service did not return a task list.');
    tasks = data.tasks;
    annotations = data.annotations || {};
    renderBoard();
    if (!selectedId && tasks.length) await selectTask((tasks.find(t=>!annotations[t.id])||tasks[0]).id);
  }
  function renderBoard() {
    $('task-list').replaceChildren();
    $('board-summary').textContent = `${tasks.length} task${tasks.length === 1 ? '' : 's'} · invitations managed by the operator`;
    $('board-empty').hidden = tasks.length !== 0;
    const retired = tasks.filter(t=>annotations[t.id]).length;
    const toggle=$('retired-toggle');toggle.hidden=retired===0;toggle.textContent=`${showRetired?'Hide':'Show'} retired pilot history (${retired})`;toggle.setAttribute('aria-pressed',String(showRetired));
    for (const task of tasks.filter(t=>showRetired||!annotations[t.id]||t.id===selectedId)) {
      const b = button('', () => selectTask(task.id).catch((e) => notice(message(e), true)), 'task-card');
      b.setAttribute('aria-current', String(task.id === selectedId));
      b.append(badge(task.state), node('h2', task.title || task.id));
      if(annotations[task.id])b.append(badge('Retired · operator note'));
      const footer = node('div', null, 'card-foot');
      footer.append(node('span', task.repo, 'small muted'), node('span', task.reward ? `${task.reward.amount} ${task.reward.asset}` : 'Terms unavailable', 'small'));
      b.append(footer); $('task-list').append(b);
    }
  }
  async function selectTask(id) {
    selectedId = id;
    detailKey = '';
    renderBoard();
    await refreshDetail();
  }
  async function refreshDetail() {
    if (!selectedId) return;
    const id = selectedId;
    const request = ++detailRequest;
    let data;
    try { data = await api(`/api/tasks/${encodeURIComponent(id)}`); }
    catch (error) { if (selectedId === id && request === detailRequest) { detailUnavailable = true; renderConnection(); } throw error; }
    if (selectedId !== id || request !== detailRequest) return;
    if (!data.task) throw new Error('Task details are unavailable. Refresh the task board.');
    lastDetailCheck = Date.now(); detailUnavailable = false;
    const previousAttempt = detail?.attempt;
    detail = data;
    if(data.annotation)annotations[id]=data.annotation;else delete annotations[id];
    if (previousAttempt?.id === data.attempt?.id && previousAttempt?.state !== data.attempt?.state) {
      if (data.attempt?.state === 'verified') notice('Result verified by the configured authority. Check the separate chain observation for payment status.');
      if (data.attempt?.state === 'failed') notice('The service recorded a failed verification outcome. Check the separate chain observation for account activity.', true);
    }
    const index = tasks.findIndex((t) => t.id === id);
    if (index >= 0) tasks[index] = data.task;
    renderBoard();
    // Polling must not erase partially entered candidate digests or move focus.
    const key = JSON.stringify([id, data.task.state, data.attempt?.id, data.attempt?.state, data.attempt?.candidate_sha256, data.attempt?.bundle_sha256, data.attempt?.verdict, data.annotation]);
    if (key !== detailKey) {
      const sameTask = displayedTaskId === data.task.id;
      const pending = sameTask ? [...$('task-detail').querySelectorAll('input[name]')].map((input) => ({name: input.name, value: input.value, focused: input === document.activeElement, start: input.selectionStart, end: input.selectionEnd})) : [];
      detailKey = key; renderDetail();
      for (const saved of pending) {
        const input = [...$('task-detail').querySelectorAll('input[name]')].find((item) => item.name === saved.name);
        if (!input) continue;
        input.value = saved.value;
        if (saved.focused) { input.focus({preventScroll: true}); if (saved.start !== null) input.setSelectionRange(saved.start, saved.end); }
      }
    }
    renderProgress(); renderConnection();
    void refreshChain();
  }
  async function refreshChain() {
    if(chainPending || !selectedId)return;
    const id=selectedId;chainPending=true;
    try {
      const observation=await api(`/api/tasks/${encodeURIComponent(id)}/chain`,{signal:AbortSignal.timeout(15000)});
      if(selectedId===id)renderChain(observation);
    } catch {if(selectedId===id)renderChain({status:'unknown'});}
    finally {chainPending=false;}
  }
  function renderChain(value) {
    const slot=$('chain-content');if(!slot)return;slot.replaceChildren();
    if(value.status!=='observed'){
      slot.append(node('p',value.status==='not_configured'?'No onchain mapping configured. Reward funding and payment are unconfirmed.':value.status==='stale'?'Chain information is stale. Current funding and payment are unknown.':'Chain information is unavailable. Current funding and payment are unknown.'));
      return;
    }
    slot.append(node('p',`${value.network} · observed at ${timestamp(value.observed_at)} · block ${value.block_number} · ${value.minimum_confirmations} confirmations. This RPC observation is not a finality proof.`));
    const facts=node('dl',null,'facts');
    fact(facts,'Escrow available (wei)',value.funding.available_wei);fact(facts,'Assignment reserved (wei)',value.funding.reserved_wei);
    fact(facts,'Account credit (wei)',value.credit.withdrawable_wei);fact(facts,'Credit owner',value.credit.account);
    slot.append(facts);
    for(const event of value.events){
      const row=node('p',`${event.kind}: ${event.amount_wei} wei · `);
      // Construct explorer links from a validated transaction hash only.
      if(/^0x[a-f0-9]{64}$/.test(event.transaction_hash)){const link=node('a','View transaction');link.href='https://sepolia.basescan.org/tx/'+event.transaction_hash;link.target='_blank';link.rel='noopener noreferrer';row.append(link);}
      slot.append(row);
    }
    slot.append(node('p','Resolution credits an account; withdrawal transfers account funds. Withdrawals can combine several rewards and are not attributed to this task by amount alone.','small muted'));
  }
  function renderConnection() {
    const target = $('connection-status'); if (!target) return;
    target.textContent = detailUnavailable ? `Updates unavailable. Showing retained service state${lastDetailCheck ? ` last checked ${new Date(lastDetailCheck).toLocaleTimeString()}` : ''}. Refresh to reconnect; this does not mean the Mac or agent stopped.` : `Service state last checked ${lastDetailCheck ? new Date(lastDetailCheck).toLocaleTimeString() : 'just now'}. This page does not connect directly to your Mac.`;
    target.className = `small ${detailUnavailable ? 'connection-stale' : 'muted'}`;
  }
  function readinessPanel(task, attempt) {
    const p = panel('Your next step', 'An invitation and a local runner are separate. This page never imports your coding subscription.'); p.classList.add('next-step');
    let title, description;
    if(detail.annotation){
      const note=detail.annotation;
      p.append(node('h4','Retired pilot · operator note'),node('p','The operator has stopped work under these terms because the broker transport is incompatible with the planned long-response generation stage. Do not start another worker run. Original terms, evidence and actual assignment state remain unchanged.'),node('p','This note does not establish a failed model job, acceptance, refund eligibility or payment. Inspect the independent chain observation below.','small muted'),node('p',`Operator note recorded ${timestamp(note.noted_at)}`,'small muted'));
      if(note.replacement)p.append(button('Open replacement task',()=>selectTask(note.replacement.task_id).catch(e=>notice(message(e),true))));
      return p;
    }
    if (!attempt) { title = 'Inspect the task, then request an invitation'; description = 'Open the issue and frozen terms. Check the chain panel for funding before spending subscription allowance. Ask the operator for the reviewed runner, diagnostic and exact launch recipe before spending subscription allowance.'; }
    else if (attempt.state === 'verified') { title = 'Review the accepted result'; description = 'The configured verification authority accepted this result. Keep the attempt record and evidence. Acceptance does not establish payment; inspect the separate chain observation for credit and withdrawals.'; }
    else if (attempt.state === 'failed') { title = 'Inspect the recorded verification failure'; description = 'Ask the operator to identify a candidate failure, missing evidence or verification infrastructure problem. Retain the same candidate and evidence for inspection; do not start another model job just to reconnect.'; }
    else if (attempt.state === 'submitted') { title = 'Await independent verification'; description = 'Your candidate identities are submitted. Keep the evidence and saved attempt record. Verification retries should use retained outputs; refreshing this page does not launch another coding run.'; }
    else if (capabilities.has(attempt.id)) { title = 'Continue with your local runner'; description = 'This tab has an attempt capability. Use the separately reviewed local launch recipe, then review its candidate and submit the retained source and evidence identities below. The browser cannot tell whether your Mac is ready or launch it for you.'; }
    else { title = 'Reconnect your saved attempt'; description = 'Use Open saved attempt above to reopen the protected CLI record for this server. If the record says claim-requested, retry the identical CLI claim with the same file first. A public task ID cannot restore a lost capability.'; }
    p.append(node('h4', title), node('p', description));
    const facts = node('dl', null, 'readiness-grid');
    fact(facts, 'Assignment', attempt ? `Assigned to ${attempt.worker}` : 'Operator invitation required');
    fact(facts, 'This tab', attempt && capabilities.has(attempt.id) ? 'Attempt capability loaded locally' : 'No attempt capability connected');
    fact(facts, 'Mac runner', 'Browser connection not available');
    fact(facts, 'Reward', 'Check the separate chain observation below');
    p.append(facts); const status = node('p', null, 'small muted'); status.id = 'connection-status'; p.append(status);
    return p;
  }
  function renderDetail() {
    const {task, attempt} = detail;
    displayedTaskId = task.id;
    const article = $('task-detail'); article.replaceChildren(); article.hidden = false; $('detail-empty').hidden = true;
    const heading = node('header', null, 'task-heading');
    const badges = node('div', null, 'badges'); badges.append(badge(task.state), badge('Funding: see chain observation', 'unfunded'));
    heading.append(badges, node('h2', task.title || task.id));
    const meta = node('div', null, 'task-meta');
    if (typeof task.repo === 'string' && /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(task.repo) && task.repo.split('/').every((part) => !['.', '..'].includes(part)) && Number.isSafeInteger(task.issue_number) && task.issue_number > 0) {
      const link = node('a', `${task.repo} #${task.issue_number} ↗`);
      link.href = `https://github.com/${task.repo.split('/').map(encodeURIComponent).join('/')}/issues/${task.issue_number}`;
      link.target = '_blank'; link.rel = 'noopener noreferrer'; meta.append(link);
    } else meta.append(node('span', task.repo));
    meta.append(node('span', `Task / ${task.id}`)); heading.append(meta); article.append(heading);
    const reward = node('div', null, 'reward-bar');
    const amount = node('div'); amount.append(node('div', 'Proposed reward', 'eyebrow'), node('p', task.reward ? `${task.reward.amount} ${task.reward.asset}` : 'Not provided', 'reward-amount'));
    amount.append(node('p', task.reward?.chain || 'Chain not specified', 'small muted'));
    reward.append(amount, node('p', 'Proposed terms. Check the separate chain observation for funding, credit and withdrawals.', 'small muted')); article.append(reward);
    const terms = node('details', null, 'panel'); terms.append(node('summary', 'Inspect frozen task terms'));
    const facts = node('dl', null, 'facts');
    for (const [label, key] of [['Base commit', 'base_commit'], ['Terms SHA-256', 'terms_sha256'], ['Acceptance checker SHA-256', 'checker_sha256'], ['Base image SHA-256', 'image_sha256'], ['Coding harness SHA-256', 'harness_sha256']]) fact(facts, label, task[key]);
    terms.append(facts); article.append(terms);
    article.append(readinessPanel(task, attempt)); renderConnection();
    const chain=panel('Onchain funding & withdrawals','Read-only observations from the operator-selected contract. This page never signs a transaction.');const chainSlot=node('div','Checking chain information…');chainSlot.id='chain-content';chain.append(chainSlot);article.append(chain);
    if (!attempt) {
      if (task.state === 'open' && !detail.annotation) article.append(claimPanel(task));
      else article.append(panel('No attempt available', 'The service returned no current attempt for this task. Refresh or ask the operator to inspect its state.'));
      return;
    }
    const who = panel('Current attempt', 'One assignment. A separate evidence check decides whether the result is accepted.');
    const af = node('dl', null, 'facts columns');
    for (const [label, value] of [['Worker', attempt.worker], ['Payee', attempt.payee], ['Attempt', attempt.id], ['Started', timestamp(attempt.created_at)]]) fact(af, label, value);
    who.append(af); article.append(who);
    const progress = panel('Attempt activity', 'Advisory worker telemetry · refreshed every two seconds during an active attempt. Progress and counters do not prove execution or authorize a reward.');
    const slot = node('div'); slot.id = 'progress-content'; progress.append(slot); article.append(progress);
    if (attempt.state === 'submitted' || attempt.state === 'verified' || attempt.state === 'failed') {
      const submitted = panel('Submitted candidate', 'Submission identities are immutable. A Git commit is a presentation reference, not the source-content digest.');
      const sf = node('dl', null, 'facts'); fact(sf, 'Candidate SHA-256', attempt.candidate_sha256); fact(sf, 'Evidence bundle SHA-256', attempt.bundle_sha256);
      if (attempt.commit_sha) fact(sf, 'Git commit', attempt.commit_sha);
      submitted.append(sf); article.append(submitted);
    } else if(!detail.annotation) article.append(submissionPanel(attempt));
    const outcomes = panel('Verification & reward', 'Draft verification integration. Independent evidence acceptance and payment are separate events.');
    const grid = node('div', null, 'verdict-grid');
    const verification = node('div', null, 'verdict-cell'); verification.append(node('h3', attempt.state === 'verified' ? 'Verified result' : attempt.state === 'failed' ? 'Result not accepted' : 'Verification pending'));
    verification.append(node('p', attempt.state === 'verified' ? 'The service accepted a certificate from its configured verification authority.' : attempt.state === 'failed' ? 'The service recorded a failed verification outcome. Ask the operator to inspect the authenticated verdict.' : 'Worker submissions and progress cannot set a verified outcome. Await the configured verification adapter.'));
    const payment = node('div', null, 'verdict-cell'); payment.append(node('h3', 'Payment is separate'), node('p', 'See the onchain observation for escrow, account credit and withdrawals. Verification alone does not establish payment.'));
    grid.append(verification, payment); outcomes.append(grid); article.append(outcomes);
  }
  function claimPanel(task) {
    const p = panel('Join this bounty', 'Ready to help? Ask the operator for an invitation using this task ID. Inspect the runner and frozen acceptance terms before providing your subscription locally.');
    const advanced = node('details'); advanced.append(node('summary', 'Operator invitation'));
    advanced.append(node('p', 'Operator access is required to assign a worker. The payee address records a destination; wallet ownership and payment are not established.', 'small muted'));
    const form = node('form'); const grid = node('div', null, 'form-grid');
    const worker = field(grid, 'Worker label', 'worker', {placeholder: 'Your worker or agent label', maxLength: 120});
    const payee = field(grid, 'Payee address', 'payee', {placeholder: '0x…', pattern: '0x[a-fA-F0-9]{40}', maxLength: 42});
    form.append(grid);
    p.append(node('p', 'Recommended: claim with the local CLI using --out in a private directory, then Open saved attempt above. The CLI retains a recoverable request before sending it. Browser-only invitations below cannot recover a lost response.', 'small muted'));
    const actions = node('div', null, 'form-actions'); actions.append(node('span', 'Browser-only capability stays in this tab’s memory.', 'small muted'));
    const submit = node('button', 'Claim task', 'button primary'); submit.type = 'submit'; actions.append(submit); form.append(actions);
    form.addEventListener('submit', (event) => { event.preventDefault(); submitForm(form, async () => {
      if (!operatorToken) throw new Error('Open Operator tools and enter an operator token before inviting a worker.');
      const result = await api(`/api/tasks/${encodeURIComponent(task.id)}/claim`, {method: 'POST', token: operatorToken, body: {worker: worker.value.trim(), payee: payee.value.trim()}});
      if (!result.attempt?.id || typeof result.token !== 'string') throw new Error('The claim response did not include an attempt capability. Ask the operator to inspect the assignment before retrying.');
      capabilities.set(result.attempt.id, result.token);
      notice('Task claimed. Its attempt capability is available only in this tab; reloading loses it.');
      await refreshDetail();
    }); }); advanced.append(form); p.append(advanced); return p;
  }
  function submissionPanel(attempt) {
    const p = panel('Submit a candidate', 'Use the exact source-content and retained evidence-bundle digests. This sends a submission; it does not verify the result.');
    if (!capabilities.has(attempt.id)) {
      const connect = node('form', null, 'inline-form');
      const input = field(connect, 'Existing attempt capability', 'capability', {type: 'password', placeholder: 'Paste a capability you already hold'});
      const submit = node('button', 'Use capability', 'button'); submit.type = 'submit'; connect.append(submit);
      connect.addEventListener('submit', (event) => { event.preventDefault(); if (!input.value.trim()) return; capabilities.set(attempt.id, input.value.trim()); input.value = ''; renderDetail(); renderProgress(); });
      p.append(connect, node('p', 'Capabilities are not returned by task lookup. If yours is lost, ask the operator for the recovery policy.', 'small muted')); return p;
    }
    const form = node('form'); const grid = node('div', null, 'form-grid');
    const candidate = field(grid, 'Candidate SHA-256', 'candidate_sha256', {full: true, pattern: '[a-f0-9]{64}', maxLength: 64});
    const bundle = field(grid, 'Evidence bundle SHA-256', 'bundle_sha256', {full: true, pattern: '[a-f0-9]{64}', maxLength: 64});
    const commit = field(grid, 'Git commit (optional)', 'commit_sha', {full: true, pattern: '[a-f0-9]{40}', maxLength: 40}); commit.required = false;
    form.append(grid); const actions = node('div', null, 'form-actions');
    actions.append(node('span', 'An identical retry is safe; a conflicting submission is rejected.', 'small muted'));
    const submit = node('button', 'Submit for verification', 'button primary'); submit.type = 'submit'; actions.append(submit); form.append(actions);
    form.addEventListener('submit', (event) => { event.preventDefault(); submitForm(form, async () => {
      const body = {candidate_sha256: candidate.value.trim(), bundle_sha256: bundle.value.trim()};
      if (commit.value.trim()) body.commit_sha = commit.value.trim();
      await api(`/api/attempts/${encodeURIComponent(attempt.id)}/submit`, {method: 'POST', token: capabilities.get(attempt.id), body});
      notice('Candidate submitted. Verification is pending; no reward has been paid.'); await refreshDetail();
    }); });
    p.append(node('p', 'Attempt capability connected · memory only', 'small muted'), form); return p;
  }
  function renderProgress() {
    const target = $('progress-content'); if (!target || !detail) return;
    target.replaceChildren();
    const events = Array.isArray(detail.events) ? detail.events : [];
    const phase = events.length ? events[events.length - 1].phase : null;
    const strip = node('div', null, 'phase-strip');
    for (const value of phases) strip.append(node('span', phaseLabels[value], `phase-chip${value === phase ? ' active' : ''}`));
    target.append(strip);
    const last = events.at(-1);
    if (last) {
      const age = Number.isFinite(last.received_at) ? (Date.now() / 1000 - last.received_at) : null;
      const freshness = age === null ? 'Last signal time unavailable' : age < -30 ? 'Signal timestamp is ahead of this browser’s clock' : age > 30 ? `Last advisory signal ${Math.floor(age)} seconds ago · may be stale` : `Last advisory signal ${Math.max(0, Math.floor(age))} seconds ago`;
      target.append(node('p', freshness, `signal-status small${age > 30 ? ' connection-stale' : ' muted'}`), node('p', 'Signals come from the worker or host observer. A heartbeat shows the observer is responding; it does not prove model progress. Missing signals do not prove the run stopped.', 'small muted'));
    }
    if (!events.length) { target.append(node('p', 'No progress events yet. The worker’s agent can report advisory events through its attempt API.', 'small muted')); return; }
    const timeline = node('ol', null, 'timeline');
    for (const item of events.slice(-12).reverse()) {
      const row = node('li'); const top = node('div', null, 'event-top'); top.append(node('strong', `${phaseLabels[item.phase] || item.phase} / ${item.kind}`), node('span', timestamp(item.received_at), 'small muted')); row.append(top);
      const counters = [];
      for (const key of ['turns', 'input_tokens', 'output_tokens', 'elapsed_ms']) {
        const value = item.counters?.[key];
        if (Number.isSafeInteger(value) && value >= 0 && value < 1e12) counters.push(`${key.replaceAll('_', ' ')} ${value.toLocaleString()}`);
      }
      row.append(node('div', `#${item.seq} · advisory${counters.length ? ` · ${counters.join(' / ')}` : ''}`, 'event-detail')); timeline.append(row);
    }
    target.append(timeline);
  }
  $('operator-form').addEventListener('submit', (event) => {
    event.preventDefault(); operatorToken = $('operator-token').value.trim(); $('operator-token').value = '';
    $('operator-status').textContent = operatorToken ? 'Operator token in memory' : 'No operator token';
  });
  $('saved-attempt').addEventListener('change', async () => {
    const input = $('saved-attempt'); const file = input.files[0]; input.value = '';
    if (!file) return;
    try {
      if (file.size > 16384) throw new Error();
      const v = JSON.parse(await file.text());
      const keys = ['schema','state','server','task_id','worker','payee','request_id','capability','attempt_id'];
      if (!v || typeof v !== 'object' || Array.isArray(v) || Object.keys(v).length !== keys.length || keys.some(k => !Object.hasOwn(v,k))) throw new Error();
      if (keys.some(k => typeof v[k] !== 'string') || v.schema !== 'dsmack-bounty-attempt/1' || v.state !== 'claimed' || v.server !== location.origin || !/^[a-z0-9-]{1,80}$/.test(v.task_id) || !/^[a-f0-9]{32}$/.test(v.attempt_id) || !/^[a-f0-9]{64}$/.test(v.request_id) || !/^0x[a-f0-9]{40}$/.test(v.payee) || typeof v.worker !== 'string' || !v.worker.length || v.worker.length > 80 || /[\x00-\x1f\x7f]/.test(v.worker) || typeof v.capability !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(v.capability) || !/[AEIMQUYcgkosw048]$/.test(v.capability)) throw new Error();
      const current = await api(`/api/tasks/${encodeURIComponent(v.task_id)}`);
      if (current.attempt?.id !== v.attempt_id || current.attempt?.task_id !== v.task_id || current.attempt?.worker !== v.worker || current.attempt?.payee !== v.payee) throw new Error();
      capabilities.set(v.attempt_id, v.capability);
      await selectTask(v.task_id);
      $('saved-attempt-status').textContent = 'Saved attempt connected in this tab. Keep the protected original file for future reconnects.';
    } catch { $('saved-attempt-status').textContent = 'Could not open this record. Use a claimed CLI record for this exact server and assignment; retry an unresolved claim with the CLI first.'; }
  });
  $('clear-token').addEventListener('click', () => {
    operatorToken = ''; capabilities.clear(); $('operator-token').value = ''; $('operator-status').textContent = 'No operator token';
    if (detail) { renderDetail(); renderProgress(); }
    notice('Operator token and attempt capabilities cleared from this tab.');
  });
  $('new-task').addEventListener('click', showCreate); $('empty-new-task').addEventListener('click', showCreate);
  $('close-dialog').addEventListener('click', () => $('task-dialog').close());
  $('create-form').addEventListener('submit', (event) => { event.preventDefault(); const form = event.currentTarget; submitForm(form, async () => {
    if (!operatorToken) throw new Error('Close this form, then enter an operator token in Operator tools before creating a task.');
    const values = Object.fromEntries(new FormData(form));
    const body = Object.fromEntries(['id', 'repo', 'title', 'base_commit', 'checker_sha256', 'image_sha256', 'harness_sha256'].map((key) => [key, values[key].trim()]));
    body.issue_number = Number(values.issue_number); body.reward = {amount: values.amount.trim(), asset: values.asset.trim(), chain: values.chain.trim()};
    await api('/api/tasks', {method: 'POST', token: operatorToken, body});
    $('task-dialog').close(); form.reset(); selectedId = body.id; detailKey = '';
    await loadBoard(); await refreshDetail(); notice('Task created with unfunded reward terms. No money moved.');
  }); });
  $('retired-toggle').addEventListener('click',()=>{showRetired=!showRetired;renderBoard();});
  $('refresh').addEventListener('click', () => loadBoard().then(refreshDetail).catch((e) => notice(message(e), true)));
  loadBoard().catch((e) => { $('board-summary').textContent = 'Unable to load tasks'; notice(message(e), true); });
  setInterval(async () => {
    if (!document.hidden && detail) { renderProgress(); renderConnection(); void refreshChain(); }
    if (document.hidden || refreshing || !selectedId || ['verified', 'failed'].includes(detail?.attempt?.state)) return;
    refreshing = true;
    try { await refreshDetail(); } catch (e) { notice(`Live updates paused: ${message(e)} Use Refresh to retry.`, true); }
    finally { refreshing = false; }
  }, 2000);
})();
