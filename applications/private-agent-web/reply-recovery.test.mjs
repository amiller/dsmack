import { test } from 'node:test';
import assert from 'node:assert/strict';
import { referenceError, replyFailure, retryCandidate, meteredReply, settleInterruptedReply, failOrphanedTools } from './reply-recovery.mjs';

test('offline, browser, broker, provider and credit failures identify an action', () => {
  const offline = replyFailure(Error('network error'), { partial: true, online: false });
  assert.equal(offline.category, 'offline');assert.equal(offline.retryable, true);
  const broken = replyFailure(Error('network error'), { partial: true, online: true });
  assert.equal(broken.category, 'browser');assert.equal(broken.interrupted, true);
  const unavailable = replyFailure(Object.assign(Error('Service unavailable'), {status:503}));
  assert.equal(unavailable.category, 'broker');assert.equal(unavailable.retryable, true);
  const provider = replyFailure(Object.assign(Error('failed'), {code:'PROVIDER_UNAVAILABLE',status:502}));
  assert.equal(provider.category, 'provider');assert.equal(provider.retryable, true);
  const credit = replyFailure(Error('CREDIT_EXHAUSTED: insufficient'));
  assert.equal(credit.category, 'credit');assert.equal(credit.retryable, false);
  assert.equal(replyFailure(Error('BUDGET_EXHAUSTED: cap')).category, 'credit');
  assert.equal(replyFailure(Error('REQUEST_IN_FLIGHT: pending')).category, 'credit');
  const pending = replyFailure(Error('USAGE_PENDING: unknown'));
  assert.equal(pending.category, 'credit');assert.equal(pending.retryable, true);
});

test('delayed settlement updates the saved reply only for its exact wallet and session', () => {
  const reply = {billing:{dispatched:true,settled:false,sessionId:'first',wallet:'0x123',reservedNanoUsd:'1000000'},usage:{cost:{total:0}}};
  const ledger = {wallet:'0x123',pendingInferenceId:null,lastModelCharge:{sessionId:'other-device',costNanoUsd:'700000'}};
  assert.equal(settleInterruptedReply(reply,ledger),false);
  assert.equal(reply.billing.settled,false);
  ledger.lastModelCharge.sessionId='first';
  assert.equal(settleInterruptedReply(reply,{...ledger,pendingInferenceId:'waiting'}),false);
  assert.equal(settleInterruptedReply(reply,{...ledger,wallet:'0x456'}),false);
  assert.equal(settleInterruptedReply(reply,ledger),true);
  assert.equal(reply.billing.costNanoUsd,'700000');assert.equal(reply.usage.cost.total,0.0007);
  assert.equal(reply.billing.exactModelCost,true);assert.equal(reply.billing.settled,true);
});

test('retry is offered only for the latest retryable failed assistant and distinguishes unresolved charges', () => {
  const failed = {role:'assistant',stopReason:'error',failure:replyFailure(Error('network error'),{partial:true})};
  assert.equal(retryCandidate([{role:'user'},failed]), failed);
  assert.equal(retryCandidate([failed,{role:'user'}]), undefined);
  assert.equal(retryCandidate([{...failed,stopReason:'stop'}]), undefined);
  assert.match(meteredReply({dispatched:true,settled:true,costNanoUsd:'300000'}),/\$0.0003/);
  assert.doesNotMatch(meteredReply({dispatched:false}),/\$/);
});

test('cancelled replies allow retry and unfinished calls get one failed result', () => {
  const cancelled = { role: 'assistant', stopReason: 'aborted', failure: replyFailure(new DOMException('Request aborted', 'AbortError')), content: [] };
  assert.equal(retryCandidate([cancelled]), cancelled);
  const messages = [{ role: 'assistant', content: [
    { type: 'toolCall', id: 'lost', name: 'bash' }, { type: 'toolCall', id: 'done', name: 'read' }] },
    { role: 'toolResult', toolCallId: 'done', isError: false }];
  failOrphanedTools(messages, 'Guest disconnected; execution was not retried.');
  failOrphanedTools(messages, 'Must not replace the result.');
  const lost = messages.filter(m => m.toolCallId === 'lost');
  assert.equal(lost.length, 1);
  assert.equal(lost[0].isError, true);
  assert.match(lost[0].content[0].text, /Guest disconnected/);
  assert.equal(messages.filter(m => m.toolCallId === 'done').length, 1);
  const lostReply = { ...cancelled, content: [{ type: 'toolCall', id: 'cancelled', name: 'bash' }] };
  const history = [lostReply];
  failOrphanedTools(history, 'Cancelled');
  assert.equal(retryCandidate(history), lostReply);
});

test('duplicate delivery and invalid provider JSON remain retryable', () => {
  for (const code of ['REQUEST_REPLAY', 'REQUEST_ALREADY_DISPATCHED']) {
    const failure = replyFailure(Object.assign(Error('already sent'), {code}));
    assert.equal(failure.category, 'credit');
    assert.equal(failure.retryable, true);
  }
  const failure = replyFailure(Error('[api.invalid_input] Cloud API client input request body is invalid: invalid_json'));
  assert.equal(failure.category, 'provider');
  assert.equal(failure.retryable, true);
  assert.equal(replyFailure(Error('BAD_REQUEST: invalid message')).category, 'request');
});

test('server codes, HTTP statuses and request refs stay in diagnostics rather than visible errors', () => {
  for (const code of ['PROVIDER_UNAVAILABLE','REQUEST_ALREADY_DISPATCHED','BAD_REQUEST','CREDIT_EXHAUSTED']) {
    const failure = replyFailure(Object.assign(Error(`${code}: refused (ref 1234abcd)`), {code,ref:'1234abcd',status:403}));
    assert.match(failure.detail, new RegExp(code));
    assert.match(failure.detail, /1234abcd/);
    assert.match(failure.detail, /403/);
    assert.doesNotMatch(failure.message, new RegExp(`${code}|1234abcd|403`));
  }
  const failure = replyFailure(Error('Node challenge mismatch. Stale attestation refused.'));
  assert.equal(failure.category, 'verification');
  assert.doesNotMatch(failure.message, /challenge|attestation/i);
  assert.match(failure.detail, /challenge mismatch/);
});


test('attaching an API ref preserves an abort with a read-only DOMException message', () => {
  const aborted=new DOMException('The operation was aborted.','AbortError');
  const linked=referenceError(aborted,'1234abcd');
  assert.equal(linked.name,'AbortError');
  assert.equal(linked.code,aborted.code);
  assert.equal(linked.cause,aborted);
  assert.equal(linked.ref,'1234abcd');
  assert.match(linked.message,/ref 1234abcd/);
  assert.equal(aborted.message,'The operation was aborted.');
  assert.equal(referenceError(aborted,undefined),aborted);
});


test('guest closure and busy capacity cannot be confused with a broker restart or an empty fleet', () => {
  const guest = replyFailure(Error('Guest stream closed before a result was received.'));
  assert.equal(guest.category, 'guest');
  assert.equal(guest.retryable, true);
  const busy = replyFailure(Object.assign(Error('busy'), { code: 'FLEET_BUSY', status: 503, retryAfterSeconds: 7 }));
  assert.equal(busy.category, 'capacity');
  const counted = replyFailure(referenceError(Object.assign(Error('All 4 slots on the Dsmack network are busy; retrying in 7s'), { code: 'FLEET_BUSY', status: 503 }), '1234abcd'));
  assert.match(counted.message, /4 slots/);
  assert.match(counted.message, /7s$/);
  assert.doesNotMatch(counted.message, /FLEET_BUSY|HTTP|ref /);

  assert.equal(replyFailure(Object.assign(Error('empty'), { code: 'FLEET_EMPTY', status: 503 })).category, 'capacity');
  const http = replyFailure(Object.assign(Error('refused'), { status: 409, code: 'BAD_REQUEST', ref: '1234abcd' }));
  assert.equal(http.category, 'broker');
  const usage = replyFailure(Object.assign(Error('This usage check was already sent. Retry with a new signed request.'), { status: 409, code: 'REQUEST_ALREADY_SENT' }));
  assert.equal(usage.category, 'broker');
  const browser = replyFailure(referenceError(new TypeError('Failed to fetch'), 'a21a5fd5'));
  assert.equal(browser.category, 'browser');
  assert.doesNotMatch(browser.message, /broker.*restarting/i);
});

test('NEAR HTTP status and structured cause reach the retry message', () => {
  for (const [code, text, retryable] of [
    ['PROVIDER_HTTP_402_INSUFFICIENT_CREDIT', 'NEAR AI returned 402 (insufficient credit).', false],
    ['PROVIDER_HTTP_402_CREDIT_EXHAUSTED', 'NEAR AI returned 402 (credit exhausted).', false],
    ['PROVIDER_HTTP_401', 'NEAR AI returned 401 (authentication failed).', false],
    ['PROVIDER_HTTP_429_RATE_LIMIT', 'NEAR AI returned 429 (rate limit).', true],
    ['PROVIDER_HTTP_503', 'NEAR AI returned 503.', true],
  ]) {
    const result = replyFailure(Error(`${code}: refused`));
    assert.equal(result.category, 'provider');
    assert.equal(result.message, text);
    assert.equal(result.retryable, retryable);
  }
});


test('attested transport failures remain distinct from rejected attestation evidence', () => {
  const failure = replyFailure(Object.assign(Error('NEAR_ATTESTATION_TRANSPORT'), { code: 'NEAR_ATTESTATION_TRANSPORT' }));
  assert.equal(failure.category, 'provider');
  assert.match(failure.message, /attested connection/);
});
