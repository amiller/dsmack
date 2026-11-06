import { test } from 'node:test';
import assert from 'node:assert/strict';
import { referenceError, replyFailure, retryCandidate, meteredReply, settleInterruptedReply, failOrphanedTools } from './reply-recovery.mjs';

test('offline, browser, broker, provider and credit failures identify an action', () => {
  const offline = replyFailure(Error('network error'), { partial: true, online: false });
  assert.equal(offline.category, 'offline');assert.match(offline.message, /Reconnect.*Retry/);
  const broken = replyFailure(Error('network error'), { partial: true, online: true });
  assert.equal(broken.category, 'browser');assert.equal(broken.interrupted, true);
  assert.match(broken.message, /browser lost its connection.*background.*Retry/);
  const unavailable = replyFailure(Object.assign(Error('Service unavailable'), {status:503}));
  assert.equal(unavailable.category, 'broker');assert.match(unavailable.message, /Broker returned HTTP 503.*Retry/);
  const provider = replyFailure(Object.assign(Error('failed'), {code:'PROVIDER_UNAVAILABLE',status:502}));
  assert.equal(provider.category, 'provider');assert.match(provider.message, /NEAR AI.*Retry/);
  const credit = replyFailure(Error('CREDIT_EXHAUSTED: insufficient'));
  assert.equal(credit.category, 'credit');assert.equal(credit.retryable, false);assert.match(credit.message,/Chat credit used up/);
  assert.equal(replyFailure(Error('BUDGET_EXHAUSTED: cap')).category, 'credit');
  assert.equal(replyFailure(Error('REQUEST_IN_FLIGHT: pending')).category, 'credit');
  const pending = replyFailure(Error('USAGE_PENDING: unknown'));
  assert.equal(pending.category, 'credit');assert.match(pending.message, /Reconcile provider usage.*cannot start until it settles/);
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
  assert.match(meteredReply({dispatched:true,settled:false}),/not yet confirmed.*ledger first/);
  assert.match(meteredReply({dispatched:true,settled:true,costNanoUsd:'300000'}),/\$0.000300.*new metered request/);
  assert.match(meteredReply({dispatched:false}),/not sent; no model charge/);
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

test('duplicate delivery and invalid provider JSON identify recovery actions and codes', () => {
  for (const code of ['REQUEST_REPLAY', 'REQUEST_ALREADY_DISPATCHED']) {
    const failure = replyFailure(Object.assign(Error('already sent'), {code}));
    assert.match(failure.message, new RegExp(code));
    assert.match(failure.message, /Reconcile provider usage.*Retry/);
    assert.equal(failure.retryable, true);
  }
  const failure = replyFailure(Error('[api.invalid_input] Cloud API client input request body is invalid: invalid_json'));
  assert.match(failure.message, /api.invalid_input.*invalid_json.*Send again.*another browser/);
  assert.equal(failure.retryable, true);
  assert.match(replyFailure(Error('BAD_REQUEST: invalid message')).message, /BAD_REQUEST.*Send again/);
});

test('request refs survive actionable provider, replay and network error rendering exactly once', () => {
  for (const code of ['PROVIDER_UNAVAILABLE','REQUEST_ALREADY_DISPATCHED','BAD_REQUEST']) {
    const failure=replyFailure(Object.assign(Error(`${code}: refused (ref 1234abcd)`),{code,ref:'1234abcd'}));
    assert.match(failure.message,/ref 1234abcd/);
    assert.equal(failure.message.match(/ref 1234abcd/g).length,1);
    assert.match(failure.message,/Retry|Send again/);
  }
  const broken=replyFailure(Object.assign(Error('connection lost'),{ref:'1234abcd',status:502}),{partial:true});
  assert.match(broken.message,/Retry.*ref 1234abcd/);
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
  assert.match(guest.message, /Mac guest disconnected.*may have run/);
  const busy = replyFailure(Object.assign(Error('busy'), { code: 'FLEET_BUSY', status: 503, retryAfterSeconds: 7 }));
  assert.equal(busy.message, 'All Macs are busy, retry in 7 seconds.');
  assert.match(replyFailure(Object.assign(Error('empty'), { code: 'FLEET_EMPTY', status: 503 })).message, /No Macs are connected/);
  const http = replyFailure(Object.assign(Error('refused'), { status: 409, code: 'BAD_REQUEST', ref: '1234abcd' }));
  assert.match(http.message, /Broker returned HTTP 409.*BAD_REQUEST.*ref 1234abcd/);
  const usage = replyFailure(Object.assign(Error('This usage check was already sent. Retry with a new signed request.'), { status: 409, code: 'REQUEST_ALREADY_SENT' }));
  assert.match(usage.message, /HTTP 409.*REQUEST_ALREADY_SENT.*already sent/);
  assert.doesNotMatch(usage.message, /waiting for|Reconcile provider/);
  const browser = replyFailure(referenceError(new TypeError('Failed to fetch'), 'a21a5fd5'));
  assert.equal(browser.category, 'browser');
  assert.doesNotMatch(browser.message, /broker.*restarting/i);
});
