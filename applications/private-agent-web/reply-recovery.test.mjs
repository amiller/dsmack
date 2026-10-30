import { test } from 'node:test';
import assert from 'node:assert/strict';
import { replyFailure, retryCandidate, meteredReply, settleInterruptedReply } from './reply-recovery.mjs';

test('offline, broker restart, provider and credit failures identify an action', () => {
  const offline = replyFailure(Error('network error'), { partial: true, online: false });
  assert.equal(offline.category, 'offline');assert.match(offline.message, /Reconnect.*Retry/);
  const broken = replyFailure(Error('network error'), { partial: true, online: true });
  assert.equal(broken.category, 'broker');assert.equal(broken.interrupted, true);
  assert.equal(broken.message, 'Connection lost mid-reply — the server may have restarted. Retry');
  const unavailable = replyFailure(Object.assign(Error('Service unavailable'), {status:503}));
  assert.equal(unavailable.category, 'broker');assert.match(unavailable.message, /restarting.*Retry.*503/);
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
