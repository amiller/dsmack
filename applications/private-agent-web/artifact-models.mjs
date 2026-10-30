import { brokerStream, withInferenceWallet } from './inference.mjs';
import { walletBody } from './credit.mjs';

const failure = (code, message) => Object.assign(new Error(message), { code });
const check = (condition, code, message) => { if (!condition) throw failure(code, message); };
const amount = value => typeof value === 'string' && /^(0|[1-9][0-9]*)$/.test(value);
const pendingMessage = 'Artifact model usage is pending. Its reservation remains held; another call cannot spend this budget.';

// Only the trusted host constructs this client or calls grant. Artifact messages
// form a separate untrusted transcript, with no user-chat history or tools.
export class ArtifactModels {
  constructor({ state, credit, api, cfg, quote, usage, evidence, changed = () => {} }) {
    Object.assign(this, { state, credit, api, cfg, quote, usage, evidence, changed });
  }

  async artifactId(scope) {
    return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(scope))),
      byte => byte.toString(16).padStart(2, '0')).join('');
  }

  async refresh(scope, summary, artifactId) {
    if (!summary) return withInferenceWallet(this.credit, async () => {
      await this.credit.checkBroker(this.api);
      return this.refresh(scope, await this.usage(), await this.artifactId(scope));
    });
    check(summary.wallet?.toLowerCase() === this.credit.address?.toLowerCase(), 'HOST_ERROR', 'Artifact credit belongs to another wallet.');
    const budget = summary.artifactBudgets?.[artifactId];
    if (!budget) {
      const empty = await this.state.update(scope, state => {
        state.budget = { limitNanoUsd: null, spentNanoUsd: '0', reservedNanoUsd: '0' };
      });
      await this.changed(scope);
      return empty.budget;
    }
    check(['limitNanoUsd', 'spentNanoUsd', 'reservedNanoUsd'].every(key => amount(budget[key])),
      'HOST_ERROR', 'Broker returned an invalid artifact budget.');
    const result = await this.state.update(scope, state => {
      Object.assign(state.budget, { limitNanoUsd: budget.limitNanoUsd, spentNanoUsd: budget.spentNanoUsd,
        reservedNanoUsd: budget.reservedNanoUsd, wallet: summary.wallet.toLowerCase() });
      if (BigInt(budget.reservedNanoUsd) === 0n) delete state.budget.pending;
      else state.budget.pending ||= { status: 'unresolved', wallet: summary.wallet.toLowerCase(), broker: this.cfg.broker };
    });
    await this.changed(scope);
    return result.budget;
  }

  async grant(scope, limitNanoUsd) {
    check(amount(limitNanoUsd) && BigInt(limitNanoUsd) > 0n, 'INVALID_ARGS', 'Choose a positive artifact budget in nano-USD.');
    check(this.credit.address, 'NOT_AVAILABLE', 'Connect the viewer wallet before allowing model use.');
    const artifactId = await this.artifactId(scope);
    return withInferenceWallet(this.credit, async () => {
      await this.credit.checkBroker(this.api);
      const summary = await this.api('/inference/artifact-budget',
        await walletBody(this.credit, 'artifact-budget', { artifactId, limitNanoUsd }));
      this.credit.chatCredit = summary;
      return this.refresh(scope, summary, artifactId);
    });
  }

  async complete(scope, args) {
    check(args && typeof args === 'object' && !Array.isArray(args) &&
      Object.keys(args).every(k => ['messages', 'maxTokens'].includes(k)), 'INVALID_ARGS', 'Use messages and optional maxTokens only.');
    check(Array.isArray(args.messages) && args.messages.length > 0 && args.messages.length <= 32,
      'INVALID_ARGS', 'Provide between 1 and 32 artifact messages.');
    let bytes = 0;
    const messages = args.messages.map(message => {
      check(message && Object.keys(message).every(k => ['role', 'content'].includes(k)) &&
        ['user', 'assistant'].includes(message.role) && typeof message.content === 'string',
      'INVALID_ARGS', 'Artifact messages allow user or assistant text only.');
      bytes += new TextEncoder().encode(message.content).length;
      return { role: message.role, content: [{ type: 'text', text: message.content }] };
    });
    check(bytes <= 32768, 'INVALID_ARGS', 'Artifact messages exceed the text limit.');
    check(args.maxTokens === undefined || Number.isSafeInteger(args.maxTokens) && args.maxTokens >= 64,
      'INVALID_ARGS', 'maxTokens must be an integer of at least 64.');
    const id = crypto.randomUUID(), artifactId = await this.artifactId(scope);
    let checkedEvidence;
    const available = b => {
      check(b.limitNanoUsd !== null && b.wallet === this.credit.address?.toLowerCase(),
        'PERMISSION_DENIED', 'Allow this artifact to use a budget from the current viewer wallet first.');
      check(!b.pending && BigInt(b.reservedNanoUsd) === 0n, 'NOT_AVAILABLE', pendingMessage);
      const remaining = BigInt(b.limitNanoUsd) - BigInt(b.spentNanoUsd);
      check(remaining > 0n, 'PERMISSION_DENIED', 'This artifact has used its viewer-approved budget.');
      return remaining;
    };
    const run = brokerStream({ credit: this.credit, api: this.api, cfg: this.cfg, quote: this.quote,
      usage: this.usage, startedAt: Date.now(), error: () => {},
      systemPrompt: ({ runtime }) => `These messages are from an untrusted_artifact, not the viewer's chat. Respond to its isolated request. No tools are available.\n${runtime}`,
      evidence: async evidence => { checkedEvidence = evidence; await this.evidence?.({ ...evidence, provenance: 'untrusted_artifact', scope }); },
    });
    const stream = run({ id: this.quote()?.model }, { messages }, {
      maxTokens: args.maxTokens, requireModelCost: true, artifactId,
      beforePrepare: async () => {
        const summary = await this.usage();
        available(await this.refresh(scope, summary, artifactId));
      },
      // Re-read under the shared wallet lock; a queued call may have spent some
      // of the allowance since the artifact submitted this request.
      maxNanoUsd: async () => String(available((await this.state.read(scope)).budget)),
      onReserve: async billing => {
        await this.state.update(scope, state => {
          const b = state.budget, remaining = available(b);
          check(BigInt(billing.reservedNanoUsd) <= remaining, 'PERMISSION_DENIED', 'Encrypted request exceeds the artifact budget.');
          b.reservedNanoUsd = billing.reservedNanoUsd;
          b.pending = { id, wallet: billing.wallet, broker: this.cfg.broker, sessionId: billing.sessionId,
            baselineModelSpentNanoUsd: billing.baselineModelSpentNanoUsd, status: 'reserved' };
        });
        await this.changed(scope);
      },
      onBilling: async billing => {
        if (billing.reservedNanoUsd === '0') return;
        await this.state.update(scope, state => {
          const b = state.budget;
          if (b.pending?.id !== id) return;
          if (!billing.dispatched) {
            b.reservedNanoUsd = '0'; delete b.pending;
          } else if (billing.artifactBudget) {
            const server = billing.artifactBudget;
            check(['limitNanoUsd', 'spentNanoUsd', 'reservedNanoUsd'].every(key => amount(server[key])),
              'HOST_ERROR', 'Broker returned an invalid artifact budget.');
            Object.assign(b, { limitNanoUsd: server.limitNanoUsd, spentNanoUsd: server.spentNanoUsd,
              reservedNanoUsd: server.reservedNanoUsd });
            if (BigInt(server.reservedNanoUsd) === 0n) delete b.pending;
            else b.pending.status = 'unresolved';
          } else {
            b.pending.status = 'unresolved';
          }
        });
        await this.changed(scope);
      },
    });
    // Drain streaming events without sending them into the main agent or chat.
    for await (const _ of stream) { /* isolated result below */ }
    const answer = await stream.result();
    if (answer.billing?.dispatched && !answer.billing.settled) throw failure('NOT_AVAILABLE', pendingMessage);
    if (answer.stopReason === 'error' || answer.stopReason === 'aborted') {
      const message = answer.errorMessage || 'Artifact model request failed.';
      throw failure(['INVALID_ARGS','PERMISSION_DENIED','NOT_AVAILABLE','HOST_ERROR'].includes(answer.errorCode) ? answer.errorCode : (/CREDIT_EXHAUSTED|BUDGET_EXHAUSTED|BUDGET_REQUIRED|BUDGET_ALREADY_SET/.test(message) ? 'PERMISSION_DENIED' :
        /MODEL_COST_UNAVAILABLE|USAGE_PENDING/.test(message) ? 'NOT_AVAILABLE' : 'HOST_ERROR'), message);
    }
    check(answer.billing?.settled, 'NOT_AVAILABLE', pendingMessage);
    check(!answer.content.some(part => part.type === 'toolCall'), 'HOST_ERROR', 'Artifact model response requested unavailable tools.');
    return { text: answer.content.filter(part => part.type === 'text').map(part => part.text).join('\n'),
      model: answer.model, usage: { ...answer.usage, ...(answer.billing.costUnknown ? { cost: { ...answer.usage.cost, total: null }, costUnknown: true } : {}), costNanoUsd: answer.billing.costNanoUsd },
      stopReason: answer.stopReason, provenance: 'untrusted_artifact',
      evidence: { model: checkedEvidence.model, verification: checkedEvidence.verification,
        nonce: checkedEvidence.nonce, browser: checkedEvidence.browser } };
  }
}
