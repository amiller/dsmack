# Applications

There is one bounty application, a separate read-only dashboard and an agent
finding runner.

- [bounties/](bounties/README.md): task requests, attempts, evidence submission and
  escrow integration. The current task is [Arcade Board search](bounties/examples/arcade/);
  its checker and task construction live with that example.
- [bounty-dashboard/](bounty-dashboard/README.md): contract state, attempts and
  withdrawals from the configured deployments.
- [agent-findings/](agent-findings/README.md): a pinned Claude Code agent answers
  a question about read-only inputs and records its verdict and transcript.
- [pilot-client/](pilot-client/README.md): shared Mac installation, workload
  preparation, VM launch, evidence verification and cleanup tools.

Start at the bounty application's README to request or perform work. Start at the
client README to integrate another application with the VM runtime.
