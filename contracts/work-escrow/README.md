# WorkEscrow

Source of the bounty escrow deployed on Base Sepolia at
`0x62fedc157f275abb8f8b4543696e6f0c717d391b` (used by `applications/bounties`).
Built with solc 0.8.21, optimizer 200 runs, no via-IR; the runtime bytecode matches
the deployed code apart from the metadata tail.

```sh
forge test --root contracts/work-escrow --offline
```
