---
status: superseded for the relay-broker (2026-11-07)
date: 2026-11-03
---

# Base Sepolia reads use ordered RPC failover

> **Superseded for the relay-broker (dsmack#101).** The broker's chain reads, meaning guest admission (App Attest keys,
> CDRegistry, canary, code pins, UsageEscrow class and broker signer), `/payments/classes` and deposit credit
> (`syncBalance`), now go through layover-chain (`chainRead`, https://pod.dstack.soc1024.com/layover-chain). That
> service answers only what its Helios OP-stack light client verified. `payments/helios-reader.mjs` pins every read
> to one verified block hash at least 30 blocks behind the verified head. It refuses a reply that is not marked
> `helios-opstack`, that is pinned to another block, that ignored the requested depth, or that comes from a head older
> than 120 s. The broker no longer uses a public RPC for any of these reads. Helios still gives no finalized head, so
> deposits are read 30 blocks (about 6 s) behind the unsafe head, and an L2 reorg deeper than that is not covered.
> Tools that submit transactions (`register-class.mjs`, `submit.mjs`) and the continuity anchor still use the reader
> below.

Public RPC rate limits and differing finalized heights were refusing Mac
registrations even when one provider was healthy.

Use one healthy Base Sepolia provider, with ordered failover and per-provider
exponential backoff for HTTP 429 and JSON-RPC quota errors. Honor `Retry-After`.
Keep chain ID, finalized height/freshness, deployed code hash and EIP-1898
canonical block pins. A replacement snapshot provider must match its block
number and hash. Receipt confirmation still checks the transaction block hash.
Contract reverts propagate immediately. Exhausted providers remain an error.

Helios has a [Base Sepolia configuration](https://github.com/a16z/helios/blob/master/opstack/src/config.rs),
but its [OP consensus client](https://github.com/a16z/helios/blob/master/opstack/src/consensus.rs)
authenticates unsafe sequencer gossip and never sends a finalized block.
It cannot supply the finalized snapshots used to authorize deposit credit.
Use the failover reader until a light client supplies authenticated finalized
Base Sepolia headers. The fallback trusts the selected public RPC for state;
block pinning prevents mixing snapshots, and code pins retain contract identity.
Before this change one lying public provider was outvoted. Now a single provider
answers the broker's trust reads: deposits and exit requests that become credit
(`payments.mjs` `syncBalance`), node class measurements and broker signer
(`register`), and the App Attest enrollment key, CDRegistry rpIdHash, category
and canary reads used for guest admission. By default the list is the configured
`rpc` followed by the public providers. A lying provider could mint credit or
admit a guest that is not attested. This is accepted for the testnet only.

The page retains its existing reader.
