# Roadmap

The [charter](charter.md) requires actual peer-to-peer operation and explicit
limits on privileged control. Public issues track implementation and acceptance;
private research and historical receipts are kept outside this source tree.

| Work | Outcome |
| --- | --- |
| [Friend feedback](https://github.com/amiller/dsmack/issues/1) | Installed Linux recipient journey with useful private inference |
| [Release packet](https://github.com/amiller/dsmack/issues/2) | Accepted Mac issuer, public artifacts and bounded operations |
| [Optimistic redemption](https://github.com/amiller/dsmack/issues/4) | Explicit provisional authorization and failure handling |
| [Network status](https://github.com/amiller/dsmack/issues/6) | Fresh observations and honest healthy/stale/unknown states |
| [Inference routing](https://github.com/amiller/dsmack/issues/8) | Useful routed responses, admission, reservations and recovery |
| [Discovery](https://github.com/amiller/dsmack/issues/9) | Public acquisition and service lookup |
| [Second-peer custody](https://github.com/amiller/dsmack/pull/10) | Joining and threshold-custody requirements under review |

## First release

The selected preview uses a Mac issuer and direct NEAR delivery: Abalone redeems
a coupon, receives a capped sponsor-managed credential and sends encrypted requests
to the provider. Fresh Mac admission, the final bundle and independent friend
acceptance remain pending. See [release gates](release.md).

The sponsor retains revocation/account powers. Identity-only admission does not
prove operator-resistant secret custody, rollback protection or anonymous funding.
Provider update exceptions must remain visible. Incognito needs no VPN.

## Funding, routing and custody

Funding and delivery are separate choices. Pool-owned capacity and owner-controlled
contributions require their own authority, recovery and accounting policies.
Stake principal is not immediately spendable inference credit without a qualified
adapter. Wallet funding does not by itself establish anonymous redemption.

Routed access needs atomic budget reservations, settlement of actual usage and
quarantine of ambiguous paid effects. Do not automatically replay a possibly paid
request or send it to another supplier as a free retry. Apply privacy, attestation,
model identity and price caps before selecting for latency.

Direct model E2EE and issuer credential custody are separate claims. A NEAR host
adapter used as a router would read prompts; a recipient-encrypted relay needs
separate implementation and qualification. Threshold custody, independent peers,
stronger platform isolation and additional providers have their own evidence gates.
