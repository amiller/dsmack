# Coupon deposit mechanics experiment

`CouponDepositExperiment.sol` is an offline reference state machine, not a
deployable production settlement policy. No chain, live funds, contract address,
hardware verifier or accounting-finality rule is selected by this implementation.
Its synthetic test verifier is deliberately unsafe for deployment.

An instance fixes a verifier, policy digest, eligible net-charge threshold in
nano-USD and maximum observation age. The deposited asset is native currency;
its amount is independent of the provider's USD allowance and threshold. Tests
use a nominal five-dollar threshold and local test balances only. There is no
additional utilization reward.

Funding records sponsor, coupon commitment, provider/account-scope commitment and
time. The deposit identifier includes the sponsor, so another sponsor cannot
reserve that identifier by copying a coupon commitment. Funding does not prove
coupon possession or provider backing. The issuer must bind its receipt to this
deposit before a release verifier accepts it; the current coupon v3 protocol
does not yet produce that receipt or integrate this escrow.

A release statement binds deposit, coupon, provider scope/key, recipient and
delivery commitments, issuance-receipt commitment, eligible net charges, issuance
and observation times, and an assertion of final accounting. The digest also
binds chain ID, escrow address, verifier address and immutable policy parameters.
The verifier must cryptographically establish both private issuance and eligible
final accounting for that exact statement. An externally supplied boolean or
signature from a whitelisted but unattested local process is insufficient.

The contract checks attribution, nonempty issuance bindings, issuance after
funding, fresh nonfuture observation, final-accounting indication and threshold.
It then calls the immutable verifier using STATICCALL. On success it consumes
the deposit and provider-scope/key pair and credits only the original sponsor.
Withdrawal uses checks-effects-interactions; a failed transfer reverts the credit
change. There is no owner withdrawal, upgrade setter, expiry refund or revocation
refund. Failure to meet the predicate leaves funds locked; this is experimental
mechanics following the requested no-use/no-return condition, not an accepted
commercial unconsumed-deposit policy.

Provider accounting finality and chain finality are different. A fresh observation
can still contain incomplete/correctable usage. The final verifier must establish
the selected provider reporting completeness, eligible categories, correction
policy and cutoff. The escrow cannot undo a release after a later correction.
Likewise it does not make its own transaction irreversible: clients need the
selected chain-verification/finality policy. Rollback prevention for attested
issuers, cross-instance issuance duplication, attested key rotation and governance
remain verifier/protocol obligations. A verifier address alone does not establish
immutable code or prevent an upgradeable verifier from changing its behavior.

Run the isolated mechanics suite from `contracts/`:

```sh
forge test --match-contract CouponDepositExperimentTest
```

The suite exercises one release/withdrawal, unauthorized withdrawal, replay,
wrong attribution/key/recipient/delivery/receipt, stale/future/predeposit times,
incomplete/below-threshold accounting, wrong proof, chain/contract domain changes,
duplicate key use and funding-identifier front running. It does not validate
TDX evidence, provider data, contract deployment or a real deposit return.
Additional adversarial cases verify that a reverting verifier consumes no
obligation, rejected transfers retain sponsor credit for later withdrawal,
reentrant withdrawal cannot spend the same credit twice, and each immutable
domain parameter independently changes the statement digest.
