# Irreversible coupon issuance attempt journal

`CouponIssuanceGuardExperiment` is an undeployed building block for preventing a
restored issuer disk from authorizing another provider-key creation. It records
one attempt per coupon commitment, under immutable issuer transaction authority
and issuance policy. It does not verify attestation or connect the current coupon
service to a chain. No production rollback-protection claim follows from its tests.

The commitment binds chain, guard address, authority, policy, coupon, recipient,
accepted offer and fresh process nonce. A different recipient, offer or process
cannot reset a consumed coupon. There is no timeout/reset/admin path. An
interrupted attempt can strand a gift; any replacement must be an explicit new
gift with separately reviewed backing, never a reset of the old obligation.

Required service integration, still unimplemented:

1. Verify the admitted code/configuration and protected transaction authority.
   Pin the chain, deployed guard code/address, immutable policy and issuer. A
   sponsor-controlled signing key does not establish private issuance.
2. Generate a fresh random process nonce in protected memory; never restore it
   from disk. Persist the ordinary issuing intent before external effects.
3. Submit the exact attempt and authenticate its finalized inclusion and guard
   state. A successful RPC receipt or latest-state read is insufficient.
4. Only the original continuously running process may progress from its own
   successful, finalized consumption to exactly one provider POST. Consume its
   in-memory permission before the call. A restarted process, duplicate handler,
   disk clone or old receipt must never reconstruct that permission.
5. Encrypt the resulting credential directly to the bound recipient and durably
   store the ciphertext and receipt, including the guard commitment. A recovered
   completed ciphertext can be redelivered without another provider POST.
   Lost or ambiguous creation stays quarantined, including a crash between guard
   consumption and the first POST. Do not automatically resubmit provider calls.

These steps require an authenticated chain/finality backend and a hardware/host
profile that excludes cloning or restoring live process memory after granting
permission. This contract alone cannot prevent that clone from repeating an
HTTP call. KMS authorization, owner upgrade/exec powers, provider idempotency,
and provider-owner secret retrieval are independent qualification requirements.
Changing policy/guard or rolling the chain back must not silently reactivate an
old coupon. A migration must preserve all consumed obligations.

There are no recipient transactions or funds in this contract; the service pays
its own transaction gas. Deposit return remains a separate verified issuance and
accounting decision in [the escrow experiment](src/application/COUPON_EXPERIMENT.md).

Run the offline contract checks with:

```sh
forge test --match-contract CouponIssuanceGuardExperimentTest
```
