# Prepaid USDC rail

`../src/UsageEscrow.sol` holds user deposits and pays broker-signed cumulative
claims. A claim names a terms hash the user accepted (`acceptTerms`, or
`acceptTermsFor` with the user's EIP-712 signature); it must pay that terms'
operator and stay within its cap. Each user's deposits cap its payouts; the
EIP-712 domain salt isolates users. Deposits come from the user (`deposit`), a
sponsor (`depositFor`), or an EIP-3009 authorization such as an x402 payment
(`depositWithAuthorization`). `depositWithAuthorization` must be the call that
executes the authorization: if anyone else (a standard x402 facilitator, a
front-runner) executes it on the token first, the call reverts
`authorization used` and those tokens sit in the escrow uncredited.

The owner can replace the claim signer at once with `rotateBroker`. That gives
the owner the signer's power: per buyer, payouts up to the sum of the caps the
buyer accepted, each paid only to the operator its terms hash names. Rotation
invalidates signed claims not yet submitted; the broker's accruals remain and
can be re-signed by the new key. Claims are all-or-nothing against the buyer's
remaining deposit, so a buyer should accept caps no larger than what they
deposit. Users can close their account and withdraw after a 14 day claim
window without any further broker signature. Node measurements and operator
addresses are immutable; posted prices live in broker configuration.

Run from the repository root:

```sh
forge test --root contracts
python3 -m unittest discover -s contracts/payments -p 'test_*.py' -v
```

Deployment uses Python 3, Foundry and `requirements.txt`. The coordinator uses the
agent testnet funding wallet (0x1FBe7a7b3f7a37A967F3d927Abd6f04DB2766c5b) and the
credit token (6 decimals and EIP-3009, e.g. Base Sepolia USDC). Prepare
`PAYMENTS_DIR/funding-wallet.address` with that wallet's public address, then run:

```sh
bash contracts/payments/deploy-and-fund.sh AGENT_WALLET_KEY PAYMENTS_DIR 0xTOKEN
bash contracts/payments/verify.sh 0xNEW_ESCROW 0xTOKEN
```

The constructor is `(address token, address owner)`. Deployment checks the wallet
identity before network access, pins a finalized Base Sepolia RPC quorum, deploys,
and checks the compiled runtime plus immutable owner/token. It requires 0.02
Sepolia ETH plus gas and preserves a 0.02 ETH reserve. Transaction records and
`deployment.json` go under `PAYMENTS_DIR/contract/`.

Use a fresh output directory for this deployment. Generate broker payment config
from `deployment.json` with `applications/payments/configure.mjs`; configure
`inferenceOperator`, S1 prices and registered classes. The first
`register-class.mjs` invocation pins the attested broker's secp256k1 address with
`registerBroker`. Rebuild and repack Linux compute guests with the new escrow and
register their new compose/image measurements before the Mac pool offers them.
Broker and guest deployment commands are in
[applications/payments](../../applications/payments/README.md#run).

`PAYMENTS_RPC_URLS` can name three comma-separated independent HTTPS RPCs.
Defaults are Base, PublicNode and dRPC. Source verification uses the coordinator's
existing Basescan API key.
