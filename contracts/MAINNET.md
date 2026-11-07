# Mainnet issuance operations

`LastResortBuyer` owns LAYC and pays units signed by registered minions. Deploy it
with `script/IssuanceLaunch.s.sol`; rehearse the launch with:

```sh
PORT=8571 BASE_RPC=https://mainnet.base.org OWNER=0x55A07f257d07986026dD6e39488954C5aCD2cd5D script/mainnet-fork.sh
```

The issuance script checks `KMS_ROOT` against Phala's Base KMS `kmsInfo()`.
The fork script sets and prints `KMS_ROOT_UNCHECKED=1` to use its test signing key.
Each `approveApp` starts a new generation. Register minions again after approval;
previous registrations stay inactive and revoked keys cannot register again.

`advance()` is permissionless. The book window lasts two hours from `epochStart`.
Anyone can advance while the minion is down; if no book is committed in that
window, that epoch's issuance is lost. Unpaid issuance is never minted.

Before `upgradeTo`, compare the current and proposed layouts using:

```sh
forge inspect LastResortBuyer storageLayout
```

OpenZeppelin 4.9 Initializable has no storage gap here. Preserve every existing
storage slot across upgrades. The implementation must keep the same token and
KMS root.
