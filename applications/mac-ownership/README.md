# Mac ownership

`dsmack` links a Mac's publisher key to its operator wallet. It uses EIP-712
on Base Sepolia with the broker's UsageEscrow address as the domain contract.
The operator authorizes a provisioner once; that provisioner and the Mac sign
each `MacLink`. Authorizations remain valid until the operator revokes them.
`MacUnlink` is signed by the Mac publisher. Higher Mac nonces replace old links.
Revocation permanently retires that provisioner for that operator. Generate and
authorize a new provisioner key to provision more Macs afterward.

The installed runner accepts `enroll` and `hvf-v3`. Its guest assertion hashes a
fixed runtime transcript rather than a supplied digest. These links bind the
publisher and operator; `kid` is the install's label. The response reports
`linkage_scope: publisher_operator`.

## Add a Mac

Use the repository's Python environment (`eth-account` in `requirements.txt`),
and put the CLI on `PATH`:

```sh
export PATH="$PWD/applications/mac-ownership:$PATH"
```

The provisioning agent writes `~/.dsmack/mac-ownership.json` with `broker`,
`publisher_key` (the existing Mac publisher key path), and `kid` (its `0x`-prefixed
32-byte install label). The provisioner key stays on that Mac.

Once per operator, sign with a Foundry keystore and its password file:

```sh
dsmack authorize --operator-keystore ~/.foundry/keystores/operator --password-file ~/.dsmack/operator-password --provisioner "$PROVISIONER_ADDRESS" --out provisioning.json
```

A hardware wallet can sign through `cast wallet` instead: replace
`--operator-keystore ... --password-file ...` with `--ledger` or `--trezor`.
`--derivation-path` selects its wallet path. The CLI never reads terminal input;
the hardware wallet itself confirms the signature.

Copy the public `provisioning.json` to the Mac, then run:

```sh
dsmack link --authorization provisioning.json --provisioner-key ~/.dsmack/provisioner.key
```

Repeated linking with the same authorization returns the existing link. To
re-link after a sale, authorize the new operator and run the same link command
with that authorization; the Mac chooses a newer nonce automatically.

```sh
dsmack revoke-provisioner --operator-keystore ~/.foundry/keystores/operator --password-file ~/.dsmack/operator-password --provisioner "$PROVISIONER_ADDRESS"
dsmack unlink
```

`--broker`, `--publisher-key`, `--kid`, `--nonce`, and `--out` allow explicit
scripted inputs. `--config` selects a different Mac configuration file.
`DSMACK_KEYSTORE_PASSWORD_FILE` supplies the keystore password file when the flag
is omitted. Files contain signatures and addresses; secret keys and passwords
are never printed.
