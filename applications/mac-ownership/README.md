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

Use the installed `dsmack` CLI and Python environment with `eth-account`. On the
Mac, `PUBLISHER_KEY` is its existing publisher-key path and `KID` is its existing
`0x`-prefixed 32-byte install label. Create the provisioner and configuration:

```sh
: "${PUBLISHER_KEY:?existing installed publisher-key path}" "${KID:?existing installed kid}"
export PUBLISHER_KEY KID
python3 - <<'PYTHON'
import json, os
from pathlib import Path
from eth_account import Account
os.umask(0o077)
root = Path.home() / '.dsmack'
root.mkdir(mode=0o700, exist_ok=True)
key = root / 'provisioner.key'
if not key.exists():
    key.write_text('0x' + Account.create().key.hex() + '\n')
key.chmod(0o600)
address = Account.from_key(key.read_text().strip()).address
(root / 'provisioner.address').write_text(address + '\n')
(root / 'mac-ownership.json').write_text(json.dumps({
    'broker': 'https://pod.dstack.soc1024.com/relay-broker',
    'publisher_key': str(Path(os.environ['PUBLISHER_KEY']).expanduser().resolve()),
    'kid': os.environ['KID']}))
print(address)
PYTHON
```

On the operator's wallet host, authorize once and send the public authorization
to the Mac (`mini-mesh` in this example), then link it:

```sh
PROVISIONER_ADDRESS=$(ssh mini-mesh 'cat ~/.dsmack/provisioner.address')
dsmack authorize --operator-keystore ~/.foundry/keystores/operator --password-file ~/.dsmack/operator-password --provisioner "$PROVISIONER_ADDRESS" --out provisioning.json
rsync --bwlimit=20000 provisioning.json mini-mesh:.dsmack/provisioning.json
ssh mini-mesh '~/.local/bin/dsmack link --authorization ~/.dsmack/provisioning.json --provisioner-key ~/.dsmack/provisioner.key'
```

Repeated linking returns the existing link. A new operator's authorization
re-links with a newer Mac nonce. Revoke the provisioner from the wallet host;
unlink from the Mac:

```sh
dsmack revoke-provisioner --operator-keystore ~/.foundry/keystores/operator --password-file ~/.dsmack/operator-password --provisioner "$PROVISIONER_ADDRESS"
ssh mini-mesh '~/.local/bin/dsmack unlink'
```

For hardware signing through `cast wallet`, replace the keystore and password
flags with `--ledger` or `--trezor`; `--derivation-path` selects its wallet path.
After revocation, generate and authorize a new provisioner key. `--broker`,
`--publisher-key`, `--kid`, `--nonce`, `--out`, and `--config` select explicit
script inputs. `DSMACK_KEYSTORE_PASSWORD_FILE` supplies the password-file path
when its flag is omitted. Keys and passwords are never printed.
