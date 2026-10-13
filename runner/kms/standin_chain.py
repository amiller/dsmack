"""Group-key registry state for stand-in nodes on a local anvil: a real DemoV2 (keyEpochs, sharedKeys,
startKeyEpoch) whose sharedKeys(scope) commitment is written with anvil_setStorageAt, since stand-in nodes hold a test
G instead of bootstrapping it through attested members. Runners then check G on chain as against a real network.
Storage slots from `forge inspect DemoV2 storageLayout`: sharedKeys mapping at slot 6, SharedKey {x, y,
bootstrapMember, committed}."""
import os, subprocess
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ec

ROOT = Path(__file__).resolve().parents[2]
ENV = {**os.environ, 'FOUNDRY_DISABLE_NIGHTLY_WARNING': '1'}
SHARED_KEYS_SLOT = 6


def cast(*a):
    return subprocess.run(['cast', *map(str, a)], check=True, capture_output=True, text=True, env=ENV).stdout.strip()


def deploy_demo(rpc, owner_key, owner):
    out = subprocess.run(['forge', 'create', '--broadcast', '--rpc-url', rpc, '--private-key', owner_key,
                          'src/application/DemoV2.sol:DemoV2', '--constructor-args', owner],
                         cwd=ROOT / 'contracts', check=True, capture_output=True, text=True, env=ENV).stdout
    return out.split('Deployed to: ')[1].split()[0]


def start_epoch(rpc, owner_key, demo, scope):
    """DemoV2.startKeyEpoch(scope): keyEpochs[scope]++, sharedKeys[scope] deleted, KeyEpochStarted emitted."""
    cast('send', '--rpc-url', rpc, '--private-key', owner_key, demo, 'startKeyEpoch(bytes32)', '0x' + scope)


def commit(rpc, demo, scope, scalar_hex):
    """sharedKeys[scope] = {x, y, 0, committed} for the P-256 group key with this scalar."""
    n = ec.derive_private_key(int(scalar_hex, 16), ec.SECP256R1()).public_key().public_numbers()
    base = int(cast('index', 'bytes32', '0x' + scope, SHARED_KEYS_SLOT), 16)
    for i, v in enumerate((n.x, n.y, 0, 1)):
        cast('rpc', '--rpc-url', rpc, 'anvil_setStorageAt', demo, hex(base + i), '0x' + v.to_bytes(32, 'big').hex())
