"""Coupon authority's NEAR account as the first dsmack-sdk app. The account key is
get_key("near-account", "ed25519:near-account"); the account id is the implicit hex of its public key.
Usage: coupon_account.py account | coupon_account.py transfer RECEIVER YOCTO
Prints the account id, the app/compose identity, the G-signed statement and transaction hashes; never the key.
chain_verified: both chain links verify against G here, and the runner checked G against the group-key registry's
sharedKeys(scope) on chain before serving the key (a verifier with RPC repeats that with verify.group_on_chain)."""
import json, os, sys
from dsmack_sdk import Client
from dsmack_sdk import verify
import near_tx

RPC = os.environ['NEAR_RPC']
client = Client(os.environ['DSMACK_SOCKET'])
info = client.info()
reply = client.get_key('near-account', 'ed25519:near-account')
verify.key_reply(reply, 'near-account', 'ed25519:near-account', info['group_public'])
seed = bytes.fromhex(reply['key'])
account = near_tx.implicit_account(seed)
out = {'account_id': account, 'app_id': info['app_id'], 'compose_hash': info['compose_hash'], 'key_epoch': info['key_epoch'],
       'group_public': info['group_public'], 'statement': reply['chain'][0]['message'], 'chain_verified': True}
if sys.argv[1] == 'transfer':
    result = near_tx.transfer(RPC, seed, account, sys.argv[2], int(sys.argv[3]))
    out['transfer'] = {'hash': result['transaction']['hash'], 'status': result['status'], 'receiver_id': sys.argv[2], 'yocto': sys.argv[3]}
print(json.dumps(out))
