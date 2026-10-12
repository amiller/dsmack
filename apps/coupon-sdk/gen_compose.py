"""Writes app-compose.json for the coupon app: its app_id, the pinned image and egress to NEAR testnet RPC only.
Usage: gen_compose.py IMAGE@sha256:DIGEST > app-compose.json; compose_hash = sha256 of those exact bytes.
The runner execs `command` as the whole argv (no image entrypoint), so it names the interpreter and script."""
import hashlib, json, sys

APP_ID = hashlib.sha256(b'dsmack-sdk/app/coupon-authority').hexdigest()
dc = {'services': {'app': {'image': sys.argv[1], 'command': ['python', '/app/coupon_account.py', 'account'],
                           'environment': {'NEAR_RPC': 'https://rpc.testnet.near.org', 'NEAR_TRANSPORT': 'egress'}}}}
sys.stdout.write(json.dumps({'app_id': APP_ID, 'docker_compose_file': json.dumps(dc, sort_keys=True),
                             'egress': {'allow': [], 'max_requests': 0, 'max_tokens': 0,
                                        'tcp': [{'host': 'rpc.testnet.near.org', 'port': 443}]},
                             'kms_enabled': True, 'manifest_version': 2, 'name': 'coupon-authority-sdk', 'runner': 'docker-compose'},
                            sort_keys=True, separators=(',', ':')))
