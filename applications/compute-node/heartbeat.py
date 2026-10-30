"""Publish the operator's signed, public pool status using its existing Mac key."""
import json
import time
from http.client import HTTPException
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


class Publisher:
    def __init__(self, key_path, publisher_address, payout, broker, version):
        from eth_account import Account
        self.account = Account.from_key(key_path.read_text().strip())
        if self.account.address.lower() != publisher_address.lower():
            raise ValueError('heartbeat publisher key/address mismatch')
        self.payout = payout.lower()
        self.url = broker.rstrip('/') + '/fleet'
        self.version = version
        self.next_at = 0

    def tick(self, snapshot):
        if time.monotonic() < self.next_at:
            return None
        self.next_at = time.monotonic() + 15
        from eth_account.messages import encode_defunct
        def numbers(value):
            if isinstance(value, float) and value.is_integer():
                return int(value)
            if isinstance(value, dict):
                return {k: numbers(v) for k, v in value.items()}
            if isinstance(value, list):
                return [numbers(v) for v in value]
            return value
        body = {**numbers(snapshot), 'publisher': self.account.address.lower(), 'payout': self.payout,
                'updated_at': int(time.time()), 'version': self.version}
        message = 'dsmack-fleet/1\n' + json.dumps(body, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
        body['signature'] = '0x' + self.account.sign_message(encode_defunct(text=message)).signature.hex()
        request = Request(self.url, json.dumps(body, ensure_ascii=False).encode(),
                          {'Content-Type': 'application/json'}, method='POST')
        try:
            with urlopen(request, timeout=5) as response:
                if response.status != 200:
                    raise ValueError('heartbeat HTTP ' + str(response.status))
                result = json.load(response)
            return {'event': 'heartbeat_posted', 'updated_at': body['updated_at'],
                    'received_at': result['received_at']}
        except (HTTPError, URLError, TimeoutError, OSError, HTTPException, ValueError, KeyError) as error:
            record = {'event': 'heartbeat_error', 'error': str(error), 'url': self.url}
            if isinstance(error, HTTPError):
                record['status'] = error.code
                try:
                    record['body'] = error.read(4096).decode(errors='replace')
                finally:
                    error.close()
            return record
