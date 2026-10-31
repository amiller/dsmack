"""Publish the operator's signed, public pool status using its existing Mac key."""
import json
import time
from http.client import HTTPException
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def operator_region(path):
    region = json.loads(path.read_bytes()).get('region')
    if region is None:
        return None
    if (not isinstance(region, dict) or set(region) != {'name', 'lat', 'lon'}
            or not isinstance(region['name'], str) or not region['name'].strip() or len(region['name']) > 100
            or type(region['lat']) is not int or abs(region['lat']) > 90
            or type(region['lon']) is not int or abs(region['lon']) > 180):
        raise ValueError('operator region requires name and whole-degree lat/lon')
    return region


class Publisher:
    def __init__(self, key_path, publisher_address, broker, version, operator_path=None):
        from eth_account import Account
        self.account = Account.from_key(key_path.read_text().strip())
        if self.account.address.lower() != publisher_address.lower():
            raise ValueError('heartbeat publisher key/address mismatch')
        self.url = broker.rstrip('/') + '/fleet'
        self.version = version
        self.operator_path = operator_path
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
        body = {**numbers(snapshot), 'publisher': self.account.address.lower(),
                'updated_at': int(time.time()), 'version': self.version}
        # Region opt-in/out is live; capacity still changes only on pool restart.
        if self.operator_path:
            try:
                region = operator_region(self.operator_path)
            except (OSError, ValueError) as error:
                return {'event': 'heartbeat_error', 'error': str(error), 'url': self.url}
            body.pop('region', None)
            if region is not None:
                body['region'] = region
            body['config'] = {k: v for k, v in body['config'].items() if k != 'region'}
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
                except (OSError, TimeoutError, HTTPException) as read_error:
                    record['body_read_error'] = str(read_error)
                finally:
                    error.close()
            return record
