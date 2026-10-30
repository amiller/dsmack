"""Fleet messages authenticate the publisher; ownership is resolved by the broker."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from eth_account import Account
from eth_account.messages import encode_defunct

from heartbeat import Publisher


class HeartbeatTests(unittest.TestCase):
    def test_signed_heartbeat_does_not_claim_a_payee(self):
        account = Account.create()
        with tempfile.TemporaryDirectory() as tmp:
            key = Path(tmp)/'publisher.key'
            key.write_text(account.key.hex())
            publisher = Publisher(key, account.address, 'https://broker.example', 'test-source')
            captured = []

            class Reply:
                status = 200

                def __enter__(self):
                    return self

                def __exit__(self, *_):
                    pass

                def read(self):
                    return b'{"received_at":100}'

            def send(request, timeout):
                captured.append(json.loads(request.data))
                return Reply()

            snapshot = {'config': {'max_guests': 1}, 'hardware': {'mem_bytes': float(1 << 30)},
                        'slots': [], 'classes': [], 'errors': []}
            with patch('heartbeat.urlopen', side_effect=send):
                self.assertEqual(publisher.tick(snapshot)['event'], 'heartbeat_posted')
            body = captured[0]
            signature = body.pop('signature')
            self.assertNotIn('payout', body)
            self.assertNotIn('operator', body)
            message = 'dsmack-fleet/1\n' + json.dumps(body, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
            self.assertEqual(Account.recover_message(encode_defunct(text=message), signature=signature), account.address)
            self.assertEqual(body['hardware']['mem_bytes'], 1 << 30)


if __name__ == '__main__':
    unittest.main()
