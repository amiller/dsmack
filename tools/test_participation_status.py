import json
import unittest

import participation_status as status

NOW = 1800000000
CATEGORY = '0x' + 'c' * 64
MEMBER = '0x' + 'a' * 64
SECOND = '0x' + 'b' * 64
REGISTRY = '0x' + '1' * 40
HASH = '0x' + 'd' * 64

def words(*values):
    return '0x' + ''.join(v.removeprefix('0x').zfill(64) if isinstance(v, str) else hex(v)[2:].zfill(64) for v in values)

class Reader:
    def __init__(self):
        self.methods = []
        self.calls = []
        self.timestamp = NOW - 2
        self.headers = 0
        self.reorg = False
        self.pause = 0
        self.revoked = 0
        self.registered = True
        self.relay_id = 84532
        self.member_category = CATEGORY
        self.rpc_failure = False
    def json(self, url, payload=None):
        self.calls.append((url, payload))
        if payload is None:
            if url.endswith('/info'):
                return {'chainId': self.relay_id, 'registry': REGISTRY, 'protocolVersion': 2}
            return {'sponsorWritesPaused': False}
        method = payload['method']; self.methods.append(method)
        if self.rpc_failure:
            return {'jsonrpc': '2.0', 'id': 1, 'error': {'message': 'secret debug'}}
        if method == 'eth_chainId': result = '0x14a34'
        elif method == 'eth_blockNumber': result = '0x100'
        elif method == 'eth_getBlockByNumber':
            self.headers += 1
            result = {'number': '0x100', 'hash': '0x' + 'f' * 64 if self.reorg and self.headers > 1 else HASH, 'timestamp': hex(self.timestamp)}
        elif method == 'eth_call':
            selector = payload['params'][0]['data'][:10]
            result = {'0x5c975abb': words(self.pause), '0xd71779d9': words(1),
                '0xd5b7abaf': words(1, 2, MEMBER, 1),
                '0x1f718bf4': words(1, self.member_category, NOW - 200, self.revoked) if self.registered else words(0,0,0,0)}[selector]
        else: raise AssertionError(method)
        return {'jsonrpc': '2.0', 'id': 1, 'result': result}

class Observations(unittest.TestCase):
    def setUp(self):
        self.manifest = {'chain': {'id':84532,'rpc':'https://rpc.test','registry':REGISTRY},
            'relay':'https://relay.test','protocolVersion':2,'category':CATEGORY}
        self.reader = Reader()
        self.roster = [MEMBER]
    def run_observe(self, **kwargs):
        return status.observe(self.manifest, self.reader, roster=self.roster, now=NOW, **kwargs)
    def test_success_is_scoped_registry_observation_not_online_or_census(self):
        r = self.run_observe()
        self.assertEqual(r['state'], 'observed')
        self.assertFalse(r['coverage']['complete_census'])
        self.assertEqual(len(r['members']), 1)
        self.assertIsNone(r['independent_operator_count'])
        self.assertIsNone(r['independent_device_count'])
        self.assertTrue(all(m['liveness'] == 'unknown' for m in r['members']))
        self.assertNotIn('owner', json.dumps(r))
        self.assertEqual(set(self.reader.methods), {'eth_chainId','eth_blockNumber','eth_getBlockByNumber','eth_call'})
        for _, payload in self.reader.calls:
            if payload and payload['method'] == 'eth_call': self.assertEqual(payload['params'][1], '0x100')
        self.assertEqual(self.reader.headers, 2)
    def test_paused_and_revoked_are_reported_without_online_claim(self):
        self.reader.pause = 1; self.reader.revoked = 1
        r = self.run_observe()
        self.assertEqual(r['state'], 'observed')
        self.assertTrue(r['network_paused'])
        self.assertTrue(r['members'][0]['revoked'])
    def test_unknown_fails_closed_without_partial_members_or_raw_error(self):
        for field, value in [('timestamp', NOW-121),('timestamp',NOW+16),('reorg',True),('pause',2),
                             ('revoked',2),('relay_id',1),('member_category',status.ZERO),('rpc_failure',True)]:
            with self.subTest(field=field):
                self.reader = Reader();setattr(self.reader,field,value)
                r = self.run_observe()
                self.assertEqual(r['state'],'unknown');self.assertEqual(r['members'],[])
                self.assertEqual(r['reason'],'observation-unavailable')
                self.assertNotIn('secret',json.dumps(r))
    def test_roster_bounds_duplicates_and_malformed_ids(self):
        for roster in ([words(n) for n in range(65)], [MEMBER, MEMBER.upper().replace('0X','0x')], ['secret'], {}):
            self.roster = roster
            self.assertEqual(self.run_observe()['state'], 'unknown')
    def test_default_empty_roster_never_discovers_or_emits_chain_identities(self):
        r=status.observe(self.manifest, self.reader, now=NOW)
        self.assertEqual(r['state'],'observed')
        self.assertEqual(r['members'],[])
        self.assertEqual(r['coverage']['opt_in_identities'],0)
        self.assertNotIn('eth_getLogs',self.reader.methods)
        self.assertNotIn(MEMBER,json.dumps(r))
    def test_absent_opted_in_member_is_explicit_not_enrolled(self):
        self.reader.registered=False
        r=self.run_observe();self.assertEqual(r['state'],'observed')
        self.assertFalse(r['members'][0]['registered']);self.assertIsNone(r['members'][0]['last_checked'])

if __name__ == '__main__': unittest.main()
