import hashlib
import json
from pathlib import Path
import unittest

import numpy as np
from render import geometry, identity, parameters

ROOT = Path(__file__).resolve().parents[2]


class FoldTests(unittest.TestCase):
    def setUp(self):
        self.receipt = json.loads((ROOT / 'release/friend-level1-receipt.json').read_text())

    def test_public_identity_is_stable(self):
        a = identity(self.receipt)
        changed = {**self.receipt, 'contract': self.receipt['contract'].lower(), 'nextId': 999, 'verified': False}
        self.assertEqual(a, identity(changed))
        for key, value in [('chainId', 31337), ('participantToken', 3), ('contract', '0x' + '12' * 20)]:
            self.assertNotEqual(a[1], identity({**self.receipt, key: value})[1])

    def test_rejects_invalid_identity(self):
        for key, value in [('chainId', 0), ('participantToken', -1), ('contract', 'bad'), ('contract', '0x' + 'gg' * 20)]:
            with self.assertRaises(ValueError):
                identity({**self.receipt, key: value})

    def test_geometry_repeats_exactly(self):
        p = parameters(identity(self.receipt)[1])
        def hashes():
            return [(name, hashlib.sha256(v.tobytes()+f.tobytes()).hexdigest()) for name,v,f,_ in geometry(p)]
        self.assertEqual(hashes(), hashes())

    def test_surfaces_have_finite_nonzero_area(self):
        for token in range(1, 9):
            p = parameters(identity({**self.receipt, 'participantToken': token})[1])
            for name, v, f, material in geometry(p):
                self.assertTrue(np.isfinite(v).all(), name)
                self.assertGreaterEqual(v[:,2].min(), .0059)
                self.assertLess(f.max(), len(v))
                a,b,c = v[f[:,0]],v[f[:,1]],v[f[:,2]]
                area = np.linalg.norm(np.cross(b-a,c-a),axis=1)
                self.assertGreater(area.min(), 1e-10, name)
                if name.startswith('outer'):
                    # Outer faces must point away from the sculpture's center.
                    center = np.array([0,0,(v[:,2].max()+v[:,2].min())/2])
                    dots = np.sum(np.cross(b-a,c-a)*((a+b+c)/3-center),axis=1)
                    self.assertGreater((dots>0).mean(), .99, name)


if __name__ == '__main__':
    unittest.main()
