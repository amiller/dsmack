import hashlib, json, struct, sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[1] / 'scripts/release'))
from measure import measure

D = Path(__file__).parents[1] / 'contracts/fixtures/resign'
V = json.loads((D / 'measure-vectors.json').read_text())


def load(name):
    if (D / f'{name}.json').exists():
        j = json.loads((D / f'{name}.json').read_text())
        h = lambda k: bytes.fromhex(j[k][2:])
        return [h('cd'), h('page0'), h('ent'), j['linkeditCmd'], j['codeSigCmd']]
    return [(D / f'{name}{e}').read_bytes() for e in ('.cd', '.page0', '.ent')] + [V['L'], V['S']]


def m(x): return '0x' + measure(*x).hex()


def test_vectors():
    for n in V['probeSame']: assert m(load(n)) == V['probe']
    for n in V['nodeSame']: assert m(load(n)) == V['node']
    assert m(load('M-modified')) == V['probeModified'] != V['probe']
    assert m(load('node-modified')) == V['nodeModified'] != V['node']
    assert len({hashlib.sha256(load(n)[0]).digest() for n in V['nodeSame']}) == 3


@pytest.mark.parametrize('name,reason', V['rejected'].items())
def test_rejected(name, reason):
    with pytest.raises(ValueError, match=reason): measure(*load(name))


def seal_ent(cd, ent):
    off = struct.unpack_from('>I', cd, 0x10)[0]
    cd[off - 224:off - 192] = hashlib.sha256(struct.pack('>II', 0xfade7172, len(ent) + 8) + ent).digest()


def test_signer_fields_free_behavior_pinned():
    cd, page0, ent, L, S = load('A-original')
    off = struct.unpack_from('>I', cd, 0x10)[0]
    def flip(at, cdx=None):
        c = bytearray(cd if cdx is None else cdx); c[at] ^= 1; return m([bytes(c), page0, ent, L, S])
    assert flip(off - 32) == flip(off - 64) == flip(off - 96) == flip(off - 160) == V['probe']  # slots -1 -2 -3 -5
    assert flip(0x30) == flip(0x14) == V['probe']                                                 # teamOffset, identOffset
    for at in (0x0d, 0x57, 0x5b, off + 40):                                                       # flags, execSeg, runtime, slot 1
        assert flip(at) != V['probe']
    with pytest.raises(ValueError, match='slots -4/-6'): flip(off - 128)
    with pytest.raises(ValueError, match='slots -4/-6'): flip(off - 192)
    with pytest.raises(ValueError, match='page0 hash'): measure(cd, page0[:-1] + b'\1', ent, L, S)
    with pytest.raises(ValueError, match='load commands'): measure(cd, page0, ent, L + 8, S)
    for i, same in ((47, True), (181, True), (134, False)):                                     # app id, team id, opt-in value
        e = bytearray(ent); e[i] ^= 1; c = bytearray(cd); seal_ent(c, bytes(e))
        assert (m([bytes(c), page0, bytes(e), L, S]) == V['probe']) == same
    p = bytearray(page0); p[L + 32] ^= 1; c = bytearray(cd); c[off:off + 32] = hashlib.sha256(p).digest()
    assert m([bytes(c), bytes(p), ent, L, S]) == V['probe']                                       # masked __LINKEDIT vmsize
