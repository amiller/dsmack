import json

import pytest

from dashcam import Chain, cast, close, verify


def test_two_writers_one_chain_verifies_and_replays(tmp_path):
    relay, sentinel = Chain(tmp_path), Chain(tmp_path)
    relay.append('relay', 'resize', meta={'rows': 24, 'cols': 80})
    relay.append('relay', 'in', b'hi\r')
    sentinel.append('sentinel', 'request', b'{}', {'method': 'POST', 'path': '/<token>/v1/messages'})
    sentinel.append('sentinel', 'response', b'{"type":"error"}', {'status': 401})
    relay.append('relay', 'out', b'hi\r\n')
    (tmp_path/'t/p').mkdir(parents=True)
    (tmp_path/'t/p/s.jsonl').write_text('{"type":"user"}\n')
    head = close(tmp_path, tmp_path/'t', tmp_path)
    assert (tmp_path/'dashcam-head').read_text().strip() == head
    log = verify(tmp_path/'chain.jsonl', head)
    assert [e['kind'] for e in log][-2:] == ['file', 'close']
    events = list(cast(log))
    assert events[0]['width'] == 80 and [1, 'i', 'hi\r'][1:] == events[2][1:]
    with pytest.raises(RuntimeError):
        relay.append('relay', 'in', b'late')


def test_edited_segment_breaks_the_chain(tmp_path):
    chain = Chain(tmp_path)
    chain.append('relay', 'in', b'rm -rf x\r')
    head = chain.append('dashcam', 'close')
    lines = (tmp_path/'chain.jsonl').read_text().splitlines()
    first = json.loads(lines[0])
    first['data'] = 'bHMNCg=='
    (tmp_path/'chain.jsonl').write_text('\n'.join([json.dumps(first)] + lines[1:]) + '\n')
    with pytest.raises(ValueError, match='breaks at entry 1'):
        verify(tmp_path/'chain.jsonl', head)
