"""One append-only hash chain for an interactive agent session (README.md).

Each line of chain.jsonl is {seq, t, src, kind, meta, data, prev}; its hash is sha256 of the
canonical line and the next line's prev. Writers in different containers share the file and
take an flock around each append.
"""
import argparse
import base64
import fcntl
import hashlib
import json
from pathlib import Path
import sys
import time

GENESIS = '0' * 64


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def entry_hash(entry):
    return hashlib.sha256(canonical(entry)).hexdigest()


class Chain:
    def __init__(self, directory):
        self.path = Path(directory)/'chain.jsonl'
        self.state = Path(directory)/'head'

    def append(self, src, kind, data=b'', meta=None):
        with open(self.path, 'a') as log:
            fcntl.flock(log, fcntl.LOCK_EX)
            seq, prev, closed = json.loads(self.state.read_text()) if self.state.exists() else (0, GENESIS, False)
            if closed:
                raise RuntimeError('chain is closed')
            entry = {'seq': seq, 't': time.time(), 'src': src, 'kind': kind, 'meta': meta or {},
                     'data': base64.b64encode(data).decode(), 'prev': prev}
            log.write(canonical(entry).decode() + '\n')
            log.flush()
            head = entry_hash(entry)
            self.state.write_text(json.dumps([seq + 1, head, kind == 'close']))
            return head


def entries(path):
    return [json.loads(line) for line in Path(path).read_text().splitlines()]


def verify(path, head):
    prev, log = GENESIS, entries(path)
    for seq, entry in enumerate(log):
        if entry['seq'] != seq or entry['prev'] != prev:
            raise ValueError('chain breaks at entry %d' % seq)
        prev = entry_hash(entry)
    if not log or log[-1]['kind'] != 'close':
        raise ValueError('chain was not closed')
    if prev != head:
        raise ValueError('chain does not hash to the declared head')
    return log


def close(chain_dir, transcripts, output):
    """Append the agent CLI's transcripts, close the chain and declare its head as an artifact."""
    chain = Chain(chain_dir)
    for path in sorted(Path(transcripts).rglob('*.jsonl')):
        chain.append('transcript', 'file', path.read_bytes(), {'path': str(path.relative_to(transcripts))})
    head = chain.append('dashcam', 'close')
    (Path(output)/'dashcam-head').write_text(head + '\n')
    return head


def cast(log):
    """asciicast v2: terminal output and input, with a marker for each model exchange."""
    size = next(e['meta'] for e in log if e['kind'] == 'resize')
    start = log[0]['t']
    yield {'version': 2, 'width': size['cols'], 'height': size['rows'], 'timestamp': int(start)}
    for e in log:
        t = round(e['t'] - start, 6)
        text = base64.b64decode(e['data']).decode(errors='replace')
        if e['kind'] in ('out', 'in'):
            yield [t, e['kind'][0], text]
        elif e['kind'] == 'resize':
            yield [t, 'r', '%dx%d' % (e['meta']['cols'], e['meta']['rows'])]
        elif e['src'] == 'sentinel':
            yield [t, 'm', ' '.join([e['kind']] + [str(e['meta'][k]) for k in ('method', 'path', 'status') if k in e['meta']])]


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest='command', required=True)
    v = sub.add_parser('verify')
    v.add_argument('chain')
    v.add_argument('head', help='the dashcam-head artifact')
    c = sub.add_parser('close')
    c.add_argument('--chain', required=True)
    c.add_argument('--transcripts', required=True)
    c.add_argument('--output', required=True)
    r = sub.add_parser('cast')
    r.add_argument('chain')
    p = sub.add_parser('play')
    p.add_argument('chain')
    p.add_argument('--speed', type=float, default=1.0)
    args = parser.parse_args()
    if args.command == 'verify':
        log = verify(args.chain, Path(args.head).read_text().strip())
        counts = {}
        for e in log:
            counts[e['src'] + '/' + e['kind']] = counts.get(e['src'] + '/' + e['kind'], 0) + 1
        print(json.dumps({'ok': True, 'entries': len(log), 'counts': counts}, sort_keys=True))
    elif args.command == 'close':
        print(close(args.chain, args.transcripts, args.output))
    elif args.command == 'cast':
        for event in cast(entries(args.chain)):
            print(json.dumps(event))
    else:
        clock = None
        for e in entries(args.chain):
            if e['kind'] == 'out':
                clock = clock or (e['t'], time.time())
                time.sleep(max(0, (e['t'] - clock[0]) / args.speed - (time.time() - clock[1])))
                sys.stdout.buffer.write(base64.b64decode(e['data']))
                sys.stdout.flush()


if __name__ == '__main__':
    main()
