"""Export a local audit DB; no secrets, but stable App Attest identifiers are included."""
import argparse
import json
import sqlite3
from pathlib import Path


def export(database):
    con = sqlite3.connect(Path(database).resolve().as_uri() + '?mode=ro', uri=True)
    con.row_factory = sqlite3.Row
    try:
        con.execute('BEGIN')
        config = json.loads(con.execute('SELECT identity FROM config WHERE id=1').fetchone()[0])
        entries = []
        for row in con.execute('SELECT * FROM evidence ORDER BY id'):
            record = dict(row)
            record['request'] = json.loads(record.pop('request_json'))
            record['response'] = json.loads(record.pop('response_json'))
            challenge = con.execute('SELECT * FROM challenges WHERE id=?',
                                    (record['request'].get('challenge_id'),)).fetchone()
            record['challenge'] = dict(challenge) if challenge else None
            entries.append(record)
        return {'format': 'ios-app-attest-server-capture/v1',
                'warning': 'Server timestamps and capture provenance are not Apple-attested.',
                **config, 'entries': entries}
    finally:
        con.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('database')
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    args.output.write_text(json.dumps(export(args.database), indent=2, sort_keys=True) + '\n')


if __name__ == '__main__':
    main()
