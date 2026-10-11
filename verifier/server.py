"""Single-policy, private-lab HTTP service with durable atomic replay protection.

Use HTTPS for the phone. No membership or fixed-code claims are emitted.
"""
import argparse
import json
import secrets
import sqlite3
import time
from dataclasses import asdict
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory

from .core import Policy, Reject, b64, require, sha, unb64, unique_json, verify_assertion, verify_attestation

APPLE_ROOT_SHA256 = '1cb9823ba28ba6ad2d33a006941de2ae4f513ef1d4e831b9f7e0fa7b6242c932'
ROOT = Path(__file__).resolve().parents[1] / 'trust/apple-app-attestation-root.pem'


def create_app(policy, database, root_pem=None, clock=time.time):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    using_bundled_root = root_pem is None
    root_pem = ROOT.read_bytes() if using_bundled_root else root_pem
    root_hash = x509.load_pem_x509_certificate(root_pem).fingerprint(hashes.SHA256()).hex()
    if using_bundled_root:
        require(root_hash == APPLE_ROOT_SHA256, 'bundled_root_fingerprint_mismatch')
    evidence_origin = 'apple_root' if root_hash == APPLE_ROOT_SHA256 else 'synthetic_test_root'
    policy_document = asdict(policy)
    # Keep old iOS database identities stable; encode an explicitly selected
    # measurement policy as JSON-safe hex, including it in the durable identity.
    policy_document.pop('cdhashes')
    policy_document.pop('require_macos_acl')
    if policy.cdhashes:
        policy_document['cdhashes'] = [x.hex() for x in policy.cdhashes]
    if policy.require_macos_acl:
        policy_document['require_macos_acl'] = True
    identity = json.dumps({'policy': policy_document, 'root_sha256': root_hash}, sort_keys=True)
    app = Flask(__name__)
    app.config['MAX_CONTENT_LENGTH'] = 180_000

    def connect():
        con = sqlite3.connect(database, timeout=10, isolation_level=None)
        con.row_factory = sqlite3.Row
        return con

    con = connect()
    try:
        con.executescript('''
        CREATE TABLE IF NOT EXISTS config (id INTEGER PRIMARY KEY, identity TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS challenges (
            id TEXT PRIMARY KEY, nonce TEXT NOT NULL, purpose TEXT NOT NULL,
            key_id TEXT, expires REAL NOT NULL, used INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS keys (
            key_id TEXT PRIMARY KEY, public_key TEXT NOT NULL, counter INTEGER NOT NULL,
            attestation TEXT NOT NULL, receipt TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS evidence (
            id INTEGER PRIMARY KEY, timestamp REAL NOT NULL, endpoint TEXT NOT NULL,
            request_json TEXT NOT NULL, response_json TEXT NOT NULL);
        ''')
        con.execute('INSERT OR IGNORE INTO config VALUES (1, ?)', (identity,))
        require(con.execute('SELECT identity FROM config WHERE id=1').fetchone()[0] == identity,
                'database_policy_mismatch_use_separate_database')
    finally:
        con.close()

    def payload():
        require(request.mimetype == 'application/json', 'expected_json_content_type')
        obj = unique_json(request.get_data())
        require(isinstance(obj, dict), 'expected_json_object')
        return obj

    def text_field(obj, name, max_size=200_000):
        value = obj.get(name)
        require(isinstance(value, str) and 0 < len(value) <= max_size, f'invalid_{name}')
        return value

    def metadata():
        return {'scope': 'app_identity_only', 'fixed_code_verified': False,
                'evidence_origin': evidence_origin, 'policy': policy_document, 'root_sha256': root_hash}

    def log(con, endpoint, body, verdict):
        con.execute('INSERT INTO evidence(timestamp,endpoint,request_json,response_json) VALUES (?,?,?,?)',
                    (clock(), endpoint, json.dumps(body, sort_keys=True), json.dumps(verdict, sort_keys=True)))

    @app.errorhandler(Reject)
    def rejected(exc):
        return jsonify({'accepted': False, 'reason': str(exc), **metadata()}), 400

    @app.get('/health')
    def health():
        return jsonify({'status': 'ready', **metadata()})

    @app.post('/challenge')
    def challenge():
        body = payload()
        purpose = body.get('purpose')
        require(purpose in ('attestation', 'assertion'), 'invalid_purpose')
        key_id = text_field(body, 'key_id', 64)
        require(len(unb64(key_id)) == 32, 'invalid_key_id')
        con = connect()
        try:
            enrolled = con.execute('SELECT 1 FROM keys WHERE key_id=?', (key_id,)).fetchone()
            require(bool(enrolled) == (purpose == 'assertion'), 'key_enrollment_state_mismatch')
            result = {'challenge_id': secrets.token_hex(24), 'challenge': b64(secrets.token_bytes(32)),
                      'purpose': purpose, 'expires_at': clock() + 120, 'key_id': key_id}
            con.execute('INSERT INTO challenges(id,nonce,purpose,key_id,expires) VALUES (?,?,?,?,?)',
                        (result['challenge_id'], result['challenge'], purpose, key_id, result['expires_at']))
            return jsonify(result)
        finally:
            con.close()

    def consume(con, body, purpose):
        cid = text_field(body, 'challenge_id', 48)
        key_id = text_field(body, 'key_id', 64)
        row = con.execute('SELECT * FROM challenges WHERE id=?', (cid,)).fetchone()
        require(row is not None, 'unknown_challenge')
        require(not row['used'], 'challenge_replay')
        require(row['expires'] > clock(), 'expired_challenge')
        require(row['purpose'] == purpose and row['key_id'] == key_id, 'challenge_binding_mismatch')
        con.execute('UPDATE challenges SET used=1 WHERE id=?', (cid,))
        return row

    def transaction(purpose):
        body = payload()
        con = connect()
        try:
            con.execute('BEGIN IMMEDIATE')
            try:
                ch = consume(con, body, purpose)
                key_id = body['key_id']
                if purpose == 'attestation':
                    require(not con.execute('SELECT 1 FROM keys WHERE key_id=?', (key_id,)).fetchone(), 'already_enrolled')
                    result = verify_attestation(unb64(text_field(body, 'attestation')), key_id,
                                                unb64(ch['nonce']), policy, root_pem)
                    con.execute('INSERT INTO keys VALUES (?,?,?,?,?)',
                                (key_id, result['public_key'], 0, body['attestation'], result['receipt']))
                    verdict = {'accepted': True, 'signals': result['signals'],
                               'receipt_status': result['receipt_status'], **metadata()}
                else:
                    key = con.execute('SELECT * FROM keys WHERE key_id=?', (key_id,)).fetchone()
                    require(key is not None, 'unknown_key')
                    client_data = unb64(text_field(body, 'client_data'))
                    obj = unique_json(client_data)
                    require(isinstance(obj, dict), 'invalid_client_data')
                    require(obj.get('protocol') == 'ios-app-attest-sok/v1', 'wrong_protocol')
                    require(obj.get('challenge_id') == ch['id'] and obj.get('challenge') == ch['nonce']
                            and obj.get('key_id') == key_id, 'client_challenge_mismatch')
                    require(obj.get('operation') == 'double' and type(obj.get('input')) is int
                            and obj['input'] == 2 and type(obj.get('output')) is int, 'wrong_operation')
                    result = verify_assertion(unb64(text_field(body, 'assertion')), client_data,
                                              key['public_key'], key['counter'], policy)
                    con.execute('UPDATE keys SET counter=? WHERE key_id=?', (result['counter'], key_id))
                    verdict = {'accepted': True, **result, **metadata(),
                               'observed_output': obj['output'], 'expected_output': 4,
                               'computation_matches': obj['output'] == 4}
                status = 200
            except Reject as exc:
                # A challenge presented for verification is spent even on a failed proof.
                verdict, status = {'accepted': False, 'reason': str(exc), **metadata()}, 400
            log(con, purpose, body, verdict)
            con.commit()
            return jsonify(verdict), status
        except Exception:
            con.rollback()
            raise
        finally:
            con.close()

    @app.post('/attest')
    def attest():
        return transaction('attestation')

    @app.post('/assert')
    def assertion():
        return transaction('assertion')

    return app


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--app-id', required=True, help='Actual App ID prefix plus bundle ID')
    parser.add_argument('--environment', choices=('development', 'production'), required=True)
    parser.add_argument('--development-aaguid', choices=('appattestdevelop', 'appattestsandbox'), default='appattestdevelop')
    parser.add_argument('--category', action='append', type=int, default=[])
    parser.add_argument('--bundle-version', action='append', default=[])
    parser.add_argument('--database', default='captures/lab.sqlite')
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=8443)
    parser.add_argument('--tls-cert')
    parser.add_argument('--tls-key')
    parser.add_argument('--install-dir', help='Serve this directory at /<--install-path>/')
    parser.add_argument('--install-path')
    args = parser.parse_args()
    require(bool(args.tls_cert) == bool(args.tls_key), 'provide_both_tls_files')
    require(args.host in ('localhost', '127.0.0.1', '::1') or args.tls_cert, 'remote_binding_requires_tls')
    Path(args.database).parent.mkdir(parents=True, exist_ok=True)
    policy = Policy(args.app_id, args.environment, args.development_aaguid,
                    tuple(args.category), tuple(args.bundle_version))
    app = create_app(policy, args.database)
    if args.install_dir:
        require(bool(args.install_path), 'install_path_required')
        app.add_url_rule(f'/{args.install_path}/<path:name>', 'install',
                         lambda name: send_from_directory(Path(args.install_dir).resolve(), name))
    app.run(host=args.host, port=args.port, debug=False,
            ssl_context=(args.tls_cert, args.tls_key) if args.tls_cert else None)


if __name__ == '__main__':
    main()
