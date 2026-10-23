"""Offline app-identity checks. All trust policy comes from the verifier operator.

Reference: Apple's 'Validating apps that connect to your server'.
Assertions sign SHA256(nonce) via ECDSA/SHA256, where nonce is already
SHA256(authenticatorData || SHA256(clientData)); do not use Prehashed here.
The receipt is retained as opaque evidence, not used as a verified fraud metric.
"""
import base64
import binascii
import hashlib
import json
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


class Reject(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise Reject(reason)


def sha(data):
    return hashlib.sha256(data).digest()


def b64(data):
    return base64.b64encode(data).decode('ascii')


def unb64(text):
    require(isinstance(text, str) and len(text) <= 200_000, 'invalid_base64')
    try:
        result = base64.b64decode(text, validate=True)
    except (ValueError, binascii.Error):
        raise Reject('invalid_base64') from None
    require(b64(result) == text, 'noncanonical_base64')
    return result


def unique_json(text):
    def pairs(items):
        out = {}
        for k, v in items:
            require(k not in out, 'duplicate_json_key')
            out[k] = v
        return out
    try:
        return json.loads(text, object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(Reject('invalid_json_number')))
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise Reject('invalid_json') from exc


class CBOR:
    """Bounded definite-length subset; rejects duplicate keys and trailing data.

    No tags, floats, indefinite containers, or arbitrary object instantiation.
    These are not part of this harness's supported App Attest wire profile.
    """
    def __init__(self, data):
        require(isinstance(data, bytes) and len(data) <= 100_000, 'invalid_cbor_size')
        self.data, self.pos = data, 0

    def take(self, n):
        require(0 <= n <= len(self.data) - self.pos, 'truncated_cbor')
        value = self.data[self.pos:self.pos + n]
        self.pos += n
        return value

    def read(self, depth=0):
        require(depth < 12, 'cbor_depth')
        head = self.take(1)[0]
        major, info = head >> 5, head & 31
        if major == 7 and info in (20, 21, 22):
            return {20: False, 21: True, 22: None}[info]
        require(major <= 5 and info <= 27, 'unsupported_cbor_type')
        n = info if info < 24 else int.from_bytes(self.take(1 << (info - 24)), 'big')
        if major in (0, 1):
            return n if major == 0 else -1 - n
        require(n <= 100_000, 'cbor_length')
        if major == 2:
            return self.take(n)
        if major == 3:
            try:
                return self.take(n).decode('utf-8')
            except UnicodeError:
                raise Reject('invalid_cbor_utf8') from None
        require(n <= 100, 'cbor_container_size')
        if major == 4:
            return [self.read(depth + 1) for _ in range(n)]
        result = {}
        for _ in range(n):
            key = self.read(depth + 1)
            require(type(key) in (int, str, bytes), 'invalid_cbor_map_key')
            require(key not in result, 'duplicate_cbor_key')
            result[key] = self.read(depth + 1)
        return result

    def end(self):
        require(self.pos == len(self.data), 'trailing_cbor')


def decode(data):
    reader = CBOR(data)
    value = reader.read()
    reader.end()
    return value


@dataclass(frozen=True)
class Policy:
    app_id: str
    environment: str = 'development'
    development_aaguid: str = 'appattestdevelop'
    categories: tuple = ()
    versions: tuple = ()
    cdhashes: tuple = ()
    require_macos_acl: bool = False

    def __post_init__(self):
        require(isinstance(self.app_id, str) and '.' in self.app_id, 'invalid_app_id')
        require(self.environment in ('development', 'production'), 'invalid_environment')
        require(self.development_aaguid in ('appattestdevelop', 'appattestsandbox'), 'invalid_aaguid_policy')
        # Apple validation category 6 is Developer ID on macOS. Policies still
        # choose an explicit category set; enabling the parser does not broaden it.
        require(all(type(x) is int and x in (2, 3, 4, 5, 6) for x in self.categories), 'invalid_validation_categories')
        require(all(isinstance(x, str) for x in self.versions), 'invalid_versions')
        require(all(isinstance(x, bytes) and len(x) == 32 for x in self.cdhashes), 'invalid_cdhash_policy')

    @property
    def aaguid(self):
        return b'appattest' + b'\0' * 7 if self.environment == 'production' else self.development_aaguid.encode()


def authenticator(data, policy, attestation=False):
    require(isinstance(data, bytes) and len(data) >= 37, 'short_authenticator')
    require(data[:32] == sha(policy.app_id.encode()), 'wrong_app_id')
    flags, counter = data[32], int.from_bytes(data[33:37], 'big')
    # No UP/UV expectation: App Attest is not a user-presence WebAuthn ceremony.
    require(not flags & 0x3e, 'unsupported_authenticator_flags')
    # Apple's legacy assertions retain AT=1 while omitting attested-key data.
    # Parse according to the message type, not AT alone (independent fixture).
    if attestation:
        require(bool(flags & 0x40), 'wrong_attested_data_flag')
    offset, cose, credential = 37, None, None
    if attestation:
        require(len(data) >= 55, 'short_attested_data')
        require(counter == 0, 'nonzero_initial_counter')
        require(data[37:53] == policy.aaguid, 'wrong_environment_aaguid')
        size = int.from_bytes(data[53:55], 'big')
        require(size == 32 and len(data) >= 55 + size, 'invalid_credential_length')
        credential = data[55:87]
        reader = CBOR(data[87:])
        cose = reader.read()
        offset = 87 + reader.pos
    extensions = {}
    if flags & 0x80:
        extensions = decode(data[offset:])
        require(isinstance(extensions, dict), 'invalid_extensions')
    else:
        require(len(data) == offset, 'unflagged_extension_or_trailing_data')
    # Unknown extension identifiers are not interpreted as verified policy facts.
    category = extensions.get('apple_validation_category_01')
    version = extensions.get('apple_bundle_version_01')
    cdhash = extensions.get('apple_cd_hash_hash_01')
    hash_type = extensions.get('apple_cd_hash_type_01')
    if policy.cdhashes:
        # Observed macOS 27 profile: a 32-byte digest and one-byte SHA256 selector.
        require(hash_type == b'\x02', 'unsupported_cdhash_type')
        require(isinstance(cdhash, bytes) and len(cdhash) == 32, 'missing_or_invalid_cdhash')
        require(cdhash in policy.cdhashes, 'cdhash_policy_failed')
    # Apple documents UInt32 but its example encodes a four-byte LE byte string.
    if isinstance(category, bytes):
        require(len(category) == 4, 'invalid_category_encoding')
        category = int.from_bytes(category, 'little')
    require(category is None or type(category) is int, 'invalid_category')
    require(version is None or isinstance(version, str), 'invalid_bundle_version')
    if policy.categories:
        require(category in policy.categories, 'category_policy_failed')
    if policy.versions:
        require(version in policy.versions, 'version_policy_failed')
    return counter, credential, cose, {'validation_category': category, 'bundle_version': version,
                                     'cdhash': cdhash.hex() if isinstance(cdhash, bytes) else None,
                                     'extension_names': sorted(str(x) for x in extensions)}


def verify_chain(chain, root_pem, at_time=None):
    require(isinstance(chain, list) and len(chain) == 2 and all(isinstance(x, bytes) for x in chain),
            'expected_leaf_and_intermediate')
    try:
        certs = [x509.load_der_x509_certificate(x) for x in chain]
        require(not certs[0].extensions.get_extension_for_class(x509.BasicConstraints).value.ca, 'leaf_is_ca')
        require(certs[1].extensions.get_extension_for_class(x509.BasicConstraints).value.ca, 'intermediate_not_ca')
        with tempfile.TemporaryDirectory(prefix='appattest-chain-') as tmp:
            folder = Path(tmp)
            (folder / 'root.pem').write_bytes(root_pem)
            for name, cert in zip(('leaf', 'intermediate'), certs):
                (folder / f'{name}.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
            command = ['openssl', 'verify', '-no-CAfile', '-no-CApath', '-no-CAstore',
                       '-trusted', str(folder / 'root.pem'), '-untrusted', str(folder / 'intermediate.pem')]
            if at_time is not None:  # Library-only, for historical fixtures; never taken from HTTP input.
                command += ['-attime', str(int(at_time))]
            command += [str(folder / 'leaf.pem')]
            result = subprocess.run(command, capture_output=True, timeout=5)
            require(result.returncode == 0, 'certificate_chain_failed')
        return certs[0]
    except (ValueError, x509.ExtensionNotFound, subprocess.SubprocessError) as exc:
        if isinstance(exc, Reject):
            raise
        raise Reject('invalid_certificate_chain') from exc


def verify_attestation(raw, key_id, challenge, policy, root_pem, at_time=None):
    obj = decode(raw)
    require(isinstance(obj, dict) and obj.get('fmt') == 'apple-appattest', 'wrong_attestation_format')
    statement, auth = obj.get('attStmt'), obj.get('authData')
    require(isinstance(statement, dict), 'missing_attestation_statement')
    require(isinstance(statement.get('receipt'), bytes) and statement['receipt'], 'missing_receipt')
    leaf = verify_chain(statement.get('x5c'), root_pem, at_time)
    _, credential, cose, signals = authenticator(auth, policy, attestation=True)
    kid = unb64(key_id)
    require(len(kid) == 32 and credential == kid, 'credential_id_mismatch')
    key = leaf.public_key()
    require(isinstance(key, ec.EllipticCurvePublicKey) and isinstance(key.curve, ec.SECP256R1), 'wrong_key_curve')
    point = key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    require(sha(point) == kid, 'key_id_mismatch')
    expected_cose = {1: 2, 3: -7, -1: 1, -2: point[1:33], -3: point[33:]}
    require(cose == expected_cose, 'cose_key_mismatch')
    try:
        nonce_ext = leaf.extensions.get_extension_for_oid(x509.ObjectIdentifier('1.2.840.113635.100.8.2')).value.value
    except x509.ExtensionNotFound:
        raise Reject('missing_nonce_extension') from None
    # DER SEQUENCE { [1] EXPLICIT OCTET STRING (32 bytes) }; no searching for byte substrings.
    require(nonce_ext == b'\x30\x24\xa1\x22\x04\x20' + sha(auth + sha(challenge)), 'attestation_nonce_mismatch')
    if policy.require_macos_acl:
        try:
            acl = leaf.extensions.get_extension_for_oid(x509.ObjectIdentifier('1.2.840.113635.100.8.6')).value.value
        except x509.ExtensionNotFound:
            raise Reject('missing_macos_acl') from None
        # Apple's documented exact ACL octets, with their DER wrappers. Matching
        # the entire extension rejects malformed wrappers and extra elements too.
        expected_acl = base64.b64decode('MEAMAjExMDowCQwCb2uhAwEB/zAJDAJvYaEDAQH/MAsMBG9kZWyhAwEB/zAVDARvc2duoAYMBHJzZWMwBaYDAgEB')
        require(acl == b'\x30\x46\xa3\x44\x04\x42' + expected_acl, 'macos_acl_policy_failed')
    return {'public_key': b64(point), 'signals': signals,
            'receipt_status': 'retained_not_validated', 'receipt': b64(statement['receipt'])}


def verify_assertion(raw, client_data, public_key, previous_counter, policy):
    obj = decode(raw)
    require(isinstance(obj, dict), 'invalid_assertion')
    auth, signature = obj.get('authenticatorData'), obj.get('signature')
    require(isinstance(signature, bytes), 'missing_signature')
    counter, _, _, signals = authenticator(auth, policy)
    require(counter > previous_counter, 'counter_replay')
    try:
        key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), unb64(public_key))
        key.verify(signature, sha(auth + sha(client_data)), ec.ECDSA(hashes.SHA256()))
    except (ValueError, InvalidSignature):
        raise Reject('invalid_assertion_signature') from None
    return {'counter': counter, 'signals': signals}
