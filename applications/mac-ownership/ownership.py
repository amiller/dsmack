"""Command-line operator authorization and publisher-countersigned Mac links."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from eth_account import Account
from eth_account.messages import encode_typed_data
from eth_utils import is_address

DEFAULT_BROKER = 'https://pod.dstack.soc1024.com/relay-broker'
HOME = Path.home() / '.dsmack'
FIELDS = {
    'MacLink': [('kid', 'bytes32'), ('publisher', 'address'), ('operator', 'address'), ('nonce', 'uint64')],
    'MacUnlink': [('kid', 'bytes32'), ('publisher', 'address'), ('operator', 'address'), ('nonce', 'uint64')],
    'ProvisioningAuthorization': [('operator', 'address'), ('provisioner', 'address'), ('nonce', 'uint64')],
    'ProvisionerRevocation': [('operator', 'address'), ('provisioner', 'address'), ('nonce', 'uint64')],
}
DOMAIN_FIELDS = [('name', 'string'), ('version', 'string'), ('chainId', 'uint256'), ('verifyingContract', 'address')]


def typed_data(domain, name, message):
    return {'domain': domain, 'primaryType': name, 'message': message,
            'types': {name: [{'name': key, 'type': kind} for key, kind in FIELDS[name]],
                      'EIP712Domain': [{'name': key, 'type': kind} for key, kind in DOMAIN_FIELDS]}}


def sign(account, domain, name, message):
    return '0x' + account.sign_message(encode_typed_data(full_message=typed_data(domain, name, message))).signature.hex()


def recover(domain, name, message, signature):
    return Account.recover_message(encode_typed_data(full_message=typed_data(domain, name, message)), signature=signature).lower()


def write_json(path, value):
    path = Path(path).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix='.' + path.name + '-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(value, stream, indent=2)
            stream.write('\n')
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def read_json(path):
    return json.loads(Path(path).expanduser().read_text())


def account_file(path, password_file=None):
    raw = Path(path).expanduser().read_text().strip()
    if raw.startswith('{'):
        password = Path(password_file).expanduser().read_text().rstrip('\r\n') if password_file else ''
        try:
            raw = Account.decrypt(json.loads(raw), password)
        except (ValueError, KeyError, TypeError):
            raise ValueError('cannot decrypt operator keystore; supply its --password-file') from None
    try:
        return Account.from_key(raw)
    except (ValueError, TypeError):
        raise ValueError('invalid signing key file') from None


def cast_run(args):
    try:
        proc = subprocess.run(['cast', 'wallet', *args], capture_output=True, text=True, stdin=subprocess.DEVNULL)
    except FileNotFoundError:
        raise ValueError('cast is required for hardware wallet signing') from None
    if proc.returncode:
        raise ValueError('cast wallet failed; verify the selected hardware wallet is connected and unlocked')
    return proc.stdout.strip()


class OperatorSigner:
    def __init__(self, args):
        self.account = None
        self.cast_flags = []
        if args.operator_keystore:
            self.account = account_file(args.operator_keystore, args.password_file)
            self.address = self.account.address.lower()
        else:
            self.cast_flags = ['--ledger' if args.ledger else '--trezor']
            if args.derivation_path:
                self.cast_flags += ['--mnemonic-derivation-path', args.derivation_path]
            self.address = cast_run(['address', *self.cast_flags]).lower()
            if not is_address(self.address):
                raise ValueError('cast wallet did not return an operator address')

    def sign(self, domain, name, message):
        if self.account:
            return sign(self.account, domain, name, message)
        with tempfile.TemporaryDirectory(prefix='dsmack-typed-data-') as folder:
            path = Path(folder) / 'typed-data.json'
            write_json(path, typed_data(domain, name, message))
            signature = cast_run(['sign', '--data', '--from-file', *self.cast_flags, str(path)])
        if recover(domain, name, message, signature) != self.address:
            raise ValueError('hardware wallet signed with a different operator')
        return signature


class Broker:
    def __init__(self, url):
        self.url = url.rstrip('/')

    def request(self, route, body=None):
        raw = None if body is None else json.dumps(body).encode()
        request = Request(self.url + route, data=raw, headers={'Content-Type': 'application/json'})
        try:
            with urlopen(request, timeout=30) as response:
                return json.load(response)
        except HTTPError as error:
            try:
                detail = json.loads(error.read(4096)).get('error', 'request refused')
            except (ValueError, AttributeError):
                detail = 'request refused'
            raise ValueError('broker HTTP ' + str(error.code) + ': ' + str(detail)) from None

    def ownership(self, **query):
        return self.request('/fleet/ownership' + ('?' + urlencode(query) if query else ''))


def nonce(value):
    number = int(value)
    if number < 0 or number >= 2 ** 64:
        raise ValueError('nonce must be uint64')
    return str(number)


def next_nonce(values):
    numbers = [int(value) for value in values if value is not None]
    return nonce(max(numbers) + 1 if numbers else 0)


def authorization_nonce(state, operator, provisioner):
    signed = [item['revocation'] for item in state['revocations']]
    signed += [item['authorization']['authorization'] for item in state['links'] if item.get('authorization')]
    return next_nonce(value['nonce'] for value in signed
                      if value['operator'].lower() == operator and value['provisioner'].lower() == provisioner)


def mac_nonce(state, publisher, kid):
    return next_nonce([state['nonces']['publishers'].get(publisher), state['nonces']['kids'].get(kid)])


def authorization(args, broker, revoke=False):
    operator = OperatorSigner(args)
    provisioner = args.provisioner.lower()
    state = broker.ownership(operator=operator.address)
    revoked = next((item for item in state['revocations']
                    if item['revocation']['operator'].lower() == operator.address
                    and item['revocation']['provisioner'].lower() == provisioner), None)
    if revoked and not revoke:
        raise ValueError('provisioner revoked; authorize a new provisioner key')
    if revoked and revoke and args.nonce is None:
        result = broker.request('/fleet/revoke-provisioner', revoked)
        if args.out:
            write_json(args.out, result)
        return result
    value = {'operator': operator.address, 'provisioner': provisioner,
             'nonce': nonce(args.nonce) if args.nonce is not None else authorization_nonce(state, operator.address, provisioner)}
    kind = 'ProvisionerRevocation' if revoke else 'ProvisioningAuthorization'
    signature = operator.sign(state['domain'], kind, value)
    if revoke:
        result = broker.request('/fleet/revoke-provisioner', {'revocation': value, 'signature': signature})
        if args.out:
            write_json(args.out, result)
        return result
    result = {'domain': state['domain'], 'authorization': value, 'signature': signature}
    output = args.out or HOME / ('provisioning-' + provisioner + '.json')
    write_json(output, result)
    return {'authorization_file': str(Path(output).expanduser()), **value}


def link(args, broker, config):
    publisher = account_file(args.publisher_key or config.get('publisher_key') or HOME / 'publisher.key')
    publisher_address = publisher.address.lower()
    kid = (args.kid or config.get('kid') or '').lower()
    if len(kid) != 66 or not kid.startswith('0x'):
        raise ValueError('configure kid in ~/.dsmack/mac-ownership.json or pass --kid 0xBYTES32')
    try:
        bytes.fromhex(kid[2:])
    except ValueError:
        raise ValueError('kid must be 0x-prefixed bytes32') from None
    state = broker.ownership(publisher=publisher_address, kid=kid)
    current = next((item for item in state['links'] if item['link']['publisher'].lower() == publisher_address
                    and item['link']['kid'].lower() == kid), None)
    if args.command == 'unlink':
        if not current:
            return {'unlinked': True, 'publisher': publisher_address, 'kid': kid, 'already_unlinked': True}
        value = {**current['link'], 'nonce': nonce(args.nonce) if args.nonce is not None else mac_nonce(state, publisher_address, kid)}
        result = broker.request('/fleet/unlink', {'unlink': value, 'publisherSignature': sign(publisher, state['domain'], 'MacUnlink', value)})
    else:
        provisioner = account_file(args.provisioner_key)
        stored = read_json(args.authorization)
        if stored.get('domain') != state['domain']:
            raise ValueError('authorization domain differs from broker ownership domain')
        auth = stored['authorization']
        envelope = {'authorization': auth, 'signature': stored['signature']}
        if provisioner.address.lower() != auth['provisioner'].lower():
            raise ValueError('provisioner key does not match authorization')
        if recover(state['domain'], 'ProvisioningAuthorization', auth, stored['signature']) != auth['operator'].lower():
            raise ValueError('invalid operator authorization signature')
        same = current and current['link']['operator'].lower() == auth['operator'].lower() and current.get('authorization') == envelope
        link_nonce = nonce(args.nonce) if args.nonce is not None else current['link']['nonce'] if same else mac_nonce(state, publisher_address, kid)
        value = {'kid': kid, 'publisher': publisher_address, 'operator': auth['operator'].lower(), 'nonce': link_nonce}
        body = {'link': value, 'authorization': envelope,
                'provisionerSignature': sign(provisioner, state['domain'], 'MacLink', value),
                'publisherSignature': sign(publisher, state['domain'], 'MacLink', value)}
        result = broker.request('/fleet/link', body)
    if args.out:
        write_json(args.out, result)
    return result


def parser():
    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest='command', required=True)
    for command in ('authorize', 'link', 'revoke-provisioner', 'unlink'):
        sub = commands.add_parser(command)
        sub.add_argument('--config', type=Path, default=HOME / 'mac-ownership.json')
        sub.add_argument('--broker')
        sub.add_argument('--nonce', type=nonce)
        sub.add_argument('--out', type=Path)
        if command in ('authorize', 'revoke-provisioner'):
            keys = sub.add_mutually_exclusive_group(required=True)
            keys.add_argument('--operator-keystore', type=Path)
            keys.add_argument('--ledger', action='store_true')
            keys.add_argument('--trezor', action='store_true')
            sub.add_argument('--password-file', type=Path, default=os.environ.get('DSMACK_KEYSTORE_PASSWORD_FILE'))
            sub.add_argument('--derivation-path')
            sub.add_argument('--provisioner', required=True)
        else:
            sub.add_argument('--publisher-key', type=Path)
            sub.add_argument('--kid')
            if command == 'link':
                sub.add_argument('--authorization', type=Path, required=True)
                sub.add_argument('--provisioner-key', type=Path, required=True)
    return root


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        config = read_json(args.config) if args.config.exists() else {}
        broker = Broker(args.broker or config.get('broker') or DEFAULT_BROKER)
        if args.command in ('authorize', 'revoke-provisioner'):
            if not is_address(args.provisioner):
                raise ValueError('provisioner must be an Ethereum address')
            result = authorization(args, broker, args.command == 'revoke-provisioner')
        else:
            result = link(args, broker, config)
        print(json.dumps(result))
        return 0
    except (ValueError, OSError, KeyError, TypeError) as error:
        # Signing libraries can include key material in their diagnostics; report
        # only bounded errors from this module or generic failure for other types.
        if isinstance(error, (KeyError, TypeError)):
            message = 'invalid ownership response or authorization file'
        elif isinstance(error, OSError):
            message = 'cannot read ownership input or reach broker: ' + (error.strerror or type(error).__name__)
        else:
            message = str(error)
        print('dsmack: ' + message, file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
