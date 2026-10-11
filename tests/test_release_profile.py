import datetime
import importlib.util
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[1] / 'scripts/release'))
spec = importlib.util.spec_from_file_location('sign_mac', Path(__file__).parents[1] / 'scripts/release/sign_mac.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def profile():
    return {'ExpirationDate': datetime.datetime.now() + datetime.timedelta(days=1),
            'TeamIdentifier': ['TEAM'], 'ApplicationIdentifierPrefix': ['PREFIX'],
            'ProvisionsAllDevices': True,
            'Entitlements': {'com.apple.application-identifier': 'PREFIX.example.node',
                             'com.apple.developer.devicecheck.app-attest-opt-in': ['CDhash'],
                             'get-task-allow': True}}


def test_explicit_app_prefix_and_no_debug_permission():
    ent = module.validate_profile(profile(), 'example.node', 'TEAM', 'developer-id')
    assert ent['com.apple.application-identifier'] == 'PREFIX.example.node'
    assert 'get-task-allow' not in ent


@pytest.mark.parametrize('change', [
    {'ExpirationDate': datetime.datetime(2000, 1, 1)},
    {'TeamIdentifier': ['OTHER']},
    {'ProvisionsAllDevices': False},
    {'ProvisionedDevices': ['private-device-id']},
    {'Entitlements': {'com.apple.application-identifier': 'PREFIX.*',
                      'com.apple.developer.devicecheck.app-attest-opt-in': ['CDhash']}},
    {'Entitlements': {'com.apple.application-identifier': 'PREFIX.example.node'}},
])
def test_reject_invalid_distribution_profile(change):
    data = profile()
    data.update(change)
    with pytest.raises(ValueError):
        module.validate_profile(data, 'example.node', 'TEAM', 'developer-id')
