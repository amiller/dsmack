"""Entitlements and codesign metadata policy for DsmackRunner.app, stdlib only.
sign.sh calls check_entitlements before and after signing and check_metadata on
`codesign -d --verbose=4` output."""
import plistlib
import re

TEAM_ID = 'DC9JH5DRMY'
BUNDLE_ID = 'dev.dsmack.provider'

REQUIRED_ENTITLEMENTS = (
    'com.apple.application-identifier',
    'com.apple.developer.team-identifier',
    'com.apple.developer.devicecheck.app-attest-opt-in',
    'keychain-access-groups',
    'com.apple.security.hypervisor',
)
ATTEST_OPTIN = ['CDhash']
FORBIDDEN_PREFIXES = ('com.apple.cs.', 'com.apple.private.', 'com.apple.security.cs.',
                      'com.apple.security.temporary-exception.')
FORBIDDEN_KEYS = ('get-task-allow',)

# codesign -d CodeDirectory flags bits: hardened runtime required; adhoc/linker-signed
# rejected. Real output has flags inside the CodeDirectory line, not a separate flags=.
RUNTIME_BIT = 0x10000
FORBIDDEN_BITS = ('adhoc', 0x2), ('linker-signed', 0x20000)


class Reject(ValueError):
    pass


def require(cond, reason):
    if not cond:
        raise Reject(reason)


def check_entitlements(plist_bytes, team_id=TEAM_ID, bundle_id=BUNDLE_ID):
    ents = plistlib.loads(bytes(plist_bytes))
    require(isinstance(ents, dict), 'entitlements_not_dict')
    for key in ents:
        require(not any(key.startswith(pre) for pre in FORBIDDEN_PREFIXES) and key not in FORBIDDEN_KEYS,
                f'entitlement_forbidden ({key})')
    require(set(ents) == set(REQUIRED_ENTITLEMENTS), 'entitlement_keys')
    require(ents['com.apple.application-identifier'] == f'{team_id}.{bundle_id}', 'entitlement_app_id')
    require(ents['com.apple.developer.team-identifier'] == team_id, 'entitlement_team')
    require(ents['com.apple.developer.devicecheck.app-attest-opt-in'] == ATTEST_OPTIN, 'entitlement_attest_optin')
    groups = ents['keychain-access-groups']
    require(isinstance(groups, list) and groups
            and all(isinstance(g, str) and g.startswith(f'{team_id}.') for g in groups),
            'entitlement_keychain_groups')
    require(ents['com.apple.security.hypervisor'] is True, 'entitlement_hypervisor')
    return ents


def check_metadata(codesign_text, team_id=TEAM_ID, bundle_id=BUNDLE_ID):
    """Validate `codesign -d --verbose=4` output: CodeDirectory flags must carry the
    hardened-runtime bit without adhoc/linker-signed bits; Identifier, TeamIdentifier
    and the Apple Development authority must match the trusted identity."""
    require(isinstance(codesign_text, str), 'metadata_not_text')
    cd = re.search(r'^CodeDirectory v=\d+ .*?flags=0x([0-9a-fA-F]+)\(.*?\)', codesign_text, re.M)
    require(cd is not None, 'metadata_codedirectory')
    flags = int(cd.group(1), 16)
    require(flags & RUNTIME_BIT, 'metadata_runtime_flag')
    for name, bit in FORBIDDEN_BITS:
        require(not flags & bit, f'metadata_{name}')
    ident = re.search(r'^Identifier=(.+)$', codesign_text, re.M)
    require(ident is not None and ident.group(1).strip() == bundle_id, 'metadata_identifier')
    team = re.search(r'^TeamIdentifier=(.+)$', codesign_text, re.M)
    require(team is not None and team.group(1).strip() == team_id, 'metadata_team')
    require(re.search(r'^Authority=Apple Development:? ', codesign_text, re.M) is not None,
            'metadata_authority')
    digest = re.search(r'^CandidateCDHashFull sha256=([0-9a-f]{64})$', codesign_text, re.M)
    require(digest is not None, 'metadata_full_cdhash')
    return {'flags': flags, 'identifier': bundle_id, 'team_identifier': team_id,
            'cdhash_full': digest.group(1)}
