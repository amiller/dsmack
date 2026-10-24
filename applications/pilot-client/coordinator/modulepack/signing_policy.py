"""Safe signing policy, stdlib only. Validates the entitlements plist and codesign
metadata for the minimal attested runner before and after signing. This module never
runs codesign or any other tool; build.sh does that and calls check_entitlements /
check_metadata on the extracted artifacts. Team and application identity are explicit
trusted arguments supplied by the caller -- never read from untrusted evidence.
Admission is explicitly versioned: check_entitlements is pinned to the legacy v1
exact-five VZ profile, and HVF builds must call check_entitlements_version with
POLICY_VERSION_HVF -- the v2 profile differs only by the hypervisor key swap and
loosens nothing else."""
import plistlib
import re

TEAM_ID = 'DC9JH5DRMY'
BUNDLE_ID = 'dev.dsmack.provider'

# The exact five keys codesign actually embeds for this app; all required, all checked
# against trusted expected values (team/bundle are caller-supplied, never from evidence).
REQUIRED_ENTITLEMENTS = (
    'com.apple.application-identifier',
    'com.apple.developer.team-identifier',
    'com.apple.developer.devicecheck.app-attest-opt-in',
    'keychain-access-groups',
    'com.apple.security.virtualization',
)

# Policy v2 (HVF admission): the ONLY delta from the legacy v1 profile above is the
# com.apple.security.virtualization (Virtualization.framework / VZ) -> com.apple.security.hypervisor
# (Hypervisor.framework / HVF) key replacement. Identity, App Attest opt-in, keychain
# groups, forbidden prefixes and hardened-runtime metadata rules are identical. Measured
# provenance (Mini, 2026-10-20, public metadata only): the signing certificate subject
# carries OU=DC9JH5DRMY (its CN suffix QJUJ9F2UE4 is a per-certificate identifier, not a
# team), and every provisioning profile on the Mini carries TeamIdentifier DC9JH5DRMY
# with application-identifier DC9JH5DRMY.dev.dsmack.provider. No current profile carries
# com.apple.security.hypervisor -- see runner-vm/packaging/sign-production.md for the endorsement
# constraint that follows from that. NOT yet Astra-approved: admission under this profile
# requires an independent review of the exact policy text and the entitlements plist.
HVF_REQUIRED_ENTITLEMENTS = (
    'com.apple.application-identifier',
    'com.apple.developer.team-identifier',
    'com.apple.developer.devicecheck.app-attest-opt-in',
    'keychain-access-groups',
    'com.apple.security.hypervisor',
)

# Explicit versioned admission registry: version -> (required keys, gated bool key,
# rejection label). check_entitlements stays pinned to v1: legacy callers must never
# see their admission set change without an explicit version argument.
ENTITLEMENT_PROFILES = {
    1: (REQUIRED_ENTITLEMENTS, 'com.apple.security.virtualization', 'entitlement_virtualization'),
    2: (HVF_REQUIRED_ENTITLEMENTS, 'com.apple.security.hypervisor', 'entitlement_hypervisor'),
}
POLICY_VERSION_LEGACY = 1
POLICY_VERSION_HVF = 2

ATTEST_OPTIN = ['CDhash']

# Dangerous entitlements never allowed on this app.
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
    """Validate the entitlements plist raw bytes against the LEGACY v1 profile
    (unchanged default: exact-five VZ admission). HVF admission requires the
    explicit check_entitlements_version(plist, POLICY_VERSION_HVF) call."""
    return _check_entitlements_version(plist_bytes, POLICY_VERSION_LEGACY, team_id, bundle_id)


def check_entitlements_version(plist_bytes, policy_version, team_id=TEAM_ID, bundle_id=BUNDLE_ID):
    """Validate the entitlements plist against an EXPLICIT admission profile version.
    Unknown versions are rejected; there is no implicit upgrade path."""
    require(isinstance(policy_version, int) and policy_version in ENTITLEMENT_PROFILES,
            'policy_version_unknown')
    return _check_entitlements_version(plist_bytes, policy_version, team_id, bundle_id)


def _check_entitlements_version(plist_bytes, version, team_id, bundle_id):
    required, virt_key, virt_label = ENTITLEMENT_PROFILES[version]
    require(isinstance(plist_bytes, (bytes, bytearray)), 'entitlements_not_bytes')
    try:
        ents = plistlib.loads(bytes(plist_bytes))
    except plistlib.InvalidFileException as e:
        raise Reject(f'entitlements_plist ({e})') from None
    require(isinstance(ents, dict), 'entitlements_not_dict')
    for key in ents:
        require(not any(key.startswith(pre) for pre in FORBIDDEN_PREFIXES) and key not in FORBIDDEN_KEYS,
                f'entitlement_forbidden ({key})')
    require(set(ents) == set(required), 'entitlement_keys')
    require(ents['com.apple.application-identifier'] == f'{team_id}.{bundle_id}', 'entitlement_app_id')
    require(ents['com.apple.developer.team-identifier'] == team_id, 'entitlement_team')
    require(ents['com.apple.developer.devicecheck.app-attest-opt-in'] == ATTEST_OPTIN, 'entitlement_attest_optin')
    groups = ents['keychain-access-groups']
    require(isinstance(groups, list) and groups
            and all(isinstance(g, str) and g.startswith(f'{team_id}.') for g in groups),
            'entitlement_keychain_groups')
    require(ents[virt_key] is True, virt_label)
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
