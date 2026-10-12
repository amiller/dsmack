# Check the participation release

The [tagged Mac app](https://github.com/amiller/apple-attest-p2p/releases/tag/v0.1.0-rc.3)
is the legacy Dsmack participation research release. It requires Apple silicon,
macOS 27, Full Security and System Integrity Protection. Opening it automatically
attempts network enrollment through a sponsored Base Sepolia transaction.
It does not install a coupon issuer or grant treasury authority.

Before sharing the download, run this dependency-free check from the repository:

```sh
python3 tools/check_participation_release.py --output /tmp/participation-check.json
python3 -m unittest discover -s tools -p test_check_participation_release.py
```

The checked-in [release manifest](release-v0.1.0-rc.3.json) pins the exact public
ZIP by byte count and SHA-256, plus its measured network's relay, chain and
contract addresses. Insecure HTTPS-to-HTTP redirects are refused. The command downloads into memory without retaining an
installed copy, reads the contracts at one observed block, and checks the relay's
advertised network and sponsor pause state. The observed block must be at most
120 seconds old and no more than 15 seconds in the future according to the local
clock, with a correctly shaped hash and matching block number. It performs no enrollment, mailbox
receive, transaction submission, app launch or coupon call. Each HTTP response is
limited to 8 MiB, requests time out after 15 seconds of socket inactivity, and a
90-second elapsed deadline is checked before and after each request. This is not
a hard process deadline under a continuously trickling response; an external
process timeout can enforce one when required.

Exit 0 means these read-only checks passed; exit 1 means a check failed; exit 2
means the manifest could not be read. A failure does not establish that the network
is down: RPC rate limits and transient network failures also fail closed. A passed
check does not verify contract bytecode identity, finality, sponsor balance, seed
liveness, app admission, peer exchange, independent operators or coupon readiness.
The public RPC and relay supply observations, not a cryptographic admission proof.
The manifest is reviewed repository configuration, not a signed network policy.

[The October 11 observation](qualification-20261011.json) passed download integrity,
relay identity and unpaused network checks. [Separate Mac verification](mac-package-verification-20261011.json)
checked the newly downloaded ZIP's strict code signature, stapled notarization ticket
and executable hash without opening the app. These are dated observations.
No new independent-device acceptance was performed; the next step is a friend
opening this exact release on their own compatible Mac and reporting admission,
peer exchange and restart results. Existing Keychain and Application Support state
must be preserved during upgrades.

## Export a native network observation

```sh
python3 tools/participation_status.py --output /tmp/participation.json
```

This reads the pinned network's current pause state, overall shared-key epoch
and public-key fingerprint, and relay configuration/pause state. It checks a
fresh block (maximum age 120 seconds, future tolerance 15 seconds) and rechecks
its hash after contract reads. The RPC remains trusted; these are observations,
not a light-client proof, finality guarantee, code-identity verification or live
peer admission. Dashboard consumers must expire the observation after 90 seconds.
The exporter shares the checker's HTTPS, byte, request and elapsed-time limits.

The participant list is **empty by default**. To include a registry identity,
obtain its operator's explicit public-directory opt-in, review that inclusion,
and supply a JSON array of member IDs with `--roster /path/to/public-opt-in.json`.
The maximum is 64 unique identities. The exporter does not authenticate consent;
the release operator is responsible for retaining and reviewing it. Public
on-chain events, past public evidence and receipt ownership are not permission
to enter a participant in this directory. The exporter does not scan events or
publish counts of nonparticipating identities.

Each opted-in identity is read at the same observed block and includes its
registration state, category, last on-chain check-in and revocation flag. Owner
addresses are neither exported nor counted as independent operators. An old
check-in does not prove online/offline state; revocation and registration do not
establish current App Attest eligibility or a service capability. Coverage is an
operator-supplied public opt-in roster, not an authenticated self-published service
directory or a network census. Independent-device/operator counts and liveness
remain unknown. Missing/malformed/stale RPC or relay data produces a narrow
`unknown` result with an empty list rather than retaining partial observations.

Write the output to a reviewed public directory only when its roster and service
publication are authorized. File replacement is atomic. Run offline checks with:

```sh
python3 -m unittest discover -s tools -p test_participation_status.py
```
