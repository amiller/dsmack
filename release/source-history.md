# Public source history

This copy preserves the sample's development history and both release tags while
removing old provisioning profiles and archived research IPAs from every retained
revision. Eighteen provisioned-device identifiers were removed; four research
records were redacted. The original repository is retained privately rather than
making its old, potentially cached objects public.

The cleanup changes Git commit IDs. Historical build manifests intentionally keep
the original source IDs and binary hashes: those are the actual build records.
Use [source-commit-map.txt](source-commit-map.txt) to locate the corresponding
public revision. The app, contract, and build-script blobs are unchanged by the
privacy cleanup. Checkout `v0.1.0-rc.2` for the admitted Mac release; latest source
contains subsequent iPhone work and is not interchangeable with that Mac baseline.

Both release application ZIPs and their evidence archives are preserved byte for
byte, with their original SHA256SUMS. The public-source audit records 72 Python
tests passed (five opt-in local-chain tests skipped) and 68 contract tests passed
in the cleaned checkout. The five admission integration tests passed separately
before cleanup. None of this proves a second-team hardware handoff or iPhone
TestFlight admission.

See [the source audit](public-source-audit.json) and
[release asset checks](public-release-asset-audit.json). Those scans cover the
listed identifiers and credential patterns; they are not a proof that arbitrary
undisclosed secrets can be recognized automatically.


After publication, both CLI and GUI jobs passed in the new repository for latest
source ([run 37689437062](https://github.com/amiller/apple-attest-p2p/actions/runs/37689437062))
and the admitted RC2 tag
([run 37689697594](https://github.com/amiller/apple-attest-p2p/actions/runs/37689697594)).
The RC2 CI GUI executable has unsigned SHA-256
`131ec74d226181401891f0c1e22136683e21b83d2917dd9ebe2b3b836b841c08`,
matching the original mini build. Comparing it with the actual signed executable
in the public app ZIP passed the existing strict payload verifier: all original
bytes match except the appended signature load command and validated LINKEDIT
sizes. This does not claim reproducible Apple signatures or notarization.
See [the comparison evidence](../data/publication-20261007/rc2-public-ci-payload.json)
and [CI build manifest](../data/publication-20261007/rc2-public-ci-build-manifest.json).
