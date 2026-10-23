# Operator-assisted alpha distribution candidate

This is a proposed distribution layout for `v0.1.0-alpha.1`, not an announced
release or a download promise. The signed application and base image are the
same artifacts qualified on the configured Apple Silicon macOS 27 Mini. A new
Mac still needs the operator exchange in [the installation guide](../pilot/operator-assisted-mac.md).
No fresh-device quarantine or first-open qualification is implied.

The starter is a credential-free, NONFUNDED full14 browser health fixture. Its
historical third-party source is test data, not new worker authorship. It has no
paid claim, provider credentials, settlement decision, or reward. The fresh
starter packet must be selected and qualified before it is advertised as tested.

## Acquisition layout

Release assets use flat filenames; an offline archive uses directories. For
example `runtime--release.tar.gz` maps to `runtime/release.tar.gz`, and
`diagnostic--workload.img` maps to `diagnostic/workload.img`. The release's
selected asset manifest must provide the exact length and SHA-256 of each file.
A checksum delivered beside an untrusted file does not establish authority.
Independently exchange the expected release-root fingerprint with the operator.

The offline layout contains:

- `runtime/`: immutable application, base, verifier and one starter profile;
  inventory and detached signature selected by the operator.
- `diagnostic/`: the starter public workload disk and its selected descriptors.
- `bootstrap/`: the public root PEM, reviewed three-module release loader,
  official Node 24.15.0 Darwin arm64 archive, and acquisition notices.
- `source/`: the specifically selected source snapshot and complete member map.
- `licenses/`: original component notices and their binary/source correspondence.
- `source-offer/`: retained corresponding-source archives, build/configuration
  records and a manifest mapping exact distributed components to those files.

The candidate inventory intentionally has no usable sequence or validity dates.
The operator selects the then-current release floor plus one after active work
has completed, and a 30-day validity interval. Do not copy a historical Mini
floor, absolute paths, App Attest enrollment, or runtime observations to another
Mac. Bootstrap binding uses the recipient's owned paths and actual runtime.
No key, token, private input disk, replay state or operator database belongs in
these assets.

The existing trust format authenticates profiles inside a complete signed
release inventory. Later task invitations therefore select their own complete
release envelope with the same application/base bytes where applicable, plus
separate public workload and signed task admission. An arbitrary detached
profile is not an authenticated extension to an installed release. Finish the
current attempt and verify its outputs before advancing the installation floor.
Offline acquisition does not make enrollment, service, provider or chain use
offline.

## Source and notices

Retain original notices rather than replacing them with a project-wide license
claim. A source manifest is evidence of selected bytes; it is not a claim that
all upstream history is present or that binaries were reproducibly rebuilt.
The distribution manifest must distinguish:

- Debian base packages: installed binary versions mapped to source package
  versions, original source archives and signed snapshot indexes.
- Ubuntu browser packages: exact installed versions mapped to signed archive
  indexes or explicitly identified historical source-publication records.
- Linux: the exact source archive, selected kernel configuration and build recipe.
- Native Rust dependencies: locked crate checksums and source/notices; a lockfile
  is a conservative dependency set, not proof that every crate was linked.
- Swift dependencies: notices at the selected package revisions, without an
  unsupported claim of a complete linked-binary dependency map.
- gvproxy: its selected original source archive and vendor notices.
- Browser and media tools: the actual bundled Chromium/headless-shell and FFmpeg
  notices, selected binary versions, corresponding source and build provenance.
  Notices alone do not substitute for required source or relinking material.

The exact modified native source snapshot and build records accompany the
application. Missing upstream Git ancestry must be described accurately; it
must not be substituted with an inference from a version string. Source and
notice completeness is assessed per component and applicable license, not from
whether a full upstream Git history was retained.

Agent task recipes and subscription import are separate from this starter.
They retain the operator-local credential boundary documented in the guide.
Distribution of those recipes must accurately describe the VM-local broker and
applicable upstream terms; a provider-free starter does not establish their
qualification or contractual status.
