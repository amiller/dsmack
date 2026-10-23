# Selected-source dependency notes

This is an inventory of observed dependencies, not a completed licensing/SBOM
approval. Preserve all original copyright, license and notice files when
reviewing a distribution.

- `native/source-tree/source` is the selected modified libkrun source. Its
  original Apache-2.0 license is retained at `native/source-tree/source/LICENSE`;
  Cargo package metadata identifies `https://github.com/containers/libkrun`.
  The exact imported modified snapshot is identified by the native inventory
  SHA-256 in `SOURCE-IMPORT.json` and `QUALIFIED-INPUTS.json`. Original Git history
  was not imported. The upstream base commit and complete patch ancestry remain
  **undocumented in this selected snapshot**. Publishing this source snapshot
  would disclose that gap, not establish upstream ancestry or complete license
  clearance. Retain the original license and notices; complete the ancestry and
  applicable redistribution review before selecting a binary distribution. Do
  not infer an upstream revision from a Cargo version.
- Native transitive Rust dependencies remain pinned in original Cargo.lock
  files. They are not vendored in this source join. A prepared build cache is
  required for the offline cross-build. Generate an SBOM and collect applicable
  dependency licenses in the release build environment.
- The Swift app references Apple `containerization` exactly `0.33.4` and
  `swift-system` exactly `1.8.1`; their concrete revisions remain in the original
  Package.resolved. Dependencies are not vendored here. Obtain and retain their
  actual license/notice material with the release rather than assuming the root
  repository license covers downloaded dependencies.
- The native Swift link uses Apple's DeviceCheck and Hypervisor frameworks and
  an Xcode/macOS SDK. The SDK is not redistributed in this repository.
- The separately qualified external network launcher source is at the selected
  helper inventory `5fe4a972d8fce0523f1bacf9e17d69bb7e9df4dbc37170246ee31ac2736c098c`.
  It is an independent Rust package (`gvproxy-launcher`, edition 2021, libc 0.2)
  and is not part of this app/native source import. Its pinned upstream gvproxy
  v0.8.9 executable, source/license and platform builds need their own release
  artifact/provenance. The host helper's missing Darwin AS/RSS hard cap remains
  an explicit runtime limitation; guest RAM does not provide that host limit.
