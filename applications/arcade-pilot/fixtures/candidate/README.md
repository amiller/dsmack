# Independently written board-search candidate

These three files were authored in this lane by reading the frozen
`5c76d40e77db1f4864dabd4b9398d02589cff330` board source and published search
requirements. They do not copy a contributor PR or a previous paid candidate.
Overlay only these files onto the complete frozen 39-file base source snapshot.
All other source bytes must remain unchanged. No package/test/config changes.

The patch adds an exported pure filter, a transient search control, filtered
counts and rendering. Card controls keep their original underlying-board indices;
filtering never writes persistence and reload starts with an empty query.
The complete overlay tree digest is
`432fc561e2a7d34cdda8c6e29c0cc7cb99c84f644a217900c80f1474f8e4510f`
under the checker path-to-file-SHA256 commitment algorithm.

Real Chromium controls on the existing Zed AMD64 browser image passed all seven
checks for this candidate; the unchanged base failed a functional search
assertion. These are engineering controls, not Mac attestation or payout proof.
