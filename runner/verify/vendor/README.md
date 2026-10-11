# App Attest verifier provenance

`appattest.mjs` is selected from Abalone `lib/appattest.mjs` at revision
`c1d9e478f9241cdaf9438714179d9bb9de38f501`, SHA256
`d888e711c463748bf8c6f8a8931a528fc930af01d3a176bdaf664d31f66e4d32`.
Its accompanying MIT license is preserved in [LICENSE](LICENSE).
The only adaptations resolve the repository root from this module and read the
existing pinned Apple root from `trust/`. Certificate, ACL, CDHash, nonce,
assertion and age verification are unchanged. No sibling checkout is required.

This port itself derives from the DSMACK/edge-tee Python verifier, as stated in
the source header. It is not a new hardware qualification or a general CBOR parser.
