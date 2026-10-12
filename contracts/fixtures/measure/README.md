# Measurement vectors

Output of `scripts/release/measure_two_teams.sh` on an Apple Silicon Mac
(macOS 27.0, Xcode 27.0 27A266a) at commit `07e9356`, CLI flavor:

- `honest-a.json`: team `TEAMAAAAAA`, bundle `org.example.alpha.node`, signature size 12000.
- `honest-b.json`: team `TEAMBBBBBB`, bundle `net.example.beta.peer`, signature size 16000,
  built from a second checkout path. Same unsigned executable as `honest-a`.
- `modified.json`: `honest-a` settings, built with `--modified`.

Each file has the `scripts/cd_args.py` fields (`cd`, `page0`, `ent`, `linkeditCmd`,
`codeSigCmd`, `cdhash`) and the expected `M`. Signatures are throwaway self-signed
identities, so these cannot run App Attest. `summary.json` lists M and CDHash per build.
Code sources change M, so these are test vectors for the definition, not admitted values.
