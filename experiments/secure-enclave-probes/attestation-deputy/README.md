# attestation-deputy

## Question

The runner's code identity is attested. Does that make what it attests, or the
helpers it runs, trustworthy? Specifically: can an unrelated host process get
the runner to attest data it chose, and can a caller-chosen executable capture
the NEAR API key that the runner passes to its quote helper?

## Answer

Yes to both, at source commit `5afe922`. An unrelated host process POSTed a
synthetic NEAR `issue-inference-key` operation to `/attest` and got back an
Apple-rooted enrollment and a valid assertion from the approved code over its
own bytes, wrapped in the `mac-compose-assert/1` domain. And
`QuoteHelper.run` hashes only the helper script, not the `node` executable it
launches, so a substitute `node` received the full (dummy) NEAR key on stdin
and its fake report was accepted.

## Guides

The runner's `/attest` and `/key` interface (`runner/Sources/runner/Guest.swift`)
and any verifier that consumes its evidence. A verifier must check the domain,
the measured guest policy, caller authorization and operation policy, not just
the runner CDHash. The quote helper needs its interpreter pinned or the key kept
out of the subprocess.

## How it works

- `runner-attest/Probe.swift` contains the `Guest` class, `canonical` and the
  `/attest` → `evidence` path copied from `Guest.swift`, with a minimal HTTP
  server on a Unix socket. It enrolls an App Attest key at start, writes
  `ready.txt`, serves one request, saves `response.json` and exits.
- `runner-attest/host-request.http` is the recorded request from the unrelated
  host process. `run.sh` replays it with `nc -U`.
- `quote-helper/Probe.swift` contains `QuoteHelper` copied verbatim from
  `Guest.swift`, with stubs. It points `node` at a shell script that saves stdin
  and prints a minimal report. Controls: a non-NEAR provider must get empty
  stdin, and a changed helper script must be rejected before any subprocess runs.

## Run

```sh
SIGN_ID=... KEYCHAIN=... KEYCHAIN_PW=... TEAM_ID=... BUNDLE_ID=... PROFILE=... \
  ./run.sh /path/to/fresh-work-dir
```

The `/attest` part needs a Mac with App Attest and the `../build-app.sh`
signing variables. The quote-helper part needs only `swiftc` on a Mac
(`xcrun swiftc -parse-as-library quote-helper/Probe.swift -o Probe && ./Probe <dir>`).

## Recorded result

11 October 2026, Mac mini M4 Pro, macOS 27.0 (26A428).

`/attest` (`results/runner-attest-verification.json`): authentic assertion from
the approved probe, counter 1. The asserted clientData is

```json
{"compose_hash":"synthetic-compose-hash",
 "data":"{\"account\":\"synthetic.near\",...,\"recipient\":\"host-selected-unrelated-process\"}",
 "domain":"mac-compose-assert/1"}
```

QuoteHelper (`results/quote-helper-output.txt`, `quote-helper-verification.json`):

```
PASS current QuoteHelper sends complete dummy NEAR credential to caller-selected node executable
PASS valid helper hash unchanged; malicious node bypasses helper execution and returns accepted synthetic report
PASS non-NEAR control passes empty stdin
PASS changed helper hash rejected before subprocess; no network or real credential used
```

## Files

| File | Purpose |
| --- | --- |
| `runner-attest/Probe.swift` | Extracted `Guest` `/attest` path behind a Unix-socket HTTP server |
| `runner-attest/host-request.http` | Recorded request from the unrelated host process |
| `quote-helper/Probe.swift` | Extracted `QuoteHelper` with a substitute `node` |
| `run.sh` | Builds and runs both on the Mac |
| `results/runner-attest-verification.json` | Recorded independent check of the `/attest` response |
| `results/quote-helper-*` | Recorded output and summary |

## Provenance

Original sources, evidence and write-ups are in the maintainer's private research archive. Both probes were extracted from
`runner/Sources/runner/Guest.swift` at `5afe922` (file SHA-256 `3cd9efd2…`,
extracted `QuoteHelper` SHA-256 `c91509ee…`). Changes: the original deputy `build.sh` is replaced by
`../build-app.sh`; `run.sh` is new and replays the recorded request with `nc`
instead of the original Python client, which was not preserved. Not copied:
`review_broker_state.py`, a NEAR broker state
concurrency check unrelated to this question.

## Limits

- Both are source extractions in a test app, not the full signed runner binary
  or its VM transport. In the real runner, `Proxy.swift` dispatches host
  `runner.local` requests to `guest.handle`, and `main.swift` relays its socket
  into the guest with 0777 permissions.
- `/attest` cannot produce an arbitrary assertion domain: it always wraps data
  in `mac-compose-assert/1` with the compose hash. A verifier expecting a
  different domain rejects it. The gap is a verifier that treats nested
  host-controlled data as guest-authorized because the CDHash passes.
- The quote-helper run used a dummy key and no provider network; no real
  attestation report was validated.
- Neither issue was fixed at `5afe922`; check the current `Guest.swift` before
  relying on these results.
