# Upgrades without losing identity: key by app, not by build

Status: design v2, built 2026-10-09 (signed CDHash `8a57f022…`; not deployed). Deviation: the legacy volume path is used for any genesis-form app id whose old dir exists, not only the booting build's own pair, so an upgraded build finds the genesis ledger. It replaces an earlier successor-record design.

## Problem

`app_key = HKDF(master, "mac-compose-app-key/1|" + cdhash + "|" + compose_hash)`, and volumes live under `volumes/<cdhash>/<compose_hash>/`. Every runner rebuild or compose change therefore gives the peer a new PeerId, a new slice key and an empty ledger. Two gifts are stranded this way so far: $0.40 on `0a5a5c15…/8a8f4a80…` and $0.38 on `003a7d4e…/21e07ef1…`.

## Design: an app id, as in dstack

1. **App.** An app is a name with a set of admitted builds. Each build is a (cdhash, compose_hash) pair. The KMS allowlist becomes `--allow APP:CDHASH:COMPOSE`, repeatable. A build belongs to exactly one app.
2. **Keys.** `app_key = HKDF(master, "mac-compose-app-key/1|" + APP)`. Every admitted build of the app gets the same app_key, so `/key` paths (PeerId, slice, eth) don't change across upgrades or NEAR rotations.
3. **Compatibility.** An app's id is the string `<cdhash>|<compose_hash>` of its first build. For the live peer, `APP = "003a7d4e…|49e702b3…"`, so its app_key is bit-identical to today's derivation. The PeerId `12D3KooWM1tE…` and its ledger survive the switch to this runner.
4. **Volumes.** `volumes/<sha256(APP)>/<name>.ext4`. When migrating, the runner looks in the old path `volumes/<cdhash>/<compose_hash>/` for the genesis build; there is no copying.
5. **One live build per app.** Before attaching a volume, the runner takes an exclusive `flock` on the image for the whole boot, and refuses to boot if the lock is held. This also closes today's hole of two concurrent boots of the same pair. VZ already refuses a double attach, but the lock makes the refusal explicit and covers the window before attach.
6. **Retiring a build.** Remove it from the allowlist. The KMS refuses `/release` at its next boot, and the lock covers any build still running.
7. **Evidence.** The boot clientData adds `"app": APP`, so `/attest` and receipts name the app. Clients keep admitting builds by (cdhash, compose_hash) as today. The admission list is grouped by app, so a client can see that a new build is the same app.

**Trust shift, stated plainly.** Whoever controls the `APP:CDHASH:COMPOSE` allowlist can admit a new build that inherits the app key, and that build can then read the app's ledger and slices. Today that is the KMS owner, which is dstack's operator-governance model: the app owner can upgrade the worker's code without changing its identity. Clients still re-verify CDHash and compose on every connection, so an upgrade shows up as a changed measurement under the same PeerId. Clients record that per PeerId and show it in `/evidence`.

What goes away from v1: the Successor record, `of: predecessor`, the volume copy, the one-successor bookkeeping, and every client change. The trust is unchanged: whoever admits builds already decides what gets the app's keys, as in dstack's DstackApp.

## The two stranded gifts

`0a5a5c15…/8a8f4a80…` → `003a7d4e…/21e07ef1…` → current is a linear chain, not a multi-predecessor case. Recovery is a one-off ledger merge:
- the old slices' keys come from the old app_keys, which the KMS can derive offline;
- the merge refuses if an account appears in both ledgers.

The ledger format is abalone's, so the abalone side writes the merge script, and the runner side provides the old keys and the images.

## Also worth adding regardless (client)

- Charge trailers report the remaining balance. A client should refuse any reported remaining that is greater than its last recorded remaining. That's the only ledger rollback a client can detect.

## Runner tests

- Two builds with the same APP get the same `/key` values; a different APP gets different values.
- The genesis app id reproduces the old derivation byte for byte. The live peer's PeerId is recomputed from the master and pair, and must match.
- The old volume path is used for the genesis app.
- A second concurrent boot of the same app is refused by the lock.
- A build removed from the allowlist is refused at release.
- The clientData names the app.
