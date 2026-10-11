# App Attest custody experiment

**Completed:** [hardware results](RESULTS.md). Modified code recovered the tested
Keychain-stored secret. The memory-only protocol passed crash/restart, stale
ciphertext and fresh-check-in controls. The canonical bundle is
`custody-20260916T173508Z`; run `verify_evidence.py` to check its public transcripts.

This experiment separates code recognition from protection of an already delivered
secret. It uses synthetic keys and ciphertexts only. Results are recorded in
timestamped `custody-*` directories with public transcripts and file manifests.

The persistent probe generates a disposable P-256 signing key and stores its raw
representation as a data-protection Keychain item, accessible when unlocked on
this device only. It encrypts a synthetic payload under a key derived from that
signing key. A modified build, signed with the same credential and app/access-group
identity, attempts to read the item, sign a fresh challenge, and decrypt the saved
ciphertext. Success demonstrates the limitation of this storage configuration;
it does not prove that every possible Keychain or Secure Enclave policy fails.

The volatile probe is a different compiled executable, containing no Keychain
storage path. Each process generates a fresh P-256 transport key in RAM and binds
its public key, session and network challenge into App Attest. The test authority
checks Apple's root, Mac ACL and the expected CDHash before encrypting a category
key to that process. Parcels also carry a signature under the network public key
pinned in the executable. The receiver decrypts previously stored ciphertext and
signs a fresh challenge using the delivered key; it emits no private-key bytes.

The controller then kills that exact probe process with SIGKILL. A restarted
honest process receives the old parcel before a new release is authorized. The
test expects rejection and no category key, followed by successful decryption and
signing under the same category public key after a new attested check-in. A modified
restart should be denied a new release and unable to reuse the old delivery.

`run_experiment.py` is an interactive lab coordinator, not an attested network peer
or smart contract. It holds the synthetic category key and network signing key in
its own RAM and uses SSH as an untrusted-message transport plus lab process control.
It uses the existing, user-authorized Mac signing rig; it does not change keychain
ACLs or platform security settings. Each run creates a unique test item and paths.

This protocol intentionally trades autonomous restart for interactive recovery.
At least one authorized holder (or a separately designed recovery arrangement)
must retain the category key. If all holders lose their volatile copies, the key
and ciphertext access are lost. A previously approved live process can still hold
the key until it exits; revocation does not erase its memory.

These are application-level lifecycle tests. They do not establish resistance to
kernel attacks, debugging bypasses, swap/hibernation recovery, crash dumps, malicious
dynamic dependencies or physical memory forensics. A production design must place
those within its explicit platform assumptions. Persistent App Attest key handles
may authenticate a new check-in, but must not become a local route to unwrap the
category key without current network authorization.
