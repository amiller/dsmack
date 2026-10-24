# Public workload disk builder

`build_review.py` packages a browser workload's OCI image, manifest and public
inputs with the reusable Linux base. It runs on Linux under `/data` and produces
`workload.img`. Run `python3 -I build_review.py --help` for its required paths.
`transport_loader.py` loads the base image's transport helpers.

The Arcade task factory selects this builder through its publisher configuration:

- `build_helper`: descriptor for this directory's `build_review.py`.
- `build_helper_imports`: descriptor for this directory's `transport_loader.py`.
- `transport_module`: descriptor for the base image's
  `build/launch_vm_dstack_arm64.py`.
- `guest_source`: the base image source containing `runner-content` and `build`.

The factory verifies these descriptors before loading the builder, then overrides
its `IMAGE` and `CONFIG` globals with the application's chosen OCI identities.
Select the new paths and their file descriptors together when updating a publisher
configuration. The builder's CLI and output JSON are unchanged.

## Private inputs

`export_subscription.py --source FILE` writes only the subscription credential
fields to stdout. Pipe it directly into `python3 -I stage_private.py` with the
selected preparation, guest source, transport module and private output directory.
The importer validates the manifest and public projection before reading stdin,
then builds the separate private-input disk for that manifest's workload name.
Its stdout contains staging metadata rather than credential values.

On Linux the importer uses the memfd transport. On macOS select
`--transport-backend darwin-owned-tempfile-v1 --portable-module "$CAPSULE/portable.py"
--temporary-parent DIR`; DIR is an owned mode-0700 directory. `CAPSULE` is this
workload directory. Run each command with `--help` for the remaining required
paths and expected public digests.

`credential_health.py` checks the explicit credential document against the OAuth
profile endpoint and reports a status category. It leaves the credential unchanged.
Run the dummy-credential checks with:

```sh
python3 -B -m unittest discover -s applications/pilot-client/workload -p 'test_*.py'
```
