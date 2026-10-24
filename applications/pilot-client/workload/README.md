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
