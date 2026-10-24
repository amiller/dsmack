# Coordinator

`coordinator.py` launches one enrollment or run of the signed Mac app from a
protected local policy file: it checks the app signature and public inputs,
starts the native helper and records the session. `modulepack/` holds its
signing policy, session parser, approved-run and native-helper modules. Both are
packaged into the signed alpha release and loaded by `../alpha_coordinator.py`.

```sh
python3 -I coordinator.py --policy /abs/policy.json --mode run --check-only
python3 -I coordinator.py --policy /abs/policy.json --mode run --execute
```

A final handoff may carry one `execution_profile`
(`dsmack-protected-execution-profile/1`) selecting the workload, resources
(4096 MiB, 1 vCPU, 600 s), scratch/result template sizes and compose manifest
digest; see `coordinator.py` for the accepted values.

Tests copy fixtures beside the source, so run them from a copy under a private
(0700, not group-writable) parent:

```sh
python3 -m unittest -v test_coordinator
```
