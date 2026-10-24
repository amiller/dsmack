# Arcade Board search example

This example checks a commit from `amiller/bounty-arcade` for the Board search testnet bonus. `task_factory.py` overlays only `apps/board/{index.html,logic.js,ui.js}` onto the fixed base. `checker/` defines the seven browser checks; `guest_driver.py` runs the base and candidate inside the selected workload. `web/` explains the task and payment steps. `fixtures/` supplies the local candidate example.

Use the [Mac client instructions](../../runner/README.md) to install and enroll a runner, request a task and submit its evidence. The [service instructions](../../service/README.md) describe hosting and worker configuration.

For an operator, `runner/configure.py` takes explicit source descriptors named `factory` and `guest_driver` in its selection:

- `factory.path`: absolute path to this directory's `task_factory.py`.
- `guest_driver.path`: absolute path to this directory's `guest_driver.py`.
- Both descriptors include the selected source's `bytes` and `sha256`.
- Publisher `build_helper` selects `applications/pilot-client/workload/build_review.py`; `build_helper_imports` selects its `transport_loader.py`.
- Publisher checker descriptors select this directory's `checker/` files.

The resulting adapter configuration uses those selected paths. Existing deployed configurations keep their selected copies until an operator explicitly updates them.

`prepare_release.py` prepares a checker runtime from existing app/base sources. It shares the factory's image and task selection. Run its `--help` for arguments; preparation, signing, installation and execution remain separate commands.
