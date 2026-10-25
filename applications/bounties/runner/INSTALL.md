# Check your Mac before setup

`doctor.py` checks this Mac against the setup requirements and prints the exact
setup command. It reads only `GET /api/task`. It downloads no runtime, creates no
directories or keys, and asks for no wallet signature.

You need:

- an Apple silicon Mac on macOS 27 or later
- Python 3 and Node 24, each at an absolute path owned by you or root and not
  group/world writable
- the maintainer public key, SHA256
  `4de4686cb585a54375a9ab859aa533e8a81255d9d2c9a76b96d0ae9006ecc0df`, obtained from
  a source other than the pilot service, saved with `chmod 600`
- free disk for the runtime downloads plus a 12 GiB reserve, and room for the
  expanded runtime and task disks
- a Base Sepolia address you control, which receives the testETH

From `applications/bounties/runner`:

```sh
python3 -I doctor.py --api https://PUBLISHED-PILOT-ORIGIN \
  --home "$HOME/.dsmack-arcade" --node /PATH/TO/NODE24 \
  --public-key /PATH/TO/release-public.pem
```

Each line is `ok`, `fail` or `unknown`, and failed checks print a fix. `unknown
release_approval` means the service publishes the signed runtime identity (key,
sequence, inventory hash) but no approval status; ask the maintainer whether that
sequence is the approved release. When nothing fails, doctor prints the `setup.py`
command and the first `client.py authorization` command. Continue with
[README.md](README.md#worker-owned-mac).

The payee is the `0x` address you pass to `authorization`. It is fixed in your
signed attempt, and only a verified passing commit earns the bonus. Running a node
alone earns nothing.

Add `--json` for machine-readable output. Exit status is 0 when no check fails.
