# Check your Mac before setup

`doctor.py` checks this Mac against the published task and its signed release,
then prints the exact setup command. It reads `GET /api/task`, downloads the small
signed inventory and signature into a temporary directory and authenticates them
with `pilot-client/alpha-release-cli.mjs`: maintainer key, key id, channel,
expiry, Developer ID category 6, platform, the task's inventory digest and the
sequence the task selects. The service chooses that sequence, so it is not a
rollback floor independent of the service. It never downloads the runtime archive, keeps no install state, creates
no keys and asks for no wallet signature.

You need:

- an Apple silicon Mac on the macOS version the signed release requires (27.0 or later)
- Python 3.9 or later and Node 24. Pass Node's resolved absolute path, not a
  symlink, owned by you or root in directories that are not group/world writable.
  Print it with:

  ```sh
  python3 -c 'import os,shutil;print(os.path.realpath(shutil.which("node")))'
  ```
- the maintainer public key:

  ```sh
  curl -fLo release-public.pem https://github.com/amiller/dsmack/releases/download/arcade-browser-v0.1.0-alpha.1/release-public.pem
  chmod 600 release-public.pem
  shasum -a 256 release-public.pem
  # 4de4686cb585a54375a9ab859aa533e8a81255d9d2c9a76b96d0ae9006ecc0df
  ```

- free disk for the expanded runtime and its archive on the `--home` volume, plus
  a 12 GiB working reserve for task and result disks on the state volume (the same
  volume unless you pass `--state-dir` elsewhere). Doctor computes the exact
  figures from the signed inventory
- a Base Sepolia address you control, which receives the testETH

From `applications/bounties/runner`:

```sh
python3 -I doctor.py --api https://pod.dstack.soc1024.com/arcade-pilot \
  --home "$HOME/.dm" --node /PATH/TO/NODE24 \
  --public-key "$PWD/release-public.pem"
```

Each line is `ok` or `fail`, and failed checks print a fix. When every check
passes, doctor prints the `setup.py` command and the first `client.py
authorization` command, quoted for your shell. That command writes
`"$HOME/.dm/REG-AUTH.json"`; the client refuses relative paths, so keep every
request, signature and attempt file in the private `--home` directory setup
creates and pass full paths. Continue with
[README.md](README.md#worker-owned-mac).

The payee is the `0x` address you pass to `authorization`. It is fixed in your
signed attempt. A verified passing commit earns the bonus for that address.

Add `--json` for machine-readable output. Exit status is 0 when every check passes.
