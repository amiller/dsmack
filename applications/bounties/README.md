# Bounties

A single-task bounty service with durable attempts, Mac registration, queued execution, evidence uploads and WorkEscrow payment steps. The operator selects the repository, task policy, runtime and verification adapter. Participants select a commit and payee; they cannot select commands, checker code or verification authority.

The [Arcade examples](examples/arcade/) check Board search, Board undo/redo, Puzzle corner deadlocks and Routes segments/gaps. Each overlays three candidate app files on a frozen base and runs a protected browser checker. [Task profiles and check definitions](examples/arcade/checker/BONUSES.md) describe the three additional profiles. The Mac app and base VM are shared across them.

## Layout

- `service/`: Node24 HTTP/SQLite service and remote worker jobs.
- `runner/`: runtime setup, Mac client/node worker, evidence verification and cleanup.
- `chain/`: WorkEscrow transaction preparation and trusted verifier bridge.
- `examples/arcade/`: Board-specific page, checker, fixtures, task factory and guest driver.

Start with the [Arcade example](examples/arcade/README.md), [Mac client](runner/README.md) or [service configuration](service/README.md). Shared runtime installation and coordinator modules live in `applications/pilot-client`.

Run the service without a build or npm install:

```sh
ARCADE_CONFIG=/absolute/private/config.json node applications/bounties/service/server.mjs
```

`ARCADE_CONFIG`, the deployed `/arcade-pilot` route, schema/domain identifiers and existing runtime installation names remain compatible with the current deployment.
