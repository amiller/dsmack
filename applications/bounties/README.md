# Bounties

A single-task bounty service with durable attempts, Mac registration, queued execution, evidence uploads and WorkEscrow payment steps. The operator selects the repository, task policy, runtime and verification adapter. Participants select a commit and payee; they cannot select commands, checker code or verification authority.

The implemented example is [Arcade Board search](examples/arcade/). It runs a fixed browser checker against a frozen base and the candidate's three Board files. The service and client mechanisms can support another operator-selected task adapter; the current example and Base Sepolia bridge provide the working configuration.

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
