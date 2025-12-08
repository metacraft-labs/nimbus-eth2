# Nimbus DVT & Raft Landing Page

Nimbus integrates Distributed Validator Technology (DVT) with a Raft-based transport so validator duties stay live even when only a quorum of nodes is reachable. The documents below explain the concept, data formats, APIs, and Nimbus-specific behavior.

## Concept & Protocol Foundations
- [@distributed-bls-key-generation.md](./distributed-bls-key-generation.md) — End-to-end DKG protocol: participants, security assumptions, message flow, and the mathematical guarantees Nimbus inherits when generating BLS shares collaboratively. Covers coordinator responsibilities, challenge mechanics, and validation of partial public keys.
- [metacraft-labs/dvt-circuits](https://github.com/metacraft-labs/dvt-circuits) — Companion repository of ZK circuits and tooling for verified DKG of Ethereum validator keys; it mirrors the commitment checks referenced throughout the specs.
- [@step-by-step-process_generation-layer.md](./step-by-step-process_generation-layer.md) — Detailed state machine for each generation object, including the ZK commitment that lets public infrastructure verify key material without learning the secrets. Describes API-facing operations (`init`, `setShareId`, `exchangingPartialSecrets`, `finish`) and timeout handling.
- [@distributed-bls-key-generation-logging.md](./distributed-bls-key-generation-logging.md) — JSON log format for replaying generator state after crashes; required for durable resumptions during long ceremonies. Specifies every `op` entry (`genOurSecrets`, `setVector`, `genKeys`, etc.) so tooling can reconstruct or audit the generator.

## Storage & Operator Hand-off
- [@dvt-keystore-specification.md](./dvt-keystore-specification.md) — Extends EIP-2335 to carry either encrypted generation logs or finalized key shares plus cluster metadata (thresholds, remote signer wiring). Includes JSON Schemas for `SensitiveInfo`, `GenerationStore`, and the per-consensus-method fields (`raftPrivateKey`, `genesisNode`, etc.).
- [@dvt-api.yml](./dvt-api.yml) — OpenAPI definition for the `/eth/v1/dvtgen/*` control plane. It covers how coordinators drive each generator state (init, approvals, exchanging shares, fetching results, teardown) and documents request/response payloads so dashboards or CLIs can automate the process.

## Raft Transport & Signing
- [@raft_in_nimbus.md](./raft_in_nimbus.md) — Narrative description of how Nimbus reuses Raft log replication to move signing commands and collect partial signatures before releasing them to Ethereum, including batching, unique IDs, timeout policy, and slashing protection hooks.
- [@raft_spec.yaml](./raft_spec.yaml) — OpenAPI spec for the Raft HTTP endpoints (`/eth/v1/raft/message`, `/eth/v1/raft/reroute`). Shows payload packing (`raw_message` + `anon_messages`), signature envelopes, reroute semantics when Web3Signer traffic must hit a Raft-backed validator, and the expected error responses.

### Reference Architecture
- **Generation layer**: Each Nimbus participant runs the generation state machine described in `step-by-step-process_generation-layer.md`. Progress is logged via the format in `distributed-bls-key-generation-logging.md`.
- **Coordination layer**: A coordinator (which can itself be automated via `dvt-api.yml`) invites participants, collects commitments, and ensures challenges/slashing happen per `distributed-bls-key-generation.md`.
- **Persistence layer**: Finished or in-progress ceremonies are serialized to the DVT keystore format so they can be handed to Nimbus signing nodes or cold storage devices and later re-imported.
- **Transport layer**: Nimbus nodes speaking Raft exchange signing commands and signature shares via the HTTP API in `raft_spec.yaml`, and their operational semantics are defined in `raft_in_nimbus.md`.
- **Execution layer**: Once a Raft leader collects a quorum of shares it assembles the final BLS signature and allows the validator duty to hit the beacon node, completing the loop.

## How DVT and Raft Fit Together in Nimbus
1. **Key material** is produced per `distributed-bls-key-generation.md`, orchestrated through the `dvt-api.yml` service, and logged according to `distributed-bls-key-generation-logging.md` so ceremonies survive restarts.
2. **Shares are stored** using the `dvt-keystore-specification.md` format, which embeds Raft or other remote signer configurations and keeps crypto material encrypted until loaded by Nimbus components.
3. **Validator duties** use Raft as the transport (`raft_spec.yaml`) so a majority of nodes can agree on every signing request before Nimbus exposes signatures, as detailed in `raft_in_nimbus.md`.

Together these artifacts document the full lifecycle: generating threshold keys, persisting them safely, exposing operator APIs, and finally executing duties through a Raft-backed validator cluster.

