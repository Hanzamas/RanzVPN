# ADR-0027: Node and controller synchronisation by Generation, delta and acknowledgement

**Status:** Accepted (2026-10-20, from the SDN spec #176 that Hilmi filed; recorded by SDN-1, #177). Keeps the control transport of ADR-0022 (nanopb on the Noise control stream) and adds the state model on top of it.

## Context

ADR-0022 fixed how the control plane talks to a node (protobuf encoded with nanopb on the Noise control stream, no gRPC in the core) but not what state it carries or how a node knows which configuration it runs. With the controller as a separate service (ADR-0026), a fleet of up to 10,000 nodes, rolling upgrades of the controller cluster and nodes that must keep working while every controller is down, the state model has to be explicit.

## Decision

1. **The transport is unchanged:** nanopb-encoded protobuf on the Noise control stream (ADR-0022). The C node and the Go controller build their messages from one protobuf schema.
2. **Desired state per node with a Generation.** The controller keeps the desired state of each node, numbered by a Generation, so a node knows exactly which configuration it runs.
3. **Deltas against the last acknowledged Generation.** The controller pushes only the changes since the Generation the node last acknowledged, so a large fleet does not resend whole tables.
4. **The node reconciles and acknowledges the Generation it applied.** Operators see which nodes lag behind.
5. **A VRF table is applied atomically:** the node rebuilds it beside the live table and swaps it in (ADR-0025).
6. **No controller reachable:** the node keeps forwarding on its last applied Generation.
7. **The schema is versioned.** A controller supports nodes of version N and N-1 and refuses older ones with a clear error, so a node never runs half-understood state. Controller clusters upgrade rolling, and the fleet follows in rolling steps.
8. **The same stream carries the node's reports:** Capabilities (ADR-0033), telemetry summaries (ADR-0030), and the ICE candidate exchange of ADR-0015.

## Consequences

- The controller conformance seam (ADR-0026) asserts these rules from outside: the node simulator receives golden control messages for Generation 1, only a delta for Generation 2, and acknowledges each Generation it applied.
- The atomic swap is checked in the vpntest harness (ADR-0025): forwarding during a Generation change sees either the old table or the new one.
- Tickets: SDN-2 (#178), SDN-3 (#179).
