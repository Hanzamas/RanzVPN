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
8. **The same stream carries the node's reports:** Capabilities (ADR-0033), telemetry summaries (ADR-0030), and the ICE candidate exchange of ADR-0015. The keys that a node reports about itself (`Pins`: the public key of its mimic server, ADR-0023) go on the same stream. The controller applies one change of the keys of a node in 10 s: a report that comes sooner is held, and the last one is applied when the interval ends (AUD1-DT-20, #522).

## Consequences

- The controller conformance seam (ADR-0026) asserts these rules from outside: the node simulator receives golden control messages for Generation 1, only a delta for Generation 2, and acknowledges each Generation it applied.
- The atomic swap is checked in the vpntest harness (ADR-0025): forwarding during a Generation change sees either the old table or the new one.
- Tickets: SDN-2 (#178), SDN-3 (#179).

## Amendment 2026-10-22: schema version 2 (SDN-17)

Recorded by SDN-17 (#193), the controller cluster of the ADR-0026 amendment of the same day.

- **Schema version 2** adds the `Controllers` message, which the leader sends a node of version 2 before the first Update of a stream and whenever the Controller resources change, and `REFUSE_REASON_NOT_LEADER` with `Refuse.leader`, the address of the leader. The `Controllers` message is not part of the desired state and has no Generation: the members do not change what a node forwards on.
- Decision 7 holds: the controller serves nodes of version 2 and 1. A node of version 1 never receives the `Controllers` message.
- A controller runs as version N, or as N-1 during a rolling upgrade of the cluster (ADR-0026 amendment); it then serves N-1 and N-2.

## Amendment 2026-10-26: the TLS fingerprints of the Controller (SDN-92)

Recorded by SDN-92 (#397), the certificate that the Controller serves (ADR-0026 amendment of the same day).

- **A Node pins a key, not a certificate.** The pin of the control stream is the SHA-256 of the SubjectPublicKeyInfo of the certificate of the Controller (SDN-90, `tlsFingerprint` of `ranz status`). A certificate with another key has another fingerprint, so replacing the certificate would strand a Node that pinned the old one, and the Controller cannot reach a Node that is down.
- **The new fingerprint reaches the Nodes over their control streams before the new certificate is served.** This is the first of the two ways that the ticket allows; the second, a pin of the key that the Controller keeps for good, would keep a key that an operator replaces because it leaked. `NodeConfig.controller_tls` holds the fingerprints that a Node accepts, 64 hex digits each, the certificate in use first. It is part of the desired state of the Node, so it has a Generation, a delta and an acknowledgement like the rest.
- **The order is the protocol.** The Controller gives each Node the next Generation with the fingerprint in use and the new one, waits until each Node that is connected has acknowledged it, serves the new certificate to the next handshakes, and gives the Nodes the new fingerprint alone. The C node takes the fingerprints as it applies the state, keeps them in its Controller setting (`tlsFingerprints`) before it acknowledges, and accepts any of them, so it reaches the Controller after the change and after its own restart. The connections that are up stay up.
- **A Node that is not connected could not take it.** The change is refused with the names of those Nodes (409), unless the operator says to go on (`-force`), and each of them gets the new fingerprint by hand with `ranz node controller set`. A Node of a release before this amendment skips the field and acknowledges the state without it, so the Controller cannot tell it from a Node that took the fingerprints: it needs the same.
- **Nothing is sent while there is nothing to say.** A Controller that serves its self-signed certificate and has had no setting sends no `controller_tls`, so its desired states are the ones of before. A certificate for the key that the Controller has already, as the ACME certificate of the Controller always is, has the same fingerprint, and the Nodes are sent it only to know it. No schema version changes with the field.

## Amendment 2026-10-27: live operations on the stream (SDN-50)

Recorded by SDN-50 (#243), the live operations of the ADR-0031 amendment of the same day.

- **Two frames.** `Operation` (controller to node, body 9 of `ControlMessage`) asks a node to read or clear the MAC table or the IP table of one of its L2 Networks, and `OperationResult` (node to controller, body 10) answers it with the same `id`. The id is the Controller's, never 0, and counts up for the life of the process. An Operation is no desired state: it has no Generation, no delta and no acknowledgement, the node does it when it arrives and keeps nothing of it, and it is not sent again to a stream that ends before the answer (the call says `not-connected` for that node). An `OperationResult` that no request of that node waits for, because it came late or because the node made up the id, is dropped and logged, and the node is not refused for it.
- **Only to a node that reports `Capabilities.operations`** (field 12; ADR-0033 amendment of the same day), since a node that does not know a frame ends its stream, as the C node does today. At most 64 Operations wait for the writer of one stream, and a call that would add more fails for that node.
- **`REFUSE_REASON_OPERATOR` (7)** ends a stream on the order of an operator: a disconnect, or the ban of the user that owns the node. `Refuse.message` says which, in at most 255 bytes: the Controller cuts it at a character (`refusal` does for every Refuse), since the reason of a ban is text of an operator and a message that ends inside a character cannot be encoded. A node that does not know the value keeps the number and the message, as the C node does (`LastRefuse`, `LastMessage`), and dials again after the delay of a refused stream.
- **No schema version changes with the frames or the reason.** A node of an older release reports no Capability `operations`, so it is sent no Operation, and the reason is a value of an enum that a reader takes as a number.
