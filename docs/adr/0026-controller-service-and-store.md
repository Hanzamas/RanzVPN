# ADR-0026: The controller is a separate Go service with rqlite as its store

**Status:** Accepted (2026-10-20, from the SDN spec #176 that Hilmi filed; recorded by SDN-1, #177). Supersedes the `controller` role of ADR-0022 (one active plus a passive standby inside the node binary), CORE-S5-1 (#77) and CORE-S6-2 (#81). See the ADR-0011 and ADR-0022 amendments of 2026-10-20.

## Context

ADR-0022 put a `controller` role into the node binary, one active per deployment plus a passive standby, and left route advertisement, approval, health checks, ECMP and controller failover for a later spec. The SDN of #176 needs much more from the control plane: an intent store with revisions, IPAM and DNS zones, compilation of intent into per-node desired state, a web UI, an HTTP API and a CLI, licence checks, event and metrics export, and high availability without manual failover.

Replicated stores on Windows (research of 2026-10-20, #176):

- **hashicorp/raft** (used by Consul and Nomad on Windows) and **rqlite** (Windows binaries, Raft failover) work.
- **dqlite** and **LiteFS** have no Windows support. **Litestream** is backup only. **sqld** has no native Windows build. **Embedded etcd** is Tier 3 on Windows.
- **Postgres** would add a database server to every installation, including a small site with one controller.
- The stores that work on Windows (rqlite, hashicorp/raft) are Go, as is GoBGP behind the `ranz-bgp` sidecar (ADR-0010).

## Decision

1. **`ranz-controller` is a Go service** that runs as a Windows service, or as a Linux service or container. It is the single authority: it stores intent, owns IPAM and DNS zones (ADR-0028), compiles intent into per-node desired state and pushes it over the Noise control stream (ADR-0027), serves the web UI, the HTTP API and the `ranz` CLI (ADR-0031), checks the licence (ADR-0036), and exports events and metrics (ADR-0030).
2. **The node is the data plane only.** The `controller` role leaves the node binary; its roles are `server`, `client`, `bridge` and `relay` (ADR-0011 amendment of 2026-10-20).
3. **The store is rqlite, run as a sidecar of each controller**, with one code path for a single member and for a 3 or 5 member cluster. If rqlite proves unreliable on Windows, the fallback is hashicorp/raft embedded in the controller with an SQLite state machine, the library that rqlite itself uses. Postgres is not used.
4. **A single controller with its embedded store is the default**, so a small site runs one process and no database server. It grows into a 3 or 5 member cluster, so losing one (or two) members does not stop management. The cluster elects a new leader by itself; a failed controller host needs no manual failover.
5. **A control-plane outage is not a data-plane outage:** nodes keep forwarding with their last applied Generation when every controller is down (ADR-0027).
6. **The node keeps `winsqlite3` for its local state** (ADR-0022). The intent lives only in the controller.
7. **Scale target: one controller cluster handles 10,000 nodes, 1,000 VRFs and 100,000 routes**, so management is not split early. Federation between controllers is after v1.

## Consequences

- A new test seam, and the only new one of #176: **controller conformance with a node simulator.** The simulator is a protocol-only node (no Wintun, no data plane) that speaks nanopb over Noise to the controller. Tests apply intent through the public API and assert the control messages each simulated node receives and acknowledges, including controller failover in a 3 member cluster and the scale target.
- CI gains a Go build and test job for the controller (SDN-2, #178).
- The controller is a second product binary next to `ranz-node`, with its own Windows service and Linux packaging.
- To verify during the work: rqlite's Windows support level in practice. A failure there moves the store to the hashicorp/raft fallback without changing the API.
- Tickets: SDN-2 (#178), SDN-17 (#193), SDN-18 (#194).
