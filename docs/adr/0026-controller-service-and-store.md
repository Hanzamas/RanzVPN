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

## Amendment 2026-10-22: how the cluster elects its leader and upgrades (SDN-17)

Recorded by SDN-17 (#193) for the points where #176 and this ADR leave the mechanism open. Decision 3 holds: rqlite, one sidecar per controller, one code path for one member and for 3 or 5.

- **Members.** Each host runs one `ranz-controller` with its own `rqlited`. The rqlite members form one Raft cluster through rqlite's automatic clustering: every member starts, at every start, with the Raft addresses of all members (`-rqlite-join`, rqlited `-join`) and the cluster size (`-rqlite-expect`, rqlited `-bootstrap-expect`). Without `-rqlite-join` the controller is a cluster of one member, as before, with the rqlite node id `1` of SDN-2. `rqlited` ends with its controller, also when the controller is killed (Pdeathsig on Linux, a job object with kill-on-close on Windows), so a restarted controller finds its ports free.
- **The leader holds a lease in the store, not the rqlite leadership.** One row of rqlite is the lease, in the way of the Kubernetes Lease (client-go `tools/leaderelection`, the reference implementation): the holder renews it every fifth of the lease duration (15 s by default, `-lease`) and steps down when it could not renew for two thirds of it; a standby takes it over once it has seen it unchanged for the whole duration on its own clock, at once when it is free or holds the standby's own name (a restart). A controller that crashes while its rqlite member lives on therefore still fails over, and the Raft leader of rqlite may be any member.
- **Fencing.** Each take-over and each release ends an epoch of the lease. Every write of the leader carries, in the same rqlite transaction, a statement that breaks a CHECK constraint when the lease has another epoch, so rqlite rolls back the whole write: a leader that lost the lease and has not noticed yet writes nothing.
- **Only the leader runs the controller:** it loads the intent and the node states from the store when it takes the lease, applies, compiles, pushes and stores the Acks. A standby refuses a node with `REFUSE_REASON_NOT_LEADER` and the address of the leader, and forwards every API call except the status to the leader, checking the leader's TLS key against the lease, so management works through any member. A forwarded call carries the caller's bearer token (SDN-14, #190), which the standby and the leader both check: the API tokens are in the store, so every member knows them.
- **The members reach the nodes through schema version 2:** the Controller resources of the intent (address and Noise key of each member) go to the nodes of version 2 in a `Controllers` message, outside the Generations, so a node can reach every member. Nodes of version 1 keep working with the members they were given.
- **Rolling upgrade.** A controller of version N serves nodes of N and N-1 (ADR-0027). During a rolling upgrade, the members of the new release start with `-schema-version N-1` until every member runs the new release, in the way of the compatibility version of Kubernetes (`--emulated-version`, KEP-4330): a member that runs as N-1 serves the nodes N-1 serves, sends nothing that N-1 lacks, and refuses resources that N-1 does not know (the Controller resources for version 1). Then the members restart at N one after the other, and the fleet follows.
- **rqlite on Windows** works in practice: the cluster tests run three members, each with its `rqlited`, on the Windows and on the Linux runner, so the hashicorp/raft fallback is not needed.
- **CI** proves it with three `ranz-controller` processes on one runner (`controller/cmd/ranz-controller/cluster_test.go`): a killed leader is replaced and applies keep working, the nodes keep their last applied Generation while no member is reachable, and a rolling upgrade from version 1 to version 2 keeps the cluster and the nodes working.
