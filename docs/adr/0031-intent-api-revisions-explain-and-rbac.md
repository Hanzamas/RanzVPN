# ADR-0031: Declarative intent API with revisions, rollback, explain and three global roles

**Status:** Accepted (2026-10-20, from the SDN spec #176 that Hilmi filed; recorded by SDN-1, #177). The API is served by the controller (ADR-0026); the web UI relates to #44 (ADR-0021).

## Context

ADR-0021 gives the slim fork an RPC-style HTTP API that mirrors the admin RPCs one to one. An SDN needs a different contract: the network described declaratively so it is reproducible and reviewable, every change undoable, a safe way to make risky changes, and a fast answer to "why can't A reach B". The intent has to stay the truth, so imperative commands must not become a second way to configure the network.

## Decision

### Resource model

1. The Intent is a set of declarative resources:
   - `VRF`: id, name, ULA /48, MTU, conntrack quota and timeouts, topology, route-target import and export lists (ADR-0025).
   - `Network`: belongs to one VRF; L3 (Wintun) or L2 (ADR-0014, VLANs per ADR-0019); IPv4 and IPv6 pools (ADR-0028).
   - `Node`: identity, tags, VRF memberships, roles, reported Capabilities and Egress tier (ADR-0033).
   - `Tag`, `Policy` (rules between tags or FQDN sets with protocol and port, priority, action; ADR-0029), `Route` (static or learned), `DnsRecord`, `Endpoint` (service IP and port in a source VRF, consumer VRF), `Mirror` (source selector, filter, sensor IP, rate limit), `Gateway` (egress, LAN prefixes, HA group), and `BgpPeer` and `EvpnPeer` per gateway and per VRF (ADR-0032).
   - The Legacy phase adds `CompatListener` and `LegacyGateway` (ADR-0037).

### Apply, revisions and rollback

2. **A declarative REST/JSON API.** `ranz apply -f` applies a file of resources, `ranz diff` shows the change, `ranz rollback <revision>` returns to an earlier state.
3. **Every apply creates a revision** that can be diffed and rolled back.
4. **`ranz apply --confirm <duration>`** (for example `--confirm 5m`) rolls back by itself unless the administrator confirms in time, so a risky change cannot lock anyone out. An automatic rollback raises an event (ADR-0030).
5. **The controller reconciles desired and actual state and reports status per resource**, so an administrator sees what is applied and what failed.
6. **Imperative calls exist only for debugging.** The declared intent stays the truth.

### Explain

7. **`ranz explain A B` walks the compiled model for a packet from A to B** and names each step: the VRF, the route (with leaking), the NAT and the policy rule.
8. **Explain is checked against the real data plane.** Scenario files (topology, intent, test packets) run twice, through `ranz explain` in the controller and through the data plane in the vpntest harness, and both must give the same verdict for each packet. Explain cannot drift from what forwarding does.

### Roles and clients

9. **Three global roles:** `admin`, `operator` (applies intent, cannot change roles) and `viewer`. There are no per-VRF roles; a multi-tenant layer is out of scope.
10. **The `ranz` CLI and the web UI are clients of the public HTTP API only**, so everything an administrator can click can also be scripted.

### Migration

11. **A one-time importer reads `ranz_server.config`:** each Virtual Hub becomes a VRF with one Network, users and groups become tags, and the access list becomes policy, building on CORE-F5 (#65) and #76. The old core runs side by side until every Hub has moved.

## Consequences

- The new core's administrative surface is this declarative API on the controller, not the RPC-style API of ADR-0021. That departs from ADR-0021's aim of an API contract that survives the core swap; #224 records the slim fork's web admin (#44) as superseded by the controller web UI (SDN-28). ADR-0021 itself is not amended by #176. *(ADR-0021 is superseded since 2026-10-21 by this ADR, ADR-0026 and ADR-0038; see its amendment.)*
- The importer settles the question left open by the ADR-0022 amendment of 2026-10-19 (whether the importer is needed): #176 keeps it, as SDN-27 (#203).
- The unified-management spec #224 (2026-10-21) adds administrators scoped to one Network with quotas and permissions (SDN-38, #231) and a separate operations API for live sessions (SDN-50, #243). The three role names stay; the scope is a Network, not a VRF.
- The controller conformance seam (ADR-0026) covers revisions, rollback, `--confirm` and RBAC; explain conformance is its own suite over shared scenario files.
- Tickets: SDN-13 (#189), SDN-14 (#190), SDN-15 (#191), SDN-27 (#203), SDN-28 (#204).

## Amendment 2026-10-23: source restrictions for the console and for enrolment (SDN-39)

Recorded by SDN-39 (#232), the source-IP restrictions of the unified-management spec #224 (stories 25 and 51). Decisions 9 and 10 hold: there are still three global roles, and the CLI and the web UI are still clients of the public API.

- **The admin source allowlist** is a list of source prefixes (CIDR prefixes or single addresses, at most 256) that the controller's API and web UI accept connections from. It replaces `$adminip.txt` of the slim fork. With no prefix in it, every address is accepted, as before: it is off until an administrator sets it, because a controller on a rented host is often managed from anywhere.
- **It is not an Intent resource.** It lives in the store (table `admin_sources`) and is read and changed through `GET` and `PUT /api/v1/admin-sources`, which need the `admin` role (`ranz admin-sources`; `Needs` names the path beside `/api/v1/tokens`). An operator applies Intent, and must not widen from where the console can be reached; a revision, a rollback or an import must not change it either. A store backup holds it, an Intent export does not.
- **The check stands in front of the API and the web UI, outside the Guard** (`api.Sources`, wired in `ranz-controller`): a request from an address outside the list is answered 403 before anyone looks at its token, so an address outside learns nothing about tokens. Every member of a controller cluster makes the check on the requests it accepts, from the store, which it reads once in 2 s. While the store fails, the list read last stays in force; a member that never read one serves nothing but loopback requests: 503.
- **A loopback address always passes**, before the list is read, so the administrator of the controller's host can always reach it, and `ranz` on that host (`https://127.0.0.1`) works whatever the list says, a damaged one or one that cannot be read included. A controller must not run behind a reverse proxy on its own host, which would make every client look like loopback; it ends its own TLS and shares its port with the control stream (ADR-0035).
- **A change cannot lock its maker out.** A `PUT` of a list that does not hold the address the call came from is refused with 409 Conflict, unless that address is loopback.
- **In a cluster, the list holds the addresses of the members too.** A standby forwards a call to the leader over HTTPS from its own address, which the leader checks like any other. No header of a forwarded call is trusted for the address of the first caller: a client could set it and skip the check.
- **Each refusal and each change is an Event** (`admin-access-refused` with the method, the path and the address; `admin-sources-changed` with the API token that made the change). An Event is a write through the Raft log of the store, so a client that is refused again and again must not make one per request: `event.Throttle` records a source once a minute and 30 sources at most in a minute, and the next record carries the count of the refusals it left out. The audit log of SDN-49 (#242) records failed authentications and enrolments too; these Events are the records until it exists.
- **Enrolment sources.** A Network may carry `enrolSources`, the source prefixes that its Nodes may open their control stream from. The controller checks the address of every control stream against every Network of the VRFs of its node, once the node's key is known and before the node reports its Capabilities or gets any state. One Network that does not hold the address refuses the node: `REFUSE_REASON_UNKNOWN_NODE`, the one reason of the control protocol for a node that is not admitted, with a message that names the address and the Network. The refusal is an Event too (`enrolment-refused`), throttled in the same way. A change of the Intent that tightens `enrolSources` refuses the streams that it no longer allows at once.
- **The check is made at every stream, not only the first.** The Intent holds no record that a node enrolled, and a stolen node key then does not work from another network. A node that moves to another address must be allowed in, or its Network lists no source prefix. `enrolSources` stays on the controller: it is no part of a node's desired state, so changing it gives no node a new Generation.
