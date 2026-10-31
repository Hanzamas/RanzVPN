# ADR-0011: One node binary with roles instead of separate vpnserver and vpnclient

**Status:** Accepted (2026-10-11), as part of the dual-mode decision (ADR-0014: "one node binary with both backends"). Hilmi stated the intent himself: "emang murni gw bikin server yang bisa jadi client, gimana itu?"; the concrete consequence for the slim fork is ADR-0012 (Accepted, ticket #23). Amended 2026-10-20 (the controller leaves the node binary, SDN spec #176), 2026-10-21 (stock SoftEther peers return through `ranz-compat` in the Legacy phase), 2026-10-22 (the product ships as one `ranz.exe`) and 2026-10-31 (the Roles of a Node are declared in its Node resource).

## Context

SoftEther ships `vpnserver`, `vpnclient` and `vpnbridge` as separate executables and separate code (`Server.c`, `Client.c`, cascade in `Link.c`). The cascade feature already is "a server acting as a client to another server". In the new architecture (ADR-0004, ADR-0005, ADR-0010) every participant is a node: a site gateway is a client of the hub and a server for its LAN at the same time; two clients can peer directly; a hub is a node that relays and advertises routes.

## Decision

- The new core is **one binary** running as one Windows service. Its role (client, gateway, relay, or several at once) comes from configuration and the control plane, not from which executable was installed. The same binary carries both data-path backends, L2 switched (TAP adapter) and L3 routed (Wintun), selected per network (ADR-0014).
- The client role carries the platform-specific pieces that a server does not need: setting local routes and DNS (default route via Wintun), handling sleep and roaming, being controllable by the logged-in user. That is a module inside the binary, not a separate program.
- `vpnbridge` is already gone from the slim fork (ticket #5); `vpnclient` is the subject of ADR-0012.

## Consequences

- Hub-to-hub, hub-to-user and P2P are one mechanism: nodes try a direct connection (STUN and hole punching) and fall back to a relay node, the model used by Tailscale and similar systems.
- During the transition, endpoint users connect with the stock SoftEther client to the legacy SE-VPN listener of the slim fork; once the new node binary exists, the client is the same binary in the client role. *(Superseded by the amendment of 2026-10-19 below.)*
- The admin surface becomes the API that the planned web UI uses; vpncmd's 25k lines of CLI are not carried over.

## Amendment 2026-10-19: no stock SoftEther client, not even during the transition

Maintainer decision (Hilmi: "kita gapakai client softether lama, dan cascade kita juga server kita yang baru"). Ranz is not used with the stock SoftEther client at any point. *(Superseded in part by the amendment of 2026-10-21 below: in the Legacy phase, stock SE-VPN clients, bridges and servers are served by `ranz-compat`; the node and the new protocol stay free of SE-VPN compatibility.)*
- There are no endpoint users before the new node binary exists; the first release that end users run is the node binary in the client role. The slim fork is the foundation and test bed under the new core, not a product on its own.
- Cascade is only ever between Ranz servers. *(Except `ranz-compat` in the Legacy phase, which also dials out as a cascade client to stock SoftEther servers; amendment of 2026-10-21 below.)*
- There are no deployed installs or configs, so wire and config compatibility with SoftEther peers is no longer a requirement. The legacy SE-VPN path (Pack wire format, SHA-0 challenge-response, cascade) is still not rewritten: it is deleted as a whole with the legacy listener in strangler step 8 (ADR-0022), so rewriting it now would be work done twice.
- Consequences for other decisions are recorded in ADR-0012 and ADR-0022 (amendments of the same date); the release spec #43 is re-scoped accordingly.

## Amendment 2026-10-20: the controller leaves the node binary

Maintainer decision, from the SDN spec #176 that Hilmi filed ("the controller leaves the node binary"). Supersedes the `controller` role of ADR-0022 and CORE-S5-1 (#77).
- **The node binary (`ranz-node`, C17) is the data plane only.** Its roles are `server`, `client`, `bridge` and `relay`. The Legacy phase adds a `legacy` role for industrial gateways (ADR-0037).
- **The controller is a separate Go service, `ranz-controller`**, on Windows or Linux, with rqlite as its store (ADR-0026). It is the single authority for intent; the node receives desired state by Generation over the Noise control stream (ADR-0027).
- The rest of this ADR stands: one node binary, one Windows service, both data-path backends, roles from configuration and the control plane, no separate client program.

## Amendment 2026-10-21: stock SoftEther peers return through `ranz-compat` in the Legacy phase

Maintainer decision (Hilmi, comment on #177: "stock SE-VPN clients, bridges and servers are served by `ranz-compat`, while the node and the new protocol stay free of SE-VPN compatibility"). The Legacy phase of #176 brings SE-VPN back through the `ranz-compat` sidecar (SDN-L1 #207, SDN-L2 #208, SDN-L18 #255; ADR-0037).
- **The node and the new protocol stay free of SE-VPN compatibility**, as the amendment of 2026-10-19 says. The legacy SE-VPN listener still leaves the node in strangler step 8 (ADR-0022).
- **After v1, `ranz-compat` serves stock SE-VPN clients, bridges and servers:** it is the frozen slim-fork Cedar with OpenSSL, run as a separate process. Clients and bridges connect to it, on TCP 443 through the front door (ADR-0035), and it dials out as a cascade client to stock SoftEther servers (#224).
- The 2026-10-19 sentence "Ranz is not used with the stock SoftEther client at any point" therefore holds for the node and for v1, not for the Legacy phase.

## Amendment 2026-10-22: the product ships as one `ranz.exe`

Maintainer decision (Hilmi: "jdi 1 exe bisa aio macam windows", then "y" to the design below). Ranz is one product in one file: no second logo, no second download, no step that fetches something else. The amendment of 2026-10-20 stands for processes (the Controller is not a Role and not part of the Node process); this amendment changes the files.

- **One executable per architecture, `ranz.exe`, signed once.** It is a Go multi-call binary: `ranz controller` (the Controller service with its web UI), `ranz bgp` (the BGP sidecar of ADR-0010), `ranz tray` (the laptop tray, SDN-55) and every verb of the CLI. `ranz-controller` and `ranz-bgp` stop being separate files (ONE-1, #310).
- **`ranz.exe` carries the data plane as a payload.** `ranz-node` (C17) and what the Node needs from outside, the Wintun driver, the SeLow package (x64) and the XDP runtime (x64), are embedded in it. `ranz install` writes them into the Ranz folder under Program Files after checking the Authenticode signature and the hash of each file (ADR-0036), installs the drivers and registers the services; `ranz uninstall` reverses it and keeps the data directory (ADR-0020 decision 3). ONE-2 (#311) and ONE-3 (#312).
- **The processes stay separate where a boundary matters.** The Node is its own process and service (`ranzvpnserver`, ADR-0020 decision 4). The Controller is another (`ranz controller`), present only where `ranz install --controller` ran. The BGP sidecar is a third (`ranz bgp`, started by the Node over the named pipe of ADR-0010). Node and Controller keep their own virtual service accounts (ADR-0039), so a Controller crash does not stop the data plane. A laptop installs the Node and the tray only.
- **The rqlite member of a Controller is part of the file too** (ONE-4, #313). ADR-0026 decision 3 stands: rqlite as the sidecar of each controller, one code path for 1, 3 or 5 members.
- **GPL and MPL parts, and `ranz-compat`, stay separate processes** (ADR-0023, ADR-0036, ADR-0037). The process boundary is the licence boundary and, for `ranz-compat`, the boundary that keeps SE-VPN compatibility and OpenSSL out of the Node. They may ride in `ranz.exe` as optional payloads, but a GPL component enters the file only after its licence terms are checked (ADR-0036).
- **Not chosen: one process.** Linking the Go and C halves into one process needs cgo with a second toolchain, or a node written in Go, which goes against ADR-0022 (C17, the strangler reuses the Hub in-process), ADR-0024 (clang-cl) and ADR-0039 (hardening). The user still sees one product: Task Manager shows the Node and `ranz.exe` as two entries of it.

Consequences
- Every installation carries Controller, GoBGP and rqlite code that it may never run, so the file is larger than any one of them; ONE-1 records its size, and each subcommand starts only from its own service or setting.
- An update replaces one signed file, and its payload is extracted and checked again (SDN-59, #252).
- The "optional MSI feature" RanzBgp of ADR-0022 is replaced by the subcommand `ranz bgp`. The MSI becomes a thin wrapper that runs `ranz install` (ONE-5, #314; ADR-0020 amendment of the same date). The XDP install path of ADR-0018 changes with it.
- Tickets ONE-1 to ONE-5 (#310 to #314) sit under #224. New terms for CONTEXT.md: `ranz.exe`, Payload.

## Amendment 2026-10-31: the Roles of a Node are declared in its Node resource (SDN-63)

Recorded by SDN-63 (#290). The Roles of this ADR (`server`, `client`, `bridge` and `relay`) come from the configuration of the node and the control plane, and the Hello of a node carries its Capabilities and no Roles, so the Controller cannot learn them from the node. The Node resource of the Intent has `roles` (the resource model of ADR-0031), which the administrator declares for the checks of the Controller. So far only `bridge` matters: the amendment of ADR-0032 of 2026-10-22 refuses a Network that has a Stretch and a Node with the Role `bridge` that is no gateway of the Stretch, and the Controller makes that check from the declared Roles. Every Node of the VRF of the Network counts as a Node of the Network, since a Network has no list of members of its own. The Controller does not compare the declared Roles with the Roles that a node runs.
