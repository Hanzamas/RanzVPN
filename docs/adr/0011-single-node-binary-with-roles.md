# ADR-0011: One node binary with roles instead of separate vpnserver and vpnclient

**Status:** Accepted (2026-10-11), as part of the dual-mode decision (ADR-0014: "one node binary with both backends"). Hilmi stated the intent himself: "emang murni gw bikin server yang bisa jadi client, gimana itu?"; the concrete consequence for the slim fork is ADR-0012 (Accepted, ticket #23).

## Context

SoftEther ships `vpnserver`, `vpnclient` and `vpnbridge` as separate executables and separate code (`Server.c`, `Client.c`, cascade in `Link.c`). The cascade feature already is "a server acting as a client to another server". In the new architecture (ADR-0004, ADR-0005, ADR-0010) every participant is a node: a site gateway is a client of the hub and a server for its LAN at the same time; two clients can peer directly; a hub is a node that relays and advertises routes.

## Decision

- The new core is **one binary** running as one Windows service. Its role (client, gateway, relay, or several at once) comes from configuration and the control plane, not from which executable was installed. The same binary carries both data-path backends, L2 switched (TAP adapter) and L3 routed (Wintun), selected per network (ADR-0014).
- The client role carries the platform-specific pieces that a server does not need: setting local routes and DNS (default route via Wintun), handling sleep and roaming, being controllable by the logged-in user. That is a module inside the binary, not a separate program.
- `vpnbridge` is already gone from the slim fork (ticket #5); `vpnclient` is the subject of ADR-0012.

## Consequences

- Hub-to-hub, hub-to-user and P2P are one mechanism: nodes try a direct connection (STUN and hole punching) and fall back to a relay node, the model used by Tailscale and similar systems.
- During the transition, endpoint users connect with the stock SoftEther client to the legacy SE-VPN listener of the slim fork; once the new node binary exists, the client is the same binary in the client role.
- The admin surface becomes the API that the planned web UI uses; vpncmd's 25k lines of CLI are not carried over.
