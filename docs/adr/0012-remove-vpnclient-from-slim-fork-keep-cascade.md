# ADR-0012: Remove vpnclient from the slim fork, keep cascade

**Status:** Accepted (2026-10-11). Tracked as ticket [Hanzamas/RanzVPN#23](https://github.com/Hanzamas/RanzVPN/issues/23); the spec in issue #1 is amended accordingly. (Earlier in the conversation this was Proposed, then briefly reported as withdrawn, then confirmed by Hilmi.)

## Context

Hilmi's intent is a server that can also be a client (ADR-0011). In the slim fork the server already has that capability as cascade (`Link.c`). The dedicated client (`Client.c`, the `vpncmd /CLIENT` command set, the Neo6 TAP adapter and its installer) exists only for endpoint users, who during the transition can use the stock SoftEther client against the legacy listener.

## Decision

The slim fork keeps only the server binary, which acts as a client through cascade. Remove:
- the `vpnclient` target, `Client.c` / `Client.h` (about 9k lines: the CLIENT object, account store, client RPC dispatch);
- the `vpncmd /CLIENT` mode and all `Pc*` command handlers in `Command.c` (about 5k lines);
- `VLanWin32.c` (client adapter), `vpndrvinst` (client driver installer), the `Neo6/` driver sources and the Neo6 driver packages in hamcore, since nothing in the fork uses them any more. Neo6 remains a candidate L2 adapter for the new product (ADR-0009) and can be taken back from upstream;
- `vpntest` mode `c` and its line in the CI smoke script.

Keep, because cascade uses them: the client side of `Protocol.c` (`ClientConnectToServer`, authentication, signature), `ClientThread` in `Session.c`, `Account.c` (`CLIENT_OPTION`, `CLIENT_AUTH`), `UdpAccel`, `Link.c`, and SeLow with `BridgeWin32.c` for Local Bridge (ADR-0013).

The ticket is blocked by #13 (SecureNAT) and #16 (cloud), because `Client.c` touches both.

## Consequences

- The slim fork becomes server plus cascade plus Local Bridge plus vpncmd server mode; about 20k lines fewer, hamcore without Neo6 packages.
- Endpoint users rely on the official SoftEther client until the new node binary exists (ADR-0011, ADR-0014). *(Superseded 2026-10-19: the stock client is not used at all; see ADR-0011.)*
- `vpntest` and the CI smoke script lose the client mode; the server mode and the named tests remain the verification seam.

## Amendment 2026-10-19

With the stock SoftEther client dropped (ADR-0011 amendment), the client side of `Protocol.c`, `ClientThread`, `Account.c` client structures, `UdpAccel` and `Link.c` are kept only for cascade between Ranz servers and for the harness, until the new core's `client` role replaces Cascade/Link (strangler step 3) and the legacy listener goes (step 8). They are not extended or modernised in the meantime beyond bug fixes and the foundation audit's behaviour-preserving clean-up.
