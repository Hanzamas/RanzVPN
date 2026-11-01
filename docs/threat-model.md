# Threat model of the new core and the Controller

AUD-1 (#362). This page is the threat model of the new core (the Node, ADR-0022) and of the Controller (ADR-0026). For each plane it says what is protected, where an attacker can reach it, what four attackers can do (an attacker on the path, a malicious peer, a malicious tenant and a thief of a node key), and which control answers each threat. A threat that no control answers is a gap, and each gap is an open ticket, a draft ticket (Appendix B) or an amendment of an open ticket (Appendix C). The standard mode (SDN-76 to SDN-79) has a section of its own, with what the operator must provide, and section 14 says what is out of scope and why.

It is written for the maintainer, for the reviewers of AUD-2 (#364), who check each module against it, and for the auditor of AUD-4 (#365), whose package starts with it. `docs/formal-model.md` proves the handshakes with ProVerif. This page does not repeat its answers: it cites them, and says what the rest of the design rests on. It describes the tree of `integration` at commit `c8bf82f` (2026-10-26). Where the code differs from an ADR it says so, and the differences that the formal model numbers D1 to D8 keep their numbers.

## 1. How to read this page

The ticket names six planes: the Noise session (with its Channel binding, Login and rekey), the transports, the front door and its handoff, the control stream, the API with the web UI and the tokens, and the store with the licence. Sections 5 to 10 take them in that order. Section 11 adds the data plane behind the sessions, because the malicious peer and the malicious tenant are stopped there and not in the sessions. Section 12 is the standard mode, section 13 the entry points that came after the ticket was written (WireGuard Devices, the relay, the sidecars, the pipes of the host).

Each plane has the same parts: what it is, as built; its assets; its entry points and the trust boundaries of section 4 that it sits on; what each attacker can do; and a table of threats. One row of a table is one threat: who makes it, what it does, the control that answers it with its evidence, the status of that control, and the gap that is left. A gap is `G-n` of Appendix A, which names the open ticket that covers it, or the draft ticket `DT-n` of Appendix B.

**Evidence.** Every control names its evidence, of one of five kinds. **code**: a file or a function that was read for this page. **test**: a vpntest or coretest case, a Go test or a CI job, by name. **model**: a query of `docs/formal-model.md`. **ADR**: a decision. **reasoned**: our own argument, which nothing tested, as in ADR-0041. The reasoned rows are the first for AUD-2 to check.

**Status.** **runs**: a production path calls the control. **tests only**: built and tested, with no production caller yet (the table "What runs in production, and what does not yet" of `docs/formal-model.md` says it for the handshakes). **designed**: an ADR or an open ticket, nothing built. **accepted**: a decision accepts the risk, and the row names it. **partial**: a control runs and leaves a part of the threat open, which the gap column names. **open**: no control answers the threat. A row may carry two words ("runs, where typed") when the status differs by case.

**Severity of a gap.** **High**: an attacker of the classes of section 3 breaks a property that the product promises, from outside the host, at little cost. **Medium**: the same with a harder precondition (a local account, an operator token, a leaked file) or a partial break. **Low**: hardening, or a limit that a later feature moves. The severity is our judgement, so it is reasoned, and the maintainer can overturn it.

## 2. What is protected

| id | asset | what matters | where it lives |
|---|---|---|---|
| A1 | The traffic between Nodes: the records of the Noise sessions and the packets of the hosts | confidentiality and integrity; no injection from outside the Intent | the outer session (QUIC or TLS 1.3), the memory of the Node, its adapters |
| A2 | The Intent and its Revisions: who may reach whom (VRFs, Networks, Nodes, Policy, Routes, Mirrors, Listeners) | integrity first, then the confidentiality of the topology | the store of the Controller, and the desired state in each Node |
| A3 | The identity key of a Node, its Noise static key | nobody else holds it | the software key storage provider, in the key set of the service account |
| A4 | The keys of the Controller: its Noise static key and its TLS key | nobody else holds them, and each guards the other | the software key storage provider, in the key set of the service account (a file of mode 0600 on Linux, in CI only) |
| A5 | API tokens | a secret is shown once and kept as its SHA-256 | the store; the file `admin.token` of the data directory; the browser of an operator |
| A6 | Passwords and pinned keys of users | not readable, not guessable offline | the Configuration store of a Node and the table `user_passwords` of the Controller (PBKDF2, 600000 iterations in both) |
| A7 | The store of the Controller and its backups | integrity, since it is the Intent; confidentiality of the hashes, the licence key and the audit targets with their secrets | the rqlite member, its Raft log, the data directory, a backup file |
| A8 | The Configuration store of a Node | the Controller pin, the settings of the sidecars, the pins of users | `ranz_node.db` in the data directory of the Node, with a protected DACL |
| A9 | Availability of the forwarding of each Node, of the control and the API of the Controller, of the front door | traffic keeps flowing while the control plane is down (ADR-0027) | the threads and the sockets of those processes |
| A10 | The audit log and the Events | what an operator or a Node did is recorded and stays | the store, and the audit targets |
| A11 | The licence key, the activation token, the Enterprise feature key, the vendor's signing key | the vendor's protection against copying; it is not a security property that an operator relies on (section 14) | the store, and the vendor's service |
| A12 | The host | no path from the network, or from a low-privilege account, to SYSTEM | Windows |

## 3. Who attacks

The ticket names four attackers. The API and the store need two more, which are marked.

| class | what it holds | what it does not hold |
|---|---|---|
| **On-path attacker** | The network between two parties: it reads, drops, delays, rewrites and sends any packet (the Dolev-Yao attacker of the formal model). Variants: a passive observer; a middlebox that terminates TLS with a certificate of its own, or with the private key of the certificate that a client pins; a prober that connects to a port to learn what listens; on an underlay of the standard mode, a host that can send packets with the source address of a peer. | a key of a Node or of the Controller, unless its scenario gives it one |
| **Malicious peer** | A Node that the Intent names, with its own key, that shares a VRF with the victim and runs code of its own choosing. A compromised Node is the same attacker. | the key of another Node; an API token |
| **Malicious tenant** | A party that controls Nodes or Devices in another VRF, or a User of it. The ticket uses the word, and this page does not call a VRF a tenant (CONTEXT.md avoids it). It holds no API token. Roles are global today (ADR-0031), so a tenant that is given a token for its own VRF is given all of them (AP-5). | a key of a Node of the victim's VRF |
| **Stolen node key** | The private static key of one Node (a copy of a disk or of a backup, a cloned VM, an evicted intruder), used from any address, and nothing else. | any other key, a token, the host |
| **Token holder** (added) | An API token of a role: viewer, operator or admin. | the host |
| **Local user** (added) | A Windows account without administrator rights on a host of the product: any interactive user and any process that it starts. | SYSTEM and the Administrators |

An administrator or SYSTEM on a host of the product is the host. This page does not try to stop it (section 14); the service accounts of ADR-0039 only limit what a flaw of a service gives it.

## 4. Trust boundaries

```
+--------------------------------------------+  +--------------------------------------------+
| ZONE 0  UNTRUSTED NETWORKS                 |  | ZONE 4  THE OPERATOR'S UNDERLAY            |
| the internet, a hostile LAN, a corporate   |  | trusted by decision (standard mode):       |
| proxy: the on-path attacker, the prober,   |  | a LAN, a data center, a private WAN        |
| the stranger, a stolen node key in use     |  |                                            |
+--------------------------------------------+  +--------------------------------------------+
   | B1        | B3        | B4        | B12                  | B9
   |           |           |           |                      |
   v           v           v           v                      v
+--------------------------------------------------------------------------------------------+
| ZONE 1  A NODE HOST   (service account NT SERVICE\ranzvpnserver)                           |
| listeners: front door (TCP 443), msquic (UDP 443), the relay UDP port, the WireGuard port  |
| B2: the front door hands each socket to its owner process: a pipe and WSADuplicateSocketW  |
| ranz-node: Noise sessions, policy, forwarding tables, adapters, relay role, VXLAN module   |
| B10: sidecars, child processes of the same account: ranz bgp, ranz mimic, ranz acme        |
| identity key in the software key storage provider; Configuration store ranz_node.db        |
| B11: admin pipe, client pipe: local accounts (SYSTEM and Administrators are the host)      |
+--------------------------------------------------------------------------------------------+
   | B5  control stream: TLS 1.3 and Noise_IK bound to the TLS exporter, ALPN ranz-control/1
   v
+--------------------------------------------------------------------------------------------+
| ZONE 2  A CONTROLLER HOST   (service account NT SERVICE\ranz-controller)                   |
| ranz controller: the control stream of the Nodes, the API and the web UI on one TLS port   |
| B7: its store is rqlited, a child process: HTTP on 127.0.0.1:4001, Raft on 4002            |
| its keys in the software key storage provider; a data directory with a protected DACL      |
+--------------------------------------------------------------------------------------------+
   ^ B6  HTTPS, bearer token                                  | B8  HTTPS, UDP (the Nodes too)
   |                                                          v
+--------------------------------------------+  +--------------------------------------------+
| ZONE 3  THE OPERATOR'S WORKSTATION         |  | ZONE 5  THIRD PARTIES AND THE VENDOR       |
| a browser with the web UI, the ranz CLI,   |  | activation service, ACME CA, STUN, UPnP,   |
| and the API token that they hold           |  | webhook, OTLP, IPFIX, syslog receivers,    |
|                                            |  | the site behind a decoy                    |
+--------------------------------------------+  +--------------------------------------------+
```

Zones 1 and 2 are two hosts, or one host that runs both (SDN-73). A Controller cluster has 3 or 5 hosts like zone 2, which reach each other on B7. The boundaries:

| id | boundary | what crosses it | who is authenticated, and by what | what protects it | sections |
|---|---|---|---|---|---|
| B1 | any network to the front door (TCP 443) and to msquic (UDP 443) of a Node | the first bytes of every connection | nobody yet | the limits of what the front door reads (a ClientHello of at most 16 KiB, 10 s); the outer handshake; then the Noise handshake | 5, 6, 7 |
| B2 | the front door to the owner process of a protocol | a duplicated socket, and the bytes that the peer already sent | the owner process is found by the name of a pipe | the DACL of the pipe, its first instance, no remote clients | 7 |
| B3 | Node to Node: an outer session (QUIC, TLS 1.3 or REALITY) with a Noise session inside | records of data and control | the server by its pinned certificate; both Nodes by their static keys, bound to the outer session | the Channel binding, the pin, the policy of the VRF | 5, 6, 11 |
| B4 | a Node to a Relay, and the direct path of ICE | datagrams of the peer layer | by static keys: sealed envelopes, bind cookies, peer sessions | the models `peer-*`; the rate limit of the Relay | 13 |
| B5 | a Node to the Controller | the control stream | the Controller by its pinned TLS key and its static key; the Node by its static key, then by the Node resources, the source prefixes and the licence | TLS 1.3, Noise_IK bound to the exporter | 8 |
| B6 | an operator to the Controller | HTTPS: the API and the web UI | a bearer token with a role; first the source address, when an allowlist is set | the Guard, the admin source allowlist, the CSP | 9 |
| B7 | the Controller to its store, and member to member | SQL over HTTP on loopback; Raft | nobody (G-18, G-19) | the loopback address and the ACL of the data directory only | 10 |
| B8 | the Controller or a Node to third parties | HTTPS, UDP | TLS toward the activation service, ACME and the receivers; nothing toward STUN or the home gateway | signatures on tokens and on the revocation list; no redirects in the webhook and audit exporters | 9, 10, 13 |
| B9 | a Node to an underlay of the standard mode, and an EVPN gateway to the fabric of a data center | VXLAN and Geneve datagrams; BGP | nobody on the wire; the source address against the list of named peers, or against the VTEPs of the routes of the fabric | the operator's underlay (section 12) | 12 |
| B10 | a Node to its sidecars | JSON lines, data streams | the sidecar is the process that the Node started | the pipe DACL of the owner alone; the Node takes only that process as the client | 6, 13 |
| B11 | local accounts to a host of the product | named pipes, loopback ports, files | the account, by the DACL of the pipe or of the file | the DACLs; the service accounts (ADR-0039) | 7, 10, 13 |
| B12 | a WireGuard Device to a gateway Node | WireGuard datagrams | the Device by its WireGuard key | WireGuardNT; the policy by overlay address | 13 |

## 5. The Noise session

### What it is, as built

A Noise session (`NOISE_SESSION`, `src/Core/Noise*.c`) runs on the first stream of each outer QUIC or TLS-443 connection. The handshake is `Noise_IK_25519_AESGCM_SHA256`, one round trip: the initiator's static key is the identity key of its Node, and the responder's is the pinned static key of the server. The prologue is the label `ranz session 1`, a type byte and the Channel binding, which is the TLS exporter of the outer session (label `EXPORTER-ranz-session-noise`, 32 bytes; on TLS-443, and on QUIC since CORE-H5). A handshake whose two ends saw different bindings fails at message 1. The handshake payloads are empty, and the records that follow go in clear inside the outer session, which encrypts them once (ADR-0023, single encryption). A session that nothing binds encrypts its records under the Noise keys instead (`NOISE_SESSION_ENCRYPT`).

The first control record of a session that dials a server Role is a Login. The Tunnel joins up to 16 connections of one peer Node, each with its own outer session. A session sends a keepalive every 10 s, is dead after 45 s of silence, and asks its owner every 120 s, or after 2^24 records, to rekey the outer session. `Noise_IKhfs_25519+MLKEM768_AESGCM_SHA256` exists, and a responder runs it when the first record asks for it and CNG has ML-KEM; no client asks (D7).

| part | status | evidence |
|---|---|---|
| the overlay sessions between Nodes: the responder completes the handshake with any static key, and `NodeOverlayAttach` keeps the session only for a peer of the desired state that has that key; there is no Login | runs | code `NodeOverlay.c` (`NodeOverlayAccept`, `NodeOverlayAttach`); the table of `docs/formal-model.md` |
| the Channel binding, by the TLS exporter on both paths | runs | code `TlsExporter`, `TransportQuicExporter`; model `tls443-cert`, `quic-cert` |
| the session with a Login, the pin of a user's key, the join of a further connection to a Tunnel | tests only | no caller of `NodeAcceptSession` outside vpntest (`noisehub`, `nodelogin`, `quic`, `tls`); no Hub of a Node holds a user from the store (`NodeAddHub` adds none) |
| the rekey of the outer session | does nothing | formal-model D5 |
| the hybrid handshake | built, never asked for | formal-model D7 |

### Assets and entry points

The assets are A1 (the records), A3 (the identity key), A6 (the Login secrets, while a Login is in flight), and the availability of the responder (A9).

The entry points are four, all of them read from a stranger before it is known: the first handshake record of every accepted stream (`NoiseSessionAccept`, `NoiseHandshakeRead`), where the responder takes the static key of any initiator and decides after the handshake; the records after it (`NoiseSessionReceive`) and the frames of the stream (`TransportNoiseReceive`: four bytes of length, at most 65537 bytes); the Login and the join Login (`NoiseLoginParse`, then Sam and the key pin); and the headers of the inner frames, which the flow hash reads (`NoiseTunnelFlowHash`). Each has a fuzz target in the registry (`fuzz_noise`, `fuzz_transport`). The trust boundaries are B3, where two Nodes meet, and B1 for the first bytes of a stream (section 4).

### What each attacker can do

- **On the path.** With the outer session intact, it reads and alters no record. A middlebox that terminates the outer session, with a certificate that the client accepts or with the private key of the pinned one, has its relayed handshake fail at message 1: the exporters of its two outer sessions differ (model `tls443-cert`, `quic-cert`, test `quicbind`). Without the binding the same middlebox reads and rewrites everything (negative controls `nobinding-cert`, `endpoint-cert`). It cannot lower the suite (`suite`), replay message 1 (`replay-server`) or complete a handshake as a Node. It can drop, delay and reset, and no software control stops that.
- **A malicious peer.** It completes the handshake as itself and sends data records for the VRFs that it shares with the victim. The victim accepts a packet only if the table of that VRF routes its source to this very peer, and then the Policy judges it (NS-7). It cannot read the session of another peer. It can dial again and replace its own session, and flood within the capacity of its session (NS-8).
- **A malicious tenant.** A handshake needs the static public key of the responder (Noise_IK). A tenant that does not know it fails at message 1; one that does completes the handshake against any responder, and the Node closes the session after it, because its key is no peer of the desired state. Either way it reads and sends nothing. What it costs the Node is a handshake, and today the time of the one thread of the overlay, which a stranger can take with no key at all (NS-9, NS-10).
- **A stolen node key.** It is the Node, to every Node that lists it as a peer and to the Controller (model `overlay-tls443-client`, `control-node-client`): the Channel binding does not matter, since the thief is an endpoint. It also replaces the live session of the real Node (NS-12), which the Node reports once it happens again and again.

### Threats

| id | who | threat | control, with its evidence | status | gap |
|---|---|---|---|---|---|
| NS-1 | on-path | Terminates the outer session and relays the Noise handshake, to read or alter the records: a middlebox with a certificate that the client accepts, or with the key of the pinned one. | The Channel binding puts the exporter of the outer session in the prologue, so the two outer sessions of a middlebox give two exporters and message 1 fails; the client also pins the server certificate and trusts no root. Evidence: model `tls443-cert`, `quic-cert`, `overlay-tls443-cert`, `overlay-quic-cert`, `tunnel-cert`, and the negative controls `nobinding-cert`, `nopin-noise`, `neither-none`, `endpoint-cert`; test `quicbind`; code `NoisePrologue`. | runs | none; a Node of the build before CORE-H5 is refused cleanly over QUIC (the fallback to TLS-443 is G-10) |
| NS-2 | on-path | Replays message 1 of a captured handshake on a new connection. | The prologue holds the exporter of the new outer session, which differs. Evidence: model `replay-server`; test `quicbind` ("a replayed message 1 opens none"). | runs | none |
| NS-3 | on-path | Lowers the suite, from the hybrid handshake to Noise_IK. | The suite is in the protocol name that the hash of the handshake holds. Evidence: model `suite`. | runs | none |
| NS-4 | on-path | Records a session now and decrypts it when a quantum computer exists. | On a bound path the records are encrypted by the outer session only, so the protection is the key exchange of the outer session: X25519MLKEM768 first on TLS-443 where the OS has ML-KEM, X25519 otherwise. The QUIC path is not proven. The Noise static keys are X25519 and stay so (see the position on the hybrid handshake below). Evidence: code `TransportTlsSetGroups`; ADR-0022. | partial | G-4 |
| NS-5 | on-path | Forces the outer session to TLS 1.2, which has the exporter of RFC 5705 and none of the downgrade protection that the model assumes. | The Listener of a Node takes TLS 1.3 only (`NodeListenerUp`; the test `listener` refuses a client of TLS 1.2 only), and so does the control stream. The client transport still offers 1.2 and 1.3 by default (D6). Evidence: code; test; formal-model D6. | partial | G-3 |
| NS-6 | on-path, malicious peer | Waits for a long session to pass the limit of an AES-GCM key (2^24.5 full-size records, RFC 8446 section 5.5). | The session asks the owner to update the outer keys on a schedule, and both transports answer true and do nothing (D5). Whether Schannel and msquic update their keys by themselves is not known: nothing tested it. Evidence: code `TlsStreamRekey`, `QuicStreamRekey`; formal-model D5; reasoned. | open | G-2 |
| NS-7 | malicious peer | Sends a packet with a source address that is not its own, or with the tag of a VRF that it is not in. | `NodeOverlayDeliver`: the table of the tagged VRF must route the source to this very peer and the destination to the host, and then the Policy of the VRF judges the flow (default deny); a tag of a VRF that the Node is not in finds no table and the packet is dropped. Evidence: code `NodeOverlay.c`; tests `vrf`, `vrfpolicy`, `leakpolicy`. | runs, for IP packets | L2 frames: G-21 |
| NS-8 | malicious peer | Floods records, handshakes or keepalives to use the Node up. | The rate limit of a VRF (SDN-20) is the sender's own, so it binds an honest peer only. The memory that a peer can take is bounded by the conntrack quota and the limits of the tables (section 11). The CPU that it can take is the capacity of its own session. Evidence: code `NodeShape.c`; reasoned. | accepted | none: a peer may use the capacity of its session, as on any VPN, and a limit at the receiver is an option (question 5, section 15) |
| NS-9 | stranger, any tenant | Completes the outer handshake and then sends nothing, or one byte of the Noise message at a time. | The Node reads the first frame within `NODE_OVERLAY_HANDSHAKE` (5 s) and closes the stream. But the one thread of the overlay does it, inline: `NodeOverlayAccept` calls `TransportNoiseAccept`, and the same thread reads the sessions of every peer and dials every peer. So each silent connection stops the forwarding of the whole Node for up to 5 s, and one connection every 5 s keeps it stopped. QUIC, and a TLS-443 listener without a decoy (TR-2), let any stranger in; a TLS listener with a decoy sends strangers to the decoy before the thread sees them. Evidence: code `NodeOverlay.c` (`NodeOverlayThread`, `NodeOverlayAccept`), `TransportNoise.c` (`TransportNoiseRead`); reasoned, not measured. | open | G-1, DT-1 |
| NS-10 | stranger | Costs the responder one Diffie-Hellman and one AEAD for each attempt, from anywhere, with no limit for a source. | The listeners that carry the handshake limit their sources before it starts (AUD1-DT-3, #451): the front door and the QUIC listener cap the connections that have not finished their transport handshake, in all and for one source, and give a source a rate for its connections and for its handshakes (`SourceLimit.h`), and what they refuse is in the state of the Node. A Noise handshake that a connection that was admitted starts is not capped by source, and the one thread of the overlay is NS-9. Evidence: code `SourceLimit.c`, `FrontDoor.c`, `TransportQuic.c`; vpntest `sourcelimits`. | partial | NS-9 |
| NS-11 | stolen node key | Completes the handshake as the Node against every Node that lists it, from any address, and holds the access that the Policy gives its tags. Deleting its Node resource, or changing its `publicKey`, removes it from the Peer objects of the next Generation; a Node that cannot reach the Controller keeps the old list (CS-10). | The key is in the software key storage provider, not exportable, in the key set of the service account. The Policy of the VRF limits what the Node may do. Evidence: model `overlay-tls443-client`, `overlay-quic-cert` (the Noise key of a Node alone is the Node to its peers); ADR-0041. | partial | G-6 |
| NS-12 | stolen node key | Replaces the live session of the real Node: a new handshake of a key closes the session that the peer holds for it (`NodeOverlayReplace`), so a thief can keep the real Node off, and the real Node dials again and does the same. | The replacement stays, since it is how a Node that roamed or woke from sleep takes its place again (CORE-S3-1), and a Node cannot tell which of two holders of a key is the real one. The overlay counts the replacements of the session of each peer in a window (more than 5 in 60 s by default) and raises the Event `session-flap` with the peer and the hosts of the sessions that replaced each other, once for each window while it goes on: the node log, `ranz get events`, the Events page and the webhooks show it, and the operator deletes the Node resource and makes a new key (ADR-0030, amendment of 2026-10-27). Evidence: code `NodeFlap.c`, `NodeOverlay.c` (`NodeOverlayReplace`), `ControlEvent.c`, `sessionflap.go` of the controller; tests vpntest `sessionflap` (two holders raise it with both addresses, a peer that roams once raises none, replacements spread over a longer time raise none), `TestSessionFlapReachesTheEvents`. | partial | none: the thief keeps the real Node off until the operator acts |
| NS-13 | stolen node key, at rest | Copies the key from a disk, a backup or a cloned VM. | ADR-0041 (Proposed) designs a TPM-bound identity that signs inside the Noise session: it stops the copy, not an intruder who is on the host. It is not built, and its follow-ups CORE-H4-1 to CORE-H4-9 are named in the ADR and not filed. Evidence: ADR-0041. | designed | G-6 |
| NS-14 | any | Reads or alters the Login password in transit, or replays a certificate Login. | A Login is the first control record of a bound session, inside the outer session, and a certificate Login signs a challenge that comes from the handshake hash of that session. Evidence: model `sec-pw`, `tls443-cert`; test `nodelogin`. | tests only | none |
| NS-15 | malicious peer, any tenant | Guesses passwords by sending Logins, with no limit on the attempts for a user or a source. | In the store, a check costs one PBKDF2 derivation of 600000 iterations, and an unknown user costs the same (`cs_dummy_salt`), so timing tells nothing of which names exist. There is no lockout and no throttle. Evidence: code `ConfigStore.c`, `NodeSession.c`; reasoned. | tests only | G-5, DT-5 |
| NS-16 | holder of a password | Logs in first and pins its own key to a user whose first Login has not come (trust on first use). A user of a Windows domain and an anonymous Login are never pinned. | The pin: later Logins must come from the pinned key (`NodeLoginPinned`; a store that fails to check refuses, FIX-8). Trust on first use is the design of ADR-0022, and admin-issued join tokens are deferred. Evidence: model `tls443-pw`, `tls443-pw-first`; formal-model D8; test `pinfail`. | accepted | none: the model shows the first Login as the attack, and the decision is ADR-0022's |
| NS-17 | stranger | Joins a Tunnel by guessing its id, or with the id of another peer's Tunnel. | The join Login must come from the static key of the Tunnel (`NoiseTunnelJoin`), whatever id it names. Evidence: model `join-identity`, and the negative control `tunnel-nokey-none`. | tests only | none |
| NS-18 | any | Crafts a handshake, a record, a Login or a frame to corrupt the memory of the Node. | The parsers of the module have fuzz targets that run under AddressSanitizer in the full set, and the registry refuses a new parser without one. Evidence: `.github/quality/fuzz-targets.txt` (`NoiseHandshakeRead`, `NoiseSessionAccept`, `NoiseSessionFinish`, `NoiseSessionReceive`, `NoiseLoginParse`, `NoiseTunnelFlowHash`, `TransportNoiseReceive`); the coretest cases `noise` and `session`. | runs | none: the long campaign is AUD-3 (#363) |
| NS-19 | any | Uses the static key of a Node in another protocol, to mount a cross-protocol attack: the key serves the sessions, the control stream and the sealed envelopes of the peer layer. | The three prologues differ in their labels, and the envelopes use another pattern (K). The models do not run the three together (`docs/formal-model.md`, "What the model leaves out"). Evidence: reasoned. | partial | none: AUD-2 (#364) reads it |

### The hybrid handshake, a position

CORE-P2-5 (#382) and the spec of the WireGuard Devices (#374) leave one question to this page: whether the Noise handshake should be hybrid, as the TLS key exchange is. The code has the pattern (`NOISE_SUITE_IKHFS`, ML-KEM-768 through CNG where the OS has it), a responder runs it when the first record asks for it, and no client asks (D7). The position is that this stays so on the bound paths, for four reasons.

- **On a bound session the Noise keys encrypt nothing.** The records go in clear inside the outer session, so what a recorded session gives a quantum attacker is decided by the key exchange of QUIC or TLS, not by Noise. The hybrid group of the outer session (CORE-P2-5) is the control, and a hybrid Noise on top would add no protection to the records.
- **What the X25519 of Noise still decides is who a Node is.** An attacker that can break X25519 later can compute a static private key from its public key, and impersonate the Node from then on. The hybrid pattern does not change that: it protects the keys of one handshake, not the long-term static key. Authentication that survives a quantum computer needs a post-quantum static key or a post-quantum signature, which nothing plans. The answer then is to replace the identity keys, which a Revision does (the Node resource holds the key).
- **A hybrid Noise pays where the records are under the Noise keys:** a session that nothing binds, which today is the CDN path of phase 2 and a QUIC client that got no exporter. For those the hybrid is the only protection of the records against record now, decrypt later. So the CDN transport of phase 2 (#86) should require IKhfs where CNG has ML-KEM, and refuse to run an unbound session without it. That is a requirement on #86, not a ticket of its own.
- **The cost** is a first message that grows by 1200 bytes and a second that grows by 1104 (the ML-KEM-768 key and ciphertext, and their tags), and the ML-KEM operations, which CNG has on Windows 11 24H2 and Windows Server 2025 and later only.

So no hybrid Noise is planned now (the maintainer's decision recorded on #374, 2026-10-25). The pattern stays in the code for the responder, and the position is revisited when the CDN path is scheduled, or when a quantum-safe outer session is proven on both paths.

## 6. The transports

### What it is, as built

A transport (`TRANSPORT`, `src/Core/Transport.h`) is a name and a set of procedures: dial, listen, accept, read, write, close, the Channel binding of a stream, and the update of its outer keys. The Noise session above it does not change with the transport. Three are built.

- **QUIC** (`TransportQuic.c`) on the signed `msquic.dll` of the Schannel build, pinned. ALPN `h3`, BBR, and one reliable bidirectional stream per connection that carries the session. The server certificate is read from the machine store by thumbprint, with its key in a CNG key storage provider. The client pins the certificate by its SHA-1 thumbprint and trusts no root. The Channel binding is the QUIC exporter, which msquic gives from 2.6.
- **TLS-443** (`TransportTls.c`) on Schannel through SSPI, over the Windows TCP stack. AES-GCM and an ephemeral key exchange only, no resumption, X25519MLKEM768 then X25519; TLS 1.3 only on the Listener of a Node, 1.2 or 1.3 on a client by default. A CoDel queue stands in front of the stream for the data records. The transport also has an own decoy (the Trojan posture), a client that splits its ClientHello and omits the SNI, and the outbound proxy path of SDN-61.
- **mimic** (`NodeMimicTransport.c`) over the sidecar `ranz mimic` (Go, REALITY and uTLS). The sidecar makes its own outer TLS session, a third one, the Node talks to it over named pipes, and the first line of each stream carries the binding.

A client races the entries of its fallback list (QUIC, then TLS-443, then mimic) happy-eyeballs style (`TransportRace`, RFC 8305). The transports of phase 2 (CDN and WebSocket, DoH and DoT, the Hysteria mode, the standard-protocol plugin; #86, #95) plug in behind the same interface and are designed only.

| part | status | evidence |
|---|---|---|
| QUIC and TLS-443, as the Listener of a Node and as the dialler of the client role | runs | code `NodeListener.c`, `NodeClient.c`; tests `quic`, `tls`, `listener` |
| the own decoy | tests only: the Listener sets none | code `NodeListener.c`; test `trojan` |
| the mimic transport | runs where its settings are typed on the Node; the Controller gives a mimic server its settings and its clients their links (SDN-94, #423), and the half on the Node that applies them is open (#424) | code `NodeMimic.c`, `controller/internal/desired/mimic.go`; test `mimic`, the mimic tests of the controller conformance |
| CDN, DoH, DoT, Hysteria, the plugin | designed | ADR-0005, ADR-0023 |

### Assets and entry points

The assets are the confidentiality and integrity of the outer session (A1), the certificates with their keys and the pin, the exporter, the camouflage posture that ADR-0023 promises (indistinguishable from HTTPS and HTTP/3 to a classifier of VPN protocols), the REALITY key of a mimic server, and the availability of the listeners (A9).

The entry points are the QUIC Initial and handshake packets (parsed by msquic); the TCP connections that the front door hands over, then the ClientHello and the TLS records (parsed by Schannel); the first frame after the TLS handshake, which the decoy reads (`TransportDecoyIsHandshake`, `TransportDecoyAuthenticate`); on a client, the answers of an HTTP or SOCKS5 proxy and the proxy list of a PAC script (`TransportProxyParse*`) and the ServerHello (`TransportTlsParseHello`); and the TCP listener of the mimic sidecar, with its pipes (B10). The trust boundaries are B1 and B3, B10 for the mimic sidecar, and B8 toward a proxy, a PAC script and an ACME CA.

### What each attacker can do

- **On the path.** It sees the ClientHello of Schannel or the Initial of msquic, which are those of ordinary Windows software, the SNI unless the client omits it, and the ALPN `h3`. It cannot read or alter the session, and a middlebox fails at the pin and at the binding (NS-1). An active prober that connects learns more: the node's certificate, then a closed connection on TLS-443, and no HTTP/3 behind `h3` on QUIC (TR-2). ADR-0023 does not promise to defeat that in v1.
- **A malicious peer.** Its outer session is that of anyone: it connects to a server with the pinned certificate. It can open up to 16 connections for a Tunnel, and no more than that is special.
- **A malicious tenant.** It is a stranger to the listeners: it can connect to every one and run the floods of TR-5, and the stall of NS-9.
- **A stolen node key.** The transports do not use the identity key. The keys of the certificates are other keys (ADR-0023, key separation), and a stolen certificate key lets a middlebox present the real certificate, which the binding then stops (model `tls443-cert`, `quic-cert`).

### Threats

| id | who | threat | control, with its evidence | status | gap |
|---|---|---|---|---|---|
| TR-1 | on-path, passive | Classifies the traffic as a VPN by its fingerprint: ClientHello, QUIC Initial, sizes and timing. | The ClientHello and the QUIC Initial are those of Schannel and msquic, so a classifier of VPN protocols finds ordinary Windows software (ADR-0006 tiers 1 and 2, ADR-0023). A client may split the ClientHello in two segments and omit the SNI toward its own servers. There is no claim against a GFW-class classifier, or against size and timing analysis. Evidence: ADR-0023; test `trojan` (the split and the omission). | accepted | none: tier 3 is the mimic path (TR-9), and the padding of the traffic shape is phase 2 |
| TR-2 | on-path, active prober | Connects to the port and learns that it is no web server. | The decoy exists: after the TLS handshake the server reads the first frame, and a prober whose first message does not open under the static key of the server, for this outer session, is reverse-proxied to a site on loopback (`TransportDecoyAuthenticate`, `TransportDecoyProxy`; test `trojan`). But the Listener of a Node configures no decoy (`NodeListenerUp`), so a prober sees the node's certificate and then a closed connection; and QUIC has no HTTP/3 server behind `h3`. Evidence: code `NodeListener.c`, `TransportTls.c`; test `trojan`. | tests only | G-9, DT-4 (the static site itself is #353) |
| TR-3 | malicious peer, any holder of the key | Tells a node from the decoy: the decoy lets a client through if its first message opens under the static public key of the server, and a peer knows that key. | The key is not published by the Node. The Intent shows it to a viewer and the control plane gives it to the peers, so the holders are insiders. Evidence: code `TransportDecoyAuthenticate`; reasoned. | accepted | none |
| TR-4 | on-path | A middlebox with its own root CA (a corporate proxy that inspects TLS) reads the traffic. | Strict pinning: the client takes the pinned certificate only, so the path fails closed and is not read. Such networks use the CDN path in phase 2. Evidence: ADR-0023 (amendment of 2026-10-15); code (`QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION`, `SCH_CRED_MANUAL_CRED_VALIDATION`). | accepted | none |
| TR-5 | stranger, any tenant | Floods the listeners: QUIC Initial packets, TCP connections, TLS handshakes, ClientHello fragments. | The front door reads at most 16 KiB of a ClientHello and gives each connection 10 s; the front door and the QUIC listener cap the connections that have not finished their handshake, in all (1024) and for one source (256, an IPv4 address or an IPv6 /64), give a source a rate for its new connections and one for its TLS handshakes (200 a second with a burst of 2000, which 1000 Nodes behind one address do not meet), and set the retry of msquic to a quarter of its default memory limit, so that a flood of Initial packets is answered with retries; the settings are in `FRONT_DOOR_CONFIG` and `TRANSPORT_QUIC_CONFIG`, and the refusals are in the state of the Node. Evidence: code `SourceLimit.c`, `FrontDoor.c`, `TransportQuic.c`, `NodeListener.c`; vpntest `sourcelimits` (the flood cut at the cap while another source is served, 1000 Nodes, the retry setting read back from msquic, the retries and the bound of the memory and the CPU under a flood of Initial packets). | runs | none |
| TR-6 | on-path | Blocks or resets QUIC to force the fallback, or blocks both paths to cut the Node off. | The client races QUIC, TLS-443 and mimic, and the control stream and the sessions dial again after a delay that grows to 60 s. Nothing stops a path attacker from dropping everything. A QUIC handshake that fails, for example against a Node of the build before CORE-H5, does not fall back to TLS-443. Evidence: test `transport` (the race); code `ControlRetry.c`; #443. | accepted | G-10 |
| TR-7 | on-path, with the certificate key | Presents the real certificate. | Key separation: the certificate key is in the Windows store, the Noise key is another, and the binding makes a stolen certificate key useless to a middlebox. Evidence: model `tls443-cert`, `quic-cert`, and `tls443-both`, where both keys of the server give the attacker the server, as they must. | runs | none |
| TR-8 | any | The pin is a SHA-1 thumbprint that a person types into a setting, and nothing ties it to the identity of the Node: a certificate that two Nodes share, or the key of a certificate alone, is not tied to a Node. | The Noise handshake authenticates the Node after the pin, so the pin guards the outer session only, and the binding closes what a stolen certificate key would leave open. The ticket moves the pin to a SHA-256 of the key that the Controller sends with the identity of the Node. Evidence: formal-model D2; code `TransportTlsDefaultConfig`, `TransportQuicDefaultConfig`. | partial | G-8 |
| TR-9 | on-path, prober | The mimic path: a third outer session, a REALITY server with its key, its short ids and a decoy, and uTLS on the client. | A client that proves the key is a client, and any other connection is spliced to the decoy, an own site with an ACME certificate or a borrowed big site. The Node starts the sidecar in a job that ends with it, over a control pipe that only its account opens and that takes only that process; the key goes over the pipe only and is blanked in the log; the listener serves 2048 connections at most and closes a flood at the accept. Not settled: the suites (the browser parrot offers ChaCha20-Poly1305, and CORE-H3 asks for AES-GCM only), the pin (the public key of the server: the Controller gives it to the clients in their links from the report that the Node of the server makes on its control stream, which ties it to the Node, but the half on the Node that makes and reports the key is open, #424), and the key updates of the Go TLS library. The formal model of the path is `tests/formal/mimic` (AUD-7, #425), which CI checks against `expected.tsv`. `mimic-none` is a prober that knows the public key of the server: it is spliced to the decoy and sees nothing of the sidecar (`probe` and `sec-shortid` hold). `mimic-link` is an attacker that holds a link, the public key and a short id: it learns that the server is no decoy (`probe` and `sec-shortid` are attacks), but it cannot answer the client as the server (`mimic-auth` holds). `mimic-key` is an attacker that holds the REALITY private key of the server: it answers the client with a temporary certificate of its own (`mimic-auth` is an attack), and the binding of the Noise handshake to the exporter of the REALITY session stops it, so it reads no password and no data and lowers no suite. `mimic-nobinding-key` is the negative control without the binding, where the same attacker wins. The models cover the REALITY handshake (the proof, the temporary certificate and its HMAC, the splice to the decoy), the Noise handshake and the Login on top of it, the binding that the first line of the data pipe carries, and the pipes and the restart of the sidecar. They leave out the clock of the proof (a ClientHello that is sent again is taken again), the fingerprint of the ClientHello, the padding and the pacing of the stream, the job that ends the sidecar with the Node, and what a prober learns from time and from the shape of the traffic (`docs/formal-model.md`, "The mimic path" and "What the model leaves out"). The Controller never holds the private key of a mimic server: no message of the control protocol has a field for one (test `TestNoMessageHasAFieldForAPrivateKey`). The short id of a server is kept for as long as its Node is a mimic server, and the rotation of it is not built (CS-5). Evidence: code `NodeMimic.c`, `controller/internal/mimic/server.go`, `controller/internal/controller/mimic.go`; model `mimic-none`, `mimic-link`, `mimic-key`, `mimic-nobinding-key`; test `mimic`; `docs/ports.md`. | runs, where typed | G-11 |
| TR-10 | local user, stolen disk | Reads the REALITY private key, which the setting of a mimic server holds as text in the Configuration store. | `ranz_node.db` is in the data directory with a protected DACL (SYSTEM, the Administrators, the service SID). The key reaches the sidecar over the pipe only, never on a command line, and is blanked in the log (CORE-P2-6, test `mimic`). CORE-P2-7 keeps the key in the store under the same rules (the decision of 2026-10-26). ADR-0023 keeps the mimicry keys apart from the identity key, and not in the key storage provider. A copy of the disk gives the key, and with it a server that clients take for the Node's mimic server. Evidence: code `NodeMimic.c`; #424. | partial | G-12 |
| TR-11 | supply chain | A flaw in msquic, Schannel, libjuice, libplum, GoBGP, REALITY, uTLS or rqlite. | msquic is the official signed `msquic.dll`, pinned; its exporter is in the preview part of the API table and the code accepts any 2.x from 2.6 (#443 item 2 asks for the exact minor). The others are pinned by version and hash, signed at release, and checked by `govulncheck` and the SBOM (SEC-1, SEC-2). Evidence: ADR-0022, ADR-0039, `.github/workflows/supply-chain.yml`; #443. | partial | G-10; the audit of the third-party code and licences is CLN-3 (#361) |
| TR-12 | on-path | An outbound proxy, or a PAC script that WPAD gives, sees the destination and can block or redirect the dial. | The TLS session is end to end with the pin and the Noise binding, so a proxy reads nothing; the destination and the availability remain exposed. The answers of a proxy are parsed by functions with fuzz targets (`TransportProxyParseHttp`, `TransportProxyParseSocks`, `TransportProxyParseList`). Evidence: code `TransportPath.c`; the fuzz registry. | accepted | none |
| TR-13 | on-path | The transports of phase 2: a CDN terminates TLS by design. | The Noise session encrypts its own records there (no binding, `NOISE_SESSION_ENCRYPT`), and by the position on the hybrid handshake in section 5 it must run that handshake. Not built. Evidence: ADR-0005, ADR-0023. | designed | requirement on #86 |

### What a new transport must keep

The transport interface is the place where a later transport can weaken the whole. A transport that plugs in must:

1. give the Channel binding of its outer session, or declare that it has none, so that the session is encrypted under the Noise keys; never a binding that is the same for every connection to a server (formal-model F1);
2. pin the server by a key that the Controller ties to the Node (the third part of #400), and trust no root store;
3. negotiate TLS 1.3 and an AES-GCM suite only, and update its keys before the AES-GCM limit;
4. run the handshake of a stranger off the forwarding thread of the Node (DT-1), and answer a prober as the decoy does, where it carries one;
5. have a fuzz target for every parser of its bytes (ADR-0040) and a model in `docs/formal-model.md` before it ships (AUD-7 is that work for the mimic path);
6. if it terminates the TLS of a third party, run the hybrid handshake (section 5).

## 7. The front door and its handoff

### What it is, as built

The front door (`src/Core/FrontDoor.c`, ADR-0035, SDN-29) is the TCP listener of a Node on 443, or on 5555 when 443 is taken. It accepts a connection and peeks the first bytes with `MSG_PEEK`, so it consumes none of them: at most 32 KiB, a ClientHello of at most 16 KiB, for at most 10 s. It routes a TLS connection by its server name and its ALPN protocols, and any other connection by its first bytes, through an owner table that it tries in order. An owner in the same process takes the socket through a procedure (the TLS transport of the Node does, `NodeListenerTake`). An owner in another process takes it through its handoff pipe: the front door duplicates the socket into the owner process with `WSADuplicateSocketW`, writes the `WSAPROTOCOL_INFOW` in a message (magic `RFD1`), the owner makes its own socket and answers one byte, and the front door closes its handle. After the handoff no byte passes through the front door. UDP 443 is QUIC only, and msquic's.

The owner's end of the pipe is `FrontDoorPipeNew`: the first instance of the named pipe, remote clients refused, a backlog of 16 sockets, 5 s for each step. The Node registers one owner, `node`, that takes every TLS connection, whatever its server name or ALPN. The Controller's end, which lets the web UI and the API of a Controller on the same host be reached through the front door, is SDN-73 (#352) and is not built.

| part | status | evidence |
|---|---|---|
| the front door with the owner in its own process | runs | code `NodeListener.c`; test `listener` |
| the handoff to another process, the C end | tests only | code `FrontDoorPipe.c`; coretest `frontdoor` |
| the handoff to the Controller, the Go end | designed | #352 |

### Assets and entry points

The assets are the availability of TCP 443 (A9), the integrity of the routing (a connection reaches only an owner that takes it), the duplicated sockets with the bytes that the peer already sent, and the pipes of the owners. The entry points are every byte that any host sends to TCP 443 before an owner has the connection (`FrontDoorParseHello`, `FrontDoorRoute`), and the handoff pipe, which is local (`FrontDoorHandoffDecode`). The trust boundaries are B1, where any network meets the listener, and B2, from the front door to the owner process.

### What each attacker can do

- **On the path.** It sees what the transports show it (section 6) and can reset connections.
- **A malicious peer or tenant.** It is a stranger: it floods, and it picks the server name and the ALPN to reach the owner that it wants. Routing is not authorization, and each owner authenticates for itself (FD-3).
- **A stolen node key.** Nothing: the front door holds no key and no state after the handoff.
- **A local user.** It can serve the pipe of an owner before the owner does (FD-4), and it can connect to the pipe if its DACL lets it in (FD-5).

### Threats

| id | who | threat | control, with its evidence | status | gap |
|---|---|---|---|---|---|
| FD-1 | stranger | Opens many connections and sends nothing, or a ClientHello one byte at a time. | Each connection takes a callback of the Windows thread pool (`CallbackMayRunLong`) for up to 10 s of peeking, and is closed after; a ClientHello that is malformed or too large is closed at once. The callbacks run on a pool of their own with a thread for every connection that may wait, and the connections that wait are capped in all and for one source, so a source that opens many and sends nothing is cut at its cap and the others are served (AUD1-DT-3, #451). Evidence: code `FrontDoor.h`, `FrontDoor.c`, `SourceLimit.c`; coretest `frontdoor`; vpntest `sourcelimits`; fuzz `fuzz_frontdoor`. | runs | none |
| FD-2 | stranger | Sends a malformed or oversized ClientHello, or a prefix that looks like the protocol of another owner. | `FrontDoorParseHello` and `FrontDoorRoute` read at most 32 KiB, a ClientHello of at most 16 KiB, a server name of at most 255 bytes and 16 ALPN protocols, and a connection that no owner takes is closed. Evidence: the fuzz targets `FrontDoorParseHello`, `FrontDoorRoute`, `FrontDoorHandoffDecode`; coretest `frontdoor`. | runs | none |
| FD-3 | stranger, any tenant | Picks the server name or the ALPN to reach the owner of another protocol, such as the web UI or the control stream of a Controller. | Routing is no authorization. Each owner makes its own TLS handshake with its own certificate and authenticates for itself: a bearer token for the API, the Noise handshake for a stream. The pages of the web UI hold no data and need no token. Evidence: ADR-0035; code `FrontDoor.h`. | runs | none |
| FD-4 | local user | Creates the named pipe of an owner while the owner is not running, and receives the sockets that the front door hands over. The front door connects to the pipe by name, asks the system which process serves it (`GetNamedPipeServerProcessId`) and duplicates the socket into that process, whoever it is. The connect passes no impersonation level (`SECURITY_SQOS_PRESENT` is not set), so a squatter that holds `SeImpersonatePrivilege`, as a service account does, could also impersonate the account of the front door. | The owner creates the pipe with `FILE_FLAG_FIRST_PIPE_INSTANCE`, so a squatter that came first makes the owner's start fail, which is loud. DT-7 (#455) closes the rest: the front door connects with `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION`, so a squatter can identify the front door's account but never impersonate it, and before `WSADuplicateSocketW` it checks that the serving process runs as the SID that the owner table names (`FRONT_DOOR_OWNER.Account`, set for the Controller from `NT SERVICE\ranz-controller`) and, where the owner names an `Image`, runs that executable; an owner without an account, or any other process, gets no socket, and the connection is closed and counted (`Impostors`). The DACL of the pipe decides who may connect as a client, not who may serve it. A process of another account must let the front door's account duplicate handles into it (`PROCESS_DUP_HANDLE`, as the comment of `FrontDoor.h` says), which a process may grant on itself. The socket carries the peer's unread ClientHello, which the squatter would answer with a certificate of its own, so a client that pins or verifies refuses it, and a browser warns. Evidence: code `FrontDoor.c` (`FrontDoorSend`), `FrontDoorPipe.c` (`FrontDoorPipeNew`); coretest `frontdoor` (another account, no account, another image, the right ones, and the impersonation level read from the pipe). The check reads the token and the image of the serving process, so an owner under another account must grant `PROCESS_QUERY_LIMITED_INFORMATION` besides `PROCESS_DUP_HANDLE` (FD-8, #352). Only the Controller's end (#352) will use a pipe in production. | runs | G-13 (the right on the Controller's process: FD-8, #352) |
| FD-5 | local user | Connects to the pipe of an owner as a client and sends a forged handoff message. | The pipe takes local clients only, with a DACL that lets in SYSTEM, the Administrators and the owner's account, or the account that the owner names. The message is decoded by `FrontDoorHandoffDecode`, which has a fuzz target. A process that may connect is trusted. Evidence: code `FrontDoorPipe.c`; the fuzz registry; reasoned. | runs | none |
| FD-6 | stranger | Floods UDP 443 with QUIC Initial packets. | The listener refuses a connection of a source over its caps (the connections that have not finished their handshake, in all and for one source) and its rates, before it allocates more than the msquic state of the Initial packet, and msquic answers new connections with a retry once the handshakes hold more than the retry limit of the listener (`TRANSPORT_QUIC_RETRY_DEFAULT`, read back from msquic); the counters of the refusals and of the retries are in the state of the Node (AUD1-DT-3, #451). Evidence: code `TransportQuic.c`, `SourceLimit.c`; vpntest `sourcelimits`. | runs | none |
| FD-7 | any | The front door as the way to a Controller on the same host: the connections for the web UI and the API reach the Controller's own TLS. | The socket is duplicated, not proxied, so the Controller sees the real address of the client, which the admin source allowlist needs. The allowlist serves a loopback address before it reads the list, so a handoff that turned into a proxy on loopback would let every remote caller past it. The tests of SDN-73 must show that the allowlist refuses a remote address through the handoff. Evidence: ADR-0035; code `api/sources.go` (`Restrict`); reasoned. | designed | #352 (Appendix C) |
| FD-8 | a flaw in the Node, a stolen service account | Uses the access that the handoff needs to reach the Controller on the same host. The Node's front door duplicates sockets into the process of the Controller, so the Controller's process must let the Node's service account duplicate handles into it. A holder of that right can also copy any handle out of the Controller's process: its open files in the data directory, its pipe to rqlited. The Node service answers the internet, and the Controller's store is a loopback port without authentication (ST-1), so on one host a flaw of the Node's TLS front end is a short way to the Controller. | None by design: ADR-0039 gives each service an account of its own, and the handoff gives one of them a right on the other. Evidence: code `FrontDoor.h` (the comment on `FrontDoorPipeNew`); reasoned. | designed | G-13, #352 (Appendix C) |

## 8. The control stream

### What it is, as built

A Node dials the TLS port of its Controller (TCP 443, or 5555 when the Controller fell back) with TLS 1.3 only and the ALPN `ranz-control/1`, and checks the certificate of the Controller against the SHA-256 of its public key, in place of a root store (`NodeControllerVerify`). On the stream it runs Noise_IK with its own static key and the static key of the Controller, with the prologue `ranz control stream 1`, the TLS exporter `EXPORTER-ranz-control-noise` and no record type byte. The frames are a 4-byte length and one protobuf `ControlMessage` (`proto/ranz/control/v1/control.proto`: nanopb on the Node, Go protobuf on the Controller).

The Controller completes the handshake with the static key of any initiator, reads the Hello within 10 s and 1 KiB, and looks the key up among the Node resources (`byKey`). It refuses a key that no Node resource holds, a Node whose source address a Network of its VRFs does not allow (`enrolSources`), a Node above the node cap of the licence, and a Node that cannot honour the desired state (its Capabilities). A Node that is admitted gets its desired state as Generations, as deltas against the last one that it acknowledged, and sends Acks, Capabilities, Leases, Telemetry and Signals, which are sealed envelopes for a peer that the Controller passes on as they came. A new stream of a Node replaces its old one. There is no password on the stream: the key is the identity, and the Intent is the list of who may have one. With no Controller reachable a Node keeps forwarding on its last Generation (ADR-0027 decision 6).

| part | status | evidence |
|---|---|---|
| the stream of a C Node to its Controller | runs | SDN-90; the table of `docs/formal-model.md` (`control-node-*`) |
| the Go client `Dial`, used by `ranz-nodesim` and the tests | tools and tests; it checks no certificate | formal-model C1, D3 |
| the sealed Signals of the peer layer | tests only: nothing in production calls `PeerSealSignal` | the same table |

### Assets and entry points

The assets are the integrity of the desired state (A2: it decides what each Node enforces), the two keys of the Controller (A4), the key of a Node as its identity at the Controller (A3), the confidentiality of the Signals, and the availability of the control plane (A9).

The entry points are the TLS port with the ALPN, before anybody is known: the TLS handshake, the Noise handshake, and the Hello frame, which is read after the handshake with a limit of its own, `MaxHello` (1 KiB), while at most 1024 streams wait for a Hello (CS-4). After the Hello, the Acks, Signals, Telemetry, Leases and Pins of an admitted Node, each with the limit of its kind that sits beside `control.options` (`Conn.Read`, protobuf; fuzz targets `FuzzRead`, `FuzzOpen`). On the Node, the Updates of the Controller (the nanopb decode and `ControlApply`). The trust boundary is B5, a Node to the Controller.

### What each attacker can do

- **On the path.** A middlebox cannot complete the handshake of a Node: the Node checks the TLS key of the Controller, its Noise key and the exporter, and fails closed before any state comes (model `control-node-none`, `control-node-cert`; tests `nodejoin`, `nodepins`).
- **A malicious peer.** A Node with its own valid key is admitted as itself. It gets its own desired state, which holds its Peers (the Nodes that share a VRF with it), the rules of its VRFs and its addresses, and no secret today. It can report any Capabilities, which affect its own admission only, send Telemetry and Leases within their size limits, report the keys of its mimic server, of which the Controller applies one change in 10 s, and send Signals to its peers (CS-6).
- **A malicious tenant.** It sees nothing of another VRF: the Controller compiles the state of a Node from its own VRFs. A stranger that knows the static public key of the Controller can complete the handshake with any key, and is refused and audited (CS-3), at the cost of CS-4.
- **A stolen node key.** It is the Node on the control stream, from any address, or from the addresses that the `enrolSources` of its Networks allow. It reads the desired state of the Node and replaces its stream (CS-5).

### Threats

| id | who | threat | control, with its evidence | status | gap |
|---|---|---|---|---|---|
| CS-1 | on-path | Terminates or relays the control stream, to feed a Node a state of its choosing. | The Node pins the SHA-256 of the Controller's public key and checks its static key, and the Noise prologue holds the exporter, so the attacker needs both keys of the Controller or fails before any state comes. Evidence: model `control-node-none`, `control-node-cert`, `control-node-noise-client`, `control-node-fs`; tests `nodejoin`, `nodepins`; code `NodeControllerVerify`. | runs | none: the Go client of `Dial` checks no certificate and is a tool of the tests (formal-model C1, D3) |
| CS-2 | on-path | Downgrades or replays the stream. | The control ALPN takes TLS 1.3 only (`port.go`), the handshake is bound to the exporter, and the TLS handshake takes 10 s at most. Evidence: code `port.go`, `stream.go`; model `control-node-none`. | runs | none |
| CS-3 | stranger, any tenant | Runs the handshake with a key of its own, to find which keys the Controller knows, or to fill the log. | A stranger that does not know the static public key of the Controller fails at message 1. One that does completes the handshake with any key, and is refused with `REFUSE_REASON_UNKNOWN_NODE` and recorded as an `auth-failed` entry of the audit log: one for a source in 10 s, at most 4096 sources remembered, and the log is held to 365 days and 2,000,000 records by default, so a flood from many sources can push old records out unless an audit target keeps them (AP-7). Evidence: code `controller.go` (`serveConn`), `audit.go`, `retention.go`. | runs | none for the log; the cost before authentication is CS-4 |
| CS-4 | stranger that knows the public key of the Controller | Makes the Controller hold memory before it knows the key: it opens connections, completes the TLS handshake and the Noise handshake, and sends nothing, or the length of a frame and then nothing. It needs a TLS handshake and the static public key of the Controller, which every Node holds and a viewer reads, and no key of a Node and no token. | A frame is read as its bytes arrive, in chunks of 4 KiB, so a connection holds no more than the bytes that it sent and one chunk (it held 16 MiB for the length of a frame of that size before AUD1-DT-2, #450). The Hello has a limit of its own, `MaxHello` (1 KiB), and a length over a limit is refused before a byte of the frame is read, with a Refuse or a close. At most 1024 control streams wait for a Hello in all and 64 for one source (an IPv4 address, or an IPv6 /64); the next are closed before their Noise handshake and counted in `ranz_control_refused_total`. The two 10 s timeouts of the stream (the Noise handshake and the Hello) and one goroutine per connection stay. Evidence: code `stream.go` (`readFrame`), `limits.go`, `waiting.go`, `controller.go` (`serveConn`); tests `TestStalledFrameHoldsOnlyWhatArrived` (counts the bytes that `Read` allocates), `TestFrameLimits`, `TestHelloOverItsLimit`, `TestStreamsThatWaitForAHelloAreCapped`. | runs | none for the stream: the TLS handshake before it has no cap yet (AP-11, G-7, DT-3) |
| CS-5 | stolen node key | Opens a control stream as the Node and gets its desired state: its Peers (names, static keys, addresses, endpoints), the rules of its VRFs, its Listener (paths and thumbprints, not secrets), its mimic links (the address, the server name, the public key and the short id of each mimic server that it dials), its DHCP and DNS data. It sends false Capabilities, Leases, Telemetry and Pins, sends Signals to the peers of the Node, and replaces the stream of the real Node. | The source prefixes of the Networks (`enrolSources`: checked at every stream, and a tightened list refuses the streams that are open at once); deleting the Node resource or changing its `publicKey` refuses the stream at once; the licence cap; the audit log (`login`, `logout`, `enrolment`). What a stolen key reads in the desired state, beyond the topology: the links of a mimic client, the short id in the settings of a mimic server and, for a gateway, the PresharedKeys of its Devices, in clear (OE-2); the HMAC key of a VRF in the standard mode (SDN-88) will join them. The link of a client holds, for each mimic server that it dials, the address, the first server name, the public key of the server and its short id (SDN-94, #423). The public key is no secret, and every client of the server holds the short id. So whoever steals the key of a client holds a link: it proves the key of the server, which answers it as a server and not as the decoy, and it learns that the server is no decoy (model `mimic-link`: `probe` and `sec-shortid` are attacks there). It cannot answer the client as the server, which takes the auth key of the ClientHello of the client (`mimic-auth` holds), and it learns no private key of the server, since no message of the control protocol has a field for one. The settings of the Node of a mimic server hold the same short id, so the stolen key of that Node gives it as well. A new short id comes only when the Node stops being a mimic server and is one again (TR-9). Evidence: code `enrol.go`, `controller.go`, `desired/mimic.go`; test `TestNoMessageHasAFieldForAPrivateKey`; model `control-node-client` (the holder of the key of a Node is that Node to the Controller), `mimic-link`; ADR-0031. | partial | G-6 |
| CS-6 | malicious peer | Lies in its Hello, floods Telemetry and Leases, reports a changed `Pins` again and again, or sends a Signal to a Node that is no peer. | The Controller checks the intent against the Capabilities that a Node reports, so a lie affects the Node's own admission only. The sizes are bounded by `control.options` (1024 leases, 16 tags, and so on), and a frame of each kind that a Node sends has a limit that sits beside it (`MaxAck`, `MaxSignal`, `MaxTelemetry`, `MaxLeases`, `MaxPins`), above the largest frame that the options allow, so the stream of a Node that sends a larger one is closed; a Signal to a Node that shares no VRF with the sender is dropped, and the queue of Signals of a stream holds 64 and drops the oldest when it is full, so a peer can push the Signals of another peer out of the queue of a Node that both reach: a path that is set up later, and no leak. A `Pins` report that differs from the keys in force (the public key of the mimic server of the Node) costs a write to the store, a compile of the whole intent and a commit while the Controller holds its lock, and a Generation for each client of the server, so a server Node that alternates two keys could keep the Controller busy (AUD1-DT-20, #522). The Controller applies one change of the keys of a Node in `PinsInterval` (10 s). A report that comes sooner is held, a later one replaces it, and one that returns to the keys in force voids it; the next look at the keys after the interval applies the last, so a report is late and never lost, and one Node costs one change in each interval: one write of its keys, one compile, one commit and one Generation for each client. The limit is for each Node and in memory: a restart forgets it, and the Node reports its keys again after its Hello. Many Nodes whose keys an attacker holds each cost one change in an interval (G-6). Evidence: code `capability.Check`, `signal` (`maxQueuedSignals`), `limits.go`, `mimic.go` (`PinsInterval`, `takePins`, `flushPins`); tests `TestLimitsHoldTheOptions`, `TestFrameOverItsLimitClosesTheStream`, `TestMimicChangedKeysAreAppliedOncePerInterval`, `TestMimicKeysThatComeBackVoidTheReportThatWaits`; fuzz `FuzzRead`; the conformance tests of `controller/internal/controller`. | runs | none |
| CS-7 | malicious tenant | Reads the desired state of another VRF through the control stream, or has the Controller carry its Signals to a Node of another VRF. | The state of a Node is compiled from its own VRFs and from the Peers that share one of them, and a Signal goes only to a peer of its sender. Evidence: code `desired.Compile`, `signal`; the conformance tests of `controller/internal/controller`. | runs | none |
| CS-8 | on-path, any | Reads the Signals (relay assignments, ICE candidates) that the Controller carries. | A Signal is sealed by the static key of the sender to the receiver's with Noise K, so the Controller can neither read, forge, alter nor redirect it, and a sequence from the clock makes a replay fail. Evidence: model `peer-leaks` (`pe-*`); code `PeerSignal.c`; coretest `envelope`, `relay`. | tests only | none |
| CS-9 | operator, a compromised Controller | Pushes any desired state to every Node: peers, rules, routes, Mirrors, a Listener with a certificate path (a UNC path is allowed, so a Node would authenticate to the server it names), an ACME directory. | Nothing at the Node: the Controller is the root of trust of the overlay (ADR-0026). What limits and records it: the three roles, Revisions with diff and rollback, `--confirm`, the audit record of every Revision, the rate limit of a Mirror. Evidence: ADR-0026, ADR-0031; code `intent/listener.go` (`nodePathRule`); reasoned for the UNC path. | accepted | none: the operator is trusted with the Intent (AP-5 to AP-7) |
| CS-10 | stolen node key, a revoked Node | Keeps working against the peers that cannot reach the Controller: a Node with no Controller keeps forwarding on its last Generation, so a peer that was not told of a revocation keeps accepting the revoked key. | None, by decision: a control-plane outage is not a data-plane outage (ADR-0026 decision 5, ADR-0027 decision 6). The revocation reaches a peer with its next Generation. Evidence: ADR-0027; code `NodeOverlay.c`. | accepted | none: a maximum age for a Generation is an option (question 4, section 15) |
| CS-11 | holder of one key of the Controller | Holds its Noise key alone, or its TLS key alone. | Each guards the other: a Node pins the TLS key and checks the Noise key, so an attacker needs both. Both keys are persisted keys of the software key storage provider, not exportable, used inside the provider, in the key set of the service account (a file of mode 0600 on Linux, in CI only). Evidence: model `control-node-cert`, `control-node-noise-client`; code `keys_windows.go`. | runs | none |
| CS-12 | operator | Replaces the certificate of the Controller while a Node is down, which then pins a key that the Controller no longer serves. | The new fingerprint goes to the connected Nodes first, in a Generation, and the Controller serves the new certificate only after each has acknowledged. A Node that is not connected makes the change refuse (409) unless the operator forces it, and then it is pinned again by hand. Evidence: ADR-0027 (amendment of 2026-10-26); code `certificate.go`; test `nodepins`. | runs | none: an operational risk that ADR-0027 states |
| CS-13 | a compromised Controller | Feeds a Node a malformed `ControlMessage` to corrupt its memory. The Node decodes it with nanopb and applies it in `ControlApply`, which is static, so the fuzz registry does not list it, and no libFuzzer target reads it. | The messages are bounded by `control.options` (nanopb has fixed sizes) and the sender is the pinned Controller. The round trip of `tests/control/nanopb_roundtrip.c` decodes what the Go tests send. Evidence: code `Control.c`; reasoned. | partial | G-15, DT-12 |

## 9. The API, the web UI and the tokens

### What it is, as built

The API is JSON over HTTPS on the TLS port of the Controller (443, or 5555 when 443 is taken), beside the control stream: after the TLS handshake `port.go` gives a connection that negotiated `ranz-control/1` to the stream and any other to the HTTP server. Every call needs the bearer token of a role. The three roles are global (ADR-0031 decision 9), and `Needs` gives each call the least role from its method and path: the tokens and the admin source allowlist need admin, the live operations of SDN-50 (`/api/v1/operations`) need operator, their reads too, any other read needs viewer, and any other request needs operator, so a call that is added later is guarded from the start. A token is `ranz_` and the base32 text of `crypto/rand`, at least 128 bits, shown once and kept as its SHA-256 (`api_tokens`). The first start creates the admin token and writes it to `admin.token` in the data directory; `ranz controller reset-admin` on the host makes another. The admin source allowlist (SDN-39) restricts the API and the web UI to source prefixes before the token is looked at; the Controller starts with it empty, which serves every address, unless the flag `-admin-from` sets it at the first start, as `ranz install --controller` does (DT-6, #454: loopback and the private subnets of the host, or the prefixes of `--admin-from`), and it always serves loopback. A call that changes something is audited under the name of the token, and so is a read of the tokens, the audit log or the licence (the kind `access`, at most once a minute for each token and read). Any other read is not. A token may have an expiry, and the Controller keeps when each token was last used.

The web UI (`controller/internal/webui`, ADR-0038) is static HTML, CSS and JavaScript embedded in the binary and served on the same port. It is a client of the API like `ranz`: the token that a person pastes at `/sign-in` stays in the `sessionStorage` of the tab, and every action is an API call that the Guard judges. Every file carries the policy `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'`. A plain HTTP port (HTTP.sys on Windows) only redirects to HTTPS and answers the ACME HTTP-01 challenge. The `ranz` CLI is the other client: it takes the token from a file or from `RANZ_TOKEN`, defaults to `https://127.0.0.1`, and toward a loopback host accepts only the fingerprint in `tls.fingerprint` of the Controller's data directory, which on Windows it takes only when no other account than SYSTEM, the Administrators and the Controller's service account owns or may write the file or its folder (DT-14), or the one that it is given; toward another host it checks the chain or a pinned fingerprint.

| part | status | evidence |
|---|---|---|
| the API with its three roles, the Guard and the audit of the calls | runs | tests `rbac_test`, `api_test`, `audit_test`, `TestRegisteredRolesMatchNeeds` |
| the admin source allowlist | runs, unless `--admin-from any` | SDN-39, AUD1-DT-6 (#454); tests `sources_test`, `TestFirstStartSetsTheAllowlistOfTheInstall` |
| the web UI | runs | ADR-0038; tests `webui_test`, `actions_test` |
| roles scoped to a Network, and Logins of users to the API | designed | SDN-38 (#231), SDN-32 (#226); the header of `rbac.go` |

### Assets and entry points

The assets are the Intent and its Revisions (A2), the tokens (A5), the audit log (A10), the availability of the API (A9) and the confidentiality of the topology. The entry points are the TLS port before the Guard (the handshake, the request line and the headers, which Go's HTTP server reads within 10 s); the JSON bodies after it (an apply, an import or a connect up to 16 MiB, the allowlist up to 64 KiB, a password up to 4 KiB, each decoded with `DisallowUnknownFields`); the plain HTTP port; the static files of the web UI (GET and HEAD only); and on the host the token file, the variable `RANZ_TOKEN` and the CLI. The trust boundaries are B6, an operator to the Controller, B11 for the files and the CLI of the host, and B8 for the targets that the Controller calls.

### What each attacker can do

- **On the path.** The certificate of the Controller is self-signed until ACME. A middlebox that presents another one gets the token of a person who clicks through the warning, or of a CLI that was not given the fingerprint (AP-2). Toward loopback the CLI checks the fingerprint in the data directory of the Controller.
- **A malicious peer.** A Node has no token. The key of a Node opens a control stream and no API call (CS-5).
- **A malicious tenant.** It holds no token. A token that it is given has a global role: a viewer reads every VRF, an operator changes every VRF (AP-5).
- **A stolen node key.** Nothing on this plane.
- **A token holder.** What its role allows, which is more than the Intent for an operator (AP-6 to AP-9).
- **A local user.** The token file, the environment of a CLI, and the port of the CLI toward loopback (AP-2).

### Threats

| id | who | threat | control, with its evidence | status | gap |
|---|---|---|---|---|---|
| AP-1 | stranger, on-path | Calls the API with no token, or guesses one, to read or change the Intent. | `Guard` answers 401 to a call whose token matches no stored hash and records an `auth-failed` entry (one for a source in 10 s), and 403 to a role that is too low. A secret has at least 128 random bits and is found by its SHA-256, so a guess fails and the lookup gives no timing worth using. `Needs` picks the role from the method and the path, and `TestRegisteredRolesMatchNeeds` ties every registered route to it. Evidence: code `api.go`, `rbac.go`; tests `rbac_test`, `api_test`, `audit_test`. | runs | none |
| AP-2 | on-path, local user, any | Gets an admin or operator token. It lives in the tab of the browser (`sessionStorage`), in `admin.token`, in a token file or `RANZ_TOKEN` of the CLI, in the history of a shell, in a log, in a bundle and on the wire. | A token is shown once and stored as a hash. Its `ranz_` form lets a secret scanner find it. The diagnostics bundle and `ranz doctor --bundle` redact by name and by form. `admin.token` is in the data directory (ST-3). A remote CLI checks the chain or a pinned fingerprint. DT-13 (#461) closed two of the three things that were left. A token can be made with an expiry, from which the Controller refuses it with 401 while an admin still lists it as expired and deletes it, and the Controller keeps when each token was last used, which `ranz tokens` shows, so a token that nobody uses stands out. And the CLI checks the certificate toward `127.0.0.1`, its default, too: it accepts only the fingerprint that the Controller writes to `tls.fingerprint` in its data directory, or the one that `-tls-fingerprint` gives, and sends no token when it has neither; `ranz login` and `ranz node login` (SDN-32), which send a password or a code, check it the same way. A browser login sends no password itself, since the user types it into a page that the browser shows, so `ranz` makes one call to that page through the check before it opens the browser, and opens none when the call is refused (DT-19, #506). DT-14 (#496) made the file worth trusting: on Windows `ranz` opens it itself and takes it only when the file and its folder are owned by SYSTEM, the Administrators or the account of the Controller service, which writes the file, and no access entry lets another account write either of them; a folder that a local user made first, one that the Users group may add files to, a file with another owner, a link and a volume without access lists are refused with the folder or the file named, and `ranz` then connects to nothing and asks for `-tls-fingerprint`. A local user that listens on that port while the Controller is not there (the Controller falls back to 5555 when 443 is taken, and a Node's front door may hold 443) gets nothing, since its key is not the one in the file; and one that makes the data directory first, which `C:\ProgramData` lets it do, and writes its own fingerprint there gets nothing either. DT-15 (#497) closed two small things of DT-13. A call with a token after its expiry is recorded as an `auth-failed` entry under that token (`token:NAME`, with the word `expired` and when the token ended), not under an actor that is unknown, so a leaked token that is tried late shows up as that token, even when its source failed another call a moment before (the throttle of one `auth-failed` entry for a source in 10 s counts a token apart, and only the holder of the secret of an expired token makes that entry); the answer still names no token. And the Controller keeps one admin token that has not expired: the delete of the last one, and the change of its role or its scope, are refused with 409 while an admin token that has expired is left, so no delete leaves nobody who can manage the tokens. What is left is the scope of a token. SDN-38 (#231) built a role that is held for one Network, which `POST /api/v1/tokens` takes as `network`, and a token made so calls that Network and no other; but `ranz token create` makes none, so a token that it makes holds its role for the whole API, and one that was made with no expiry still works until an admin deletes it. And an Administrator, SYSTEM or a flaw of the Controller that runs as its service account can still write the file, which is the host (section 14); the check of who wrote the file is Windows only, since elsewhere the data directory of the service is under `/var/lib`, which only root can make. And a browser cannot check the fingerprint itself, so a program that takes the port in the instant between the call of a browser login and the connection of the browser is not stopped: the browser shows its page and the user can type a password into it, and `ranz` sends it nothing. Evidence: code `rbac.go`, `rbac/lastadmin.go`, `store/tokens.go` (`api_token_life`), `store/tokenguard.go`, `api.go` (`NewClient`, `Pin`, `Guard`), `api/auditexpired.go`, `audit/throttlekey.go`, `servercert/fingerprintfile.go`, `controller/fingerprintfile_windows.go` (`ReadFingerprint`, `checkWriters`), `cmd/ranz/loopback.go`, `cmd/ranz/login.go` (`browserLogin`), `login/client.go` (`CheckAuthorize`), `cmd/ranz/tokens.go`, `bundle/redact.go`; tests `TestATokenWithAnExpiryIsRefusedAfterIt`, `TestTheLastUseOfATokenIsKeptAndListed`, `TestTokenListShowsTheLastUseOfEachToken`, `TestAnExpiredAdminTokenDoesNotCountAsTheLastAdminToken`, `TestARefusalOfAnExpiredTokenIsAuditedUnderItsName`, `TestAnExpiredTokenIsRecordedAfterAnotherRefusalOfItsSource`, `TestAFailedAuthenticationUnderATokenIsCountedApartFromItsSource`, `TestRanzRefusesAnotherKeyOnLoopbackAndSendsNoToken`, `TestRanzLoginChecksLoopbackToo`, `TestRanzLoginOpensNoBrowserBeforeItHasCheckedTheCertificate`, `TestRanzNodeLoginOpensNoBrowserBeforeItHasCheckedTheCertificate`, `TestRanzRefusesAFingerprintFileThatAnotherAccountMayHaveWritten`, `TestReadFingerprintRefusesWhatAnotherAccountMayHaveWritten`, `TestReadFingerprintTakesTheFilesOfTheInstallAndTheService`, `TestCheckWritersByTheOwnerAndTheAccessList`, and the checks of `controller-service.ps1` (`Test-FingerprintFile` of `controller-hostfiles.ps1`) and of the job first test; fuzz `FuzzRedact`, `FuzzReadFingerprint`. | partial | SDN-38 (#231) built the scope below the role in the API; a verb of `ranz` that makes a token for one Network is not built |
| AP-3 | stranger on the network | Reaches the API and the web UI from outside the operator's network. | The admin source allowlist: a source that the list does not hold is refused with 403 before the token is read, and recorded as an event and as an `auth-failed` entry. A standby that forwards a call to the leader is a source there, so the addresses of the members go in the list. The control stream is not behind it: a Network limits where its Nodes enrol from. `ranz install --controller` opens TCP 443 and 5555 for every firewall profile and, since DT-6 (#454), registers the service with `-admin-from`, so that the first start sets the list to loopback and the private subnets of the host, or to the prefixes of `--admin-from`; the install, the first start and `ranz status` say which sources are allowed and how to change them. The first start sets the list before it makes the first admin token, so a Controller that holds a token has had its list set, and `ranz controller reset-admin` refuses a store that holds no token, so no token comes before the first start; every later start says in its log which list it keeps. A Controller that is run by hand with no flag, and one that is installed with `--admin-from any`, start with an empty list, and there the token is the only barrier; the log and `ranz status` say so. A store that exists already, which a registered service or the data directory that `ranz uninstall` leaves holds, keeps its own list, empty for a Controller that was installed before DT-6, and the install says so in place of promising the list of its flag. `ranz status` shows the prefixes of the list to an admin only, as the call for the list is an admin's. Loopback is always served, so a handoff that turned into a proxy on loopback would pass every remote caller (FD-7). The default list is wrong in two cases, which `docs/first-test.md` (step 5) names (DT-15, #497). The list trusts every address of the private subnets of the host, and the Controller sees the address of the last device that connected to it, so a reverse proxy, a load balancer or a router that rewrites the source address of what it passes on (source NAT, SNAT, which masquerading is) inside such a subnet, if it passes callers from the internet on to the Controller, makes every one of them look private, and the default lets them in: the sources that may reach the Controller are named with `--admin-from`, without the subnet of that device, or its ports are not passed on. A router that only forwards the port (destination NAT, DNAT, a port forward) keeps the public source of the caller, and the default list refuses that caller with 403, so it is not this case. A proxy on the host itself is the same case through loopback. The list holds no global IPv6 subnet, so a dual-stack client of the same LAN that reaches the host by an AAAA name from the same global `/64` is refused with 403 until that `/64` is named with `--admin-from`. Members of a cluster that start fresh at the same time each make the first start: the first write of the list wins, and the others write nothing and log the list that won, so the cluster ends with one list. Evidence: code `api/sources.go`, `api/adminsources.go`, `controller/adminfrom.go`, `install/adminfrom.go`, `store/adminsourcesfirst.go`; tests `sources_test`, `TestAdminAllows`, `TestFirstStartSetsTheAllowlistOfTheInstall`, `TestAFirstStartThatCannotSetTheListMakesNoToken`, `TestResetAdminRefusesAStoreBeforeItsFirstStart`, `TestALaterStartKeepsTheListAndSaysWhichOneItIs`, `TestAFirstStartThatIsNotFirstLogsTheListThatWon`, `TestTwoMembersThatStartFreshTogetherEndWithOneList`, `TestSetFirstAdminSourcesTheFirstWriteWins`, `TestSetFirstAdminSourcesOfMembersThatStartTogether`, `TestAdminFromDefaultIsLoopbackAndThePrivateSubnets`, `TestAdminFromDefaultStaysWithinThePrivateBlocks`, `TestAdminFromDefaultLeavesOutTheGlobalIPv6Subnets`, `TestDocsSayWhereTheDefaultAllowlistIsTooWideAndTooNarrow`, `TestANodeEnrolsFromAnAddressOutsideTheAdminAllowlist`; the jobs first test and the default VRF tracer. | runs, unless `--admin-from any` | none |
| AP-4 | stranger, any tenant | Attacks a person who has the web UI open: a script injected into a page, a forged cross-site request, a framed page, a script from another origin. | The policy above allows no inline script or style, no other origin, no frame, no other form target and no base URL. The files are embedded and served for GET and HEAD only, with `nosniff`, `no-referrer` and same-origin policies. There is no cookie, so no forged request: the token goes in a header that the script sets. A test refuses `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write` and `eval(` in the files of the UI. A name is a DNS label and any other text is shown as text. Evidence: code `webui.go`, `ui/assets/api.js`; test `webui_test`. | runs | none: a flaw would put the token of the tab in reach, and `sessionStorage` ends with the tab |
| AP-5 | token holder, a tenant that is given a token | Does more than its role was meant for. Roles are global, so a viewer reads the Intent of every VRF, the keys and the addresses of every Node and the audit log, which names the API tokens that acted (AP-8), and an operator changes every VRF. A party that is given a token for its own VRF is given all of them. | The three roles and the decision that the operator is trusted with the Intent (ADR-0026, ADR-0031; CS-9). Roles scoped to one Network are #231 and not built. Evidence: ADR-0031; the header of `rbac.go`. | accepted | none: no token goes to a party outside the operator's own staff until #231 |
| AP-6 | token holder, operator | Points the Controller or a Node at a host of its choosing. (a) An export or audit target (webhook, OTLP, IPFIX or syslog) is checked for its scheme, a host and a port and for no user name, and nothing else, so the Controller's POSTs and its TCP and UDP connections go to any host it can reach: loopback and the HTTP port of its own store (ST-1), the address of a cloud host's metadata service, a server of the internal network. They are blind, and the body is a JSON event. (b) A Mirror takes any unicast address as its sensor, and the selected Nodes send the plaintext packets of their VRFs there as plain VXLAN, up to the rate that the Mirror names. (c) The Listener of a Node takes the path of a certificate file, and a UNC path is allowed, so the service account of the Node would authenticate to the host that the path names; and the URL of an ACME directory. (d) The certificate of the Controller takes file paths of the Controller's host. | Redirects are off in the exporters, the URL carries no user name, the secret never comes back from the API, and a Mirror has a rate limit and at most 16 for a Node. Nothing limits where they point. Evidence: code `export/target.go` (`checkURL`), `intent/mirror.go` (`ParseSensor`), `intent/listener.go` (`nodePathRule`), `servercert/setting.go`; the exporters' own clients; reasoned for the effects, which no test shows. | open | G-16, DT-9 |
| AP-7 | token holder, operator | Erases the trail of its own changes: sets the audit retention to 1 day and 1000 records, deletes the audit target that keeps a copy, or has the log pushed out by a flood of `auth-failed` entries (CS-3). | The change of the retention and of a target is itself recorded, under the name of the token, as an operation. A Revision keeps the content of every change, and names nobody. A copy at a target that the operator cannot reach survives, and nothing makes the retention or the targets an admin matter: both are operator calls. Evidence: code `audit/retention.go` (`minDays`, `minRecords`), `api/audit.go`, `api.go` (`Needs`), `intent/revision.go`. | open | G-16, DT-9 |
| AP-8 | token holder, viewer | Reads what a viewer may: the whole Intent, the Nodes with their keys and addresses, the events, the audit log, the Controller's public key and TLS fingerprint, and the licence. | A viewer sees no secret: the secret of a target never comes back, a URL shows its scheme and host only, the hash of a user's password is not returned. DT-13 (#461) audits the three reads whose trail matters: a read of the tokens (and of the API roles of users, which SDN-32 keeps under them), the audit log or the licence is recorded as an `access` under the name of the token, or `user:NAME` for a user token, at most once a minute for each caller and read, so that the log shows who looked and when; any other read is not audited. The audit log names the API tokens, and a viewer reads it, since ADR-0030 and ADR-0031 keep `GET /api/v1/audit` with the viewer: a call that changes something, and each of those three reads, is recorded under `token:NAME` (`user:NAME` for a user token), and since DT-15 (#497) so is a call with the secret of a token after its expiry, as an `auth-failed` entry that says when the token ended and where the call came from. So a viewer reads the name of every token that acted or whose secret was tried after its end, and can filter the log by it (`actor=token:NAME`), while `GET /api/v1/tokens` is the admin's and refuses a viewer with 403. A name is no secret, and no secret of a token comes into the log. A rule in the Guard that kept the names from a viewer is not built, since the other records name the tokens as well, and DT-15-R1 (#561) says it here and tests it. Evidence: code `export/target.go` (`Info`), `api/users.go`, `api/accessaudit.go`, `audit/access.go`, `api/auditexpired.go`; tests `TestAReadOfTheTokensTheAuditLogOrTheLicenceLeavesAnAccessRecord`, `TestAReadWithAUserTokenLeavesAnAccessRecordUnderTheUser`, `TestAuditCallsRecordsTheReadsOfTheTokensTheAuditLogAndTheLicence`, `TestAccessIsRecordedOnceAMinuteForEachTokenAndRead`, `TestAViewerReadsTheNamesOfTheTokensInTheAuditLog`, `TestDocsSayThatAViewerReadsTheNamesOfTheTokensInTheAuditLog`; reasoned for the rest. | accepted | none |
| AP-9 | token holder, operator | Uses the calls of an operator that go beyond the Intent: the diagnostics bundle (the logs, the configuration and the status of the Controller and of its host); the licence key (PUT or DELETE, which lowers the node cap to Personal and refuses the Nodes above it); the password of a user (`PUT /api/v1/users/{name}/password`); the certificate of the Controller. | The bundle is redacted and leaves out the keys, the token file and the store. The calls are audited as operations. A licence change never stops a live tunnel (ADR-0036, amendment of 2026-10-22). The comment of `diagnostics.go` itself says that keeping the logs from the operators needs a rule in the Guard that was left out. Evidence: code `api/diagnostics.go`, `bundle/bundle.go`, `api/licence.go`; reasoned. | accepted | G-16, DT-9 (question 2, section 15, decides the logs and the passwords) |
| AP-10 | any, a malformed body | Crafts a body to crash or to corrupt the Controller. | Bodies are bounded and decoded with `DisallowUnknownFields`; the Intent is checked before it is stored (names, sizes, addresses, references); the parsers have Go fuzz targets (`FuzzParseDocument`, `FuzzParseSources`, `FuzzParseMirror`, `FuzzUsers`, `FuzzValidate`, `FuzzParseFilter`, `FuzzRedact`) and Go is memory-safe. Evidence: code; the fuzz targets, which run on their corpus in the tests; the long campaign is AUD-3. | runs | none |
| AP-11 | stranger | Floods the port with TLS handshakes and requests, with no token. | The TLS handshake and the request headers each take 10 s at most, and a call without a token costs a lookup. The port caps the connections that wait for their TLS handshake, in all (4096) and for one source (1024, an IPv4 address or an IPv6 /64), and gives a source a rate for its new connections and one for its TLS handshakes (200 a second with a burst of 2000), settings of `ranz controller`; the connection over a limit is closed and counted in the status of the Controller (AUD1-DT-3, #451). The control stream is on the same port: the caps are the ones of the handshake, a stream that is admitted is not refused by a flood from another source, and the streams that wait for a Hello are capped (CS-4). What stays open is a flood of requests from many sources, or one that stays within the rates. Evidence: code `port.go`, `limits.go`; tests `TestFloodFromOneSourceIsCutAtItsCap`, `TestAdmittedControlStreamIsNotRefusedByAFloodFromAnotherSource`, `TestThousandNodesBehindOneAddressConnectWithTheDefaults`. | partial | none |
| AP-12 | stranger | Sends crafted requests to the plain HTTP port. | HTTP.sys parses them in the kernel; the Controller reads the cooked URL, answers 301 to `https://` and answers the ACME challenge path, takes no body (a buffer of 1 MiB), and its URL prefixes are reserved for the service account. The Go side reads the structures of HTTP.sys through `unsafe`, bounded by the lengths that HTTP.sys gives. The port is off unless `-http-listen` is set. The development listener `-api-listen` serves the API over plain HTTP and the Controller refuses an address that is not loopback; `-control-listen` is a second TLS port for the stream. Evidence: code `port/plain_windows.go`, `controller.go`; test `plain_windows_test.go`. | runs, when it is set | none: AUD-2 reads the `unsafe` code |
| AP-13 | stranger, on-path | A standby of a cluster forwards calls to the leader, which sees the standby as the source. | Each member checks the allowlist and the token on the requests that it accepts, and the leader checks them again on the ones forwarded to it, so the members' addresses must be in the list. Evidence: ADR-0031 (amendment of SDN-39); code `api/sources.go`. | runs | none |
| AP-14 | token holder, operator | Cuts users off, or reads who is connected: ends the sessions of any node, bans any User of the Intent (every device of the user is refused until the ban is lifted, and the other Nodes lose it as a Peer), lists every session with its user, address and traffic, and reads or clears the MAC table and the IP table of any L2 Network on any Node that reports the Capability `operations`. A token that leaks does it to every user. | The calls need the role operator, the reads too (a viewer is refused with 403). Each is an `operation` record of the audit log under the name of the token, the reads included, and one that fails is a record too. A ban is no Intent, so a revision, a rollback or an import does not lift it. A Node is sent an Operation only when it reports the Capability, and the Controller bounds the answer (512 entries, a name of 63 bytes, 10 s) and drops one that no request of that Node waits for. Nothing limits whom an operator may ban, and roles are global (AP-5), so a scope to one Network waits for #231. Evidence: ADR-0031 (amendment of SDN-50); code `api/operations.go`, `controller/bans.go`, `controller/sessions.go`, `controller/tables.go`; tests `TestBanCutsAUserOffAtOnce`, `TestOperationsNeedTheOperatorRole`, `TestOperationsAreAudited`. | runs | none: scoped administrators are #231 (AP-5) |

## 10. The store and the licence

### What it is, as built

The store is rqlite (SQLite with Raft), run by the Controller as a child process, `rqlited`. The Go side (`controller/internal/store`) talks to it over HTTP with parameterized statements; no statement is built by concatenation. A single Controller uses `127.0.0.1:4001` for HTTP and `127.0.0.1:4002` for Raft. A cluster of 3 or 5 (SDN-17, Enterprise) runs one Controller on each host, their rqlite members form one Raft group, the Raft address is one that the others reach (`-rqlite-raft`, `-rqlite-raft-adv`, `-rqlite-join`), and the leader of the Controllers is chosen by a lease in the store. The tables are `resources`, `revisions`, `node_state`, `node_capabilities`, `node_pins`, `api_tokens`, `user_passwords`, `user_bans`, `admin_sources`, `audit_log`, `audit_targets`, `audit_retention`, `export_targets`, `licence`, `controller_certificate`, `cluster_key`, `cluster_key_copies`, `events`, `dhcp_leases`, `device_keys`, `lease` and `fence`. The data directory, `C:\ProgramData\Ranz\controller`, holds the data of `rqlited`, `admin.token`, the log and the state of the ACME client; the keys of the Controller (its Noise static key, its TLS key and, since AUD1-DT-10 (#458), the Sealing key of the secrets of the targets and, since SDN-82 (#377), of the PresharedKeys of the Devices) are in the software key storage provider, and not in files. The Administrators own the data directory, and its access list is protected (ST-3). `ranz controller backup FILE`, `restore FILE` and `reset-admin` run on the host and need the rights of a local administrator; the last two write to the store directly, with no token. The secrets of the export and audit targets are in the store as Sealed secrets (`ranz-sealed:1:` and a box that only the Sealing key opens, or in a cluster the Cluster key, of which the store holds only copies that the Sealing key of each member opens: AUD1-DT-16, #501), and a backup file has an access list of its own (ST-4). The URL of a target is not sealed, and the data of `rqlited` still holds the old text of a secret that an upgrade sealed until it is truncated or replaced (ST-4). The PresharedKeys of the WireGuard Devices are in the table `device_keys` as sealed boxes of the same key, the Sealing key or in a cluster the Cluster key, under the label `device_keys:NAME`; the private key of a Device is in no table (OE-2).

A licence key is `key/`, the base64url of the licence as JSON (tier, node count, expiry, fallback version, watermark), `.`, and the Ed25519 signature of the vendor, checked with the vendor public keys that the release build links in (`vendorKeys`). A development build verifies none and runs the Personal tier, ten Nodes. The Controller is the one place that enforces it: a cap on the Nodes that it serves, the gate on the Enterprise features (EVPN with BGP, and the cluster), and a revocation list that the update channel delivers as a file. A Node never decides, and the core tunnel is never gated (ADR-0036). The activation service of the vendor (`controller/internal/activation`: the service, the client, the offline path and the Enterprise feature key) is a package that no binary links yet.

| part | status | evidence |
|---|---|---|
| the store with one Controller | runs | code `sidecar/rqlited.go`, `store`; test `rqlited_test` |
| the cluster of 3 or 5 | runs | SDN-17; `internal/cluster` |
| backup, restore and reset-admin | runs | code `backup.go`, `reset.go` |
| the files of the host: the owner of the data directory, the access list of a backup, the sealed secrets of the targets and the sealed PresharedKeys of the Devices | runs, in a cluster too | AUD1-DT-10 (#458), AUD1-DT-18 (#503), SDN-82 (#377); code `datadir_windows.go`, `backup_windows.go`, `sealing.go`, `store/sealed.go`, `store/devicekeys.go`, `controller/devicekeys.go`, `keys/sealer.go`; tests `datadir_windows_test.go`, `datadir_window_windows_test.go`, `backup_windows_test.go`, `store/sealed_test.go`, `TestPresharedKeyIsSealedAtRest`. The Cluster key of a cluster: AUD1-DT-16 (#501); code `clusterkey.go`, `clusterkey/clusterkey.go`, `store/clusterkey.go`; tests `clusterkey/clusterkey_test.go`, `cluster_sealed_test.go`, `TestClusterSealsThePresharedKeysOfTheDevices` |
| the licence key, the node cap, the revocation file | runs | code `licence`, `controller.go`; fuzz `FuzzParse`, `FuzzParseRevocations` |
| the activation service and its client | tests only | `activation` has no importer outside its own tests; ADR-0036 (the amendment of 2026-10-22) |

Two ADRs carry the number 0036 (`0036-licensing.md` and `0036-anti-debug-and-anti-re-release-variant.md`). This page means the first one by ADR-0036.

### Assets and entry points

The assets are the store (A7) with what it holds (A2, A5, A6, A10, A11), the two keys of the Controller (A4), the backups, and the availability of the store (A9). The entry points are the HTTP port of `rqlited` on loopback and its Raft port; the data directory and its files; the files of a backup and a restore; the licence key (`PUT /api/v1/licence`, `licence.Parse`) and the revocation file; and the commands of a local administrator. The trust boundaries are B7, between the Controller and its store and between its members, B11 for the files and the commands of the host, and B8 toward the activation service.

### What each attacker can do

- **On the path.** With one Controller, nothing: the store is on loopback. In a cluster, the Raft traffic crosses the network between the members, in clear (ST-2).
- **A malicious peer.** Nothing from the network. The Node service on the same host as the Controller is a local process, and a flaw in it reaches the store (FD-8, ST-1).
- **A malicious tenant.** Nothing.
- **A stolen node key.** Nothing: it opens a control stream (CS-5), which reads and writes no table of its own.
- **A local user.** The HTTP port of the store (ST-1), a data directory that it created first (ST-3) and the files that it can read (ST-4).
- **A token holder.** The operator's calls on the licence and the targets (AP-6, AP-9).

### Threats

| id | who | threat | control, with its evidence | status | gap |
|---|---|---|---|---|---|
| ST-1 | local user, a flaw of any service on the host | Uses the HTTP port of `rqlited` on `127.0.0.1:4001`, which asks for no credential: runs any SQL, so it inserts the hash of a secret of its own into `api_tokens` and is an admin, edits the Intent, adds a Node resource with a key of its own and enrols as that Node, reads the hashes, the licence key and the secrets of the targets. `reset-admin` does the same, with the rights of a local administrator, over this port. | The loopback address, and the data directory that holds the files. The port is open to every local account and process. rqlite can ask for a credential (`-auth`), and the Controller starts it with none. Evidence: code `sidecar/rqlited.go` (`args`), `controller.go` (`-rqlite`), `reset.go`; reasoned: the exploit was not run. | open | G-18, DT-8 |
| ST-2 | on-path, any host that reaches the Raft port (cluster) | Reads and rewrites the Raft traffic of the members, or joins as a member (`-join`): the whole store. | The Raft address of a cluster is explicit, and `docs/ports.md` says to open it between the members only, on a private network: the operator's firewall is the control, and `ranz install` opens no rule for it. rqlite can encrypt and authenticate the traffic between nodes, and the Controller starts it with neither. `-rqlite-external` takes any `-rqlite` URL, so a store on another host would be reached over plain HTTP with no credential. Evidence: code `sidecar/rqlited.go`, `controller.go` (`-rqlite-raft`, `-rqlite-raft-adv`, `-rqlite-join`, `-rqlite-external`); `docs/ports.md`; reasoned. | open | G-19, DT-8 |
| ST-3 | local user | Creates `C:\ProgramData\Ranz\controller` before the install, since `C:\ProgramData` lets any user create a folder, and keeps the directory that the Controller then fills: `admin.token`, the data of `rqlited`, the log, and the `rqlited.exe` that the service starts from it (`payload.Ensure` checks its SHA-256 and its signature when it writes the file, and not when the service runs it, so an owner of the directory can swap it in between and run code as the service account). Or puts a directory of its own in the place of the real one while the service is stopped. Or polls for the new folder, which had the access list of its parent until the install set its own (on a default Windows a list that lets the Users group add files and folders), opens it in that moment with the right to add to it, which the handle keeps after the list changed, and makes `payload\` in it, which the list that the install passes down keeps open to its owner: it swaps `payload\rqlited.exe` later, and `checkDataDirOwner` does not see it, since the owner of the folder at the top is the Administrators. Or has made `payload\`, or any file, in a folder that an earlier install or an administrator kept: the object keeps its owner, and the list that the install passes down gives that owner full control of it. Or, while the install runs, renames the new folder or a kept one away and puts a folder of its own or a junction in its place before its owner and its list are set (a user that owns the folder above it, or any user under a folder whose list lets every user change what is made in it, such as one that the install makes in the root of a volume), switches a folder that it owns between a folder and a junction while the install looks, names an entry so that Windows reads its path as another one (a period or a space at its end, or the name of a device such as `NUL`), or plants a hard link to a file elsewhere on the volume, which the list of the install would then reach. | The data directory belongs to SYSTEM, the Administrators or the account of the service (AUD1-DT-10, #458; ADR-0026 amendment of 2026-10-27). `ranz install` makes it with the Administrators as its owner and the protected access list of `dataDirSDDL` (full control for SYSTEM, the Administrators, the owner and the service account, inherited), as `NodeMakeDataDir` does for the Node. A directory that exists and that one of them, or the administrator who installs, owns is kept with what it holds, and gets that owner and that list. A directory that another account owns is not adopted, since its owner may have put anything in it, a store with a token that it knows or an `rqlited.exe` of its own, and may hold it open: an empty one is removed, which fails while anybody holds it open, and made anew; one that holds anything, a link, or a folder that cannot be read or removed is refused with a message that says what to do. A new directory, the one that the install makes and the one that the service makes for itself, is made with its owner (the Administrators, for the install) and its protected list in the call that makes it (`NtCreateFile` with the security descriptor, which makes the folder and opens it in one call, `makeProtectedDir`; AUD1-DT-18, #503, and AUD1-DT-18-R1, #554), so that there is no moment at which it has the list of its parent, and no handle with the right to add to it can be opened before its own list is there; a volume that keeps no access lists is said so, and the folder is removed again. The path is cleaned first, since `-data` is kept as it was typed and the folder above a path that ends in a separator is the folder itself, which would be made with the list of its own folder (`TestNewDataDirWithATrailingSeparatorIsMadeWithItsOwnList`). A path whose last element ends in a period or a space is refused before anything is made (`checkDataDirName`, called by the install, the start of the service, `reset-admin`, `backup` and `restore`): Windows takes those off the end of a path and `filepath.Clean` keeps them, so the folder above such a path is the data directory itself, as with a trailing separator, and the files of the Controller, which are joined to the path, would not lie in the folder that was looked at (the same test). The same list is set once more after the call, through the handle of the call (`SetSecurityInfo`), as the install sets it over a kept folder: a folder that only the creation call made does not pass a later change of its list down to a file in it that was given an owner, since that call does not mark the list as one that passes changes down (measured on the hosted runners). A kept directory is looked at before the install changes it (`checkDataDirChildren`): a file or a folder in it, at any depth, that an account other than SYSTEM, the Administrators, the service and the account that runs the install owns, a reparse point (a junction or a symbolic link, for example, which the look does not go into), a file with more than one name (a hard link, which may name a file outside the folder: a file has one owner and one list whatever name it is reached by, so the list that the install passes down would reach that file; AUD1-DT-18-R1, #554), or what cannot be read makes the install refuse it, naming it, with nothing changed. It is not re-owned and given the list, since what a user made would run as the controller, `takeown` changes only the owner, so an entry that the user put on its list stays, and a handle that the user opened before the list changed still writes after it. The message says to remove it, and offers `takeown` with a reset of the list (`icacls /reset /T`) only for what an administrator made, and never for a link. The refusal of a directory that another account owns, by the install and by the start of the service, `reset-admin`, `backup` and `restore`, gives the same advice for the directory itself (`takeownAdvice`): after `takeown` alone the next install would pass it, since it reads only owners, and an entry that the user put on the list of `payload\` would stay and pass down to the `rqlited.exe` that the service writes there. The refusal of the start says to register the service again over the folder before it starts, since the reset leaves it the list of the folder above it, which lets the Users group read it, and only the install sets the list of a folder that is there. The service refuses to start in a data directory that any other account owns, or that is a link, before it makes a file in it and with an entry of the Application log (ID 3) that names the owner, and so do `reset-admin`, `backup` and `restore`, which run the `rqlited` of its `payload` folder as the administrator. The install and the start of the service work on the folder through a handle, not by its name (AUD1-DT-18-R1, #554). The call that makes a new folder opens it, and its owner and its list are set through that handle (`SetSecurityInfo`); the install opens a kept folder as itself, without following a link, and looks at what it holds, sets its owner and its list, and looks again, all through that handle. Each then refuses the data directory when its path no longer names that folder (`stillNamed`), and a new folder is removed again through its handle. A user that may change the folder above, one that owns `C:\ProgramData\Ranz` since it made it first, or any user under a folder that the install makes in the root of a volume, whose list lets every user change what is made in it, can still rename the folder away in that moment and put a folder of its own, with `payload\` inside and a handle held, or a junction in its place: what it put there gets neither the owner nor the list, and the install and the start stop with a message that says that the data directory was replaced. Before, the steps after the call and after the look worked by name, and gave the folder of the user, or the folder that the junction named with the list passed down to what it holds, to the Administrators, and the service accepted the folder of the user, whose `payload\rqlited.exe` the user could swap later. The look opens each file and folder once, by its exact name in the folder that it holds open (`NtCreateFile` relative to that handle, with `FILE_OPEN_REPARSE_POINT` and `FILE_OPEN_FOR_BACKUP_INTENT`, the native form of `FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_BACKUP_SEMANTICS`), and reads its attributes and its number of names (`GetFileInformationByHandle`), its owner (`GetSecurityInfo`) and what a folder holds through that one handle. So an entry that its owner switches between a folder and a junction, a folder of its own emptied and a junction to a folder of SYSTEM, is one of the two for all of it, and the look never reads what a junction points at as a part of the data directory; and an entry whose name ends in a period or a space, or is the name of a device such as `NUL`, is that entry and not the one that Windows would make of its path, so a folder of a user named `admin.token ` is not read as the file `admin.token` of the service next to it. The look runs a second time once the owner and the list are set, and refuses what a user added to the folder while the install looked; the install has given the folder to the Administrators by then, says so, and undoes nothing. What is left, which the gap column lists: a user that owns the folder above the data directory (`C:\ProgramData\Ranz`, when it made that one first) can make the start of the service fail by putting a folder of its own in the real one's place while the service is stopped, or between the install and the start, and nothing more, since the service refuses it and no file of the user runs. The children of a kept folder are looked at when the install registers the service over it (a folder that `ranz uninstall` left, or that an administrator made), and not at each start of the service, nor when `ranz install` finds the service registered already: a data directory that an earlier release made, in which a user made `payload\` in the gap at its creation, stays so until the service is registered again over it. What a user adds to a kept folder whose list lets it, in the moment between the look and the change of the list, is refused by the second look, but after the list of the install was passed down to it; for a hard link, that is the list of the file that it names, outside the data directory, a file that the user may write, which making a hard link needs. The list of a folder that ranz made is protected, so for such a folder the list that lets it is one that an administrator loosened; but a kept folder that an administrator made by hand in `C:\ProgramData\Ranz` has the list that it inherits there, which lets the Users group add files and folders. The list that is passed down does not go through a junction (`TestTheListThatTheInstallPassesDownStopsAtAJunction`). And the install cannot see a handle that a user opened in a kept folder, before it had its list, on a file or a folder that the Administrators own. Between the check of the owner and the use of the folder there is a gap that only that user could use: the service closes it by opening its log file in the folder, which keeps the folder from being renamed, and the three commands of the administrator do not (reasoned, not tested). Evidence: code `datadir_windows.go` (`takeOverDataDir`, `checkDataDirOwner`, `makeProtectedDir`, `createDataDir`, `checkDataDirChildren`), `service_windows.go` (`dataDirSDDL`, `installService`), `controller.go` (`makeDataDir`), `reset.go`, `backup.go` (`onHost`), `Node.c` (`NodeMakeDataDir`); tests `datadir_windows_test.go` (its `TestInstallRefusesADataDirOfAStandardUserThatHoldsFiles` and `TestControllerRefusesADataDirOfAStandardUser` want the advice of `takeownAdvice` in the refusal of a directory that another account owns), `datadir_window_windows_test.go` (`TestNoStandardUserOpensANewDataDirWhileItIsMade`, in the step Test of `ranz (Windows x64)`, which runs on x64 only: a thread with the token of a standard user tries to open each of 300 new folders for adding files and folders while the install and the start of the service make it, in a folder with the list of `C:\ProgramData`, and opens none. Its control shows first that the thread sees a window: of 20 folders made with the two steps of before, `Mkdir` and then the list 5 ms apart, it must open one at least. With no pause, the throwaway workflow `exp-datadir-sd.yml` (run 41066865697) had the thread open the folder of the two steps in 300 of 300 rounds on x64 and 283 of 300 on arm64, and none of the folders made the way of now; `TestNewDataDirPassesALaterChangeOfItsListDown`; `TestNewDataDirWithATrailingSeparatorIsMadeWithItsOwnList`, which gives each way of making the folder a path with a trailing backslash and with a trailing slash, and wants the folder made with its own list, closed to a standard user, and kept by the start that follows, and a path that ends in a space, in three periods, in a period and a space, or in a space and a backslash, which it wants refused by each way and by the start that follows, with nothing made; `TestCheckDataDirName`, which pins the paths that `checkDataDirName` lets pass (a trailing separator, a last element of `.` or `..`, the root of a drive) and the ones that it refuses; `TestControllerRefusesAnExistingDataDirNamedWithATrailingPeriodOrSpace`, which makes the data directory first and wants the start, `run`, `reset-admin`, `backup` and `restore` to refuse five such paths to it, with controls that show that Windows finds the folder by each path and that the owner check alone passes it, so that the check of the name in `checkDataDirOwner` is the one that refuses; `TestInstallRefusesAKeptDataDirThatHoldsAChildOfAStandardUser`, whose message says to remove what a user made and offers `takeown`, with `icacls /reset /T`, only for what an administrator made; `TestInstallRefusesALinkInAKeptDataDir`, a junction refused as a reparse point with no `takeown` offered; `TestInstallKeepsWhatTheAdministratorsAndTheServiceMade`, whose files and folders get the list of the data directory), `datadir_race_windows_test.go` (AUD1-DT-18-R1, #554, in the same step: `TestNewDataDirThatIsReplacedBeforeItsListIsSetIsRefused` puts a folder of a standard user, or a junction, in the place of the new folder between the call that makes it and the step that sets its list, for the install and for the start of the service, and wants a refusal, the folder of the user and what the junction points at as they were, and the new folder removed again; `TestNewDataDirUnderTheRootOfAVolumeIsNotGivenAway` has a standard user rename the folder above, under a folder with the list of the root of a volume, in that moment; `TestInstallRefusesAHardLinkInAKeptDataDir` wants a hard link to a file of SYSTEM outside refused, with that file as it was; `TestInstallLooksAtAnEntryThatIsSwitchedBetweenAFolderAndAJunctionOnce` runs 300 installs while `payload\` is switched in place between a folder of a standard user and a junction, and wants each refused and nothing opened in what the junction points at, after a control that shows that a look by name reads it; `TestInstallLooksAtAnEntryByItsExactName`, names that end in a space or a period, next to the file of that name without them, and names of devices; `TestKeptDataDirThatIsReplacedBeforeItsListIsSetIsRefused`, a junction or a folder of a standard user put in the place of a kept folder between the look and the change; `TestInstallLooksAgainOnceTheListIsSet`; `TestTheListThatTheInstallPassesDownStopsAtAJunction`), `Test-DataDirOwner`, `Test-ServiceRefusesDataDir` and `Test-DataDirChildren` of `controller-hostfiles.ps1` (run by `controller-service.ps1`), step 6 of the first-test runbook; reasoned, with no test: what the gap column lists. | partial | G-20. Open with no ticket of their own, and said above: what a user adds to a kept folder whose list lets it, between the look and the change of the list, gets the list of the install before the second look refuses it, which for a hard link is the list of a file outside the data directory; a data directory of an earlier release under a service that is registered already is not looked at until the service is registered again over it; a handle that a user opened in a kept folder before it had its list, on a file or a folder that the Administrators own; the owner of the folder above, which can make the start fail. #554 (AUD1-DT-18-R1) closed the swap of a new folder and of a kept one, the hard link that a kept folder holds, the look by name, and the names that Windows reads as other ones |
| ST-4 | thief of a disk, of a VM snapshot or of a backup, a user that can read a file | Reads what the store holds: the Intent, the hashes of the tokens (of no use: 128 bits), the hashes of the users' passwords (PBKDF2, 600000 iterations, open to an offline guess), the licence key (which can be copied, and whose watermark names its customer), the URLs of the targets, whose path or query often holds the token of a webhook, and the secrets of the audit and export targets, a webhook's HMAC key and an OTLP bearer token, which were in clear. The PresharedKeys of the WireGuard Devices (SDN-82, #377) are kept sealed from the start, and the private key of a Device is not in the store at all (OE-2). A backup that an administrator restores and that was changed is the Intent, because nothing signs it. | The data directory's access list and its owner (ST-3); `backup` and `restore` need a local administrator. The file of a backup is made with a protected access list of its own, for SYSTEM and the Administrators, whatever the folder it goes to says, and no other handle of it is open while the store is written to it (AUD1-DT-10, #458): a folder that the Users group may read gives Users nothing, not even a handle opened before the list was set, and a volume with no access lists is said so. The secrets of the targets are kept as Sealed secrets, `ranz-sealed:1:` and a sealed box that only the Sealing key of the Controller opens, an X25519 key of the key storage provider whose private half never leaves it, so for a secret that is put after the upgrade, which is sealed before it is written, the table, the data of `rqlited` (its SQLite file, its Raft log and its snapshots), a snapshot of the host and a backup show none in clear, and a restore on the same host keeps them working. A secret that an earlier release kept in clear and that the upgrade sealed, by changing its row (`SealTargetSecrets`), is sealed in the table and in every backup that this release makes, which is vacuumed (`GET /db/backup?vacuum`) so that it holds none of the free space where SQLite leaves the old text of a changed row. It is not gone from the data of `rqlited`: rqlite keeps the first write in its Raft log until a snapshot truncates the log, in its older snapshots until newer ones replace them, and in the free space of its SQLite file until the file is vacuumed, and a backup that the earlier release made holds it as it was. Nothing of the Controller reaches that data, so `docs/upgrade-notes.md` tells the operator to put each such target again with a new secret and to change it at the receiver (AUD1-DT-17, #502; ADR-0026, amendment of 2026-10-30). The label of the secret of a target holds the table, the name and the SHA-256 of the URL, so a secret that is moved to another row, or that stays in a row whose URL was changed, does not open: whoever can write a row or change a backup, and points a target at a URL of its own, gets the events there and no secret, as the targets of another host do. The URL itself is not sealed: it is in the table, in the data of `rqlited` and in every backup as it was put, with the token that the path or the query of a webhook URL may hold, because the Controller must know where a target goes without the key, and a lost key would otherwise lose the destination too (the API shows only the scheme, the host and the port, and `Validate` asks for a secret in the secret field and not in the URL). On another host, or with another data directory, the targets come back with no secret, and the log of the Controller names them (ADR-0026, amendment of 2026-10-27). The PresharedKeys of the Devices are sealed the same way, under the label `device_keys:NAME`, so a sealed key that is moved to the row of another Device does not open there; on another host the Devices come back with a key that does not open, their gateway terminates them without it, and the log says so. The message of `backup` names everything that a backup holds, and who may read it. The keys of the Controller are not in the store. A cluster, whose members have no Sealing key in common, seals the secrets of the targets and the PresharedKeys of the Devices with its Cluster key, which a member holds in memory only and the store holds only as copies that the Sealing key of each member opens, so no row, no backup and no log holds it or a private key in clear; a restore keeps the Cluster key of the store that it replaces, so a backup of another cluster brings its targets with no secret and its Devices with a PresharedKey that does not open (AUD1-DT-16, #501; ADR-0026, amendment of 2026-10-29). What is left: the hashes and the licence key are in a backup as they were; the URL of a target, with the token that its path or query may hold, is in clear in the table, in the data of `rqlited` and in every backup; the old text of a secret that an upgrade sealed is in the data of `rqlited` until it is truncated, replaced or vacuumed, which putting the target again with a new secret makes of no use; and two Controllers that use one store through `-rqlite-external` seal with the key of their own hosts and cannot open each other's secrets, since only `-rqlite-join` makes a cluster (their logs name the secrets that do not open). A single Controller seals the secrets that a restore of an earlier backup brings back within a minute, with no restart (`sealAgain`). Evidence: code `backup.go`, `backup_windows.go`, `sealing.go`, `store/sealed.go`, `store/backup.go` (`Backup`), `store/devicekeys.go`, `controller/devicekeys.go`, `keys/sealer.go`, `clusterkey.go`, `clusterkey/clusterkey.go`, `store/clusterkey.go`; tests `TestPresharedKeyIsSealedAtRest`, `TestDeviceWithoutASealingKey`, `TestBackupIsNotReadableByUsers`, `TestBackupFileIsProtectedFromTheStart`, `TestBackupMessageNamesWhatItHolds`, `TestBackupThenRestoreKeepsTheSecretsOfTheTargets`, `TestTargetSecretsAreSealed`, `TestTargetSecretsAreSealedAtTheController`, `TestSealTargets`, `TestMembersShareTheClusterKey`, `TestNoClusterKeyInTheStoreTheBackupOrTheLog`, `TestRestoreKeepsTheClusterKeyOfTheCluster`, `TestClusterSealsWhatAnEarlierReleaseKeptInClear`, `TestClusterSealsTheSecretsOfTheTargets`, `TestClusterSealsThePresharedKeysOfTheDevices`, `TestBackupOfAMigratedStoreHoldsNoSecretInClear` (a plain copy of the SQLite file holds the old text of a migrated secret, the backup holds none, and the URL of a target is in it in clear), `TestSealedSecretStaysWithItsURL`, `TestChangedURLOfATargetSendsNoSecret`, `TestRestoreOfAnEarlierBackupIsSealedWithoutARestart`, `TestTwoControllersOnOneStoreCannotOpenEachOther`, `TestBackupMessageNamesWhatItHolds`, `TestRestoreMessageNamesTheSecretsOfAnEarlierBackup`; fuzz `FuzzSealerOpen`, `FuzzOpenCopy`, `FuzzDecodeCopy`; the step `Test-Backup` of `controller-hostfiles.ps1`; reasoned (no test reads them): that the Raft log and the snapshots of rqlite keep the old text until they are truncated or replaced. | partial | none: a token in the URL of a target is in clear (put the token in the secret where the receiver takes it); the old text of a migrated secret is in the data of `rqlited` (put the target again with a new secret, and change it at the receiver) |
| ST-5 | thief of a file | Reads the private key of a certificate that an operator gave the Controller as files (`servercert` File: a PKCS #8 key, not encrypted, at an absolute path that the service account must read). | The default is the Controller's own TLS key in the key storage provider, with a self-signed or an ACME certificate for it. A file is the operator's choice, protected as the operator protects it. A leaked key is replaced through the pin mechanism of ADR-0027 (CS-12). Evidence: code `servercert/setting.go`; ADR-0027; the first-test guide, step 21. | partial | none: the operator's file; step 21 of `docs/first-test.md` shows how to give the service its read access |
| ST-6 | operator, stranger | Gives the Controller a licence key that is forged, or edited to raise the tier, the node count or the expiry. | The signature, checked with the vendor keys that the release links in; a key that does not verify is refused (400) and a stored one is checked again at load. Evidence: code `licence/licence.go`; fuzz `FuzzParse`; tests `licence_test`. | runs | none |
| ST-7 | token holder, operator | Lowers or removes the licence to take Nodes away from the Controller: the Personal tier serves ten. | A licence change is audited, and a live tunnel is never bricked, since a Node keeps forwarding on its last Generation (ADR-0036, ADR-0027). Evidence: code `controller.go` (`SetLicence`); ADR-0036. | accepted | G-16 (it is in DT-9) |
| ST-8 | on-path to the vendor, a holder of an old file | Replays an older revocation list, or removes the file, so that a revoked key is licensed again. A list that does not verify, and an absent file, leave the empty list on purpose, so that a forged or corrupt list never bricks the Controller; the date of a list (`Issued`) is not compared with the one in force. The client of the activation service takes any base URL, and nothing in it refuses `http`. | The signature of the vendor on the list and on the activation token, and the expiry of a token. Evidence: code `controller.go` (`loadRevocations`), `licence/revocation.go`, `activation/client.go`. | accepted | G-23: a requirement on #283 and #284 (Appendix C); licensing is not a security property (A11) |
| ST-9 | an attacker of the vendor | Takes the signing key of the vendor or the activation service, and signs a licence of any tier. | The key is to live in an HSM or a CNG key storage provider; the release builds hold several vendor keys at once, so a key can be retired. Today a software provider stands in, in CI only, and the service is a near-release step. This page does not cover the vendor's own systems (section 14). Evidence: ADR-0036 (the amendment of 2026-10-22); code `activation/activation.go` (`SoftKSP`). | designed | none: out of scope |
| ST-10 | local administrator | Makes an admin token with `reset-admin`, or restores a backup, on the Controller's host. | The command needs the rights of a local administrator (`adminRights`). It is recorded in the Application log of Windows, and in no table of the store, since it writes to the store and not through the API. An administrator of the host is the host (section 14). Evidence: code `reset.go`, `backup.go`. | accepted | none |
| ST-11 | any | Loses the store: a full disk, a lost member, a stopped `rqlited`. | The Controller cannot change the Intent, and every Node keeps forwarding on the Generation that it applied last (ADR-0027). A cluster of 3 or 5 survives the loss of a minority of its members. Evidence: ADR-0026, ADR-0027; tests `rqlited_test` and `internal/cluster`. | accepted | none |
| ST-12 | a writer of the store: a member, an administrator of the host of a member, a holder of the credential of the store on such a host | Gets the Cluster key of a cluster (AUD1-DT-16, #501): publishes a key of its own in a row of `cluster_key_copies`, which a member that holds the Cluster key then gives a copy to, and opens every secret of the targets and every PresharedKey of the Devices; or puts a copy of a key of its own in the row of a member, which then seals the secrets and the PresharedKeys that are put after with a key that the writer knows. | Any writer of the store can publish a key: that is the price of handing the key over through the store, which the members share already, with no link of its own. A writer of the store has more already: it is an admin of the Controller with a token of its own in `api_tokens` (ST-1), and it can point a target at a URL of its own, which gets the events and, since AUD1-DT-17 (#502), no secret: the label of a sealed secret holds the URL, so the secret does not open for another one. The store asks for the credential of `rqlited` on loopback and for a certificate of the cluster CA on the Raft port (AUD1-DT-8), which keeps out everybody else. The Cluster key is what keeps the secrets from a reader of the store, of its data, of a snapshot and of a backup (ST-4), as the Sealing key of a single Controller does, not from a writer. A member opens its own copy only, holds a key only while the store names it, and removes a copy that its key does not open; each copy that a member gives, and a key that is made again because no row held a copy, is in its log. Evidence: ADR-0026 (amendment of 2026-10-29); code `clusterkey/clusterkey.go`, `store/clusterkey.go`; tests `TestCopyThatDoesNotOpenIsGivenAgain`, `TestTheStoreNamesTheClusterKey`, `TestLostClusterKeyIsMadeAgain`; fuzz `FuzzOpenCopy`. | accepted | none: a writer of the store is an admin of the Controller |

## 11. The data plane behind the sessions

### What it is, as built

The sessions of section 5 say who a peer is. What it may then do is decided in the Node, from the Intent that the Controller compiled. For a data record of peer p (`NodeOverlayDeliver`, `NodeOverlay.c`): its first four bytes name a VRF, and the Node must hold a forwarding table for it; the IP header gives the two addresses; the table must route the source to this very peer and the destination to the host of the Node, so a Node forwards nothing between two peers; the policy engine of the VRF judges the flow as a packet of that peer, with its tags (`NodePolicyInbound`); a Mirror copies what passed; 1:1 NAT and 4via6 translate it; the adapter of the VRF delivers it. A packet of the host goes the other way round (`NodeOverlayInput`). The policy engine (`Policy.h`, ADR-0019, ADR-0029) runs one Network for each VRF, each with a conntrack table and a quota of its own. Its default action is deny. It judges the first packet of a flow, so the replies pass on the conntrack fast path, and a rule that is taken out ends the flows it allowed. When the engine refuses a document, the VRFs with a policy drop every packet. The Intent of a first install has VRF `default` with the explicit starter rule "allow all inside VRF default" (ADR-0034), so a first install forwards between all its Nodes.

The L2 side is a library. The switch (`Switch.c`: a MAC table for each VLAN, with a limit on its size, and broadcast and multicast limits for each VLAN) and the guard of the policy engine (client isolation, the MAC and IP checks, no DHCP server, no router advertisement) have unit tests and fuzz targets, and no code of a Node calls them yet. The adapter backends for L2 (`NodeL2.c`, XDP and SeLow) exist. The L2 protections of SDN-41 (#234) are open.

| part | status | evidence |
|---|---|---|
| the forwarding tables and the check of the source against the peer | runs | code `NodeOverlay.c` (`NodeOverlayDeliver`); test `vrf` |
| the policy engine for IP: default deny, conntrack, one Network for each VRF | runs | code `NodePolicy.c`; tests `vrfpolicy`, `leakpolicy`; coretest `policy`; fuzz `fuzz_policy` |
| 1:1 NAT, 4via6 and the Mirrors | runs | code `NodeNat.c`, `NodeMirror.c`; fuzz `fuzz_nat`, `fuzz_mirror` |
| the L2 switch and the guard of the policy engine | tests only | `Switch.c`, `Policy.c`: no caller in `src/Cedar`; coretest `switch`, `policy`; fuzz `fuzz_switch`, `fuzz_policy` |
| the L2 protections of SDN-41 | designed | #234 |

### Assets and entry points

The assets are the traffic (A1), the Intent as the Node enforces it (A2) and the availability of the forwarding (A9). The entry points are the data records of every session after the handshake (`NodeOverlayDeliver`, which reads the VRF tag and the IP header, then the policy, NAT and Mirror code that reads the rest of the packet); the packets of the host (`NodeOverlayInput`); the DNS and DHCP responders of the overlay (OE-10); and, once the L2 path is wired, the frames of the adapters. The trust boundary is B3: the table and the policy of the VRF are its controls on the far side, and the adapter of the host lies behind them.

### What each attacker can do

- **On the path.** Nothing here: the records are authenticated by the session.
- **A malicious peer.** It is a sender that the Node trusts as far as the table and the policy say. Everything below is its.
- **A malicious tenant.** It has no session of its own with a Node of the victim's VRF unless it controls a Node that the Intent lists there, and then it is a peer of that VRF. Toward another VRF it is stopped by the table and by the policy (DP-4).
- **A stolen node key.** The Node: the routes and the tags that the Intent gives it (DP-1, DP-2).

### Threats

| id | who | threat | control, with its evidence | status | gap |
|---|---|---|---|---|---|
| DP-1 | malicious peer, stolen node key | Reaches every host of a VRF whose rules are too wide: after a first install every Node of `default` reaches every other on every port. | The starter rule is an explicit Policy resource of the Intent, which the operator narrows or deletes, and the engine's own default is deny; a Node of another VRF, or an address that no VRF holds, is "the end outside" with no tag. Since DT-6 (#454) the first start says in its log, and `ranz status` says as long as the rule exists, that it allows all traffic inside VRF `default` and how to narrow it, and docs/first-test.md shows the steps. Evidence: ADR-0034, ADR-0029; code `intent/defaults.go`, `NodePolicy.c`; test `TestStatusSaysWhoMayReachTheControllerAndWhatTheStarterRuleDoes`. | accepted | none: the rule itself is ADR-0034's decision |
| DP-2 | malicious peer | Spoofs the source address or the VRF of a packet (NS-7). The case that is left: a peer that holds a route, as a gateway for a LAN or a prefix that a NAT rule or a leak gives it, may source any address of that prefix. | The table binds each address to one next hop, and the Controller compiles the routes from the Intent, so a route is the statement of what the peer may source. Evidence: code `NodeOverlayDeliver`; tests `vrf`, `leakpolicy`. | runs | none |
| DP-3 | malicious peer | Uses the Node as a router to a third peer, or to the Node's own LAN: sends a packet whose destination is another peer's address or a LAN address. | The destination must be the host (`NODE_VRF_LOCAL`), so a Node forwards between no two peers. The one exception is the Hub node of a VRF of topology hub-and-spoke, which sends the packet of one Spoke on to another (SDN-19, #195); since SDN-19-R2 (#508) it is the place where the policy of the VRF decides that traffic: it judges each such packet by its two real ends, the Peer that sent it and the Peer of its next hop, with the same rules as a packet of its host, so with no rule between two Spokes the default deny keeps them apart, whatever the rules between the Spokes and the Hub node allow. The destination Spoke judges the packet as one of the Hub node (ADR-0029, amendment of 2026-10-29). What the host does with a packet for another address is its own routing, which is off unless the operator turned it on for a gateway role (a router Device, #378; the EVPN gateway). Evidence: code `NodeOverlayDeliver`, `NodeGatewayTransit`, `NodePolicyTransit`; tests `hubspoke`, `TestCompileHubRules`. | runs | none |
| DP-4 | malicious tenant, a peer of another VRF | Hops between VRFs: sends the tag of a VRF that the Node is in and the sender is not, or uses a route that another VRF leaks into its own. | The table of the tagged VRF holds no route that leads to a sender that is not a member, so the source check fails. A leak (SDN-7) is reachability, not a firewall bypass: the packets of a leaked route are judged as from "the end outside the VRF", which has no tag, so default deny applies, and each VRF has its own conntrack table. Evidence: ADR-0029 decision 6; code `NodePolicy.c`, `intent/leak.go`; tests `vrf`, `leakpolicy`. | runs | none |
| DP-5 | malicious peer | Fills the conntrack table of a VRF with flows from many source ports. A full table evicts its least recently used flow, so a reply that was tracked is judged again as a first packet, and default deny drops it until the flow is opened again. | The table is per VRF with a quota (65536 flows by default, 1048576 at most), so a VRF takes no room from another, and an eviction is counted (`evicted`), so the flood shows. There is no share for a member. Evidence: code `PolicyTrack.c` (`PolicyTrackAdd`), `NodePolicy.c`; reasoned: no test floods a table. | partial | question 5 (section 15) |
| DP-6 | the Controller, a state of an older schema | A VRF whose state carries no policy forwards as the overlay did before SDN-8, with no check. The Controller sends a policy with every VRF, and the harness of vpntest leaves it out on purpose. | The engine fails closed when it refuses a document. Whether a state of one of the older schemas that the Controller still serves (ADR-0027) can leave the policy out is for AUD-2 to check. Evidence: code `NodePolicy.c` (its header); reasoned. | accepted | none: for AUD-2 (section 15) |
| DP-7 | malicious peer | Crafts a packet to corrupt the memory of the Node: a malformed header, a fragment, an option, an ICMP message that is no echo. | The parsers have fuzz targets under AddressSanitizer (`fuzz_policy`, `fuzz_nat`, `fuzz_mirror`, `fuzz_switch`). A later fragment has no ports and an ICMP message other than an echo is judged one by one. `NodeOverlayInput` is exempt in the registry, with a target of its own still to come. Evidence: `.github/quality/fuzz-targets.txt`; code `Policy.h`. | partial | G-15, DT-12 |
| DP-8 | malicious peer, a host of a stretched Network | Attacks an L2 Network: MAC spoofing, a flood of source MACs, a broadcast storm, ARP spoofing, a rogue DHCP server or router advertisement. | The switch bounds its MAC table (65536 entries by default, 1048576 at most, and counts the sources that it refused) and limits broadcast and multicast for each VLAN; the guard has client isolation, the MAC and IP checks, no DHCP server, no router advertisement, and ARP and DHCP only. No code of a Node calls them yet, so a Node carries no L2 Network between peers today, and the protections that SDN-41 specifies are open. Evidence: code `Switch.h`, `Policy.h`; coretest `switch`, `policy`; fuzz `fuzz_switch`, `fuzz_policy`. | tests only | G-21, #234 |
| DP-9 | malicious peer | Floods packets at the rate of its link. | The rate limit of a VRF (SDN-20) is the sender's own, so it binds an honest peer only (NS-8). | accepted | question 5 (section 15) |

## 12. The standard mode

### What it is

The standard mode is a plain mode for a network that the operator trusts: a LAN, an intranet, a data center, a private WAN. Two Nodes there exchange VXLAN or Geneve datagrams directly (SDN-76, #356), peer by BGP (SDN-77, #357) or by EVPN (SDN-78, #358), and may use a Node as a route reflector (SDN-79, #359). It is plain by decision of the maintainer (2026-10-24): no Noise session and no IPsec of ours, and the operator may put IPsec or MACsec under it. The Intent chooses the kind of a link for each Network or VRF: `noise`, the default, which is the sessions of section 5 and fits any underlay, or `vxlan` or `geneve`. The Controller stays the control plane: it tells each Node its peers, the VNI of each VRF and the flood list, and the policy engine, the forwarding tables and the VRF adapters see no difference. A VRF uses one form of the standard mode, the form that the Controller fills or the BGP and EVPN peering, never both. The trust boundary is B9, a Node to an underlay of the standard mode; the `noise` kind stays on B3.

Group IDs and tag sets travel with each packet (SDN-87, #386; SDN-88, #387). In `off` the option is ignored. In `trusted-underlay` a forged tag is honoured, which is the limit of that mode, and `ranz explain` marks the Network "tags not authenticated". In `hmac` the option carries a MAC, HMAC-SHA256 truncated to 64 bits over the VNI, the group, the tags, the inner IP and L4 headers and a timestamp, with a window of 30 s and one key for each VRF, which the Controller sends in the Generation and rotates with two keys active. A packet without a valid option is judged by the map of address to group that the Controller sends, then by default deny.

Today the parts exist and the mode does not. The VXLAN module with Geneve (SDN-62, SDN-71) runs for the Mirrors, counts every datagram it drops by reason, and drops a datagram of a VNI that it does not carry. The sidecar `ranz bgp` runs toward the routers of an operator: it exports only the Node's own prefixes, imports only what an accept list covers, rejects by default, and sets no authentication on a session. The link kinds, the peering of two Ranz Nodes and the tag option are open tickets.

The EVPN gateway (SDN-25, #201; ADR-0032) is an edge of the same trust, the fabric edge: a gateway Node hands VRFs of the overlay to the fabric of a data center as EVPN type-5 routes through `ranz bgp`, and carries their packets in VXLAN between its own VTEP and the VTEPs of the fabric, plain, on the underlay of the data center. It sits on B9 too, and there the source address of a datagram is all that names a VTEP of the fabric (SM-11).

| part | status | evidence |
|---|---|---|
| the link kinds `noise`, `vxlan` and `geneve` between two Nodes (SDN-76) | designed | #356 |
| BGP, EVPN and the route reflector between Nodes (SDN-77 to SDN-79) | designed | #357, #358, #359 |
| the group and tag option, in `off`, `trusted-underlay` and `hmac` (SDN-87, SDN-88) | designed | #386, #387 |
| the VXLAN and Geneve module | runs, for the Mirrors | `Vxlan.h`; fuzz `fuzz_vxlan`, `fuzz_geneve` |
| the BGP sidecar toward the routers of an operator | runs | code `ranz-bgp/internal/sidecar/sidecar.go`; tests `sidecar_test`, `bgptest` |
| the EVPN gateway toward the fabric of a data center, with the check of the outer source of a frame (SDN-25, SDN-25-R1) | runs | code `NodeEvpn.c`; tests `vpntest evpn`, `TestFRREVPN`; fuzz `fuzz_evpn`; #201, #549 |

### What the operator must provide

The standard mode gives the Node a list of peers and the policy engine. Everything under that is the operator's, and each row names what is lost without it.

| the operator provides | what it is | what is lost without it |
|---|---|---|
| a trusted underlay | A network that the operator controls: nobody who is not trusted can send or capture packets on it. A LAN, an intranet, a data center, a private WAN. | Everything below: reading, injection and replay (SM-1 to SM-3). The product cannot tell an underlay that is not trusted. |
| confidentiality, where it is needed | IPsec, MACsec or WireGuard under the links, outside the product. The mode carries frames and packets in clear. | Any host that can capture reads the traffic. |
| source-address validation | Ingress filtering or unicast reverse path forwarding at the edge of each segment, port security or DHCP snooping on the switches: no host sends with the address of another. In these links the source address of a datagram is the only identity of a peer. | A host injects frames and packets as a peer (SM-2). |
| border filtering | UDP 4789, UDP 6081 and TCP 179 reachable from the peers' addresses only, never from the internet. `ranz install` opens none of them (`docs/ports.md`). | The receivers are open to the world, and a flood or a crafted datagram reaches them (SM-5). |
| stable addresses for the peers | Each Node keeps the underlay address that the Intent names, by a static address or a DHCP reservation. | The address of a peer that another host takes over is trusted as that peer. |
| protection of the BGP and EVPN sessions | TCP-AO or MD5 on the session or an IPsec path under it, a TTL check where the peers are one hop away; the product sets none (SM-5). | A session is reset or taken over by a host on the segment. |
| limits on what a peer may announce | The prefixes, the MACs and the VNIs that each peer may announce, and a maximum. The product has the mechanism in the sidecar (an accept list, default reject); the Intent must feed it for each peer (SM-6). | A peer announces a prefix that is not its own, or a default route, and the Node installs it in the routing table of the host. |
| authenticated time | A trusted NTP source, or NTS, with the clocks within 30 s, for `hmac`. | The MAC window is widened, so that a replay works, or closed, so that every packet fails (SM-9). |
| care of the key of a VRF | The key of `hmac` is in the store, in its backups and in the Generation of every Node of the VRF (ST-4, CS-5). A Node that holds it can forge a tag for the whole VRF. | A forged tag is honoured as a real one. |
| watching the counters | The drops by source, by unknown VNI, by wrong MAC and the refused claims, which the Node exports. | An injection goes on and nobody sees it. |

What the product provides: the list of peers and VNIs from the Controller, the drop and the count of a datagram from an unnamed source or on an unknown VNI, the policy engine with its default deny on the group that a packet carries, one table and one conntrack for each VRF, the mark "unencrypted" on a plain link in `ranz explain` and the web UI, the `hmac` option where its key is set, and the filters of the BGP sidecar. What it does not provide: authentication of a data packet (an address is not an identity), confidentiality, protection against replay beyond the window of `hmac`, and any limit on a peer that holds the key of its VRF.

### What each attacker can do

- **A host on the underlay, the attacker on the path.** It reads all the traffic. It injects datagrams with the source address of a peer, and with any inner address, and the Node cannot tell them from the peer's. It replays packets inside the window of `hmac`. It floods the ports and resets a BGP session.
- **A malicious peer.** A Node of the VRF. It sends a datagram on the VNI of another VRF that the Node carries (SM-4), announces prefixes and MACs that are not its own (SM-6), and, with the key of the VRF, forges tags for all of it (SM-3).
- **A malicious tenant.** A Node of another VRF on the same underlay does the same with the VNIs of the Nodes that it can reach.
- **A stolen node key.** The key authenticates the control stream and nothing on the data path of this mode. The thief gets the Generation of the Node, with the key of `hmac` of each of its VRFs (CS-5), and, if the Node is a route reflector, the routes of its clients (SM-7).

### Threats

| id | who | threat | control, with its evidence | status | gap |
|---|---|---|---|---|---|
| SM-1 | host on the underlay | Reads the traffic: the links are plain by decision, so `vxlan` and `geneve` carry frames and packets in clear. | The operator's underlay, with IPsec or MACsec under it where that is needed. The product marks the link as unencrypted in `ranz explain` and the web UI, as information and not as a refusal. Evidence: #356; ADR-0032. | designed, accepted by decision | none |
| SM-2 | host on the underlay | Injects datagrams that look like a peer's. The Node accepts datagrams from the addresses that the Controller named, and learns nothing from the wire, but an address is no identity: a host that can send with a peer's source address, or sits on its segment, injects frames into the VNI. The tag modes do not stop it. In `trusted-underlay` a forged tag is honoured. In `hmac` a packet with a wrong MAC is treated as a packet with no option and judged by the map of address to group, so a host that spoofs the address of another is that host. | The list of peers; a datagram from an unnamed source and one on an unknown VNI are dropped and counted. The operator's source-address validation. Evidence: #356, #386, #387; code `Vxlan.h` (the drop reasons); reasoned for the fall back. | designed | G-24, Appendix C (#387) |
| SM-3 | host on the underlay, a holder of the key | Forges tags and replays packets. In `trusted-underlay` any tag is honoured. In `hmac` a holder of the VRF key, which is every Node of the VRF, forges the tags of the whole VRF, and a packet is good for 30 s. | #387 states the limits (replay inside the window, no encryption of the payload, one key for the VRF) and asks that the key travels only in the Generation over the authenticated stream and is in no log, no audit record and no bundle. It does not cover the copy of the key in the store and in its backups (ST-4), the key that a viewer could read if it were a field of a resource (AP-8), or the key that a stolen node key gives (CS-5). Evidence: #387; reasoned. | designed | G-24, Appendix C (#387) |
| SM-4 | malicious peer or tenant | Sends a datagram on the VNI of a VRF that it is not a member of. #356 drops a datagram from an address that the Controller did not name, and one on a VNI that is unknown, each on its own; a named peer that sends on a VNI that the Node carries for another VRF passes both. For an L3 VRF the table of that VRF must still route the inner source to that peer (NS-7); for an L2 VNI nothing does. | None as written. The amendment is to accept a datagram only from a source that the Controller named for that very VNI. Evidence: #356; reasoned. | designed | G-25, Appendix C (#356) |
| SM-5 | host on the underlay | Floods UDP 4789, UDP 6081 or TCP 179, or resets a BGP session. | A datagram from an unnamed source is dropped and counted, and a BGP session is accepted only from a named peer. The operator filters the ports at the border. The sidecar sets no TCP-AO or MD5, no TTL security and no maximum number of prefixes on a peer, and the Node has no limit for a source. Evidence: code `ranz-bgp/internal/sidecar/sidecar.go` (`peerRequest`); `docs/ports.md`; #357. | designed | G-26, G-7 |
| SM-6 | malicious peer (BGP, EVPN) | Announces what is not its own, to take traffic or to blackhole it: a more specific prefix, a default route, a prefix of another VRF, a MAC of another host (an EVPN type-2 route with MAC mobility moves a MAC to whoever announces it). The Node installs what it learns in the routing table of the host. | The sidecar of today exports only the Node's own prefixes and imports only what its accept list covers, with default reject, which is the control; #357 requires that the routes of a VRF never appear in another VRF, and #359 that a reflector never reflects into another. The accept list of each peer has to come from the Intent: what that Node may announce, a maximum, and no default route unless the Intent says so. EVPN needs the same for MACs and VNIs, and a limit on the rate of MAC moves. Evidence: code `sidecar.go` (`setPolicies`); #357, #358, #359; reasoned. | designed | G-26, Appendix C (#357, #358) |
| SM-7 | stolen key of a route reflector, a reflector that is compromised | Decides the routes of every client of its VRF: it reflects what it likes and withholds the rest. | Two reflectors for redundancy (#359), named by the Controller. Its key is a node key: ADR-0041 would bind it to the TPM. A reflector is a point of trust, and its key is the first that deserves that binding. Evidence: #359; ADR-0041. | designed | G-6 |
| SM-8 | operator | Configures a plain link where it does not belong: `vxlan` over the internet, two VRFs on one VNI, a VRF that mixes the two forms. | The Controller checks the Intent (a VRF uses one form, #358; a VNI belongs to one VRF) and a Node reports the Capability. `ranz explain` marks the link unencrypted. Nothing refuses a link whose endpoint is a public address. Evidence: #356, #358; reasoned for the public address. | designed | G-27, Appendix C (#356) |
| SM-9 | on-path to the clock | Moves the clock of a Node, with a spoofed NTP answer on the underlay, to widen the window of `hmac` or to make every packet fail it. | The operator's time source. Evidence: #387 (a window of 30 s). | designed | none: the operator provides authenticated time |
| SM-10 | the Controller | Is the only source of the peers, the VNIs and the flood lists, and no session checks it on the data path of this mode: a wrong Intent sends the datagrams of a VRF to any address on the flood list. | The control stream of section 8, and CS-9: the operator is trusted with the Intent. | accepted | none |
| SM-11 | host on the underlay, or any host that reaches the VTEP port of an EVPN gateway | Forges a frame of the fabric to an EVPN gateway, at the fabric edge (SDN-25): a datagram on the L3 VNI of an EVPN VRF, with the router MAC of the gateway as its destination (the default `02:52:5a:00:00:05` is public) and a source inside a prefix that the gateway learned from the fabric. Its packet goes to the host of the gateway, which neither the session profile nor the policy judges (`NodeOverlayFabricInput`), or on to a peer of that VRF. | The gateway takes a frame of the fabric only from a VTEP that it knows for the VRF of its VNI: the next hop of an IP prefix route of the VRF that it learned. The address alone names the VTEP, which sends from any source port, so a frame of an L3 VNI from any other address is dropped and counted as `UnknownVtep`, whatever it holds (`NodeEvpnReceive`, `NodeEvpnHasVtep`; SDN-25-R1, #549). The module reads the VXLAN header of each datagram before that check, whatever its source: it drops a datagram that holds no frame, counted as `Malformed`, and one on a VNI of no EVPN VRF, counted as `UnknownVni` (`VxlanInput`), so a host that is no VTEP raises those two counters too, and nothing of its datagram is delivered or learned. After the check the gateway drops a frame that is not addressed to its router MAC (`NotOurs`), that holds no IP packet (`Malformed`) or whose source no route of the fabric in the VRF holds (`Strangers`): those count the frames of known VTEPs alone (SDN-25-R3, #571). What is left: a host that sends with the address of a VTEP that the fabric owns, spoofed at the underlay, is that VTEP to the gateway; the operator's source-address validation and border filtering answer it (the VTEP port of the gateway, UDP 4789 by default, open to the VTEPs of the fabric only), as for SM-2. The check also drops the frames of a VTEP that is the next hop of no route that a peer offers the gateway: an anycast or ECMP VTEP that announces no route of its own. A leaf whose route of a shared prefix lost to the route of another leaf in the sidecar, which reports one route for each prefix of a VRF, is known all the same: the learned message names the next hops of every route that the peers offer for the prefix (`vteps`, 16 at most; SDN-25-R3, #571). An operator sees the frames of unknown VTEPs: the node log names one once every 10 s at most, with their number, `ranz node state` counts them (`unknownVtep` of its `evpn`), and the Controller exports them as `ranz_evpn_dropped_frames_total{reason="unknown-vtep"}`. Evidence: code `NodeEvpnReceive`, `NodeEvpnHasVtep`; tests `vpntest evpn` (a frame of red from 127.0.0.3 is dropped and counted, and the same frame from 127.0.0.2, the VTEP of the routes, reaches the host, also from another source port; a frame of red from 127.0.0.4, a second leaf whose route of 172.16.1.0/24 lost and which has no prefix of its own in red, reaches the host until the leaf withdraws its route), `TestEVPN` (the vteps of the second leaf grow and shrink with its route), `TestFRREVPN` (each echo reply of FRR comes from the next hop of its routes); fuzz `fuzz_evpn` (the VTEPs and the vteps of the routes, sorted, against a list of them). | runs | none: the operator provides source-address validation |

## 13. The other entry points

These came after the ticket was written, or sit beside the planes above. Each is a way in that the threat model of a plane would otherwise miss. Their trust boundaries are B4 (the peer layer), B10 and B11 (the sidecars and the pipes of the host) and B12 (the Devices).

### What each is, as built

The WireGuard Devices (SDN-80 to SDN-86, #375 to #381; spec #374) are phones, laptops and routers that join one Network over standard WireGuard through a gateway Node, with WireGuardNT of the pinned SDK 0.10.1 loaded from the directory of the Node's executable. The tracer (`NodeWireGuard.c`) is built in part, and so are the keys (SDN-82, #377): an administrator makes a Device, and the Controller makes its key pair and a PresharedKey, answers once with the finished configuration and its QR code, and keeps only the public key and the sealed PresharedKey (`devicekeys.go`); the life cycle and the self-service are open. The WireGuard key pair of a gateway is derived from its static key and never stored. The peer layer (`Peer.h`, ADR-0015) is the relay role and the direct path with ICE: Noise_IK between the static keys of two Nodes in the manner of WireGuard, sealed envelopes for the signals, and a relay that both ends are bound to. Its models are the `peer-*` queries; nothing in production calls it yet (CS-8). The sidecars (`ranz bgp`, `ranz mimic`, `ranz acme`) are child processes of the Node's account, reached over named pipes. The admin pipe and the client pipe are the local ways to drive a Node. The Configuration store of the Node, `ranz_node.db`, holds its settings.

### What each attacker can do

- **On the path.** It reads and drops the datagrams of the peer layer and of the WireGuard port, and it reads the clear header of the peer layer (OE-5). It cannot read a peer session or the tunnel of a Device.
- **A malicious peer.** It can bind to a relay that it is named for (OE-4), and learns from the signals the addresses of the peers that it shares a VRF with (OE-6).
- **A malicious tenant.** A Device or a host of another VRF reaches nothing outside its own VRF, since the policy judges a Device by its address (OE-3, DP-4).
- **A stolen node key.** For a gateway, the WireGuard key pair of the gateway too, which derives from the static key and is never stored. For any Node, its peer sessions (NS-11).
- **A local user.** The pipes and the Configuration store (OE-7 to OE-11).

### Threats

| id | who | threat | control, with its evidence | status | gap |
|---|---|---|---|---|---|
| OE-1 | stranger | Probes or floods the UDP port of a WireGuard gateway (51820 by default, open to the internet). | WireGuard does not answer a packet that has no valid MAC, and asks for a cookie under load. The driver is the pinned `wireguard.dll`, called only through its published API. The gateway reports the Capability only when the library loads. Evidence: the WireGuard protocol; code `NodeWireGuard.c`; `docs/ports.md`; reasoned. | designed | none: the supply chain is TR-11 |
| OE-2 | stolen Device key, a lost phone | Is the Device, from any address, until the Intent drops it: the Device's overlay address and its tags, and what the policy gives them. | The policy by the address of the Device, and the Device is a member of its VRF of its own, never taken for the host of its gateway. The keys are decided (SDN-82, #377). The Controller makes the private key of a Device in the memory of the one call that makes the Device, puts it into the one answer, with the finished configuration and its QR code, and forgets it: it is in no row of the store, resource, revision, export, log, audit record or diagnostics bundle, and when the administrator supplies the public key the Controller never sees a private key. The answer says `Cache-Control: no-store`, and a second call for the same Device is refused, since a key is never changed in place. The PresharedKey is made with it and kept like the secret of a target (ST-4): a Sealed secret in the table `device_keys`, never in the Intent or its revisions, opened only for the gateway of its Device and carried in clear inside the control stream to that gateway alone. A configuration file or a QR code that is stolen is a stolen Device key, since it holds both keys: it shows once, and the clients guide says to delete the file. The life cycle (revoke, disable, expire, audit; #376) is open. A revoke is a Generation to the gateway, so it takes as long as the stream to the gateway does. Evidence: `NodePolicy.c`, `NodeWireGuard.c`; code `controller/internal/controller/devicekeys.go`, `store/devicekeys.go`, `devicekey`; tests `TestDeviceKeysAreFoundNowhere` (both keys searched for in the store and the files of `rqlited`, the log, the audit log, the revisions, the export, the diagnostics bundle and the frames of the nodes), `TestPresharedKeyIsSealedAtRest`, `TestCreatedDeviceHasItsConfigurationAndQRCode`, `TestDeviceWithAPublicKeyOfItsOwn`; the step WireGuard Device tracer of `windows.yml`, in which a stock client that holds the PresharedKey completes its handshake with the gateway and one that does not gets none; #375, #376, #377. | partial | G-28 (the life cycle), Appendix C (#376) |
| OE-3 | Device | Reaches beyond its VRF through the OS forwarding of the gateway: the host of the gateway forwards between the WireGuard interface and the adapter of the VRF, and the host's own services are on the other end. | Forwarding is on for those two interfaces only (the weak host model on); the policy judges a packet of a Device by its address; Windows does not forward between two Devices on the WireGuard interface unless the rules let every packet between them through, so a rule of only some of their flows keeps them apart whole (`NodeWireGuardFilter.c`, ADR-0029 amendment of 2026-10-27); the host's own firewall judges what is for the host. Evidence: code `NodeWireGuard.c` (its header); test `devicetrace` (the WireGuard Device tracer: two Devices of one gateway, and a Device of each of two gateways); ADR-0029; reasoned. | runs | none |
| OE-4 | stranger, any bound peer | Abuses a relay: floods binds or data, or uses it to reach a peer that is not in its VRF. | A bind needs the cookie that the relay sealed to that node for that address, so an address that is spoofed gets none; a relay forwards only when the source is a peer and the destination is the node or a peer that shares a VRF with the source; and it has a rate limit for each source (`PEER_DROP_RATE`). Evidence: code `Peer.h`, `PeerChallenge.c`, `Peer.c`; model `peer-*`; coretest `relay`. | tests only | none |
| OE-5 | on-path, a relay | Learns who talks to whom: every datagram of the peer layer starts with a clear header of 65 bytes, its kind, the key of the source, the key of the destination and a session index, which a relay forwards by. The static keys are a stable name for a Node across addresses. | On a UDP socket, none. `Peer.h` plans to carry the datagrams on the QUIC datagrams of the outer session, where this header is inside the encryption. Nothing ships the peer layer yet. Evidence: code `Peer.h`; ADR-0035. | tests only | none: a requirement on that move (section 15) |
| OE-6 | on-path, a home gateway | Answers the port mapping of a Node (PCP, NAT-PMP, UPnP) with its own mapping, or reads the ICE candidates, or a STUN server learns the address. | Every datagram between two Nodes is in a peer session under their static keys, so a wrong mapping loses the path and reads nothing; a peer learns the addresses in the candidates, which the sealed signals carry only to a peer that shares a VRF. Evidence: code `PeerPortMap.c`, `PeerIce.c`; model `peer-leaks`; `docs/ports.md`. | tests only | none |
| OE-7 | a flaw of a sidecar, a local user | Takes a sidecar: it runs in the account of the Node, so it is the Node to the host. Or opens the pipe of a sidecar. | The Node starts a sidecar in a job object that ends with the Node; the control pipe of `ranz mimic` and the pipe of `ranz bgp` open for the Node's account alone (ADR-0039 decision 3, `NODE_MIMIC_PIPE_SDDL`, `NODE_BGP_PIPE_SDDL`) and take only the process that the Node started; the keys go over the pipe, never on a command line. Evidence: code `NodeMimic.c`, `NodeBgp.c`; tests `mimic`, `bgptest`. | runs | none: the sidecar and the Node share an account, by design |
| OE-8 | local user | Drives the Node over the admin pipe. | Only SYSTEM and the Administrators may open it. One command line is split by `ParseToken` and its Controller settings pass the checks of an address, a base64 key of 32 bytes and 64 hex digits; the registry exempts `NodeAdminCommand` from a fuzz target for that reason. Evidence: `.github/quality/fuzz-targets.txt`; code `NodeAdminCommand`. | runs | none |
| OE-9 | local user | Takes the VPN of a client role up or down, or reads its status, over the client pipe, which the interactive users may read and write (`(A;;GRGW;;;IU)`); on a host with several interactive users, one user can disconnect the others. | The pipe takes no remote client; its commands are `status`, `up` and `down`, each answered with the status of the role as one JSON object. A client role is a person's PC. Evidence: code `NodeClient.c` (`NODE_CLIENT_PIPE_SDDL`, `NodeClientCommand`). | accepted | none |
| OE-10 | any host on the overlay | Sends crafted queries or requests to the overlay DNS and DHCP responders of a Node (SDN-11, SDN-43), or starves the pool of leases with many requests. | The responders read what the host sends on the overlay adapter, answer from the records of the Intent, and hold at most 1024 leases; both have fuzz targets. Evidence: `.github/quality/fuzz-targets.txt` (`NodeDnsAnswer`, `NodeDhcpInput`); `proto/ranz/control/v1/control.options`. | runs | none |
| OE-11 | local user | Reads or changes the Configuration store of the Node, `ranz_node.db`: the Controller pin, the settings of the sidecars with the REALITY key (TR-10), the pins of users. | The data directory of the Node has a protected access list (SYSTEM, the Administrators, the service SID) and, when the Node runs elevated, the Administrators as its owner (`NodeMakeDataDir`). Evidence: code `Node.c`. | runs | none |

## 14. What is out of scope, and why

The page covers the new core (the Node) and the Controller as they are in the tree of `integration`, against the four attackers of section 3 and the two that were added. Each item below is left out for one of three reasons: it is another ticket's work, no control of the product could answer it, or it is not a property that anybody relies on. The reason is written with the item.

| out of scope | why | where it is covered, if it is |
|---|---|---|
| The slim fork, its legacy listener, `vpncmd` and OpenSSL | They are being retired (CORE-S8-1, #84), and their surface is the one that the fork has always had. This page is about what replaces them. | #84; ADR-0037 for the legacy phase |
| The Windows kernel, its drivers (Wintun, WireGuardNT, SeLow, XDP), msquic, Schannel and CNG | Third-party and OS code. The product pins and signs what it ships and reads what the OS reports. This page names the use of each, not their flaws. | TR-11; SEC-1, SEC-2; CLN-3 (#361) |
| An administrator or SYSTEM on a host of the product, a kernel-mode attacker, physical access, a hypervisor | They hold the host, so they hold the keys that it uses and the memory that it works in. The service accounts of ADR-0039 only limit what a flaw of one service gives. | A12; section 3 |
| An operator or a Controller that does wrong with the Intent | The Controller is the root of trust of the overlay (ADR-0026). The page records what limits and records its abuse (CS-9, AP-5 to AP-7), and does not claim to prevent it. | AP-5 to AP-7; DT-9 |
| Censorship beyond tiers 1 and 2 of ADR-0006, traffic analysis by size and timing | The product claims to look like ordinary Windows software on the wire, and no more. A classifier of the GFW class, or a study of sizes and timing, is not answered in v1. | TR-1, TR-2; the mimic path is AUD-7 (#425) |
| Volumetric denial of service | A flood that fills the link cannot be answered by software on the host. The exhaustion of a thread, a table or the memory of the product is in scope. | G-1, G-7, G-14, DP-5 |
| Side channels: timing, caches, speculative execution | Beyond the compiler's mitigations (ADR-0024, a draft) the product relies on the libraries for constant time. The page does not audit them. | ADR-0024; AUD-2 for the code that is ours |
| The cryptographic primitives and the Noise framework | AES-GCM, X25519, SHA-256, ML-KEM, Ed25519, HMAC and PBKDF2 are assumed sound. The ProVerif models assume perfect cryptography and say what else they leave out. | `docs/formal-model.md` |
| A quantum attacker on authentication | The static keys are X25519 and nothing plans a post-quantum signature. The records are protected by the key exchange of the outer session. | NS-4; the position in section 5; #382 |
| The vendor's infrastructure, and licence enforcement against the administrator of a host | The activation service, its HSM and its signing key are the vendor's systems. A licence is not a security property that an operator relies on: an administrator who patches the binary beats it, and ADR-0036 says it never stops a live tunnel. | A11; ST-6 to ST-9 |
| Features that are not built | They have no code to review. Each is named so that its threat model is written with it: the Controller's end of the handoff (SDN-73, #352), the static site (#353), ingress (#354), roles scoped to a Network (#231), multi-factor login (postponed in #226), the phase-2 transports (#86, #95), the TPM-bound identity (ADR-0041), and the life cycle of a Device and the self-service Devices (#376, #381). | Appendix C names what each must say |
| The security of the other end: the OS of a phone with a Device key, the receiver of a webhook, the router of an operator | The product ends at its own interface. It limits what it sends (AP-6) and what it accepts (SM-6). | AP-6, SM-6, OE-2 |
| Social engineering, phishing of an operator, the process around the product (backup policy, patching, who holds a token) | No control of the product answers it. Section 12 says what the operator of the standard mode must do. | section 12 |
| The repository and its build pipeline | A supply-chain risk to what is shipped, not a threat to the running product. | SEC-1 to SEC-3; AUD-4 (#365) |

## 15. Questions, and where to start

### For the maintainer

The numbers are the ones that the rows cite.

1. **The Login.** The Login of a Node (NS-14 to NS-16) is built and tested, and nothing in production calls it. Is it wired to the users that the Controller keeps (`user_passwords`, PBKDF2) when SDN-32 (#226) lands, or retired in favour of the Controller's own logins? DT-5 puts a throttle on it either way.
2. **Which operator powers are admin's.** Targets and audit targets (AP-6), Mirror sensors, Listener file paths, the audit retention (AP-7), the licence (ST-7), the logs in the diagnostics bundle and the password of a user (AP-9). DT-9 assumes: targets, sensors, UNC paths, the retention and the audit targets become admin's, the rest stay operator's.
3. **The default reach of the API.** `ranz install --controller` opens TCP 443 and 5555 on every profile and the admin source allowlist is empty, so the token is the only barrier (AP-3). Should the first install narrow the allowlist (DT-6), as the mesh of ADR-0034 narrows nothing? DT-6 is built (#454): the install narrows it, and `--admin-from any` lifts it.
4. **A maximum age for a Generation.** A Node with no Controller keeps forwarding on its last Generation, so a revoked key stays good at the peers that did not hear (CS-10). An optional maximum age, after which a Node drops the peers that the Generation named, would bound it at the price of making a Controller outage a data-plane outage. Accept the risk as ADR-0027 does, or add the option?
5. **Limits at the receiver.** The rate limit of a VRF is the sender's own (NS-8), and the conntrack table has no share for a member (DP-5). Should a Node limit what it takes from one peer, and the flows that one peer may hold?
6. **The Controller's Noise key.** The Nodes pin it, and the `Controllers` message carries the keys of the members, but no document says how a key is replaced after a leak (CS-11). The TLS key has the mechanism of ADR-0027 (CS-12).
7. **ADR-0041.** Accept it, so that CORE-H4-1 to CORE-H4-9 are filed (G-6)? The reflectors of the standard mode and the gateways of Devices deserve the binding first (SM-7).
8. **The position on the hybrid handshake.** Section 5 proposes to keep it off on the bound paths and to require it of the CDN path (#86). Accept it as the decision that CORE-P2-5 and #374 leave to this page?
9. **The peer layer.** Does the direct path ship inside the QUIC datagrams, as `Peer.h` plans, so that its clear header of 65 bytes is inside the outer encryption (OE-5)?
10. **Plain links across the internet.** Should the Controller refuse a `vxlan` or `geneve` link whose endpoint is a public address unless the Intent says that it knows (SM-8)?

### For AUD-2 and AUD-4

The rows marked reasoned are ours and nothing tested them. These are the ones whose answer would change a severity, so read them first:

- NS-9: measure the stall of the overlay thread with silent connections, and NS-6: whether Schannel and msquic update their keys by themselves.
- CS-4: the memory that a stalled frame holds is counted by a test now (`TestStalledFrameHoldsOnlyWhatArrived`); measure the connections that it takes to exhaust a Controller with the caps of 1024 streams in all and 64 for a source, and the cost of the TLS handshakes that come before them (AP-11).
- FD-4, FD-8: try the squat of a handoff pipe, and read what `PROCESS_DUP_HANDLE` on the Controller's process gives the Node's account.
- ST-1: run the exploit (a token row, a Node resource) from a local user. ST-3 is tested since AUD1-DT-10 (`datadir_windows_test.go` makes the data directory of a standard user), and since AUD1-DT-18 also for the gap at the creation of the folder (`TestNoStandardUserOpensANewDataDirWhileItIsMade`) and for what a kept folder holds (`datadir_window_windows_test.go`), and since AUD1-DT-18-R1 (#554) for the swap of a new folder and of a kept one by an account that may change the folder above, a hard link in a kept folder, an entry that its owner switches between a folder and a junction while the install looks, and the names that Windows reads as other ones (`datadir_race_windows_test.go`); what is left to try is what a user adds to a kept folder whose list lets it while the install looks, a hard link above all, which gets the list of the install before the second look refuses it, and a handle that a user opened in a kept folder before it had its list.
- AP-6 (a target on `127.0.0.1:4001`, a UNC path in a Listener, a Mirror sensor off the network). The loopback case of AP-2 is run since DT-13: `TestRanzRefusesAnotherKeyOnLoopbackAndSendsNoToken`, and the file that another account made or wrote since DT-14: `TestRanzRefusesAFingerprintFileThatAnotherAccountMayHaveWritten`.
- DP-6: whether a state of an older schema can leave the policy out, and where else a Node fails open.
- NS-19: the use of one static key by three protocols, which no model runs together.
- Everything that reads memory of the peer's bytes: `NodeOverlayInput`, the nanopb decode in `Control.c`, `CsImportForkConfig` (DT-12).

### How this page is kept

A new transport, a new owner behind the front door, a new sidecar or a new way into the Controller adds a section or a row and a box on the diagram of section 4. A ticket that closes a gap changes the status of its row, and the register of Appendix A is updated in the same pull request. The page is reviewed by the maintainer and by AUD-2, and is the first part of the package of AUD-4.

## Appendix A. The register of gaps

Severity is defined in section 1 and is our judgement. A gap is answered by an open ticket (`#n`), by a draft ticket of Appendix B (`DT-n`), or by an amendment of Appendix C. The integrator files the drafts: the lane that wrote this page may not open issues.

| id | gap | rows | severity | answered by |
|---|---|---|---|---|
| G-1 | A stranger that holds no key stops the forwarding of a Node: the handshake runs on the one thread of the overlay. | NS-9 | High | DT-1 |
| G-2 | The outer keys are never updated, and nobody knows whether the OS does it. | NS-6 | Low | #400 |
| G-3 | A client still offers TLS 1.2 by default. | NS-5 | Low | #400 |
| G-4 | The hybrid key exchange of the QUIC path is not proven. | NS-4 | Low | #382 |
| G-5 | The Login has no throttle or lockout, and nothing calls it. | NS-15 | Medium | DT-5, #226 (Appendix C) |
| G-6 | A copy of a node key is the Node, from anywhere, until the Intent drops it. | NS-11, NS-13, CS-5, SM-7 | Medium | ADR-0041, then CORE-H4-1 to CORE-H4-9 (question 7) |
| G-7 | No limit for a source and no cap on unauthenticated connections: the front door, QUIC, the Controller's port. | NS-10, TR-5, FD-1, FD-6, AP-11, SM-5 | Medium | #451 (AUD1-DT-3), closed for the front door, QUIC and the Controller's port; SM-5 stays with the sidecar (G-26) |
| G-8 | The pin is a SHA-1 thumbprint that a person types. | TR-8 | Low | #400 |
| G-9 | The Listener of a Node configures no decoy, so a prober sees a closed connection. | TR-2 | Low | DT-4 (the static site is #353) |
| G-10 | A QUIC handshake that fails does not fall back to TLS-443, and the msquic minor is not pinned. | NS-1, TR-6, TR-11 | Low | #443 |
| G-11 | The suites and the pin of the mimic path are not settled. Its formal model exists (`tests/formal/mimic`, TR-9). | TR-9 | Medium | #400; #425 (AUD-7) made the model and is closed |
| G-12 | The REALITY key of a mimic server is kept as text in the Configuration store. | TR-10 | Medium | #424 (Appendix C) |
| G-13 | Nothing checks who serves a handoff pipe, and the handoff gives the Node's account a right on the Controller's process. | FD-4, FD-8 | Medium | DT-7, #352 (Appendix C) |
| G-14 | The Controller allocates up to 16 MiB for each connection before it knows who it is. | CS-4, CS-6 | Medium | #450 (AUD1-DT-2), closed |
| G-15 | Parsers that read a peer's or the Controller's bytes have no fuzz target: `NodeOverlayInput`, `CsImportForkConfig`, the nanopb decode of a Node. | CS-13, DP-7 | Low | DT-12 |
| G-16 | An operator can point the Controller or a Node at any host and any address, copy a VRF's traffic to any sensor, and shorten the log that records it. | AP-6, AP-7, AP-9, ST-7 | Medium | DT-9 |
| G-17 | A token never expires, shows no last use, and a read is not audited; the CLI checks no certificate toward loopback, and then took a fingerprint file that a local user could have written. | AP-2, AP-8 | Low | #461 (AUD1-DT-13) and #496 (AUD1-DT-14), closed |
| G-18 | The store's HTTP port on loopback asks for no credential: a local process is an admin of the Controller. | ST-1 | High | DT-8 |
| G-19 | The Raft traffic of a cluster is neither encrypted nor authenticated. | ST-2 | Medium | DT-8 |
| G-20 | A data directory that a local user made first stays that user's, and holds the `rqlited.exe` that the service runs; a new one had the list of its parent until the install set its own, and a kept one kept what a user made in it. | ST-3 | Medium | #458 (AUD1-DT-10), #503 (AUD1-DT-18) and #554 (AUD1-DT-18-R1), closed: #554 works on the folder through a handle, so the swap of a new folder or of a kept one by an account that may change the folder above it gives that account nothing, refuses a hard link in a kept folder, and looks at each entry once, by its exact name, which an entry switched between a folder and a junction, or named so that Windows reads it as another one, cannot pass. What they leave is in the status of ST-3 |
| G-21 | The L2 protections of SDN-41 are open, and the switch and the guard are not wired into a Node. | NS-7, DP-8 | Medium | #234 (and #292, #293 for the stretch) |
| G-22 | The secrets of the targets are in the store in clear, and a backup is written with the access list of its folder. | ST-4 | Medium | #458 (AUD1-DT-10), for a Controller cluster #501 (AUD1-DT-16), and for a secret that an upgrade sealed, the URL of a target and the label of a sealed secret #502 (AUD1-DT-17), closed; what #502 leaves, the token in a URL and the old text of a migrated secret in the data of `rqlited`, is in the status of ST-4 |
| G-23 | A revocation list can be replayed or removed, and the activation client takes any base URL. | ST-8 | Low | Appendix C (the release work that links the activation package) |
| G-24 | In the standard mode a packet with a wrong MAC falls back to the address, an address is an identity, and the key of `hmac` is one for the VRF and sits in the store. | SM-2, SM-3 | Medium | #387 (Appendix C) |
| G-25 | The two rules of SDN-76 do not bind a source address to a VNI. | SM-4 | Medium | #356 (Appendix C) |
| G-26 | The BGP sidecar sets no session protection and no maximum, and the accept list is not yet fed per peer from the Intent; EVPN has no per-peer limits. | SM-5, SM-6 | Medium | #357, #358 (Appendix C); #292, #293 |
| G-27 | Nothing refuses a plain link whose endpoint is a public address. | SM-8 | Low | #356 (Appendix C), question 10 |
| G-28 | The life cycle of a Device is open: revoke, disable, expiry and audit. Its keys have a rule since SDN-82: the private key is never kept, the PresharedKey is sealed. | OE-2 | Medium | #376 (Appendix C); the keys: #377, closed |
| G-29 | A first install leaves the API open to every address, with the token as the only barrier, and the starter rule allows all inside `default` with no notice. | AP-3, DP-1 | Low | #454 (AUD1-DT-6), closed |
| G-30 | Nothing shows a session that is replaced again and again by two holders of one key. | NS-12 | Low | #459 (AUD1-DT-11), closed |

## Appendix B. Draft tickets

The format is the one of the tickets of this repository. The lane that wrote this page may not create issues, so these are drafts: the integrator files them and assigns their keys (the CORE-H series for the Node, SEC for the Controller). Each one names the gap it closes, and carries acceptance criteria that a test or a CI job can check.

### DT-1. A stranger's handshake never runs on the forwarding thread of a Node

```markdown
## Parent

#45

## What to build

`NodeOverlayAccept` reads the first frame of an accepted stream inline, on the one thread that also reads the sessions of every peer and dials every peer (NS-9). A connection that finishes the outer handshake and then sends nothing stops the forwarding of the whole Node for up to `NODE_OVERLAY_HANDSHAKE` (5 s), and one such connection every 5 s keeps it stopped. After this ticket the handshake of a stream that has not proved a key runs off that thread, in a bounded pool of workers or in a state machine that never blocks, with a cap on the handshakes in flight. The thread of the overlay only takes a session that finished.

## Seam

the vpntest harness (seam 2 of #45)

## Phase

Hardening phase (after the core data path)

## Acceptance criteria

- [ ] With 64 connections that complete the outer handshake and send nothing, the forwarding of an established session between two Nodes is delayed by no more than a bound that the test states, measured by the harness.
- [ ] A handshake that does not finish in its time is closed and counted, and the count is in the status of the overlay.
- [ ] No more than a configured number of handshakes are in flight; the next are refused at the accept and counted.
- [ ] The test fails on the code before the change, which the PR shows.
- [ ] `NodeOverlayAccept` makes no blocking read on the thread of the overlay.

## Blocked by

None

---
Ticket key: to be assigned. Draft of AUD-1 (#362), gap G-1.
```

### DT-2. The Controller reads little before it knows the Node

```markdown
## Parent

#45

## What to build

`control.Conn.Read` takes a frame of up to 16 MiB (`MaxFrame`) from the first one, and `readFrame` allocates the whole length as soon as it has read the four bytes of it. After the Noise handshake the Controller reads the Hello within 10 s, so a connection that sends the length of a 16 MiB frame and stalls holds 16 MiB for that time, with no key of a Node and no token (CS-4). After this ticket the Hello is read with a limit of its own (the largest Hello that a Node sends, with room), a frame is read as its bytes arrive and not allocated up front, the frames of an admitted Node have a limit for each kind of message (the Acks, Signals, Telemetry and Leases that `control.options` sizes), and the Controller caps the connections that have not sent a Hello.

## Seam

the controller conformance seam with the node simulator (seam of #176)

## Phase

Hardening phase (after the core data path)

## Acceptance criteria

- [ ] A connection that sends the length of a 16 MiB frame and then stalls holds no more than the bytes that it sent plus a small buffer, shown by a test that counts allocations.
- [ ] A Hello over its limit gets a Refuse or a close, and a frame of an admitted Node over the limit of its kind closes the stream; the limits are constants that sit beside `control.options`.
- [ ] At most a stated number of connections wait for a Hello, in all and for one source; the next are closed and counted.
- [ ] `FuzzRead` and `FuzzOpen` pass with the new limits, and the node simulator and the C Node still work.

## Blocked by

None

---
Ticket key: to be assigned. Draft of AUD-1 (#362), gap G-14.
```

### DT-3. Limits for a source and a cap on unauthenticated connections

```markdown
## Parent

#45

## What to build

The front door, the msquic listener and the TLS port of the Controller accept without a limit (NS-10, TR-5, FD-1, FD-6, AP-11). After this ticket each has: a cap on the connections that have not finished their handshake, in all and for one source address (a /32 or a /64); a rate limit on new connections and on handshake attempts for a source; QUIC retry under load; and counters in the status. The limits are settings with defaults that an honest site does not hit: many Nodes behind one NAT address are not starved by the default for one source.

## Seam

the vpntest harness (seam 2 of #45) and the controller conformance seam with the node simulator (seam of #176)

## Phase

Hardening phase (after the core data path)

## Acceptance criteria

- [ ] A flood of new TCP connections from one source is cut at its cap, and a connection from another source is served meanwhile (harness).
- [ ] Under a flood of QUIC Initial packets, retry is on and the memory and the CPU of the listener stay bounded; the setting is read back from msquic in the test.
- [ ] The Controller's TLS port has the same caps, and the control stream of an admitted Node is not refused by a flood from another source.
- [ ] 1000 Nodes behind one address connect with the defaults.
- [ ] The counters of the refusals are in the status of the Node and of the Controller.

## Blocked by

None

---
Ticket key: to be assigned. Draft of AUD-1 (#362), gap G-7.
```

### DT-4. The Listener of a Node sets the decoy

```markdown
## Parent

#45

## What to build

The TLS transport has a decoy (`TransportDecoyAuthenticate`, `TransportDecoyProxy`; test `trojan`), and `NodeListenerUp` configures none, so a prober sees the certificate of the Node and then a closed connection (TR-2). After this ticket the Listener resource of the Intent has a decoy target, a loopback address and port, which the Controller sends and the Node passes to the TLS transport. Left out, there is no decoy, as today, and `ranz explain` says so. The static site that it points at is #353.

## Seam

the vpntest harness (seam 2 of #45) and the controller conformance seam (seam of #176)

## Phase

Hardening phase (after the core data path)

## Acceptance criteria

- [ ] A prober that sends a first frame that does not open under the static key of the Node gets the answer of the decoy, shown by a test client, and a real peer still connects.
- [ ] With no decoy set the Listener behaves as before and `ranz explain` says that there is none.
- [ ] The Controller refuses a decoy target that is not a loopback address.
- [ ] The decoy field is in the schema and the node simulator conformance shows it.

## Blocked by

None

---
Ticket key: to be assigned. Draft of AUD-1 (#362), gap G-9.
```

### DT-5. A throttle on the Login of a Node

```markdown
## Parent

#45

## What to build

A Login costs one PBKDF2 derivation of 600000 iterations, for an unknown user too, and nothing limits the attempts for a user or a source (NS-15). It has no caller in production yet. After this ticket the Login has a throttle that is in place before it is wired: after a number of failures for a user or from a source in a window, further attempts are delayed or refused without a derivation, an unknown user counts as a known one, and each refusal is recorded (the audit of #226). Which store the Login checks is decided in question 1 of the threat model.

## Seam

the vpntest harness (seam 2 of #45)

## Phase

Hardening phase (after the core data path)

## Acceptance criteria

- [ ] After N wrong passwords for one user in a window, the next attempt for that user is refused in less time than one derivation takes, from any source.
- [ ] After N wrong passwords from one source across many users, the source is refused for a window, and an honest source is not.
- [ ] An unknown user is throttled as a known one, and the time of its answer does not tell the two apart.
- [ ] Every refusal is counted and logged without the password.
- [ ] The tests `nodelogin` and `pinfail` pass.

## Blocked by

None

---
Ticket key: to be assigned. Draft of AUD-1 (#362), gap G-5.
```

### DT-6. The first install narrows who may reach the API

```markdown
## Parent

#45

## What to build

`ranz install --controller` opens TCP 443 and 5555 on every firewall profile, and the admin source allowlist is empty, so the token is the only barrier (AP-3, question 3 of the threat model). After this ticket the install sets the admin source allowlist: loopback and the subnets of the private interfaces of the host by default, or the sources that `--admin-from` names, or everything only with `--admin-from any`. The first start says in its log and in `ranz status` which sources are allowed and how to change them, and that the starter rule allows all traffic inside VRF `default` and how to narrow it. The mesh of ADR-0034 is not changed: the control stream is not behind the allowlist, and the starter rule stays.

## Seam

the controller conformance seam (seam of #176) and the first-test script

## Phase

Hardening phase (after the core data path)

## Acceptance criteria

- [ ] After an install with no flag, a call from a source outside the default set gets 403 and is recorded, and a call from loopback and from a private subnet of the host is served.
- [ ] `--admin-from` takes prefixes, and `any` restores the open default; both show in `ranz status`.
- [ ] A Node enrols from an address outside the allowlist.
- [ ] The first start and `ranz status` say that the starter rule allows all inside VRF `default`, and `docs/first-test.md` shows how to narrow it.
- [ ] The first-test script and the multi-node job pass with their runners' addresses allowed.

## Blocked by

None

---
Ticket key: to be assigned. Draft of AUD-1 (#362), gap G-29. The maintainer decides question 3 first.
```

### DT-7. The front door checks who serves a handoff pipe

```markdown
## Parent

#45

## What to build

`FrontDoorSend` connects to the pipe of an owner by name, takes the process id of whoever serves it and duplicates the socket into that process (FD-4). It passes no impersonation level, and it checks neither the account nor the image of the server. After this ticket it connects with `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION`, and checks that the serving process runs as the account that the owner table names (a SID) and, where the owner names one, that its image is the executable that it expects, before `WSADuplicateSocketW`. It refuses otherwise and counts.

## Seam

the coretest harness (`frontdoor`)

## Phase

Hardening phase (after the core data path)

## Acceptance criteria

- [ ] A pipe of the owner's name that another account serves gets no socket, and the connection is closed and counted.
- [ ] A pipe served by the right account gets the socket.
- [ ] The owner table has the SID, and the Controller's end of #352 sets it.
- [ ] The connect passes no impersonation level above identification, which the test reads from the pipe.

## Blocked by

None

---
Ticket key: to be assigned. Draft of AUD-1 (#362), gap G-13.
```

### DT-8. The store asks for a credential and encrypts between members

```markdown
## Parent

#45

## What to build

The Controller starts `rqlited` with no credential and no encryption (ST-1, ST-2). After this ticket the first start makes a random credential, keeps it in a file of the data directory with its protected access list, and starts `rqlited` with `-auth`. The store client sends it, and so do `reset-admin`, `backup` and `restore`. In a cluster the Raft and the node API use mutual TLS (`-node-encrypt`, `-node-cert`, `-node-key`, `-node-ca-cert`); how the members get their certificates is decided here and written as an amendment of ADR-0026. `-rqlite-external` accepts an `https` URL with its CA, and a plain `http` URL only on loopback.

## Seam

the controller conformance seam with a real `rqlited` (the cluster tests of ADR-0026)

## Phase

Hardening phase (after the core data path)

## Acceptance criteria

- [ ] A request to the HTTP port with no credential, or a wrong one, gets 401, and a local process that does not hold the file cannot read the `api_tokens` table.
- [ ] The three-member cluster tests run with encrypted and authenticated Raft, and a fourth process that joins without a certificate is refused.
- [ ] `reset-admin`, `backup` and `restore` work against a running and a stopped service.
- [ ] `-rqlite-external` refuses a plain URL that is not loopback.
- [ ] ADR-0026 is amended with the credential and the certificates.

## Blocked by

None

---
Ticket key: to be assigned. Draft of AUD-1 (#362), gaps G-18 and G-19.
```

### DT-9. An operator cannot point the Controller or a Node anywhere

```markdown
## Parent

#45

## What to build

An operator token can point the Controller at any host (the targets), copy the traffic of a VRF to any address (a Mirror), have a Node reach any UNC path (a Listener), and shorten the audit log (AP-6, AP-7). After this ticket the admin owns the list of hosts and prefixes that these may name, and the operator works inside it: the targets refuse loopback, link-local and the Controller's own store unless the admin lists the host, and the name is resolved and the address checked at the connect; the sensor of a Mirror must be inside an admin-listed prefix; a UNC path in a Listener is refused unless the admin allows the server; the audit retention and the audit targets need admin, as the tokens do. Question 2 of the threat model decides what else moves to admin.

## Seam

the controller conformance seam with the node simulator (seam of #176)

## Phase

Hardening phase (after the core data path)

## Acceptance criteria

- [ ] A target on `127.0.0.1:4001`, on a link-local address and on a name that resolves to either is refused when it is made and when it is used; one in a listed prefix is accepted.
- [ ] A Mirror whose sensor is outside the listed prefixes is refused by apply.
- [ ] A Listener with a UNC path to a server that is not allowed is refused by apply.
- [ ] `PUT /api/v1/audit/retention` and the calls on audit targets need admin, and `TestRegisteredRolesMatchNeeds` says so.
- [ ] ADR-0031 is amended with the new admin lists.

## Blocked by

None

---
Ticket key: to be assigned. Draft of AUD-1 (#362), gap G-16.
```

### DT-10. The files of the Controller's host

```markdown
## Parent

#45

## What to build

Three things about what the Controller leaves on its host (ST-3, ST-4). First, a data directory that a local user made before the install stays that user's: `protectDir` replaces the access list but not the owner, and the list holds the owner. After this ticket the install takes the directory over, with the Administrators as its owner, as `NodeMakeDataDir` does, and the service refuses to start in a data directory that SYSTEM, the Administrators or its own account do not own. Second, a backup takes the access list of the folder it is written to: it is written with a protected access list of its own. Third, the secrets of the audit and export targets are in the store in clear: they are kept encrypted with a key of the Controller in the key storage provider, and the message of `backup` names everything that a backup holds.

## Seam

the Windows tests of the Controller and the first-test script

## Phase

Hardening phase (after the core data path)

## Acceptance criteria

- [ ] A data directory that a standard user made before the install is taken over (owner Administrators, protected list) or the install refuses with a message, shown by a Windows test; the service does not start in a directory owned by a standard user.
- [ ] A backup written to a folder that the Users group can read cannot be read by Users.
- [ ] The table of the targets, read through the store, shows no secret in clear, and a restore on the same host keeps them working; the documentation says what a restore on another host does.
- [ ] The text that `backup` prints names the hashes, the licence key, the secrets of the targets and the Intent.

## Blocked by

None

---
Ticket key: to be assigned. Draft of AUD-1 (#362), gaps G-20 and G-22.
```

### DT-11. A session that two holders of one key replace again and again is shown

```markdown
## Parent

#45

## What to build

A new handshake of a key closes the session that a peer holds for it, so a thief and the real Node can keep each other off by taking turns (NS-12). After this ticket a Node counts the replacements of the session of each peer in a window, and above a number raises an Event (`session-flap`) with the name of the peer and the source addresses of the sessions that replaced each other. The Event goes to the Controller with the Telemetry and shows in the web UI and `ranz events`.

## Seam

the vpntest harness (seam 2 of #45) and the controller conformance seam (seam of #176)

## Phase

Hardening phase (after the core data path)

## Acceptance criteria

- [ ] Two dialers that use one key, against one Node, make the Event appear within the window, with both addresses.
- [ ] A Node that roams once raises none.
- [ ] The Event reaches the Controller and is listed in `ranz events`.
- [ ] The documentation says what to do: delete the Node resource and make a new key.

## Blocked by

None

---
Ticket key: to be assigned. Draft of AUD-1 (#362), gap G-30.
```

### DT-12. The fuzz targets that are still to come

```markdown
## Parent

#45

## What to build

Three readers of foreign bytes have no fuzz target of their own: `NodeOverlayInput` and `CsImportForkConfig` are exempt in the registry with "a fuzz target of its own is still to come", and the nanopb decode of a message of the Controller and `ControlApply` (`Control.c`) are not in it at all (CS-13, DP-7). After this ticket each has a libFuzzer target in the registry, with seeds from the existing tests, and the two exemptions are gone.

## Seam

the fuzz job of `quality.yml` (ADR-0040)

## Phase

Hardening phase (after the core data path)

## Acceptance criteria

- [ ] The registry check passes with the two exempt lines turned into targets and the decode and the apply of a Controller message listed.
- [ ] The full fuzz set runs the three targets under AddressSanitizer for the time of the CI budget, with no finding, or with the findings fixed in the same pull request.
- [ ] The seeds of the control target include the messages that `tests/control/nanopb_roundtrip.c` decodes.

## Blocked by

None

---
Ticket key: to be assigned. Draft of AUD-1 (#362), gap G-15.
```

### DT-13. A token has a life, and the CLI checks the certificate toward loopback

```markdown
## Parent

#45

## What to build

A token never expires, shows no last use, and a read is not audited (AP-2, AP-8). The CLI checks no certificate toward `127.0.0.1`, its default. After this ticket a token can be made with an expiry and is refused after it; the last use of each token is kept (at most one write a minute) and shown by `ranz tokens`; a read of the tokens, the audit log and the licence is recorded as an access; and the CLI pins the TLS fingerprint toward loopback as well, reading it from the data directory when it can read it and asking for `-fingerprint` when it cannot.

## Seam

the controller conformance seam (seam of #176)

## Phase

Hardening phase (after the core data path)

## Acceptance criteria

- [ ] A token with an expiry is refused with 401 after it, is shown as expired, and an admin can still delete it.
- [ ] `ranz tokens` shows the last use of each token.
- [ ] A listener on `127.0.0.1:443` that presents another key makes `ranz` refuse and send no token; the right key works.
- [ ] A read of the tokens, the audit log or the licence leaves an access record under the name of the token.

## Blocked by

None

---
Ticket key: to be assigned. Draft of AUD-1 (#362), gap G-17.
```

## Appendix C. Amendments proposed for open tickets

These tickets are open and the threat model reads each of them as written. Each line is a sentence that the ticket lacks, and the gap that it closes. The maintainer or the integrator makes the edit; this lane does not touch tickets.

| ticket | amendment | gap, rows |
|---|---|---|
| #352 (SDN-73) | Say that the Controller sees the real address of the client through the handoff, and test that the admin source allowlist refuses a remote address through it. Decide the account of the Controller's process and the right that the handoff gives to the Node's account (`PROCESS_DUP_HANDLE`), so that a flaw of the Node on the same host is not a short way to the Controller. Use the owner check of DT-7. | G-13; FD-4, FD-7, FD-8 |
| #356 (SDN-76) | Accept a datagram only from a source that the Controller named for that very VNI, not from any named source on any VNI that the Node carries. When the endpoint of a plain link is a public address, raise an Event and ask for an acknowledgement in the Intent. | G-25, G-27; SM-4, SM-8 |
| #357 (SDN-77) | The Controller writes for each peer the accept list (the prefixes that Node may announce, from its Networks and the addresses of its VRFs) and a maximum number of prefixes; no default route is accepted unless the Intent says so. Add a setting for session protection (TCP MD5 and TTL security, which GoBGP offers), or say in the ticket that the underlay provides it. | G-26; SM-5, SM-6 |
| #358 (SDN-78) | Apply the limits of SDN-65 (#292: MAC mobility, limits and events) and SDN-66 (#293) to the EVPN peers that are Ranz Nodes, and give each peer a list of the MACs, VNIs and prefixes it may announce. | G-26; SM-6 |
| #359 (SDN-79) | Note that a reflector is a point of trust: its key is the first to bind (ADR-0041), and two reflectors are named. | G-6; SM-7 |
| #387 (SDN-88) | Add an option for a Network in `hmac` mode to drop a packet with no valid MAC, instead of judging it by the map of address to group. Keep the key of a VRF out of every resource that a viewer reads, and in a table of its own that DT-10 protects in backups. Say in the documentation that in the standard mode an address is the identity of a peer unless that option is on. | G-24; SM-2, SM-3 |
| #226 (SDN-32) | The criterion "a wrong password is refused and audited" gets a second line: repeated failures for one user or from one source are delayed, and the delay is audited. DT-5 does the Node's part. | G-5; NS-15 |
| #376 (SDN-81) | A revoke reaches the gateway within a stated time, the web UI shows a gateway that has not acknowledged it, and the revoke is audited. | G-28; OE-2 |
| #377 (SDN-82) | Applied by SDN-82: the private key of a Device is made by the Controller in the memory of the call that makes the Device, and never kept; the PresharedKey is kept like the secret of a target (DT-10), and is in no log, audit record, bundle or resource that a viewer reads; the configuration file and the QR code are shown once. A Controller that is a member of a cluster seals it with the Cluster key of the cluster (AUD1-DT-16, #501; ST-4). | G-28; OE-2 |
| #382 (CORE-P2-5) | Show on the QUIC path, from the connection information, that the group negotiated is the hybrid one where the OS has ML-KEM. | G-4; NS-4 |
| #424 (CORE-P2-7) | The decision of 2026-10-26 keeps the REALITY key in the Configuration store. Say how: as text, or protected with a key of the host that only the service account can use. | G-12; TR-10 |
| #234 (SDN-41) | Say which protections apply to an L2 VNI of the standard mode, and that the switch and the guard are wired into the Node before an L2 Network is carried between peers. | G-21; DP-8, SM-4 |
| the release work that links the activation package | Refuse a revocation list older than the one in force (`Issued`), keep the last list in the store, and require `https` for the base URL. The fail-open of an absent or corrupt list stays, by the decision of ADR-0036. SEC-7 (#284) is closed, so this is a new ticket when the work is scheduled. | G-23; ST-8 |
| the move of the peer layer onto the QUIC datagrams | Put the 65-byte clear header inside the encryption of the outer session, and limit the sources of a relay (question 9). | OE-5, OE-4 |
| the ADR numbers | Two ADRs carry the number 0036 (`0036-licensing.md` and `0036-anti-debug-and-anti-re-release-variant.md`). Renumber the second. | documentation |
| #400 (CORE-H3), #443, #425 (AUD-7) | None: they cover G-2, G-3 and G-8; G-10; and G-11 as they are written. | G-2, G-3, G-8, G-10, G-11 |
