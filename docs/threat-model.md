# Threat model of the new core and the Controller

AUD-1 (#362). This page is the threat model of the new core (the Node, ADR-0022) and of the Controller (ADR-0026). For each plane it says what is protected, where an attacker can reach it, what four attackers can do (an attacker on the path, a malicious peer, a malicious tenant and a thief of a node key), and which control answers each threat. A threat that no control answers is a gap, and each gap is an open ticket or a draft ticket (Appendix B). The standard mode (SDN-76 to SDN-79) has a section of its own, with what the operator must provide, and section 14 says what is out of scope and why.

It is written for the maintainer, for the reviewers of AUD-2 (#364), who check each module against it, and for the auditor of AUD-4 (#365), whose package starts with it. `docs/formal-model.md` proves the handshakes with ProVerif. This page does not repeat its answers: it cites them, and says what the rest of the design rests on. It describes the tree of `integration` at commit `c8bf82f` (2026-10-26). Where the code differs from an ADR it says so, and the differences that the formal model numbers D1 to D8 keep their numbers.

## 1. How to read this page

The ticket names six planes: the Noise session (with its Channel binding, Login and rekey), the transports, the front door and its handoff, the control stream, the API with the web UI and the tokens, and the store with the licence. Sections 5 to 10 take them in that order. Section 11 adds the data plane behind the sessions, because the malicious peer and the malicious tenant are stopped there and not in the sessions. Section 12 is the standard mode, section 13 the entry points that came after the ticket was written (WireGuard Devices, the relay, the sidecars, the pipes of the host).

Each plane has the same parts: what it is, as built; its assets; its entry points; what each attacker can do; and a table of threats. One row of a table is one threat: who makes it, what it does, the control that answers it with its evidence, the status of that control, and the gap that is left. A gap is `G-n` of Appendix A, which names the open ticket that covers it, or the draft ticket `DT-n` of Appendix B.

**Evidence.** Every control names its evidence, of one of five kinds. **code**: a file or a function that was read for this page. **test**: a vpntest or coretest case, a Go test or a CI job, by name. **model**: a query of `docs/formal-model.md`. **ADR**: a decision. **reasoned**: our own argument, which nothing tested, as in ADR-0041. The reasoned rows are the first for AUD-2 to check.

**Status.** **runs**: a production path calls the control. **tests only**: built and tested, with no production caller yet (the table "What runs in production, and what does not yet" of `docs/formal-model.md` says it for the handshakes). **designed**: an ADR or an open ticket, nothing built. **accepted**: a decision accepts the risk, and the row names it.

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
| B7 | the Controller to its store, and member to member | SQL over HTTP on loopback; Raft | nobody (G-1, G-2) | the loopback address and the ACL of the data directory only | 10 |
| B8 | the Controller or a Node to third parties | HTTPS, UDP | TLS toward the activation service, ACME and the receivers; nothing toward STUN or the home gateway | signatures on tokens and on the revocation list; redirects off | 9, 10, 13 |
| B9 | a Node to an underlay of the standard mode | VXLAN and Geneve datagrams; BGP | nobody on the wire; the source address against the list of named peers | the operator's underlay (section 12) | 12 |
| B10 | a Node to its sidecars | JSON lines, data streams | the sidecar is the process that the Node started | the pipe DACL of the owner alone; the Node takes only that process as the client | 6, 13 |
| B11 | local accounts to a host of the product | named pipes, loopback ports, files | the account, by the DACL of the pipe or of the file | the DACLs; the service accounts (ADR-0039) | 7, 10, 13 |
| B12 | a WireGuard Device to a gateway Node | WireGuard datagrams | the Device by its WireGuard key | WireGuardNT; the policy by overlay address | 13 |

<!-- END-OF-PART -->
