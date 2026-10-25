# The formal model of the session handshake

AUD-5 (#389). The design of the handshake of Ranz VPN is proved, not only tested: ProVerif checks models of the session handshake of a client over TLS 1.3 and over QUIC, of the join of a further connection to a tunnel, of the control stream, of Noise_IK alone and of the peer layer, and a CI job fails when a query that must hold does not hold, or an attack that must show does not. The models follow the code as it is today, and where the code differs from ADR-0022 and ADR-0023 this page says how (D1 to D7). Every query of every model gets an answer from the prover: none is left to Tamarin.

Files:

| file | what it is |
|---|---|
| `tests/formal/*.pvl` | the declarations of the models: `prims.pvl` (Diffie-Hellman, hash, HKDF, AEAD, the static keys), `session-lib.pvl` (the outer session, the handshake, the Login, the compromises), `tunnel-lib.pvl` (the join of a further connection to a tunnel), `noise-lib.pvl` (Noise_IK alone), `peer-lib.pvl` (the peer layer), and the queries: `q-*.pvl` in groups for the session models, `tunnel-queries.pvl`, `noise-queries.pvl`, `peer-queries.pvl` |
| `tests/formal/session/*.pv`, `tunnel/`, `noise/`, `peer/` | the variants: the last file of a model, the process that composes it |
| `tests/formal/variants.tsv` | the files that make each variant, in the order in which `formal.py` joins them, and into how many ProVerif runs (slices) its queries are cut |
| `tests/formal/expected.tsv` | what each query must give in each variant: `holds`, `attack`, `fails` or `reach` |
| `tests/formal/model-to-code.tsv` | the table from the model to the code: every name, message and field of the models, with the file, the function and the field of the code; `check` finds each function defined in its file and each field in the body of one of the functions of its row |
| `src/vpntest/formaltable.c` | the vpntest test `formaltable`: it refers to every C function of the table that is not static, so a function that the code loses or renames breaks the build of vpntest, and it pins the facts of the code that the models take (the suite name, the layout of the prologue, the exporter labels, TLS 1.2 by default) |
| `.github/scripts/formal.py` | `check` (the table and the expectations, no prover), `list` (the jobs of the workflow), `smoke` (every variant for a few seconds, to catch a mistake of syntax at once), `run` (ProVerif on a variant, or on a slice of its queries), `selftest` |
| `.github/workflows/formal.yml` | the Linux jobs of the full set: one builds ProVerif 2.05, pinned by the SHA-256 of its archive, and one job for each variant, or for each slice of its queries, runs it |

The check of the table runs in `quality.yml` on every pull request. The prover runs in the full set (a push to `integration` or `master`, the nightly run, a pull request that changes the models, the workflow or the script, and a pull request with the label `full-ci` that changes a file that the table names), as one job for each variant; the input and the log of ProVerif of a job, with the traces of its attacks, are its artifact `formal-<variant>` or `formal-<variant>-<n>of<k>`. The whole set answers in about two minutes.

## The model

The attacker is the network (the Dolev-Yao attacker of ProVerif): it reads, drops, rewrites and sends every message, runs as many sessions as it likes, and may hold a key that its scenario gives it.

**The outer session.** A TLS 1.3 handshake of one round trip with the authentication of the server only: the client sends a random value and a key share, the server its random value, its key share, its certificate and a signature of the transcript. The keys of the records and the exporter come from the Diffie-Hellman secret and the transcript, so two sessions that differ in any value of the transcript have different keys and different exporters, as the key schedule of RFC 8446 gives. The client does not check the chain: it compares the certificate with its pin (`TlsCheckPin`, `QuicConnCallback`), which a variant can leave out. A middlebox is the attacker with a certificate of its own that terminates the session of the client and opens one to the server.

**The Noise handshake.** On the first stream the client runs Noise_IK with the static key of the node identity and the pinned static key of the server, with the prologue that holds the binding: the label, the binding type, and the binding of the outer session. The binding is the TLS exporter (`NOISE_BINDING_EXPORTER`, the TLS-443 path and the control stream) or the tls-server-end-point of RFC 5929 (`NOISE_BINDING_SERVER_END_POINT`, the QUIC path). The handshake payloads are empty and the records after it go in clear inside the outer session, which encrypts them once (ADR-0023, single encryption). The first control record is the Login (a password, checked by Sam, and the Noise static key pinned to the user on the first login) or, on the control stream, the Hello with the schema version and the Capabilities; the server answers with a record of the data stream or the Update. A server runs the suites that it supports as one process each (`Server`, one `suite`), and takes the records of its own suite only.

**The two keys of a node.** A server node has its Noise identity key and the key of its TLS certificate, and a compromise of one does not give the other (ADR-0023, key separation).

**The scenarios.** A model is the session with the compromises of one scenario and no others, and none of its queries is conditional on a leak: it holds in the scenario or it does not. The scenarios are `none` (the attacker is the network), `cert` (it holds the key of the certificate of the server: the middlebox that can present the pinned certificate), `cert-client` (that and the Noise key of the client), `noise-client` (the Noise keys of the server and of the client), `both` (both keys of the server), `noise` (the Noise key of the server) and `fs` (every key, after the sessions, in phase 1 of ProVerif, which is what forward secrecy asks). A leak is an event, so the trace of an attack shows it.

**The tunnel join** (`tunnel-*`). A tunnel of several connections (ADR-0022, amendment of 2026-10-15): the first connection of a peer node logs in and makes the Tunnel of an id, which is the HMAC-SHA256 of a label under its handshake hash (`NoiseTunnelId`); each further connection runs a handshake of its own in an outer session of its own and sends a join Login that names the id (`NOISE_LOGIN_JOIN`), and the server adds it to the Tunnel when the id is the Tunnel's and the static key of the connection is the one of the Tunnel (`TunnelJoin`, `NoiseTunnelJoin`). The model has the first connection as the Tunnel that it makes, a new id for the static key of its peer, which the attacker is given, since the id is no secret inside the outer session and nothing rests on it; and it has the join in full: the outer session with the pin, the binding, the handshake and the join Login. `charlie`, whose keys the attacker holds, has a Tunnel of his own and dials with the ids of the others. No production client dials a second connection yet: the client of a join is in vpntest (`noisehub.c`, `nodelogin.c`).

**Noise_IK alone** (`noise-encrypted`). A session that nothing binds encrypts its records under the Noise keys (`NOISE_SESSION_ENCRYPT`: the CDN path of phase 2 and the loopback transport of vpntest). That is where the session keys of Noise, their secrecy and their forward secrecy, are graded: the authentication and confidentiality grades of the Noise Explorer for the four messages of IK. The handshake payloads are empty in the code (the Login follows in the first control record, "under the forward secrecy of the complete handshake"), and the grades show why: message a has no forward secrecy, message c has all of it.

**The peer layer** (`peer-leaks`, `peer-honest`). The envelopes of binds, bounds, signals and punch probes, sealed with the one-way pattern K, and the data datagrams, as the code has them.

### How the models are written for the prover

The models are written so that ProVerif answers in seconds. Three choices do it, and a model that leaves them breaks the prover: the first runs of the models, with the habits of the Noise Explorer, ran for twenty minutes and at 15 GB without an answer.

- **Diffie-Hellman has no equation.** The Noise Explorer gives it the equation dh(a, pk(b)) = dh(b, pk(a)), and ProVerif then tries both orders of every Diffie-Hellman term of every clause. Every Diffie-Hellman of these handshakes is between a key of the side that dials and a key of the side that listens (es, ss, ee and se of IK, es and ss of K, the key shares of the outer session), so the model gives the initiator's computation as the term `dhi(a, B)` and rewrites the responder's `dhr(b, pk(a))` to the same term. The two sides agree, and an attacker still computes the secret when it has a scalar and the public key of the other side. What the encoding leaves out is a public key that is no `pk` of any scalar (a point of low order), which the code refuses (`NoiseMixDh`) and the responder's computation fails on.
- **A process creates its names before its first input.** ProVerif gives a name that is created after an input the received values as arguments: the ephemeral key of the responder was `e[cs, cp, E, sid]`, and every term that held it held both ciphertexts of the first message, a few hundred nodes each, over and over in the key schedule.
- **The pin, the binding and the suite are the choice of a rewrite rule or of the process that runs**, not boolean terms, and a model is one scenario with the queries that the scenario is about: the models that leaked three keys at once and asked "unless this key" never finished.

Where the attacker holds the Noise key of the server, the queries of the client (`auth-client`, `data-auth`) and of replay are left out of the model: the attacker is the server there, and ProVerif would have to prove a long list of attacks false one by one for no gain.

### The variants

| variant | what it is |
|---|---|
| `tls443-none`, `tls443-cert`, `tls443-cert-client`, `tls443-noise-client`, `tls443-both`, `tls443-fs` | the session over TLS 1.3 on TCP 443, as the code has it (pinned certificate, handshake bound to the exporter), in the scenarios none, cert, cert-client, noise-client, both and fs |
| `quic-none`, `quic-cert`, `quic-noise-client`, `quic-fs` | the session over QUIC, as the code has it (pinned certificate, handshake bound to the tls-server-end-point) |
| `nobinding-cert` | negative control: no binding in the prologue, the key of the certificate leaked |
| `nopin-noise` | negative control: the client pins no certificate, the Noise key of the server leaked |
| `neither-none` | negative control: no pin and no binding, no key leaked: the middlebox |
| `control-node-none`, `control-node-cert`, `control-node-noise-client`, `control-node-fs` | the control stream of a C node: pinned certificate, exporter of the control label |
| `control-go-none`, `control-go-noise` | the control stream of a Go client, which checks no certificate |
| `tunnel-none`, `tunnel-cert`, `tunnel-quic-cert` | the join of a further connection to a tunnel over TLS 1.3 and over QUIC, as the code has it |
| `tunnel-nokey-none` | negative control: the server joins by the id alone, with no comparison of the static key |
| `noise-encrypted` | Noise_IK alone with the records under the Noise keys |
| `peer-leaks`, `peer-honest` | the peer layer, with the keys leaked and with none |

### The queries of the session models

| id | says |
|---|---|
| `reach-login`, `reach-done` | the Login and the handshake can complete, so no query that holds is true for want of a run |
| `sec-pw`, `sec-data` | the password that the client sends, and what the server sends back, are secret |
| `fs-pw`, `fs-data` | the same after every long-term key leaked: forward secrecy |
| `auth-server` | the server takes the handshake of the client only if the client started it, in the TLS session that the server is in (the transcript of the TLS session is its identity): the binding of a handshake to its session |
| `auth-client` | the client takes the answer only if the server with the key that it pinned made it, in its TLS session and with the same handshake hash |
| `data-auth` | what the client takes from the server after the handshake (a record of the data stream, or the Update of the controller) is what the server sent in that session |
| `negotiation` | the version and the Capabilities that the server settles on are ones that the client offered: the attacker cannot lower them |
| `suite` | the suite that the server runs is one that the client chose: the suite is in the protocol name that the hash of the handshake holds |
| `replay-server`, `replay-client` | no replay: each handshake that the server takes, and each answer that the client takes, is one that was sent once |

The queries of the tunnel models (`tunnel-queries.pvl`):

| id | says |
|---|---|
| `reach-join` | a connection can join, so no query is true for want of a run |
| `join-auth` | a connection that joins the Tunnel of alice is one that alice made, in the outer session that the server is in: a middlebox that terminates the outer session of the join and opens one to the server is the case that the binding rules out |
| `join-identity` | a node joins only a Tunnel that was made for its own static key, whatever ids it knows: the ids of all Tunnels are the attacker's |
| `join-replay` | no replay: each join that the server takes is of a Login that was sent once |

The queries of `noise-encrypted` are the grades of the Noise Explorer for the messages a, b, c and d (`a-auth1` to `d-conf5`), and the ones of the peer layer are in `peer-queries.pvl`.

### What holds

Every answer below is the one that ProVerif gives in the job of the variant, and `expected.tsv` is checked against it.

**The session over TLS-443, as the code has it.** Against an attacker that is the network (`tls443-none`) every query holds. Against the middlebox that holds the key of the certificate of the server (`tls443-cert`) every query holds too: it presents the pinned certificate and terminates the TLS session of the client, and the handshake that it relays to the server is in the prologue of another exporter, so the handshake does not complete, and it reads and rewrites nothing. The version, the Capabilities and the suite cannot be lowered. With the key of the certificate and the Noise key of the client (`tls443-cert-client`) the password, the data, the answer of the server and the Capabilities are still safe, and the attacker is the client: `auth-server`, `suite` and `replay-server` fail, since the first message of Noise_IK is open to the compromise of the key of its initiator. With the Noise keys of the server and of the client (`tls443-noise-client`) the password and the data are safe, because the pin keeps the holder of the keys from answering the client in a TLS session of its own. With both keys of the server (`tls443-both`) the attacker is the server and every secrecy query fails: each key guards the other. With every key leaked after the sessions (`tls443-fs`) the password and the data are still secret: forward secrecy. The control stream of a C node (`control-node-*`) gives the same.

**The tunnel.** A connection that joins the Tunnel of alice is one that alice made, in the outer session that the server is in, also against the middlebox with the key of the certificate (`tunnel-none`, `tunnel-cert`), and a node joins only a Tunnel that was made for its own static key, whatever ids it knows.

**Noise_IK alone** (`noise-encrypted`) gives the grades of the Noise Explorer for the four messages: message a has the authentication of its sender only against a receiver whose key is not compromised (`a-auth1` and `a-auth3` hold, `a-auth2` and `a-auth4` do not), and no forward secrecy (`a-conf4` and `a-conf5` fail); message b holds every authentication grade and every confidentiality grade up to `b-conf4`; messages c and d, the first records of the two directions, hold every grade, with strong forward secrecy (`c-conf5`, `d-conf5`): that is why the Login is in the first control record and the handshake payloads are empty.

The negative controls each show their attack, and CI fails when one does not:

- **NC1, `nobinding-cert`.** Without the binding, the key of the certificate of the server alone is enough for a middlebox: it terminates the TLS session of the client with the pinned certificate, opens one of its own to the server, and the two Noise handshakes cross it unchanged. Every query but `suite` that holds in `tls443-cert` fails here.
- **NC2, `nopin-noise`.** Without the pin, the Noise key of the server alone is enough: its holder answers the client in a TLS session of its own, and the binding, which is of that session, matches. Every query but the two that say the handshake can complete fails.
- **NC3, `neither-none`.** With neither, and no key leaked, the middlebox reads and rewrites every record: nothing is left for it to need. Every query but `suite` fails.
- **NC4, `tunnel-nokey-none`.** If the server joined a connection to the Tunnel of the id that it names without comparing the static key of the connection with the Tunnel's, `charlie` would join the Tunnel of alice with her id, which the attacker is given. `join-identity` holds in `tunnel-none` and fails here.

## Findings

Each of these is an attack that the prover finds, and a result of `expected.tsv` that CI checks, so a fix of the code changes `expected.tsv` in the same change. The trace of each is in the artifact of its job (`formal-<variant>.attacks.txt`) and in the log of the job.

### F1: on QUIC the key of the certificate alone gives a middlebox the session

`quic-cert`: `sec-pw`, `sec-data`, `auth-server`, `auth-client`, `data-auth`, `negotiation`, `replay-server` and `replay-client` fail, where `tls443-cert` proves them. The tls-server-end-point is the same for every connection to one certificate (D1), so an attacker that holds the key of the certificate of the server, and not its Noise key, terminates the TLS session of the client with the pinned certificate, relays the Noise handshake to the server over a TLS session of its own (the binding is equal on both), and then reads and rewrites every record: the password, the data, the Hello. The attacker uses the Noise key of nobody; it needs the key of the certificate and a position on the path. The pin keeps it out without that key (`quic-noise-client` holds). ADR-0023 binds the handshake to the outer session so that a middlebox that terminates it cannot read the data; on QUIC it can, with the certificate key. The code states the cause: msquic exposes no exporter. The join of a further connection is open to the same middlebox (`tunnel-quic-cert`: `join-auth` and `join-replay` fail, where `tunnel-cert` proves them); the static key still decides which Tunnel a node joins (`join-identity` holds).

### F2: the data datagrams of the peer layer have no confidentiality and no authentication

`peer-leaks` and `peer-honest`: `pd-secret` and `pd-forgery` fail with no key leaked. `PeerSend` writes the tag, the key of the source, the key of the destination and the payload in the clear, and `PeerInputData` delivers a datagram whose source address is a path of its source (a relay, a binding or a direct path) and whose source is a peer: no key is checked, and a UDP source address is not authentication. Anyone on the path reads the payload and sends a datagram in the name of any peer. ADR-0015 items 3 and 7 and ADR-0023 have the data in the session of QUIC or TLS (D4). A node with the relay role runs the peer layer on a UDP socket of its own (`NodeRelayStart`): it takes the binds of its nodes and forwards their data datagrams. The overlay of `NodeOverlay.c` does not use the peer layer, it runs a Noise session over a data transport to each peer, so no node sends peer datagrams to a relay yet, and the exposure today is the UDP port of the relay role and the harness.

### F3: a relay binds the node to the address of the datagram, and the replay check forgets

`peer-leaks` and `peer-honest`: `pe-addr` and `pe-replay` fail. The envelope of a bind holds a version and a sequence, not an address, and `PeerInputBind` binds the node to the address that the datagram came from, so an attacker on the path that drops the bind of a node and sends the same envelope from an address of its own takes the binding, and with it the datagrams that other nodes send to the node through the relay (F2 makes them readable). The sequence that must grow (`PeerInputBind`, `PeerOpenSignal`, `PeerPunchInput`) is kept in memory: `PeerTick` drops the binding, and its sequence with it, after `BindExpiry` without a renewal, and `PeerSetPeers` makes a new entry, with sequence 0, for a peer that left the table and came back, so a bind or a signal that was captured earlier is taken again then. The model has a receiver that keeps no sequence, which is what such a receiver is.

The envelope has no forward secrecy (`pe-fs` fails in `peer-leaks`): its key comes from es and ss, as in every Noise_K, so a leak of the static key of the receiver opens the envelopes that were recorded. What it holds is a relay assignment and ICE candidates, which are no secret after the session.

### C1: the Go client of the control stream relies on the key of the controller alone

`control-go-noise`: `sec-pw`, `sec-data`, `auth-server`, `negotiation` and `suite` fail: the client that sets `InsecureSkipVerify` (`controller/internal/control`, `Dial`) has the pinned static key of the controller and the exporter, and nothing else, so the key of the controller alone is enough for an attacker. This is `nopin-noise` with the control labels. The C node pins the certificate (`control-node-noise-client` holds).

## Differences from ADR-0022 and ADR-0023

The model follows the code, so these are differences of the code from the ADRs, which the table cites by their number.

### D1: the QUIC path binds tls-server-end-point, not the TLS exporter

ADR-0023 (amendment of 2026-10-15) binds the Noise handshake to the TLS exporter, RFC 8446 section 7.5. The TLS-443 path does (`TlsExporter`: label `NOISE_EXPORTER_LABEL`, no context, 32 bytes). msquic exposes no exporter, so the QUIC path binds the tls-server-end-point of RFC 5929, the hash of the pinned server certificate (`QuicCertBinding`, `CryptoCertEndPoint`), which ADR-0022 (amendment of 2026-10-15) names as the fallback. The value is the same for every connection to one certificate, so it binds the handshake to the certificate and not to the connection. F1 is the consequence.

### D2: the pin is a SHA-1 thumbprint that the client setting holds, not derived from the node identity

ADR-0023 pins the server certificate to the node identity. The pin is the 40 hex digits of the SHA-1 thumbprint of the certificate in the Client setting (`servers[].thumbprint`, `NodeClientAddServer`), which `TransportTlsDefaultConfig` and `TransportQuicDefaultConfig` take; the static key of the server comes from the desired state that the controller sends. Nothing ties the one to the other, so a certificate that two nodes share, or the key of a certificate alone, is not tied to a node. The system roots are not trusted (`SCH_CRED_MANUAL_CRED_VALIDATION`, `QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION`), as ADR-0023 asks. The model takes the thumbprint as a hash without collisions; SHA-1 is deprecated, and `CryptoCertThumbprint` uses it because the certificate store finds a certificate by it.

### D3: the control stream: the Go client checks no certificate, and the C client has no production transport

The Go client of the control stream (`Dial` of `controller/internal/control`, used by `ranz-nodesim` and the tests of the controller) sets `InsecureSkipVerify`: C1. `Control.h` asks for a transport whose streams are TLS sessions with the ALPN protocol `ranz-control/1` and the exporter of `CONTROL_EXPORTER_LABEL`, and the only transport that has both is the OpenSSL client of vpntest (`SdnTraceTlsInit`): the Schannel transport offers no ALPN and always exports `NOISE_EXPORTER_LABEL`, so a C node on it would compute another exporter than the controller and the handshake would fail closed. `ControlRun` checks only the type and the size of the binding, not its label. Nothing but vpntest calls `NodeOverlayStart` yet.

### D4: the peer layer has no session

ADR-0015 items 3, 6 and 7 and ADR-0023 have the relay speak the same QUIC or TLS-443 session as the direct path, with the Noise_IK handshake of the first stream bound to it, and the signals signed with the node keys. The peer layer has no handshake and no outer session: its envelopes are one-shot Noise_K messages (kind, sender key, ephemeral key, ciphertext; prologue `ranz peer 1` and the kind), sealed and not signed, and its data datagrams are in the clear (F2). A relay forwards the datagram as it came. Peer.h says the socket stands in for the QUIC datagrams until the transport interface carries them.

### D5: the outer rekey is a call that does nothing

ADR-0023 asks for a periodic rekey through the QUIC key update and the TLS 1.3 KeyUpdate. `NoiseSessionPoll` asks for it every `NOISE_REKEY_INTERVAL`, and `TlsStreamRekey` and `QuicStreamRekey` return true without updating anything. The keys of a session change by what the outer stack does by itself, and the forward secrecy of a long session rests on the ephemeral Diffie-Hellman of its handshake. The model has no rekey.

### D6: TLS 1.2 is allowed by default on TLS-443

ADR-0022 puts the session on Schannel TLS 1.3. `TransportTlsDefaultConfig` sets `Versions` to TLS 1.2 and TLS 1.3, and the exporter of a TLS 1.2 session is the one of RFC 5705. The model is TLS 1.3 only: a session that negotiates 1.2 has the exporter and the downgrade protection of that version, which the model does not hold.

### D7: Noise_IKhfs exists, and no caller selects it

ADR-0022 has the post-quantum hybrid "used where the OS provides it in both TLS and Noise". `NOISE_SUITE_IKHFS` is implemented (`NoiseHandshakeInit` and the tokens e1 and ekem1), and the TLS side puts X25519MLKEM768 first (`TransportTlsSetGroups`), but every caller of the session module (`NodeOverlaySessionConfig`, `ControlRun`, the transports of the tests) sets `NOISE_SUITE_IK`. The responder runs the suite of the first record if it can run it (`NoiseSuiteAvailable`), with no policy of its own, and the suite is in the protocol name that `InitializeSymmetric` hashes into `h`, so an attacker that changes the byte makes the handshake fail (`suite` holds). The model has IKhfs up to its protocol name, not its KEM tokens; the client of the session models offers it (the client of the control models offers IK, as `ControlRun` does), so that a change of the byte to IK is the downgrade that `suite` asks about.

## What the model leaves out

- The TLS and QUIC stacks themselves: the model has an abstract TLS 1.3 handshake with the authentication of the server and an exporter, not Schannel or msquic, their record layers, their resumption (the code uses none) or their downgrade protection.
- The bytes: lengths, framing and parsing (the fuzz targets and the tests of the module cover them), and the AEAD nonce counters of a long session.
- Time: the timers, the dead-peer timeout, the expiry of a binding, which the model has only as the receiver that has lost its sequence.
- Of the multi-connection tunnel, the first connection (its Login and the id that its handshake gives are the session model, and the id is the attacker's here), the routing of the flows over the connections (`NoiseTunnelRoute`), the loss of a connection and its return, the index that a connection takes and the number of connections that a tunnel holds. Several connections of a tunnel are dialled only in vpntest today.
- The first login of a user, when the Noise static key is pinned to the user on trust (`NodeLoginPinned`): the models start with the key pinned, and the server serves the one client whose key it has.
- Denial of service, traffic analysis, the decoy of the Trojan posture and the mimicry sidecar.
- Cross-protocol use of the node static key in the session, the control stream and the envelopes: the three prologues differ in their labels and the envelopes in their pattern, but the models do not run them together. A node that is both a client and a server with one static key is not modelled either: the Diffie-Hellman of the models is between an initiator and a responder.
- Several compromises at once beyond the scenarios: the models answer for one compromise, or two where the second is the key of the client, and for both keys of the server.

## Running it

ProVerif 2.05 builds from its source archive (`./build -nointeract` with OCaml). The models are text:

```
python .github/scripts/formal.py check
python .github/scripts/formal.py run --proverif /path/to/proverif --out build/formal tls443-none tls443-cert
```

`run` writes each variant as one `.pv` file and its log to the directory of `--out`; the file runs on its own with `proverif -in pitype build/formal/tls443-none.pv`. The result of a query is `is true`, `is false` (an attack, with its trace) or `cannot be proved`. ProVerif keeps its state for every query of one run, so `variants.tsv` can cut a variant into slices, each a run of ProVerif with consecutive queries of its own and a job of the workflow (`python .github/scripts/formal.py run --slice 2/4 noise-encrypted` runs the second of four).

To add a model, write its process in a file of `session/`, `tunnel/` or `noise/`, give it a line in `variants.tsv` and a line for each of its queries in `expected.tsv`, and a row for each name that it declares in the table. A variant whose name starts with `try-` is an experiment: it needs no line in `expected.tsv`, the jobs of the workflow leave it out, and `formal.py run try-name` reports what ProVerif answers for each query without judging it, with the last lines of ProVerif when it runs out of time. Run `formal.py smoke` and an experiment first when a model is new: a process that creates a name after an input, or an equation, is what makes ProVerif run for hours.
