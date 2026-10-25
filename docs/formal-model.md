# The formal model of the session handshake

AUD-5 (#389). The design of the handshake of Ranz VPN is proved, not only tested: ProVerif checks models of the session handshake of a client over TLS 1.3 and over QUIC, of the join of a further connection to a tunnel, of the control stream, of Noise_IK alone and of the peer layer, and a CI job fails when a query that must hold does not hold. The models follow the code as it is today, and where the code differs from ADR-0022 and ADR-0023 this page says how (D1 to D7).

Files:

| file | what it is |
|---|---|
| `tests/formal/*.pvl` | the declarations of the models: `prims.pvl` (Diffie-Hellman, hash, HKDF, AEAD, the static keys), `session-lib.pvl` and `session-queries.pvl` (the outer session, the handshake, the Login), `tunnel-lib.pvl` and `tunnel-queries.pvl` (the join of a further connection to a tunnel), `noise-lib.pvl` and `noise-queries.pvl` (Noise_IK alone), `peer-lib.pvl` and `peer-queries.pvl` (the peer layer) |
| `tests/formal/session/*.pv`, `tunnel/`, `noise/`, `peer/` | the variants: the last file of a model, the process that composes it |
| `tests/formal/variants.tsv` | the files that make each variant, in the order in which `formal.py` joins them, and into how many ProVerif runs (slices) its queries are cut |
| `tests/formal/expected.tsv` | what each query must give in each variant: `holds`, `attack`, `fails` or `reach` |
| `tests/formal/model-to-code.tsv` | the table from the model to the code: every name, message and field of the models, with the file, the function and the field of the code; `check` finds each function defined in its file and each field in the body of one of the functions of its row |
| `src/vpntest/formaltable.c` | the vpntest test `formaltable`: it refers to every C function of the table that is not static, so a function that the code loses or renames breaks the build of vpntest, and it pins the facts of the code that the models take (the suite name, the layout of the prologue, the exporter labels, TLS 1.2 by default) |
| `.github/scripts/formal.py` | `check` (the table and the expectations, no prover), `list` (the jobs of the workflow), `run` (ProVerif on a variant, or on a slice of its queries), `selftest` |
| `.github/workflows/formal.yml` | the Linux jobs of the full set: one builds ProVerif 2.05, pinned by the SHA-256 of its archive, and one job for each variant, or for each slice of its queries, runs it |

The check of the table runs in `quality.yml` on every pull request. The prover runs in the full set (a push to `integration` or `master`, the nightly run, a pull request that changes the models, the workflow or the script, and a pull request with the label `full-ci` that changes a file that the table names), as one job for each variant, or for each slice of its queries when `variants.tsv` cuts a variant into slices, so that the answers of a job are in its log when it is done; the input and the log of ProVerif of a job, with the traces of its attacks, are its artifact `formal-<variant>` or `formal-<variant>-<n>of<k>`.

## The model

The attacker is the network (the Dolev-Yao attacker of ProVerif): it reads, drops, rewrites and sends every message, runs as many sessions as it likes, and may hold a key that a leak gives it. A leak is an event of a phase: in phase 0, before or during the sessions, and in phase 1, after them, which is what forward secrecy asks.

**The outer session.** A TLS 1.3 handshake of one round trip with the authentication of the server only: the client sends a random value and a key share, the server its random value, its key share, its certificate and a signature of the transcript. The keys of the records and the exporter come from the Diffie-Hellman secret and the transcript, so two sessions that differ in any value of the transcript have different keys and different exporters, as the key schedule of RFC 8446 gives. Its key exchange is in a group of its own in the model (`tdhexp`), since no key share of TLS meets a Noise key in the code. The client does not check the chain: it compares the certificate with its pin (`TlsCheckPin`, `QuicConnCallback`), which a variant can leave out. A middlebox is the attacker with a certificate of its own that terminates the session of the client and opens one to the server.

**The Noise handshake.** On the first stream the client runs Noise_IK with the static key of the node identity and the pinned static key of the server, with the prologue that holds the binding: the label, the binding type, and the binding of the outer session. The binding is the TLS exporter (`NOISE_BINDING_EXPORTER`, the TLS-443 path and the control stream) or the tls-server-end-point of RFC 5929 (`NOISE_BINDING_SERVER_END_POINT`, the QUIC path). The handshake payloads are empty and the records after it go in clear inside the outer session, which encrypts them once (ADR-0023, single encryption). The first control record is the Login (a password, checked by Sam, and the Noise static key pinned to the user on the first login) or, on the control stream, the Hello with the schema version and the Capabilities; the server answers with a record of the data stream or the Update.

**The two keys of a node.** A server node has its Noise identity key (`LeakS`) and the key of its TLS certificate (`LeakCert`), and a compromise of one does not give the other (ADR-0023, key separation). The queries say which compromises an attack needs.

**The tunnel join** (`tunnel`, `tunnel-honest`, `tunnel-quic`, `tunnel-nokey`). A tunnel of several connections (ADR-0022, amendment of 2026-10-15): the first connection of a peer node logs in and makes the Tunnel of an id, which is the HMAC-SHA256 of a label under its handshake hash (`NoiseTunnelId`); each further connection runs a handshake of its own in an outer session of its own and sends a join Login that names the id (`NOISE_LOGIN_JOIN`), and the server adds it to the Tunnel when the id is the Tunnel's and the static key of the connection is the one of the Tunnel (`TunnelJoin`, `NoiseTunnelJoin`). The model has the first connection as the Tunnel that it makes, a new id for the static key of its peer, which the attacker is given, since the id is no secret inside the outer session and nothing rests on it; and it has the join in full: the outer session with the pin, the binding, the handshake and the join Login. `charlie`, whose keys the attacker holds, has a Tunnel of his own and dials with the ids of the others. No production client dials a second connection yet: the client of a join is in vpntest (`noisehub.c`, `nodelogin.c`).

**Noise_IK alone** (`noise-encrypted`). A session that nothing binds encrypts its records under the Noise keys (`NOISE_SESSION_ENCRYPT`: the CDN path of phase 2 and the loopback transport of vpntest). That is where the session keys of Noise, their secrecy and their forward secrecy, are proved: the authentication and confidentiality grades of the Noise Explorer for the four messages of IK, which equal the grades that it publishes. The handshake payloads are empty in the code (the Login follows in the first control record, "under the forward secrecy of the complete handshake"), and the grades show why: message a has no forward secrecy, message c has all of it.

**The peer layer** (`peer-leaks`, `peer-honest`). The envelopes of binds, bounds, signals and punch probes, sealed with the one-way pattern K, and the data datagrams, as the code has them.

### The variants

| variant | what it is |
|---|---|
| `tls443` | the session over TLS 1.3 on TCP 443, as the code has it: pinned certificate, handshake bound to the exporter; the keys leak |
| `tls443-honest` | the same with no key leaked |
| `quic` | the session over QUIC, as the code has it: pinned certificate, handshake bound to the tls-server-end-point; the keys leak |
| `quic-honest` | the same with no key leaked |
| `tls443-nobinding` | negative control: no binding in the prologue |
| `tls443-nopin` | negative control: the client pins no certificate |
| `tls443-neither-honest` | negative control: no pin and no binding, no key leaked: the middlebox |
| `tunnel`, `tunnel-honest` | the join of a further connection to a tunnel over TLS 1.3 as the code has it, with the keys leaked and with none |
| `tunnel-quic` | the same over QUIC: the binding is the one of the certificate |
| `tunnel-nokey` | negative control: the server joins by the id alone, with no comparison of the static key |
| `control-node` | the control stream of a C node: pinned certificate, exporter of the control label |
| `control-go` | the control stream of a Go client, which checks no certificate |
| `noise-encrypted` | Noise_IK alone with the records under the Noise keys |
| `peer-leaks`, `peer-honest` | the peer layer, with the keys leaked and with none |

### The queries of the session models

| id | says |
|---|---|
| `reach-login`, `reach-done` | the Login and the handshake can complete, so no query is true for want of a run |
| `sec-pw` | the password that the client sends is secret |
| `sec-pw-unless-noise`, `sec-pw-unless-cert`, `sec-pw-unless-both` | the password is secret unless the Noise key of the server, the key of its certificate, or both, are leaked in phase 0: a query "unless X" holds when every attack needs X |
| `sec-data-unless-both` | what the server sends back is secret unless both keys of the server are leaked |
| `fs-data` | forward secrecy: a leak of every long-term key after the session gives nothing that a leak before it does not |
| `auth-server` | the server takes the handshake of the client only if the client started it, in the TLS session that the server is in (the transcript of the TLS session is its identity) |
| `auth-client`, `auth-client-both` | the client takes the answer only if the server with the key that it pinned made it, in its TLS session and with the same handshake hash, unless the Noise key (or both keys) of the server is leaked |
| `data-auth` | what the client takes from the server after the handshake (a record of the data stream, or the Update of the controller) is what the server sent, unless the Noise key of the server is leaked |
| `negotiation` | the version and the Capabilities that the server settles on are the ones that the client offered: the attacker cannot lower them |
| `suite` | the suite that the server runs is the one that the client chose: the suite is in the protocol name that the hash of the handshake holds |
| `replay-server`, `replay-client` | no replay: each handshake that the server takes, and each answer that the client takes, is one that was sent once; these hold where no key leaks |

The queries of the tunnel models (`tunnel-queries.pvl`):

| id | says |
|---|---|
| `reach-join` | a connection can join, so no query is true for want of a run |
| `join-auth` | a connection that joins the Tunnel of alice is one that alice made, in the outer session that the server is in, unless the Noise key of alice or of the server is leaked: a middlebox that terminates the outer session of the join and opens one to the server is the case that the binding rules out |
| `join-identity` | a node joins only a Tunnel that was made for its own static key, whatever ids it knows: the ids of all Tunnels are the attacker's |
| `join-replay` | no replay: each join that the server takes is of a Login that was sent once; this holds where no key leaks |

The queries of `noise-encrypted` are the grades of the Noise Explorer for the messages a, b, c and d (`a-auth1` to `d-conf5`), and the ones of the peer layer are in `peer-queries.pvl`.

### What holds

The session over TLS-443 as the code has it (`tls443`) proves every query: against a middlebox the handshake needs both keys of the server, the Noise key and the key of the certificate; the version, the Capabilities and the suite cannot be lowered; the data of a session stay secret when every long-term key leaks after it; and with no key leaked (`tls443-honest`) the password, the data, the authentication in both directions and the absence of replay all hold. The control stream of a C node (`control-node`) gives the same. The join of a further connection to a tunnel (`tunnel`) proves that a connection that joins the Tunnel of alice is one that alice made, in the outer session that the server is in, and that a node joins only a Tunnel that was made for its own static key, whatever ids it knows. `noise-encrypted` gives the grades of the Noise Explorer for IK: both ends authenticate the static key of the other (messages b, c and d with the strongest grades, message a open to the key compromise of its receiver), and the first records of both directions have strong forward secrecy.

The negative controls each show their attack, and CI fails when one does not:

- **NC1, `tls443-nobinding`.** Without the binding, the key of the certificate of the server alone is enough for a middlebox: it terminates the TLS session of the client with the pinned certificate, opens one of its own to the server, and the two Noise handshakes cross it unchanged. `sec-pw-unless-noise`, `sec-data-unless-both`, `auth-server`, `auth-client` and `negotiation` hold in `tls443` and fail here.
- **NC2, `tls443-nopin`.** Without the pin, the Noise key of the server alone is enough: its holder answers the client in a TLS session of its own, and the binding, which is of that session, matches. `sec-pw-unless-cert` and `auth-client-both` hold in `tls443` and fail here.
- **NC3, `tls443-neither-honest`.** With neither, and no key leaked, the middlebox reads and rewrites every record: nothing is left for it to need.
- **NC4, `tunnel-nokey`.** If the server joined a connection to the Tunnel of the id that it names without comparing the static key of the connection with the Tunnel's, `charlie` would join the Tunnel of alice with her id, which the attacker is given. `join-identity` holds in `tunnel` and fails here.

With either protection alone a middlebox needs a key; the two together need both, so each guards the other's key.

## Findings

Each of these is an attack that the prover finds and a negative or positive result of `expected.tsv` that CI checks, so a fix of the code changes `expected.tsv` in the same change.

### F1: on QUIC the key of the certificate alone gives a middlebox the session

`quic`: `sec-pw-unless-noise`, `sec-pw-unless-both`, `sec-data-unless-both`, `auth-server`, `auth-client`, `auth-client-both` and `negotiation` fail, where `tls443` proves them. The tls-server-end-point is the same for every connection to one certificate (D1), so an attacker that holds the key of the certificate of the server, and not its Noise key, terminates the TLS session of the client, relays the Noise handshake to the server over a TLS session of its own (the binding is equal on both), and then reads and rewrites every record: the password, the data, the Hello. The pin keeps it out without that key (`sec-pw-unless-cert` holds). ADR-0023 asks for key separation so that a compromise of the certificate does not give the node identity; on QUIC it does. The code states the cause: msquic exposes no exporter. The join of a further connection is open to the same middlebox (`tunnel-quic`: `join-auth` fails, where `tunnel` proves it); the static key still decides which Tunnel a node joins (`join-identity` holds).

### F2: the data datagrams of the peer layer have no confidentiality and no authentication

`peer-leaks` and `peer-honest`: `pd-secret` and `pd-forgery` fail with no key leaked. `PeerSend` writes the tag, the key of the source, the key of the destination and the payload in the clear, and `PeerInputData` delivers a datagram whose source address is a path of its source (a relay, a binding or a direct path) and whose source is a peer: no key is checked, and a UDP source address is not authentication. Anyone on the path reads the payload and sends a datagram in the name of any peer. ADR-0015 items 3 and 7 and ADR-0023 have the data in the session of QUIC or TLS (D4). A node with the relay role runs the peer layer on a UDP socket of its own (`NodeRelayStart`): it takes the binds of its nodes and forwards their data datagrams. The overlay of `NodeOverlay.c` does not use the peer layer, it runs a Noise session over a data transport to each peer, so no node sends peer datagrams to a relay yet, and the exposure today is the UDP port of the relay role and the harness.

### F3: a relay binds the node to the address of the datagram, and the replay check forgets

`peer-leaks` and `peer-honest`: `pe-addr` and `pe-replay` fail. The envelope of a bind holds a version and a sequence, not an address, and `PeerInputBind` binds the node to the address that the datagram came from, so an attacker on the path that drops the bind of a node and sends the same envelope from an address of its own takes the binding, and with it the datagrams that other nodes send to the node through the relay (F2 makes them readable). The sequence that must grow (`PeerInputBind`, `PeerOpenSignal`, `PeerPunchInput`) is kept in memory: `PeerTick` drops the binding, and its sequence with it, after `BindExpiry` without a renewal, and `PeerSetPeers` makes a new entry, with sequence 0, for a peer that left the table and came back, so a bind or a signal that was captured earlier is taken again then. The model has a receiver that keeps no sequence, which is what such a receiver is.

The envelope has no forward secrecy (`pe-fs` fails in `peer-leaks`): its key comes from es and ss, as in every Noise_K, so a leak of the static key of the receiver opens the envelopes that were recorded. What it holds is a relay assignment and ICE candidates, which are no secret after the session.

### C1: the Go client of the control stream relies on the key of the controller alone

`control-go`: `sec-pw-unless-cert` and `auth-client-both` fail: the client that sets `InsecureSkipVerify` (`controller/internal/control`, `Dial`) has the pinned static key of the controller and the exporter, and nothing else, so the key of the controller alone is enough for an attacker. This is `tls443-nopin` with the control labels. The C node pins the certificate (`control-node` proves all).

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

ADR-0022 has the post-quantum hybrid "used where the OS provides it in both TLS and Noise". `NOISE_SUITE_IKHFS` is implemented (`NoiseHandshakeInit` and the tokens e1 and ekem1), and the TLS side puts X25519MLKEM768 first (`TransportTlsSetGroups`), but every caller of the session module (`NodeOverlaySessionConfig`, `ControlRun`, the transports of the tests) sets `NOISE_SUITE_IK`. The responder runs the suite of the first record if it can run it (`NoiseSuiteAvailable`), with no policy of its own, and the suite is in the protocol name that `InitializeSymmetric` hashes into `h`, so an attacker that changes the byte makes the handshake fail (`suite` holds). The model has IKhfs up to its protocol name, not its KEM tokens.

## What the model leaves out

- The TLS and QUIC stacks themselves: the model has an abstract TLS 1.3 handshake with the authentication of the server and an exporter, not Schannel or msquic, their record layers, their resumption (the code uses none) or their downgrade protection.
- The bytes: lengths, framing and parsing (the fuzz targets and the tests of the module cover them), and the AEAD nonce counters of a long session.
- Time: the timers, the dead-peer timeout, the expiry of a binding, which the model has only as the receiver that has lost its sequence.
- Of the multi-connection tunnel, the first connection (its Login and the id that its handshake gives are the session model, and the id is the attacker's here), the routing of the flows over the connections (`NoiseTunnelRoute`), the loss of a connection and its return, the index that a connection takes and the number of connections that a tunnel holds. Several connections of a tunnel are dialled only in vpntest today.
- Denial of service, traffic analysis, the decoy of the Trojan posture and the mimicry sidecar.
- Cross-protocol use of the node static key in the session, the control stream and the envelopes: the three prologues differ in their labels and the envelopes in their pattern, but the models do not run them together.

## Running it

ProVerif 2.05 builds from its source archive (`./build -nointeract` with OCaml). The models are text:

```
python .github/scripts/formal.py check
python .github/scripts/formal.py run --proverif /path/to/proverif --out build/formal tls443 quic
```

`run` writes each variant as one `.pv` file and its log to the directory of `--out`; the file runs on its own with `proverif -in pitype build/formal/tls443.pv`. The result of a query is `is true`, `is false` (an attack, with its trace) or `cannot be proved`. ProVerif keeps its state for every query of one run, and a variant has many queries, so `variants.tsv` cuts the heavier variants into slices, each a run of ProVerif with consecutive queries of its own and a job of the workflow (`python .github/scripts/formal.py run --slice 2/4 tls443` runs the second of four).
