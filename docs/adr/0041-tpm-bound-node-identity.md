# ADR-0041: A TPM-bound identity for a Node, next to the Noise static key

**Status:** Proposed (2026-10-25, CORE-H4, #401, under #45). An evaluation: nothing in the product changes with it. It recommends adopting the TPM-bound identity in a later phase (the hardening phase), as an opt-in identity kind that a TPM-held key proves with a signature inside the Noise session, not with a client certificate on the outer session, and only after one experiment on real TPM hardware (Decision 1 and 2). It builds on ADR-0022 (amendment of 2026-10-21), ADR-0023, ADR-0033, ADR-0035 and ADR-0039, and on the formal model of AUD-5 (`docs/formal-model.md`).

## In short

1. **Protection.** A TPM-held key that must also sign in the session stops the copy of a disk, of a backup and of a VM from becoming a second Node, which the software key cannot do. It does not stop an attacker on the running host, which can use the TPM key while it is there, but the identity survives its eviction. It adds failure modes: a cleared or replaced TPM loses the identity.
2. **Windows.** The platform provider keeps non-extractable keys in the TPM. Microsoft does not list its algorithms, and the one TPM attestation that Windows documents attests RSA keys only. A service that runs as a virtual account cannot make a machine key, and keeps its key in its own key set (E6). The hosted runners have no TPM, so everything that needs one is untested and the script runs it elsewhere.
3. **Cost.** One TPM signature per Tunnel at its setup, none on the data path. The time of a TPM signature was not measured; the condition is 100 ms.
4. **Controller.** The Node resource gets an identity kind and a TPM pin. The first control record of a Noise session carries the proof, three places check it, and a Revision revokes it. The Noise session itself does not change.
5. **No TPM.** The software kind stays the default. A Capability `tpm` tells the Controller what a host can do, and a Node of the TPM kind never falls back.
6. **Formal model.** One message and two scenarios are added to the Noise session. The model of the outer session does not change.

The recommendation is Decision 1: adopt in a later phase, with the proof in the Noise session, after the experiment on TPM hardware. Nine follow-up tickets carry it.

## Context

A Node proves who it is with its Noise static key and with nothing else. What the code does today:

- **The key.** An X25519 key, persisted in the Microsoft Software Key Storage Provider and never exportable (`CryptoIdentityCreate`, `src/Core/CryptoX25519.c`). This ADR calls that provider the software provider, and the Microsoft Platform Crypto Provider, which keeps keys in the TPM, the platform provider. (CONTEXT.md uses "Software KSP" for the in-memory signer of CI; this ADR does not use that term.)
- **Its key set.** The ticket and the entry Node of CONTEXT.md put the key in the machine key set. The code does that only for a process that holds the rights of a local administrator (`PeerKeyScope` in `src/Core/PeerSignal.c`, and `keyScope` in `controller/internal/keys`). The Node service runs as its virtual account `NT SERVICE\ranzvpnserver` (ADR-0039 decision 3), which may not create machine keys, so its identity key is in the key set of that account. E6 below shows both halves on Windows.
- **Where it is used.** Noise_IK on the control stream (TLS 1.3 with no client certificate; the Controller reads the static key from the handshake and looks the Node up by it, `controller/internal/control/stream.go`) and on every Noise session to a server-role Node or to a peer. A Node is admitted by that key in three places: the Node resource (`publicKey`) at the Controller, the pinned key of a user (trust on first login) in the Configuration store of a server-role Node, and the Peer objects of the desired state of a Node.
- **What ties it to the outer session.** The Channel binding: the TLS exporter on TLS-443 and on the control stream, and the tls-server-end-point on QUIC, because msquic exposes no exporter (formal model, D1 and F1; RFC 9266 and RFC 5929, S2).
- **What already limits a stolen key.** The `enrolSources` of a Network refuse a control stream from outside its source prefixes, at every stream (ADR-0031, amendment of 2026-10-23).
- **What ADR-0022 says.** Its amendment of 2026-10-21 keeps the key in the software provider because "the TPM provider has no curve25519", and leaves "a TPM-held wrapping key for the identity key" as an option after v1.

The problem is the one of the ticket: a person with SYSTEM rights, or a copy of a disk image, can take the key, and a cloned VM then holds the identity of the original. (The Machine identity of FIX-5 has the same clone case: servers cloned from one image differ only when each has its own Config file.)

### The candidates

| | what it is |
|---|---|
| A | The software provider alone, as today. |
| B | A TPM-held key that wraps the Noise scalar: the scalar is stored encrypted and unwrapped in memory at start. The option that ADR-0022 left open. |
| C1 | A TPM-held key of a kind the TPM has (ECDSA P-256), pinned in the Node resource next to the Noise key. The Node signs the handshake hash of a Noise session with it and sends the signature and the public half in its first control record. |
| C2 | The same key as the client certificate of the outer TLS or QUIC session (mTLS), pinned the same way. |
| D | A TPM attestation at enrolment only, with no use of the TPM afterwards. |
| E | A key of the software provider that virtualization-based security protects (the VBS flags of `NCryptCreatePersistedKey`, D6). Not evaluated, see "What was not tested". |

C1 and C2 differ only in where the proof is made. What the six questions say of "C" holds for both, unless it names one.

## Evidence

Four kinds, and every claim says which: **documentation** (D1 to D17, listed at the end), **experiment** (E1 to E7 of `docs/experiments/core-h4-tpm/Test-TpmIdentity.ps1`), **code** (a file named in the text) and **reasoned** (the argument is ours and nothing tested it).

The experiments ran in `.github/workflows/tpm-experiment.yml` on the GitHub-hosted runners, in PowerShell 7 and in Windows PowerShell 5.1: run 40237081376 of commit 7a2a59c1. Its artifacts `tpm-experiment-x64` and `tpm-experiment-arm64` hold `results.json` and `report.txt` for 30 days; the tables below keep the numbers. Neither runner has a TPM. That is the limit of this ADR: what needs a TPM is in "What was not tested", and the script gives a person with a TPM the commands.

| | x64: Windows Server 2025 Datacenter, 10.0.26100 | arm64: Windows 11 Enterprise, 10.0.26200 |
|---|---|---|
| E1 the TPM | none: `Tbsi_GetDeviceInfo` gives 0x8028400F (TBS_E_TPM_NOT_FOUND, D11); `Get-Tpm` says TpmPresent False | the same |
| E2 the providers | the software provider opens; the platform provider does not: 0x80090030, "The device that is required by this cryptographic provider is not ready for use." | the same |
| E3 the software provider makes | ECDSA and ECDH on P-256, P-384 and P-521, an ECDH key on curve25519, RSA 2048, 3072 and 4096; every signature verifies (RSA with PKCS#1 and with PSS), every agreement derives 32 bytes. The key of curve25519 is only made, not used | the same |
| E4 one ECDSA P-256 signature, software provider, median (p95) | 0.20 ms (0.31) in PowerShell 7, 0.36 ms (0.54) in Windows PowerShell 5.1 | 0.27 ms (0.34), 0.61 ms (0.78) |
| E4 four threads at once | 48 of 48 signatures, no error; 2,287 and 9,505 per second (an earlier run, before the change of E6, gave 6,610 and 10,333: the figure moves between runs) | 48 of 48, no error; 14,887 and 5,637 per second |
| E5 a handshake over the loopback with Schannel, median: no client certificate, then a client certificate with a software key | TLS 1.3: 2.73 ms, 2.92 ms. TLS 1.2: 0.94 ms, 1.02 ms | TLS 1.3: 4.25 ms, 4.56 ms. TLS 1.2: 1.75 ms, 1.84 ms |
| E5 the first handshake of the process | 27 to 51 ms without a client certificate, 168 to 178 ms with one | 84 ms without, 187 ms with |
| E5 a client certificate that the server does not pin | refused in both versions: the server saw the certificate, the client got "The decryption operation failed" (TLS 1.3, on its first read) or "An existing connection was forcibly closed" (TLS 1.2) | the same |
| E7 the endorsement key | `Get-TpmEndorsementKeyInfo`: 0x80131500, TrustedPlatformModuleNotFoundException | the same |

E5 goes through .NET `SslStream`, which is Schannel with a callback of its own, not the native API that `src/Core/TransportTls.c` calls. E6 runs a service as a virtual account. It is the same on both architectures and in both editions of PowerShell:

| as `NT SERVICE\RanzH4Probe`, a service made like the Node service (an unrestricted service SID) | result |
|---|---|
| makes a key in the machine key set | fails: 0x80090010, "Access denied." |
| opens a machine-set key that an administrator made (the DACL its maker got: SYSTEM and Administrators, full control) | fails: 0x80090016, "Keyset does not exist" |
| the same, after the installer gave the SID of the service read access to the file of the key (`icacls /grant *SID:R`) | works, the signature verifies |
| makes a key in its own key set, signs and verifies | works. The file is `C:\Windows\ServiceProfiles\<service>\AppData\Roaming\Microsoft\Crypto\Keys\<name>_<machine guid>`; its owner is the service SID, its DACL gives SYSTEM, Administrators and the service SID full control, all inherited |

The key that an administrator makes in the machine key set is a file under `C:\ProgramData\Microsoft\Crypto\Keys` with a protected DACL: `O:BAG:S-1-5-21-...-513D:P(A;;FA;;;SY)(A;;FA;;;BA)`, SYSTEM and Administrators with full control. Whoever can read that file, or the file of the key of a service, is in position to take the key. Whether the content of the file is protected beyond its DACL, and by what, was not tested.

## The six questions

### 1. What does it protect against, and what does it not?

| the attack | A: software | B: wrapped scalar | C: a TPM key (C1 or C2) | D: attestation only |
|---|---|---|---|---|
| a copy of the disk or of a backup | no. The file admits SYSTEM and Administrators (E6), and the ticket's premise is that either, or an image of the disk, can take the key. What protects the content of the file beyond its DACL was not tested (the machine scope of DPAPI protects nothing from a process on the same system, D17) | yes: the blob needs the TPM that wrapped it | yes | no |
| a cloned VM or image that runs beside the original | no | yes, unless the clone gets the same TPM state (below) | yes, the same | no |
| an attacker with SYSTEM or Administrator rights on the running host, evicted later | the identity is burned: the key file and the process are readable | burned too: the scalar is unwrapped in memory | the attacker can use the TPM key while it is on the host, as a signing oracle, but cannot take it away, and the Noise key alone is no longer enough: the identity survives the eviction (reasoned; the model of CORE-H4-2 checks it) | burned |
| the same attacker while it stays | it acts as the Node from that host (reasoned), in every column | | | |
| a middlebox that holds the key of the server certificate (F1 of the model, on QUIC) | not covered | not covered | C1 does not cover it. C2 does for a Node that presents a client certificate: the signature of TLS 1.3 client authentication covers the transcript of the session (S1), which the QUIC binding by tls-server-end-point does not (reasoned). Any client key would do: the TPM is not what closes F1 | not covered |
| a rogue Node that an administrator, or a stolen API token, enrols | no | no | no | only with a list of the endorsement keys that may enrol (D1), and then only as to which TPMs |
| the Controller | no | no | no | no |
| the operator of the hypervisor or of the cloud, for a vTPM | no | no | no: the vTPM is theirs (D12, D13, D14) | no |
| a flaw of the TPM chip or its firmware | | | C adds that risk (TPM-FAIL, S4), and the Noise key stays the second factor | |

The "yes" of columns B and C rests on the TPM, not on Windows: for a key that cannot be migrated, "the private portion of the key is never exposed outside the TPM" (D4), and the keys of the platform provider "cannot be extracted" (D2). Column B has a second weakness that C has not: the scalar must be unwrapped into memory to be used.

**Where the TPM state goes decides the clone row on a VM.** Hyper-V: a VM with a vTPM can be migrated to a host that its Key Protector authorizes, and "If you migrate it to another host, you might not be able to start it" until the protector is updated (D12), so the administrator of the hypervisor can move the identity. AWS: "The NitroTPM state is not included in Amazon EBS snapshots." and "BitLocker volumes that are encrypted with NitroTPM-based keys can only be used on the original instance." (D14), so a clone made from a snapshot has another TPM. Azure and Google: their pages do not say what a copy of a disk gets (D13, D15); not tested.

**BitLocker, which keeps its disk key in the TPM (D4), is the Windows answer to the copy of a disk, and the TPM kind adds to it.** An administrator who holds the recovery key can boot a clone, which then holds the Noise key (reasoned). A key that only the original TPM can use is what stops that clone.

**What it adds to the cost, as failure modes:**

- **The identity is lost when the TPM is cleared or replaced:** a motherboard swap, a firmware reset, "clear the TPM before reinstalling" (D5). The Node then cannot prove itself, and an administrator enrols a new TPM key (CORE-H4-7). The software kind never fails that way.
- **Lockout.** A TPM 2.0 that Windows configures locks after 32 authorization failures and forgets one every 10 minutes, and "TPM 2.0 allows some keys to be created without an authorization value associated with them. These keys can be used when the TPM is locked." (D4). Whether the platform provider makes its keys without one was not tested.
- **A TPM that is not ready when the service starts**, or a service of the TPM Base Services that is still starting: TBS_E_SERVICE_START_PENDING, TBS_E_TPM_NOT_FOUND, TBS_E_IOERROR (D11); E2 shows what the provider says when there is no TPM. The Node must retry, and must not fall back to the software kind.
- **No TPM on many hosts.** A TPM is optional on Windows Server (D5), Azure has a vTPM on some sizes only (D13) and AWS on some instance types and AMIs only (D14), and a rented host of another kind may have none (reasoned). The TPM kind is an option of a Node and never the requirement of a feature, so ADR-0033 decision 4 holds.
- **Not proposed:** sealing the key to PCR values, which D4 describes. A change of firmware or of the boot chain changes the PCRs and would lock the identity out (reasoned).

### 2. What do Windows and Schannel offer?

- **The platform provider** is "a key storage provider (KSP) that utilizes the Trusted Platform Module (TPM)", and its private keys "cannot be extracted" (D2). Without a TPM it does not open: 0x80090030 (E2). Microsoft's text on TPM-based certificate storage says "The TPM protects certificates and RSA keys" and "TPM-based certificates are standard certificates" (D4). A TPM 1.2 allows RSA and SHA-1 only; a TPM 2.0 "supports newer algorithms ... Some TPMs don't support all algorithms" (D5).
- **Algorithms.** Microsoft's pages do not list what the platform provider makes (D2; the page that D5 names for the list covers the primitive provider only). The software provider makes ECDSA and ECDH on P-256, P-384 and P-521 and RSA, which D2 lists, and also an ECDH key on curve25519 on builds 26100 and 26200 (E3), which D2 does not list; `CryptoIdentityCreate` relies on it. Whether the platform provider makes a curve25519 key is the claim of ADR-0022 ("no curve25519"): the documentation is silent, no TPM was at hand, and the TCG algorithm registry could not be read from the build environment (S3). E3 has the row. The recommendation does not depend on its answer: if the platform provider made an X25519 key, the Noise key itself could be TPM-held and C would not be needed.
- **x64 and arm64.** The same API on both, and the software provider gave the same results on both (E3, E4, E6). A new device model for the desktop editions of Windows must implement and enable TPM 2.0, since 2016 (D5). There is no Windows Server on arm64 (ADR-0022), so an arm64 Node is a Windows 11 host or a guest with a vTPM, and Azure trusted launch supports Arm64 (D13).
- **A virtual TPM.** Hyper-V generation 2 VMs (D12); Azure trusted launch for Windows 10, Windows 11 and Windows Server 2016 to 2025 on x64 and Arm64 (D13); AWS NitroTPM on the instance types and the UEFI AMIs that D14 lists, which "conforms to the TPM 2.0 specification"; Google Shielded VM, whose vTPM Google calls compatible with the TCG library specification 2.0 (D15). The endorsement key of a vTPM can be read from the cloud (D14, D15). A hosted runner has none (E1).
- **A service and the key sets (E6).** A service that runs as a virtual account cannot make a machine key; it uses an administrator's machine key only after the installer grants its SID access to the file of the key; it makes and uses a key of its own in its own key set, under `C:\Windows\ServiceProfiles\<service>`. CNG names these places: the shared (machine) keys are in `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\Keys`, which E6 found as `C:\ProgramData\Microsoft\Crypto\Keys`; a user's are in `%APPDATA%\Microsoft\Crypto\Keys`; those of LocalService and NetworkService are under `%WINDIR%\ServiceProfiles` (D3), where E6 found the keys of a virtual account too. The Node does the last (`PeerKeyScope`), and a TPM key that the Node makes itself at first start needs no work of the installer. Whether the platform provider behaves the same in a service was not tested.
- **TPM key attestation.** Windows has it for a certification authority (D1): three trust models (the credentials of a user, the chain of the endorsement certificate, a list of the endorsement keys that may enrol), for Windows 8.1 and Windows Server 2012 R2 and later and an enterprise CA, and "TPM key attestation only works for RSA keys". The one attestation that Windows documents cannot attest an ECDSA P-256 key. `NCryptCreateClaim` is documented for VBS claims only (D7). `Get-TpmEndorsementKeyInfo` gives the hash of the endorsement key, its certificates and the additional certificates, and "Not all TPMs have EKCert" (D1; E7 reads and chains them on a host with a TPM).
- **What the Controller must verify** of an attested TPM key, with what a TPM 2.0 gives (S3; reasoned): (1) the endorsement key is on a list of allowed keys (the highest assurance of D1), or its certificate chains to a manufacturer root that the Controller trusts, and a vTPM chains to the vendor of the cloud; (2) the attestation key is in the same TPM as the endorsement key, by credential activation (`TPM2_MakeCredential` at the verifier, `TPM2_ActivateCredential` in the TPM); (3) the TPM key was made by that TPM and cannot be moved: the `TPM2_Certify` structure, signed by the attestation key, names the key by the hash of its public area and carries a nonce that the Controller chose, so it is fresh; the Node sends the public area too, and the verifier checks that it hashes to the name and that its attributes say fixedTPM, fixedParent and sensitiveDataOrigin; (4) the public key of the certify equals the TPM pin that the administrator applied; (5) the manufacturer and the firmware are not on a list of weak parts (S4). The check is own code on the Controller, or a Go library (candidates `github.com/google/go-attestation` and `github.com/google/go-tpm`; their licence and fit are for CORE-H4-6 to check, ADR-0036 decision 6).
- **A client certificate on the outer session (C2).** Documented: the server asks for it with `ASC_REQ_MUTUAL_AUTH`, "The client is required to supply a certificate to be used for client authentication." (D9); the client puts it in `paCred`, which is "optional for client unless server requests client authentication" (D10), and stops Schannel from looking for another with `SCH_CRED_NO_DEFAULT_CREDS` (D8); msquic has `REQUIRE_CLIENT_AUTHENTICATION` for a server, a `CERTIFICATE_CONTEXT` credential for a client, and `INDICATE_CERTIFICATE_RECEIVED` with the Schannel-only `DEFER_CERTIFICATE_VALIDATION` to let the application judge the certificate (D16). E5: Schannel does TLS 1.3 and TLS 1.2 client authentication with a client certificate whose key is in the software provider, the server saw the certificate in 20 of 20 handshakes, and a certificate it does not pin was refused. Not tested: the same with the platform provider; a native Schannel server that accepts a self-signed client certificate and judges it itself (D8 lists `SCH_CRED_MANUAL_CRED_VALIDATION` as client only and `hRootStore` for servers that require client authentication); an optional request of a certificate.
- **Why C1 first, and not C2.** (1) The Trojan posture of CORE-S2-2 (`src/Core/TransportDecoy.c`) completes the TLS handshake with a prober and only then reverse-proxies it to a website, so that it meets an ordinary HTTPS site. A server that requires a client certificate in the TLS handshake ends the prober's session there, and one that only requests it shows a `CertificateRequest` that a public website does not normally send (reasoned; how much that matters is the threat model of ADR-0023, where active probing is designed for now and enabled in phase 2). The signature in the Noise session comes after the first valid Noise frame and changes nothing that a prober sees. (2) The signature goes to CNG directly (`NCryptSignHash`, as the identity key does today), so no TPM key has to work through Schannel and msquic in a service. (3) It works on every Transport above the interface, the mimicry sidecar and the CDN path of phase 2 included, which terminate the outer session somewhere else. (4) The model of the outer session does not change (question 6). What C1 gives up is the closing of F1 on QUIC, which C2 would give for the Nodes that present a certificate, and which stays with AUD-5 (CORE-H4-9).

### 3. What does it cost?

| what | how often | cost |
|---|---|---|
| TLS client authentication on its own (C2), software key (E5) | once per outer session | 0.04 to 0.3 ms on a loopback handshake of 0.9 to 4.6 ms (medians); the first handshake of a process is 80 to 140 ms slower with a client certificate: the first use of the key |
| one ECDSA P-256 signature in the software provider (E4) | C1: once per Tunnel; C2: once per outer session | 0.20 to 0.61 ms median; four threads at once, no error |
| one ECDSA P-256 signature in a TPM | the same | **not measured**: no TPM. E4 measures it on a host with one. The condition of Decision 2 is a median of at most 100 ms and a p95 of at most 250 ms |
| the creation of the TPM key | once per Node | not measured; E3 times each kind |
| the data path | never | the TPM signs the proof only; the data keys come from the (EC)DHE of the outer session (ADR-0023) and the Noise static key stays in the software provider |

The proof is sent by the first connection of a Tunnel only: a further connection joins by the id of the Tunnel (`NOISE_LOGIN_JOIN`), as it does today. A Tunnel of 16 connections then costs one TPM signature, not 16, and a lost connection that joins again costs none. A Node with 100 peers that starts cold makes up to 100 signatures; at 100 ms each, behind a TPM that runs one command at a time, that is 10 s (reasoned). A server-role Node only verifies, which is cheap (a P-256 verification in CNG), so a busy hub is not slower.

- **A busy TPM** runs one command at a time (reasoned). The TPM Base Services have TBS_E_TOO_MANY_TBS_CONTEXTS and TBS_E_COMMAND_CANCELED (D11). The four-thread run of E4 measures the queue on a host with a TPM. A dial needs a timeout above the TPM latency: the control stream bounds its TLS and Noise handshakes together by 10 s (`handshakeTimeout`).
- **A locked-out TPM.** The Node cannot sign while the TPM refuses the key (D4). It reports the Capability as missing and stays out of the overlay until the TPM answers; it never falls back to the software key.
- **A cleared TPM.** The key is gone, the Node reports no TPM Capability, and the Controller refuses it (question 5) until an administrator enrols a new TPM key.

### 4. How would the Controller enrol, check, pin and revoke it?

This is the design of the follow-ups; nothing of it is built.

- **The Node resource says the kind.** `identity` holds `kind` (`software`, the default, or `tpm`) and, for `tpm`, `tpmKey`: the **TPM pin**, the SHA-256 of the SubjectPublicKeyInfo of the TPM key, base64, the same kind of value as the `tlsFingerprint` that `ranz status` prints. A resource of the software kind may hold no `tpmKey`. `publicKey` stays the Noise static key. The Controller adds the tag `identity-tpm` to a Node of the TPM kind, as it adds the groups of an owner (`intent.NodeTags`), so a Policy rule that matches that tag requires the kind; a tag is a DNS label, so the name has no colon, and an intent that names a tag or a Group `identity-tpm` is refused. The tag counts as one of the 16 of a Node, and two Nodes may not hold one TPM pin, as two may not hold one `publicKey` today.
- **Enrol.** The Node makes its TPM key at its first start, in its own key set (question 2), and prints one enrolment record: its Noise public key and the TPM pin. The administrator applies a Node resource with both (`ranz apply`, or a verb that writes it). With an attestation (CORE-H4-6) the Node first asks the Controller for a nonce and sends the attestation of question 2, and the Controller writes the Node resource only when it verifies. Without one, the kind is a claim of the administrator, as a pinned key is today.
- **Check.** The first control record of a Noise session of a Node of the TPM kind holds the public key of the TPM key and the signature of that key over a label, the handshake hash of the session and the public key. The handshake hash is the one that the Noise session already exposes as its channel binding (`NOISE_SESSION.HandshakeHash`), and it holds the prologue with the Channel binding, so the signature belongs to this session and, on TLS-443 and on the control stream, to its outer session. The checker looks the Node up by its static key, hashes the public key of the record, compares the hash with the TPM pin, and verifies the signature. A mismatch, or no proof from a Node of the TPM kind, is a refusal.
- **Three places check it,** the three places that admit a Node by its static key today: the Controller on a control stream (`Hello` carries the proof, and the Node resource holds the pin); a server-role Node on a Login (the pinned key of the user is joined by a pinned TPM key in the Configuration store); a Node on a peer (the Peer object of the desired state carries the pin). The place that decides does not change.
- **How a refused Node learns why.** The refusal is made after the Noise handshake, from inside the session, so the Controller can still answer `REFUSE_REASON_UNKNOWN_NODE` with a message that names the cause, as it does for `enrolSources`, and records an Event and an audit record, throttled the same way. A refusal at the TLS layer (C2) would give the Node a bare alert and no message: in E5 the client saw "The decryption operation failed" on its first read.
- **Pin, not PKI.** There is no CA, no certificate and no revocation list: the public key is sent as it is, and the pin is a list of what may enrol, like the pin of the server certificate (ADR-0023). C2 would add a self-signed certificate that no one validates but the pin.
- **Revoke.** Delete the Node resource, or apply another `tpmKey`: a Revision, as any change, that can be rolled back. The Controller then refuses the open streams of that Node at once, as it does when `enrolSources` tighten (`refuseOutsideSources`). A server-role Node loses the pin when the user record loses it; a peer, when its desired state drops the Peer, which takes a Generation. A TPM that was cleared is a revocation by accident, and the remedy is the same: a new `tpmKey`.
- **The Noise session does not change.** The prologue, the handshakes and the Login are as they are; the exporter binding stays. The proof is one more field of the first control record: an optional field in `Hello` of the control schema, and a version of the Login of a Noise session for a Login (CORE-H4-5 decides which). A Noise session of a Node of the software kind is byte for byte what it is today.

### 5. What happens on a host with no TPM?

The software key stays and the Node is of the software kind, which is the default. E1, E2 and E7 show what such a host says: no TPM from the TPM Base Services (0x8028400F), no platform provider (0x80090030), no endorsement key (0x80131500).

The Node resource says which kind a Node has, and the Node reports what its host can do as a new Capability `tpm` of the `Capabilities` message (ADR-0033), true when the platform provider opened and made its key. A Node whose resource says `tpm` and whose `Hello` lacks the Capability gets `REFUSE_REASON_CAPABILITY`, and an apply that asks it for the kind is refused with the name of the Node and the missing Capability, as ADR-0033 decision 2 has it. A host with a TPM may stay of the software kind. There is no downgrade: the Controller, not the Node, decides the kind, so a clone without a TPM is refused and does not fall back to the Noise key alone. A Policy can require the kind through the tag `identity-tpm` of question 4, so a Network can be limited to Nodes of the TPM kind and still carry Nodes of the software kind elsewhere.

CI has no TPM. The tests of the follow-ups use the software provider as the stand-in for the platform provider, behind the same functions, which is what the TPM gate of CORE-H4-1 completes by hand.

### 6. What would it change in the formal model of the handshake?

C1 leaves the model of the outer session as it is and adds to the Noise session. C2 would change the outer session too.

- **A key and a message.** `prims.pvl` gets a signature key pair for the TPM key of a node, and `session-lib.pvl` one more message of the first control record, `proof(pk(tpmk), sign(label, h, pk(tpmk)))`, where `h` is the handshake hash that the model has. The server process looks up the TPM pin of the node whose static key the handshake showed, with the pin of the Noise key, and takes the session only when the signature checks and the key is the pinned one. The control models take the same message in `Hello`, and the tunnel models keep the join as it is: only the first connection of a tunnel proves.
- **Scenarios.** The scenarios are one compromise each. The new ones are `tpm-noise-client` (the Noise key of the client leaked, its TPM key not) and `tpm-use` (a signing oracle for the TPM key in phase 0 of ProVerif, the compromised host, and no oracle in phase 1, the evicted attacker, with the Noise key leaked throughout). They model the claims of question 1 that are marked reasoned: that the identity survives an eviction, and that a key that can be used but not taken is not stolen.
- **Queries.** `auth-server` and `suite` are attacks today in `tls443-cert-client` and in `tls443-noise-client`, and `replay-server` in `tls443-cert-client`: the Noise key of the client lets the attacker be the client (`tests/formal/expected.tsv`). They must hold in `tpm-noise-client`, and in `tpm-use` in phase 1 only. A new query says that the server takes a session as node n only if the TPM key of n signed its handshake hash.
- **Negative controls,** so that CI fails when the defence is not there: `tpm-nopin` (the server verifies the signature but takes any key: the attack with the stolen Noise key and a key of the attacker must show) and `tpm-noproof` (a server of the TPM kind that does not ask for the proof: the attack of `noise-client` must show).
- **What stays the same.** F1 (`quic-cert`): the middlebox relays the handshake and the proof unchanged, so the signature does not help there. The queries of the software kind and their expected answers do not move.
- **The table and the code check.** `tests/formal/model-to-code.tsv` gets a row for each name of the new message and each function of the check, and `src/vpntest/formaltable.c` pins the label of the proof as it pins the layout of the prologue.
- **What the model leaves out, and the follow-ups too:** the enrolment and its attestation (the models leave out the first login too, and the attestation needs the primitives of the endorsement key and of credential activation, which are a model of their own), the lockout and the clearing of the TPM, and the ACLs of the key sets.
- **C2 on top of C1 or alone** would add `CertificateRequest`, a client `Certificate` and `CertificateVerify` to the outer session of `session-lib.pvl`, a client key pair, and for QUIC a variant `quic-cert-client` that must hold where `quic-cert` fails.

## What was not tested

| not tested | why | where it is tested |
|---|---|---|
| everything that needs a TPM: that the platform provider opens in a service and in the key set of a virtual account, which keys it makes (P-256, P-384, P-521, RSA 2048 to 4096, curve25519), the time of one signature and of four at once, the time to make a key, the endorsement key and its chain (E7) | the hosted runners have no TPM (E1, E2) | CORE-H4-1: E1 to E4, E6 and E7 on the hosts below |
| lockout, clearing and a busy TPM of the platform provider | the script never clears the TPM and never sends a wrong authorization value, by design | CORE-H4-1, by hand, on a machine that may be cleared |
| what a copy of a vTPM host gets: Hyper-V export and import, an Azure or Google snapshot | no such hosts in CI; only AWS says it (D14) | CORE-H4-1, one VM of each kind in use |
| a client certificate with a TPM key in a Schannel or msquic session (C2 only) | no TPM; msquic is not in the script | CORE-H4-9, if C2 is wanted |
| a native Schannel server that accepts a self-signed client certificate and judges it by its pin; an optional request of a certificate | E5 goes through .NET `SslStream`; D8 lists `SCH_CRED_MANUAL_CRED_VALIDATION` as client only | CORE-H4-9: a spike in vpntest with a software key, which runs in CI |
| TPM key attestation and the nonce flow | no TPM; the script reads the endorsement key only | CORE-H4-6 |
| whether a key file of the software provider can be decrypted from a disk image alone | the ticket's premise carries it, and D17 describes the machine scope of DPAPI; E6 shows only whom the DACL admits | not planned: the TPM kind does not depend on the answer |
| the VBS flags of `NCryptCreatePersistedKey` (candidate E) | VBS is not on the runners, D6 calls the information prerelease, and its page gives no numeric values | CORE-H4-8 |
| a curve25519 key in a TPM, per the TCG algorithm registry | the registry could not be read from the build environment | CORE-H4-1, the E3 row of the platform provider |

## Running the experiments with a TPM

From a checkout of this branch, in an elevated prompt on each host:

```
powershell -NoProfile -ExecutionPolicy Bypass -File docs\experiments\core-h4-tpm\Test-TpmIdentity.ps1 -OutDir out\ps51 -IncludeRsa -Machine -ReadEk
pwsh -NoProfile -File docs\experiments\core-h4-tpm\Test-TpmIdentity.ps1 -OutDir out\pwsh7 -IncludeRsa -Machine -ReadEk
```

PowerShell 7 and Windows PowerShell 5.1 give TLS 1.3 and TLS 1.2 in E5. The script touches only keys whose names start with `ranz-h4-`, deletes them at the end, and never clears the TPM, changes its owner or lockout values, or sends a wrong authorization value. `results.json` and `report.txt` land in `-OutDir`. The output of `-ReadEk` names the device: leave E7 out of anything posted. What each experiment answers: E1 the TPM the host has; E2 whether the platform provider opens; E3 which keys each provider makes (the row of curve25519 is the claim of ADR-0022); E4 the time of one signature and of several at once; E5 a handshake with a client certificate whose key is in the TPM; E6 the key sets and a service as a virtual account; E7 the endorsement key and its chain.

## References

Documentation (read on 2026-10-25):

- D1: TPM Key Attestation, https://learn.microsoft.com/windows-server/identity/ad-ds/manage/component-updates/tpm-key-attestation
- D2: CNG Key Storage Providers, https://learn.microsoft.com/windows/win32/seccertenroll/cng-key-storage-providers
- D3: Key Storage and Retrieval (the directories of CNG keys), https://learn.microsoft.com/windows/win32/seccng/key-storage-and-retrieval
- D4: Trusted Platform Module fundamentals, https://learn.microsoft.com/windows/security/hardware-security/tpm/tpm-fundamentals
- D5: TPM recommendations, https://learn.microsoft.com/windows/security/hardware-security/tpm/tpm-recommendations
- D6: NCryptCreatePersistedKey, https://learn.microsoft.com/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey
- D7: NCryptCreateClaim, https://learn.microsoft.com/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreateclaim
- D8: SCH_CREDENTIALS, https://learn.microsoft.com/windows/win32/api/schannel/ns-schannel-sch_credentials
- D9: AcceptSecurityContext (Schannel), https://learn.microsoft.com/windows/win32/secauthn/acceptsecuritycontext--schannel
- D10: Obtaining Schannel credentials, https://learn.microsoft.com/windows/win32/secauthn/obtaining-schannel-credentials
- D11: TBS return codes, https://learn.microsoft.com/windows/win32/tbs/tbs-return-codes
- D12: Hyper-V generation 2 virtual machine security features, https://learn.microsoft.com/windows-server/virtualization/hyper-v/generation-2-virtual-machine-security-features
- D13: Trusted Launch for Azure VMs, https://learn.microsoft.com/azure/virtual-machines/trusted-launch
- D14: NitroTPM for Amazon EC2 instances, https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/nitrotpm.html, and its requirements, https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/enable-nitrotpm-prerequisites.html
- D15: Shielded VM, https://docs.cloud.google.com/compute/shielded-vm/docs/shielded-vm
- D16: msquic, QUIC_CREDENTIAL_CONFIG, https://github.com/microsoft/msquic/blob/main/docs/api/QUIC_CREDENTIAL_CONFIG.md
- D17: Windows Data Protection (archived, NAI Labs for Microsoft, 2001), https://learn.microsoft.com/previous-versions/ms995355(v=msdn.10)

Standards and papers:

- S1: RFC 8446, TLS 1.3: section 4.3.2 (CertificateRequest), section 4.4.3 (CertificateVerify signs the hash of the handshake transcript), section 7.5 (exporters).
- S2: RFC 9266 (channel bindings for TLS 1.3) and RFC 5929 (tls-server-end-point), which the Channel binding uses.
- S3: TCG TPM 2.0 Library Specification: Part 2 (TPMA_OBJECT), Part 3 (TPM2_Certify, TPM2_MakeCredential, TPM2_ActivateCredential); TCG Algorithm Registry.
- S4: Moghimi, Sunar, Eisenbarth and Heninger, "TPM-FAIL: TPM meets Timing and Lattice Attacks", USENIX Security 2020.

## Decision

1. **Adopt the TPM-bound identity in a later phase, as an opt-in identity kind.** The hardening phase, after the core data path. A Node has the identity kind `software` (today, and the default) or `tpm`. A Node of the TPM kind has, next to its Noise static key, a TPM-held ECDSA P-256 key, pinned in its Node resource, and it proves the key with a signature of the handshake hash in the first control record of each Tunnel (C1, question 4). The algorithm is settled by E3 of CORE-H4-1: ECDSA P-256, and RSA 2048 only if the TPMs in use lack it. It is a hardening option, never a requirement of a feature.
2. **No code before conditions (a) and (b), no release before (c).** (a) CORE-H4-1 passes on real hardware, in the key set of a virtual account: the platform provider opens, makes an ECDSA P-256 key, and a signature through CNG verifies, with a median of at most 100 ms and a p95 of at most 250 ms for one signature and no error with four threads at once. (b) The formal model of CORE-H4-2 holds the proof in `tpm-noise-client` and in the phase 1 of `tpm-use`, and shows the attacks of its two negative controls. (c) A vpntest test shows, with the software provider as the stand-in, that a Node of the TPM kind is refused when its proof or its pin is wrong, and that a Node of the software kind is untouched. If (a) fails, the answer becomes "do not adopt" and this ADR is superseded; if the platform provider turns out to make an X25519 key, the Noise key moves into it and C is not needed.
3. **Not adopted:** B, the wrapped scalar, which protects a copy of the disk and the clone but not a live attacker, and costs an unwrapped scalar in memory (it replaces the option that ADR-0022 left open; the key stays in the software provider as that amendment decides); D alone, which proves at enrolment what no later session uses, so a stolen Noise key still works from anywhere; C2 first, for the decoy and the Schannel and msquic risks of question 2, kept as the option of CORE-H4-9; sealing to PCR values.
4. **Attestation is a later addition** (CORE-H4-6), not a condition of the first release: the pin gives the protection against theft and clones, the attestation only tells the Controller that the pinned key is in a genuine TPM.

## Follow-up tickets

To be filed by the maintainer; the numbers are not assigned. "Blocked by" is the edge of the graph, and a ticket with none can start now.

| ticket | what | blocked by |
|---|---|---|
| CORE-H4-1 | Run the script on TPM hardware, by a person: x64 with a discrete TPM and with a firmware TPM, Windows 11 on arm64, a Hyper-V vTPM, and each cloud vTPM in use, as `-IncludeRsa -Machine -ReadEk`, in PowerShell 7 and in Windows PowerShell 5.1 (commands below). Add the results to this ADR as an amendment and settle condition (a) | none |
| CORE-H4-2 | The formal model of question 6: the proof, the scenarios `tpm-noise-client` and `tpm-use`, the two negative controls, the table and the `formaltable` rows. Settles condition (b) | none |
| CORE-H4-3 | The Controller side (Go and the control schema): `identity` of the Node resource, the tag, the Capability `tpm`, `Hello.tpm_proof`, the check, the refusal with its Event and audit record, the refusal of open streams on a Revision; `ranz-nodesim` with a software stand-in. A fuzz target for the proof parser, and a floor line for any new package | CORE-H4-1, CORE-H4-2 |
| CORE-H4-4 | The Node side (C, `src/Core/Crypto*`, a sensitive path, so the full set of CI): `CryptoTpm*` to make, open and sign with a key of the platform provider in the key set of the service; the proof; the Capability. A fuzz target and a line in `.github/quality/fuzz-targets.txt` for the proof parser; the software provider as the stand-in in vpntest | CORE-H4-1, CORE-H4-2 |
| CORE-H4-5 | The two other places that admit a Node: the Login of a server-role Node (the pin next to the pinned key of a user, in the Configuration store) and the Peer object of the desired state. Settles condition (c) | CORE-H4-2, CORE-H4-3, CORE-H4-4 |
| CORE-H4-6 | Attestation at enrolment: the nonce, the endorsement key list or chain, the credential activation, the certify check, with a Go library if its licence and fit pass. The verb of the CLI that enrols | CORE-H4-3, CORE-H4-4 |
| CORE-H4-7 | Operations: the runbook for a cleared or replaced TPM and the re-enrolment, the Events, the identity kind in `ranz get nodes` and in the web UI | CORE-H4-3 |
| CORE-H4-8 | An experiment: the VBS flags of the software provider for the Noise key itself, with the script of CORE-H4-1 as the model. It could make C unnecessary | none |
| CORE-H4-9 | An evaluation, independent of the TPM and a finding of AUD-5 (F1): a client certificate on the QUIC outer session. Starts with a spike in vpntest that runs in CI with a software key: a native Schannel server with `ASC_REQ_MUTUAL_AUTH` and a pinned self-signed certificate, msquic `REQUIRE_CLIENT_AUTHENTICATION`, and an optional request | none |

## Consequences

- Nothing changes in the product with this ADR. The pull request holds this document, the script of the experiments and the workflow that runs it on the hosted runners.
- If the ADR is accepted, the Node resource, the `Hello` message and the `Capabilities` message gain fields. The control schema stays at the version it has: a field that an older Node does not send counts as missing, and a Controller serves Nodes of the version before as ADR-0027 decision 7 has it.
- The CI of the follow-ups needs no TPM except for the gate that CORE-H4-1 runs by hand, because the software provider stands in for the platform provider behind the same functions.
- The entry Node of CONTEXT.md says the identity key is in the machine key set "when the process runs elevated, as the service does". The service does not: it uses the key set of its virtual account (Context, E6). The entry needs a correction that this pull request does not make. "Software KSP" of CONTEXT.md and "software KSP" of ADR-0022 mean two things (the CI signer and the Microsoft provider).
- It does not contradict the amendment of 2026-10-21 of ADR-0022: the Noise key stays in the software provider. It names another option than that amendment's TPM-held wrapping key (Decision 3). ADR-0033 decision 4 holds, because the kind is an option of a Node. ADR-0023's key separation holds: the TPM key is a third key, and a leak of one key does not give a session.
- The new terms for CONTEXT.md are Identity kind, TPM pin and TPM proof. The maintainer decides whether they join it.
