// Noise.h
// The session module of the new core (ADR-0022, ADR-0023; CORE-F2, #62), on the crypto module
// (Core/Crypto.h). It has three parts:
// - The Noise handshake (Noise.c): Noise_IK_25519_AESGCM_SHA256 of the Noise Protocol Framework,
//   revision 34, and its post-quantum variant Noise_IKhfs_25519+MLKEM768_AESGCM_SHA256, the IK
//   pattern with the hfs extension (Noise HFS, revision 1) on ML-KEM-768, where CNG has ML-KEM. The
//   responder's static key is the node identity of the server node, which the initiator knows in
//   advance (pinned); the initiator's is the node identity of the client node, which the responder
//   learns from the handshake.
// - The Noise session (NoiseSession.c): the records of a data stream and a control stream over a
//   completed handshake, with keepalive, rekey on a schedule and the dead-peer timeout, independent
//   of the transport that carries the records. The handshake is bound to the outer TLS or QUIC
//   session by its prologue (channel binding); the records then go in clear inside that session,
//   which encrypts them once (ADR-0023, single encryption). Only a session that nothing binds, the
//   CDN path of phase 2, encrypts its records under the Noise keys (NOISE_SESSION_ENCRYPT). The
//   first control message of the initiator is its Login, which the server node's Sam checks
//   (NodeLogin, Cedar/Node.c).
// - The tunnel (NoiseSession.c): the sessions of up to NOISE_TUNNEL_MAX_CONNECTIONS connections
//   to one peer node, each bound to its own outer session, with the inner flows spread over them
//   by a flow hash and moved off a connection that is lost (ADR-0022, multi-connection tunnels).
//
// The module has no state of its own and allocates no memory: every object is the caller's, and
// the caller serialises the calls on one object. Times are milliseconds of the caller's clock,
// such as GetTickCount64. A function that fails returns false and leaves its secret outputs
// zeroed; a handshake or session that failed stays failed.

#ifndef CORE_NOISE_H
#define CORE_NOISE_H

#include "Core/Crypto.h"

#define NOISE_KEY_SIZE    32    // An X25519 key, a cipher key, the chaining key, the handshake hash
#define NOISE_TAG_SIZE    16    // The AES-GCM tag of every encrypted part
#define NOISE_MAX_MESSAGE 65535 // The largest Noise message, handshake or transport (Noise section 3)

// The handshakes. The protocol name is hashed into the handshake, so the two never mix.
#define NOISE_SUITE_IK    1 // Noise_IK_25519_AESGCM_SHA256
#define NOISE_SUITE_IKHFS 2 // Noise_IKhfs_25519+MLKEM768_AESGCM_SHA256, where CNG has ML-KEM

// The sizes of the handshake messages with an empty payload; a payload adds its own size.
// IK: -> e, es, s, ss and <- e, ee, se. IKhfs: -> e, es, e1, s, ss and <- e, ee, ekem1, se.
#define NOISE_IK_MESSAGE1_SIZE    (2 * NOISE_KEY_SIZE + 2 * NOISE_TAG_SIZE)
#define NOISE_IK_MESSAGE2_SIZE    (NOISE_KEY_SIZE + NOISE_TAG_SIZE)
#define NOISE_IKHFS_MESSAGE1_SIZE (NOISE_IK_MESSAGE1_SIZE + CRYPTO_MLKEM768_ENCAPS_KEY_SIZE + NOISE_TAG_SIZE)
#define NOISE_IKHFS_MESSAGE2_SIZE (NOISE_IK_MESSAGE2_SIZE + CRYPTO_MLKEM768_CIPHERTEXT_SIZE + NOISE_TAG_SIZE)

// A cipher state (Noise section 5.1): an AES-GCM key and the nonce of the next message
typedef struct NOISE_CIPHER {
	CRYPTO_AEAD Aead; // The key k; Aead.Key is NULL while there is none
	UINT64 Nonce;     // n
} NOISE_CIPHER;

// One handshake, from NoiseHandshakeInit to NoiseHandshakeSplit (Noise sections 5.2 and 5.3)
typedef struct NOISE_HANDSHAKE {
	UINT Suite;                                       // NOISE_SUITE_*
	bool Initiator;                                   // The initiator writes the first message
	UINT Messages;                                    // Messages written and read so far; 2 when the handshake is complete
	bool Failed;                                      // A message failed: the handshake is over
	UCHAR Ck[NOISE_KEY_SIZE];                         // The chaining key
	UCHAR H[NOISE_KEY_SIZE];                          // The handshake hash, the channel binding of the session once complete
	NOISE_CIPHER Cipher;                              // k and n of the symmetric state
	CRYPTO_IDENTITY *Identity;                        // The local static key in the key storage provider, or NULL
	UCHAR StaticKey[NOISE_KEY_SIZE];                  // The local static scalar where Identity is NULL
	UCHAR StaticPub[NOISE_KEY_SIZE];                  // s, the public half
	UCHAR EphemeralKey[NOISE_KEY_SIZE];               // e
	UCHAR EphemeralPub[NOISE_KEY_SIZE];               // e, the public half
	bool FixedEphemeral;                              // e was set by NoiseHandshakeSetEphemeral (known-answer tests)
	UCHAR RemoteStatic[NOISE_KEY_SIZE];               // rs: the initiator's pinned key, or what the responder learnt
	UCHAR RemoteEphemeral[NOISE_KEY_SIZE];            // re
	CRYPTO_MLKEM Kem;                                 // e1 of the initiator (IKhfs)
	UCHAR RemoteKem[CRYPTO_MLKEM768_ENCAPS_KEY_SIZE]; // re1 that the responder read (IKhfs)
} NOISE_HANDSHAKE;

// The cipher states (Noise.c). Init takes a 32-byte key and nonce 0. Encrypt writes size bytes of
// ciphertext and the tag, size + NOISE_TAG_SIZE bytes; Decrypt takes the ciphertext with its tag
// and writes size - NOISE_TAG_SIZE bytes. dst may be src. A failed Decrypt leaves the nonce as it
// was (Noise section 5.1). Rekey replaces the key by REKEY(k) and keeps the nonce (Noise section
// 11.3).
bool NoiseCipherInit(NOISE_CIPHER *c, const UCHAR *key);
bool NoiseCipherEncrypt(NOISE_CIPHER *c, const void *ad, UINT ad_size, const void *src, UINT size, UCHAR *dst);
bool NoiseCipherDecrypt(NOISE_CIPHER *c, const void *ad, UINT ad_size, const UCHAR *src, UINT size, void *dst);
bool NoiseCipherRekey(NOISE_CIPHER *c);
void NoiseCipherFree(NOISE_CIPHER *c);

// The handshake (Noise.c). Init starts it: the local static key is a scalar (static_key) or the
// node identity in the key storage provider (identity), exactly one of them; remote_static is the
// responder's static key, given to the initiator only. NOISE_SUITE_IKHFS fails where CNG has no
// ML-KEM. SetEphemeral fixes the ephemeral scalar, for known-answer tests only; otherwise a fresh
// one is generated. The initiator writes the first message and reads the second, the responder
// the other way round; out of turn, both fail. Write puts the message into msg (max bytes at
// most), Read the payload into payload. After the second message, Split gives the cipher states
// of the transport: send for the messages this side writes, recv for the ones it reads. H is then
// the handshake hash and RemoteStatic the peer's static key. Free wipes the handshake.
bool NoiseHandshakeInit(NOISE_HANDSHAKE *hs, UINT suite, bool initiator, const void *prologue, UINT prologue_size,
                        const UCHAR *static_key, CRYPTO_IDENTITY *identity, const UCHAR *remote_static);
void NoiseHandshakeSetEphemeral(NOISE_HANDSHAKE *hs, const UCHAR *priv);
bool NoiseHandshakeWrite(NOISE_HANDSHAKE *hs, const void *payload, UINT payload_size, UCHAR *msg, UINT max, UINT *msg_size);
bool NoiseHandshakeRead(NOISE_HANDSHAKE *hs, const UCHAR *msg, UINT msg_size, void *payload, UINT max, UINT *payload_size);
bool NoiseHandshakeSplit(NOISE_HANDSHAKE *hs, NOISE_CIPHER *send, NOISE_CIPHER *recv);
void NoiseHandshakeFree(NOISE_HANDSHAKE *hs);
const char *NoiseSuiteName(UINT suite);
bool NoiseSuiteAvailable(UINT suite);

// The channel binding in the prologue of a session handshake: the label NOISE_PROLOGUE_LABEL, the
// binding type (one byte) and the binding. The exporter is the TLS exporter of RFC 8446 section
// 7.5 (QUIC: RFC 9001 section 4.1) with NOISE_EXPORTER_LABEL, no context and NOISE_EXPORTER_SIZE
// bytes. tls-server-end-point (RFC 5929) is the hash of the pinned server certificate
// (CryptoCertEndPoint), for a stack that has no exporter. A session that nothing binds has none.
// A binding that differs on the two sides fails the handshake, so a TLS or QUIC session that a
// third party terminates is closed (ADR-0023).
#define NOISE_BINDING_NONE             0
#define NOISE_BINDING_EXPORTER         1
#define NOISE_BINDING_SERVER_END_POINT 2
#define NOISE_PROLOGUE_LABEL           "ranz session 1"
#define NOISE_EXPORTER_LABEL           "EXPORTER-ranz-session-noise"
#define NOISE_EXPORTER_SIZE            32
#define NOISE_MAX_BINDING              CRYPTO_END_POINT_MAX_SIZE
#define NOISE_MAX_PROLOGUE             (sizeof(NOISE_PROLOGUE_LABEL) + NOISE_MAX_BINDING)

// The prologue of a session handshake (NoiseSession.c): its size, or 0 when the binding does not
// fit or does not match its type
UINT NoisePrologue(UCHAR *dst, UINT max, UINT binding_type, const UCHAR *binding, UINT binding_size);

// The records of a session. Each record is one unit of the transport: a QUIC datagram or stream
// frame, a frame of the TLS stream. The first byte is the record type. A handshake record
// (NOISE_RECORD_HANDSHAKE) is the type, the suite (one byte) and the Noise message. Every later
// record is the type, then its payload: in clear on a bound session; with NOISE_SESSION_ENCRYPT,
// the Noise transport message of the payload under the sender's key with the type byte as
// associated data, so records must then arrive in order and complete, as on a stream.
// NOISE_RECORD_REKEYED on the type of an encrypted record marks the last record under the
// sender's current key: the receiver takes the next key (REKEY) after it.
#define NOISE_RECORD_HANDSHAKE 0x00 // The two handshake messages
#define NOISE_RECORD_DATA      0x01 // The data stream: an Ethernet frame (L2 network) or an IP packet (L3 network)
#define NOISE_RECORD_CONTROL   0x02 // The control stream: the Login first, then the session's control messages
#define NOISE_RECORD_KEEPALIVE 0x03 // No payload: keeps an idle session open
#define NOISE_RECORD_CLOSE     0x04 // No payload: the sender closes the session
#define NOISE_RECORD_REKEYED   0x80 // Flag on the type of an encrypted record
#define NOISE_RECORD_TYPE_MASK 0x7F

#define NOISE_RECORD_OVERHEAD (1 + NOISE_TAG_SIZE)                        // Type and tag around a payload, at most
#define NOISE_MAX_PAYLOAD     (NOISE_MAX_MESSAGE - NOISE_RECORD_OVERHEAD) // The largest payload of one record
#define NOISE_MAX_RECORD      (2 + NOISE_MAX_MESSAGE)                     // The largest record: a handshake record

// The flags of a session
#define NOISE_SESSION_ENCRYPT 0x01 // The records are under the Noise keys: the session is not bound (the CDN path)

// The timers of a session (milliseconds) and the records under one key. A keepalive goes out
// after the keepalive interval without a record sent; the session is dead after the dead timeout
// without a record received (WireGuard's 10 s keepalive and 180 s reject time, shortened to three
// missed keepalives and a margin). An encrypted session takes its next key after the rekey
// interval (WireGuard's REKEY_AFTER_TIME) or after the records of one key, whichever comes first:
// 2^24 records keeps AES-GCM within the limit of RFC 8446 section 5.5 (2^24.5 full-size records
// per key). On a bound session the outer TLS or QUIC session holds the keys: the owner is told
// to update them on the same schedule (NOISE_POLL_REKEY).
#define NOISE_KEEPALIVE_INTERVAL 10000
#define NOISE_DEAD_TIMEOUT       45000
#define NOISE_REKEY_INTERVAL     120000
#define NOISE_REKEY_RECORDS      (1ULL << 24)

// The states of a session
#define NOISE_STATE_NONE      0 // Not started, or freed
#define NOISE_STATE_HANDSHAKE 1 // The initiator waits for the second handshake message
#define NOISE_STATE_OPEN      2 // Records go both ways
#define NOISE_STATE_CLOSED    3 // Closed by either side, dead, or failed: nothing more goes either way

// What NoiseSessionReceive found in a record
#define NOISE_RECEIVE_ERROR   0 // A record that is malformed, out of place or fails to decrypt: the session is closed
#define NOISE_RECEIVE_NONE    1 // A keepalive: nothing for the owner
#define NOISE_RECEIVE_DATA    2 // A payload of the data stream
#define NOISE_RECEIVE_CONTROL 3 // A payload of the control stream
#define NOISE_RECEIVE_CLOSE   4 // The peer closed the session

// What NoiseSessionPoll asks of the owner
#define NOISE_POLL_IDLE  0 // Nothing until the next poll
#define NOISE_POLL_SEND  1 // Send the record it wrote (a keepalive)
#define NOISE_POLL_REKEY 2 // A bound session: update the keys of the outer TLS or QUIC session now
#define NOISE_POLL_DEAD  3 // Nothing came from the peer within the dead timeout: the session is closed

// How a session starts. The initiator chooses the suite; the responder takes the initiator's, if
// it can run it. 0 in a timer takes its default.
typedef struct NOISE_SESSION_CONFIG {
	UINT Suite;                // Initiator: NOISE_SUITE_IK or NOISE_SUITE_IKHFS
	UINT Flags;                // NOISE_SESSION_*
	const UCHAR *StaticKey;    // The local static key: a scalar ...
	CRYPTO_IDENTITY *Identity; // ... or the node identity in the key storage provider
	const UCHAR *RemoteStatic; // Initiator: the responder's static key
	UINT BindingType;          // NOISE_BINDING_*: NONE exactly where Flags has NOISE_SESSION_ENCRYPT
	const UCHAR *Binding;      // The channel binding of the outer session
	UINT BindingSize;          // Its size
	UINT KeepaliveInterval;    // NOISE_KEEPALIVE_INTERVAL
	UINT DeadTimeout;          // NOISE_DEAD_TIMEOUT
	UINT RekeyInterval;        // NOISE_REKEY_INTERVAL
	UINT64 RekeyRecords;       // NOISE_REKEY_RECORDS
	const UCHAR *Ephemeral;    // Known-answer tests only: the ephemeral scalar; NULL makes one
} NOISE_SESSION_CONFIG;

// One session: one connection to one peer node
typedef struct NOISE_SESSION {
	UINT State;                          // NOISE_STATE_*
	UINT Flags;                          // NOISE_SESSION_*
	bool Initiator;                      // This side wrote the first handshake message
	bool LoggedIn;                       // Responder: its owner accepted the Login (NoiseSessionAcceptLogin)
	NOISE_HANDSHAKE Handshake;           // The handshake, wiped once the session is open
	NOISE_CIPHER Send;                   // Encrypted sessions: the key of the records this side sends
	NOISE_CIPHER Recv;                   // ... and of the records it receives
	UCHAR HandshakeHash[NOISE_KEY_SIZE]; // h: the channel binding of the session (Noise section 11.2)
	UCHAR RemoteStatic[NOISE_KEY_SIZE];  // The static key of the peer node
	UINT KeepaliveInterval;              // The timers (ms) and the records under one key
	UINT DeadTimeout;
	UINT RekeyInterval;
	UINT64 RekeyRecords;
	UINT64 LastSent;      // When this side last sent a record
	UINT64 LastReceived;  // When it last received one
	UINT64 LastRekey;     // When the current key, or the outer keys, last changed
	UINT64 SentUnderKey;  // Records sent under the current key
	UINT64 NumRekeys;     // Keys this side changed: its own (encrypted) or the outer ones (bound)
	UINT64 NumPeerRekeys; // Keys the peer changed (encrypted sessions)
} NOISE_SESSION;

// The session (NoiseSession.c). Connect starts the initiator and writes the first handshake
// record; Accept takes it on the responder, which writes the second into reply and is open; Finish
// takes the second on the initiator, which is then open. Send writes one record of a stream
// (NOISE_RECORD_DATA or NOISE_RECORD_CONTROL) or a NOISE_RECORD_CLOSE; Receive reads one and
// writes its payload into data. A responder refuses data records until its owner accepted the
// Login (AcceptLogin). Poll runs the timers: call it after every receive and at least once per
// keepalive interval; repeat it while it returns NOISE_POLL_SEND or NOISE_POLL_REKEY. Challenge
// gives the bytes a certificate Login signs, Free wipes the session.
bool NoiseSessionConnect(NOISE_SESSION *s, const NOISE_SESSION_CONFIG *cfg, UINT64 now, UCHAR *record, UINT max, UINT *record_size);
bool NoiseSessionAccept(NOISE_SESSION *s, const NOISE_SESSION_CONFIG *cfg, UINT64 now, const UCHAR *record, UINT record_size,
                        UCHAR *reply, UINT max, UINT *reply_size);
bool NoiseSessionFinish(NOISE_SESSION *s, UINT64 now, const UCHAR *record, UINT record_size);
bool NoiseSessionSend(NOISE_SESSION *s, UINT64 now, UINT type, const void *data, UINT size, UCHAR *record, UINT max, UINT *record_size);
UINT NoiseSessionReceive(NOISE_SESSION *s, UINT64 now, const UCHAR *record, UINT record_size, void *data, UINT max, UINT *data_size);
UINT NoiseSessionPoll(NOISE_SESSION *s, UINT64 now, UCHAR *record, UINT max, UINT *record_size);
void NoiseSessionAcceptLogin(NOISE_SESSION *s);
bool NoiseSessionChallenge(const NOISE_SESSION *s, UCHAR *challenge, UINT size);
void NoiseSessionFree(NOISE_SESSION *s);

// The Login: the payload of the initiator's first control record. The server node's Sam checks a
// password against a password user or, for a user of a Windows domain, with the domain
// (CLIENT_AUTHTYPE_PLAIN_PASSWORD); a certificate Login holds the certificate and its key's
// signature of the challenge of the session (NoiseSessionChallenge, NOISE_LOGIN_CHALLENGE_SIZE
// bytes). A further connection of a tunnel joins it by the tunnel id instead (NOISE_LOGIN_JOIN).
// The encoding, sizes big-endian: version (1 byte), method (1), hub name (its size in 1 byte,
// then the name), user name (the same), secret (its size in 2 bytes, then the password, the DER
// certificate or the tunnel id), signature (its size in 2 bytes, then the signature; certificate
// Logins only). Names and passwords are UTF-8 without a terminator and hold no zero byte; nothing
// follows the signature.
#define NOISE_LOGIN_VERSION        1
#define NOISE_LOGIN_ANONYMOUS      0     // No secret: an anonymous user
#define NOISE_LOGIN_PASSWORD       1     // A password, or the password of a Windows domain account
#define NOISE_LOGIN_CERT           2     // A certificate and the signature of the challenge
#define NOISE_LOGIN_JOIN           3     // The id of a tunnel of the same peer node (NoiseTunnelId)
#define NOISE_LOGIN_MAX_NAME       255   // Bytes of a hub name or a user name at most
#define NOISE_LOGIN_MAX_PASSWORD   255   // ... of a password
#define NOISE_LOGIN_MAX_CERT       16384 // ... of a certificate
#define NOISE_LOGIN_MAX_SIGN       512   // ... of a signature (RSA 4096)
#define NOISE_LOGIN_CHALLENGE_SIZE 20    // Bytes that a certificate Login signs (Sam: SHA1_SIZE)
#define NOISE_TUNNEL_ID_SIZE       16    // Bytes of a tunnel id

// One Login. Cert and Sign point into the record that NoiseLoginParse read.
typedef struct NOISE_LOGIN {
	UINT Method;                                 // NOISE_LOGIN_*
	char HubName[NOISE_LOGIN_MAX_NAME + 1];      // The hub of the server role
	char UserName[NOISE_LOGIN_MAX_NAME + 1];     // The user
	char Password[NOISE_LOGIN_MAX_PASSWORD + 1]; // NOISE_LOGIN_PASSWORD
	const UCHAR *Cert;                           // NOISE_LOGIN_CERT: the DER certificate and its size
	UINT CertSize;
	const UCHAR *Sign; // NOISE_LOGIN_CERT: the signature of the challenge and its size
	UINT SignSize;
	UCHAR TunnelId[NOISE_TUNNEL_ID_SIZE]; // NOISE_LOGIN_JOIN
} NOISE_LOGIN;

// The Login (NoiseSession.c): Encode writes the payload of the control record, Parse reads one;
// Parse fails for anything but a complete, valid encoding
bool NoiseLoginEncode(const NOISE_LOGIN *l, UCHAR *buf, UINT max, UINT *size);
bool NoiseLoginParse(NOISE_LOGIN *l, const UCHAR *buf, UINT size);

// A tunnel: the sessions of the connections to one peer node (ADR-0022, multi-connection
// tunnels). Each connection runs its own handshake, bound to its own outer session, which
// encrypts it with keys of its own; the tunnel holds those with the same peer static key. The
// first connection logs in; the others join with the tunnel id (NOISE_LOGIN_JOIN). An inner flow
// goes over the connection its hash selects, so the packets of one flow keep their order; a lost
// connection's flows move to the others and come back when it joins again, and the tunnel stays
// up while one connection is left.
#define NOISE_TUNNEL_MAX_CONNECTIONS 16

typedef struct NOISE_TUNNEL {
	UCHAR Id[NOISE_TUNNEL_ID_SIZE];                           // From the handshake hash of the first connection
	UCHAR RemoteStatic[NOISE_KEY_SIZE];                       // The peer node of every connection
	UINT NumConnections;                                      // N: the connections the tunnel spreads over
	NOISE_SESSION *Connections[NOISE_TUNNEL_MAX_CONNECTIONS]; // Connection i, NULL while it is lost
} NOISE_TUNNEL;

// The tunnel (NoiseSession.c). Init makes a tunnel of num connections with first, an open session,
// as connection 0; Join puts an open session of the same peer node at connection index; Lose
// takes a connection out. Route gives the connection of a flow hash, NULL when none is left.
// TunnelId gives the id that a joining connection sends.
bool NoiseTunnelInit(NOISE_TUNNEL *t, NOISE_SESSION *first, UINT num);
bool NoiseTunnelJoin(NOISE_TUNNEL *t, UINT index, NOISE_SESSION *s);
void NoiseTunnelLose(NOISE_TUNNEL *t, UINT index);
NOISE_SESSION *NoiseTunnelRoute(const NOISE_TUNNEL *t, UINT flow_hash);
UINT NoiseTunnelNumAlive(const NOISE_TUNNEL *t);
bool NoiseTunnelId(const NOISE_SESSION *s, UCHAR *id);

// The flow hash of an Ethernet frame of the data stream, for Route (NoiseSession.c; CORE-S1-2, #68):
// the frames of one inner flow get the same hash, so they go over one connection and keep their
// order, never spread packet by packet (ADR-0022, multi-connection tunnels). An IPv4 or IPv6 frame
// hashes its addresses, its protocol and, for TCP and UDP outside a fragment, its ports (the IP
// 5-tuple); any other frame its MAC pair. The EtherType and the VLAN id of each 802.1Q or 802.1ad
// tag count too. Both directions of a flow give the same hash. 0 for a frame shorter than an
// Ethernet header.
UINT NoiseTunnelFlowHash(const UCHAR *frame, UINT size);

#endif // CORE_NOISE_H
