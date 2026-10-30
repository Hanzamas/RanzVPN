// fuzz_peer.c
// libFuzzer target: the parsers of the peer layer of the new core (Core/Peer.c, Core/PeerSignal.c, CORE-S5-2 #78)
// that read what the network and the control plane send. Every input runs as a datagram through PeerInput of a
// relay that two nodes are bound to, once from the address of a bound node and once from an address that is
// none; as a datagram from A at a node with ICE on and an ICE session with A, whose STUN messages go through
// PeerIceInput to libjuice (Core/PeerIce.c; CORE-S5-3 #79, CORE-S5-6 #412); as a signal envelope through
// PeerOpenSignal; and as the payload of a signal through PeerSignalDecode. For the peer sessions
// (Core/PeerSession.c, CORE-H2 #399) it also runs as a datagram from A at the node B, which holds keys of a session
// with A, and through PeerRecordParse and PeerHandshakeParse, the parsers of the clear header of a datagram between
// two nodes and of the payloads of the handshake messages.
// For the symmetric-NAT punch (Core/PeerPunch.c, CORE-S5-7 #413) it runs through PeerPunchParse, the parser of the
// payload of a punch message; as that payload, sealed by B to A and by A to B, at an A and a B that have a punch open
// with each other, so that the probes, the exchange of nonces and the keepalives of an input reach the punch of the
// leader and of the other end past the envelope, which no fuzzed byte opens; and as the payload of a punch offer or a
// punch answer, sealed likewise, at an A and a B that can tell their NATs, so that the candidates and the NAT of an
// input reach the targets of an attempt.
// The keys are the fixed ones of coretest (src/coretest/envelope.c), so a seed can be a datagram between the
// two bound nodes or a known answer of coretest.
//
// fuzz-max-len: 2048

#include "fuzz_common.h"

#include "Core/Peer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// The payload of a punch message: the version, the sequence, the type, a nonce and an echo of 16 bytes each (PeerPunch.c)
#define	FUZZ_PUNCH_PAYLOAD_SIZE	42

// Largest input accepted: the largest datagram of the peer layer; longer inputs are skipped
#define	FUZZ_MAX_INPUT_SIZE		PEER_MAX_DATAGRAM

static PEER_KEY fuzz_relay_key;
static PEER_KEY fuzz_a_key;
static PEER_KEY fuzz_b_key;
static PEER_AGENT *fuzz_relay = NULL;
static PEER_ADDR fuzz_a_addr;
static PEER_ADDR fuzz_other_addr;

static PEER_AGENT *fuzz_node = NULL;
static PEER_AGENT *fuzz_a = NULL;

// The node B again, with ICE on and an ICE session with A, which its offer to A started
static PEER_AGENT *fuzz_ice = NULL;

// The last datagram that the relay sent, during the setup: the challenge of a bind
static UCHAR fuzz_sent[PEER_MAX_DATAGRAM];
static UINT fuzz_sent_size = 0;

// The punch (Core/PeerPunch.c): A and B again with punching on, each bound to the relays R and R2, whose answers tell it
// its NAT. fuzz_punch_a and fuzz_punch_b sit behind sequential symmetric NATs and have a punch open with each other, which
// no tick ends: A, the end of the lower key, leads. fuzz_signals_a, behind a cone, and fuzz_signals_b, behind a sequential
// NAT, take the signals of the inputs, which may end an attempt, so that the punch of the two above stays open.
static PEER_KEY fuzz_relay2_key;
static PEER_ADDR fuzz_relay_addrs[2];
static PEER_AGENT *fuzz_punch_a = NULL;
static PEER_AGENT *fuzz_punch_b = NULL;
static PEER_AGENT *fuzz_signals_a = NULL;
static PEER_AGENT *fuzz_signals_b = NULL;
static PEER_ADDR fuzz_punch_from_a;		// Where the punch messages of A come from: the mapping of its NAT towards B
static PEER_ADDR fuzz_punch_from_b;		// ... and those of B
static UINT64 fuzz_sequence = 0;		// The last sequence that the harness wrote into a punch message or a signal

// The binds of a punching node, one for each of R and R2, during the setup
static UCHAR fuzz_binds[2][PEER_MAX_DATAGRAM];
static UINT fuzz_bind_sizes[2];

// The send procedure of the relay and of the node: their datagrams go nowhere, and the relay's last one is kept
static bool FuzzPeerSend(void *param, const PEER_ADDR *dst, const void *data, UINT size)
{
	if (param == NULL && size <= sizeof(fuzz_sent))
	{
		memcpy(fuzz_sent, data, size);
		fuzz_sent_size = size;
	}

	return true;
}

// The send procedure of A: its datagrams reach the node B from A's address
static bool FuzzPeerToNode(void *param, const PEER_ADDR *dst, const void *data, UINT size)
{
	if (fuzz_node != NULL)
	{
		PeerInput(fuzz_node, &fuzz_a_addr, data, size);
	}

	return true;
}

// The fixed key of the scalar first, first + 1, ...
static bool FuzzPeerKey(PEER_KEY *k, UCHAR first)
{
	UCHAR priv[PEER_KEY_SIZE];

	for (UINT i = 0;i < PEER_KEY_SIZE;i++)
	{
		priv[i] = (UCHAR)(first + i);
	}

	return PeerKeyFromScalar(k, priv);
}

// Bind the node of key to the relay from addr, with the largest sequence: no bind of an input can replace it. The
// first bind draws the relay's challenge (Core/PeerChallenge.c), whose cookie the second carries.
static void FuzzPeerBind(PEER_KEY *key, const PEER_ADDR *addr)
{
	UCHAR payload[25];
	UCHAR challenge[25];
	UCHAR sender[PEER_KEY_SIZE];
	UCHAR env[PEER_MAX_ENVELOPE];
	UINT len = 0;

	payload[0] = 1;
	memset(payload + 1, 0xFF, 8);

	fuzz_sent_size = 0;
	UINT size = PeerEnvelopeSeal(key, fuzz_relay_key.Public, PEER_MSG_BIND, NULL, payload, 9, env, sizeof(env));
	if (size != 0)
	{
		PeerInput(fuzz_relay, addr, env, size);
	}

	if (fuzz_sent_size == 0 || PeerEnvelopeOpen(key, fuzz_sent, fuzz_sent_size, sender, challenge, sizeof(challenge), &len) == false || len != sizeof(challenge))
	{
		return;
	}

	memcpy(payload + 9, challenge + 9, 16);
	size = PeerEnvelopeSeal(key, fuzz_relay_key.Public, PEER_MSG_BIND, NULL, payload, sizeof(payload), env, sizeof(env));
	if (size != 0)
	{
		PeerInput(fuzz_relay, addr, env, size);
	}
}

// A setup that does not hold: the run stops at once, with no abort message box and no Windows Error Reporting (as
// FuzzRun in fuzz_common.c), so that a harness that no longer reaches the punch fails instead of fuzzing less
static void FuzzPeerFail(const char *what)
{
	fprintf(stderr, "==RANZ FUZZ== %s\n", what);
	fflush(stderr);
	_set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
	abort();
}

// A sequence above every one that the harness and its nodes wrote before: the wall clock in 100 ns units, as the peer
// layer draws one (PeerNextSequence), or one more than the last
static UINT64 FuzzPeerSequence()
{
	FILETIME ft;

	GetSystemTimePreciseAsFileTime(&ft);
	UINT64 now = ((UINT64)ft.dwHighDateTime << 32) | ft.dwLowDateTime;

	fuzz_sequence = (now > fuzz_sequence ? now : fuzz_sequence + 1);

	return fuzz_sequence;
}

// v big-endian at p
static void FuzzPeerPutUint64(UCHAR *p, UINT64 v)
{
	for (UINT i = 0;i < 8;i++)
	{
		p[i] = (UCHAR)(v >> (56 - 8 * i));
	}
}

// The send procedure of a punching node: its binds to R and R2 are kept for the setup to answer, the rest goes nowhere
static bool FuzzPeerPunchSend(void *param, const PEER_ADDR *dst, const void *data, UINT size)
{
	for (UINT i = 0;i < 2;i++)
	{
		if (size != 0 && size <= sizeof(fuzz_binds[i]) && ((const UCHAR *)data)[0] == PEER_MSG_BIND && PeerAddrEqual(dst, &fuzz_relay_addrs[i]))
		{
			memcpy(fuzz_binds[i], data, size);
			fuzz_bind_sizes[i] = size;
		}
	}

	return true;
}

// Answer the bind of the punching node of key to the relay i, whose static key is relay_key, with the bound that the
// relay seals: the version and the sequence of the bind, and the address and the port that the relay saw the node at
static void FuzzPeerBound(PEER_AGENT *node, PEER_KEY *key, UINT i, PEER_KEY *relay_key, const PEER_ADDR *seen)
{
	UCHAR bind[64];
	UCHAR bound[27];
	UCHAR sender[PEER_KEY_SIZE];
	UCHAR env[PEER_MAX_ENVELOPE];
	UINT len = 0;

	if (fuzz_bind_sizes[i] == 0 || PeerEnvelopeOpen(relay_key, fuzz_binds[i], fuzz_bind_sizes[i], sender, bind, sizeof(bind), &len) == false || len < 9)
	{
		return;
	}

	memcpy(bound, bind, 9);
	memcpy(bound + 9, seen->Ip, sizeof(seen->Ip));
	bound[25] = (UCHAR)(seen->Port >> 8);
	bound[26] = (UCHAR)seen->Port;

	UINT size = PeerEnvelopeSeal(relay_key, key->Public, PEER_MSG_BOUND, NULL, bound, sizeof(bound), env, sizeof(env));
	if (size != 0)
	{
		PeerInput(node, &fuzz_relay_addrs[i], env, size);
	}
}

// A punching node of key whose one peer is other: R and R2 see it at the ports port and port + step of the public
// address 203.0.113.at of its NAT, so that it tells its NAT is a cone (step 0) or a sequential symmetric one (step 1). No
// number of attempts reaches the backoff, so that every punch offer of an input that the node can take begins an
// attempt, as the first one did.
static PEER_AGENT *FuzzPeerPuncher(PEER_KEY *key, PEER_INFO *other, UCHAR at, USHORT port, USHORT step)
{
	PEER_CONFIG c;
	PEER_RELAY_INFO relays[2];
	PEER_ADDR seen;

	PeerDefaultConfig(&c);
	c.Punch = true;
	c.PunchAttempts = 0xFFFFFFFF;

	PEER_AGENT *a = PeerNew(key, &c, FuzzPeerPunchSend, NULL, NULL, NULL);
	if (a == NULL)
	{
		return NULL;
	}

	memset(relays, 0, sizeof(relays));
	strcpy_s(relays[0].Name, sizeof(relays[0].Name), "r");
	memcpy(relays[0].Key, fuzz_relay_key.Public, PEER_KEY_SIZE);
	relays[0].Addr = fuzz_relay_addrs[0];
	strcpy_s(relays[1].Name, sizeof(relays[1].Name), "r2");
	memcpy(relays[1].Key, fuzz_relay2_key.Public, PEER_KEY_SIZE);
	relays[1].Addr = fuzz_relay_addrs[1];

	PeerSetPeers(a, other, 1);
	memset(fuzz_bind_sizes, 0, sizeof(fuzz_bind_sizes));
	PeerSetRelays(a, relays, 2);

	PeerAddrSetV4(&seen, 203, 0, 113, at, port);
	FuzzPeerBound(a, key, 0, &fuzz_relay_key, &seen);
	seen.Port = (USHORT)(port + step);
	FuzzPeerBound(a, key, 1, &fuzz_relay2_key, &seen);

	return a;
}

// The punch of the node to with the peer of key: open, or ended
static UINT FuzzPeerPunchState(PEER_AGENT *to, PEER_KEY *key)
{
	PEER_STATUS st;

	if (PeerGetStatus(to, key->Public, &st) == false)
	{
		return PEER_PUNCH_NONE;
	}

	return st.Punch;
}

// The NAT that the node a tells from the answers of its binds
static UINT FuzzPeerNat(PEER_AGENT *a)
{
	PEER_STATS st;

	PeerGetStats(a, &st);

	return st.Nat;
}

// The input as the payload of a punch message of the node of key to the node to, which has a punch open with it, from the
// address from: with a sequence above every one before, so that no input is a replay of the one before it. Only a payload
// of the size of a punch message is sealed: the parser refuses every other size before the punch looks at the message
// (PeerPunchParse, which the input runs through on its own too).
static void FuzzPeerPunch(PEER_AGENT *to, PEER_KEY *key, const UCHAR *to_key, const PEER_ADDR *from, const UCHAR *data, UINT size)
{
	UCHAR payload[FUZZ_PUNCH_PAYLOAD_SIZE];
	UCHAR env[PEER_MAX_DATAGRAM];

	if (to == NULL || size != sizeof(payload))
	{
		return;
	}

	memcpy(payload, data, size);
	FuzzPeerPutUint64(payload + 1, FuzzPeerSequence());

	UINT len = PeerEnvelopeSeal(key, to_key, PEER_MSG_PUNCH, NULL, payload, size, env, sizeof(env));
	if (len != 0)
	{
		PeerInput(to, from, env, len);
	}
}

// The input as the payload of a signal of the node of key to the node to: with a sequence above every one before. Only a
// punch offer or a punch answer is sealed, the signals that reach the punch (PeerSignalDecode reads every other one on its
// own).
static void FuzzPeerPunchSignal(PEER_AGENT *to, PEER_KEY *key, const UCHAR *to_key, const UCHAR *data, UINT size)
{
	UCHAR payload[PEER_MAX_ENVELOPE];
	UCHAR env[PEER_MAX_DATAGRAM];

	if (to == NULL || size < 10 || size > sizeof(payload) || (data[1] != PEER_SIGNAL_PUNCH_OFFER && data[1] != PEER_SIGNAL_PUNCH_ANSWER))
	{
		return;
	}

	memcpy(payload, data, size);
	FuzzPeerPutUint64(payload + 2, FuzzPeerSequence());

	UINT len = PeerEnvelopeSeal(key, to_key, PEER_MSG_SIGNAL, NULL, payload, size, env, sizeof(env));
	if (len != 0)
	{
		PeerOpenSignal(to, env, len, NULL);
	}
}

// Once: the relay, with A and B as its peers in VRF 10, both bound to it
static bool FuzzPeerSetup()
{
	PEER_CONFIG c;
	PEER_INFO peers[2];
	PEER_ADDR b_addr;

	if (fuzz_relay != NULL)
	{
		return true;
	}

	if (FuzzPeerKey(&fuzz_relay_key, 129) == false || FuzzPeerKey(&fuzz_a_key, 1) == false || FuzzPeerKey(&fuzz_b_key, 33) == false)
	{
		return false;
	}

	PeerDefaultConfig(&c);
	c.Relay = true;
	fuzz_relay = PeerNew(&fuzz_relay_key, &c, FuzzPeerSend, NULL, NULL, NULL);
	if (fuzz_relay == NULL)
	{
		return false;
	}

	memset(peers, 0, sizeof(peers));
	strcpy_s(peers[0].Name, sizeof(peers[0].Name), "a");
	memcpy(peers[0].Key, fuzz_a_key.Public, PEER_KEY_SIZE);
	peers[0].NumVrfs = 1;
	peers[0].VrfIds[0] = 10;
	strcpy_s(peers[1].Name, sizeof(peers[1].Name), "b");
	memcpy(peers[1].Key, fuzz_b_key.Public, PEER_KEY_SIZE);
	peers[1].NumVrfs = 1;
	peers[1].VrfIds[0] = 10;
	PeerSetPeers(fuzz_relay, peers, 2);

	PeerAddrSetV4(&fuzz_a_addr, 203, 0, 113, 10, 40000);
	PeerAddrSetV4(&b_addr, 203, 0, 113, 20, 40000);
	PeerAddrSetV4(&fuzz_other_addr, 198, 51, 100, 66, 4000);

	FuzzPeerBind(&fuzz_a_key, &fuzz_a_addr);
	FuzzPeerBind(&fuzz_b_key, &b_addr);

	// The node B, with A as its peer on the direct path, and the keys of a peer session with A: A's first datagram
	// starts the handshake, which B answers, so B holds keys that the records of an input are looked up under
	fuzz_node = PeerNew(&fuzz_b_key, NULL, FuzzPeerSend, &fuzz_node, NULL, NULL);
	fuzz_a = PeerNew(&fuzz_a_key, NULL, FuzzPeerToNode, NULL, NULL, NULL);
	if (fuzz_node == NULL || fuzz_a == NULL)
	{
		return false;
	}

	PeerSetPeers(fuzz_node, &peers[0], 1);
	PeerSetDirect(fuzz_node, fuzz_a_key.Public, &fuzz_a_addr);
	PeerSetPeers(fuzz_a, &peers[1], 1);
	PeerSetDirect(fuzz_a, fuzz_b_key.Public, &b_addr);
	PeerSend(fuzz_a, fuzz_b_key.Public, "fuzz", 4);

	// B with ICE on: its offer to A starts its ICE session with A, whose agent of libjuice takes the STUN messages of
	// an input (Core/PeerIce.c); and with punching on, so that a punch message of an input is opened (Core/PeerPunch.c)
	UCHAR env[PEER_MAX_ENVELOPE];

	PeerDefaultConfig(&c);
	c.Ice = true;
	c.Punch = true;
	fuzz_ice = PeerNew(&fuzz_b_key, &c, FuzzPeerSend, &fuzz_ice, NULL, NULL);
	if (fuzz_ice == NULL)
	{
		return false;
	}

	PeerSetPeers(fuzz_ice, &peers[0], 1);
	PeerSetHostCandidates(fuzz_ice, &b_addr, 1);
	PeerSealSignal(fuzz_ice, fuzz_a_key.Public, PEER_SIGNAL_OFFER, env, sizeof(env));

	// The punch: A and B behind sequential symmetric NATs, whose punch offer of A and punch answer of B begin an attempt
	// at both ends, as the control plane times one (Core/PeerPunch.c)
	if (FuzzPeerKey(&fuzz_relay2_key, 161) == false)
	{
		return false;
	}

	PeerAddrSetV4(&fuzz_relay_addrs[0], 192, 0, 2, 10, 7000);
	PeerAddrSetV4(&fuzz_relay_addrs[1], 192, 0, 2, 11, 7000);
	PeerAddrSetV4(&fuzz_punch_from_a, 203, 0, 113, 10, 40002);
	PeerAddrSetV4(&fuzz_punch_from_b, 203, 0, 113, 20, 40002);

	// The signals of the inputs go to an A behind a cone and a B behind a sequential NAT, so that they reach the targets
	// of both kinds of NAT
	fuzz_punch_a = FuzzPeerPuncher(&fuzz_a_key, &peers[1], 10, 40000, 1);
	fuzz_punch_b = FuzzPeerPuncher(&fuzz_b_key, &peers[0], 20, 40000, 1);
	fuzz_signals_a = FuzzPeerPuncher(&fuzz_a_key, &peers[1], 10, 40000, 0);
	fuzz_signals_b = FuzzPeerPuncher(&fuzz_b_key, &peers[0], 20, 40000, 1);
	if (fuzz_punch_a == NULL || fuzz_punch_b == NULL || fuzz_signals_a == NULL || fuzz_signals_b == NULL)
	{
		return false;
	}

	UINT size = PeerSealSignal(fuzz_punch_a, fuzz_b_key.Public, PEER_SIGNAL_PUNCH_OFFER, env, sizeof(env));
	PeerOpenSignal(fuzz_punch_b, env, size, NULL);
	size = PeerSealSignal(fuzz_punch_b, fuzz_a_key.Public, PEER_SIGNAL_PUNCH_ANSWER, env, sizeof(env));
	PeerOpenSignal(fuzz_punch_a, env, size, NULL);

	if (FuzzPeerNat(fuzz_signals_a) != PEER_NAT_CONE || FuzzPeerNat(fuzz_signals_b) != PEER_NAT_SEQUENTIAL)
	{
		FuzzPeerFail("the setup: a node with punching on does not tell its NAT from the bounds of R and R2");
	}
	if (FuzzPeerPunchState(fuzz_punch_a, &fuzz_b_key) != PEER_PUNCH_PROBING || FuzzPeerPunchState(fuzz_punch_b, &fuzz_a_key) != PEER_PUNCH_PROBING)
	{
		FuzzPeerFail("the setup: the punch offer of A and the punch answer of B do not open a punch at both ends");
	}

	return true;
}

// One input: a datagram from A and from a stranger, a datagram from A at a node with an ICE session with A, a signal
// envelope, a signal payload; the payload of a punch message and of a punch signal
static void FuzzPeer(const uint8_t *data, size_t size)
{
	PEER_SIGNAL sig;
	PEER_RECORD_INFO rec;
	PEER_HANDSHAKE_INFO hs;
	PEER_PUNCH_INFO punch;

	if (size == 0 || size > FUZZ_MAX_INPUT_SIZE || FuzzPeerSetup() == false)
	{
		return;
	}

	// malloc() rather than Malloc(): the copy is exactly 'size' bytes, so AddressSanitizer reports any read past
	// the end of the input
	UCHAR *copy = malloc(size);
	if (copy == NULL)
	{
		return;
	}
	memcpy(copy, data, size);

	PeerInput(fuzz_relay, &fuzz_a_addr, copy, (UINT)size);
	PeerInput(fuzz_relay, &fuzz_other_addr, copy, (UINT)size);
	PeerInput(fuzz_ice, &fuzz_a_addr, copy, (UINT)size);
	PeerOpenSignal(fuzz_relay, copy, (UINT)size, &sig);
	PeerSignalDecode(copy, (UINT)size, &sig);

	// The peer sessions (Core/PeerSession.c): the input as a datagram of A at the node B, which holds keys of a session
	// with A, and through the parsers of the clear header and of the payloads of the two handshake messages
	PeerInput(fuzz_node, &fuzz_a_addr, copy, (UINT)size);
	PeerRecordParse(copy, (UINT)size, &rec);
	PeerHandshakeParse(PEER_MSG_INIT, copy, (UINT)size, &hs);
	PeerHandshakeParse(PEER_MSG_RESPONSE, copy, (UINT)size, &hs);

	// The punch (Core/PeerPunch.c): the input through the parser of the payload of a punch message; as that payload, of A
	// at B and of B at A, the leader, whose punches with each other are open; and as a punch offer or a punch answer of A
	// at B and of B at A
	PeerPunchParse(copy, (UINT)size, &punch);
	FuzzPeerPunch(fuzz_punch_b, &fuzz_a_key, fuzz_b_key.Public, &fuzz_punch_from_a, copy, (UINT)size);
	FuzzPeerPunch(fuzz_punch_a, &fuzz_b_key, fuzz_a_key.Public, &fuzz_punch_from_b, copy, (UINT)size);
	FuzzPeerPunchSignal(fuzz_signals_b, &fuzz_a_key, fuzz_b_key.Public, copy, (UINT)size);
	FuzzPeerPunchSignal(fuzz_signals_a, &fuzz_b_key, fuzz_a_key.Public, copy, (UINT)size);

	free(copy);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	FuzzRun(FuzzPeer, data, size);

	return 0;
}
