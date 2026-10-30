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
// The keys are the fixed ones of coretest (src/coretest/envelope.c), so a seed can be a datagram between the
// two bound nodes or a known answer of coretest.
//
// fuzz-max-len: 2048

#include "fuzz_common.h"

#include "Core/Peer.h"

#include <stdlib.h>
#include <string.h>

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

	return true;
}

// One input: a datagram from A and from a stranger, a datagram from A at a node with an ICE session with A, a signal
// envelope, a signal payload
static void FuzzPeer(const uint8_t *data, size_t size)
{
	PEER_SIGNAL sig;
	PEER_RECORD_INFO rec;
	PEER_HANDSHAKE_INFO hs;

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

	free(copy);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	FuzzRun(FuzzPeer, data, size);

	return 0;
}
