// fuzz_peer.c
// libFuzzer target: the parsers of the peer layer of the new core (Core/Peer.c, Core/PeerSignal.c, CORE-S5-2 #78)
// that read what the network and the control plane send. Every input runs as a datagram through PeerInput of a
// relay that two nodes are bound to, once from the address of a bound node and once from an address that is
// none; as a datagram that the ICE session with a bound node delivered, through PeerInputDirect (CORE-S5-3 #79);
// as a signal envelope through PeerOpenSignal; and as the payload of a signal through PeerSignalDecode.
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

// What the ICE session with the peer of key delivered (Core/Peer.c), declared in Core/PeerInternal.h, which only the
// files of the peer module include
void PeerInputDirect(PEER_AGENT *a, const UCHAR *key, const UCHAR *data, UINT size);

static PEER_KEY fuzz_relay_key;
static PEER_KEY fuzz_a_key;
static PEER_KEY fuzz_b_key;
static PEER_AGENT *fuzz_relay = NULL;
static PEER_ADDR fuzz_a_addr;
static PEER_ADDR fuzz_other_addr;

// The send procedure of the relay: its datagrams go nowhere
static bool FuzzPeerSend(void *param, const PEER_ADDR *dst, const void *data, UINT size)
{
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

// Bind the node of key to the relay from addr, with the largest sequence: no bind of an input can replace it
static void FuzzPeerBind(PEER_KEY *key, const PEER_ADDR *addr)
{
	UCHAR payload[9];
	UCHAR env[PEER_MAX_ENVELOPE];

	payload[0] = 1;
	memset(payload + 1, 0xFF, 8);

	UINT size = PeerEnvelopeSeal(key, fuzz_relay_key.Public, PEER_MSG_BIND, NULL, payload, sizeof(payload), env, sizeof(env));
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

	return true;
}

// One input: a datagram from A and from a stranger, a datagram of the ICE session with A, a signal envelope, a signal
// payload
static void FuzzPeer(const uint8_t *data, size_t size)
{
	PEER_SIGNAL sig;

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
	PeerInputDirect(fuzz_relay, fuzz_a_key.Public, copy, (UINT)size);
	PeerOpenSignal(fuzz_relay, copy, (UINT)size, &sig);
	PeerSignalDecode(copy, (UINT)size, &sig);

	free(copy);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	FuzzRun(FuzzPeer, data, size);

	return 0;
}
