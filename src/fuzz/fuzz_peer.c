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
// The ICE session with A has A's answer, so its agent takes the checks that name its username fragment and hands them
// to the dispatch of libjuice (agent_dispatch_stun; CORE-S5-6-R1, #537). That fragment is random, so a seed names it
// as FUZZ_PEER_UFRAG, which the copy of the input for the session holds in its place: the seeds stun_check*.bin of
// make_seeds.py. Libjuice fails a session whose checks all go unanswered after 39.5 s; the next input then starts a
// new one, with A's answer again. The copy then has the MESSAGE-INTEGRITY of the session in the place of what the input
// holds there, an HMAC with the password that B's offer gave A (FuzzPeerIntegrity; CORE-S5-6-R2, #557), so a check of
// the seeds or of the fuzzer passes the check of its integrity and reaches the processing of a check by libjuice: the
// roles, USE-CANDIDATE and the peer reflexive candidates.
//
// The log of libjuice goes nowhere (FuzzPeerJuiceLog). Without a handler it writes to stdout, and it quotes the username
// fragment of a check that does not match, so an input would write a line of its own into the output of the run; the
// coverage that run_fuzzers.ps1 checks for the two reach lines below is read from the report of libFuzzer alone
// (CORE-S5-6-R3, #574).
//
// fuzz-max-len: 2048
// fuzz-libs: libjuice
// fuzz-reach: agent_dispatch_stun
// fuzz-reach: agent_process_stun_binding

#include "fuzz_common.h"

#include "Core/Peer.h"
#include <bcrypt.h>
#include <juice/juice.h>

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

// The username fragment that a seed names for B's ICE session with A, as long as one of B (Core/PeerIce.c), and the one
// of the session now, which the copy of an input for B holds in its place; and the password of the session, which the
// MESSAGE-INTEGRITY of a check in that copy is made with
#define	FUZZ_PEER_UFRAG			"RanzUfrg"
#define	FUZZ_PEER_UFRAG_LEN		8
static char fuzz_ice_ufrag[PEER_ICE_UFRAG_SIZE];
static char fuzz_ice_pwd[PEER_ICE_PWD_SIZE];

// The password of A's session in its answer, which the MESSAGE-INTEGRITY of an answer to a check of B is made with
#define	FUZZ_PEER_A_PWD			"RanzFuzzPasswordOfPeerA0"

// The sequence of A's last answer to B's offer: above the clock of B's entry of A (PeerFloorOf), and growing
static UINT64 fuzz_ice_sequence = 1ULL << 60;

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

// The log of libjuice: libjuice still formats every message, what an input puts into it as well, so the fuzzer still
// checks that, and the message goes nowhere
static void FuzzPeerJuiceLog(juice_log_level_t level, const char *message)
{
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

// A's answer to the offer env of size bytes that B sealed for A, which started B's ICE session with A: A opens the offer
// for the username fragment of the session, and its answer, with an address and credentials of A, gives the session the
// remote description, so that the agent of the session takes a check that names that fragment. False when a step failed.
static bool FuzzPeerAnswer(const UCHAR *env, UINT size)
{
	UCHAR payload[PEER_MAX_ENVELOPE];
	UCHAR answer[PEER_MAX_ENVELOPE];
	UCHAR sender[PEER_KEY_SIZE];
	PEER_SIGNAL s;
	UINT len = 0;

	if (size == 0 || PeerEnvelopeOpen(&fuzz_a_key, env, size, sender, payload, sizeof(payload), &len) == false ||
		PeerSignalDecode(payload, len, &s) == false || strlen(s.IceUfrag) != FUZZ_PEER_UFRAG_LEN)
	{
		return false;
	}
	strcpy_s(fuzz_ice_ufrag, sizeof(fuzz_ice_ufrag), s.IceUfrag);
	strcpy_s(fuzz_ice_pwd, sizeof(fuzz_ice_pwd), s.IcePwd);

	memset(&s, 0, sizeof(s));
	s.Type = PEER_SIGNAL_ANSWER;
	s.Sequence = ++fuzz_ice_sequence;
	s.NumCandidates = 1;
	s.Candidates[0].Type = PEER_CANDIDATE_HOST;
	s.Candidates[0].Addr = fuzz_a_addr;
	strcpy_s(s.IceUfrag, sizeof(s.IceUfrag), "RanzPeer");
	strcpy_s(s.IcePwd, sizeof(s.IcePwd), FUZZ_PEER_A_PWD);

	len = PeerSignalEncode(&s, payload, sizeof(payload));
	size = (len != 0 ? PeerEnvelopeSeal(&fuzz_a_key, fuzz_b_key.Public, PEER_MSG_SIGNAL, NULL, payload, len, answer, sizeof(answer)) : 0);

	return size != 0 && PeerOpenSignal(fuzz_ice, answer, size, NULL) == PEER_OK;
}

// A new ICE session of B with A, in the place of one that libjuice failed as its checks went unanswered: B offers again,
// and A answers
static bool FuzzPeerIce()
{
	UCHAR env[PEER_MAX_ENVELOPE];
	UINT size = PeerSealSignal(fuzz_ice, fuzz_a_key.Public, PEER_SIGNAL_OFFER, env, sizeof(env));

	return FuzzPeerAnswer(env, size);
}

// The MESSAGE-INTEGRITY and MESSAGE-INTEGRITY-SHA256 attributes of a STUN message in the copy of an input for B, made
// again once the username fragment of B's session is in its place (RFC 8489 sections 14.5 and 14.6): the HMAC of the
// message up to the attribute, with the length of the header up to the end of the attribute, keyed with the password of
// B's session for a check and with A's for an answer, as libjuice checks them (agent_verify_stun_binding). The short-term
// credentials of ICE: a message with a REALM, which libjuice keys otherwise, keeps an HMAC that fails. Every other input
// is left as it is.
static void FuzzPeerIntegrity(UCHAR *data, size_t size)
{
	UCHAR mac[32];

	// A STUN message: the first two bits zero, the magic cookie, and the attributes within the input
	if (size < 20 || (data[0] & 0xC0) != 0 || data[4] != 0x21 || data[5] != 0x12 || data[6] != 0xA4 || data[7] != 0x42)
	{
		return;
	}

	size_t end = 20 + (((size_t)data[2] << 8) | data[3]);
	if (end > size)
	{
		return;
	}

	// The class of a request has neither of its two bits (RFC 8489 section 5)
	const char *pwd = ((data[0] & 0x01) == 0 && (data[1] & 0x10) == 0 ? fuzz_ice_pwd : FUZZ_PEER_A_PWD);

	for (size_t pos = 20;pos + 4 <= end;)
	{
		size_t type = ((size_t)data[pos] << 8) | data[pos + 1];
		size_t len = ((size_t)data[pos + 2] << 8) | data[pos + 3];
		size_t mac_size = (type == 0x0008 ? 20 : (type == 0x001C ? 32 : 0));

		if (pos + 4 + len > end)
		{
			break;
		}

		if (mac_size != 0 && len == mac_size)
		{
			// The length of the header up to the end of the attribute while the HMAC is made, then the length again
			UCHAR length[2] = {data[2], data[3]};
			size_t upto = pos + 4 + mac_size - 20;

			data[2] = (UCHAR)(upto >> 8);
			data[3] = (UCHAR)upto;
			NTSTATUS status = BCryptHash(mac_size == 20 ? BCRYPT_HMAC_SHA1_ALG_HANDLE : BCRYPT_HMAC_SHA256_ALG_HANDLE,
				(PUCHAR)pwd, (ULONG)strlen(pwd), data, (ULONG)pos, mac, (ULONG)mac_size);
			data[2] = length[0];
			data[3] = length[1];

			if (BCRYPT_SUCCESS(status))
			{
				memcpy(data + pos + 4, mac, mac_size);
			}
		}

		pos += 4 + ((len + 3) & ~(size_t)3);
	}
}

// The copy of an input for B's ICE session with A: the username fragment of the session in the place of each
// FUZZ_PEER_UFRAG, then the MESSAGE-INTEGRITY of the session (FuzzPeerIntegrity)
static void FuzzPeerUfrag(UCHAR *data, size_t size)
{
	if (strlen(fuzz_ice_ufrag) != FUZZ_PEER_UFRAG_LEN)
	{
		return;
	}

	for (size_t i = 0;i + FUZZ_PEER_UFRAG_LEN <= size;i++)
	{
		if (memcmp(data + i, FUZZ_PEER_UFRAG, FUZZ_PEER_UFRAG_LEN) == 0)
		{
			memcpy(data + i, fuzz_ice_ufrag, FUZZ_PEER_UFRAG_LEN);
		}
	}

	FuzzPeerIntegrity(data, size);
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

	juice_set_log_handler(FuzzPeerJuiceLog);

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
	// an input (Core/PeerIce.c)
	UCHAR env[PEER_MAX_ENVELOPE];

	PeerDefaultConfig(&c);
	c.Ice = true;
	fuzz_ice = PeerNew(&fuzz_b_key, &c, FuzzPeerSend, &fuzz_ice, NULL, NULL);
	if (fuzz_ice == NULL)
	{
		return false;
	}

	PeerSetPeers(fuzz_ice, &peers[0], 1);
	PeerSetHostCandidates(fuzz_ice, &b_addr, 1);
	UINT size = PeerSealSignal(fuzz_ice, fuzz_a_key.Public, PEER_SIGNAL_OFFER, env, sizeof(env));

	// A's answer gives the session the remote description; without it the session takes no check, and no seed reaches
	// agent_dispatch_stun
	FuzzPeerAnswer(env, size);

	return true;
}

// One input: a datagram from A and from a stranger, a datagram from A at a node with an ICE session with A, a signal
// envelope, a signal payload
static void FuzzPeer(const uint8_t *data, size_t size)
{
	PEER_SIGNAL sig;
	PEER_RECORD_INFO rec;
	PEER_HANDSHAKE_INFO hs;
	PEER_STATUS st;

	if (size == 0 || size > FUZZ_MAX_INPUT_SIZE || FuzzPeerSetup() == false)
	{
		return;
	}

	// B's ICE session with A again, once libjuice failed the last one
	if (PeerGetStatus(fuzz_ice, fuzz_a_key.Public, &st) && st.Ice == PEER_ICE_FAILED)
	{
		FuzzPeerIce();
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

	// At B with its ICE session with A: a copy of the input that names the username fragment of the session
	UCHAR *ice = malloc(size);
	if (ice != NULL)
	{
		memcpy(ice, data, size);
		FuzzPeerUfrag(ice, size);
		PeerInput(fuzz_ice, &fuzz_a_addr, ice, (UINT)size);
		free(ice);
	}

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
