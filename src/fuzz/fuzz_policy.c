// fuzz_policy.c
// libFuzzer target: the policy engine of the new core (Core/Policy.c, Core/PolicyRules.c, CORE-S4-2 #75), which reads the
// JSON documents of rules that the controller sends and the frames that the members of a Network send.
// - An input that starts with '{' is a document of rules: PolicyParseRules checks it, and PolicySetRules puts it in force
//   on an engine of its own, through which a fixed set of frames of its members then passes, so that the rules that the
//   input compiles are matched; the counters of the engine are then written as the JSON of the admin API and as the text
//   of the CLI.
// - Any other input is a frame for PolicyInput: its first byte chooses the member that sends it (bits 0 to 2, modulo the
//   7 members) and the member that it goes to (bits 3 to 5; 7 for an end outside the Network), its second byte moves the
//   clock on by tens of ms (0xFF also ages the conntrack tables after the frame), the low bits of its third byte choose
//   its VLAN, and the rest is the frame. It is judged by a fixed document of an L2 and an L3 Network whose members carry
//   every guard flag between them, with conntrack tables of 64 flows, so that inputs reach eviction, and with the
//   learning of the addresses that the checked members own. Every frame that passes is then offered to PolicyDeliver for
//   the member it goes to, or for every member when it goes to none, so that PolicyDeliver reads it to its last byte too.
//
// fuzz-max-len: 16384
// fuzz-libs: corepolicy

#include "fuzz_common.h"

#include "Core/Policy.h"

#include <stdlib.h>
#include <string.h>

// Largest input accepted; longer inputs are skipped
#define	FUZZ_MAX_INPUT_SIZE		16384

#define	FUZZ_NUM_MEMBERS		7				// The members of the engine of the frames
#define	FUZZ_AGE				0xFF			// The clock byte that ages the conntrack tables after the frame
#define	FUZZ_DOC_FRAMES			8				// The frames that pass through the engine of a fuzzed document

// The document of the engine of the frames
static const char fuzz_policy_doc[] =
	"{\"networks\": ["
	"{\"name\": \"lab\", \"mode\": \"l2\", \"maxFlows\": 64, \"timeouts\": {\"tcpEstablished\": 60, \"tcpTransitory\": 5, \"udp\": 3, \"icmp\": 2, \"other\": 4}},"
	"{\"name\": \"wan\", \"mode\": \"l3\", \"maxFlows\": 64}],"
	"\"addressGroups\": [{\"name\": \"servers\", \"addresses\": [\"10.0.0.0/24\", \"fd00::/64\"]}],"
	"\"rules\": ["
	"{\"name\": \"block-telnet\", \"action\": \"deny\", \"priority\": 5, \"protocol\": \"tcp\", \"ports\": [23]},"
	"{\"name\": \"staff-web\", \"action\": \"allow\", \"priority\": 10, \"from\": {\"groups\": [\"staff\"]}, \"to\": {\"addressGroups\": [\"servers\"]}, \"protocol\": \"tcp\", \"ports\": [80, 443, \"8000-8080\"]},"
	"{\"name\": \"dns\", \"action\": \"allow\", \"priority\": 20, \"protocol\": \"udp\", \"ports\": [53]},"
	"{\"name\": \"ping\", \"action\": \"allow\", \"priority\": 30, \"protocol\": \"icmp\", \"direction\": \"both\"},"
	"{\"name\": \"vlan-10\", \"action\": \"allow\", \"priority\": 40, \"networks\": [\"lab\"], \"vlans\": [10]},"
	"{\"name\": \"gateway\", \"action\": \"allow\", \"priority\": 50, \"networks\": [\"wan\"], \"from\": {\"tags\": [\"gateway\"]}},"
	"{\"name\": \"gre\", \"action\": \"allow\", \"priority\": 60, \"protocol\": 47},"
	"{\"name\": \"lan\", \"action\": \"allow\", \"priority\": 70, \"from\": {\"tags\": [\"lan\"]}, \"protocol\": \"any\", \"direction\": \"both\"}]}";

static POLICY_ENGINE *fuzz_frames = NULL;		// The engine of the frames
static POLICY_ENGINE *fuzz_docs = NULL;			// The engine of the fuzzed documents
static UINT fuzz_members[FUZZ_NUM_MEMBERS];
static UINT fuzz_doc_members[4];
static UINT64 fuzz_now = 1000;

// The frames that pass through the engine of a fuzzed document, and their sizes
static UCHAR fuzz_doc_frame[FUZZ_DOC_FRAMES][96];
static UINT fuzz_doc_size[FUZZ_DOC_FRAMES];

// A member of an engine
static UINT FuzzPolicyMember(POLICY_ENGINE *p, const char *network, const char *user, const char *group, const char *tag, UINT guard)
{
	POLICY_MEMBER_CONFIG c;
	const char *groups[1] = {group};
	const char *tags[1] = {tag};

	memset(&c, 0, sizeof(c));
	c.Network = network;
	c.User = user;
	c.Groups = groups;
	c.NumGroups = (group != NULL ? 1 : 0);
	c.Tags = tags;
	c.NumTags = (tag != NULL ? 1 : 0);
	c.Guard = guard;
	c.MaxMacs = 2;
	c.MaxIps = 4;

	return PolicyAddMember(p, &c);
}

// An IPv4 packet at f from 10.0.0.<src> to 10.0.0.<dst> of an IP protocol, with the transport header l4 of size bytes;
// its size
static UINT FuzzPolicyIpv4(UCHAR *f, UCHAR src, UCHAR dst, UCHAR protocol, const UCHAR *l4, UINT size)
{
	static const UCHAR header[20] = {0x45, 0, 0, 0, 0, 1, 0x40, 0, 64, 0, 0, 0, 10, 0, 0, 0, 10, 0, 0, 0};

	memcpy(f, header, sizeof(header));
	f[2] = (UCHAR)((20 + size) >> 8);
	f[3] = (UCHAR)(20 + size);
	f[9] = protocol;
	f[15] = src;
	f[19] = dst;
	memcpy(f + 20, l4, size);

	return 20 + size;
}

// An IPv6 packet at f from fd00::<src> to fd00::<dst>, as FuzzPolicyIpv4
static UINT FuzzPolicyIpv6(UCHAR *f, UCHAR src, UCHAR dst, UCHAR protocol, const UCHAR *l4, UINT size)
{
	memset(f, 0, 40);
	f[0] = 0x60;
	f[4] = (UCHAR)(size >> 8);
	f[5] = (UCHAR)size;
	f[6] = protocol;
	f[7] = 64;
	f[8] = 0xFD;
	f[23] = src;
	f[24] = 0xFD;
	f[39] = dst;
	memcpy(f + 40, l4, size);

	return 40 + size;
}

// An Ethernet frame at f from 02:00:00:00:00:<src> to 02:00:00:00:00:<dst> of an EtherType, with the packet that the
// procedure ip writes after its header; its size
static UINT FuzzPolicyEth(UCHAR *f, UCHAR src, UCHAR dst, USHORT type, UINT (*ip)(UCHAR *, UCHAR, UCHAR, UCHAR, const UCHAR *, UINT),
	UCHAR protocol, const UCHAR *l4, UINT size)
{
	static const UCHAR mac[6] = {0x02, 0, 0, 0, 0, 0};

	memcpy(f, mac, 6);
	f[5] = dst;
	memcpy(f + 6, mac, 6);
	f[11] = src;
	f[12] = (UCHAR)(type >> 8);
	f[13] = (UCHAR)type;

	return 14 + ip(f + 14, src, dst, protocol, l4, size);
}

// Once: the two engines, their members, the document of the frames and the frames of the fuzzed documents
static bool FuzzPolicySetup()
{
	static const UCHAR syn[20] = {0x9C, 0x40, 0x00, 0x50, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x02, 0xFF, 0xFF, 0, 0, 0, 0};
	static const UCHAR synack[20] = {0x00, 0x50, 0x9C, 0x40, 0, 0, 0, 9, 0, 0, 0, 2, 0x50, 0x12, 0xFF, 0xFF, 0, 0, 0, 0};
	static const UCHAR dns[12] = {0x9C, 0x41, 0x00, 0x35, 0x00, 0x0C, 0, 0, 0x12, 0x34, 0x01, 0x00};
	static const UCHAR echo[12] = {8, 0, 0, 0, 0x12, 0x34, 0, 1, 'p', 'i', 'n', 'g'};
	static const UCHAR echo6[12] = {128, 0, 0, 0, 0x12, 0x34, 0, 1, 'p', 'i', 'n', 'g'};
	static const UCHAR gre[4] = {0, 0, 0x08, 0x00};
	char error[256];

	if (fuzz_frames != NULL)
	{
		return true;
	}

	fuzz_frames = PolicyNew(16);
	fuzz_docs = PolicyNew(8);
	if (fuzz_frames == NULL || fuzz_docs == NULL)
	{
		return false;
	}

	fuzz_members[0] = FuzzPolicyMember(fuzz_frames, "lab", "alice", "staff", NULL,
		POLICY_GUARD_ISOLATE | POLICY_GUARD_CHECK_MAC | POLICY_GUARD_CHECK_IP | POLICY_GUARD_ARP_DHCP_ONLY | POLICY_GUARD_NO_DHCP_SERVER | POLICY_GUARD_NO_RA);
	fuzz_members[1] = FuzzPolicyMember(fuzz_frames, "lab", "bob", "staff", NULL, POLICY_GUARD_ISOLATE);
	fuzz_members[2] = FuzzPolicyMember(fuzz_frames, "lab", NULL, NULL, "lan", POLICY_GUARD_NO_IPV6);
	fuzz_members[3] = FuzzPolicyMember(fuzz_frames, "lab", NULL, NULL, "server", POLICY_GUARD_NO_NON_IP | POLICY_GUARD_CHECK_MAC);
	fuzz_members[4] = FuzzPolicyMember(fuzz_frames, "wan", "carol", NULL, NULL, POLICY_GUARD_CHECK_IP | POLICY_GUARD_NO_RA);
	fuzz_members[5] = FuzzPolicyMember(fuzz_frames, "wan", NULL, NULL, "gateway", POLICY_GUARD_NO_IPV4);
	fuzz_members[6] = FuzzPolicyMember(fuzz_frames, "wan", NULL, "staff", NULL, 0);

	fuzz_doc_members[0] = FuzzPolicyMember(fuzz_docs, "lab", "alice", "staff", NULL, POLICY_GUARD_CHECK_IP);
	fuzz_doc_members[1] = FuzzPolicyMember(fuzz_docs, "lab", "bob", NULL, "server", 0);
	fuzz_doc_members[2] = FuzzPolicyMember(fuzz_docs, "wan", "carol", "staff", NULL, 0);
	fuzz_doc_members[3] = FuzzPolicyMember(fuzz_docs, "wan", NULL, NULL, "gateway", POLICY_GUARD_ISOLATE);

	for (UINT i = 0; i < FUZZ_NUM_MEMBERS; i++)
	{
		if (fuzz_members[i] == POLICY_NO_MEMBER || (i < 4 && fuzz_doc_members[i] == POLICY_NO_MEMBER))
		{
			return false;
		}
	}

	// The frames of the fuzzed documents: L2 frames of lab between members 0 and 1, L3 packets of wan between 2 and 3
	fuzz_doc_size[0] = FuzzPolicyEth(fuzz_doc_frame[0], 1, 2, 0x0800, FuzzPolicyIpv4, 6, syn, sizeof(syn));
	fuzz_doc_size[1] = FuzzPolicyEth(fuzz_doc_frame[1], 2, 1, 0x0800, FuzzPolicyIpv4, 6, synack, sizeof(synack));
	fuzz_doc_size[2] = FuzzPolicyEth(fuzz_doc_frame[2], 1, 2, 0x0800, FuzzPolicyIpv4, 17, dns, sizeof(dns));
	fuzz_doc_size[3] = FuzzPolicyEth(fuzz_doc_frame[3], 1, 2, 0x0800, FuzzPolicyIpv4, 1, echo, sizeof(echo));
	fuzz_doc_size[4] = FuzzPolicyEth(fuzz_doc_frame[4], 1, 2, 0x88B5, FuzzPolicyIpv4, 47, gre, sizeof(gre));
	fuzz_doc_size[5] = FuzzPolicyIpv6(fuzz_doc_frame[5], 1, 2, 6, syn, sizeof(syn));
	fuzz_doc_size[6] = FuzzPolicyIpv6(fuzz_doc_frame[6], 2, 1, 58, echo6, sizeof(echo6));
	fuzz_doc_size[7] = FuzzPolicyIpv4(fuzz_doc_frame[7], 1, 2, 47, gre, sizeof(gre));

	return PolicySetRules(fuzz_frames, fuzz_policy_doc, (UINT)strlen(fuzz_policy_doc), error, sizeof(error));
}

// A document of rules: checked, put in force, and judged by the fixed frames
static void FuzzPolicyDocument(const uint8_t *data, size_t size)
{
	char error[256];

	PolicyParseRules((const char *)data, (UINT)size, error, sizeof(error));
	if (PolicySetRules(fuzz_docs, (const char *)data, (UINT)size, error, sizeof(error)) == false)
	{
		return;
	}

	for (UINT round = 0; round < 2; round++)
	{
		for (UINT i = 0; i < FUZZ_DOC_FRAMES; i++)
		{
			UINT from = (i < 5 ? fuzz_doc_members[(i == 1) ? 1 : 0] : fuzz_doc_members[(i == 6) ? 3 : 2]);
			UINT to = (i < 5 ? fuzz_doc_members[(i == 1) ? 0 : 1] : fuzz_doc_members[(i == 6) ? 2 : 3]);
			POLICY_RESULT r;

			if (PolicyInput(fuzz_docs, fuzz_now, from, to, (round == 0 ? 0 : 10), fuzz_doc_frame[i], fuzz_doc_size[i], &r))
			{
				PolicyDeliver(fuzz_docs, from, to, fuzz_doc_frame[i], fuzz_doc_size[i]);
			}
		}
		fuzz_now += 1000;
	}

	char *json = PolicyCountersJson(fuzz_docs);
	char *text = PolicyCountersText(fuzz_docs);
	PolicyFreeString(json);
	PolicyFreeString(text);
	PolicyAge(fuzz_docs, fuzz_now);
}

// A frame: the members, the step of the clock, the VLAN and the frame
static void FuzzPolicyFrame(const uint8_t *data, size_t size)
{
	static const UINT vlans[4] = {0, 10, 20, 100};
	POLICY_RESULT r;

	if (size < 3)
	{
		return;
	}

	// malloc() rather than Malloc(): the copy is exactly the size of the frame, so AddressSanitizer reports any read past
	// its end
	UINT frame_size = (UINT)size - 3;
	UCHAR *frame = malloc(frame_size != 0 ? frame_size : 1);
	if (frame == NULL)
	{
		return;
	}
	if (frame_size != 0)
	{
		memcpy(frame, data + 3, frame_size);
	}

	UINT from = fuzz_members[(data[0] & 7) % FUZZ_NUM_MEMBERS];
	UINT pick = (data[0] >> 3) & 7;
	UINT to = (pick < FUZZ_NUM_MEMBERS ? fuzz_members[pick] : POLICY_NO_MEMBER);

	// A frame to an end outside the Network, or to a group address, is offered to every member as the switch offers it
	fuzz_now += (UINT64)data[1] * 10;
	if (PolicyInput(fuzz_frames, fuzz_now, from, to, vlans[data[2] & 3], frame, frame_size, &r))
	{
		for (UINT i = 0; i < FUZZ_NUM_MEMBERS; i++)
		{
			if (to == POLICY_NO_MEMBER || to == fuzz_members[i])
			{
				PolicyDeliver(fuzz_frames, from, fuzz_members[i], frame, frame_size);
			}
		}
	}
	if (data[1] == FUZZ_AGE)
	{
		PolicyAge(fuzz_frames, fuzz_now);
	}

	free(frame);
}

// One input: a document when it starts with '{', else a frame
static void FuzzPolicy(const uint8_t *data, size_t size)
{
	if (size == 0 || size > FUZZ_MAX_INPUT_SIZE || FuzzPolicySetup() == false)
	{
		return;
	}

	if (data[0] == '{')
	{
		FuzzPolicyDocument(data, size);
	}
	else
	{
		FuzzPolicyFrame(data, size);
	}
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	FuzzRun(FuzzPolicy, data, size);

	return 0;
}
