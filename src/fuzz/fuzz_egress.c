// fuzz_egress.c
// libFuzzer target: the internet exit of the Node module (Cedar/NodeEgress.c, SDN-12 #188), which reads the IPv4 packets
// that the peers of a VRF send to an address outside it (NodeEgressParse), gives their TCP segments and UDP datagrams the
// ends of the proxy and the host's answers back the ends that the peer reached (NodeEgressRewrite), writes the echo reply
// of an echo request (NodeEgressEchoReply) and refuses the destinations that are no address of the outside
// (NodeEgressRefuses). A segment or datagram that parses is given other ends and must parse again with them and with its
// protocol, its length and its payload where they were, a checksum that held before holding still; given its own ends
// back, its addresses and ports are the ones of the input again, with a checksum that holds as before. An echo request
// gives an echo reply that parses with its identifier and its sequence number. The input is copied into a buffer of its
// size exactly, so that AddressSanitizer reports a read past it.
//
// fuzz-max-len: 65536

#include "fuzz_common.h"

#include "Cedar/CedarType.h"
#include "Cedar/Node.h"
#include "Cedar/NodeEgress.h"

#include <stdlib.h>
#include <string.h>

// Largest input accepted: an IPv4 packet of the largest total length; longer inputs are skipped
#define	FUZZ_MAX_INPUT_SIZE		65536

// The ends that the proxy gives a segment or a datagram: the peer's address with another port, the address of the node
// in the VRF with the port of a listener
static const UCHAR fuzz_egress_peer[4] = {10, 0, 0, 7};
static const UCHAR fuzz_egress_listener[4] = {10, 0, 0, 1};

// The 16-bit one's complement sum of size bytes at data on top of sum
static UINT FuzzEgressSum(UINT sum, const UCHAR *data, UINT size)
{
	for (UINT i = 0; i + 1 < size; i += 2)
	{
		sum += ((UINT)data[i] << 8) | data[i + 1];
	}
	if (size % 2 != 0)
	{
		sum += (UINT)data[size - 1] << 8;
	}
	while ((sum >> 16) != 0)
	{
		sum = (sum & 0xFFFF) + (sum >> 16);
	}

	return sum;
}

// Whether the TCP or UDP checksum of the packet that p read at buf holds over its pseudo-header: a UDP datagram without
// one holds
static bool FuzzEgressValid(const UCHAR *buf, const NODE_EGRESS_PACKET *p)
{
	const UCHAR *l4 = buf + p->HeaderSize;
	UINT length = (p->Protocol == NODE_EGRESS_UDP ? (((UINT)l4[4] << 8) | l4[5]) : p->Total - p->HeaderSize);
	UCHAR pseudo[12];

	if (p->Protocol == NODE_EGRESS_UDP && l4[6] == 0 && l4[7] == 0)
	{
		return true;
	}

	memcpy(pseudo, buf + 12, 8);
	pseudo[8] = 0;
	pseudo[9] = (UCHAR)p->Protocol;
	pseudo[10] = (UCHAR)(length >> 8);
	pseudo[11] = (UCHAR)length;

	return (FuzzEgressSum(FuzzEgressSum(0, pseudo, sizeof(pseudo)), l4, length) == 0xFFFF);
}

// One input: an IPv4 packet of a peer
static void FuzzEgress(const uint8_t *data, size_t size)
{
	NODE_EGRESS_PACKET p;
	NODE_EGRESS_PACKET q;

	if (size < 1 || size > FUZZ_MAX_INPUT_SIZE)
	{
		return;
	}

	// malloc() rather than Malloc(): the copy is exactly the input, so AddressSanitizer reports any read past it
	UINT n = (UINT)size;
	UCHAR *buf = malloc(n);
	if (buf == NULL)
	{
		return;
	}
	memcpy(buf, data, n);

	if (n >= 20)
	{
		NodeEgressRefuses(buf + 16);
	}

	if (NodeEgressParse(buf, n, &p))
	{
		if (p.HeaderSize < 20 || p.Total > n || p.Total < p.HeaderSize || p.Payload > p.Total)
		{
			abort();
		}

		if (p.Protocol == NODE_EGRESS_TCP || p.Protocol == NODE_EGRESS_UDP)
		{
			bool valid = FuzzEgressValid(buf, &p);

			// The ends of the proxy: what goes into the adapter to its listener
			NodeEgressRewrite(buf, &p, fuzz_egress_peer, 40000, fuzz_egress_listener, 50000);
			if (NodeEgressParse(buf, n, &q) == false || q.Protocol != p.Protocol || q.Total != p.Total || q.Payload != p.Payload ||
				q.SrcPort != 40000 || q.DstPort != 50000 || memcmp(q.Src, fuzz_egress_peer, 4) != 0 || memcmp(q.Dst, fuzz_egress_listener, 4) != 0 ||
				(valid && FuzzEgressValid(buf, &q) == false))
			{
				abort();
			}

			// ... and back: the ends of the input
			NodeEgressRewrite(buf, &q, p.Src, p.SrcPort, p.Dst, p.DstPort);
			if (memcmp(buf + 12, data + 12, 8) != 0 || memcmp(buf + p.HeaderSize, data + p.HeaderSize, 4) != 0 || (valid && FuzzEgressValid(buf, &p) == false))
			{
				abort();
			}
		}

		if (p.Protocol == NODE_EGRESS_ICMP && p.IcmpType == NODE_EGRESS_ECHO_REQUEST && p.Total - p.Payload <= NODE_EGRESS_MAX_ECHO)
		{
			UCHAR reply[20 + 8 + NODE_EGRESS_MAX_ECHO];
			UINT size_echo = p.Total - p.Payload;
			UINT r = NodeEgressEchoReply(reply, sizeof(reply), p.Dst, p.Src, p.EchoId, p.EchoSeq, buf + p.Payload, size_echo);

			if (r != 28 + size_echo || NodeEgressParse(reply, r, &q) == false || q.Protocol != NODE_EGRESS_ICMP || q.IcmpType != NODE_EGRESS_ECHO_REPLY ||
				q.EchoId != p.EchoId || q.EchoSeq != p.EchoSeq || FuzzEgressSum(0, reply, 20) != 0xFFFF || FuzzEgressSum(0, reply + 20, r - 20) != 0xFFFF)
			{
				abort();
			}
		}
	}

	free(buf);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	FuzzRun(FuzzEgress, data, size);

	return 0;
}
