// fuzz_routed.c
// libFuzzer target: the routed networks of the server role of the Node module (Cedar/NodeRouted.c, CORE-S6-1 #80), which read
// the frames that the host sends out of the KM-TEST adapter of a routed network (NodeRoutedParseFrame), answer its ARP
// requests and Neighbor Solicitations (NodeRoutedAnswer), take the IP packets of the members of the network into frames for
// the host (NodeRoutedFrame), and read the Routed setting of the configuration store (NodeRoutedParseSetting), whose IPv4
// gateways give the supernet of the NAT (NodeRoutedSupernet). The network is 198.18.81.0/24 and fd81:a::/64, with the gateways
// 198.18.81.1 and fd81:a::1. The first byte of an input, modulo 3, picks what the rest is: 0, a frame of the host; 1, a packet
// of a member; 2, the setting as text, read for the network lab.
// - A frame that reads as an IP packet to the member side lies within the input. One that reads as an ARP request or a
//   Neighbor Solicitation gets an answer of the fixed size of its kind, from the member side, which reads again as nothing
//   that the port answers.
// - A packet that becomes a frame gives one from the member side to the adapter, no shorter than the shortest Ethernet frame
//   and no longer than the largest frame of the L2 adapter, which holds the packet after its Ethernet header.
// - A setting that is taken gives one to NODE_ROUTED_MAX_GATEWAYS gateways, each of 4 or 16 bytes with a prefix length that
//   leaves room for members; one that is not gives none and no NAT.
// The rest of the input is copied into a buffer of its size exactly, so that AddressSanitizer reports a read past it.
//
// fuzz-max-len: 4096

#include "fuzz_common.h"

#include "Cedar/CedarType.h"
#include "Cedar/Node.h"
#include "Cedar/NodeRouted.h"

#include <stdlib.h>
#include <string.h>

// Largest input accepted: the kind byte and a setting of a few networks; longer inputs are skipped
#define	FUZZ_MAX_INPUT_SIZE		4096

// The MAC addresses of the adapter and of the member side of its port
static const UCHAR fuzz_adapter_mac[6] = {0x02, 0x52, 0x4F, 0x55, 0x54, 0x45};
static const UCHAR fuzz_member_mac[6] = {0x02, 0x52, 0x4F, 0x55, 0x54, 0x44};

// The gateways of the network: 198.18.81.1/24 and fd81:a::1/64
static void FuzzRoutedGateways(NODE_ROUTED_GATEWAY *gw)
{
	memset(gw, 0, sizeof(NODE_ROUTED_GATEWAY) * 2);
	gw[0].Size = 4;
	gw[0].Address[0] = 198;
	gw[0].Address[1] = 18;
	gw[0].Address[2] = 81;
	gw[0].Address[3] = 1;
	gw[0].Length = 24;
	gw[1].Size = 16;
	gw[1].Address[0] = 0xFD;
	gw[1].Address[1] = 0x81;
	gw[1].Address[3] = 0x0A;
	gw[1].Address[15] = 0x01;
	gw[1].Length = 64;
}

// A frame of the host
static void FuzzRoutedFrame(const UCHAR *buf, UINT n, const NODE_ROUTED_GATEWAY *gw)
{
	NODE_ROUTED_FRAME f;
	NODE_ROUTED_FRAME g;
	UCHAR answer[NODE_ROUTED_NA_SIZE];

	UINT kind = NodeRoutedParseFrame(buf, n, fuzz_member_mac, gw, 2, &f);
	if (kind != f.Kind)
	{
		abort();
	}

	if (kind == NODE_ROUTED_FRAME_IP)
	{
		if (f.Offset != NODE_ROUTED_ETHER || f.Size < 20 || f.Offset + f.Size > n)
		{
			abort();
		}
	}
	else if (kind == NODE_ROUTED_FRAME_ARP || kind == NODE_ROUTED_FRAME_NS)
	{
		UINT len = NodeRoutedAnswer(answer, sizeof(answer), &f, fuzz_member_mac);

		if (len != (kind == NODE_ROUTED_FRAME_ARP ? 60 : NODE_ROUTED_NA_SIZE) || memcmp(answer + 6, fuzz_member_mac, 6) != 0)
		{
			abort();
		}

		// An answer is no question: the port never answers its own answer
		UINT again = NodeRoutedParseFrame(answer, len, fuzz_member_mac, gw, 2, &g);
		if (again == NODE_ROUTED_FRAME_ARP || again == NODE_ROUTED_FRAME_NS)
		{
			abort();
		}
	}
	else if (kind != NODE_ROUTED_FRAME_OTHER)
	{
		abort();
	}
}

// A packet of a member
static void FuzzRoutedPacket(const UCHAR *buf, UINT n, const NODE_ROUTED_GATEWAY *gw)
{
	UCHAR frame[NODE_L2_MAX_FRAME];

	UINT len = NodeRoutedFrame(frame, sizeof(frame), buf, n, fuzz_adapter_mac, fuzz_member_mac, gw, 2);
	if (len == 0)
	{
		return;
	}

	// The packet is at least an IPv4 header, which the frame holds after its Ethernet header; a frame of a short packet is
	// padded to the shortest Ethernet frame
	if (len < 60 || len > NODE_L2_MAX_FRAME || memcmp(frame, fuzz_adapter_mac, 6) != 0 || memcmp(frame + 6, fuzz_member_mac, 6) != 0 ||
		memcmp(frame + NODE_ROUTED_ETHER, buf, 20) != 0)
	{
		abort();
	}
}

// The Routed setting, as text
static void FuzzRoutedSetting(const UCHAR *buf, UINT n)
{
	NODE_ROUTED_GATEWAY gw[NODE_ROUTED_MAX_GATEWAYS];
	UCHAR super[4];
	UINT num = 99;
	bool nat = true;

	char *text = malloc(n + 1);
	if (text == NULL)
	{
		return;
	}
	memcpy(text, buf, n);
	text[n] = 0;

	if (NodeRoutedParseSetting(text, "lab", gw, &num, &nat))
	{
		if (num == 0 || num > NODE_ROUTED_MAX_GATEWAYS)
		{
			abort();
		}
		for (UINT i = 0;i < num;i++)
		{
			if ((gw[i].Size != 4 && gw[i].Size != 16) || (gw[i].Size == 4 && (gw[i].Length < 8 || gw[i].Length > 30)) ||
				(gw[i].Size == 16 && (gw[i].Length < 16 || gw[i].Length > 126)))
			{
				abort();
			}
		}
		if (NodeRoutedSupernet(gw, num, super) > 30)
		{
			abort();
		}
	}
	else if (num != 0 || nat)
	{
		abort();
	}

	free(text);
}

// One input: the kind, then a frame, a packet or the setting
static void FuzzRouted(const uint8_t *data, size_t size)
{
	NODE_ROUTED_GATEWAY gw[2];

	if (size < 1 || size > FUZZ_MAX_INPUT_SIZE)
	{
		return;
	}

	// malloc() rather than Malloc(): the copy is exactly the rest of the input, so AddressSanitizer reports any read past it
	UINT n = (UINT)size - 1;
	UCHAR *buf = malloc(n != 0 ? n : 1);
	if (buf == NULL)
	{
		return;
	}
	memcpy(buf, data + 1, n);
	FuzzRoutedGateways(gw);

	switch (data[0] % 3)
	{
	case 0:
		FuzzRoutedFrame(buf, n, gw);
		break;
	case 1:
		FuzzRoutedPacket(buf, n, gw);
		break;
	default:
		FuzzRoutedSetting(buf, n);
		break;
	}

	free(buf);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	FuzzRun(FuzzRouted, data, size);

	return 0;
}
