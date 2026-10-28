// fuzz_evpn.c
// libFuzzer target: the EVPN of a gateway node (Cedar/NodeEvpn.c, SDN-25 #201), which reads two kinds of bytes from outside
// the node: the messages of its BGP sidecar, one JSON object per line, as IP prefix routes of an EVPN VRF
// (NodeEvpnParseRoute), and the frames that the VTEPs of a fabric send on the L3 VNI of an EVPN VRF (NodeEvpnParseFrame,
// which reads the two ends of the packet of a frame with NodeEvpnEnds). The first byte of an input picks the parser: an even
// byte the messages, an odd one the frame. The messages are the rest of the input split at each newline, as the node splits
// what it reads, each copied into a buffer of its size and its NUL exactly; the frame is the rest of the input, copied into a
// buffer of its size exactly, so that AddressSanitizer reports a read past either. A route that a message gives has a VRF, a
// VNI of 24 bits and a prefix of IPv4 or IPv6 whose texts end within their fields, and a learned one a VTEP and the router
// MAC of one host; the packet of a frame that the parser takes lies behind the Ethernet header to the router MAC, to the end
// of the frame, and has two ends of one family.
//
// fuzz-max-len: 9217

#include "fuzz_common.h"

#include "Cedar/CedarType.h"
#include "Cedar/Node.h"
#include "Cedar/NodeEvpn.h"

#include <stdlib.h>
#include <string.h>

// The router MAC of the gateway that the frames of the input are for: the default of the node
static const UCHAR fuzz_evpn_router_mac[6] = {0x02, 0x52, 0x5A, 0x00, 0x00, 0x05};

// One message of the sidecar, without its newline
static void FuzzEvpnLine(const uint8_t *data, size_t size)
{
	NODE_EVPN_ROUTE *r = malloc(sizeof(NODE_EVPN_ROUTE));
	char *line = malloc(size + 1);

	if (r == NULL || line == NULL)
	{
		abort();
	}

	memcpy(line, data, size);
	line[size] = 0;

	UINT what = NodeEvpnParseRoute(line, r);
	if (what > NODE_EVPN_BAD)
	{
		abort();
	}

	if (what == NODE_EVPN_LEARNED || what == NODE_EVPN_WITHDRAWN)
	{
		if (r->VrfId == 0 || r->Vni == 0 || r->Vni > VXLAN_MAX_VNI || (r->AddressSize != 4 && r->AddressSize != 16) ||
			r->Length > r->AddressSize * 8 || strnlen(r->Prefix, sizeof(r->Prefix)) >= sizeof(r->Prefix) ||
			strnlen(r->Peer, sizeof(r->Peer)) >= sizeof(r->Peer))
		{
			abort();
		}
	}

	if (what == NODE_EVPN_LEARNED)
	{
		size_t next_hop = strnlen(r->NextHop, sizeof(r->NextHop));

		if (next_hop == 0 || next_hop >= sizeof(r->NextHop) || (r->RouterMac[0] & 0x01) != 0)
		{
			abort();
		}
	}

	free(line);
	free(r);
}

// The frame of the input
static void FuzzEvpnFrame(const uint8_t *data, size_t size)
{
	NODE_EVPN_FRAME f;

	// malloc() rather than Malloc(): the copy is exactly the frame, so AddressSanitizer reports any read past it
	UCHAR *frame = malloc(size != 0 ? size : 1);
	if (frame == NULL)
	{
		abort();
	}
	memcpy(frame, data, size);

	UINT parsed = NodeEvpnParseFrame(frame, (UINT)size, fuzz_evpn_router_mac, &f);
	if (parsed > NODE_EVPN_FRAME_MALFORMED)
	{
		abort();
	}

	if (parsed == NODE_EVPN_FRAME_OK)
	{
		if (f.Packet != frame + NODE_EVPN_ETHER || f.Size != size - NODE_EVPN_ETHER || (f.AddrSize != 4 && f.AddrSize != 16) ||
			memcmp(frame, fuzz_evpn_router_mac, 6) != 0)
		{
			abort();
		}
	}
	else if (f.Packet != NULL || f.Size != 0)
	{
		abort();
	}

	free(frame);
}

static void FuzzEvpn(const uint8_t *data, size_t size)
{
	size_t start = 1;

	if (size == 0)
	{
		return;
	}

	if ((data[0] & 0x01) != 0)
	{
		FuzzEvpnFrame(data + 1, size - 1);
		return;
	}

	for (size_t i = 1;i <= size;i++)
	{
		if (i == size || data[i] == '\n')
		{
			FuzzEvpnLine(data + start, i - start);
			start = i + 1;
		}
	}
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	FuzzRun(FuzzEvpn, data, size);

	return 0;
}
