// fuzz_evpn.c
// libFuzzer target: the EVPN of a gateway node (Cedar/NodeEvpn.c, SDN-25 #201), which reads two kinds of bytes from outside
// the node: the messages of its BGP sidecar, one JSON object per line, as IP prefix routes of an EVPN VRF
// (NodeEvpnParseRoute), and the frames that the VTEPs of a fabric send on the L3 VNI of an EVPN VRF (NodeEvpnParseFrame,
// which reads the two ends of the packet of a frame with NodeEvpnEnds), which the gateway takes only from a VTEP that it knows
// for the VRF, the VTEP of a route of the VRF that it learned (NodeEvpnSortVteps, NodeEvpnHasVtep; SDN-25-R1 #549), and the
// stretch messages of the sidecar, the type-2 and type-3 routes of the fabric on the L2 VNIs of the stretches of the gateway
// (NodeStretchParseRoutes; Cedar/NodeStretch.c, SDN-64 #291). The first byte of an input, modulo 4, picks what the rest is: 0,
// the messages; 1, the frame; 2, the outer source of a frame and the messages of the routes that the gateway learned; 3, the
// stretch messages. A route of a stretch message that the parser takes has a VNI of 24 bits, and a type-3 route no MAC address
// and no IP address, a type-2 route the MAC address of one host and an IP address of 4 or 16 bytes or none; a parser of no room
// takes no route. The messages are the rest of the input split at each newline, as the node
// splits what it reads, each copied into a buffer of its size and its NUL exactly; the frame is the rest of the input, copied
// into a buffer of its size exactly, so that AddressSanitizer reports a read past either. A route that a message gives has a
// VRF, a VNI of 24 bits and a prefix of IPv4 or IPv6 whose texts end within their fields, and a learned one a VTEP, the
// router MAC of one host and NODE_EVPN_MAX_OFFERS vteps at most (SDN-25-R3 #571), a withdrawn one none; the packet of a frame
// that the parser takes lies behind the Ethernet header to the router MAC, to the end of the frame, and has two ends of one
// family. The outer source is the VRF of the frame (4 bytes, big-endian) and the address that it came from (16 bytes, an IPv4
// address as an IPv4-mapped one), and the messages follow: the VTEPs of the learned routes, sorted and each copied into a
// buffer of their number exactly, hold the VTEP and the vteps of each learned route with its VRF once, in order, and the
// gateway knows the address for the VRF exactly when a learned route of the VRF has it as its VTEP or among its vteps.
// The seeds vtep_*.bin reach the sort and the check of the VTEPs, and the replay of run_fuzzers.ps1 fails when they no longer
// do, by the two reach lines below (SDN-25-R3, #571).
//
// fuzz-max-len: 9217
// fuzz-reach: NodeEvpnSortVteps
// fuzz-reach: NodeEvpnHasVtep

#include "fuzz_common.h"

#include "Cedar/CedarType.h"
#include "Cedar/Node.h"
#include "Cedar/NodeEvpn.h"

#include <stdlib.h>
#include <string.h>

// The VRF and the address of the outer source of a frame, in front of the messages
#define	FUZZ_EVPN_SOURCE		(4 + 16)

// The VTEPs of one learned route at most: its VTEP and its vteps
#define	FUZZ_EVPN_PER_ROUTE		(1 + NODE_EVPN_MAX_OFFERS)

// The router MAC of the gateway that the frames of the input are for: the default of the node
static const UCHAR fuzz_evpn_router_mac[6] = {0x02, 0x52, 0x5A, 0x00, 0x00, 0x05};

// One message of the sidecar, without its newline, into r: what NodeEvpnParseRoute finds in it
static UINT FuzzEvpnLine(const uint8_t *data, size_t size, NODE_EVPN_ROUTE *r)
{
	char *line = malloc(size + 1);

	if (line == NULL)
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

		if (next_hop == 0 || next_hop >= sizeof(r->NextHop) || (r->RouterMac[0] & 0x01) != 0 || r->NumVteps > NODE_EVPN_MAX_OFFERS)
		{
			abort();
		}
	}
	else if (r->NumVteps != 0)
	{
		abort();
	}

	free(line);

	return what;
}

// The messages of data, size bytes, split at each newline: the VTEP and the vteps of each learned route with its VRF into
// vteps, which has room for FUZZ_EVPN_PER_ROUTE per message, unless it is NULL; their number
static size_t FuzzEvpnMessages(const uint8_t *data, size_t size, NODE_EVPN_VTEP *vteps)
{
	NODE_EVPN_ROUTE *r = malloc(sizeof(NODE_EVPN_ROUTE));
	size_t start = 0;
	size_t num = 0;

	if (r == NULL)
	{
		abort();
	}

	for (size_t i = 0;i <= size;i++)
	{
		if (i == size || data[i] == '\n')
		{
			if (FuzzEvpnLine(data + start, i - start, r) == NODE_EVPN_LEARNED && vteps != NULL)
			{
				vteps[num].VrfId = r->VrfId;
				memcpy(vteps[num].Ip, r->Vtep, sizeof(vteps[num].Ip));
				num++;
				for (UINT j = 0;j < r->NumVteps;j++)
				{
					vteps[num].VrfId = r->VrfId;
					memcpy(vteps[num].Ip, r->Vteps[j], sizeof(vteps[num].Ip));
					num++;
				}
			}
			start = i + 1;
		}
	}

	free(r);

	return num;
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

// The order of NodeEvpnSortVteps: by VRF, then by address
static int FuzzEvpnCompareVtep(const NODE_EVPN_VTEP *a, const NODE_EVPN_VTEP *b)
{
	if (a->VrfId != b->VrfId)
	{
		return (a->VrfId < b->VrfId ? -1 : 1);
	}

	return memcmp(a->Ip, b->Ip, sizeof(a->Ip));
}

// Whether a VTEP of the VRF vrf_id with the address ip is among the num VTEPs of list, in any order: what NodeEvpnHasVtep must
// find in the sorted ones
static bool FuzzEvpnListed(const NODE_EVPN_VTEP *list, size_t num, UINT vrf_id, const UCHAR *ip)
{
	for (size_t i = 0;i < num;i++)
	{
		if (list[i].VrfId == vrf_id && memcmp(list[i].Ip, ip, sizeof(list[i].Ip)) == 0)
		{
			return true;
		}
	}

	return false;
}

// The outer source of a frame against the VTEPs of the learned routes of the messages
static void FuzzEvpnVteps(const uint8_t *data, size_t size)
{
	size_t lines = 1;

	if (size < FUZZ_EVPN_SOURCE)
	{
		return;
	}

	UINT vrf_id = ((UINT)data[0] << 24) | ((UINT)data[1] << 16) | ((UINT)data[2] << 8) | (UINT)data[3];
	UCHAR *source = malloc(16);
	if (source == NULL)
	{
		abort();
	}
	memcpy(source, data + 4, 16);

	for (size_t i = FUZZ_EVPN_SOURCE;i < size;i++)
	{
		if (data[i] == '\n')
		{
			lines++;
		}
	}

	NODE_EVPN_VTEP *learned = malloc(sizeof(NODE_EVPN_VTEP) * lines * FUZZ_EVPN_PER_ROUTE);
	NODE_EVPN_VTEP *sorted = malloc(sizeof(NODE_EVPN_VTEP) * lines * FUZZ_EVPN_PER_ROUTE);
	if (learned == NULL || sorted == NULL)
	{
		abort();
	}

	size_t num = FuzzEvpnMessages(data + FUZZ_EVPN_SOURCE, size - FUZZ_EVPN_SOURCE, learned);
	if (num > lines * FUZZ_EVPN_PER_ROUTE)
	{
		abort();
	}
	memcpy(sorted, learned, sizeof(NODE_EVPN_VTEP) * num);

	// The VTEPs that the gateway knows, each in a buffer of their number exactly, so that AddressSanitizer reports a read past them
	UINT known = NodeEvpnSortVteps(sorted, (UINT)num);
	if (known > num || (num != 0 && known == 0))
	{
		abort();
	}

	NODE_EVPN_VTEP *vteps = malloc(sizeof(NODE_EVPN_VTEP) * (known != 0 ? known : 1));
	if (vteps == NULL)
	{
		abort();
	}
	memcpy(vteps, sorted, sizeof(NODE_EVPN_VTEP) * known);

	// In order, each once, and each a VTEP of a learned route of its VRF
	for (UINT i = 0;i < known;i++)
	{
		if ((i != 0 && FuzzEvpnCompareVtep(&vteps[i - 1], &vteps[i]) >= 0) || FuzzEvpnListed(learned, num, vteps[i].VrfId, vteps[i].Ip) == false)
		{
			abort();
		}
	}

	// The VTEP of each learned route is known for its VRF, and the outer source exactly when a learned route of its VRF has it
	for (size_t i = 0;i < num;i++)
	{
		if (NodeEvpnHasVtep(vteps, known, learned[i].VrfId, learned[i].Ip) == false)
		{
			abort();
		}
	}

	if (NodeEvpnHasVtep(vteps, known, vrf_id, source) != FuzzEvpnListed(learned, num, vrf_id, source))
	{
		abort();
	}

	free(vteps);
	free(sorted);
	free(learned);
	free(source);
}

// One stretch message of the sidecar, without its newline: what NodeStretchParseRoutes finds in it, with room for
// NODE_STRETCH_MAX_ROUTES routes in list and with none
static void FuzzEvpnStretchLine(const uint8_t *data, size_t size, NODE_STRETCH_ROUTE *list)
{
	static const UCHAR zero[6] = {0};
	char *line = malloc(size + 1);
	UINT bad = 0;

	if (line == NULL)
	{
		abort();
	}

	memcpy(line, data, size);
	line[size] = 0;

	UINT num = NodeStretchParseRoutes(line, list, NODE_STRETCH_MAX_ROUTES, &bad);
	if (num == NODE_STRETCH_NO_MESSAGE)
	{
		if (bad != 0)
		{
			abort();
		}
	}
	else if (num > NODE_STRETCH_MAX_ROUTES)
	{
		abort();
	}

	for (UINT i = 0;num != NODE_STRETCH_NO_MESSAGE && i < num;i++)
	{
		const NODE_STRETCH_ROUTE *r = &list[i];

		if (r->Vni == 0 || r->Vni > VXLAN_MAX_VNI || (r->IpSize != 0 && r->IpSize != 4 && r->IpSize != 16) ||
			(r->Imet && (r->IpSize != 0 || memcmp(r->Mac, zero, sizeof(zero)) != 0)) ||
			(r->Imet == false && ((r->Mac[0] & 0x01) != 0 || memcmp(r->Mac, zero, sizeof(zero)) == 0)))
		{
			abort();
		}
	}

	// A parser of no room takes no route
	num = NodeStretchParseRoutes(line, NULL, 0, &bad);
	if (num != 0 && num != NODE_STRETCH_NO_MESSAGE)
	{
		abort();
	}

	free(line);
}

// The stretch messages of the input, split at each newline
static void FuzzEvpnStretch(const uint8_t *data, size_t size)
{
	NODE_STRETCH_ROUTE *list = malloc(sizeof(NODE_STRETCH_ROUTE) * NODE_STRETCH_MAX_ROUTES);
	size_t start = 0;

	if (list == NULL)
	{
		abort();
	}

	for (size_t i = 0;i <= size;i++)
	{
		if (i == size || data[i] == '\n')
		{
			FuzzEvpnStretchLine(data + start, i - start, list);
			start = i + 1;
		}
	}

	free(list);
}

static void FuzzEvpn(const uint8_t *data, size_t size)
{
	if (size == 0)
	{
		return;
	}

	switch (data[0] % 4)
	{
	case 0:
		FuzzEvpnMessages(data + 1, size - 1, NULL);
		break;
	case 1:
		FuzzEvpnFrame(data + 1, size - 1);
		break;
	case 2:
		FuzzEvpnVteps(data + 1, size - 1);
		break;
	default:
		FuzzEvpnStretch(data + 1, size - 1);
		break;
	}
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	FuzzRun(FuzzEvpn, data, size);

	return 0;
}
