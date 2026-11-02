// fuzz_tagmac.c
// libFuzzer target: the tag mode hmac of the overlay of a node (Cedar/NodeTagMac.c, SDN-88 #387), which checks the MAC of the
// source group of every datagram of a link of kind geneve of a VRF in that mode. Every input is a datagram from a tunnel endpoint
// of Geneve, copied into a buffer of its size exactly, so that AddressSanitizer reports a read past it. What the node does with
// it must hold:
// - the Geneve header (VxlanParseGeneve) and the option of the source group in it (VxlanParseGroupOption), in either of its
//   forms, make the claim that the link of a node makes (NodeSourceGroupClaim); the IP packet is what follows the header and the
//   Ethernet header of a frame of a link;
// - NodeTagMacHeaders gives no more bytes than the packet has, and each of them is read;
// - NodeTagMacCheck judges the claim with the two keys of VRF 101 at a fixed clock: a claim that it takes as authentic carries a
//   MAC under one of the keys and a timestamp within the window of the clock;
// - the group of the claim, signed by the node for the packet (NodeTagMacSign) with the key to send with, is authentic, and is
//   not once a bit of its MAC or of its tag set changes, or its timestamp leaves the window;
// - the same group on a link of kind vxlan goes without a source group, as VXLAN has no room for the MAC.
//
// fuzz-max-len: 9217
// fuzz-libs: corevxlan

#include "fuzz_common.h"

#include "Cedar/CedarType.h"
#include "Cedar/Node.h"
#include "Cedar/NodeLink.h"
#include "Cedar/NodeTagMac.h"

#include "Core/Control.h"
#include "Core/Vxlan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Largest input accepted: one byte above the largest datagram of the module; longer inputs are skipped
#define	FUZZ_MAX_INPUT_SIZE		(VXLAN_MAX_DATAGRAM + 1)
#define	FUZZ_TAGMAC_VRF			101			// The VRF of the link geneve in the tag mode hmac
#define	FUZZ_TAGMAC_VXLAN_VRF	103			// ... and one of the link vxlan
#define	FUZZ_TAGMAC_VNI			5101		// The VNI of the VRF, which the MAC covers
#define	FUZZ_TAGMAC_NOW			0x65000000	// The clock of the node, near which the seeds have their timestamps

// The sum of the bytes of the headers, so that the compiler keeps the reads
static volatile UINT fuzz_sum = 0;

// A property that does not hold: libFuzzer saves the input, with no abort message box and no Windows Error Reporting
static void FuzzFail(const char *what)
{
	fprintf(stderr, "==RANZ FUZZ== %s\n", what);
	fflush(stderr);
	_set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
	abort();
}

// The keys of the VRFs, as the state of a node gives them: in VRF 101 of the link geneve, key 1 of the bytes 0x00 to 0x1f and
// key 2 of the bytes 0x40 to 0x5f, which the node sends with; in VRF 103 of the link vxlan, key 1
static NODE_TAG_MAC_TABLE *FuzzTagMacTable()
{
	CONTROL_STATE *st = calloc(1, sizeof(CONTROL_STATE));
	NODE_TAG_MAC_TABLE *t;

	if (st == NULL)
	{
		return NULL;
	}

	st->NumVrfs = 2;
	for (UINT i = 0;i < 2;i++)
	{
		CONTROL_VRF *v = &st->Vrfs[i];

		v->Id = (i == 0 ? FUZZ_TAGMAC_VRF : FUZZ_TAGMAC_VXLAN_VRF);
		v->Vni = FUZZ_TAGMAC_VNI + 2 * i;
		v->Link = (i == 0 ? CONTROL_LINK_GENEVE : CONTROL_LINK_VXLAN);
		v->TagMode = CONTROL_TAG_MODE_HMAC;
		v->NumTagKeys = (i == 0 ? 2 : 1);
		for (UINT k = 0;k < v->NumTagKeys;k++)
		{
			v->TagKeys[k].Id = k + 1;
			v->TagKeys[k].Send = (k + 1 == v->NumTagKeys);
			for (UINT j = 0;j < CONTROL_TAG_KEY_SIZE;j++)
			{
				v->TagKeys[k].Key[j] = (UCHAR)(0x40 * k + j);
			}
		}
	}

	t = NodeTagMacNew(st);
	free(st);

	return t;
}

// Whether the claim that a link makes of the group g is authentic for the packet at the clock of the node
static bool FuzzTagMacAuthentic(NODE_TAG_MAC_TABLE *t, const VXLAN_GROUP *g, const UCHAR *packet, UINT size, UINT now)
{
	NODE_SOURCE_CLAIM claim;

	NodeSourceGroupClaim(&claim, NODE_CARRIER_GENEVE, g);
	NodeTagMacCheck(t, FUZZ_TAGMAC_VRF, packet, size, now, &claim);

	return claim.Authentic;
}

// One input: a datagram from a tunnel endpoint of Geneve
static void FuzzTagMac(const uint8_t *data, size_t size)
{
	GENEVE_HEADER h;
	VXLAN_GROUP g;
	NODE_SOURCE_CLAIM claim;

	if (size == 0 || size > FUZZ_MAX_INPUT_SIZE)
	{
		return;
	}

	NODE_TAG_MAC_TABLE *t = FuzzTagMacTable();
	// malloc() rather than Malloc(): the copy is exactly 'size' bytes, so AddressSanitizer reports any read past the end of
	// the input
	UCHAR *copy = malloc(size);
	if (t == NULL || copy == NULL)
	{
		NodeTagMacFree(t);
		free(copy);
		return;
	}
	memcpy(copy, data, size);

	// The datagram as the ingress of the module reads it, and its frame as the link of a node does
	if (VxlanParseGeneve(copy, (UINT)size, &h) && size >= NODE_LINK_ETHER && h.Size <= size - NODE_LINK_ETHER)
	{
		const UCHAR *packet = copy + h.Size + NODE_LINK_ETHER;
		UINT packet_size = (UINT)size - h.Size - NODE_LINK_ETHER;
		UINT sum = 0;

		memset(&g, 0, sizeof(g));
		for (UINT i = 0;i < h.NumOptions && g.Carried == false;i++)
		{
			VxlanParseGroupOption(&h.Options[i], &g);
		}

		UINT headers = NodeTagMacHeaders(packet, packet_size);
		if (headers > packet_size)
		{
			FuzzFail("NodeTagMacHeaders gave more bytes than the packet has");
		}
		for (UINT i = 0;i < headers;i++)
		{
			sum += packet[i];
		}
		fuzz_sum += sum;

		// The claim of the datagram, as a node of the VRF judges it
		NodeSourceGroupClaim(&claim, NODE_CARRIER_GENEVE, &g);
		NodeTagMacCheck(t, FUZZ_TAGMAC_VRF, packet, packet_size, FUZZ_TAGMAC_NOW, &claim);
		INT delta = (INT)(FUZZ_TAGMAC_NOW - claim.Time);
		if (claim.Authentic && (claim.HasMac == false || claim.KeyId < 1 || claim.KeyId > 2 || delta > NODE_TAG_MAC_WINDOW || delta < -NODE_TAG_MAC_WINDOW))
		{
			FuzzFail("NodeTagMacCheck took a claim without a MAC of a key of the VRF or with a timestamp outside the window");
		}

		// The group of the claim, signed by the node for the packet, is authentic, and not once it changes
		if (g.Carried)
		{
			VXLAN_GROUP s;

			memset(&s, 0, sizeof(s));
			s.Carried = true;
			s.HasTags = true;
			s.HasGeneration = true;
			s.Group = g.Group;
			s.Tags = g.Tags;
			s.Generation = g.Generation;
			if (NodeTagMacSign(t, FUZZ_TAGMAC_VRF, packet, packet_size, FUZZ_TAGMAC_NOW, &s) == false || s.HasMac == false || s.KeyId != 2 ||
				s.Time != FUZZ_TAGMAC_NOW)
			{
				FuzzFail("NodeTagMacSign did not sign a group of a VRF of the link geneve with the key to send with at the clock of the node");
			}
			if (FuzzTagMacAuthentic(t, &s, packet, packet_size, FUZZ_TAGMAC_NOW) == false)
			{
				FuzzFail("a group that the node signed is not authentic");
			}

			s.Mac[packet_size % GENEVE_GROUP_MAC_SIZE] ^= (UCHAR)(1 << (packet_size % 8));
			bool changed_mac = FuzzTagMacAuthentic(t, &s, packet, packet_size, FUZZ_TAGMAC_NOW);
			s.Mac[packet_size % GENEVE_GROUP_MAC_SIZE] ^= (UCHAR)(1 << (packet_size % 8));
			s.Tags ^= (1ULL << (packet_size % 64));
			bool changed_tags = FuzzTagMacAuthentic(t, &s, packet, packet_size, FUZZ_TAGMAC_NOW);
			s.Tags ^= (1ULL << (packet_size % 64));
			bool late = FuzzTagMacAuthentic(t, &s, packet, packet_size, FUZZ_TAGMAC_NOW + NODE_TAG_MAC_WINDOW + 1);
			if (changed_mac || changed_tags || late)
			{
				FuzzFail("a signed group whose MAC or tag set changed, or whose timestamp left the window, is authentic");
			}

			// A link of kind vxlan has no room for the MAC: the group goes without one
			memset(&s, 0, sizeof(s));
			s.Carried = true;
			s.Group = g.Group;
			if (NodeTagMacSign(t, FUZZ_TAGMAC_VXLAN_VRF, packet, packet_size, FUZZ_TAGMAC_NOW, &s) || s.Carried)
			{
				FuzzFail("NodeTagMacSign gave a group of a VRF of the link vxlan a MAC");
			}
		}
	}

	free(copy);
	NodeTagMacFree(t);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	FuzzRun(FuzzTagMac, data, size);

	return 0;
}
