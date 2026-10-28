// fuzz_nodeprofile.c
// libFuzzer target: the session profiles of the Node module (Cedar/NodeProfile.c, SDN-40 #233), which read the IP packets
// that the overlay sends to a peer (NodeProfileOutbound) and takes from one (NodeProfileInbound): their two addresses, the
// extension headers of IPv6 and the flags of TCP. An input is a list of packets, each after a byte that picks the way (bit
// 0: a packet of the host to the peer) and the next hop (bits 1 and 2: the peer under a profile, the peer under none, the
// next hop of a route that a VRF of the first leaks, and one that the tables do not have), and the size of the packet in 2
// bytes. The profile of the peer limits its uploads and downloads and the IPv4 and IPv6 addresses that its session sends
// from, and has no-routing, no-server and the privacy filter, as the node's own profile has, so the packets of one input
// fill the addresses of its session one after the other. Each input builds the profiles and the tables anew and frees them,
// so Mayaqua's leak check finds nothing left. Each packet is copied into a buffer of its size exactly, so that
// AddressSanitizer reports a read past it.
//
// fuzz-max-len: 4096

#include "fuzz_common.h"

#include "Cedar/CedarType.h"
#include "Cedar/Node.h"
#include "Cedar/NodeProfile.h"

#include "Mayaqua/Memory.h"

#include "Core/Control.h"

#include <stdlib.h>
#include <string.h>

// Largest input accepted; longer inputs are skipped
#define	FUZZ_MAX_INPUT_SIZE		4096

// The VRF of the node and of its peers, and the next hop that the tables do not have
#define	FUZZ_PROFILE_VRF		101
#define	FUZZ_PROFILE_NO_HOP		7

// The addresses of the node and of its two peers in the VRF: 10.0.0.1 to .3, and fd00::1 to ::3
static const UCHAR fuzz_profile_ipv4[3][4] = {{10, 0, 0, 1}, {10, 0, 0, 2}, {10, 0, 0, 3}};
static const UCHAR fuzz_profile_ipv6[3][16] =
{
	{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01},
	{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02},
	{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x03},
};

// The IPv4 and the IPv6 address of node i (0 the node, 1 and 2 its peers) into a: their number
static UINT FuzzProfileAddresses(CONTROL_ADDRESS *a, UINT i)
{
	memset(a, 0, sizeof(CONTROL_ADDRESS) * 2);
	a[0].VrfId = FUZZ_PROFILE_VRF;
	memcpy(a[0].Address, fuzz_profile_ipv4[i], 4);
	a[0].AddressSize = 4;
	a[0].Length = 24;
	a[1].VrfId = FUZZ_PROFILE_VRF;
	memcpy(a[1].Address, fuzz_profile_ipv6[i], 16);
	a[1].AddressSize = 16;
	a[1].Length = 64;

	return 2;
}

// A profile with every limit and every flag: 1 Mbit/s each way, 2 IPv4 addresses, 1 IPv6 address
static void FuzzProfileOf(CONTROL_PROFILE *p, const char *name)
{
	memset(p, 0, sizeof(CONTROL_PROFILE));
	p->Set = true;
	memcpy(p->Name, name, strlen(name) + 1);
	memcpy(p->User, "alice", 6);
	p->UploadLimit = 1000000;
	p->DownloadLimit = 1000000;
	p->MaxSessions = 1;
	p->MaxIpv4 = 2;
	p->MaxIpv6 = 1;
	p->IdleTimeout = 600;
	p->AutoDisconnect = 3600;
	p->NoRouting = true;
	p->NoServer = true;
	p->PrivacyFilter = true;
}

// One input: packets, each after the byte of its way and its next hop and its size
static void FuzzProfile(const uint8_t *data, size_t size)
{
	void *hops[3];

	if (size < 3 || size > FUZZ_MAX_INPUT_SIZE)
	{
		return;
	}

	// The node under a profile of its own, and its two peers: the first under a profile, the second under none
	CONTROL_STATE *st = ZeroMalloc(sizeof(CONTROL_STATE));
	st->Generation = 1;
	memcpy(st->Name, "node", 5);
	st->NumAddresses = FuzzProfileAddresses(st->Addresses, 0);
	FuzzProfileOf(&st->Profile, "own");
	st->Peers = ZeroMalloc(sizeof(CONTROL_PEER) * 2);
	st->NumPeers = 2;
	for (UINT i = 0;i < 2;i++)
	{
		CONTROL_PEER *p = &st->Peers[i];

		memcpy(p->Name, (i == 0 ? "peer-1" : "peer-2"), 7);
		memset(p->Key, 1 + i, sizeof(p->Key));
		p->NumVrfs = 1;
		p->VrfIds[0] = FUZZ_PROFILE_VRF;
		p->NumAddresses = FuzzProfileAddresses(p->Addresses, 1 + i);
	}
	FuzzProfileOf(&st->Peers[0].Profile, "laptops");

	// The next hops: the two peers, then a route that a VRF of the first leaks, which leads to it too
	hops[0] = &st->Peers[0];
	hops[1] = &st->Peers[1];
	hops[2] = &st->Peers[0];

	NODE *n = ZeroMalloc(sizeof(NODE));
	NodeProfileStart(n);

	NODE_VRF_TABLES *v = NodeNewVrfTables(1, NULL, 0, hops, 3);
	if (v != NULL)
	{
		NodeProfileAttach(n, v, st);

		for (size_t offset = 0;offset + 3 <= size;)
		{
			UINT pick = data[offset];
			UINT len = ((UINT)data[offset + 1] << 8) | data[offset + 2];
			UINT hop = (pick >> 1) & 0x03;

			offset += 3;
			len = (UINT)MIN((size_t)len, size - offset);

			// malloc() rather than Malloc(): the copy is exactly the packet, so AddressSanitizer reports any read past it
			UCHAR *packet = malloc(len != 0 ? len : 1);
			if (packet == NULL)
			{
				break;
			}
			memcpy(packet, data + offset, len);
			offset += len;

			if (hop == 3)
			{
				hop = FUZZ_PROFILE_NO_HOP;
			}
			if ((pick & 0x01) != 0)
			{
				NodeProfileOutbound(n, v, FUZZ_PROFILE_VRF, hop, packet, len);
			}
			else
			{
				NodeProfileInbound(n, v, FUZZ_PROFILE_VRF, hop, packet, len);
			}

			free(packet);
		}

		NodeFreeVrfTables(v);
	}

	NodeProfileStop(n);
	Free(n);
	Free(st->Peers);
	Free(st);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	FuzzRun(FuzzProfile, data, size);

	return 0;
}
