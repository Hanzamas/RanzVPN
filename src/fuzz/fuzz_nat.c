// fuzz_nat.c
// libFuzzer target: the 1:1 NAT and 4via6 of the Node module (Cedar/NodeNat.c, SDN-6 #182), which read the IP packets
// of the host (NodeNatEnds, NodeNatCopy) and of the peers (NodeNatInbound), ICMP errors with the packets they quote
// among them. The first byte of an input picks the VRF (its two low bits) and the way (bit 2: into the overlay); the
// rest is the packet. The rules: none in VRF 0, the 4via6 of VRF 1, 1:1 NAT of IPv4 and of IPv6 in VRF 2, and the
// 4via6 of VRF 3 with a 1:1 NAT rule of IPv4 behind it. Each input builds the rules and the tables anew and frees
// them, so Mayaqua's leak check finds nothing left. The packet is copied into a buffer of its size exactly, so that
// AddressSanitizer reports a read past it; a packet that NodeNatEnds takes goes into a record of its own size, which
// the translation must not outgrow, and one of a peer into a buffer of its size and NODE_NAT_GROWTH.

#include "fuzz_common.h"

#include "Cedar/CedarType.h"
#include "Cedar/Node.h"

#include "Core/Control.h"

#include <stdlib.h>
#include <string.h>

// Largest input accepted: the way and VRF byte and a packet that a jumbo frame holds; longer inputs are skipped
#define	FUZZ_MAX_INPUT_SIZE		(1 + 9216)

// The prefixes of the rules
static const UCHAR fuzz_nat_4via6_1[16] = {0xfd, 0x00, 0x00, 0x01, 0x00, 0x00, 0xff, 0xff};	// fd00:1:0:ffff::/96
static const UCHAR fuzz_nat_4via6_3[16] = {0xfd, 0x00, 0x00, 0x03, 0x00, 0x00, 0xff, 0xff};	// fd00:3:0:ffff::/96
static const UCHAR fuzz_nat_any[4] = {0, 0, 0, 0};											// 0.0.0.0/0
static const UCHAR fuzz_nat_lan[4] = {192, 168, 1, 0};										// 192.168.1.0/24 ...
static const UCHAR fuzz_nat_lan_out[4] = {10, 99, 1, 0};									// ... as 10.99.1.0/24
static const UCHAR fuzz_nat_lan6[16] = {0xfd, 0x00, 0x00, 0x07};							// fd00:7::/64 ...
static const UCHAR fuzz_nat_lan6_out[16] = {0xfd, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x99};	// ... as fd00:2:0:99::/64
static const UCHAR fuzz_nat_behind[4] = {10, 4, 0, 0};										// 10.4.0.0/24 ...
static const UCHAR fuzz_nat_behind_out[4] = {10, 204, 0, 0};								// ... as 10.204.0.0/24

// Add one rule to the state
static void FuzzNatRule(CONTROL_STATE *st, UINT vrf_id, const UCHAR *inside, UINT inside_size, UINT inside_length, const UCHAR *outside, UINT outside_size, UINT outside_length)
{
	CONTROL_NAT *c = &st->Nats[st->NumNats++];

	c->VrfId = vrf_id;
	memcpy(c->Inside, inside, inside_size);
	c->InsideSize = inside_size;
	c->InsideLength = inside_length;
	memcpy(c->Outside, outside, outside_size);
	c->OutsideSize = outside_size;
	c->OutsideLength = outside_length;
}

// One input: the way and the VRF, then a packet
static void FuzzNat(const uint8_t *data, size_t size)
{
	CONTROL_STATE st;
	UCHAR src[16], dst[16];
	UINT addr_size = 0;

	if (size < 2 || size > FUZZ_MAX_INPUT_SIZE)
	{
		return;
	}

	memset(&st, 0, sizeof(st));
	FuzzNatRule(&st, 1, fuzz_nat_4via6_1, 16, 96, fuzz_nat_any, 4, 0);
	FuzzNatRule(&st, 2, fuzz_nat_lan, 4, 24, fuzz_nat_lan_out, 4, 24);
	FuzzNatRule(&st, 2, fuzz_nat_lan6, 16, 64, fuzz_nat_lan6_out, 16, 64);
	FuzzNatRule(&st, 3, fuzz_nat_4via6_3, 16, 96, fuzz_nat_any, 4, 0);
	FuzzNatRule(&st, 3, fuzz_nat_behind, 4, 24, fuzz_nat_behind_out, 4, 24);

	NODE_VRF_TABLES *v = NodeNewVrfTables(1, NULL, 0, NULL, 0);
	if (v == NULL)
	{
		return;
	}
	v->Nat = NodeNewNat(&st);

	UINT vrf_id = data[0] & 0x03;
	bool out = ((data[0] & 0x04) != 0);
	UINT packet_size = (UINT)size - 1;

	// malloc() rather than Malloc(): the copy is exactly the packet, so AddressSanitizer reports any read past it
	UCHAR *packet = malloc(packet_size);
	if (packet != NULL)
	{
		memcpy(packet, data + 1, packet_size);

		if (out && NodeNatEnds(v, vrf_id, packet, packet_size, src, dst, &addr_size))
		{
			UCHAR *record = malloc(packet_size);

			if (record != NULL)
			{
				// What NodeNatEnds takes NodeNatCopy writes, never larger than the packet
				UINT n = NodeNatCopy(v, vrf_id, record, packet, packet_size);
				if (n == 0 || n > packet_size || (addr_size != 4 && addr_size != 16))
				{
					abort();
				}
				free(record);
			}
		}
		else if (out == false)
		{
			UINT buf_size = packet_size + NODE_NAT_GROWTH;
			UCHAR *buf = malloc(buf_size);
			const UCHAR *p = packet;
			UINT n = packet_size;

			if (buf != NULL && NodeNatInbound(v, vrf_id, &p, &n, buf, buf_size) && p == buf && n > buf_size)
			{
				abort();
			}
			free(buf);
		}

		free(packet);
	}

	NodeFreeVrfTables(v);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	FuzzRun(FuzzNat, data, size);

	return 0;
}
