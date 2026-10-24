// fuzz_mirror.c
// libFuzzer target: the Mirrors of the Node module (Cedar/NodeMirror.c, SDN-23 #199), which read the IP packets that
// the overlay sends to a peer and delivers to the host (NodeMirrorCopy): the IPv4 header, the IPv6 extension headers and
// the ports of TCP and UDP, to find the Mirrors that take a packet. The first byte of an input picks the VRF (its two
// low bits) and the way (bit 2: a packet of the host); the rest is the packet. The Mirrors: UDP port 53 in VRF 101, TCP
// port 8080 in every VRF under a rate limit, ICMP in VRF 202 to an IPv6 sensor, and every packet of every VRF; the
// fourth VRF has an id of 25 bits, which no VNI holds. Each input builds the Mirrors and the tables anew and frees them,
// so Mayaqua's leak check finds nothing left. The packet is copied into a buffer of its size exactly, so that
// AddressSanitizer reports a read past it, and the send procedure checks that each datagram is the VXLAN header, the
// Ethernet header of the IP version of the packet, and the packet.
//
// fuzz-max-len: 9217

#include "fuzz_common.h"

#include "Cedar/CedarType.h"
#include "Cedar/Node.h"

#include "Core/Control.h"

#include <stdlib.h>
#include <string.h>

// Largest input accepted: the way and VRF byte and a packet that a jumbo frame holds; longer inputs are skipped
#define	FUZZ_MAX_INPUT_SIZE		(1 + VXLAN_MAX_DATAGRAM)

// The VRFs by the two low bits of the first byte: the last has an id of 25 bits
static const UINT fuzz_mirror_vrf_ids[4] = {101, 202, 303, 0x1000000};

// The sensors
static const UCHAR fuzz_mirror_sensor4[4] = {192, 0, 2, 50};														// 192.0.2.50
static const UCHAR fuzz_mirror_sensor6[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x05};	// 2001:db8::5

// The packet of the input, which each datagram of the send procedure carries
typedef struct FUZZ_MIRROR_PACKET
{
	const UCHAR *Packet;
	UINT Size;
} FUZZ_MIRROR_PACKET;

// The send procedure of the Mirrors: each datagram must be the VXLAN header with the I flag, the Ethernet header with
// the EtherType of the IP version of the packet, and the packet; it goes nowhere
static bool FuzzMirrorSend(void *param, const VXLAN_ADDR *dst, const void *data, UINT size)
{
	FUZZ_MIRROR_PACKET *p = (FUZZ_MIRROR_PACKET *)param;
	const UCHAR *d = (const UCHAR *)data;
	UINT ether_type = ((p->Packet[0] >> 4) == 4 ? 0x0800 : 0x86DD);

	if (size != VXLAN_HEADER_SIZE + NODE_MIRROR_ETHER + p->Size || d[0] != VXLAN_FLAG_VNI ||
		(((UINT)d[VXLAN_HEADER_SIZE + 12] << 8) | d[VXLAN_HEADER_SIZE + 13]) != ether_type ||
		memcmp(d + VXLAN_HEADER_SIZE + NODE_MIRROR_ETHER, p->Packet, p->Size) != 0)
	{
		abort();
	}

	return true;
}

// Add one Mirror to the state, to the sensor of sensor_size bytes on the VXLAN port
static void FuzzMirrorRule(CONTROL_STATE *st, UINT vrf_id, UINT protocol, UINT port, const UCHAR *sensor, UINT sensor_size, UINT vni, UINT64 rate)
{
	CONTROL_MIRROR *m = &st->Mirrors[st->NumMirrors++];

	m->VrfId = vrf_id;
	m->Protocol = protocol;
	m->Port = port;
	memcpy(m->Sensor, sensor, sensor_size);
	m->SensorSize = sensor_size;
	m->SensorPort = VXLAN_PORT;
	m->Vni = vni;
	m->RateLimit = rate;
}

// One input: the way and the VRF, then a packet
static void FuzzMirror(const uint8_t *data, size_t size)
{
	CONTROL_STATE st;
	FUZZ_MIRROR_PACKET p;

	if (size < 2 || size > FUZZ_MAX_INPUT_SIZE)
	{
		return;
	}

	// UDP port 53 in VRF 101; TCP port 8080 in every VRF, on VNI 7, at most 1 Mbit/s; ICMP in VRF 202 to the IPv6
	// sensor, on VNI 4242; every packet of every VRF, on the VNI of its VRF id
	memset(&st, 0, sizeof(st));
	FuzzMirrorRule(&st, 101, 17, 53, fuzz_mirror_sensor4, 4, 0, 0);
	FuzzMirrorRule(&st, 0, 6, 8080, fuzz_mirror_sensor4, 4, 7, 1000000);
	FuzzMirrorRule(&st, 202, 1, 0, fuzz_mirror_sensor6, 16, 4242, 0);
	FuzzMirrorRule(&st, 0, 0, 0, fuzz_mirror_sensor4, 4, 0, 0);

	UINT vrf_id = fuzz_mirror_vrf_ids[data[0] & 0x03];
	bool from_host = ((data[0] & 0x04) != 0);

	// malloc() rather than Malloc(): the copy is exactly the packet, so AddressSanitizer reports any read past it
	p.Size = (UINT)size - 1;
	UCHAR *packet = malloc(p.Size);
	if (packet == NULL)
	{
		return;
	}
	memcpy(packet, data + 1, p.Size);
	p.Packet = packet;

	NODE_MIRROR *m = NodeNewMirror(FuzzMirrorSend, &p);
	NODE_VRF_TABLES *v = (m != NULL ? NodeNewVrfTables(1, NULL, 0, NULL, 0) : NULL);
	if (v != NULL)
	{
		v->Mirror = NodeNewMirrorTable(m, &st);
		NodeMirrorCopy(v, vrf_id, packet, p.Size, from_host);
		NodeFreeVrfTables(v);
	}
	NodeFreeMirror(m);

	free(packet);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	FuzzRun(FuzzMirror, data, size);

	return 0;
}
