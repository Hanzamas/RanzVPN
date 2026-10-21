// PktChecksum.c
// Internet checksums: the one's-complement sum, IpChecksum, the IPv4 and IPv6 pseudo-header checksums and the checksum correction of a parsed packet (offload fix-up)

#include "TcpIp.h"

#include "Memory.h"
#include "TcpIpInternal.h"

// Adds v to a 64-bit one's complement sum: the carry out of the top is added back at the bottom
// (RFC 1071), so the sum stays congruent to the total modulo 2^64-1 and so modulo 0xFFFF
static UINT64 IpChecksumCarry(UINT64 sum, UINT64 v)
{
	sum += v;

	return sum + (sum < v);
}

// Adds size bytes of buf to a one's complement sum, eight bytes at a time. The bytes are read as
// 16-bit words in the byte order of the machine and an odd last byte is a word of its own, the
// same words as the sum over 16-bit words of RFC 1071; the 16-bit lanes of a wider load add up the
// same, so the result does not depend on the width of the loads. The pseudo-header of the caller
// has an even size, so it is added first and buf (the upper layer data) is added behind it. buf
// is read through memcpy, so it needs no alignment
static UINT64 IpChecksumAdd(UINT64 sum, void *buf, UINT size)
{
	UCHAR *p = (UCHAR *)buf;

	while (size >= sizeof(UINT64))
	{
		UINT64 v;

		memcpy(&v, p, sizeof(v));
		sum = IpChecksumCarry(sum, v);

		p += sizeof(v);
		size -= sizeof(v);
	}

	if (size >= sizeof(UINT))
	{
		UINT v;

		memcpy(&v, p, sizeof(v));
		sum = IpChecksumCarry(sum, v);

		p += sizeof(v);
		size -= sizeof(v);
	}

	if (size >= sizeof(USHORT))
	{
		USHORT v;

		memcpy(&v, p, sizeof(v));
		sum = IpChecksumCarry(sum, v);

		p += sizeof(v);
		size -= sizeof(v);
	}

	if (size == 1)
	{
		USHORT v = 0;

		// The odd byte goes into the first byte of the word, as the old word-by-word sum did
		*(UCHAR *)(&v) = *p;
		sum = IpChecksumCarry(sum, v);
	}

	return sum;
}

// Folds the sum down to 16 bits and complements it. A sum of nonzero words stays nonzero while it
// is folded (a nonzero value has a nonzero sum of its halves), as in the word-by-word sum before it
static USHORT IpChecksumFinish(UINT64 sum)
{
	sum = (sum >> 32) + (sum & 0xFFFFFFFF);
	sum = (sum >> 32) + (sum & 0xFFFFFFFF);
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum = (sum >> 16) + (sum & 0xFFFF);

	return (USHORT)~sum;
}

USHORT CalcChecksumForIPv4(UINT src_ip, UINT dst_ip, UCHAR protocol, void *data, UINT size, UINT real_size)
{
	IPV4_PSEUDO_HEADER ph;
	if (data == NULL && size != 0)
	{
		return 0;
	}

	if (real_size == 0)
	{
		real_size = size;
	}

	if (real_size == INFINITE)
	{
		real_size = 0;
	}

	ph.SrcIP = src_ip;
	ph.DstIP = dst_ip;
	ph.PacketLength = Endian16(real_size);
	ph.Protocol = protocol;
	ph.Reserved = 0;

	UINT64 sum = IpChecksumAdd(0, &ph, sizeof(ph));
	sum = IpChecksumAdd(sum, data, size);

	return IpChecksumFinish(sum);
}

USHORT CalcChecksumForIPv6(IPV6_ADDR *src_ip, IPV6_ADDR *dest_ip, UCHAR protocol, void *data, UINT size, UINT real_size)
{
	IPV6_PSEUDO_HEADER ph;
	if (data == NULL && size != 0)
	{
		return 0;
	}

	if (real_size == 0)
	{
		real_size = size;
	}

	if (real_size == INFINITE)
	{
		real_size = 0;
	}

	Zero(&ph, sizeof(ph));
	Copy(&ph.SrcAddress, src_ip, sizeof(IPV6_ADDR));
	Copy(&ph.DestAddress, dest_ip, sizeof(IPV6_ADDR));
	ph.UpperLayerPacketSize = Endian32(real_size);
	ph.NextHeader = protocol;

	UINT64 sum = IpChecksumAdd(0, &ph, sizeof(ph));
	sum = IpChecksumAdd(sum, data, size);

	return IpChecksumFinish(sum);
}

// The checksum of a TCP or UDP segment over the pseudo-header of the packet's IP version, with the
// size and the real_size of CalcChecksumForIPv4 and CalcChecksumForIPv6
static USHORT CalcL4Checksum(const PKT *p, UCHAR protocol, void *data, UINT size, UINT real_size)
{
	if (p->TypeL3 == L3_IPV4)
	{
		IPV4_HEADER *v4 = p->L3.IPv4Header;

		return CalcChecksumForIPv4(v4->SrcIP, v4->DstIP, protocol, data, size, real_size);
	}
	else
	{
		IPV6_HEADER *v6 = p->L3.IPv6Header;

		return CalcChecksumForIPv6(&v6->SrcAddress, &v6->DestAddress, protocol, data, size, real_size);
	}
}

// A NIC that offloads the checksum of a segment leaves its field at 0 (TCP only), at the sum of the
// pseudo-header or at the complement of it. Such a checksum is replaced with the real one over the len
// bytes of the segment l4. A UDP datagram with checksum 0 has none. When the segment is not complete
// (complete is false) the field is cleared instead
static void FixOffloadChecksum(const PKT *p, UCHAR protocol, void *l4, void *checksum_field, UINT len, bool complete)
{
	USHORT checksum;

	Copy(&checksum, checksum_field, sizeof(checksum));

	if (protocol == IP_PROTO_UDP && checksum == 0)
	{
		return;
	}

	USHORT offloading_checksum = CalcL4Checksum(p, protocol, NULL, 0, len);

	if (checksum != 0 && checksum != offloading_checksum && checksum != (USHORT)~offloading_checksum)
	{
		return;
	}

	checksum = 0;
	Copy(checksum_field, &checksum, sizeof(checksum));

	if (complete)
	{
		checksum = CalcL4Checksum(p, protocol, l4, len, 0);
		Copy(checksum_field, &checksum, sizeof(checksum));
	}
}

void CorrectChecksum(PKT *p)
{
	UINT payload_size;
	bool tcp_checked;
	bool udp_checked;
	bool last_fragment;

	if (p == NULL)
	{
		return;
	}

	if (p->TypeL3 == L3_IPV4)
	{
		IPV4_HEADER *v4 = p->L3.IPv4Header;

		if (v4 == NULL)
		{
			return;
		}

		if (v4->Checksum == 0x0000)
		{
			v4->Checksum = IpChecksum(v4, IPV4_GET_HEADER_LEN(v4) * 4);
		}

		payload_size = p->IPv4PayloadSize;
		last_fragment = ((IPV4_GET_FLAGS(v4) & 0x01) == 0);
		// A fragment has no TCP checksum of its own. UDP is passed when either the first or the last
		// fragment: it has always been an OR here where TCP has an AND
		tcp_checked = (IPV4_GET_OFFSET(v4) == 0 && last_fragment);
		udp_checked = (IPV4_GET_OFFSET(v4) == 0 || last_fragment);
	}
	else if (p->TypeL3 == L3_IPV6)
	{
		IPV6_HEADER_PACKET_INFO *v6info = &p->IPv6HeaderPacketInfo;

		if (p->L3.IPv6Header == NULL)
		{
			return;
		}

		payload_size = v6info->PayloadSize;
		last_fragment = (v6info->FragmentHeader == NULL || ((IPV6_GET_FLAGS(v6info->FragmentHeader) & IPV6_FRAGMENT_HEADER_FLAG_MORE_FRAGMENTS) == 0));
		tcp_checked = (v6info->IsFragment == false && last_fragment);
		udp_checked = (v6info->IsFragment == false);
	}
	else
	{
		return;
	}

	if (p->TypeL4 == L4_TCP)
	{
		TCP_HEADER *tcp = p->L4.TCPHeader;

		if (tcp_checked && tcp != NULL)
		{
			FixOffloadChecksum(p, IP_PROTO_TCP, tcp, &tcp->Checksum, payload_size, true);
		}
	}
	else if (p->TypeL4 == L4_UDP)
	{
		UDP_HEADER *udp = p->L4.UDPHeader;

		if (udp_checked && udp != NULL)
		{
			UINT udp_len = Endian16(udp->PacketLength);

			// The first fragment holds only a part of the data, so it cannot be checksummed
			FixOffloadChecksum(p, IP_PROTO_UDP, udp, &udp->Checksum, udp_len, last_fragment && payload_size >= udp_len);
		}
	}
}

USHORT IpChecksum(void *buf, UINT size)
{
	return IpChecksumFinish(IpChecksumAdd(0, buf, size));
}
