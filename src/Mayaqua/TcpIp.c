// TcpIp.c
// Utility module for TCP/IP packet processing

#include "TcpIp.h"

#include "Cfg.h"
#include "Memory.h"
#include "Str.h"

// Offset of the DHCP magic cookie (RFC 2131): the fixed header, then sname (64 bytes) and file
// (128 bytes). The options follow the cookie.
#define	DHCP_MAGIC_COOKIE_OFFSET	(sizeof(DHCPV4_HEADER) + 64 + 128)

// Bits of the first flag byte of a DNS header (RFC 1035 4.1.1): QR (the message is a response) and
// the opcode (0 is a standard query). The AA, TC and RD bits below them say nothing about the query
#define	DNS_FLAG1_QR				0x80
#define	DNS_FLAG1_OPCODE			0x78

// Longest label and longest name of a DNS question, in octets on the wire with the length bytes
// and the root label (RFC 1035 2.3.4)
#define	DNS_MAX_LABEL_LEN			63
#define	DNS_MAX_NAME_LEN			255

static void ParseDNS(PKT *p, UCHAR *buf, UINT size);

bool IsDhcpPacketForSpecificMac(UCHAR *data, UINT size, UCHAR *mac_address)
{
	USHORT *us;
	IPV4_HEADER *ip;
	UDP_HEADER *udp;
	UINT ip_header_size;
	bool is_send = false, is_recv = false;
	if (data == NULL || mac_address == NULL || IsZero(mac_address, 6))
	{
		return false;
	}

	if (size < 14)
	{
		return false;
	}

	if (Cmp(data, mac_address, 6) == 0)
	{
		is_recv = true;
	}
	size -= 6;
	data += 6;

	if (Cmp(data, mac_address, 6) == 0)
	{
		is_send = true;
	}
	size -= 6;
	data += 6;

	if (is_send == false && is_recv == false)
	{
		return false;
	}
	if (is_send && is_recv)
	{
		return false;
	}

	us = (USHORT *)data;
	size -= 2;
	data += 2;

	if (READ_USHORT(us) != MAC_PROTO_IPV4)
	{
		return false;
	}

	ip_header_size = GetIpHeaderSize(data, size);
	if (ip_header_size == 0)
	{
		return false;
	}

	ip = (IPV4_HEADER *)data;
	data += ip_header_size;
	size -= ip_header_size;

	if (ip->Protocol != IP_PROTO_UDP)
	{
		return false;
	}

	if (size < sizeof(UDP_HEADER))
	{
		return false;
	}
	udp = (UDP_HEADER *)data;
	data += sizeof(UDP_HEADER);
	size -= sizeof(UDP_HEADER);

	if (is_send)
	{
		if (Endian16(udp->DstPort) == 67)
		{
			return true;
		}
	}
	else if (is_recv)
	{
		if (Endian16(udp->SrcPort) == 67)
		{
			return true;
		}
	}

	return false;
}

bool AdjustTcpMssL2(UCHAR *src, UINT src_size, UINT mss, USHORT tag_vlan_tpid)
{
	MAC_HEADER *mac;
	USHORT proto;
	if (src == NULL || src_size == 0 || mss == 0)
	{
		return false;
	}
	if (tag_vlan_tpid == 0)
	{
		tag_vlan_tpid = MAC_PROTO_TAGVLAN;
	}

	if (src_size < sizeof(MAC_HEADER))
	{
		return false;
	}

	mac = (MAC_HEADER *)src;

	src += sizeof(MAC_HEADER);
	src_size -= sizeof(MAC_HEADER);

	proto = Endian16(mac->Protocol);

	if (proto == MAC_PROTO_IPV4 || proto == MAC_PROTO_IPV6)
	{
		return AdjustTcpMssL3(src, src_size, mss);
	}
	else if (proto == tag_vlan_tpid)
	{
		if (src_size < 4)
		{
			return false;
		}

		src += 2;
		src_size -= 2;

		proto = READ_USHORT(src);

		if (proto == MAC_PROTO_IPV4 || proto == MAC_PROTO_IPV6)
		{
			if (mss >= 5)
			{
				mss -= 4;

				src += 2;
				src_size -= 2;

				return AdjustTcpMssL3(src, src_size, mss);
			}
		}
	}

	return false;
}

UINT GetIpHeaderSize(UCHAR *src, UINT src_size)
{
	UCHAR ip_ver;
	IPV4_HEADER *ip = NULL;
	IPV6_HEADER *ip6 = NULL;
	if (src == NULL || src_size == 0)
	{
		return 0;
	}

	ip_ver = (src[0] >> 4) & 0x0f;

	if (ip_ver == 4)
	{
		UINT ip_header_size;
		if (src_size < sizeof(IPV4_HEADER))
		{
			return 0;
		}

		ip = (IPV4_HEADER *)src;

		ip_header_size = IPV4_GET_HEADER_LEN(ip) * 4;
		if (ip_header_size < sizeof(IPV4_HEADER))
		{
			return 0;
		}

		if (src_size < ip_header_size)
		{
			return 0;
		}

		return ip_header_size;
	}
	else if (ip_ver == 6)
	{
		IPV6_HEADER_PACKET_INFO v6;

		if (ParsePacketIPv6Header(&v6, src, src_size) == false)
		{
			return 0;
		}

		ip6 = v6.IPv6Header;
		if (ip6 == NULL)
		{
			return 0;
		}

		if (src_size < v6.TotalHeaderSize)
		{
			return 0;
		}

		return v6.TotalHeaderSize;
	}
	else
	{
		return 0;
	}
}

bool AdjustTcpMssL3(UCHAR *src, UINT src_size, UINT mss)
{
	UCHAR ip_ver;
	TCP_HEADER *tcp = NULL;
	UINT tcp_size = 0;
	UINT tcp_header_size;
	UCHAR *options;
	UINT options_size;
	UCHAR *mss_option = NULL;
	UINT i;
	IPV4_HEADER *ip = NULL;
	IPV6_HEADER *ip6 = NULL;
	if (src == NULL || src_size == 0 || mss == 0)
	{
		return false;
	}

	ip_ver = (src[0] >> 4) & 0x0f;

	if (ip_ver == 4)
	{
		UINT ip_header_size;
		UINT ip_total_length;
		if (src_size < sizeof(IPV4_HEADER))
		{
			return false;
		}

		ip = (IPV4_HEADER *)src;

		if (ip->Protocol != IP_PROTO_TCP)
		{
			return false;
		}

		if (IPV4_GET_OFFSET(ip) != 0)
		{
			return false;
		}

		if (IPV4_GET_FLAGS(ip) & 0x01)
		{
			return false;
		}

		ip_header_size = IPV4_GET_HEADER_LEN(ip) * 4;
		if (ip_header_size < sizeof(IPV4_HEADER))
		{
			return false;
		}

		if (src_size < ip_header_size)
		{
			return false;
		}

		ip_total_length = READ_USHORT(&ip->TotalLength);

		if (ip_total_length < ip_header_size)
		{
			return false;
		}

		if (src_size < ip_total_length)
		{
			return false;
		}

		src += ip_header_size;
		src_size = ip_total_length - ip_header_size;

		if (src_size < sizeof(TCP_HEADER))
		{
			return false;
		}

		tcp = (TCP_HEADER *)src;
		tcp_size = src_size;
	}
	else if (ip_ver == 6)
	{
		IPV6_HEADER_PACKET_INFO v6;

		if (ParsePacketIPv6Header(&v6, src, src_size) == false)
		{
			return false;
		}

		ip6 = v6.IPv6Header;
		if (ip6 == NULL)
		{
			return false;
		}

		if (v6.Protocol != IP_PROTO_TCP)
		{
			return false;
		}

		if (v6.IsFragment)
		{
			return false;
		}

		if (v6.FragmentHeader != NULL)
		{
			if (IPV6_GET_FLAGS(v6.FragmentHeader) & IPV6_FRAGMENT_HEADER_FLAG_MORE_FRAGMENTS)
			{
				return false;
			}
		}

		tcp = (TCP_HEADER *)v6.Payload;
		tcp_size = v6.PayloadSize;
	}
	else
	{
		return false;
	}

	if (tcp == NULL || tcp_size < sizeof(TCP_HEADER))
	{
		return false;
	}

	tcp_header_size = TCP_GET_HEADER_SIZE(tcp) * 4;
	if (tcp_header_size < sizeof(TCP_HEADER))
	{
		return false;
	}

	if (tcp_size < tcp_header_size)
	{
		return false;
	}

	if (((tcp->Flag & TCP_SYN) == false) ||
	        ((tcp->Flag & TCP_RST) ||
	         (tcp->Flag & TCP_PSH) ||
	         (tcp->Flag & TCP_URG)))
	{
		return false;
	}

	options = ((UCHAR *)tcp) + sizeof(TCP_HEADER);
	options_size = tcp_header_size - sizeof(TCP_HEADER);

	// Find the MSS option (kind 2, length 4) wherever it is in the option list (RFC 9293 3.1):
	// End of Option List (kind 0) ends the list, No-Operation (kind 1) is one byte, and every other
	// option has a length byte of at least 2 that keeps it inside the options. A list that does not
	// keep to that is left alone.
	i = 0;
	while (i < options_size)
	{
		UCHAR kind = options[i];
		UINT len;

		if (kind == 0x00)
		{
			break;
		}

		if (kind == 0x01)
		{
			i++;
			continue;
		}

		if ((options_size - i) < 2)
		{
			break;
		}

		len = options[i + 1];
		if (len < 2 || len > (options_size - i))
		{
			break;
		}

		if (kind == 0x02 && len == 4)
		{
			mss_option = options + i;
			break;
		}

		i += len;
	}

	if (ip6 != NULL)
	{
		// Reduce MSS by 20 since an IP header for IPv6 is 20 bytes larger than IPv4
		if (mss >= 20)
		{
			mss -= 20;
		}
	}

	// MSS should be at least 64
	mss = MAX(mss, 64);

	if (mss_option != NULL)
	{
		USHORT current_mss = READ_USHORT(mss_option + 2);

		if (current_mss <= mss)
		{
			// Leave the MSS alone if it is already at or below the target
			return false;
		}
		else
		{
			WRITE_USHORT(mss_option + 2, mss);

			tcp->Checksum = 0;

			if (ip != NULL)
			{
				tcp->Checksum = CalcChecksumForIPv4(ip->SrcIP, ip->DstIP, IP_PROTO_TCP, tcp, tcp_size, 0);
			}
			else
			{
				tcp->Checksum = CalcChecksumForIPv6(&ip6->SrcAddress, &ip6->DestAddress,
				                                    IP_PROTO_TCP, tcp, tcp_size, 0);
			}

			return true;
		}
	}
	else
	{
		return false;
	}
}

// The options of a DHCP payload: the bytes behind the magic cookie. The cookie is read only at its fixed
// offset, and only when it is inside the payload: cookie bytes in sname, file or chaddr select nothing.
// NULL when the payload has no cookie
static UCHAR *DhcpOptionsOf(void *data, UINT size, UINT *options_size)
{
	UINT magic_cookie = Endian32(DHCP_MAGIC_COOKIE);
	if (data == NULL || size < DHCP_MAGIC_COOKIE_OFFSET + sizeof(UINT))
	{
		return NULL;
	}

	if (Cmp(((UCHAR *)data) + DHCP_MAGIC_COOKIE_OFFSET, &magic_cookie, sizeof(UINT)) != 0)
	{
		return NULL;
	}

	*options_size = size - (UINT)(DHCP_MAGIC_COOKIE_OFFSET + sizeof(UINT));

	return ((UCHAR *)data) + DHCP_MAGIC_COOKIE_OFFSET + sizeof(UINT);
}

// The DHCP message type (option 53) of an option list: 0 when the list has none or it is not one byte long
static UINT DhcpMessageType(LIST *o)
{
	DHCP_OPTION *opt = GetDhcpOption(o, DHCP_ID_MESSAGE_TYPE);
	if (opt == NULL || opt->Size != 1)
	{
		return 0;
	}

	return *((UCHAR *)opt->Data);
}

void VLanInsertTag(void **packet_data, UINT *packet_size, UINT vlan_id, UINT vlan_tpid)
{
	UINT dest_size;
	UCHAR *dest_data;
	UINT src_size;
	UCHAR *src_data;
	USHORT vlan_ushort = Endian16(((USHORT)vlan_id) & 0xFFF);
	USHORT vlan_tpid_ushort;
	if (packet_data == NULL || *packet_data == NULL || packet_size == NULL ||
	        *packet_size < 14 || vlan_id == 0)
	{
		return;
	}
	if (vlan_tpid == 0)
	{
		vlan_tpid = MAC_PROTO_TAGVLAN;
	}

	vlan_tpid_ushort = Endian16((USHORT)vlan_tpid);

	src_size = *packet_size;
	src_data = (UCHAR *)(*packet_data);

	dest_size = src_size + 4;
	dest_data = Malloc(dest_size);

	Copy(&dest_data[12], &vlan_tpid_ushort, sizeof(USHORT));
	Copy(&dest_data[14], &vlan_ushort, sizeof(USHORT));

	Copy(&dest_data[0], &src_data[0], 12);
	Copy(&dest_data[16], &src_data[12], src_size - 12);

	*packet_size = dest_size;
	*packet_data = dest_data;

	Free(src_data);
}

bool VLanRemoveTag(void **packet_data, UINT *packet_size, UINT vlan_id, UINT vlan_tpid)
{
	UCHAR *src_data;
	UINT src_size;
	USHORT vlan_tpid_ushort;
	UCHAR *vlan_tpid_uchar;
	if (packet_data == NULL || *packet_data == NULL || packet_size == NULL ||
	        *packet_size < 14)
	{
		return false;
	}

	if (vlan_tpid == 0)
	{
		vlan_tpid = MAC_PROTO_TAGVLAN;
	}

	vlan_tpid_ushort = Endian16((USHORT)vlan_tpid);
	vlan_tpid_uchar = (UCHAR *)(&vlan_tpid_ushort);

	src_data = (UCHAR *)(*packet_data);
	src_size = *packet_size;

	if (src_data[12] == vlan_tpid_uchar[0] && src_data[13] == vlan_tpid_uchar[1])
	{
		if (src_size >= 18)
		{
			USHORT vlan_ushort;

			vlan_ushort = READ_USHORT(&src_data[14]);
			vlan_ushort = vlan_ushort & 0xFFF;

			if (vlan_id == 0 || (vlan_ushort == vlan_id))
			{
				UINT dest_size = src_size - 4;
				UINT i;

				for (i = 12; i < dest_size; i++)
				{
					src_data[i] = src_data[i + 4];
				}

				*packet_size = dest_size;

				return true;
			}
		}
	}

	return false;
}

// Builds the IPv6 packet of a Neighbor Solicitation (RFC 4861 4.3) from src_ip to target_ip, sent to
// the unicast address of the target: IPv6 header, ICMPv6 header, the target address and the source
// link-layer address option with my_mac_address, 72 bytes. The hop limit is 255; the flow label is
// 0. Returns NULL when an argument is NULL
BUF *BuildNeighborSolicitation(IPV6_ADDR *src_ip, IPV6_ADDR *target_ip, UCHAR *my_mac_address)
{
	UINT icmp_size = sizeof(ICMP_HEADER) + sizeof(ICMPV6_NEIGHBOR_SOLICIATION_HEADER) +
		sizeof(ICMPV6_OPTION_LINK_LAYER);
	UCHAR *packet;
	IPV6_HEADER *ip;
	ICMP_HEADER *icmp;
	ICMPV6_NEIGHBOR_SOLICIATION_HEADER *ns;
	ICMPV6_OPTION_LINK_LAYER *link;
	BUF *ret;
	if (src_ip == NULL || target_ip == NULL || my_mac_address == NULL)
	{
		return NULL;
	}

	packet = ZeroMalloc(sizeof(IPV6_HEADER) + icmp_size);
	ip = (IPV6_HEADER *)packet;
	icmp = (ICMP_HEADER *)(packet + sizeof(IPV6_HEADER));
	ns = (ICMPV6_NEIGHBOR_SOLICIATION_HEADER *)(icmp + 1);
	link = (ICMPV6_OPTION_LINK_LAYER *)(ns + 1);

	IPV6_SET_VERSION(ip, 6);
	ip->PayloadLength = Endian16((USHORT)icmp_size);
	ip->NextHeader = IP_PROTO_ICMPV6;
	ip->HopLimit = 255;
	Copy(&ip->SrcAddress, src_ip, sizeof(IPV6_ADDR));
	Copy(&ip->DestAddress, target_ip, sizeof(IPV6_ADDR));

	icmp->Type = ICMPV6_TYPE_NEIGHBOR_SOLICIATION;
	Copy(&ns->TargetAddress, target_ip, sizeof(IPV6_ADDR));
	link->IcmpOptionHeader.Type = ICMPV6_OPTION_TYPE_SOURCE_LINK_LAYER;
	link->IcmpOptionHeader.Length = sizeof(ICMPV6_OPTION_LINK_LAYER) / 8;
	Copy(link->Address, my_mac_address, 6);

	icmp->Checksum = CalcChecksumForIPv6(src_ip, target_ip, IP_PROTO_ICMPV6, icmp, icmp_size, 0);

	ret = NewBufFromMemory(packet, sizeof(IPV6_HEADER) + icmp_size);

	Free(packet);

	return ret;
}

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
	UINT64 sum;
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

	sum = IpChecksumAdd(0, &ph, sizeof(ph));
	sum = IpChecksumAdd(sum, data, size);

	return IpChecksumFinish(sum);
}

USHORT CalcChecksumForIPv6(IPV6_ADDR *src_ip, IPV6_ADDR *dest_ip, UCHAR protocol, void *data, UINT size, UINT real_size)
{
	IPV6_PSEUDO_HEADER ph;
	UINT64 sum;
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

	sum = IpChecksumAdd(0, &ph, sizeof(ph));
	sum = IpChecksumAdd(sum, data, size);

	return IpChecksumFinish(sum);
}

void FreeClonePacket(PKT *p)
{
	if (p == NULL)
	{
		return;
	}

	Free(p->IPv6HeaderPacketInfo.IPv6Header);
	Free(p->IPv6HeaderPacketInfo.HopHeader);
	Free(p->IPv6HeaderPacketInfo.EndPointHeader);
	Free(p->IPv6HeaderPacketInfo.RoutingHeader);
	Free(p->IPv6HeaderPacketInfo.FragmentHeader);
	Free(p->IPv6HeaderPacketInfo.Payload);
	Free(p->ICMPv6HeaderPacketInfo.Data);
	Free(p->ICMPv6HeaderPacketInfo.EchoData);
	Free(p->ICMPv6HeaderPacketInfo.Headers.HeaderPointer);
	FreeCloneICMPv6Options(&p->ICMPv6HeaderPacketInfo.OptionList);
	Free(p->L3.PointerL3);
	Free(p->L4.PointerL4);
	Free(p->L7.PointerL7);
	Free(p->PacketData);
	Free(p->MacHeader);
	Free(p->HttpLog);
	Free(p);
}

PKT *ClonePacket(PKT *p, bool copy_data)
{
	PKT *ret;
	if (p == NULL)
	{
		return NULL;
	}

	ret = ZeroMallocFast(sizeof(PKT));
	ret->PacketSize = p->PacketSize;

	ret->MacHeader = MallocFast(sizeof(MAC_HEADER));
	Copy(ret->MacHeader, p->MacHeader, sizeof(MAC_HEADER));

	ret->BroadcastPacket = p->BroadcastPacket;
	ret->InvalidSourcePacket = p->InvalidSourcePacket;

	Copy(&ret->IPv6HeaderPacketInfo, &p->IPv6HeaderPacketInfo, sizeof(IPV6_HEADER_PACKET_INFO));
	Copy(&ret->ICMPv6HeaderPacketInfo, &p->ICMPv6HeaderPacketInfo, sizeof(ICMPV6_HEADER_INFO));

	ret->TypeL3 = p->TypeL3;
	switch (ret->TypeL3)
	{
	case L3_ARPV4:
		ret->L3.ARPv4Header = MallocFast(sizeof(ARPV4_HEADER));
		Copy(ret->L3.ARPv4Header, p->L3.ARPv4Header, sizeof(ARPV4_HEADER));
		break;

	case L3_IPV4:
		ret->L3.IPv4Header = MallocFast(sizeof(IPV4_HEADER));
		Copy(ret->L3.IPv4Header, p->L3.IPv4Header, sizeof(IPV4_HEADER));
		break;

	case L3_IPV6:
		ret->L3.IPv6Header = MallocFast(sizeof(IPV6_HEADER));
		Copy(ret->L3.IPv6Header, p->L3.IPv6Header, sizeof(IPV6_HEADER));

		ret->IPv6HeaderPacketInfo.IPv6Header = Clone(p->IPv6HeaderPacketInfo.IPv6Header,
		                                       sizeof(IPV6_HEADER));

		ret->IPv6HeaderPacketInfo.HopHeader = Clone(p->IPv6HeaderPacketInfo.HopHeader,
		                                      sizeof(IPV6_OPTION_HEADER));

		ret->IPv6HeaderPacketInfo.EndPointHeader = Clone(p->IPv6HeaderPacketInfo.EndPointHeader,
		        sizeof(IPV6_OPTION_HEADER));

		ret->IPv6HeaderPacketInfo.RoutingHeader = Clone(p->IPv6HeaderPacketInfo.RoutingHeader,
		        sizeof(IPV6_OPTION_HEADER));

		ret->IPv6HeaderPacketInfo.FragmentHeader = Clone(p->IPv6HeaderPacketInfo.FragmentHeader,
		        sizeof(IPV6_FRAGMENT_HEADER));

		ret->IPv6HeaderPacketInfo.Payload = Clone(p->IPv6HeaderPacketInfo.Payload,
		                                    p->IPv6HeaderPacketInfo.PayloadSize);
		break;
	}

	ret->TypeL4 = p->TypeL4;
	switch (ret->TypeL4)
	{
	case L4_ICMPV4:
		ret->L4.ICMPHeader = MallocFast(sizeof(ICMP_HEADER));
		Copy(ret->L4.ICMPHeader, p->L4.ICMPHeader, sizeof(ICMP_HEADER));
		break;

	case L4_ICMPV6:
		ret->L4.ICMPHeader = MallocFast(sizeof(ICMP_HEADER));
		Copy(ret->L4.ICMPHeader, p->L4.ICMPHeader, sizeof(ICMP_HEADER));

		ret->ICMPv6HeaderPacketInfo.Data = Clone(p->ICMPv6HeaderPacketInfo.Data,
		                                   p->ICMPv6HeaderPacketInfo.DataSize);

		ret->ICMPv6HeaderPacketInfo.EchoData = Clone(p->ICMPv6HeaderPacketInfo.EchoData,
		                                       p->ICMPv6HeaderPacketInfo.EchoDataSize);

		switch (ret->ICMPv6HeaderPacketInfo.Type)
		{
		case ICMPV6_TYPE_ECHO_REQUEST:
		case ICMPV6_TYPE_ECHO_RESPONSE:
			break;

		case ICMPV6_TYPE_ROUTER_SOLICIATION:
			ret->ICMPv6HeaderPacketInfo.Headers.RouterSoliciationHeader =
			    Clone(p->ICMPv6HeaderPacketInfo.Headers.RouterSoliciationHeader,
			          sizeof(ICMPV6_ROUTER_SOLICIATION_HEADER));
			break;

		case ICMPV6_TYPE_ROUTER_ADVERTISEMENT:
			ret->ICMPv6HeaderPacketInfo.Headers.RouterAdvertisementHeader =
			    Clone(p->ICMPv6HeaderPacketInfo.Headers.RouterAdvertisementHeader,
			          sizeof(ICMPV6_ROUTER_ADVERTISEMENT_HEADER));
			break;

		case ICMPV6_TYPE_NEIGHBOR_SOLICIATION:
			ret->ICMPv6HeaderPacketInfo.Headers.NeighborSoliciationHeader =
			    Clone(p->ICMPv6HeaderPacketInfo.Headers.NeighborSoliciationHeader,
			          sizeof(ICMPV6_NEIGHBOR_SOLICIATION_HEADER));
			break;

		case ICMPV6_TYPE_NEIGHBOR_ADVERTISEMENT:
			ret->ICMPv6HeaderPacketInfo.Headers.NeighborAdvertisementHeader =
			    Clone(p->ICMPv6HeaderPacketInfo.Headers.NeighborAdvertisementHeader,
			          sizeof(ICMPV6_NEIGHBOR_ADVERTISEMENT_HEADER));
			break;
		}

		CloneICMPv6Options(&ret->ICMPv6HeaderPacketInfo.OptionList,
		                   &p->ICMPv6HeaderPacketInfo.OptionList);
		break;

	case L4_TCP:
		ret->L4.TCPHeader = MallocFast(sizeof(TCP_HEADER));
		Copy(ret->L4.TCPHeader, p->L4.TCPHeader, sizeof(TCP_HEADER));
		break;

	case L4_UDP:
		ret->L4.UDPHeader = MallocFast(sizeof(UDP_HEADER));
		Copy(ret->L4.UDPHeader, p->L4.UDPHeader, sizeof(UDP_HEADER));
		break;
	}

	ret->TypeL7 = p->TypeL7;
	switch (ret->TypeL7)
	{
	case L7_DHCPV4:
		ret->L7.DHCPv4Header = MallocFast(sizeof(DHCPV4_HEADER));
		Copy(ret->L7.DHCPv4Header, p->L7.DHCPv4Header, sizeof(DHCPV4_HEADER));
		break;

	case L7_IKECONN:
		ret->L7.IkeHeader = MallocFast(sizeof(IKE_HEADER));
		Copy(ret->L7.IkeHeader, p->L7.IkeHeader, sizeof(IKE_HEADER));
		break;

	case L7_DNS:
		StrCpy(ret->DnsQueryHost, sizeof(ret->DnsQueryHost), p->DnsQueryHost);
		break;
	}

	ret->MacAddressSrc = ret->MacHeader->SrcAddress;
	ret->MacAddressDest = ret->MacHeader->DestAddress;

	if (copy_data)
	{
		ret->PacketData = MallocFast(p->PacketSize);
		Copy(ret->PacketData, p->PacketData, p->PacketSize);
	}

	if (p->HttpLog != NULL)
	{
		ret->HttpLog = Clone(p->HttpLog, sizeof(HTTPLOG));
	}

	return ret;
}

PKT *ParsePacket(UCHAR *buf, UINT size)
{
	return ParsePacketEx4(buf, size, false, 0, true, false, false);
}
PKT *ParsePacketEx4(UCHAR *buf, UINT size, bool no_l3, UINT vlan_type_id, bool bridge_id_as_mac_address, bool no_http, bool correct_checksum)
{
	return ParsePacketEx5(buf, size, no_l3, vlan_type_id, bridge_id_as_mac_address, no_http, correct_checksum, false);
}
PKT *ParsePacketEx5(UCHAR *buf, UINT size, bool no_l3, UINT vlan_type_id, bool bridge_id_as_mac_address, bool no_http, bool correct_checksum, bool no_dns)
{
	PKT *p;
	USHORT vlan_type_id_16;
	if (buf == NULL || size == 0)
	{
		return NULL;
	}

	if (vlan_type_id == 0)
	{
		vlan_type_id = MAC_PROTO_TAGVLAN;
	}

	vlan_type_id_16 = Endian16((USHORT)vlan_type_id);

	p = ZeroMallocFast(sizeof(PKT));

	// Drop any garbage after the payload of IPv4 and IPv6 packets
	if (size >= 24)
	{
		if (buf[12] == 0x08 && buf[13] == 0x00)
		{
			USHORT ip_total_size2 = READ_USHORT(&buf[16]);
			UINT mac_packet_size;

			if (ip_total_size2 >= 1)
			{
				mac_packet_size = (UINT)ip_total_size2 + 14;

				if (size > mac_packet_size)
				{
					size = mac_packet_size;
				}
			}
		}
		else if (buf[12] == 0x86 && buf[13] == 0xdd)
		{
			USHORT ip_payload_size_2 = READ_USHORT(&buf[18]);
			UINT mac_packet_size;

			if (ip_payload_size_2 >= 1)
			{
				mac_packet_size = (UINT)ip_payload_size_2 + 14 + 40;

				if (size > mac_packet_size)
				{
					size = mac_packet_size;
				}
			}
		}
		else if (buf[12] == ((UCHAR *)&vlan_type_id_16)[0] && buf[13] == ((UCHAR *)&vlan_type_id_16)[1])
		{
			if (buf[16] == 0x08 && buf[17] == 0x00)
			{
				USHORT ip_total_size2 = READ_USHORT(&buf[20]);
				UINT mac_packet_size;

				if (ip_total_size2 >= 1)
				{
					mac_packet_size = (UINT)ip_total_size2 + 14 + 4;

					if (size > mac_packet_size)
					{
						size = mac_packet_size;
					}
				}
			}
			else if (buf[16] == 0x86 && buf[17] == 0xdd)
			{
				USHORT ip_payload_size_2 = READ_USHORT(&buf[22]);
				UINT mac_packet_size;

				if (ip_payload_size_2 >= 1)
				{
					mac_packet_size = (UINT)ip_payload_size_2 + 14 + 40 + 4;

					if (size > mac_packet_size)
					{
						size = mac_packet_size;
					}
				}
			}
		}
	}

	if (ParsePacketL2Ex(p, buf, size, no_l3, (USHORT)vlan_type_id) == false)
	{
		FreePacket(p);
		return NULL;
	}

	p->PacketData = buf;
	p->PacketSize = size;

	p->MacAddressSrc = p->MacHeader->SrcAddress;
	p->MacAddressDest = p->MacHeader->DestAddress;

	if (bridge_id_as_mac_address)
	{
		if (p->TypeL3 == L3_BPDU)
		{
			if (p->L3.BpduHeader != NULL)
			{
				p->MacAddressSrc = p->L3.BpduHeader->BridgeMacAddress;
			}
		}
	}

	if (no_http == false)
	{
		USHORT port_raw = Endian16(80);
		USHORT port_raw2 = Endian16(8080);
		USHORT port_raw3 = Endian16(443);
		USHORT port_raw4 = Endian16(3128);

		if ((p->TypeL3 == L3_IPV4 || p->TypeL3 == L3_IPV6) && p->TypeL4 == L4_TCP)
		{
			TCP_HEADER *tcp = p->L4.TCPHeader;
			if (tcp != NULL && (tcp->DstPort == port_raw || tcp->DstPort == port_raw2 || tcp->DstPort == port_raw4) &&
			        (!((tcp->Flag & TCP_SYN) || (tcp->Flag & TCP_RST) || (tcp->Flag & TCP_FIN))))
			{
				if (p->PayloadSize >= 1)
				{
					p->HttpLog = ParseHttpAccessLog(p);
				}
			}
			if (tcp != NULL && tcp->DstPort == port_raw3 &&
			        (!((tcp->Flag & TCP_SYN) || (tcp->Flag & TCP_RST) || (tcp->Flag & TCP_FIN))))
			{
				if (p->PayloadSize >= 1)
				{
					p->HttpLog = ParseHttpsAccessLog(p);
				}
			}
		}
	}

	// DNS query name of a query to UDP port 53. It is parsed here and not in ParseUDP so that a caller can
	// skip it (no_dns): only packet logging reads it
	if (no_dns == false && p->TypeL4 == L4_UDP && p->L4.UDPHeader != NULL && Endian16(p->L4.UDPHeader->DstPort) == 53)
	{
		ParseDNS(p, p->Payload, p->PayloadSize);
	}

	if (p->TypeL3 == L3_IPV4 && p->TypeL4 == L4_UDP && p->TypeL7 == L7_DHCPV4)
	{
		UINT dhcp_size = (UINT)(p->PacketSize - (((UCHAR *)p->L7.PointerL7) - ((UCHAR *)p->PacketData)));
		UINT options_size;
		UCHAR *options = DhcpOptionsOf(p->L7.PointerL7, dhcp_size, &options_size);

		if (options != NULL)
		{
			LIST *o = ParseDhcpOptions(options, options_size);

			p->DhcpOpCode = DhcpMessageType(o);

			FreeDhcpOptions(o);
		}
	}

	if (correct_checksum)
	{
		CorrectChecksum(p);
	}

	return p;
}

void CorrectChecksum(PKT *p)
{
	if (p == NULL)
	{
		return;
	}

	if (p->TypeL3 == L3_IPV4)
	{
		IPV4_HEADER *v4 = p->L3.IPv4Header;

		if (v4 != NULL)
		{
			if (v4->Checksum == 0x0000)
			{
				v4->Checksum = IpChecksum(v4, IPV4_GET_HEADER_LEN(v4) * 4);
			}

			if (p->TypeL4 == L4_TCP)
			{
				if (IPV4_GET_OFFSET(v4) == 0 && (IPV4_GET_FLAGS(v4) & 0x01) == 0)
				{
					// No TCP checksum for fragmented IP packets
					TCP_HEADER *tcp = p->L4.TCPHeader;

					if (tcp != NULL)
					{
						USHORT tcp_offloading_checksum1 = CalcChecksumForIPv4(v4->SrcIP, v4->DstIP, IP_PROTO_TCP, NULL, 0, p->IPv4PayloadSize);
						USHORT tcp_offloading_checksum2 = ~tcp_offloading_checksum1;

						if (tcp->Checksum == 0 || tcp->Checksum == tcp_offloading_checksum1 || tcp->Checksum == tcp_offloading_checksum2)
						{
							tcp->Checksum = 0;
							tcp->Checksum = CalcChecksumForIPv4(v4->SrcIP, v4->DstIP, IP_PROTO_TCP, tcp, p->IPv4PayloadSize, 0);
						}
					}
				}
			}

			if (p->TypeL4 == L4_UDP)
			{
				if (IPV4_GET_OFFSET(v4) == 0 || (IPV4_GET_FLAGS(v4) & 0x01) == 0)
				{
					UDP_HEADER *udp = p->L4.UDPHeader;

					if (udp != NULL && udp->Checksum != 0)
					{
						USHORT udp_len = Endian16(udp->PacketLength);
						USHORT udp_offloading_checksum1 = CalcChecksumForIPv4(v4->SrcIP, v4->DstIP, IP_PROTO_UDP, NULL, 0, udp_len);
						USHORT udp_offloading_checksum2 = ~udp_offloading_checksum1;

						if (udp->Checksum == udp_offloading_checksum1 || udp->Checksum == udp_offloading_checksum2)
						{
							udp->Checksum = 0;

							if ((IPV4_GET_FLAGS(v4) & 0x01) == 0 && (p->IPv4PayloadSize >= udp_len))
							{
								udp->Checksum = CalcChecksumForIPv4(v4->SrcIP, v4->DstIP, IP_PROTO_UDP, udp, udp_len, 0);
							}
							else
							{
								// First fragment: the data is incomplete, so the checksum is set to 0
								udp->Checksum = 0;
							}
						}
					}
				}
			}
		}
	}
	else if (p->TypeL3 == L3_IPV6)
	{
		IPV6_HEADER *v6 = p->L3.IPv6Header;
		IPV6_HEADER_PACKET_INFO *v6info = &p->IPv6HeaderPacketInfo;

		if (v6 != NULL)
		{
			if (p->TypeL4 == L4_TCP)
			{
				if (v6info->IsFragment == false)
				{
					if (v6info->FragmentHeader == NULL || ((IPV6_GET_FLAGS(v6info->FragmentHeader) & IPV6_FRAGMENT_HEADER_FLAG_MORE_FRAGMENTS) == 0))
					{
						// No TCP checksum for fragmented packets
						TCP_HEADER *tcp = p->L4.TCPHeader;

						if (tcp != NULL)
						{
							USHORT tcp_offloading_checksum1 = CalcChecksumForIPv6(&v6->SrcAddress, &v6->DestAddress, IP_PROTO_TCP, NULL, 0, v6info->PayloadSize);
							USHORT tcp_offloading_checksum2 = ~tcp_offloading_checksum1;

							if (tcp->Checksum == 0 || tcp->Checksum == tcp_offloading_checksum1 || tcp->Checksum == tcp_offloading_checksum2)
							{
								tcp->Checksum = 0;
								tcp->Checksum = CalcChecksumForIPv6(&v6->SrcAddress, &v6->DestAddress, IP_PROTO_TCP, tcp, v6info->PayloadSize, 0);
							}
						}
					}
				}
			}
			else if (p->TypeL4 == L4_UDP)
			{
				if (v6info->IsFragment == false)
				{
					UDP_HEADER *udp = p->L4.UDPHeader;

					if (udp != NULL && udp->Checksum != 0)
					{
						USHORT udp_len = Endian16(udp->PacketLength);
						USHORT udp_offloading_checksum1 = CalcChecksumForIPv6(&v6->SrcAddress, &v6->DestAddress, IP_PROTO_UDP, NULL, 0, udp_len);
						USHORT udp_offloading_checksum2 = ~udp_offloading_checksum1;

						if (udp->Checksum == udp_offloading_checksum1 || udp->Checksum == udp_offloading_checksum2)
						{
							udp->Checksum = 0;

							if ((v6info->FragmentHeader == NULL || ((IPV6_GET_FLAGS(v6info->FragmentHeader) & IPV6_FRAGMENT_HEADER_FLAG_MORE_FRAGMENTS) == 0)) && (v6info->PayloadSize >= udp_len))
							{
								udp->Checksum = CalcChecksumForIPv6(&v6->SrcAddress, &v6->DestAddress, IP_PROTO_UDP, udp, udp_len, 0);
							}
							else
							{
								// Fragmented packets cannot be checksummed here
							}
						}
					}
				}
			}
		}
	}
}


HTTPLOG *ParseHttpsAccessLog(PKT *pkt)
{
	HTTPLOG h;
	char sni[MAX_PATH];
	if (pkt == NULL)
	{
		return NULL;
	}

	if (GetSniNameFromSslPacket(pkt->Payload, pkt->PayloadSize, sni, sizeof(sni)) == false)
	{
		return NULL;
	}

	Zero(&h, sizeof(h));

	StrCpy(h.Method, sizeof(h.Method), "SSL_Connect");
	StrCpy(h.Hostname, sizeof(h.Hostname), sni);
	h.Port = Endian16(pkt->L4.TCPHeader->DstPort);
	StrCpy(h.Path, sizeof(h.Path), "/");
	h.IsSsl = true;

	return Clone(&h, sizeof(h));
}

HTTPLOG *ParseHttpAccessLog(PKT *pkt)
{
	HTTPLOG h;
	UCHAR *buf;
	UINT size;
	BUF *b;
	char *line1;
	bool ok = false;
	if (pkt == NULL)
	{
		return NULL;
	}

	buf = pkt->Payload;
	size = pkt->PayloadSize;

	if (size <= 5)
	{
		return NULL;
	}

	if (CmpCaseIgnore(buf, "GET ", 4) != 0 &&
	        CmpCaseIgnore(buf, "HEAD ", 5) != 0 &&
	        CmpCaseIgnore(buf, "POST ", 5) != 0)
	{
		return NULL;
	}

	Zero(&h, sizeof(h));

	h.Port = Endian16(pkt->L4.TCPHeader->DstPort);

	b = NewBuf();
	WriteBuf(b, buf, size);
	SeekBuf(b, 0, 0);

	line1 = CfgReadNextLine(b);

	if (line1 != NULL)
	{
		TOKEN_LIST *tokens = ParseToken(line1, " \t");
		if (tokens != NULL)
		{
			if (tokens->NumTokens == 3)
			{
				StrCpy(h.Method, sizeof(h.Method), tokens->Token[0]);
				Trim(h.Method);

				StrCpy(h.Path, sizeof(h.Path), tokens->Token[1]);
				Trim(h.Path);

				StrCpy(h.Protocol, sizeof(h.Protocol), tokens->Token[2]);
				Trim(h.Protocol);

				StrUpper(h.Method);

				while (true)
				{
					char *line = CfgReadNextLine(b);
					UINT i;

					if (line == NULL)
					{
						break;
					}

					i = SearchStr(line, ":", 0);
					if (i != INFINITE && i < (MAX_SIZE / 2))
					{
						char name[MAX_SIZE];
						char value[MAX_SIZE];

						StrCpy(name, sizeof(name), line);
						name[i] = 0;
						Trim(name);

						StrCpy(value, sizeof(value), line + i + 1);
						Trim(value);

						if (StrCmpi(name, "host") == 0)
						{
							StrCpy(h.Hostname, sizeof(h.Hostname), value);
						}
						else if (StrCmpi(name, "referer") == 0)
						{
							StrCpy(h.Referer, sizeof(h.Referer), value);
						}
						else if (StrCmpi(name, "user-agent") == 0)
						{
							StrCpy(h.UserAgent, sizeof(h.UserAgent), value);
						}
					}

					Free(line);
				}

				if (IsEmptyStr(h.Hostname) == false)
				{
					ok = true;
				}
			}
			FreeToken(tokens);
		}
	}

	Free(line1);
	FreeBuf(b);

	if (ok)
	{
		return Clone(&h, sizeof(h));
	}
	else
	{
		return NULL;
	}
}


// Parse the Ethernet header. A frame tagged with 0x8100 (802.1Q) or with vlan_tpid, the VLAN TPID of
// the hub (HUB_OPTION.VlanTypeId, for example 0x88A8), is a VLAN frame: ParsePacketTAGVLAN parses
// what is behind the tag, as VLanInsertTag, VLanRemoveTag and AdjustTcpMssL2 use that TPID. A
// vlan_tpid that is the type of ARP, IPv4 or IPv6 tags nothing, so those frames stay what they are
bool ParsePacketL2Ex(PKT *p, UCHAR *buf, UINT size, bool no_l3, USHORT vlan_tpid)
{
	UINT i;
	bool b1, b2;
	USHORT type_id_16;
	bool is_tag_vlan;
	if (p == NULL || buf == NULL)
	{
		return false;
	}

	if (size < sizeof(MAC_HEADER))
	{
		return false;
	}

	p->MacHeader = (MAC_HEADER *)buf;

	buf += sizeof(MAC_HEADER);
	size -= sizeof(MAC_HEADER);

	p->BroadcastPacket = true;
	b1 = true;
	b2 = true;
	for (i = 0; i < 6; i++)
	{
		if (p->MacHeader->DestAddress[i] != 0xff)
		{
			p->BroadcastPacket = false;
		}
		if (p->MacHeader->SrcAddress[i] != 0xff)
		{
			b1 = false;
		}
		if (p->MacHeader->SrcAddress[i] != 0x00)
		{
			b2 = false;
		}
	}
	if (b1 || b2 || (Cmp(p->MacHeader->SrcAddress, p->MacHeader->DestAddress, 6) == 0))
	{
		p->InvalidSourcePacket = true;
	}
	else
	{
		p->InvalidSourcePacket = false;
	}

	if (p->MacHeader->DestAddress[0] & 0x01)
	{
		p->BroadcastPacket = true;
	}

	type_id_16 = Endian16(p->MacHeader->Protocol);

	is_tag_vlan = (type_id_16 == MAC_PROTO_TAGVLAN);
	if (type_id_16 == vlan_tpid && vlan_tpid != MAC_PROTO_ARPV4 && vlan_tpid != MAC_PROTO_IPV4 && vlan_tpid != MAC_PROTO_IPV6)
	{
		is_tag_vlan = true;
	}

	if (type_id_16 > 1500)
	{
		if (is_tag_vlan)
		{
			return ParsePacketTAGVLAN(p, buf, size, no_l3);
		}
		else
		{
			return ParsePacketL3(p, buf, size, type_id_16, no_l3);
		}
	}
	else
	{
		// Old IEEE 802.3 frame: the header holds the payload length (used by BPDU, etc.)
		UINT length = (UINT)type_id_16;
		LLC_HEADER *llc;

		if (size < length || size < sizeof(LLC_HEADER))
		{
			return true;
		}

		llc = (LLC_HEADER *)buf;
		buf += sizeof(LLC_HEADER);
		size -= sizeof(LLC_HEADER);

		if (llc->Dsap == LLC_DSAP_BPDU && llc->Ssap == LLC_SSAP_BPDU)
		{
			return ParsePacketBPDU(p, buf, size);
		}
		else
		{
			return true;
		}
	}
}

bool ParsePacketL3(PKT *p, UCHAR *buf, UINT size, USHORT proto, bool no_l3)
{
	switch (proto)
		{
		case MAC_PROTO_ARPV4:
			if (no_l3)
			{
				return true;
			}

			return ParsePacketARPv4(p, buf, size);

		case MAC_PROTO_IPV4:
			if (no_l3)
			{
				return true;
			}

			return ParsePacketIPv4(p, buf, size);

		case MAC_PROTO_IPV6:
			if (no_l3)
			{
				return true;
			}

			return ParsePacketIPv6(p, buf, size);

		default:
			return true;
		}
}

bool ParsePacketTAGVLAN(PKT *p, UCHAR *buf, UINT size, bool no_l3)
{
	USHORT vlan_ushort;
	USHORT proto_ushort;
	if (p == NULL || buf == NULL)
	{
		return false;
	}

	if (size < sizeof(TAGVLAN_HEADER))
	{
		return false;
	}

	p->L3.TagVlanHeader = (TAGVLAN_HEADER *)buf;
	p->TypeL3 = L3_TAGVLAN;

	buf += sizeof(TAGVLAN_HEADER);
	size -= sizeof(TAGVLAN_HEADER);

	vlan_ushort = READ_USHORT(p->L3.TagVlanHeader->TagID);
	vlan_ushort = vlan_ushort & 0xFFF;

	p->VlanId = vlan_ushort;

	proto_ushort = READ_USHORT(p->L3.TagVlanHeader->Protocol);
	proto_ushort = proto_ushort & 0xFFFF;

	
	return ParsePacketL3(p, buf, size, proto_ushort, no_l3);
}

bool ParsePacketBPDU(PKT *p, UCHAR *buf, UINT size)
{
	if (p == NULL || buf == NULL)
	{
		return false;
	}

	if (size < sizeof(BPDU_HEADER))
	{
		return true;
	}

	p->L3.BpduHeader = (BPDU_HEADER *)buf;
	p->TypeL3 = L3_BPDU;

	buf += sizeof(BPDU_HEADER);
	size -= sizeof(BPDU_HEADER);

	return true;
}

bool ParsePacketARPv4(PKT *p, UCHAR *buf, UINT size)
{
	if (p == NULL || buf == NULL)
	{
		return false;
	}

	if (size < sizeof(ARPV4_HEADER))
	{
		return false;
	}

	p->L3.ARPv4Header = (ARPV4_HEADER *)buf;
	p->TypeL3 = L3_ARPV4;

	buf += sizeof(ARPV4_HEADER);
	size -= sizeof(ARPV4_HEADER);

	return true;
}

static bool ParseIPv6ExtHeader(IPV6_HEADER_PACKET_INFO *info, UCHAR next_header, UCHAR *buf, UINT size)
{
	IPV6_OPTION_HEADER *option_header;
	UINT option_header_size;
	UCHAR next_header_2 = IPV6_HEADER_NONE;
	if (info == NULL || buf == NULL)
	{
		return false;
	}

	info->IsFragment = false;

	while (true)
	{
		if (size > 8)
		{
			next_header_2 = *((UCHAR *)buf);
		}

		switch (next_header)
		{
		case IPV6_HEADER_HOP:
		case IPV6_HEADER_ENDPOINT:
		case IPV6_HEADER_ROUTING:
			if (size < 8)
			{
				return false;
			}

			option_header = (IPV6_OPTION_HEADER *)buf;
			option_header_size = (option_header->Size + 1) * 8;
			if (size < option_header_size)
			{
				return false;
			}

			switch (next_header)
			{
			case IPV6_HEADER_HOP:
				info->HopHeader = (IPV6_OPTION_HEADER *)buf;
				info->HopHeaderSize = option_header_size;
				break;

			case IPV6_HEADER_ENDPOINT:
				info->EndPointHeader = (IPV6_OPTION_HEADER *)buf;
				info->EndPointHeaderSize = option_header_size;
				break;

			case IPV6_HEADER_ROUTING:
				info->RoutingHeader = (IPV6_OPTION_HEADER *)buf;
				info->RoutingHeaderSize = option_header_size;
				break;
			}

			buf += option_header_size;
			size -= option_header_size;
			break;

		case IPV6_HEADER_FRAGMENT:
			if (size < sizeof(IPV6_FRAGMENT_HEADER))
			{
				return false;
			}

			info->FragmentHeader = (IPV6_FRAGMENT_HEADER *)buf;

			if (IPV6_GET_FRAGMENT_OFFSET(info->FragmentHeader) != 0)
			{
				info->IsFragment = true;
			}

			buf += sizeof(IPV6_FRAGMENT_HEADER);
			size -= sizeof(IPV6_FRAGMENT_HEADER);
			break;

		default:
			if (next_header != IPV6_HEADER_NONE)
			{
				info->Payload = buf;
				info->PayloadSize = size;
			}
			else
			{
				info->Payload = NULL;
				info->PayloadSize = 0;
			}
			info->Protocol = next_header;
			return true;
		}

		next_header = next_header_2;
	}
}

bool ParsePacketIPv6Header(IPV6_HEADER_PACKET_INFO *info, UCHAR *buf, UINT size)
{
	if (info == NULL || buf == NULL)
	{
		Zero(info, sizeof(IPV6_HEADER_PACKET_INFO));
		return false;
	}

	Zero(info, sizeof(IPV6_HEADER_PACKET_INFO));

	if (size < sizeof(IPV6_HEADER))
	{
		return false;
	}

	info->IPv6Header = (IPV6_HEADER *)buf;
	buf += sizeof(IPV6_HEADER);
	size -= sizeof(IPV6_HEADER);

	if (IPV6_GET_VERSION(info->IPv6Header) != 6)
	{
		return false;
	}

	if (ParseIPv6ExtHeader(info, info->IPv6Header->NextHeader, buf, size) == false)
	{
		return false;
	}

	if (info->Payload != NULL)
	{
		info->TotalHeaderSize = (UINT)((UINT64)(info->Payload) - (UINT64)(info->IPv6Header));
	}

	return true;
}

static bool ParseICMPv6Options(ICMPV6_OPTION_LIST *o, UCHAR *buf, UINT size)
{
	if (o == NULL || buf == NULL)
	{
		return false;
	}

	Zero(o, sizeof(ICMPV6_OPTION_LIST));

	while (true)
	{
		ICMPV6_OPTION *option_header;
		UINT header_total_size;
		UCHAR *header_pointer;
		if (size < sizeof(ICMPV6_OPTION))
		{
			return true;
		}

		option_header = (ICMPV6_OPTION *)buf;
		header_total_size = option_header->Length * 8;
		if (header_total_size == 0)
		{
			return true;
		}
		if (size < header_total_size)
		{
			return true;
		}

		header_pointer = buf;
		buf += header_total_size;
		size -= header_total_size;

		switch (option_header->Type)
		{
		case ICMPV6_OPTION_TYPE_SOURCE_LINK_LAYER:
		case ICMPV6_OPTION_TYPE_TARGET_LINK_LAYER:
			if (header_total_size >= sizeof(ICMPV6_OPTION_LINK_LAYER))
			{
				if (option_header->Type == ICMPV6_OPTION_TYPE_SOURCE_LINK_LAYER)
				{
					o->SourceLinkLayer = (ICMPV6_OPTION_LINK_LAYER *)header_pointer;
				}
				else
				{
					o->TargetLinkLayer = (ICMPV6_OPTION_LINK_LAYER *)header_pointer;
				}
			}
			else
			{
				return false;
			}
			break;

		case ICMPV6_OPTION_TYPE_PREFIX:
			if (header_total_size >= sizeof(ICMPV6_OPTION_PREFIX))
			{
				UINT i;
				for (i = 0; i < ICMPV6_OPTION_PREFIXES_MAX_COUNT; i++)
				{
					if (o->Prefix[i] == NULL)
					{
						o->Prefix[i] = (ICMPV6_OPTION_PREFIX *)header_pointer;
						break;
					}
				}
			}
			else
			{
			}
			break;

		case ICMPV6_OPTION_TYPE_MTU:
			if (header_total_size >= sizeof(ICMPV6_OPTION_MTU))
			{
				o->Mtu = (ICMPV6_OPTION_MTU *)header_pointer;
			}
			else
			{
			}
			break;
		}
	}
}

static bool ParseICMPv6(PKT *p, UCHAR *buf, UINT size)
{
	ICMPV6_HEADER_INFO icmp_info;
	ICMP_HEADER *icmp;
	ICMP_ECHO *echo;
	UINT msg_size;
	if (p == NULL || buf == NULL)
	{
		return false;
	}

	Zero(&icmp_info, sizeof(icmp_info));

	if (size < sizeof(ICMP_HEADER))
	{
		return false;
	}

	icmp = (ICMP_HEADER *)buf;
	p->L4.ICMPHeader = icmp;

	msg_size = size - sizeof(ICMP_HEADER);

	icmp_info.Type = icmp->Type;
	icmp_info.Data = ((UCHAR *)buf) + sizeof(ICMP_HEADER);
	icmp_info.DataSize = msg_size;

	switch (icmp_info.Type)
	{
	case ICMPV6_TYPE_ECHO_REQUEST:
	case ICMPV6_TYPE_ECHO_RESPONSE:
		if (icmp_info.DataSize < sizeof(ICMP_ECHO))
		{
			return false;
		}

		echo = (ICMP_ECHO *)icmp_info.Data;

		icmp_info.EchoHeader.Identifier = Endian16(echo->Identifier);
		icmp_info.EchoHeader.SeqNo = Endian16(echo->SeqNo);
		icmp_info.EchoData = (UCHAR *)echo + sizeof(ICMP_ECHO);
		icmp_info.EchoDataSize = icmp_info.DataSize - sizeof(ICMP_ECHO);

		break;

	case ICMPV6_TYPE_ROUTER_SOLICIATION:
		if (icmp_info.DataSize < sizeof(ICMPV6_ROUTER_SOLICIATION_HEADER))
		{
			return false;
		}

		icmp_info.Headers.RouterSoliciationHeader =
		    (ICMPV6_ROUTER_SOLICIATION_HEADER *)(((UCHAR *)icmp_info.Data));

		if (ParseICMPv6Options(&icmp_info.OptionList, ((UCHAR *)icmp_info.Headers.HeaderPointer) + sizeof(ICMPV6_ROUTER_SOLICIATION_HEADER),
		                       icmp_info.DataSize - sizeof(ICMPV6_ROUTER_SOLICIATION_HEADER)) == false)
		{
			return false;
		}

		break;

	case ICMPV6_TYPE_ROUTER_ADVERTISEMENT:
		if (icmp_info.DataSize < sizeof(ICMPV6_ROUTER_ADVERTISEMENT_HEADER))
		{
			return false;
		}

		icmp_info.Headers.RouterAdvertisementHeader =
		    (ICMPV6_ROUTER_ADVERTISEMENT_HEADER *)(((UCHAR *)icmp_info.Data));

		if (ParseICMPv6Options(&icmp_info.OptionList, ((UCHAR *)icmp_info.Headers.HeaderPointer) + sizeof(ICMPV6_ROUTER_ADVERTISEMENT_HEADER),
		                       icmp_info.DataSize - sizeof(ICMPV6_ROUTER_ADVERTISEMENT_HEADER)) == false)
		{
			return false;
		}

		break;

	case ICMPV6_TYPE_NEIGHBOR_SOLICIATION:
		if (icmp_info.DataSize < sizeof(ICMPV6_NEIGHBOR_SOLICIATION_HEADER))
		{
			return false;
		}

		icmp_info.Headers.NeighborSoliciationHeader =
		    (ICMPV6_NEIGHBOR_SOLICIATION_HEADER *)(((UCHAR *)icmp_info.Data));

		if (ParseICMPv6Options(&icmp_info.OptionList, ((UCHAR *)icmp_info.Headers.HeaderPointer) + sizeof(ICMPV6_NEIGHBOR_SOLICIATION_HEADER),
		                       icmp_info.DataSize - sizeof(ICMPV6_NEIGHBOR_SOLICIATION_HEADER)) == false)
		{
			return false;
		}

		break;

	case ICMPV6_TYPE_NEIGHBOR_ADVERTISEMENT:
		if (icmp_info.DataSize < sizeof(ICMPV6_NEIGHBOR_ADVERTISEMENT_HEADER))
		{
			return false;
		}

		icmp_info.Headers.NeighborAdvertisementHeader =
		    (ICMPV6_NEIGHBOR_ADVERTISEMENT_HEADER *)(((UCHAR *)icmp_info.Data));

		if (ParseICMPv6Options(&icmp_info.OptionList, ((UCHAR *)icmp_info.Headers.HeaderPointer) + sizeof(ICMPV6_NEIGHBOR_ADVERTISEMENT_HEADER),
		                       icmp_info.DataSize - sizeof(ICMPV6_NEIGHBOR_ADVERTISEMENT_HEADER)) == false)
		{
			return false;
		}

		break;
	}

	p->TypeL4 = L4_ICMPV6;
	Copy(&p->ICMPv6HeaderPacketInfo, &icmp_info, sizeof(ICMPV6_HEADER_INFO));

	return true;
}

void FreeCloneICMPv6Options(ICMPV6_OPTION_LIST *o)
{
	UINT i;
	if (o == NULL)
	{
		return;
	}

	Free(o->SourceLinkLayer);
	Free(o->TargetLinkLayer);

	for (i = 0; i < ICMPV6_OPTION_PREFIXES_MAX_COUNT; i++)
	{
		Free(o->Prefix[i]);
		o->Prefix[i] = NULL;
	}
	Free(o->Mtu);
}

void CloneICMPv6Options(ICMPV6_OPTION_LIST *dst, ICMPV6_OPTION_LIST *src)
{
	UINT i;
	if (dst == NULL || src == NULL)
	{
		return;
	}

	Zero(dst, sizeof(ICMPV6_OPTION_LIST));

	dst->SourceLinkLayer = Clone(src->SourceLinkLayer, sizeof(ICMPV6_OPTION_LINK_LAYER));
	dst->TargetLinkLayer = Clone(src->TargetLinkLayer, sizeof(ICMPV6_OPTION_LINK_LAYER));
	for (i = 0; i < ICMPV6_OPTION_PREFIXES_MAX_COUNT; i++)
	{
		if (src->Prefix[i] != NULL)
		{
			dst->Prefix[i] = Clone(src->Prefix[i], sizeof(ICMPV6_OPTION_PREFIX));
		}
		else
		{
			break;
		}
	}
	dst->Mtu = Clone(src->Mtu, sizeof(ICMPV6_OPTION_MTU));
}

bool ParsePacketIPv6(PKT *p, UCHAR *buf, UINT size)
{
	if (p == NULL || buf == NULL)
	{
		return false;
	}

	if (ParsePacketIPv6Header(&p->IPv6HeaderPacketInfo, buf, size) == false)
	{
		return false;
	}

	p->TypeL3 = L3_IPV6;
	p->L3.IPv6Header = p->IPv6HeaderPacketInfo.IPv6Header;

	if (p->IPv6HeaderPacketInfo.Payload == NULL)
	{
		return true;
	}

	buf = p->IPv6HeaderPacketInfo.Payload;
	size = p->IPv6HeaderPacketInfo.PayloadSize;

	if (p->IPv6HeaderPacketInfo.IsFragment)
	{
		// This is a fragmented packet. Quit interpreting
		p->TypeL4 = L4_FRAGMENT;
		return true;
	}

	switch (p->IPv6HeaderPacketInfo.Protocol)
	{
	case IP_PROTO_ICMPV6:
		if (ParseICMPv6(p, buf, size) == false)
		{
			// Returns true also if it fails to parse ICMPv6
			return true;
		}
		else
		{
			return true;
		}

	case IP_PROTO_TCP:
		return ParseTCP(p, buf, size);

	case IP_PROTO_UDP:
		return ParseUDP(p, buf, size);

	default:
		return true;
	}

	return true;
}

bool ParsePacketIPv4(PKT *p, UCHAR *buf, UINT size)
{
	UINT header_size;
	if (p == NULL || buf == NULL)
	{
		return false;
	}

	if (size < sizeof(IPV4_HEADER))
	{
		return false;
	}

	p->L3.IPv4Header = (IPV4_HEADER *)buf;
	p->TypeL3 = L3_IPV4;

	header_size = IPV4_GET_HEADER_LEN(p->L3.IPv4Header) * 4;
	if (header_size < sizeof(IPV4_HEADER) || size < header_size)
	{
		p->L3.IPv4Header = NULL;
		p->TypeL3= L3_UNKNOWN;
		return true;
	}

	buf += header_size;
	size -= header_size;

	p->IPv4PayloadSize = MIN(size, Endian16(p->L3.IPv4Header->TotalLength) - header_size);
	if (Endian16(p->L3.IPv4Header->TotalLength) < header_size)
	{
		p->IPv4PayloadSize = 0;
	}

	if (IPV4_GET_OFFSET(p->L3.IPv4Header) != 0)
	{
		p->TypeL4 = L4_FRAGMENT;

		return true;
	}

	switch (p->L3.IPv4Header->Protocol)
	{
	case IP_PROTO_ICMPV4:
		return ParseICMPv4(p, buf, size);

	case IP_PROTO_UDP:
		return ParseUDP(p, buf, size);

	case IP_PROTO_TCP:
		return ParseTCP(p, buf, size);

	default:
		return true;
	}
}

bool ParseICMPv4(PKT *p, UCHAR *buf, UINT size)
{
	if (p == NULL || buf == NULL)
	{
		return false;
	}

	if (size < sizeof(ICMP_HEADER))
	{
		return false;
	}

	p->L4.ICMPHeader = (ICMP_HEADER *)buf;
	p->TypeL4 = L4_ICMPV4;

	buf += sizeof(ICMP_HEADER);
	size -= sizeof(ICMP_HEADER);

	return true;
}

bool ParseTCP(PKT *p, UCHAR *buf, UINT size)
{
	UINT header_size;
	if (p == NULL || buf == NULL)
	{
		return false;
	}

	if (size < sizeof(TCP_HEADER))
	{
		return false;
	}

	p->L4.TCPHeader = (TCP_HEADER *)buf;
	p->TypeL4 = L4_TCP;

	header_size = TCP_GET_HEADER_SIZE(p->L4.TCPHeader) * 4;
	if (header_size < sizeof(TCP_HEADER) || size < header_size)
	{
		p->L4.TCPHeader = NULL;
		p->TypeL4 = L4_UNKNOWN;
		return true;
	}

	buf += header_size;
	size -= header_size;

	p->Payload = buf;
	p->PayloadSize = size;

	return true;
}

static UCHAR GetNextByte(BUF *b)
{
	UCHAR c = 0;
	if (b == NULL)
	{
		return 0;
	}

	if (ReadBuf(b, &c, 1) != 1)
	{
		return 0;
	}

	return c;
}

static bool ParseDnsQuery(char *name, UINT name_size, void *data, UINT data_size)
{
	BUF *b;
	char tmp[DNS_MAX_LABEL_LEN + 1];
	bool ok = true;
	UINT wire_len = 1;		// Octets of the name on the wire: the root label, then each label with its length byte
	USHORT val;
	if (name == NULL || data == NULL || data_size == 0)
	{
		return false;
	}
	StrCpy(name, name_size, "");

	b = NewBuf();
	WriteBuf(b, data, data_size);
	SeekBuf(b, 0, 0);

	while (true)
	{
		UINT next_len = (UINT)GetNextByte(b);
		if (next_len > 0)
		{
			// A label is at most 63 octets and a name at most 255 (RFC 1035 2.3.4). A length byte
			// above 63 is no length: 0xC0 starts a compression pointer, 0x40 and 0x80 extended
			// label types. None of them is read as a label
			wire_len += 1 + next_len;
			if (next_len > DNS_MAX_LABEL_LEN || wire_len > DNS_MAX_NAME_LEN)
			{
				ok = false;
				break;
			}

			Zero(tmp, sizeof(tmp));
			if (ReadBuf(b, tmp, next_len) != next_len)
			{
				ok = false;
				break;
			}
			if (StrLen(name) != 0)
			{
				StrCat(name, name_size, ".");
			}
			StrCat(name, name_size, tmp);
		}
		else
		{
			break;
		}
	}

	if (ReadBuf(b, &val, sizeof(val)) != sizeof(val))
	{
		ok = false;
	}
	else
	{
		if (Endian16(val) != 0x01 && Endian16(val) != 0x0c)
		{
			ok = false;
		}
	}

	if (ReadBuf(b, &val, sizeof(val)) != sizeof(val))
	{
		ok = false;
	}
	else
	{
		if (Endian16(val) != 0x01)
		{
			ok = false;
		}
	}

	FreeBuf(b);

	if (ok == false || StrLen(name) == 0)
	{
		return false;
	}
	else
	{
		return true;
	}
}

static void ParseDNS(PKT *p, UCHAR *buf, UINT size)
{
	UCHAR *query_data;
	UINT query_data_size;
	DNSV4_HEADER *dns;
	char hostname[MAX_SIZE];
	if (p == NULL|| buf == NULL)
	{
		return;
	}

	if (size < sizeof(DNSV4_HEADER))
	{
		return;
	}

	dns = (DNSV4_HEADER *)buf;

	// A standard query only: not a response, opcode 0 (QUERY), whatever its AA, TC and RD bits
	if ((dns->Flag1 & (DNS_FLAG1_QR | DNS_FLAG1_OPCODE)) != 0)
	{
		return;
	}
	if (Endian16(dns->NumQuery) != 1)
	{
		return;
	}

	query_data = ((UCHAR *)dns) + sizeof(DNSV4_HEADER);
	query_data_size = size - sizeof(DNSV4_HEADER);

	if (ParseDnsQuery(hostname, sizeof(hostname), query_data, query_data_size) == false)
	{
		return;
	}

	StrCpy(p->DnsQueryHost, sizeof(p->DnsQueryHost), hostname);
	p->TypeL7 = L7_DNS;
}

bool ParseUDP(PKT *p, UCHAR *buf, UINT size)
{
	USHORT src_port, dst_port;
	if (p == NULL || buf == NULL)
	{
		return false;
	}

	if (size < sizeof(UDP_HEADER))
	{
		return false;
	}

	p->L4.UDPHeader = (UDP_HEADER *)buf;
	p->TypeL4 = L4_UDP;

	buf += sizeof(UDP_HEADER);
	size -= sizeof(UDP_HEADER);

	p->Payload = buf;
	p->PayloadSize = size;

	src_port = Endian16(p->L4.UDPHeader->SrcPort);
	dst_port = Endian16(p->L4.UDPHeader->DstPort);

	if ((src_port == 67 && dst_port == 68) ||
	        (src_port == 68 && dst_port == 67))
	{
		if (p->TypeL3 == L3_IPV4)
		{
			ParseDHCPv4(p, buf, size);

			return true;
		}
	}

	if (dst_port == 53)
	{
		// ParsePacketEx5 parses the DNS query, unless its caller skips it
		return true;
	}


	if (src_port == 500 || dst_port == 500 || src_port == 4500 || dst_port == 4500)
	{
		if (p->PayloadSize >= sizeof(IKE_HEADER))
		{
			IKE_HEADER *ike_header = (IKE_HEADER *)p->Payload;

			if (ike_header->InitiatorCookie != 0 && ike_header->ResponderCookie == 0 &&
			        (ike_header->ExchangeType == IKE_EXCHANGE_TYPE_MAIN ||
			         ike_header->ExchangeType == IKE_EXCHANGE_TYPE_AGGRESSIVE))
			{
				p->TypeL7 = L7_IKECONN;
				p->L7.IkeHeader = ike_header;
				return true;
			}
		}
	}

	return true;
}

void ParseDHCPv4(PKT *p, UCHAR *buf, UINT size)
{
	if (p == NULL || buf == NULL)
	{
		return;
	}

	if (size < sizeof(DHCPV4_HEADER))
	{
		return;
	}

	p->L7.DHCPv4Header = (DHCPV4_HEADER *)buf;
	p->TypeL7 = L7_DHCPV4;
}

void FreePacket(PKT *p)
{
	if (p == NULL)
	{
		return;
	}

	// The headers of a PKT point into the buffer the caller owns: only the HTTP log is the PKT's own
	Free(p->HttpLog);
	Free(p);
}

USHORT IpChecksum(void *buf, UINT size)
{
	return IpChecksumFinish(IpChecksumAdd(0, buf, size));
}

static BUF *BuildDhcpOptionsBuf(LIST *o)
{
	BUF *b;
	UINT i;
	UCHAR id;
	UCHAR sz;
	if (o == NULL)
	{
		return NULL;
	}

	b = NewBuf();
	for (i = 0; i < LIST_NUM(o); i++)
	{
		DHCP_OPTION *d = LIST_DATA(o, i);
		UINT current_size = d->Size;
		UINT current_pos = 0;

		id = (UCHAR)d->Id;
		if (d->Size <= 255)
		{
			sz = (UCHAR)d->Size;
		}
		else
		{
			sz = 0xFF;
		}
		WriteBuf(b, &id, 1);
		WriteBuf(b, &sz, 1);
		WriteBuf(b, d->Data, sz);

		current_size -= sz;
		current_pos += sz;

		while (current_size != 0)
		{
			id = DHCP_ID_PRIVATE;
			if (current_size <= 255)
			{
				sz = (UCHAR)current_size;
			}
			else
			{
				sz = 0xFF;
			}
			WriteBuf(b, &id, 1);
			WriteBuf(b, &sz, 1);
			WriteBuf(b, ((UCHAR *)d->Data) + current_pos, sz);

			current_size -= sz;
			current_pos += sz;
		}

	}

	id = 0xff;
	WriteBuf(b, &id, 1);

	return b;
}

static DHCP_OPTION *NewDhcpOption(UINT id, void *data, UINT size)
{
	DHCP_OPTION *ret;
	if (size != 0 && data == NULL)
	{
		return NULL;
	}

	ret = ZeroMalloc(sizeof(DHCP_OPTION));
	ret->Data = ZeroMalloc(size);
	Copy(ret->Data, data, size);
	ret->Size = size;
	ret->Id = id;

	return ret;
}

DHCP_OPTION *GetDhcpOption(LIST *o, UINT id)
{
	UINT i;
	DHCP_OPTION *ret = NULL;
	if (o == NULL)
	{
		return NULL;
	}

	for (i = 0; i < LIST_NUM(o); i++)
	{
		DHCP_OPTION *opt = LIST_DATA(o, i);
		if (opt->Id == id)
		{
			ret = opt;
		}
	}

	return ret;
}

void FreeDhcpOptions(LIST *o)
{
	UINT i;
	if (o == NULL)
	{
		return;
	}

	for (i = 0; i < LIST_NUM(o); i++)
	{
		DHCP_OPTION *opt = LIST_DATA(o, i);
		Free(opt->Data);
		Free(opt);
	}

	ReleaseList(o);
}

// Parse DHCP options (RFC 2132 3): Pad (0) is one byte, End (255) or the end of the data ends the
// list, and every other option is its code, its length byte and that many bytes. An option is taken
// only with its whole body: an option code without its length byte, or a body that runs past the
// end of the data, ends the list without that option. Option 250 (DHCP_ID_PRIVATE) continues the
// option before it: BuildDhcpOptionsBuf splits an option of more than 255 bytes that way
LIST *ParseDhcpOptions(void *data, UINT size)
{
	BUF *b;
	LIST *o;
	DHCP_OPTION *last_opt;
	if (data == NULL)
	{
		return NULL;
	}

	b = NewBuf();
	WriteBuf(b, data, size);
	SeekBuf(b, 0, 0);

	o = NewListFast(NULL);

	last_opt = NULL;

	while (true)
	{
		UCHAR c = 0;
		UCHAR sz = 0;
		UCHAR *body;
		DHCP_OPTION *opt;
		if (ReadBuf(b, &c, 1) != 1)
		{
			break;
		}
		if (c == 0xff)
		{
			break;
		}
		if (c == 0x00)
		{
			// Pad: one byte, without a length
			continue;
		}
		if (ReadBuf(b, &sz, 1) != 1)
		{
			break;
		}

		body = ZeroMalloc((UINT)sz);
		if (ReadBuf(b, body, sz) != sz)
		{
			// The body runs past the end of the data
			Free(body);
			break;
		}

		if (c == DHCP_ID_PRIVATE && last_opt != NULL)
		{
			UINT new_size = last_opt->Size + (UINT)sz;
			UCHAR *new_buf = ZeroMalloc(new_size);
			Copy(new_buf, last_opt->Data, last_opt->Size);
			Copy(new_buf + last_opt->Size, body, sz);
			Free(body);
			Free(last_opt->Data);
			last_opt->Data = new_buf;
			last_opt->Size = new_size;
		}
		else
		{
			opt = ZeroMalloc(sizeof(DHCP_OPTION));
			opt->Id = (UINT)c;
			opt->Size = (UINT)sz;
			opt->Data = body;
			Add(o, opt);

			last_opt = opt;
		}
	}

	FreeBuf(b);

	return o;
}

BUF *DhcpModifyIPv4(DHCP_MODIFY_OPTION *m, void *data, UINT size)
{
	PKT *p;
	BUF *ret = NULL;
	if (m == NULL || data == NULL || size == 0)
	{
		return NULL;
	}

	p = ParsePacketEx4(data, size, false, 0, false, false, false);

	if (p != NULL && p->TypeL3 == L3_IPV4 && p->TypeL4 == L4_UDP && p->TypeL7 == L7_DHCPV4)
	{
		BUF *new_buf = DhcpModify(m, p->Payload, p->PayloadSize);

		if (new_buf != NULL)
		{
			ret = NewBuf();

			WriteBuf(ret, p->PacketData, p->PacketSize - p->PayloadSize);
			WriteBuf(ret, new_buf->Buf, new_buf->Size);

			FreeBuf(new_buf);
		}
	}

	FreePacket(p);

	if (ret != NULL)
	{
		PKT *p = ParsePacketEx4(ret->Buf, ret->Size, false, 0, false, false, false);

		if (p != NULL)
		{
			if (p->TypeL3 == L3_IPV4 && p->TypeL4 == L4_UDP)
			{
				UDP_HEADER *udp = p->L4.UDPHeader;

				udp->Checksum = 0;
				udp->Checksum = CalcChecksumForIPv4(p->L3.IPv4Header->SrcIP,
				                                    p->L3.IPv4Header->DstIP,
				                                    IP_PROTO_UDP,
				                                    udp,
				                                    p->PacketSize - (UINT)(((UCHAR *)udp) - ((UCHAR *)p->PacketData)), 0);
			}

			FreePacket(p);
		}
	}

	return ret;
}

BUF *DhcpModify(DHCP_MODIFY_OPTION *m, void *data, UINT size)
{
	UCHAR *options;
	UINT options_size;
	UINT opcode;
	bool ret_ok = false;
	BUF *ret = NULL;
	BUF *opt_buf = NULL;
	LIST *opt_list = NULL;
	LIST *opt_list2 = NULL;
	UINT src_size = size;
	UINT i;
	UINT dhcp_min_size;
	if (m == NULL || data == NULL || size == 0)
	{
		return NULL;
	}

	options = DhcpOptionsOf(data, size, &options_size);
	if (options == NULL)
	{
		goto LABEL_CLEANUP;
	}

	ret = NewBuf();
	WriteBuf(ret, data, (UINT)(options - ((UCHAR *)data)));

	opt_list = ParseDhcpOptions(options, options_size);
	if (opt_list == NULL)
	{
		goto LABEL_CLEANUP;
	}

	opcode = DhcpMessageType(opt_list);

	opt_list2 = NewListFast(NULL);

	for (i = 0; i < LIST_NUM(opt_list); i++)
	{
		DHCP_OPTION *o = LIST_DATA(opt_list, i);
		DHCP_OPTION *o2 = NULL;
		bool ok = true;

		if (m->RemoveDefaultGatewayOnReply)
		{
			if (opcode == DHCP_OFFER || opcode == DHCP_ACK)
			{
				if (o->Id == DHCP_ID_GATEWAY_ADDR)
				{
					ok = false;
				}
				if (o->Id == DHCP_ID_DNS_ADDR || o->Id == DHCP_ID_WINS_ADDR || o->Id == DHCP_ID_DOMAIN_NAME)
				{
					ok = false;
				}
			}
		}

		if (ok)
		{
			o2 = NewDhcpOption(o->Id, o->Data, o->Size);
			if (o2 != NULL)
			{
				Add(opt_list2, o2);
			}

		}

	}

	opt_buf = BuildDhcpOptionsBuf(opt_list2);

	WriteBuf(ret, opt_buf->Buf, opt_buf->Size);

	if (src_size != ret->Size || Cmp(data, ret->Buf, ret->Size) != 0)
	{
		ret_ok = true;

		// Use src_size as the minimum DHCP size when it exceeds DHCP_MIN_SIZE
		dhcp_min_size = MAX(src_size, DHCP_MIN_SIZE);
		if (ret->Size < dhcp_min_size)
		{
			UCHAR *pad_buf;
			UINT pad_size = dhcp_min_size - ret->Size;

			pad_buf = ZeroMalloc(pad_size);

			WriteBuf(ret, pad_buf, pad_size);

			Free(pad_buf);
		}
	}

LABEL_CLEANUP:
	if (opt_buf != NULL)
	{
		FreeBuf(opt_buf);
	}

	if (opt_list != NULL)
	{
		FreeDhcpOptions(opt_list);
	}

	if (opt_list2 != NULL)
	{
		FreeDhcpOptions(opt_list2);
	}

	if (ret_ok)
	{
		return ret;
	}
	else
	{
		FreeBuf(ret);
		return NULL;
	}
}

void GenMacAddress(UCHAR *mac)
{
	UCHAR rand_data[32];
	UINT64 now;
	BUF *b;
	UCHAR hash[SHA1_SIZE];
	if (mac == NULL)
	{
		return;
	}

	now = SystemTime64();

	Rand(rand_data, sizeof(rand_data));

	b = NewBuf();
	WriteBuf(b, &now, sizeof(now));
	WriteBuf(b, rand_data, sizeof(rand_data));

	Sha0(hash, b->Buf, b->Size);

	mac[0] = 0x5E;
	mac[1] = hash[0];
	mac[2] = hash[1];
	mac[3] = hash[2];
	mac[4] = hash[3];
	mac[5] = hash[4];

	FreeBuf(b);
}
