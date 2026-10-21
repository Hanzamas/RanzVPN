// TcpIp.c
// Utility module for TCP/IP packet processing

#include "TcpIp.h"

#include "Cfg.h"
#include "Memory.h"
#include "Str.h"

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

		if (v6.IPv6Header == NULL)
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

// The checksum of a TCP or UDP segment over the pseudo-header of the packet's IP version, with the
// size and the real_size of CalcChecksumForIPv4 and CalcChecksumForIPv6
static USHORT CalcL4Checksum(PKT *p, UCHAR protocol, void *data, UINT size, UINT real_size)
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
static void FixOffloadChecksum(PKT *p, UCHAR protocol, void *l4, void *checksum_field, UINT len, bool complete)
{
	USHORT checksum;
	USHORT offloading_checksum;

	Copy(&checksum, checksum_field, sizeof(checksum));

	if (protocol == IP_PROTO_UDP && checksum == 0)
	{
		return;
	}

	offloading_checksum = CalcL4Checksum(p, protocol, NULL, 0, len);

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
			break;

		case ICMPV6_OPTION_TYPE_MTU:
			if (header_total_size >= sizeof(ICMPV6_OPTION_MTU))
			{
				o->Mtu = (ICMPV6_OPTION_MTU *)header_pointer;
			}
			break;
		}
	}
}

// The ICMPv6 messages that have a fixed header followed by options, and the size of that header
static const struct
{
	UCHAR Type;
	UINT HeaderSize;
} icmpv6_option_messages[] =
{
	{ICMPV6_TYPE_ROUTER_SOLICIATION, sizeof(ICMPV6_ROUTER_SOLICIATION_HEADER)},
	{ICMPV6_TYPE_ROUTER_ADVERTISEMENT, sizeof(ICMPV6_ROUTER_ADVERTISEMENT_HEADER)},
	{ICMPV6_TYPE_NEIGHBOR_SOLICIATION, sizeof(ICMPV6_NEIGHBOR_SOLICIATION_HEADER)},
	{ICMPV6_TYPE_NEIGHBOR_ADVERTISEMENT, sizeof(ICMPV6_NEIGHBOR_ADVERTISEMENT_HEADER)},
};

static bool ParseICMPv6(PKT *p, UCHAR *buf, UINT size)
{
	ICMPV6_HEADER_INFO icmp_info;
	ICMP_HEADER *icmp;
	ICMP_ECHO *echo;
	UINT msg_size;
	UINT i;
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

	if (icmp_info.Type == ICMPV6_TYPE_ECHO_REQUEST || icmp_info.Type == ICMPV6_TYPE_ECHO_RESPONSE)
	{
		if (icmp_info.DataSize < sizeof(ICMP_ECHO))
		{
			return false;
		}

		echo = (ICMP_ECHO *)icmp_info.Data;

		icmp_info.EchoHeader.Identifier = Endian16(echo->Identifier);
		icmp_info.EchoHeader.SeqNo = Endian16(echo->SeqNo);
		icmp_info.EchoData = (UCHAR *)echo + sizeof(ICMP_ECHO);
		icmp_info.EchoDataSize = icmp_info.DataSize - sizeof(ICMP_ECHO);
	}

	for (i = 0; i < sizeof(icmpv6_option_messages) / sizeof(icmpv6_option_messages[0]); i++)
	{
		if (icmpv6_option_messages[i].Type == icmp_info.Type)
		{
			UINT header_size = icmpv6_option_messages[i].HeaderSize;

			if (icmp_info.DataSize < header_size)
			{
				return false;
			}

			icmp_info.Headers.HeaderPointer = icmp_info.Data;

			if (ParseICMPv6Options(&icmp_info.OptionList, ((UCHAR *)icmp_info.Headers.HeaderPointer) + header_size,
			                       icmp_info.DataSize - header_size) == false)
			{
				return false;
			}

			break;
		}
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
}

USHORT IpChecksum(void *buf, UINT size)
{
	return IpChecksumFinish(IpChecksumAdd(0, buf, size));
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
