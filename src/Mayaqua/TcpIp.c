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
	TCP_HEADER *tcp = NULL;
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

	if (options_size >= 4 && options[0] == 0x02 && options[1] == 0x04)
	{
		USHORT current_mss = READ_USHORT(((UCHAR *)options) + 2);

		if (current_mss <= mss)
		{
			// Leave the MSS alone if it is already at or below the target
			return false;
		}
		else
		{
			WRITE_USHORT(((UCHAR *)options) + 2, mss);

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


DHCPV4_DATA *ParseDHCPv4Data(PKT *pkt)
{
	DHCPV4_DATA *d;
	UCHAR *data;
	UINT size;
	UINT magic_cookie = Endian32(DHCP_MAGIC_COOKIE);
	bool ok = false;
	DHCP_OPTION *o;
	if (pkt == NULL)
	{
		return NULL;
	}
	if (pkt->TypeL3 != L3_IPV4 || pkt->TypeL4 != L4_UDP || pkt->TypeL7 != L7_DHCPV4)
	{
		return NULL;
	}

	d = ZeroMalloc(sizeof(DHCPV4_DATA));
	d->Size = (UINT)(pkt->PacketSize - (((UCHAR *)pkt->L7.PointerL7) - ((UCHAR *)pkt->PacketData)));
	d->Data = Clone(pkt->L7.PointerL7, d->Size);

	if (d->Size < sizeof(DHCPV4_HEADER))
	{
		goto LABEL_ERROR;
	}

	d->Header = (DHCPV4_HEADER *)d->Data;

	data = d->Data;
	size = d->Size;

	ok = false;
	while (size >= 5)
	{
		if (Cmp(data, &magic_cookie, 4) == 0)
		{
			data += 4;
			size -= 4;
			ok = true;
			break;
		}

		data++;
		size--;
	}

	if (ok == false)
	{
		goto LABEL_ERROR;
	}

	d->OptionData = data;
	d->OptionSize = size;

	d->OptionList = ParseDhcpOptions(data, size);
	if (d->OptionList == NULL)
	{
		goto LABEL_ERROR;
	}

	UINTToIP(&d->SrcIP, pkt->L3.IPv4Header->SrcIP);
	UINTToIP(&d->DestIP, pkt->L3.IPv4Header->DstIP);

	d->SrcPort = Endian16(pkt->L4.UDPHeader->SrcPort);
	d->DestPort = Endian16(pkt->L4.UDPHeader->DstPort);

	o = GetDhcpOption(d->OptionList, DHCP_ID_MESSAGE_TYPE);
	if (o == NULL || o->Size != 1)
	{
		goto LABEL_ERROR;
	}

	d->OpCode = *((UCHAR *)o->Data);

	d->ParsedOptionList = ParseDhcpOptionList(d->OptionData, d->OptionSize);

	if (d->ParsedOptionList == NULL)
	{
		goto LABEL_ERROR;
	}

	if (d->ParsedOptionList->ServerAddress == 0)
	{
		d->ParsedOptionList->ServerAddress = d->Header->ServerIP;
	}

	d->ParsedOptionList->ClientAddress = d->Header->YourIP;

	return d;

LABEL_ERROR:
	FreeDHCPv4Data(d);
	return NULL;
}

void FreeDHCPv4Data(DHCPV4_DATA *d)
{
	if (d == NULL)
	{
		return;
	}

	FreeDhcpOptions(d->OptionList);
	Free(d->Data);

	Free(d->ParsedOptionList);

	Free(d);
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

BUF *BuildICMPv6(IPV6_ADDR *src_ip, IPV6_ADDR *dest_ip, UCHAR hop_limit, UCHAR type, UCHAR code, void *data, UINT size, UINT id)
{
	ICMP_HEADER *icmp;
	void *data_buf;
	BUF *ret;
	if (src_ip == NULL || dest_ip == NULL || data == NULL)
	{
		return NULL;
	}

	icmp = ZeroMalloc(sizeof(ICMP_HEADER) + size);
	data_buf = ((UCHAR *)icmp) + sizeof(ICMP_HEADER);
	Copy(data_buf, data, size);

	icmp->Type = type;
	icmp->Code = code;
	icmp->Checksum = CalcChecksumForIPv6(src_ip, dest_ip, IP_PROTO_ICMPV6, icmp,
	                                     sizeof(ICMP_HEADER) + size, 0);

	ret = BuildIPv6(dest_ip, src_ip, id, IP_PROTO_ICMPV6, hop_limit, icmp,
	                sizeof(ICMP_HEADER) + size);

	Free(icmp);

	return ret;
}

BUF *BuildICMPv6NeighborSoliciation(IPV6_ADDR *src_ip, IPV6_ADDR *target_ip, UCHAR *my_mac_address, UINT id, bool use_multicast)
{
	ICMPV6_OPTION_LIST opt;
	ICMPV6_OPTION_LINK_LAYER link;
	ICMPV6_NEIGHBOR_SOLICIATION_HEADER header;
	BUF *b;
	BUF *b2;
	BUF *ret;
	if (src_ip == NULL || target_ip == NULL || my_mac_address == NULL)
	{
		return NULL;
	}

	Zero(&link, sizeof(link));
	Copy(link.Address, my_mac_address, 6);

	Zero(&opt, sizeof(opt));
	opt.SourceLinkLayer = &link;

	b = BuildICMPv6Options(&opt);

	Zero(&header, sizeof(header));
	Copy(&header.TargetAddress, target_ip, sizeof(IPV6_ADDR));

	b2 = NewBuf();

	WriteBuf(b2, &header, sizeof(header));
	WriteBufBuf(b2, b);

	if (use_multicast)
	{
		IPV6_ADDR solicitAddress;
		Zero(&solicitAddress, sizeof(IPV6_ADDR));
		solicitAddress.Value[0] = 0xFF;
		solicitAddress.Value[1] = 0x02;
		solicitAddress.Value[11] = 0x01;
		solicitAddress.Value[12] = 0xFF;
		Copy(&solicitAddress.Value[13], &target_ip->Value[13], 3);

		ret = BuildICMPv6(src_ip, &solicitAddress, 255,
	                          ICMPV6_TYPE_NEIGHBOR_SOLICIATION, 0, b2->Buf, b2->Size, id);
	}
	else
	{
		ret = BuildICMPv6(src_ip, target_ip, 255,
	                          ICMPV6_TYPE_NEIGHBOR_SOLICIATION, 0, b2->Buf, b2->Size, id);
	}

	FreeBuf(b);
	FreeBuf(b2);

	return ret;
}

UCHAR IPv6GetNextHeaderFromQueue(QUEUE *q)
{
	UINT *p;
	UCHAR v = 0;
	if (q == NULL)
	{
		return IPV6_HEADER_NONE;
	}

	p = (UINT *)GetNext(q);
	if (p != NULL)
	{
		v = (UCHAR)(*p);
		Free(p);
	}

	return v;
}

void BuildAndAddIPv6PacketOptionHeader(BUF *b, IPV6_OPTION_HEADER *opt, UCHAR next_header, UINT size)
{
	IPV6_OPTION_HEADER *h;
	UINT total_size;
	if (b == NULL || opt == NULL)
	{
		return;
	}

	total_size = size;
	if ((total_size % 8) != 0)
	{
		total_size = ((total_size / 8) + 1) * 8;
	}

	h = ZeroMalloc(total_size);
	Copy(h, opt, size);
	h->Size = (total_size / 8) - 1;
	h->NextHeader = next_header;

	WriteBuf(b, h, total_size);

	Free(h);
}

BUF *BuildIPv6(IPV6_ADDR *dest_ip, IPV6_ADDR *src_ip, UINT id, UCHAR protocol, UCHAR hop_limit, void *data,
               UINT size)
{
	IPV6_HEADER_PACKET_INFO info;
	IPV6_HEADER ip_header;
	BUF *buf;
	UINT size_for_headers;
	if (dest_ip == NULL || src_ip == NULL || data == NULL)
	{
		return NULL;
	}
	if (hop_limit == 0)
	{
		hop_limit = 255;
	}

	Zero(&ip_header, sizeof(ip_header));
	IPV6_SET_VERSION(&ip_header, 6);
	ip_header.HopLimit = hop_limit;
	Copy(&ip_header.SrcAddress, src_ip, sizeof(IPV6_ADDR));
	Copy(&ip_header.DestAddress, dest_ip, sizeof(IPV6_ADDR));

	Zero(&info, sizeof(info));
	info.IPv6Header = &ip_header;
	info.Protocol = protocol;
	info.Payload = data;
	info.PayloadSize = size;

	buf = BuildIPv6PacketHeader(&info, &size_for_headers);
	if (buf == NULL)
	{
		return NULL;
	}

	return buf;
}

BUF *BuildIPv6PacketHeader(IPV6_HEADER_PACKET_INFO *info, UINT *bytes_before_payload)
{
	BUF *b;
	QUEUE *q;
	UINT bbp = 0;
	if (info == NULL)
	{
		return NULL;
	}

	b = NewBuf();
	q = NewQueueFast();

	if (info->HopHeader != NULL)
	{
		InsertQueueInt(q, IPV6_HEADER_HOP);
	}
	if (info->EndPointHeader != NULL)
	{
		InsertQueueInt(q, IPV6_HEADER_ENDPOINT);
	}
	if (info->RoutingHeader != NULL)
	{
		InsertQueueInt(q, IPV6_HEADER_ROUTING);
	}
	if (info->FragmentHeader != NULL)
	{
		InsertQueueInt(q, IPV6_HEADER_FRAGMENT);
	}
	InsertQueueInt(q, info->Protocol);

	info->IPv6Header->NextHeader = IPv6GetNextHeaderFromQueue(q);
	WriteBuf(b, info->IPv6Header, sizeof(IPV6_HEADER));

	if (info->HopHeader != NULL)
	{
		BuildAndAddIPv6PacketOptionHeader(b, info->HopHeader,
		                                  IPv6GetNextHeaderFromQueue(q), info->HopHeaderSize);
	}

	if (info->EndPointHeader != NULL)
	{
		BuildAndAddIPv6PacketOptionHeader(b, info->EndPointHeader,
		                                  IPv6GetNextHeaderFromQueue(q), info->EndPointHeaderSize);
	}

	if (info->RoutingHeader != NULL)
	{
		BuildAndAddIPv6PacketOptionHeader(b, info->RoutingHeader,
		                                  IPv6GetNextHeaderFromQueue(q), info->RoutingHeaderSize);
	}

	if (info->FragmentHeader != NULL)
	{
		info->FragmentHeader->NextHeader = IPv6GetNextHeaderFromQueue(q);
		WriteBuf(b, info->FragmentHeader, sizeof(IPV6_FRAGMENT_HEADER));
	}

	bbp = b->Size;
	if (info->FragmentHeader == NULL)
	{
		bbp += sizeof(IPV6_FRAGMENT_HEADER);
	}

	if (info->Protocol != IPV6_HEADER_NONE)
	{
		WriteBuf(b, info->Payload, info->PayloadSize);
	}

	ReleaseQueue(q);

	SeekBuf(b, 0, 0);

	((IPV6_HEADER *)b->Buf)->PayloadLength = Endian16(b->Size - (USHORT)sizeof(IPV6_HEADER));

	if (bytes_before_payload != NULL)
	{
		// Length up to the payload, assuming a fragment header is always present
		*bytes_before_payload = bbp;
	}

	return b;
}

void BuildICMPv6OptionValue(BUF *b, UCHAR type, void *header_pointer, UINT total_size)
{
	UINT packet_size;
	UCHAR *packet;
	ICMPV6_OPTION *opt;
	if (b == NULL || header_pointer == NULL)
	{
		return;
	}

	packet_size = ((total_size + 7) / 8) * 8;
	packet = ZeroMalloc(packet_size);

	Copy(packet, header_pointer, total_size);
	opt = (ICMPV6_OPTION *)packet;
	opt->Length = (UCHAR)(packet_size / 8);
	opt->Type = type;

	WriteBuf(b, packet, packet_size);

	Free(packet);
}

BUF *BuildICMPv6Options(ICMPV6_OPTION_LIST *o)
{
	BUF *b;
	UINT i;
	if (o == NULL)
	{
		return NULL;
	}

	b = NewBuf();

	if (o->SourceLinkLayer != NULL)
	{
		BuildICMPv6OptionValue(b, ICMPV6_OPTION_TYPE_SOURCE_LINK_LAYER, o->SourceLinkLayer, sizeof(ICMPV6_OPTION_LINK_LAYER));
	}
	if (o->TargetLinkLayer != NULL)
	{
		BuildICMPv6OptionValue(b, ICMPV6_OPTION_TYPE_TARGET_LINK_LAYER, o->TargetLinkLayer, sizeof(ICMPV6_OPTION_LINK_LAYER));
	}
	for (i = 0; i < ICMPV6_OPTION_PREFIXES_MAX_COUNT; i++)
	{
		if (o->Prefix[i] != NULL)
		{
			BuildICMPv6OptionValue(b, ICMPV6_OPTION_TYPE_PREFIX, o->Prefix[i], sizeof(ICMPV6_OPTION_PREFIX));
		}
		else
		{
			break;
		}
	}
	if (o->Mtu != NULL)
	{
		BuildICMPv6OptionValue(b, ICMPV6_OPTION_TYPE_MTU, o->Mtu, sizeof(ICMPV6_OPTION_MTU));
	}

	SeekBuf(b, 0, 0);

	return b;
}

USHORT CalcChecksumForIPv4(UINT src_ip, UINT dst_ip, UCHAR protocol, void *data, UINT size, UINT real_size)
{
	UCHAR *tmp;
	UINT tmp_size;
	IPV4_PSEUDO_HEADER *ph;
	USHORT ret;
	bool use_free = false;
	UCHAR tmp_buffer[1600];
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

	tmp_size = size + sizeof(IPV4_PSEUDO_HEADER);

	if (tmp_size > sizeof(tmp_buffer))
	{
		tmp = Malloc(tmp_size);

		use_free = true;
	}
	else
	{
		tmp = tmp_buffer;
	}

	ph = (IPV4_PSEUDO_HEADER *)tmp;
	ph->SrcIP = src_ip;
	ph->DstIP = dst_ip;
	ph->PacketLength = Endian16(real_size);
	ph->Protocol = protocol;
	ph->Reserved = 0;

	if (size >= 1)
	{
		Copy(((UCHAR *)tmp) + sizeof(IPV4_PSEUDO_HEADER), data, size);
	}

	ret = IpChecksum(tmp, tmp_size);

	if (use_free)
	{
		Free(tmp);
	}

	return ret;
}

USHORT CalcChecksumForIPv6(IPV6_ADDR *src_ip, IPV6_ADDR *dest_ip, UCHAR protocol, void *data, UINT size, UINT real_size)
{
	UCHAR *tmp;
	UINT tmp_size;
	IPV6_PSEUDO_HEADER *ph;
	USHORT ret;
	bool use_free = false;
	UCHAR tmp_buffer[256];
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

	tmp_size = size + sizeof(IPV6_PSEUDO_HEADER);

	if (tmp_size > sizeof(tmp_buffer))
	{
		tmp = Malloc(tmp_size);

		use_free = true;
	}
	else
	{
		tmp = tmp_buffer;
	}

	ph = (IPV6_PSEUDO_HEADER *)tmp;
	Zero(ph, sizeof(IPV6_PSEUDO_HEADER));
	Copy(&ph->SrcAddress, src_ip, sizeof(IPV6_ADDR));
	Copy(&ph->DestAddress, dest_ip, sizeof(IPV6_ADDR));
	ph->UpperLayerPacketSize = Endian32(real_size);
	ph->NextHeader = protocol;

	Copy(((UCHAR *)tmp) + sizeof(IPV6_PSEUDO_HEADER), data, size);

	ret = IpChecksum(tmp, tmp_size);

	if (use_free)
	{
		Free(tmp);
	}

	return ret;
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
PKT *ParsePacketEx5(UCHAR *buf, UINT size, bool no_l3, UINT vlan_type_id, bool bridge_id_as_mac_address, bool no_http, bool correct_checksum, bool no_l3_l4_except_icmpv6)
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

	p->VlanTypeID = vlan_type_id;

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

	if (ParsePacketL2Ex(p, buf, size, no_l3, no_l3_l4_except_icmpv6) == false)
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

	if (p->TypeL3 == L3_IPV4 && p->TypeL4 == L4_UDP && p->TypeL7 == L7_DHCPV4)
	{
		DHCPV4_DATA *d = ParseDHCPv4Data(p);

		if (d != NULL)
		{
			p->DhcpOpCode = d->OpCode;

			FreeDHCPv4Data(d);
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
				StrCpy(h.Method, sizeof(h.Hostname), tokens->Token[0]);
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


bool ParsePacketL2Ex(PKT *p, UCHAR *buf, UINT size, bool no_l3, bool no_l3_l4_except_icmpv6)
{
	UINT i;
	bool b1, b2;
	USHORT type_id_16;
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

	if (type_id_16 > 1500)
	{
		if (type_id_16 == MAC_PROTO_TAGVLAN)
		{
			return ParsePacketTAGVLAN(p, buf, size, no_l3, no_l3_l4_except_icmpv6);
		}
		else
		{
			return ParsePacketL3(p, buf, size, type_id_16, no_l3, no_l3_l4_except_icmpv6);
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

bool ParsePacketL3(PKT *p, UCHAR *buf, UINT size, USHORT proto, bool no_l3, bool no_l3_l4_except_icmpv6)
{
	switch (proto)
		{
		case MAC_PROTO_ARPV4:
			if (no_l3 || no_l3_l4_except_icmpv6)
			{
				return true;
			}

			return ParsePacketARPv4(p, buf, size);

		case MAC_PROTO_IPV4:
			if (no_l3 || no_l3_l4_except_icmpv6)
			{
				return true;
			}

			return ParsePacketIPv4(p, buf, size);

		case MAC_PROTO_IPV6:
			if (no_l3)
			{
				return true;
			}

			return ParsePacketIPv6(p, buf, size, no_l3_l4_except_icmpv6);

		default:
			return true;
		}
}

bool ParsePacketTAGVLAN(PKT *p, UCHAR *buf, UINT size, bool no_l3, bool no_l3_l4_except_icmpv6)
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

	
	return ParsePacketL3(p, buf, size, proto_ushort, no_l3, no_l3_l4_except_icmpv6);
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

bool ParseIPv6ExtHeader(IPV6_HEADER_PACKET_INFO *info, UCHAR next_header, UCHAR *buf, UINT size)
{
	bool ret = false;
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

bool ParseICMPv6Options(ICMPV6_OPTION_LIST *o, UCHAR *buf, UINT size)
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

bool ParseICMPv6(PKT *p, UCHAR *buf, UINT size)
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
	icmp_info.Code = icmp->Code;
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

bool ParsePacketIPv6(PKT *p, UCHAR *buf, UINT size, bool no_l3_l4_except_icmpv6)
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
		if (no_l3_l4_except_icmpv6)
		{
			return true;
		}
		return ParseTCP(p, buf, size);

	case IP_PROTO_UDP:
		if (no_l3_l4_except_icmpv6)
		{
			return true;
		}
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

	p->IPv4PayloadData = buf;

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

UCHAR GetNextByte(BUF *b)
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

bool ParseDnsQuery(char *name, UINT name_size, void *data, UINT data_size)
{
	BUF *b;
	char tmp[257];
	bool ok = true;
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

void ParseDNS(PKT *p, UCHAR *buf, UINT size)
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

	if ((dns->Flag1 & 78) != 0 || (dns->Flag1 & 0x80) != 0)
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
		ParseDNS(p, buf, size);
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

	if (p->MacHeader != NULL)
	{
		switch (p->TypeL3)
		{
		case L3_IPV4:
			FreePacketIPv4(p);
			break;

		case L3_ARPV4:
			FreePacketARPv4(p);
			break;

		case L3_TAGVLAN:
			FreePacketTagVlan(p);
			break;
		}
	}

	if (p->HttpLog != NULL)
	{
		Free(p->HttpLog);
	}

	Free(p);
}

void FreePacketIPv4(PKT *p)
{
	if (p == NULL)
	{
		return;
	}

	switch (p->TypeL4)
	{
	case L4_ICMPV4:
		FreePacketICMPv4(p);
		break;

	case L4_TCP:
		FreePacketTCPv4(p);
		break;

	case L4_UDP:
		FreePacketUDPv4(p);
		break;
	}

	p->L3.IPv4Header = NULL;
	p->TypeL3 = L3_UNKNOWN;
}

void FreePacketTagVlan(PKT *p)
{
	if (p == NULL)
	{
		return;
	}

	p->L3.TagVlanHeader = NULL;
	p->TypeL3 = L3_UNKNOWN;
}

void FreePacketARPv4(PKT *p)
{
	if (p == NULL)
	{
		return;
	}

	p->L3.ARPv4Header = NULL;
	p->TypeL3 = L3_UNKNOWN;
}

void FreePacketUDPv4(PKT *p)
{
	if (p == NULL)
	{
		return;
	}

	switch (p->TypeL7)
	{
	case L7_DHCPV4:
		FreePacketDHCPv4(p);
		break;
	}

	p->L4.UDPHeader = NULL;
	p->TypeL4 = L4_UNKNOWN;
}

void FreePacketTCPv4(PKT *p)
{
	if (p == NULL)
	{
		return;
	}

	p->L4.TCPHeader = NULL;
	p->TypeL4 = L4_UNKNOWN;
}

void FreePacketICMPv4(PKT *p)
{
	if (p == NULL)
	{
		return;
	}

	p->L4.ICMPHeader = NULL;
	p->TypeL4 = L4_UNKNOWN;
}

void FreePacketDHCPv4(PKT *p)
{
	if (p == NULL)
	{
		return;
	}

	p->L7.DHCPv4Header = NULL;
	p->TypeL7 = L7_UNKNOWN;
}


USHORT IpChecksum(void *buf, UINT size)
{
	int sum = 0;
	USHORT *addr = (USHORT *)buf;
	int len = (int)size;
	USHORT *w = addr;
	int nleft = len;
	USHORT answer = 0;

	while (nleft > 1)
	{
		USHORT ww = 0;
		Copy(&ww, w++, sizeof(USHORT));
		sum += ww;
		nleft -= 2;
	}

	if (nleft == 1)
	{
		*(UCHAR *)(&answer) = *(UCHAR *)w;
		sum += answer;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);

	answer = ~sum;

	return answer;
}

BUF *BuildDhcpOptionsBuf(LIST *o)
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

DHCP_OPTION *NewDhcpOption(UINT id, void *data, UINT size)
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

DHCP_OPTION_LIST *ParseDhcpOptionList(void *data, UINT size)
{
	DHCP_OPTION_LIST *ret;
	LIST *o;
	DHCP_OPTION *a;
	if (data == NULL)
	{
		return NULL;
	}

	o = ParseDhcpOptions(data, size);
	if (o == NULL)
	{
		return NULL;
	}

	ret = ZeroMalloc(sizeof(DHCP_OPTION_LIST));

	a = GetDhcpOption(o, DHCP_ID_MESSAGE_TYPE);
	if (a != NULL)
	{
		if (a->Size == 1)
		{
			ret->Opcode = *((UCHAR *)a->Data);
		}
	}

	switch (ret->Opcode)
	{
	case DHCP_DISCOVER:
	case DHCP_REQUEST:
		a = GetDhcpOption(o, DHCP_ID_REQUEST_IP_ADDRESS);
		if (a != NULL && a->Size == 4)
		{
			Copy(&ret->RequestedIp, a->Data, 4);
		}
		a = GetDhcpOption(o, DHCP_ID_HOST_NAME);
		if (a != NULL)
		{
			if (a->Size > 1)
			{
				Copy(ret->Hostname, a->Data, MIN(a->Size, sizeof(ret->Hostname) - 1));
			}
		}
		break;

	case DHCP_OFFER:
	case DHCP_ACK:
		a = GetDhcpOption(o, DHCP_ID_SUBNET_MASK);
		if (a != NULL && a->Size >= 4)
		{
			Copy(&ret->SubnetMask, a->Data, 4);
		}

		a = GetDhcpOption(o, DHCP_ID_LEASE_TIME);
		if (a != NULL && a->Size == 4)
		{
			ret->LeaseTime = READ_UINT(a->Data);
		}

		a = GetDhcpOption(o, DHCP_ID_SERVER_ADDRESS);
		if (a != NULL && a->Size >= 4)
		{
			Copy(&ret->ServerAddress, a->Data, 4);
		}

		a = GetDhcpOption(o, DHCP_ID_DOMAIN_NAME);
		if (a != NULL && a->Size >= 1)
		{
			Zero(ret->DomainName, sizeof(ret->DomainName));
			Copy(ret->DomainName, a->Data, MIN(a->Size, sizeof(ret->DomainName) - 1));
		}

		a = GetDhcpOption(o, DHCP_ID_GATEWAY_ADDR);
		if (a != NULL && a->Size >= 4)
		{
			Copy(&ret->Gateway, a->Data, 4);
		}

		a = GetDhcpOption(o, DHCP_ID_DNS_ADDR);
		if (a != NULL && a->Size >= 4)
		{
			Copy(&ret->DnsServer, a->Data, 4);

			if (a->Size >= 8)
			{
				Copy(&ret->DnsServer2, ((UCHAR *)a->Data) + 4, 4);
			}
		}

		a = GetDhcpOption(o, DHCP_ID_WINS_ADDR);
		if (a != NULL && a->Size >= 4)
		{
			Copy(&ret->WinsServer, a->Data, 4);

			if (a->Size >= 8)
			{
				Copy(&ret->WinsServer2, ((UCHAR *)a->Data) + 4, 4);
			}
		}

		// RFC 3442
		a = GetDhcpOption(o, DHCP_ID_CLASSLESS_ROUTE);
		if (a != NULL)
		{
			DhcpParseClasslessRouteData(&ret->ClasslessRoute, a->Data, a->Size);
		}
		// Microsoft Extension
		a = GetDhcpOption(o, DHCP_ID_MS_CLASSLESS_ROUTE);
		if (a != NULL)
		{
			DhcpParseClasslessRouteData(&ret->ClasslessRoute, a->Data, a->Size);
		}

		break;
	}

	FreeDhcpOptions(o);

	return ret;
}

void DhcpParseClasslessRouteData(DHCP_CLASSLESS_ROUTE_TABLE *t, void *data, UINT size)
{
	BUF *b;
	if (t == NULL || data == NULL || size == 0)
	{
		return;
	}

	b = MemToBuf(data, size);

	while (b->Current < b->Size)
	{
		UCHAR c;
		UINT subnet_mask_len;
		UINT data_len;
		BYTE tmp[IPV4_SIZE];
		IP ip;
		IP mask;
		IP gateway;
		DHCP_CLASSLESS_ROUTE r;
		UINT ip32;
		bool exists = false;
		UINT i;

		c = ReadBufChar(b);
		subnet_mask_len = c;
		if (subnet_mask_len > 32)
		{
			break;
		}

		data_len = (subnet_mask_len + 7) / 8;

		Zero(tmp, sizeof(tmp));
		if (ReadBuf(b, tmp, data_len) != data_len)
		{
			break;
		}

		ZeroIP4(&ip);
		Copy(IPV4(ip.address), tmp, sizeof(tmp));

		Zero(&mask, sizeof(mask));
		IntToSubnetMask4(&mask, subnet_mask_len);

		Zero(&gateway, sizeof(gateway));
		if (ReadBuf(b, &ip32, sizeof(UINT)) != sizeof(UINT))
		{
			break;
		}
		UINTToIP(&gateway, ip32);

		Zero(&r, sizeof(r));
		r.Exists = true;
		Copy(&r.Gateway, &gateway, sizeof(IP));
		Copy(&r.Network, &ip, sizeof(IP));
		Copy(&r.SubnetMask, &mask, sizeof(IP));
		r.SubnetMaskLen = subnet_mask_len;

		for (i = 0; i < MAX_DHCP_CLASSLESS_ROUTE_ENTRIES; i++)
		{
			if (Cmp(&t->Entries[i], &r, sizeof(DHCP_CLASSLESS_ROUTE)) == 0)
			{
				exists = true;
				break;
			}
		}

		if (exists == false)
		{
			if (t->NumExistingRoutes >= MAX_DHCP_CLASSLESS_ROUTE_ENTRIES)
			{
				break;
			}

			Copy(&t->Entries[t->NumExistingRoutes], &r, sizeof(DHCP_CLASSLESS_ROUTE));
			t->NumExistingRoutes++;
		}
	}

	FreeBuf(b);
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
		DHCP_OPTION *opt;
		if (ReadBuf(b, &c, 1) != 1)
		{
			break;
		}
		if (c == 0xff)
		{
			break;
		}
		if (ReadBuf(b, &sz, 1) != 1)
		{
			break;
		}

		if (c == DHCP_ID_PRIVATE && last_opt != NULL)
		{
			UINT new_size = last_opt->Size + (UINT)sz;
			UCHAR *new_buf = ZeroMalloc(new_size);
			Copy(new_buf, last_opt->Data, last_opt->Size);
			ReadBuf(b, new_buf + last_opt->Size, sz);
			Free(last_opt->Data);
			last_opt->Data = new_buf;
			last_opt->Size = new_size;
		}
		else
		{
			opt = ZeroMalloc(sizeof(DHCP_OPTION));
			opt->Id = (UINT)c;
			opt->Size = (UINT)sz;
			opt->Data = ZeroMalloc((UINT)sz);
			ReadBuf(b, opt->Data, sz);
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
	DHCPV4_HEADER *dhcp_header;
	UCHAR *data_ptr;
	bool ret_ok = false;
	BUF *ret = NULL;
	BUF *opt_buf = NULL;
	UINT magic_cookie = Endian32(DHCP_MAGIC_COOKIE);
	bool ok = false;
	DHCP_OPTION_LIST *opt = NULL;
	LIST *opt_list = NULL;
	LIST *opt_list2 = NULL;
	UINT src_size = size;
	UINT i;
	UINT dhcp_min_size;
	if (m == NULL || data == NULL || size == 0)
	{
		return NULL;
	}

	data_ptr = (UCHAR *)data;

	if (size < sizeof(DHCPV4_HEADER))
	{
		goto LABEL_CLEANUP;
	}

	dhcp_header = (DHCPV4_HEADER *)data_ptr;
	data_ptr += sizeof(DHCPV4_HEADER);

	while (size >= 5)
	{
		if (Cmp(data_ptr, &magic_cookie, sizeof(UINT)) == 0)
		{
			data_ptr += sizeof(UINT);
			size -= sizeof(UINT);
			ok = true;
			break;
		}

		data_ptr++;
		size--;
	}

	if (ok == false)
	{
		goto LABEL_CLEANUP;
	}

	ret = NewBuf();
	WriteBuf(ret, data, (UINT)(data_ptr - ((UCHAR *)data)));

	opt = ParseDhcpOptionList(data_ptr, size);
	if (opt == NULL)
	{
		goto LABEL_CLEANUP;
	}

	opt_list = ParseDhcpOptions(data_ptr, size);
	if (opt_list == NULL)
	{
		goto LABEL_CLEANUP;
	}

	opt_list2 = NewListFast(NULL);

	for (i = 0; i < LIST_NUM(opt_list); i++)
	{
		DHCP_OPTION *o = LIST_DATA(opt_list, i);
		DHCP_OPTION *o2 = NULL;
		bool ok = true;

		if (m->RemoveDefaultGatewayOnReply)
		{
			if (opt->Opcode == DHCP_OFFER || opt->Opcode == DHCP_ACK)
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

	if (opt != NULL)
	{
		Free(opt);
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
