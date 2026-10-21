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
