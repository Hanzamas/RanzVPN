// Pkt.c
// Packet parser core: ParsePacket and the L2 to L4 parse stages, clone and free of a parsed packet, VLAN tag insert and remove; with the DNS, HTTP log and DHCP hooks of ParsePacketEx5, and DhcpModify, which shares the DHCP option helpers DhcpOptionsOf and DhcpMessageType with ParsePacketEx5

#include "TcpIp.h"

#include "Cfg.h"
#include "Memory.h"
#include "Str.h"
#include "TcpIpInternal.h"

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
	USHORT vlan_ushort = Endian16(((USHORT)vlan_id) & 0xFFF);
	if (packet_data == NULL || *packet_data == NULL || packet_size == NULL ||
	        *packet_size < 14 || vlan_id == 0)
	{
		return;
	}
	if (vlan_tpid == 0)
	{
		vlan_tpid = MAC_PROTO_TAGVLAN;
	}

	USHORT vlan_tpid_ushort = Endian16((USHORT)vlan_tpid);

	UINT src_size = *packet_size;
	UCHAR *src_data = (UCHAR *)(*packet_data);

	UINT dest_size = src_size + 4;
	UCHAR *dest_data = Malloc(dest_size);

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
	if (packet_data == NULL || *packet_data == NULL || packet_size == NULL ||
	        *packet_size < 14)
	{
		return false;
	}

	if (vlan_tpid == 0)
	{
		vlan_tpid = MAC_PROTO_TAGVLAN;
	}

	USHORT vlan_tpid_ushort = Endian16((USHORT)vlan_tpid);
	UCHAR *vlan_tpid_uchar = (UCHAR *)(&vlan_tpid_ushort);

	UCHAR *src_data = (UCHAR *)(*packet_data);
	UINT src_size = *packet_size;

	if (src_data[12] == vlan_tpid_uchar[0] && src_data[13] == vlan_tpid_uchar[1])
	{
		if (src_size >= 18)
		{
			USHORT vlan_ushort = READ_USHORT(&src_data[14]);
			vlan_ushort = vlan_ushort & 0xFFF;

			if (vlan_id == 0 || (vlan_ushort == vlan_id))
			{
				UINT dest_size = src_size - 4;

				for (UINT i = 12; i < dest_size; i++)
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

// Cuts a frame down to the length its IPv4 or IPv6 header gives, where l2_len is the size of the
// Ethernet header (with a VLAN tag if it has one) and the Ethernet type sits just before it. Returns
// false when the frame carries neither IPv4 nor IPv6. buf holds at least l2_len + 6 bytes
static bool TrimToIpLength(UCHAR *buf, UINT *size, UINT l2_len)
{
	UINT ip_len;
	UINT frame_size;

	if (buf[l2_len - 2] == 0x08 && buf[l2_len - 1] == 0x00)
	{
		// IPv4: the total length counts its own header
		ip_len = READ_USHORT(&buf[l2_len + 2]);
		frame_size = ip_len + l2_len;
	}
	else if (buf[l2_len - 2] == 0x86 && buf[l2_len - 1] == 0xdd)
	{
		// IPv6: the payload length leaves out the 40 byte header
		ip_len = READ_USHORT(&buf[l2_len + 4]);
		frame_size = ip_len + l2_len + 40;
	}
	else
	{
		return false;
	}

	if (ip_len >= 1 && *size > frame_size)
	{
		*size = frame_size;
	}

	return true;
}

// Reads the HTTP request or the TLS server name out of the first data segment of a TCP packet to a
// web proxy or web server port, and keeps it in p->HttpLog
static void ParseTcpHttpLog(PKT *p)
{
	if ((p->TypeL3 != L3_IPV4 && p->TypeL3 != L3_IPV6) || p->TypeL4 != L4_TCP)
	{
		return;
	}

	TCP_HEADER *tcp = p->L4.TCPHeader;
	if (tcp == NULL || (tcp->Flag & (TCP_SYN | TCP_RST | TCP_FIN)) != 0 || p->PayloadSize == 0)
	{
		return;
	}

	USHORT port = tcp->DstPort;

	if (port == Endian16(80) || port == Endian16(8080) || port == Endian16(3128))
	{
		p->HttpLog = ParseHttpAccessLog(p);
	}
	else if (port == Endian16(443))
	{
		p->HttpLog = ParseHttpsAccessLog(p);
	}
}

PKT *ParsePacketEx5(UCHAR *buf, UINT size, bool no_l3, UINT vlan_type_id, bool bridge_id_as_mac_address, bool no_http, bool correct_checksum, bool no_dns)
{
	if (buf == NULL || size == 0)
	{
		return NULL;
	}

	if (vlan_type_id == 0)
	{
		vlan_type_id = MAC_PROTO_TAGVLAN;
	}

	USHORT vlan_type_id_16 = Endian16((USHORT)vlan_type_id);

	PKT *p = ZeroMalloc(sizeof(PKT));

	// Drop any garbage after the payload of IPv4 and IPv6 packets, tagged with a VLAN or not
	if (size >= 24)
	{
		if (TrimToIpLength(buf, &size, 14) == false && buf[12] == ((UCHAR *)&vlan_type_id_16)[0] && buf[13] == ((UCHAR *)&vlan_type_id_16)[1])
		{
			TrimToIpLength(buf, &size, 18);
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
		ParseTcpHttpLog(p);
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

static bool ParseDnsQuery(char *name, UINT name_size, const void *data, UINT data_size)
{
	char tmp[DNS_MAX_LABEL_LEN + 1];
	bool ok = true;
	UINT wire_len = 1;		// Octets of the name on the wire: the root label, then each label with its length byte
	USHORT val;
	if (name == NULL || data == NULL || data_size == 0)
	{
		return false;
	}
	StrCpy(name, name_size, "");

	BUF *b = NewBuf();
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
	char hostname[MAX_SIZE];
	if (p == NULL|| buf == NULL)
	{
		return;
	}

	if (size < sizeof(DNSV4_HEADER))
	{
		return;
	}

	DNSV4_HEADER *dns = (DNSV4_HEADER *)buf;

	// A standard query only: not a response, opcode 0 (QUERY), whatever its AA, TC and RD bits
	if ((dns->Flag1 & (DNS_FLAG1_QR | DNS_FLAG1_OPCODE)) != 0)
	{
		return;
	}
	if (Endian16(dns->NumQuery) != 1)
	{
		return;
	}

	UCHAR *query_data = ((UCHAR *)dns) + sizeof(DNSV4_HEADER);
	UINT query_data_size = size - sizeof(DNSV4_HEADER);

	if (ParseDnsQuery(hostname, sizeof(hostname), query_data, query_data_size) == false)
	{
		return;
	}

	StrCpy(p->DnsQueryHost, sizeof(p->DnsQueryHost), hostname);
	p->TypeL7 = L7_DNS;
}

static BUF *BuildDhcpOptionsBuf(LIST *o)
{
	UCHAR id;
	UCHAR sz;
	if (o == NULL)
	{
		return NULL;
	}

	BUF *b = NewBuf();
	for (UINT i = 0; i < LIST_NUM(o); i++)
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

static DHCP_OPTION *NewDhcpOption(UINT id, const void *data, UINT size)
{
	if (size != 0 && data == NULL)
	{
		return NULL;
	}

	DHCP_OPTION *ret = ZeroMalloc(sizeof(DHCP_OPTION));
	ret->Data = ZeroMalloc(size);
	Copy(ret->Data, data, size);
	ret->Size = size;
	ret->Id = id;

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

	for (UINT i = 0; i < LIST_NUM(opt_list); i++)
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
	if (p == NULL)
	{
		return NULL;
	}

	PKT *ret = ZeroMalloc(sizeof(PKT));
	ret->PacketSize = p->PacketSize;

	ret->MacHeader = Malloc(sizeof(MAC_HEADER));
	Copy(ret->MacHeader, p->MacHeader, sizeof(MAC_HEADER));

	ret->BroadcastPacket = p->BroadcastPacket;
	ret->InvalidSourcePacket = p->InvalidSourcePacket;

	Copy(&ret->IPv6HeaderPacketInfo, &p->IPv6HeaderPacketInfo, sizeof(IPV6_HEADER_PACKET_INFO));
	Copy(&ret->ICMPv6HeaderPacketInfo, &p->ICMPv6HeaderPacketInfo, sizeof(ICMPV6_HEADER_INFO));

	ret->TypeL3 = p->TypeL3;
	switch (ret->TypeL3)
	{
	case L3_ARPV4:
		ret->L3.ARPv4Header = Malloc(sizeof(ARPV4_HEADER));
		Copy(ret->L3.ARPv4Header, p->L3.ARPv4Header, sizeof(ARPV4_HEADER));
		break;

	case L3_IPV4:
		ret->L3.IPv4Header = Malloc(sizeof(IPV4_HEADER));
		Copy(ret->L3.IPv4Header, p->L3.IPv4Header, sizeof(IPV4_HEADER));
		break;

	case L3_IPV6:
		ret->L3.IPv6Header = Malloc(sizeof(IPV6_HEADER));
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
		ret->L4.ICMPHeader = Malloc(sizeof(ICMP_HEADER));
		Copy(ret->L4.ICMPHeader, p->L4.ICMPHeader, sizeof(ICMP_HEADER));
		break;

	case L4_ICMPV6:
		ret->L4.ICMPHeader = Malloc(sizeof(ICMP_HEADER));
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
		ret->L4.TCPHeader = Malloc(sizeof(TCP_HEADER));
		Copy(ret->L4.TCPHeader, p->L4.TCPHeader, sizeof(TCP_HEADER));
		break;

	case L4_UDP:
		ret->L4.UDPHeader = Malloc(sizeof(UDP_HEADER));
		Copy(ret->L4.UDPHeader, p->L4.UDPHeader, sizeof(UDP_HEADER));
		break;
	}

	ret->TypeL7 = p->TypeL7;
	switch (ret->TypeL7)
	{
	case L7_DHCPV4:
		ret->L7.DHCPv4Header = Malloc(sizeof(DHCPV4_HEADER));
		Copy(ret->L7.DHCPv4Header, p->L7.DHCPv4Header, sizeof(DHCPV4_HEADER));
		break;

	case L7_IKECONN:
		ret->L7.IkeHeader = Malloc(sizeof(IKE_HEADER));
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
		ret->PacketData = Malloc(p->PacketSize);
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

// Parse the Ethernet header. A frame tagged with 0x8100 (802.1Q) or with vlan_tpid, the VLAN TPID of
// the hub (HUB_OPTION.VlanTypeId, for example 0x88A8), is a VLAN frame: ParsePacketTAGVLAN parses
// what is behind the tag, as VLanInsertTag, VLanRemoveTag and AdjustTcpMssL2 use that TPID. A
// vlan_tpid that is the type of ARP, IPv4 or IPv6 tags nothing, so those frames stay what they are
bool ParsePacketL2Ex(PKT *p, UCHAR *buf, UINT size, bool no_l3, USHORT vlan_tpid)
{
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
	bool b1 = true;
	bool b2 = true;
	for (UINT i = 0; i < 6; i++)
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

	USHORT type_id_16 = Endian16(p->MacHeader->Protocol);

	bool is_tag_vlan = (type_id_16 == MAC_PROTO_TAGVLAN);
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

		if (size < length || size < sizeof(LLC_HEADER))
		{
			return true;
		}

		LLC_HEADER *llc = (LLC_HEADER *)buf;
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

	USHORT vlan_ushort = READ_USHORT(p->L3.TagVlanHeader->TagID);
	vlan_ushort = vlan_ushort & 0xFFF;

	p->VlanId = vlan_ushort;

	USHORT proto_ushort = READ_USHORT(p->L3.TagVlanHeader->Protocol);

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

	return true;
}

bool ParsePacketIPv4(PKT *p, UCHAR *buf, UINT size)
{
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

	UINT header_size = IPV4_GET_HEADER_LEN(p->L3.IPv4Header) * 4;
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

	return true;
}

bool ParseTCP(PKT *p, UCHAR *buf, UINT size)
{
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

	UINT header_size = TCP_GET_HEADER_SIZE(p->L4.TCPHeader) * 4;
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

bool ParseUDP(PKT *p, UCHAR *buf, UINT size)
{
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

	USHORT src_port = Endian16(p->L4.UDPHeader->SrcPort);
	USHORT dst_port = Endian16(p->L4.UDPHeader->DstPort);

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
