// Pkt.c
// Packet parser core: ParsePacket and the L2 to L4 parse stages, clone and free of a parsed packet, VLAN tag insert and remove; with the DNS, HTTP log and DHCP hooks of ParsePacketEx5, and DhcpModify, which shares the DHCP option helpers DhcpOptionsOf and DhcpMessageType with ParsePacketEx5

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
	TCP_HEADER *tcp;
	USHORT port;

	if ((p->TypeL3 != L3_IPV4 && p->TypeL3 != L3_IPV6) || p->TypeL4 != L4_TCP)
	{
		return;
	}

	tcp = p->L4.TCPHeader;
	if (tcp == NULL || (tcp->Flag & (TCP_SYN | TCP_RST | TCP_FIN)) != 0 || p->PayloadSize == 0)
	{
		return;
	}

	port = tcp->DstPort;

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

	p = ZeroMalloc(sizeof(PKT));

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
