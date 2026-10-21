// Dhcp.c
// DHCP: the DHCP packet test for a client MAC address, the option list parse, lookup and free, and the IPv4 DHCP rewrite (DhcpModifyIPv4)

#include "TcpIp.h"

#include "Cfg.h"
#include "Memory.h"
#include "TcpIpInternal.h"

bool IsDhcpPacketForSpecificMac(UCHAR *data, UINT size, UCHAR *mac_address) {
	bool is_send = false, is_recv = false;
	if (data == NULL || mac_address == NULL || IsZero(mac_address, 6))
		return false;

	if (size < 14)
		return false;

	if (Cmp(data, mac_address, 6) == 0)
		is_recv = true;
	size -= 6;
	data += 6;

	if (Cmp(data, mac_address, 6) == 0)
		is_send = true;
	size -= 6;
	data += 6;

	if (is_send == false && is_recv == false)
		return false;
	if (is_send && is_recv)
		return false;

	USHORT *us = (USHORT *)data;
	size -= 2;
	data += 2;

	if (READ_USHORT(us) != MAC_PROTO_IPV4)
		return false;

	UINT ip_header_size = GetIpHeaderSize(data, size);
	if (ip_header_size == 0)
		return false;

	IPV4_HEADER *ip = (IPV4_HEADER *)data;
	data += ip_header_size;
	size -= ip_header_size;

	if (ip->Protocol != IP_PROTO_UDP)
		return false;

	if (size < sizeof(UDP_HEADER))
		return false;
	UDP_HEADER *udp = (UDP_HEADER *)data;

	if (is_send) {
		if (Endian16(udp->DstPort) == 67)
			return true;
	} else if (is_recv) {
		if (Endian16(udp->SrcPort) == 67)
			return true;
	}

	return false;
}

DHCP_OPTION *GetDhcpOption(LIST *o, UINT id) {
	DHCP_OPTION *ret = NULL;
	if (o == NULL)
		return NULL;

	for (UINT i = 0; i < LIST_NUM(o); i++) {
		DHCP_OPTION *opt = LIST_DATA(o, i);
		if (opt->Id == id)
			ret = opt;
	}

	return ret;
}

void FreeDhcpOptions(LIST *o) {
	if (o == NULL)
		return;

	for (UINT i = 0; i < LIST_NUM(o); i++) {
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
LIST *ParseDhcpOptions(void *data, UINT size) {
	if (data == NULL)
		return NULL;

	BUF *b = NewBuf();
	WriteBuf(b, data, size);
	SeekBuf(b, 0, 0);

	LIST *o = NewListFast(NULL);

	DHCP_OPTION *last_opt = NULL;

	while (true) {
		UCHAR c = 0;
		UCHAR sz = 0;
		DHCP_OPTION *opt;
		if (ReadBuf(b, &c, 1) != 1)
			break;
		if (c == 0xff)
			break;
		if (c == 0x00) {
			// Pad: one byte, without a length
			continue;
		}
		if (ReadBuf(b, &sz, 1) != 1)
			break;

		UCHAR *body = ZeroMalloc((UINT)sz);
		if (ReadBuf(b, body, sz) != sz) {
			// The body runs past the end of the data
			Free(body);
			break;
		}

		if (c == DHCP_ID_PRIVATE && last_opt != NULL) {
			UINT new_size = last_opt->Size + (UINT)sz;
			UCHAR *new_buf = ZeroMalloc(new_size);
			Copy(new_buf, last_opt->Data, last_opt->Size);
			Copy(new_buf + last_opt->Size, body, sz);
			Free(body);
			Free(last_opt->Data);
			last_opt->Data = new_buf;
			last_opt->Size = new_size;
		} else {
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

BUF *DhcpModifyIPv4(DHCP_MODIFY_OPTION *m, void *data, UINT size) {
	BUF *ret = NULL;
	if (m == NULL || data == NULL || size == 0)
		return NULL;

	PKT *p = ParsePacketEx4(data, size, false, 0, false, false, false);

	if (p != NULL && p->TypeL3 == L3_IPV4 && p->TypeL4 == L4_UDP && p->TypeL7 == L7_DHCPV4) {
		BUF *new_buf = DhcpModify(m, p->Payload, p->PayloadSize);

		if (new_buf != NULL) {
			ret = NewBuf();

			WriteBuf(ret, p->PacketData, p->PacketSize - p->PayloadSize);
			WriteBuf(ret, new_buf->Buf, new_buf->Size);

			FreeBuf(new_buf);
		}
	}

	FreePacket(p);

	if (ret != NULL) {
		PKT *p = ParsePacketEx4(ret->Buf, ret->Size, false, 0, false, false, false);

		if (p != NULL) {
			if (p->TypeL3 == L3_IPV4 && p->TypeL4 == L4_UDP) {
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
