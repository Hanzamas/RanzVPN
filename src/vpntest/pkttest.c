// pkttest.c
// Named packet parser test of vpntest ("pktparse" command, FND-38 #113)
//
// pktparse pins the parsers of Mayaqua/TcpIp.c that read the DNS and DHCP traffic of VPN clients
// for the packet log and the IP table of the hub:
// - ParseDNS takes a standard query: no response bit and opcode 0, whatever its AA, TC and RD
//   bits. The old test (Flag1 & 78, and 78 is 0x4E) dropped queries with AA or TC set and took
//   opcodes 2 and 4.
// - ParseDnsQuery takes labels of at most 63 octets and names of at most 255 octets on the wire
//   (RFC 1035 2.3.4). A length byte above 63, such as the 0xC0 of a compression pointer, ends the
//   parse; the old code read it as a length.
// - ParseDhcpOptions skips Pad (0) as one byte, and takes an option only with its whole body: an
//   option code without its length byte or a body that runs past the end ends the list without
//   that option. The old code read the byte behind a Pad as a length and filled a short body with
//   zeros.
// - ParseDHCPv4Data (PKT.DhcpOpCode of ParsePacket) reads the magic cookie only at offset 236.
//   The old code took the first cookie bytes anywhere in the payload, also in sname or file.
// Every frame and option list is in a heap block of exactly its size, so AddressSanitizer reports
// a read past its end. Prints "PKTPARSE TEST OK" only when every check passes, and frees
// everything it allocates. The [PASS] lines carry no values; the [FAIL] details do.

#include "Mayaqua/Memory.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/TcpIp.h"

#include <stdarg.h>

#define	PKTTEST_DHCP_SIZE			300		// Size of a DHCP payload of the test (DHCP_MIN_SIZE)
#define	PKTTEST_COOKIE_OFFSET		236		// Offset of the magic cookie: fixed header (44 bytes), sname (64), file (128)
#define	PKTTEST_SNAME_OFFSET		44		// Offset of sname, right behind the fixed header
#define	PKTTEST_FILE_OFFSET			108		// Offset of file, right behind sname
#define	PKTTEST_DNS_PORT			53		// Destination port of the DNS queries
#define	PKTTEST_DNS_CLIENT_PORT		53000	// Source port of the DNS queries
#define	PKTTEST_VLAN_ID				10		// VLAN ID of the tagged frames
#define	PKTTEST_NUM(a)				(sizeof(a) / sizeof((a)[0]))

// Run state of the test
typedef struct PKTTEST_CTX
{
	UINT NumChecks;						// Checks run so far
	UINT NumFailed;						// Checks failed so far
} PKTTEST_CTX;

// MAC addresses of the frames: the server and the client
static UCHAR pkttest_mac_server[6] = {0x5E, 0x00, 0x53, 0x00, 0x00, 0x01};
static UCHAR pkttest_mac_client[6] = {0x5E, 0x00, 0x53, 0x00, 0x00, 0x02};
static UCHAR pkttest_mac_broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

// Magic cookie of the DHCP options, in network byte order
static UCHAR pkttest_cookie[4] = {0x63, 0x82, 0x53, 0x63};

// Record one check: print [PASS], or [FAIL] with the formatted detail
static void PktTestCheck(PKTTEST_CTX *ctx, bool ok, char *what, char *detail_fmt, ...)
{
	char detail[MAX_SIZE];
	va_list args;

	ctx->NumChecks++;

	if (ok)
	{
		Print("  [PASS] %s\n", what);
		return;
	}

	va_start(args, detail_fmt);
	FormatArgs(detail, sizeof(detail), detail_fmt, args);
	va_end(args);

	Print("  [FAIL] %s (%s)\n", what, detail);

	ctx->NumFailed++;
}

// Ethernet header from src_mac to dst_mac for the EtherType type, with a VLAN tag (tpid, VLAN ID
// PKTTEST_VLAN_ID) in front of the type when tpid is not 0. Returns its size: 14, or 18 with the tag
static UINT PktTestEthernet(UCHAR *buf, UCHAR *dst_mac, UCHAR *src_mac, USHORT tpid, USHORT type)
{
	UINT size = 12;

	Copy(buf, dst_mac, 6);
	Copy(buf + 6, src_mac, 6);

	if (tpid != 0)
	{
		buf[size++] = (UCHAR)(tpid >> 8);
		buf[size++] = (UCHAR)(tpid & 0xFF);
		buf[size++] = (UCHAR)(PKTTEST_VLAN_ID >> 8);
		buf[size++] = (UCHAR)(PKTTEST_VLAN_ID & 0xFF);
	}

	buf[size++] = (UCHAR)(type >> 8);
	buf[size++] = (UCHAR)(type & 0xFF);

	return size;
}

// Ethernet frame from src_mac to dst_mac (tagged as PktTestEthernet does) with an IPv4 UDP datagram
// from src:sport to dst:dport that carries the payload, with a valid IPv4 checksum and UDP checksum 0
// (none), in a heap block of exactly its size (*size)
static UCHAR *PktTestUdpFrame(UCHAR *dst_mac, UCHAR *src_mac, USHORT tpid, UCHAR *src, UCHAR *dst,
	USHORT sport, USHORT dport, void *payload, UINT payload_size, UINT *size)
{
	UCHAR l2[18];
	UINT l2_size = PktTestEthernet(l2, dst_mac, src_mac, tpid, MAC_PROTO_IPV4);
	UINT udp_size = 8 + payload_size;
	UINT ip_size = 20 + udp_size;
	UCHAR *buf;
	UCHAR *ip;
	UCHAR *udp;
	USHORT sum;

	*size = l2_size + ip_size;
	buf = ZeroMalloc(*size);
	Copy(buf, l2, l2_size);
	ip = buf + l2_size;
	udp = ip + 20;

	ip[0] = 0x45;								// Version 4, 20-byte header
	ip[2] = (UCHAR)(ip_size >> 8);
	ip[3] = (UCHAR)(ip_size & 0xFF);
	ip[8] = 64;									// TTL
	ip[9] = IP_PROTO_UDP;
	Copy(ip + 12, src, 4);
	Copy(ip + 16, dst, 4);
	sum = IpChecksum(ip, 20);
	Copy(ip + 10, &sum, sizeof(USHORT));

	udp[0] = (UCHAR)(sport >> 8);
	udp[1] = (UCHAR)(sport & 0xFF);
	udp[2] = (UCHAR)(dport >> 8);
	udp[3] = (UCHAR)(dport & 0xFF);
	udp[4] = (UCHAR)(udp_size >> 8);
	udp[5] = (UCHAR)(udp_size & 0xFF);
	Copy(udp + 8, payload, payload_size);

	return buf;
}

// Letter i of a test label: 'a' to 'z', then 'a' again
static UCHAR PktTestLabelChar(UINT i)
{
	return (UCHAR)('a' + (i % 26));
}

// DNS query message (RFC 1035 4.1) with the first flag byte flag1 and one question for type A, class
// IN. Its name is num_labels labels, each a length byte from labels[] and that many letters, then the
// root label. A length above 63 is written as it is
static BUF *PktTestDnsQuery(UCHAR flag1, UINT *labels, UINT num_labels)
{
	BUF *b = NewBuf();
	UCHAR header[12];
	UCHAR tail[5] = {0x00, 0x00, 0x01, 0x00, 0x01};	// Root label, type A, class IN
	UINT i, j;

	Zero(header, sizeof(header));
	header[0] = 0x52;								// Transaction ID
	header[1] = 0x41;
	header[2] = flag1;
	header[5] = 1;									// One question
	WriteBuf(b, header, sizeof(header));

	for (i = 0; i < num_labels; i++)
	{
		UCHAR len = (UCHAR)labels[i];

		WriteBuf(b, &len, 1);

		for (j = 0; j < labels[i]; j++)
		{
			UCHAR c = PktTestLabelChar(j);

			WriteBuf(b, &c, 1);
		}
	}

	WriteBuf(b, tail, sizeof(tail));

	return b;
}

// Name of the labels of PktTestDnsQuery as ParseDnsQuery gives it: the labels joined with dots
static void PktTestDnsName(char *name, UINT name_size, UINT *labels, UINT num_labels)
{
	UINT i, j;

	StrCpy(name, name_size, "");

	for (i = 0; i < num_labels; i++)
	{
		if (i != 0)
		{
			StrCat(name, name_size, ".");
		}

		for (j = 0; j < labels[i]; j++)
		{
			char c[2];

			c[0] = (char)PktTestLabelChar(j);
			c[1] = 0;
			StrCat(name, name_size, c);
		}
	}
}

// One DNS case: the query of PktTestDnsQuery from the client to port 53, through ParsePacket. With
// parsed true the frame must give a DNS query (L7_DNS) with the name of the labels, as far as
// PKT.DnsQueryHost holds it; with parsed false it must give none
static void PktTestDnsCase(PKTTEST_CTX *ctx, char *what, UCHAR flag1, UINT *labels, UINT num_labels, bool parsed)
{
	UCHAR client[4] = {10, 0, 0, 1};
	UCHAR server[4] = {10, 0, 0, 53};
	BUF *q = PktTestDnsQuery(flag1, labels, num_labels);
	UINT size;
	UCHAR *f = PktTestUdpFrame(pkttest_mac_server, pkttest_mac_client, 0, client, server,
		PKTTEST_DNS_CLIENT_PORT, PKTTEST_DNS_PORT, q->Buf, q->Size, &size);
	PKT *p = ParsePacket(f, size);
	bool is_dns = (p != NULL && p->TypeL7 == L7_DNS);
	bool ok = false;

	if (p != NULL)
	{
		if (parsed)
		{
			char full[MAX_SIZE];
			char expect[MAX_SIZE];

			// The name as far as PKT.DnsQueryHost holds it
			PktTestDnsName(full, sizeof(full), labels, num_labels);
			StrCpy(expect, sizeof(p->DnsQueryHost), full);

			ok = (is_dns && StrCmp(p->DnsQueryHost, expect) == 0);
		}
		else
		{
			ok = (is_dns == false);
		}
	}

	PktTestCheck(ctx, ok, what, "%s, %s, host \"%s\"; expected %s",
		p == NULL ? "frame not parsed" : "frame parsed", is_dns ? "a DNS query" : "no DNS query",
		p == NULL ? "" : p->DnsQueryHost, parsed ? "a DNS query" : "no DNS query");

	FreePacket(p);
	Free(f);
	FreeBuf(q);
}

// ParseDNS and ParseDnsQuery through ParsePacket
static void PktTestDns(PKTTEST_CTX *ctx)
{
	UINT name[] = {7, 3};							// abcdefg.abc
	UINT label_63[] = {63, 3};
	UINT label_64[] = {64, 3};
	// 0xC0 starts a compression pointer; 192 letters follow it here, so read as a length it is a label
	UINT pointer[] = {0xC0};
	// 255 and 256 octets on the wire, with the length bytes and the root label
	UINT name_255[] = {63, 63, 63, 61};
	UINT name_256[] = {63, 63, 63, 62};

	PktTestDnsCase(ctx, "ParseDNS takes a standard query with recursion desired",
		0x01, name, PKTTEST_NUM(name), true);
	PktTestDnsCase(ctx, "ParseDNS takes a query with TC set (the old mask dropped it)",
		0x03, name, PKTTEST_NUM(name), true);
	PktTestDnsCase(ctx, "ParseDNS takes a query with AA set (the old mask dropped it)",
		0x05, name, PKTTEST_NUM(name), true);
	PktTestDnsCase(ctx, "ParseDNS drops opcode 1 (IQUERY)",
		0x09, name, PKTTEST_NUM(name), false);
	PktTestDnsCase(ctx, "ParseDNS drops opcode 2 (STATUS; the old mask took it)",
		0x11, name, PKTTEST_NUM(name), false);
	PktTestDnsCase(ctx, "ParseDNS drops opcode 4 (NOTIFY; the old mask took it)",
		0x21, name, PKTTEST_NUM(name), false);
	PktTestDnsCase(ctx, "ParseDNS drops a response",
		0x81, name, PKTTEST_NUM(name), false);
	PktTestDnsCase(ctx, "ParseDnsQuery takes a label of 63 octets",
		0x01, label_63, PKTTEST_NUM(label_63), true);
	PktTestDnsCase(ctx, "ParseDnsQuery drops a label of 64 octets",
		0x01, label_64, PKTTEST_NUM(label_64), false);
	PktTestDnsCase(ctx, "ParseDnsQuery stops at a length byte 0xC0 (a compression pointer), reading nothing behind it as a label",
		0x01, pointer, PKTTEST_NUM(pointer), false);
	PktTestDnsCase(ctx, "ParseDnsQuery takes a name of 255 octets",
		0x01, name_255, PKTTEST_NUM(name_255), true);
	PktTestDnsCase(ctx, "ParseDnsQuery drops a name of 256 octets",
		0x01, name_256, PKTTEST_NUM(name_256), false);
}

// The option of the list with the id, as GetDhcpOption finds it, holds exactly expect (expect_size bytes)
static bool PktTestHasOption(LIST *o, UINT id, void *expect, UINT expect_size)
{
	DHCP_OPTION *opt = GetDhcpOption(o, id);

	return (opt != NULL && opt->Size == expect_size && Cmp(opt->Data, expect, expect_size) == 0);
}

// One ParseDhcpOptions case on the options, in a heap block of exactly options_size bytes: the list
// must hold expect_num options, the option expect_id among them with the bytes expect (expect_size)
static void PktTestOptionsCase(PKTTEST_CTX *ctx, char *what, UCHAR *options, UINT options_size,
	UINT expect_num, UINT expect_id, void *expect, UINT expect_size)
{
	UCHAR *data = Clone(options, options_size);
	LIST *o = ParseDhcpOptions(data, options_size);
	bool has = (o != NULL && PktTestHasOption(o, expect_id, expect, expect_size));
	bool ok = (o != NULL && LIST_NUM(o) == expect_num && has);

	PktTestCheck(ctx, ok, what, "%s of %u options, option %u %s; expected %u options",
		o == NULL ? "NULL" : "a list", o == NULL ? 0 : LIST_NUM(o), expect_id,
		has ? "as expected" : "missing or not as expected", expect_num);

	FreeDhcpOptions(o);
	Free(data);
}

// One ParseDhcpOptionList case on the options, in a heap block of exactly options_size bytes: it
// must give the opcode expect_opcode and the host name expect_host
static void PktTestOptionListCase(PKTTEST_CTX *ctx, char *what, UCHAR *options, UINT options_size,
	UINT expect_opcode, char *expect_host)
{
	UCHAR *data = Clone(options, options_size);
	DHCP_OPTION_LIST *list = ParseDhcpOptionList(data, options_size);
	bool ok = (list != NULL && list->Opcode == expect_opcode && StrCmp(list->Hostname, expect_host) == 0);

	PktTestCheck(ctx, ok, what, "%s, opcode %u, host name \"%s\"; expected opcode %u, host name \"%s\"",
		list == NULL ? "NULL" : "a list", list == NULL ? 0 : list->Opcode,
		list == NULL ? "" : list->Hostname, expect_opcode, expect_host);

	Free(list);
	Free(data);
}

// ParseDhcpOptions and ParseDhcpOptionList
static void PktTestDhcpOptions(PKTTEST_CTX *ctx)
{
	UCHAR discover[] = {DHCP_DISCOVER};
	UCHAR host[] = {'h', 'o', 's', 't'};
	UCHAR host_part[] = {'h', 'o'};
	UCHAR requested_ip[] = {192, 168, 30, 10};
	// A Pad, then the message type
	UCHAR pad_first[] = {0, 53, 1, 1, 255};
	// Pads between the message type and the host name
	UCHAR pad_between[] = {53, 1, 1, 0, 0, 0, 12, 4, 'h', 'o', 's', 't', 255};
	// No End option: the list ends with the data
	UCHAR no_end[] = {53, 1, 1};
	// Pads behind End
	UCHAR pad_after_end[] = {53, 1, 3, 50, 4, 192, 168, 30, 10, 255, 0, 0, 0};
	// Option 250 continues the host name (BuildDhcpOptionsBuf splits an option of more than 255 bytes so)
	UCHAR continued[] = {12, 2, 'h', 'o', 250, 2, 's', 't', 255};
	// The host name says 10 bytes, 2 are left
	UCHAR body_short[] = {53, 1, 1, 12, 10, 'h', 'o'};
	// The last byte is the code of the host name, without its length
	UCHAR no_length[] = {53, 1, 1, 12};
	// The continuation says 5 bytes, 2 are left
	UCHAR continued_short[] = {12, 2, 'h', 'o', 250, 5, 's', 't'};
	// A DISCOVER with Pads around its message type
	UCHAR discover_pads[] = {0, 53, 1, 1, 0, 12, 4, 'h', 'o', 's', 't', 255};

	PktTestOptionsCase(ctx, "ParseDhcpOptions skips a Pad before the message type (the old code read the byte behind it as a length)",
		pad_first, sizeof(pad_first), 1, DHCP_ID_MESSAGE_TYPE, discover, sizeof(discover));
	PktTestOptionsCase(ctx, "ParseDhcpOptions skips Pads between two options",
		pad_between, sizeof(pad_between), 2, DHCP_ID_HOST_NAME, host, sizeof(host));
	PktTestOptionsCase(ctx, "ParseDhcpOptions takes a list that ends with the data, without End",
		no_end, sizeof(no_end), 1, DHCP_ID_MESSAGE_TYPE, discover, sizeof(discover));
	PktTestOptionsCase(ctx, "ParseDhcpOptions stops at End, before the Pads behind it",
		pad_after_end, sizeof(pad_after_end), 2, DHCP_ID_REQUEST_IP_ADDRESS, requested_ip, sizeof(requested_ip));
	PktTestOptionsCase(ctx, "ParseDhcpOptions joins option 250 to the option before it",
		continued, sizeof(continued), 1, DHCP_ID_HOST_NAME, host, sizeof(host));
	PktTestOptionsCase(ctx, "ParseDhcpOptions rejects an option whose body runs past the end (the old code filled it with zeros)",
		body_short, sizeof(body_short), 1, DHCP_ID_MESSAGE_TYPE, discover, sizeof(discover));
	PktTestOptionsCase(ctx, "ParseDhcpOptions rejects an option code without its length",
		no_length, sizeof(no_length), 1, DHCP_ID_MESSAGE_TYPE, discover, sizeof(discover));
	PktTestOptionsCase(ctx, "ParseDhcpOptions rejects an option 250 whose body runs past the end, keeping the option before it",
		continued_short, sizeof(continued_short), 1, DHCP_ID_HOST_NAME, host_part, sizeof(host_part));

	PktTestOptionListCase(ctx, "ParseDhcpOptionList reads the message type and the host name of a DISCOVER with Pads",
		discover_pads, sizeof(discover_pads), DHCP_DISCOVER, "host");
	PktTestOptionListCase(ctx, "ParseDhcpOptionList takes no host name whose body runs past the end",
		body_short, sizeof(body_short), DHCP_DISCOVER, "");
}

// DHCP payload of a BOOTREQUEST of the client in a zeroed heap block of PKTTEST_DHCP_SIZE bytes: the
// fixed header, the magic cookie at PKTTEST_COOKIE_OFFSET and the options (if any) behind it
static UCHAR *PktTestDhcpRequest(UCHAR *options, UINT options_size)
{
	UCHAR *p = ZeroMalloc(PKTTEST_DHCP_SIZE);

	p[0] = 1;									// BOOTREQUEST
	p[1] = 1;									// Ethernet
	p[2] = 6;									// Length of a MAC address
	p[4] = 0x12;								// Transaction ID
	p[5] = 0x34;
	p[6] = 0x56;
	p[7] = 0x78;
	Copy(p + 28, pkttest_mac_client, 6);		// Client hardware address
	Copy(p + PKTTEST_COOKIE_OFFSET, pkttest_cookie, sizeof(pkttest_cookie));

	if (options != NULL)
	{
		Copy(p + PKTTEST_COOKIE_OFFSET + sizeof(pkttest_cookie), options, options_size);
	}

	return p;
}

// Frame of the DHCP payload (PKTTEST_DHCP_SIZE bytes) from the client 0.0.0.0:68 to
// 255.255.255.255:67, tagged as PktTestEthernet does, in a heap block of exactly its size (*size)
static UCHAR *PktTestDhcpFrame(USHORT tpid, UCHAR *payload, UINT *size)
{
	UCHAR src[4] = {0, 0, 0, 0};
	UCHAR dst[4] = {255, 255, 255, 255};

	return PktTestUdpFrame(pkttest_mac_broadcast, pkttest_mac_client, tpid, src, dst, 68, 67,
		payload, PKTTEST_DHCP_SIZE, size);
}

// One DhcpOpCode case: ParsePacket on the frame of the payload must give a DHCP packet with the
// message type expect (0: none)
static void PktTestOpCodeCase(PKTTEST_CTX *ctx, char *what, UCHAR *payload, UINT expect)
{
	UINT size;
	UCHAR *f = PktTestDhcpFrame(0, payload, &size);
	PKT *p = ParsePacket(f, size);
	bool ok = (p != NULL && p->TypeL7 == L7_DHCPV4 && p->DhcpOpCode == expect);

	PktTestCheck(ctx, ok, what, "%s, layer 7 type %u, message type %u; expected a DHCP packet with message type %u",
		p == NULL ? "frame not parsed" : "frame parsed", p == NULL ? 0 : p->TypeL7,
		p == NULL ? 0 : p->DhcpOpCode, expect);

	FreePacket(p);
	Free(f);
}

// ParseDHCPv4Data through ParsePacket (PKT.DhcpOpCode, which the IP table of the hub reads)
static void PktTestOpCode(PKTTEST_CTX *ctx)
{
	UCHAR discover[] = {53, 1, 1, 255};
	UCHAR request[] = {53, 1, 3, 255};
	UCHAR pad_first[] = {0, 53, 1, 1, 255};
	UCHAR *p;

	p = PktTestDhcpRequest(discover, sizeof(discover));
	PktTestOpCodeCase(ctx, "ParsePacket gives the message type of a well-formed DISCOVER", p, DHCP_DISCOVER);

	// Cookie bytes and the options of a REQUEST planted in sname: only the cookie at offset 236 counts
	Copy(p + PKTTEST_SNAME_OFFSET, pkttest_cookie, sizeof(pkttest_cookie));
	Copy(p + PKTTEST_SNAME_OFFSET + sizeof(pkttest_cookie), request, sizeof(request));
	PktTestOpCodeCase(ctx, "ParsePacket reads the options behind the cookie at offset 236, not behind cookie bytes in sname",
		p, DHCP_DISCOVER);
	Free(p);

	// No cookie at offset 236; cookie bytes and the options of a DISCOVER in file
	p = PktTestDhcpRequest(NULL, 0);
	Zero(p + PKTTEST_COOKIE_OFFSET, sizeof(pkttest_cookie));
	Copy(p + PKTTEST_FILE_OFFSET, pkttest_cookie, sizeof(pkttest_cookie));
	Copy(p + PKTTEST_FILE_OFFSET + sizeof(pkttest_cookie), discover, sizeof(discover));
	PktTestOpCodeCase(ctx, "ParsePacket gives no message type without the cookie at offset 236", p, 0);
	Free(p);

	p = PktTestDhcpRequest(pad_first, sizeof(pad_first));
	PktTestOpCodeCase(ctx, "ParsePacket skips a Pad before the message type", p, DHCP_DISCOVER);
	Free(p);
}

// pktparse: DNS opcode mask and label limits, DHCP Pad, whole option bodies, the cookie at offset 236
void pktparse_test(UINT num, char **arg)
{
	PKTTEST_CTX ctx;

	Zero(&ctx, sizeof(ctx));

	Print("Packet parser test\n");

	PktTestDns(&ctx);
	PktTestDhcpOptions(&ctx);
	PktTestOpCode(&ctx);

	if (ctx.NumFailed == 0)
	{
		Print("PKTPARSE TEST OK\n");
	}
	else
	{
		Print("PKTPARSE TEST FAILED (%u of %u checks failed)\n", ctx.NumFailed, ctx.NumChecks);
	}
}
