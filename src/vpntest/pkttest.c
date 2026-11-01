// pkttest.c
// Named packet parser tests of vpntest ("pktparse" command, FND-38 #113; "vlantpid" command,
// FND-39 #113; "icmpv6ns" command, FND-54 #117)
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
// - the DHCP message type reader (PKT.DhcpOpCode of ParsePacket) reads the magic cookie only at offset 236.
//   The old code took the first cookie bytes anywhere in the payload, also in sname or file.
//
// vlantpid pins the VLAN TPID of the packet parser. A hub with VlanTypeId set (here 0x88A8, the
// TPID of 802.1ad) tags and untags the frames of its VLAN sessions with that TPID, and
// ParsePacketEx5 parses a frame tagged with it through ParsePacketTAGVLAN into layers 3 and 4, as
// it does a frame tagged with 0x8100. The old parser compared 0x8100 only and left such a frame at
// L3_UNKNOWN, so the access list, the ARP, IP, DHCP and RA policy filters and the packet log of the
// hub saw no layer 3 in it. The check on a hub runs frames through the hub packet adapter of two
// in-process sessions, as the storepacket test does.
//
// Every frame and option list is in a heap block of exactly its size, so AddressSanitizer reports
// a read past its end. Each command prints "<COMMAND> TEST OK" only when every check passes, and
// frees everything it allocates. The [PASS] lines carry no values; the [FAIL] details do.

#include "testlist.h"

#include "Cedar/Account.h"
#include "Cedar/Cedar.h"
#include "Cedar/Connection.h"
#include "Cedar/Hub.h"
#include "Cedar/Session.h"

#include "Mayaqua/Kernel.h"
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
#define	PKTTEST_TPID_8021AD			0x88A8	// TPID of 802.1ad, the VlanTypeId of the vlantpid cases
#define	PKTTEST_HUB_NAME			"PKTTEST_VLANTPID"	// Hub of the vlantpid case with an access list
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
static UINT PktTestEthernet(UCHAR *buf, const UCHAR *dst_mac, const UCHAR *src_mac, USHORT tpid, USHORT type)
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
static UCHAR *PktTestUdpFrame(const UCHAR *dst_mac, const UCHAR *src_mac, USHORT tpid, const UCHAR *src, const UCHAR *dst,
	USHORT sport, USHORT dport, const void *payload, UINT payload_size, UINT *size)
{
	UCHAR l2[18];
	UINT l2_size = PktTestEthernet(l2, dst_mac, src_mac, tpid, MAC_PROTO_IPV4);
	UINT udp_size = 8 + payload_size;
	UINT ip_size = 20 + udp_size;

	*size = l2_size + ip_size;
	UCHAR *buf = ZeroMalloc(*size);
	Copy(buf, l2, l2_size);
	UCHAR *ip = buf + l2_size;
	UCHAR *udp = ip + 20;

	ip[0] = 0x45;								// Version 4, 20-byte header
	ip[2] = (UCHAR)(ip_size >> 8);
	ip[3] = (UCHAR)(ip_size & 0xFF);
	ip[8] = 64;									// TTL
	ip[9] = IP_PROTO_UDP;
	Copy(ip + 12, src, 4);
	Copy(ip + 16, dst, 4);
	USHORT sum = IpChecksum(ip, 20);
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
static BUF *PktTestDnsQuery(UCHAR flag1, const UINT *labels, UINT num_labels)
{
	BUF *b = NewBuf();
	UCHAR header[12];
	UCHAR tail[5] = {0x00, 0x00, 0x01, 0x00, 0x01};	// Root label, type A, class IN

	Zero(header, sizeof(header));
	header[0] = 0x52;								// Transaction ID
	header[1] = 0x41;
	header[2] = flag1;
	header[5] = 1;									// One question
	WriteBuf(b, header, sizeof(header));

	for (UINT i = 0; i < num_labels; i++)
	{
		UCHAR len = (UCHAR)labels[i];

		WriteBuf(b, &len, 1);

		for (UINT j = 0; j < labels[i]; j++)
		{
			UCHAR c = PktTestLabelChar(j);

			WriteBuf(b, &c, 1);
		}
	}

	WriteBuf(b, tail, sizeof(tail));

	return b;
}

// Name of the labels of PktTestDnsQuery as ParseDnsQuery gives it: the labels joined with dots
static void PktTestDnsName(char *name, UINT name_size, const UINT *labels, UINT num_labels)
{
	StrCpy(name, name_size, "");

	for (UINT i = 0; i < num_labels; i++)
	{
		if (i != 0)
		{
			StrCat(name, name_size, ".");
		}

		for (UINT j = 0; j < labels[i]; j++)
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
static void PktTestDnsCase(PKTTEST_CTX *ctx, char *what, UCHAR flag1, const UINT *labels, UINT num_labels, bool parsed)
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
static bool PktTestHasOption(LIST *o, UINT id, const void *expect, UINT expect_size)
{
	DHCP_OPTION *opt = GetDhcpOption(o, id);

	return (opt != NULL && opt->Size == expect_size && Cmp(opt->Data, expect, expect_size) == 0);
}

// One ParseDhcpOptions case on the options, in a heap block of exactly options_size bytes: the list
// must hold expect_num options, the option expect_id among them with the bytes expect (expect_size)
static void PktTestOptionsCase(PKTTEST_CTX *ctx, char *what, const UCHAR *options, UINT options_size,
	UINT expect_num, UINT expect_id, const void *expect, UINT expect_size)
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

// ParseDhcpOptions
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

	PktTestOptionsCase(ctx, "ParseDhcpOptions reads the message type and the host name of a DISCOVER with Pads",
		discover_pads, sizeof(discover_pads), 2, DHCP_ID_HOST_NAME, host, sizeof(host));
}

// DHCP payload of a BOOTREQUEST of the client in a zeroed heap block of PKTTEST_DHCP_SIZE bytes: the
// fixed header, the magic cookie at PKTTEST_COOKIE_OFFSET and the options (if any) behind it
static UCHAR *PktTestDhcpRequest(const UCHAR *options, UINT options_size)
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
static UCHAR *PktTestDhcpFrame(USHORT tpid, const UCHAR *payload, UINT *size)
{
	UCHAR src[4] = {0, 0, 0, 0};
	UCHAR dst[4] = {255, 255, 255, 255};

	return PktTestUdpFrame(pkttest_mac_broadcast, pkttest_mac_client, tpid, src, dst, 68, 67,
		payload, PKTTEST_DHCP_SIZE, size);
}

// One DhcpOpCode case: ParsePacket on the frame of the payload must give a DHCP packet with the
// message type expect (0: none)
static void PktTestOpCodeCase(PKTTEST_CTX *ctx, char *what, const UCHAR *payload, UINT expect)
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

// The DHCP message type reader through ParsePacket (PKT.DhcpOpCode, which the IP table of the hub reads)
static void PktTestOpCode(PKTTEST_CTX *ctx)
{
	UCHAR discover[] = {53, 1, 1, 255};
	UCHAR request[] = {53, 1, 3, 255};
	UCHAR pad_first[] = {0, 53, 1, 1, 255};

	UCHAR *p = PktTestDhcpRequest(discover, sizeof(discover));
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
RANZ_TEST("pktparse", pktparse_test, "Packet parsers: DNS opcode mask and label limits, DHCP Pad and whole option bodies, the DHCP cookie at offset 236.");
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

// Hub of the vlantpid case with an access list: two in-process sessions, no server
typedef struct PKTTEST_HUB
{
	CEDAR *Cedar;						// Owner of the hub
	HUB *Hub;							// Hub of the two sessions (not in the hub list of the Cedar)
	THREAD *Thread;						// Owner of the session connections; it has nothing to run
	SESSION *Sender;					// Stores every frame of the case into the hub
	SESSION *Receiver;					// Takes the frames the hub floods
} PKTTEST_HUB;

// ARP request of the client (10.0.0.1 asks for 10.0.0.2) in a broadcast frame, tagged as
// PktTestEthernet does, in a heap block of exactly its size (*size)
static UCHAR *PktTestArpFrame(USHORT tpid, UINT *size)
{
	UCHAR l2[18];
	UINT l2_size = PktTestEthernet(l2, pkttest_mac_broadcast, pkttest_mac_client, tpid, MAC_PROTO_ARPV4);

	*size = l2_size + 28;
	UCHAR *buf = ZeroMalloc(*size);
	Copy(buf, l2, l2_size);
	UCHAR *arp = buf + l2_size;

	arp[1] = 1;									// Hardware type: Ethernet
	arp[2] = 0x08;								// Protocol type: IPv4
	arp[4] = 6;									// Size of a hardware address
	arp[5] = 4;									// Size of a protocol address
	arp[7] = 1;									// Request
	Copy(arp + 8, pkttest_mac_client, 6);		// Sender: the client, 10.0.0.1
	arp[14] = 10;
	arp[17] = 1;
	arp[24] = 10;								// Target: 10.0.0.2, MAC address unknown (zero)
	arp[27] = 2;

	return buf;
}

// One parse case: ParsePacketEx4 with the VLAN TPID of a hub (vlan_type_id, 0 for the default
// 0x8100) must give the layer 3 type expect_l3 and the VLAN ID expect_vlan; for L3_IPV4 also the
// DHCP DISCOVER of the frame (L4_UDP, L7_DHCPV4, message type DISCOVER)
static void PktTestTpidCase(PKTTEST_CTX *ctx, char *what, UCHAR *frame, UINT size, UINT vlan_type_id,
	UINT expect_l3, UINT expect_vlan)
{
	PKT *p = ParsePacketEx4(frame, size, false, vlan_type_id, true, false, false);
	bool ok = (p != NULL && p->TypeL3 == expect_l3 && p->VlanId == expect_vlan);

	if (ok && expect_l3 == L3_IPV4)
	{
		ok = (p->TypeL4 == L4_UDP && p->TypeL7 == L7_DHCPV4 && p->DhcpOpCode == DHCP_DISCOVER);
	}

	PktTestCheck(ctx, ok, what, "%s, layer 3 type %u, VLAN ID %u, layer 7 type %u, message type %u; expected layer 3 type %u, VLAN ID %u",
		p == NULL ? "frame not parsed" : "frame parsed", p == NULL ? 0 : p->TypeL3, p == NULL ? 0 : p->VlanId,
		p == NULL ? 0 : p->TypeL7, p == NULL ? 0 : p->DhcpOpCode, expect_l3, expect_vlan);

	FreePacket(p);
}

// ParsePacketEx4 (ParsePacketEx5, as the hub calls it) with the default and a custom VLAN TPID
static void PktTestTpidParse(PKTTEST_CTX *ctx)
{
	UCHAR discover[] = {53, 1, 1, 255};
	UCHAR *payload = PktTestDhcpRequest(discover, sizeof(discover));
	UINT dhcp_8021ad_size, dhcp_8021q_size, dhcp_untagged_size, arp_8021ad_size;

	UCHAR *dhcp_8021ad = PktTestDhcpFrame(PKTTEST_TPID_8021AD, payload, &dhcp_8021ad_size);
	UCHAR *dhcp_8021q = PktTestDhcpFrame(MAC_PROTO_TAGVLAN, payload, &dhcp_8021q_size);
	UCHAR *dhcp_untagged = PktTestDhcpFrame(0, payload, &dhcp_untagged_size);
	UCHAR *arp_8021ad = PktTestArpFrame(PKTTEST_TPID_8021AD, &arp_8021ad_size);

	PktTestTpidCase(ctx, "TPID 0x88A8: a 0x88A8-tagged DHCP DISCOVER is IPv4, UDP and DHCP with its VLAN ID (the old parser left it at L3_UNKNOWN)",
		dhcp_8021ad, dhcp_8021ad_size, PKTTEST_TPID_8021AD, L3_IPV4, PKTTEST_VLAN_ID);
	PktTestTpidCase(ctx, "TPID 0x88A8: a 0x88A8-tagged ARP request is ARP with its VLAN ID (the old parser left it at L3_UNKNOWN)",
		arp_8021ad, arp_8021ad_size, PKTTEST_TPID_8021AD, L3_ARPV4, PKTTEST_VLAN_ID);
	PktTestTpidCase(ctx, "default TPID: a 0x8100-tagged DHCP DISCOVER is parsed as before",
		dhcp_8021q, dhcp_8021q_size, 0, L3_IPV4, PKTTEST_VLAN_ID);
	PktTestTpidCase(ctx, "TPID 0x88A8: a 0x8100-tagged DHCP DISCOVER is still parsed as before",
		dhcp_8021q, dhcp_8021q_size, PKTTEST_TPID_8021AD, L3_IPV4, PKTTEST_VLAN_ID);
	PktTestTpidCase(ctx, "default TPID: a 0x88A8-tagged frame is no VLAN frame",
		dhcp_8021ad, dhcp_8021ad_size, 0, L3_UNKNOWN, 0);
	PktTestTpidCase(ctx, "TPID 0x0800 (IPv4): an untagged IPv4 frame is still IPv4",
		dhcp_untagged, dhcp_untagged_size, MAC_PROTO_IPV4, L3_IPV4, 0);

	Free(arp_8021ad);
	Free(dhcp_untagged);
	Free(dhcp_8021q);
	Free(dhcp_8021ad);
	Free(payload);
}

// The session connections have nothing to run
static void PktTestIdleThread(THREAD *thread, void *param)
{
}

// In-process server session on the hub of the case with the hub packet adapter and the default
// policy, made like the sessions of the storepacket test
static SESSION *PktTestNewSession(PKTTEST_HUB *h, char *username)
{
	POLICY *policy = ClonePolicy(GetDefaultPolicy());

	CONNECTION *c = NewServerConnection(h->Cedar, NULL, h->Thread);
	SESSION *s = NewServerSession(h->Cedar, c, h->Hub, username, policy);
	c->Session = s;
	ReleaseConnection(c);

	s->Username = CopyStr(username);

	s->PacketAdapter->Init(s);

	return s;
}

// Release a session in the order of the end of SessionMain: leave the hub, free the packet adapter, release
static void PktTestFreeSession(SESSION *s)
{
	DelSession(s->Hub, s);
	s->PacketAdapter->Free(s);
	ReleaseSession(s);
}

// One hub case: the sender stores a broadcast IPv4 UDP frame from 10.5.0.1 to dst, tagged with tpid
// (VLAN ID PKTTEST_VLAN_ID), into the hub. With pass true the receiver must get it once and
// unchanged, with pass false not at all
static void PktTestHubCase(PKTTEST_CTX *ctx, const PKTTEST_HUB *h, char *what, USHORT tpid, const UCHAR *dst, bool pass)
{
	UCHAR src[4] = {10, 5, 0, 1};
	UCHAR data[8] = {0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7};
	SESSION *r = h->Receiver;
	UINT size;
	UCHAR *frame = PktTestUdpFrame(pkttest_mac_broadcast, pkttest_mac_client, tpid, src, dst, 40000, 40001,
		data, sizeof(data), &size);
	void *recv;
	UINT recv_size;
	UINT num_recv = 0;
	UINT num_equal = 0;

	// The hub owns the copy; a send without data ends the receive loop of the sender
	h->Sender->PacketAdapter->PutPacket(h->Sender, Clone(frame, size), size);
	h->Sender->PacketAdapter->PutPacket(h->Sender, NULL, 0);

	while ((recv_size = r->PacketAdapter->GetNextPacket(r, &recv)) != 0)
	{
		if (recv_size == size && Cmp(recv, frame, size) == 0)
		{
			num_equal++;
		}

		Free(recv);
		num_recv++;
	}

	PktTestCheck(ctx, pass ? (num_recv == 1 && num_equal == 1) : (num_recv == 0), what,
		"%u frames delivered (%u unchanged); expected %u", num_recv, num_equal, pass ? 1 : 0);

	Free(frame);
}

// A hub with VlanTypeId 0x88A8 and an access list entry that discards every IPv4 frame to 192.0.2.99
static void PktTestTpidHub(PKTTEST_CTX *ctx)
{
	PKTTEST_HUB h;
	HUB_OPTION o;
	ACCESS a;
	UCHAR denied[4] = {192, 0, 2, 99};
	UCHAR allowed[4] = {192, 0, 2, 100};

	Zero(&h, sizeof(h));

	h.Cedar = NewCedar(NULL, NULL);

	// The defaults of a new hub with the 802.1ad TPID; no watchdog thread (ARP and neighbor polling), no log files
	Zero(&o, sizeof(o));
	SiSetDefaultHubOption(&o);
	o.NoArpPolling = true;
	o.VlanTypeId = PKTTEST_TPID_8021AD;
	h.Hub = NewHub(h.Cedar, PKTTEST_HUB_NAME, &o);
	h.Hub->LogSetting.SavePacketLog = false;
	h.Hub->LogSetting.SaveSecurityLog = false;

	h.Thread = NewThread(PktTestIdleThread, NULL);
	h.Sender = PktTestNewSession(&h, "vlantpid-sender");
	h.Receiver = PktTestNewSession(&h, "vlantpid-receiver");

	Zero(&a, sizeof(a));
	a.Active = true;
	a.Priority = 1;
	a.Discard = true;
	Copy(&a.DestIpAddress, denied, sizeof(denied));
	a.DestSubnetMask = 0xFFFFFFFF;
	AddAccessListEx(h.Hub, &a, false, false);

	PktTestHubCase(ctx, &h, "hub with VlanTypeId 0x88A8: the access list drops a 0x88A8-tagged frame to the denied IPv4 address (the old parser saw no IPv4 in it)",
		PKTTEST_TPID_8021AD, denied, false);
	PktTestHubCase(ctx, &h, "hub with VlanTypeId 0x88A8: a 0x88A8-tagged frame to another IPv4 address passes unchanged",
		PKTTEST_TPID_8021AD, allowed, true);
	PktTestHubCase(ctx, &h, "hub with VlanTypeId 0x88A8: the access list drops a 0x8100-tagged frame to the denied IPv4 address, as before",
		MAC_PROTO_TAGVLAN, denied, false);

	PktTestFreeSession(h.Receiver);
	PktTestFreeSession(h.Sender);
	ReleaseThread(h.Thread);
	ReleaseHub(h.Hub);
	ReleaseCedar(h.Cedar);
}

// vlantpid: the parser honours the VLAN TPID of the hub, the access list of a hub with a custom TPID
RANZ_TEST("vlantpid", vlantpid_test, "VLAN TPID: frames tagged with the hub's VlanTypeId reach layer 3 and 4, the access list of such a hub sees their IPv4.");
void vlantpid_test(UINT num, char **arg)
{
	PKTTEST_CTX ctx;

	Zero(&ctx, sizeof(ctx));

	Print("VLAN TPID test\n");

	PktTestTpidParse(&ctx);
	PktTestTpidHub(&ctx);

	if (ctx.NumFailed == 0)
	{
		Print("VLANTPID TEST OK\n");
	}
	else
	{
		Print("VLANTPID TEST FAILED (%u of %u checks failed)\n", ctx.NumFailed, ctx.NumChecks);
	}
}

// icmpv6ns: BuildNeighborSolicitation gives the bytes the former builder chain (BuildICMPv6NeighborSoliciation,
// BuildICMPv6, BuildIPv6, BuildIPv6PacketHeader, BuildICMPv6Options) gave for the unicast case
// the hub sends, for the source fe80::1, the target 2001:db8::7 and the MAC address of the server:
// the 40-byte IPv6 header (hop limit 255, next header 58, payload length 32), the ICMPv6 header
// (type 135, checksum over the pseudo-header), the target address and the source link-layer option.
// The frame below was computed from the former code's layout, independently of the new function
static UCHAR pkttest_ns_golden[72] =
{
	0x60, 0x00, 0x00, 0x00, 0x00, 0x20, 0x3A, 0xFF,
	0xFE, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	0x20, 0x01, 0x0D, 0xB8, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07,
	0x87, 0x00, 0x6C, 0xA0, 0x00, 0x00, 0x00, 0x00,
	0x20, 0x01, 0x0D, 0xB8, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07,
	0x01, 0x01, 0x5E, 0x00, 0x53, 0x00, 0x00, 0x01,
};

RANZ_TEST("icmpv6ns", icmpv6ns_test, "Neighbor Solicitation: BuildNeighborSolicitation gives the bytes of the former builder chain, nothing for a NULL argument.");
void icmpv6ns_test(UINT num, char **arg)
{
	PKTTEST_CTX ctx;
	IPV6_ADDR src;
	IPV6_ADDR target;

	Zero(&ctx, sizeof(ctx));

	Print("ICMPv6 Neighbor Solicitation test\n");

	Zero(&src, sizeof(src));
	src.Value[0] = 0xFE;
	src.Value[1] = 0x80;
	src.Value[15] = 0x01;

	Zero(&target, sizeof(target));
	target.Value[0] = 0x20;
	target.Value[1] = 0x01;
	target.Value[2] = 0x0D;
	target.Value[3] = 0xB8;
	target.Value[15] = 0x07;

	BUF *b = BuildNeighborSolicitation(&src, &target, pkttest_mac_server);

	PktTestCheck(&ctx, b != NULL && b->Size == sizeof(pkttest_ns_golden),
		"BuildNeighborSolicitation gives the 72 bytes of the packet", "size %u", (b == NULL) ? 0 : b->Size);
	PktTestCheck(&ctx, b != NULL && b->Size == sizeof(pkttest_ns_golden) &&
		Cmp(b->Buf, pkttest_ns_golden, sizeof(pkttest_ns_golden)) == 0,
		"BuildNeighborSolicitation gives the bytes of the former builder chain", "bytes differ");
	PktTestCheck(&ctx, b != NULL && b->Current == 0, "the packet is read from its start", "position %u",
		(b == NULL) ? 0 : b->Current);
	FreeBuf(b);

	b = BuildNeighborSolicitation(NULL, &target, pkttest_mac_server);
	PktTestCheck(&ctx, b == NULL, "BuildNeighborSolicitation without a source gives nothing", "got a packet");
	FreeBuf(b);

	b = BuildNeighborSolicitation(&src, NULL, pkttest_mac_server);
	PktTestCheck(&ctx, b == NULL, "BuildNeighborSolicitation without a target gives nothing", "got a packet");
	FreeBuf(b);

	b = BuildNeighborSolicitation(&src, &target, NULL);
	PktTestCheck(&ctx, b == NULL, "BuildNeighborSolicitation without a MAC address gives nothing", "got a packet");
	FreeBuf(b);

	if (ctx.NumFailed == 0)
	{
		Print("ICMPV6NS TEST OK\n");
	}
	else
	{
		Print("ICMPV6NS TEST FAILED (%u of %u checks failed)\n", ctx.NumFailed, ctx.NumChecks);
	}
}
