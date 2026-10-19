// tcpiptest.c
// Named TCP/IP packet test of vpntest ("tcpip" command, SEC-1 #96)
//
// Pins two functions of Mayaqua/TcpIp.c that the hub runs on the frames of VPN clients:
// - DhcpModify, called by DhcpModifyIPv4 when the hub removes the default gateway from DHCP
//   replies. It looks for the magic cookie and reads the options behind it. The cookie is read only
//   at its fixed offset 236 (RFC 2131), and nothing past the end of the payload is read: the old
//   code kept the 44-byte fixed header in the size, so it scanned for the cookie and copied the
//   options up to 44 bytes past the end of every payload, and a cookie behind the end or inside
//   sname selected options that are not the ones of the packet.
// - AdjustTcpMssL3, called by AdjustTcpMssL2 to clamp the MSS of a SYN. It walks the TCP options
//   with checked lengths, so the MSS option is clamped wherever it is in the list, and a malformed
//   list is left alone. The old code clamped it only when it was the first option.
// Every payload, frame and packet is in a heap block of exactly its size, so AddressSanitizer
// reports a read past its end. Prints "TCPIP TEST OK" only when every check passes, and frees
// everything it allocates. The [PASS] lines carry no values; the [FAIL] details do.

#include "Mayaqua/Memory.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/TcpIp.h"

#include <stdarg.h>

#define	TCPIPTEST_DHCP_SIZE			300		// Size of a DHCP payload of the test (DHCP_MIN_SIZE)
#define	TCPIPTEST_COOKIE_OFFSET		236		// Offset of the magic cookie: fixed header (44 bytes), sname (64), file (128)
#define	TCPIPTEST_SNAME_OFFSET		44		// Offset of sname, right behind the fixed header
#define	TCPIPTEST_BEHIND_SIZE		64		// Bytes behind the payload in the block of the "cookie behind the end" check
#define	TCPIPTEST_TARGET_MSS		1300	// MSS that the SYN checks clamp to (0x0514)

// Run state of the test
typedef struct TCPIPTEST_CTX
{
	UINT NumChecks;						// Checks run so far
	UINT NumFailed;						// Checks failed so far
} TCPIPTEST_CTX;

// MAC addresses of the frames: the server (DHCP server, SYN receiver) and the client
static UCHAR tcpiptest_mac_server[6] = {0x5E, 0x00, 0x53, 0x00, 0x00, 0x01};
static UCHAR tcpiptest_mac_client[6] = {0x5E, 0x00, 0x53, 0x00, 0x00, 0x02};

// Magic cookie of the DHCP options, in network byte order
static UCHAR tcpiptest_cookie[4] = {0x63, 0x82, 0x53, 0x63};

// Record one check: print [PASS], or [FAIL] with the formatted detail
static void TcpIpTestCheck(TCPIPTEST_CTX *ctx, bool ok, char *what, char *detail_fmt, ...)
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

// Ethernet header (14 bytes) of an IPv4 frame from src_mac to dst_mac
static void TcpIpTestEthernet(UCHAR *buf, UCHAR *dst_mac, UCHAR *src_mac)
{
	Copy(buf, dst_mac, 6);
	Copy(buf + 6, src_mac, 6);
	buf[12] = 0x08;								// IPv4
	buf[13] = 0x00;
}

// IPv4 header (20 bytes, zeroed before) of an ip_size-byte packet from src to dst, with its checksum.
// The checksum of the layer 4 header behind it is TcpIpTestL4Checksum's
static void TcpIpTestIpv4(UCHAR *ip, UINT ip_size, UCHAR protocol, UCHAR *src, UCHAR *dst)
{
	USHORT sum;

	ip[0] = 0x45;								// Version 4, 20-byte header
	ip[2] = (UCHAR)(ip_size >> 8);
	ip[3] = (UCHAR)(ip_size & 0xFF);
	ip[4] = 0x12;								// Identification
	ip[5] = 0x34;
	ip[6] = 0x40;								// Don't fragment
	ip[8] = 64;									// TTL
	ip[9] = protocol;
	Copy(ip + 12, src, 4);
	Copy(ip + 16, dst, 4);
	sum = IpChecksum(ip, 20);
	Copy(ip + 10, &sum, sizeof(USHORT));
}

// Checksum of the TCP or UDP segment behind the IPv4 header ip, written at sum_offset of the segment
static void TcpIpTestL4Checksum(UCHAR *ip, UINT l4_size, UINT sum_offset)
{
	UINT src_ip, dst_ip;
	USHORT sum;

	Copy(&src_ip, ip + 12, sizeof(UINT));
	Copy(&dst_ip, ip + 16, sizeof(UINT));
	sum = CalcChecksumForIPv4(src_ip, dst_ip, ip[9], ip + 20, l4_size, 0);
	Copy(ip + 20 + sum_offset, &sum, sizeof(USHORT));
}

// DHCP payload (a BOOTREPLY to the client) in a zeroed heap block of block_size bytes: the fixed
// header, the magic cookie at TCPIPTEST_COOKIE_OFFSET and the options behind it
static UCHAR *TcpIpTestDhcp(UINT block_size, UCHAR *options, UINT options_size)
{
	UCHAR *p = ZeroMalloc(block_size);

	p[0] = 2;									// BOOTREPLY
	p[1] = 1;									// Ethernet
	p[2] = 6;									// Length of a MAC address
	p[4] = 0x12;								// Transaction ID
	p[5] = 0x34;
	p[6] = 0x56;
	p[7] = 0x78;
	p[16] = 192;								// Your IP address: 192.168.30.10
	p[17] = 168;
	p[18] = 30;
	p[19] = 10;
	Copy(p + 28, tcpiptest_mac_client, 6);		// Client hardware address
	Copy(p + TCPIPTEST_COOKIE_OFFSET, tcpiptest_cookie, sizeof(tcpiptest_cookie));
	Copy(p + TCPIPTEST_COOKIE_OFFSET + sizeof(tcpiptest_cookie), options, options_size);

	return p;
}

// Ethernet frame of the DHCP server 192.168.30.1:67 to the client 192.168.30.10:68 that carries the
// payload, with valid IPv4 and UDP checksums, in a heap block of exactly its size (*size)
static UCHAR *TcpIpTestDhcpFrame(UCHAR *payload, UINT payload_size, UINT *size)
{
	UCHAR src[4] = {192, 168, 30, 1};
	UCHAR dst[4] = {192, 168, 30, 10};
	UINT udp_size = 8 + payload_size;
	UINT ip_size = 20 + udp_size;
	UCHAR *buf;
	UCHAR *ip;
	UCHAR *udp;

	*size = 14 + ip_size;
	buf = ZeroMalloc(*size);
	ip = buf + 14;
	udp = ip + 20;

	TcpIpTestEthernet(buf, tcpiptest_mac_client, tcpiptest_mac_server);
	TcpIpTestIpv4(ip, ip_size, IP_PROTO_UDP, src, dst);

	udp[1] = 67;								// Source port 67
	udp[3] = 68;								// Destination port 68
	udp[4] = (UCHAR)(udp_size >> 8);
	udp[5] = (UCHAR)(udp_size & 0xFF);
	Copy(udp + 8, payload, payload_size);

	TcpIpTestL4Checksum(ip, udp_size, 6);

	return buf;
}

// IPv4 TCP SYN of the client 10.0.0.1:49152 to 10.0.0.2:443 with the options (a multiple of 4
// bytes) and no data, behind an Ethernet header when ethernet is true, with valid IPv4 and TCP
// checksums, in a heap block of exactly its size (*size)
static UCHAR *TcpIpTestSyn(UCHAR *options, UINT options_size, bool ethernet, UINT *size)
{
	UCHAR src[4] = {10, 0, 0, 1};
	UCHAR dst[4] = {10, 0, 0, 2};
	UINT l2_size = (ethernet ? 14 : 0);
	UINT tcp_size = 20 + options_size;
	UINT ip_size = 20 + tcp_size;
	UCHAR *buf;
	UCHAR *ip;
	UCHAR *tcp;

	*size = l2_size + ip_size;
	buf = ZeroMalloc(*size);
	ip = buf + l2_size;
	tcp = ip + 20;

	if (ethernet)
	{
		TcpIpTestEthernet(buf, tcpiptest_mac_server, tcpiptest_mac_client);
	}

	TcpIpTestIpv4(ip, ip_size, IP_PROTO_TCP, src, dst);

	tcp[0] = 0xC0;								// Source port 49152
	tcp[2] = 0x01;								// Destination port 443
	tcp[3] = 0xBB;
	tcp[7] = 0x01;								// Sequence number
	tcp[12] = (UCHAR)((tcp_size / 4) << 4);		// Header size in 32-bit words
	tcp[13] = TCP_SYN;
	tcp[14] = 0xFA;								// Window 64240
	tcp[15] = 0xF0;
	Copy(tcp + 20, options, options_size);

	TcpIpTestL4Checksum(ip, tcp_size, 16);

	return buf;
}

// One check of a DhcpModify or DhcpModifyIPv4 result: with expect NULL the call must have returned
// NULL, otherwise expect_size bytes equal to expect. Frees the result
static void TcpIpTestBuf(TCPIPTEST_CTX *ctx, char *what, BUF *b, UCHAR *expect, UINT expect_size)
{
	bool ok;

	if (expect == NULL)
	{
		ok = (b == NULL);
	}
	else
	{
		ok = (b != NULL && b->Size == expect_size && Cmp(b->Buf, expect, expect_size) == 0);
	}

	TcpIpTestCheck(ctx, ok, what, "returned %s of %u bytes; expected %s of %u bytes",
		b == NULL ? "NULL" : "a buffer", b == NULL ? 0 : b->Size,
		expect == NULL ? "NULL" : "a buffer", expect == NULL ? 0 : expect_size);

	FreeBuf(b);
}

// DhcpModify and DhcpModifyIPv4
static void TcpIpTestDhcpModify(TCPIPTEST_CTX *ctx)
{
	// Options of a DHCP ACK
	UCHAR ack[] =
	{
		53, 1, 5,								// Message type: ACK
		1, 4, 255, 255, 255, 0,					// Subnet mask
		3, 4, 192, 168, 30, 1,					// Router (the default gateway)
		6, 4, 192, 168, 30, 1,					// DNS server
		15, 3, 'l', 'a', 'n',					// Domain name
		44, 4, 192, 168, 30, 2,					// WINS server
		51, 4, 0x00, 0x00, 0x0E, 0x10,			// Lease time: 3600 s
		255,									// End
	};
	// The same options with the router, DNS, domain name and WINS options removed
	UCHAR ack_modified[] =
	{
		53, 1, 5,
		1, 4, 255, 255, 255, 0,
		51, 4, 0x00, 0x00, 0x0E, 0x10,
		255,
	};
	// Options of a DHCP REQUEST, planted in sname behind cookie bytes
	UCHAR request[] = {53, 1, 3, 255};
	UINT short_sizes[] = {44, 100, TCPIPTEST_COOKIE_OFFSET + 3};
	DHCP_MODIFY_OPTION m;
	UCHAR *p;
	UCHAR *e;
	UCHAR *q;
	UCHAR *f;
	UCHAR *g;
	UINT f_size;
	UINT g_size;
	UINT i;

	Zero(&m, sizeof(m));
	m.RemoveDefaultGatewayOnReply = true;

	// A well-formed ACK: the gateway, DNS, domain name and WINS options go, the result is padded to the
	// size of the payload. The old code read the 44 bytes behind the payload as options.
	p = TcpIpTestDhcp(TCPIPTEST_DHCP_SIZE, ack, sizeof(ack));
	e = TcpIpTestDhcp(TCPIPTEST_DHCP_SIZE, ack_modified, sizeof(ack_modified));
	TcpIpTestBuf(ctx, "DhcpModify removes the gateway, DNS, domain name and WINS options of an ACK, reading nothing past it",
		DhcpModify(&m, p, TCPIPTEST_DHCP_SIZE), e, TCPIPTEST_DHCP_SIZE);

	// The parent: the frame of that ACK through DhcpModifyIPv4, with its UDP checksum computed again
	f = TcpIpTestDhcpFrame(p, TCPIPTEST_DHCP_SIZE, &f_size);
	g = TcpIpTestDhcpFrame(e, TCPIPTEST_DHCP_SIZE, &g_size);
	TcpIpTestBuf(ctx, "DhcpModifyIPv4 modifies the frame of the ACK and computes its UDP checksum again",
		DhcpModifyIPv4(&m, f, f_size), g, g_size);
	Free(f);
	Free(g);

	// Cookie bytes in sname: the options are only the ones behind the cookie at offset 236
	Copy(p + TCPIPTEST_SNAME_OFFSET, tcpiptest_cookie, sizeof(tcpiptest_cookie));
	Copy(p + TCPIPTEST_SNAME_OFFSET + sizeof(tcpiptest_cookie), request, sizeof(request));
	Copy(e + TCPIPTEST_SNAME_OFFSET, tcpiptest_cookie, sizeof(tcpiptest_cookie));
	Copy(e + TCPIPTEST_SNAME_OFFSET + sizeof(tcpiptest_cookie), request, sizeof(request));
	TcpIpTestBuf(ctx, "DhcpModify reads the options behind the cookie at offset 236, not behind cookie bytes in sname",
		DhcpModify(&m, p, TCPIPTEST_DHCP_SIZE), e, TCPIPTEST_DHCP_SIZE);
	Free(p);
	Free(e);

	// A payload without the cookie at offset 236, and a cookie with ACK options right behind the end of
	// the payload (inside the block, so only the result can tell)
	p = TcpIpTestDhcp(TCPIPTEST_DHCP_SIZE + TCPIPTEST_BEHIND_SIZE, NULL, 0);
	Zero(p + TCPIPTEST_COOKIE_OFFSET, sizeof(tcpiptest_cookie));
	Copy(p + TCPIPTEST_DHCP_SIZE, tcpiptest_cookie, sizeof(tcpiptest_cookie));
	Copy(p + TCPIPTEST_DHCP_SIZE + sizeof(tcpiptest_cookie), ack, sizeof(ack));
	TcpIpTestBuf(ctx, "DhcpModify returns NULL when the cookie is behind the end of the payload",
		DhcpModify(&m, p, TCPIPTEST_DHCP_SIZE), NULL, 0);
	Free(p);

	// Payloads that end before the options: only the fixed header, part of sname, part of the cookie
	p = TcpIpTestDhcp(TCPIPTEST_DHCP_SIZE, ack, sizeof(ack));
	for (i = 0; i < sizeof(short_sizes) / sizeof(short_sizes[0]); i++)
	{
		char what[MAX_SIZE];

		q = Clone(p, short_sizes[i]);
		Format(what, sizeof(what), "DhcpModify returns NULL for a %u-byte payload, reading nothing past it", short_sizes[i]);
		TcpIpTestBuf(ctx, what, DhcpModify(&m, q, short_sizes[i]), NULL, 0);
		Free(q);
	}

	// The parent on a frame with a 50-byte DHCP payload: the frame stays as it is
	f = TcpIpTestDhcpFrame(p, 50, &f_size);
	TcpIpTestBuf(ctx, "DhcpModifyIPv4 returns NULL for a frame with a 50-byte DHCP payload, reading nothing past it",
		DhcpModifyIPv4(&m, f, f_size), NULL, 0);
	Free(f);
	Free(p);
}

// One MSS clamp of a SYN with the options (options_size bytes), by AdjustTcpMssL2 on an Ethernet frame
// when ethernet is true, else by AdjustTcpMssL3. With expect not NULL the call must return true and
// leave the SYN with the options expect and a valid TCP checksum; with expect NULL it must return
// false and change no byte
static void TcpIpTestMssCase(TCPIPTEST_CTX *ctx, char *what, UCHAR *options, UCHAR *expect, UINT options_size, bool ethernet)
{
	UINT size;
	UINT expect_size;
	UCHAR *p = TcpIpTestSyn(options, options_size, ethernet, &size);
	UCHAR *e = TcpIpTestSyn(expect != NULL ? expect : options, options_size, ethernet, &expect_size);
	bool ret;
	bool same;

	if (ethernet)
	{
		ret = AdjustTcpMssL2(p, size, TCPIPTEST_TARGET_MSS, 0);
	}
	else
	{
		ret = AdjustTcpMssL3(p, size, TCPIPTEST_TARGET_MSS);
	}

	same = (size == expect_size && Cmp(p, e, size) == 0);

	TcpIpTestCheck(ctx, ret == (expect != NULL) && same, what, "returned %s, the SYN is %s; expected %s",
		ret ? "true" : "false", same ? "as expected" : "not as expected", expect != NULL ? "true" : "false");

	Free(p);
	Free(e);
}

// AdjustTcpMssL3 and AdjustTcpMssL2. The client asks for MSS 1460 (0x05B4); the clamp is to
// TCPIPTEST_TARGET_MSS, 1300 (0x0514)
static void TcpIpTestMss(TCPIPTEST_CTX *ctx)
{
	UCHAR first[] = {2, 4, 0x05, 0xB4};
	UCHAR first_clamped[] = {2, 4, 0x05, 0x14};
	// No-Operation, No-Operation, SACK permitted, MSS
	UCHAR after_sack[] = {1, 1, 4, 2, 2, 4, 0x05, 0xB4};
	UCHAR after_sack_clamped[] = {1, 1, 4, 2, 2, 4, 0x05, 0x14};
	// Timestamps, MSS, No-Operation, window scale, SACK permitted
	UCHAR after_ts[] = {8, 10, 0, 0, 0, 1, 0, 0, 0, 0, 2, 4, 0x05, 0xB4, 1, 3, 3, 7, 4, 2};
	UCHAR after_ts_clamped[] = {8, 10, 0, 0, 0, 1, 0, 0, 0, 0, 2, 4, 0x05, 0x14, 1, 3, 3, 7, 4, 2};
	// MSS 1200, already below the target
	UCHAR below[] = {1, 1, 4, 2, 2, 4, 0x04, 0xB0};
	// End of Option List before the MSS
	UCHAR after_end[] = {1, 0, 0, 0, 2, 4, 0x05, 0xB4};
	// An option with length 0, 1 or a length past the end of the options, before the MSS
	UCHAR length_0[] = {30, 0, 2, 4, 0x05, 0xB4, 1, 1};
	UCHAR length_1[] = {30, 1, 2, 4, 0x05, 0xB4, 1, 1};
	UCHAR length_past[] = {1, 1, 30, 12, 2, 4, 0x05, 0xB4};
	// No MSS, the last byte of the options is the kind of an option without its length
	UCHAR lone_kind[] = {1, 1, 1, 8};

	TcpIpTestMssCase(ctx, "AdjustTcpMssL3 clamps the MSS option at the start of the options", first, first_clamped, sizeof(first), false);
	TcpIpTestMssCase(ctx, "AdjustTcpMssL3 clamps the MSS option behind No-Operation and SACK permitted", after_sack, after_sack_clamped, sizeof(after_sack), false);
	TcpIpTestMssCase(ctx, "AdjustTcpMssL3 clamps the MSS option behind timestamps", after_ts, after_ts_clamped, sizeof(after_ts), false);
	TcpIpTestMssCase(ctx, "AdjustTcpMssL2 clamps the MSS option behind other options in an Ethernet frame", after_sack, after_sack_clamped, sizeof(after_sack), true);
	TcpIpTestMssCase(ctx, "AdjustTcpMssL3 leaves an MSS below the target alone", below, NULL, sizeof(below), false);
	TcpIpTestMssCase(ctx, "AdjustTcpMssL3 ignores MSS bytes behind End of Option List", after_end, NULL, sizeof(after_end), false);
	TcpIpTestMssCase(ctx, "AdjustTcpMssL3 leaves a list with an option of length 0 alone", length_0, NULL, sizeof(length_0), false);
	TcpIpTestMssCase(ctx, "AdjustTcpMssL3 leaves a list with an option of length 1 alone", length_1, NULL, sizeof(length_1), false);
	TcpIpTestMssCase(ctx, "AdjustTcpMssL3 leaves a list with an option longer than the options alone", length_past, NULL, sizeof(length_past), false);
	TcpIpTestMssCase(ctx, "AdjustTcpMssL3 stops at an option kind without its length, reading nothing past it", lone_kind, NULL, sizeof(lone_kind), false);
}

void tcpip_test(UINT num, char **arg)
{
	TCPIPTEST_CTX ctx;

	Zero(&ctx, sizeof(ctx));

	Print("TCP/IP packet test\n");

	TcpIpTestDhcpModify(&ctx);
	TcpIpTestMss(&ctx);

	if (ctx.NumFailed == 0)
	{
		Print("TCPIP TEST OK\n");
	}
	else
	{
		Print("TCPIP TEST FAILED (%u of %u checks failed)\n", ctx.NumFailed, ctx.NumChecks);
	}
}
