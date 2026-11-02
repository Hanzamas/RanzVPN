// l3routetest.c
// Named L3 routed network test of vpntest ("l3route" command, CORE-S6-1 #80)
//
// The routed networks of the server role of a node (Cedar/NodeRouted.c) on real Microsoft KM-TEST Loopback Adapters, with
// the backend that the host gives their ports, on one runner, as the ADR-0002 amendment of 2026-10-21 has the criteria of
// the new core proven. The kmtest job of windows.yml runs it as administrator after ranz install, which gives the ports
// XDP (.github/scripts/l3route.ps1); the smoke loop leaves it out (.github/quality/smoke-exclude.txt). Its argument is the
// backend that the host must give: "xdp" (the default) or "selow".
// - The server role: a node whose configuration store holds the L2 Network lan and the L3 Networks lab-a, lab-b, lab-c
//   (offline) and lab-d, and the Routed setting with the gateways of lab-a (198.18.81.1/24 and fd81:a::1/64, with NAT) and
//   lab-b (198.18.82.1/24 and fd81:b::1/64), brings lab-a and lab-b up, each on a KM-TEST adapter of its own whose
//   interfaces hold its gateway addresses and forward IPv4 and IPv6, as GetIpInterfaceEntry reads them back. lab-c, which
//   is offline, and lab-d, which the setting does not name, stay down.
// - Routing through the Windows IP stack (golden family l3route, l3route_routing.txt): the test plays the members of the
//   two networks behind their ports. UDP and an echo request of IPv4 from lab-a to lab-b, UDP of IPv4 back, and UDP of
//   IPv6 from lab-a to lab-b reach the member of the other network as a router forwards them: the TTL or the hop limit one
//   less, the IPv4 header checksum made anew and every other byte as it was. A packet from an address of another network is
//   refused by the port. The oracle of the slim fork has no routing between its Hubs since its Layer 3 switch went (#26),
//   so the golden file is the reference of the routing.
// - The kernel forwards, the node does not: with the forwarding of the IPv4 interface of lab-a off, a packet of lab-a to
//   lab-b arrives nowhere, and with it on again it arrives; the forwarded datagrams that the IPv4 and IPv6 stacks of the
//   host count (GetIpStatisticsEx) grow by the packets that went across at least; the port of each network took from its
//   members only what they sent and handed them only what the kernel routed to them.
// - The NAT to the internet (l3route_nat.txt): a KM-TEST adapter of the test with its own L2 adapter, the uplink
//   (198.18.83.1/24, with a route to 198.18.201.0/24 through a neighbour behind it), stands in for the internet, which a
//   hosted runner cannot answer from. The NAT network of WinNAT of the node, RanzVPN-Egress, is over 198.18.81.0/24, the
//   prefix of lab-a. UDP of lab-a to 198.18.201.10 leaves by the uplink from the address of the uplink, translated by
//   WinNAT, and the answer that the test puts into the uplink reaches the member of lab-a translated back; UDP of lab-b,
//   which asks for no NAT, leaves by the uplink from its own address. Once the node stopped, the NAT network of the node and
//   the gateway addresses are gone.
// Prints "L3ROUTE TEST OK" only when every check passes.

#include "harness_int.h"
#include "testlist.h"

#include "Cedar/ConfigStore.h"
#include "Cedar/Node.h"
#include "Cedar/NodeEgress.h"
#include "Cedar/NodeL2.h"
#include "Cedar/NodeRouted.h"

#include "Mayaqua/Encrypt.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Kernel.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/TcpIp.h"

#include <iphlpapi.h>

#include <stdio.h>

#define	L3ROUTE_BUDGET			400000		// The whole test ends within this time, or the watchdog ends the process (ms)
#define	L3ROUTE_BOUND			15000		// A bounded wait on observable state (ms)
#define	L3ROUTE_POLL			20			// Poll interval of observable state (ms)
#define	L3ROUTE_QUIET			1500		// ms that a packet that must arrive nowhere is waited for
#define	L3ROUTE_MAX_PACKET		1600		// Bytes of a packet that a member keeps at most
#define	L3ROUTE_MAX_PACKETS		64			// Packets that a member keeps: the last ones
#define	L3ROUTE_TTL				64			// The TTL and the hop limit of the packets of the members
#define	L3ROUTE_KEY				"Ranz L3Route Test"		// The identity key of the node, in the software KSP; deleted at the end
#define	L3ROUTE_KEY_W			L"Ranz L3Route Test"
#define	L3ROUTE_UPLINK			83			// The Network id of the MAC address of the uplink (NodeL2Mac)
#define	L3ROUTE_LENGTH			24			// The prefix length of the uplink
#define	L3ROUTE_ECHO_PORT		7			// The UDP port of the address behind the uplink
#define	L3ROUTE_GOLDEN			"l3route_routing.txt"
#define	L3ROUTE_GOLDEN_NAT		"l3route_nat.txt"
#define	L3ROUTE_DATA			"ranz l3route"
#define	L3ROUTE_ANSWER			"ranz l3route answer"

// The Routed setting of the node: lab-a with NAT, lab-b without
static char *l3route_setting =
	"{\"networks\": ["
	"{\"name\": \"lab-a\", \"gateways\": [\"198.18.81.1/24\", \"fd81:a::1/64\"], \"nat\": true},"
	"{\"name\": \"lab-b\", \"gateways\": [\"198.18.82.1/24\", \"fd81:b::1/64\"]}"
	"]}";

// The addresses of the test, in network byte order
static UCHAR l3route_a4[4] = {198, 18, 81, 10};				// The member of lab-a
static UCHAR l3route_b4[4] = {198, 18, 82, 10};				// The member of lab-b
static UCHAR l3route_b4_other[4] = {198, 18, 82, 11};		// Another address of lab-b
static UCHAR l3route_gw_a4[4] = {198, 18, 81, 1};			// The gateway of lab-a
static UCHAR l3route_gw_b4[4] = {198, 18, 82, 1};			// ... and of lab-b
static UCHAR l3route_uplink4[4] = {198, 18, 83, 1};			// The uplink
static UCHAR l3route_neighbour4[4] = {198, 18, 83, 2};		// The neighbour behind the uplink ...
static UCHAR l3route_outside_net[4] = {198, 18, 201, 0};	// ... the network behind it ...
static UCHAR l3route_outside4[4] = {198, 18, 201, 10};		// ... and the address there that answers
static UCHAR l3route_a6[16] = {0xFD, 0x81, 0, 0x0A, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10};	// The member of lab-a: fd81:a::10
static UCHAR l3route_b6[16] = {0xFD, 0x81, 0, 0x0B, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10};	// ... of lab-b: fd81:b::10
static UCHAR l3route_gw_a6[16] = {0xFD, 0x81, 0, 0x0A, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01};	// The gateway of lab-a: fd81:a::1
static UCHAR l3route_gw_b6[16] = {0xFD, 0x81, 0, 0x0B, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01};	// ... and of lab-b

// The MAC address of the neighbour behind the uplink
static UCHAR l3route_neighbour_mac[6] = {0x02, 0x00, 0x00, 0x00, 0x83, 0x02};

// The checks of the test
typedef struct L3ROUTE_CTX
{
	UINT NumChecks;
	UINT NumFailed;
} L3ROUTE_CTX;

// A member side that the test plays, or the neighbour behind the uplink: the last IP packets that it took
typedef struct L3ROUTE_MEMBER
{
	SRWLOCK Lock;
	UINT Taken;											// Packets taken in all; packet i is at i % L3ROUTE_MAX_PACKETS
	UINT Sizes[L3ROUTE_MAX_PACKETS];
	UCHAR Packets[L3ROUTE_MAX_PACKETS][L3ROUTE_MAX_PACKET];
} L3ROUTE_MEMBER;

// What a packet that the test waits for is
typedef struct L3ROUTE_MATCH
{
	UINT Version;			// 4 or 6
	UINT Protocol;			// The IP protocol: 17 for UDP, 1 for ICMP
	UINT AddressSize;		// 4 or 16
	UCHAR Src[16];			// The source, all zero for any
	UCHAR Dst[16];			// The destination
	UINT SrcPort;			// UDP: the source port, 0 for any ...
	UINT DstPort;			// ... and the destination port
} L3ROUTE_MATCH;

// The uplink: a KM-TEST adapter of the test with its L2 adapter, its address, the neighbour behind it and the route to the
// network behind it
typedef struct L3ROUTE_UPLINK
{
	UCHAR Mac[6];
	NODE_KMTEST *KmTest;
	UINT IfIndex;
	UINT64 Luid;
	NODE_L2 *L2;
	bool Address;
	bool Neighbour;
	bool Route;
	L3ROUTE_MEMBER *Taken;
} L3ROUTE_UPLINK;

static bool L3Check(L3ROUTE_CTX *ctx, bool ok, char *what, char *fmt, ...) RANZ_PRINTF_FORMAT(4, 5);
static bool L3Check(L3ROUTE_CTX *ctx, bool ok, char *what, char *fmt, ...)
{
	char detail[MAX_SIZE * 2];
	va_list args;

	ctx->NumChecks++;

	if (ok)
	{
		Print("  [PASS] %s\n", what);
		return true;
	}

	va_start(args, fmt);
	FormatArgs(detail, sizeof(detail), fmt, args);
	va_end(args);

	Print("  [FAIL] %s: %s\n", what, detail);
	ctx->NumFailed++;

	return false;
}

// The watchdog: a native thread that ends a run that hangs, so that a stuck driver is a failed test instead of a hung CI step
static DWORD WINAPI L3Watchdog(LPVOID param)
{
	char msg[MAX_SIZE];
	DWORD written = 0;

	if (WaitForSingleObject((HANDLE)param, L3ROUTE_BUDGET) != WAIT_TIMEOUT)
	{
		return 0;
	}

	int len = snprintf(msg, sizeof(msg), "L3ROUTE TEST FAILED (did not finish within %u ms)\n", (UINT)L3ROUTE_BUDGET);
	if (len > 0)
	{
		WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), msg, (DWORD)MIN((UINT)len, (UINT)sizeof(msg) - 1), &written, NULL);
	}

	TerminateProcess(GetCurrentProcess(), 1);

	return 0;
}

// Add a line to a text
static void L3Line(BUF *b, char *line)
{
	WriteBuf(b, line, StrLen(line));
	WriteBuf(b, "\n", 1);
}

// An IPv4 address as text
static void L3Ip4Str(char *str, UINT size, const UCHAR *a)
{
	Format(str, size, "%u.%u.%u.%u", (UINT)a[0], (UINT)a[1], (UINT)a[2], (UINT)a[3]);
}

//
// The members
//

// Keep a copy of a packet
static void L3Take(L3ROUTE_MEMBER *m, const UCHAR *packet, UINT size)
{
	AcquireSRWLockExclusive(&m->Lock);
	UINT i = m->Taken % L3ROUTE_MAX_PACKETS;
	m->Sizes[i] = MIN(size, (UINT)L3ROUTE_MAX_PACKET);
	Copy(m->Packets[i], packet, m->Sizes[i]);
	m->Taken++;
	ReleaseSRWLockExclusive(&m->Lock);
}

// The owner of the member side of a routed network: it keeps what the kernel routed to the members
static void L3MemberProc(NODE_ROUTED *r, void *param, const UCHAR *packet, UINT size)
{
	L3Take((L3ROUTE_MEMBER *)param, packet, size);
}

// The neighbour behind the uplink: it keeps the IPv4 packets that the host sends to it out of the uplink
static void L3UplinkProc(NODE_L2 *a, void *param, const UCHAR *frame, UINT size)
{
	if (size > 14 && Cmp(frame, l3route_neighbour_mac, 6) == 0 && frame[12] == 0x08 && frame[13] == 0x00)
	{
		L3Take((L3ROUTE_MEMBER *)param, frame + 14, size - 14);
	}
}

// The packets that a member took so far, the mark from which L3Wait looks
static UINT L3Mark(L3ROUTE_MEMBER *m)
{
	AcquireSRWLockShared(&m->Lock);
	UINT ret = m->Taken;
	ReleaseSRWLockShared(&m->Lock);

	return ret;
}

// Whether a packet is what want names
static bool L3Matches(const UCHAR *p, UINT size, const L3ROUTE_MATCH *want)
{
	static const UCHAR any[16] = {0};
	UINT header = 0;
	UINT proto = 0;
	const UCHAR *src = NULL;
	const UCHAR *dst = NULL;

	if (size < 20 || (UINT)(p[0] >> 4) != want->Version)
	{
		return false;
	}

	if (want->Version == 4)
	{
		header = (UINT)(p[0] & 0x0F) * 4;
		proto = p[9];
		src = p + 12;
		dst = p + 16;
	}
	else
	{
		if (size < 40)
		{
			return false;
		}
		header = 40;
		proto = p[6];
		src = p + 8;
		dst = p + 24;
	}

	if (proto != want->Protocol || Cmp(dst, want->Dst, want->AddressSize) != 0)
	{
		return false;
	}
	if (Cmp(want->Src, any, want->AddressSize) != 0 && Cmp(src, want->Src, want->AddressSize) != 0)
	{
		return false;
	}
	if (proto == 17)
	{
		if (size < header + 8)
		{
			return false;
		}
		if (want->SrcPort != 0 && READ_USHORT(p + header) != want->SrcPort)
		{
			return false;
		}
		if (want->DstPort != 0 && READ_USHORT(p + header + 2) != want->DstPort)
		{
			return false;
		}
	}

	return true;
}

// The first packet that the member took from the mark since on that matches want, copied into out (L3ROUTE_MAX_PACKET bytes),
// waiting up to wait ms for it: its size, 0 when none came
static UINT L3Wait(L3ROUTE_MEMBER *m, UINT since, const L3ROUTE_MATCH *want, UCHAR *out, UINT wait)
{
	UINT64 end = GetTickCount64() + wait;

	while (true)
	{
		UINT found = 0;

		AcquireSRWLockShared(&m->Lock);
		for (UINT i = since;i < m->Taken && found == 0;i++)
		{
			UINT slot = i % L3ROUTE_MAX_PACKETS;

			if (m->Taken - i <= L3ROUTE_MAX_PACKETS && L3Matches(m->Packets[slot], m->Sizes[slot], want))
			{
				found = m->Sizes[slot];
				Copy(out, m->Packets[slot], found);
			}
		}
		ReleaseSRWLockShared(&m->Lock);

		if (found != 0)
		{
			return found;
		}
		if (GetTickCount64() >= end)
		{
			return 0;
		}
		SleepThread(L3ROUTE_POLL);
	}
}

//
// The packets
//

// An IPv4 packet into buf from src to dst of the protocol proto with the identification id and size bytes of data after the
// header, whose checksum holds; its size
static UINT L3Ipv4(UCHAR *buf, const UCHAR *src, const UCHAR *dst, UCHAR proto, USHORT id, const UCHAR *data, UINT size)
{
	UINT total = 20 + size;

	Zero(buf, 20);
	buf[0] = 0x45;
	WRITE_USHORT(buf + 2, total);
	WRITE_USHORT(buf + 4, id);
	buf[8] = L3ROUTE_TTL;
	buf[9] = proto;
	Copy(buf + 12, src, 4);
	Copy(buf + 16, dst, 4);
	USHORT sum = IpChecksum(buf, 20);
	Copy(buf + 10, &sum, 2);
	Copy(buf + 20, data, size);

	return total;
}

// A UDP datagram of IPv4 into buf with the text as its data, its UDP checksum set; its size
static UINT L3Udp4(UCHAR *buf, const UCHAR *src, USHORT sport, const UCHAR *dst, USHORT dport, USHORT id, char *text)
{
	UCHAR udp[L3ROUTE_MAX_PACKET];
	UINT len = StrLen(text);
	UINT udp_len = 8 + len;
	UINT s = 0;
	UINT d = 0;

	WRITE_USHORT(udp, sport);
	WRITE_USHORT(udp + 2, dport);
	WRITE_USHORT(udp + 4, udp_len);
	udp[6] = 0;
	udp[7] = 0;
	Copy(udp + 8, text, len);
	Copy(&s, src, 4);
	Copy(&d, dst, 4);
	USHORT sum = CalcChecksumForIPv4(s, d, 17, udp, udp_len, 0);
	Copy(udp + 6, &sum, 2);

	return L3Ipv4(buf, src, dst, 17, id, udp, udp_len);
}

// An ICMP echo request of IPv4 into buf with the text as its data; its size
static UINT L3Echo4(UCHAR *buf, const UCHAR *src, const UCHAR *dst, USHORT id, USHORT seq, char *text)
{
	UCHAR icmp[L3ROUTE_MAX_PACKET];
	UINT len = StrLen(text);

	icmp[0] = 8;
	icmp[1] = 0;
	icmp[2] = 0;
	icmp[3] = 0;
	WRITE_USHORT(icmp + 4, id);
	WRITE_USHORT(icmp + 6, seq);
	Copy(icmp + 8, text, len);
	USHORT sum = IpChecksum(icmp, 8 + len);
	Copy(icmp + 2, &sum, 2);

	return L3Ipv4(buf, src, dst, 1, id, icmp, 8 + len);
}

// A UDP datagram of IPv6 into buf with the text as its data, its UDP checksum set; its size
static UINT L3Udp6(UCHAR *buf, const UCHAR *src, USHORT sport, const UCHAR *dst, USHORT dport, char *text)
{
	UINT len = StrLen(text);
	UINT udp_len = 8 + len;
	UCHAR *udp = buf + 40;

	Zero(buf, 40 + udp_len);
	buf[0] = 0x60;
	WRITE_USHORT(buf + 4, udp_len);
	buf[6] = 17;
	buf[7] = L3ROUTE_TTL;
	Copy(buf + 8, src, 16);
	Copy(buf + 24, dst, 16);
	WRITE_USHORT(udp, sport);
	WRITE_USHORT(udp + 2, dport);
	WRITE_USHORT(udp + 4, udp_len);
	Copy(udp + 8, text, len);
	USHORT sum = CalcChecksumForIPv6((IPV6_ADDR *)(buf + 8), (IPV6_ADDR *)(buf + 24), 17, udp, udp_len, 0);
	Copy(udp + 6, &sum, 2);

	return 40 + udp_len;
}

// Whether the packet got is the packet sent as a router forwards it: the TTL or the hop limit one less, the IPv4 header
// checksum anew, and every other byte as it was
static bool L3AsRouted(const UCHAR *sent, UINT sent_size, const UCHAR *got, UINT got_size)
{
	UCHAR a[L3ROUTE_MAX_PACKET];
	UCHAR b[L3ROUTE_MAX_PACKET];

	if (sent_size != got_size || sent_size < 20 || sent_size > sizeof(a))
	{
		return false;
	}

	Copy(a, sent, sent_size);
	Copy(b, got, got_size);

	if ((a[0] >> 4) == 4)
	{
		if ((UINT)b[8] + 1 != (UINT)a[8] || IpChecksum(b, (UINT)(b[0] & 0x0F) * 4) != 0)
		{
			return false;
		}
		a[8] = 0;
		b[8] = 0;
		a[10] = 0;
		a[11] = 0;
		b[10] = 0;
		b[11] = 0;
	}
	else
	{
		if ((UINT)b[7] + 1 != (UINT)a[7])
		{
			return false;
		}
		a[7] = 0;
		b[7] = 0;
	}

	return (Cmp(a, b, sent_size) == 0);
}

//
// The routing between lab-a and lab-b
//

// What a case of the routing expects of its packet
#define	L3ROUTE_ROUTED			0			// The member of the other network gets it as a router forwards it
#define	L3ROUTE_NOWHERE			1			// No one gets it
#define	L3ROUTE_REFUSED			2			// The port refuses it

// One packet of a member of from: it goes into the host through the port of from, and the member to_member of the network
// to_name, or the member other of other_name, gets it, or no one does. The line of the case, its description desc and what
// the test saw, goes into text. True when it went as expect says.
static bool L3Case(L3ROUTE_CTX *ctx, BUF *text, char *desc, UINT expect, NODE_ROUTED *from, char *to_name, L3ROUTE_MEMBER *to_member,
	char *other_name, L3ROUTE_MEMBER *other, const UCHAR *packet, UINT size, const L3ROUTE_MATCH *want)
{
	UCHAR got[L3ROUTE_MAX_PACKET];
	UCHAR got_other[L3ROUTE_MAX_PACKET];
	char line[MAX_SIZE * 2];
	char what[MAX_SIZE * 2];
	bool ok = false;
	bool v4 = ((packet[0] >> 4) == 4);
	UINT mark = L3Mark(to_member);
	UINT mark_other = L3Mark(other);

	bool sent = NodeRoutedSend(from, packet, size);
	UINT got_size = (sent ? L3Wait(to_member, mark, want, got, expect == L3ROUTE_ROUTED ? L3ROUTE_BOUND : L3ROUTE_QUIET) : 0);
	UINT other_size = L3Wait(other, mark_other, want, got_other, 0);

	if (sent == false)
	{
		Format(line, sizeof(line), "%s: refused by the port", desc);
		ok = (expect == L3ROUTE_REFUSED);
	}
	else if (got_size != 0)
	{
		bool routed = L3AsRouted(packet, size, got, got_size);

		Format(line, sizeof(line), "%s: delivered to %s, %s", desc, to_name,
			routed ? (v4 ? "ttl 64 > 63, header checksum anew, the rest as it was" : "hop limit 64 > 63, the rest as it was") : "changed otherwise than a router changes it");
		ok = (expect == L3ROUTE_ROUTED && routed);
	}
	else if (other_size != 0)
	{
		Format(line, sizeof(line), "%s: delivered to %s", desc, other_name);
	}
	else
	{
		Format(line, sizeof(line), "%s: delivered nowhere", desc);
		ok = (expect == L3ROUTE_NOWHERE);
	}

	L3Line(text, line);
	Format(what, sizeof(what), "%s, as expected", line);
	L3Check(ctx, ok, what, "%s", expect == L3ROUTE_ROUTED ? "it did not arrive as a router forwards it" : (expect == L3ROUTE_NOWHERE ? "it arrived" : "the port took it"));

	return ok;
}

// The forwarded datagrams that the IP stack of the family counts, 0 when it cannot say
static UINT64 L3Forwarded(ULONG family)
{
	MIB_IPSTATS st;

	Zero(&st, sizeof(st));
	if (GetIpStatisticsEx(&st, family) != NO_ERROR)
	{
		return 0;
	}

	return (UINT64)st.dwForwDatagrams;
}

// The routing between lab-a and lab-b, as the golden file l3route_routing.txt has it, and the forwarding of the kernel
static void L3Routing(L3ROUTE_CTX *ctx, BUF *text, NODE_ROUTED *a, NODE_ROUTED *b, L3ROUTE_MEMBER *ma, L3ROUTE_MEMBER *mb)
{
	UCHAR packet[L3ROUTE_MAX_PACKET];
	L3ROUTE_MATCH m;
	NODE_ROUTED_STATUS sa;
	NODE_ROUTED_STATUS sb;
	UINT across4 = 0;
	UINT across6 = 0;

	L3Line(text, "# lab-a (198.18.81.0/24, fd81:a::/64) and lab-b (198.18.82.0/24, fd81:b::/64): routed networks of the server role, each on a KM-TEST adapter of its own");

	UINT64 forwarded4 = L3Forwarded(AF_INET);
	UINT64 forwarded6 = L3Forwarded(AF_INET6);

	// UDP of IPv4 from lab-a to lab-b
	Zero(&m, sizeof(m));
	m.Version = 4;
	m.Protocol = 17;
	m.AddressSize = 4;
	Copy(m.Src, l3route_a4, 4);
	Copy(m.Dst, l3route_b4, 4);
	m.SrcPort = 40001;
	m.DstPort = 40002;
	UINT size = L3Udp4(packet, l3route_a4, 40001, l3route_b4, 40002, 0x5201, L3ROUTE_DATA);
	if (L3Case(ctx, text, "lab-a > lab-b ipv4 udp 198.18.81.10:40001 > 198.18.82.10:40002", L3ROUTE_ROUTED, a, "lab-b", mb, "lab-a", ma, packet, size, &m))
	{
		across4++;
	}

	// ... and back
	Zero(&m, sizeof(m));
	m.Version = 4;
	m.Protocol = 17;
	m.AddressSize = 4;
	Copy(m.Src, l3route_b4, 4);
	Copy(m.Dst, l3route_a4, 4);
	m.SrcPort = 40002;
	m.DstPort = 40001;
	size = L3Udp4(packet, l3route_b4, 40002, l3route_a4, 40001, 0x5202, L3ROUTE_DATA);
	if (L3Case(ctx, text, "lab-b > lab-a ipv4 udp 198.18.82.10:40002 > 198.18.81.10:40001", L3ROUTE_ROUTED, b, "lab-a", ma, "lab-b", mb, packet, size, &m))
	{
		across4++;
	}

	// An echo request of IPv4 from lab-a to lab-b
	Zero(&m, sizeof(m));
	m.Version = 4;
	m.Protocol = 1;
	m.AddressSize = 4;
	Copy(m.Src, l3route_a4, 4);
	Copy(m.Dst, l3route_b4, 4);
	size = L3Echo4(packet, l3route_a4, l3route_b4, 0x5203, 1, L3ROUTE_DATA);
	if (L3Case(ctx, text, "lab-a > lab-b ipv4 icmp echo request 198.18.81.10 > 198.18.82.10", L3ROUTE_ROUTED, a, "lab-b", mb, "lab-a", ma, packet, size, &m))
	{
		across4++;
	}

	// UDP of IPv6 from lab-a to lab-b
	Zero(&m, sizeof(m));
	m.Version = 6;
	m.Protocol = 17;
	m.AddressSize = 16;
	Copy(m.Src, l3route_a6, 16);
	Copy(m.Dst, l3route_b6, 16);
	m.SrcPort = 40003;
	m.DstPort = 40004;
	size = L3Udp6(packet, l3route_a6, 40003, l3route_b6, 40004, L3ROUTE_DATA);
	if (L3Case(ctx, text, "lab-a > lab-b ipv6 udp [fd81:a::10]:40003 > [fd81:b::10]:40004", L3ROUTE_ROUTED, a, "lab-b", mb, "lab-a", ma, packet, size, &m))
	{
		across6++;
	}

	// A member of lab-a that sends from an address of lab-b: the port of lab-a refuses it
	Zero(&m, sizeof(m));
	m.Version = 4;
	m.Protocol = 17;
	m.AddressSize = 4;
	Copy(m.Dst, l3route_b4_other, 4);
	m.DstPort = 40006;
	size = L3Udp4(packet, l3route_b4, 40005, l3route_b4_other, 40006, 0x5204, L3ROUTE_DATA);
	L3Case(ctx, text, "lab-a ipv4 udp from an address of lab-b 198.18.82.10:40005 > 198.18.82.11:40006", L3ROUTE_REFUSED, a, "lab-b", mb, "lab-a", ma, packet, size, &m);

	// The forwarding of the kernel off on the IPv4 interface of lab-a: the packet arrives nowhere; on again, it arrives
	bool off = NodeRoutedSetForwarding(a, false);
	NodeRoutedGetStatus(a, &sa);
	L3Check(ctx, off && sa.Forwarding4 == false, "the forwarding of the interfaces of lab-a off, as GetIpInterfaceEntry reads it back", "set %u, IPv4 %u", (UINT)off, (UINT)sa.Forwarding4);
	Zero(&m, sizeof(m));
	m.Version = 4;
	m.Protocol = 17;
	m.AddressSize = 4;
	Copy(m.Src, l3route_a4, 4);
	Copy(m.Dst, l3route_b4, 4);
	m.SrcPort = 40007;
	m.DstPort = 40008;
	size = L3Udp4(packet, l3route_a4, 40007, l3route_b4, 40008, 0x5205, L3ROUTE_DATA);
	L3Case(ctx, text, "forwarding of lab-a off: lab-a > lab-b ipv4 udp 198.18.81.10:40007 > 198.18.82.10:40008", L3ROUTE_NOWHERE, a, "lab-b", mb, "lab-a", ma, packet, size, &m);

	bool on = NodeRoutedSetForwarding(a, true);
	NodeRoutedGetStatus(a, &sa);
	L3Check(ctx, on && sa.Forwarding4 && sa.Forwarding6, "the forwarding of the interfaces of lab-a on again, as GetIpInterfaceEntry reads it back", "set %u, IPv4 %u, IPv6 %u", (UINT)on, (UINT)sa.Forwarding4, (UINT)sa.Forwarding6);
	m.SrcPort = 40009;
	m.DstPort = 40010;
	size = L3Udp4(packet, l3route_a4, 40009, l3route_b4, 40010, 0x5206, L3ROUTE_DATA);
	if (L3Case(ctx, text, "forwarding of lab-a on again: lab-a > lab-b ipv4 udp 198.18.81.10:40009 > 198.18.82.10:40010", L3ROUTE_ROUTED, a, "lab-b", mb, "lab-a", ma, packet, size, &m))
	{
		across4++;
	}

	// The kernel counted what went across as forwarded datagrams
	UINT64 more4 = L3Forwarded(AF_INET) - forwarded4;
	UINT64 more6 = L3Forwarded(AF_INET6) - forwarded6;
	Print("  the IPv4 stack of the host counted %I64u forwarded datagrams meanwhile, the IPv6 stack %I64u\n", more4, more6);
	L3Check(ctx, across4 == 4 && across6 == 1 && more4 >= across4 && more6 >= across6, "the kernel forwarded what went across: the forwarded datagrams that the IPv4 and IPv6 stacks of the host count grew by that at least",
		"%u IPv4 and %u IPv6 packets across, the stacks counted %I64u and %I64u", across4, across6, more4, more6);

	// The node handed each packet only to the network that it went into and out of: the ports took what their members sent,
	// lab-a refused the one from an address of lab-b, and handed their members what the kernel routed to them
	NodeRoutedGetStatus(a, &sa);
	NodeRoutedGetStatus(b, &sb);
	Print("  lab-a: from its members %I64u, to its members %I64u, answers %I64u, refused %I64u, ignored %I64u; lab-b: from its members %I64u, to its members %I64u, answers %I64u, refused %I64u, ignored %I64u\n",
		sa.FromMembers, sa.ToMembers, sa.Answers, sa.Refused, sa.Ignored, sb.FromMembers, sb.ToMembers, sb.Answers, sb.Refused, sb.Ignored);
	L3Check(ctx, sa.FromMembers == 5 && sa.Refused == 1 && sb.FromMembers == 1 && sb.Refused == 0 && sa.ToMembers >= 1 && sb.ToMembers >= 4 && sa.Answers >= 1 && sb.Answers >= 1,
		"the ports took from their members only what they sent and handed them what the kernel routed to them, after their answers to the neighbour discovery of the host",
		"lab-a %I64u in, %I64u out, %I64u refused, %I64u answers; lab-b %I64u in, %I64u out, %I64u refused, %I64u answers", sa.FromMembers, sa.ToMembers, sa.Refused, sa.Answers, sb.FromMembers, sb.ToMembers, sb.Refused, sb.Answers);
}

//
// The uplink and the NAT
//

// Set the IPv4 interface of the uplink up without duplicate address detection, give it its address and the neighbour behind
// it, and route the network behind it there; false, with the step that failed in error, when one does not succeed
static bool L3UplinkSetUp(L3ROUTE_UPLINK *u, char *error, UINT error_size)
{
	MIB_IPINTERFACE_ROW ifr;
	MIB_UNICASTIPADDRESS_ROW row;
	MIB_IPNET_ROW2 nb;
	MIB_IPFORWARD_ROW2 route;

	InitializeIpInterfaceEntry(&ifr);
	ifr.Family = AF_INET;
	ifr.InterfaceLuid.Value = u->Luid;
	DWORD err = GetIpInterfaceEntry(&ifr);
	if (err == NO_ERROR)
	{
		ifr.DadTransmits = 0;
		ifr.SitePrefixLength = 0;
		err = SetIpInterfaceEntry(&ifr);
	}
	if (err != NO_ERROR)
	{
		Format(error, error_size, "SetIpInterfaceEntry: error %u", (UINT)err);
		return false;
	}

	InitializeUnicastIpAddressEntry(&row);
	row.InterfaceLuid.Value = u->Luid;
	row.Address.Ipv4.sin_family = AF_INET;
	Copy(&row.Address.Ipv4.sin_addr, l3route_uplink4, 4);
	row.OnLinkPrefixLength = L3ROUTE_LENGTH;
	row.DadState = IpDadStatePreferred;
	err = CreateUnicastIpAddressEntry(&row);
	if (err != NO_ERROR && err != ERROR_OBJECT_ALREADY_EXISTS)
	{
		Format(error, error_size, "CreateUnicastIpAddressEntry: error %u", (UINT)err);
		return false;
	}
	u->Address = true;

	Zero(&nb, sizeof(nb));
	nb.InterfaceLuid.Value = u->Luid;
	nb.Address.Ipv4.sin_family = AF_INET;
	Copy(&nb.Address.Ipv4.sin_addr, l3route_neighbour4, 4);
	Copy(nb.PhysicalAddress, l3route_neighbour_mac, 6);
	nb.PhysicalAddressLength = 6;
	nb.State = NlnsPermanent;
	err = CreateIpNetEntry2(&nb);
	if (err != NO_ERROR && err != ERROR_OBJECT_ALREADY_EXISTS)
	{
		Format(error, error_size, "CreateIpNetEntry2: error %u", (UINT)err);
		return false;
	}
	u->Neighbour = true;

	InitializeIpForwardEntry(&route);
	route.InterfaceLuid.Value = u->Luid;
	route.DestinationPrefix.Prefix.Ipv4.sin_family = AF_INET;
	Copy(&route.DestinationPrefix.Prefix.Ipv4.sin_addr, l3route_outside_net, 4);
	route.DestinationPrefix.PrefixLength = L3ROUTE_LENGTH;
	route.NextHop.Ipv4.sin_family = AF_INET;
	Copy(&route.NextHop.Ipv4.sin_addr, l3route_neighbour4, 4);
	route.Metric = 0;
	route.Protocol = MIB_IPPROTO_NETMGMT;
	err = CreateIpForwardEntry2(&route);
	if (err != NO_ERROR && err != ERROR_OBJECT_ALREADY_EXISTS)
	{
		Format(error, error_size, "CreateIpForwardEntry2: error %u", (UINT)err);
		return false;
	}
	u->Route = true;

	for (UINT64 end = GetTickCount64() + L3ROUTE_BOUND;GetTickCount64() < end;SleepThread(100))
	{
		MIB_UNICASTIPADDRESS_ROW r;

		InitializeUnicastIpAddressEntry(&r);
		r.InterfaceLuid.Value = u->Luid;
		r.Address.Ipv4.sin_family = AF_INET;
		Copy(&r.Address.Ipv4.sin_addr, l3route_uplink4, 4);
		if (GetUnicastIpAddressEntry(&r) == NO_ERROR && r.DadState == IpDadStatePreferred)
		{
			return true;
		}
	}

	Format(error, error_size, "the address of the uplink did not become preferred within %u ms", (UINT)L3ROUTE_BOUND);
	return false;
}

// Take the route, the neighbour and the address of the uplink away again
static void L3UplinkTearDown(L3ROUTE_UPLINK *u)
{
	if (u->Route)
	{
		MIB_IPFORWARD_ROW2 route;

		InitializeIpForwardEntry(&route);
		route.InterfaceLuid.Value = u->Luid;
		route.DestinationPrefix.Prefix.Ipv4.sin_family = AF_INET;
		Copy(&route.DestinationPrefix.Prefix.Ipv4.sin_addr, l3route_outside_net, 4);
		route.DestinationPrefix.PrefixLength = L3ROUTE_LENGTH;
		route.NextHop.Ipv4.sin_family = AF_INET;
		Copy(&route.NextHop.Ipv4.sin_addr, l3route_neighbour4, 4);
		DeleteIpForwardEntry2(&route);
	}

	if (u->Neighbour)
	{
		MIB_IPNET_ROW2 nb;

		Zero(&nb, sizeof(nb));
		nb.InterfaceLuid.Value = u->Luid;
		nb.Address.Ipv4.sin_family = AF_INET;
		Copy(&nb.Address.Ipv4.sin_addr, l3route_neighbour4, 4);
		DeleteIpNetEntry2(&nb);
	}

	if (u->Address)
	{
		MIB_UNICASTIPADDRESS_ROW row;

		InitializeUnicastIpAddressEntry(&row);
		row.InterfaceLuid.Value = u->Luid;
		row.Address.Ipv4.sin_family = AF_INET;
		Copy(&row.Address.Ipv4.sin_addr, l3route_uplink4, 4);
		DeleteUnicastIpAddressEntry(&row);
	}
}

// Bring the uplink up: a KM-TEST adapter of the test, its L2 adapter on the backend of the host, whose captures go to the
// neighbour behind it, and its address, neighbour and route
static bool L3UplinkNew(L3ROUTE_CTX *ctx, L3ROUTE_UPLINK *u, NODE *n)
{
	UCHAR key[PEER_KEY_SIZE];
	NET_LUID luid;
	NODE_L2_CONFIG cfg;
	char error[MAX_SIZE];

	memset(key, 0x83, sizeof(key));
	NodeL2Mac(u->Mac, key, L3ROUTE_UPLINK);
	u->KmTest = NodeKmTestNew(n, u->Mac);
	u->IfIndex = NodeKmTestIndex(u->KmTest);
	if (L3Check(ctx, u->KmTest != NULL && ConvertInterfaceIndexToLuid(u->IfIndex, &luid) == NO_ERROR, "the uplink, a KM-TEST adapter of the test, comes up", "interface %u", u->IfIndex) == false)
	{
		return false;
	}
	u->Luid = luid.Value;

	StrCpy(error, sizeof(error), "");
	if (L3Check(ctx, L3UplinkSetUp(u, error, sizeof(error)), "the uplink takes 198.18.83.1/24, the neighbour 198.18.83.2 and the route to 198.18.201.0/24 through it", "%s", error) == false)
	{
		return false;
	}

	Zero(&cfg, sizeof(cfg));
	cfg.IfIndex = u->IfIndex;
	cfg.Proc = L3UplinkProc;
	cfg.Param = u->Taken;
	cfg.Reset = NodeKmTestReset;
	cfg.ResetParam = u->KmTest;
	u->L2 = NodeL2New(n, &cfg);

	return L3Check(ctx, u->L2 != NULL, "the uplink: its L2 adapter carries what the host sends to the neighbour behind it", "no backend bound");
}

// Take the uplink down and its KM-TEST adapter off the machine
static void L3UplinkFree(L3ROUTE_UPLINK *u)
{
	NodeL2Free(u->L2);
	u->L2 = NULL;
	if (u->KmTest != NULL)
	{
		L3UplinkTearDown(u);
	}
	NodeKmTestFree(u->KmTest, true);
	u->KmTest = NULL;
}

// One UDP datagram of a member of from to the address behind the uplink: the source with which it leaves by the uplink
// goes into the line of the case, and with answer, the answer that the test puts back into the uplink, from the address
// behind it to that source, and how it reaches the member of from
static void L3NatCase(L3ROUTE_CTX *ctx, BUF *text, char *desc, NODE_ROUTED *from, L3ROUTE_MEMBER *from_member, L3ROUTE_UPLINK *u,
	const UCHAR *src, USHORT sport, bool translated, bool answer)
{
	UCHAR packet[L3ROUTE_MAX_PACKET];
	UCHAR got[L3ROUTE_MAX_PACKET];
	UCHAR frame[NODE_L2_MAX_FRAME];
	L3ROUTE_MATCH m;
	char line[MAX_SIZE * 2];
	char what[MAX_SIZE * 2];
	char addr[64];

	Zero(&m, sizeof(m));
	m.Version = 4;
	m.Protocol = 17;
	m.AddressSize = 4;
	Copy(m.Dst, l3route_outside4, 4);
	m.SrcPort = 0;
	m.DstPort = L3ROUTE_ECHO_PORT;

	UINT mark = L3Mark(u->Taken);
	UINT size = L3Udp4(packet, src, sport, l3route_outside4, L3ROUTE_ECHO_PORT, (USHORT)(0x5300 + sport % 256), L3ROUTE_DATA);
	bool sent = NodeRoutedSend(from, packet, size);
	UINT got_size = (sent ? L3Wait(u->Taken, mark, &m, got, L3ROUTE_BOUND) : 0);

	if (got_size == 0)
	{
		Format(line, sizeof(line), "%s: leaves nowhere", desc);
		L3Line(text, line);
		L3Check(ctx, false, line, "%s", sent ? "nothing left by the uplink" : "the port refused it");
		return;
	}

	UCHAR out_src[4];
	UINT header = (UINT)(got[0] & 0x0F) * 4;
	USHORT out_port = READ_USHORT(got + header);
	Copy(out_src, got + 12, 4);
	L3Ip4Str(addr, sizeof(addr), out_src);
	bool via_uplink = (Cmp(out_src, l3route_uplink4, 4) == 0);
	Format(line, sizeof(line), "%s: leaves by the uplink from %s, %s", desc, addr, via_uplink ? "the address of the uplink, translated by WinNAT" : "not translated");
	L3Line(text, line);
	Format(what, sizeof(what), "%s, as expected", line);
	L3Check(ctx, via_uplink == translated && (translated || out_port == sport), what, "from port %u", (UINT)out_port);

	if (answer == false)
	{
		return;
	}

	// The answer of the address behind the uplink to the source and port that it saw, into the uplink from the neighbour
	UINT mark_member = L3Mark(from_member);
	UINT answer_size = L3Udp4(packet, l3route_outside4, L3ROUTE_ECHO_PORT, out_src, out_port, 0x5400, L3ROUTE_ANSWER);
	Zero(frame, sizeof(frame));
	Copy(frame, u->Mac, 6);
	Copy(frame + 6, l3route_neighbour_mac, 6);
	frame[12] = 0x08;
	frame[13] = 0x00;
	Copy(frame + 14, packet, answer_size);
	bool put = NodeL2Send(u->L2, frame, MAX(14 + answer_size, 60));

	Zero(&m, sizeof(m));
	m.Version = 4;
	m.Protocol = 17;
	m.AddressSize = 4;
	Copy(m.Src, l3route_outside4, 4);
	Copy(m.Dst, src, 4);
	m.SrcPort = L3ROUTE_ECHO_PORT;
	m.DstPort = sport;
	got_size = (put ? L3Wait(from_member, mark_member, &m, got, L3ROUTE_BOUND) : 0);

	L3Ip4Str(addr, sizeof(addr), src);
	if (got_size != 0)
	{
		Format(line, sizeof(line), "the answer of 198.18.201.10:7 to the uplink: delivered to the member %s:%u, translated back by WinNAT", addr, (UINT)sport);
	}
	else
	{
		Format(line, sizeof(line), "the answer of 198.18.201.10:7 to the uplink: delivered nowhere");
	}
	L3Line(text, line);
	Format(what, sizeof(what), "%s, as expected", line);
	L3Check(ctx, got_size != 0, what, "%s", put ? "the member did not get it" : "the uplink did not take it");
}

// The NAT to the internet, as the golden file l3route_nat.txt has it
static void L3Nat(L3ROUTE_CTX *ctx, BUF *text, NODE *n, NODE_ROUTED *a, NODE_ROUTED *b, L3ROUTE_MEMBER *ma, L3ROUTE_MEMBER *mb)
{
	L3ROUTE_UPLINK u;
	wchar_t prefix[MAX_SIZE];
	char prefix_a[MAX_SIZE];
	char line[MAX_SIZE * 2];

	L3Line(text, "# the uplink (198.18.83.1/24, with a route to 198.18.201.0/24 through the neighbour 198.18.83.2) stands in for the internet; lab-a asks for NAT, lab-b does not");

	bool found = NodeEgressNetNatPrefix(NODE_EGRESS_NETNAT_NAME, prefix, sizeof(prefix));
	UniToStr(prefix_a, sizeof(prefix_a), prefix);
	Format(line, sizeof(line), "the NAT network of WinNAT of the node, RanzVPN-Egress: %s", found ? prefix_a : "none");
	L3Line(text, line);
	L3Check(ctx, found && StrCmp(prefix_a, "198.18.81.0/24") == 0, "the NAT network of WinNAT of the node, RanzVPN-Egress, is over 198.18.81.0/24, the prefix of lab-a", "%s", found ? prefix_a : "none");

	Zero(&u, sizeof(u));
	u.Taken = ZeroMalloc(sizeof(L3ROUTE_MEMBER));
	InitializeSRWLock(&u.Taken->Lock);

	if (L3UplinkNew(ctx, &u, n))
	{
		L3NatCase(ctx, text, "lab-a > outside ipv4 udp 198.18.81.10:40011 > 198.18.201.10:7", a, ma, &u, l3route_a4, 40011, true, true);
		L3NatCase(ctx, text, "lab-b > outside ipv4 udp 198.18.82.10:40012 > 198.18.201.10:7", b, mb, &u, l3route_b4, 40012, false, false);
	}

	L3UplinkFree(&u);
	Free(u.Taken);
}

//
// The node
//

// A new data directory under the temp directory of the process, with a configuration store: the server role, one worker, the
// identity key of the test, the Networks and the Routed setting
static void L3NewDir(wchar_t *dir, UINT size)
{
	wchar_t tmp[MAX_PATH];
	wchar_t path[MAX_PATH];

	UniFormat(tmp, sizeof(tmp), L"l3routetest_%u", Rand32());
	ConbinePathW(dir, size, MsGetMyTempDirW(), tmp);
	MakeDirExW(dir);

	ConbinePathW(path, sizeof(path), dir, CS_FILE_NAME);
	CONFIG_STORE *s = CsOpen(path);
	if (s != NULL)
	{
		CsSetSetting(s, NODE_SETTING_ROLES, "server");
		CsSetSetting(s, NODE_SETTING_WORKERS, "1");
		CsSetSetting(s, NODE_SETTING_IDENTITY_KEY, L3ROUTE_KEY);
		CsSetSetting(s, NODE_SETTING_ROUTED, l3route_setting);
		CsAddNetwork(s, "lan", CS_MODE_L2, true);
		CsAddNetwork(s, "lab-a", CS_MODE_L3, true);
		CsAddNetwork(s, "lab-b", CS_MODE_L3, true);
		CsAddNetwork(s, "lab-c", CS_MODE_L3, false);
		CsAddNetwork(s, "lab-d", CS_MODE_L3, true);
		CsClose(s);
	}
}

// The lines of the node log about the routed networks, then the files of a data directory and the directory
static void L3DeleteDir(wchar_t *dir)
{
	wchar_t log_dir[MAX_PATH];

	ConbinePathW(log_dir, sizeof(log_dir), dir, NODE_LOG_DIR_NAME);
	for (UINT pass = 0;pass < 2;pass++)
	{
		wchar_t *d_name = (pass == 0 ? log_dir : dir);
		DIRLIST *d = EnumDirW(d_name);

		for (UINT i = 0;d != NULL && i < d->NumFiles;i++)
		{
			DIRENT *e = d->File[i];
			wchar_t path[MAX_PATH];

			if (e->Folder)
			{
				continue;
			}

			ConbinePathW(path, sizeof(path), d_name, e->FileNameW);
			if (pass == 0)
			{
				BUF *b = ReadDumpW(path);
				if (b != NULL)
				{
					char *text = ZeroMalloc(b->Size + 1);
					Copy(text, b->Buf, b->Size);
					TOKEN_LIST *t = ParseToken(text, "\r\n");
					for (UINT j = 0;j < t->NumTokens;j++)
					{
						if (InStr(t->Token[j], "Routed") || InStr(t->Token[j], "Network lab") || InStr(t->Token[j], "KM-TEST") || InStr(t->Token[j], "L2 adapter"))
						{
							Print("  [LOG] %s\n", t->Token[j]);
						}
					}
					FreeToken(t);
					Free(text);
					FreeBuf(b);
				}
			}
			FileDeleteW(path);
		}

		FreeDir(d);
		DeleteDirW(d_name);
	}
}

// Whether the interface of the routed network of the status st holds the address of size bytes, preferred
static bool L3HasAddress(const NODE_ROUTED_STATUS *st, const UCHAR *addr, UINT size)
{
	MIB_UNICASTIPADDRESS_ROW row;
	NET_LUID luid;

	if (ConvertInterfaceIndexToLuid(st->IfIndex, &luid) != NO_ERROR)
	{
		return false;
	}

	InitializeUnicastIpAddressEntry(&row);
	row.InterfaceLuid = luid;
	if (size == 4)
	{
		row.Address.Ipv4.sin_family = AF_INET;
		Copy(&row.Address.Ipv4.sin_addr, addr, 4);
	}
	else
	{
		row.Address.Ipv6.sin6_family = AF_INET6;
		Copy(&row.Address.Ipv6.sin6_addr, addr, 16);
	}

	return (GetUnicastIpAddressEntry(&row) == NO_ERROR && row.DadState == IpDadStatePreferred);
}

// The server role brought lab-a and lab-b up on KM-TEST adapters with the backend expect, their interfaces forward and hold
// their gateway addresses, and lab-c and lab-d stay down
static bool L3RoleUp(L3ROUTE_CTX *ctx, NODE *n, NODE_ROUTED *a, NODE_ROUTED *b, char *expect, NODE_ROUTED_STATUS *sa, NODE_ROUTED_STATUS *sb)
{
	NODE_STATUS ns;
	MIB_IF_ROW2 row;

	NodeGetStatus(n, &ns);
	NodeRoutedGetStatus(a, sa);
	NodeRoutedGetStatus(b, sb);

	if (L3Check(ctx, (ns.Roles & NODE_ROLE_SERVER) != 0 && a != NULL && b != NULL, "the server role runs with the routed networks lab-a and lab-b", "roles %u, lab-a %s, lab-b %s",
		ns.Roles, a != NULL ? "up" : "down", b != NULL ? "up" : "down") == false)
	{
		return false;
	}

	L3Check(ctx, NodeRoutedFind(n, "lab-c") == NULL && NodeRoutedFind(n, "lab-d") == NULL, "lab-c, which is offline, and lab-d, which the Routed setting does not name, stay down", "one is up");

	for (UINT i = 0;i < 2;i++)
	{
		NODE_ROUTED_STATUS *st = (i == 0 ? sa : sb);
		char what[MAX_SIZE];

		Zero(&row, sizeof(row));
		row.InterfaceIndex = st->IfIndex;
		bool mac = (st->IfIndex != 0 && GetIfEntry2(&row) == NO_ERROR && row.PhysicalAddressLength == 6 && Cmp(row.PhysicalAddress, st->Mac, 6) == 0);
		Format(what, sizeof(what), "%s: a KM-TEST adapter of its own with the MAC address of the node and the Network, and its port on the %s backend", i == 0 ? "lab-a" : "lab-b", expect);
		L3Check(ctx, mac && StrCmpi(st->Backend, expect) == 0 && (i == 0 || st->IfIndex != sa->IfIndex), what, "interface %u, backend '%s'", st->IfIndex, st->Backend);

		Format(what, sizeof(what), "%s: its IPv4 and IPv6 interfaces forward, as GetIpInterfaceEntry reads them back", i == 0 ? "lab-a" : "lab-b");
		L3Check(ctx, st->Forwarding4 && st->Forwarding6, what, "IPv4 %u, IPv6 %u", (UINT)st->Forwarding4, (UINT)st->Forwarding6);

		Format(what, sizeof(what), "%s: its interface holds its gateway addresses %s, preferred", i == 0 ? "lab-a" : "lab-b", i == 0 ? "198.18.81.1/24 and fd81:a::1/64" : "198.18.82.1/24 and fd81:b::1/64");
		L3Check(ctx, L3HasAddress(st, i == 0 ? l3route_gw_a4 : l3route_gw_b4, 4) && L3HasAddress(st, i == 0 ? l3route_gw_a6 : l3route_gw_b6, 16), what, "one is not there");
	}

	return (ctx->NumFailed == 0);
}

// Take the KM-TEST adapter of a routed network off the machine, found by its MAC address
static void L3RemoveAdapter(NODE *n, const UCHAR *mac)
{
	NODE_KMTEST *k = NodeKmTestNew(n, mac);

	NodeKmTestFree(k, true);
}

// l3route: the routed networks of the server role on KM-TEST adapters, the routing between them in the kernel and their NAT
RANZ_TEST("l3route", l3route_test, "L3 routed networks: the routed networks of the server role on real KM-TEST Loopback Adapters (argument: xdp or selow, the backend the host gives): routing between them through the Windows IP stack (golden family l3route), the forwarding of the kernel, and their NAT to an uplink through WinNAT (administrator rights, the drivers of ranz install).");
void l3route_test(UINT num, char **arg)
{
	L3ROUTE_CTX ctx;
	HARNESS h;
	wchar_t dir[MAX_PATH];
	char out_dir[MAX_PATH];
	char golden_dir[MAX_PATH];
	bool update = false;
	char *expect = (num >= 1 ? arg[0] : "xdp");
	NODE_ROUTED_STATUS sa;
	NODE_ROUTED_STATUS sb;
	wchar_t prefix[MAX_SIZE];

	HANDLE done = CreateEventW(NULL, TRUE, FALSE, NULL);
	HANDLE watchdog = (done != NULL ? CreateThread(NULL, 0, L3Watchdog, done, 0, NULL) : NULL);

	Zero(&ctx, sizeof(ctx));
	Zero(&h, sizeof(h));
	Zero(&sa, sizeof(sa));
	Zero(&sb, sizeof(sb));

	Print("L3 routed network test: the routed networks of the server role on KM-TEST adapters with the %s backend, the routing of the kernel between them and their NAT\n", expect);

	L3NewDir(dir, sizeof(dir));
	NODE *n = NewNode(dir);
	bool started = (n != NULL && NodeStart(n));

	if (L3Check(&ctx, started, "a node with the server role runs", "NewNode or NodeStart failed"))
	{
		NODE_ROUTED *a = NodeRoutedFind(n, "lab-a");
		NODE_ROUTED *b = NodeRoutedFind(n, "lab-b");

		if (L3RoleUp(&ctx, n, a, b, expect, &sa, &sb))
		{
			L3ROUTE_MEMBER *ma = ZeroMalloc(sizeof(L3ROUTE_MEMBER));
			L3ROUTE_MEMBER *mb = ZeroMalloc(sizeof(L3ROUTE_MEMBER));
			BUF *routing = NewBuf();
			BUF *nat = NewBuf();

			InitializeSRWLock(&ma->Lock);
			InitializeSRWLock(&mb->Lock);
			NodeRoutedSetProc(a, L3MemberProc, ma);
			NodeRoutedSetProc(b, L3MemberProc, mb);

			L3Routing(&ctx, routing, a, b, ma, mb);
			L3Nat(&ctx, nat, n, a, b, ma, mb);

			NodeRoutedSetProc(a, NULL, NULL);
			NodeRoutedSetProc(b, NULL, NULL);

			HarnessGetFamilyDirs("l3route", out_dir, sizeof(out_dir), golden_dir, sizeof(golden_dir), &update);
			MakeDirEx(out_dir);
			Print("L3ROUTE GOLDEN MODE %s\n", update ? "update" : "compare");
			Print("  golden directory: %s\n", golden_dir);

			char *text = HarnessBufToStr(routing);
			HarnessCompareGolden(&h, out_dir, golden_dir, L3ROUTE_GOLDEN, text, update);
			Free(text);
			text = HarnessBufToStr(nat);
			HarnessCompareGolden(&h, out_dir, golden_dir, L3ROUTE_GOLDEN_NAT, text, update);
			Free(text);
			L3Check(&ctx, h.NumFail == 0, "the routing and the NAT are as the golden files " L3ROUTE_GOLDEN " and " L3ROUTE_GOLDEN_NAT " say", "%u differ", h.NumFail);

			FreeBuf(routing);
			FreeBuf(nat);
			Free(ma);
			Free(mb);
		}
	}

	if (n != NULL)
	{
		NodeStop(n);

		// The role is down: the NAT network that its routed networks made and their gateway addresses are gone
		if (started && sa.IfIndex != 0)
		{
			bool netnat = NodeEgressNetNatPrefix(NODE_EGRESS_NETNAT_NAME, prefix, sizeof(prefix));
			L3Check(&ctx, netnat == false, "once the node stopped, the NAT network of WinNAT of the node is gone", "it is still there");
			L3Check(&ctx, L3HasAddress(&sa, l3route_gw_a4, 4) == false && L3HasAddress(&sb, l3route_gw_b4, 4) == false && L3HasAddress(&sa, l3route_gw_a6, 16) == false,
				"once the node stopped, the gateway addresses are gone from the interfaces of the routed networks", "one is still there");
		}

		// The KM-TEST adapters of the routed networks stay for the next start of the node: the test takes them off
		if (sa.IfIndex != 0)
		{
			L3RemoveAdapter(n, sa.Mac);
		}
		if (sb.IfIndex != 0)
		{
			L3RemoveAdapter(n, sb.Mac);
		}

		FreeNode(n);
	}
	L3DeleteDir(dir);
	PeerKeyDelete(L3ROUTE_KEY_W);

	if (watchdog != NULL)
	{
		SetEvent(done);
		WaitForSingleObject(watchdog, INFINITE);
		CloseHandle(watchdog);
	}
	if (done != NULL)
	{
		CloseHandle(done);
	}

	if (ctx.NumFailed == 0)
	{
		Print("L3ROUTE TEST OK\n");
	}
	else
	{
		Print("L3ROUTE TEST FAILED (%u of %u checks failed)\n", ctx.NumFailed, ctx.NumChecks);
	}
}
