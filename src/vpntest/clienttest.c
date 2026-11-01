// clienttest.c
// Named client role test of vpntest ("client" command, CORE-S3-1 #71)
//
// The client role of a node (Cedar/NodeClient.c) on a Wintun adapter (NodeWintun.c), against a server node of the new
// core that runs in the same process, its listeners on test ports of the loopback interface, over QUIC and over
// TLS-443. The host of the client is the runner itself: its own IP stack sends into the Wintun adapter, as an
// application of a laptop does. The host of the server is a fake adapter that answers ICMP echo requests, UDP datagrams
// and DNS queries. Both nodes take their states from the test (NodeOverlayApply): VRF 1, the client 100.64.0.2/10, the
// server 100.64.0.1/10 in Network default and 198.18.0.1/24 in Network lan.
// - Routes and DNS: the address of the client is on its adapter, Windows takes the adapter for both networks of the
//   server with that address as the source, and the adapter has the DNS server and the suffix of the Client setting.
// - Routing against the oracle: an ICMP echo, a datagram to each network of the server, a DNS query on the adapter and
//   a datagram to an address of no node leave the runner's stack. What each host gets is one report per path, which
//   must be the golden file client/client_routing.txt (golden family "client"): over QUIC; over TLS-443 when the QUIC
//   entry of the fallback list reaches nothing; and on the oracle, two nodes with fake hosts on the in-process loopback
//   transport, the path of SDN-3 and SDN-4, which send the same flows with the same states.
// - The logged-in user: a local user who is no administrator, logged on interactively, takes the role down and up
//   through its pipe; the same user logged on over the network cannot open the pipe.
// - Sleep and roaming: the runner cannot sleep, so the test drives the suspend and resume events; a real address change
//   on another Wintun adapter is the roaming. Before each, the server's side of the session goes silent, as a sleep or
//   a new path leaves it: the client dials again, the server replaces the session, and the echo comes back.
// - Clean-up: once the client role stops, its adapter is gone.
// Print "CLIENT TEST OK" only when every check passes. Needs administrator rights and wintun.dll next to vpntest
// (.github/scripts/fetch-wintun.ps1).

#include "golden.h"
#include "testlist.h"

#include "Cedar/ConfigStore.h"
#include "Cedar/Node.h"

#include "Mayaqua/Encrypt.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/IpAddr.h"
#include "Mayaqua/Kernel.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Network.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/TcpIp.h"
#include "Mayaqua/Tick64.h"

#include "Core/Control.h"
#include "Core/Transport.h"

#include <WinDNS.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <lmcons.h>
#include <lmaccess.h>
#include <lmerr.h>
#include <sddl.h>
#include <AclAPI.h>
#include <WS2tcpip.h>

#include <stdio.h>

#define	CLIENTTEST_BUDGET		420000		// The whole test ends within this time, or the watchdog ends the process (ms)
#define	CLIENTTEST_BOUND		20000		// A bounded wait on observable state (ms)
#define	CLIENTTEST_POLL			20			// Poll interval of observable state (ms)
#define	CLIENTTEST_REPLY		3000		// An echo, a datagram or a DNS answer comes back within this (ms)
#define	CLIENTTEST_SILENCE		700			// ... and what must reach no host does not, within this (ms)
#define	CLIENTTEST_ACCEPT		10			// ms between two looks of the server's listener at its QUIC and TLS listeners
#define	CLIENTTEST_VRF			1			// The VRF of the test
#define	CLIENTTEST_UDP_PORT		9821		// The UDP port of the hosts: the port of ranz test throughput
#define	CLIENTTEST_CLIENT_PORT	47801		// The client end of the datagrams
#define	CLIENTTEST_DNS_PORT		53
#define	CLIENTTEST_DNS_NAME		"probe.ranz.test"	// The name that the fake DNS server of node-s answers
#define	CLIENTTEST_DNS_NAME_W	L"probe.ranz.test"
#define	CLIENTTEST_SUFFIX		"ranz.test"			// The DNS suffix of the adapter
#define	CLIENTTEST_SUFFIX_W		L"ranz.test"
#define	CLIENTTEST_MAX_PACKET	1500
#define	CLIENTTEST_GOLDEN		"client_routing.txt"
#define	CLIENTTEST_CN			L"CN=localhost"
#define	CLIENTTEST_SAN			L"localhost"
#define	CLIENTTEST_NODE_C		"node-c"
#define	CLIENTTEST_NODE_S		"node-s"
#define	CLIENTTEST_ICMP_DATA	"ranz client icmp"
#define	CLIENTTEST_UDP_DATA_1	"ranz client udp 1"
#define	CLIENTTEST_UDP_DATA_2	"ranz client udp 2"
#define	CLIENTTEST_UDP_DATA_3	"ranz client udp 3"
#define	CLIENTTEST_HEADER		"# CORE-S3-1: what each host gets for the same routing in VRF 1: node-c 100.64.0.2/10; node-s 100.64.0.1/10 and 198.18.0.1/24"

// The addresses of the test, in network byte order
static UINT clienttest_c;			// 100.64.0.2: node-c in Network default
static UINT clienttest_s;			// 100.64.0.1: node-s in Network default
static UINT clienttest_lan;			// 198.18.0.1: node-s in Network lan
static UINT clienttest_nowhere;		// 100.64.0.9: no node
static UINT clienttest_roam;		// 198.51.100.7: the address that the roaming puts on another adapter

// The checks of the test
typedef struct CLIENTTEST_CTX
{
	UINT NumChecks;
	UINT NumFailed;
} CLIENTTEST_CTX;

// The report of one path: what each host got, one line each, in order
typedef struct CLIENTTEST_REPORT
{
	SRWLOCK Lock;
	BUF *Text;
	bool DnsSeen;						// node-s reported the DNS query of the probe: a repeated one is not reported again
} CLIENTTEST_REPORT;

// The fake host of a node. The host of node-s answers what reaches it and reports each test packet; the host of the
// oracle's node-c keeps the packet that reached it last.
typedef struct CLIENTTEST_HOST
{
	char *Name;							// The node of the host
	CLIENTTEST_REPORT *volatile Report;	// node-s: the report it writes to
	HANDLE Arrived;						// node-c: a packet reached the host (auto-reset)
	SRWLOCK Lock;						// node-c: Packet and Size
	UCHAR Packet[CLIENTTEST_MAX_PACKET];
	UINT Size;
	volatile LONG64 Other;				// Packets that are no test packet
} CLIENTTEST_HOST;

// One node of the test
typedef struct CLIENTTEST_NODE
{
	wchar_t Dir[MAX_PATH];				// Its data directory
	PEER_KEY Key;						// Its static key (node-s and the oracle)
	NODE *Node;
	NODE_READER Reader;					// The test thread as a reader of its forwarding tables (the oracle's node-c)
	bool Registered;					// ... registered
} CLIENTTEST_NODE;

// The listener of node-s on QUIC and TLS-443 at once: the data transport of its overlay, whose Listen takes the node's
// name and gives both listeners. Its streams can be frozen: they then read nothing and drop what they write, as the
// server sees the session of a client that went to sleep or moved to another path.
typedef struct CLIENTTEST_SERVER
{
	TRANSPORT Transport;				// The data transport of the server's overlay
	TRANSPORT *Quic;					// The QUIC server transport, NULL without msquic.dll
	TRANSPORT *Tls;						// The TLS server transport
	TRANSPORT_LISTENER *QuicListener;	// Their listeners on test ports of 127.0.0.1
	TRANSPORT_LISTENER *TlsListener;
	USHORT QuicPort;
	USHORT TlsPort;
	LOCK *Lock;							// Streams
	LIST *Streams;						// The streams that the overlay holds (CLIENTTEST_STREAM)
} CLIENTTEST_SERVER;

// A stream of the listener of node-s
typedef struct CLIENTTEST_STREAM
{
	CLIENTTEST_SERVER *Server;
	TRANSPORT_STREAM *Stream;			// The stream of QUIC or TLS-443
	volatile LONG Frozen;				// It reads nothing and drops what it writes
} CLIENTTEST_STREAM;

// The parts of an IPv4 packet that the test reads
typedef struct CLIENTTEST_PKT
{
	UINT Src;							// The addresses, in network byte order
	UINT Dst;
	UINT Protocol;						// IP_PROTO_ICMPV4 or IP_PROTO_UDP
	UINT IcmpType;						// ICMP: 8 echo request, 0 echo reply
	USHORT IcmpId;						// ... its identifier and sequence number
	USHORT IcmpSeq;
	USHORT SrcPort;						// UDP, in host order
	USHORT DstPort;
	const UCHAR *Data;					// The data after the ICMP header, or the UDP payload
	UINT DataSize;
} CLIENTTEST_PKT;

static bool ClientTestCheck(CLIENTTEST_CTX *ctx, bool ok, char *what, char *fmt, ...) RANZ_PRINTF_FORMAT(4, 5);
static bool ClientTestCheck(CLIENTTEST_CTX *ctx, bool ok, char *what, char *fmt, ...)
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

// The watchdog: a native thread that ends a run that hangs, so that a lost packet is a failed test instead of a hung
// CI step
static DWORD WINAPI ClientTestWatchdog(LPVOID param)
{
	char msg[MAX_SIZE];
	DWORD written = 0;

	if (WaitForSingleObject((HANDLE)param, CLIENTTEST_BUDGET) != WAIT_TIMEOUT)
	{
		return 0;
	}

	int len = snprintf(msg, sizeof(msg), "CLIENT TEST FAILED (did not finish within %u ms)\n", CLIENTTEST_BUDGET);
	if (len > 0)
	{
		WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), msg, (DWORD)MIN((UINT)len, (UINT)sizeof(msg) - 1), &written, NULL);
	}

	TerminateProcess(GetCurrentProcess(), 1);

	return 0;
}

//
// Packets
//

// An IPv4 address of four bytes, in network byte order
static UINT ClientTestAddr(UCHAR a, UCHAR b, UCHAR c, UCHAR d)
{
	UCHAR x[4];
	UINT ret = 0;

	x[0] = a;
	x[1] = b;
	x[2] = c;
	x[3] = d;
	Copy(&ret, x, 4);

	return ret;
}

// An IPv4 packet from src to dst of protocol, after it the l4 bytes with their checksum, TTL 64: its size
static UINT ClientTestIp(UCHAR *buf, UINT src, UINT dst, UCHAR protocol, const UCHAR *l4, UINT l4_size)
{
	UINT size = 20 + l4_size;
	USHORT sum;

	Zero(buf, 20);
	buf[0] = 0x45;
	buf[2] = (UCHAR)(size >> 8);
	buf[3] = (UCHAR)size;
	buf[8] = 64;
	buf[9] = protocol;
	Copy(buf + 12, &src, 4);
	Copy(buf + 16, &dst, 4);
	sum = IpChecksum(buf, 20);
	Copy(buf + 10, &sum, 2);
	Copy(buf + 20, l4, l4_size);

	return size;
}

// An ICMP echo request (type 8) or reply (type 0) with its identifier, sequence number and data: its size
static UINT ClientTestIcmp(UCHAR *buf, UINT src, UINT dst, UCHAR type, USHORT id, USHORT seq, const UCHAR *data, UINT data_size)
{
	UCHAR icmp[CLIENTTEST_MAX_PACKET];
	UINT icmp_size = 8 + data_size;
	USHORT sum;

	Zero(icmp, 8);
	icmp[0] = type;
	icmp[4] = (UCHAR)(id >> 8);
	icmp[5] = (UCHAR)id;
	icmp[6] = (UCHAR)(seq >> 8);
	icmp[7] = (UCHAR)seq;
	Copy(icmp + 8, data, data_size);
	sum = IpChecksum(icmp, icmp_size);
	Copy(icmp + 2, &sum, 2);

	return ClientTestIp(buf, src, dst, IP_PROTO_ICMPV4, icmp, icmp_size);
}

// A UDP datagram with its checksum over the pseudo-header of RFC 768: its size
static UINT ClientTestUdp(UCHAR *buf, UINT src, UINT dst, USHORT src_port, USHORT dst_port, const UCHAR *data, UINT data_size)
{
	UCHAR udp[CLIENTTEST_MAX_PACKET];
	UINT udp_size = 8 + data_size;

	udp[0] = (UCHAR)(src_port >> 8);
	udp[1] = (UCHAR)src_port;
	udp[2] = (UCHAR)(dst_port >> 8);
	udp[3] = (UCHAR)dst_port;
	udp[4] = (UCHAR)(udp_size >> 8);
	udp[5] = (UCHAR)udp_size;
	udp[6] = 0;
	udp[7] = 0;
	Copy(udp + 8, data, data_size);

	USHORT sum = CalcChecksumForIPv4(src, dst, IP_PROTO_UDP, udp, udp_size, 0);
	if (sum == 0)
	{
		sum = 0xFFFF;
	}
	Copy(udp + 6, &sum, 2);

	return ClientTestIp(buf, src, dst, IP_PROTO_UDP, udp, udp_size);
}

// Read an IPv4 packet that carries ICMP or UDP; false for anything else
static bool ClientTestParse(CLIENTTEST_PKT *p, const UCHAR *packet, UINT size)
{
	Zero(p, sizeof(CLIENTTEST_PKT));

	if (packet == NULL || size < 20 || (packet[0] >> 4) != 4)
	{
		return false;
	}

	UINT ihl = (packet[0] & 0x0F) * 4;
	UINT total = ((UINT)packet[2] << 8) | packet[3];
	if (ihl < 20 || total < ihl + 8 || total > size)
	{
		return false;
	}

	Copy(&p->Src, packet + 12, 4);
	Copy(&p->Dst, packet + 16, 4);
	p->Protocol = packet[9];

	const UCHAR *l4 = packet + ihl;
	UINT l4_size = total - ihl;

	if (p->Protocol == IP_PROTO_ICMPV4)
	{
		p->IcmpType = l4[0];
		p->IcmpId = (USHORT)(((UINT)l4[4] << 8) | l4[5]);
		p->IcmpSeq = (USHORT)(((UINT)l4[6] << 8) | l4[7]);
		p->Data = l4 + 8;
		p->DataSize = l4_size - 8;
		return true;
	}

	if (p->Protocol == IP_PROTO_UDP)
	{
		UINT udp_len = ((UINT)l4[4] << 8) | l4[5];

		if (udp_len < 8 || udp_len > l4_size)
		{
			return false;
		}

		p->SrcPort = (USHORT)(((UINT)l4[0] << 8) | l4[1]);
		p->DstPort = (USHORT)(((UINT)l4[2] << 8) | l4[3]);
		p->Data = l4 + 8;
		p->DataSize = udp_len - 8;
		return true;
	}

	return false;
}

// The data of a test packet as text: the printable characters as they are, any other byte as '?'
static void ClientTestText(char *dst, UINT size, const UCHAR *data, UINT data_size)
{
	UINT n = 0;

	for (UINT i = 0;i < data_size && n + 1 < size;i++)
	{
		UCHAR ch = data[i];

		dst[n++] = ((ch >= 0x20 && ch < 0x7F && ch != '"' && ch != '\\') ? (char)ch : '?');
	}

	dst[n] = 0;
}

// The name at *pos of a DNS message, without compression, in lower case with its dots; *pos after it. False when it is
// malformed or longer than size.
static bool ClientTestDnsReadName(const UCHAR *msg, UINT msg_size, UINT *pos, char *name, UINT size)
{
	UINT p = *pos;
	UINT used = 0;

	if (size == 0)
	{
		return false;
	}

	while (true)
	{
		if (p >= msg_size)
		{
			return false;
		}

		UINT len = msg[p++];
		if (len == 0)
		{
			break;
		}
		if (len > 63 || p + len > msg_size || used + len + 2 > size)
		{
			return false;
		}

		if (used != 0)
		{
			name[used++] = '.';
		}
		for (UINT i = 0;i < len;i++)
		{
			char ch = (char)msg[p + i];

			name[used++] = ((ch >= 'A' && ch <= 'Z') ? (char)(ch + 32) : ch);
		}
		p += len;
	}

	name[used] = 0;
	*pos = p;

	return true;
}

// The question of a DNS query (answer false), or of an answer of NOERROR with a record (answer true): its name, its type
// and *end, the offset after it; the class must be IN
static bool ClientTestDnsQuestion(const UCHAR *msg, UINT size, bool answer, char *name, UINT name_size, UINT *qtype, UINT *end)
{
	UINT pos = 12;

	if (msg == NULL || size < 12)
	{
		return false;
	}

	UINT flags = ((UINT)msg[2] << 8) | msg[3];
	UINT qd = ((UINT)msg[4] << 8) | msg[5];
	UINT an = ((UINT)msg[6] << 8) | msg[7];

	if (((flags & 0x8000) != 0) != answer || qd != 1 || (answer && ((flags & 0x000F) != 0 || an == 0)))
	{
		return false;
	}

	if (ClientTestDnsReadName(msg, size, &pos, name, name_size) == false || pos + 4 > size)
	{
		return false;
	}

	*qtype = ((UINT)msg[pos] << 8) | msg[pos + 1];
	if ((((UINT)msg[pos + 2] << 8) | msg[pos + 3]) != 1)
	{
		return false;
	}

	*end = pos + 4;

	return true;
}

// The address of the first record of a DNS answer, which follows its question at end, when it is an A record; 0 else
static UINT ClientTestDnsAddress(const UCHAR *msg, UINT size, UINT end)
{
	char name[MAX_SIZE];
	UINT pos = end;
	UINT ret = 0;

	if (pos + 2 > size)
	{
		return 0;
	}

	if ((msg[pos] & 0xC0) == 0xC0)
	{
		pos += 2;
	}
	else if (ClientTestDnsReadName(msg, size, &pos, name, sizeof(name)) == false)
	{
		return 0;
	}

	if (pos + 10 > size)
	{
		return 0;
	}

	UINT type = ((UINT)msg[pos] << 8) | msg[pos + 1];
	UINT rdlen = ((UINT)msg[pos + 8] << 8) | msg[pos + 9];
	pos += 10;
	if (type != 1 || rdlen != 4 || pos + 4 > size)
	{
		return 0;
	}

	Copy(&ret, msg + pos, 4);

	return ret;
}

// The answer of the fake DNS server to the query whose question ends at end: the header with the query's id and its
// question, then an A record of address for the name of the question, or NXDOMAIN when address is 0. Its size, 0 when
// it does not fit.
static UINT ClientTestDnsAnswer(UCHAR *msg, UINT max, const UCHAR *query, UINT end, UINT address)
{
	UINT size = end;
	UINT flags = 0x8000 | 0x0400 | 0x0080 | (((UINT)query[2] << 8) & 0x0100) | (address == 0 ? 3 : 0);

	if (end < 12 || end + 16 > max)
	{
		return 0;
	}

	Copy(msg, query, end);
	msg[2] = (UCHAR)(flags >> 8);
	msg[3] = (UCHAR)flags;
	msg[4] = 0;
	msg[5] = 1;
	msg[6] = 0;
	msg[7] = (address != 0 ? 1 : 0);
	Zero(msg + 8, 4);

	if (address != 0)
	{
		UCHAR *a = msg + size;

		// The name of the question, A, IN, a TTL of 60 s, 4 bytes of the address
		a[0] = 0xC0;
		a[1] = 0x0C;
		a[2] = 0;
		a[3] = 1;
		a[4] = 0;
		a[5] = 1;
		a[6] = 0;
		a[7] = 0;
		a[8] = 0;
		a[9] = 60;
		a[10] = 0;
		a[11] = 4;
		Copy(a + 12, &address, 4);
		size += 16;
	}

	return size;
}

// A DNS query of the A record of name, as the oracle's host of node-c sends it: its size
static UINT ClientTestDnsQueryMsg(UCHAR *msg, UINT max, const char *name)
{
	UINT pos = 12;
	TOKEN_LIST *t = ParseToken(name, ".");

	Zero(msg, 12);
	msg[0] = 0x5A;
	msg[1] = 0x5A;
	msg[2] = 0x01;
	msg[5] = 1;

	for (UINT i = 0;i < t->NumTokens;i++)
	{
		UINT len = StrLen(t->Token[i]);

		if (len == 0 || len > 63 || pos + 1 + len + 5 > max)
		{
			FreeToken(t);
			return 0;
		}
		msg[pos++] = (UCHAR)len;
		Copy(msg + pos, t->Token[i], len);
		pos += len;
	}
	FreeToken(t);

	msg[pos++] = 0;
	msg[pos++] = 0;
	msg[pos++] = 1;
	msg[pos++] = 0;
	msg[pos++] = 1;

	return pos;
}

//
// The report
//

static void ClientTestDescIcmp(char *desc, UINT size, UINT type, UINT src, UINT dst, const UCHAR *data, UINT data_size)
{
	char a[64], b[64], text[MAX_SIZE];

	IPToStr32(a, sizeof(a), src);
	IPToStr32(b, sizeof(b), dst);
	ClientTestText(text, sizeof(text), data, data_size);
	Format(desc, size, "icmp echo %s %s > %s data \"%s\"", (type == 8 ? "request" : "reply"), a, b, text);
}

static void ClientTestDescUdp(char *desc, UINT size, UINT src, USHORT src_port, UINT dst, USHORT dst_port, const UCHAR *data, UINT data_size)
{
	char a[64], b[64], text[MAX_SIZE];

	IPToStr32(a, sizeof(a), src);
	IPToStr32(b, sizeof(b), dst);
	ClientTestText(text, sizeof(text), data, data_size);
	Format(desc, size, "udp %s:%u > %s:%u data \"%s\"", a, (UINT)src_port, b, (UINT)dst_port, text);
}

static void ClientTestDescDnsQuery(char *desc, UINT size, const char *name, UINT src, UINT dst)
{
	char a[64], b[64];

	IPToStr32(a, sizeof(a), src);
	IPToStr32(b, sizeof(b), dst);
	Format(desc, size, "dns query A %s from %s to %s:%u", name, a, b, (UINT)CLIENTTEST_DNS_PORT);
}

static void ClientTestDescDnsAnswer(char *desc, UINT size, const char *name, UINT address)
{
	char a[64];

	IPToStr32(a, sizeof(a), address);
	Format(desc, size, "dns answer %s A %s", name, a);
}

// One line of a report: "<who> <what>"
static void ClientTestReportLine(CLIENTTEST_REPORT *r, char *who, char *what)
{
	char line[MAX_SIZE * 2];

	if (r == NULL)
	{
		return;
	}

	Format(line, sizeof(line), "%s %s\n", who, what);

	AcquireSRWLockExclusive(&r->Lock);
	WriteBuf(r->Text, line, StrLen(line));
	ReleaseSRWLockExclusive(&r->Lock);
}

static void ClientTestNewReport(CLIENTTEST_REPORT *r)
{
	Zero(r, sizeof(CLIENTTEST_REPORT));
	InitializeSRWLock(&r->Lock);
	r->Text = NewBuf();
}

// The text of a report: its header line, then its lines
static char *ClientTestReportText(CLIENTTEST_REPORT *r)
{
	char *ret;

	AcquireSRWLockExclusive(&r->Lock);
	{
		UINT header = StrLen(CLIENTTEST_HEADER);

		ret = ZeroMalloc(header + 1 + r->Text->Size + 1);
		Copy(ret, CLIENTTEST_HEADER, header);
		ret[header] = '\n';
		Copy(ret + header + 1, r->Text->Buf, r->Text->Size);
	}
	ReleaseSRWLockExclusive(&r->Lock);

	return ret;
}

// Compare the report of a path with the golden file
static void ClientTestCompare(CLIENTTEST_CTX *ctx, CLIENTTEST_REPORT *r, char *out_dir, char *golden_dir, bool update, char *what)
{
	HARNESS h;
	char tmp[MAX_SIZE];

	Zero(&h, sizeof(h));
	char *text = ClientTestReportText(r);
	HarnessCompareGolden(&h, out_dir, golden_dir, CLIENTTEST_GOLDEN, text, update);
	Free(text);

	Format(tmp, sizeof(tmp), "%s: each host gets what the golden file " CLIENTTEST_GOLDEN " says, as on the oracle", what);
	ClientTestCheck(ctx, h.NumFail == 0, tmp, "it differs (see the diff above)");
}

//
// The hosts
//

// The host of node-s: an ICMP echo request gets its reply, a datagram to CLIENTTEST_UDP_PORT comes back, a DNS query
// gets the address of node-s for the probe and NXDOMAIN for any other name. Each test packet is a line of the report;
// a DNS query of the probe only the first time. On the thread of the overlay, an online reader of the tables of node-s.
static void ClientTestServerHost(NODE *n, void *param, UINT vrf_id, const UCHAR *packet, UINT size)
{
	CLIENTTEST_HOST *h = (CLIENTTEST_HOST *)param;
	CLIENTTEST_REPORT *r = (CLIENTTEST_REPORT *)ReadPointerAcquire((PVOID const volatile *)&h->Report);
	CLIENTTEST_PKT p;
	UCHAR reply[CLIENTTEST_MAX_PACKET];
	char desc[MAX_SIZE];
	char who[MAX_SIZE];
	UINT reply_size = 0;

	Format(who, sizeof(who), "%s gets", h->Name);

	if (ClientTestParse(&p, packet, size) == false)
	{
		InterlockedIncrement64(&h->Other);
		return;
	}

	if (p.Protocol == IP_PROTO_ICMPV4 && p.IcmpType == 8 && p.DataSize <= 256)
	{
		ClientTestDescIcmp(desc, sizeof(desc), 8, p.Src, p.Dst, p.Data, p.DataSize);
		ClientTestReportLine(r, who, desc);
		reply_size = ClientTestIcmp(reply, p.Dst, p.Src, 0, p.IcmpId, p.IcmpSeq, p.Data, p.DataSize);
	}
	else if (p.Protocol == IP_PROTO_UDP && p.DstPort == CLIENTTEST_UDP_PORT && p.DataSize <= 256)
	{
		ClientTestDescUdp(desc, sizeof(desc), p.Src, p.SrcPort, p.Dst, p.DstPort, p.Data, p.DataSize);
		ClientTestReportLine(r, who, desc);
		reply_size = ClientTestUdp(reply, p.Dst, p.Src, p.DstPort, p.SrcPort, p.Data, p.DataSize);
	}
	else if (p.Protocol == IP_PROTO_UDP && p.DstPort == CLIENTTEST_DNS_PORT)
	{
		UCHAR msg[CLIENTTEST_MAX_PACKET];
		char name[MAX_SIZE];
		UINT qtype = 0;
		UINT end = 0;

		if (ClientTestDnsQuestion(p.Data, p.DataSize, false, name, sizeof(name), &qtype, &end) == false)
		{
			InterlockedIncrement64(&h->Other);
			return;
		}

		bool probe = (StrCmp(name, CLIENTTEST_DNS_NAME) == 0 && qtype == 1);
		if (probe && r != NULL)
		{
			bool first;

			AcquireSRWLockExclusive(&r->Lock);
			first = (r->DnsSeen == false);
			r->DnsSeen = true;
			ReleaseSRWLockExclusive(&r->Lock);

			if (first)
			{
				ClientTestDescDnsQuery(desc, sizeof(desc), name, p.Src, p.Dst);
				ClientTestReportLine(r, who, desc);
			}
		}
		else if (probe == false)
		{
			InterlockedIncrement64(&h->Other);
		}

		UINT msg_size = ClientTestDnsAnswer(msg, sizeof(msg), p.Data, end, probe ? clienttest_s : 0);
		reply_size = (msg_size != 0 ? ClientTestUdp(reply, p.Dst, p.Src, p.DstPort, p.SrcPort, msg, msg_size) : 0);
	}
	else
	{
		InterlockedIncrement64(&h->Other);
		return;
	}

	if (reply_size != 0)
	{
		NodeOverlayInput(n, vrf_id, reply, reply_size);
	}
}

// The host of the oracle's node-c: it keeps the packet that reached it last
static void ClientTestOracleHost(NODE *n, void *param, UINT vrf_id, const UCHAR *packet, UINT size)
{
	CLIENTTEST_HOST *h = (CLIENTTEST_HOST *)param;

	AcquireSRWLockExclusive(&h->Lock);
	h->Size = MIN(size, (UINT)sizeof(h->Packet));
	Copy(h->Packet, packet, h->Size);
	ReleaseSRWLockExclusive(&h->Lock);

	SetEvent(h->Arrived);
}

//
// The listener of node-s
//

static bool ClientTestServerDial(void *param, const char *address, HANDLE cancel, void **stream)
{
	// node-s dials no client: the clients dial it
	*stream = NULL;
	return false;
}

static bool ClientTestServerListen(void *param, const char *address, void **listener)
{
	*listener = param;
	return true;
}

// The next stream that dialled the QUIC or the TLS listener within timeout
static bool ClientTestServerAccept(void *listener, UINT timeout, void **stream)
{
	CLIENTTEST_SERVER *srv = (CLIENTTEST_SERVER *)listener;
	UINT64 end = Tick64() + timeout;

	*stream = NULL;

	while (true)
	{
		TRANSPORT_STREAM *t = (srv->QuicListener != NULL ? TransportAccept(srv->QuicListener, 0) : NULL);

		if (t == NULL && srv->TlsListener != NULL)
		{
			t = TransportAccept(srv->TlsListener, 0);
		}

		if (t != NULL)
		{
			CLIENTTEST_STREAM *s = ZeroMalloc(sizeof(CLIENTTEST_STREAM));

			s->Server = srv;
			s->Stream = t;
			Lock(srv->Lock);
			Add(srv->Streams, s);
			Unlock(srv->Lock);

			*stream = s;
			return true;
		}

		UINT64 now = Tick64();
		if (now >= end)
		{
			return false;
		}
		SleepThread((UINT)MIN(end - now, (UINT64)CLIENTTEST_ACCEPT));
	}
}

static void ClientTestServerCloseListener(void *listener)
{
	// The test closes the QUIC and TLS listeners once the overlay of node-s stopped
	return;
}

static UINT ClientTestServerRead(void *stream, void *buf, UINT size, UINT timeout)
{
	CLIENTTEST_STREAM *s = (CLIENTTEST_STREAM *)stream;

	if (ReadAcquire(&s->Frozen) != 0)
	{
		SleepThread(MIN(timeout, (UINT)CLIENTTEST_ACCEPT));
		return TRANSPORT_LATER;
	}

	return TransportRead(s->Stream, buf, size, timeout);
}

static bool ClientTestServerWrite(void *stream, const void *buf, UINT size)
{
	CLIENTTEST_STREAM *s = (CLIENTTEST_STREAM *)stream;

	if (ReadAcquire(&s->Frozen) != 0)
	{
		return true;
	}

	return TransportWrite(s->Stream, buf, size);
}

static void ClientTestServerClose(void *stream)
{
	CLIENTTEST_STREAM *s = (CLIENTTEST_STREAM *)stream;
	CLIENTTEST_SERVER *srv = s->Server;

	Lock(srv->Lock);
	Delete(srv->Streams, s);
	Unlock(srv->Lock);

	TransportClose(s->Stream);
	Free(s);
}

static UINT ClientTestServerBinding(void *stream, UCHAR *binding, UINT max, UINT *size)
{
	return TransportBinding(((CLIENTTEST_STREAM *)stream)->Stream, binding, max, size);
}

static bool ClientTestServerRekey(void *stream)
{
	CLIENTTEST_STREAM *s = (CLIENTTEST_STREAM *)stream;

	return (ReadAcquire(&s->Frozen) != 0 ? true : TransportRekey(s->Stream));
}

// Freeze every stream that node-s holds now: the server's side of the session of node-c goes silent. The number of
// streams frozen.
static UINT ClientTestFreeze(CLIENTTEST_SERVER *srv)
{
	UINT num = 0;

	Lock(srv->Lock);
	for (UINT i = 0;i < LIST_NUM(srv->Streams);i++)
	{
		CLIENTTEST_STREAM *s = LIST_DATA(srv->Streams, i);

		if (InterlockedExchange(&s->Frozen, 1) == 0)
		{
			num++;
		}
	}
	Unlock(srv->Lock);

	return num;
}

// The listener of node-s: the QUIC (where msquic.dll is present) and TLS server transports with the certificate of
// thumbprint, each listening on a port of 127.0.0.1 that the system picks
static CLIENTTEST_SERVER *ClientTestServerNew(char *thumbprint)
{
	CLIENTTEST_SERVER *srv = ZeroMalloc(sizeof(CLIENTTEST_SERVER));
	TRANSPORT_QUIC_CONFIG qc;
	TRANSPORT_TLS_CONFIG tc;

	srv->Lock = NewLock();
	srv->Streams = NewListFast(NULL);

	if (TransportQuicAvailable())
	{
		TransportQuicDefaultConfig(&qc, thumbprint, false);
		srv->Quic = TransportQuicServerNew(&qc);
		srv->QuicListener = (srv->Quic != NULL ? TransportListen(srv->Quic, "127.0.0.1:0") : NULL);
		srv->QuicPort = (srv->QuicListener != NULL ? TransportQuicBoundPort(srv->Quic) : 0);
	}

	TransportTlsDefaultConfig(&tc, thumbprint, false);
	srv->Tls = TransportTlsServerNew(&tc);
	srv->TlsListener = (srv->Tls != NULL ? TransportListen(srv->Tls, "127.0.0.1:0") : NULL);
	srv->TlsPort = (srv->TlsListener != NULL ? TransportTlsBoundPort(srv->Tls) : 0);

	StrCpy(srv->Transport.Name, sizeof(srv->Transport.Name), "server");
	srv->Transport.Param = srv;
	srv->Transport.Dial = ClientTestServerDial;
	srv->Transport.Listen = ClientTestServerListen;
	srv->Transport.Accept = ClientTestServerAccept;
	srv->Transport.CloseListener = ClientTestServerCloseListener;
	srv->Transport.Read = ClientTestServerRead;
	srv->Transport.Write = ClientTestServerWrite;
	srv->Transport.Close = ClientTestServerClose;
	srv->Transport.Binding = ClientTestServerBinding;
	srv->Transport.Rekey = ClientTestServerRekey;
	srv->Transport.Queue = TRANSPORT_QUEUE_NONE;

	return srv;
}

// Close the listeners and the transports, once the overlay of node-s stopped and closed every stream
static void ClientTestServerFree(CLIENTTEST_SERVER *srv)
{
	if (srv == NULL)
	{
		return;
	}

	TransportCloseListener(srv->QuicListener);
	TransportCloseListener(srv->TlsListener);
	TransportQuicFree(srv->Quic);
	TransportTlsFree(srv->Tls);
	ReleaseList(srv->Streams);
	DeleteLock(srv->Lock);
	Free(srv);
}

//
// The nodes
//

// A new empty data directory under the temp directory of the process, with a configuration store: the roles, one
// worker, and the identity key and the Client setting when they are not NULL
static void ClientTestNewDir(wchar_t *dir, UINT size, char *name, char *roles, char *identity, char *client)
{
	wchar_t tmp[MAX_PATH];
	wchar_t path[MAX_PATH];

	UniFormat(tmp, sizeof(tmp), L"clienttest_%S_%u", name, Rand32());
	ConbinePathW(dir, size, MsGetMyTempDirW(), tmp);
	MakeDirExW(dir);

	ConbinePathW(path, sizeof(path), dir, CS_FILE_NAME);
	CONFIG_STORE *s = CsOpen(path);
	if (s != NULL)
	{
		CsSetSetting(s, NODE_SETTING_ROLES, roles);
		CsSetSetting(s, NODE_SETTING_WORKERS, "1");
		if (identity != NULL)
		{
			CsSetSetting(s, NODE_SETTING_IDENTITY_KEY, identity);
		}
		if (client != NULL)
		{
			CsSetSetting(s, NODE_SETTING_CLIENT, client);
		}
		CsClose(s);
	}
}

// Delete the files of a directory, then the directory (it holds no subdirectory)
static void ClientTestDeleteDir(wchar_t *dir)
{
	DIRLIST *d = EnumDirW(dir);

	for (UINT i = 0;d != NULL && i < d->NumFiles;i++)
	{
		DIRENT *e = d->File[i];
		wchar_t path[MAX_PATH];

		if (e->Folder == false)
		{
			ConbinePathW(path, sizeof(path), dir, e->FileNameW);
			FileDeleteW(path);
		}
	}

	FreeDir(d);
	DeleteDirW(dir);
}

// Stop and free a node of the test, and delete its data directory with its node log
static void ClientTestFreeNode(CLIENTTEST_NODE *t)
{
	wchar_t log_dir[MAX_PATH];

	if (t->Node != NULL)
	{
		if (t->Registered)
		{
			NodeReaderUnregister(t->Node, &t->Reader);
			t->Registered = false;
		}
		NodeStop(t->Node);
		FreeNode(t->Node);
		t->Node = NULL;

		ConbinePathW(log_dir, sizeof(log_dir), t->Dir, NODE_LOG_DIR_NAME);
		ClientTestDeleteDir(log_dir);
		ClientTestDeleteDir(t->Dir);
	}

	PeerKeyClose(&t->Key);
}

// The address of a node in a Network of VRF 1
static void ClientTestAddress(CONTROL_ADDRESS *a, char *network, UINT addr, UINT length)
{
	Zero(a, sizeof(CONTROL_ADDRESS));
	StrCpy(a->Network, sizeof(a->Network), network);
	a->VrfId = CLIENTTEST_VRF;
	Copy(a->Address, &addr, 4);
	a->AddressSize = 4;
	a->Length = length;
}

// The desired state of node-s (server) or node-c, with the other node, whose static key is peer_key, as its peer
static void ClientTestState(CONTROL_STATE *st, CONTROL_PEER *peer, bool server, const UCHAR *peer_key)
{
	Zero(st, sizeof(CONTROL_STATE));
	Zero(peer, sizeof(CONTROL_PEER));

	st->Generation = 1;
	StrCpy(st->Name, sizeof(st->Name), server ? CLIENTTEST_NODE_S : CLIENTTEST_NODE_C);

	if (server)
	{
		ClientTestAddress(&st->Addresses[0], "default", clienttest_s, 10);
		ClientTestAddress(&st->Addresses[1], "lan", clienttest_lan, 24);
		st->NumAddresses = 2;
		StrCpy(peer->Name, sizeof(peer->Name), CLIENTTEST_NODE_C);
		ClientTestAddress(&peer->Addresses[0], "default", clienttest_c, 10);
		peer->NumAddresses = 1;
	}
	else
	{
		ClientTestAddress(&st->Addresses[0], "default", clienttest_c, 10);
		st->NumAddresses = 1;
		StrCpy(peer->Name, sizeof(peer->Name), CLIENTTEST_NODE_S);
		ClientTestAddress(&peer->Addresses[0], "default", clienttest_s, 10);
		ClientTestAddress(&peer->Addresses[1], "lan", clienttest_lan, 24);
		peer->NumAddresses = 2;
	}

	Copy(peer->Key, peer_key, PEER_KEY_SIZE);
	peer->NumVrfs = 1;
	peer->VrfIds[0] = CLIENTTEST_VRF;
	st->NumPeers = 1;
	st->Peers = peer;
}

// Apply the state of node-s or node-c to its overlay, as the control stream does
static bool ClientTestApply(CLIENTTEST_NODE *t, bool server, const UCHAR *peer_key)
{
	CONTROL_STATE st;
	CONTROL_PEER peer;

	ClientTestState(&st, &peer, server, peer_key);

	return NodeOverlayApply(t->Node, &st);
}

// The number of Noise sessions of the overlay of a node
static UINT ClientTestLinks(CLIENTTEST_NODE *t)
{
	NODE_OVERLAY_STATUS st;

	NodeOverlayGetStatus(t->Node, &st);

	return st.NumLinks;
}

//
// The oracle: node-c and node-s on the in-process loopback transport, with fake hosts
//

// A packet of the host of the oracle's node-c, sent while the test thread is an online reader of its tables
static bool ClientTestOracleSend(CLIENTTEST_NODE *t, UCHAR *packet, UINT size)
{
	NodeReaderOnline(t->Node, &t->Reader);
	bool sent = NodeOverlayInput(t->Node, CLIENTTEST_VRF, packet, size);
	NodeReaderOffline(&t->Reader);

	return sent;
}

// The next packet that the host of the oracle's node-c takes within timeout: its size, 0 for none
static UINT ClientTestOracleTake(CLIENTTEST_HOST *h, UCHAR *buf, UINT size, UINT timeout)
{
	UINT ret = 0;

	if (WaitForSingleObject(h->Arrived, timeout) != WAIT_OBJECT_0)
	{
		return 0;
	}

	AcquireSRWLockExclusive(&h->Lock);
	ret = MIN(size, h->Size);
	Copy(buf, h->Packet, ret);
	h->Size = 0;
	ReleaseSRWLockExclusive(&h->Lock);

	return ret;
}

// The line of the oracle's node-c for a packet that its host took: the reply of a flow
static void ClientTestOracleReport(CLIENTTEST_REPORT *r, UCHAR *packet, UINT size)
{
	CLIENTTEST_PKT p;
	char desc[MAX_SIZE];
	char name[MAX_SIZE];
	UINT qtype = 0;
	UINT end = 0;

	if (ClientTestParse(&p, packet, size) == false)
	{
		return;
	}

	if (p.Protocol == IP_PROTO_ICMPV4 && p.IcmpType == 0)
	{
		ClientTestDescIcmp(desc, sizeof(desc), 0, p.Src, p.Dst, p.Data, p.DataSize);
	}
	else if (p.Protocol == IP_PROTO_UDP && p.SrcPort == CLIENTTEST_DNS_PORT)
	{
		if (ClientTestDnsQuestion(p.Data, p.DataSize, true, name, sizeof(name), &qtype, &end) == false || qtype != 1)
		{
			return;
		}
		ClientTestDescDnsAnswer(desc, sizeof(desc), name, ClientTestDnsAddress(p.Data, p.DataSize, end));
	}
	else if (p.Protocol == IP_PROTO_UDP)
	{
		ClientTestDescUdp(desc, sizeof(desc), p.Src, p.SrcPort, p.Dst, p.DstPort, p.Data, p.DataSize);
	}
	else
	{
		return;
	}

	ClientTestReportLine(r, CLIENTTEST_NODE_C " gets", desc);
}

// The flows of the report, sent by the host of the oracle's node-c as the runner's stack sends them on the other paths
static void ClientTestOracleFlows(CLIENTTEST_REPORT *r, CLIENTTEST_NODE *c, CLIENTTEST_HOST *h)
{
	UCHAR packet[CLIENTTEST_MAX_PACKET];
	UCHAR got[CLIENTTEST_MAX_PACKET];
	UCHAR msg[CLIENTTEST_MAX_PACKET];
	char desc[MAX_SIZE];
	UINT size;
	UINT got_size;

	// The ICMP echo to node-s
	size = ClientTestIcmp(packet, clienttest_c, clienttest_s, 8, 0x5A5A, 1, (const UCHAR *)CLIENTTEST_ICMP_DATA, StrLen(CLIENTTEST_ICMP_DATA));
	ClientTestOracleSend(c, packet, size);
	got_size = ClientTestOracleTake(h, got, sizeof(got), CLIENTTEST_REPLY);
	ClientTestOracleReport(r, got, got_size);

	// A datagram to each network of node-s
	size = ClientTestUdp(packet, clienttest_c, clienttest_s, CLIENTTEST_CLIENT_PORT, CLIENTTEST_UDP_PORT, (const UCHAR *)CLIENTTEST_UDP_DATA_1, StrLen(CLIENTTEST_UDP_DATA_1));
	ClientTestOracleSend(c, packet, size);
	got_size = ClientTestOracleTake(h, got, sizeof(got), CLIENTTEST_REPLY);
	ClientTestOracleReport(r, got, got_size);

	size = ClientTestUdp(packet, clienttest_c, clienttest_lan, CLIENTTEST_CLIENT_PORT, CLIENTTEST_UDP_PORT, (const UCHAR *)CLIENTTEST_UDP_DATA_2, StrLen(CLIENTTEST_UDP_DATA_2));
	ClientTestOracleSend(c, packet, size);
	got_size = ClientTestOracleTake(h, got, sizeof(got), CLIENTTEST_REPLY);
	ClientTestOracleReport(r, got, got_size);

	// The DNS query of the probe
	UINT msg_size = ClientTestDnsQueryMsg(msg, sizeof(msg), CLIENTTEST_DNS_NAME);
	size = ClientTestUdp(packet, clienttest_c, clienttest_s, CLIENTTEST_CLIENT_PORT + 1, CLIENTTEST_DNS_PORT, msg, msg_size);
	ClientTestOracleSend(c, packet, size);
	got_size = ClientTestOracleTake(h, got, sizeof(got), CLIENTTEST_REPLY);
	ClientTestOracleReport(r, got, got_size);

	// A datagram to an address of no node: the overlay of node-c drops it, and nothing comes back
	size = ClientTestUdp(packet, clienttest_c, clienttest_nowhere, CLIENTTEST_CLIENT_PORT, CLIENTTEST_UDP_PORT, (const UCHAR *)CLIENTTEST_UDP_DATA_3, StrLen(CLIENTTEST_UDP_DATA_3));
	bool sent = ClientTestOracleSend(c, packet, size);
	got_size = ClientTestOracleTake(h, got, sizeof(got), CLIENTTEST_SILENCE);
	if (sent == false && got_size == 0)
	{
		ClientTestDescUdp(desc, sizeof(desc), clienttest_c, CLIENTTEST_CLIENT_PORT, clienttest_nowhere, CLIENTTEST_UDP_PORT, (const UCHAR *)CLIENTTEST_UDP_DATA_3, StrLen(CLIENTTEST_UDP_DATA_3));
		ClientTestReportLine(r, "no host gets", desc);
	}
}

// The oracle: two nodes of the overlay with fake hosts on the loopback transport and the states of the test, the path
// that SDN-3 and SDN-4 proved; its report must be the golden file
static void ClientTestOracle(CLIENTTEST_CTX *ctx, char *out_dir, char *golden_dir, bool update)
{
	CLIENTTEST_NODE *c = ZeroMalloc(sizeof(CLIENTTEST_NODE));
	CLIENTTEST_NODE *s = ZeroMalloc(sizeof(CLIENTTEST_NODE));
	CLIENTTEST_HOST *hc = ZeroMalloc(sizeof(CLIENTTEST_HOST));
	CLIENTTEST_HOST *hs = ZeroMalloc(sizeof(CLIENTTEST_HOST));
	CLIENTTEST_REPORT report;
	TRANSPORT *loopback = TransportLoopbackNew("loopback", 0, false);
	UCHAR scalar[PEER_KEY_SIZE];
	NODE_OVERLAY_CONFIG cfg;

	Print("[the oracle: node-c and node-s with fake hosts on the in-process loopback transport]\n");

	ClientTestNewReport(&report);
	hc->Name = CLIENTTEST_NODE_C;
	hc->Arrived = CreateEventW(NULL, FALSE, FALSE, NULL);
	InitializeSRWLock(&hc->Lock);
	hs->Name = CLIENTTEST_NODE_S;
	hs->Report = &report;
	InitializeSRWLock(&hs->Lock);

	bool ok = (loopback != NULL);
	for (UINT i = 0;i < PEER_KEY_SIZE;i++)
	{
		scalar[i] = (UCHAR)(0x20 + i);
	}
	ok = ok && PeerKeyFromScalar(&c->Key, scalar);
	for (UINT i = 0;i < PEER_KEY_SIZE;i++)
	{
		scalar[i] = (UCHAR)(0x60 + i);
	}
	ok = ok && PeerKeyFromScalar(&s->Key, scalar);
	Zero(scalar, sizeof(scalar));

	if (ok)
	{
		ClientTestNewDir(c->Dir, sizeof(c->Dir), "oraclec", "none", NULL, NULL);
		c->Node = NewNode(c->Dir);
		NodeStart(c->Node);
		NodeReaderRegister(c->Node, &c->Reader);
		NodeReaderOffline(&c->Reader);
		c->Registered = true;

		ClientTestNewDir(s->Dir, sizeof(s->Dir), "oracles", "none", NULL, NULL);
		s->Node = NewNode(s->Dir);
		NodeStart(s->Node);

		Zero(&cfg, sizeof(cfg));
		cfg.Data = loopback;
		cfg.Key = &c->Key;
		cfg.Adapter = ClientTestOracleHost;
		cfg.AdapterParam = hc;
		ok = NodeOverlayStart(c->Node, &cfg);

		Zero(&cfg, sizeof(cfg));
		cfg.Data = loopback;
		cfg.Key = &s->Key;
		cfg.Adapter = ClientTestServerHost;
		cfg.AdapterParam = hs;
		ok = NodeOverlayStart(s->Node, &cfg) && ok;

		ok = ok && ClientTestApply(s, true, c->Key.Public) && ClientTestApply(c, false, s->Key.Public);
	}

	bool linked = false;
	for (UINT64 end = Tick64() + CLIENTTEST_BOUND;ok && linked == false && Tick64() < end;)
	{
		linked = (ClientTestLinks(c) == 1 && ClientTestLinks(s) == 1);
		if (linked == false)
		{
			SleepThread(CLIENTTEST_POLL);
		}
	}

	if (ClientTestCheck(ctx, ok && linked, "oracle: node-c and node-s apply their states and their Noise session is up on the loopback transport",
		"started %u, linked %u", (UINT)ok, (UINT)linked))
	{
		ClientTestOracleFlows(&report, c, hc);
		ClientTestCompare(ctx, &report, out_dir, golden_dir, update, "oracle");
	}

	ClientTestFreeNode(c);
	ClientTestFreeNode(s);
	TransportLoopbackFree(loopback);

	if (hc->Arrived != NULL)
	{
		CloseHandle(hc->Arrived);
	}
	FreeBuf(report.Text);
	Free(hc);
	Free(hs);
	Free(c);
	Free(s);
}

//
// The client node on Wintun
//

// Whether the address of node-c is on the interface of luid, preferred
static bool ClientTestAddressUp(UINT64 luid)
{
	MIB_UNICASTIPADDRESS_ROW row;

	InitializeUnicastIpAddressEntry(&row);
	row.InterfaceLuid.Value = luid;
	row.Address.Ipv4.sin_family = AF_INET;
	Copy(&row.Address.Ipv4.sin_addr, &clienttest_c, 4);

	return (GetUnicastIpAddressEntry(&row) == NO_ERROR && row.DadState == IpDadStatePreferred);
}

// Whether Windows takes the interface of luid to dst, by the route of prefix and length, with the address of node-c as
// the source
static bool ClientTestRouteVia(UINT64 luid, UINT dst, UINT prefix, UINT length, char *detail, UINT detail_size)
{
	SOCKADDR_INET d;
	SOCKADDR_INET src;
	MIB_IPFORWARD_ROW2 best;
	UINT got_prefix = 0;
	UINT got_src = 0;
	char a[64], b[64];

	Zero(&d, sizeof(d));
	Zero(&src, sizeof(src));
	Zero(&best, sizeof(best));
	d.Ipv4.sin_family = AF_INET;
	Copy(&d.Ipv4.sin_addr, &dst, 4);

	DWORD err = GetBestRoute2(NULL, 0, NULL, &d, 0, &best, &src);
	Copy(&got_prefix, &best.DestinationPrefix.Prefix.Ipv4.sin_addr, 4);
	Copy(&got_src, &src.Ipv4.sin_addr, 4);
	IPToStr32(a, sizeof(a), got_prefix);
	IPToStr32(b, sizeof(b), got_src);
	Format(detail, detail_size, "GetBestRoute2 %u: interface LUID %I64u (the adapter's %I64u), prefix %s/%u, source %s",
		(UINT)err, (UINT64)best.InterfaceLuid.Value, luid, a, (UINT)best.DestinationPrefix.PrefixLength, b);

	return (err == NO_ERROR && best.InterfaceLuid.Value == luid && got_prefix == prefix && best.DestinationPrefix.PrefixLength == length && got_src == clienttest_c);
}

// Whether the interface of index has the DNS server of node-s and the suffix of the Client setting
static bool ClientTestDnsSet(UINT index, char *detail, UINT detail_size)
{
	ULONG size = 65536;
	bool server = false;
	bool suffix = false;
	IP_ADAPTER_ADDRESSES *list = ZeroMalloc(size);

	ULONG err = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST, NULL, list, &size);
	if (err == ERROR_BUFFER_OVERFLOW)
	{
		Free(list);
		list = ZeroMalloc(size);
		err = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST, NULL, list, &size);
	}

	for (IP_ADAPTER_ADDRESSES *a = (err == NO_ERROR ? list : NULL);a != NULL;a = a->Next)
	{
		if (a->IfIndex != index)
		{
			continue;
		}

		suffix = (a->DnsSuffix != NULL && UniStrCmpi(a->DnsSuffix, CLIENTTEST_SUFFIX_W) == 0);
		for (IP_ADAPTER_DNS_SERVER_ADDRESS *d = a->FirstDnsServerAddress;d != NULL;d = d->Next)
		{
			if (d->Address.lpSockaddr != NULL && d->Address.lpSockaddr->sa_family == AF_INET)
			{
				UINT got = 0;

				Copy(&got, &((struct sockaddr_in *)d->Address.lpSockaddr)->sin_addr, 4);
				server = server || (got == clienttest_s);
			}
		}
	}

	Free(list);
	Format(detail, detail_size, "GetAdaptersAddresses %u: the DNS server of node-s %u, the suffix %u", (UINT)err, (UINT)server, (UINT)suffix);

	return (server && suffix);
}

// An ICMP echo from the runner's stack, from node-c's address to dst: whether its reply came back with the same data
// within timeout
static bool ClientTestPing(UINT dst, UINT timeout)
{
	UINT64 reply[64];
	bool ok = false;

	HANDLE icmp = IcmpCreateFile();
	if (icmp == INVALID_HANDLE_VALUE)
	{
		return false;
	}

	Zero(reply, sizeof(reply));
	DWORD n = IcmpSendEcho2Ex(icmp, NULL, NULL, NULL, (IPAddr)clienttest_c, (IPAddr)dst, (LPVOID)CLIENTTEST_ICMP_DATA, (WORD)StrLen(CLIENTTEST_ICMP_DATA),
		NULL, reply, sizeof(reply), timeout);
	if (n != 0)
	{
		ICMP_ECHO_REPLY *e = (ICMP_ECHO_REPLY *)reply;

		ok = (e->Status == IP_SUCCESS && e->Address == (IPAddr)dst && e->DataSize == StrLen(CLIENTTEST_ICMP_DATA) && e->Data != NULL &&
			Cmp(e->Data, CLIENTTEST_ICMP_DATA, e->DataSize) == 0);
	}

	IcmpCloseHandle(icmp);

	return ok;
}

// Whether an ICMP echo to node-s comes back within CLIENTTEST_BOUND, the echoes sent one after another
static bool ClientTestPingWithin()
{
	for (UINT64 end = Tick64() + CLIENTTEST_BOUND;Tick64() < end;)
	{
		if (ClientTestPing(clienttest_s, 1000))
		{
			return true;
		}
	}

	return false;
}

// A datagram from the runner's stack, from node-c's address and CLIENTTEST_CLIENT_PORT to dst and CLIENTTEST_UDP_PORT.
// With expect_reply, whether the same data came back from there within CLIENTTEST_REPLY; without, whether nothing came
// within CLIENTTEST_SILENCE.
static bool ClientTestDatagram(UINT dst, char *data, bool expect_reply)
{
	struct sockaddr_in local, remote, from;
	char buf[256];
	int from_len = sizeof(from);
	DWORD timeout = (expect_reply ? CLIENTTEST_REPLY : CLIENTTEST_SILENCE);
	BOOL exclusive = TRUE;
	bool ok = false;

	SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (s == INVALID_SOCKET)
	{
		return false;
	}

	Zero(&local, sizeof(local));
	local.sin_family = AF_INET;
	local.sin_port = htons(CLIENTTEST_CLIENT_PORT);
	Copy(&local.sin_addr, &clienttest_c, 4);
	Zero(&remote, sizeof(remote));
	remote.sin_family = AF_INET;
	remote.sin_port = htons(CLIENTTEST_UDP_PORT);
	Copy(&remote.sin_addr, &dst, 4);
	Zero(&from, sizeof(from));

	setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (char *)&exclusive, sizeof(exclusive));
	setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));

	int len = (int)StrLen(data);
	if (bind(s, (struct sockaddr *)&local, sizeof(local)) == 0 && sendto(s, data, len, 0, (struct sockaddr *)&remote, sizeof(remote)) == len)
	{
		int n = recvfrom(s, buf, sizeof(buf), 0, (struct sockaddr *)&from, &from_len);
		UINT from_addr = 0;

		Copy(&from_addr, &from.sin_addr, 4);
		if (expect_reply)
		{
			ok = (n == len && Cmp(buf, data, (UINT)n) == 0 && from_addr == dst && ntohs(from.sin_port) == CLIENTTEST_UDP_PORT);
		}
		else
		{
			ok = (n == SOCKET_ERROR && WSAGetLastError() == WSAETIMEDOUT);
		}
	}

	closesocket(s);

	return ok;
}

// DnsQueryEx and DnsFree of dnsapi.dll, which the test takes by name: Mayaqua has a DnsFree of its own (DNS.c), so
// vpntest cannot link the import library of dnsapi.dll
typedef DNS_STATUS(WINAPI CLIENTTEST_DNS_QUERY_EX)(PDNS_QUERY_REQUEST request, PDNS_QUERY_RESULT result, PDNS_QUERY_CANCEL cancel);
typedef VOID(WINAPI CLIENTTEST_DNS_FREE)(PVOID data, DNS_FREE_TYPE type);

// A DNS query of the probe through the DNS servers of the interface of index, as an application of the runner asks:
// the address of the A record of the answer, 0 for none
static UINT ClientTestDnsQuery(UINT index)
{
	DNS_QUERY_REQUEST req;
	DNS_QUERY_RESULT res;
	UINT ret = 0;

	HMODULE dnsapi = LoadLibraryExW(L"dnsapi.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
	CLIENTTEST_DNS_QUERY_EX *query = (dnsapi != NULL ? (CLIENTTEST_DNS_QUERY_EX *)(void *)GetProcAddress(dnsapi, "DnsQueryEx") : NULL);
	CLIENTTEST_DNS_FREE *free_records = (dnsapi != NULL ? (CLIENTTEST_DNS_FREE *)(void *)GetProcAddress(dnsapi, "DnsFree") : NULL);
	if (query == NULL || free_records == NULL)
	{
		Print("  [INFO] dnsapi.dll has no DnsQueryEx or DnsFree (error %u)\n", (UINT)GetLastError());
		if (dnsapi != NULL)
		{
			FreeLibrary(dnsapi);
		}
		return 0;
	}

	Zero(&req, sizeof(req));
	Zero(&res, sizeof(res));
	req.Version = DNS_QUERY_REQUEST_VERSION1;
	req.QueryName = CLIENTTEST_DNS_NAME_W;
	req.QueryType = DNS_TYPE_A;
	req.QueryOptions = DNS_QUERY_BYPASS_CACHE | DNS_QUERY_NO_HOSTS_FILE | DNS_QUERY_NO_MULTICAST | DNS_QUERY_NO_NETBT | DNS_QUERY_WIRE_ONLY;
	req.InterfaceIndex = index;
	res.Version = DNS_QUERY_REQUEST_VERSION1;

	DNS_STATUS status = query(&req, &res, NULL);
	if (status == ERROR_SUCCESS && res.QueryStatus == ERROR_SUCCESS)
	{
		for (PDNS_RECORD r = res.pQueryRecords;r != NULL && ret == 0;r = r->pNext)
		{
			if (r->wType == DNS_TYPE_A)
			{
				ret = (UINT)r->Data.A.IpAddress;
			}
		}
	}
	else
	{
		Print("  [INFO] DnsQueryEx on interface %u: status %u, query status %u\n", index, (UINT)status, (UINT)res.QueryStatus);
	}

	if (res.pQueryRecords != NULL)
	{
		free_records(res.pQueryRecords, DnsFreeRecordList);
	}
	FreeLibrary(dnsapi);

	return ret;
}

// The flows of the report from the runner's own stack through the Wintun adapter of node-c, whose interface is index.
// node-s reports what reaches it; the replies that come back make the lines of node-c.
static void ClientTestWintunFlows(CLIENTTEST_REPORT *r, UINT index)
{
	char desc[MAX_SIZE];

	// The ICMP echo to node-s
	if (ClientTestPing(clienttest_s, CLIENTTEST_REPLY))
	{
		ClientTestDescIcmp(desc, sizeof(desc), 0, clienttest_s, clienttest_c, (const UCHAR *)CLIENTTEST_ICMP_DATA, StrLen(CLIENTTEST_ICMP_DATA));
		ClientTestReportLine(r, CLIENTTEST_NODE_C " gets", desc);
	}

	// A datagram to each network of node-s
	if (ClientTestDatagram(clienttest_s, CLIENTTEST_UDP_DATA_1, true))
	{
		ClientTestDescUdp(desc, sizeof(desc), clienttest_s, CLIENTTEST_UDP_PORT, clienttest_c, CLIENTTEST_CLIENT_PORT, (const UCHAR *)CLIENTTEST_UDP_DATA_1, StrLen(CLIENTTEST_UDP_DATA_1));
		ClientTestReportLine(r, CLIENTTEST_NODE_C " gets", desc);
	}

	if (ClientTestDatagram(clienttest_lan, CLIENTTEST_UDP_DATA_2, true))
	{
		ClientTestDescUdp(desc, sizeof(desc), clienttest_lan, CLIENTTEST_UDP_PORT, clienttest_c, CLIENTTEST_CLIENT_PORT, (const UCHAR *)CLIENTTEST_UDP_DATA_2, StrLen(CLIENTTEST_UDP_DATA_2));
		ClientTestReportLine(r, CLIENTTEST_NODE_C " gets", desc);
	}

	// The DNS query of the probe through the DNS server that the client role set on the adapter
	UINT address = ClientTestDnsQuery(index);
	if (address != 0)
	{
		ClientTestDescDnsAnswer(desc, sizeof(desc), CLIENTTEST_DNS_NAME, address);
		ClientTestReportLine(r, CLIENTTEST_NODE_C " gets", desc);
	}

	// A datagram to an address of no node: the overlay of node-c drops it, and nothing comes back
	if (ClientTestDatagram(clienttest_nowhere, CLIENTTEST_UDP_DATA_3, false))
	{
		ClientTestDescUdp(desc, sizeof(desc), clienttest_c, CLIENTTEST_CLIENT_PORT, clienttest_nowhere, CLIENTTEST_UDP_PORT, (const UCHAR *)CLIENTTEST_UDP_DATA_3, StrLen(CLIENTTEST_UDP_DATA_3));
		ClientTestReportLine(r, "no host gets", desc);
	}
}

// Whether node-c is up within CLIENTTEST_BOUND: the client role runs, its address is on the adapter, and its session
// to node-s is up
static bool ClientTestWaitUp(CLIENTTEST_NODE *c)
{
	for (UINT64 end = Tick64() + CLIENTTEST_BOUND;Tick64() < end;SleepThread(CLIENTTEST_POLL))
	{
		NODE_CLIENT_STATUS cs;

		NodeClientGetStatus(c->Node, &cs);
		if (cs.Running && ClientTestLinks(c) == 1 && ClientTestAddressUp(cs.InterfaceLuid))
		{
			return true;
		}
	}

	return false;
}

// Whether the session of node-c to node-s is down within CLIENTTEST_BOUND
static bool ClientTestWaitDown(CLIENTTEST_NODE *c)
{
	for (UINT64 end = Tick64() + CLIENTTEST_BOUND;Tick64() < end;SleepThread(CLIENTTEST_POLL))
	{
		if (ClientTestLinks(c) == 0)
		{
			return true;
		}
	}

	return false;
}

// Whether node-c dialled node-s again and its session is up within CLIENTTEST_BOUND: more streams connected than dials
// and roams more roaming than roams (INFINITE: not looked at)
static bool ClientTestWaitRedial(CLIENTTEST_NODE *c, UINT64 dials, UINT64 roams)
{
	for (UINT64 end = Tick64() + CLIENTTEST_BOUND;Tick64() < end;SleepThread(CLIENTTEST_POLL))
	{
		NODE_CLIENT_STATUS cs;

		NodeClientGetStatus(c->Node, &cs);
		if (cs.NumDials > dials && (roams == INFINITE || cs.NumRoams > roams) && ClientTestLinks(c) == 1)
		{
			return true;
		}
	}

	return false;
}

// Whether the interface of luid is gone within CLIENTTEST_BOUND
static bool ClientTestAdapterGone(UINT64 luid)
{
	for (UINT64 end = Tick64() + CLIENTTEST_BOUND;Tick64() < end;SleepThread(CLIENTTEST_POLL))
	{
		NET_LUID l;
		NET_IFINDEX index = 0;

		l.Value = luid;
		if (ConvertInterfaceLuidToIndex(&l, &index) != NO_ERROR)
		{
			return true;
		}
	}

	return false;
}

// The Client setting of node-c: its adapter, the DNS server and suffix of the network, its pipe, and node-s with the
// thumbprint of its certificate and the fallback list dial
static void ClientTestSetting(char *setting, UINT size, wchar_t *adapter, char *pipe, char *thumbprint, char *dial)
{
	char adapter_a[MAX_SIZE];

	UniToStr(adapter_a, sizeof(adapter_a), adapter);
	Format(setting, size,
		"{\"adapter\":\"%s\",\"pipe\":\"%s\",\"dns\":[\"100.64.0.1\"],\"suffix\":\"" CLIENTTEST_SUFFIX "\","
		"\"servers\":[{\"name\":\"" CLIENTTEST_NODE_S "\",\"thumbprint\":\"%s\",\"dial\":\"%s\"}]}",
		adapter_a, pipe, thumbprint, dial);
}

//
// The logged-in user
//

// One command through the pipe of the client role: the line of the answer into reply. False when the pipe cannot be
// opened (*err: the error of CreateFile) or does not answer.
static bool ClientTestPipe(wchar_t *pipe, char *command, char *reply, UINT size, UINT *err)
{
	char line[MAX_SIZE];
	DWORD n = 0;
	UINT used = 0;
	HANDLE h = INVALID_HANDLE_VALUE;

	*err = 0;
	StrCpy(reply, size, "");

	for (UINT64 end = Tick64() + CLIENTTEST_REPLY;;)
	{
		h = CreateFileW(pipe, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
		if (h != INVALID_HANDLE_VALUE)
		{
			break;
		}

		*err = (UINT)GetLastError();
		if (*err != ERROR_PIPE_BUSY || Tick64() >= end)
		{
			return false;
		}
		WaitNamedPipeW(pipe, 200);
	}

	Format(line, sizeof(line), "%s\n", command);
	bool ok = (WriteFile(h, line, StrLen(line), &n, NULL) && n == StrLen(line));

	while (ok && used + 1 < size)
	{
		char ch = 0;

		ok = (ReadFile(h, &ch, 1, &n, NULL) && n == 1);
		if (ok == false || ch == '\n')
		{
			break;
		}
		reply[used++] = ch;
	}
	reply[used] = 0;

	CloseHandle(h);

	return ok;
}

// One command through the pipe as the user of token, by impersonation
static bool ClientTestPipeAs(HANDLE token, wchar_t *pipe, char *command, char *reply, UINT size, UINT *err)
{
	*err = 0;
	StrCpy(reply, size, "");

	if (ImpersonateLoggedOnUser(token) == FALSE)
	{
		*err = (UINT)GetLastError();
		return false;
	}

	bool ok = ClientTestPipe(pipe, command, reply, size, err);
	RevertToSelf();

	return ok;
}

// Whether the DACL of the pipe, as Windows holds it, gives full control to SYSTEM, the Administrators and the account of
// the service, read and write without the right to change the DACL or the owner to the interactive users, and nothing
// to anyone else
static bool ClientTestPipeAcl(wchar_t *pipe, char *detail, UINT detail_size)
{
	PSECURITY_DESCRIPTOR sd = NULL;
	PACL dacl = NULL;
	PSID system = NULL, admins = NULL, service = NULL, interactive = NULL;
	UINT num_system = 0, num_admins = 0, num_service = 0, num_interactive = 0, others = 0;
	ACCESS_MASK interactive_mask = 0;
	DWORD err = ERROR_INVALID_HANDLE;

	HANDLE h = CreateFileW(pipe, GENERIC_READ | READ_CONTROL, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (h != INVALID_HANDLE_VALUE)
	{
		err = GetSecurityInfo(h, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &dacl, NULL, &sd);
		CloseHandle(h);
	}

	ConvertStringSidToSidW(L"SY", &system);
	ConvertStringSidToSidW(L"BA", &admins);
	ConvertStringSidToSidW(NODE_SERVICE_SID, &service);
	ConvertStringSidToSidW(L"IU", &interactive);

	for (DWORD i = 0;err == ERROR_SUCCESS && dacl != NULL && i < dacl->AceCount;i++)
	{
		ACE_HEADER *ace = NULL;

		if (GetAce(dacl, i, (LPVOID *)&ace) == FALSE || ace->AceType != ACCESS_ALLOWED_ACE_TYPE)
		{
			others++;
			continue;
		}

		ACCESS_ALLOWED_ACE *a = (ACCESS_ALLOWED_ACE *)ace;
		PSID sid = (PSID)&a->SidStart;

		if (system != NULL && EqualSid(sid, system))
		{
			num_system++;
		}
		else if (admins != NULL && EqualSid(sid, admins))
		{
			num_admins++;
		}
		else if (service != NULL && EqualSid(sid, service))
		{
			num_service++;
		}
		else if (interactive != NULL && EqualSid(sid, interactive))
		{
			num_interactive++;
			interactive_mask = a->Mask;
		}
		else
		{
			others++;
		}
	}

	LocalFree(system);
	LocalFree(admins);
	LocalFree(service);
	LocalFree(interactive);
	if (sd != NULL)
	{
		LocalFree(sd);
	}

	Format(detail, detail_size, "GetSecurityInfo %u: SYSTEM %u, Administrators %u, service %u, interactive %u (mask 0x%x), others %u",
		(UINT)err, num_system, num_admins, num_service, num_interactive, (UINT)interactive_mask, others);

	// Windows keeps the generic rights of the SDDL mapped to the rights of a file, or as they were
	bool read_write = ((interactive_mask & (FILE_READ_DATA | FILE_WRITE_DATA)) == (FILE_READ_DATA | FILE_WRITE_DATA) ||
		(interactive_mask & (GENERIC_READ | GENERIC_WRITE)) == (GENERIC_READ | GENERIC_WRITE));

	return (err == ERROR_SUCCESS && num_system == 1 && num_admins == 1 && num_service == 1 && num_interactive == 1 && others == 0 &&
		read_write && (interactive_mask & (WRITE_DAC | WRITE_OWNER | DELETE | GENERIC_ALL)) == 0);
}

// The logged-in user drives the role: a local user who is no administrator and logs on interactively takes the role
// down and up through its pipe; the same user logged on over the network cannot open it
static void ClientTestUser(CLIENTTEST_CTX *ctx, CLIENTTEST_NODE *c)
{
	USER_INFO_1 ui;
	wchar_t account[64];
	wchar_t password[64];
	char password_a[64];
	char reply[NODE_CLIENT_REPLY];
	char detail[MAX_SIZE];
	DWORD parm_err = 0;
	HANDLE interactive = NULL;
	HANDLE network = NULL;
	UINT err = 0;
	UCHAR r[8];
	NODE_CLIENT_STATUS cs;

	Print("[the logged-in user]\n");

	NodeClientGetStatus(c->Node, &cs);
	ClientTestCheck(ctx, ClientTestPipeAcl(cs.Pipe, detail, sizeof(detail)),
		"the pipe of the client role gives full control to SYSTEM, the Administrators and the service, read and write to the interactive users, nothing to anyone else",
		"%s", detail);

	// A local user who is no administrator, with a random name and a password that meets the complexity policy of Windows Server
	Rand(r, sizeof(r));
	UniFormat(account, sizeof(account), L"ranzcl%02x%02x", r[0], r[1]);
	Format(password_a, sizeof(password_a), "Rz#%02x%02x%02x%02x%02x%02x-Cl7", r[2], r[3], r[4], r[5], r[6], r[7]);
	StrToUni(password, sizeof(password), password_a);

	Zero(&ui, sizeof(ui));
	ui.usri1_name = account;
	ui.usri1_password = password;
	ui.usri1_priv = USER_PRIV_USER;
	ui.usri1_flags = UF_SCRIPT | UF_DONT_EXPIRE_PASSWD;

	NET_API_STATUS st = NetUserAdd(NULL, 1, (LPBYTE)&ui, &parm_err);
	if (ClientTestCheck(ctx, st == NERR_Success, "a local user who is no administrator (administrator rights)", "NetUserAdd: status %lu", (unsigned long)st))
	{
		bool logged_on = LogonUserW(account, L".", password, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &interactive);
		UINT logon_err = (UINT)GetLastError();
		ClientTestCheck(ctx, logged_on, "the user logs on interactively", "LogonUserW: error %u", logon_err);

		if (logged_on)
		{
			bool ok = ClientTestPipeAs(interactive, cs.Pipe, "status", reply, sizeof(reply), &err);
			Print("  [INFO] status: %s\n", reply);
			ClientTestCheck(ctx, ok && InStr(reply, "\"state\":\"connected\""), "the logged-in user reads the status of the role through its pipe: connected",
				"error %u, answer %s", err, reply);

			ok = ClientTestPipeAs(interactive, cs.Pipe, "down", reply, sizeof(reply), &err);
			bool down = ClientTestWaitDown(c);
			ClientTestCheck(ctx, ok && InStr(reply, "\"state\":\"down\"") && down && ClientTestPing(clienttest_s, 1000) == false,
				"down from the logged-in user: the session to node-s closes, and no echo goes through", "error %u, answer %s, session down %u", err, reply, (UINT)down);

			NodeClientGetStatus(c->Node, &cs);
			UINT64 dials = cs.NumDials;
			ok = ClientTestPipeAs(interactive, cs.Pipe, "up", reply, sizeof(reply), &err);
			bool up = ClientTestWaitRedial(c, dials, INFINITE);
			ClientTestCheck(ctx, ok && up && ClientTestPingWithin(), "up from the logged-in user: node-c dials node-s again and the echo comes back",
				"error %u, answer %s, session up %u", err, reply, (UINT)up);
		}

		// The same user logged on over the network is no interactive user
		bool network_logon = LogonUserW(account, L".", password, LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, &network);
		if (ClientTestCheck(ctx, network_logon, "the user logs on over the network", "LogonUserW: error %u", (UINT)GetLastError()))
		{
			bool ok = ClientTestPipeAs(network, cs.Pipe, "down", reply, sizeof(reply), &err);
			ClientTestCheck(ctx, ok == false && err == ERROR_ACCESS_DENIED, "the user logged on over the network cannot open the pipe",
				"answer %s, error %u", reply, err);
		}

		if (interactive != NULL)
		{
			CloseHandle(interactive);
		}
		if (network != NULL)
		{
			CloseHandle(network);
		}

		st = NetUserDel(NULL, account);
		ClientTestCheck(ctx, st == NERR_Success, "the local user is deleted", "NetUserDel: status %lu", (unsigned long)st);
	}

	Zero(password, sizeof(password));
	Zero(password_a, sizeof(password_a));
}

//
// Sleep and roaming
//

static void ClientTestSleep(CLIENTTEST_CTX *ctx, CLIENTTEST_NODE *c, CLIENTTEST_SERVER *srv)
{
	NODE_CLIENT_STATUS cs;

	Print("[sleep and resume]\n");

	// The server's side of the session goes silent, as for a client that sleeps: the server holds its session
	UINT frozen = ClientTestFreeze(srv);
	NodeClientPower(c->Node, PBT_APMSUSPEND);
	bool down = ClientTestWaitDown(c);
	NodeClientGetStatus(c->Node, &cs);
	ClientTestCheck(ctx, frozen != 0 && down && cs.Asleep && ClientTestPing(clienttest_s, 1000) == false,
		"suspend: node-c closes its session and dials nothing, so no echo goes through", "%u streams of node-s frozen, session down %u, asleep %u",
		frozen, (UINT)down, (UINT)cs.Asleep);

	UINT64 dials = cs.NumDials;
	NodeClientPower(c->Node, PBT_APMRESUMEAUTOMATIC);
	bool up = ClientTestWaitRedial(c, dials, INFINITE);
	NodeClientGetStatus(c->Node, &cs);
	ClientTestCheck(ctx, up && cs.Asleep == false && ClientTestPingWithin(),
		"resume: node-c dials node-s again, node-s replaces the session that the sleep left, and the echo comes back",
		"session up %u, asleep %u, %I64u dials", (UINT)up, (UINT)cs.Asleep, cs.NumDials);
}

static void ClientTestRoam(CLIENTTEST_CTX *ctx, CLIENTTEST_NODE *c, CLIENTTEST_SERVER *srv, wchar_t *roam_name)
{
	NODE_CLIENT_STATUS cs;
	NODE_PREFIX p;

	Print("[roaming]\n");

	// The server's side of the session goes silent, as for a client whose old path went
	UINT frozen = ClientTestFreeze(srv);
	NodeClientGetStatus(c->Node, &cs);
	UINT64 dials = cs.NumDials;
	UINT64 roams = cs.NumRoams;

	// A real address change on another interface: a second Wintun adapter that takes an address
	NODE_WINTUN *roam = NodeWintunNew(c->Node, roam_name, NULL, NULL);
	Zero(&p, sizeof(p));
	Copy(p.Address, &clienttest_roam, 4);
	p.AddressSize = 4;
	p.Length = 32;
	bool set = (roam != NULL && NodeWintunSetAddresses(roam, &p, 1));

	bool up = ClientTestWaitRedial(c, dials, roams);
	NodeClientGetStatus(c->Node, &cs);
	ClientTestCheck(ctx, frozen != 0 && set && up && ClientTestPingWithin(),
		"roaming: an address that comes on another interface has node-c dial node-s again on the new path, node-s replaces the old session, and the echo comes back",
		"%u streams of node-s frozen, address set %u, redialled %u, %I64u roams, %I64u dials", frozen, (UINT)set, (UINT)up, cs.NumRoams, cs.NumDials);

	// The adapter goes: another change, after which the session comes up again
	NodeWintunFree(roam);
	ClientTestCheck(ctx, ClientTestPingWithin(), "roaming: once the other adapter went, the echo comes back", "no echo within %u ms", (UINT)CLIENTTEST_BOUND);
}

// A UDP port of 127.0.0.1 where nothing listens: one that the system gave a socket a moment ago
static USHORT ClientTestDeadPort()
{
	struct sockaddr_in a;
	int len = sizeof(a);
	USHORT port = 0;

	SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (s == INVALID_SOCKET)
	{
		return 9;
	}

	Zero(&a, sizeof(a));
	a.sin_family = AF_INET;
	a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (bind(s, (struct sockaddr *)&a, sizeof(a)) == 0 && getsockname(s, (struct sockaddr *)&a, &len) == 0)
	{
		port = ntohs(a.sin_port);
	}

	closesocket(s);

	return (port != 0 ? port : 9);
}

//
// The paths over Wintun
//

// The Wintun paths: node-s with its listener on QUIC and TLS-443, node-c with the client role on a Wintun adapter.
// Over QUIC the routes, the DNS servers, the report, the logged-in user, sleep and roaming; over TLS-443 the report
// again, when the QUIC entry of the fallback list reaches nothing.
static void ClientTestWintun(CLIENTTEST_CTX *ctx, char *out_dir, char *golden_dir, bool update)
{
	CLIENTTEST_NODE *c = ZeroMalloc(sizeof(CLIENTTEST_NODE));
	CLIENTTEST_NODE *s = ZeroMalloc(sizeof(CLIENTTEST_NODE));
	CLIENTTEST_HOST *hs = ZeroMalloc(sizeof(CLIENTTEST_HOST));
	CLIENTTEST_REPORT quic, tls, scratch;
	CLIENTTEST_SERVER *srv = NULL;
	NODE_OVERLAY_CONFIG cfg;
	NODE_CLIENT_STATUS cs;
	PEER_KEY key;
	UCHAR scalar[PEER_KEY_SIZE];
	UCHAR client_key[PEER_KEY_SIZE];
	char thumbprint[MAX_SIZE];
	char identity[MAX_SIZE];
	wchar_t identity_w[MAX_SIZE];
	wchar_t adapter_q[MAX_SIZE];
	wchar_t adapter_t[MAX_SIZE];
	wchar_t roam_name[MAX_SIZE];
	char pipe[MAX_SIZE];
	char dial[MAX_SIZE];
	char detail[MAX_SIZE];
	char what[MAX_SIZE];
	char *setting = ZeroMalloc(NODE_CLIENT_MAX_SETTING);
	UINT scope = 0;
	UINT r = Rand32() & 0xFFFF;

	ClientTestNewReport(&quic);
	ClientTestNewReport(&tls);
	ClientTestNewReport(&scratch);
	hs->Name = CLIENTTEST_NODE_S;
	hs->Report = &scratch;
	InitializeSRWLock(&hs->Lock);
	Zero(&key, sizeof(key));

	Format(identity, sizeof(identity), "Ranz clienttest %u", r);
	StrToUni(identity_w, sizeof(identity_w), identity);
	UniFormat(adapter_q, sizeof(adapter_q), L"RanzQ%04x", r);
	UniFormat(adapter_t, sizeof(adapter_t), L"RanzT%04x", r);
	UniFormat(roam_name, sizeof(roam_name), L"RanzR%04x", r);
	Format(pipe, sizeof(pipe), "ranz-clienttest-%u", r);

	// The certificate of node-s, which both transports of node-c pin
	StrCpy(thumbprint, sizeof(thumbprint), "");
	PCCERT_CONTEXT cert = CryptoCertCreateSelfSigned(CLIENTTEST_CN, CLIENTTEST_SAN, NULL, 30, scope);
	bool ok = ClientTestCheck(ctx, cert != NULL && CryptoCertThumbprintStr(cert, thumbprint, sizeof(thumbprint)) && CryptoCertAddToStore(cert, NULL, scope),
		"node-s: a self-signed ECDSA P-256 certificate in the My store, by its thumbprint", "CryptoCertCreateSelfSigned or the store failed");

	// The static key of node-c: its identity key in the key storage provider, which its role opens
	ok = ok && ClientTestCheck(ctx, PeerKeyOpen(&key, identity_w), "node-c: its identity key in the software key storage provider", "PeerKeyOpen failed");
	Copy(client_key, key.Public, PEER_KEY_SIZE);
	PeerKeyClose(&key);

	// node-s: its listener on QUIC and TLS-443, its static key and the fake host
	if (ok)
	{
		srv = ClientTestServerNew(thumbprint);
		Print("  [INFO] node-s listens on QUIC port %u (msquic.dll %s) and TLS port %u of 127.0.0.1\n", (UINT)srv->QuicPort,
			TransportQuicAvailable() ? "present" : "missing", (UINT)srv->TlsPort);
		ok = ClientTestCheck(ctx, srv->TlsListener != NULL && (srv->QuicListener != NULL || TransportQuicAvailable() == false),
			"node-s: its listeners on QUIC and TLS-443 on test ports of the loopback interface", "QUIC %u, TLS %u", (UINT)srv->QuicPort, (UINT)srv->TlsPort);
	}

	if (ok)
	{
		for (UINT i = 0;i < PEER_KEY_SIZE;i++)
		{
			scalar[i] = (UCHAR)(0x80 + i);
		}
		ok = PeerKeyFromScalar(&s->Key, scalar);
		Zero(scalar, sizeof(scalar));

		ClientTestNewDir(s->Dir, sizeof(s->Dir), "nodes", "none", NULL, NULL);
		s->Node = NewNode(s->Dir);
		NodeStart(s->Node);

		Zero(&cfg, sizeof(cfg));
		cfg.Data = &srv->Transport;
		cfg.Key = &s->Key;
		cfg.Adapter = ClientTestServerHost;
		cfg.AdapterParam = hs;
		ok = ok && NodeOverlayStart(s->Node, &cfg) && ClientTestApply(s, true, client_key);
		ClientTestCheck(ctx, ok, "node-s: its overlay runs on its listener and applies its state", "NodeOverlayStart or NodeOverlayApply failed");
	}

	// node-c with the client role over QUIC and TLS-443 (TLS-443 alone without msquic.dll)
	if (ok)
	{
		Print("[the client role over QUIC]\n");

		if (srv->QuicListener != NULL)
		{
			Format(dial, sizeof(dial), "quic:127.0.0.1:%u, tls:127.0.0.1:%u", (UINT)srv->QuicPort, (UINT)srv->TlsPort);
		}
		else
		{
			Format(dial, sizeof(dial), "tls:127.0.0.1:%u", (UINT)srv->TlsPort);
		}
		ClientTestSetting(setting, NODE_CLIENT_MAX_SETTING, adapter_q, pipe, thumbprint, dial);

		ClientTestNewDir(c->Dir, sizeof(c->Dir), "nodec", "client", identity, setting);
		c->Node = NewNode(c->Dir);
		NodeStart(c->Node);
		NodeClientGetStatus(c->Node, &cs);
		ok = ClientTestCheck(ctx, cs.Running && Cmp(cs.Key, client_key, PEER_KEY_SIZE) == 0,
			"node-c: the client role runs on its identity key, its Wintun adapters to come with the VRFs of its state (SDN-5)", "running %u", (UINT)cs.Running);
	}

	if (ok)
	{
		ok = ClientTestApply(c, false, s->Key.Public) && ClientTestWaitUp(c);
		NodeClientGetStatus(c->Node, &cs);
		ClientTestCheck(ctx, ok && cs.InterfaceIndex != 0, "node-c reaches node-s: the L3 network comes up on the Wintun adapter of VRF 1 with the address of node-c",
			"applied and up %u, interface %u, %I64u dials, transport %s", (UINT)ok, cs.InterfaceIndex, cs.NumDials, cs.Transport);
		Print("  [INFO] Wintun driver %u.%u, adapter interface %u\n", NodeWintunDriverVersion() >> 16, NodeWintunDriverVersion() & 0xFFFF, cs.InterfaceIndex);
		if (srv->QuicListener != NULL)
		{
			ClientTestCheck(ctx, StrCmp(cs.Transport, "quic") == 0, "node-c: QUIC wins the race of its fallback list", "transport %s", cs.Transport);
		}
	}

	if (ok)
	{
		ClientTestCheck(ctx, ClientTestRouteVia(cs.InterfaceLuid, clienttest_s, ClientTestAddr(100, 64, 0, 0), 10, detail, sizeof(detail)),
			"routes: Windows takes the adapter to 100.64.0.1, by the route of Network default 100.64.0.0/10 that the client role set", "%s", detail);
		ClientTestCheck(ctx, ClientTestRouteVia(cs.InterfaceLuid, clienttest_lan, ClientTestAddr(198, 18, 0, 0), 24, detail, sizeof(detail)),
			"routes: Windows takes the adapter to 198.18.0.1, by the route of Network lan 198.18.0.0/24 that the client role set", "%s", detail);
		ClientTestCheck(ctx, ClientTestDnsSet(cs.InterfaceIndex, detail, sizeof(detail)),
			"DNS: the adapter has the DNS server 100.64.0.1 and the suffix " CLIENTTEST_SUFFIX " of the Client setting", "%s", detail);

		InterlockedExchangePointer((PVOID volatile *)&hs->Report, &quic);
		ClientTestWintunFlows(&quic, cs.InterfaceIndex);
		InterlockedExchangePointer((PVOID volatile *)&hs->Report, &scratch);
		ClientTestCompare(ctx, &quic, out_dir, golden_dir, update, "QUIC");

		ClientTestUser(ctx, c);
		ClientTestSleep(ctx, c, srv);
		ClientTestRoam(ctx, c, srv, roam_name);
	}

	// The client role over TLS-443 when the QUIC entry of its fallback list reaches nothing: the role stops, its adapter
	// goes, and it starts again with the new setting
	if (ok)
	{
		Print("[the client role over TLS-443]\n");

		NodeClientGetStatus(c->Node, &cs);
		UINT64 luid = cs.InterfaceLuid;
		NodeSetRoles(c->Node, 0);
		ClientTestCheck(ctx, ClientTestAdapterGone(luid), "node-c: once the client role stopped, its Wintun adapter is gone", "interface LUID %I64u still there", luid);

		Format(dial, sizeof(dial), "quic:127.0.0.1:%u, tls:127.0.0.1:%u", (UINT)ClientTestDeadPort(), (UINT)srv->TlsPort);
		ClientTestSetting(setting, NODE_CLIENT_MAX_SETTING, adapter_t, pipe, thumbprint, dial);
		CsSetSetting(c->Node->Store, NODE_SETTING_CLIENT, setting);
		NodeSetRoles(c->Node, NODE_ROLE_CLIENT);

		ok = ClientTestApply(c, false, s->Key.Public) && ClientTestWaitUp(c);
		NodeClientGetStatus(c->Node, &cs);
		Format(what, sizeof(what), "node-c reaches node-s over TLS-443 when the QUIC entry of its fallback list reaches nothing");
		ClientTestCheck(ctx, ok && StrCmp(cs.Transport, "tls") == 0, what, "up %u, transport %s", (UINT)ok, cs.Transport);

		if (ok)
		{
			InterlockedExchangePointer((PVOID volatile *)&hs->Report, &tls);
			ClientTestWintunFlows(&tls, cs.InterfaceIndex);
			InterlockedExchangePointer((PVOID volatile *)&hs->Report, &scratch);
			ClientTestCompare(ctx, &tls, out_dir, golden_dir, update, "TLS-443");
		}

		luid = cs.InterfaceLuid;
		NodeStop(c->Node);
		ClientTestCheck(ctx, ClientTestAdapterGone(luid), "node-c: once the node stopped, its Wintun adapter is gone", "interface LUID %I64u still there", luid);
	}

	Print("  [INFO] packets of no test at node-s: %I64u\n", (UINT64)hs->Other);

	ClientTestFreeNode(c);
	ClientTestFreeNode(s);
	ClientTestServerFree(srv);
	PeerKeyDelete(identity_w);

	if (cert != NULL)
	{
		CryptoCertRemoveFromStore(thumbprint, NULL, scope);
		CryptoCertDeleteKey(cert);
		CryptoCertFree(cert);
	}

	FreeBuf(quic.Text);
	FreeBuf(tls.Text);
	FreeBuf(scratch.Text);
	Free(setting);
	Free(hs);
	Free(c);
	Free(s);
}

RANZ_TEST("client", client_test, "Client role: a node on a Wintun adapter reaches a server node over QUIC and TLS-443, sets routes and DNS, routes the runner's own packets as the oracle does (golden family client), is driven by the logged-in user through its pipe, and survives sleep and roaming (administrator rights, wintun.dll).");
void client_test(UINT num, char **arg)
{
	CLIENTTEST_CTX ctx;
	char out_dir[MAX_SIZE];
	char golden_dir[MAX_SIZE];
	bool update = false;
	UINT error = 0;
	HANDLE done = CreateEventW(NULL, TRUE, FALSE, NULL);
	HANDLE watchdog = (done != NULL ? CreateThread(NULL, 0, ClientTestWatchdog, done, 0, NULL) : NULL);

	Zero(&ctx, sizeof(ctx));

	Print("Client role test: node-c on a Wintun adapter reaches node-s over QUIC and TLS-443, routes, DNS, the logged-in user, sleep and roaming, against the oracle\n");

	clienttest_c = ClientTestAddr(100, 64, 0, 2);
	clienttest_s = ClientTestAddr(100, 64, 0, 1);
	clienttest_lan = ClientTestAddr(198, 18, 0, 1);
	clienttest_nowhere = ClientTestAddr(100, 64, 0, 9);
	clienttest_roam = ClientTestAddr(198, 51, 100, 7);

	HarnessGetFamilyDirs("client", out_dir, sizeof(out_dir), golden_dir, sizeof(golden_dir), &update);
	MakeDirEx(out_dir);
	Print("CLIENT GOLDEN MODE %s\n", update ? "update" : "compare");
	Print("  golden directory: %s\n", golden_dir);

	bool ready = ClientTestCheck(&ctx, CryptoInit(), "the crypto module of the new core runs on CNG", "CryptoInit failed");
	ready = ClientTestCheck(&ctx, NodeWintunAvailable(&error), "wintun.dll is next to vpntest and has the API of wintun.h", "error %u", error) && ready;

	if (ready)
	{
		ClientTestOracle(&ctx, out_dir, golden_dir, update);
		ClientTestWintun(&ctx, out_dir, golden_dir, update);
	}

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
		Print("CLIENT TEST OK\n");
	}
	else
	{
		Print("CLIENT TEST FAILED (%u of %u checks failed)\n", ctx.NumFailed, ctx.NumChecks);
	}
}
