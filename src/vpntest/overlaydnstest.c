// overlaydnstest.c
// Named overlay DNS test of vpntest ("overlaydns" command, SDN-11 #187)
//
// Overlay DNS of a node (Cedar/NodeDns.c; ADR-0028 decisions 6 to 8): a stub resolver answers the zone of each VRF on the
// node's addresses there, the addresses of the Wintun adapter of that VRF (Cedar/NodeVrfAdapter.c), and the NRPT of
// Windows sends the names under the suffix of each zone, and only those, to it. The host is the runner itself: the DNS
// client of Windows resolves the names (DnsQuery_W), as an application of a laptop does.
// - Two VRFs: node-c joins red (101) and blue (202) through its VRF adapters, with the states that the controller sends
//   (controller/internal/desired dns.go): red has the suffix red.ranz.internal and blue blue.ranz.internal, and the
//   record fileserver of each answers another host. node-s, a peer in both, answers by its name in each, and node-c by
//   its own. The local NRPT holds one rule per VRF, read back from the registry: the suffix as its namespace and the
//   address of node-c in the VRF as its DNS server. A query sent straight to the stub resolver of red is answered from
//   the zone of red and refuses a name of blue. Through the DNS client, fileserver.red.ranz.internal and
//   fileserver.blue.ranz.internal answer their two hosts, the names of the nodes answer their addresses in each VRF,
//   and a name under a suffix that the zone does not have is NXDOMAIN from the stub resolver. A name outside the
//   suffixes resolves through the host's own DNS, and the stub resolver sees no query for it.
// - 4via6: node-c's red and blue overlap, so the state gives node-c the 4via6 of each (ADR-0025 decision 4). The adapter
//   of each VRF holds the 4via6 address of node-c, the stub resolver listens there and the NRPT rule names it. The
//   record fileserver of both VRFs holds the same IPv4 address, and answers two different IPv6 addresses in AAAA
//   records, the 4via6 address of that IPv4 address in each VRF, and no A record.
// - Once the adapters of node-c are freed, its NRPT rules are gone.
// Print "OVERLAYDNS TEST OK" only when every check passes. Needs administrator rights and wintun.dll next to vpntest
// (.github/scripts/fetch-wintun.ps1).

#include "testlist.h"

#include "Cedar/ConfigStore.h"
#include "Cedar/Node.h"

#include "Mayaqua/Encrypt.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Kernel.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Tick64.h"

#include "Core/Control.h"

#include <windns.h>
#include <ws2tcpip.h>

#include <stdio.h>

#define	OVERLAYDNSTEST_BUDGET		240000		// The whole test ends within this time, or the watchdog ends the process (ms)
#define	OVERLAYDNSTEST_BOUND		30000		// A bounded wait on observable state (ms)
#define	OVERLAYDNSTEST_POLL			100			// Poll interval of observable state (ms)
#define	OVERLAYDNSTEST_ANSWER		2000		// An answer of the stub resolver comes within this (ms)
#define	OVERLAYDNSTEST_RED			101
#define	OVERLAYDNSTEST_BLUE			202
#define	OVERLAYDNSTEST_LENGTH		24			// The prefix length of the Networks of the test
#define	OVERLAYDNSTEST_NODE_C		"node-c"
#define	OVERLAYDNSTEST_NODE_S		"node-s"
#define	OVERLAYDNSTEST_OUTSIDE		L"github.com"	// A name outside the suffixes, which the DNS of the runner answers
#define	OVERLAYDNSTEST_NRPT			L"SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters\\DnsPolicyConfig"	// The local NRPT (MS-GPNRPT 2.2)
#define	OVERLAYDNSTEST_TYPE_A		1
#define	OVERLAYDNSTEST_TYPE_AAAA	28

typedef DNS_STATUS (WINAPI OVERLAYDNSTEST_QUERY)(PCWSTR name, WORD type, DWORD options, PVOID extra, PDNS_RECORDW *results, PVOID *reserved);
typedef VOID (WINAPI OVERLAYDNSTEST_FREE)(PVOID data, DNS_FREE_TYPE type);

// The checks of the test, and the DNS client of Windows
typedef struct OVERLAYDNSTEST_CTX
{
	UINT NumChecks;
	UINT NumFailed;
	HMODULE Dnsapi;						// dnsapi.dll
	OVERLAYDNSTEST_QUERY *Query;		// Its DnsQuery_W ...
	OVERLAYDNSTEST_FREE *Free;			// ... and DnsFree
	UINT Bound;							// ms that a name may take to resolve as wanted: OVERLAYDNSTEST_BOUND until one does not
} OVERLAYDNSTEST_CTX;

// What a query of the DNS client gave
typedef struct OVERLAYDNSTEST_ANSWERS
{
	DNS_STATUS Status;					// The status of DnsQuery_W
	UINT NumAddresses;					// The addresses of its A or AAAA records
	char Text[MAX_SIZE];				// ... as text, separated by spaces
} OVERLAYDNSTEST_ANSWERS;

static bool OverlayDnsTestCheck(OVERLAYDNSTEST_CTX *ctx, bool ok, char *what, char *fmt, ...) RANZ_PRINTF_FORMAT(4, 5);
static bool OverlayDnsTestCheck(OVERLAYDNSTEST_CTX *ctx, bool ok, char *what, char *fmt, ...)
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

// The watchdog: a native thread that ends a run that hangs, so that a lost answer is a failed test instead of a hung
// CI step
static DWORD WINAPI OverlayDnsTestWatchdog(LPVOID param)
{
	char msg[MAX_SIZE];
	DWORD written = 0;

	if (WaitForSingleObject((HANDLE)param, OVERLAYDNSTEST_BUDGET) != WAIT_TIMEOUT)
	{
		return 0;
	}

	int len = snprintf(msg, sizeof(msg), "OVERLAYDNS TEST FAILED (did not finish within %u ms)\n", OVERLAYDNSTEST_BUDGET);
	if (len > 0)
	{
		WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), msg, (DWORD)MIN((UINT)len, (UINT)sizeof(msg) - 1), &written, NULL);
	}

	TerminateProcess(GetCurrentProcess(), 1);

	return 0;
}

// An IPv4 address of four bytes into a
static void OverlayDnsTestV4(UCHAR *a, UCHAR b0, UCHAR b1, UCHAR b2, UCHAR b3)
{
	a[0] = b0;
	a[1] = b1;
	a[2] = b2;
	a[3] = b3;
}

// The 4via6 address of the IPv4 address v4 in the VRF vrf_id, the /96 itself for v4 NULL: the /96 at the start of the
// 4via6 /64 of the ULA of the VRF, fd00:101::/48 for red and fd00:202::/48 for blue, with v4 in its last 32 bits
// (ADR-0025 decision 4)
static void OverlayDnsTestVia6(UCHAR *a, UINT vrf_id, const UCHAR *v4)
{
	Zero(a, 16);
	InetPtonW(AF_INET6, vrf_id == OVERLAYDNSTEST_RED ? L"fd00:101:0:ffff::" : L"fd00:202:0:ffff::", a);
	if (v4 != NULL)
	{
		Copy(a + 12, v4, 4);
	}
}

// An address as text
static void OverlayDnsTestText(char *text, UINT size, const UCHAR *addr, UINT addr_size)
{
	wchar_t w[INET6_ADDRSTRLEN];

	if (InetNtopW(addr_size == 4 ? AF_INET : AF_INET6, addr, w, INET6_ADDRSTRLEN) == NULL)
	{
		StrCpy(text, size, "?");
		return;
	}

	UniToStr(text, size, w);
}

//
// The states of the test, as the control stream hands them over
//

// The address addr (size bytes) of a node in the Network network of the VRF vrf_id
static void OverlayDnsTestAddress(CONTROL_ADDRESS *a, char *network, UINT vrf_id, const UCHAR *addr)
{
	Zero(a, sizeof(CONTROL_ADDRESS));
	StrCpy(a->Network, sizeof(a->Network), network);
	a->VrfId = vrf_id;
	Copy(a->Address, addr, 4);
	a->AddressSize = 4;
	a->Length = OVERLAYDNSTEST_LENGTH;
}

// The zone of a VRF: its suffix and the record fileserver with the num addresses of addrs (sizes: their sizes)
static void OverlayDnsTestZone(CONTROL_DNS_ZONE *z, char *suffix, UCHAR (*addrs)[16], const UINT *sizes, UINT num)
{
	Zero(z, sizeof(CONTROL_DNS_ZONE));
	StrCpy(z->Suffix, sizeof(z->Suffix), suffix);
	StrCpy(z->Records[0].Name, sizeof(z->Records[0].Name), "fileserver");
	for (UINT i = 0;i < num;i++)
	{
		Copy(z->Records[0].Addresses[i], addrs[i], sizes[i]);
		z->Records[0].AddressSizes[i] = sizes[i];
	}
	z->Records[0].NumAddresses = num;
	z->NumRecords = 1;
}

// The state of node-c at generation in red and blue, as the controller sends it (ordered by Network name, then VRF
// name): its addresses c_red and c_blue, the zones red and blue, node-s at s_red and s_blue as its peer, and with
// via6 the 4via6 of both VRFs
static void OverlayDnsTestState(CONTROL_STATE *st, CONTROL_PEER *peer, UINT64 generation, const UCHAR *c_red, const UCHAR *c_blue, const UCHAR *s_red, const UCHAR *s_blue,
	CONTROL_DNS_ZONE *red, CONTROL_DNS_ZONE *blue, const UCHAR *s_key, bool via6)
{
	Zero(st, sizeof(CONTROL_STATE));
	Zero(peer, sizeof(CONTROL_PEER));

	st->Generation = generation;
	StrCpy(st->Name, sizeof(st->Name), OVERLAYDNSTEST_NODE_C);
	OverlayDnsTestAddress(&st->Addresses[0], "blue-lan", OVERLAYDNSTEST_BLUE, c_blue);
	OverlayDnsTestAddress(&st->Addresses[1], "red-lan", OVERLAYDNSTEST_RED, c_red);
	st->NumAddresses = 2;

	StrCpy(st->Vrfs[0].Name, sizeof(st->Vrfs[0].Name), "blue");
	st->Vrfs[0].Id = OVERLAYDNSTEST_BLUE;
	st->Vrfs[0].Dns = blue;
	StrCpy(st->Vrfs[1].Name, sizeof(st->Vrfs[1].Name), "red");
	st->Vrfs[1].Id = OVERLAYDNSTEST_RED;
	st->Vrfs[1].Dns = red;
	st->NumVrfs = 2;

	if (via6)
	{
		for (UINT i = 0;i < 2;i++)
		{
			CONTROL_NAT *n = &st->Nats[i];
			UINT vrf = (i == 0 ? OVERLAYDNSTEST_RED : OVERLAYDNSTEST_BLUE);

			n->VrfId = vrf;
			OverlayDnsTestVia6(n->Inside, vrf, NULL);
			n->InsideSize = 16;
			n->InsideLength = 96;
			n->OutsideSize = 4;
			n->OutsideLength = 0;
		}
		st->NumNats = 2;
	}

	StrCpy(peer->Name, sizeof(peer->Name), OVERLAYDNSTEST_NODE_S);
	Copy(peer->Key, s_key, PEER_KEY_SIZE);
	peer->VrfIds[0] = OVERLAYDNSTEST_RED;
	peer->VrfIds[1] = OVERLAYDNSTEST_BLUE;
	peer->NumVrfs = 2;
	OverlayDnsTestAddress(&peer->Addresses[0], "blue-lan", OVERLAYDNSTEST_BLUE, s_blue);
	OverlayDnsTestAddress(&peer->Addresses[1], "red-lan", OVERLAYDNSTEST_RED, s_red);
	peer->NumAddresses = 2;
	st->NumPeers = 1;
	st->Peers = peer;
}

//
// What Windows holds and answers
//

// Whether the local NRPT holds the rule of the VRF vrf_id of the node of the static key key, with the namespace
// .<suffix> and the DNS servers servers; detail says what it holds
static bool OverlayDnsTestRule(const UCHAR *key, UINT vrf_id, char *suffix, char *servers, char *detail, UINT detail_size)
{
	wchar_t rule[NODE_DNS_RULE_NAME_SIZE];
	wchar_t path[MAX_PATH];
	wchar_t names[MAX_SIZE];
	wchar_t got[MAX_SIZE];
	char names_a[MAX_SIZE];
	char got_a[MAX_SIZE];
	char want[MAX_SIZE];
	DWORD size = sizeof(names);
	DWORD version = 0;
	DWORD version_size = sizeof(version);

	NodeDnsRuleName(rule, sizeof(rule), key, vrf_id);
	UniFormat(path, sizeof(path), L"%s\\%s", OVERLAYDNSTEST_NRPT, rule);
	Zero(names, sizeof(names));
	Zero(got, sizeof(got));

	LSTATUS err = RegGetValueW(HKEY_LOCAL_MACHINE, path, L"Name", RRF_RT_REG_MULTI_SZ, NULL, names, &size);
	if (err == ERROR_SUCCESS)
	{
		size = sizeof(got);
		err = RegGetValueW(HKEY_LOCAL_MACHINE, path, L"GenericDNSServers", RRF_RT_REG_SZ, NULL, got, &size);
	}
	if (err == ERROR_SUCCESS)
	{
		err = RegGetValueW(HKEY_LOCAL_MACHINE, path, L"Version", RRF_RT_REG_DWORD, NULL, &version, &version_size);
	}
	if (err != ERROR_SUCCESS)
	{
		Format(detail, detail_size, "the key %S has no rule (error %u)", rule, (UINT)err);
		return false;
	}

	UniToStr(names_a, sizeof(names_a), names);
	UniToStr(got_a, sizeof(got_a), got);
	Format(want, sizeof(want), ".%s", suffix);
	Format(detail, detail_size, "the key %S: Name %s, GenericDNSServers %s, Version %u", rule, names_a, got_a, (UINT)version);

	return (StrCmp(names_a, want) == 0 && StrCmp(got_a, servers) == 0);
}

// Whether the local NRPT holds no rule of the VRF vrf_id of the node of the static key key
static bool OverlayDnsTestNoRule(const UCHAR *key, UINT vrf_id)
{
	wchar_t rule[NODE_DNS_RULE_NAME_SIZE];
	wchar_t path[MAX_PATH];
	HKEY h = NULL;

	NodeDnsRuleName(rule, sizeof(rule), key, vrf_id);
	UniFormat(path, sizeof(path), L"%s\\%s", OVERLAYDNSTEST_NRPT, rule);
	if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_READ, &h) != ERROR_SUCCESS)
	{
		return true;
	}

	RegCloseKey(h);
	return false;
}

// Ask the DNS client of Windows for name of type type, past its cache: the addresses of the answer of that type
static void OverlayDnsTestResolve(OVERLAYDNSTEST_CTX *ctx, wchar_t *name, WORD type, OVERLAYDNSTEST_ANSWERS *a)
{
	PDNS_RECORDW records = NULL;

	Zero(a, sizeof(OVERLAYDNSTEST_ANSWERS));
	a->Status = ctx->Query(name, type, DNS_QUERY_BYPASS_CACHE, NULL, &records, NULL);

	for (PDNS_RECORDW r = (a->Status == 0 ? records : NULL);r != NULL;r = r->pNext)
	{
		char text[MAX_SIZE];

		if (r->wType != type || (type != OVERLAYDNSTEST_TYPE_A && type != OVERLAYDNSTEST_TYPE_AAAA))
		{
			continue;
		}

		if (type == OVERLAYDNSTEST_TYPE_A)
		{
			OverlayDnsTestText(text, sizeof(text), (const UCHAR *)&r->Data.A.IpAddress, 4);
		}
		else
		{
			OverlayDnsTestText(text, sizeof(text), (const UCHAR *)&r->Data.AAAA.Ip6Address, 16);
		}

		if (a->NumAddresses != 0)
		{
			StrCat(a->Text, sizeof(a->Text), " ");
		}
		StrCat(a->Text, sizeof(a->Text), text);
		a->NumAddresses++;
	}

	if (records != NULL)
	{
		ctx->Free(records, DnsFreeRecordList);
	}
}

// Whether the DNS client of Windows answers name with exactly the addresses want (as text, separated by spaces) within
// ctx->Bound: the NRPT takes a changed rule a moment after the node wrote it. After a name that does not resolve as
// wanted, the next ones get OVERLAYDNSTEST_ANSWER, so a run whose NRPT does not work fails within the budget.
static bool OverlayDnsTestResolves(OVERLAYDNSTEST_CTX *ctx, wchar_t *name, WORD type, char *want, char *detail, UINT detail_size)
{
	OVERLAYDNSTEST_ANSWERS a;

	Zero(&a, sizeof(a));
	for (UINT64 end = Tick64() + ctx->Bound;Tick64() < end;SleepThread(OVERLAYDNSTEST_POLL * 5))
	{
		OverlayDnsTestResolve(ctx, name, type, &a);
		if (a.Status == 0 && StrCmp(a.Text, want) == 0)
		{
			Format(detail, detail_size, "%s", a.Text);
			return true;
		}
	}

	ctx->Bound = OVERLAYDNSTEST_ANSWER;
	Format(detail, detail_size, "status %d, addresses \"%s\", want \"%s\"", (int)a.Status, a.Text, want);
	return false;
}

// Ask the stub resolver at the IPv4 address addr for name of type A, straight to its socket, past the DNS client and its
// NRPT: the RCODE of the answer, and the address of its first A record as text into first. False when no answer came.
static bool OverlayDnsTestAsk(const UCHAR *addr, char *name, UINT *rcode, char *first, UINT first_size)
{
	UCHAR q[NODE_DNS_MAX_ANSWER];
	UCHAR r[NODE_DNS_MAX_ANSWER];
	SOCKADDR_IN sa;
	DWORD timeout = OVERLAYDNSTEST_ANSWER;
	UINT size = 12;

	*rcode = 0;
	StrCpy(first, first_size, "");

	// The header: id 0x5244, RD, one question; then the labels of the name, type A, class IN
	Zero(q, sizeof(q));
	q[0] = 0x52;
	q[1] = 0x44;
	q[2] = 0x01;
	q[5] = 1;
	TOKEN_LIST *t = ParseToken(name, ".");
	for (UINT i = 0;i < t->NumTokens && size + 2 + StrLen(t->Token[i]) < sizeof(q) - 4;i++)
	{
		UINT n = StrLen(t->Token[i]);

		q[size++] = (UCHAR)n;
		Copy(q + size, t->Token[i], n);
		size += n;
	}
	FreeToken(t);
	q[size++] = 0;
	q[size++] = 0;
	q[size++] = OVERLAYDNSTEST_TYPE_A;
	q[size++] = 0;
	q[size++] = 1;
	UINT question = size;

	Zero(&sa, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(NODE_DNS_PORT);
	Copy(&sa.sin_addr, addr, 4);

	SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (s == INVALID_SOCKET)
	{
		return false;
	}

	setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));
	int got = -1;
	if (sendto(s, (const char *)q, (int)size, 0, (const SOCKADDR *)&sa, sizeof(sa)) == (int)size)
	{
		got = recv(s, (char *)r, (int)sizeof(r), 0);
	}
	closesocket(s);

	if (got < 12 || r[0] != 0x52 || r[1] != 0x44 || (r[2] & 0x80) == 0)
	{
		return false;
	}

	*rcode = r[3] & 0x0F;

	// The first answer after the question: the name as a pointer, the type, the class, the TTL, the size of the data
	if (READ_USHORT(r + 6) != 0 && (UINT)got >= question + 16 && READ_USHORT(r + question + 2) == OVERLAYDNSTEST_TYPE_A && READ_USHORT(r + question + 10) == 4)
	{
		OverlayDnsTestText(first, first_size, r + question + 12, 4);
	}

	return true;
}

// Wait until the stub resolver listens on want addresses, of num_zones zones, and the node wrote num_zones NRPT rules
static bool OverlayDnsTestReady(NODE_DNS *dns, UINT num_zones, UINT want, NODE_DNS_STATUS *st)
{
	for (UINT64 end = Tick64() + OVERLAYDNSTEST_BOUND;Tick64() < end;SleepThread(OVERLAYDNSTEST_POLL))
	{
		NodeDnsGetStatus(dns, st);
		if (st->Ready && st->NumZones == num_zones && st->NumAddresses == want && st->NumRules == num_zones)
		{
			return true;
		}
	}

	return false;
}

//
// The parts of the test
//

// The lines of the node log in a data directory that tell about overlay DNS and the adapters, for a part that failed
static void OverlayDnsTestPrintLog(wchar_t *dir)
{
	wchar_t log_dir[MAX_PATH];

	ConbinePathW(log_dir, sizeof(log_dir), dir, NODE_LOG_DIR_NAME);
	DIRLIST *d = EnumDirW(log_dir);

	for (UINT i = 0;d != NULL && i < d->NumFiles;i++)
	{
		DIRENT *e = d->File[i];
		wchar_t path[MAX_PATH];

		if (e->Folder)
		{
			continue;
		}

		ConbinePathW(path, sizeof(path), log_dir, e->FileNameW);
		BUF *b = ReadDumpW(path);
		if (b == NULL)
		{
			continue;
		}

		char *text = ZeroMalloc(b->Size + 1);
		Copy(text, b->Buf, b->Size);
		TOKEN_LIST *t = ParseToken(text, "\r\n");
		for (UINT j = 0;j < t->NumTokens;j++)
		{
			if (InStr(t->Token[j], "DNS:") || InStr(t->Token[j], "VRF adapters") || InStr(t->Token[j], "Wintun"))
			{
				Print("  [LOG] %s\n", t->Token[j]);
			}
		}
		FreeToken(t);
		Free(text);
		FreeBuf(b);
	}

	FreeDir(d);
}

// Delete the files of a directory, then the directory (it holds no subdirectory)
static void OverlayDnsTestDeleteDir(wchar_t *dir)
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

// Two VRFs: the zones of red and blue on their adapters, through the stub resolver and through the NRPT
static bool OverlayDnsTestTwoVrfs(OVERLAYDNSTEST_CTX *ctx, NODE_VRF_ADAPTERS *set, const UCHAR *c_key, const UCHAR *s_key)
{
	UCHAR c_red[4], c_blue[4], s_red[4], s_blue[4];
	UCHAR files[2][16];
	UINT sizes[2] = {4, 16};
	char detail[MAX_SIZE * 2];
	char first[MAX_SIZE];
	NODE_DNS_STATUS st;
	UINT rcode = 0;
	CONTROL_STATE *state = ZeroMalloc(sizeof(CONTROL_STATE));
	CONTROL_PEER *peer = ZeroMalloc(sizeof(CONTROL_PEER));
	CONTROL_DNS_ZONE *red = ZeroMalloc(sizeof(CONTROL_DNS_ZONE));
	CONTROL_DNS_ZONE *blue = ZeroMalloc(sizeof(CONTROL_DNS_ZONE));
	NODE_DNS *dns = NodeVrfAdaptersDns(set);
	UINT failed = ctx->NumFailed;

	Zero(&st, sizeof(st));
	Print("[two VRFs: the zones of red and blue on their adapters]\n");

	OverlayDnsTestV4(c_red, 198, 18, 101, 2);
	OverlayDnsTestV4(c_blue, 198, 18, 202, 2);
	OverlayDnsTestV4(s_red, 198, 18, 101, 1);
	OverlayDnsTestV4(s_blue, 198, 18, 202, 1);

	// fileserver of red is 198.18.101.10, fileserver of blue 198.18.202.20 and fd00:202::20
	Zero(files, sizeof(files));
	OverlayDnsTestV4(files[0], 198, 18, 101, 10);
	OverlayDnsTestZone(red, "red.ranz.internal", files, sizes, 1);
	OverlayDnsTestV4(files[0], 198, 18, 202, 20);
	InetPtonW(AF_INET6, L"fd00:202::20", files[1]);
	OverlayDnsTestZone(blue, "blue.ranz.internal", files, sizes, 2);

	OverlayDnsTestState(state, peer, 1, c_red, c_blue, s_red, s_blue, red, blue, s_key, false);
	bool ok = OverlayDnsTestCheck(ctx, NodeVrfAdaptersApply(set, state), "node-c applies its state in red (101) and blue (202): an adapter per VRF with its address",
		"NodeVrfAdaptersApply failed");
	ok = OverlayDnsTestCheck(ctx, ok && OverlayDnsTestReady(dns, 2, 2, &st),
		"the stub resolver listens on the address of node-c in each VRF, and the node wrote an NRPT rule per zone",
		"zones %u, addresses %u, listening %u, ready %u, rules %u, last bind error %u", st.NumZones, st.NumAddresses, st.NumListening, (UINT)st.Ready, st.NumRules,
		st.LastBindError) && ok;

	if (ok)
	{
		OverlayDnsTestCheck(ctx, OverlayDnsTestRule(c_key, OVERLAYDNSTEST_RED, "red.ranz.internal", "198.18.101.2", detail, sizeof(detail)),
			"the local NRPT sends .red.ranz.internal to the address of node-c in red", "%s", detail);
		OverlayDnsTestCheck(ctx, OverlayDnsTestRule(c_key, OVERLAYDNSTEST_BLUE, "blue.ranz.internal", "198.18.202.2", detail, sizeof(detail)),
			"the local NRPT sends .blue.ranz.internal to the address of node-c in blue", "%s", detail);

		// Straight to the stub resolver of red, past the NRPT
		bool asked = OverlayDnsTestAsk(c_red, "fileserver.red.ranz.internal", &rcode, first, sizeof(first));
		OverlayDnsTestCheck(ctx, asked && rcode == NODE_DNS_RCODE_NOERROR && StrCmp(first, "198.18.101.10") == 0,
			"straight to its socket, the stub resolver of red answers fileserver.red.ranz.internal from the zone of red", "answered %u, rcode %u, address %s", (UINT)asked,
			rcode, first);
		asked = OverlayDnsTestAsk(c_red, "fileserver.blue.ranz.internal", &rcode, first, sizeof(first));
		OverlayDnsTestCheck(ctx, asked && rcode == NODE_DNS_RCODE_REFUSED, "the stub resolver of red refuses fileserver.blue.ranz.internal, a name outside its suffix",
			"answered %u, rcode %u", (UINT)asked, rcode);
		NodeDnsGetStatus(dns, &st);
		UINT64 refused = st.Refused;

		// Through the DNS client of Windows and its NRPT
		OverlayDnsTestCheck(ctx, OverlayDnsTestResolves(ctx, L"fileserver.red.ranz.internal", OVERLAYDNSTEST_TYPE_A, "198.18.101.10", detail, sizeof(detail)),
			"the DNS client resolves fileserver.red.ranz.internal to the host of red", "%s", detail);
		OverlayDnsTestCheck(ctx, OverlayDnsTestResolves(ctx, L"fileserver.blue.ranz.internal", OVERLAYDNSTEST_TYPE_A, "198.18.202.20", detail, sizeof(detail)),
			"the same name resolves to another host in blue: fileserver.blue.ranz.internal is the host of blue", "%s", detail);
		OverlayDnsTestCheck(ctx, OverlayDnsTestResolves(ctx, L"fileserver.blue.ranz.internal", OVERLAYDNSTEST_TYPE_AAAA, "fd00:202::20", detail, sizeof(detail)),
			"fileserver.blue.ranz.internal answers its IPv6 address in an AAAA record", "%s", detail);
		OverlayDnsTestCheck(ctx, OverlayDnsTestResolves(ctx, L"node-s.red.ranz.internal", OVERLAYDNSTEST_TYPE_A, "198.18.101.1", detail, sizeof(detail)) &&
			OverlayDnsTestResolves(ctx, L"node-s.blue.ranz.internal", OVERLAYDNSTEST_TYPE_A, "198.18.202.1", detail, sizeof(detail)),
			"the name of the peer node-s answers its address in each VRF", "%s", detail);
		OverlayDnsTestCheck(ctx, OverlayDnsTestResolves(ctx, L"NODE-C.Red.Ranz.Internal", OVERLAYDNSTEST_TYPE_A, "198.18.101.2", detail, sizeof(detail)),
			"node-c answers by its own name, in any case of the letters", "%s", detail);

		NodeDnsGetStatus(dns, &st);
		UINT64 name_errors = st.NameErrors;
		OVERLAYDNSTEST_ANSWERS a;
		OverlayDnsTestResolve(ctx, L"nothing.red.ranz.internal", OVERLAYDNSTEST_TYPE_A, &a);
		NodeDnsGetStatus(dns, &st);
		OverlayDnsTestCheck(ctx, a.Status == DNS_ERROR_RCODE_NAME_ERROR && st.NameErrors > name_errors,
			"nothing.red.ranz.internal, under the suffix of red but no name of its zone, is NXDOMAIN from the stub resolver", "status %d, NXDOMAIN of the stub resolver %I64u to %I64u",
			(int)a.Status, name_errors, st.NameErrors);

		// A name outside the suffixes goes to the host's own DNS, and never reaches the stub resolver
		bool outside = false;
		for (UINT64 end = Tick64() + OVERLAYDNSTEST_BOUND;Tick64() < end && outside == false;SleepThread(OVERLAYDNSTEST_POLL * 5))
		{
			OverlayDnsTestResolve(ctx, OVERLAYDNSTEST_OUTSIDE, OVERLAYDNSTEST_TYPE_A, &a);
			outside = (a.Status == 0 && a.NumAddresses != 0);
		}
		NodeDnsGetStatus(dns, &st);
		Print("  [INFO] %S: %s\n", OVERLAYDNSTEST_OUTSIDE, a.Text);
		OverlayDnsTestCheck(ctx, outside && st.Refused == refused,
			"github.com, outside the suffixes, resolves through the host's own DNS, and the stub resolver sees no query outside its suffixes",
			"status %d, %u addresses, queries refused by the stub resolver %I64u to %I64u", (int)a.Status, a.NumAddresses, refused, st.Refused);

		Print("  [INFO] the stub resolver: %I64u queries answered, %I64u of them NXDOMAIN, %I64u refused, %I64u dropped\n", st.Queries, st.NameErrors, st.Refused, st.Dropped);
	}

	Free(state);
	Free(peer);
	Free(red);
	Free(blue);

	return ctx->NumFailed == failed;
}

// 4via6: red and blue overlap, so node-c reaches each through its 4via6, and the same IPv4 address of fileserver in both
// answers two IPv6 addresses
static bool OverlayDnsTestVia6Vrfs(OVERLAYDNSTEST_CTX *ctx, NODE_VRF_ADAPTERS *set, const UCHAR *c_key, const UCHAR *s_key)
{
	UCHAR c_red[4], c_blue[4], s_both[4];
	UCHAR files[1][16];
	UCHAR mapped[16];
	UINT sizes[1] = {4};
	char want[MAX_SIZE];
	char detail[MAX_SIZE * 2];
	NODE_DNS_STATUS st;
	CONTROL_STATE *state = ZeroMalloc(sizeof(CONTROL_STATE));
	CONTROL_PEER *peer = ZeroMalloc(sizeof(CONTROL_PEER));
	CONTROL_DNS_ZONE *red = ZeroMalloc(sizeof(CONTROL_DNS_ZONE));
	CONTROL_DNS_ZONE *blue = ZeroMalloc(sizeof(CONTROL_DNS_ZONE));
	NODE_DNS *dns = NodeVrfAdaptersDns(set);
	UINT failed = ctx->NumFailed;

	Zero(&st, sizeof(st));
	Print("[4via6: red and blue overlap]\n");

	// 198.18.77.0/24 in both VRFs: node-c is .2 in red and .3 in blue, node-s .1 in both, fileserver .10 in both
	OverlayDnsTestV4(c_red, 198, 18, 77, 2);
	OverlayDnsTestV4(c_blue, 198, 18, 77, 3);
	OverlayDnsTestV4(s_both, 198, 18, 77, 1);
	Zero(files, sizeof(files));
	OverlayDnsTestV4(files[0], 198, 18, 77, 10);
	OverlayDnsTestZone(red, "red.ranz.internal", files, sizes, 1);
	OverlayDnsTestZone(blue, "blue.ranz.internal", files, sizes, 1);

	OverlayDnsTestState(state, peer, 2, c_red, c_blue, s_both, s_both, red, blue, s_key, true);
	bool ok = OverlayDnsTestCheck(ctx, NodeVrfAdaptersApply(set, state), "node-c applies its state with the 4via6 of red and of blue", "NodeVrfAdaptersApply failed");
	ok = OverlayDnsTestCheck(ctx, ok && OverlayDnsTestReady(dns, 2, 2, &st), "the stub resolver listens on the 4via6 address of node-c in each VRF",
		"zones %u, addresses %u, listening %u, ready %u, rules %u, last bind error %u", st.NumZones, st.NumAddresses, st.NumListening, (UINT)st.Ready, st.NumRules,
		st.LastBindError) && ok;

	for (UINT i = 0;ok && i < 2;i++)
	{
		UINT vrf = (i == 0 ? OVERLAYDNSTEST_RED : OVERLAYDNSTEST_BLUE);
		char *suffix = (i == 0 ? "red.ranz.internal" : "blue.ranz.internal");
		wchar_t name[MAX_SIZE];
		char what[MAX_SIZE];

		OverlayDnsTestVia6(mapped, vrf, i == 0 ? c_red : c_blue);
		OverlayDnsTestText(want, sizeof(want), mapped, 16);
		Format(what, sizeof(what), "the NRPT sends .%s to the 4via6 address %s of node-c", suffix, want);
		OverlayDnsTestCheck(ctx, OverlayDnsTestRule(c_key, vrf, suffix, want, detail, sizeof(detail)), what, "%s", detail);

		OverlayDnsTestVia6(mapped, vrf, files[0]);
		OverlayDnsTestText(want, sizeof(want), mapped, 16);
		UniFormat(name, sizeof(name), L"fileserver.%S", suffix);
		Format(what, sizeof(what), "fileserver.%s, 198.18.77.10 of the VRF, answers its 4via6 address %s in an AAAA record", suffix, want);
		OverlayDnsTestCheck(ctx, OverlayDnsTestResolves(ctx, name, OVERLAYDNSTEST_TYPE_AAAA, want, detail, sizeof(detail)), what, "%s", detail);

		OVERLAYDNSTEST_ANSWERS a;
		OverlayDnsTestResolve(ctx, name, OVERLAYDNSTEST_TYPE_A, &a);
		Format(what, sizeof(what), "fileserver.%s has no A record: the host reaches the IPv4 of the VRF through 4via6", suffix);
		OverlayDnsTestCheck(ctx, a.NumAddresses == 0, what, "status %d, addresses %s", (int)a.Status, a.Text);
	}

	Free(state);
	Free(peer);
	Free(red);
	Free(blue);

	return ctx->NumFailed == failed;
}

static void OverlayDnsTestRun(OVERLAYDNSTEST_CTX *ctx)
{
	NODE *c = NULL;
	wchar_t dir[MAX_PATH];
	wchar_t tmp[MAX_PATH];
	wchar_t store_path[MAX_PATH];
	wchar_t name[MAX_SIZE];
	UCHAR c_key[PEER_KEY_SIZE];
	UCHAR s_key[PEER_KEY_SIZE];

	// node-c: a node with no role, whose adapters of the VRFs take the states of the test; random keys, so the adapters
	// and the NRPT rules of a run are its own
	Rand(c_key, sizeof(c_key));
	Rand(s_key, sizeof(s_key));
	UniFormat(name, sizeof(name), L"RanzD%04x", Rand32() & 0xFFFF);
	UniFormat(tmp, sizeof(tmp), L"overlaydnstest_%u", Rand32());
	ConbinePathW(dir, sizeof(dir), MsGetMyTempDirW(), tmp);
	MakeDirExW(dir);
	ConbinePathW(store_path, sizeof(store_path), dir, CS_FILE_NAME);
	CONFIG_STORE *store = CsOpen(store_path);
	if (store != NULL)
	{
		CsSetSetting(store, NODE_SETTING_ROLES, "none");
		CsSetSetting(store, NODE_SETTING_WORKERS, "1");
		CsClose(store);
	}

	c = NewNode(dir);
	NodeStart(c);
	NODE_VRF_ADAPTERS *set = NodeVrfAdaptersNew(c, name, c_key, false);
	bool ok = OverlayDnsTestCheck(ctx, set != NULL && NodeVrfAdaptersDns(set) != NULL, "node-c: its adapters of the VRFs and its overlay DNS",
		"NodeVrfAdaptersNew or NodeDnsNew failed");

	if (ok)
	{
		ok = OverlayDnsTestTwoVrfs(ctx, set, c_key, s_key);
		ok = OverlayDnsTestVia6Vrfs(ctx, set, c_key, s_key) && ok;
	}

	if (set != NULL)
	{
		NodeVrfAdaptersFree(set);
		OverlayDnsTestCheck(ctx, OverlayDnsTestNoRule(c_key, OVERLAYDNSTEST_RED) && OverlayDnsTestNoRule(c_key, OVERLAYDNSTEST_BLUE),
			"once the adapters of node-c are freed, its NRPT rules are gone", "a rule is still in the local NRPT");
	}

	NodeStop(c);
	FreeNode(c);
	if (ok == false)
	{
		OverlayDnsTestPrintLog(dir);
	}

	ConbinePathW(tmp, sizeof(tmp), dir, NODE_LOG_DIR_NAME);
	OverlayDnsTestDeleteDir(tmp);
	OverlayDnsTestDeleteDir(dir);
}

// overlaydns: the stub resolver of overlay DNS and the NRPT (SDN-11)
RANZ_TEST("overlaydns", overlaydns_test, "Overlay DNS: a stub resolver answers the zone of each VRF on the node's addresses there, the NRPT sends only the suffix of each zone to it, the same name answers another host in each VRF, names outside the suffixes go to the host's own DNS, and a VRF of 4via6 answers AAAA records (administrator rights, wintun.dll).");
void overlaydns_test(UINT num, char **arg)
{
	OVERLAYDNSTEST_CTX ctx;
	UINT error = 0;
	HANDLE done = CreateEventW(NULL, TRUE, FALSE, NULL);
	HANDLE watchdog = (done != NULL ? CreateThread(NULL, 0, OverlayDnsTestWatchdog, done, 0, NULL) : NULL);

	Zero(&ctx, sizeof(ctx));
	ctx.Bound = OVERLAYDNSTEST_BOUND;

	Print("Overlay DNS test: the stub resolver of each VRF on the node's addresses there, and the NRPT that sends only the overlay suffixes to it\n");

	ctx.Dnsapi = LoadLibraryExW(L"dnsapi.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
	ctx.Query = (ctx.Dnsapi != NULL ? (OVERLAYDNSTEST_QUERY *)(void *)GetProcAddress(ctx.Dnsapi, "DnsQuery_W") : NULL);
	ctx.Free = (ctx.Dnsapi != NULL ? (OVERLAYDNSTEST_FREE *)(void *)GetProcAddress(ctx.Dnsapi, "DnsFree") : NULL);

	bool ready = OverlayDnsTestCheck(&ctx, ctx.Query != NULL && ctx.Free != NULL, "the DNS client of Windows: DnsQuery_W and DnsFree of dnsapi.dll", "error %u",
		(UINT)GetLastError());
	ready = OverlayDnsTestCheck(&ctx, NodeWintunAvailable(&error), "wintun.dll is next to vpntest and has the API of wintun.h", "error %u", error) && ready;

	if (ready)
	{
		OverlayDnsTestRun(&ctx);
	}

	if (ctx.Dnsapi != NULL)
	{
		FreeLibrary(ctx.Dnsapi);
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
		Print("OVERLAYDNS TEST OK\n");
	}
	else
	{
		Print("OVERLAYDNS TEST FAILED (%u of %u checks failed)\n", ctx.NumFailed, ctx.NumChecks);
	}
}
