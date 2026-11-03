// vrfadaptertest.c
// Named VRF adapter test of vpntest ("vrfadapter" command, SDN-5 #181)
//
// One Wintun adapter per VRF that a node joins (Cedar/NodeVrfAdapter.c), with a fixed requested GUID, kept across a
// tunnel restart with its routes, and the forwarding of a gateway or an exit. The host is the runner itself: its own IP
// stack sends into the adapters, as an application of a laptop does.
// - Two VRFs on Wintun: node-c joins red (101) and blue (202), and node-s, whose fake host answers the ICMP echo
//   requests to its addresses, joins both too; the two nodes run on the in-process loopback transport (the path of
//   SDN-3 and SDN-4). node-c shows two adapters. Windows gives each interface the GUID of node-c's static key and its
//   VRF, which the test derives on its own (ADR-0025 decision 3), so a change of the derivation, which would give every
//   node new interfaces, fails it; the two GUIDs differ. Each adapter holds the address of node-c in its VRF and the
//   route of its Network, Windows takes the adapter of each VRF to node-s there, and an echo of the runner's stack comes
//   back through the adapter of each VRF. node-c is no gateway: forwarding and weak host are off on its adapters.
// - Tunnel restart: node-s drops node-c from its state and takes it back, so the session goes down and comes up again,
//   and node-c applies its state again, as a new control stream brings it. Windows reports no deletion of an interface
//   of the adapters or of a route of their Networks meanwhile; the adapters, their GUIDs, their addresses and their
//   routes are the same, and the echoes come back in both VRFs.
// - A gateway or an exit: node-g runs the client role (Cedar/NodeClient.c) with "forwarding": true in its Client
//   setting and states from the test. Its two adapters have the GUIDs of its static key and the VRFs, and Forwarding,
//   WeakHostSend and WeakHostReceive on, as GetIpInterfaceEntry reads them back for IPv4 and IPv6. The role restarts:
//   its adapters go and come back with the same GUIDs and the same settings. The role closes its streams and dials
//   again (suspend and resume): its adapters stay. Once the node stops, its adapters are gone.
// Print "VRFADAPTER TEST OK" only when every check passes. Needs administrator rights and wintun.dll next to vpntest
// (.github/scripts/fetch-wintun.ps1).

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

#include <iphlpapi.h>
#include <icmpapi.h>

#include <stdio.h>

#define	VRFADAPTERTEST_BUDGET		300000		// The whole test ends within this time, or the watchdog ends the process (ms)
#define	VRFADAPTERTEST_BOUND		20000		// A bounded wait on observable state (ms)
#define	VRFADAPTERTEST_POLL			20			// Poll interval of observable state (ms)
#define	VRFADAPTERTEST_ECHO			1000		// An echo comes back within this (ms)
#define	VRFADAPTERTEST_SETTLE		500			// ms that a deletion that Windows reports takes at most to reach the watch
#define	VRFADAPTERTEST_NUM_VRFS		2			// red and blue
#define	VRFADAPTERTEST_RED			101
#define	VRFADAPTERTEST_BLUE			202
#define	VRFADAPTERTEST_LENGTH		24			// The prefix length of the Networks of the test
#define	VRFADAPTERTEST_MAX_PACKET	1500
#define	VRFADAPTERTEST_NODE_C		"node-c"
#define	VRFADAPTERTEST_NODE_S		"node-s"
#define	VRFADAPTERTEST_NODE_G		"node-g"
#define	VRFADAPTERTEST_SERVER		"node-t"	// The server of the Client setting of node-g, which its states name no peer of: the role dials nothing
#define	VRFADAPTERTEST_THUMBPRINT	"00112233445566778899AABBCCDDEEFF00112233"
#define	VRFADAPTERTEST_LABEL		"ranz vrf adapter"	// What the name of the GUID of an adapter begins with (ADR-0025 decision 3, SDN-5)
#define	VRFADAPTERTEST_LABEL_SIZE	16
#define	VRFADAPTERTEST_ICMP_DATA	"ranz vrf adapter icmp"

// The VRFs of the test, red first, and the Network of each
static UINT vrfadaptertest_vrfs[VRFADAPTERTEST_NUM_VRFS] = {VRFADAPTERTEST_RED, VRFADAPTERTEST_BLUE};
static char *vrfadaptertest_vrf_names[VRFADAPTERTEST_NUM_VRFS] = {"red", "blue"};
static char *vrfadaptertest_networks[VRFADAPTERTEST_NUM_VRFS] = {"red-lan", "blue-lan"};

// The addresses of the test by VRF, in network byte order
static UINT vrfadaptertest_c[VRFADAPTERTEST_NUM_VRFS];		// node-c: 198.19.1.2, 198.19.2.2
static UINT vrfadaptertest_s[VRFADAPTERTEST_NUM_VRFS];		// node-s: 198.19.1.1, 198.19.2.1
static UINT vrfadaptertest_c_net[VRFADAPTERTEST_NUM_VRFS];	// Their Networks: 198.19.1.0/24, 198.19.2.0/24
static UINT vrfadaptertest_g[VRFADAPTERTEST_NUM_VRFS];		// node-g: 198.19.11.2, 198.19.12.2
static UINT vrfadaptertest_gs[VRFADAPTERTEST_NUM_VRFS];		// node-s in the states of node-g: 198.19.11.1, 198.19.12.1
static UINT vrfadaptertest_g_net[VRFADAPTERTEST_NUM_VRFS];	// Their Networks: 198.19.11.0/24, 198.19.12.0/24

// The checks of the test
typedef struct VRFADAPTERTEST_CTX
{
	UINT NumChecks;
	UINT NumFailed;
} VRFADAPTERTEST_CTX;

// The fake host of node-s: it answers the echo requests to its addresses
typedef struct VRFADAPTERTEST_HOST
{
	volatile LONG Echoes[VRFADAPTERTEST_NUM_VRFS];	// Echo requests that it answered, by VRF
	volatile LONG Other;							// Packets that are no echo request
} VRFADAPTERTEST_HOST;

// The deletions that Windows reports while the test watches the adapters of two interfaces
typedef struct VRFADAPTERTEST_WATCH
{
	UINT64 Luids[VRFADAPTERTEST_NUM_VRFS];	// The interfaces of the adapters
	volatile LONG Interfaces;				// Their IP interfaces that Windows deleted
	volatile LONG Routes;					// The routes of their Networks (IPv4, /24) through them that Windows deleted
	HANDLE InterfaceNotify;					// The registrations of the notifications
	HANDLE RouteNotify;
} VRFADAPTERTEST_WATCH;

static bool VrfAdapterTestCheck(VRFADAPTERTEST_CTX *ctx, bool ok, char *what, char *fmt, ...) RANZ_PRINTF_FORMAT(4, 5);
static bool VrfAdapterTestCheck(VRFADAPTERTEST_CTX *ctx, bool ok, char *what, char *fmt, ...)
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
static DWORD WINAPI VrfAdapterTestWatchdog(LPVOID param)
{
	char msg[MAX_SIZE];
	DWORD written = 0;

	if (WaitForSingleObject((HANDLE)param, VRFADAPTERTEST_BUDGET) != WAIT_TIMEOUT)
	{
		return 0;
	}

	int len = snprintf(msg, sizeof(msg), "VRFADAPTER TEST FAILED (did not finish within %u ms)\n", VRFADAPTERTEST_BUDGET);
	if (len > 0)
	{
		WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), msg, (DWORD)MIN((UINT)len, (UINT)sizeof(msg) - 1), &written, NULL);
	}

	TerminateProcess(GetCurrentProcess(), 1);

	return 0;
}

// An IPv4 address of four bytes, in network byte order
static UINT VrfAdapterTestAddr(UCHAR a, UCHAR b, UCHAR c, UCHAR d)
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

// The GUID that a node of the static key key asks for the adapter of the VRF vrf_id: the name-based GUID (RFC 4122
// section 4.3) of the SHA-256 of "ranz vrf adapter", the key and the VRF id (4 bytes, big-endian). The test derives it on
// its own instead of asking the node.
static void VrfAdapterTestGuid(GUID *guid, const UCHAR *key, UINT vrf_id)
{
	UCHAR name[VRFADAPTERTEST_LABEL_SIZE + PEER_KEY_SIZE + 4];
	UCHAR hash[SHA256_SIZE];

	Copy(name, VRFADAPTERTEST_LABEL, VRFADAPTERTEST_LABEL_SIZE);
	Copy(name + VRFADAPTERTEST_LABEL_SIZE, key, PEER_KEY_SIZE);
	name[VRFADAPTERTEST_LABEL_SIZE + PEER_KEY_SIZE] = (UCHAR)(vrf_id >> 24);
	name[VRFADAPTERTEST_LABEL_SIZE + PEER_KEY_SIZE + 1] = (UCHAR)(vrf_id >> 16);
	name[VRFADAPTERTEST_LABEL_SIZE + PEER_KEY_SIZE + 2] = (UCHAR)(vrf_id >> 8);
	name[VRFADAPTERTEST_LABEL_SIZE + PEER_KEY_SIZE + 3] = (UCHAR)vrf_id;
	Sha2_256(hash, name, sizeof(name));

	Copy(guid, hash, sizeof(GUID));
	guid->Data3 = (USHORT)((guid->Data3 & 0x0FFF) | 0x5000);
	guid->Data4[0] = (UCHAR)((guid->Data4[0] & 0x3F) | 0x80);
}

// A GUID in its registry form
static void VrfAdapterTestGuidStr(char *str, UINT size, const GUID *g)
{
	Format(str, size, "{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}", (UINT)g->Data1, (UINT)g->Data2, (UINT)g->Data3,
		(UINT)g->Data4[0], (UINT)g->Data4[1], (UINT)g->Data4[2], (UINT)g->Data4[3], (UINT)g->Data4[4], (UINT)g->Data4[5],
		(UINT)g->Data4[6], (UINT)g->Data4[7]);
}

//
// The nodes
//

// A new empty data directory under the temp directory of the process, with a configuration store: the roles, one
// worker, and the identity key and the Client setting when they are not NULL
static void VrfAdapterTestNewDir(wchar_t *dir, UINT size, char *name, char *roles, char *identity, char *client)
{
	wchar_t tmp[MAX_PATH];
	wchar_t path[MAX_PATH];

	UniFormat(tmp, sizeof(tmp), L"vrfadaptertest_%S_%u", name, Rand32());
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
static void VrfAdapterTestDeleteDir(wchar_t *dir)
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

// The lines of the node log in a data directory that tell about the adapters and the client role, for a part of the
// test that failed
static void VrfAdapterTestPrintLog(wchar_t *dir)
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
			if (InStr(t->Token[j], "Wintun") || InStr(t->Token[j], "VRF adapters") || InStr(t->Token[j], "Role client") || InStr(t->Token[j], "Client:"))
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

// Stop and free a node of the test, and delete its data directory with its node log, whose lines about the adapters
// are printed first with print_log
static void VrfAdapterTestFreeNode(NODE *n, wchar_t *dir, bool print_log)
{
	wchar_t log_dir[MAX_PATH];

	if (n == NULL)
	{
		return;
	}

	NodeStop(n);
	FreeNode(n);

	if (print_log)
	{
		VrfAdapterTestPrintLog(dir);
	}

	ConbinePathW(log_dir, sizeof(log_dir), dir, NODE_LOG_DIR_NAME);
	VrfAdapterTestDeleteDir(log_dir);
	VrfAdapterTestDeleteDir(dir);
}

// The address addr of a node in the Network of the VRF of index vrf
static void VrfAdapterTestAddress(CONTROL_ADDRESS *a, UINT vrf, UINT addr)
{
	Zero(a, sizeof(CONTROL_ADDRESS));
	StrCpy(a->Network, sizeof(a->Network), vrfadaptertest_networks[vrf]);
	a->VrfId = vrfadaptertest_vrfs[vrf];
	Copy(a->Address, &addr, 4);
	a->AddressSize = 4;
	a->Length = VRFADAPTERTEST_LENGTH;
}

// The desired state of the node name in red and blue, its addresses mine by VRF; with peer_key, the node peer_name of
// that static key, its addresses theirs, as its peer. In the order of the protocol: the VRFs by name, the addresses by
// Network name (blue first).
static void VrfAdapterTestState(CONTROL_STATE *st, CONTROL_PEER *peer, UINT64 generation, char *name, UINT *mine, char *peer_name, UINT *theirs,
	const UCHAR *peer_key)
{
	Zero(st, sizeof(CONTROL_STATE));
	Zero(peer, sizeof(CONTROL_PEER));

	st->Generation = generation;
	StrCpy(st->Name, sizeof(st->Name), name);

	for (UINT i = 0;i < VRFADAPTERTEST_NUM_VRFS;i++)
	{
		UINT vrf = VRFADAPTERTEST_NUM_VRFS - 1 - i;

		VrfAdapterTestAddress(&st->Addresses[i], vrf, mine[vrf]);
		StrCpy(st->Vrfs[i].Name, sizeof(st->Vrfs[i].Name), vrfadaptertest_vrf_names[vrf]);
		st->Vrfs[i].Id = vrfadaptertest_vrfs[vrf];
	}
	st->NumAddresses = VRFADAPTERTEST_NUM_VRFS;
	st->NumVrfs = VRFADAPTERTEST_NUM_VRFS;

	if (peer_key == NULL)
	{
		return;
	}

	StrCpy(peer->Name, sizeof(peer->Name), peer_name);
	Copy(peer->Key, peer_key, PEER_KEY_SIZE);
	for (UINT i = 0;i < VRFADAPTERTEST_NUM_VRFS;i++)
	{
		UINT vrf = VRFADAPTERTEST_NUM_VRFS - 1 - i;

		peer->VrfIds[i] = vrfadaptertest_vrfs[i];
		VrfAdapterTestAddress(&peer->Addresses[i], vrf, theirs[vrf]);
	}
	peer->NumVrfs = VRFADAPTERTEST_NUM_VRFS;
	peer->NumAddresses = VRFADAPTERTEST_NUM_VRFS;
	st->NumPeers = 1;
	st->Peers = peer;
}

// Apply a state of the test to the overlay of a node, as the control stream does (VrfAdapterTestState)
static bool VrfAdapterTestApply(NODE *n, UINT64 generation, char *name, UINT *mine, char *peer_name, UINT *theirs, const UCHAR *peer_key)
{
	CONTROL_STATE *st = ZeroMalloc(sizeof(CONTROL_STATE));
	CONTROL_PEER *peer = ZeroMalloc(sizeof(CONTROL_PEER));

	VrfAdapterTestState(st, peer, generation, name, mine, peer_name, theirs, peer_key);
	bool ok = NodeOverlayApply(n, st);

	Free(peer);
	Free(st);

	return ok;
}

// The number of Noise sessions of the overlay of a node
static UINT VrfAdapterTestLinks(NODE *n)
{
	NODE_OVERLAY_STATUS st;

	NodeOverlayGetStatus(n, &st);

	return st.NumLinks;
}

// Whether the overlay of a node has want sessions within VRFADAPTERTEST_BOUND
static bool VrfAdapterTestWaitLinks(NODE *n, UINT want)
{
	for (UINT64 end = Tick64() + VRFADAPTERTEST_BOUND;Tick64() < end;SleepThread(VRFADAPTERTEST_POLL))
	{
		if (VrfAdapterTestLinks(n) == want)
		{
			return true;
		}
	}

	return false;
}

// The host of node-s, on the thread of its overlay, an online reader of its tables: an echo request gets its reply,
// into the overlay in the VRF that it came in
static void VrfAdapterTestServerHost(NODE *n, void *param, UINT vrf_id, const UCHAR *packet, UINT size)
{
	VRFADAPTERTEST_HOST *h = (VRFADAPTERTEST_HOST *)param;
	UCHAR reply[VRFADAPTERTEST_MAX_PACKET];
	USHORT sum;

	// An IPv4 echo request without options
	UINT total = (size >= 4 ? (((UINT)packet[2] << 8) | packet[3]) : 0);
	if (size < 28 || total < 28 || total > size || total > sizeof(reply) || packet[0] != 0x45 || packet[9] != IP_PROTO_ICMPV4 || packet[20] != 8)
	{
		InterlockedIncrement(&h->Other);
		return;
	}

	// The reply: the addresses swapped, type 0, both checksums anew
	Copy(reply, packet, total);
	Copy(reply + 12, packet + 16, 4);
	Copy(reply + 16, packet + 12, 4);
	reply[8] = 64;
	reply[10] = 0;
	reply[11] = 0;
	sum = IpChecksum(reply, 20);
	Copy(reply + 10, &sum, 2);
	reply[20] = 0;
	reply[22] = 0;
	reply[23] = 0;
	sum = IpChecksum(reply + 20, total - 20);
	Copy(reply + 22, &sum, 2);

	InterlockedIncrement(&h->Echoes[vrf_id == VRFADAPTERTEST_RED ? 0 : 1]);
	NodeOverlayInput(n, vrf_id, reply, total);
}

// The host of node-c: its adapters of the VRFs, which the test plugs into its overlay as the client role does
static void VrfAdapterTestToHost(NODE *n, void *param, UINT vrf_id, const UCHAR *packet, UINT size)
{
	NodeVrfAdaptersSend((NODE_VRF_ADAPTERS *)param, vrf_id, packet, size);
}

static void VrfAdapterTestApplied(NODE *n, void *param, const CONTROL_STATE *st)
{
	NodeVrfAdaptersApply((NODE_VRF_ADAPTERS *)param, st);
}

static void VrfAdapterTestHalt(NODE *n, void *param)
{
	NodeVrfAdaptersHalt((NODE_VRF_ADAPTERS *)param);
}

//
// What Windows holds
//

// The adapter of the VRF vrf_id in a list of adapters, NULL for none
static NODE_VRF_ADAPTER_STATUS *VrfAdapterTestFind(NODE_VRF_ADAPTER_STATUS *list, UINT num, UINT vrf_id)
{
	for (UINT i = 0;i < num;i++)
	{
		if (list[i].VrfId == vrf_id)
		{
			return &list[i];
		}
	}

	return NULL;
}

// Whether the address addr is on the interface of luid, preferred
static bool VrfAdapterTestAddressOn(UINT64 luid, UINT addr)
{
	MIB_UNICASTIPADDRESS_ROW row;

	InitializeUnicastIpAddressEntry(&row);
	row.InterfaceLuid.Value = luid;
	row.Address.Ipv4.sin_family = AF_INET;
	Copy(&row.Address.Ipv4.sin_addr, &addr, 4);

	return (GetUnicastIpAddressEntry(&row) == NO_ERROR && row.DadState == IpDadStatePreferred);
}

// Whether Windows holds the on-link route to net/VRFADAPTERTEST_LENGTH through the interface of luid
static bool VrfAdapterTestRouteOn(UINT64 luid, UINT net)
{
	MIB_IPFORWARD_ROW2 row;

	InitializeIpForwardEntry(&row);
	row.InterfaceLuid.Value = luid;
	row.DestinationPrefix.Prefix.Ipv4.sin_family = AF_INET;
	Copy(&row.DestinationPrefix.Prefix.Ipv4.sin_addr, &net, 4);
	row.DestinationPrefix.PrefixLength = VRFADAPTERTEST_LENGTH;
	row.NextHop.Ipv4.sin_family = AF_INET;

	return (GetIpForwardEntry2(&row) == NO_ERROR);
}

// Whether Windows takes the interface of luid to dst, with src as the source
static bool VrfAdapterTestBestRoute(UINT64 luid, UINT dst, UINT src, char *detail, UINT detail_size)
{
	SOCKADDR_INET d;
	SOCKADDR_INET from;
	MIB_IPFORWARD_ROW2 best;
	UINT got = 0;
	char a[64];

	Zero(&d, sizeof(d));
	Zero(&from, sizeof(from));
	Zero(&best, sizeof(best));
	d.Ipv4.sin_family = AF_INET;
	Copy(&d.Ipv4.sin_addr, &dst, 4);

	DWORD err = GetBestRoute2(NULL, 0, NULL, &d, 0, &best, &from);
	Copy(&got, &from.Ipv4.sin_addr, 4);
	IPToStr32(a, sizeof(a), got);
	Format(detail, detail_size, "GetBestRoute2 %u: interface LUID %I64u (the adapter's %I64u), source %s", (UINT)err, (UINT64)best.InterfaceLuid.Value, luid, a);

	return (err == NO_ERROR && best.InterfaceLuid.Value == luid && got == src);
}

// The forwarding of the interface of luid in one family as Windows holds it: bit 0 Forwarding, bit 1 WeakHostSend, bit 2
// WeakHostReceive; *err the error of GetIpInterfaceEntry
static UINT VrfAdapterTestFlags(UINT64 luid, ADDRESS_FAMILY family, DWORD *err)
{
	MIB_IPINTERFACE_ROW row;

	InitializeIpInterfaceEntry(&row);
	row.Family = family;
	row.InterfaceLuid.Value = luid;
	*err = GetIpInterfaceEntry(&row);
	if (*err != NO_ERROR)
	{
		return 0;
	}

	return (row.ForwardingEnabled ? 1 : 0) | (row.WeakHostSend ? 2 : 0) | (row.WeakHostReceive ? 4 : 0);
}

// Whether the interface of luid has Forwarding, WeakHostSend and WeakHostReceive all on (on) or all off, for IPv4, and
// for IPv6 when the interface has one, as GetIpInterfaceEntry reads them back
static bool VrfAdapterTestForwarding(UINT64 luid, bool on, char *detail, UINT detail_size)
{
	DWORD err4 = 0;
	DWORD err6 = 0;
	UINT want = (on ? 7 : 0);
	UINT v4 = VrfAdapterTestFlags(luid, AF_INET, &err4);
	UINT v6 = VrfAdapterTestFlags(luid, AF_INET6, &err6);

	Format(detail, detail_size, "IPv4 (error %u): forwarding %u, weak host send %u, weak host receive %u; IPv6 (error %u): forwarding %u, weak host send %u, weak host receive %u",
		(UINT)err4, v4 & 1, (v4 >> 1) & 1, (v4 >> 2) & 1, (UINT)err6, v6 & 1, (v6 >> 1) & 1, (v6 >> 2) & 1);

	return (err4 == NO_ERROR && v4 == want && (err6 == ERROR_NOT_FOUND || (err6 == NO_ERROR && v6 == want)));
}

// Whether the interface of luid is gone within VRFADAPTERTEST_BOUND
static bool VrfAdapterTestGone(UINT64 luid)
{
	for (UINT64 end = Tick64() + VRFADAPTERTEST_BOUND;Tick64() < end;SleepThread(VRFADAPTERTEST_POLL))
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

// The adapters of a node, one per VRF of the test: whether there are two, of red and of blue, each an interface that
// Windows holds with the GUID of the static key key and its VRF; their LUIDs and GUIDs go into luids and guids, by VRF
static bool VrfAdapterTestTwo(VRFADAPTERTEST_CTX *ctx, char *who, NODE_VRF_ADAPTER_STATUS *list, UINT num, const UCHAR *key, UINT64 *luids, GUID *guids)
{
	char what[MAX_SIZE];

	Format(what, sizeof(what), "%s shows two Wintun adapters, one per VRF it joins", who);
	bool ok = VrfAdapterTestCheck(ctx, num == VRFADAPTERTEST_NUM_VRFS && VrfAdapterTestFind(list, num, VRFADAPTERTEST_RED) != NULL &&
		VrfAdapterTestFind(list, num, VRFADAPTERTEST_BLUE) != NULL, what, "%u adapters", num);

	for (UINT i = 0;i < VRFADAPTERTEST_NUM_VRFS && ok;i++)
	{
		NODE_VRF_ADAPTER_STATUS *a = VrfAdapterTestFind(list, num, vrfadaptertest_vrfs[i]);
		wchar_t alias[MAX_SIZE];
		char want_str[64];
		char got_str[64];
		GUID want;
		GUID got;
		NET_LUID l;

		Zero(&got, sizeof(got));
		Zero(alias, sizeof(alias));
		l.Value = a->InterfaceLuid;
		bool has = (ConvertInterfaceLuidToGuid(&l, &got) == NO_ERROR);
		ConvertInterfaceLuidToAlias(&l, alias, MAX_SIZE);
		VrfAdapterTestGuid(&want, key, a->VrfId);
		VrfAdapterTestGuidStr(want_str, sizeof(want_str), &want);
		VrfAdapterTestGuidStr(got_str, sizeof(got_str), &got);

		Print("  [INFO] %s, VRF %s (%u): adapter \"%S\", interface %u, alias \"%S\", GUID %s\n", who, vrfadaptertest_vrf_names[i], a->VrfId, a->Name,
			a->InterfaceIndex, alias, got_str);

		Format(what, sizeof(what), "%s: Windows gives the interface of the adapter of %s the GUID of the node's static key and the VRF", who, vrfadaptertest_vrf_names[i]);
		ok = VrfAdapterTestCheck(ctx, has && Cmp(&got, &want, sizeof(GUID)) == 0 && Cmp(&a->Guid, &want, sizeof(GUID)) == 0, what,
			"Windows %s (%u), derived %s", got_str, (UINT)has, want_str) && ok;

		luids[i] = a->InterfaceLuid;
		guids[i] = got;
	}

	if (ok)
	{
		Format(what, sizeof(what), "%s: the adapters of the two VRFs are two interfaces with two GUIDs", who);
		ok = VrfAdapterTestCheck(ctx, luids[0] != luids[1] && Cmp(&guids[0], &guids[1], sizeof(GUID)) != 0, what, "LUIDs %I64u and %I64u", luids[0], luids[1]);
	}

	return ok;
}

// The adapters of a node again, after a restart: whether they are the ones of luids and guids (same is true: the same
// interfaces; false: new interfaces of the same GUIDs)
static bool VrfAdapterTestSame(VRFADAPTERTEST_CTX *ctx, char *what, NODE_VRF_ADAPTER_STATUS *list, UINT num, UINT64 *luids, GUID *guids, bool same)
{
	char detail[MAX_SIZE];
	bool ok = (num == VRFADAPTERTEST_NUM_VRFS);

	StrCpy(detail, sizeof(detail), "");
	for (UINT i = 0;i < VRFADAPTERTEST_NUM_VRFS && ok;i++)
	{
		NODE_VRF_ADAPTER_STATUS *a = VrfAdapterTestFind(list, num, vrfadaptertest_vrfs[i]);
		GUID got;
		NET_LUID l;

		Zero(&got, sizeof(got));
		l.Value = (a != NULL ? a->InterfaceLuid : 0);
		ok = (a != NULL && ConvertInterfaceLuidToGuid(&l, &got) == NO_ERROR && Cmp(&got, &guids[i], sizeof(GUID)) == 0 &&
			(same == false || a->InterfaceLuid == luids[i]));
		Format(detail, sizeof(detail), "VRF %u: LUID %I64u (before %I64u)", vrfadaptertest_vrfs[i], l.Value, luids[i]);
	}

	return VrfAdapterTestCheck(ctx, ok, what, "%u adapters; %s", num, detail);
}

// Watch the deletions of the IP interfaces and the routes of the adapters of luids
static VOID WINAPI VrfAdapterTestInterfaceChanged(PVOID context, PMIB_IPINTERFACE_ROW row, MIB_NOTIFICATION_TYPE type)
{
	VRFADAPTERTEST_WATCH *w = (VRFADAPTERTEST_WATCH *)context;

	if (row != NULL && type == MibDeleteInstance && (row->InterfaceLuid.Value == w->Luids[0] || row->InterfaceLuid.Value == w->Luids[1]))
	{
		InterlockedIncrement(&w->Interfaces);
	}
}

static VOID WINAPI VrfAdapterTestRouteChanged(PVOID context, PMIB_IPFORWARD_ROW2 row, MIB_NOTIFICATION_TYPE type)
{
	VRFADAPTERTEST_WATCH *w = (VRFADAPTERTEST_WATCH *)context;

	if (row != NULL && type == MibDeleteInstance && row->DestinationPrefix.Prefix.si_family == AF_INET &&
		row->DestinationPrefix.PrefixLength == VRFADAPTERTEST_LENGTH && (row->InterfaceLuid.Value == w->Luids[0] || row->InterfaceLuid.Value == w->Luids[1]))
	{
		InterlockedIncrement(&w->Routes);
	}
}

static bool VrfAdapterTestWatchStart(VRFADAPTERTEST_WATCH *w, UINT64 *luids)
{
	Zero(w, sizeof(VRFADAPTERTEST_WATCH));
	Copy(w->Luids, luids, sizeof(w->Luids));

	DWORD e1 = NotifyIpInterfaceChange(AF_UNSPEC, VrfAdapterTestInterfaceChanged, w, FALSE, &w->InterfaceNotify);
	DWORD e2 = NotifyRouteChange2(AF_UNSPEC, VrfAdapterTestRouteChanged, w, FALSE, &w->RouteNotify);

	return (e1 == NO_ERROR && e2 == NO_ERROR);
}

// Stop watching, once a deletion that Windows reported a moment ago reached the watch: no callback runs once it returns
static void VrfAdapterTestWatchStop(VRFADAPTERTEST_WATCH *w)
{
	SleepThread(VRFADAPTERTEST_SETTLE);

	if (w->InterfaceNotify != NULL)
	{
		CancelMibChangeNotify2(w->InterfaceNotify);
		w->InterfaceNotify = NULL;
	}
	if (w->RouteNotify != NULL)
	{
		CancelMibChangeNotify2(w->RouteNotify);
		w->RouteNotify = NULL;
	}
}

// An ICMP echo from the runner's stack, from src to dst: whether its reply came back with the same data within
// VRFADAPTERTEST_ECHO
static bool VrfAdapterTestPing(UINT src, UINT dst)
{
	UINT64 reply[64];
	bool ok = false;

	HANDLE icmp = IcmpCreateFile();
	if (icmp == INVALID_HANDLE_VALUE)
	{
		return false;
	}

	Zero(reply, sizeof(reply));
	DWORD n = IcmpSendEcho2Ex(icmp, NULL, NULL, NULL, (IPAddr)src, (IPAddr)dst, (LPVOID)VRFADAPTERTEST_ICMP_DATA, (WORD)StrLen(VRFADAPTERTEST_ICMP_DATA),
		NULL, reply, sizeof(reply), VRFADAPTERTEST_ECHO);
	if (n != 0)
	{
		ICMP_ECHO_REPLY *e = (ICMP_ECHO_REPLY *)reply;

		ok = (e->Status == IP_SUCCESS && e->Address == (IPAddr)dst && e->DataSize == StrLen(VRFADAPTERTEST_ICMP_DATA) && e->Data != NULL &&
			Cmp(e->Data, VRFADAPTERTEST_ICMP_DATA, e->DataSize) == 0);
	}

	IcmpCloseHandle(icmp);

	return ok;
}

// The packets that the adapter of the VRF vrf_id of a set put into its ring for the host
static UINT64 VrfAdapterTestToHostCount(NODE_VRF_ADAPTERS *set, UINT vrf_id)
{
	NODE_VRF_ADAPTER_STATUS *list = ZeroMalloc(sizeof(NODE_VRF_ADAPTER_STATUS) * NODE_VRF_MAX_ADAPTERS);
	UINT num = NodeVrfAdaptersGetStatus(set, list, NODE_VRF_MAX_ADAPTERS);
	NODE_VRF_ADAPTER_STATUS *a = VrfAdapterTestFind(list, num, vrf_id);
	UINT64 ret = (a != NULL ? a->ToHost : 0);

	Free(list);

	return ret;
}

// An echo of the runner's stack from node-c to node-s in each VRF: whether it comes back within VRFADAPTERTEST_BOUND,
// node-s having answered it in that VRF and its reply having come into the adapter of that VRF
static void VrfAdapterTestEchoes(VRFADAPTERTEST_CTX *ctx, char *when, NODE_VRF_ADAPTERS *set, VRFADAPTERTEST_HOST *host)
{
	for (UINT i = 0;i < VRFADAPTERTEST_NUM_VRFS;i++)
	{
		char what[MAX_SIZE];
		LONG echoes = ReadAcquire(&host->Echoes[i]);
		UINT64 to_host = VrfAdapterTestToHostCount(set, vrfadaptertest_vrfs[i]);
		bool back = false;

		for (UINT64 end = Tick64() + VRFADAPTERTEST_BOUND;back == false && Tick64() < end;)
		{
			back = VrfAdapterTestPing(vrfadaptertest_c[i], vrfadaptertest_s[i]);
		}

		LONG answered = ReadAcquire(&host->Echoes[i]) - echoes;
		UINT64 into = VrfAdapterTestToHostCount(set, vrfadaptertest_vrfs[i]) - to_host;
		Format(what, sizeof(what), "%s: an echo of the runner's stack to node-s in %s comes back through the adapter of %s", when, vrfadaptertest_vrf_names[i],
			vrfadaptertest_vrf_names[i]);
		VrfAdapterTestCheck(ctx, back && answered > 0 && into > 0, what, "came back %u, node-s answered %d in the VRF, %I64u packets into the adapter", (UINT)back,
			(int)answered, into);
	}
}

//
// Two VRFs on Wintun, and a tunnel restart
//

static void VrfAdapterTestTwoVrfs(VRFADAPTERTEST_CTX *ctx)
{
	NODE *c = NULL;
	NODE *s = NULL;
	wchar_t c_dir[MAX_PATH];
	wchar_t s_dir[MAX_PATH];
	wchar_t name[MAX_SIZE];
	char detail[MAX_SIZE * 2];
	char what[MAX_SIZE];
	UCHAR scalar[PEER_KEY_SIZE];
	PEER_KEY c_key;
	PEER_KEY s_key;
	NODE_OVERLAY_CONFIG cfg;
	VRFADAPTERTEST_WATCH watch;
	UINT64 luids[VRFADAPTERTEST_NUM_VRFS];
	GUID guids[VRFADAPTERTEST_NUM_VRFS];
	NODE_VRF_ADAPTERS *set = NULL;
	NODE_VRF_ADAPTER_STATUS *list = ZeroMalloc(sizeof(NODE_VRF_ADAPTER_STATUS) * NODE_VRF_MAX_ADAPTERS);
	VRFADAPTERTEST_HOST *host = ZeroMalloc(sizeof(VRFADAPTERTEST_HOST));
	TRANSPORT *loopback = TransportLoopbackNew("loopback", 0, false);
	UINT failed = ctx->NumFailed;

	Print("[two VRFs on Wintun]\n");

	Zero(&c_key, sizeof(c_key));
	Zero(&s_key, sizeof(s_key));
	Zero(&watch, sizeof(watch));
	Zero(luids, sizeof(luids));
	Zero(guids, sizeof(guids));
	UniFormat(name, sizeof(name), L"RanzV%04x", Rand32() & 0xFFFF);

	// The static keys of the two nodes: random scalars, so the adapters of a run have GUIDs of their own
	Rand(scalar, sizeof(scalar));
	bool ok = PeerKeyFromScalar(&c_key, scalar);
	Rand(scalar, sizeof(scalar));
	ok = PeerKeyFromScalar(&s_key, scalar) && ok;
	Zero(scalar, sizeof(scalar));
	ok = VrfAdapterTestCheck(ctx, ok && loopback != NULL, "node-c and node-s: their static keys and the in-process loopback transport", "a key or the transport failed");

	if (ok)
	{
		// node-s: its fake host answers the echo requests to its addresses
		VrfAdapterTestNewDir(s_dir, sizeof(s_dir), "nodes", "none", NULL, NULL);
		s = NewNode(s_dir);
		NodeStart(s);
		Zero(&cfg, sizeof(cfg));
		cfg.Data = loopback;
		cfg.Key = &s_key;
		cfg.Adapter = VrfAdapterTestServerHost;
		cfg.AdapterParam = host;
		ok = NodeOverlayStart(s, &cfg);

		// node-c: its adapters of the VRFs are the host of its overlay
		VrfAdapterTestNewDir(c_dir, sizeof(c_dir), "nodec", "none", NULL, NULL);
		c = NewNode(c_dir);
		NodeStart(c);
		set = NodeVrfAdaptersNew(c, name, c_key.Public, false);
		Zero(&cfg, sizeof(cfg));
		cfg.Data = loopback;
		cfg.Key = &c_key;
		cfg.Adapter = VrfAdapterTestToHost;
		cfg.AdapterParam = set;
		cfg.AdapterStop = VrfAdapterTestHalt;
		cfg.State = VrfAdapterTestApplied;
		ok = (set != NULL && NodeOverlayStart(c, &cfg)) && ok;

		ok = VrfAdapterTestCheck(ctx, ok, "node-c and node-s: their overlays run, node-c with its adapters of the VRFs as its host", "NodeVrfAdaptersNew or NodeOverlayStart failed");
	}

	if (ok)
	{
		ok = VrfAdapterTestApply(s, 1, VRFADAPTERTEST_NODE_S, vrfadaptertest_s, VRFADAPTERTEST_NODE_C, vrfadaptertest_c, c_key.Public);
		ok = VrfAdapterTestApply(c, 1, VRFADAPTERTEST_NODE_C, vrfadaptertest_c, VRFADAPTERTEST_NODE_S, vrfadaptertest_s, s_key.Public) && ok;
		bool up = (ok && VrfAdapterTestWaitLinks(c, 1) && VrfAdapterTestWaitLinks(s, 1));
		ok = VrfAdapterTestCheck(ctx, up, "node-c and node-s apply their states in red (101) and blue (202), and their session is up", "applied %u, sessions %u and %u",
			(UINT)ok, VrfAdapterTestLinks(c), VrfAdapterTestLinks(s));
	}

	if (ok)
	{
		UINT num = NodeVrfAdaptersGetStatus(set, list, NODE_VRF_MAX_ADAPTERS);

		ok = VrfAdapterTestTwo(ctx, VRFADAPTERTEST_NODE_C, list, num, c_key.Public, luids, guids);
	}

	if (ok)
	{
		for (UINT i = 0;i < VRFADAPTERTEST_NUM_VRFS;i++)
		{
			bool held = (VrfAdapterTestAddressOn(luids[i], vrfadaptertest_c[i]) && VrfAdapterTestRouteOn(luids[i], vrfadaptertest_c_net[i]));
			bool best = VrfAdapterTestBestRoute(luids[i], vrfadaptertest_s[i], vrfadaptertest_c[i], detail, sizeof(detail));

			Format(what, sizeof(what), "node-c: the adapter of %s holds the address of node-c and the route of its Network there, and Windows takes it to node-s in %s",
				vrfadaptertest_vrf_names[i], vrfadaptertest_vrf_names[i]);
			VrfAdapterTestCheck(ctx, held && best, what, "address and route %u; %s", (UINT)held, detail);

			Format(what, sizeof(what), "node-c is no gateway: Forwarding, WeakHostSend and WeakHostReceive are off on the adapter of %s", vrfadaptertest_vrf_names[i]);
			VrfAdapterTestCheck(ctx, VrfAdapterTestForwarding(luids[i], false, detail, sizeof(detail)), what, "%s", detail);
		}

		VrfAdapterTestEchoes(ctx, "two VRFs", set, host);
	}

	// The tunnel restart: the session goes down and comes up again, and node-c gets its state again
	if (ok)
	{
		Print("[tunnel restart]\n");

		bool watching = VrfAdapterTestWatchStart(&watch, luids);
		bool dropped = VrfAdapterTestApply(s, 2, VRFADAPTERTEST_NODE_S, vrfadaptertest_s, NULL, NULL, NULL);
		bool down = (dropped && VrfAdapterTestWaitLinks(c, 0));
		bool back = VrfAdapterTestApply(s, 3, VRFADAPTERTEST_NODE_S, vrfadaptertest_s, VRFADAPTERTEST_NODE_C, vrfadaptertest_c, c_key.Public);
		bool up = (back && VrfAdapterTestWaitLinks(c, 1) && VrfAdapterTestWaitLinks(s, 1));
		bool again = VrfAdapterTestApply(c, 2, VRFADAPTERTEST_NODE_C, vrfadaptertest_c, VRFADAPTERTEST_NODE_S, vrfadaptertest_s, s_key.Public);
		VrfAdapterTestWatchStop(&watch);

		ok = VrfAdapterTestCheck(ctx, watching && down && up && again,
			"tunnel restart: node-s drops node-c and the session goes down, node-s takes node-c back and the session comes up again, and node-c applies its state again as a new control stream brings it",
			"watching %u, down %u, up %u, applied again %u", (UINT)watching, (UINT)down, (UINT)up, (UINT)again);
		VrfAdapterTestCheck(ctx, ReadAcquire(&watch.Interfaces) == 0 && ReadAcquire(&watch.Routes) == 0,
			"tunnel restart: Windows reports no deletion of an interface of the adapters or of a route of their Networks", "%d interfaces and %d routes deleted",
			(int)ReadAcquire(&watch.Interfaces), (int)ReadAcquire(&watch.Routes));

		UINT num = NodeVrfAdaptersGetStatus(set, list, NODE_VRF_MAX_ADAPTERS);
		VrfAdapterTestSame(ctx, "tunnel restart: node-c keeps its adapters, the same interfaces with the same GUIDs", list, num, luids, guids, true);

		for (UINT i = 0;i < VRFADAPTERTEST_NUM_VRFS;i++)
		{
			Format(what, sizeof(what), "tunnel restart: the adapter of %s still holds the address of node-c and the route of its Network", vrfadaptertest_vrf_names[i]);
			VrfAdapterTestCheck(ctx, VrfAdapterTestAddressOn(luids[i], vrfadaptertest_c[i]) && VrfAdapterTestRouteOn(luids[i], vrfadaptertest_c_net[i]), what,
				"the address or the route is gone");
		}

		VrfAdapterTestEchoes(ctx, "tunnel restart", set, host);
	}

	// node-c's overlay stops, which halts its adapters, then the adapters go with their set
	if (c != NULL)
	{
		NodeOverlayStop(c);
	}
	if (set != NULL)
	{
		NodeVrfAdaptersFree(set);
		if (luids[0] != 0)
		{
			VrfAdapterTestCheck(ctx, VrfAdapterTestGone(luids[0]) && VrfAdapterTestGone(luids[1]), "node-c: once its adapters are freed, their interfaces are gone",
				"an interface is still there");
		}
	}

	Print("  [INFO] packets at node-s that are no echo request: %d\n", (int)ReadAcquire(&host->Other));

	VrfAdapterTestFreeNode(c, c_dir, ctx->NumFailed != failed);
	VrfAdapterTestFreeNode(s, s_dir, false);
	if (loopback != NULL)
	{
		TransportLoopbackFree(loopback);
	}
	PeerKeyClose(&c_key);
	PeerKeyClose(&s_key);
	Free(host);
	Free(list);
}

//
// A gateway or an exit: the client role with forwarding
//

// Whether both adapters of luids have Forwarding, WeakHostSend and WeakHostReceive on, and the address of node-g and the
// route of its Network
static void VrfAdapterTestGatewayAdapters(VRFADAPTERTEST_CTX *ctx, char *when, UINT64 *luids)
{
	char detail[MAX_SIZE * 2];
	char what[MAX_SIZE];

	for (UINT i = 0;i < VRFADAPTERTEST_NUM_VRFS;i++)
	{
		bool on = VrfAdapterTestForwarding(luids[i], true, detail, sizeof(detail));

		Print("  [INFO] %s, the adapter of %s: %s\n", when, vrfadaptertest_vrf_names[i], detail);
		Format(what, sizeof(what), "%s: the adapter of %s has Forwarding, WeakHostSend and WeakHostReceive on, as GetIpInterfaceEntry reads them back", when,
			vrfadaptertest_vrf_names[i]);
		VrfAdapterTestCheck(ctx, on, what, "%s", detail);

		Format(what, sizeof(what), "%s: the adapter of %s holds the address of node-g and the route of its Network", when, vrfadaptertest_vrf_names[i]);
		VrfAdapterTestCheck(ctx, VrfAdapterTestAddressOn(luids[i], vrfadaptertest_g[i]) && VrfAdapterTestRouteOn(luids[i], vrfadaptertest_g_net[i]), what,
			"the address or the route is missing");
	}
}

static void VrfAdapterTestGateway(VRFADAPTERTEST_CTX *ctx)
{
	NODE *g = NULL;
	wchar_t dir[MAX_PATH];
	wchar_t identity_w[MAX_SIZE];
	char identity[MAX_SIZE];
	char adapter[MAX_SIZE];
	char pipe[MAX_SIZE];
	UCHAR key[PEER_KEY_SIZE];
	UCHAR peer_key[PEER_KEY_SIZE];
	NODE_CLIENT_STATUS cs;
	VRFADAPTERTEST_WATCH watch;
	UINT64 luids[VRFADAPTERTEST_NUM_VRFS];
	UINT64 luids2[VRFADAPTERTEST_NUM_VRFS];
	GUID guids[VRFADAPTERTEST_NUM_VRFS];
	GUID guids2[VRFADAPTERTEST_NUM_VRFS];
	char *setting = ZeroMalloc(NODE_CLIENT_MAX_SETTING);
	NODE_VRF_ADAPTER_STATUS *list = ZeroMalloc(sizeof(NODE_VRF_ADAPTER_STATUS) * NODE_VRF_MAX_ADAPTERS);
	UINT r = Rand32() & 0xFFFF;
	UINT failed = ctx->NumFailed;

	Print("[a gateway or an exit]\n");

	Zero(&watch, sizeof(watch));
	Zero(luids, sizeof(luids));
	Zero(luids2, sizeof(luids2));
	Zero(guids, sizeof(guids));
	Zero(guids2, sizeof(guids2));
	Rand(peer_key, sizeof(peer_key));

	Format(identity, sizeof(identity), "Ranz vrfadaptertest %u", r);
	StrToUni(identity_w, sizeof(identity_w), identity);
	Format(adapter, sizeof(adapter), "RanzG%04x", r);
	Format(pipe, sizeof(pipe), "ranz-vrfadaptertest-%u", r);
	Format(setting, NODE_CLIENT_MAX_SETTING,
		"{\"adapter\":\"%s\",\"pipe\":\"%s\",\"forwarding\":true,"
		"\"servers\":[{\"name\":\"" VRFADAPTERTEST_SERVER "\",\"thumbprint\":\"" VRFADAPTERTEST_THUMBPRINT "\",\"dial\":\"tls:127.0.0.1:9\"}]}",
		adapter, pipe);

	// node-g: the client role with forwarding, its identity key in the key storage provider
	VrfAdapterTestNewDir(dir, sizeof(dir), "nodeg", "client", identity, setting);
	g = NewNode(dir);
	NodeStart(g);
	NodeClientGetStatus(g, &cs);
	Copy(key, cs.Key, PEER_KEY_SIZE);
	bool ok = VrfAdapterTestCheck(ctx, cs.Running, "node-g: the client role runs with \"forwarding\": true in its Client setting", "running %u", (UINT)cs.Running);

	if (ok)
	{
		bool applied = VrfAdapterTestApply(g, 1, VRFADAPTERTEST_NODE_G, vrfadaptertest_g, VRFADAPTERTEST_NODE_S, vrfadaptertest_gs, peer_key);
		UINT num = NodeClientGetAdapters(g, list, NODE_VRF_MAX_ADAPTERS);

		ok = VrfAdapterTestCheck(ctx, applied, "node-g: the role applies its state in red and blue", "NodeOverlayApply failed");
		ok = ok && VrfAdapterTestTwo(ctx, VRFADAPTERTEST_NODE_G, list, num, key, luids, guids);
	}

	if (ok)
	{
		VrfAdapterTestGatewayAdapters(ctx, VRFADAPTERTEST_NODE_G, luids);
	}

	// The role restarts: its adapters go with it and come back with the same GUIDs, on the state that the role gets again
	if (ok)
	{
		NodeSetRoles(g, 0);
		bool gone = (VrfAdapterTestGone(luids[0]) && VrfAdapterTestGone(luids[1]));
		NodeSetRoles(g, NODE_ROLE_CLIENT);
		NodeClientGetStatus(g, &cs);
		bool applied = (cs.Running && VrfAdapterTestApply(g, 2, VRFADAPTERTEST_NODE_G, vrfadaptertest_g, VRFADAPTERTEST_NODE_S, vrfadaptertest_gs, peer_key));
		UINT num = NodeClientGetAdapters(g, list, NODE_VRF_MAX_ADAPTERS);

		ok = VrfAdapterTestCheck(ctx, gone && applied, "role restart: the adapters of node-g go with its role, and the role comes back on its state", "gone %u, applied %u",
			(UINT)gone, (UINT)applied);
		ok = ok && VrfAdapterTestTwo(ctx, "node-g after the role restarted", list, num, key, luids2, guids2);
		ok = ok && VrfAdapterTestSame(ctx, "role restart: the adapters come back with the same GUIDs, so Windows keeps the interface of each VRF", list, num, luids, guids, false);
	}

	if (ok)
	{
		Copy(luids, luids2, sizeof(luids));
		VrfAdapterTestGatewayAdapters(ctx, "role restart", luids);
	}

	// The role closes its streams and dials again, as on a suspend and a resume: its adapters stay
	if (ok)
	{
		NodeClientGetStatus(g, &cs);
		UINT64 resets = cs.NumResets;
		bool watching = VrfAdapterTestWatchStart(&watch, luids);

		NodeClientPower(g, PBT_APMSUSPEND);
		NodeClientPower(g, PBT_APMRESUMEAUTOMATIC);
		bool applied = VrfAdapterTestApply(g, 3, VRFADAPTERTEST_NODE_G, vrfadaptertest_g, VRFADAPTERTEST_NODE_S, vrfadaptertest_gs, peer_key);
		VrfAdapterTestWatchStop(&watch);

		NodeClientGetStatus(g, &cs);
		UINT num = NodeClientGetAdapters(g, list, NODE_VRF_MAX_ADAPTERS);
		VrfAdapterTestCheck(ctx, watching && applied && cs.NumResets >= resets + 2 && cs.Asleep == false && ReadAcquire(&watch.Interfaces) == 0 &&
			ReadAcquire(&watch.Routes) == 0,
			"the role of node-g closes its streams and dials again (suspend and resume), and gets its state again: Windows reports no deletion of an interface of its adapters or of a route of their Networks",
			"watching %u, applied %u, %I64u resets (%I64u before), asleep %u, %d interfaces and %d routes deleted", (UINT)watching, (UINT)applied, cs.NumResets, resets,
			(UINT)cs.Asleep, (int)ReadAcquire(&watch.Interfaces), (int)ReadAcquire(&watch.Routes));
		VrfAdapterTestSame(ctx, "the role of node-g keeps its adapters, the same interfaces with the same GUIDs", list, num, luids, guids, true);
		VrfAdapterTestGatewayAdapters(ctx, "after the streams closed", luids);
	}

	// The node stops: its adapters go
	if (g != NULL)
	{
		NodeStop(g);
		if (luids[0] != 0)
		{
			VrfAdapterTestCheck(ctx, VrfAdapterTestGone(luids[0]) && VrfAdapterTestGone(luids[1]), "node-g: once the node stopped, its adapters are gone",
				"an interface is still there");
		}
	}

	VrfAdapterTestFreeNode(g, dir, ctx->NumFailed != failed);
	PeerKeyDelete(identity_w);
	Free(list);
	Free(setting);
}

// vrfadapter: one Wintun adapter per VRF with a fixed GUID (SDN-5)
RANZ_TEST("vrfadapter", vrfadapter_test, "VRF adapters: a node that joins two VRFs shows two Wintun adapters whose GUIDs derive from its static key and the VRF, kept with their routes across a tunnel restart, and the client role with forwarding sets Forwarding and weak host on them (administrator rights, wintun.dll).");
void vrfadapter_test(UINT num, char **arg)
{
	VRFADAPTERTEST_CTX ctx;
	UINT error = 0;
	HANDLE done = CreateEventW(NULL, TRUE, FALSE, NULL);
	HANDLE watchdog = (done != NULL ? CreateThread(NULL, 0, VrfAdapterTestWatchdog, done, 0, NULL) : NULL);

	Zero(&ctx, sizeof(ctx));

	Print("VRF adapter test: one Wintun adapter per VRF with a fixed GUID, kept across a tunnel restart with its routes, and the forwarding of a gateway or an exit\n");

	for (UINT i = 0;i < VRFADAPTERTEST_NUM_VRFS;i++)
	{
		UCHAR third = (UCHAR)(i + 1);

		vrfadaptertest_c[i] = VrfAdapterTestAddr(198, 19, third, 2);
		vrfadaptertest_s[i] = VrfAdapterTestAddr(198, 19, third, 1);
		vrfadaptertest_c_net[i] = VrfAdapterTestAddr(198, 19, third, 0);
		vrfadaptertest_g[i] = VrfAdapterTestAddr(198, 19, (UCHAR)(10 + third), 2);
		vrfadaptertest_gs[i] = VrfAdapterTestAddr(198, 19, (UCHAR)(10 + third), 1);
		vrfadaptertest_g_net[i] = VrfAdapterTestAddr(198, 19, (UCHAR)(10 + third), 0);
	}

	bool ready = VrfAdapterTestCheck(&ctx, CryptoInit(), "the crypto module of the new core runs on CNG", "CryptoInit failed");
	ready = VrfAdapterTestCheck(&ctx, NodeWintunAvailable(&error), "wintun.dll is next to vpntest and has the API of wintun.h", "error %u", error) && ready;

	if (ready)
	{
		VrfAdapterTestTwoVrfs(&ctx);
		VrfAdapterTestGateway(&ctx);
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
		Print("VRFADAPTER TEST OK\n");
	}
	else
	{
		Print("VRFADAPTER TEST FAILED (%u of %u checks failed)\n", ctx.NumFailed, ctx.NumChecks);
	}
}
