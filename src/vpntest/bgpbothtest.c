// bgpbothtest.c
// Named test of vpntest ("bgpboth" command, SDN-77-R1 #531)
//
// The two BGP sidecars of one host: the one toward the routers of the operator (Cedar/NodeBgp.c), whose settings name no
// listen_addresses, so that GoBGP listens on TCP 179 of every address, and the one of the BGP peering of the standard mode
// (Cedar/NodePeering.c), which listens on TCP 179 of the address of its node on the network that the operator trusts only,
// 127.0.0.2 here. Each sidecar starts BGP, which sends ready only once GoBGP listens, while the other one runs, in either
// order of start:
// - the order of a node: the sidecar of the operator starts first, at NodeStart, and the one of the peering with the first
//   Generation that has a peering of the node; one node runs both;
// - the other order: the sidecar of the peering of one node runs, and another node of the same host starts the sidecar of
//   the operator.
// In each order the test reads from the TCP table of Windows that each sidecar listens where it should: the one of the
// operator on 0.0.0.0, the one of the peering on 127.0.0.2; and a session to 127.0.0.2:179 from 127.0.0.9, an address that no
// peer has, reaches the sidecar of the peering, which refuses it and its node counts it, and not the one of the operator. A
// sidecar that cannot listen sends an error and exits, and the node log, which the test prints then, names the error of the
// bind.
// Print "BGPBOTH TEST OK" only when every check passes. .github/scripts/bgp-peering.ps1 runs it after vpntest peering.

#include "testlist.h"

#include "Cedar/Cedar.h"
#include "Cedar/ConfigStore.h"
#include "Cedar/Node.h"
#include "Cedar/NodePeering.h"

#include "Mayaqua/Encrypt.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/IpAddr.h"
#include "Mayaqua/Kernel.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Tick64.h"

#include "Core/Control.h"
#include "Core/Transport.h"

#include <WinDNS.h>
#include <iphlpapi.h>
#include <WS2tcpip.h>

#include <stdio.h>

#define	BGPBOTHTEST_BUDGET		240000		// The whole test ends within this time, or the watchdog ends the process (ms)
#define	BGPBOTHTEST_BOUND		30000		// A bounded wait on observable state (ms)
#define	BGPBOTHTEST_EXIT		15000		// A sidecar of a node that stopped exits within this time (ms)
#define	BGPBOTHTEST_POLL		100			// Poll interval of observable state (ms)
#define	BGPBOTHTEST_PORT		179			// The BGP port of both sidecars
#define	BGPBOTHTEST_ASN			4200000000U	// The AS of the overlay (intent.PeeringASN)
#define	BGPBOTHTEST_VRF			101			// The VRF that peers by BGP
#define	BGPBOTHTEST_HOLD		9			// The hold time of the session of the peering in s
#define	BGPBOTHTEST_ADDRESS		"127.0.0.2"	// The address of the node on the network that the operator trusts
#define	BGPBOTHTEST_PEER		"127.0.0.3"	// ... and of the sidecar of its peer, which never answers
#define	BGPBOTHTEST_STRANGER	"127.0.0.9"	// An address that no peer has

// The settings of the sidecar of the operator: no listen_addresses, so GoBGP listens on every address, and one peer that
// waits for a connection that never comes
#define	BGPBOTHTEST_SETTINGS	"{\"asn\":65001,\"router_id\":\"192.0.2.1\"," \
								"\"peers\":[{\"address\":\"192.0.2.99\",\"asn\":65002,\"passive\":true}]}"

// A node of the test
typedef struct BGPBOTHTEST_NODE
{
	wchar_t Dir[MAX_PATH];				// Its data directory
	NODE *Node;
	PEER_KEY Key;						// Its static key, for its overlay
	bool HasKey;
	bool Overlay;						// Its overlay runs
} BGPBOTHTEST_NODE;

// The test
typedef struct BGPBOTHTEST_CTX
{
	UINT NumChecks;
	UINT NumFailed;
	TRANSPORT *Loopback;				// The in-process loopback transport of the overlays
} BGPBOTHTEST_CTX;

static bool BgpBothCheck(BGPBOTHTEST_CTX *ctx, bool ok, char *what, char *fmt, ...) RANZ_PRINTF_FORMAT(4, 5);
static bool BgpBothCheck(BGPBOTHTEST_CTX *ctx, bool ok, char *what, char *fmt, ...)
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

// The watchdog: a native thread that ends a run that hangs, so that a sidecar that never comes is a failed test instead of a
// hung CI step
static DWORD WINAPI BgpBothWatchdog(LPVOID param)
{
	char msg[MAX_SIZE];
	DWORD written = 0;

	if (WaitForSingleObject((HANDLE)param, BGPBOTHTEST_BUDGET) != WAIT_TIMEOUT)
	{
		return 0;
	}

	int len = snprintf(msg, sizeof(msg), "BGPBOTH TEST FAILED (did not finish within %u ms)\n", BGPBOTHTEST_BUDGET);
	if (len > 0)
	{
		WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), msg, (DWORD)MIN((UINT)len, (UINT)sizeof(msg) - 1), &written, NULL);
	}

	TerminateProcess(GetCurrentProcess(), 1);

	return 0;
}

// The IPv4 address of a text into addr, 4 bytes: false for anything else
static bool BgpBothIp(UCHAR *addr, char *str)
{
	IP ip;

	Zero(addr, 4);
	if (StrToIP(&ip, str) == false || IsIP4(&ip) == false)
	{
		return false;
	}

	Copy(addr, IPV4(ip.address), 4);
	return true;
}

// The IPv4 address of a text in network byte order, as the TCP table of Windows holds it; 0 for anything else
static UINT BgpBothIpUint(char *str)
{
	UCHAR addr[4];
	UINT ret = 0;

	BgpBothIp(addr, str);
	Copy(&ret, addr, 4);

	return ret;
}

// The desired state of a node whose VRF red peers by BGP, as the Controller compiles it: the node at BGPBOTHTEST_ADDRESS,
// with one peer whose sidecar at BGPBOTHTEST_PEER never answers. BgpBothFreeState frees it.
static CONTROL_STATE *BgpBothState(char *name)
{
	CONTROL_STATE *st = ZeroMalloc(sizeof(CONTROL_STATE));
	CONTROL_PEERING *own = ZeroMalloc(sizeof(CONTROL_PEERING));
	CONTROL_PEER_PEERING *pp = ZeroMalloc(sizeof(CONTROL_PEER_PEERING));

	st->Generation = 1;
	StrCpy(st->Name, sizeof(st->Name), name);

	st->NumVrfs = 1;
	StrCpy(st->Vrfs[0].Name, sizeof(st->Vrfs[0].Name), "red");
	st->Vrfs[0].Id = BGPBOTHTEST_VRF;
	st->Vrfs[0].Link = CONTROL_LINK_NOISE;
	st->Vrfs[0].Peering = true;

	st->NumAddresses = 1;
	StrCpy(st->Addresses[0].Network, sizeof(st->Addresses[0].Network), "red");
	st->Addresses[0].VrfId = BGPBOTHTEST_VRF;
	st->Addresses[0].AddressSize = 4;
	st->Addresses[0].Length = 24;
	BgpBothIp(st->Addresses[0].Address, "10.0.0.1");

	own->Asn = BGPBOTHTEST_ASN;
	BgpBothIp(own->RouterId, BGPBOTHTEST_ADDRESS);
	BgpBothIp(own->Address, BGPBOTHTEST_ADDRESS);
	own->AddressSize = 4;
	st->Peering = own;

	st->Peers = ZeroMalloc(sizeof(CONTROL_PEER));
	st->NumPeers = 1;

	CONTROL_PEER *cp = &st->Peers[0];
	StrCpy(cp->Name, sizeof(cp->Name), "node-far");
	for (UINT i = 0;i < PEER_KEY_SIZE;i++)
	{
		cp->Key[i] = (UCHAR)(0x01 + i);
	}
	cp->NumVrfs = 1;
	cp->VrfIds[0] = BGPBOTHTEST_VRF;
	cp->NumAddresses = 1;
	StrCpy(cp->Addresses[0].Network, sizeof(cp->Addresses[0].Network), "red");
	cp->Addresses[0].VrfId = BGPBOTHTEST_VRF;
	cp->Addresses[0].AddressSize = 4;
	cp->Addresses[0].Length = 24;
	BgpBothIp(cp->Addresses[0].Address, "10.0.0.2");

	BgpBothIp(pp->Address, BGPBOTHTEST_PEER);
	pp->AddressSize = 4;
	pp->HoldTime = BGPBOTHTEST_HOLD;
	pp->NumVrfs = 1;
	pp->VrfIds[0] = BGPBOTHTEST_VRF;
	pp->NumAccept = 1;
	pp->Accept[0].VrfId = BGPBOTHTEST_VRF;
	pp->Accept[0].AddressSize = 4;
	pp->Accept[0].Length = 32;
	BgpBothIp(pp->Accept[0].Address, "10.0.0.2");
	cp->Peering = pp;

	return st;
}

static void BgpBothFreeState(CONTROL_STATE *st)
{
	for (UINT i = 0;i < st->NumPeers;i++)
	{
		Free(st->Peers[i].Peering);
	}

	Free(st->Peers);
	Free(st->Peering);
	Free(st);
}

// Delete the files of a directory, which holds no subdirectory, and then the directory
static void BgpBothDeleteFiles(wchar_t *dir)
{
	DIRLIST *d = EnumDirW(dir);

	for (UINT i = 0;d != NULL && i < d->NumFiles;i++)
	{
		wchar_t path[MAX_PATH];

		if (d->File[i]->Folder == false)
		{
			ConbinePathW(path, sizeof(path), dir, d->File[i]->FileNameW);
			FileDeleteW(path);
		}
	}

	FreeDir(d);
	DeleteDirW(dir);
}

// The text of every file of the node log directory of dir; NULL when there is none. The caller frees it.
static char *BgpBothReadLog(wchar_t *dir)
{
	wchar_t log_dir[MAX_PATH];
	BUF *all = NewBuf();

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
		if (b != NULL)
		{
			WriteBuf(all, b->Buf, b->Size);
			FreeBuf(b);
		}
	}
	FreeDir(d);

	char *ret = NULL;
	if (all->Size != 0)
	{
		ret = ZeroMalloc(all->Size + 1);
		Copy(ret, all->Buf, all->Size);
	}
	FreeBuf(all);

	return ret;
}

// Start a node in a new data directory under the temp directory of the process, with no role on one worker and, with
// with_operator, the settings of the sidecar of the operator, which it starts at NodeStart
static void BgpBothStartNode(BGPBOTHTEST_NODE *t, char *name, bool with_operator)
{
	wchar_t tmp[MAX_PATH];
	wchar_t path[MAX_PATH];

	Zero(t, sizeof(BGPBOTHTEST_NODE));
	UniFormat(tmp, sizeof(tmp), L"bgpboth_%S_%u", name, Rand32());
	ConbinePathW(t->Dir, sizeof(t->Dir), MsGetMyTempDirW(), tmp);
	MakeDirExW(t->Dir);

	ConbinePathW(path, sizeof(path), t->Dir, CS_FILE_NAME);
	CONFIG_STORE *s = CsOpen(path);
	if (s != NULL)
	{
		CsSetSetting(s, NODE_SETTING_ROLES, "none");
		CsSetSetting(s, NODE_SETTING_WORKERS, "1");
		if (with_operator)
		{
			CsSetSetting(s, NODE_SETTING_BGP, BGPBOTHTEST_SETTINGS);
		}
		CsClose(s);
	}

	t->Node = NewNode(t->Dir);
	NodeStart(t->Node);
}

// Start the overlay of node t without a control stream and apply the Generation that has a peering of the node: its sidecar
// of the peering starts. Whether the overlay took the Generation.
static bool BgpBothStartPeering(BGPBOTHTEST_CTX *ctx, BGPBOTHTEST_NODE *t, char *name, UCHAR seed)
{
	UCHAR scalar[PEER_KEY_SIZE];
	NODE_OVERLAY_CONFIG c;

	for (UINT i = 0;i < PEER_KEY_SIZE;i++)
	{
		scalar[i] = (UCHAR)(seed + i);
	}
	t->HasKey = PeerKeyFromScalar(&t->Key, scalar);
	Zero(scalar, sizeof(scalar));
	if (t->HasKey == false)
	{
		return false;
	}

	Zero(&c, sizeof(c));
	c.Data = ctx->Loopback;
	c.Key = &t->Key;
	t->Overlay = NodeOverlayStart(t->Node, &c);
	if (t->Overlay == false)
	{
		return false;
	}

	CONTROL_STATE *st = BgpBothState(name);
	bool ok = NodeOverlayApply(t->Node, st);
	BgpBothFreeState(st);

	return ok;
}

// Whether the process pid listens on TCP 179 of the IPv4 address addr, in network byte order (0 for every address)
static bool BgpBothListens(UINT pid, UINT addr)
{
	DWORD size = 0;
	bool ret = false;

	if (pid == 0)
	{
		return false;
	}

	GetExtendedTcpTable(NULL, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_LISTENER, 0);
	if (size == 0)
	{
		return false;
	}

	MIB_TCPTABLE_OWNER_PID *t = ZeroMalloc(size);

	if (GetExtendedTcpTable(t, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_LISTENER, 0) == NO_ERROR)
	{
		for (DWORD i = 0;i < t->dwNumEntries;i++)
		{
			MIB_TCPROW_OWNER_PID *r = &t->table[i];

			if (r->dwOwningPid == pid && ntohs((USHORT)r->dwLocalPort) == BGPBOTHTEST_PORT && r->dwLocalAddr == addr)
			{
				ret = true;
			}
		}
	}

	Free(t);

	return ret;
}

// Whether the sidecar of the operator of node t runs BGP and listens on TCP 179 of every address, within BGPBOTHTEST_BOUND;
// its process into pid
static bool BgpBothWaitOperator(BGPBOTHTEST_NODE *t, UINT *pid)
{
	UINT64 end = Tick64() + BGPBOTHTEST_BOUND;

	while (true)
	{
		NODE_BGP_STATUS st;

		NodeBgpGetStatus(t->Node, &st);
		*pid = st.ProcessId;
		if (st.Running && BgpBothListens(st.ProcessId, 0))
		{
			return true;
		}
		if (Tick64() >= end)
		{
			return false;
		}
		SleepThread(BGPBOTHTEST_POLL);
	}
}

// Whether the sidecar of the peering of node t runs BGP and listens on TCP 179 of BGPBOTHTEST_ADDRESS, within
// BGPBOTHTEST_BOUND; its process into pid
static bool BgpBothWaitPeering(BGPBOTHTEST_NODE *t, UINT *pid)
{
	UINT64 end = Tick64() + BGPBOTHTEST_BOUND;

	while (true)
	{
		NODE_PEERING_STATUS st;

		NodePeeringGetStatus(t->Node, &st);
		*pid = st.ProcessId;
		if (st.Running && BgpBothListens(st.ProcessId, BgpBothIpUint(BGPBOTHTEST_ADDRESS)))
		{
			return true;
		}
		if (Tick64() >= end)
		{
			return false;
		}
		SleepThread(BGPBOTHTEST_POLL);
	}
}

// Whether a session to TCP 179 of BGPBOTHTEST_ADDRESS from BGPBOTHTEST_STRANGER, an address that no peer has, reaches the sidecar of
// the peering of node t and not the sidecar of the operator, which listens on every address: the sidecar of the peering refuses it
// and node t counts it (NODE_PEERING_STATUS.Refused), within BGPBOTHTEST_BOUND
static bool BgpBothReachesPeering(BGPBOTHTEST_NODE *t)
{
	NODE_PEERING_STATUS before, after;
	struct sockaddr_in local, remote;

	NodePeeringGetStatus(t->Node, &before);

	Zero(&local, sizeof(local));
	local.sin_family = AF_INET;
	InetPtonA(AF_INET, BGPBOTHTEST_STRANGER, &local.sin_addr);
	Zero(&remote, sizeof(remote));
	remote.sin_family = AF_INET;
	remote.sin_port = htons(BGPBOTHTEST_PORT);
	InetPtonA(AF_INET, BGPBOTHTEST_ADDRESS, &remote.sin_addr);

	SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	bool connected = (s != INVALID_SOCKET && bind(s, (struct sockaddr *)&local, sizeof(local)) == 0 && connect(s, (struct sockaddr *)&remote, sizeof(remote)) == 0);

	UINT64 end = Tick64() + BGPBOTHTEST_BOUND;
	bool counted = false;
	while (connected)
	{
		NodePeeringGetStatus(t->Node, &after);
		counted = (after.Refused > before.Refused);
		if (counted || Tick64() >= end)
		{
			break;
		}
		SleepThread(BGPBOTHTEST_POLL);
	}

	if (s != INVALID_SOCKET)
	{
		closesocket(s);
	}

	return counted;
}

// Whether the process pid ended; 0 is none
static bool BgpBothExited(UINT pid)
{
	HANDLE p = (pid != 0 ? OpenProcess(SYNCHRONIZE, FALSE, pid) : NULL);
	bool exited = (p == NULL || WaitForSingleObject(p, 0) == WAIT_OBJECT_0);

	if (p != NULL)
	{
		CloseHandle(p);
	}

	return exited;
}

// Whether the processes pid1 and pid2 ended within BGPBOTHTEST_EXIT
static bool BgpBothWaitExited(UINT pid1, UINT pid2)
{
	UINT64 end = Tick64() + BGPBOTHTEST_EXIT;

	while (BgpBothExited(pid1) == false || BgpBothExited(pid2) == false)
	{
		if (Tick64() >= end)
		{
			return false;
		}
		SleepThread(BGPBOTHTEST_POLL);
	}

	return true;
}

// The lines of the node log of t that name BGP, printed after what
static void BgpBothPrintLog(BGPBOTHTEST_NODE *t, char *what)
{
	char *log = BgpBothReadLog(t->Dir);
	TOKEN_LIST *lines = (log != NULL ? ParseToken(log, "\r\n") : NULL);

	Print("  --- the lines of %s that name BGP ---\n", what);
	for (UINT i = 0;lines != NULL && i < lines->NumTokens;i++)
	{
		if (SearchStrEx(lines->Token[i], "BGP", 0, true) != INFINITE || SearchStrEx(lines->Token[i], "listen", 0, false) != INFINITE)
		{
			Print("  %s\n", lines->Token[i]);
		}
	}
	Print("  ---\n");

	FreeToken(lines);
	Free(log);
}

// Stop and free a node of the test, and delete its data directory
static void BgpBothCloseNode(BGPBOTHTEST_NODE *t)
{
	wchar_t log_dir[MAX_PATH];

	if (t->Node == NULL)
	{
		return;
	}

	NodeStop(t->Node);
	FreeNode(t->Node);
	t->Node = NULL;
	if (t->HasKey)
	{
		PeerKeyClose(&t->Key);
		t->HasKey = false;
	}

	ConbinePathW(log_dir, sizeof(log_dir), t->Dir, NODE_LOG_DIR_NAME);
	BgpBothDeleteFiles(log_dir);
	BgpBothDeleteFiles(t->Dir);
}

// The order of a node: its sidecar of the operator starts at NodeStart and listens on every address, then the first
// Generation with a peering of the node starts its sidecar of the peering, which listens on BGPBOTHTEST_ADDRESS; both run
static void BgpBothOperatorFirst(BGPBOTHTEST_CTX *ctx)
{
	BGPBOTHTEST_NODE t;
	UINT op_pid = 0, peering_pid = 0;

	Print("[one node: the sidecar of the operator starts first, then the one of the peering]\n");

	BgpBothStartNode(&t, "one", true);
	bool op = BgpBothWaitOperator(&t, &op_pid);
	BgpBothCheck(ctx, op, "The sidecar of the operator runs BGP and listens on TCP 179 of every address", "process %u", op_pid);

	bool applied = BgpBothStartPeering(ctx, &t, "node-one", 0x31);
	bool peering = (applied && BgpBothWaitPeering(&t, &peering_pid));
	BgpBothCheck(ctx, peering, "The sidecar of the peering of the same node then runs BGP and listens on TCP 179 of 127.0.0.2", "applied %u, process %u",
		(UINT)applied, peering_pid);

	bool both = (op && peering && BgpBothListens(op_pid, 0) && BgpBothListens(peering_pid, BgpBothIpUint(BGPBOTHTEST_ADDRESS)));
	BgpBothCheck(ctx, both, "Both sidecars of the node listen at once, the one of the operator on 0.0.0.0:179 and the one of the peering on 127.0.0.2:179",
		"operator %u, peering %u", (UINT)op, (UINT)peering);
	BgpBothCheck(ctx, both && BgpBothReachesPeering(&t), "A session to 127.0.0.2:179 from 127.0.0.9 reaches the sidecar of the peering, which refuses it and the node counts it, and not the one of the operator",
		"both listen %u", (UINT)both);

	if (both == false)
	{
		BgpBothPrintLog(&t, "the node");
	}

	BgpBothCloseNode(&t);
	BgpBothCheck(ctx, BgpBothWaitExited(op_pid, peering_pid), "Both sidecars exit once the node stops", "process %u and %u", op_pid, peering_pid);
}

// The other order: the sidecar of the peering of one node runs and listens on BGPBOTHTEST_ADDRESS, then another node of the
// host starts the sidecar of the operator, which listens on every address; both run
static void BgpBothPeeringFirst(BGPBOTHTEST_CTX *ctx)
{
	BGPBOTHTEST_NODE a, b;
	UINT op_pid = 0, peering_pid = 0;

	Print("[two nodes of one host: the sidecar of the peering runs, then the one of the operator starts]\n");

	BgpBothStartNode(&a, "peering", false);
	bool applied = BgpBothStartPeering(ctx, &a, "node-peering", 0x51);
	bool peering = (applied && BgpBothWaitPeering(&a, &peering_pid));
	BgpBothCheck(ctx, peering, "The sidecar of the peering runs BGP and listens on TCP 179 of 127.0.0.2", "applied %u, process %u", (UINT)applied, peering_pid);

	BgpBothStartNode(&b, "operator", true);
	bool op = BgpBothWaitOperator(&b, &op_pid);
	BgpBothCheck(ctx, op, "The sidecar of the operator then runs BGP and listens on TCP 179 of every address", "process %u", op_pid);

	bool both = (op && peering && BgpBothListens(op_pid, 0) && BgpBothListens(peering_pid, BgpBothIpUint(BGPBOTHTEST_ADDRESS)));
	BgpBothCheck(ctx, both, "Both sidecars listen at once, the one of the peering on 127.0.0.2:179 and the one of the operator on 0.0.0.0:179",
		"peering %u, operator %u", (UINT)peering, (UINT)op);
	BgpBothCheck(ctx, both && BgpBothReachesPeering(&a), "A session to 127.0.0.2:179 from 127.0.0.9 reaches the sidecar of the peering, which refuses it and the node counts it, and not the one of the operator",
		"both listen %u", (UINT)both);

	if (both == false)
	{
		BgpBothPrintLog(&a, "the node of the peering");
		BgpBothPrintLog(&b, "the node of the operator");
	}

	BgpBothCloseNode(&b);
	BgpBothCloseNode(&a);
	BgpBothCheck(ctx, BgpBothWaitExited(op_pid, peering_pid), "Both sidecars exit once the nodes stop", "process %u and %u", op_pid, peering_pid);
}

// bgpboth: the sidecar of the operator and the sidecar of the peering on one host, in either order of start
RANZ_TEST("bgpboth", bgpboth_test, "The two BGP sidecars of one host (ranz.exe next to vpntest): the one of the operator, which listens on TCP 179 of every address, and the one of the BGP peering of the standard mode, which listens on TCP 179 of 127.0.0.2, both run in either order of start.");
void bgpboth_test(UINT num, char **arg)
{
	BGPBOTHTEST_CTX *ctx = ZeroMalloc(sizeof(BGPBOTHTEST_CTX));
	HANDLE done = CreateEventW(NULL, TRUE, FALSE, NULL);
	HANDLE watchdog = (done != NULL ? CreateThread(NULL, 0, BgpBothWatchdog, done, 0, NULL) : NULL);
	wchar_t sidecar[MAX_PATH];

	Print("BGP sidecars test: the sidecar of the operator and the sidecar of the peering of the standard mode on one host\n");

	ctx->Loopback = TransportLoopbackNew("loopback", 0, false);

	// Where a node looks for the sidecars: ranz.exe next to its own executable
	GetExeDirW(sidecar, sizeof(sidecar));
	ConbinePathW(sidecar, sizeof(sidecar), sidecar, NODE_BGP_EXE_NAME);

	if (BgpBothCheck(ctx, ctx->Loopback != NULL && IsFileExistsW(sidecar), "ranz.exe, which holds both sidecars, is next to vpntest.exe", "%S is missing, or no loopback transport", sidecar))
	{
		BgpBothOperatorFirst(ctx);
		BgpBothPeeringFirst(ctx);
	}

	TransportLoopbackFree(ctx->Loopback);

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

	if (ctx->NumFailed == 0)
	{
		Print("BGPBOTH TEST OK\n");
	}
	else
	{
		Print("BGPBOTH TEST FAILED (%u of %u checks failed)\n", ctx->NumFailed, ctx->NumChecks);
	}

	Free(ctx);
}
