// firsttest.c
// Named stand-in test of vpntest ("firsttest" command): the two Nodes of the first test of the product on two PCs
// (docs/first-test.md, .github/scripts/first-test.ps1)
//
// The ranzvpnserver service of a PC joins its Controller (step 20 of docs/first-test.md, SDN-90 #395), but two Node
// services cannot form a Noise session yet (Gap 3). This test is the pair of Nodes that does. It runs the overlay of two nodes of the new
// core, pc-a and pc-b, with the static keys of sdntrace.c, and opens the control stream of each to a running ranz controller
// as sdntrace does (Core/Control.h, through NodeOverlayStart). The Intent of the controller holds a Node resource with each
// of those keys, so each node applies its desired state, acknowledges its Generation and gets its address from the
// automatic pool of VRF default. The Noise session between the two nodes runs on the in-process loopback transport.
// - pc-b brings up a real Wintun adapter for VRF default, as the client role of the Node does (NodeClient.c): the adapter
//   holds the address of pc-b and a route to the Network of VRF default, and the packets of the IP stack of the machine on
//   it go into the overlay.
// - pc-a has a fake host that answers an ICMP echo request to its address. Windows delivers a packet for an address of the
//   machine itself on the machine, so two adapters of one machine could not ping each other over the overlay: what this
//   test can show is the ping of the stack of the machine to pc-a, through the adapter of pc-b, the overlay and back.
// "vpntest firsttest <host:port> <key> [<ready file> <stop file>]": the address of the controller's TLS port and its static
// key in base64. With the two files, the test creates the ready file once both nodes joined and the adapter holds its
// address, runs until the stop file exists or Ctrl+C, and then checks that the echo requests of the machine reached the
// fake host and that their replies came back into the adapter. Without them it runs until Ctrl+C and only prints what it
// saw. Print "FIRSTTEST TEST OK" only when every check passes. Needs administrator rights and wintun.dll next to vpntest
// (.github/scripts/fetch-wintun.ps1, or the copy that ranz install writes into the Ranz folder).

#include "controltls.h"
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
#include "Mayaqua/Str.h"
#include "Mayaqua/TcpIp.h"
#include "Mayaqua/Tick64.h"

#include "Core/Control.h"
#include "Core/Transport.h"

#include <iphlpapi.h>

#include <stdio.h>

#define	FIRSTTEST_BUDGET		4200000		// The whole test ends within this time, or the watchdog ends the process (ms)
#define	FIRSTTEST_JOIN			90000		// Both nodes applied their state, with an address, and their session is up within this time (ms)
#define	FIRSTTEST_BOUND			20000		// A bounded wait on what Windows holds (ms)
#define	FIRSTTEST_HOLD			3600000		// The test waits this long for the stop file or Ctrl+C (ms)
#define	FIRSTTEST_POLL			100			// Poll interval of observable state (ms)
#define	FIRSTTEST_NUM_NODES		2
#define	FIRSTTEST_HOST_NODE		0			// The index of pc-a, whose host is the fake host
#define	FIRSTTEST_ADAPTER_NODE	1			// The index of pc-b, whose host is its Wintun adapter
#define	FIRSTTEST_MAX_PACKET	2048

// The two nodes: their names in the intent, and the X25519 public keys of their static scalars 1, 2, ... 32 and 33,
// 34, ... 64, which sdntrace.c and the controller conformance tests use as well (controller/internal/controller)
static char *firsttest_names[FIRSTTEST_NUM_NODES] = {"pc-a", "pc-b"};
static char *firsttest_keys[FIRSTTEST_NUM_NODES] = {"B6N8vBQgk8i3VdwbEOhstCY3StFqqFPtC9/AsrhtHHw=", "WGmv9FBUlzLLqu1eXfmzCm2jHLDldCutWtShp2jxpns="};

// Set by Ctrl+C: the test goes on from its wait to its checks and its clean-up
static HANDLE firsttest_stop = NULL;

// The checks of the test
typedef struct FIRSTTEST_CTX
{
	UINT NumChecks;
	UINT NumFailed;
} FIRSTTEST_CTX;

// One node of the test
typedef struct FIRSTTEST_NODE
{
	char *Name;
	wchar_t Dir[MAX_PATH];				// Its data directory
	PEER_KEY Key;						// Its static key
	NODE *Node;
} FIRSTTEST_NODE;

// The fake host of pc-a: it answers the echo requests to its address
typedef struct FIRSTTEST_HOST
{
	volatile LONG Echoes;				// Echo requests that it answered
	volatile LONG Other;				// Packets that are no echo request
} FIRSTTEST_HOST;

static bool FirstTestCheck(FIRSTTEST_CTX *ctx, bool ok, char *what, char *fmt, ...) RANZ_PRINTF_FORMAT(4, 5);
static bool FirstTestCheck(FIRSTTEST_CTX *ctx, bool ok, char *what, char *fmt, ...)
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
static DWORD WINAPI FirstTestWatchdog(LPVOID param)
{
	char msg[MAX_SIZE];
	DWORD written = 0;

	if (WaitForSingleObject((HANDLE)param, FIRSTTEST_BUDGET) != WAIT_TIMEOUT)
	{
		return 0;
	}

	int len = snprintf(msg, sizeof(msg), "FIRSTTEST TEST FAILED (did not finish within %u ms)\n", FIRSTTEST_BUDGET);
	if (len > 0)
	{
		WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), msg, (DWORD)MIN((UINT)len, (UINT)sizeof(msg) - 1), &written, NULL);
	}

	TerminateProcess(GetCurrentProcess(), 1);

	return 0;
}

// Ctrl+C, Ctrl+Break or the close of the console: the test stops waiting and cleans up, which removes the Wintun adapter
static BOOL WINAPI FirstTestCtrl(DWORD type)
{
	if (firsttest_stop != NULL)
	{
		SetEvent(firsttest_stop);
	}

	return TRUE;
}

// A new empty data directory under the temp directory of the process, with a configuration store that runs no role on
// one worker
static void FirstTestNewDir(wchar_t *dir, UINT size, char *name)
{
	wchar_t tmp[MAX_PATH];
	wchar_t path[MAX_PATH];

	UniFormat(tmp, sizeof(tmp), L"firsttest_%S_%u", name, Rand32());
	ConbinePathW(dir, size, MsGetMyTempDirW(), tmp);
	MakeDirExW(dir);

	ConbinePathW(path, sizeof(path), dir, CS_FILE_NAME);
	CONFIG_STORE *s = CsOpen(path);
	if (s != NULL)
	{
		CsSetSetting(s, NODE_SETTING_ROLES, "none");
		CsSetSetting(s, NODE_SETTING_WORKERS, "1");
		CsClose(s);
	}
}

// The lines of the node log in a data directory that tell about the overlay and the adapters, for a node that did not join
static void FirstTestPrintLog(char *name, wchar_t *dir)
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
			if (InStr(t->Token[j], "Overlay") || InStr(t->Token[j], "Wintun") || InStr(t->Token[j], "VRF adapters") || InStr(t->Token[j], "Peers"))
			{
				Print("  [LOG] %s: %s\n", name, t->Token[j]);
			}
		}
		FreeToken(t);
		Free(text);
		FreeBuf(b);
	}

	FreeDir(d);
}

// Delete the files of a directory, then the directory (it holds no subdirectory)
static void FirstTestDeleteDir(wchar_t *dir)
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

//
// The hosts of the two nodes
//

// The host of pc-a, on the thread of its overlay, an online reader of its tables: an echo request gets its reply, into the
// overlay in the VRF that it came in
static void FirstTestFakeHost(NODE *n, void *param, UINT vrf_id, const UCHAR *packet, UINT size)
{
	FIRSTTEST_HOST *h = (FIRSTTEST_HOST *)param;
	UCHAR reply[FIRSTTEST_MAX_PACKET];
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

	InterlockedIncrement(&h->Echoes);
	NodeOverlayInput(n, vrf_id, reply, total);
}

// The host of pc-b: its adapter of the VRF, which the test plugs into its overlay as the client role does
static void FirstTestToHost(NODE *n, void *param, UINT vrf_id, const UCHAR *packet, UINT size)
{
	NodeVrfAdaptersSend((NODE_VRF_ADAPTERS *)param, vrf_id, packet, size);
}

static void FirstTestApplied(NODE *n, void *param, const CONTROL_STATE *st)
{
	NodeVrfAdaptersApply((NODE_VRF_ADAPTERS *)param, st);
}

static void FirstTestHalt(NODE *n, void *param)
{
	NodeVrfAdaptersHalt((NODE_VRF_ADAPTERS *)param);
}

//
// What the overlay and Windows hold
//

// The first IPv4 address of the overlay of a node, in network byte order: its address in VRF default
static UINT FirstTestAddress(NODE *n)
{
	NODE_OVERLAY_STATUS st;

	NodeOverlayGetStatus(n, &st);

	return (st.NumAddresses != 0 ? st.Addresses[0] : 0);
}

// Whether both nodes applied a state with an address and their Noise session is up, within FIRSTTEST_JOIN
static bool FirstTestWaitJoined(FIRSTTEST_NODE *nodes)
{
	UINT64 end = Tick64() + FIRSTTEST_JOIN;

	while (Tick64() < end)
	{
		bool all = true;

		for (UINT i = 0;i < FIRSTTEST_NUM_NODES;i++)
		{
			NODE_OVERLAY_STATUS st;

			NodeOverlayGetStatus(nodes[i].Node, &st);
			if (st.Connected == false || st.Generation == 0 || st.NumAddresses == 0 || st.NumPeers != FIRSTTEST_NUM_NODES - 1 || st.NumLinks != st.NumPeers)
			{
				all = false;
			}
		}

		if (all)
		{
			return true;
		}
		SleepThread(FIRSTTEST_POLL);
	}

	return false;
}

static void FirstTestShowNodes(FIRSTTEST_NODE *nodes)
{
	for (UINT i = 0;i < FIRSTTEST_NUM_NODES;i++)
	{
		NODE_OVERLAY_STATUS st;
		char addr[64] = "";

		NodeOverlayGetStatus(nodes[i].Node, &st);
		if (st.NumAddresses != 0)
		{
			IPToStr32(addr, sizeof(addr), st.Addresses[0]);
		}
		Print("  [INFO] %s: control stream %s, generation %I64u, name %s, address %s, %u peers, %u sessions, %I64u forwarded, %I64u delivered, %I64u dropped\n",
			nodes[i].Name, (st.Connected ? "open" : "down"), st.Generation, st.Name, addr, st.NumPeers, st.NumLinks, st.Forwarded, st.Delivered, st.Dropped);
	}
}

// Whether the address addr is on the interface of luid, preferred
static bool FirstTestAddressOn(UINT64 luid, UINT addr)
{
	MIB_UNICASTIPADDRESS_ROW row;

	InitializeUnicastIpAddressEntry(&row);
	row.InterfaceLuid.Value = luid;
	row.Address.Ipv4.sin_family = AF_INET;
	Copy(&row.Address.Ipv4.sin_addr, &addr, 4);

	return (GetUnicastIpAddressEntry(&row) == NO_ERROR && row.DadState == IpDadStatePreferred);
}

// Whether Windows takes the interface of luid to dst, with src as the source
static bool FirstTestBestRoute(UINT64 luid, UINT dst, UINT src, char *detail, UINT detail_size)
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

// Whether the interface of luid is gone within FIRSTTEST_BOUND
static bool FirstTestGone(UINT64 luid)
{
	for (UINT64 end = Tick64() + FIRSTTEST_BOUND;Tick64() < end;SleepThread(FIRSTTEST_POLL))
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

// Whether the adapter of pc-b holds its address within FIRSTTEST_BOUND, and which adapter it is: its status into adapter
static bool FirstTestWaitAdapter(NODE_VRF_ADAPTERS *set, UINT addr, NODE_VRF_ADAPTER_STATUS *adapter)
{
	NODE_VRF_ADAPTER_STATUS *list = ZeroMalloc(sizeof(NODE_VRF_ADAPTER_STATUS) * NODE_VRF_MAX_ADAPTERS);
	bool held = false;

	for (UINT64 end = Tick64() + FIRSTTEST_BOUND;held == false && Tick64() < end;SleepThread(FIRSTTEST_POLL))
	{
		UINT num = NodeVrfAdaptersGetStatus(set, list, NODE_VRF_MAX_ADAPTERS);

		if (num == 1 && FirstTestAddressOn(list[0].InterfaceLuid, addr))
		{
			Copy(adapter, &list[0], sizeof(NODE_VRF_ADAPTER_STATUS));
			held = true;
		}
	}

	Free(list);

	return held;
}

// Wait for the stop file, Ctrl+C or the end of FIRSTTEST_HOLD: whether it was one of the first two
static bool FirstTestHold(char *stop_file)
{
	UINT64 end = Tick64() + FIRSTTEST_HOLD;

	while (Tick64() < end)
	{
		if (WaitForSingleObject(firsttest_stop, FIRSTTEST_POLL) != WAIT_TIMEOUT)
		{
			return true;
		}
		if (stop_file != NULL && GetFileAttributesA(stop_file) != INVALID_FILE_ATTRIBUTES)
		{
			return true;
		}
	}

	return false;
}

RANZ_TEST("firsttest", firsttest_test, "Stand-in Nodes of the first test: firsttest <host:port> <key> [<ready file> <stop file>]: two nodes join VRF default of a running ranz controller, pc-b with a Wintun adapter, pc-a with a fake host (docs/first-test.md, .github/scripts/first-test.ps1).");
void firsttest_test(UINT num, char **arg)
{
	FIRSTTEST_CTX *ctx = ZeroMalloc(sizeof(FIRSTTEST_CTX));
	FIRSTTEST_NODE *nodes = ZeroMalloc(sizeof(FIRSTTEST_NODE) * FIRSTTEST_NUM_NODES);
	FIRSTTEST_HOST *host = ZeroMalloc(sizeof(FIRSTTEST_HOST));
	TRANSPORT *tls = ZeroMalloc(sizeof(TRANSPORT));
	TRANSPORT *loopback = NULL;
	NODE_VRF_ADAPTERS *set = NULL;
	NODE_VRF_ADAPTER_STATUS adapter;
	UCHAR controller_key[PEER_KEY_SIZE];
	wchar_t adapter_name[MAX_SIZE];
	HANDLE done = CreateEventW(NULL, TRUE, FALSE, NULL);
	HANDLE watchdog = (done != NULL ? CreateThread(NULL, 0, FirstTestWatchdog, done, 0, NULL) : NULL);
	char *ready_file = (num >= 4 ? arg[2] : NULL);
	char *stop_file = (num >= 4 ? arg[3] : NULL);
	bool joined = false;
	bool holding = false;
	bool ok = false;

	Print("First test: two nodes join VRF default of the controller, pc-b with a Wintun adapter, pc-a with a fake host\n");

	firsttest_stop = CreateEventW(NULL, TRUE, FALSE, NULL);
	SetConsoleCtrlHandler(FirstTestCtrl, TRUE);
	Zero(&adapter, sizeof(adapter));

	// A ready file or a stop file of an earlier run is not this run's
	if (ready_file != NULL)
	{
		DeleteFileA(ready_file);
		DeleteFileA(stop_file);
	}

	// The controller: its address and its static key
	Zero(controller_key, sizeof(controller_key));
	if (num >= 2)
	{
		UINT key_size = 0;
		void *key = Base64ToBin(&key_size, arg[1], StrLen(arg[1]));

		ok = (key != NULL && key_size == PEER_KEY_SIZE);
		if (ok)
		{
			Copy(controller_key, key, PEER_KEY_SIZE);
		}
		Free(key);
	}
	if (FirstTestCheck(ctx, ok, "the controller: its address and its static key", "usage: firsttest <host:port of the controller> <its static key in base64> [<ready file> <stop file>]") == false)
	{
		goto END;
	}

	// The transports: TLS to the controller, loopback between the nodes
	SdnTraceTlsInit(tls);
	loopback = TransportLoopbackNew("loopback", 0, false);
	if (FirstTestCheck(ctx, loopback != NULL && firsttest_stop != NULL, "the in-process loopback transport between the nodes", "TransportLoopbackNew failed") == false)
	{
		goto END;
	}

	// The nodes, each with its static key; pc-b with the adapter of its host, pc-a with the fake host
	StrToUni(adapter_name, sizeof(adapter_name), NODE_CLIENT_ADAPTER);
	for (UINT i = 0;i < FIRSTTEST_NUM_NODES;i++)
	{
		FIRSTTEST_NODE *t = &nodes[i];
		NODE_OVERLAY_CONFIG c;
		UCHAR scalar[PEER_KEY_SIZE];
		UINT size = 0;
		char what[MAX_SIZE];

		t->Name = firsttest_names[i];
		for (UINT j = 0;j < PEER_KEY_SIZE;j++)
		{
			scalar[j] = (UCHAR)(1 + PEER_KEY_SIZE * i + j);
		}
		bool keyed = PeerKeyFromScalar(&t->Key, scalar);
		Zero(scalar, sizeof(scalar));

		void *pub = Base64ToBin(&size, firsttest_keys[i], StrLen(firsttest_keys[i]));
		Format(what, sizeof(what), "%s: its static key is the one of its Node resource", t->Name);
		FirstTestCheck(ctx, keyed && pub != NULL && size == PEER_KEY_SIZE && Cmp(pub, t->Key.Public, PEER_KEY_SIZE) == 0, what, "%s", firsttest_keys[i]);
		Free(pub);

		FirstTestNewDir(t->Dir, sizeof(t->Dir), t->Name);
		t->Node = NewNode(t->Dir);
		NodeStart(t->Node);

		Zero(&c, sizeof(c));
		c.Control = tls;
		StrCpy(c.Controller, sizeof(c.Controller), arg[0]);
		Copy(c.ControllerKey, controller_key, PEER_KEY_SIZE);
		c.Data = loopback;
		c.Key = &t->Key;
		if (i == FIRSTTEST_ADAPTER_NODE)
		{
			// The adapters of the VRFs of pc-b are its host, named as the client role names them: "Ranz default"
			set = NodeVrfAdaptersNew(t->Node, adapter_name, t->Key.Public, false);
			c.Adapter = FirstTestToHost;
			c.AdapterParam = set;
			c.AdapterStop = FirstTestHalt;
			c.State = FirstTestApplied;
		}
		else
		{
			c.Adapter = FirstTestFakeHost;
			c.AdapterParam = host;
		}
		Format(what, sizeof(what), "%s: its overlay runs, with its control stream to %s", t->Name, arg[0]);
		FirstTestCheck(ctx, (i != FIRSTTEST_ADAPTER_NODE || set != NULL) && NodeOverlayStart(t->Node, &c), what, "NodeVrfAdaptersNew (wintun.dll next to vpntest?) or NodeOverlayStart failed");
	}

	// Both join VRF default: a state with an address from its pool, the other node as the peer, the session up
	joined = FirstTestWaitJoined(nodes);
	FirstTestShowNodes(nodes);
	FirstTestCheck(ctx, joined, "both nodes applied their state from the controller, with an address, and their Noise session is up", "not within %u ms", FIRSTTEST_JOIN);

	if (joined)
	{
		UINT addr_a = FirstTestAddress(nodes[FIRSTTEST_HOST_NODE].Node);
		UINT addr_b = FirstTestAddress(nodes[FIRSTTEST_ADAPTER_NODE].Node);
		char a[64];
		char b[64];
		char detail[MAX_SIZE * 2];
		bool held;

		IPToStr32(a, sizeof(a), addr_a);
		IPToStr32(b, sizeof(b), addr_b);
		FirstTestCheck(ctx, addr_a != addr_b && addr_a != 0 && addr_b != 0, "the two addresses differ", "pc-a %s, pc-b %s", a, b);

		held = FirstTestWaitAdapter(set, addr_b, &adapter);
		FirstTestCheck(ctx, held, "the Wintun adapter of pc-b for VRF default holds the address of pc-b", "no adapter with the address %s within %u ms", b, FIRSTTEST_BOUND);

		if (held)
		{
			Print("  [INFO] pc-b: adapter \"%S\", interface %u\n", adapter.Name, adapter.InterfaceIndex);
			FirstTestCheck(ctx, FirstTestBestRoute(adapter.InterfaceLuid, addr_a, addr_b, detail, sizeof(detail)), "Windows takes the adapter of pc-b to pc-a, with the address of pc-b as the source", "%s", detail);

			// The script and the person at the console read the addresses and the adapter from these lines
			Print("FIRSTTEST NODE pc-a ADDRESS %s HOST fake\n", a);
			Print("FIRSTTEST NODE pc-b ADDRESS %s ADAPTER \"%S\"\n", b, adapter.Name);
			Print("FIRSTTEST READY\n");

			if (ready_file != NULL)
			{
				HANDLE f = CreateFileA(ready_file, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

				FirstTestCheck(ctx, f != INVALID_HANDLE_VALUE, "the ready file", "CreateFile %s: error %u", ready_file, (UINT)GetLastError());
				if (f != INVALID_HANDLE_VALUE)
				{
					CloseHandle(f);
				}
			}

			Print("Ping %s from this machine now. Stop the test with Ctrl+C%s.\n", a, (stop_file != NULL ? " or by creating the stop file" : ""));
			holding = FirstTestHold(stop_file);
			FirstTestShowNodes(nodes);

			// What the ping of the machine did: the fake host of pc-a answered it, and the replies came into the adapter
			NODE_VRF_ADAPTER_STATUS *list = ZeroMalloc(sizeof(NODE_VRF_ADAPTER_STATUS) * NODE_VRF_MAX_ADAPTERS);
			UINT listed = NodeVrfAdaptersGetStatus(set, list, NODE_VRF_MAX_ADAPTERS);
			UINT64 from_host = (listed == 1 ? list[0].FromHost : 0);
			UINT64 to_host = (listed == 1 ? list[0].ToHost : 0);
			LONG echoes = ReadAcquire(&host->Echoes);

			Free(list);
			Print("  [INFO] the adapter of pc-b took %I64u packets of the machine and put %I64u into the machine; the fake host of pc-a answered %d echo requests and saw %d other packets\n",
				from_host, to_host, (int)echoes, (int)ReadAcquire(&host->Other));
			if (stop_file != NULL)
			{
				FirstTestCheck(ctx, holding && echoes > 0, "the echo requests of the machine reached the host of pc-a through the adapter of pc-b and the overlay", "stopped by the file or Ctrl+C %u, answered %d", (UINT)holding, (int)echoes);
				FirstTestCheck(ctx, to_host > 0, "the echo replies of pc-a came back into the adapter of pc-b", "%I64u packets", to_host);
			}
		}
	}

	// The overlay of pc-b stops, which halts its adapter, then the adapter goes with its set
	if (nodes[FIRSTTEST_ADAPTER_NODE].Node != NULL)
	{
		NodeOverlayStop(nodes[FIRSTTEST_ADAPTER_NODE].Node);
	}
	if (set != NULL)
	{
		NodeVrfAdaptersFree(set);
		if (adapter.InterfaceLuid != 0)
		{
			FirstTestCheck(ctx, FirstTestGone(adapter.InterfaceLuid), "once the adapter of pc-b is freed, its interface is gone", "the interface is still there");
		}
	}

	for (UINT i = 0;i < FIRSTTEST_NUM_NODES;i++)
	{
		FIRSTTEST_NODE *t = &nodes[i];
		wchar_t log_dir[MAX_PATH];

		if (t->Node == NULL)
		{
			continue;
		}

		NodeStop(t->Node);
		FreeNode(t->Node);
		PeerKeyClose(&t->Key);

		// The node log is written once the node is freed
		if (ctx->NumFailed != 0)
		{
			FirstTestPrintLog(t->Name, t->Dir);
		}
		ConbinePathW(log_dir, sizeof(log_dir), t->Dir, NODE_LOG_DIR_NAME);
		FirstTestDeleteDir(log_dir);
		FirstTestDeleteDir(t->Dir);
	}

END:
	TransportLoopbackFree(loopback);
	SetConsoleCtrlHandler(FirstTestCtrl, FALSE);
	if (firsttest_stop != NULL)
	{
		CloseHandle(firsttest_stop);
		firsttest_stop = NULL;
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

	if (ctx->NumFailed == 0)
	{
		Print("FIRSTTEST TEST OK\n");
	}
	else
	{
		Print("FIRSTTEST TEST FAILED (%u of %u checks failed)\n", ctx->NumFailed, ctx->NumChecks);
	}

	Free(tls);
	Free(host);
	Free(nodes);
	Free(ctx);
}
