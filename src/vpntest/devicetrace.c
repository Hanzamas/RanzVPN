// devicetrace.c
// Named test of vpntest ("devicetrace" command): the gateway Node and the overlay host of the WireGuard Device tracer
// (SDN-80, #375; .github/scripts/device-tracer.ps1)
//
// Two nodes of the new core, gw and host, with the static keys of sdntrace.c, open their control streams to a running ranz
// controller (Core/Control.h, through NodeOverlayStart) whose Intent holds a Node resource with each key and a WireGuard
// Device whose gateway is gw. Their Noise session runs on the in-process loopback transport.
// - gw is the gateway: its host is a real Wintun adapter for VRF default that forwards, as the adapter of a gateway does
//   (NodeVrfAdapter.c), and its WireGuard interface (NodeWireGuard.c, on the wireguard.dll of WireGuardNT next to vpntest)
//   terminates the Device on the UDP port of its state. Windows forwards between the two.
// - host has a fake host, the overlay host of the tracer: it answers an ICMP echo request to its address and echoes the
//   bytes of a TCP connection to any of its ports, keeping no state (DeviceTraceTcp).
// A stock WireGuard client outside the process (ranz-wgpeer, controller/cmd/ranz-wgpeer) reaches host through gw: its
// packets leave the WireGuard interface, Windows forwards them into the adapter of gw, and the overlay of gw judges them
// by the policy of the VRF as the packets of the Device (NodePolicy.c) before it sends them to host; the replies come
// back the same way. Windows delivers a packet for an address of the machine itself on the machine, which is why the
// overlay host is a fake host of the other node and not the IP stack of the machine.
// "vpntest devicetrace <host:port> <key> <ready file> <stop file>": the address of the controller's TLS port and its static
// key in base64. The test creates the ready file once both nodes joined, the adapter of gw holds its address and the
// WireGuard interface of gw is up with the Device, and prints the addresses and the port; then it runs until the stop file
// exists or Ctrl+C, prints what the fake host answered and what the policy of gw dropped, and checks that the WireGuard
// interface goes with the overlay of gw. Print "DEVICETRACE TEST OK" only when every check passes. Needs administrator
// rights, and wintun.dll and wireguard.dll next to vpntest (.github/scripts/fetch-wintun.ps1 and fetch-wireguard.ps1).

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

#define	DEVICETRACE_BUDGET		4200000		// The whole test ends within this time, or the watchdog ends the process (ms)
#define	DEVICETRACE_JOIN		90000		// Both nodes applied their state, with an address, and their session is up within this time (ms)
#define	DEVICETRACE_BOUND		60000		// A bounded wait on what Windows holds: the first WireGuard interface installs its driver (ms)
#define	DEVICETRACE_HOLD		3600000		// The test waits this long for the stop file or Ctrl+C (ms)
#define	DEVICETRACE_POLL		100			// Poll interval of observable state (ms)
#define	DEVICETRACE_NUM_NODES	2
#define	DEVICETRACE_GATEWAY		0			// The index of gw, the gateway of the Device
#define	DEVICETRACE_HOST		1			// The index of host, whose host is the fake host
#define	DEVICETRACE_MAX_PACKET	2048
#define	DEVICETRACE_ISN			0x52414E5A	// The initial sequence number of the TCP of the fake host ("RANZ")

// The two nodes: their names in the intent, and the X25519 public keys of their static scalars 1, 2, ... 32 and 33, 34,
// ... 64, which sdntrace.c and the controller conformance tests use as well (controller/internal/controller)
static char *devicetrace_names[DEVICETRACE_NUM_NODES] = {"gw", "host"};
static char *devicetrace_keys[DEVICETRACE_NUM_NODES] = {"B6N8vBQgk8i3VdwbEOhstCY3StFqqFPtC9/AsrhtHHw=", "WGmv9FBUlzLLqu1eXfmzCm2jHLDldCutWtShp2jxpns="};

// Set by Ctrl+C: the test goes on from its wait to its checks and its clean-up
static HANDLE devicetrace_stop = NULL;

// The checks of the test
typedef struct DEVICETRACE_CTX
{
	UINT NumChecks;
	UINT NumFailed;
} DEVICETRACE_CTX;

// One node of the test
typedef struct DEVICETRACE_NODE
{
	char *Name;
	wchar_t Dir[MAX_PATH];				// Its data directory
	PEER_KEY Key;						// Its static key
	NODE *Node;
} DEVICETRACE_NODE;

// The fake host of node host: what it answered
typedef struct DEVICETRACE_HOST
{
	volatile LONG Echoes;				// ICMP echo requests that it answered
	volatile LONG Accepted;				// TCP SYNs that it answered with a SYN-ACK
	volatile LONG Echoed;				// TCP segments whose bytes it sent back
	volatile LONG Other;				// Packets that it did not answer
} DEVICETRACE_HOST;

static bool DeviceTraceCheck(DEVICETRACE_CTX *ctx, bool ok, char *what, char *fmt, ...) RANZ_PRINTF_FORMAT(4, 5);
static bool DeviceTraceCheck(DEVICETRACE_CTX *ctx, bool ok, char *what, char *fmt, ...)
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

// The watchdog: a native thread that ends a run that hangs, so that a lost packet is a failed test instead of a hung CI
// step
static DWORD WINAPI DeviceTraceWatchdog(LPVOID param)
{
	char msg[MAX_SIZE];
	DWORD written = 0;

	if (WaitForSingleObject((HANDLE)param, DEVICETRACE_BUDGET) != WAIT_TIMEOUT)
	{
		return 0;
	}

	int len = snprintf(msg, sizeof(msg), "DEVICETRACE TEST FAILED (did not finish within %u ms)\n", DEVICETRACE_BUDGET);
	if (len > 0)
	{
		WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), msg, (DWORD)MIN((UINT)len, (UINT)sizeof(msg) - 1), &written, NULL);
	}

	TerminateProcess(GetCurrentProcess(), 1);

	return 0;
}

// Ctrl+C, Ctrl+Break or the close of the console: the test stops waiting and cleans up, which removes the adapters
static BOOL WINAPI DeviceTraceCtrl(DWORD type)
{
	if (devicetrace_stop != NULL)
	{
		SetEvent(devicetrace_stop);
	}

	return TRUE;
}

// A new empty data directory of a node under the temp directory of the process, whose configuration store runs no role
// on one worker
static void DeviceTraceNewDir(wchar_t *dir, UINT size, char *name)
{
	wchar_t tmp[MAX_PATH];
	wchar_t path[MAX_PATH];

	UniFormat(tmp, sizeof(tmp), L"devicetrace_%S_%u", name, Rand32());
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

// The lines of the node log of a data directory about the overlay, the adapters and WireGuard, for a failed run
static void DeviceTracePrintLog(char *name, wchar_t *dir)
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
			char *line = t->Token[j];

			if (InStr(line, "Overlay") || InStr(line, "Wintun") || InStr(line, "VRF adapters") || InStr(line, "Peers") || InStr(line, "WireGuard"))
			{
				Print("  [LOG] %s: %s\n", name, line);
			}
		}
		FreeToken(t);
		Free(text);
		FreeBuf(b);
	}

	FreeDir(d);
}

// Delete the files of a directory, then the directory, which holds no directory
static void DeviceTraceDeleteDir(wchar_t *dir)
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
// The fake host of node host
//

// The IPv4 header of the reply to the packet p into reply: total bytes in all, the protocol, the addresses of p swapped
// and its checksum
static void DeviceTraceReplyHeader(UCHAR *reply, const UCHAR *p, UCHAR protocol, UINT total)
{
	USHORT sum;

	Zero(reply, 20);
	reply[0] = 0x45;
	reply[2] = (UCHAR)(total >> 8);
	reply[3] = (UCHAR)(total & 0xFF);
	reply[8] = 64;
	reply[9] = protocol;
	Copy(reply + 12, p + 16, 4);
	Copy(reply + 16, p + 12, 4);
	sum = IpChecksum(reply, 20);
	Copy(reply + 10, &sum, 2);
}

// The echo reply to the ICMP echo request p of total bytes into reply: its size, 0 when p is no echo request
static UINT DeviceTraceEcho(const UCHAR *p, UINT total, UCHAR *reply)
{
	USHORT sum;

	if (total < 28 || p[20] != 8)
	{
		return 0;
	}

	DeviceTraceReplyHeader(reply, p, IP_PROTO_ICMPV4, total);
	Copy(reply + 20, p + 20, total - 20);
	reply[20] = 0;
	reply[22] = 0;
	reply[23] = 0;
	sum = IpChecksum(reply + 20, total - 20);
	Copy(reply + 22, &sum, 2);

	return total;
}

// The answer to the TCP segment p of total bytes into reply, as an echo server answers on any port: its size, 0 for no
// answer. The fake host keeps no state. A SYN gets a SYN-ACK from DEVICETRACE_ISN; a segment with bytes gets the same
// bytes back, and a FIN gets a FIN, from the sequence number that the client acknowledges, which is the next one of the
// fake host. A bare acknowledgement and a reset get nothing.
static UINT DeviceTraceTcp(DEVICETRACE_HOST *h, const UCHAR *p, UINT total, UCHAR *reply)
{
	UCHAR *t = reply + 20;
	UINT size, seq, ack, data, len, next;
	UINT src = 0, dst = 0;
	UCHAR flags, out;
	USHORT sum;

	if (total < 40)
	{
		return 0;
	}

	size = (UINT)(p[32] >> 4) * 4;
	if (size < 20 || 20 + size > total)
	{
		return 0;
	}

	data = total - 20 - size;
	seq = READ_UINT(p + 24);
	ack = READ_UINT(p + 28);
	flags = p[33];

	if ((flags & TCP_RST) != 0)
	{
		return 0;
	}
	else if ((flags & TCP_SYN) != 0 && (flags & TCP_ACK) == 0)
	{
		out = (UCHAR)(TCP_SYN | TCP_ACK);
		ack = seq + 1;
		seq = DEVICETRACE_ISN;
		data = 0;
		InterlockedIncrement(&h->Accepted);
	}
	else if ((flags & TCP_ACK) != 0 && (data != 0 || (flags & TCP_FIN) != 0))
	{
		out = (UCHAR)(TCP_ACK | (data != 0 ? TCP_PSH : 0) | (flags & TCP_FIN));
		len = data + ((flags & TCP_FIN) != 0 ? 1 : 0);
		next = ack;
		ack = seq + len;
		seq = next;
		if (data != 0)
		{
			InterlockedIncrement(&h->Echoed);
		}
	}
	else
	{
		return 0;
	}

	if (40 + data > DEVICETRACE_MAX_PACKET)
	{
		return 0;
	}

	DeviceTraceReplyHeader(reply, p, IP_PROTO_TCP, 40 + data);
	Zero(t, 20);
	Copy(t, p + 22, 2);
	Copy(t + 2, p + 20, 2);
	WRITE_UINT(t + 4, seq);
	WRITE_UINT(t + 8, ack);
	t[12] = 5 << 4;
	t[13] = out;
	t[14] = 0xFF;
	t[15] = 0xFF;
	Copy(t + 20, p + 20 + size, data);
	Copy(&src, reply + 12, 4);
	Copy(&dst, reply + 16, 4);
	sum = CalcChecksumForIPv4(src, dst, IP_PROTO_TCP, t, 20 + data, 0);
	Copy(t + 16, &sum, 2);

	return 40 + data;
}

// The host of node host, on the thread of its overlay, an online reader of its tables: the answer to an IPv4 packet
// without options goes into the overlay in the VRF that the packet came in
static void DeviceTraceFakeHost(NODE *n, void *param, UINT vrf_id, const UCHAR *packet, UINT size)
{
	DEVICETRACE_HOST *h = (DEVICETRACE_HOST *)param;
	UCHAR reply[DEVICETRACE_MAX_PACKET];
	UINT total = (size >= 4 ? (((UINT)packet[2] << 8) | packet[3]) : 0);
	UINT len = 0;

	if (size >= 20 && packet[0] == 0x45 && total >= 20 && total <= size && total <= sizeof(reply))
	{
		if (packet[9] == IP_PROTO_ICMPV4)
		{
			len = DeviceTraceEcho(packet, total, reply);
			if (len != 0)
			{
				InterlockedIncrement(&h->Echoes);
			}
		}
		else if (packet[9] == IP_PROTO_TCP)
		{
			len = DeviceTraceTcp(h, packet, total, reply);
		}
	}

	if (len == 0)
	{
		InterlockedIncrement(&h->Other);
		return;
	}

	NodeOverlayInput(n, vrf_id, reply, len);
}

//
// The host of node gw: its adapter of the VRF, which the test plugs into its overlay as the client role does
//

static void DeviceTraceToHost(NODE *n, void *param, UINT vrf_id, const UCHAR *packet, UINT size)
{
	NodeVrfAdaptersSend((NODE_VRF_ADAPTERS *)param, vrf_id, packet, size);
}

static void DeviceTraceApplied(NODE *n, void *param, const CONTROL_STATE *st)
{
	NodeVrfAdaptersApply((NODE_VRF_ADAPTERS *)param, st);
}

static void DeviceTraceHalt(NODE *n, void *param)
{
	NodeVrfAdaptersHalt((NODE_VRF_ADAPTERS *)param);
}

//
// What the overlay and Windows hold
//

// The first IPv4 address of the overlay of a node, in network byte order: its address in VRF default
static UINT DeviceTraceAddress(NODE *n)
{
	NODE_OVERLAY_STATUS st;

	NodeOverlayGetStatus(n, &st);

	return (st.NumAddresses != 0 ? st.Addresses[0] : 0);
}

static void DeviceTraceShowNodes(DEVICETRACE_NODE *nodes)
{
	for (UINT i = 0;i < DEVICETRACE_NUM_NODES;i++)
	{
		NODE_OVERLAY_STATUS st;
		char addr[64] = "";

		NodeOverlayGetStatus(nodes[i].Node, &st);
		if (st.NumAddresses != 0)
		{
			IPToStr32(addr, sizeof(addr), st.Addresses[0]);
		}
		Print("  [INFO] %s: control stream %s, generation %I64u, address %s, %u peers, %u sessions, %I64u forwarded, %I64u delivered, %I64u dropped\n",
			nodes[i].Name, (st.Connected ? "open" : "down"), st.Generation, addr, st.NumPeers, st.NumLinks, st.Forwarded, st.Delivered, st.Dropped);
	}
}

// Whether both nodes applied a state with an address and their Noise session is up, within DEVICETRACE_JOIN
static bool DeviceTraceWaitJoined(DEVICETRACE_NODE *nodes)
{
	for (UINT64 end = Tick64() + DEVICETRACE_JOIN;Tick64() < end;SleepThread(DEVICETRACE_POLL))
	{
		UINT joined = 0;

		for (UINT i = 0;i < DEVICETRACE_NUM_NODES;i++)
		{
			NODE_OVERLAY_STATUS st;

			NodeOverlayGetStatus(nodes[i].Node, &st);
			if (st.Connected && st.Generation != 0 && st.NumAddresses != 0 && st.NumPeers == DEVICETRACE_NUM_NODES - 1 && st.NumLinks == st.NumPeers)
			{
				joined++;
			}
		}

		if (joined == DEVICETRACE_NUM_NODES)
		{
			return true;
		}
	}

	return false;
}

// Whether the adapter of gw holds the address addr, preferred, within DEVICETRACE_BOUND: the adapter into adapter
static bool DeviceTraceWaitAdapter(NODE_VRF_ADAPTERS *set, UINT addr, NODE_VRF_ADAPTER_STATUS *adapter)
{
	NODE_VRF_ADAPTER_STATUS *list = ZeroMalloc(sizeof(NODE_VRF_ADAPTER_STATUS) * NODE_VRF_MAX_ADAPTERS);
	bool held = false;

	for (UINT64 end = Tick64() + DEVICETRACE_BOUND;held == false && Tick64() < end;SleepThread(DEVICETRACE_POLL))
	{
		MIB_UNICASTIPADDRESS_ROW row;

		if (NodeVrfAdaptersGetStatus(set, list, NODE_VRF_MAX_ADAPTERS) != 1)
		{
			continue;
		}

		InitializeUnicastIpAddressEntry(&row);
		row.InterfaceLuid.Value = list[0].InterfaceLuid;
		row.Address.Ipv4.sin_family = AF_INET;
		Copy(&row.Address.Ipv4.sin_addr, &addr, 4);
		if (GetUnicastIpAddressEntry(&row) == NO_ERROR && row.DadState == IpDadStatePreferred)
		{
			Copy(adapter, &list[0], sizeof(NODE_VRF_ADAPTER_STATUS));
			held = true;
		}
	}

	Free(list);

	return held;
}

// Whether the WireGuard interface of gw is up with one Device and the routes of its addresses, within DEVICETRACE_BOUND:
// its status into wg
static bool DeviceTraceWaitWireGuard(NODE *gw, NODE_WIREGUARD_STATUS *wg)
{
	for (UINT64 end = Tick64() + DEVICETRACE_BOUND;Tick64() < end;SleepThread(DEVICETRACE_POLL))
	{
		NodeWireGuardGetStatus(gw, wg);
		if (wg->Up && wg->NumDevices == 1 && wg->Port != 0 && wg->NumRoutes != 0)
		{
			return true;
		}
	}

	return false;
}

// Whether the interface of luid is gone within DEVICETRACE_BOUND
static bool DeviceTraceGone(UINT64 luid)
{
	for (UINT64 end = Tick64() + DEVICETRACE_BOUND;Tick64() < end;SleepThread(DEVICETRACE_POLL))
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

// Wait for the stop file, Ctrl+C or the end of DEVICETRACE_HOLD: whether it was one of the first two
static bool DeviceTraceHold(char *stop_file)
{
	for (UINT64 end = Tick64() + DEVICETRACE_HOLD;Tick64() < end;)
	{
		if (WaitForSingleObject(devicetrace_stop, DEVICETRACE_POLL) != WAIT_TIMEOUT)
		{
			return true;
		}
		if (GetFileAttributesA(stop_file) != INVALID_FILE_ATTRIBUTES)
		{
			return true;
		}
	}

	return false;
}

RANZ_TEST("devicetrace", devicetrace_test, "Gateway of the WireGuard Device tracer: devicetrace <host:port> <key> <ready file> <stop file>: gw terminates a Device on WireGuardNT and forwards it into the overlay, host answers echo requests and TCP (.github/scripts/device-tracer.ps1).");
void devicetrace_test(UINT num, char **arg)
{
	DEVICETRACE_CTX *ctx = ZeroMalloc(sizeof(DEVICETRACE_CTX));
	DEVICETRACE_NODE *nodes = ZeroMalloc(sizeof(DEVICETRACE_NODE) * DEVICETRACE_NUM_NODES);
	DEVICETRACE_HOST *host = ZeroMalloc(sizeof(DEVICETRACE_HOST));
	TRANSPORT *tls = ZeroMalloc(sizeof(TRANSPORT));
	TRANSPORT *loopback = NULL;
	NODE_VRF_ADAPTERS *set = NULL;
	NODE_VRF_ADAPTER_STATUS adapter;
	NODE_WIREGUARD_STATUS wg;
	UCHAR controller_key[PEER_KEY_SIZE];
	wchar_t adapter_name[MAX_SIZE];
	HANDLE done = CreateEventW(NULL, TRUE, FALSE, NULL);
	HANDLE watchdog = (done != NULL ? CreateThread(NULL, 0, DeviceTraceWatchdog, done, 0, NULL) : NULL);
	char *ready_file = (num >= 4 ? arg[2] : NULL);
	char *stop_file = (num >= 4 ? arg[3] : NULL);
	bool joined = false;
	bool ok = false;

	Print("WireGuard Device tracer: gw terminates the Device on WireGuardNT and forwards it into the overlay, host answers it\n");

	devicetrace_stop = CreateEventW(NULL, TRUE, FALSE, NULL);
	SetConsoleCtrlHandler(DeviceTraceCtrl, TRUE);
	Zero(&adapter, sizeof(adapter));
	Zero(&wg, sizeof(wg));

	// The controller: its address and its static key; and the two files of the script
	Zero(controller_key, sizeof(controller_key));
	if (num >= 4)
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
	if (DeviceTraceCheck(ctx, ok, "the controller: its address and its static key, and the ready and stop files", "usage: devicetrace <host:port of the controller> <its static key in base64> <ready file> <stop file>") == false)
	{
		goto END;
	}

	// A ready file or a stop file of an earlier run is not this run's
	DeleteFileA(ready_file);
	DeleteFileA(stop_file);

	// The transports: TLS to the controller, loopback between the nodes
	SdnTraceTlsInit(tls);
	loopback = TransportLoopbackNew("loopback", 0, false);
	if (DeviceTraceCheck(ctx, loopback != NULL && devicetrace_stop != NULL, "the in-process loopback transport between the nodes", "TransportLoopbackNew failed") == false)
	{
		goto END;
	}

	// The nodes, each with its static key; gw with the forwarding adapter of its host, host with the fake host
	StrToUni(adapter_name, sizeof(adapter_name), "Ranz tracer");
	for (UINT i = 0;i < DEVICETRACE_NUM_NODES;i++)
	{
		DEVICETRACE_NODE *t = &nodes[i];
		NODE_OVERLAY_CONFIG c;
		UCHAR scalar[PEER_KEY_SIZE];
		UINT size = 0;
		char what[MAX_SIZE];

		t->Name = devicetrace_names[i];
		for (UINT j = 0;j < PEER_KEY_SIZE;j++)
		{
			scalar[j] = (UCHAR)(1 + PEER_KEY_SIZE * i + j);
		}
		bool keyed = PeerKeyFromScalar(&t->Key, scalar);
		Zero(scalar, sizeof(scalar));

		void *pub = Base64ToBin(&size, devicetrace_keys[i], StrLen(devicetrace_keys[i]));
		Format(what, sizeof(what), "%s: its static key is the one of its Node resource", t->Name);
		DeviceTraceCheck(ctx, keyed && pub != NULL && size == PEER_KEY_SIZE && Cmp(pub, t->Key.Public, PEER_KEY_SIZE) == 0, what, "%s", devicetrace_keys[i]);
		Free(pub);

		DeviceTraceNewDir(t->Dir, sizeof(t->Dir), t->Name);
		t->Node = NewNode(t->Dir);
		NodeStart(t->Node);

		Zero(&c, sizeof(c));
		c.Control = tls;
		StrCpy(c.Controller, sizeof(c.Controller), arg[0]);
		Copy(c.ControllerKey, controller_key, PEER_KEY_SIZE);
		c.Data = loopback;
		c.Key = &t->Key;
		if (i == DEVICETRACE_GATEWAY)
		{
			// A gateway forwards between its adapters and the other interfaces of the host: here its WireGuard interface
			set = NodeVrfAdaptersNew(t->Node, adapter_name, t->Key.Public, true);
			c.Adapter = DeviceTraceToHost;
			c.AdapterParam = set;
			c.AdapterStop = DeviceTraceHalt;
			c.State = DeviceTraceApplied;
		}
		else
		{
			c.Adapter = DeviceTraceFakeHost;
			c.AdapterParam = host;
		}
		Format(what, sizeof(what), "%s: its overlay runs, with its control stream to %s", t->Name, arg[0]);
		DeviceTraceCheck(ctx, (i != DEVICETRACE_GATEWAY || set != NULL) && NodeOverlayStart(t->Node, &c), what, "NodeVrfAdaptersNew (wintun.dll next to vpntest?) or NodeOverlayStart failed");
	}

	// Both join VRF default: a state with an address from its pool, the other node as the peer, the session up
	joined = DeviceTraceWaitJoined(nodes);
	DeviceTraceShowNodes(nodes);
	DeviceTraceCheck(ctx, joined, "both nodes applied their state from the controller, with an address, and their Noise session is up", "not within %u ms", DEVICETRACE_JOIN);

	if (joined)
	{
		UINT addr_gw = DeviceTraceAddress(nodes[DEVICETRACE_GATEWAY].Node);
		UINT addr_host = DeviceTraceAddress(nodes[DEVICETRACE_HOST].Node);
		char a[64];
		char b[64];
		UINT error = 0;

		IPToStr32(a, sizeof(a), addr_gw);
		IPToStr32(b, sizeof(b), addr_host);
		DeviceTraceCheck(ctx, addr_gw != addr_host && addr_gw != 0 && addr_host != 0, "the two addresses differ", "gw %s, host %s", a, b);

		bool held = DeviceTraceWaitAdapter(set, addr_gw, &adapter);
		DeviceTraceCheck(ctx, held, "the Wintun adapter of gw for VRF default holds the address of gw", "no adapter with the address %s within %u ms", a, DEVICETRACE_BOUND);

		DeviceTraceCheck(ctx, NodeWireGuardAvailable(&error), "wireguard.dll of WireGuardNT loads next to vpntest", "error %u", error);
		bool up = DeviceTraceWaitWireGuard(nodes[DEVICETRACE_GATEWAY].Node, &wg);
		DeviceTraceCheck(ctx, up, "the WireGuard interface of gw is up with the Device of the intent and the routes of its addresses", "up %u, %u Devices, port %u, %u routes within %u ms",
			(UINT)wg.Up, wg.NumDevices, wg.Port, wg.NumRoutes, DEVICETRACE_BOUND);

		if (held && up)
		{
			Print("  [INFO] gw: adapter \"%S\", interface %u; WireGuard interface %u on UDP port %u, %u Devices, %u routes\n",
				adapter.Name, adapter.InterfaceIndex, wg.InterfaceIndex, wg.Port, wg.NumDevices, wg.NumRoutes);

			// The script reads the addresses and the port from these lines
			Print("DEVICETRACE NODE host ADDRESS %s HOST fake\n", b);
			Print("DEVICETRACE NODE gw ADDRESS %s WIREGUARD PORT %u INTERFACE %u\n", a, wg.Port, wg.InterfaceIndex);
			Print("DEVICETRACE READY\n");

			HANDLE f = CreateFileA(ready_file, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
			DeviceTraceCheck(ctx, f != INVALID_HANDLE_VALUE, "the ready file", "CreateFile %s: error %u", ready_file, (UINT)GetLastError());
			if (f != INVALID_HANDLE_VALUE)
			{
				CloseHandle(f);
			}

			bool stopped = DeviceTraceHold(stop_file);
			DeviceTraceShowNodes(nodes);
			DeviceTraceCheck(ctx, stopped, "the script created the stop file", "not within %u ms", DEVICETRACE_HOLD);

			// What the Device did: the script reads these lines, and its client said what it saw
			NODE_POLICY_VRF_STATUS policy;
			NodePolicyGetVrf(nodes[DEVICETRACE_GATEWAY].Node, "default", &policy);
			NodeWireGuardGetStatus(nodes[DEVICETRACE_GATEWAY].Node, &wg);
			Print("DEVICETRACE HOST ECHOES %d ACCEPTED %d ECHOED %d OTHER %d\n", (int)ReadAcquire(&host->Echoes), (int)ReadAcquire(&host->Accepted),
				(int)ReadAcquire(&host->Echoed), (int)ReadAcquire(&host->Other));
			Print("DEVICETRACE POLICY gw RULES %u DROPPED %I64u\n", policy.NumRules, policy.Dropped);
			Print("DEVICETRACE WIREGUARD gw UP %u PORT %u DEVICES %u\n", (UINT)wg.Up, wg.Port, wg.NumDevices);
		}
	}

	// The overlay of gw stops, which halts its adapter and takes its WireGuard interface away, then the adapter goes with
	// its set
	if (nodes[DEVICETRACE_GATEWAY].Node != NULL)
	{
		NodeOverlayStop(nodes[DEVICETRACE_GATEWAY].Node);
		if (wg.InterfaceLuid != 0)
		{
			DeviceTraceCheck(ctx, DeviceTraceGone(wg.InterfaceLuid), "once the overlay of gw stopped, its WireGuard interface is gone", "the interface is still there");
		}
	}
	if (set != NULL)
	{
		NodeVrfAdaptersFree(set);
		if (adapter.InterfaceLuid != 0)
		{
			DeviceTraceCheck(ctx, DeviceTraceGone(adapter.InterfaceLuid), "once the adapter of gw is freed, its interface is gone", "the interface is still there");
		}
	}

	for (UINT i = 0;i < DEVICETRACE_NUM_NODES;i++)
	{
		DEVICETRACE_NODE *t = &nodes[i];
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
			DeviceTracePrintLog(t->Name, t->Dir);
		}
		ConbinePathW(log_dir, sizeof(log_dir), t->Dir, NODE_LOG_DIR_NAME);
		DeviceTraceDeleteDir(log_dir);
		DeviceTraceDeleteDir(t->Dir);
	}

END:
	TransportLoopbackFree(loopback);
	SetConsoleCtrlHandler(DeviceTraceCtrl, FALSE);
	if (devicetrace_stop != NULL)
	{
		CloseHandle(devicetrace_stop);
		devicetrace_stop = NULL;
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
		Print("DEVICETRACE TEST OK\n");
	}
	else
	{
		Print("DEVICETRACE TEST FAILED (%u of %u checks failed)\n", ctx->NumFailed, ctx->NumChecks);
	}

	Free(tls);
	Free(host);
	Free(nodes);
	Free(ctx);
}
