// stretchtest.c
// Named stretch test of vpntest ("stretch" command, SDN-64 #291)
//
// The stretch of a gateway (Cedar/NodeStretch.c; ADR-0032 amendment of 2026-10-22): node gw extends the L2 Network lan of the
// overlay into a data-centre fabric on the L2 VNI 5010, with EVPN type-2 and type-3 routes through its BGP sidecar (ranz.exe
// bgp) and VXLAN in user space. The fabric is two leaves on this runner, as the multi-node seam has it (ADR-0002 amendment of
// 2026-10-21: no second host; FRR on a second host is TestFRRStretch of ranz.yml): the nodes leaf-a and leaf-b, whose sidecars
// carry the L2 VNI 5010 with the route target of lan and listen on 127.0.0.2 and 127.0.0.3, where the sidecar of gw dials them,
// and their data planes, two harness VTEPs on 127.0.0.2 and 127.0.0.3, which take and send the VXLAN datagrams of the fabric (the
// leaves send theirs to a port where nothing listens). Behind leaf-a is the fabric host a, behind leaf-b the fabric host b, each a
// member of the switch of lan of its leaf, so the leaves announce them as type-2 routes. At gw the switch of lan has two members
// of the overlay: host 1, which subscribes to the broadcast group, and host 2, which subscribes to no group. The L2 data path of
// each node is the test's: it attaches the switch of lan before the node starts (NodeStretchAttach), and each host announces its
// MAC address and its IP address with a gratuitous ARP into its switch.
// - The routes: gw learns the type-3 routes of both leaves, its flood list, and the type-2 routes of host a and host b, MAC only
//   and MAC plus IP, each via the VTEP of its leaf; each leaf learns the type-3 route of gw and the type-2 routes of host 1 and
//   host 2, MAC only and MAC plus IP, the form that lets a fabric answer ARP for a known host of the overlay itself.
// - Overlay to fabric: a frame of host 1 to host a goes to the VTEP of leaf-a alone, byte for byte on VNI 5010, before any frame
//   of host a reached gw: the type-2 route of host a put it into the switch at the port of the fabric, so host 2 gets nothing. A
//   broadcast of host 1 goes to each VTEP of the flood list once, and host 2, which subscribes to no group, gets nothing.
// - Fabric to overlay: a frame of host a to host 1 from the VTEP of leaf-a reaches host 1 alone; a broadcast of host a reaches
//   host 1 once, and neither host 2 nor a VTEP of the fabric: the overlay keeps its group subscription and is not flooded across
//   the WAN, and nothing of the fabric goes back into the fabric. A frame from an address that is the VTEP of no route of the VNI
//   is dropped and counted.
// - The resync: the sidecar of gw restarts (NodeBgpRestart), so the pipe to ranz bgp reconnects. gw holds no route of the fabric
//   until its new sidecar learns them again, and sends a full resync; the routes of the fabric that gw learns again, and the
//   routes of gw that the leaves learn again, are the ones from before. A frame of host 1 to host a goes to leaf-a again.
// Print "STRETCH TEST OK" only when every check passes. .github/scripts/bgp-spike.ps1 runs it, with ranz.exe next to vpntest.

#include "harness_int.h"
#include "testlist.h"

#include "Cedar/ConfigStore.h"
#include "Cedar/Node.h"
#include "Cedar/NodeEvpn.h"

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

#include "Core/Switch.h"
#include "Core/Vxlan.h"

#include <WS2tcpip.h>

#include <stdio.h>

#define	STRETCHTEST_BUDGET		420000		// The whole test ends within this time, or the watchdog ends the process (ms)
#define	STRETCHTEST_BOUND		120000		// A bounded wait on BGP: the sessions, which wait out the idle hold time of a leaf after a reset, and the routes (ms)
#define	STRETCHTEST_WAIT		10000		// A bounded wait on a frame or a counter (ms)
#define	STRETCHTEST_QUIET		500			// A side that gets nothing gets nothing within this time (ms)
#define	STRETCHTEST_POLL		20			// Poll interval of observable state (ms)
#define	STRETCHTEST_VNI			5010		// The L2 VNI of lan
#define	STRETCHTEST_VLAN		1			// The VLAN of lan on each switch
#define	STRETCHTEST_FRAME		78			// A test frame: the Ethernet header and an IPv4 packet of UDP of 64 bytes
#define	STRETCHTEST_DATAGRAM	(VXLAN_HEADER_SIZE + STRETCHTEST_FRAME)
#define	STRETCHTEST_ROUTES		16			// The routes of the fabric that a node of the test holds at most

// The nodes
#define	STRETCHTEST_GW			0
#define	STRETCHTEST_LEAF_A		1
#define	STRETCHTEST_LEAF_B		2

// The hosts: two of the overlay at gw, and one of the fabric behind each leaf
#define	STRETCHTEST_HOST_1		0
#define	STRETCHTEST_HOST_2		1
#define	STRETCHTEST_HOST_A		2
#define	STRETCHTEST_HOST_B		3

static char *stretchtest_names[3] = {"gw", "leaf-a", "leaf-b"};

// The broadcast address
static const UCHAR stretchtest_broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

// The address of each leaf, its VTEP and its harness VTEP, and of an address that is the VTEP of no route
static char *stretchtest_leaf_addr[2] = {"127.0.0.2", "127.0.0.3"};
#define	STRETCHTEST_STRANGER	0x7F000004

// The Bgp setting of gw (the BGP ports of leaf-a and leaf-b, the UDP port of its VTEP and of the VTEPs of the fabric): its sidecar
// has no listener and dials both leaves, and stretches lan on the L2 VNI 5010 with the route target 65000:5010
#define	STRETCHTEST_GW_BGP	"{\"asn\":65001,\"router_id\":\"192.0.2.1\",\"listen_port\":-1," \
	"\"peers\":[{\"address\":\"127.0.0.2\",\"asn\":65010,\"port\":%u},{\"address\":\"127.0.0.3\",\"asn\":65011,\"port\":%u}]," \
	"\"evpn\":{\"vtep\":\"127.0.0.1\",\"port\":%u,\"fabric_port\":%u," \
	"\"stretches\":[{\"network\":\"lan\",\"vni\":5010,\"route_targets\":[\"65000:5010\"]}]}}"

// The Bgp setting of a leaf (its AS, the last byte of its router id, its BGP port and its address, its address as its VTEP, the UDP
// port of its own VTEP and of the VTEP of gw for it): its sidecar listens on its address for gw, and stretches lan as gw does. The
// VTEP of gw for it is on a port where nothing listens, so the VXLAN of the leaf reaches no one: the harness VTEP on its address
// is its data plane.
#define	STRETCHTEST_LEAF_BGP	"{\"asn\":%u,\"router_id\":\"192.0.2.%u\",\"listen_port\":%u,\"listen_addresses\":[\"%s\"]," \
	"\"peers\":[{\"address\":\"127.0.0.1\",\"asn\":65001,\"passive\":true}]," \
	"\"evpn\":{\"vtep\":\"%s\",\"port\":%u,\"fabric_port\":%u," \
	"\"stretches\":[{\"network\":\"lan\",\"vni\":5010,\"route_targets\":[\"65000:5010\"]}]}}"

// A host: a member of the switch of lan of its node, which keeps the last frame that it took
typedef struct STRETCHTEST_HOST
{
	char *Name;
	UINT Node;							// The node of its switch
	UCHAR Mac[6];						// Its MAC address ...
	char *Ip;							// ... and its IP address
	bool Broadcast;						// It subscribes to the broadcast group
	UINT Port;							// Its port on the switch
	SRWLOCK Lock;						// Last and LastSize
	volatile LONG Frames;				// Frames that it took
	UCHAR Last[STRETCHTEST_FRAME];		// The last one, as much as fits ...
	UINT LastSize;						// ... and its size
} STRETCHTEST_HOST;

// A node and the switch of lan, whose L2 data path is the test
typedef struct STRETCHTEST_NODE
{
	wchar_t Dir[MAX_PATH];				// Its data directory
	NODE *Node;
	SWITCH *Switch;						// The switch of lan
	bool Attached;						// The test attached it to the stretch of the node
} STRETCHTEST_NODE;

// The test
typedef struct STRETCHTEST_CTX
{
	UINT NumChecks;
	UINT NumFailed;
	STRETCHTEST_NODE Nodes[3];
	STRETCHTEST_HOST Hosts[4];
	SOCKET Vteps[2];					// The harness VTEPs of leaf-a and leaf-b, on their addresses ...
	USHORT FabricPort;					// ... and their UDP port: the port of the VTEPs of the fabric for gw
	USHORT GwPort;						// The UDP port of the VTEP of gw
	SOCKET Stranger;					// A socket on 127.0.0.4, the VTEP of no route
} STRETCHTEST_CTX;

static bool StretchTestCheck(STRETCHTEST_CTX *ctx, bool ok, char *what, char *fmt, ...) RANZ_PRINTF_FORMAT(4, 5);
static bool StretchTestCheck(STRETCHTEST_CTX *ctx, bool ok, char *what, char *fmt, ...)
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

// The watchdog: a native thread that ends a run that hangs, so that a lost session or frame is a failed test instead of a hung CI
// step
static DWORD WINAPI StretchTestWatchdog(LPVOID param)
{
	char msg[MAX_SIZE];
	DWORD written = 0;

	if (WaitForSingleObject((HANDLE)param, STRETCHTEST_BUDGET) != WAIT_TIMEOUT)
	{
		return 0;
	}

	int len = snprintf(msg, sizeof(msg), "STRETCH TEST FAILED (did not finish within %u ms)\n", STRETCHTEST_BUDGET);
	if (len > 0)
	{
		WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), msg, (DWORD)MIN((UINT)len, (UINT)sizeof(msg) - 1), &written, NULL);
	}

	TerminateProcess(GetCurrentProcess(), 1);

	return 0;
}

//
// Frames and the harness VTEPs
//

// The IPv4 address of a text into addr, 4 bytes; false for none
static bool StretchTestIp4(UCHAR *addr, char *str)
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

// The gratuitous ARP of host h into buf, an ARP request for its own address to every host: the switch of its node learns its MAC
// address and its IP address from it. Its size.
static UINT StretchTestAnnounce(UCHAR *buf, STRETCHTEST_HOST *h)
{
	UCHAR ip[4];

	StretchTestIp4(ip, h->Ip);
	Zero(buf, 42);
	Copy(buf, stretchtest_broadcast, 6);
	Copy(buf + 6, h->Mac, 6);
	WRITE_USHORT(buf + 12, MAC_PROTO_ARPV4);
	WRITE_USHORT(buf + 14, 1);
	WRITE_USHORT(buf + 16, MAC_PROTO_IPV4);
	buf[18] = 6;
	buf[19] = 4;
	WRITE_USHORT(buf + 20, 1);
	Copy(buf + 22, h->Mac, 6);
	Copy(buf + 28, ip, 4);
	Copy(buf + 38, ip, 4);

	return 42;
}

// A frame of host from to the MAC address mac into buf, STRETCHTEST_FRAME bytes: an IPv4 packet of UDP from the address of the host
// to the address to, with the data seq. Its size.
static UINT StretchTestUdp(UCHAR *buf, STRETCHTEST_HOST *from, const UCHAR *mac, char *to, UINT seq)
{
	UCHAR *ip = buf + 14;
	UCHAR *udp = ip + 20;

	Zero(buf, STRETCHTEST_FRAME);
	Copy(buf, mac, 6);
	Copy(buf + 6, from->Mac, 6);
	WRITE_USHORT(buf + 12, MAC_PROTO_IPV4);

	ip[0] = 0x45;
	WRITE_USHORT(ip + 2, STRETCHTEST_FRAME - 14);
	ip[8] = 64;
	ip[9] = IP_PROTO_UDP;
	StretchTestIp4(ip + 12, from->Ip);
	StretchTestIp4(ip + 16, to);
	USHORT sum = IpChecksum(ip, 20);
	Copy(ip + 10, &sum, 2);

	WRITE_USHORT(udp, 5000);
	WRITE_USHORT(udp + 2, 5001);
	WRITE_USHORT(udp + 4, STRETCHTEST_FRAME - 14 - 20);
	WRITE_UINT(udp + 8, seq);
	for (UINT i = 34 + 12;i < STRETCHTEST_FRAME;i++)
	{
		buf[i] = (UCHAR)(i * 7 + seq);
	}

	return STRETCHTEST_FRAME;
}

// A free port, which the system picks: of UDP on the wildcard address, or of TCP on 127.0.0.1 with tcp. 0 for none.
static USHORT StretchTestFreePort(bool tcp)
{
	struct sockaddr_in6 sa6;
	struct sockaddr_in sa4;
	int size;
	USHORT port = 0;
	SOCKET s = (tcp ? socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) : socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP));

	if (s == INVALID_SOCKET)
	{
		return 0;
	}

	if (tcp)
	{
		Zero(&sa4, sizeof(sa4));
		sa4.sin_family = AF_INET;
		sa4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		size = sizeof(sa4);
		if (bind(s, (struct sockaddr *)&sa4, sizeof(sa4)) == 0 && getsockname(s, (struct sockaddr *)&sa4, &size) == 0)
		{
			port = ntohs(sa4.sin_port);
		}
	}
	else
	{
		Zero(&sa6, sizeof(sa6));
		sa6.sin6_family = AF_INET6;
		size = sizeof(sa6);
		if (bind(s, (struct sockaddr *)&sa6, sizeof(sa6)) == 0 && getsockname(s, (struct sockaddr *)&sa6, &size) == 0)
		{
			port = ntohs(sa6.sin6_port);
		}
	}

	closesocket(s);

	return port;
}

// A UDP socket on the IPv4 address addr, in host byte order, and port, 0 for one that the system picks, into *s: its port, 0 when it
// could not be opened
static USHORT StretchTestBind(SOCKET *s, UINT addr, USHORT port)
{
	struct sockaddr_in sa;
	int size = sizeof(sa);

	*s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (*s == INVALID_SOCKET)
	{
		return 0;
	}

	Zero(&sa, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = htonl(addr);
	sa.sin_port = htons(port);
	if (bind(*s, (struct sockaddr *)&sa, sizeof(sa)) != 0 || getsockname(*s, (struct sockaddr *)&sa, &size) != 0)
	{
		closesocket(*s);
		*s = INVALID_SOCKET;
		return 0;
	}

	return ntohs(sa.sin_port);
}

// The harness VTEPs of the leaves on 127.0.0.2 and 127.0.0.3, on one UDP port that the system picks for the first, and the socket of
// the stranger on 127.0.0.4, into ctx
static bool StretchTestOpenVteps(STRETCHTEST_CTX *ctx)
{
	for (UINT tries = 0;tries < 8 && ctx->Vteps[1] == INVALID_SOCKET;tries++)
	{
		if (ctx->Vteps[0] != INVALID_SOCKET)
		{
			closesocket(ctx->Vteps[0]);
			ctx->Vteps[0] = INVALID_SOCKET;
		}

		ctx->FabricPort = StretchTestBind(&ctx->Vteps[0], 0x7F000002, 0);
		if (ctx->FabricPort != 0)
		{
			StretchTestBind(&ctx->Vteps[1], 0x7F000003, ctx->FabricPort);
		}
	}

	StretchTestBind(&ctx->Stranger, STRETCHTEST_STRANGER, 0);

	return (ctx->Vteps[0] != INVALID_SOCKET && ctx->Vteps[1] != INVALID_SOCKET && ctx->Stranger != INVALID_SOCKET);
}

// The next datagram that the socket s takes within timeout ms, into buf of size bytes: its size, 0 for none
static UINT StretchTestTake(SOCKET s, UCHAR *buf, UINT size, UINT timeout)
{
	fd_set fds;
	struct timeval tv;

	FD_ZERO(&fds);
	FD_SET(s, &fds);
	tv.tv_sec = (long)(timeout / 1000);
	tv.tv_usec = (long)((timeout % 1000) * 1000);

	if (select(0, &fds, NULL, NULL, &tv) != 1)
	{
		return 0;
	}

	int got = recvfrom(s, (char *)buf, (int)size, 0, NULL, NULL);

	return (got > 0 ? (UINT)got : 0);
}

// Drop what the harness VTEPs hold
static void StretchTestDrain(STRETCHTEST_CTX *ctx)
{
	UCHAR buf[VXLAN_MAX_DATAGRAM];

	for (UINT i = 0;i < 2;i++)
	{
		while (StretchTestTake(ctx->Vteps[i], buf, sizeof(buf), 0) != 0)
		{
		}
	}
}

// Whether the datagram d of size bytes is the VXLAN datagram of frame, frame_size bytes, on the VNI of lan: the I flag and the VNI,
// then the frame as it was sent
static bool StretchTestIsFrame(const UCHAR *d, UINT size, const UCHAR *frame, UINT frame_size)
{
	if (size != VXLAN_HEADER_SIZE + frame_size || d[0] != VXLAN_FLAG_VNI)
	{
		return false;
	}

	if ((((UINT)d[4] << 16) | ((UINT)d[5] << 8) | d[6]) != STRETCHTEST_VNI)
	{
		return false;
	}

	return (Cmp(d + VXLAN_HEADER_SIZE, frame, frame_size) == 0);
}

// Send gw, from the socket s, a VXLAN datagram on the VNI of lan with frame, size bytes: whether it went
static bool StretchTestInject(STRETCHTEST_CTX *ctx, SOCKET s, const UCHAR *frame, UINT size)
{
	UCHAR d[STRETCHTEST_DATAGRAM];
	struct sockaddr_in sa;

	if (size > STRETCHTEST_FRAME)
	{
		return false;
	}

	Zero(d, sizeof(d));
	d[0] = VXLAN_FLAG_VNI;
	d[4] = (UCHAR)(STRETCHTEST_VNI >> 16);
	d[5] = (UCHAR)(STRETCHTEST_VNI >> 8);
	d[6] = (UCHAR)STRETCHTEST_VNI;
	Copy(d + VXLAN_HEADER_SIZE, frame, size);

	Zero(&sa, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sa.sin_port = htons(ctx->GwPort);

	UINT len = VXLAN_HEADER_SIZE + size;

	return sendto(s, (char *)d, (int)len, 0, (struct sockaddr *)&sa, sizeof(sa)) == (int)len;
}

//
// The hosts and the switches
//

// A host takes a frame that the switch of its node delivers to its port (SWITCH_SEND_PROC): a frame of the fabric comes on the
// receive thread of the socket of gw, one of another host on the thread of the test, so the lock orders the two
static void StretchTestHostTake(void *param, UINT port, const UCHAR *frame, UINT size)
{
	STRETCHTEST_HOST *h = (STRETCHTEST_HOST *)param;

	UNREFERENCED_PARAMETER(port);

	AcquireSRWLockExclusive(&h->Lock);
	{
		h->LastSize = size;
		Copy(h->Last, frame, MIN(size, (UINT)sizeof(h->Last)));
		InterlockedIncrement(&h->Frames);
	}
	ReleaseSRWLockExclusive(&h->Lock);
}

// The frames that host h took so far
static LONG StretchTestFrames(STRETCHTEST_HOST *h)
{
	return InterlockedCompareExchange(&h->Frames, 0, 0);
}

// Whether host h took more than before frames within timeout ms
static bool StretchTestArrived(STRETCHTEST_HOST *h, LONG before, UINT timeout)
{
	UINT64 end = Tick64() + timeout;

	while (StretchTestFrames(h) <= before)
	{
		if (Tick64() >= end)
		{
			return false;
		}
		SleepThread(STRETCHTEST_POLL);
	}

	return true;
}

// Whether the last frame of host h is frame, size bytes
static bool StretchTestLastIs(STRETCHTEST_HOST *h, const UCHAR *frame, UINT size)
{
	bool same = false;

	AcquireSRWLockShared(&h->Lock);
	{
		same = (h->LastSize == size && size <= sizeof(h->Last) && Cmp(h->Last, frame, size) == 0);
	}
	ReleaseSRWLockShared(&h->Lock);

	return same;
}

// Host h sends frame, size bytes, into the switch of its node
static UINT StretchTestSend(STRETCHTEST_CTX *ctx, STRETCHTEST_HOST *h, const UCHAR *frame, UINT size)
{
	return SwitchInput(ctx->Nodes[h->Node].Switch, GetTickCount64(), h->Port, frame, size);
}

// Whether the switch of node t holds the MAC address mac at a port that is no port of a host of the test, the port of the fabric,
// within STRETCHTEST_WAIT
static bool StretchTestWaitRemoteMac(STRETCHTEST_CTX *ctx, STRETCHTEST_NODE *t, const UCHAR *mac)
{
	UINT64 end = Tick64() + STRETCHTEST_WAIT;
	SWITCH_MAC_ENTRY list[32];

	while (true)
	{
		UINT num = SwitchGetMacs(t->Switch, list, 32);

		for (UINT i = 0;i < num && i < 32;i++)
		{
			bool host = false;

			for (UINT j = 0;j < 4;j++)
			{
				host = host || (ctx->Hosts[j].Node == (UINT)(t - ctx->Nodes) && ctx->Hosts[j].Port == list[i].Port);
			}
			if (Cmp(list[i].Mac, mac, 6) == 0 && host == false)
			{
				return true;
			}
		}
		if (Tick64() >= end)
		{
			return false;
		}
		SleepThread(STRETCHTEST_POLL);
	}
}

//
// The nodes
//

// A new empty data directory under the temp directory of the process, with a configuration store that runs no role on one
// worker, with the Bgp setting bgp
static void StretchTestNewDir(wchar_t *dir, UINT size, char *name, char *bgp)
{
	wchar_t tmp[MAX_PATH];
	wchar_t path[MAX_PATH];

	UniFormat(tmp, sizeof(tmp), L"stretchtest_%S_%u", name, (UINT)Tick64());
	ConbinePathW(dir, size, MsGetMyTempDirW(), tmp);
	MakeDirExW(dir);

	ConbinePathW(path, sizeof(path), dir, CS_FILE_NAME);
	CONFIG_STORE *s = CsOpen(path);
	if (s != NULL)
	{
		CsSetSetting(s, NODE_SETTING_ROLES, "none");
		CsSetSetting(s, NODE_SETTING_WORKERS, "1");
		CsSetSetting(s, NODE_SETTING_BGP, bgp);
		CsClose(s);
	}
}

// Delete the files of a directory, which holds no subdirectory, and then the directory
static void StretchTestDeleteFiles(wchar_t *dir)
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

// The text of a file of the node log directory of dir, or of every file there for NULL; NULL when there is none. The caller frees
// it.
static char *StretchTestReadLog(wchar_t *dir, wchar_t *name)
{
	wchar_t log_dir[MAX_PATH];
	BUF *all = NewBuf();

	ConbinePathW(log_dir, sizeof(log_dir), dir, NODE_LOG_DIR_NAME);

	DIRLIST *d = EnumDirW(log_dir);
	for (UINT i = 0;d != NULL && i < d->NumFiles;i++)
	{
		DIRENT *e = d->File[i];
		wchar_t path[MAX_PATH];

		if (e->Folder || (name != NULL && UniStrCmpi(e->FileNameW, name) != 0))
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

// Print the log of the sidecar of node t, so that the job log shows its BGP sessions and its routes
static void StretchTestPrintSidecarLog(STRETCHTEST_NODE *t, char *name)
{
	char *log = StretchTestReadLog(t->Dir, NODE_BGP_LOG_NAME);

	Print("  --- %s: %S ---\n%s  ---\n", name, NODE_BGP_LOG_NAME, log == NULL ? "(none)\n" : log);

	Free(log);
}

// Whether the sidecar of node t runs (ready) with established sessions, within STRETCHTEST_BOUND
static bool StretchTestWaitBgp(STRETCHTEST_NODE *t, UINT established)
{
	UINT64 end = Tick64() + STRETCHTEST_BOUND;

	while (true)
	{
		NODE_BGP_STATUS st;

		NodeBgpGetStatus(t->Node, &st);
		if (st.Running && st.NumEstablished == established)
		{
			return true;
		}
		if (Tick64() >= end)
		{
			return false;
		}
		SleepThread(STRETCHTEST_POLL * 10);
	}
}

//
// The routes
//

// Whether list, num routes of the fabric, holds the type-3 route of the VTEP vtep (mac NULL), or the type-2 route of mac with the IP
// address ip (NULL for MAC only) via the VTEP vtep, on the VNI of lan
static bool StretchTestHasRoute(const NODE_STRETCH_ROUTE *list, UINT num, const UCHAR *mac, char *ip, char *vtep)
{
	UCHAR want_vtep[16];
	UCHAR want_ip[4];

	Zero(want_vtep, sizeof(want_vtep));
	Zero(want_ip, sizeof(want_ip));
	want_vtep[10] = 0xFF;
	want_vtep[11] = 0xFF;
	StretchTestIp4(want_vtep + 12, vtep);
	if (ip != NULL)
	{
		StretchTestIp4(want_ip, ip);
	}

	for (UINT i = 0;i < num;i++)
	{
		const NODE_STRETCH_ROUTE *r = &list[i];

		if (r->Vni != STRETCHTEST_VNI || r->Imet != (mac == NULL) || Cmp(r->Vtep, want_vtep, 16) != 0)
		{
			continue;
		}
		if (mac == NULL)
		{
			return true;
		}
		if (Cmp(r->Mac, mac, 6) == 0 && ((ip == NULL && r->IpSize == 0) || (ip != NULL && r->IpSize == 4 && Cmp(r->Ip, want_ip, 4) == 0)))
		{
			return true;
		}
	}

	return false;
}

// Whether node t holds the routes of the fabric of the other side, and these only: at gw the type-3 routes of both leaves and the
// type-2 routes of host a and host b, MAC only and MAC plus IP, each via the VTEP of its leaf; at a leaf the type-3 route of gw and
// the type-2 routes of host 1 and host 2, MAC only and MAC plus IP, via the VTEP of gw
static bool StretchTestHasAll(STRETCHTEST_CTX *ctx, UINT node)
{
	NODE_STRETCH_ROUTE list[STRETCHTEST_ROUTES];
	UINT num = NodeStretchGetRoutes(ctx->Nodes[node].Node, list, STRETCHTEST_ROUTES);

	if (num > STRETCHTEST_ROUTES)
	{
		return false;
	}

	if (node == STRETCHTEST_GW)
	{
		STRETCHTEST_HOST *a = &ctx->Hosts[STRETCHTEST_HOST_A];
		STRETCHTEST_HOST *b = &ctx->Hosts[STRETCHTEST_HOST_B];

		return (num == 6 && StretchTestHasRoute(list, num, NULL, NULL, "127.0.0.2") && StretchTestHasRoute(list, num, NULL, NULL, "127.0.0.3") &&
			StretchTestHasRoute(list, num, a->Mac, NULL, "127.0.0.2") && StretchTestHasRoute(list, num, a->Mac, a->Ip, "127.0.0.2") &&
			StretchTestHasRoute(list, num, b->Mac, NULL, "127.0.0.3") && StretchTestHasRoute(list, num, b->Mac, b->Ip, "127.0.0.3"));
	}

	STRETCHTEST_HOST *h1 = &ctx->Hosts[STRETCHTEST_HOST_1];
	STRETCHTEST_HOST *h2 = &ctx->Hosts[STRETCHTEST_HOST_2];

	return (num == 5 && StretchTestHasRoute(list, num, NULL, NULL, "127.0.0.1") &&
		StretchTestHasRoute(list, num, h1->Mac, NULL, "127.0.0.1") && StretchTestHasRoute(list, num, h1->Mac, h1->Ip, "127.0.0.1") &&
		StretchTestHasRoute(list, num, h2->Mac, NULL, "127.0.0.1") && StretchTestHasRoute(list, num, h2->Mac, h2->Ip, "127.0.0.1"));
}

// Whether node t holds every route of the fabric of the other side and these only (StretchTestHasAll), or with none no route of the
// fabric at all, within STRETCHTEST_BOUND
static bool StretchTestWaitRoutes(STRETCHTEST_CTX *ctx, UINT node, bool none)
{
	UINT64 end = Tick64() + STRETCHTEST_BOUND;

	while (true)
	{
		if (none ? NodeStretchGetRoutes(ctx->Nodes[node].Node, NULL, 0) == 0 : StretchTestHasAll(ctx, node))
		{
			return true;
		}
		if (Tick64() >= end)
		{
			return false;
		}
		SleepThread(STRETCHTEST_POLL * 5);
	}
}

// Whether node t holds the num routes of list, in their order: the routes of the fabric from before the resync
static bool StretchTestSameRoutes(STRETCHTEST_NODE *t, const NODE_STRETCH_ROUTE *list, UINT num)
{
	NODE_STRETCH_ROUTE now[STRETCHTEST_ROUTES];
	UINT got = NodeStretchGetRoutes(t->Node, now, STRETCHTEST_ROUTES);

	if (got != num || num > STRETCHTEST_ROUTES)
	{
		return false;
	}

	for (UINT i = 0;i < num;i++)
	{
		const NODE_STRETCH_ROUTE *a = &list[i];
		const NODE_STRETCH_ROUTE *b = &now[i];

		if (a->Vni != b->Vni || a->Imet != b->Imet || Cmp(a->Mac, b->Mac, 6) != 0 || a->IpSize != b->IpSize || Cmp(a->Ip, b->Ip, 16) != 0 ||
			Cmp(a->Vtep, b->Vtep, 16) != 0)
		{
			return false;
		}
	}

	return true;
}

//
// The cases
//

// The nodes, their sidecars with their sessions, the switches of lan, which the L2 data path of the test attaches before each node
// starts, and the harness VTEPs
static bool StretchTestOpen(STRETCHTEST_CTX *ctx)
{
	char bgp[MAX_SIZE * 4];
	char what[MAX_SIZE];
	USHORT bgp_ports[2];
	USHORT own_ports[2];
	USHORT nowhere = 0;
	bool ok = true;

	Print("[the nodes, their sidecars, the switches of lan and the harness VTEPs of the fabric]\n");

	ctx->GwPort = StretchTestFreePort(false);
	own_ports[0] = StretchTestFreePort(false);
	own_ports[1] = StretchTestFreePort(false);
	nowhere = StretchTestFreePort(false);
	bgp_ports[0] = StretchTestFreePort(true);
	bgp_ports[1] = StretchTestFreePort(true);
	ok = StretchTestCheck(ctx, ctx->GwPort != 0 && own_ports[0] != 0 && own_ports[1] != 0 && nowhere != 0 && bgp_ports[0] != 0 && bgp_ports[1] != 0 &&
		StretchTestOpenVteps(ctx) && ctx->GwPort != ctx->FabricPort,
		"Free ports: the UDP ports of the VTEPs of gw and the leaves, the TCP ports of the sidecars of the leaves, the harness VTEPs on 127.0.0.2 and 127.0.0.3 and a stranger on 127.0.0.4",
		"VTEP ports %u, %u and %u, BGP ports %u and %u, harness VTEP port %u, error %u", (UINT)ctx->GwPort, (UINT)own_ports[0], (UINT)own_ports[1],
		(UINT)bgp_ports[0], (UINT)bgp_ports[1], (UINT)ctx->FabricPort, (UINT)WSAGetLastError());
	if (ok == false)
	{
		return false;
	}
	Print("  [INFO] gw: VTEP 127.0.0.1:%u; leaf-a: sidecar on 127.0.0.2:%u, harness VTEP 127.0.0.2:%u; leaf-b: sidecar on 127.0.0.3:%u, harness VTEP 127.0.0.3:%u\n",
		(UINT)ctx->GwPort, (UINT)bgp_ports[0], (UINT)ctx->FabricPort, (UINT)bgp_ports[1], (UINT)ctx->FabricPort);

	// The switch of lan of each node, with its hosts, attached to the stretch of the node before it starts
	for (UINT i = 0;i < 3;i++)
	{
		STRETCHTEST_NODE *t = &ctx->Nodes[i];

		if (i == STRETCHTEST_GW)
		{
			Format(bgp, sizeof(bgp), STRETCHTEST_GW_BGP, (UINT)bgp_ports[0], (UINT)bgp_ports[1], (UINT)ctx->GwPort, (UINT)ctx->FabricPort);
		}
		else
		{
			Format(bgp, sizeof(bgp), STRETCHTEST_LEAF_BGP, 65009 + i, 9 + i, (UINT)bgp_ports[i - 1], stretchtest_leaf_addr[i - 1], stretchtest_leaf_addr[i - 1],
				(UINT)own_ports[i - 1], (UINT)nowhere);
		}
		StretchTestNewDir(t->Dir, sizeof(t->Dir), stretchtest_names[i], bgp);
		t->Node = NewNode(t->Dir);
		t->Switch = SwitchNew(NULL);
	}
	ok = StretchTestCheck(ctx, IsFileExistsW(ctx->Nodes[STRETCHTEST_GW].Node->BgpSidecar), "ranz.exe is next to vpntest.exe", "%S is missing",
		ctx->Nodes[STRETCHTEST_GW].Node->BgpSidecar) && ok;

	bool members = true;
	for (UINT i = 0;i < 4;i++)
	{
		STRETCHTEST_HOST *h = &ctx->Hosts[i];
		STRETCHTEST_NODE *t = &ctx->Nodes[h->Node];
		SWITCH_PORT_CONFIG pc;

		Zero(&pc, sizeof(pc));
		pc.Mode = SWITCH_ACCESS;
		pc.Vlan = STRETCHTEST_VLAN;
		pc.Send = StretchTestHostTake;
		pc.Param = h;
		h->Port = SwitchAddPort(t->Switch, &pc);
		members = (h->Port != SWITCH_PORT_NONE) && members;
		if (h->Broadcast)
		{
			members = (h->Port != SWITCH_PORT_NONE && SwitchSubscribe(t->Switch, h->Port, STRETCHTEST_VLAN, stretchtest_broadcast)) && members;
		}
	}
	for (UINT i = 0;i < 3;i++)
	{
		STRETCHTEST_NODE *t = &ctx->Nodes[i];

		t->Attached = (t->Switch != NULL && NodeStretchAttach(t->Node, "lan", t->Switch, STRETCHTEST_VLAN));
		members = t->Attached && members;
	}
	ok = StretchTestCheck(ctx, members, "The switch of lan of each node, with host 1 and host 2 at gw (host 1 subscribes to the broadcast group, host 2 to none), host a at leaf-a and host b at leaf-b; the L2 data path of the test attaches each to the stretch of its node",
		"%s", "SwitchNew, SwitchAddPort, SwitchSubscribe or NodeStretchAttach failed") && ok;

	// The leaves first, which gw dials once its sidecar starts
	for (UINT i = STRETCHTEST_LEAF_A;i <= STRETCHTEST_LEAF_B;i++)
	{
		NodeStart(ctx->Nodes[i].Node);
		bool ready = StretchTestWaitBgp(&ctx->Nodes[i], 0);
		Format(what, sizeof(what), "%s: its sidecar runs, listening on %s for gw", stretchtest_names[i], stretchtest_leaf_addr[i - 1]);
		ok = StretchTestCheck(ctx, ready, what, "%s", "not ready") && ok;
	}

	NodeStart(ctx->Nodes[STRETCHTEST_GW].Node);
	bool established = StretchTestWaitBgp(&ctx->Nodes[STRETCHTEST_GW], 2) && StretchTestWaitBgp(&ctx->Nodes[STRETCHTEST_LEAF_A], 1) &&
		StretchTestWaitBgp(&ctx->Nodes[STRETCHTEST_LEAF_B], 1);
	ok = StretchTestCheck(ctx, established, "The sidecar of gw dials both leaves: its sessions with leaf-a and leaf-b are established", "%s", "not established") && ok;

	NODE_STRETCH_STATUS st;
	NODE_EVPN_STATUS es;
	NodeStretchGetStatus(ctx->Nodes[STRETCHTEST_GW].Node, &st);
	NodeEvpnGetStatus(ctx->Nodes[STRETCHTEST_GW].Node, &es);
	ok = StretchTestCheck(ctx, es.Running && es.Port == ctx->GwPort && es.NumVrfs == 0 && st.NumStretches == 1 && st.NumAttached == 1,
		"gw: its EVPN runs on the VTEP of its Bgp setting with no EVPN VRF and one stretch, and the fabric is a member of the switch of lan",
		"EVPN running %u, port %u, %u VRFs, %u stretches, %u attached", (UINT)es.Running, (UINT)es.Port, es.NumVrfs, st.NumStretches, st.NumAttached) && ok;

	return ok;
}

// The routes: each host announces itself into its switch, and the routes of each side reach the other
static void StretchTestRoutes(STRETCHTEST_CTX *ctx)
{
	UCHAR frame[STRETCHTEST_FRAME];
	NODE_STRETCH_STATUS st;
	char what[MAX_SIZE];

	Print("[the routes: EVPN type-2 and type-3 both ways]\n");

	for (UINT i = 0;i < 4;i++)
	{
		STRETCHTEST_HOST *h = &ctx->Hosts[i];

		StretchTestSend(ctx, h, frame, StretchTestAnnounce(frame, h));
	}

	bool gw = StretchTestWaitRoutes(ctx, STRETCHTEST_GW, false);
	NodeStretchGetStatus(ctx->Nodes[STRETCHTEST_GW].Node, &st);
	StretchTestCheck(ctx, gw && st.NumVteps == 2 && st.NumMacs == 4,
		"gw learns the type-3 routes of leaf-a and leaf-b, its flood list, and the type-2 routes of host a and host b, MAC only and MAC plus IP, each via the VTEP of its leaf",
		"all %u, %u type-3 and %u type-2 routes", (UINT)gw, st.NumVteps, st.NumMacs);

	for (UINT i = STRETCHTEST_LEAF_A;i <= STRETCHTEST_LEAF_B;i++)
	{
		bool leaf = StretchTestWaitRoutes(ctx, i, false);

		Format(what, sizeof(what), "%s learns the type-3 route of gw and the type-2 routes of host 1 and host 2 via the VTEP of gw, MAC only and MAC plus IP: the form that lets the fabric answer ARP for a known host of the overlay", stretchtest_names[i]);
		StretchTestCheck(ctx, leaf, what, "%s", "not all of them, or more");
	}

	NodeStretchGetStatus(ctx->Nodes[STRETCHTEST_GW].Node, &st);
	StretchTestCheck(ctx, st.NumAnnounced == 4 && st.Resyncs >= 1, "gw announces its 4 type-2 routes, after a full resync at the start of its sidecar",
		"%u announced, %I64u resyncs", st.NumAnnounced, st.Resyncs);
}

// Overlay to fabric: a frame of host 1 to host a goes to the VTEP of leaf-a alone, and a broadcast of host 1 to each VTEP of the
// flood list once; host 2 gets neither. With again, after the resync.
static void StretchTestIntoFabric(STRETCHTEST_CTX *ctx, bool again)
{
	STRETCHTEST_HOST *h1 = &ctx->Hosts[STRETCHTEST_HOST_1];
	STRETCHTEST_HOST *h2 = &ctx->Hosts[STRETCHTEST_HOST_2];
	STRETCHTEST_HOST *a = &ctx->Hosts[STRETCHTEST_HOST_A];
	UCHAR frame[STRETCHTEST_FRAME];
	UCHAR d[VXLAN_MAX_DATAGRAM];
	NODE_STRETCH_STATUS before, after;

	Print(again ? "[overlay to fabric, after the resync]\n" : "[overlay to fabric: a type-2 route, and ingress replication to the flood list]\n");

	NodeStretchGetStatus(ctx->Nodes[STRETCHTEST_GW].Node, &before);

	// The type-2 route of host a put it into the switch of gw at the port of the fabric
	bool remote = StretchTestWaitRemoteMac(ctx, &ctx->Nodes[STRETCHTEST_GW], a->Mac);
	StretchTestDrain(ctx);
	LONG frames_2 = StretchTestFrames(h2);
	UINT size = StretchTestUdp(frame, h1, a->Mac, a->Ip, again ? 21 : 11);
	UINT reached = StretchTestSend(ctx, h1, frame, size);
	UINT got_a = StretchTestTake(ctx->Vteps[0], d, sizeof(d), STRETCHTEST_WAIT);
	bool is_frame = StretchTestIsFrame(d, got_a, frame, size);
	UINT got_b = StretchTestTake(ctx->Vteps[1], d, sizeof(d), STRETCHTEST_QUIET);
	UINT more_a = StretchTestTake(ctx->Vteps[0], d, sizeof(d), 0);
	StretchTestCheck(ctx, remote && reached == 1 && is_frame && got_b == 0 && more_a == 0 && StretchTestFrames(h2) == frames_2,
		"A frame of host 1 to host a goes to the port of the fabric alone and to the VTEP of leaf-a alone, byte for byte on VNI 5010, before any frame of host a reached gw; host 2 gets nothing",
		"host a at the port of the fabric %u, %u ports reached, leaf-a took %u bytes (the frame %u, one more %u), leaf-b %u bytes, host 2 %d frames more", (UINT)remote, reached,
		got_a, (UINT)is_frame, more_a, got_b, (int)(StretchTestFrames(h2) - frames_2));

	if (again)
	{
		return;
	}

	StretchTestDrain(ctx);
	frames_2 = StretchTestFrames(h2);
	size = StretchTestUdp(frame, h1, stretchtest_broadcast, "10.50.0.255", 12);
	reached = StretchTestSend(ctx, h1, frame, size);
	got_a = StretchTestTake(ctx->Vteps[0], d, sizeof(d), STRETCHTEST_WAIT);
	bool copy_a = StretchTestIsFrame(d, got_a, frame, size);
	got_b = StretchTestTake(ctx->Vteps[1], d, sizeof(d), STRETCHTEST_WAIT);
	bool copy_b = StretchTestIsFrame(d, got_b, frame, size);
	more_a = StretchTestTake(ctx->Vteps[0], d, sizeof(d), STRETCHTEST_QUIET);
	UINT more_b = StretchTestTake(ctx->Vteps[1], d, sizeof(d), 0);
	StretchTestCheck(ctx, reached == 1 && copy_a && copy_b && more_a == 0 && more_b == 0 && StretchTestFrames(h2) == frames_2,
		"A broadcast of host 1 goes to each VTEP of the flood list once, leaf-a and leaf-b, byte for byte on VNI 5010; host 2, which subscribes to no group, gets nothing",
		"%u ports reached, leaf-a %u (one more %u), leaf-b %u (one more %u), host 2 %d frames more", reached, (UINT)copy_a, more_a, (UINT)copy_b, more_b,
		(int)(StretchTestFrames(h2) - frames_2));

	NodeStretchGetStatus(ctx->Nodes[STRETCHTEST_GW].Node, &after);
	StretchTestCheck(ctx, after.Unicast == before.Unicast + 1 && after.Flooded == before.Flooded + 1 && after.Failed == before.Failed,
		"The counters of the stretch of gw: one frame to the VTEP of a type-2 route, one to the flood list, none failed",
		"unicast %I64u to %I64u, flooded %I64u to %I64u, failed %I64u to %I64u", before.Unicast, after.Unicast, before.Flooded, after.Flooded, before.Failed, after.Failed);
}

// Fabric to overlay: a frame of host a to host 1 reaches host 1 alone, a broadcast of host a reaches host 1 once and neither host 2
// nor the fabric, and a frame from an address that is the VTEP of no route is dropped
static void StretchTestFromFabric(STRETCHTEST_CTX *ctx)
{
	STRETCHTEST_HOST *h1 = &ctx->Hosts[STRETCHTEST_HOST_1];
	STRETCHTEST_HOST *h2 = &ctx->Hosts[STRETCHTEST_HOST_2];
	STRETCHTEST_HOST *a = &ctx->Hosts[STRETCHTEST_HOST_A];
	UCHAR frame[STRETCHTEST_FRAME];
	UCHAR d[VXLAN_MAX_DATAGRAM];
	NODE_STRETCH_STATUS before, after;

	Print("[fabric to overlay: the switch of lan, and its group subscription]\n");

	NodeStretchGetStatus(ctx->Nodes[STRETCHTEST_GW].Node, &before);

	StretchTestDrain(ctx);
	LONG frames_1 = StretchTestFrames(h1);
	LONG frames_2 = StretchTestFrames(h2);
	UINT size = StretchTestUdp(frame, a, h1->Mac, h1->Ip, 13);
	bool sent = StretchTestInject(ctx, ctx->Vteps[0], frame, size);
	bool arrived = StretchTestArrived(h1, frames_1, STRETCHTEST_WAIT);
	bool same = StretchTestLastIs(h1, frame, size);
	SleepThread(STRETCHTEST_QUIET);
	UINT back_a = StretchTestTake(ctx->Vteps[0], d, sizeof(d), 0);
	UINT back_b = StretchTestTake(ctx->Vteps[1], d, sizeof(d), 0);
	StretchTestCheck(ctx, sent && arrived && same && StretchTestFrames(h1) == frames_1 + 1 && StretchTestFrames(h2) == frames_2 && back_a == 0 && back_b == 0,
		"A frame of host a to host 1 from the VTEP of leaf-a reaches host 1 alone, as it was sent; host 2 and the fabric get nothing",
		"sent %u, host 1 took it %u (the frame %u, %d frames more), host 2 %d frames more, leaf-a %u bytes back, leaf-b %u bytes", (UINT)sent, (UINT)arrived, (UINT)same,
		(int)(StretchTestFrames(h1) - frames_1), (int)(StretchTestFrames(h2) - frames_2), back_a, back_b);

	frames_1 = StretchTestFrames(h1);
	frames_2 = StretchTestFrames(h2);
	size = StretchTestUdp(frame, a, stretchtest_broadcast, "10.50.0.255", 14);
	sent = StretchTestInject(ctx, ctx->Vteps[0], frame, size);
	arrived = StretchTestArrived(h1, frames_1, STRETCHTEST_WAIT);
	same = StretchTestLastIs(h1, frame, size);
	SleepThread(STRETCHTEST_QUIET);
	back_a = StretchTestTake(ctx->Vteps[0], d, sizeof(d), 0);
	back_b = StretchTestTake(ctx->Vteps[1], d, sizeof(d), 0);
	StretchTestCheck(ctx, sent && arrived && same && StretchTestFrames(h1) == frames_1 + 1 && StretchTestFrames(h2) == frames_2 && back_a == 0 && back_b == 0,
		"A broadcast of host a reaches host 1, the subscriber of the broadcast group, once; host 2 gets nothing, and nothing of it goes back to a VTEP of the fabric",
		"sent %u, host 1 took it %u (the frame %u, %d frames more), host 2 %d frames more, leaf-a %u bytes back, leaf-b %u bytes", (UINT)sent, (UINT)arrived, (UINT)same,
		(int)(StretchTestFrames(h1) - frames_1), (int)(StretchTestFrames(h2) - frames_2), back_a, back_b);

	// The address of a VTEP is all that names it: the same frame from 127.0.0.4, the VTEP of no route of lan, goes nowhere
	frames_1 = StretchTestFrames(h1);
	size = StretchTestUdp(frame, a, h1->Mac, h1->Ip, 15);
	sent = StretchTestInject(ctx, ctx->Stranger, frame, size);
	arrived = StretchTestArrived(h1, frames_1, STRETCHTEST_QUIET);
	NodeStretchGetStatus(ctx->Nodes[STRETCHTEST_GW].Node, &after);
	StretchTestCheck(ctx, sent && arrived == false && after.UnknownVtep == before.UnknownVtep + 1 && after.Delivered == before.Delivered + 2,
		"A frame to host 1 from 127.0.0.4, the VTEP of no route of the VNI, is dropped and counted; the two frames of leaf-a were delivered",
		"sent %u, host 1 took it %u, unknown VTEP %I64u to %I64u, delivered %I64u to %I64u", (UINT)sent, (UINT)arrived, before.UnknownVtep, after.UnknownVtep,
		before.Delivered, after.Delivered);
}

// The resync: the sidecar of gw restarts, so the pipe to ranz bgp reconnects, and both sides hold the routes of before again
static void StretchTestResync(STRETCHTEST_CTX *ctx)
{
	NODE_STRETCH_ROUTE before[3][STRETCHTEST_ROUTES];
	UINT num[3];
	NODE_STRETCH_STATUS st;
	char what[MAX_SIZE];

	Print("[the resync: the pipe of gw to ranz bgp reconnects]\n");

	for (UINT i = 0;i < 3;i++)
	{
		UINT got = NodeStretchGetRoutes(ctx->Nodes[i].Node, before[i], STRETCHTEST_ROUTES);

		num[i] = MIN(got, (UINT)STRETCHTEST_ROUTES);
	}
	NodeStretchGetStatus(ctx->Nodes[STRETCHTEST_GW].Node, &st);
	UINT64 resyncs = st.Resyncs;

	bool restarted = NodeBgpRestart(ctx->Nodes[STRETCHTEST_GW].Node);
	UINT held = NodeStretchGetRoutes(ctx->Nodes[STRETCHTEST_GW].Node, NULL, 0);
	StretchTestCheck(ctx, restarted && held == 0, "The sidecar of gw restarts with a new pipe, and gw holds no route of the fabric of its old one",
		"restarted %u, %u routes held", (UINT)restarted, held);

	bool gone = StretchTestWaitRoutes(ctx, STRETCHTEST_LEAF_A, true) && StretchTestWaitRoutes(ctx, STRETCHTEST_LEAF_B, true);
	StretchTestCheck(ctx, gone, "The leaves lose the routes of gw with its old session", "%s", "a leaf holds them still");

	bool established = StretchTestWaitBgp(&ctx->Nodes[STRETCHTEST_GW], 2);
	StretchTestCheck(ctx, established, "The new sidecar of gw dials both leaves again: its sessions are established", "%s", "not established");

	bool learned = StretchTestWaitRoutes(ctx, STRETCHTEST_GW, false) && StretchTestSameRoutes(&ctx->Nodes[STRETCHTEST_GW], before[STRETCHTEST_GW], num[STRETCHTEST_GW]);
	StretchTestCheck(ctx, learned, "gw learns the routes of the fabric again, and they match the ones before: the type-3 routes of both leaves and the type-2 routes of host a and host b",
		"%u routes before, %u now", num[STRETCHTEST_GW], NodeStretchGetRoutes(ctx->Nodes[STRETCHTEST_GW].Node, NULL, 0));

	for (UINT i = STRETCHTEST_LEAF_A;i <= STRETCHTEST_LEAF_B;i++)
	{
		bool again = StretchTestWaitRoutes(ctx, i, false) && StretchTestSameRoutes(&ctx->Nodes[i], before[i], num[i]);

		Format(what, sizeof(what), "%s learns the routes of gw again from its full resync, and they match the ones before", stretchtest_names[i]);
		StretchTestCheck(ctx, again, what, "%u routes before, %u now", num[i], NodeStretchGetRoutes(ctx->Nodes[i].Node, NULL, 0));
	}

	NodeStretchGetStatus(ctx->Nodes[STRETCHTEST_GW].Node, &st);
	StretchTestCheck(ctx, st.Resyncs == resyncs + 1 && st.NumAnnounced == 4, "gw sent its new sidecar one full resync of its 4 type-2 routes",
		"resyncs %I64u to %I64u, %u announced", resyncs, st.Resyncs, st.NumAnnounced);
}

// The switches leave the stretches, the nodes stop and their sidecars with them, and the node log of gw tells the story; the logs of
// the sidecars go into the job log when a check failed
static void StretchTestClose(STRETCHTEST_CTX *ctx)
{
	STRETCHTEST_NODE *gw = &ctx->Nodes[STRETCHTEST_GW];
	bool gw_ran = (gw->Node != NULL);

	for (UINT i = 0;i < 3;i++)
	{
		STRETCHTEST_NODE *t = &ctx->Nodes[i];

		if (t->Node != NULL)
		{
			if (t->Attached)
			{
				NodeStretchDetach(t->Node, "lan");
			}
			NodeStop(t->Node);
		}
	}

	if (gw_ran)
	{
		NODE_STRETCH_STATUS st;
		NODE_BGP_STATUS bs;

		NodeStretchGetStatus(gw->Node, &st);
		NodeBgpGetStatus(gw->Node, &bs);
		StretchTestCheck(ctx, st.NumStretches == 0 && st.NumAttached == 0 && bs.ProcessId == 0, "NodeStop ends the stretch of gw with its sidecar",
			"%u stretches, %u attached, sidecar %u", st.NumStretches, st.NumAttached, bs.ProcessId);
	}

	// A node holds the file of its log open while it lives: FreeNode writes the last lines and closes it (FreeLog)
	for (UINT i = 0;i < 3;i++)
	{
		FreeNode(ctx->Nodes[i].Node);
		ctx->Nodes[i].Node = NULL;
		SwitchFree(ctx->Nodes[i].Switch);
		ctx->Nodes[i].Switch = NULL;
	}

	if (gw_ran)
	{
		char *log = StretchTestReadLog(gw->Dir, NULL);
		char *lines[] =
		{
			"EVPN started: the VTEP 127.0.0.1 on UDP port",
			"EVPN stretch: 1 L2 Networks stretched into the fabric",
			"EVPN stretch: the fabric is port",
			"EVPN stretch: a full resync of 4 routes of the gateway went to the sidecar",
			"EVPN stretch: the fabric left the switch of the L2 Network lan",
			"EVPN stretch stopped:",
		};
		char missing[MAX_SIZE * 2];
		bool all = true;

		StrCpy(missing, sizeof(missing), "");
		for (UINT i = 0;i < sizeof(lines) / sizeof(lines[0]);i++)
		{
			if (log == NULL || SearchStrEx(log, lines[i], 0, true) == INFINITE)
			{
				all = false;
				StrCat(missing, sizeof(missing), " \"");
				StrCat(missing, sizeof(missing), lines[i]);
				StrCat(missing, sizeof(missing), "\"");
			}
		}
		StretchTestCheck(ctx, all, "The node log of gw names its stretch, the port of the fabric on the switch of lan, the full resync after the restart and the stop",
			"missing:%s", missing);
		Free(log);

		if (ctx->NumFailed != 0)
		{
			for (UINT i = 0;i < 3;i++)
			{
				StretchTestPrintSidecarLog(&ctx->Nodes[i], stretchtest_names[i]);
			}
		}
	}

	// The data directory of each node that the test made (StretchTestNewDir)
	for (UINT i = 0;i < 3;i++)
	{
		STRETCHTEST_NODE *t = &ctx->Nodes[i];
		wchar_t log_dir[MAX_PATH];

		if (UniIsEmptyStr(t->Dir) == false)
		{
			ConbinePathW(log_dir, sizeof(log_dir), t->Dir, NODE_LOG_DIR_NAME);
			StretchTestDeleteFiles(log_dir);
			StretchTestDeleteFiles(t->Dir);
		}
	}

	for (UINT i = 0;i < 2;i++)
	{
		if (ctx->Vteps[i] != INVALID_SOCKET)
		{
			closesocket(ctx->Vteps[i]);
		}
	}
	if (ctx->Stranger != INVALID_SOCKET)
	{
		closesocket(ctx->Stranger);
	}
}

// The hosts of the test: host 1 and host 2 of the overlay at gw, host a and host b of the fabric behind leaf-a and leaf-b
static void StretchTestHosts(STRETCHTEST_CTX *ctx)
{
	static const UCHAR macs[4][6] =
	{
		{0x02, 0x52, 0x5A, 0x64, 0x00, 0x01},
		{0x02, 0x52, 0x5A, 0x64, 0x00, 0x02},
		{0x02, 0x00, 0x5E, 0x50, 0x00, 0x0A},
		{0x02, 0x00, 0x5E, 0x50, 0x00, 0x0B},
	};
	static char *names[4] = {"host 1", "host 2", "host a", "host b"};
	static char *ips[4] = {"10.50.0.1", "10.50.0.2", "10.50.0.10", "10.50.0.11"};
	static const UINT nodes[4] = {STRETCHTEST_GW, STRETCHTEST_GW, STRETCHTEST_LEAF_A, STRETCHTEST_LEAF_B};

	for (UINT i = 0;i < 4;i++)
	{
		STRETCHTEST_HOST *h = &ctx->Hosts[i];

		h->Name = names[i];
		h->Node = nodes[i];
		Copy(h->Mac, macs[i], 6);
		h->Ip = ips[i];
		h->Broadcast = (i != STRETCHTEST_HOST_2);
		h->Port = SWITCH_PORT_NONE;
		InitializeSRWLock(&h->Lock);
	}
}

// stretch: the L2 stretch of a gateway into a fabric
RANZ_TEST("stretch", stretch_test, "EVPN L2 stretch: a gateway node stretches an L2 Network of the overlay into a fabric of two leaves with EVPN type-2 and type-3 routes through ranz bgp (ranz.exe next to vpntest): the type-2 routes both ways, MAC only and MAC plus IP, a frame to a host of the other side by its route, a broadcast of the overlay to each VTEP of the flood list once and one of the fabric only to the subscribers of the overlay, and a full resync once the pipe of the gateway to ranz bgp reconnects.");
void stretch_test(UINT num, char **arg)
{
	STRETCHTEST_CTX *ctx = ZeroMalloc(sizeof(STRETCHTEST_CTX));
	HANDLE done = CreateEventW(NULL, TRUE, FALSE, NULL);
	HANDLE watchdog = (done != NULL ? CreateThread(NULL, 0, StretchTestWatchdog, done, 0, NULL) : NULL);

	Print("Stretch test: a gateway stretches the L2 Network lan into a fabric of two leaves with EVPN type-2 and type-3 routes, and VXLAN carries its frames both ways\n");

	ctx->Vteps[0] = INVALID_SOCKET;
	ctx->Vteps[1] = INVALID_SOCKET;
	ctx->Stranger = INVALID_SOCKET;
	StretchTestHosts(ctx);

	if (StretchTestOpen(ctx))
	{
		StretchTestRoutes(ctx);
		StretchTestIntoFabric(ctx, false);
		StretchTestFromFabric(ctx);
		StretchTestResync(ctx);
		StretchTestIntoFabric(ctx, true);
	}

	StretchTestClose(ctx);

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
		Print("STRETCH TEST OK\n");
	}
	else
	{
		Print("STRETCH TEST FAILED (%u of %u checks failed)\n", ctx->NumFailed, ctx->NumChecks);
	}

	Free(ctx);
}
