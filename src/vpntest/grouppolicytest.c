// grouppolicytest.c
// Named source group policy test of vpntest ("grouppolicy" command, SDN-87 #386)
//
// The node that takes a packet of a peer judges it by the rules of its VRF for the source group that the packet carried
// (Cedar/NodeSourceGroup.c, NodePolicy.c). The test runs the overlay of two in-process nodes, as seam 2 of #45 runs the
// data plane and linktest.c the kinds of the links: fake adapters stand in for the hosts of node-a and node-b, the
// in-process loopback transport carries their Noise session, both have a tunnel endpoint on 127.0.0.1, and the test
// applies their desired states itself (NodeOverlayApply), as the controller makes them (desired/sourcegroup.go). VRF red
// (101) has three groups: admin (1, the tag set 0x1), the WireGuard Device phone at 10.0.0.50, whose gateway node-a is;
// guest (2, 0x2), node-a; and server (3, 0x4), node-b. Node-b enforces the policy of red, one rule written by tag,
// admin-in, from the tag admin to the tag server, and default deny; node-a enforces none, so every packet of its host
// leaves it. Each case sends one UDP packet to node-b's host, from a source port of its own so that no flow of the
// conntrack of node-b carries a verdict from one case to the next. It waits until node-b counted the packet in the tag
// mode in which it judged it (NodeSourceGroupGetStatus), exactly once, then for what node-b's host takes.
// - Over each kind of link, noise, vxlan and geneve (in the tag mode trusted-underlay): a packet of node-a's host from
//   10.0.0.1 carries guest, which admin-in does not allow, and is dropped; one from 10.0.0.50, the address of phone,
//   carries admin and arrives. In the next Generation node-a stamps admin on the packets of its own address, a group that
//   it may assert as the gateway of phone, and the packet from 10.0.0.1 arrives: the rule judges it by the group that it
//   carries. In the one after, node-a stamps server, the group of node-b, which it may not assert: node-b drops the packet
//   as an unknown group, counts it as refused and logs it.
// - Over vxlan and geneve a harness tunnel endpoint on 127.0.0.1, the address of node-a, sends node-b datagrams that it
//   made itself. In trusted-underlay a forged admin on a packet from 10.0.0.1 is honoured, the limit of that mode, and
//   guest on one from 10.0.0.50 is judged as guest; without the option, the map of address to group judges the packet,
//   so the one from 10.0.0.1 is dropped and the one from 10.0.0.50 arrives; a claim of server is refused, and over
//   geneve so is admin with the tag set of another group; and a packet from 10.0.0.99, an address that no route of red
//   leads to node-a, is in no group and dropped. In the tag mode off the option is ignored and the map judges each
//   packet, and node-a sends none, which node-b counts as missing.
// - The Generations roll out: node-a reports the Capability tags and stamps admin on the records that it sends node-b,
//   while the state of node-b gives node-a the frame version 0 and none of its groups, as until the Generation of node-b
//   goes in, or while the controller cannot reach node-b. Node-b ignores those claims and judges the packets by the map:
//   the one from 10.0.0.1 is dropped as guest, the one from 10.0.0.50 arrives as admin, and it counts both as ignored.
// - Frame version 0: with node-a a node without the Capability tags, which has no group and sends node-b records of frame
//   version 0, its packets over noise still go and are judged by the map: the one from 10.0.0.50 arrives, the one from
//   10.0.0.1 is dropped, and node-b counts both as missing.
// Print "GROUPPOLICY TEST OK" only when every check passes.

#include "harness_int.h"
#include "testlist.h"

#include "Cedar/ConfigStore.h"
#include "Cedar/Node.h"
#include "Cedar/NodeLink.h"
#include "Cedar/NodeSourceGroup.h"

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
#include "Core/Vxlan.h"

#include <WS2tcpip.h>

#include <stdio.h>

#define	GPTEST_BUDGET			120000		// The whole test ends within this time, or the watchdog ends the process (ms)
#define	GPTEST_BOUND			10000		// A bounded wait on observable state (ms)
#define	GPTEST_QUIET			300			// A host that gets nothing gets nothing within this time (ms)
#define	GPTEST_POLL				10			// Poll interval of observable state (ms)
#define	GPTEST_SIZE				100			// The size of a test packet
#define	GPTEST_VNI				5101		// The VNI of red over vxlan and geneve
#define	GPTEST_VRF				101			// The id of red
#define	GPTEST_PORT				9000		// The UDP port of node-b's host that every packet goes to
#define	GPTEST_FIRST_PORT		20000		// The UDP source port of the first case; each case takes the next
#define	GPTEST_PHONE			"10.0.0.50"	// The address of the Device phone

// The nodes
#define	GPTEST_A				0
#define	GPTEST_B				1

// The groups of red, as the controller numbers them (desired/sourcegroup.go): one for each set of tags of an endpoint,
// admin, guest and server in name order, and a bit of the tag set for each tag of red in name order
#define	GPTEST_ADMIN			1
#define	GPTEST_GUEST			2
#define	GPTEST_SERVER			3
#define	GPTEST_ADMIN_TAGS		0x1ULL
#define	GPTEST_GUEST_TAGS		0x2ULL
#define	GPTEST_SERVER_TAGS		0x4ULL

// What node-b counts a packet as in the tag mode of the case (NODE_SOURCE_GROUP_STATUS), or GPTEST_UNCOUNTED: its overlay
// drops it before it judges its source group, as no route of red leads its source to node-a
#define	GPTEST_CARRIED			0
#define	GPTEST_MISSING			1
#define	GPTEST_IGNORED			2
#define	GPTEST_REFUSED			3
#define	GPTEST_UNCOUNTED		4

static char *gptest_names[2] = {"node-a", "node-b"};

// The addresses of each node in red, IPv4 and IPv6, and its tag
static char *gptest_addrs[2][2] =
{
	{"10.0.0.1", "fd00::1"},
	{"10.0.0.2", "fd00::2"},
};
static char *gptest_tags[2] = {"guest", "server"};

static char *gptest_kind_names[3] = {"noise", "vxlan", "geneve"};
static char *gptest_mode_names[CONTROL_TAG_MODES] = {"off", "trusted-underlay", "session"};
static char *gptest_results[4] = {"carried", "missing", "ignored", "refused"};

// The MAC address of both ends of the Ethernet header of a frame of a link
static const UCHAR gptest_mac[6] = {0x02, 0x52, 0x5A, 0x00, 0x00, 0x03};

// One case: a UDP packet of red to node-b's host, which node-a's host sends, or the harness tunnel endpoint with the source
// group that its datagram carries; and what node-b counts it as and whether its host takes it
typedef struct GPTEST_CASE
{
	char *What;							// What the case shows
	bool Inject;						// The harness tunnel endpoint sends it, else node-a's host
	char *Src;							// Its source address
	bool HasGroup;						// An injected datagram carries a source group ...
	UINT Group;							// ... of this group ID ...
	UINT64 Tags;						// ... with this tag set, which only Geneve carries
	UINT Result;						// What node-b counts it as (GPTEST_*)
	bool Arrives;						// Node-b's host takes it, as it was sent
} GPTEST_CASE;

// The packets of node-a's host while node-a stamps guest, its own group, on the packets of its address and admin, the group
// of phone, on those of the address of phone
static GPTEST_CASE gptest_own[] =
{
	{"a packet of node-a's host from 10.0.0.1 carries guest, its group, which the rule admin-in does not allow: dropped", false, "10.0.0.1", false, 0, 0, GPTEST_CARRIED, false},
	{"one from 10.0.0.50, the address of phone, carries admin, the group of phone, which admin-in allows: it arrives", false, GPTEST_PHONE, false, 0, 0, GPTEST_CARRIED, true},
};

// ... while node-a stamps admin, which it may assert as the gateway of phone, on the packets of its own address
static GPTEST_CASE gptest_admin[] =
{
	{"the same packet from 10.0.0.1 carries admin now: the rule written by tag judges it by the group that it carries, and it arrives", false, "10.0.0.1", false, 0, 0, GPTEST_CARRIED, true},
};

// ... while node-a stamps server, the group of node-b, which it may not assert
static GPTEST_CASE gptest_rogue[] =
{
	{"a packet from 10.0.0.1 that claims server, which node-a may not assert: dropped as an unknown group, counted as refused", false, "10.0.0.1", false, 0, 0, GPTEST_REFUSED, false},
};

// The datagrams of the harness tunnel endpoint on 127.0.0.1, the address of node-a, in the tag mode trusted-underlay
static GPTEST_CASE gptest_trusted[] =
{
	{"trusted-underlay: a forged admin on a packet from 10.0.0.1 is honoured, the limit of that mode: it arrives", true, "10.0.0.1", true, GPTEST_ADMIN, GPTEST_ADMIN_TAGS, GPTEST_CARRIED, true},
	{"trusted-underlay: guest on a packet from 10.0.0.50 is judged as guest, not as the group of the address of phone: dropped", true, GPTEST_PHONE, true, GPTEST_GUEST, GPTEST_GUEST_TAGS, GPTEST_CARRIED, false},
	{"trusted-underlay: without the option, the map of address to group judges the packet from 10.0.0.1 as guest: dropped", true, "10.0.0.1", false, 0, 0, GPTEST_MISSING, false},
	{"trusted-underlay: without the option, the map judges the packet from 10.0.0.50 as admin: it arrives", true, GPTEST_PHONE, false, 0, 0, GPTEST_MISSING, true},
	{"trusted-underlay: a claim of server, which node-a may not assert, is dropped as an unknown group and counted as refused", true, "10.0.0.1", true, GPTEST_SERVER, GPTEST_SERVER_TAGS, GPTEST_REFUSED, false},
	{"trusted-underlay: without the option, a packet from 10.0.0.99, an address that no route of red leads to node-a, is in no group: dropped", true, "10.0.0.99", false, 0, 0, GPTEST_UNCOUNTED, false},
};

// ... and over geneve, which carries the tag set: a claim of admin with the tag set of guest and admin
static GPTEST_CASE gptest_tag_set[] =
{
	{"trusted-underlay: a claim of admin with the tag set 0x3, not the one of admin, is refused", true, "10.0.0.1", true, GPTEST_ADMIN, 0x3ULL, GPTEST_REFUSED, false},
};

// ... and in the tag mode off
static GPTEST_CASE gptest_off[] =
{
	{"off: a forged admin on a packet from 10.0.0.1 is ignored, and the map judges it as guest: dropped", true, "10.0.0.1", true, GPTEST_ADMIN, GPTEST_ADMIN_TAGS, GPTEST_IGNORED, false},
	{"off: guest on a packet from 10.0.0.50 is ignored, and the map judges it as admin: it arrives", true, GPTEST_PHONE, true, GPTEST_GUEST, GPTEST_GUEST_TAGS, GPTEST_IGNORED, true},
	{"off: node-a sends no option, and the map judges the packet of its host from 10.0.0.1 as guest: dropped", false, "10.0.0.1", false, 0, 0, GPTEST_MISSING, false},
	{"off: ... and the one from 10.0.0.50 as admin: it arrives", false, GPTEST_PHONE, false, 0, 0, GPTEST_MISSING, true},
};

// The packets of node-a's host over noise while node-a stamps admin on them and node-b does not know the groups of node-a
// yet
static GPTEST_CASE gptest_rollout[] =
{
	{"a claim of admin from node-a, whose groups node-b does not know yet, is ignored, and the map judges the packet from 10.0.0.1 as guest: dropped", false, "10.0.0.1", false, 0, 0, GPTEST_IGNORED, false},
	{"... and the one from 10.0.0.50 as admin: it arrives", false, GPTEST_PHONE, false, 0, 0, GPTEST_IGNORED, true},
};

// The packets of node-a's host over noise while node-a is a node without the Capability tags
static GPTEST_CASE gptest_version0[] =
{
	{"a record of frame version 0 of a packet from 10.0.0.50 is judged by the map, as admin: it arrives", false, GPTEST_PHONE, false, 0, 0, GPTEST_MISSING, true},
	{"one of a packet from 10.0.0.1 is judged by the map, as guest: dropped", false, "10.0.0.1", false, 0, 0, GPTEST_MISSING, false},
};

// One node and the fake adapter of its host, which keeps the last packet that the host took
typedef struct GPTEST_NODE
{
	wchar_t Dir[MAX_PATH];				// Its data directory
	PEER_KEY Key;						// Its static key
	NODE *Node;
	NODE_READER Reader;					// The test thread as a reader of the node's tables, online while it sends
	USHORT VxlanPort;					// The UDP port of its socket of VXLAN ...
	USHORT GenevePort;					// ... and of Geneve
	UINT64 Generation;					// The Generation of the last state that the test applied
	SRWLOCK Lock;						// Arrivals, Last and LastSize
	volatile LONG Arrivals;				// Packets that the host took
	UCHAR Last[GPTEST_SIZE * 2];		// The last one, as much as fits
	UINT LastSize;
} GPTEST_NODE;

// The test
typedef struct GPTEST_CTX
{
	UINT NumChecks;
	UINT NumFailed;
	GPTEST_NODE Nodes[2];
	SOCKET Vtep;						// The harness tunnel endpoint, on 127.0.0.1: the address of the tunnel endpoint of node-a
	UINT NextPort;						// The UDP source port of the next case
} GPTEST_CTX;

static bool GpTestCheck(GPTEST_CTX *ctx, bool ok, char *what, char *fmt, ...) RANZ_PRINTF_FORMAT(4, 5);
static bool GpTestCheck(GPTEST_CTX *ctx, bool ok, char *what, char *fmt, ...)
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
static DWORD WINAPI GpTestWatchdog(LPVOID param)
{
	char msg[MAX_SIZE];
	DWORD written = 0;

	if (WaitForSingleObject((HANDLE)param, GPTEST_BUDGET) != WAIT_TIMEOUT)
	{
		return 0;
	}

	int len = snprintf(msg, sizeof(msg), "GROUPPOLICY TEST FAILED (did not finish within %u ms)\n", GPTEST_BUDGET);
	if (len > 0)
	{
		WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), msg, (DWORD)MIN((UINT)len, (UINT)sizeof(msg) - 1), &written, NULL);
	}

	TerminateProcess(GetCurrentProcess(), 1);

	return 0;
}

// The address of a text into addr: 4 bytes for IPv4, 16 for IPv6, and their number; 0 for no address
static UINT GpTestAddress(UCHAR *addr, char *str)
{
	IP ip;

	Zero(addr, 16);
	if (StrToIP(&ip, str) == false)
	{
		return 0;
	}

	if (IsIP4(&ip))
	{
		Copy(addr, IPV4(ip.address), 4);
		return 4;
	}

	Copy(addr, ip.address, 16);
	return 16;
}

// The test packet from the address src and the UDP port sport to node-b's host on GPTEST_PORT, GPTEST_SIZE bytes of
// IPv4, into buf
static void GpTestPacket(UCHAR *buf, char *src, UINT sport)
{
	UCHAR addr[16];

	Zero(buf, GPTEST_SIZE);
	buf[0] = 0x45;
	WRITE_USHORT(buf + 2, GPTEST_SIZE);
	buf[8] = 64;
	buf[9] = IP_PROTO_UDP;
	GpTestAddress(addr, src);
	Copy(buf + 12, addr, 4);
	GpTestAddress(addr, gptest_addrs[GPTEST_B][0]);
	Copy(buf + 16, addr, 4);
	USHORT sum = IpChecksum(buf, 20);
	Copy(buf + 10, &sum, 2);

	WRITE_USHORT(buf + 20, sport);
	WRITE_USHORT(buf + 22, GPTEST_PORT);
	WRITE_USHORT(buf + 24, GPTEST_SIZE - 20);
	for (UINT i = 28;i < GPTEST_SIZE;i++)
	{
		buf[i] = (UCHAR)(i * 13 + sport);
	}
}

// The num free UDP ports of the wildcard address into ports, which the system picks, each another: the sockets that
// found them stay open until all are found. False when one cannot be found.
static bool GpTestFreePorts(USHORT *ports, UINT num)
{
	SOCKET sockets[4] = {INVALID_SOCKET, INVALID_SOCKET, INVALID_SOCKET, INVALID_SOCKET};
	bool ok = (num <= 4);

	for (UINT i = 0;i < num && ok;i++)
	{
		struct sockaddr_in6 sa;
		int sa_size = sizeof(sa);

		ports[i] = 0;
		sockets[i] = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
		Zero(&sa, sizeof(sa));
		sa.sin6_family = AF_INET6;
		if (sockets[i] != INVALID_SOCKET && bind(sockets[i], (struct sockaddr *)&sa, sizeof(sa)) == 0 && getsockname(sockets[i], (struct sockaddr *)&sa, &sa_size) == 0)
		{
			ports[i] = ntohs(sa.sin6_port);
		}
		ok = (ports[i] != 0);
	}

	for (UINT i = 0;i < num && i < 4;i++)
	{
		if (sockets[i] != INVALID_SOCKET)
		{
			closesocket(sockets[i]);
		}
	}

	return ok;
}

// The harness tunnel endpoint: a UDP socket on 127.0.0.1, on a port that the system picks
static SOCKET GpTestOpenVtep()
{
	SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	struct sockaddr_in sa;

	if (s == INVALID_SOCKET)
	{
		return INVALID_SOCKET;
	}

	Zero(&sa, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (bind(s, (struct sockaddr *)&sa, sizeof(sa)) != 0)
	{
		closesocket(s);
		return INVALID_SOCKET;
	}

	return s;
}

// Send node-b, from the harness tunnel endpoint, a datagram of the encapsulation of the link of kind on the VNI of red: its
// header, with the source group group and its tag set tags when has_group is set (the group policy extension of VXLAN,
// the group ID alone, or the option of the source group of Geneve, Core/VxlanGroup.c), then the frame of packet behind the
// Ethernet header of a link. Whether it went.
static bool GpTestInject(GPTEST_CTX *ctx, UINT kind, const UCHAR *packet, bool has_group, UINT group, UINT64 tags)
{
	UCHAR datagram[GENEVE_HEADER_SIZE + GENEVE_GROUP_OPTION + NODE_LINK_ETHER + GPTEST_SIZE];
	GPTEST_NODE *b = &ctx->Nodes[GPTEST_B];
	bool geneve = (kind == CONTROL_LINK_GENEVE);
	UINT header = VXLAN_HEADER_SIZE;
	struct sockaddr_in sa;

	Zero(datagram, sizeof(datagram));
	if (geneve)
	{
		VxlanWriteGeneve(datagram, GPTEST_VNI);
		header = GENEVE_HEADER_SIZE;
		if (has_group)
		{
			// The length of the one option in 4-byte words, and the option
			datagram[0] |= (UCHAR)(GENEVE_GROUP_OPTION / 4);
			VxlanWriteGroupOption(datagram + GENEVE_HEADER_SIZE, (USHORT)group, tags);
			header += GENEVE_GROUP_OPTION;
		}
	}
	else
	{
		datagram[0] = VXLAN_FLAG_VNI;
		datagram[4] = (UCHAR)(GPTEST_VNI >> 16);
		datagram[5] = (UCHAR)(GPTEST_VNI >> 8);
		datagram[6] = (UCHAR)GPTEST_VNI;
		if (has_group)
		{
			VxlanWriteGroup(datagram, (USHORT)group);
		}
	}

	// The frame: the Ethernet header of a link and the packet
	Copy(datagram + header, gptest_mac, 6);
	Copy(datagram + header + 6, gptest_mac, 6);
	WRITE_USHORT(datagram + header + 12, MAC_PROTO_IPV4);
	Copy(datagram + header + NODE_LINK_ETHER, packet, GPTEST_SIZE);

	UINT size = header + NODE_LINK_ETHER + GPTEST_SIZE;
	Zero(&sa, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sa.sin_port = htons(geneve ? b->GenevePort : b->VxlanPort);

	return sendto(ctx->Vtep, (char *)datagram, (int)size, 0, (struct sockaddr *)&sa, sizeof(sa)) == (int)size;
}

//
// The nodes
//

// A new empty data directory under the temp directory of the process, with a configuration store that runs no role
// on one worker
static void GpTestNewDir(wchar_t *dir, UINT size, char *name)
{
	wchar_t tmp[MAX_PATH];
	wchar_t path[MAX_PATH];

	UniFormat(tmp, sizeof(tmp), L"grouppolicytest_%S_%u", name, Rand32());
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

// Delete the files of a directory, which holds no subdirectory, and then the directory
static void GpTestDeleteFiles(wchar_t *dir)
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

// The fake adapter of a host: it counts the packets that the host takes and keeps the last one. A link delivers on the
// receive thread of its socket and a session on the thread of the overlay, so the lock orders the two.
static void GpTestAdapter(NODE *n, void *param, UINT vrf_id, const UCHAR *packet, UINT size)
{
	GPTEST_NODE *t = (GPTEST_NODE *)param;

	AcquireSRWLockExclusive(&t->Lock);
	{
		t->LastSize = size;
		Copy(t->Last, packet, MIN(size, sizeof(t->Last)));
		InterlockedIncrement(&t->Arrivals);
	}
	ReleaseSRWLockExclusive(&t->Lock);
}

// The addresses of node i in red into a
static UINT GpTestAddresses(UINT i, CONTROL_ADDRESS *a)
{
	for (UINT k = 0;k < 2;k++)
	{
		Zero(&a[k], sizeof(CONTROL_ADDRESS));
		StrCpy(a[k].Network, sizeof(a[k].Network), "red");
		a[k].VrfId = GPTEST_VRF;
		a[k].AddressSize = GpTestAddress(a[k].Address, gptest_addrs[i][k]);
		a[k].Length = (a[k].AddressSize == 4 ? 24 : 64);
	}

	return 2;
}

// The tunnel endpoint of node i into v: 127.0.0.1 and its ports, or only its ports for itself
static void GpTestVtep(GPTEST_CTX *ctx, UINT i, CONTROL_VTEP *v, bool address)
{
	Zero(v, sizeof(CONTROL_VTEP));
	if (address)
	{
		v->AddressSize = GpTestAddress(v->Address, "127.0.0.1");
	}
	v->VxlanPort = ctx->Nodes[i].VxlanPort;
	v->GenevePort = ctx->Nodes[i].GenevePort;
}

// The Device phone into d: its address in red and its tag admin, its source group admin when grouped, and in the state of
// node-a, its gateway, the WireGuard key that makes node-a terminate it. The state names no WireGuard port, so node-a runs
// no WireGuard interface for it, and the address of phone leads to node-a's host, which sends from it as phone would.
static void GpTestPhone(CONTROL_DEVICE *d, bool gateway, bool grouped)
{
	Zero(d, sizeof(CONTROL_DEVICE));
	StrCpy(d->Name, sizeof(d->Name), "phone");
	d->VrfId = GPTEST_VRF;
	d->NumAddresses = 1;
	StrCpy(d->Addresses[0].Network, sizeof(d->Addresses[0].Network), "red");
	d->Addresses[0].VrfId = GPTEST_VRF;
	d->Addresses[0].AddressSize = GpTestAddress(d->Addresses[0].Address, GPTEST_PHONE);
	d->Addresses[0].Length = 32;
	d->NumTags = 1;
	StrCpy(d->Tags[0], sizeof(d->Tags[0]), "admin");
	StrCpy(d->Gateway, sizeof(d->Gateway), gptest_names[GPTEST_A]);

	if (gateway)
	{
		d->HasKey = true;
		for (UINT i = 0;i < NOISE_KEY_SIZE;i++)
		{
			d->Key[i] = (UCHAR)(0x11 + i);
		}
	}

	if (grouped)
	{
		d->Group = GPTEST_ADMIN;
		d->TagSet = GPTEST_ADMIN_TAGS;
	}
}

// Apply the next Generation of node i: its addresses, its tag and its tunnel endpoint; VRF red with the link of kind and
// the tag mode mode, whose policy node-b enforces with the rule admin-in and node-a not at all; the other node as its
// peer; and the Device phone. With tagged, both nodes report the Capability tags, as the controller then makes their
// states: node-a's own group in red is own_group with the tag set own_tags, node-b's server, each node's Peer object names
// the group of the other and the frame version 1, and phone has its group. Without, node-a is a node without the
// Capability: its state names no group and no frame version, and node-b's names no group of node-a and no frame version,
// but its own group and that of phone, as node-b still reports the Capability.
static bool GpTestApply(GPTEST_CTX *ctx, UINT i, UINT kind, UINT mode, bool tagged, UINT own_group, UINT64 own_tags)
{
	CONTROL_STATE *st = ZeroMalloc(sizeof(CONTROL_STATE));
	CONTROL_RULE *rule = ZeroMalloc(sizeof(CONTROL_RULE));
	CONTROL_PEER *p = ZeroMalloc(sizeof(CONTROL_PEER));
	CONTROL_DEVICE *phone = ZeroMalloc(sizeof(CONTROL_DEVICE));
	GPTEST_NODE *t = &ctx->Nodes[i];
	bool b = (i == GPTEST_B);
	UINT j = 1 - i;

	st->Generation = ++t->Generation;
	StrCpy(st->Name, sizeof(st->Name), gptest_names[i]);
	st->NumAddresses = GpTestAddresses(i, st->Addresses);
	st->NumTags = 1;
	StrCpy(st->Tags[0], sizeof(st->Tags[0]), gptest_tags[i]);
	GpTestVtep(ctx, i, &st->Vtep, false);

	st->NumVrfs = 1;
	StrCpy(st->Vrfs[0].Name, sizeof(st->Vrfs[0].Name), "red");
	st->Vrfs[0].Id = GPTEST_VRF;
	st->Vrfs[0].Policy = b;
	st->Vrfs[0].Link = kind;
	st->Vrfs[0].Vni = (kind != CONTROL_LINK_NOISE ? GPTEST_VNI : 0);
	st->Vrfs[0].TagMode = mode;

	// The rule of red that node-b enforces: from the tag admin to the tag server, any protocol
	if (b)
	{
		StrCpy(rule->Name, sizeof(rule->Name), "admin-in");
		rule->VrfId = GPTEST_VRF;
		rule->Priority = 100;
		rule->From.NumTags = 1;
		StrCpy(rule->From.Tags[0], sizeof(rule->From.Tags[0]), "admin");
		rule->To.NumTags = 1;
		StrCpy(rule->To.Tags[0], sizeof(rule->To.Tags[0]), "server");
		st->NumRules = 1;
		st->Rules = rule;
	}

	// Its own source group in red
	if (tagged || b)
	{
		st->NumGroups = 1;
		st->Groups[0].VrfId = GPTEST_VRF;
		st->Groups[0].Group = (b ? GPTEST_SERVER : own_group);
		st->Groups[0].TagSet = (b ? GPTEST_SERVER_TAGS : own_tags);
	}

	// The other node, its peer, with the group that the controller gives it from its tag
	StrCpy(p->Name, sizeof(p->Name), gptest_names[j]);
	Copy(p->Key, ctx->Nodes[j].Key.Public, PEER_KEY_SIZE);
	p->NumVrfs = 1;
	p->VrfIds[0] = GPTEST_VRF;
	p->NumAddresses = GpTestAddresses(j, p->Addresses);
	p->NumTags = 1;
	StrCpy(p->Tags[0], sizeof(p->Tags[0]), gptest_tags[j]);
	GpTestVtep(ctx, j, &p->Vtep, true);
	if (tagged)
	{
		p->NumGroups = 1;
		p->Groups[0].VrfId = GPTEST_VRF;
		p->Groups[0].Group = (b ? GPTEST_GUEST : GPTEST_SERVER);
		p->Groups[0].TagSet = (b ? GPTEST_GUEST_TAGS : GPTEST_SERVER_TAGS);
		p->FrameVersion = NODE_FRAME_VERSION;
	}
	st->NumPeers = 1;
	st->Peers = p;

	// The Device phone, whose gateway node-a is
	GpTestPhone(phone, b == false, tagged || b);
	st->NumDevices = 1;
	st->Devices = phone;

	bool ok = NodeOverlayApply(t->Node, st);

	Free(phone);
	Free(p);
	Free(rule);
	Free(st);

	return ok;
}

// Whether each node runs the Generation that the test applied last with its session to the other up, within GPTEST_BOUND
static bool GpTestWaitLinks(GPTEST_CTX *ctx)
{
	UINT64 end = Tick64() + GPTEST_BOUND;

	while (true)
	{
		NODE_OVERLAY_STATUS a, b;

		NodeOverlayGetStatus(ctx->Nodes[GPTEST_A].Node, &a);
		NodeOverlayGetStatus(ctx->Nodes[GPTEST_B].Node, &b);
		if (a.NumLinks == 1 && b.NumLinks == 1 && a.Generation == ctx->Nodes[GPTEST_A].Generation && b.Generation == ctx->Nodes[GPTEST_B].Generation)
		{
			return true;
		}
		if (Tick64() >= end)
		{
			return false;
		}
		SleepThread(GPTEST_POLL);
	}
}

// One Generation of node-a, as GpTestApply makes it, and the wait for it
static bool GpTestApplyA(GPTEST_CTX *ctx, UINT kind, UINT mode, bool tagged, UINT own_group, UINT64 own_tags)
{
	return GpTestApply(ctx, GPTEST_A, kind, mode, tagged, own_group, own_tags) && GpTestWaitLinks(ctx);
}

// One Generation of each node with the link of kind and the tag mode mode, node-b first, node-a with its own group guest:
// each runs it and the session stays up
static bool GpTestSwitch(GPTEST_CTX *ctx, UINT kind, UINT mode, bool tagged)
{
	char what[MAX_SIZE];

	bool applied = GpTestApply(ctx, GPTEST_B, kind, mode, tagged, 0, 0) && GpTestApply(ctx, GPTEST_A, kind, mode, tagged, GPTEST_GUEST, GPTEST_GUEST_TAGS);
	bool linked = applied && GpTestWaitLinks(ctx);

	Format(what, sizeof(what), "The link of red is %s in the tag mode %s, %s: one Generation of each node, node-b first, and the session stays up",
		gptest_kind_names[kind], gptest_mode_names[mode], tagged ? "both nodes with the Capability tags" : "node-a without the Capability tags");
	return GpTestCheck(ctx, applied && linked, what, "applied %u, the Generations %I64u and %I64u and the session on both %u", (UINT)applied,
		ctx->Nodes[GPTEST_A].Generation, ctx->Nodes[GPTEST_B].Generation, (UINT)linked);
}

// Whether the host of node t took at least target packets within timeout
static bool GpTestArrived(GPTEST_NODE *t, LONG target, UINT timeout)
{
	UINT64 end = Tick64() + timeout;

	while (InterlockedCompareExchange(&t->Arrivals, 0, 0) < target)
	{
		if (Tick64() >= end)
		{
			return false;
		}
		SleepThread(GPTEST_POLL);
	}

	return true;
}

// The counter of the status st that counts the packets of the tag mode mode as result (GPTEST_*)
static UINT64 GpTestCount(const NODE_SOURCE_GROUP_STATUS *st, UINT mode, UINT result)
{
	const CONTROL_GROUP_COUNTERS *c = &st->Modes[mode];

	switch (result)
	{
	case GPTEST_CARRIED:
		return c->Carried;
	case GPTEST_MISSING:
		return c->Missing;
	case GPTEST_IGNORED:
		return c->Ignored;
	case GPTEST_REFUSED:
		return c->Refused;
	}

	return 0;
}

// All the packets that the status st counts
static UINT64 GpTestTotal(const NODE_SOURCE_GROUP_STATUS *st)
{
	UINT64 sum = 0;

	for (UINT mode = 0;mode < CONTROL_TAG_MODES;mode++)
	{
		for (UINT result = 0;result < GPTEST_UNCOUNTED;result++)
		{
			sum += GpTestCount(st, mode, result);
		}
	}

	return sum;
}

// Whether node-b logged at least num lines about the claims that it refused within GPTEST_BOUND, with its status in *st
static bool GpTestLogged(GPTEST_CTX *ctx, UINT64 num, NODE_SOURCE_GROUP_STATUS *st)
{
	UINT64 end = Tick64() + GPTEST_BOUND;

	while (true)
	{
		NodeSourceGroupGetStatus(ctx->Nodes[GPTEST_B].Node, st);
		if (st->Logged >= num)
		{
			return true;
		}
		if (Tick64() >= end)
		{
			return false;
		}
		SleepThread(GPTEST_POLL);
	}
}

//
// The cases
//

// One case over the link of kind, whose packets of node-a node-b judges in the tag mode mode: the packet goes from a source
// port of its own; node-b must count it once, as the case says, or drop it uncounted, and its host take it as it was sent
// or nothing
static void GpTestCase(GPTEST_CTX *ctx, UINT kind, UINT mode, GPTEST_CASE *c)
{
	GPTEST_NODE *a = &ctx->Nodes[GPTEST_A];
	GPTEST_NODE *b = &ctx->Nodes[GPTEST_B];
	NODE_SOURCE_GROUP_STATUS before, after;
	NODE_OVERLAY_STATUS ob, oa;
	UCHAR packet[GPTEST_SIZE];
	char what[MAX_SIZE * 2];
	bool sent, counted = false, same = false;

	GpTestPacket(packet, c->Src, ctx->NextPort++);
	NodeSourceGroupGetStatus(b->Node, &before);
	NodeOverlayGetStatus(b->Node, &ob);
	LONG arrivals = InterlockedCompareExchange(&b->Arrivals, 0, 0);

	if (c->Inject)
	{
		sent = GpTestInject(ctx, kind, packet, c->HasGroup, c->Group, c->Tags);
	}
	else
	{
		NodeReaderOnline(a->Node, &a->Reader);
		sent = NodeOverlayInput(a->Node, GPTEST_VRF, packet, GPTEST_SIZE);
		NodeReaderOffline(&a->Reader);
	}

	// Node-b judged the packet once it counted it: by its tag mode and its source group, or, for a packet whose source no
	// route leads to node-a, as a drop of its overlay before any group
	UINT64 end = Tick64() + GPTEST_BOUND;
	while (sent && counted == false)
	{
		NodeSourceGroupGetStatus(b->Node, &after);
		NodeOverlayGetStatus(b->Node, &oa);
		counted = (c->Result == GPTEST_UNCOUNTED ? oa.Dropped > ob.Dropped : GpTestCount(&after, mode, c->Result) > GpTestCount(&before, mode, c->Result));
		if (counted == false)
		{
			if (Tick64() >= end)
			{
				break;
			}
			SleepThread(GPTEST_POLL);
		}
	}

	bool arrived = sent && GpTestArrived(b, arrivals + 1, c->Arrives ? GPTEST_BOUND : GPTEST_QUIET);
	NodeSourceGroupGetStatus(b->Node, &after);

	AcquireSRWLockShared(&b->Lock);
	{
		same = (arrived && b->LastSize == GPTEST_SIZE && Cmp(b->Last, packet, GPTEST_SIZE) == 0);
	}
	ReleaseSRWLockShared(&b->Lock);

	// The packet of the case is the one packet that node-b counted, none for one that it dropped before any group
	UINT64 counts = GpTestTotal(&after) - GpTestTotal(&before);
	UINT64 want = (c->Result == GPTEST_UNCOUNTED ? 0 : 1);

	Format(what, sizeof(what), "  %s: %s", gptest_kind_names[kind], c->What);
	GpTestCheck(ctx, sent && counted && counts == want && arrived == c->Arrives && (c->Arrives == false || same), what,
		"sent %u, counted as %s in the tag mode %s %u, %I64u counted in all, arrived %u, as it was sent %u", (UINT)sent,
		c->Result < GPTEST_UNCOUNTED ? gptest_results[c->Result] : "a drop of the overlay", gptest_mode_names[mode], (UINT)counted, counts,
		(UINT)arrived, (UINT)same);
}

// The num cases of cases, in order
static void GpTestCases(GPTEST_CTX *ctx, UINT kind, UINT mode, GPTEST_CASE *cases, UINT num)
{
	for (UINT i = 0;i < num;i++)
	{
		GpTestCase(ctx, kind, mode, &cases[i]);
	}
}

// The packets of node-a's host over the link of kind, by the group that node-a stamps on them: guest, its own, and admin for
// the address of phone; then admin, which it may assert as the gateway of phone, and server, the group of node-b, which it
// may not, on the packets of its own address. Node-b logs the first claim that it refuses.
static void GpTestStamped(GPTEST_CTX *ctx, UINT kind)
{
	UINT mode = (kind == CONTROL_LINK_NOISE ? CONTROL_TAG_MODE_SESSION : CONTROL_TAG_MODE_TRUSTED);
	NODE_SOURCE_GROUP_STATUS st;
	char what[MAX_SIZE];

	GpTestCases(ctx, kind, mode, gptest_own, sizeof(gptest_own) / sizeof(gptest_own[0]));

	Format(what, sizeof(what), "  %s: node-a stamps admin on the packets of its own address, one Generation of node-a", gptest_kind_names[kind]);
	if (GpTestCheck(ctx, GpTestApplyA(ctx, kind, CONTROL_TAG_MODE_TRUSTED, true, GPTEST_ADMIN, GPTEST_ADMIN_TAGS), what, "not within %u ms", GPTEST_BOUND))
	{
		GpTestCases(ctx, kind, mode, gptest_admin, sizeof(gptest_admin) / sizeof(gptest_admin[0]));
	}

	NodeSourceGroupGetStatus(ctx->Nodes[GPTEST_B].Node, &st);
	UINT64 logged = st.Logged;

	Format(what, sizeof(what), "  %s: node-a stamps server, the group of node-b, on them, one Generation of node-a", gptest_kind_names[kind]);
	if (GpTestCheck(ctx, GpTestApplyA(ctx, kind, CONTROL_TAG_MODE_TRUSTED, true, GPTEST_SERVER, GPTEST_SERVER_TAGS), what, "not within %u ms", GPTEST_BOUND))
	{
		GpTestCases(ctx, kind, mode, gptest_rogue, sizeof(gptest_rogue) / sizeof(gptest_rogue[0]));
	}

	// The first claim that node-b refused is logged; it counts the ones within NODE_SOURCE_GROUP_LOG ms after it in its next
	// line
	if (logged == 0)
	{
		bool ok = GpTestLogged(ctx, 1, &st);

		Format(what, sizeof(what), "  %s: node-b logged the claim that it refused, as an unknown group", gptest_kind_names[kind]);
		GpTestCheck(ctx, ok && InStr(st.Last, "node-a claimed the group 3") && InStr(st.Last, "dropped as an unknown group"), what, "%I64u lines, the last \"%s\"",
			st.Logged, st.Last);
	}

	Format(what, sizeof(what), "  %s: node-a stamps guest again, one Generation of node-a", gptest_kind_names[kind]);
	GpTestCheck(ctx, GpTestApplyA(ctx, kind, CONTROL_TAG_MODE_TRUSTED, true, GPTEST_GUEST, GPTEST_GUEST_TAGS), what, "not within %u ms", GPTEST_BOUND);
}

// The datagrams of the harness tunnel endpoint over the link of kind, vxlan or geneve, in the tag mode trusted-underlay,
// then off
static void GpTestInjected(GPTEST_CTX *ctx, UINT kind)
{
	GpTestCases(ctx, kind, CONTROL_TAG_MODE_TRUSTED, gptest_trusted, sizeof(gptest_trusted) / sizeof(gptest_trusted[0]));
	if (kind == CONTROL_LINK_GENEVE)
	{
		GpTestCases(ctx, kind, CONTROL_TAG_MODE_TRUSTED, gptest_tag_set, sizeof(gptest_tag_set) / sizeof(gptest_tag_set[0]));
	}

	if (GpTestSwitch(ctx, kind, CONTROL_TAG_MODE_OFF, true))
	{
		GpTestCases(ctx, kind, CONTROL_TAG_MODE_OFF, gptest_off, sizeof(gptest_off) / sizeof(gptest_off[0]));
	}
}

// The nodes, their overlays and the harness tunnel endpoint, and the first Generation of each: noise, both with the
// Capability tags
static bool GpTestOpen(GPTEST_CTX *ctx, TRANSPORT *loopback)
{
	UCHAR scalar[PEER_KEY_SIZE];
	char what[MAX_SIZE];
	bool ok = (loopback != NULL);
	USHORT ports[4];

	Print("[the nodes, their overlays and the harness tunnel endpoint]\n");

	// The UDP ports of VXLAN and of Geneve of each node
	ok = GpTestCheck(ctx, ok && GpTestFreePorts(ports, 4), "Four free UDP ports for the tunnel endpoints of the nodes", "error %u", (UINT)WSAGetLastError()) && ok;

	ctx->Vtep = GpTestOpenVtep();
	ok = GpTestCheck(ctx, ok && ctx->Vtep != INVALID_SOCKET, "A harness tunnel endpoint on 127.0.0.1, the address of the tunnel endpoint of node-a", "error %u", (UINT)WSAGetLastError()) && ok;

	for (UINT i = 0;i < 2 && ok;i++)
	{
		GPTEST_NODE *t = &ctx->Nodes[i];
		NODE_OVERLAY_CONFIG c;

		InitializeSRWLock(&t->Lock);
		t->VxlanPort = ports[2 * i];
		t->GenevePort = ports[2 * i + 1];
		for (UINT j = 0;j < PEER_KEY_SIZE;j++)
		{
			scalar[j] = (UCHAR)(0x61 + PEER_KEY_SIZE * i + j);
		}
		ok = PeerKeyFromScalar(&t->Key, scalar);

		GpTestNewDir(t->Dir, sizeof(t->Dir), gptest_names[i]);
		t->Node = NewNode(t->Dir);
		NodeStart(t->Node);
		NodeReaderRegister(t->Node, &t->Reader);
		NodeReaderOffline(&t->Reader);

		Zero(&c, sizeof(c));
		c.Data = loopback;
		c.Key = &t->Key;
		c.Adapter = GpTestAdapter;
		c.AdapterParam = t;
		Format(what, sizeof(what), "  %s: its overlay runs without a control stream, its tunnel endpoint on the UDP ports %u (VXLAN) and %u (Geneve)", gptest_names[i], (UINT)t->VxlanPort, (UINT)t->GenevePort);
		ok = GpTestCheck(ctx, ok && NodeOverlayStart(t->Node, &c), what, "PeerKeyFromScalar or NodeOverlayStart failed") && ok;
	}
	Zero(scalar, sizeof(scalar));

	return ok && GpTestSwitch(ctx, CONTROL_LINK_NOISE, CONTROL_TAG_MODE_TRUSTED, true);
}

// The nodes first, whose overlays stop with every thread joined, then the harness tunnel endpoint
static void GpTestClose(GPTEST_CTX *ctx)
{
	for (UINT i = 0;i < 2;i++)
	{
		GPTEST_NODE *t = &ctx->Nodes[i];
		wchar_t log_dir[MAX_PATH];

		if (t->Node != NULL)
		{
			NodeReaderUnregister(t->Node, &t->Reader);
			NodeStop(t->Node);
			FreeNode(t->Node);

			ConbinePathW(log_dir, sizeof(log_dir), t->Dir, NODE_LOG_DIR_NAME);
			GpTestDeleteFiles(log_dir);
			GpTestDeleteFiles(t->Dir);
		}
		PeerKeyClose(&t->Key);
	}

	if (ctx->Vtep != INVALID_SOCKET)
	{
		closesocket(ctx->Vtep);
	}
}

// The cases over noise, vxlan and geneve, each in a Generation of its own of both nodes, then the records of frame version 0
static void GpTestRun(GPTEST_CTX *ctx)
{
	UINT kinds[3] = {CONTROL_LINK_NOISE, CONTROL_LINK_VXLAN, CONTROL_LINK_GENEVE};

	for (UINT k = 0;k < 3;k++)
	{
		UINT kind = kinds[k];

		Print("[the link of red is %s]\n", gptest_kind_names[kind]);
		if (k != 0 && GpTestSwitch(ctx, kind, CONTROL_TAG_MODE_TRUSTED, true) == false)
		{
			return;
		}

		GpTestStamped(ctx, kind);
		if (kind != CONTROL_LINK_NOISE)
		{
			GpTestInjected(ctx, kind);
		}
	}

	// One Generation of each node: node-b's without the groups of node-a, node-a's that stamps admin
	Print("[the Generations roll out: node-a stamps its records before node-b knows its groups, over noise]\n");
	bool applied = GpTestApply(ctx, GPTEST_B, CONTROL_LINK_NOISE, CONTROL_TAG_MODE_TRUSTED, false, 0, 0) &&
		GpTestApply(ctx, GPTEST_A, CONTROL_LINK_NOISE, CONTROL_TAG_MODE_TRUSTED, true, GPTEST_ADMIN, GPTEST_ADMIN_TAGS) && GpTestWaitLinks(ctx);
	if (GpTestCheck(ctx, applied, "The link of red is noise; node-a sends records of frame version 1 that claim admin, and the state of node-b gives node-a the frame version 0 and none of its groups",
		"not within %u ms", GPTEST_BOUND))
	{
		GpTestCases(ctx, CONTROL_LINK_NOISE, CONTROL_TAG_MODE_SESSION, gptest_rollout, sizeof(gptest_rollout) / sizeof(gptest_rollout[0]));
	}

	Print("[frame version 0: node-a is a node without the Capability tags, over noise]\n");
	if (GpTestSwitch(ctx, CONTROL_LINK_NOISE, CONTROL_TAG_MODE_TRUSTED, false))
	{
		GpTestCases(ctx, CONTROL_LINK_NOISE, CONTROL_TAG_MODE_SESSION, gptest_version0, sizeof(gptest_version0) / sizeof(gptest_version0[0]));
	}
}

// grouppolicy: the policy of a VRF by the source group that a packet carries
RANZ_TEST_TAGS("grouppolicy", grouppolicy_test, "core", "Source group policy (SDN-87): between two nodes, a rule written by tag allows or denies a packet by the source group that it carries, over noise, vxlan and geneve; a claim of a group that the sending node may not assert is dropped, counted and logged; a packet without one is judged by the map of address to group; trusted-underlay honours a forged group and off ignores it; a node ignores the claims of a peer whose groups it does not know yet; a node of frame version 0 still gets through.");
void grouppolicy_test(UINT num, char **arg)
{
	GPTEST_CTX *ctx = ZeroMalloc(sizeof(GPTEST_CTX));
	HANDLE done = CreateEventW(NULL, TRUE, FALSE, NULL);
	HANDLE watchdog = (done != NULL ? CreateThread(NULL, 0, GpTestWatchdog, done, 0, NULL) : NULL);
	TRANSPORT *loopback = TransportLoopbackNew("loopback", 0, false);

	Print("Source group policy test: the node that takes a packet of a peer judges it by the source group that the packet carried\n");

	ctx->Vtep = INVALID_SOCKET;
	ctx->NextPort = GPTEST_FIRST_PORT;

	if (GpTestOpen(ctx, loopback))
	{
		GpTestRun(ctx);
	}

	GpTestClose(ctx);
	TransportLoopbackFree(loopback);

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
		Print("GROUPPOLICY TEST OK\n");
	}
	else
	{
		Print("GROUPPOLICY TEST FAILED (%u of %u checks failed)\n", ctx->NumFailed, ctx->NumChecks);
	}

	Free(ctx);
}
