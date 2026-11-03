// hmactagtest.c
// Named tag mode hmac test of vpntest ("hmactags" command, SDN-88 #387)
//
// In the tag mode hmac a node takes the source group of a datagram of a link of kind geneve only with a MAC under a key of the
// VRF and a timestamp within 30 s of its clock (Cedar/NodeTagMac.c), and judges any other claim as a packet without the option,
// by the map of address to group, then default deny. The test runs the overlay of two in-process nodes, as the group policy
// test does (grouppolicytest.c; seam 3 of #45 as ADR-0002 amended it on 2026-10-21): fake adapters stand in for their hosts,
// the in-process loopback transport carries their Noise sessions, both have a tunnel endpoint on 127.0.0.1, and the test
// applies their desired states itself, with the keys of the VRF in its Vrf object, as the controller makes them
// (controller/internal/controller/tagkeys.go). VRF red (101) has three groups: admin (1, the tag set 0x1), the WireGuard Device
// phone at 10.0.0.50, whose gateway node-a is; guest (2, 0x2), node-a; and server (3, 0x4), node-b. Node-b enforces one rule
// written by tag, admin-in, from the tag admin to the tag server, and default deny. A harness tunnel endpoint on 127.0.0.1, the
// address of node-a, is the injector: it sends node-b datagrams that it made itself, as a host on the underlay can.
// - The link of red is geneve in hmac, with key 1. A packet of node-a's host carries its group with a valid MAC: the one from
//   10.0.0.1 is guest, which admin-in does not allow, and is dropped; the one from 10.0.0.50 is admin and arrives; node-b counts
//   both as carried. The injector, with the key, sends admin on a packet from 10.0.0.1 with a valid MAC: honoured, it arrives.
//   Without the key it sends admin on a packet from 10.0.0.1 with a forged MAC, a MAC under a wrong key, a MAC of the same tag
//   on another flow (the destination port changed), a valid MAC whose timestamp is 60 s behind or ahead of the clock of node-b,
//   and admin in the option of trusted-underlay, without a MAC: each is dropped as if the option were missing, as the packet
//   without the option is, since the map judges 10.0.0.1 as guest, and node-b counts each as unauthenticated. The same forged
//   MAC that claims guest on a packet from 10.0.0.50 is judged by the map as admin and arrives: as if the option were missing.
// - The link of red is vxlan in hmac, which the controller refuses, as the group policy extension of VXLAN has no room for the
//   MAC: node-a sends no source group, and node-b judges a forged admin in the extension as unauthenticated.
// - The key of red rotates while a flow is open between the phone, behind node-a, and node-b's host: node-a stamps admin, the
//   group of the phone, on its packets, which admin-in allows, and node-b's host answers each of them. Node-b tracks them as
//   one flow, as it judges the answer of its host by the map of address to group (NodePolicy.c), which gives the phone admin:
//   an honest node stamps on a packet the group that the map gives its source. The Generations of the two nodes go in one
//   after the other, in the order that the controller allows: the new key 2 at node-b, then at node-a, beside key 1, which
//   both send with; then key 2 as the one to send with at node-a, then at node-b; then the next rotation, key 3 beside key 2
//   at node-a, then at node-b. At each step a packet of the flow from the phone arrives at node-b's host and node-b's answer
//   at node-a's host for the phone, and each node counts the other's packet as carried with a valid MAC: no packet of the open
//   flow is lost. Last, the order that the controller never allows, with admin as node-a's own group, which the map of node-b
//   does not give 10.0.0.1: node-a sends with a key that node-b does not hold, and node-b counts its packet as unauthenticated
//   and drops it, as the map judges 10.0.0.1 as guest.
// - Once the nodes stopped, no file that a node wrote, its node log or a file of its data directory, holds a key of red, as it is,
//   in hex or in base64: a node gets the key in its state alone.
// Print "HMACTAGS TEST OK" only when every check passes.

#include "harness_int.h"
#include "testlist.h"

#include "Cedar/ConfigStore.h"
#include "Cedar/Node.h"
#include "Cedar/NodeLink.h"
#include "Cedar/NodeTagMac.h"

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
#include "Core/Vxlan.h"

#include <WS2tcpip.h>

#include <stdio.h>

#define	HTTEST_BUDGET			120000		// The whole test ends within this time, or the watchdog ends the process (ms)
#define	HTTEST_BOUND			10000		// A bounded wait on observable state (ms)
#define	HTTEST_QUIET			300			// A host that gets nothing gets nothing within this time (ms)
#define	HTTEST_POLL				10			// Poll interval of observable state (ms)
#define	HTTEST_SIZE				100			// The size of a test packet
#define	HTTEST_VNI				5101		// The VNI of red
#define	HTTEST_VRF				101			// The id of red
#define	HTTEST_PORT				9000		// The UDP port of node-b's host that every packet goes to
#define	HTTEST_FIRST_PORT		21000		// The UDP source port of the first case; each case takes the next
#define	HTTEST_FLOW_PORT		30000		// The UDP source port of the open flow of the rotation
#define	HTTEST_PHONE			"10.0.0.50"	// The address of the Device phone
#define	HTTEST_SINCE			1			// The group generation of each node in red

#define	HTTEST_A				0
#define	HTTEST_B				1
#define	HTTEST_NUM_NODES		2

// The groups of red and their tag sets
#define	HTTEST_ADMIN			1
#define	HTTEST_GUEST			2
#define	HTTEST_SERVER			3
#define	HTTEST_ADMIN_TAGS		0x1ULL
#define	HTTEST_GUEST_TAGS		0x2ULL
#define	HTTEST_SERVER_TAGS		0x4ULL

// What node-b counts a packet as, in the tag mode hmac
#define	HTTEST_CARRIED			0
#define	HTTEST_MISSING			1
#define	HTTEST_UNAUTHENTICATED	2

// What the injector puts into the option of the source group
#define	HTTEST_NO_OPTION		0			// No option
#define	HTTEST_VALID			1			// A valid MAC under key 1, at the clock of the nodes
#define	HTTEST_FORGED			2			// A MAC of zeros, as a host without the key makes it
#define	HTTEST_WRONG_KEY		3			// A MAC under another key that names key 1
#define	HTTEST_OTHER_FLOW		4			// The valid MAC of the same tag on a packet of another destination port
#define	HTTEST_BEHIND			5			// A valid MAC whose timestamp is 60 s behind the clock of the nodes
#define	HTTEST_AHEAD			6			// ... or 60 s ahead of it
#define	HTTEST_PLAIN			7			// The option of trusted-underlay, without a MAC

static char *httest_names[HTTEST_NUM_NODES] = {"node-a", "node-b"};
static char *httest_addrs[HTTEST_NUM_NODES][2] = {{"10.0.0.1", "fd00::1"}, {"10.0.0.2", "fd00::2"}};
static char *httest_tags[HTTEST_NUM_NODES] = {"guest", "server"};
static char *httest_results[3] = {"carried", "missing", "unauthenticated"};

// The MAC address of both ends of the Ethernet header of a frame of a link
static const UCHAR httest_mac[6] = {0x02, 0x52, 0x5A, 0x00, 0x00, 0x03};

// A key of red in a state: its ID, the first byte of its 32 bytes, each one more than the one before, and whether the node sends
// with it
typedef struct HTTEST_KEY
{
	UINT Id;
	UCHAR First;
	bool Send;
} HTTEST_KEY;

// One case of the injector, or of node-a's host: a UDP packet of red to node-b's host, what node-b counts it as and whether
// node-b's host takes it
typedef struct HTTEST_CASE
{
	char *What;
	bool Inject;						// The injector sends it, else node-a's host
	char *Src;							// Its source address
	UINT Option;						// What the injector puts into the option (HTTEST_NO_OPTION to HTTEST_PLAIN)
	UINT Group;							// ... of this group ID
	UINT64 Tags;						// ... with this tag set
	UINT Result;						// What node-b counts it as (HTTEST_CARRIED to HTTEST_UNAUTHENTICATED)
	bool Arrives;						// Node-b's host takes it, as it was sent
} HTTEST_CASE;

// The packets of node-a's host and of the injector over geneve in the tag mode hmac
static HTTEST_CASE httest_geneve[] =
{
	{"a packet of node-a's host from 10.0.0.1 carries guest with a valid MAC: taken as guest, which admin-in does not allow: dropped", false, "10.0.0.1", 0, 0, 0, HTTEST_CARRIED, false},
	{"one from 10.0.0.50 carries admin, the group of phone, with a valid MAC: taken as admin, which admin-in allows: it arrives", false, HTTEST_PHONE, 0, 0, 0, HTTEST_CARRIED, true},
	{"the injector with the key: admin on a packet from 10.0.0.1 with a valid MAC is honoured: it arrives", true, "10.0.0.1", HTTEST_VALID, HTTEST_ADMIN, HTTEST_ADMIN_TAGS, HTTEST_CARRIED, true},
	{"without the option, the map of address to group judges a packet from 10.0.0.1 as guest: dropped", true, "10.0.0.1", HTTEST_NO_OPTION, 0, 0, HTTEST_MISSING, false},
	{"a forged tag: admin on a packet from 10.0.0.1 with a MAC that the injector made without the key is dropped as if the option were missing, counted as unauthenticated", true, "10.0.0.1", HTTEST_FORGED, HTTEST_ADMIN, HTTEST_ADMIN_TAGS, HTTEST_UNAUTHENTICATED, false},
	{"a wrong key: admin with a MAC under another key that names key 1 is dropped as if the option were missing", true, "10.0.0.1", HTTEST_WRONG_KEY, HTTEST_ADMIN, HTTEST_ADMIN_TAGS, HTTEST_UNAUTHENTICATED, false},
	{"a changed inner header: the valid MAC of admin on a packet of another destination port, the tag pasted onto another flow, is dropped as if the option were missing", true, "10.0.0.1", HTTEST_OTHER_FLOW, HTTEST_ADMIN, HTTEST_ADMIN_TAGS, HTTEST_UNAUTHENTICATED, false},
	{"a timestamp outside the window: a valid MAC of admin 60 s behind the clock of node-b is dropped as if the option were missing", true, "10.0.0.1", HTTEST_BEHIND, HTTEST_ADMIN, HTTEST_ADMIN_TAGS, HTTEST_UNAUTHENTICATED, false},
	{"... and one 60 s ahead of it", true, "10.0.0.1", HTTEST_AHEAD, HTTEST_ADMIN, HTTEST_ADMIN_TAGS, HTTEST_UNAUTHENTICATED, false},
	{"admin in the option of trusted-underlay, without a MAC, is dropped as if the option were missing", true, "10.0.0.1", HTTEST_PLAIN, HTTEST_ADMIN, HTTEST_ADMIN_TAGS, HTTEST_UNAUTHENTICATED, false},
	{"a forged guest on a packet from 10.0.0.50 is judged by the map as admin, as if the option were missing: it arrives", true, HTTEST_PHONE, HTTEST_FORGED, HTTEST_GUEST, HTTEST_GUEST_TAGS, HTTEST_UNAUTHENTICATED, true},
};

// ... and over vxlan in the tag mode hmac
static HTTEST_CASE httest_vxlan[] =
{
	{"vxlan: node-a sends no source group, as the extension of VXLAN has no room for the MAC, and the map judges the packet from 10.0.0.50 as admin: it arrives", false, HTTEST_PHONE, 0, 0, 0, HTTEST_MISSING, true},
	{"vxlan: a forged admin in the group policy extension on a packet from 10.0.0.1 is judged as unauthenticated: dropped", true, "10.0.0.1", HTTEST_PLAIN, HTTEST_ADMIN, 0, HTTEST_UNAUTHENTICATED, false},
};

// One node and the fake adapter of its host, which keeps the last packet that the host took
typedef struct HTTEST_NODE
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
	UCHAR Last[HTTEST_SIZE * 2];		// The last one, as much as fits
	UINT LastSize;
} HTTEST_NODE;

// The test
typedef struct HTTEST_CTX
{
	UINT NumChecks;
	UINT NumFailed;
	HTTEST_NODE Nodes[HTTEST_NUM_NODES];
	SOCKET Vtep;						// The injector, a harness tunnel endpoint on 127.0.0.1: the address of the tunnel endpoint of node-a
	UINT NextPort;						// The UDP source port of the next case
} HTTEST_CTX;

static bool HtTestCheck(HTTEST_CTX *ctx, bool ok, char *what, char *fmt, ...) RANZ_PRINTF_FORMAT(4, 5);
static bool HtTestCheck(HTTEST_CTX *ctx, bool ok, char *what, char *fmt, ...)
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

// The watchdog: a native thread that ends a run that hangs, so that a lost packet is a failed test instead of a hung CI step
static DWORD WINAPI HtTestWatchdog(LPVOID param)
{
	char msg[MAX_SIZE];
	DWORD written = 0;

	if (WaitForSingleObject((HANDLE)param, HTTEST_BUDGET) != WAIT_TIMEOUT)
	{
		return 0;
	}

	int len = snprintf(msg, sizeof(msg), "HMACTAGS TEST FAILED (did not finish within %u ms)\n", HTTEST_BUDGET);
	if (len > 0)
	{
		WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), msg, (DWORD)MIN((UINT)len, (UINT)sizeof(msg) - 1), &written, NULL);
	}

	TerminateProcess(GetCurrentProcess(), 1);

	return 0;
}

// The address of a text into addr: 4 bytes for IPv4, 16 for IPv6, and their number; 0 for no address
static UINT HtTestAddress(UCHAR *addr, char *str)
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

// The test packet from the address src and the UDP port sport to the address dst and the UDP port dport, HTTEST_SIZE bytes of
// IPv4, into buf
static void HtTestPacket(UCHAR *buf, char *src, char *dst, UINT sport, UINT dport)
{
	UCHAR addr[16];

	Zero(buf, HTTEST_SIZE);
	buf[0] = 0x45;
	WRITE_USHORT(buf + 2, HTTEST_SIZE);
	buf[8] = 64;
	buf[9] = IP_PROTO_UDP;
	HtTestAddress(addr, src);
	Copy(buf + 12, addr, 4);
	HtTestAddress(addr, dst);
	Copy(buf + 16, addr, 4);
	USHORT sum = IpChecksum(buf, 20);
	Copy(buf + 10, &sum, 2);

	WRITE_USHORT(buf + 20, sport);
	WRITE_USHORT(buf + 22, dport);
	WRITE_USHORT(buf + 24, HTTEST_SIZE - 20);
	for (UINT i = 28;i < HTTEST_SIZE;i++)
	{
		buf[i] = (UCHAR)(i * 13 + sport);
	}
}

// The num free UDP ports of the wildcard address into ports, which the system picks, each another: the sockets that found them
// stay open until all are found. False when one cannot be found.
static bool HtTestFreePorts(USHORT *ports, UINT num)
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

// The injector: a UDP socket on 127.0.0.1, on a port that the system picks
static SOCKET HtTestOpenVtep()
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

// The key of 32 bytes from first on, each byte one more than the one before
static void HtTestKey(UCHAR *key, UCHAR first)
{
	for (UINT i = 0;i < CONTROL_TAG_KEY_SIZE;i++)
	{
		key[i] = (UCHAR)(first + i);
	}
}

// Send node-b, from the injector, a datagram of the encapsulation of the link of kind on the VNI of red, its header with what the
// case puts into the option of the source group, then the frame of packet behind the Ethernet header of a link. Whether it went.
static bool HtTestInject(HTTEST_CTX *ctx, UINT kind, const HTTEST_CASE *c, const UCHAR *packet)
{
	UCHAR datagram[GENEVE_HEADER_SIZE + GENEVE_GROUP_MAC_OPTION + NODE_LINK_ETHER + HTTEST_SIZE];
	UCHAR other[HTTEST_SIZE];
	UCHAR key[CONTROL_TAG_KEY_SIZE];
	HTTEST_NODE *b = &ctx->Nodes[HTTEST_B];
	bool geneve = (kind == CONTROL_LINK_GENEVE);
	UINT header = VXLAN_HEADER_SIZE;
	UINT now = NodeTagMacNow();
	struct sockaddr_in sa;
	VXLAN_GROUP g;

	// The source group, with its MAC under key 1, of the bytes 0x10 on, or under another key, of the bytes 0x99 on
	Zero(&g, sizeof(g));
	g.Carried = true;
	g.HasTags = true;
	g.HasGeneration = true;
	g.Group = (USHORT)c->Group;
	g.Tags = c->Tags;
	g.Generation = HTTEST_SINCE;
	g.HasMac = (c->Option != HTTEST_PLAIN && c->Option != HTTEST_NO_OPTION);
	g.KeyId = 1;
	g.Time = (c->Option == HTTEST_BEHIND ? now - 60 : (c->Option == HTTEST_AHEAD ? now + 60 : now));
	HtTestKey(key, c->Option == HTTEST_WRONG_KEY ? 0x99 : 0x10);
	Copy(other, packet, HTTEST_SIZE);
	WRITE_USHORT(other + 22, HTTEST_PORT + 1);
	if (g.HasMac && c->Option != HTTEST_FORGED)
	{
		NodeTagMacCompute(key, HTTEST_VNI, &g, c->Option == HTTEST_OTHER_FLOW ? other : packet, HTTEST_SIZE, g.Mac);
	}

	Zero(datagram, sizeof(datagram));
	if (geneve)
	{
		VxlanWriteGeneve(datagram, HTTEST_VNI);
		header = GENEVE_HEADER_SIZE;
		if (c->Option != HTTEST_NO_OPTION)
		{
			UINT option = (g.HasMac ? GENEVE_GROUP_MAC_OPTION : GENEVE_GROUP_OPTION);

			// The length of the one option in 4-byte words, and the option
			datagram[0] |= (UCHAR)(option / 4);
			if (g.HasMac)
			{
				VxlanWriteGroupMacOption(datagram + GENEVE_HEADER_SIZE, &g);
			}
			else
			{
				VxlanWriteGroupOption(datagram + GENEVE_HEADER_SIZE, g.Group, g.Tags, g.Generation);
			}
			header += option;
		}
	}
	else
	{
		datagram[0] = VXLAN_FLAG_VNI;
		datagram[4] = (UCHAR)(HTTEST_VNI >> 16);
		datagram[5] = (UCHAR)(HTTEST_VNI >> 8);
		datagram[6] = (UCHAR)HTTEST_VNI;
		if (c->Option != HTTEST_NO_OPTION)
		{
			VxlanWriteGroup(datagram, g.Group);
		}
	}

	// The frame: the Ethernet header of a link and the packet
	Copy(datagram + header, httest_mac, 6);
	Copy(datagram + header + 6, httest_mac, 6);
	WRITE_USHORT(datagram + header + 12, MAC_PROTO_IPV4);
	Copy(datagram + header + NODE_LINK_ETHER, packet, HTTEST_SIZE);

	UINT size = header + NODE_LINK_ETHER + HTTEST_SIZE;
	Zero(&sa, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sa.sin_port = htons(geneve ? b->GenevePort : b->VxlanPort);

	return sendto(ctx->Vtep, (char *)datagram, (int)size, 0, (struct sockaddr *)&sa, sizeof(sa)) == (int)size;
}

//
// The nodes
//

// A new empty data directory under the temp directory of the process, with a configuration store that runs no role on one
// worker
static void HtTestNewDir(wchar_t *dir, UINT size, char *name)
{
	wchar_t tmp[MAX_PATH];
	wchar_t path[MAX_PATH];

	UniFormat(tmp, sizeof(tmp), L"hmactagtest_%S_%u", name, Rand32());
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
static void HtTestDeleteFiles(wchar_t *dir)
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

// The first bytes of the keys of red that the states of the test give the nodes (HtTestRotation): keys 1, 2 and 3
static const UCHAR httest_key_firsts[] = {0x10, 0x20, 0x30};

// Whether a file of the directory dir, which holds no subdirectory, holds the key of CONTROL_TAG_KEY_SIZE bytes at key: as it is,
// in hex of either case or in base64. The name of the file that holds it goes into found, and the bytes that were read are added
// to *read.
static bool HtTestFilesHoldKey(wchar_t *dir, const UCHAR *key, char *found, UINT found_size, UINT *read)
{
	char upper[CONTROL_TAG_KEY_SIZE * 2 + 1];
	char lower[CONTROL_TAG_KEY_SIZE * 2 + 1];
	char *base64 = Base64FromBin(NULL, key, CONTROL_TAG_KEY_SIZE);
	DIRLIST *d = EnumDirW(dir);
	bool held = false;

	BinToStr(upper, sizeof(upper), key, CONTROL_TAG_KEY_SIZE);
	StrCpy(lower, sizeof(lower), upper);
	StrLower(lower);

	for (UINT i = 0;d != NULL && i < d->NumFiles && held == false;i++)
	{
		wchar_t path[MAX_PATH];
		BUF *b;

		if (d->File[i]->Folder)
		{
			continue;
		}

		ConbinePathW(path, sizeof(path), dir, d->File[i]->FileNameW);
		b = ReadDumpW(path);
		if (b == NULL)
		{
			continue;
		}

		*read += b->Size;
		held = (SearchBin(b->Buf, b->Size, key, CONTROL_TAG_KEY_SIZE) != INFINITE || SearchBin(b->Buf, b->Size, upper, StrLen(upper)) != INFINITE ||
			SearchBin(b->Buf, b->Size, lower, StrLen(lower)) != INFINITE || (base64 != NULL && SearchBin(b->Buf, b->Size, base64, StrLen(base64)) != INFINITE));
		if (held)
		{
			UniToStr(found, found_size, d->File[i]->FileNameW);
		}
		FreeBuf(b);
	}

	FreeDir(d);
	Free(base64);

	return held;
}

// No file that node i wrote holds a key of red that its states gave it: neither its node log, in log_dir, nor a file of its data
// directory, the dump of its configuration among them (the third criterion of SDN-88, at a node). The node is stopped, so its log
// is on disk, and it holds at least the lines of the start and the stop of the node.
static void HtTestKeysFoundNowhere(HTTEST_CTX *ctx, UINT i, wchar_t *log_dir)
{
	HTTEST_NODE *t = &ctx->Nodes[i];
	char what[MAX_SIZE];
	char found[MAX_PATH];
	UINT logged = 0;
	UINT stored = 0;
	bool held = false;

	StrCpy(found, sizeof(found), "");
	for (UINT k = 0;k < sizeof(httest_key_firsts) && held == false;k++)
	{
		UCHAR key[CONTROL_TAG_KEY_SIZE];

		HtTestKey(key, httest_key_firsts[k]);
		held = HtTestFilesHoldKey(log_dir, key, found, sizeof(found), &logged) || HtTestFilesHoldKey(t->Dir, key, found, sizeof(found), &stored);
		Zero(key, sizeof(key));
	}

	Format(what, sizeof(what), "%s: its node log and the files of its data directory hold none of the keys of red, as they are, in hex or in base64",
		httest_names[i]);
	HtTestCheck(ctx, held == false && logged != 0, what, "%s holds one, or the node log is empty (%u bytes read)", found, logged);
}

// The fake adapter of a host: it counts the packets that the host takes and keeps the last one. A link delivers on the receive
// thread of its socket and a session on the thread of the overlay, so the lock orders the two.
static void HtTestAdapter(NODE *n, void *param, UINT vrf_id, const UCHAR *packet, UINT size)
{
	HTTEST_NODE *t = (HTTEST_NODE *)param;

	AcquireSRWLockExclusive(&t->Lock);
	{
		t->LastSize = size;
		Copy(t->Last, packet, MIN(size, sizeof(t->Last)));
		InterlockedIncrement(&t->Arrivals);
	}
	ReleaseSRWLockExclusive(&t->Lock);
}

// The addresses of node i in red into a
static UINT HtTestAddresses(UINT i, CONTROL_ADDRESS *a)
{
	for (UINT k = 0;k < 2;k++)
	{
		Zero(&a[k], sizeof(CONTROL_ADDRESS));
		StrCpy(a[k].Network, sizeof(a[k].Network), "red");
		a[k].VrfId = HTTEST_VRF;
		a[k].AddressSize = HtTestAddress(a[k].Address, httest_addrs[i][k]);
		a[k].Length = (a[k].AddressSize == 4 ? 24 : 64);
	}

	return 2;
}

// The tunnel endpoint of node i into v: 127.0.0.1 and its ports, or only its ports for itself
static void HtTestVtep(HTTEST_CTX *ctx, UINT i, CONTROL_VTEP *v, bool address)
{
	Zero(v, sizeof(CONTROL_VTEP));
	if (address)
	{
		v->AddressSize = HtTestAddress(v->Address, "127.0.0.1");
	}
	v->VxlanPort = ctx->Nodes[i].VxlanPort;
	v->GenevePort = ctx->Nodes[i].GenevePort;
}

// Apply the next Generation of node i: its addresses, its tag and its tunnel endpoint; VRF red with the link of kind in the tag
// mode hmac and the num keys of keys in its Vrf object, whose policy node-b enforces with the rule admin-in and node-a not at
// all; the other node as its peer with its group and the frame version 1; and the Device phone, admin, whose gateway node-a
// is. Node-a's own group is own_group, with the tag set own_tags, which it stamps on the packets of its own address; node-b's
// is server.
static bool HtTestApply(HTTEST_CTX *ctx, UINT i, UINT kind, UINT own_group, UINT64 own_tags, const HTTEST_KEY *keys, UINT num)
{
	CONTROL_STATE *st = ZeroMalloc(sizeof(CONTROL_STATE));
	CONTROL_RULE *rule = ZeroMalloc(sizeof(CONTROL_RULE));
	CONTROL_PEER *p = ZeroMalloc(sizeof(CONTROL_PEER));
	CONTROL_DEVICE *phone = ZeroMalloc(sizeof(CONTROL_DEVICE));
	HTTEST_NODE *t = &ctx->Nodes[i];
	bool b = (i == HTTEST_B);
	UINT j = 1 - i;

	st->Generation = ++t->Generation;
	StrCpy(st->Name, sizeof(st->Name), httest_names[i]);
	st->NumAddresses = HtTestAddresses(i, st->Addresses);
	st->NumTags = 1;
	StrCpy(st->Tags[0], sizeof(st->Tags[0]), httest_tags[i]);
	HtTestVtep(ctx, i, &st->Vtep, false);

	st->NumVrfs = 1;
	StrCpy(st->Vrfs[0].Name, sizeof(st->Vrfs[0].Name), "red");
	st->Vrfs[0].Id = HTTEST_VRF;
	st->Vrfs[0].Policy = b;
	st->Vrfs[0].Link = kind;
	st->Vrfs[0].Vni = HTTEST_VNI;
	st->Vrfs[0].TagMode = CONTROL_TAG_MODE_HMAC;
	st->Vrfs[0].NumTagKeys = MIN(num, CONTROL_TAG_KEYS);
	for (UINT k = 0;k < st->Vrfs[0].NumTagKeys;k++)
	{
		st->Vrfs[0].TagKeys[k].Id = keys[k].Id;
		st->Vrfs[0].TagKeys[k].Send = keys[k].Send;
		HtTestKey(st->Vrfs[0].TagKeys[k].Key, keys[k].First);
	}

	// The rule of red that node-b enforces: from the tag admin to the tag server, any protocol
	if (b)
	{
		StrCpy(rule->Name, sizeof(rule->Name), "admin-in");
		rule->VrfId = HTTEST_VRF;
		rule->Priority = 100;
		rule->From.NumTags = 1;
		StrCpy(rule->From.Tags[0], sizeof(rule->From.Tags[0]), "admin");
		rule->To.NumTags = 1;
		StrCpy(rule->To.Tags[0], sizeof(rule->To.Tags[0]), "server");
		st->NumRules = 1;
		st->Rules = rule;
	}

	// Its own source group in red
	st->NumGroups = 1;
	st->Groups[0].VrfId = HTTEST_VRF;
	st->Groups[0].Group = (b ? HTTEST_SERVER : own_group);
	st->Groups[0].TagSet = (b ? HTTEST_SERVER_TAGS : own_tags);
	st->Groups[0].Generation = HTTEST_SINCE;

	// The other node, its peer, with the group that the controller gives it from its tag
	StrCpy(p->Name, sizeof(p->Name), httest_names[j]);
	Copy(p->Key, ctx->Nodes[j].Key.Public, PEER_KEY_SIZE);
	p->NumVrfs = 1;
	p->VrfIds[0] = HTTEST_VRF;
	p->NumAddresses = HtTestAddresses(j, p->Addresses);
	p->NumTags = 1;
	StrCpy(p->Tags[0], sizeof(p->Tags[0]), httest_tags[j]);
	HtTestVtep(ctx, j, &p->Vtep, true);
	p->NumGroups = 1;
	p->Groups[0].VrfId = HTTEST_VRF;
	p->Groups[0].Group = (b ? HTTEST_GUEST : HTTEST_SERVER);
	p->Groups[0].TagSet = (b ? HTTEST_GUEST_TAGS : HTTEST_SERVER_TAGS);
	p->Groups[0].Generation = HTTEST_SINCE;
	p->FrameVersion = NODE_FRAME_VERSION;
	st->NumPeers = 1;
	st->Peers = p;

	// The Device phone, admin, whose gateway node-a is: in the state of node-a with the WireGuard key that makes it terminate it
	StrCpy(phone->Name, sizeof(phone->Name), "phone");
	phone->VrfId = HTTEST_VRF;
	phone->NumAddresses = 1;
	StrCpy(phone->Addresses[0].Network, sizeof(phone->Addresses[0].Network), "red");
	phone->Addresses[0].VrfId = HTTEST_VRF;
	phone->Addresses[0].AddressSize = HtTestAddress(phone->Addresses[0].Address, HTTEST_PHONE);
	phone->Addresses[0].Length = 32;
	phone->NumTags = 1;
	StrCpy(phone->Tags[0], sizeof(phone->Tags[0]), "admin");
	StrCpy(phone->Gateway, sizeof(phone->Gateway), httest_names[HTTEST_A]);
	phone->Group = HTTEST_ADMIN;
	phone->TagSet = HTTEST_ADMIN_TAGS;
	if (b == false)
	{
		phone->HasKey = true;
		for (UINT k = 0;k < NOISE_KEY_SIZE;k++)
		{
			phone->Key[k] = (UCHAR)(0x11 + k);
		}
	}
	st->NumDevices = 1;
	st->Devices = phone;

	bool ok = NodeOverlayApply(t->Node, st);

	Zero(st, sizeof(CONTROL_STATE));
	Free(phone);
	Free(p);
	Free(rule);
	Free(st);

	return ok;
}

// Whether each node runs the Generation that the test applied last with its session to the other up, within HTTEST_BOUND
static bool HtTestWaitLinks(HTTEST_CTX *ctx)
{
	UINT64 end = Tick64() + HTTEST_BOUND;

	while (true)
	{
		NODE_OVERLAY_STATUS a, b;

		NodeOverlayGetStatus(ctx->Nodes[HTTEST_A].Node, &a);
		NodeOverlayGetStatus(ctx->Nodes[HTTEST_B].Node, &b);
		if (a.NumLinks == 1 && b.NumLinks == 1 && a.Generation == ctx->Nodes[HTTEST_A].Generation && b.Generation == ctx->Nodes[HTTEST_B].Generation)
		{
			return true;
		}
		if (Tick64() >= end)
		{
			return false;
		}
		SleepThread(HTTEST_POLL);
	}
}

// Whether the host of node t took at least target packets within timeout
static bool HtTestArrived(HTTEST_NODE *t, LONG target, UINT timeout)
{
	UINT64 end = Tick64() + timeout;

	while (InterlockedCompareExchange(&t->Arrivals, 0, 0) < target)
	{
		if (Tick64() >= end)
		{
			return false;
		}
		SleepThread(HTTEST_POLL);
	}

	return true;
}

// The counter of the status st that counts the packets of the tag mode hmac as result (HTTEST_*)
static UINT64 HtTestCount(const NODE_SOURCE_GROUP_STATUS *st, UINT result)
{
	const CONTROL_GROUP_COUNTERS *c = &st->Modes[CONTROL_TAG_MODE_HMAC];

	switch (result)
	{
	case HTTEST_CARRIED:
		return c->Carried;
	case HTTEST_MISSING:
		return c->Missing;
	case HTTEST_UNAUTHENTICATED:
		return c->Unauthenticated;
	}

	return 0;
}

// All the packets that the status st counts, in every tag mode
static UINT64 HtTestTotal(const NODE_SOURCE_GROUP_STATUS *st)
{
	UINT64 sum = 0;

	for (UINT mode = 0;mode < CONTROL_TAG_MODES;mode++)
	{
		const CONTROL_GROUP_COUNTERS *c = &st->Modes[mode];

		sum += c->Carried + c->Missing + c->Ignored + c->Refused + c->Unauthenticated;
	}

	return sum;
}

// Send one packet of the host of node from, from the address src and the UDP port sport to the address dst and the UDP port
// dport, through its overlay, or have the injector send the case c; then whether the node to counted it once, as result, in the
// tag mode hmac, and whether its host took it as it was sent, as arrives says. what names the check.
static void HtTestSend(HTTEST_CTX *ctx, UINT from, UINT to, char *src, char *dst, UINT sport, UINT dport, UINT kind, const HTTEST_CASE *c,
	UINT result, bool arrives, char *what)
{
	HTTEST_NODE *f = &ctx->Nodes[from];
	HTTEST_NODE *d = &ctx->Nodes[to];
	NODE_SOURCE_GROUP_STATUS before, after;
	UCHAR packet[HTTEST_SIZE];
	bool sent, counted = false, same = false;

	HtTestPacket(packet, src, dst, sport, dport);
	NodeSourceGroupGetStatus(d->Node, &before);
	LONG arrivals = InterlockedCompareExchange(&d->Arrivals, 0, 0);

	if (c != NULL && c->Inject)
	{
		sent = HtTestInject(ctx, kind, c, packet);
	}
	else
	{
		NodeReaderOnline(f->Node, &f->Reader);
		sent = NodeOverlayInput(f->Node, HTTEST_VRF, packet, HTTEST_SIZE);
		NodeReaderOffline(&f->Reader);
	}

	// The node judged the packet once it counted it
	UINT64 end = Tick64() + HTTEST_BOUND;
	while (sent && counted == false)
	{
		NodeSourceGroupGetStatus(d->Node, &after);
		counted = (HtTestCount(&after, result) > HtTestCount(&before, result));
		if (counted == false)
		{
			if (Tick64() >= end)
			{
				break;
			}
			SleepThread(HTTEST_POLL);
		}
	}

	bool arrived = sent && HtTestArrived(d, arrivals + 1, arrives ? HTTEST_BOUND : HTTEST_QUIET);
	NodeSourceGroupGetStatus(d->Node, &after);

	AcquireSRWLockShared(&d->Lock);
	{
		same = (arrived && d->LastSize == HTTEST_SIZE && Cmp(d->Last, packet, HTTEST_SIZE) == 0);
	}
	ReleaseSRWLockShared(&d->Lock);

	// The packet of the case is the one packet that the node counted
	UINT64 counts = HtTestTotal(&after) - HtTestTotal(&before);

	HtTestCheck(ctx, sent && counted && counts == 1 && arrived == arrives && (arrives == false || same), what,
		"sent %u, counted as %s in the tag mode hmac %u, %I64u counted in all, arrived %u, as it was sent %u", (UINT)sent, httest_results[result],
		(UINT)counted, counts, (UINT)arrived, (UINT)same);
}

// One case over the link of kind, to node-b's host, from a source port of its own
static void HtTestCase(HTTEST_CTX *ctx, UINT kind, const HTTEST_CASE *c)
{
	char what[MAX_SIZE * 2];

	Format(what, sizeof(what), "  %s", c->What);
	HtTestSend(ctx, HTTEST_A, HTTEST_B, c->Src, httest_addrs[HTTEST_B][0], ctx->NextPort++, HTTEST_PORT, kind, c, c->Result, c->Arrives, what);
}

// One Generation of each node, node-b first, with the link of kind, node-a's own group own_group with the tag set own_tags and
// the keys of each: each runs it and the session stays up
static bool HtTestSwitch(HTTEST_CTX *ctx, UINT kind, UINT own_group, UINT64 own_tags, const HTTEST_KEY *keys_a, UINT num_a,
	const HTTEST_KEY *keys_b, UINT num_b, char *what)
{
	bool applied = HtTestApply(ctx, HTTEST_B, kind, own_group, own_tags, keys_b, num_b) &&
		HtTestApply(ctx, HTTEST_A, kind, own_group, own_tags, keys_a, num_a);
	bool linked = applied && HtTestWaitLinks(ctx);

	return HtTestCheck(ctx, linked, what, "applied %u, the Generations %I64u and %I64u", (UINT)applied, ctx->Nodes[HTTEST_A].Generation,
		ctx->Nodes[HTTEST_B].Generation);
}

// One Generation of node i alone, with the keys
static bool HtTestStep(HTTEST_CTX *ctx, UINT i, const HTTEST_KEY *keys, UINT num, char *what)
{
	bool applied = HtTestApply(ctx, i, CONTROL_LINK_GENEVE, HTTEST_ADMIN, HTTEST_ADMIN_TAGS, keys, num) && HtTestWaitLinks(ctx);

	return HtTestCheck(ctx, applied, what, "the Generations %I64u and %I64u", ctx->Nodes[HTTEST_A].Generation, ctx->Nodes[HTTEST_B].Generation);
}

// One packet of the open flow each way: from the phone at 10.0.0.50, on whose packets node-a stamps admin, to node-b's host,
// which admin-in allows, and node-b's answer, which node-b's policy lets through as the answer of that flow, to node-a's host
// for the phone; each node counts the packet of the other as carried with a valid MAC, and its host takes it
static void HtTestFlow(HTTEST_CTX *ctx, char *step)
{
	char what[MAX_SIZE * 2];

	Format(what, sizeof(what), "  %s: a packet of the open flow from the phone behind node-a, admin with a valid MAC, arrives at node-b's host", step);
	HtTestSend(ctx, HTTEST_A, HTTEST_B, HTTEST_PHONE, httest_addrs[HTTEST_B][0], HTTEST_FLOW_PORT, HTTEST_PORT, CONTROL_LINK_GENEVE, NULL,
		HTTEST_CARRIED, true, what);
	Format(what, sizeof(what), "  %s: node-b's answer, server with a valid MAC, arrives at node-a's host for the phone", step);
	HtTestSend(ctx, HTTEST_B, HTTEST_A, httest_addrs[HTTEST_B][0], HTTEST_PHONE, HTTEST_PORT, HTTEST_FLOW_PORT, CONTROL_LINK_GENEVE, NULL,
		HTTEST_CARRIED, true, what);
}

// The rotation of the key of red while a flow is open, in the order of the controller, then the order that it never allows
static void HtTestRotation(HTTEST_CTX *ctx)
{
	static const HTTEST_KEY k1[] = {{1, 0x10, true}};
	static const HTTEST_KEY k1_k2[] = {{1, 0x10, true}, {2, 0x20, false}};
	static const HTTEST_KEY k2_used[] = {{1, 0x10, false}, {2, 0x20, true}};
	static const HTTEST_KEY k2_k3[] = {{2, 0x20, true}, {3, 0x30, false}};
	static const HTTEST_KEY k3_alone[] = {{3, 0x30, true}};

	Print("[the key of red rotates while a flow between the phone behind node-a and node-b's host is open]\n");
	if (HtTestSwitch(ctx, CONTROL_LINK_GENEVE, HTTEST_ADMIN, HTTEST_ADMIN_TAGS, k1, 1, k1, 1, "both nodes send with key 1, node-a stamps admin") == false)
	{
		return;
	}
	HtTestFlow(ctx, "key 1 at both");

	if (HtTestStep(ctx, HTTEST_B, k1_k2, 2, "the new key 2 at node-b, beside key 1, which it sends with"))
	{
		HtTestFlow(ctx, "key 2 at node-b only");
	}
	if (HtTestStep(ctx, HTTEST_A, k1_k2, 2, "key 2 at node-a too, which still sends with key 1"))
	{
		HtTestFlow(ctx, "key 2 at both, both send with key 1");
	}
	if (HtTestStep(ctx, HTTEST_A, k2_used, 2, "both acknowledged key 2: node-a sends with it first"))
	{
		HtTestFlow(ctx, "node-a sends with key 2, node-b with key 1");
	}
	if (HtTestStep(ctx, HTTEST_B, k2_used, 2, "node-b sends with key 2 too"))
	{
		HtTestFlow(ctx, "both send with key 2");
	}
	if (HtTestStep(ctx, HTTEST_A, k2_k3, 2, "the next rotation: key 3 at node-a beside key 2, and key 1 gone"))
	{
		HtTestFlow(ctx, "key 3 at node-a only");
	}
	if (HtTestStep(ctx, HTTEST_B, k2_k3, 2, "key 3 at node-b too, both send with key 2"))
	{
		HtTestFlow(ctx, "key 3 at both");
	}

	// The order that the controller never allows, on a packet of node-a's own address, whose group admin the map of node-b does
	// not give it: node-b holds key 1 alone while node-a sends with key 2, then node-a sends with key 3 alone
	if (HtTestStep(ctx, HTTEST_B, k1, 1, "the order that the controller never allows: node-b holds key 1 alone, while node-a sends with key 2"))
	{
		HtTestSend(ctx, HTTEST_A, HTTEST_B, httest_addrs[HTTEST_A][0], httest_addrs[HTTEST_B][0], ctx->NextPort++, HTTEST_PORT, CONTROL_LINK_GENEVE, NULL,
			HTTEST_UNAUTHENTICATED, false,
			"  a packet of node-a under key 2, which node-b does not hold, is unauthenticated, and the map judges 10.0.0.1 as guest: dropped");
	}
	if (HtTestStep(ctx, HTTEST_A, k3_alone, 1, "... and node-a sends with key 3 alone"))
	{
		HtTestSend(ctx, HTTEST_A, HTTEST_B, httest_addrs[HTTEST_A][0], httest_addrs[HTTEST_B][0], ctx->NextPort++, HTTEST_PORT, CONTROL_LINK_GENEVE, NULL,
			HTTEST_UNAUTHENTICATED, false, "  a packet of node-a under key 3, which node-b does not hold either, is unauthenticated: dropped");
	}
}

// The nodes, their overlays and the injector, and the first Generation of each: geneve in the tag mode hmac with key 1
static bool HtTestOpen(HTTEST_CTX *ctx, TRANSPORT *loopback)
{
	static const HTTEST_KEY k1[] = {{1, 0x10, true}};
	UCHAR scalar[PEER_KEY_SIZE];
	char what[MAX_SIZE];
	bool ok = (loopback != NULL);
	USHORT ports[4];

	Print("[the nodes, their overlays and the injector]\n");

	ok = HtTestCheck(ctx, ok && HtTestFreePorts(ports, 4), "Four free UDP ports for the tunnel endpoints of the nodes", "error %u", (UINT)WSAGetLastError()) && ok;

	ctx->Vtep = HtTestOpenVtep();
	ok = HtTestCheck(ctx, ok && ctx->Vtep != INVALID_SOCKET, "The injector, a harness tunnel endpoint on 127.0.0.1, the address of the tunnel endpoint of node-a",
		"error %u", (UINT)WSAGetLastError()) && ok;

	for (UINT i = 0;i < HTTEST_NUM_NODES && ok;i++)
	{
		HTTEST_NODE *t = &ctx->Nodes[i];
		NODE_OVERLAY_CONFIG c;

		InitializeSRWLock(&t->Lock);
		t->VxlanPort = ports[2 * i];
		t->GenevePort = ports[2 * i + 1];
		for (UINT j = 0;j < PEER_KEY_SIZE;j++)
		{
			scalar[j] = (UCHAR)(0x71 + PEER_KEY_SIZE * i + j);
		}
		ok = PeerKeyFromScalar(&t->Key, scalar);

		HtTestNewDir(t->Dir, sizeof(t->Dir), httest_names[i]);
		t->Node = NewNode(t->Dir);
		NodeStart(t->Node);
		NodeReaderRegister(t->Node, &t->Reader);
		NodeReaderOffline(&t->Reader);

		Zero(&c, sizeof(c));
		c.Data = loopback;
		c.Key = &t->Key;
		c.Adapter = HtTestAdapter;
		c.AdapterParam = t;
		Format(what, sizeof(what), "  %s: its overlay runs without a control stream, its tunnel endpoint on the UDP ports %u (VXLAN) and %u (Geneve)", httest_names[i],
			(UINT)t->VxlanPort, (UINT)t->GenevePort);
		ok = HtTestCheck(ctx, ok && NodeOverlayStart(t->Node, &c), what, "PeerKeyFromScalar or NodeOverlayStart failed") && ok;
	}
	Zero(scalar, sizeof(scalar));

	return ok && HtTestSwitch(ctx, CONTROL_LINK_GENEVE, HTTEST_GUEST, HTTEST_GUEST_TAGS, k1, 1, k1, 1,
		"The link of red is geneve in the tag mode hmac, with key 1: one Generation of each node, node-b first, and the session stays up");
}

// The nodes first, whose overlays stop with every thread joined, then the injector. Before the files of a node go, the test looks
// for the keys of red in them.
static void HtTestClose(HTTEST_CTX *ctx)
{
	Print("[the keys of red are in no file that a node wrote]\n");
	for (UINT i = 0;i < HTTEST_NUM_NODES;i++)
	{
		HTTEST_NODE *t = &ctx->Nodes[i];
		wchar_t log_dir[MAX_PATH];

		if (t->Node != NULL)
		{
			NodeReaderUnregister(t->Node, &t->Reader);
			NodeStop(t->Node);
			FreeNode(t->Node);

			ConbinePathW(log_dir, sizeof(log_dir), t->Dir, NODE_LOG_DIR_NAME);
			HtTestKeysFoundNowhere(ctx, i, log_dir);
			HtTestDeleteFiles(log_dir);
			HtTestDeleteFiles(t->Dir);
		}
		PeerKeyClose(&t->Key);
	}

	if (ctx->Vtep != INVALID_SOCKET)
	{
		closesocket(ctx->Vtep);
	}
}

// The cases over geneve, then over vxlan, then the rotation of the key
static void HtTestRun(HTTEST_CTX *ctx)
{
	static const HTTEST_KEY k1[] = {{1, 0x10, true}};

	Print("[the link of red is geneve in the tag mode hmac: a valid MAC is honoured, and any other claim is dropped as if the option were missing]\n");
	for (UINT i = 0;i < sizeof(httest_geneve) / sizeof(httest_geneve[0]);i++)
	{
		HtTestCase(ctx, CONTROL_LINK_GENEVE, &httest_geneve[i]);
	}

	Print("[the link of red is vxlan in the tag mode hmac, which has no room for the MAC]\n");
	if (HtTestSwitch(ctx, CONTROL_LINK_VXLAN, HTTEST_GUEST, HTTEST_GUEST_TAGS, k1, 1, k1, 1, "The link of red is vxlan in the tag mode hmac, with key 1"))
	{
		for (UINT i = 0;i < sizeof(httest_vxlan) / sizeof(httest_vxlan[0]);i++)
		{
			HtTestCase(ctx, CONTROL_LINK_VXLAN, &httest_vxlan[i]);
		}
	}

	HtTestRotation(ctx);
}

// hmactags: the tag mode hmac between two nodes
RANZ_TEST_TAGS("hmactags", hmactags_test, "core", "Tag mode hmac (SDN-88): between two nodes over geneve, a source group with a valid MAC is honoured, and a forged tag, a wrong key, a changed inner header, a timestamp outside the window and an option without a MAC are dropped as if the option were missing, sent by an injector on the underlay; over vxlan no source group is taken; the key of the VRF rotates while a flow is open without losing a packet of it, in the order that the controller allows.");
void hmactags_test(UINT num, char **arg)
{
	HTTEST_CTX *ctx = ZeroMalloc(sizeof(HTTEST_CTX));
	HANDLE done = CreateEventW(NULL, TRUE, FALSE, NULL);
	HANDLE watchdog = (done != NULL ? CreateThread(NULL, 0, HtTestWatchdog, done, 0, NULL) : NULL);
	TRANSPORT *loopback = TransportLoopbackNew("loopback", 0, false);

	Print("Tag mode hmac test: a node takes the source group of a link of kind geneve only with a valid MAC under a key of the VRF\n");

	ctx->Vtep = INVALID_SOCKET;
	ctx->NextPort = HTTEST_FIRST_PORT;

	if (HtTestOpen(ctx, loopback))
	{
		HtTestRun(ctx);
	}

	HtTestClose(ctx);
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
		Print("HMACTAGS TEST OK\n");
	}
	else
	{
		Print("HMACTAGS TEST FAILED (%u of %u checks failed)\n", ctx->NumFailed, ctx->NumChecks);
	}

	Free(ctx);
}
