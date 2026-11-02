// l2bridgetest.c
// Named L2 bridge test of vpntest ("l2bridge" command, CORE-S3-3 #73)
//
// The bridge of the L2 adapter of the node (Cedar/NodeL2Bridge.c, Cedar/NodeL2Npcap.c) on backends of the test and on
// what this runner holds, with no driver, so that it runs on every runner; the nicbridge test (nicbridgetest.c) runs a
// bridge on the runner's NIC, on a KM-TEST adapter standing in for a Hyper-V switch and on a Hyper-V switch of the runner,
// with SeLow, XDP and Npcap.
// - Where a frame of the segment goes (NodeL2BridgeWay): a frame to the MAC address of the NIC to the host only; a
//   broadcast, an IPv4 and an IPv6 multicast frame to the host and to the others; a frame to another unicast address
//   to the others only.
// - The backends of a bridge whose owner names none: SeLow first, the bundled default, then Npcap.
// - Npcap is used only where it is installed: on a runner without it NodeL2NpcapPresent says that it is not installed,
//   a bridge whose backends are Npcap and one of the test binds the latter, and the hold of promiscuous mode for the XDP
//   backend refuses.
// - A bridge is never reset: a backend of the test that reports itself broken and attaches no more is reattached by the
//   health check again and again, and the reset of the owner never runs.
// - An L2 bridge (NodeL2BridgeNew) is the member of a port of the switch of an L2 Network: a frame of the segment reaches
//   a member of the Network, and the switch learns the segment's address on the port of the bridge; the Network's frames
//   to that address, its broadcast frames and its multicast frames, which no member asked for, reach the segment; a frame
//   of the segment to another address of the segment goes nowhere; and the bridge leaves the switch when it goes, which
//   forgets the segment's addresses. As a trunk port, the frames of a VLAN of its allowed list leave the bridge with the
//   tag of that VLAN, and a frame of the segment with such a tag reaches the members of that VLAN only.
// - The Npcap backend on a stand-in of Npcap's pcap API with no driver (NodeL2NpcapStandIn): the handle that it opens with
//   the three flags of a bridge on the device of the NIC, the frames of the segment that it hands the owner, a frame cut
//   short, the frames that it sends, a read that fails and the reattach after it, the hold of promiscuous mode for the XDP
//   backend with a filter that takes no frame, and every handle closed again.
// - The interface of a bridge: NodeL2BridgeIndex finds the runner's NIC (the interface of its route to 8.8.8.8), which no
//   external Hyper-V virtual switch owns, by its alias and by its GUID, and refuses a name that no interface has and the
//   loopback interface, which is no Ethernet;
//   NodeL2HyperVIndex refuses a virtual switch that the host does not have, and says how to give the host a vNIC of one.
// - arm64 is L3 only: no bridge either, whatever the backend.
// Prints "L2BRIDGE TEST OK" only when every check passes.

#include "testlist.h"

#include "Cedar/ConfigStore.h"
#include "Cedar/Node.h"
#include "Cedar/NodeL2.h"

#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Kernel.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Str.h"

#include "Core/Switch.h"

#include <iphlpapi.h>

#include <stdio.h>

#define	L2BRIDGE_BUDGET			120000		// The whole test ends within this time, or the watchdog ends the process (ms)
#define	L2BRIDGE_BOUND			15000		// A bounded wait on observable state (ms)
#define	L2BRIDGE_POLL			10			// Poll interval of observable state (ms)
#define	L2BRIDGE_SLOTS			256			// Frames of each ring of the adapters of the test
#define	L2BRIDGE_SWITCH			"ranz-l2bridge-no-such-switch"	// A Hyper-V virtual switch that no host has
#define	L2BRIDGE_FRAME			60			// Bytes of the frames of the test
#define	L2BRIDGE_ETHERTYPE		0x88B5		// Their EtherType: the local experimental one of IEEE 802
#define	L2BRIDGE_VLAN			10			// The VLAN of the members of the switch
#define	L2BRIDGE_VLAN2			20			// The VLAN of the member of the trunk test
#define	L2BRIDGE_VLAN3			30			// A VLAN that no port of the trunk test carries
#define	L2BRIDGE_PCAP_QUEUE		16			// Frames that a handle of the stand-in of the pcap API holds at most
#define	L2BRIDGE_PCAP_FRAME		64			// Bytes of such a frame at most
#define	L2BRIDGE_PCAP_ERRBUF	256			// Bytes of the error text of a pcap call (PCAP_ERRBUF_SIZE)

// The checks of the test
typedef struct L2BRIDGE_CTX
{
	UINT NumChecks;
	UINT NumFailed;
} L2BRIDGE_CTX;

// The backend of the test: binds unless it is told to fail, reports itself broken while it is told to, and counts what
// the bridge hands it for the segment
typedef struct L2BRIDGE_FAKE
{
	volatile LONG FailAttaches;		// Attaches fail while this is set
	volatile LONG Broken;			// The backend reports its binding broken while this is set
	volatile LONG Attaches;			// Attaches that succeeded
	volatile LONG Detaches;			// Detaches
	volatile LONG Resets;			// Times that the reset of the owner ran
	NODE_L2 *volatile Adapter;		// The adapter that it is attached to, whose segment the test plays
	volatile LONG Injected;			// Frames that it took for the segment
	volatile LONG ToLan;			// ... of these, to the address of the segment
	volatile LONG Broadcasts;		// ... to the broadcast address
	volatile LONG Multicasts;		// ... to another group address
	volatile LONG Tagged;			// ... with a tag of TPID 0x8100
	volatile LONG LastVlan;			// The VLAN id of the last tagged one
} L2BRIDGE_FAKE;

// A member of the L2 Network that the test plays: counts what the switch hands it
typedef struct L2BRIDGE_MEMBER
{
	volatile LONG Frames;			// Frames that the switch handed it
	volatile LONG FromLan;			// ... of these, from the address of the segment
	volatile LONG Tagged;			// ... with a tag
} L2BRIDGE_MEMBER;

// A handle of the stand-in of Npcap's pcap API in this test, with no driver: the frames of the segment that the test
// gives it, which pcap_next_ex hands over in place, and the frames that pcap_sendpacket took
typedef struct L2BRIDGE_PCAP
{
	int Flags;						// The flags of pcap_open
	int Snaplen;					// ... and its snapshot length
	HANDLE Event;					// Set while frames wait (manual reset)
	SRWLOCK Lock;					// The queue
	UCHAR Queue[L2BRIDGE_PCAP_QUEUE][L2BRIDGE_PCAP_FRAME];
	UINT Sizes[L2BRIDGE_PCAP_QUEUE];
	bool Cut[L2BRIDGE_PCAP_QUEUE];	// The handle cut the frame short
	UINT Head;
	UINT Num;
	UCHAR Current[L2BRIDGE_PCAP_FRAME];	// The frame that pcap_next_ex handed over last
	NODE_L2_PCAP_HEADER Header;
	bool Reject;					// A filter that takes no frame is set
} L2BRIDGE_PCAP;

// The stand-in's own: the capture handle of the backend and the hold, the handles opened and closed, and the reads that fail
typedef struct L2BRIDGE_PCAPS
{
	SRWLOCK Lock;					// The two handles and the counts
	L2BRIDGE_PCAP *Capture;			// The handle opened without the capture of its own frames, the backend's
	L2BRIDGE_PCAP *Hold;			// The handle opened promiscuous only, the hold for the XDP backend
	char Source[MAX_SIZE];			// The device that the backend's handle was opened on last
	int CaptureFlags;				// ... with these flags
	int HoldFlags;					// The flags of the hold
	bool HoldRejected;				// The hold took no frame when it was closed
	UINT Opens;
	UINT Closes;
	volatile LONG Sent;				// Frames that pcap_sendpacket took
	volatile LONG FailReads;		// Reads fail while this is set
} L2BRIDGE_PCAPS;

static L2BRIDGE_FAKE l2bridge_fake;
static L2BRIDGE_PCAPS l2bridge_pcaps;

// The addresses of the test: of the segment, of another device on it, and of a member of the Network
static UCHAR l2bridge_lan_mac[6] = {0x02, 0x00, 0x5E, 0x10, 0x73, 0x0A};
static UCHAR l2bridge_lan2_mac[6] = {0x02, 0x00, 0x5E, 0x10, 0x73, 0x0C};
static UCHAR l2bridge_member_mac[6] = {0x02, 0x00, 0x5E, 0x10, 0x73, 0x0B};
static UCHAR l2bridge_broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
static UCHAR l2bridge_group[6] = {0x01, 0x00, 0x5E, 0x00, 0x00, 0xFB};

static bool L2BridgeCheck(L2BRIDGE_CTX *ctx, bool ok, char *what, char *fmt, ...) RANZ_PRINTF_FORMAT(4, 5);
static bool L2BridgeCheck(L2BRIDGE_CTX *ctx, bool ok, char *what, char *fmt, ...)
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

// The watchdog: a native thread that ends a run that hangs, so that a stuck thread is a failed test instead of a hung CI step
static DWORD WINAPI L2BridgeWatchdog(LPVOID param)
{
	char msg[MAX_SIZE];
	DWORD written = 0;

	if (WaitForSingleObject((HANDLE)param, L2BRIDGE_BUDGET) != WAIT_TIMEOUT)
	{
		return 0;
	}

	int len = snprintf(msg, sizeof(msg), "L2BRIDGE TEST FAILED (did not finish within %u ms)\n", L2BRIDGE_BUDGET);
	if (len > 0)
	{
		WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), msg, (DWORD)MIN((UINT)len, (UINT)sizeof(msg) - 1), &written, NULL);
	}

	TerminateProcess(GetCurrentProcess(), 1);

	return 0;
}

// Wait up to L2BRIDGE_BOUND ms until *value reaches at least want; false when it does not
static bool L2BridgeWait(volatile LONG *value, LONG want)
{
	UINT64 end = GetTickCount64() + L2BRIDGE_BOUND;

	while (ReadAcquire(value) < want)
	{
		if (GetTickCount64() >= end)
		{
			return false;
		}
		Sleep(L2BRIDGE_POLL);
	}

	return true;
}

// A frame of L2BRIDGE_FRAME bytes into f from src to dst, of the local experimental EtherType; with vlan other than 0, with
// a tag of TPID 0x8100 of that VLAN in front of it. Its size.
static UINT L2BridgeFrame(UCHAR *f, const UCHAR *dst, const UCHAR *src, UINT vlan)
{
	UINT at = 12;

	Zero(f, L2BRIDGE_FRAME);
	Copy(f, dst, 6);
	Copy(f + 6, src, 6);
	if (vlan != 0)
	{
		f[12] = 0x81;
		f[13] = 0x00;
		f[14] = (UCHAR)((vlan >> 8) & 0x0F);
		f[15] = (UCHAR)vlan;
		at = 16;
	}
	f[at] = (UCHAR)(L2BRIDGE_ETHERTYPE >> 8);
	f[at + 1] = (UCHAR)L2BRIDGE_ETHERTYPE;

	return L2BRIDGE_FRAME;
}

static bool L2BridgeFakeAttach(NODE_L2 *a, char *error, UINT error_size)
{
	if (ReadAcquire(&l2bridge_fake.FailAttaches) != 0)
	{
		StrCpy(error, error_size, "the backend of the test refuses this attach on purpose");
		return false;
	}

	InterlockedIncrement(&l2bridge_fake.Attaches);
	a->BackendState = &l2bridge_fake;
	l2bridge_fake.Adapter = a;

	return true;
}

// Takes the frames for the segment, on the injector thread, and counts them by their destination and their tag
static UINT L2BridgeFakeInject(NODE_L2 *a, const UCHAR **frames, const UINT *sizes, UINT num)
{
	for (UINT i = 0;i < num;i++)
	{
		const UCHAR *f = frames[i];

		InterlockedIncrement(&l2bridge_fake.Injected);
		if (sizes[i] < 16)
		{
			continue;
		}

		if (Cmp(f, l2bridge_lan_mac, 6) == 0)
		{
			InterlockedIncrement(&l2bridge_fake.ToLan);
		}
		else if (Cmp(f, l2bridge_broadcast, 6) == 0)
		{
			InterlockedIncrement(&l2bridge_fake.Broadcasts);
		}
		else if ((f[0] & 0x01) != 0)
		{
			InterlockedIncrement(&l2bridge_fake.Multicasts);
		}

		if (f[12] == 0x81 && f[13] == 0x00)
		{
			InterlockedExchange(&l2bridge_fake.LastVlan, (LONG)(((UINT)(f[14] & 0x0F) << 8) | f[15]));
			InterlockedIncrement(&l2bridge_fake.Tagged);
		}
	}

	return num;
}

static bool L2BridgeFakeHealthy(NODE_L2 *a)
{
	return (ReadAcquire(&l2bridge_fake.Broken) == 0);
}

static bool L2BridgeFakeDetach(NODE_L2 *a, UINT timeout)
{
	if (a->BackendState != NULL)
	{
		a->BackendState = NULL;
		l2bridge_fake.Adapter = NULL;
		InterlockedIncrement(&l2bridge_fake.Detaches);
	}

	return true;
}

static const NODE_L2_BACKEND l2bridge_fake_backend = {"fake", L2BridgeFakeAttach, L2BridgeFakeInject, L2BridgeFakeHealthy, L2BridgeFakeDetach};

// The reset of the owner: counts; a bridge must never call it
static bool L2BridgeReset(void *param, UINT *if_index)
{
	InterlockedIncrement(&l2bridge_fake.Resets);
	return true;
}

// The owner: takes the frames and does nothing with them
static void L2BridgeOwnerProc(NODE_L2 *a, void *param, const UCHAR *frame, UINT size)
{
}

// The port of a member of the Network that the test plays: counts what the switch hands it
static void L2BridgeMemberSend(void *param, UINT port, const UCHAR *frame, UINT size)
{
	L2BRIDGE_MEMBER *m = (L2BRIDGE_MEMBER *)param;

	InterlockedIncrement(&m->Frames);
	if (size >= 12 && Cmp(frame + 6, l2bridge_lan_mac, 6) == 0)
	{
		InterlockedIncrement(&m->FromLan);
	}
	if (size >= 14 && frame[12] == 0x81 && frame[13] == 0x00)
	{
		InterlockedIncrement(&m->Tagged);
	}
}

// A frame of the segment, which the test plays, to the adapter of the backend of the test: into its capture ring, as its
// drain thread would put it there
static void L2BridgeFromLan(const UCHAR *frame, UINT size)
{
	NODE_L2 *a = l2bridge_fake.Adapter;

	if (a != NULL)
	{
		NodeL2Capture(a, frame, size);
		NodeL2CaptureDone(a);
	}
}

//
// The stand-in of Npcap's pcap API (NodeL2NpcapStandIn)
//

static void *L2BridgePcapOpen(const char *source, int snaplen, int flags, int read_timeout, void *auth, char *errbuf)
{
	L2BRIDGE_PCAP *p = ZeroMalloc(sizeof(L2BRIDGE_PCAP));

	p->Flags = flags;
	p->Snaplen = snaplen;
	InitializeSRWLock(&p->Lock);
	p->Event = CreateEventW(NULL, TRUE, FALSE, NULL);
	if (p->Event == NULL)
	{
		StrCpy(errbuf, L2BRIDGE_PCAP_ERRBUF, "the stand-in of the test has no event");
		Free(p);
		return NULL;
	}

	AcquireSRWLockExclusive(&l2bridge_pcaps.Lock);
	if ((flags & NODE_L2_PCAP_NOCAPTURE_LOCAL) != 0)
	{
		l2bridge_pcaps.Capture = p;
		l2bridge_pcaps.CaptureFlags = flags;
		StrCpy(l2bridge_pcaps.Source, sizeof(l2bridge_pcaps.Source), source);
	}
	else
	{
		l2bridge_pcaps.Hold = p;
		l2bridge_pcaps.HoldFlags = flags;
	}
	l2bridge_pcaps.Opens++;
	ReleaseSRWLockExclusive(&l2bridge_pcaps.Lock);

	return p;
}

static void L2BridgePcapClose(void *h)
{
	L2BRIDGE_PCAP *p = (L2BRIDGE_PCAP *)h;

	AcquireSRWLockExclusive(&l2bridge_pcaps.Lock);
	if (l2bridge_pcaps.Capture == p)
	{
		l2bridge_pcaps.Capture = NULL;
	}
	if (l2bridge_pcaps.Hold == p)
	{
		l2bridge_pcaps.HoldRejected = p->Reject;
		l2bridge_pcaps.Hold = NULL;
	}
	l2bridge_pcaps.Closes++;
	ReleaseSRWLockExclusive(&l2bridge_pcaps.Lock);

	CloseHandle(p->Event);
	Free(p);
}

// The next frame that the handle holds, in place: 1 with it, 0 for none, -1 while reads fail
static int L2BridgePcapNextEx(void *h, NODE_L2_PCAP_HEADER **header, const UCHAR **data)
{
	L2BRIDGE_PCAP *p = (L2BRIDGE_PCAP *)h;
	int ret = 0;

	if (ReadAcquire(&l2bridge_pcaps.FailReads) != 0)
	{
		return -1;
	}

	AcquireSRWLockExclusive(&p->Lock);
	if (p->Num != 0)
	{
		UINT size = p->Sizes[p->Head];

		Copy(p->Current, p->Queue[p->Head], size);
		Zero(&p->Header, sizeof(p->Header));
		p->Header.Size = size;
		p->Header.Captured = (p->Cut[p->Head] ? size - 1 : size);
		p->Head = (p->Head + 1) % L2BRIDGE_PCAP_QUEUE;
		p->Num--;
		*header = &p->Header;
		*data = p->Current;
		ret = 1;
	}
	if (p->Num == 0)
	{
		ResetEvent(p->Event);
	}
	ReleaseSRWLockExclusive(&p->Lock);

	return ret;
}

static int L2BridgePcapSendPacket(void *h, const UCHAR *data, int size)
{
	if (size < NODE_L2_MIN_FRAME)
	{
		return -1;
	}

	InterlockedIncrement(&l2bridge_pcaps.Sent);

	return 0;
}

static HANDLE L2BridgePcapGetEvent(void *h)
{
	return ((L2BRIDGE_PCAP *)h)->Event;
}

// A filter: the one instruction "ret #0" takes no frame; the stand-in takes no other filter
static int L2BridgePcapSetFilter(void *h, NODE_L2_BPF_PROGRAM *program)
{
	L2BRIDGE_PCAP *p = (L2BRIDGE_PCAP *)h;

	if (program == NULL || program->Length != 1 || program->Instructions[0].Code != NODE_L2_BPF_REJECT || program->Instructions[0].K != 0)
	{
		return -1;
	}
	p->Reject = true;

	return 0;
}

static char *L2BridgePcapGetErr(void *h)
{
	return "the stand-in of the test takes no other filter";
}

static const NODE_L2_PCAP_API l2bridge_pcap_api = {L2BridgePcapOpen, L2BridgePcapClose, L2BridgePcapNextEx, L2BridgePcapSendPacket, L2BridgePcapGetEvent, L2BridgePcapSetFilter, L2BridgePcapGetErr};

// Give the backend's handle of the stand-in a frame of the segment; cut, one that the handle cut short. False when no such
// handle is open or its queue is full.
static bool L2BridgePcapPush(const UCHAR *frame, UINT size, bool cut)
{
	bool ok = false;

	AcquireSRWLockExclusive(&l2bridge_pcaps.Lock);
	L2BRIDGE_PCAP *p = l2bridge_pcaps.Capture;
	if (p != NULL && size <= L2BRIDGE_PCAP_FRAME)
	{
		AcquireSRWLockExclusive(&p->Lock);
		if (p->Num < L2BRIDGE_PCAP_QUEUE)
		{
			UINT i = (p->Head + p->Num) % L2BRIDGE_PCAP_QUEUE;

			Copy(p->Queue[i], frame, size);
			p->Sizes[i] = size;
			p->Cut[i] = cut;
			p->Num++;
			SetEvent(p->Event);
			ok = true;
		}
		ReleaseSRWLockExclusive(&p->Lock);
	}
	ReleaseSRWLockExclusive(&l2bridge_pcaps.Lock);

	return ok;
}

// A new empty data directory under the temp directory of the process, with a configuration store: no role, one worker
static void L2BridgeNewDir(wchar_t *dir, UINT size)
{
	wchar_t tmp[MAX_PATH];
	wchar_t path[MAX_PATH];

	UniFormat(tmp, sizeof(tmp), L"l2bridgetest_%u", Rand32());
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

// Delete the files of a directory, then the directory (it holds no subdirectory)
static void L2BridgeDeleteDir(wchar_t *dir)
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

// The configuration of a bridge of the test on the backends of list
static void L2BridgeConfig(NODE_L2_CONFIG *cfg, const NODE_L2_BACKEND *const *list, UINT num)
{
	Zero(cfg, sizeof(NODE_L2_CONFIG));
	cfg->Proc = L2BridgeOwnerProc;
	cfg->Reset = L2BridgeReset;
	cfg->Backends = list;
	cfg->NumBackends = num;
	cfg->Slots = L2BRIDGE_SLOTS;
	cfg->Bridge = true;
}

// Where frames go on the segment of a bridge
static void L2BridgeWays(L2BRIDGE_CTX *ctx)
{
	static UCHAR mac[6] = {0x02, 0x00, 0x5E, 0x10, 0x73, 0x01};
	static UCHAR broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
	static UCHAR ipv4_group[6] = {0x01, 0x00, 0x5E, 0x00, 0x00, 0xFB};
	static UCHAR ipv6_group[6] = {0x33, 0x33, 0xFF, 0x10, 0x73, 0x01};
	static UCHAR other[6] = {0x02, 0x00, 0x5E, 0x10, 0x73, 0x02};
	UCHAR frame[60];

	Zero(frame, sizeof(frame));
	Copy(frame + 6, other, 6);

	Copy(frame, mac, 6);
	UINT to_mac = NodeL2BridgeWay(frame, sizeof(frame), mac);
	Copy(frame, broadcast, 6);
	UINT to_broadcast = NodeL2BridgeWay(frame, sizeof(frame), mac);
	Copy(frame, ipv4_group, 6);
	UINT to_ipv4_group = NodeL2BridgeWay(frame, sizeof(frame), mac);
	Copy(frame, ipv6_group, 6);
	UINT to_ipv6_group = NodeL2BridgeWay(frame, sizeof(frame), mac);
	Copy(frame, other, 6);
	UINT to_other = NodeL2BridgeWay(frame, sizeof(frame), mac);
	UINT short_frame = NodeL2BridgeWay(frame, 5, mac);

	L2BridgeCheck(ctx, to_mac == NODE_L2_TO_HOST, "a frame to the MAC address of the NIC goes to the host only", "way %u", to_mac);
	L2BridgeCheck(ctx, to_broadcast == (NODE_L2_TO_HOST | NODE_L2_TO_OTHERS) && to_ipv4_group == (NODE_L2_TO_HOST | NODE_L2_TO_OTHERS) && to_ipv6_group == (NODE_L2_TO_HOST | NODE_L2_TO_OTHERS),
		"a broadcast, an IPv4 multicast and an IPv6 multicast frame go to the host and to the others", "ways %u, %u, %u", to_broadcast, to_ipv4_group, to_ipv6_group);
	L2BridgeCheck(ctx, to_other == NODE_L2_TO_OTHERS && short_frame == NODE_L2_TO_OTHERS, "a frame to another unicast address goes to the others only, as does one shorter than an address",
		"ways %u, %u", to_other, short_frame);
}

// The backends of a bridge, and Npcap only where it is installed
static void L2BridgeBackends(L2BRIDGE_CTX *ctx, NODE *n)
{
	const NODE_L2_BACKEND *defaults[NODE_L2_MAX_BACKENDS];
	const NODE_L2_BACKEND *list[2];
	NODE_L2_CONFIG cfg;
	NODE_L2_STATUS st;
	char error[MAX_SIZE];

	Zero(defaults, sizeof(defaults));
	UINT num = NodeL2BridgeBackends(defaults, NODE_L2_MAX_BACKENDS);
	L2BridgeCheck(ctx, num == 2 && StrCmp(defaults[0]->Name, "selow") == 0 && StrCmp(defaults[1]->Name, "npcap") == 0,
		"a bridge whose owner names no backend takes SeLow first, the bundled default, then Npcap", "%u backends: %s, %s", num,
		num >= 1 ? defaults[0]->Name : "", num >= 2 ? defaults[1]->Name : "");

	bool present = NodeL2NpcapPresent(error, sizeof(error));
	Print("  Npcap on this runner: %s%s%s\n", present ? "installed" : "not installed", present ? "" : ", ", error);
	if (present)
	{
		Print("  Npcap is installed here: the checks of a host without it are left out\n");
		return;
	}

	L2BridgeCheck(ctx, InStr(error, "not installed") && InStr(error, "Npcap"), "without Npcap, NodeL2NpcapPresent says that it is not installed", "'%s'", error);

	// A bridge on Npcap and a backend of the test: Npcap does not bind where it is missing, so the other one does
	list[0] = NodeL2NpcapBackend();
	list[1] = &l2bridge_fake_backend;
	L2BridgeConfig(&cfg, list, 2);
	NODE_L2 *a = NodeL2New(n, &cfg);
	NodeL2GetStatus(a, &st);
	L2BridgeCheck(ctx, a != NULL && StrCmp(st.Backend, "fake") == 0 && st.Bridge, "a bridge uses Npcap only where it is installed: without it the next backend binds",
		"%s, backend '%s'", a != NULL ? "a bridge" : "no bridge", st.Backend);

	if (a != NULL)
	{
		void *hold = NULL;
		bool held = NodeL2NpcapHold(a, &hold, error, sizeof(error));
		L2BridgeCheck(ctx, held == false && hold == NULL && InStr(error, "not installed"),
			"without Npcap nothing holds a NIC in promiscuous mode for the XDP backend, which then does not bind", "%s: '%s'", held ? "held" : "not held", error);
		NodeL2NpcapLetGo(hold);
	}

	NodeL2Free(a);
}

// A bridge is never reset: a broken backend that attaches no more is reattached again and again, and the reset of the
// owner never runs
static void L2BridgeNoReset(L2BRIDGE_CTX *ctx, NODE *n)
{
	const NODE_L2_BACKEND *list[1];
	NODE_L2_CONFIG cfg;
	NODE_L2_STATUS st;

	list[0] = &l2bridge_fake_backend;
	L2BridgeConfig(&cfg, list, 1);
	NODE_L2 *a = NodeL2New(n, &cfg);
	if (L2BridgeCheck(ctx, a != NULL, "a bridge on a backend of the test comes up", "NodeL2New failed") == false)
	{
		return;
	}

	InterlockedExchange(&l2bridge_fake.FailAttaches, 1);
	InterlockedExchange(&l2bridge_fake.Broken, 1);
	UINT64 end = GetTickCount64() + L2BRIDGE_BOUND;
	NodeL2GetStatus(a, &st);
	while (st.Reattaches < NODE_L2_RESETS + 3 && GetTickCount64() < end)
	{
		Sleep(L2BRIDGE_POLL * 10);
		NodeL2GetStatus(a, &st);
	}
	L2BridgeCheck(ctx, st.Reattaches >= NODE_L2_RESETS + 3 && st.Resets == 0 && ReadAcquire(&l2bridge_fake.Resets) == 0,
		"a bridge whose backend stays broken is reattached, and its NIC, the host's, is never reset",
		"%I64u reattaches, %I64u resets counted, %d resets of the owner", st.Reattaches, st.Resets, (int)ReadAcquire(&l2bridge_fake.Resets));

	InterlockedExchange(&l2bridge_fake.FailAttaches, 0);
	InterlockedExchange(&l2bridge_fake.Broken, 0);
	NodeL2Free(a);
}

// Count the frames that the backend of the test took for the segment from 0 again
static void L2BridgeFakeZero()
{
	InterlockedExchange(&l2bridge_fake.Injected, 0);
	InterlockedExchange(&l2bridge_fake.ToLan, 0);
	InterlockedExchange(&l2bridge_fake.Broadcasts, 0);
	InterlockedExchange(&l2bridge_fake.Multicasts, 0);
	InterlockedExchange(&l2bridge_fake.Tagged, 0);
	InterlockedExchange(&l2bridge_fake.LastVlan, 0);
}

// Whether the MAC table of the switch learnt the address mac in the VLAN vlan on the port port
static bool L2BridgeLearnt(SWITCH *sw, const UCHAR *mac, UINT vlan, UINT port)
{
	SWITCH_MAC_ENTRY macs[16];
	UINT num = SwitchGetMacs(sw, macs, 16);

	for (UINT i = 0;i < num;i++)
	{
		if (Cmp(macs[i].Mac, mac, 6) == 0 && macs[i].Vlan == vlan && macs[i].Port == port)
		{
			return true;
		}
	}

	return false;
}

// An L2 bridge as an access port of the switch of an L2 Network, beside a member of the Network that the test plays
static void L2BridgeMember(L2BRIDGE_CTX *ctx, NODE *n)
{
	const NODE_L2_BACKEND *list[1];
	SWITCH_PORT_CONFIG pc;
	SWITCH_STATS ss;
	NODE_L2_CONFIG cfg;
	NODE_L2_STATUS st;
	L2BRIDGE_MEMBER m;
	UCHAR frame[L2BRIDGE_FRAME];

	Zero(&m, sizeof(m));
	L2BridgeFakeZero();

	SWITCH *sw = SwitchNew(NULL);
	if (L2BridgeCheck(ctx, sw != NULL, "an L2 switch for the Network", "SwitchNew failed") == false)
	{
		return;
	}

	// The member: an access port of the VLAN, in its broadcast group, which also takes the frames to an address that the
	// VLAN has not learnt
	Zero(&pc, sizeof(pc));
	pc.Mode = SWITCH_ACCESS;
	pc.Vlan = L2BRIDGE_VLAN;
	pc.Send = L2BridgeMemberSend;
	pc.Param = &m;
	UINT port = SwitchAddPort(sw, &pc);
	bool ok = (port != SWITCH_PORT_NONE && SwitchSubscribe(sw, port, L2BRIDGE_VLAN, l2bridge_broadcast));

	// The bridge: an access port of the VLAN too, whose procedures are its own
	list[0] = &l2bridge_fake_backend;
	L2BridgeConfig(&cfg, list, 1);
	pc.Send = NULL;
	pc.Param = NULL;
	NODE_L2_BRIDGE *b = (ok ? NodeL2BridgeNew(n, sw, &pc, &cfg) : NULL);
	UINT bport = NodeL2BridgePort(b);
	NodeL2BridgeGetStatus(b, &st);
	SwitchGetStats(sw, &ss);
	if (L2BridgeCheck(ctx, b != NULL && l2bridge_fake.Adapter != NULL && st.Bridge && StrCmp(st.Backend, "fake") == 0 && bport != SWITCH_PORT_NONE && bport != port && ss.NumPorts == 2,
		"an L2 bridge on a backend of the test is the member of a port of the switch of an L2 Network, beside a member of the Network",
		"%s, backend '%s', port %u, %u ports", b != NULL ? "a bridge" : "no bridge", st.Backend, bport, ss.NumPorts) == false)
	{
		NodeL2BridgeFree(b);
		SwitchFree(sw);
		return;
	}

	// A frame of the segment to the member, whose address the Network has not learnt yet
	L2BridgeFrame(frame, l2bridge_member_mac, l2bridge_lan_mac, 0);
	L2BridgeFromLan(frame, sizeof(frame));
	bool reached = L2BridgeWait(&m.FromLan, 1);
	L2BridgeCheck(ctx, reached && L2BridgeLearnt(sw, l2bridge_lan_mac, L2BRIDGE_VLAN, bport),
		"a frame of the segment reaches the member of the Network, and the switch learns the address of the segment on the port of the bridge",
		"%d frames of the segment at the member, the address %s", (int)ReadAcquire(&m.FromLan), L2BridgeLearnt(sw, l2bridge_lan_mac, L2BRIDGE_VLAN, bport) ? "learnt" : "not learnt");

	// The member's frames: to the address of the segment, to the broadcast address, and to a group that no member asked for
	L2BridgeFrame(frame, l2bridge_lan_mac, l2bridge_member_mac, 0);
	UINT to_lan = SwitchInput(sw, GetTickCount64(), port, frame, sizeof(frame));
	L2BridgeFrame(frame, l2bridge_broadcast, l2bridge_member_mac, 0);
	UINT to_all = SwitchInput(sw, GetTickCount64(), port, frame, sizeof(frame));
	L2BridgeFrame(frame, l2bridge_group, l2bridge_member_mac, 0);
	UINT to_group = SwitchInput(sw, GetTickCount64(), port, frame, sizeof(frame));
	bool taken = L2BridgeWait(&l2bridge_fake.ToLan, 1) && L2BridgeWait(&l2bridge_fake.Broadcasts, 1) && L2BridgeWait(&l2bridge_fake.Multicasts, 1);
	L2BridgeCheck(ctx, to_lan == 1 && to_all == 1 && to_group == 1 && taken,
		"the Network's frames to the address of the segment, to the broadcast address and to a group that no member asked for reach the segment through the bridge",
		"handed to %u, %u and %u ports; the backend took %d to the segment, %d broadcast and %d multicast frames", to_lan, to_all, to_group,
		(int)ReadAcquire(&l2bridge_fake.ToLan), (int)ReadAcquire(&l2bridge_fake.Broadcasts), (int)ReadAcquire(&l2bridge_fake.Multicasts));

	// A frame of the segment to another address of the segment, which the switch learnt on the port of the bridge: it goes
	// nowhere, not back onto the segment and not to the member
	L2BridgeFrame(frame, l2bridge_broadcast, l2bridge_lan2_mac, 0);
	L2BridgeFromLan(frame, sizeof(frame));
	L2BridgeWait(&m.Frames, 2);
	LONG frames = ReadAcquire(&m.Frames);
	LONG injected = ReadAcquire(&l2bridge_fake.Injected);
	L2BridgeFrame(frame, l2bridge_lan2_mac, l2bridge_lan_mac, 0);
	L2BridgeFromLan(frame, sizeof(frame));
	Sleep(500);
	L2BridgeCheck(ctx, frames == 2 && ReadAcquire(&m.Frames) == frames && ReadAcquire(&l2bridge_fake.Injected) == injected,
		"a frame of the segment to another address of the segment goes nowhere: not back onto the segment and not to the member",
		"%d frames at the member (%d before), %d frames for the segment (%d before)", (int)ReadAcquire(&m.Frames), (int)frames, (int)ReadAcquire(&l2bridge_fake.Injected), (int)injected);

	// The bridge goes: its port leaves the switch, which forgets the addresses of the segment, and the Network's frames to
	// them reach nobody
	bool freed = NodeL2BridgeFree(b);
	SwitchGetStats(sw, &ss);
	L2BridgeFrame(frame, l2bridge_lan_mac, l2bridge_member_mac, 0);
	UINT after = SwitchInput(sw, GetTickCount64(), port, frame, sizeof(frame));
	L2BridgeCheck(ctx, freed && ss.NumPorts == 1 && L2BridgeLearnt(sw, l2bridge_lan_mac, L2BRIDGE_VLAN, bport) == false && after == 0,
		"NodeL2BridgeFree takes the bridge off its switch, which forgets the addresses of the segment",
		"%s, %u ports, a frame to the segment handed to %u ports", freed ? "freed" : "not freed in time", ss.NumPorts, after);

	SwitchFree(sw);
}

// An L2 bridge as a trunk port: its native VLAN and a VLAN of its allowed list, whose frames leave it with their tag
static void L2BridgeTrunk(L2BRIDGE_CTX *ctx, NODE *n)
{
	const NODE_L2_BACKEND *list[1];
	SWITCH_PORT_CONFIG pc;
	NODE_L2_CONFIG cfg;
	L2BRIDGE_MEMBER m;
	USHORT allowed[1] = {L2BRIDGE_VLAN2};
	UCHAR frame[L2BRIDGE_FRAME];

	Zero(&m, sizeof(m));
	L2BridgeFakeZero();

	SWITCH *sw = SwitchNew(NULL);
	if (L2BridgeCheck(ctx, sw != NULL, "an L2 switch for the trunk", "SwitchNew failed") == false)
	{
		return;
	}

	// The member: an access port of the second VLAN
	Zero(&pc, sizeof(pc));
	pc.Mode = SWITCH_ACCESS;
	pc.Vlan = L2BRIDGE_VLAN2;
	pc.Send = L2BridgeMemberSend;
	pc.Param = &m;
	UINT port = SwitchAddPort(sw, &pc);
	bool ok = (port != SWITCH_PORT_NONE && SwitchSubscribe(sw, port, L2BRIDGE_VLAN2, l2bridge_broadcast));

	// The bridge: a trunk port, native VLAN the first, the second on its allowed list
	list[0] = &l2bridge_fake_backend;
	L2BridgeConfig(&cfg, list, 1);
	Zero(&pc, sizeof(pc));
	pc.Mode = SWITCH_TRUNK;
	pc.Vlan = L2BRIDGE_VLAN;
	pc.Allowed = allowed;
	pc.NumAllowed = 1;
	NODE_L2_BRIDGE *b = (ok ? NodeL2BridgeNew(n, sw, &pc, &cfg) : NULL);
	if (L2BridgeCheck(ctx, b != NULL, "an L2 bridge is a trunk port of the switch", "NodeL2BridgeNew failed") == false)
	{
		SwitchFree(sw);
		return;
	}

	// The member's broadcast frame leaves the bridge with the tag of its VLAN
	L2BridgeFrame(frame, l2bridge_broadcast, l2bridge_member_mac, 0);
	SwitchInput(sw, GetTickCount64(), port, frame, sizeof(frame));
	bool tagged = L2BridgeWait(&l2bridge_fake.Tagged, 1);
	L2BridgeCheck(ctx, tagged && ReadAcquire(&l2bridge_fake.LastVlan) == L2BRIDGE_VLAN2,
		"a frame of a VLAN on the allowed list of a trunk bridge leaves it with the tag of that VLAN", "%d tagged frames, the last of VLAN %d",
		(int)ReadAcquire(&l2bridge_fake.Tagged), (int)ReadAcquire(&l2bridge_fake.LastVlan));

	// The segment's frames: one with the tag of that VLAN reaches the member without it; one with the tag of a VLAN that the
	// trunk does not carry, and an untagged one, of the native VLAN, do not reach it
	L2BridgeFrame(frame, l2bridge_broadcast, l2bridge_lan_mac, L2BRIDGE_VLAN3);
	L2BridgeFromLan(frame, sizeof(frame));
	L2BridgeFrame(frame, l2bridge_broadcast, l2bridge_lan_mac, 0);
	L2BridgeFromLan(frame, sizeof(frame));
	L2BridgeFrame(frame, l2bridge_broadcast, l2bridge_lan_mac, L2BRIDGE_VLAN2);
	L2BridgeFromLan(frame, sizeof(frame));
	bool reached = L2BridgeWait(&m.FromLan, 1);
	Sleep(500);
	L2BridgeCheck(ctx, reached && ReadAcquire(&m.FromLan) == 1 && ReadAcquire(&m.Tagged) == 0,
		"a frame of the segment with the tag of a VLAN of the trunk reaches the members of that VLAN untagged, and a frame of another VLAN does not",
		"%d frames of the segment at the member, %d of them tagged", (int)ReadAcquire(&m.FromLan), (int)ReadAcquire(&m.Tagged));

	L2BridgeCheck(ctx, NodeL2BridgeFree(b), "NodeL2BridgeFree takes the trunk bridge down", "a step did not finish in time");
	SwitchFree(sw);
}

// The Npcap backend on the stand-in of Npcap's pcap API, with no driver
static void L2BridgeNpcap(L2BRIDGE_CTX *ctx, NODE *n)
{
	const NODE_L2_BACKEND *list[1];
	NODE_L2_CONFIG cfg;
	NODE_L2_STATUS st;
	UCHAR frame[L2BRIDGE_FRAME];
	char error[MAX_SIZE];
	int flags = NODE_L2_PCAP_PROMISCUOUS | NODE_L2_PCAP_NOCAPTURE_LOCAL | NODE_L2_PCAP_MAX_RESPONSIVENESS;

	Zero(&l2bridge_pcaps, sizeof(l2bridge_pcaps));
	InitializeSRWLock(&l2bridge_pcaps.Lock);
	NodeL2NpcapStandIn(&l2bridge_pcap_api);
	bool present = NodeL2NpcapPresent(error, sizeof(error));

	list[0] = NodeL2NpcapBackend();
	L2BridgeConfig(&cfg, list, 1);
	NODE_L2 *a = (present ? NodeL2New(n, &cfg) : NULL);
	NodeL2GetStatus(a, &st);
	AcquireSRWLockExclusive(&l2bridge_pcaps.Lock);
	bool opened = (l2bridge_pcaps.Opens == 1 && l2bridge_pcaps.CaptureFlags == flags && StartWith(l2bridge_pcaps.Source, "\\Device\\NPF_{"));
	ReleaseSRWLockExclusive(&l2bridge_pcaps.Lock);
	if (L2BridgeCheck(ctx, present && a != NULL && StrCmp(st.Backend, "npcap") == 0 && opened,
		"on a stand-in of Npcap's pcap API the Npcap backend binds a bridge: one handle on the device of the NIC, promiscuous, blind to its own frames and handing each over at once",
		"%s, backend '%s', %u handles, flags 0x%X, '%s'", a != NULL ? "a bridge" : "no bridge", st.Backend, l2bridge_pcaps.Opens, (UINT)l2bridge_pcaps.CaptureFlags, l2bridge_pcaps.Source) == false)
	{
		NodeL2Free(a);
		NodeL2NpcapStandIn(NULL);
		return;
	}

	// The frames of the segment reach the owner; a frame that the handle cut short is counted, not handed over
	UINT pushed = 0;
	for (UINT i = 0;i < 5;i++)
	{
		L2BridgeFrame(frame, l2bridge_member_mac, l2bridge_lan_mac, 0);
		pushed += (L2BridgePcapPush(frame, sizeof(frame), false) ? 1 : 0);
	}
	pushed += (L2BridgePcapPush(frame, sizeof(frame), true) ? 1 : 0);
	UINT64 end = GetTickCount64() + L2BRIDGE_BOUND;
	NodeL2GetStatus(a, &st);
	while ((st.Delivered < 5 || st.Oversize < 1) && GetTickCount64() < end)
	{
		Sleep(L2BRIDGE_POLL);
		NodeL2GetStatus(a, &st);
	}
	L2BridgeCheck(ctx, pushed == 6 && st.Delivered == 5 && st.Oversize == 1, "the Npcap backend hands the owner the frames of the segment, and counts a frame that its handle cut short",
		"%u frames given, %I64u handed over, %I64u cut short", pushed, st.Delivered, st.Oversize);

	// The owner's frames go onto the segment
	for (UINT i = 0;i < 3;i++)
	{
		L2BridgeFrame(frame, l2bridge_lan_mac, l2bridge_member_mac, 0);
		NodeL2Send(a, frame, sizeof(frame));
	}
	bool sent = L2BridgeWait(&l2bridge_pcaps.Sent, 3);
	L2BridgeCheck(ctx, sent, "the Npcap backend sends the owner's frames onto the segment through its handle", "%d frames sent", (int)ReadAcquire(&l2bridge_pcaps.Sent));

	// A read that fails marks the binding broken: the health check closes the handle and opens another, which carries the
	// frames of the segment again once reads work
	InterlockedExchange(&l2bridge_pcaps.FailReads, 1);
	end = GetTickCount64() + L2BRIDGE_BOUND;
	NodeL2GetStatus(a, &st);
	while (st.Reattaches < 1 && GetTickCount64() < end)
	{
		Sleep(L2BRIDGE_POLL);
		NodeL2GetStatus(a, &st);
	}
	UINT64 reattaches = st.Reattaches;
	InterlockedExchange(&l2bridge_pcaps.FailReads, 0);
	UINT64 delivered = st.Delivered;
	end = GetTickCount64() + L2BRIDGE_BOUND;
	while (st.Delivered == delivered && GetTickCount64() < end)
	{
		L2BridgeFrame(frame, l2bridge_member_mac, l2bridge_lan_mac, 0);
		L2BridgePcapPush(frame, sizeof(frame), false);
		Sleep(L2BRIDGE_POLL * 20);
		NodeL2GetStatus(a, &st);
	}
	L2BridgeCheck(ctx, reattaches >= 1 && st.Delivered > delivered && l2bridge_pcaps.Opens >= 2,
		"a read of the Npcap backend that fails marks it broken; it is attached again on another handle, which carries the frames of the segment",
		"%I64u reattaches, %u handles opened, %I64u frames handed over (%I64u before)", reattaches, l2bridge_pcaps.Opens, st.Delivered, delivered);

	// The hold of promiscuous mode for the XDP backend: a handle opened promiscuous only, whose filter takes no frame, until
	// the backend lets go of it
	void *hold = NULL;
	bool held = NodeL2NpcapHold(a, &hold, error, sizeof(error));
	AcquireSRWLockExclusive(&l2bridge_pcaps.Lock);
	bool rejecting = (l2bridge_pcaps.Hold != NULL && l2bridge_pcaps.Hold->Reject && l2bridge_pcaps.HoldFlags == NODE_L2_PCAP_PROMISCUOUS);
	ReleaseSRWLockExclusive(&l2bridge_pcaps.Lock);
	NodeL2NpcapLetGo(hold);
	L2BridgeCheck(ctx, held && hold != NULL && rejecting && l2bridge_pcaps.Hold == NULL && l2bridge_pcaps.HoldRejected,
		"Npcap holds a NIC in promiscuous mode for the XDP backend with a handle whose filter takes no frame, and lets go of it",
		"%s: '%s', flags 0x%X", held ? "held" : "not held", error, (UINT)l2bridge_pcaps.HoldFlags);

	bool freed = NodeL2Free(a);
	L2BridgeCheck(ctx, freed && l2bridge_pcaps.Opens == l2bridge_pcaps.Closes && l2bridge_pcaps.Capture == NULL,
		"the bridge on Npcap goes, and every handle of the stand-in is closed again", "%s, %u handles opened, %u closed", freed ? "freed" : "not freed in time",
		l2bridge_pcaps.Opens, l2bridge_pcaps.Closes);

	NodeL2NpcapStandIn(NULL);
	bool installed = NodeL2NpcapPresent(error, sizeof(error));
	Print("  without the stand-in, Npcap on this runner: %s\n", installed ? "installed" : "not installed");
}

// The interface of the route of this runner to 8.8.8.8, 0 for none
static UINT L2BridgeRouteIndex()
{
	UCHAR dst[4] = {8, 8, 8, 8};
	DWORD index = 0;
	IPAddr addr = 0;

	Copy(&addr, dst, 4);
	if (GetBestInterface(addr, &index) != NO_ERROR)
	{
		return 0;
	}

	return (UINT)index;
}

// The interface of a bridge by its name
static void L2BridgeNames(L2BRIDGE_CTX *ctx)
{
	MIB_IF_TABLE2 *t = NULL;
	MIB_IF_ROW2 row;
	char alias[MAX_SIZE];
	char guid[64];
	char error[MAX_SIZE * 2];
	UINT index = L2BridgeRouteIndex();

	Zero(&row, sizeof(row));
	row.InterfaceIndex = index;
	if (L2BridgeCheck(ctx, index != 0 && GetIfEntry2(&row) == NO_ERROR, "this runner has a route to the internet through a NIC", "interface %u", index))
	{
		const GUID *g = &row.InterfaceGuid;

		Zero(alias, sizeof(alias));
		UniToUtf8((UCHAR *)alias, sizeof(alias) - 1, row.Alias);
		Format(guid, sizeof(guid), "{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}", (UINT)g->Data1, (UINT)g->Data2, (UINT)g->Data3, (UINT)g->Data4[0], (UINT)g->Data4[1],
			(UINT)g->Data4[2], (UINT)g->Data4[3], (UINT)g->Data4[4], (UINT)g->Data4[5], (UINT)g->Data4[6], (UINT)g->Data4[7]);
		Print("  the NIC of this runner: interface %u, '%s', %s, type %u\n", index, alias, guid, (UINT)row.Type);

		UINT by_alias = NodeL2BridgeIndex(alias, error, sizeof(error));
		L2BridgeCheck(ctx, by_alias == index, "NodeL2BridgeIndex finds the NIC by its alias", "interface %u: %s", by_alias, error);
		UINT by_guid = NodeL2BridgeIndex(guid, error, sizeof(error));
		L2BridgeCheck(ctx, by_guid == index, "NodeL2BridgeIndex finds the NIC by its GUID", "interface %u: %s", by_guid, error);
	}

	UINT none = NodeL2BridgeIndex("ranz no such interface", error, sizeof(error));
	L2BridgeCheck(ctx, none == 0 && InStr(error, "no interface is named"), "NodeL2BridgeIndex refuses a name that no interface has", "interface %u: '%s'", none, error);

	// The loopback interface: no Ethernet
	if (GetIfTable2(&t) == NO_ERROR)
	{
		bool found = false;

		for (ULONG i = 0;i < t->NumEntries && found == false;i++)
		{
			if (t->Table[i].Type != IF_TYPE_SOFTWARE_LOOPBACK)
			{
				continue;
			}

			found = true;
			Zero(alias, sizeof(alias));
			UniToUtf8((UCHAR *)alias, sizeof(alias) - 1, t->Table[i].Alias);
			UINT loopback = NodeL2BridgeIndex(alias, error, sizeof(error));
			L2BridgeCheck(ctx, loopback == 0 && InStr(error, "not an Ethernet interface"), "NodeL2BridgeIndex refuses the loopback interface, which is no Ethernet",
				"'%s': interface %u, '%s'", alias, loopback, error);
		}

		FreeMibTable(t);
	}

	UINT hyperv = NodeL2HyperVIndex(L2BRIDGE_SWITCH, error, sizeof(error));
	L2BridgeCheck(ctx, hyperv == 0 && InStr(error, "vEthernet (" L2BRIDGE_SWITCH ")") && InStr(error, "Add-VMNetworkAdapter -ManagementOS"),
		"NodeL2HyperVIndex refuses a virtual switch that the host has no vNIC of, and says how to add one", "interface %u: '%s'", hyperv, error);
}

// l2bridge: the bridge of the L2 adapter of the node on backends of the test (CORE-S3-3)
RANZ_TEST("l2bridge", l2bridge_test, "L2 bridge: the bridge of an L2 Network on a NIC or a Hyper-V switch on backends of the test: where a frame goes, SeLow the default and Npcap only where it is installed, no reset of the host's NIC, the L2 bridge as an access or trunk port of the switch of an L2 Network, the Npcap backend on a stand-in of its pcap API, the interface by its alias, GUID or switch, arm64 L3 only.");
void l2bridge_test(UINT num, char **arg)
{
	L2BRIDGE_CTX ctx;
	SYSTEM_INFO info;
	HANDLE done = CreateEventW(NULL, TRUE, FALSE, NULL);
	HANDLE watchdog = (done != NULL ? CreateThread(NULL, 0, L2BridgeWatchdog, done, 0, NULL) : NULL);
	wchar_t dir[MAX_PATH];
	wchar_t log_dir[MAX_PATH];

	Zero(&ctx, sizeof(ctx));
	Zero(&l2bridge_fake, sizeof(l2bridge_fake));
	Zero(&info, sizeof(info));
	GetNativeSystemInfo(&info);

	Print("L2 bridge test: the bridge of an L2 Network on backends of the test\n");

	L2BridgeWays(&ctx);
	L2BridgeNames(&ctx);

	L2BridgeNewDir(dir, sizeof(dir));
	NODE *n = NewNode(dir);
	bool started = (n != NULL && NodeStart(n));

	if (L2BridgeCheck(&ctx, started, "a node without a role runs for the bridges", "NewNode or NodeStart failed"))
	{
		if (info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64)
		{
			L2BridgeBackends(&ctx, n);
			L2BridgeNoReset(&ctx, n);
			L2BridgeMember(&ctx, n);
			L2BridgeTrunk(&ctx, n);
			L2BridgeNpcap(&ctx, n);
		}
		else
		{
			// This host is L3 only: not even a backend that would bind gives a bridge
			const NODE_L2_BACKEND *list[1];
			NODE_L2_CONFIG cfg;

			list[0] = &l2bridge_fake_backend;
			L2BridgeConfig(&cfg, list, 1);
			NODE_L2 *a = NodeL2New(n, &cfg);
			L2BridgeCheck(&ctx, a == NULL && l2bridge_fake.Attaches == 0, "on this host (architecture %u) no bridge is offered, whatever the backend",
				"a bridge with %d attaches", (int)l2bridge_fake.Attaches);
			NodeL2Free(a);
			Print("  architecture %u: L3 only, the bridge itself is not tested here\n", (UINT)info.wProcessorArchitecture);
		}
	}

	if (n != NULL)
	{
		NodeStop(n);
		FreeNode(n);
	}
	ConbinePathW(log_dir, sizeof(log_dir), dir, NODE_LOG_DIR_NAME);
	L2BridgeDeleteDir(log_dir);
	L2BridgeDeleteDir(dir);

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
		Print("L2BRIDGE TEST OK\n");
	}
	else
	{
		Print("L2BRIDGE TEST FAILED (%u of %u checks failed)\n", ctx.NumFailed, ctx.NumChecks);
	}
}
