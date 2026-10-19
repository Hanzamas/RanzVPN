// storepacket.c
// Named StorePacket test of vpntest ("storepacket" command, SEC-5 #96)
//
// Runs frames through the hub packet adapter of two in-process sessions on a hub of its own (no
// server, no transport, no SessionMain thread), as the flood bench of harness.c does: the sender
// stores frames into the hub, the receiver takes what the hub floods to it.
// - Broadcast storm list: the sender sends broadcast frames to STOREPACKET_TEST_FLOOD distinct
//   destination addresses. Its storm list (HUB_PA.StormList, one entry per source MAC, source IP and
//   destination IP) stays at MAX_STORM_LIST_ENTRIES and the oldest entries go first; the old list
//   kept one entry per destination for the life of the session. The storm detection still drops a
//   flow above the threshold, below the cap and at it.
// - Delay and jitter of the access list: Delay 10 ms with Jitter 5 % holds a frame for 10 ms and then
//   delivers it unchanged. The old jitter span (int)(5 * 10 / 100.0f) was 0 and the modulo by it ended
//   the process. Sampled Delay and Jitter values hold every frame within Delay +- Jitter % of Delay.
// Prints "STOREPACKET TEST OK" only when every check passes, and frees everything it allocates.

#include "Cedar/Account.h"
#include "Cedar/Cedar.h"
#include "Cedar/Connection.h"
#include "Cedar/Hub.h"
#include "Cedar/Server.h"
#include "Cedar/Session.h"

#include "Mayaqua/Kernel.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Network.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/TcpIp.h"
#include "Mayaqua/Tick64.h"

#include <stdarg.h>

#define	STOREPACKET_TEST_HUB			"STOREPACKET_TEST"
#define	STOREPACKET_TEST_FRAME_MAX		128		// Buffer of one test frame
#define	STOREPACKET_TEST_RAW_SIZE		64		// Frame of EtherType 0x88B5
#define	STOREPACKET_TEST_FLOOD			10000	// Distinct destinations of the storm list flood
#define	STOREPACKET_TEST_FLOOD_NET		0x0A010000	// Their addresses: 10.1.0.0 and up
#define	STOREPACKET_TEST_DETECT_BELOW	0xC0A8FF01	// Destination of the storm flow below the cap: 192.168.255.1
#define	STOREPACKET_TEST_DETECT_AT		0xC0A8FF02	// Destination of the storm flow at the cap: 192.168.255.2
#define	STOREPACKET_TEST_BATCH			32		// Frames between two drains of the receiver
#define	STOREPACKET_TEST_STORM_FRAMES	100		// Frames of one flow within one storm check span
#define	STOREPACKET_TEST_STORM_MARGIN	200		// Milliseconds waited past STORM_CHECK_SPAN
#define	STOREPACKET_TEST_DELAY			10		// Delay of the delivery case (ms)
#define	STOREPACKET_TEST_JITTER			5		// Its jitter (%): a span of 0 ms
#define	STOREPACKET_TEST_DELIVER_MARGIN	50		// Milliseconds waited past that delay
#define	STOREPACKET_TEST_SAMPLE_DELAY	99		// Sampled delays 1 .. this, each with every jitter
#define	STOREPACKET_TEST_LARGE_REPEAT	20		// Frames per large Delay and Jitter pair

// Run state of the test
typedef struct STOREPACKET_TEST
{
	UINT NumChecks;						// Checks run so far
	UINT NumFailed;						// Checks failed so far
	CEDAR *Cedar;						// Owner of the hub
	HUB *Hub;							// Hub of the two sessions (not in the hub list of the Cedar)
	THREAD *Thread;						// Owner of the session connections; it has nothing to run
	SESSION *Sender;					// Stores every frame of the test into the hub
	SESSION *Receiver;					// Takes the frames the hub floods
} STOREPACKET_TEST;

static UCHAR storepacket_test_mac_sender[6] = {0x02, 0x42, 0x55, 0x52, 0x00, 0x5A};
static UCHAR storepacket_test_mac_broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

// Record one check: print [PASS], or [FAIL] with the formatted detail
static bool StorePacketTestCheck(STOREPACKET_TEST *t, bool ok, char *what, char *detail_fmt, ...)
{
	char detail[MAX_SIZE];
	va_list args;

	t->NumChecks++;

	if (ok)
	{
		Print("  [PASS] %s\n", what);
		return true;
	}

	va_start(args, detail_fmt);
	FormatArgs(detail, sizeof(detail), detail_fmt, args);
	va_end(args);

	Print("  [FAIL] %s (%s)\n", what, detail);

	t->NumFailed++;

	return false;
}

// The session connections have nothing to run
static void StorePacketTestIdleThread(THREAD *thread, void *param)
{
}

// In-process server session on the test hub with the hub packet adapter and the default policy
// (the broadcast storm guard is on), made like the flood bench sessions of harness.c
static SESSION *StorePacketTestNewSession(STOREPACKET_TEST *t, char *username)
{
	CONNECTION *c;
	SESSION *s;
	POLICY *policy = ClonePolicy(GetDefaultPolicy());

	c = NewServerConnection(t->Cedar, NULL, t->Thread);
	s = NewServerSession(t->Cedar, c, t->Hub, username, policy);
	c->Session = s;
	ReleaseConnection(c);

	s->Username = CopyStr(username);

	s->PacketAdapter->Init(s);

	return s;
}

// Release a session in the order of the end of SessionMain: leave the hub, free the packet adapter, release
static void StorePacketTestFreeSession(SESSION *s)
{
	DelSession(s->Hub, s);
	s->PacketAdapter->Free(s);
	ReleaseSession(s);
}

// Broadcast IPv4 UDP frame of the sender from 10.5.0.1 to dst (host order), ports 40000 to 40001,
// 8 bytes of data. Returns its size
static UINT StorePacketTestIpFrame(UCHAR *buf, UINT dst)
{
	UCHAR *ip = buf + 14;
	UCHAR *udp = ip + 20;
	UINT udp_size = 8 + 8;
	UINT ip_size = 20 + udp_size;
	USHORT sum;
	UINT i;

	Zero(buf, 14 + ip_size);

	Copy(buf, storepacket_test_mac_broadcast, 6);
	Copy(buf + 6, storepacket_test_mac_sender, 6);
	buf[12] = 0x08;								// IPv4
	buf[13] = 0x00;

	ip[0] = 0x45;								// Version 4, 20-byte header
	ip[2] = (UCHAR)(ip_size >> 8);
	ip[3] = (UCHAR)(ip_size & 0xFF);
	ip[8] = 64;									// TTL
	ip[9] = IP_PROTO_UDP;
	ip[12] = 10;
	ip[13] = 5;
	ip[14] = 0;
	ip[15] = 1;
	ip[16] = (UCHAR)(dst >> 24);
	ip[17] = (UCHAR)(dst >> 16);
	ip[18] = (UCHAR)(dst >> 8);
	ip[19] = (UCHAR)dst;
	sum = IpChecksum(ip, 20);
	Copy(ip + 10, &sum, sizeof(USHORT));

	udp[0] = 0x9C;								// Source port 40000
	udp[1] = 0x40;
	udp[2] = 0x9C;								// Destination port 40001
	udp[3] = 0x41;
	udp[5] = (UCHAR)udp_size;					// Length; checksum 0 (none)

	for (i = 0;i < 8;i++)
	{
		udp[8 + i] = (UCHAR)(0xA0 + i);
	}

	return 14 + ip_size;
}

// Broadcast frame of the sender with EtherType 0x88B5 (IEEE local experimental), no IP: only an access
// list entry without addresses matches it. Returns its size
static UINT StorePacketTestRawFrame(UCHAR *buf, UINT seq)
{
	UINT i;

	Copy(buf, storepacket_test_mac_broadcast, 6);
	Copy(buf + 6, storepacket_test_mac_sender, 6);
	buf[12] = 0x88;
	buf[13] = 0xB5;
	buf[14] = (UCHAR)(seq >> 24);
	buf[15] = (UCHAR)(seq >> 16);
	buf[16] = (UCHAR)(seq >> 8);
	buf[17] = (UCHAR)seq;

	for (i = 18;i < STOREPACKET_TEST_RAW_SIZE;i++)
	{
		buf[i] = (UCHAR)i;
	}

	return STOREPACKET_TEST_RAW_SIZE;
}

// Hand one frame to the hub as the sender's SessionMain would (the hub owns the copy)
static void StorePacketTestSend(STOREPACKET_TEST *t, UCHAR *frame, UINT size)
{
	void *data = Malloc(size);

	Copy(data, frame, size);
	t->Sender->PacketAdapter->PutPacket(t->Sender, data, size);
}

// End of a receive loop of the sender: the delayed frames that are due go on, the receivers are woken
static void StorePacketTestFlush(STOREPACKET_TEST *t)
{
	t->Sender->PacketAdapter->PutPacket(t->Sender, NULL, 0);
}

// Take the frames queued for the receiver. Returns their number; num_equal (optional) gets the number
// of them that are byte-identical to expected
static UINT StorePacketTestDrain(STOREPACKET_TEST *t, UCHAR *expected, UINT expected_size, UINT *num_equal)
{
	SESSION *r = t->Receiver;
	void *data;
	UINT size;
	UINT num = 0;

	if (num_equal != NULL)
	{
		*num_equal = 0;
	}

	while ((size = r->PacketAdapter->GetNextPacket(r, &data)) != 0)
	{
		if (num_equal != NULL && expected != NULL && size == expected_size && Cmp(data, expected, size) == 0)
		{
			(*num_equal)++;
		}

		Free(data);
		num++;
	}

	return num;
}

// Number of entries of the sender's broadcast storm list
static UINT StorePacketTestStormNum(STOREPACKET_TEST *t)
{
	HUB_PA *pa = (HUB_PA *)t->Sender->PacketAdapter->Param;
	UINT num;

	LockList(pa->StormList);
	{
		num = LIST_NUM(pa->StormList);
	}
	UnlockList(pa->StormList);

	return num;
}

// Whether the sender's broadcast storm list holds the flow from 10.5.0.1 to dst (host order)
static bool StorePacketTestHasStorm(STOREPACKET_TEST *t, UINT dst)
{
	HUB_PA *pa = (HUB_PA *)t->Sender->PacketAdapter->Param;
	IP src_ip, dest_ip;
	bool ret;

	SetIP(&src_ip, 10, 5, 0, 1);
	SetIP(&dest_ip, (UCHAR)(dst >> 24), (UCHAR)(dst >> 16), (UCHAR)(dst >> 8), (UCHAR)dst);

	LockList(pa->StormList);
	{
		ret = (SearchStormList(pa, storepacket_test_mac_sender, &src_ip, &dest_ip, false) != NULL);
	}
	UnlockList(pa->StormList);

	return ret;
}

// One flow above the storm threshold: STOREPACKET_TEST_STORM_FRAMES frames within one check span all
// pass; the first frame after the span finds their rate above the threshold and is dropped
static void StorePacketTestStormDetect(STOREPACKET_TEST *t, char *when, UINT dst)
{
	UCHAR frame[STOREPACKET_TEST_FRAME_MAX];
	UINT size = StorePacketTestIpFrame(frame, dst);
	UINT num_within, num_after;
	char what[MAX_SIZE];
	UINT i;

	StorePacketTestDrain(t, NULL, 0, NULL);

	for (i = 0;i < STOREPACKET_TEST_STORM_FRAMES;i++)
	{
		StorePacketTestSend(t, frame, size);
	}
	StorePacketTestFlush(t);
	num_within = StorePacketTestDrain(t, NULL, 0, NULL);

	SleepThread(STORM_CHECK_SPAN + STOREPACKET_TEST_STORM_MARGIN);

	StorePacketTestSend(t, frame, size);
	StorePacketTestFlush(t);
	num_after = StorePacketTestDrain(t, NULL, 0, NULL);

	Format(what, sizeof(what), "storm %s: %u frames of one flow within a check span pass, the next one after the span is dropped",
		when, STOREPACKET_TEST_STORM_FRAMES);
	StorePacketTestCheck(t, num_within == STOREPACKET_TEST_STORM_FRAMES && num_after == 0, what,
		"%u of %u passed, then %u of 1", num_within, STOREPACKET_TEST_STORM_FRAMES, num_after);
}

// STOREPACKET_TEST_FLOOD flows of one broadcast frame each: none is a storm, the storm list stays at its cap
static void StorePacketTestStormFlood(STOREPACKET_TEST *t)
{
	UCHAR frame[STOREPACKET_TEST_FRAME_MAX];
	UINT num_recv = 0;
	UINT num_list;
	bool has_first, has_last, has_detect;
	UINT i;

	for (i = 0;i < STOREPACKET_TEST_FLOOD;i++)
	{
		UINT size = StorePacketTestIpFrame(frame, STOREPACKET_TEST_FLOOD_NET + i);

		StorePacketTestSend(t, frame, size);

		if ((i % STOREPACKET_TEST_BATCH) == (STOREPACKET_TEST_BATCH - 1))
		{
			StorePacketTestFlush(t);
			num_recv += StorePacketTestDrain(t, NULL, 0, NULL);
		}
	}
	StorePacketTestFlush(t);
	num_recv += StorePacketTestDrain(t, NULL, 0, NULL);

	num_list = StorePacketTestStormNum(t);
	has_first = StorePacketTestHasStorm(t, STOREPACKET_TEST_FLOOD_NET);
	has_last = StorePacketTestHasStorm(t, STOREPACKET_TEST_FLOOD_NET + STOREPACKET_TEST_FLOOD - 1);
	has_detect = StorePacketTestHasStorm(t, STOREPACKET_TEST_DETECT_BELOW);

	StorePacketTestCheck(t, num_recv == STOREPACKET_TEST_FLOOD,
		"storm flood: one frame per flow is no storm, every frame of the distinct flows passes",
		"%u of %u passed", num_recv, STOREPACKET_TEST_FLOOD);

	StorePacketTestCheck(t, num_list == MAX_STORM_LIST_ENTRIES,
		"storm flood: the storm list of the session stays at MAX_STORM_LIST_ENTRIES (the old list kept every flow)",
		"%u entries after %u flows, cap %u", num_list, STOREPACKET_TEST_FLOOD + 1, MAX_STORM_LIST_ENTRIES);

	StorePacketTestCheck(t, has_last && has_first == false && has_detect == false,
		"storm flood: the newest flow is kept, the oldest flows went first",
		"newest %s, oldest %s, the earlier storm flow %s", has_last ? "kept" : "missing",
		has_first ? "kept" : "dropped", has_detect ? "kept" : "dropped");
}

// The single access list entry of the test hub: every frame but ARP, with the given delay and jitter
static void StorePacketTestSetDelay(STOREPACKET_TEST *t, UINT delay, UINT jitter)
{
	LockList(t->Hub->AccessList);
	{
		ACCESS *a = LIST_DATA(t->Hub->AccessList, 0);

		a->Delay = delay;
		a->Jitter = jitter;
	}
	UnlockList(t->Hub->AccessList);
}

// Frames the sender holds back for a delay. Returns their number; forward_tick (optional) gets the
// forward tick of the first one. take: free them and empty the list
static UINT StorePacketTestDelayed(STOREPACKET_TEST *t, bool take, UINT64 *forward_tick)
{
	LIST *o = t->Sender->DelayedPacketList;
	UINT num;
	UINT i;

	LockList(o);
	{
		num = LIST_NUM(o);

		if (forward_tick != NULL && num >= 1)
		{
			PKT *p = LIST_DATA(o, 0);

			*forward_tick = p->DelayedForwardTick;
		}

		if (take)
		{
			for (i = 0;i < num;i++)
			{
				PKT *p = LIST_DATA(o, i);

				Free(p->PacketData);
				FreePacket(p);
			}

			DeleteAll(o);
		}
	}
	UnlockList(o);

	return num;
}

// Delay 10 ms, Jitter 5 %: the jitter span is below 1 ms, the frame is held for exactly the delay, then delivered
static void StorePacketTestDelayDeliver(STOREPACKET_TEST *t)
{
	UCHAR frame[STOREPACKET_TEST_FRAME_MAX];
	UINT size = StorePacketTestRawFrame(frame, 1);
	UINT64 before, after;
	UINT64 tick = 0;
	UINT num_held, num_early, num_recv, num_equal;

	StorePacketTestSetDelay(t, STOREPACKET_TEST_DELAY, STOREPACKET_TEST_JITTER);
	StorePacketTestDrain(t, NULL, 0, NULL);

	before = TickHighres64();
	StorePacketTestSend(t, frame, size);
	after = TickHighres64();

	num_held = StorePacketTestDelayed(t, false, &tick);
	num_early = StorePacketTestDrain(t, NULL, 0, NULL);

	StorePacketTestCheck(t, num_held == 1 && num_early == 0 &&
		tick >= before + STOREPACKET_TEST_DELAY && tick <= after + STOREPACKET_TEST_DELAY,
		"delay: Delay 10 Jitter 5 holds the frame for 10 ms (a jitter span of 0 ms; the old code took a modulo by it)",
		"%u held, %u delivered at once, forward tick %I64u, sent between %I64u and %I64u",
		num_held, num_early, tick, before, after);

	SleepThread(STOREPACKET_TEST_DELAY + STOREPACKET_TEST_DELIVER_MARGIN);
	StorePacketTestFlush(t);

	num_recv = StorePacketTestDrain(t, frame, size, &num_equal);
	num_held = StorePacketTestDelayed(t, false, NULL);

	StorePacketTestCheck(t, num_recv == 1 && num_equal == 1 && num_held == 0,
		"delay: after the delay the frame is delivered unchanged",
		"%u delivered (%u unchanged), %u still held", num_recv, num_equal, num_held);
}

// One frame with the given delay and jitter: held once, with a forward tick of Delay +- (span - 1) ms after
// the send, span = Jitter % of Delay in whole ms (exactly Delay when the span is 0). Returns false and the
// detail in fail on a frame out of range
static bool StorePacketTestDelayCase(STOREPACKET_TEST *t, UINT delay, UINT jitter, UCHAR *frame, UINT size,
	char *fail, UINT fail_size)
{
	UINT span = (UINT)((UINT64)delay * (UINT64)jitter / 100);
	UINT low = delay;
	UINT high = delay;
	UINT64 before, after;
	UINT64 tick = 0;
	UINT num;

	if (span != 0)
	{
		low = delay - (span - 1);
		high = delay + (span - 1);
	}

	StorePacketTestSetDelay(t, delay, jitter);

	before = TickHighres64();
	StorePacketTestSend(t, frame, size);
	after = TickHighres64();

	num = StorePacketTestDelayed(t, true, &tick);

	if (num != 1 || tick < before + low || tick > after + high)
	{
		Format(fail, fail_size, "Delay %u Jitter %u: %u held, forward tick %I64u, expected %I64u .. %I64u",
			delay, jitter, num, tick, before + low, after + high);
		return false;
	}

	return true;
}

// Sampled Delay and Jitter pairs: delays 1 .. STOREPACKET_TEST_SAMPLE_DELAY with every jitter, and a few
// large pairs several times each
static void StorePacketTestDelaySampled(STOREPACKET_TEST *t)
{
	static UINT large_delay[] = {100, 1000, HUB_ACCESSLIST_DELAY_MAX};
	static UINT large_jitter[] = {1, 50, HUB_ACCESSLIST_JITTER_MAX};
	UCHAR frame[STOREPACKET_TEST_FRAME_MAX];
	UINT size = StorePacketTestRawFrame(frame, 2);
	char first_fail[MAX_SIZE];
	char what[MAX_SIZE];
	UINT num_cases = 0;
	UINT num_fail = 0;
	UINT delay, jitter, i, j, k;

	StrCpy(first_fail, sizeof(first_fail), "");

	for (delay = 1;delay <= STOREPACKET_TEST_SAMPLE_DELAY;delay++)
	{
		for (jitter = 1;jitter <= HUB_ACCESSLIST_JITTER_MAX;jitter++)
		{
			char fail[MAX_SIZE];

			num_cases++;
			if (StorePacketTestDelayCase(t, delay, jitter, frame, size, fail, sizeof(fail)) == false)
			{
				if (num_fail++ == 0)
				{
					StrCpy(first_fail, sizeof(first_fail), fail);
				}
			}
		}
	}

	for (i = 0;i < sizeof(large_delay) / sizeof(large_delay[0]);i++)
	{
		for (j = 0;j < sizeof(large_jitter) / sizeof(large_jitter[0]);j++)
		{
			for (k = 0;k < STOREPACKET_TEST_LARGE_REPEAT;k++)
			{
				char fail[MAX_SIZE];

				num_cases++;
				if (StorePacketTestDelayCase(t, large_delay[i], large_jitter[j], frame, size, fail, sizeof(fail)) == false)
				{
					if (num_fail++ == 0)
					{
						StrCpy(first_fail, sizeof(first_fail), fail);
					}
				}
			}
		}
	}

	Format(what, sizeof(what), "delay: %u sampled Delay and Jitter pairs hold every frame within Delay +- Jitter %% of Delay",
		num_cases);
	StorePacketTestCheck(t, num_fail == 0, what, "%u out of range, first: %s", num_fail, first_fail);
}

// storepacket: bounded broadcast storm list, access list delay and jitter without a divide by zero
void storepacket_test(UINT num, char **arg)
{
	STOREPACKET_TEST t;
	HUB_OPTION o;
	ACCESS a;

	Zero(&t, sizeof(t));

	Print("StorePacket test\n");

	t.Cedar = NewCedar(NULL, NULL);

	// The defaults of a new hub; no watchdog thread (ARP and neighbor polling), no log files
	Zero(&o, sizeof(o));
	SiSetDefaultHubOption(&o);
	o.NoArpPolling = true;
	t.Hub = NewHub(t.Cedar, STOREPACKET_TEST_HUB, &o);
	t.Hub->LogSetting.SavePacketLog = false;
	t.Hub->LogSetting.SaveSecurityLog = false;

	t.Thread = NewThread(StorePacketTestIdleThread, NULL);
	t.Sender = StorePacketTestNewSession(&t, "storepacket-sender");
	t.Receiver = StorePacketTestNewSession(&t, "storepacket-receiver");

	// Storm list first: the access list entry of the delay cases would hold these frames back
	StorePacketTestStormDetect(&t, "below the cap", STOREPACKET_TEST_DETECT_BELOW);
	StorePacketTestStormFlood(&t);
	StorePacketTestStormDetect(&t, "at the cap", STOREPACKET_TEST_DETECT_AT);
	StorePacketTestCheck(&t, StorePacketTestStormNum(&t) == MAX_STORM_LIST_ENTRIES,
		"storm: a new flow at the cap takes the place of the oldest one", "%u entries, cap %u",
		StorePacketTestStormNum(&t), MAX_STORM_LIST_ENTRIES);

	Zero(&a, sizeof(a));
	a.Active = true;
	a.Priority = 1;
	a.Delay = STOREPACKET_TEST_DELAY;
	a.Jitter = STOREPACKET_TEST_JITTER;
	AddAccessListEx(t.Hub, &a, false, false);

	StorePacketTestDelayDeliver(&t);
	StorePacketTestDelaySampled(&t);

	StorePacketTestFreeSession(t.Receiver);
	StorePacketTestFreeSession(t.Sender);
	ReleaseThread(t.Thread);
	ReleaseHub(t.Hub);
	ReleaseCedar(t.Cedar);

	if (t.NumFailed == 0)
	{
		Print("STOREPACKET TEST OK\n");
	}
	else
	{
		Print("STOREPACKET TEST FAILED (%u of %u checks failed)\n", t.NumFailed, t.NumChecks);
	}
}
