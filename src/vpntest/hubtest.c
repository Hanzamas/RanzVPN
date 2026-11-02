// hubtest.c
// The Hub code that the Node keeps, which the harness of the slim fork's SE-VPN server tested in process until CORE-S8-3
// (#577) retired that server:
// - "bench" times the data path of a hub of the server role of a node (a flood to many sessions, also while one of
//   them waits for the log writer, and new source addresses into the hub IP table), the ParsePacket of the hub, the
//   expiry of its IP table, the Pack and the FIFO and queue of Mayaqua. Every case runs HARNESS_BENCH_RUNS times and
//   prints "BENCH <name> <median> <unit>", then "BENCH <name>_runs <run 1>,...,<run n> <unit>" in run order; the
//   performance regression gate of windows.yml compares them with the recorded medians (.github/quality/bench-<arch>.txt).
//   A wrong result of a case prints a "BENCH WARNING" line and skips the case; it does not fail the test.
// - "packetlog" compares the packet log lines and levels of fixed frames with tests/golden/harness/packetlog.txt
//   (golden family "harness"), and checks the log record of InsertUnicodeRecord.
// - "ptrkey" checks that POINTER_TO_KEY keys a block by its address.

#include "golden.h"
#include "testlist.h"

#include "Cedar/Account.h"
#include "Cedar/Cedar.h"
#include "Cedar/ConfigStore.h"
#include "Cedar/Connection.h"
#include "Cedar/Hub.h"
#include "Cedar/HubLog.h"
#include "Cedar/LogWriter.h"
#include "Cedar/Node.h"
#include "Cedar/PacketLog.h"
#include "Cedar/Session.h"

#include "Mayaqua/Encrypt.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/IpAddr.h"
#include "Mayaqua/Kernel.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Pack.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/TcpIp.h"
#include "Mayaqua/Tick64.h"

#define	HARNESS_HUB_FLOOD			"HARNESS_FLOOD"		// The hub of the flood and IP table add cases
#define	HARNESS_FRAME_SIZE			96
#define	HARNESS_ETHERTYPE_HI		0x88				// EtherType 0x88B5 (IEEE local experimental)
#define	HARNESS_ETHERTYPE_LO		0xB5
#define	HARNESS_BENCH_HOST			"www.example.invalid"	// Host name in the HTTP, TLS and DNS bench frames
#define	HARNESS_BENCH_BUDGET		30000				// Whole "bench" test (warning only)
#define	HARNESS_BENCH_PACK_SPAN		200					// Per run of a Pack case
#define	HARNESS_BENCH_FLOOD_SPAN	200					// Per run of a flood case
#define	HARNESS_BENCH_MICRO_SPAN	100					// Per run of a ParsePacket case
#define	HARNESS_BENCH_RUNS			5					// Runs per bench case: the median and every run are printed
#define	HARNESS_FLOOD_BATCH			32					// Frames the flood sender stores per receive loop
#define	HARNESS_LOGWAIT_BACKLOG		PACKET_LOG_WAIT_RECORDS	// Queued packet log records of a session from which PacketLog makes it wait
#define	HARNESS_LOGWAIT_DELAY		20					// flood_fps_logwait floods this long (ms) into that wait of up to 250 ms
#define	HARNESS_IPTABLE_ADD_BATCH	1024				// New source addresses per run of an ip_table_add case
#define	HARNESS_PACK_NAMES			500					// Distinct element names of the many-names Pack case
#define	HARNESS_PARSE_FRAME_MAX		512					// Buffer of one ParsePacket bench frame
#define	HARNESS_NUM_PARSE_FRAMES	5					// ParsePacket bench frames: l2, tcp, http, tls, dns
#define	HARNESS_FIFO_BACKLOG		1000				// Standing bytes of the fifo_cycle case
#define	HARNESS_FIFO_CYCLE			3000				// Bytes written, then read, per fifo_cycle operation
#define	HARNESS_QUEUE_BACKLOG		1000				// Standing items of the queue_cycle case
#define	HARNESS_QUEUE_BURST			4096				// Items inserted, then taken, per queue_burst operation
#define	HARNESS_NS_PER_MS			1000000ULL
#define	HARNESS_NS_PER_S			1000000000ULL
#define	HARNESS_IPTABLE_PORT		9					// UDP destination port of the IP table frames (discard)

// One operation of a timed bench case: false means a wrong result and stops the case
typedef bool (HARNESS_BENCH_OP)(void *param);

// State of the Pack bench cases
typedef struct HARNESS_PACK_BENCH
{
	BUF *Buf;					// Decoded by the decode case
	char **Names;				// HARNESS_PACK_NAMES distinct element names, not in sorted order
} HARNESS_PACK_BENCH;

// Frame of the ParsePacket bench cases
typedef struct HARNESS_PARSE_FRAME
{
	char *Kind;					// Case name: parse_packet_<Kind>
	UCHAR Data[HARNESS_PARSE_FRAME_MAX];
	UINT Size;
} HARNESS_PARSE_FRAME;

// State of the ParsePacket bench cases
typedef struct HARNESS_PARSE_BENCH
{
	HARNESS_PARSE_FRAME Frames[HARNESS_NUM_PARSE_FRAMES];
	UINT Current;				// Frame of a single-frame case
	UINT Next;					// Next frame of the mixed case
	bool NoLog;					// Parse as with the hub packet log off
} HARNESS_PARSE_BENCH;

// State of the FIFO and queue bench cases
typedef struct HARNESS_FIFO_BENCH
{
	FIFO *Fifo;					// fifo_cycle: HARNESS_FIFO_BACKLOG bytes stay in it between operations
	UINT PeakMemSize;			// Largest Fifo->memsize seen
	QUEUE *Queue;				// queue_cycle: HARNESS_QUEUE_BACKLOG items stay in it between operations
	UINT NextInsert;			// Item the next InsertQueue adds, as a pointer value
	UINT NextGet;				// Item the next GetNext must return
	UCHAR Buf[HARNESS_FIFO_CYCLE];
} HARNESS_FIFO_BENCH;

// Waiting session of flood_fps_logwait: its packet log backlog is at the back-pressure mark of PacketLog
typedef struct HARNESS_LOGWAIT
{
	SESSION *Session;			// A session of the flood hub
	UCHAR Frame[128];			// The logged frame it sends once per run (UDP)
	UINT Size;
	EVENT *Sending;				// Set right before the frame goes into the hub
} HARNESS_LOGWAIT;

// Locally administered MAC addresses of the two ends of the frames
static UCHAR harness_mac_a[6] = {0x02, 0x42, 0x55, 0x52, 0x00, 0x0A};
static UCHAR harness_mac_b[6] = {0x02, 0x42, 0x55, 0x52, 0x00, 0x0B};
static UCHAR harness_mac_broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

static UINT HarnessBuildIpFrame(UCHAR *buf, UINT buf_size, UCHAR protocol, USHORT dst_port, UCHAR *payload, UINT payload_size);
static UINT HarnessBuildDnsQuery(UCHAR *buf, UINT buf_size, char *host);

// Build a deterministic test frame: dst, src, EtherType 0x88B5, sequence number, pattern
static void HarnessBuildFrame(UCHAR *buf, UINT size, const UCHAR *dst, const UCHAR *src, UINT seq)
{
	Copy(buf, dst, 6);
	Copy(buf + 6, src, 6);
	buf[12] = HARNESS_ETHERTYPE_HI;
	buf[13] = HARNESS_ETHERTYPE_LO;
	buf[14] = (UCHAR)((seq >> 24) & 0xFF);
	buf[15] = (UCHAR)((seq >> 16) & 0xFF);
	buf[16] = (UCHAR)((seq >> 8) & 0xFF);
	buf[17] = (UCHAR)(seq & 0xFF);

	for (UINT i = 18;i < size;i++)
	{
		buf[i] = (UCHAR)((i * 7 + seq * 13) & 0xFF);
	}
}

////////////////////////////
// Benchmark

// Monotonic time in nanoseconds from the high-resolution counter (Tick64 steps in whole milliseconds)
static UINT64 HarnessNowNs()
{
	return TickHighresNano64();
}

// One bench value as text; centi: the value is in hundredths and gets two decimals
static void HarnessBenchValue(char *str, UINT size, UINT64 value, bool centi)
{
	if (centi)
	{
		Format(str, size, "%I64u.%02u", value / 100, (UINT)(value % 100));
	}
	else
	{
		Format(str, size, "%I64u", value);
	}
}

// Print one case: "BENCH <name> <median> <unit>", then "BENCH <name>_runs <run 1>,...,<run n> <unit>" in run order
static void HarnessBenchReport(char *name, const UINT64 *runs, UINT num, char *unit, bool centi)
{
	UINT64 sorted[HARNESS_BENCH_RUNS];
	char list[MAX_SIZE];
	char value[64];
	UINT j;

	if (num == 0 || num > HARNESS_BENCH_RUNS)
	{
		return;
	}

	Copy(sorted, runs, sizeof(UINT64) * num);
	for (UINT i = 1;i < num;i++)
	{
		UINT64 v = sorted[i];

		for (j = i;j > 0 && sorted[j - 1] > v;j--)
		{
			sorted[j] = sorted[j - 1];
		}
		sorted[j] = v;
	}

	list[0] = 0;
	for (UINT i = 0;i < num;i++)
	{
		HarnessBenchValue(value, sizeof(value), runs[i], centi);
		if (i != 0)
		{
			StrCat(list, sizeof(list), ",");
		}
		StrCat(list, sizeof(list), value);
	}

	// HARNESS_BENCH_RUNS is odd: the median is the middle run
	HarnessBenchValue(value, sizeof(value), sorted[num / 2], centi);
	Print("BENCH %s %s %s\n", name, value, unit);
	Print("BENCH %s_runs %s %s\n", name, list, unit);
}

// Run one case HARNESS_BENCH_RUNS times for span milliseconds each and report the operations per second.
// The clock is read every check_every operations (1 for slow operations, more when the clock would cost too much)
static bool HarnessBenchOps(char *name, HARNESS_BENCH_OP *op, void *param, UINT span, UINT check_every)
{
	UINT64 runs[HARNESS_BENCH_RUNS];
	UINT64 span_ns = (UINT64)span * HARNESS_NS_PER_MS;

	for (UINT r = 0;r < HARNESS_BENCH_RUNS;r++)
	{
		UINT64 start = HarnessNowNs();
		UINT64 now = start;
		UINT64 ops = 0;

		while (true)
		{
			if (op(param) == false)
			{
				Print("BENCH WARNING %s: wrong result, case skipped\n", name);
				return false;
			}

			ops++;
			if ((ops % check_every) == 0)
			{
				now = HarnessNowNs();
				if ((now - start) >= span_ns)
				{
					break;
				}
			}
		}

		runs[r] = ops * HARNESS_NS_PER_S / (now - start);
	}

	HarnessBenchReport(name, runs, HARNESS_BENCH_RUNS, "ops/s", false);

	return true;
}

////////////////////////////
// Flood benchmark: in-process sessions on hub HARNESS_FLOOD, no transport and no TLS

// Owner of the flood session connections (a server CONNECTION holds a THREAD); it has nothing to run
static void HarnessFloodIdleThread(THREAD *thread, void *param)
{
}

// In-process server session on the flood hub: a CONNECTION without sockets and the hub packet adapter, but no
// SessionMain thread. The bench thread calls the packet adapter itself, so a frame goes through HubPaPutPacket,
// StorePacket and HubPaGetNextPacket only
static SESSION *HarnessNewFloodSession(HUB *hub, THREAD *thread, UINT index, bool sender)
{
	POLICY *policy = ClonePolicy(GetDefaultPolicy());
	char username[MAX_USERNAME_LEN + 1];

	Format(username, sizeof(username), "bench-flood-%u", index);

	if (sender)
	{
		// The single sender floods at full rate: the broadcast storm guard would drop most of its frames
		policy->NoBroadcastLimiter = true;
	}

	CONNECTION *c = NewServerConnection(hub->Cedar, NULL, thread);
	SESSION *s = NewServerSession(hub->Cedar, c, hub, username, policy);
	c->Session = s;
	ReleaseConnection(c);

	s->Username = CopyStr(username);

	// Joined the hub in NewServerSession; floods reach it from here on (HubPaInit always succeeds)
	s->PacketAdapter->Init(s);

	return s;
}

// Release a flood session in the order of the end of SessionMain: leave the hub, free the packet adapter, release
static void HarnessFreeFloodSession(SESSION *s)
{
	DelSession(s->Hub, s);
	s->PacketAdapter->Free(s);
	ReleaseSession(s);
}

// One receive loop of the sender: HARNESS_FLOOD_BATCH broadcast frames into the hub, the end-of-loop call that
// wakes the receivers (cancel list), then every receiver takes its queued frames as its SessionMain would.
// Returns the frames the receivers got
static UINT64 HarnessFloodBatch(SESSION *sender, SESSION **recv, UINT num_recv, const UCHAR *frame, UINT size)
{
	PACKET_ADAPTER *pa = sender->PacketAdapter;
	UINT64 delivered = 0;

	for (UINT i = 0;i < HARNESS_FLOOD_BATCH;i++)
	{
		void *data = Malloc(size);

		Copy(data, frame, size);
		pa->PutPacket(sender, data, size);
	}

	pa->PutPacket(sender, NULL, 0);

	for (UINT i = 0;i < num_recv;i++)
	{
		SESSION *s = recv[i];
		void *data;

		while (s->PacketAdapter->GetNextPacket(s, &data) != 0)
		{
			Free(data);
			delivered++;
		}
	}

	return delivered;
}

// flood_fps_<n>: broadcast frames per second that one session floods to n receiving sessions of the hub
static void HarnessBenchFloodCase(HUB *hub, UINT num_recv)
{
	UCHAR frame[HARNESS_FRAME_SIZE];
	UCHAR mac_sender[6] = {0x02, 0x42, 0x55, 0x52, 0x00, 0xF0};
	UINT64 runs[HARNESS_BENCH_RUNS];
	UINT64 span_ns = (UINT64)HARNESS_BENCH_FLOOD_SPAN * HARNESS_NS_PER_MS;
	UINT64 sent = 0;
	UINT64 delivered = 0;
	char name[MAX_SIZE];

	Format(name, sizeof(name), "flood_fps_%u", num_recv);

	THREAD *thread = NewThread(HarnessFloodIdleThread, NULL);
	SESSION *sender = HarnessNewFloodSession(hub, thread, 0, true);
	SESSION **recv = ZeroMalloc(sizeof(SESSION *) * num_recv);
	for (UINT i = 0;i < num_recv;i++)
	{
		recv[i] = HarnessNewFloodSession(hub, thread, i + 1, false);
	}

	HarnessBuildFrame(frame, sizeof(frame), harness_mac_broadcast, mac_sender, 0x20000 + num_recv);

	// Warm-up: the hub learns the sender MAC address
	HarnessFloodBatch(sender, recv, num_recv, frame, sizeof(frame));

	for (UINT r = 0;r < HARNESS_BENCH_RUNS;r++)
	{
		UINT64 start = HarnessNowNs();
		UINT64 now;
		UINT64 frames = 0;

		do
		{
			delivered += HarnessFloodBatch(sender, recv, num_recv, frame, sizeof(frame));
			frames += HARNESS_FLOOD_BATCH;
			now = HarnessNowNs();
		}
		while ((now - start) < span_ns);

		sent += frames;
		runs[r] = frames * HARNESS_NS_PER_S / (now - start);
	}

	HarnessBenchReport(name, runs, HARNESS_BENCH_RUNS, "frames/s", false);

	// Every frame reaches every receiver: fewer copies means the hub dropped frames and the number is no flood rate
	if (delivered < sent * (UINT64)num_recv)
	{
		Print("BENCH WARNING %s: %I64u of %I64u copies delivered\n", name, delivered, sent * (UINT64)num_recv);
	}

	for (UINT i = 0;i < num_recv;i++)
	{
		HarnessFreeFloodSession(recv[i]);
	}
	Free(recv);
	HarnessFreeFloodSession(sender);

	ReleaseThread(thread);
}

// Thread of the waiting session of flood_fps_logwait: one logged frame into the hub. PacketLog finds the backlog of
// the session at its back-pressure mark and makes this thread wait up to 250 ms for the log writer
static void HarnessLogWaitThread(THREAD *thread, void *param)
{
	HARNESS_LOGWAIT *w = (HARNESS_LOGWAIT *)param;

	if (w == NULL)
	{
		return;
	}

	void *data = Malloc(w->Size);
	Copy(data, w->Frame, w->Size);

	Set(w->Sending);
	w->Session->PacketAdapter->PutPacket(w->Session, data, w->Size);
	w->Session->PacketAdapter->PutPacket(w->Session, NULL, 0);
}

// flood_fps_logwait_<n>: broadcast frames per second that one session floods to n receiving sessions while another
// session of the hub waits for the log writer. That session holds HARNESS_LOGWAIT_BACKLOG queued packet log records;
// each run it sends one logged frame on a thread of its own, and one flood batch starts HARNESS_LOGWAIT_DELAY ms
// later, inside the back-pressure wait of that frame (up to 250 ms). For the case the packet logger of the hub is a
// LOG with a record queue and no log thread, so the backlog stays at the mark
static void HarnessBenchFloodLogWaitCase(HUB *hub, UINT num_recv)
{
	UCHAR frame[HARNESS_FRAME_SIZE];
	UCHAR mac_sender[6] = {0x02, 0x42, 0x55, 0x52, 0x00, 0xF1};
	UCHAR payload[8];
	UINT64 runs[HARNESS_BENCH_RUNS];
	UINT64 sent = 0;
	UINT64 delivered = 0;
	HARNESS_LOGWAIT w;
	HUB_LOG old_setting;
	LOG *old_logger = hub->PacketLogger;
	LOG *capture = ZeroMalloc(sizeof(LOG));
	RECORD *rec;
	UINT num_records = 0;
	char name[MAX_SIZE];
	void *data;

	Format(name, sizeof(name), "flood_fps_logwait_%u", num_recv);

	THREAD *thread = NewThread(HarnessFloodIdleThread, NULL);
	SESSION *sender = HarnessNewFloodSession(hub, thread, 0, true);
	SESSION **recv = ZeroMalloc(sizeof(SESSION *) * num_recv);
	for (UINT i = 0;i < num_recv;i++)
	{
		recv[i] = HarnessNewFloodSession(hub, thread, i + 1, false);
	}

	// The waiting session sends UDP frames from 10.0.0.1 to a MAC address no session has: the hub floods them too
	Zero(&w, sizeof(w));
	Zero(payload, sizeof(payload));
	w.Session = HarnessNewFloodSession(hub, thread, num_recv + 1, false);
	w.Size = HarnessBuildIpFrame(w.Frame, sizeof(w.Frame), IP_PROTO_UDP, HARNESS_IPTABLE_PORT, payload, sizeof(payload));
	w.Sending = NewEvent();

	HarnessBuildFrame(frame, sizeof(frame), harness_mac_broadcast, mac_sender, 0x30000 + num_recv);

	// UDP frames are logged at header level, into a record queue that nothing drains
	Copy(&old_setting, &hub->LogSetting, sizeof(HUB_LOG));
	hub->LogSetting.SavePacketLog = true;
	hub->LogSetting.PacketLogConfig[PACKET_LOG_UDP] = PACKET_LOG_HEADER;
	capture->RecordQueue = NewQueue();
	capture->Event = NewEvent();
	hub->PacketLogger = capture;
	InterlockedExchangeAdd((volatile LONG *)&w.Session->LoggingRecordCount->c, (LONG)HARNESS_LOGWAIT_BACKLOG);

	// Warm-up: the hub learns the sender MAC address
	HarnessFloodBatch(sender, recv, num_recv, frame, sizeof(frame));

	for (UINT r = 0;r < HARNESS_BENCH_RUNS;r++)
	{
		THREAD *t = NewThread(HarnessLogWaitThread, &w);

		Wait(w.Sending, INFINITE);
		SleepThread(HARNESS_LOGWAIT_DELAY);

		UINT64 start = HarnessNowNs();
		delivered += HarnessFloodBatch(sender, recv, num_recv, frame, sizeof(frame));
		UINT64 now = HarnessNowNs();

		sent += HARNESS_FLOOD_BATCH;
		runs[r] = (UINT64)HARNESS_FLOOD_BATCH * HARNESS_NS_PER_S / MAX(now - start, 1);

		WaitThread(t, INFINITE);
		ReleaseThread(t);
	}

	HarnessBenchReport(name, runs, HARNESS_BENCH_RUNS, "frames/s", false);

	// Every receiver gets every flood frame (and the frames of the waiting session on top)
	if (delivered < sent * (UINT64)num_recv)
	{
		Print("BENCH WARNING %s: %I64u of %I64u copies delivered\n", name, delivered, sent * (UINT64)num_recv);
	}

	// One record per logged frame: freeing it gives back its record count and its session reference
	hub->PacketLogger = old_logger;
	while ((rec = GetNext(capture->RecordQueue)) != NULL)
	{
		rec->FreeProc(rec->Data);
		Free(rec);
		num_records++;
	}
	ReleaseQueue(capture->RecordQueue);
	ReleaseEvent(capture->Event);
	Free(capture);
	InterlockedExchangeAdd((volatile LONG *)&w.Session->LoggingRecordCount->c, -(LONG)HARNESS_LOGWAIT_BACKLOG);
	Copy(&hub->LogSetting, &old_setting, sizeof(HUB_LOG));

	if (num_records != HARNESS_BENCH_RUNS)
	{
		Print("BENCH WARNING %s: %u packet log records of the waiting session, %u expected\n", name, num_records,
			HARNESS_BENCH_RUNS);
	}

	// The flood frames queued for the waiting session
	while (w.Session->PacketAdapter->GetNextPacket(w.Session, &data) != 0)
	{
		Free(data);
	}

	HarnessFreeFloodSession(w.Session);
	ReleaseEvent(w.Sending);
	for (UINT i = 0;i < num_recv;i++)
	{
		HarnessFreeFloodSession(recv[i]);
	}
	Free(recv);
	HarnessFreeFloodSession(sender);

	ReleaseThread(thread);
}

// One UDP frame of the ip_table_add cases into the hub through the packet adapter of session s. Its source address
// is 10.x.y.z, x.y.z the low 24 bits of index times an odd number: another address for every index below 2^24, in
// no particular order
static void HarnessIpTableAddFrame(SESSION *s, UCHAR *frame, UINT size, UINT index)
{
	UINT v = (index * 2654435761U) & 0xFFFFFF;
	USHORT sum;

	// Source address (frame bytes 26-29), then the IPv4 header checksum again. The UDP checksum covers the source
	// address: 0 (no checksum) instead
	frame[26] = 10;
	frame[27] = (UCHAR)((v >> 16) & 0xFF);
	frame[28] = (UCHAR)((v >> 8) & 0xFF);
	frame[29] = (UCHAR)(v & 0xFF);
	frame[24] = 0;
	frame[25] = 0;
	sum = IpChecksum(frame + 14, 20);
	Copy(frame + 24, &sum, sizeof(USHORT));
	frame[40] = 0;
	frame[41] = 0;

	void *data = Malloc(size);
	Copy(data, frame, size);
	s->PacketAdapter->PutPacket(s, data, size);
}

// ip_table_add_<n>: frames per second from new source addresses into a hub IP table that holds n live entries,
// through the hub packet adapter of one session of the flood hub (HubPaPutPacket, StorePacket, IpTableAddEntry).
// The frames go to a MAC address no session has and the hub has no other session, so the flood loop has no
// destination. Each run sends HARNESS_IPTABLE_ADD_BATCH new addresses
static void HarnessBenchIpTableAdd(HUB *hub, UINT num)
{
	UCHAR frame[128];
	UCHAR payload[8];
	UINT64 runs[HARNESS_BENCH_RUNS];
	UINT index = 0;
	char name[MAX_SIZE];

	Format(name, sizeof(name), "ip_table_add_%u", num);

	Zero(payload, sizeof(payload));
	UINT size = HarnessBuildIpFrame(frame, sizeof(frame), IP_PROTO_UDP, HARNESS_IPTABLE_PORT, payload, sizeof(payload));

	// A sender session: the broadcast storm guard is off, which would keep one storm list entry per address
	THREAD *thread = NewThread(HarnessFloodIdleThread, NULL);
	SESSION *s = HarnessNewFloodSession(hub, thread, 0, true);

	// The n entries that the table holds before the measured runs
	while (index < num)
	{
		HarnessIpTableAddFrame(s, frame, size, index++);
	}

	for (UINT r = 0;r < HARNESS_BENCH_RUNS;r++)
	{
		UINT64 start = HarnessNowNs();

		for (UINT i = 0;i < HARNESS_IPTABLE_ADD_BATCH;i++)
		{
			HarnessIpTableAddFrame(s, frame, size, index++);
		}

		UINT64 now = HarnessNowNs();
		runs[r] = (UINT64)HARNESS_IPTABLE_ADD_BATCH * HARNESS_NS_PER_S / MAX(now - start, 1);
	}

	HarnessBenchReport(name, runs, HARNESS_BENCH_RUNS, "frames/s", false);

	// Every frame added one entry: none expired and none was evicted (MAX_IP_TABLES is far away)
	HubLockTables(hub);
	UINT num_entries = HubIpTableNum(hub);
	HubUnlockTables(hub);

	if (num_entries != index)
	{
		Print("BENCH WARNING %s: %u IP table entries after %u new source addresses\n", name, num_entries, index);
	}

	HarnessFreeFloodSession(s);
	ReleaseThread(thread);
}

////////////////////////////
// Packet log golden (FND-101)

// The packet log line of PacketLogParseProc and the packet log level of CalcPacketLoggingLevel for fixed frames
// (ARP, IPv4 and IPv6 with TCP, HTTP, UDP, DNS, IKE, ICMP and an unknown protocol, DHCP). The frames are parsed as
// the hub parses them with the packet log on, and the text is compared with packetlog.txt of the golden directory.
// It needs no server: the port names come from a list of three services of its own

#define	HARNESS_PLOG_FILE			"packetlog.txt"
#define	HARNESS_PLOG_FRAME			256					// Largest frame
#define	HARNESS_PLOG_L3				34					// Ethernet and IPv4 header of a frame of HarnessBuildIpFrame
#define	HARNESS_PLOG_HOST			"example.test"
#define	HARNESS_PLOG_HTTP			"GET /index.html HTTP/1.1\r\nHost: " HARNESS_PLOG_HOST "\r\nUser-Agent: ranz-test/1.0\r\n\r\n"

// Frame kinds
#define	HARNESS_PLOG_ARP_REQUEST	0
#define	HARNESS_PLOG_ARP_REPLY		1
#define	HARNESS_PLOG_ICMP			2					// ICMPv4 echo request
#define	HARNESS_PLOG_OTHER			3					// Protocol 47, no parser
#define	HARNESS_PLOG_TCP_SYN		4
#define	HARNESS_PLOG_TCP_DATA		5
#define	HARNESS_PLOG_HTTP_GET		6
#define	HARNESS_PLOG_UDP			7
#define	HARNESS_PLOG_DNS			8
#define	HARNESS_PLOG_IKE			9
#define	HARNESS_PLOG_DHCP			10
#define	HARNESS_PLOG_ICMP6_ECHO		11
#define	HARNESS_PLOG_ICMP6_RS		12

typedef struct HARNESS_PLOG_CASE
{
	char *Name;
	UINT Kind;
	bool V6;					// IPv6 frame, otherwise IPv4
	bool Data;					// The record holds the frame data (level ALL)
	bool Physical;				// The record holds the physical IP addresses
} HARNESS_PLOG_CASE;

static HARNESS_PLOG_CASE harness_plog_cases[] =
{
	{"arp-request", HARNESS_PLOG_ARP_REQUEST, false, true, false},
	{"arp-reply", HARNESS_PLOG_ARP_REPLY, false, false, false},
	{"icmp4-echo", HARNESS_PLOG_ICMP, false, false, false},
	{"ip4-other", HARNESS_PLOG_OTHER, false, false, false},
	{"tcp4-syn", HARNESS_PLOG_TCP_SYN, false, false, false},
	{"tcp4-data", HARNESS_PLOG_TCP_DATA, false, false, true},
	{"tcp4-http", HARNESS_PLOG_HTTP_GET, false, false, false},
	{"udp4", HARNESS_PLOG_UDP, false, false, false},
	{"dns4", HARNESS_PLOG_DNS, false, false, false},
	{"ike4", HARNESS_PLOG_IKE, false, false, false},
	{"dhcp4", HARNESS_PLOG_DHCP, false, false, false},
	{"icmp6-echo", HARNESS_PLOG_ICMP6_ECHO, true, false, false},
	{"icmp6-rs", HARNESS_PLOG_ICMP6_RS, true, false, false},
	{"ip6-other", HARNESS_PLOG_OTHER, true, false, false},
	{"tcp6-syn", HARNESS_PLOG_TCP_SYN, true, false, false},
	{"tcp6-data", HARNESS_PLOG_TCP_DATA, true, false, false},
	{"tcp6-http", HARNESS_PLOG_HTTP_GET, true, false, false},
	{"udp6", HARNESS_PLOG_UDP, true, false, false},
	{"dns6", HARNESS_PLOG_DNS, true, false, false},
	{"ike6", HARNESS_PLOG_IKE, true, false, false},
};

// Order of the services of GetSvcName: by port, then TCP before UDP
static int HarnessPlogCompareSvc(void *p1, void *p2)
{
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}

	NETSVC *n1 = *(NETSVC **)p1;
	NETSVC *n2 = *(NETSVC **)p2;

	if (n1 == NULL || n2 == NULL)
	{
		return 0;
	}

	if (n1->Port != n2->Port)
	{
		return (n1->Port > n2->Port ? 1 : -1);
	}

	if (n1->Udp != n2->Udp)
	{
		return (n1->Udp > n2->Udp ? 1 : -1);
	}

	return 0;
}

static void HarnessPlogAddSvc(CEDAR *cedar, bool udp, UINT port, char *name)
{
	NETSVC *n = ZeroMalloc(sizeof(NETSVC));

	n->Udp = udp;
	n->Port = port;
	n->Name = name;

	Add(cedar->NetSvcList, n);
}

// ARP frame of test session A for 10.0.0.2: a request to everyone, or a reply to B
static UINT HarnessPlogBuildArp(UCHAR *buf, bool request)
{
	UCHAR *arp = buf + 14;

	Zero(buf, 42);

	Copy(buf, (request ? harness_mac_broadcast : harness_mac_b), 6);
	Copy(buf + 6, harness_mac_a, 6);
	buf[12] = 0x08;								// ARP
	buf[13] = 0x06;

	arp[1] = 0x01;								// Ethernet
	arp[2] = 0x08;								// IPv4
	arp[4] = 6;									// Hardware address size
	arp[5] = 4;									// Protocol address size
	arp[7] = (request ? ARP_OPERATION_REQUEST : ARP_OPERATION_RESPONSE);
	Copy(arp + 8, harness_mac_a, 6);			// Sender 10.0.0.1
	arp[14] = 10;
	arp[17] = 1;
	if (request == false)
	{
		Copy(arp + 18, harness_mac_b, 6);
	}
	arp[24] = 10;								// Target 10.0.0.2
	arp[27] = 2;

	return 42;
}

// Ethernet frame from A to B around an L4 segment: IPv4 10.0.0.1 to 10.0.0.2 or IPv6 fe80::1 to fe80::2, no
// checksum (the parser does not check one). Returns the size, 0 if it does not fit
static UINT HarnessPlogWrap(UCHAR *buf, UINT buf_size, bool v6, UCHAR protocol, const UCHAR *l4, UINT l4_size)
{
	UINT ip_header = (v6 ? 40 : 20);
	UINT ip_size = ip_header + l4_size;
	UINT size = 14 + ip_size;
	UCHAR *ip = buf + 14;

	if (size > buf_size)
	{
		return 0;
	}

	Zero(buf, size);

	Copy(buf, harness_mac_b, 6);
	Copy(buf + 6, harness_mac_a, 6);

	if (v6 == false)
	{
		buf[12] = 0x08;							// IPv4
		buf[13] = 0x00;
		ip[0] = 0x45;							// Version 4, 20-byte header
		ip[2] = (UCHAR)(ip_size >> 8);
		ip[3] = (UCHAR)(ip_size & 0xFF);
		ip[8] = 64;								// TTL
		ip[9] = protocol;
		ip[12] = 10;
		ip[15] = 1;
		ip[16] = 10;
		ip[19] = 2;
	}
	else
	{
		buf[12] = 0x86;							// IPv6
		buf[13] = 0xDD;
		ip[0] = 0x60;							// Version 6
		ip[4] = (UCHAR)(l4_size >> 8);
		ip[5] = (UCHAR)(l4_size & 0xFF);
		ip[6] = protocol;						// Next header
		ip[7] = 64;								// Hop limit
		ip[8] = 0xFE;
		ip[9] = 0x80;
		ip[23] = 1;
		ip[24] = 0xFE;
		ip[25] = 0x80;
		ip[39] = 2;
	}

	Copy(ip + ip_header, l4, l4_size);

	return size;
}

// IPv4 frame of a TCP or UDP kind: HarnessBuildIpFrame sets the ports and the TCP header
static UINT HarnessPlogBuildL4Frame(UINT kind, UCHAR *buf, UINT buf_size)
{
	UCHAR payload[96];
	UINT payload_size = 0;
	UCHAR protocol = IP_PROTO_UDP;
	USHORT dst_port = 40002;

	Zero(payload, sizeof(payload));

	switch (kind)
	{
	case HARNESS_PLOG_TCP_SYN:
		protocol = IP_PROTO_TCP;
		dst_port = 40001;
		break;

	case HARNESS_PLOG_TCP_DATA:
		protocol = IP_PROTO_TCP;
		dst_port = 40001;
		Copy(payload, "ranz", 4);
		payload_size = 4;
		break;

	case HARNESS_PLOG_HTTP_GET:
		protocol = IP_PROTO_TCP;
		dst_port = 80;
		payload_size = StrLen(HARNESS_PLOG_HTTP);
		Copy(payload, HARNESS_PLOG_HTTP, payload_size);
		break;

	case HARNESS_PLOG_UDP:
		Copy(payload, "ranz", 4);
		payload_size = 4;
		break;

	case HARNESS_PLOG_DNS:
		dst_port = 53;
		payload_size = HarnessBuildDnsQuery(payload, sizeof(payload), HARNESS_PLOG_HOST);
		break;

	case HARNESS_PLOG_IKE:
		// Initiator cookie 0x0102030405060708, no responder cookie, main mode, 28 bytes
		dst_port = 500;
		payload[0] = 1;
		payload[1] = 2;
		payload[2] = 3;
		payload[3] = 4;
		payload[4] = 5;
		payload[5] = 6;
		payload[6] = 7;
		payload[7] = 8;
		payload[16] = 1;						// Next payload
		payload[17] = 0x10;						// Version
		payload[18] = IKE_EXCHANGE_TYPE_MAIN;
		payload[27] = 28;						// Message size
		payload_size = 28;
		break;

	case HARNESS_PLOG_DHCP:
		// Request from port 68 to port 67 with the transaction id 256: the 44 bytes of DHCPV4_HEADER
		dst_port = 67;
		payload[0] = 1;
		payload[6] = 1;
		payload_size = 44;
		break;
	}

	UINT size = HarnessBuildIpFrame(buf, buf_size, protocol, dst_port, payload, payload_size);

	if (size != 0 && kind == HARNESS_PLOG_TCP_SYN)
	{
		buf[HARNESS_PLOG_L3 + 13] = TCP_SYN;	// Flags: SYN instead of PSH and ACK
	}

	if (size != 0 && kind == HARNESS_PLOG_DHCP)
	{
		buf[HARNESS_PLOG_L3] = 0x00;			// Source port 68
		buf[HARNESS_PLOG_L3 + 1] = 0x44;
	}

	return size;
}

// Frame of a case. Returns its size, 0 if it does not fit
static UINT HarnessPlogBuild(HARNESS_PLOG_CASE *c, UCHAR *buf, UINT buf_size)
{
	UCHAR frame[HARNESS_PLOG_FRAME];
	UCHAR l4[12];
	UINT l4_size = 8;
	UCHAR protocol = 0;
	UINT size;

	Zero(l4, sizeof(l4));

	switch (c->Kind)
	{
	case HARNESS_PLOG_ARP_REQUEST:
	case HARNESS_PLOG_ARP_REPLY:
		if (buf_size < 42)
		{
			return 0;
		}

		return HarnessPlogBuildArp(buf, c->Kind == HARNESS_PLOG_ARP_REQUEST);

	case HARNESS_PLOG_ICMP:
		protocol = IP_PROTO_ICMPV4;
		l4[0] = ICMP_TYPE_ECHO_REQUEST;
		l4[5] = 1;
		l4[7] = 2;
		break;

	case HARNESS_PLOG_OTHER:
		protocol = 47;
		break;

	case HARNESS_PLOG_ICMP6_ECHO:
		protocol = IP_PROTO_ICMPV6;
		l4[0] = ICMPV6_TYPE_ECHO_REQUEST;
		l4[5] = 1;
		l4[7] = 2;
		Copy(l4 + 8, "data", 4);
		l4_size = 12;
		break;

	case HARNESS_PLOG_ICMP6_RS:
		protocol = IP_PROTO_ICMPV6;
		l4[0] = ICMPV6_TYPE_ROUTER_SOLICIATION;
		break;

	default:
		size = HarnessPlogBuildL4Frame(c->Kind, frame, sizeof(frame));

		if (size == 0)
		{
			return 0;
		}

		if (c->V6 == false)
		{
			if (size > buf_size)
			{
				return 0;
			}

			Copy(buf, frame, size);

			return size;
		}

		return HarnessPlogWrap(buf, buf_size, true, frame[14 + 9], frame + HARNESS_PLOG_L3, size - HARNESS_PLOG_L3);
	}

	return HarnessPlogWrap(buf, buf_size, c->V6, protocol, l4, l4_size);
}

// The packet log line of a frame as PacketLog makes the record: a clone of the parsed frame (with its data for a
// case of level ALL), the session name of A and no destination session. NULL if the frame does not parse
static char *HarnessPlogLine(HARNESS_PLOG_CASE *c, CEDAR *cedar, UCHAR *frame, UINT size)
{
	PKT *p = ParsePacketEx5(frame, size, false, 0, true, false, false, false);
	RECORD rec;

	if (p == NULL)
	{
		return NULL;
	}

	PACKET_LOG *pl = ZeroMalloc(sizeof(PACKET_LOG));
	pl->Cedar = cedar;
	pl->Packet = ClonePacket(p, c->Data);
	pl->SrcSessionName = CopyStr("sess-a");
	pl->DestSessionName = CopyStr("");

	if (c->Physical)
	{
		pl->WritePhysicalIP = true;
		StrCpy(pl->SrcPhysicalIP, sizeof(pl->SrcPhysicalIP), "192.0.2.1");
		StrCpy(pl->DestPhysicalIP, sizeof(pl->DestPhysicalIP), "192.0.2.2");
	}

	FreePacket(p);

	Zero(&rec, sizeof(rec));
	rec.Data = pl;

	// The parse proc releases the record
	char *ret = PacketLogParseProc(&rec);

	return ret;
}

static void HarnessPlogWriteLine(BUF *b, const char *name, const char *sep, const char *text)
{
	WriteBuf(b, name, StrLen(name));
	WriteBuf(b, sep, StrLen(sep));
	WriteBuf(b, text, StrLen(text));
	WriteBuf(b, "\n", 1);
}

// The packet log lines and the packet log levels of all cases, compared with packetlog.txt
static void HarnessPacketLogGolden(HARNESS *h)
{
	char out_dir[MAX_SIZE];
	char golden_dir[MAX_SIZE];
	char tmp[MAX_SIZE];
	bool update;
	CEDAR *cedar = ZeroMalloc(sizeof(CEDAR));
	HUB_LOG *g = ZeroMalloc(sizeof(HUB_LOG));
	BUF *b = NewBuf();

	Print("[packetlog]\n");

	HarnessGetFamilyDirs("harness", out_dir, sizeof(out_dir), golden_dir, sizeof(golden_dir), &update);
	MakeDirEx(out_dir);

	// Fixed machine-readable mode line: CI fails a run that records the golden file in place of comparing it
	Print("HARNESS GOLDEN MODE %s\n", update ? "update" : "compare");
	Print("  golden directory: %s (%s)\n", golden_dir,
		update ? "update mode: missing or empty, or RANZ_UPDATE_GOLDEN=1" : "compare mode");
	Print("  output directory: %s\n", out_dir);

	cedar->NetSvcList = NewList(HarnessPlogCompareSvc);
	HarnessPlogAddSvc(cedar, true, 53, "domain");
	HarnessPlogAddSvc(cedar, true, 500, "isakmp");
	HarnessPlogAddSvc(cedar, false, 80, "http");

	HarnessPlogWriteLine(b, "# packet log lines (PacketLogParseProc): session sess-a, no destination session", "", "");

	for (UINT i = 0;i < sizeof(harness_plog_cases) / sizeof(harness_plog_cases[0]);i++)
	{
		HARNESS_PLOG_CASE *c = &harness_plog_cases[i];
		UCHAR frame[HARNESS_PLOG_FRAME];
		UINT size = HarnessPlogBuild(c, frame, sizeof(frame));
		char *line = (size != 0 ? HarnessPlogLine(c, cedar, frame, size) : NULL);

		if (line == NULL)
		{
			Format(tmp, sizeof(tmp), "packet log case %s: the frame is built and parsed", c->Name);
			HarnessCheck(h, false, tmp);
			continue;
		}

		HarnessPlogWriteLine(b, c->Name, ": ", line);
		Free(line);
	}

	HarnessPlogWriteLine(b, "# packet log levels (CalcPacketLoggingLevel), the level when only one entry is ALL: "
		"TCP_CONN TCP DHCP UDP ICMP IP ARP ETHERNET", "", "");

	for (UINT i = 0;i < sizeof(harness_plog_cases) / sizeof(harness_plog_cases[0]);i++)
	{
		HARNESS_PLOG_CASE *c = &harness_plog_cases[i];
		UCHAR frame[HARNESS_PLOG_FRAME];
		UINT size = HarnessPlogBuild(c, frame, sizeof(frame));
		PKT *p = (size != 0 ? ParsePacketEx5(frame, size, false, 0, true, false, false, false) : NULL);

		if (p == NULL)
		{
			continue;
		}

		tmp[0] = 0;

		for (UINT j = PACKET_LOG_TCP_CONN;j <= PACKET_LOG_ETHERNET;j++)
		{
			char num[16];

			Zero(g->PacketLogConfig, sizeof(g->PacketLogConfig));
			g->PacketLogConfig[j] = PACKET_LOG_ALL;

			Format(num, sizeof(num), " %u", CalcPacketLoggingLevel(g, p));
			StrCat(tmp, sizeof(tmp), num);
		}

		HarnessPlogWriteLine(b, c->Name, "", tmp);
		FreePacket(p);
	}

	char *actual = HarnessBufToStr(b);
	HarnessCompareGolden(h, out_dir, golden_dir, HARNESS_PLOG_FILE, actual, update);

	Free(actual);
	FreeBuf(b);
	Free(g);

	for (UINT i = 0;i < LIST_NUM(cedar->NetSvcList);i++)
	{
		Free(LIST_DATA(cedar->NetSvcList, i));
	}

	ReleaseList(cedar->NetSvcList);
	Free(cedar);
}

// InsertUnicodeRecord queues the UTF-8 text of the line itself (one allocation): a CR and an LF become '?', the other
// characters stay. The LOG has a record queue and no log thread, so the test reads the record from the queue
static void HarnessLogRecordCheck(HARNESS *h)
{
	LOG *g = ZeroMalloc(sizeof(LOG));
	RECORD *rec;

	Print("[logrecord]\n");

	g->RecordQueue = NewQueue();
	g->Event = NewEvent();

	InsertUnicodeRecord(g, L"a\r\nb\x00e9");

	LockQueue(g->RecordQueue);
	{
		rec = GetNext(g->RecordQueue);
	}
	UnlockQueue(g->RecordQueue);

	bool ok = (rec != NULL && rec->Data != NULL && StrCmp((char *)rec->Data, "a??b\xC3\xA9") == 0);
	HarnessCheck(h, ok, "log record: InsertUnicodeRecord queues the UTF-8 line with control characters mapped to '?'");

	if (rec != NULL)
	{
		Free(rec->Data);
		Free(rec);
	}

	ReleaseQueue(g->RecordQueue);
	ReleaseEvent(g->Event);
	Free(g);
}

// "ptrkey" (FND-84 #127): POINTER_TO_KEY (HashPtrToUINT) keys a block by its address. It hashed the first
// pointer-size bytes the block holds instead, so blocks with the same leading bytes got the same key and the key
// of a block changed with its content. The admin RPC of the retired server handed these keys out as ids and found
// the entry again by them; its case of the access list went with it (CORE-S8-3, #577).
#define	PTRKEY_BLOCK				64					// Bytes of the blocks of the key checks

// Two blocks with equal content: a key each, found again by it, unchanged when the content changes
static void PtrKeyBlocks(HARNESS *h)
{
	UCHAR *a = ZeroMalloc(PTRKEY_BLOCK);
	UCHAR *b = ZeroMalloc(PTRKEY_BLOCK);
	LIST *o = NewListFast(NULL);
	UINT key_a = POINTER_TO_KEY(a);
	UINT key_b = POINTER_TO_KEY(b);

	HarnessCheck(h, key_a != 0 && key_b != 0, "two zeroed blocks get a key");
	HarnessCheck(h, key_a != key_b, "two blocks with equal content get different keys");

	Add(o, a);
	Add(o, b);
	HarnessCheck(h, ListKeyToPointer(o, key_a) == a && ListKeyToPointer(o, key_b) == b,
		"ListKeyToPointer finds each of the two blocks by its own key");

	for (UINT i = 0;i < PTRKEY_BLOCK;i++)
	{
		a[i] = (UCHAR)(0x5A + i);
	}
	HarnessCheck(h, POINTER_TO_KEY(a) == key_a, "the key of a block stays the same when its content changes");

	ReleaseList(o);
	Free(b);
	Free(a);
}

// Pack with HARNESS_PACK_NAMES distinct element names (integers and strings), added in a non-sorted order
static PACK *HarnessNewNamesPack(const HARNESS_PACK_BENCH *b)
{
	PACK *p = NewPack();

	for (UINT i = 0;i < HARNESS_PACK_NAMES;i++)
	{
		if ((i % 2) == 0)
		{
			PackAddInt(p, b->Names[i], i);
		}
		else
		{
			PackAddStr(p, b->Names[i], b->Names[i]);
		}
	}

	return p;
}

// Encode the many-names Pack: element adds -> BUF
static bool HarnessOpEncodeNames(void *param)
{
	HARNESS_PACK_BENCH *b = (HARNESS_PACK_BENCH *)param;
	PACK *p = HarnessNewNamesPack(b);
	BUF *buf = PackToBuf(p);

	FreePack(p);
	FreeBuf(buf);

	return true;
}

// Decode a Pack: BUF -> PACK
static bool HarnessOpDecodePack(void *param)
{
	HARNESS_PACK_BENCH *b = (HARNESS_PACK_BENCH *)param;

	SeekBufToBegin(b->Buf);
	PACK *p = BufToPack(b->Buf);
	if (p == NULL)
	{
		return false;
	}

	FreePack(p);

	return true;
}

// pack_<encode|decode>_names_<n>: a Pack with many distinct element names (every new name is looked up first)
static void HarnessBenchPackNames()
{
	HARNESS_PACK_BENCH b;
	bool ok = false;
	char name[MAX_SIZE];

	Zero(&b, sizeof(b));
	b.Names = ZeroMalloc(sizeof(char *) * HARNESS_PACK_NAMES);
	for (UINT i = 0;i < HARNESS_PACK_NAMES;i++)
	{
		char tmp[MAX_ELEMENT_NAME_LEN + 1];

		// 7919 is a prime: (i * 7919) % n takes every value below n once, in a non-sorted order
		Format(tmp, sizeof(tmp), "bench_item_%03u", (i * 7919) % HARNESS_PACK_NAMES);
		b.Names[i] = CopyStr(tmp);
	}

	PACK *p = HarnessNewNamesPack(&b);
	b.Buf = PackToBuf(p);
	FreePack(p);

	Print("BENCH pack_names_%u_bytes %u bytes\n", HARNESS_PACK_NAMES, b.Buf->Size);

	SeekBufToBegin(b.Buf);
	p = BufToPack(b.Buf);
	if (p != NULL)
	{
		ok = (LIST_NUM(p->elements) == HARNESS_PACK_NAMES && PackGetInt(p, b.Names[2]) == 2);
		FreePack(p);
	}

	Format(name, sizeof(name), "pack_encode_names_%u", HARNESS_PACK_NAMES);
	HarnessBenchOps(name, HarnessOpEncodeNames, &b, HARNESS_BENCH_PACK_SPAN, 1);

	Format(name, sizeof(name), "pack_decode_names_%u", HARNESS_PACK_NAMES);
	if (ok)
	{
		HarnessBenchOps(name, HarnessOpDecodePack, &b, HARNESS_BENCH_PACK_SPAN, 1);
	}
	else
	{
		Print("BENCH WARNING %s: the decoded Pack does not hold the encoded names, case skipped\n", name);
	}

	FreeBuf(b.Buf);
	for (UINT i = 0;i < HARNESS_PACK_NAMES;i++)
	{
		Free(b.Names[i]);
	}
	Free(b.Names);
}

////////////////////////////
// ParsePacket and IP table benchmarks

// IPv4 frame from 10.0.0.1 (harness_mac_a) to 10.0.0.2 (harness_mac_b): a TCP header (PSH+ACK) or a UDP header
// from port 49152, then the payload, with valid IPv4, TCP and UDP checksums. Returns the size, 0 if it does not fit
static UINT HarnessBuildIpFrame(UCHAR *buf, UINT buf_size, UCHAR protocol, USHORT dst_port, UCHAR *payload, UINT payload_size)
{
	UINT l4_header = (protocol == IP_PROTO_TCP ? 20 : 8);
	UINT l4_size = l4_header + payload_size;
	UINT ip_size = 20 + l4_size;
	UINT size = 14 + ip_size;
	UCHAR *ip = buf + 14;
	UCHAR *l4 = ip + 20;
	UINT src_ip, dst_ip;

	if (size > buf_size)
	{
		return 0;
	}

	Zero(buf, size);

	Copy(buf, harness_mac_b, 6);
	Copy(buf + 6, harness_mac_a, 6);
	buf[12] = 0x08;								// IPv4
	buf[13] = 0x00;

	ip[0] = 0x45;								// Version 4, 20-byte header
	ip[2] = (UCHAR)(ip_size >> 8);
	ip[3] = (UCHAR)(ip_size & 0xFF);
	ip[4] = 0x12;								// Identification
	ip[5] = 0x34;
	ip[6] = 0x40;								// Don't fragment
	ip[8] = 64;									// TTL
	ip[9] = protocol;
	ip[12] = 10;
	ip[15] = 1;
	ip[16] = 10;
	ip[19] = 2;
	USHORT sum = IpChecksum(ip, 20);
	Copy(ip + 10, &sum, sizeof(USHORT));

	l4[0] = 0xC0;								// Source port 49152
	l4[2] = (UCHAR)(dst_port >> 8);
	l4[3] = (UCHAR)(dst_port & 0xFF);

	if (protocol == IP_PROTO_TCP)
	{
		l4[5] = 0x01;							// Sequence number
		l4[9] = 0x02;							// Acknowledgment number
		l4[12] = 0x50;							// 20-byte header
		l4[13] = TCP_PSH | TCP_ACK;
		l4[14] = 0xFA;							// Window 64240
		l4[15] = 0xF0;
	}
	else
	{
		l4[4] = (UCHAR)(l4_size >> 8);
		l4[5] = (UCHAR)(l4_size & 0xFF);
	}

	Copy(l4 + l4_header, payload, payload_size);

	Copy(&src_ip, ip + 12, sizeof(UINT));
	Copy(&dst_ip, ip + 16, sizeof(UINT));
	sum = CalcChecksumForIPv4(src_ip, dst_ip, protocol, l4, l4_size, 0);
	Copy(l4 + (protocol == IP_PROTO_TCP ? 16 : 6), &sum, sizeof(USHORT));

	return size;
}

// TLS ClientHello with one cipher suite and only the server_name extension (the part GetSniNameFromSslPacket reads).
// Returns the size, 0 if it does not fit
static UINT HarnessBuildClientHello(UCHAR *buf, UINT buf_size, const char *host)
{
	UINT name_len = StrLen(host);
	UINT ext_data = 2 + 1 + 2 + name_len;		// server_name_list length, name type, name length, name
	UINT ext_len = 4 + ext_data;				// Extension type and length, then its data
	UINT body = 43 + ext_len;					// Version 2, random 32, session id 1, ciphers 4, compression 2, extensions length 2
	UINT size = 5 + 4 + body;					// Record header, handshake header, ClientHello body
	UCHAR *p = buf;

	if (size > buf_size)
	{
		return 0;
	}

	*p++ = 0x16;								// Handshake record, record version TLS 1.0
	*p++ = 0x03;
	*p++ = 0x01;
	*p++ = (UCHAR)((4 + body) >> 8);
	*p++ = (UCHAR)((4 + body) & 0xFF);
	*p++ = 0x01;								// ClientHello, 24-bit length
	*p++ = 0x00;
	*p++ = (UCHAR)(body >> 8);
	*p++ = (UCHAR)(body & 0xFF);
	*p++ = 0x03;								// Client version TLS 1.2
	*p++ = 0x03;
	for (UINT i = 0;i < 32;i++)
	{
		*p++ = (UCHAR)(i * 11 + 1);				// Random
	}
	*p++ = 0x00;								// No session id
	*p++ = 0x00;								// One cipher suite: TLS_AES_128_GCM_SHA256
	*p++ = 0x02;
	*p++ = 0x13;
	*p++ = 0x01;
	*p++ = 0x01;								// Null compression only
	*p++ = 0x00;
	*p++ = (UCHAR)(ext_len >> 8);
	*p++ = (UCHAR)(ext_len & 0xFF);
	*p++ = 0x00;								// server_name extension
	*p++ = 0x00;
	*p++ = (UCHAR)(ext_data >> 8);
	*p++ = (UCHAR)(ext_data & 0xFF);
	*p++ = (UCHAR)((3 + name_len) >> 8);
	*p++ = (UCHAR)((3 + name_len) & 0xFF);
	*p++ = 0x00;								// host_name
	*p++ = (UCHAR)(name_len >> 8);
	*p++ = (UCHAR)(name_len & 0xFF);
	Copy(p, host, name_len);
	p += name_len;

	return (UINT)(p - buf);
}

// DNS query (recursion desired, one question, type A, class IN). Returns the size, 0 if it does not fit
static UINT HarnessBuildDnsQuery(UCHAR *buf, UINT buf_size, char *host)
{
	UINT len = StrLen(host);
	UINT start = 0;

	if ((12 + len + 2 + 4) > buf_size)
	{
		return 0;
	}

	Zero(buf, 12);
	buf[0] = 0x52;								// Transaction id
	buf[1] = 0x41;
	buf[2] = 0x01;								// Recursion desired
	buf[5] = 0x01;								// One question

	UCHAR *p = buf + 12;
	for (UINT i = 0;i <= len;i++)
	{
		if (i == len || host[i] == '.')
		{
			*p++ = (UCHAR)(i - start);
			Copy(p, host + start, i - start);
			p += i - start;
			start = i + 1;
		}
	}
	*p++ = 0x00;								// Root label
	*p++ = 0x00;								// Type A
	*p++ = 0x01;
	*p++ = 0x00;								// Class IN
	*p++ = 0x01;

	return (UINT)(p - buf);
}

// Parse a frame as HubPaPutPacket does with the default hub options: IP and HTTP parsing, BPDU bridge id,
// checksum correction (the frames have valid checksums, so the buffer is not changed). no_log: the hub packet
// log is off, so HTTP, TLS SNI and DNS are not parsed
static PKT *HarnessParseLikeHub(HARNESS_PARSE_FRAME *f, bool no_log)
{
	return ParsePacketEx5(f->Data, f->Size, false, 0, true, no_log, true, no_log);
}

// The parser reached the layer the frame was built for (no_log: and stopped before layer 7)
static bool HarnessParsedAsBuilt(const HARNESS_PARSE_FRAME *f, const PKT *p, bool no_log)
{
	if (p == NULL)
	{
		return false;
	}

	if (StrCmp(f->Kind, "tcp") == 0 || (no_log && (StrCmp(f->Kind, "http") == 0 || StrCmp(f->Kind, "tls") == 0)))
	{
		return (p->TypeL4 == L4_TCP && p->HttpLog == NULL);
	}

	if (no_log && StrCmp(f->Kind, "dns") == 0)
	{
		return (p->TypeL4 == L4_UDP && p->TypeL7 == L7_UNKNOWN);
	}

	if (StrCmp(f->Kind, "http") == 0)
	{
		return (p->HttpLog != NULL && p->HttpLog->IsSsl == false && StrCmp(p->HttpLog->Hostname, HARNESS_BENCH_HOST) == 0);
	}

	if (StrCmp(f->Kind, "tls") == 0)
	{
		return (p->HttpLog != NULL && p->HttpLog->IsSsl && StrCmp(p->HttpLog->Hostname, HARNESS_BENCH_HOST) == 0);
	}

	if (StrCmp(f->Kind, "dns") == 0)
	{
		return (p->TypeL7 == L7_DNS && StrCmp(p->DnsQueryHost, HARNESS_BENCH_HOST) == 0);
	}

	return true;
}

// Parse the frame of a single-frame case
static bool HarnessOpParseOne(void *param)
{
	HARNESS_PARSE_BENCH *b = (HARNESS_PARSE_BENCH *)param;
	PKT *p = HarnessParseLikeHub(&b->Frames[b->Current], b->NoLog);

	if (p == NULL)
	{
		return false;
	}

	FreePacket(p);

	return true;
}

// Parse the next frame of the mix, in turn
static bool HarnessOpParseMix(void *param)
{
	HARNESS_PARSE_BENCH *b = (HARNESS_PARSE_BENCH *)param;
	PKT *p = HarnessParseLikeHub(&b->Frames[b->Next], b->NoLog);

	b->Next = (b->Next + 1) % HARNESS_NUM_PARSE_FRAMES;

	if (p == NULL)
	{
		return false;
	}

	FreePacket(p);

	return true;
}

// parse_packet_<kind>: ParsePacket per frame kind, then over the mix of all kinds in turn.
// l2: non-IP frame; tcp: TCP data without a layer 7 parser; http: request to TCP 80; tls: ClientHello with SNI
// to TCP 443; dns: query to UDP 53. The _nolog cases parse the same frames as with the hub packet log off
static void HarnessBenchParse()
{
	HARNESS_PARSE_BENCH b;
	UCHAR payload[HARNESS_PARSE_FRAME_MAX];
	char *http = "GET /index.html HTTP/1.1\r\nHost: " HARNESS_BENCH_HOST "\r\nUser-Agent: ranz-bench/1.0\r\nAccept: */*\r\n\r\n";
	bool ok;
	char name[MAX_SIZE];

	Zero(&b, sizeof(b));

	HARNESS_PARSE_FRAME *f = &b.Frames[0];
	f->Kind = "l2";
	f->Size = HARNESS_FRAME_SIZE;
	HarnessBuildFrame(f->Data, f->Size, harness_mac_b, harness_mac_a, 1);

	f = &b.Frames[1];
	f->Kind = "tcp";
	for (UINT i = 0;i < 64;i++)
	{
		payload[i] = (UCHAR)(i * 3);
	}
	f->Size = HarnessBuildIpFrame(f->Data, sizeof(f->Data), IP_PROTO_TCP, 5001, payload, 64);

	f = &b.Frames[2];
	f->Kind = "http";
	f->Size = HarnessBuildIpFrame(f->Data, sizeof(f->Data), IP_PROTO_TCP, 80, (UCHAR *)http, StrLen(http));

	f = &b.Frames[3];
	f->Kind = "tls";
	UINT size = HarnessBuildClientHello(payload, sizeof(payload), HARNESS_BENCH_HOST);
	f->Size = HarnessBuildIpFrame(f->Data, sizeof(f->Data), IP_PROTO_TCP, 443, payload, size);

	f = &b.Frames[4];
	f->Kind = "dns";
	size = HarnessBuildDnsQuery(payload, sizeof(payload), HARNESS_BENCH_HOST);
	f->Size = HarnessBuildIpFrame(f->Data, sizeof(f->Data), IP_PROTO_UDP, 53, payload, size);

	for (UINT pass = 0;pass < 2;pass++)
	{
		char *suffix = (pass == 0 ? "" : "_nolog");

		b.NoLog = (pass != 0);
		b.Next = 0;
		ok = true;

		for (UINT i = 0;i < HARNESS_NUM_PARSE_FRAMES;i++)
		{
			PKT *p = NULL;

			f = &b.Frames[i];
			Format(name, sizeof(name), "parse_packet_%s%s", f->Kind, suffix);

			if (f->Size != 0)
			{
				p = HarnessParseLikeHub(f, b.NoLog);
			}

			if (HarnessParsedAsBuilt(f, p, b.NoLog))
			{
				b.Current = i;
				HarnessBenchOps(name, HarnessOpParseOne, &b, HARNESS_BENCH_MICRO_SPAN, 16);
			}
			else
			{
				Print("BENCH WARNING %s: the frame does not parse as built, case skipped\n", name);
				ok = false;
			}

			FreePacket(p);
		}

		if (ok)
		{
			Format(name, sizeof(name), "parse_packet_mix%s", suffix);
			HarnessBenchOps(name, HarnessOpParseMix, &b, HARNESS_BENCH_MICRO_SPAN, 16);
		}
	}
}

// ip_table_expire_<n>: microseconds of one DeleteExpiredIpTableEntry pass over an IP table of n entries,
// every second entry expired: the part that the hub runs under its table lock. ip_table_free_<n>: microseconds to
// free the entries that the pass took out, which the hub does after the lock (FreeIpTableEntries, CORE-F6)
static void HarnessBenchIpTableExpire(UINT num)
{
	UINT64 runs[HARNESS_BENCH_RUNS];
	UINT64 free_runs[HARNESS_BENCH_RUNS];
	bool ok = true;
	char name[MAX_SIZE];
	char free_name[MAX_SIZE];

	Format(name, sizeof(name), "ip_table_expire_%u", num);
	Format(free_name, sizeof(free_name), "ip_table_free_%u", num);

	for (UINT r = 0;r < HARNESS_BENCH_RUNS;r++)
	{
		LIST *o = NewList(CompareIpTable);
		IP_TABLE_EXPIRY x;
		UINT num_expired = 0;
		UINT64 now = Tick64();

		IpTableExpiryInit(&x);

		for (UINT i = 0;i < num;i++)
		{
			IP_TABLE_ENTRY *e = ZeroMalloc(sizeof(IP_TABLE_ENTRY));

			SetIP(&e->Ip, 10, (UCHAR)((i >> 16) & 0xFF), (UCHAR)((i >> 8) & 0xFF), (UCHAR)(i & 0xFF));
			e->MacAddress[0] = 0x02;
			e->MacAddress[4] = (UCHAR)((i >> 8) & 0xFF);
			e->MacAddress[5] = (UCHAR)(i & 0xFF);
			e->CreatedTime = now;
			// Expired entries were last updated more than IP_TABLE_EXPIRE_TIME ago. Unsigned arithmetic wraps
			// consistently, so this also holds when the machine has been up for less than that time
			e->UpdatedTime = ((i % 2) == 0 ? now - (UINT64)IP_TABLE_EXPIRE_TIME - 1000ULL : now);
			Insert(o, e);
		}

		UINT64 start = HarnessNowNs();
		DeleteExpiredIpTableEntry(o, &x, Tick64());
		runs[r] = (HarnessNowNs() - start) / 1000ULL;

		for (IP_TABLE_ENTRY *e = x.Expired;e != NULL;e = e->NextExpired)
		{
			num_expired++;
		}

		if (LIST_NUM(o) != (num - (num + 1) / 2) || num_expired != (num + 1) / 2)
		{
			ok = false;
		}

		start = HarnessNowNs();
		FreeIpTableEntries(x.Expired);
		free_runs[r] = (HarnessNowNs() - start) / 1000ULL;

		for (UINT i = 0;i < LIST_NUM(o);i++)
		{
			Free(LIST_DATA(o, i));
		}
		ReleaseList(o);
	}

	HarnessBenchReport(name, runs, HARNESS_BENCH_RUNS, "us", false);
	HarnessBenchReport(free_name, free_runs, HARNESS_BENCH_RUNS, "us", false);

	if (ok == false)
	{
		Print("BENCH WARNING %s: the pass did not delete exactly the expired entries\n", name);
	}
}

// One fifo_cycle operation: write HARNESS_FIFO_CYCLE bytes behind the backlog, then read as many from its front
static bool HarnessOpFifoCycle(void *param)
{
	HARNESS_FIFO_BENCH *b = (HARNESS_FIFO_BENCH *)param;

	WriteFifo(b->Fifo, b->Buf, HARNESS_FIFO_CYCLE);
	b->PeakMemSize = MAX(b->PeakMemSize, b->Fifo->memsize);

	if (ReadFifo(b->Fifo, b->Buf, HARNESS_FIFO_CYCLE) != HARNESS_FIFO_CYCLE)
	{
		return false;
	}

	return FifoSize(b->Fifo) == HARNESS_FIFO_BACKLOG;
}

// One queue_cycle operation: insert one item behind the backlog, then take the oldest one
static bool HarnessOpQueueCycle(void *param)
{
	HARNESS_FIFO_BENCH *b = (HARNESS_FIFO_BENCH *)param;

	InsertQueue(b->Queue, (void *)(UINT_PTR)b->NextInsert);
	b->NextInsert++;

	if (GetNext(b->Queue) != (void *)(UINT_PTR)b->NextGet)
	{
		return false;
	}
	b->NextGet++;

	return true;
}

// One queue_burst operation: insert HARNESS_QUEUE_BURST items into the empty queue, then take them all
static bool HarnessOpQueueBurst(void *param)
{
	HARNESS_FIFO_BENCH *b = (HARNESS_FIFO_BENCH *)param;
	bool ok = true;

	for (UINT i = 0;i < HARNESS_QUEUE_BURST;i++)
	{
		InsertQueue(b->Queue, (void *)(UINT_PTR)(i + 1));
	}

	for (UINT i = 0;i < HARNESS_QUEUE_BURST;i++)
	{
		if (GetNext(b->Queue) != (void *)(UINT_PTR)(i + 1))
		{
			ok = false;
		}
	}

	return ok && GetQueueNum(b->Queue) == 0;
}

// fifo_cycle: operations per second of write HARNESS_FIFO_CYCLE / read HARNESS_FIFO_CYCLE bytes over a standing
// backlog of HARNESS_FIFO_BACKLOG bytes, in one FIFO kept across the runs: a producer and a consumer that never
// fully drain it. fifo_cycle_peak_memsize is the largest buffer the FIFO reached. queue_cycle: insert one / take
// one item over a standing backlog of HARNESS_QUEUE_BACKLOG items; queue_burst_<n>: n items into an empty queue,
// then all of them out (FND-215)
static void HarnessBenchFifo()
{
	HARNESS_FIFO_BENCH *b = ZeroMalloc(sizeof(HARNESS_FIFO_BENCH));
	char name[MAX_SIZE];

	b->Fifo = NewFifo();
	WriteFifo(b->Fifo, b->Buf, HARNESS_FIFO_BACKLOG);
	b->PeakMemSize = b->Fifo->memsize;

	HarnessBenchOps("fifo_cycle", HarnessOpFifoCycle, b, HARNESS_BENCH_MICRO_SPAN, 16);
	Print("BENCH fifo_cycle_peak_memsize %u bytes\n", b->PeakMemSize);

	ReleaseFifo(b->Fifo);

	b->Queue = NewQueueFast();
	b->NextInsert = 1;
	b->NextGet = 1;
	for (UINT i = 0;i < HARNESS_QUEUE_BACKLOG;i++)
	{
		InsertQueue(b->Queue, (void *)(UINT_PTR)b->NextInsert);
		b->NextInsert++;
	}

	HarnessBenchOps("queue_cycle", HarnessOpQueueCycle, b, HARNESS_BENCH_MICRO_SPAN, 16);

	while (GetQueueNum(b->Queue) != 0)
	{
		GetNext(b->Queue);
	}

	Format(name, sizeof(name), "queue_burst_%u", HARNESS_QUEUE_BURST);
	HarnessBenchOps(name, HarnessOpQueueBurst, b, HARNESS_BENCH_MICRO_SPAN, 1);

	ReleaseQueue(b->Queue);
	Free(b);
}

////////////////////////////
// The node of the flood hub

// A new empty data directory with the configuration store of the server role: one worker and the flood hub as an
// online L2 network
static void HarnessNewNodeDir(wchar_t *dir, UINT size)
{
	wchar_t tmp[MAX_PATH];
	wchar_t path[MAX_PATH];

	UniFormat(tmp, sizeof(tmp), L"hub_bench_%u", Rand32());
	ConbinePathW(dir, size, MsGetMyTempDirW(), tmp);
	MakeDirExW(dir);

	ConbinePathW(path, sizeof(path), dir, CS_FILE_NAME);
	CONFIG_STORE *s = CsOpen(path);
	if (s == NULL)
	{
		Print("  configuration store %S cannot be opened\n", path);
		return;
	}

	CsSetSetting(s, NODE_SETTING_ROLES, "server");
	CsSetSetting(s, NODE_SETTING_WORKERS, "1");
	CsAddNetwork(s, HARNESS_HUB_FLOOD, CS_MODE_L2, true);
	CsClose(s);
}

// Delete the files of a directory, then the directory (it holds no subdirectory)
static void HarnessDeleteDirFiles(wchar_t *dir)
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

// The flood cases on the hub of a node: the flood loop of StorePacket sends to every session of the hub. The hub has
// the default options and log settings of a new hub; its watchdog sends no ARP or neighbor polls into the sessions
static void HarnessBenchFlood(HARNESS *h)
{
	wchar_t dir[MAX_PATH];
	wchar_t log_dir[MAX_PATH];

	HarnessNewNodeDir(dir, sizeof(dir));
	NODE *n = NewNode(dir);
	NodeStart(n);

	HUB *hub = NodeGetHub(n, HARNESS_HUB_FLOOD);
	if (HarnessCheck(h, hub != NULL, "the server role of a node runs the hub " HARNESS_HUB_FLOOD))
	{
		hub->Option->NoArpPolling = true;
		hub->Option->NoIPv6AddrPolling = true;

		HarnessBenchFloodCase(hub, 8);
		HarnessBenchFloodCase(hub, 64);
		HarnessBenchFloodLogWaitCase(hub, 8);

		// The IP table cases use the same hub, with one session
		HarnessBenchIpTableAdd(hub, 1024);
		HarnessBenchIpTableAdd(hub, 16384);

		ReleaseHub(hub);
	}

	NodeStop(n);
	FreeNode(n);
	ConbinePathW(log_dir, sizeof(log_dir), dir, NODE_LOG_DIR_NAME);
	HarnessDeleteDirFiles(log_dir);
	HarnessDeleteDirFiles(dir);
}

////////////////////////////
// Entry points

// "bench": the hub flood, IP table, ParsePacket, Pack, IP table expiry, FIFO and queue cases (informational, fails only
// on errors). Every case runs HARNESS_BENCH_RUNS times: the median, then every run
RANZ_TEST("bench", bench_test, "Hub flood, IP table, ParsePacket, Pack, FIFO and queue benchmarks on a hub of the server role of a node (informational).");
void bench_test(UINT num, char **arg)
{
	HARNESS h;
	UINT64 start = Tick64();

	Zero(&h, sizeof(h));

	Print("Ranz bench: %u runs per case (median, then every run); per run: hub flood %u ms, Pack %u ms, ParsePacket %u ms, "
		"one IP table expiry pass\n", HARNESS_BENCH_RUNS, HARNESS_BENCH_FLOOD_SPAN, HARNESS_BENCH_PACK_SPAN,
		HARNESS_BENCH_MICRO_SPAN);

	Print("[bench]\n");
	HarnessBenchFlood(&h);
	HarnessBenchPackNames();
	HarnessBenchParse();
	HarnessBenchIpTableExpire(1024);
	HarnessBenchIpTableExpire(4096);
	HarnessBenchIpTableExpire(16384);
	HarnessBenchFifo();

	UINT64 elapsed = Tick64() - start;
	Print("BENCH bench_runtime_ms %I64u ms\n", elapsed);

	// Informational like the numbers: the budget is reported, never failed
	if (elapsed >= HARNESS_BENCH_BUDGET)
	{
		Print("WARNING: bench runtime %I64u ms is over the %u ms budget\n", elapsed, HARNESS_BENCH_BUDGET);
	}

	if (h.NumFail == 0)
	{
		Print("BENCH TEST OK\n");
	}
	else
	{
		Print("BENCH TEST FAILED (%u failed checks)\n", h.NumFail);
	}
}

// "packetlog": the packet log lines and levels of fixed frames against the golden file packetlog.txt, and the log record
RANZ_TEST("packetlog", packetlog_test, "Packet log of a hub: the lines of PacketLogParseProc and the levels of CalcPacketLoggingLevel against packetlog.txt (golden family harness), and the log record of InsertUnicodeRecord.");
void packetlog_test(UINT num, char **arg)
{
	HARNESS h;

	Zero(&h, sizeof(h));

	Print("Ranz packetlog: the packet log of a hub against its golden file, and the log record\n");

	HarnessPacketLogGolden(&h);
	HarnessLogRecordCheck(&h);

	if (h.NumFail == 0)
	{
		Print("PACKETLOG TEST OK\n");
	}
	else
	{
		Print("PACKETLOG TEST FAILED (%u failed checks)\n", h.NumFail);
	}
}

// "ptrkey": POINTER_TO_KEY keys a block by its address
RANZ_TEST("ptrkey", ptrkey_test, "Pointer keys: POINTER_TO_KEY keys a block by its address, and ListKeyToPointer finds the block again by that key.");
void ptrkey_test(UINT num, char **arg)
{
	HARNESS h;

	Zero(&h, sizeof(h));

	Print("Ranz ptrkey: POINTER_TO_KEY keys a block by its address\n");

	Print("[blocks]\n");
	PtrKeyBlocks(&h);

	if (h.NumFail == 0)
	{
		Print("PTRKEY TEST OK\n");
	}
	else
	{
		Print("PTRKEY TEST FAILED (%u failed checks)\n", h.NumFail);
	}
}
