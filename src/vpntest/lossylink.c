// lossylink.c
// Named lossy-link test of vpntest ("lossylink" command, CORE-S2-1 #69: the scope addition of the ADR-0022 amendment
// of 2026-10-15 on the TCP-over-TCP meltdown)
//
// The ingress queue of the session layer (src/Core/TransportQueue.c) on its own, then under an inner TCP flow on a
// simulated lossy link. The queue: a FIFO queue lets the records out in the order they came and drops at its limit, at
// the tail; CoDel never drops a record that waited less than the target, nor one that waits alone, drops the first
// record once the records waited longer for an interval, then at the times of the control law of RFC 8289, and leaves
// the dropping state once a record waited less than the target again.
//
// The lossy link runs in virtual time: no socket and no clock, and a seeded generator decides the losses, so every
// run gives the same numbers on every machine. An inner TCP flow sends through the tunnel of the TLS-443 path: its
// segments enter the ingress queue, whose writer moves them into the stream of the outer TCP while the socket takes
// them (the window in flight and a little more, as the ideal send backlog of Windows lets a socket buffer); the outer
// TCP carries the stream over a link of 10 Mbit/s and 50 ms round-trip time that loses 1% or 2% of its segments; the
// outer receiver hands the inner segments over in the order of the stream, so a lost outer segment holds up every one
// behind it; the inner receiver's acknowledgements come back after 25 ms. Both TCPs are the same sender: selective
// acknowledgements, the loss detection of RACK (RFC 8985), CUBIC's multiplicative decrease of 0.7 (RFC 9438) and Reno's
// growth, the retransmission timeout of RFC 6298 with a minimum of 200 ms for the inner TCP (Linux) and 300 ms for the
// outer one (Windows). For each loss rate the test runs the outer TCP alone with a stream that never runs dry (what
// the link carries), then the inner TCP over a queue that CoDel runs and over a FIFO queue, and prints the inner TCP's
// goodput, the time its segments waited in the queue and its retransmissions. With CoDel the goodput must be at least
// LOSSYLINK_FLOOR percent of what the link carries (no collapse), and the median wait below the target.
//
// TCP splitting (CORE-P2-3 #94, Cedar/NodeSplit.c): a fourth run at each loss rate splits the inner TCP. The Windows TCP stack
// of the client node terminates it, so the application's segments never cross the lossy link: only their byte stream does,
// as the data records of the split flow, NODE_SPLIT_CHUNK bytes each, which the writer appends to the stream of the outer TCP
// while the socket takes them and the window of the flow (NODE_SPLIT_WINDOW) lets it; the server node writes each record that
// the outer receiver hands over to the real destination at once and grants its bytes again a one-way delay later. Its goodput
// is the bytes of the stream that the destination got. Splitting must beat both the plain run (FIFO) and the run with the
// active queue alone (CoDel) by LOSSYLINK_SPLIT_GAIN percent at least, and keep LOSSYLINK_FLOOR percent of what the link
// carries.
// Print "LOSSYLINK TEST OK" only when every check passes.

#include "testlist.h"

#include "Mayaqua/Memory.h"
#include "Mayaqua/Str.h"

#include "Core/Transport.h"

#define	LOSSYLINK_TICK			100				// The step of the virtual clock (us)
#define	LOSSYLINK_RUN			40000000		// One run (us) ...
#define	LOSSYLINK_MEASURE		10000000		// ... whose goodput counts from here
#define	LOSSYLINK_SER_NUM		4				// The link sends a byte in 4/5 us: 10 Mbit/s
#define	LOSSYLINK_SER_DEN		5
#define	LOSSYLINK_ONE_WAY		25000			// The delay of each direction (us): a round trip of 50 ms
#define	LOSSYLINK_ROUTER		(128 * 1024)	// Bytes the bottleneck queues before it drops a segment
#define	LOSSYLINK_OUTER_MSS		1448			// The outer TCP's segment
#define	LOSSYLINK_OUTER_RTO		300000			// ... and its least retransmission timeout (us): Windows
#define	LOSSYLINK_INNER_MSS		1200			// The inner TCP's segment
#define	LOSSYLINK_INNER_RTO		200000			// ... and its least retransmission timeout (us): Linux
#define	LOSSYLINK_RECORD		(LOSSYLINK_INNER_MSS + 54 + 4 + 1 + 22)	// The record of an inner segment on the stream: the frame with its
																		// Ethernet, IP and TCP headers, the frame header, the record type and
																		// the overhead of a TLS 1.3 record
#define	LOSSYLINK_IW			10				// The initial window of both TCPs (segments)
#define	LOSSYLINK_SLACK			(8 * 1024)		// Bytes the socket takes beyond the window in flight
#define	LOSSYLINK_MAX			(1 << 16)		// Segments, records and events of one run at most
#define	LOSSYLINK_HISTOGRAM		100000			// Ticks of the histogram of the waits: 10 s
#define	LOSSYLINK_SEED			0x2545F491		// The generator of the losses
#define	LOSSYLINK_FLOOR			75				// The goodput with CoDel at least, in percent of what the link carries
#define	LOSSYLINK_ALONE			0xFFFFFFFF		// The mode of a run of the outer TCP alone, beside TRANSPORT_QUEUE_*
#define	LOSSYLINK_SPLIT			0xFFFFFFFE		// ... and of a run with TCP splitting
#define	LOSSYLINK_SPLIT_CHUNK	16384			// The bytes of the stream in one data record of a split flow (NODE_SPLIT_CHUNK)
#define	LOSSYLINK_SPLIT_RECORD	(LOSSYLINK_SPLIT_CHUNK + 6 + 4 + 1 + 22)	// ... and the record on the outer stream: the header of the split
																		// record, the frame header, the record type and the overhead of a
																		// TLS 1.3 record
#define	LOSSYLINK_SPLIT_WINDOW	262144			// The bytes that the server node takes at first, and holds at most (NODE_SPLIT_WINDOW)
#define	LOSSYLINK_SPLIT_GAIN	108				// The goodput with splitting at least, in percent of the plain run and of the run with CoDel

// The states of a segment of a sender
#define	LOSSYLINK_UNSENT		0
#define	LOSSYLINK_INFLIGHT		1				// Sent, not acknowledged yet
#define	LOSSYLINK_SACKED		2				// Acknowledged
#define	LOSSYLINK_LOST			3				// Taken for lost: sent again as the window lets it

// The state of the test
typedef struct LOSSYLINK_CTX
{
	UINT NumChecks;
	UINT NumFailed;
} LOSSYLINK_CTX;

typedef struct LOSSYLINK_SIM LOSSYLINK_SIM;

// The procedures of a sender: New makes segment index of the data that waits and gives its size, 0 when none waits;
// Transmit puts a transmission of the segment into the sender's network
typedef UINT(LOSSYLINK_NEW_PROC)(LOSSYLINK_SIM *sim, UINT index);
typedef void(LOSSYLINK_TRANSMIT_PROC)(LOSSYLINK_SIM *sim, UINT64 now, UINT index, UINT size);

// A TCP sender over segments
typedef struct LOSSYLINK_SENDER
{
	LOSSYLINK_SIM *Sim;
	UINT Mss;							// The segment size of the window
	UINT64 MinRto;						// The least retransmission timeout (us)
	LOSSYLINK_NEW_PROC *New;
	LOSSYLINK_TRANSMIT_PROC *Transmit;
	UINT Num;							// The segments so far, each with ...
	UINT *Size;							// ... its size
	UINT64 *Sent;						// ... when its last transmission went
	UCHAR *State;						// ... its state (LOSSYLINK_UNSENT, ...)
	UINT *Retx;							// ... and its transmissions after the first
	UINT Una;							// The first segment not acknowledged
	UINT NextLost;						// The first segment that may be taken for lost and not sent again yet
	UINT64 Cwnd;						// The congestion window (bytes)
	UINT64 Ssthresh;					// The slow start threshold (bytes)
	UINT64 Inflight;					// The bytes of the segments in flight
	bool Recovery;						// A loss is being recovered ...
	UINT RecoveryPoint;					// ... until every segment up to this one is acknowledged
	UINT64 Srtt;						// The smoothed round-trip time (us)
	UINT64 Rttvar;						// ... its variation
	UINT64 MinRtt;						// ... the least round-trip time
	UINT64 Rto;							// The retransmission timeout (us) ...
	UINT Backoff;						// ... and its backoff
	UINT64 RackTime;					// RACK: when the newest acknowledged transmission went
	UINT Retransmits;					// Transmissions after the first
	UINT Timeouts;						// Retransmission timeouts
} LOSSYLINK_SENDER;

// An event on its way, in the order the events arrive: a transmission to a receiver, an acknowledgement to a sender,
// a segment that waits at the bottleneck
typedef struct LOSSYLINK_EVENT
{
	UINT64 Time;						// When it arrives
	UINT Segment;						// The segment ...
	UINT64 Sent;						// ... and when that transmission of it went
	UINT Size;							// Its bytes
} LOSSYLINK_EVENT;

// The events of one kind: a run fills the array once, and Head is the first that did not arrive yet
typedef struct LOSSYLINK_FIFO
{
	LOSSYLINK_EVENT *Events;
	UINT Num;
	UINT Head;
} LOSSYLINK_FIFO;

// What the record of an inner segment carries: the segment and when that transmission of it went
typedef struct LOSSYLINK_PAYLOAD
{
	UINT Segment;
	UINT64 Sent;
} LOSSYLINK_PAYLOAD;

// One run
struct LOSSYLINK_SIM
{
	UINT Mode;							// LOSSYLINK_ALONE, TRANSPORT_QUEUE_CODEL or TRANSPORT_QUEUE_FIFO
	UINT LossBp;						// The segments the link loses, in 1/10000
	UINT Rand;							// The generator of the losses (xorshift32)
	bool Full;							// The run went past LOSSYLINK_MAX: its numbers do not count
	TRANSPORT_QUEUE Queue;				// The ingress queue of the inner TCP's records
	UCHAR *Record;						// One record, LOSSYLINK_RECORD bytes
	LOSSYLINK_SENDER Outer;				// The outer TCP
	LOSSYLINK_SENDER Inner;				// The inner TCP
	UINT64 Appended;					// The stream: the bytes the writer appended ...
	UINT NumRecords;					// ... in records, each with ...
	UINT64 *RecordEnd;					// ... the offset of its end
	LOSSYLINK_PAYLOAD *RecordPayload;	// ... and what it carries
	UINT RecordHead;					// The first record not handed over yet
	UINT64 Segmented;					// The bytes of the stream in outer segments ...
	UINT64 *SegStart;					// ... the offset of each
	LOSSYLINK_FIFO Router;				// The segments that wait at the bottleneck ...
	UINT64 RouterBytes;					// ... and their bytes
	UINT64 LinkFree;					// When the link finishes its segment
	bool LinkBusy;						// It sends one ...
	LOSSYLINK_EVENT LinkItem;			// ... this one
	LOSSYLINK_FIFO Forward;				// Outer segments to the outer receiver
	LOSSYLINK_FIFO OuterAcks;			// ... and its acknowledgements to the outer sender
	bool *RcvHave;						// The outer receiver: the segments it has ...
	UINT RcvSeg;						// ... the first it does not have
	UINT64 RcvCum;						// ... and the bytes of the stream it has in order
	LOSSYLINK_FIFO InnerAcks;			// The inner receiver's acknowledgements to the inner sender
	bool *InnerRcv;						// The inner receiver: the segments it has ...
	UINT InnerRcvNext;					// ... the first it does not have
	UINT64 AloneDelivered;				// The records of the outer TCP alone handed over
	UINT64 SplitAppended;				// Splitting: the bytes of the stream that the writer appended ...
	UINT64 SplitGranted;				// ... the ones that the server node granted again, as the client node knows it ...
	UINT64 SplitDelivered;				// ... and the ones that the real destination got
	UINT LinkLosses;					// Segments the link lost
	UINT RouterDrops;					// Segments the bottleneck dropped
	UINT *Waits;						// The histogram of the waits in the queue, in ticks ...
	UINT NumWaits;						// ... and their number
};

// What one run gave
typedef struct LOSSYLINK_RESULT
{
	UINT Kbps;							// The goodput (kbit/s): of the inner TCP, or of the records of the outer TCP alone
	UINT64 Wait50;						// The median wait of a record in the queue (us)
	UINT64 Wait95;						// ... and its 95th percentile
	UINT Retransmits;					// The inner TCP's transmissions after the first
	UINT Timeouts;						// ... and its retransmission timeouts
	UINT64 Dropped;						// Records that CoDel dropped
	UINT64 Overflow;					// ... dropped at the limit of the queue
	UINT LinkLosses;					// Outer segments the link lost
	bool Full;							// The run went past its arrays
} LOSSYLINK_RESULT;

static bool LossyLinkCheck(LOSSYLINK_CTX *ctx, bool ok, char *what, char *fmt, ...) RANZ_PRINTF_FORMAT(4, 5);
static bool LossyLinkCheck(LOSSYLINK_CTX *ctx, bool ok, char *what, char *fmt, ...)
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

//
// The ingress queue on its own
//

// The FIFO queue: the order, the bytes, the limit, a record larger than the buffer, the free
static void LossyLinkFifo(LOSSYLINK_CTX *ctx)
{
	TRANSPORT_QUEUE q;
	UCHAR buf[16];
	UINT size = 0, value = 0, taken = 0;

	Print("[the ingress queue: FIFO]\n");

	TransportQueueInit(&q, TRANSPORT_QUEUE_FIFO);
	bool pushed = TransportQueuePush(&q, 0, "a", 1) && TransportQueuePush(&q, 0, "bb", 2) && TransportQueuePush(&q, 0, "ccc", 3);
	bool first = TransportQueuePop(&q, 10000000, buf, sizeof(buf), &size) && size == 1 && Cmp(buf, "a", 1) == 0;
	bool second = TransportQueuePop(&q, 10000000, buf, sizeof(buf), &size) && size == 2 && Cmp(buf, "bb", 2) == 0;
	bool third = TransportQueuePop(&q, 10000000, buf, sizeof(buf), &size) && size == 3 && Cmp(buf, "ccc", 3) == 0;
	bool empty = (TransportQueuePop(&q, 10000000, buf, sizeof(buf), &size) == false && size == 0);
	LossyLinkCheck(ctx, pushed && first && second && third && empty && q.NumDropped == 0,
		"  records leave in the order they came, with their bytes, however long they waited; an empty queue gives none",
		"pushed %u, out %u %u %u, empty %u, dropped %I64u", (UINT)pushed, (UINT)first, (UINT)second, (UINT)third, (UINT)empty, q.NumDropped);

	for (UINT i = 0; i < TRANSPORT_QUEUE_LIMIT + 5; i++)
	{
		if (TransportQueuePush(&q, 0, &i, sizeof(i)))
		{
			taken++;
		}
	}
	bool head = TransportQueuePop(&q, 0, &value, sizeof(value), &size) && size == sizeof(value) && value == 0;
	LossyLinkCheck(ctx, taken == TRANSPORT_QUEUE_LIMIT && q.NumOverflow == 5 && head, "  at its limit of 1000 records the queue drops at the tail",
		"took %u, overflow %I64u, head %u", taken, q.NumOverflow, (UINT)head);

	TransportQueueFree(&q);
	LossyLinkCheck(ctx, q.NumRecords == 0 && q.Bytes == 0 && TransportQueuePop(&q, 0, buf, sizeof(buf), &size) == false,
		"  Free drops every record that waits", "%u records wait", q.NumRecords);

	TransportQueueInit(&q, TRANSPORT_QUEUE_FIFO);
	TransportQueuePush(&q, 0, "0123456789", 10);
	TransportQueuePush(&q, 0, "x", 1);
	bool next = TransportQueuePop(&q, 0, buf, 4, &size) && size == 1 && buf[0] == 'x';
	LossyLinkCheck(ctx, next && q.NumDropped == 1, "  a record larger than the buffer is dropped, and the next one leaves", "next %u, dropped %I64u",
		(UINT)next, q.NumDropped);
	TransportQueueFree(&q);
}

// CoDel: no drop below the target, none of a record that waits alone, the drops of a standing queue at the times of
// the control law, the end of the dropping state
static void LossyLinkCodel(LOSSYLINK_CTX *ctx)
{
	// A queue that stands at 20 ms, one record pushed every ms and one taken every ms from 20 ms on: the first drop
	// comes an interval after the first record that waited above the target, the next ones an interval over the square
	// root of the drops after the one before, each takes 1 ms off the wait, and the dropping state ends after the 16th,
	// when the records wait 4 ms
	static const UINT expect[] = {120, 220, 291, 349, 399, 444, 484, 522, 558, 591, 623, 653, 682, 709, 736, 762};
	UINT drops[32];
	UINT num_drops = 0;
	TRANSPORT_QUEUE q;
	UCHAR buf[128];
	UINT size = 0;

	Print("[the ingress queue: CoDel]\n");

	// Records that wait 4 ms, below the target of 5 ms
	TransportQueueInit(&q, TRANSPORT_QUEUE_CODEL);
	Zero(buf, sizeof(buf));
	for (UINT t = 0; t < 2000; t++)
	{
		TransportQueuePush(&q, (UINT64)t * 1000, buf, 100);
		if (t >= 4)
		{
			TransportQueuePop(&q, (UINT64)t * 1000, buf, sizeof(buf), &size);
		}
	}
	LossyLinkCheck(ctx, q.NumDropped == 0 && q.NumPopped == 1996, "  records that wait 4 ms, below the target of 5 ms, are never dropped",
		"dropped %I64u, out %I64u", q.NumDropped, q.NumPopped);
	TransportQueueFree(&q);

	// A record that waits 50 ms while no other one waits: one record keeps the stream busy, so CoDel drops none
	TransportQueueInit(&q, TRANSPORT_QUEUE_CODEL);
	for (UINT k = 0; k < 40; k++)
	{
		if (k != 0)
		{
			TransportQueuePop(&q, (UINT64)k * 50000, buf, sizeof(buf), &size);
		}
		TransportQueuePush(&q, (UINT64)k * 50000, buf, 100);
	}
	LossyLinkCheck(ctx, q.NumDropped == 0 && q.NumPopped == 39, "  a record that waits 50 ms alone is not dropped: one record keeps the stream busy",
		"dropped %I64u, out %I64u", q.NumDropped, q.NumPopped);
	TransportQueueFree(&q);

	// The standing queue
	TransportQueueInit(&q, TRANSPORT_QUEUE_CODEL);
	for (UINT t = 0; t < 1000; t++)
	{
		UINT64 before = q.NumDropped;

		TransportQueuePush(&q, (UINT64)t * 1000, buf, 100);
		if (t >= 20)
		{
			TransportQueuePop(&q, (UINT64)t * 1000, buf, sizeof(buf), &size);
		}
		if (q.NumDropped != before && num_drops < 32)
		{
			drops[num_drops++] = t;
		}
	}

	bool schedule = (num_drops == sizeof(expect) / sizeof(expect[0]));
	for (UINT i = 0; schedule && i < num_drops; i++)
	{
		schedule = (drops[i] == expect[i]);
	}
	char got[MAX_SIZE];
	StrCpy(got, sizeof(got), "");
	for (UINT i = 0; i < num_drops; i++)
	{
		char one[32];

		Format(one, sizeof(one), " %u", drops[i]);
		StrCat(got, sizeof(got), one);
	}
	Print("  the standing queue dropped at (ms):%s\n", got);
	LossyLinkCheck(ctx, schedule, "  a queue that stands at 20 ms: the first drop an interval after it went above the target, then at the times of the control law",
		"%u drops", num_drops);
	LossyLinkCheck(ctx, q.Dropping == false && q.NumRecords == 4 && q.NumDropped == 16, "  the dropping state ends once the records wait less than the target (4 ms)",
		"dropping %u, %u records wait, %I64u dropped", (UINT)q.Dropping, q.NumRecords, q.NumDropped);
	TransportQueueFree(&q);
}

//
// The lossy link
//

// The next number of the generator
static UINT LossyLinkRand(LOSSYLINK_SIM *sim)
{
	UINT x = sim->Rand;

	x ^= x << 13;
	x ^= x >> 17;
	x ^= x << 5;
	sim->Rand = x;

	return x;
}

// Put an event at the end of its array; a run that goes past LOSSYLINK_MAX is full
static void LossyLinkPut(LOSSYLINK_SIM *sim, LOSSYLINK_FIFO *f, UINT64 time, UINT segment, UINT64 sent, UINT size)
{
	if (f->Num >= LOSSYLINK_MAX)
	{
		sim->Full = true;
		return;
	}

	f->Events[f->Num].Time = time;
	f->Events[f->Num].Segment = segment;
	f->Events[f->Num].Sent = sent;
	f->Events[f->Num].Size = size;
	f->Num++;
}

// A sender of segments of mss bytes on its procedures
static void LossyLinkSenderInit(LOSSYLINK_SIM *sim, LOSSYLINK_SENDER *s, UINT mss, UINT64 min_rto, LOSSYLINK_NEW_PROC *new_proc, LOSSYLINK_TRANSMIT_PROC *transmit)
{
	Zero(s, sizeof(LOSSYLINK_SENDER));
	s->Sim = sim;
	s->Mss = mss;
	s->MinRto = min_rto;
	s->New = new_proc;
	s->Transmit = transmit;
	s->Size = ZeroMalloc(sizeof(UINT) * LOSSYLINK_MAX);
	s->Sent = ZeroMalloc(sizeof(UINT64) * LOSSYLINK_MAX);
	s->State = ZeroMalloc(sizeof(UCHAR) * LOSSYLINK_MAX);
	s->Retx = ZeroMalloc(sizeof(UINT) * LOSSYLINK_MAX);
	s->Cwnd = (UINT64)LOSSYLINK_IW * mss;
	s->Ssthresh = 1ULL << 40;
	s->Rto = 1000000;
	s->Backoff = 1;
}

static void LossyLinkSenderFree(LOSSYLINK_SENDER *s)
{
	Free(s->Size);
	Free(s->Sent);
	Free(s->State);
	Free(s->Retx);
}

// Send segment i, again when it was taken for lost
static void LossyLinkSendOne(LOSSYLINK_SENDER *s, UINT64 now, UINT i)
{
	if (s->State[i] == LOSSYLINK_LOST)
	{
		s->Retx[i]++;
		s->Retransmits++;
	}
	s->State[i] = LOSSYLINK_INFLIGHT;
	s->Sent[i] = now;
	s->Inflight += s->Size[i];
	s->Transmit(s->Sim, now, i, s->Size[i]);
}

// The sender's step: the retransmission timeout of the oldest segment in flight, then the segments taken for lost,
// then new ones, as the window lets them
static void LossyLinkSenderStep(LOSSYLINK_SENDER *s, UINT64 now)
{
	UINT first = INFINITE;

	for (UINT i = s->Una; i < s->Num; i++)
	{
		if (s->State[i] == LOSSYLINK_INFLIGHT)
		{
			first = i;
			break;
		}
	}
	if (first != INFINITE && now >= s->Sent[first] + s->Rto * s->Backoff)
	{
		// Every segment in flight is taken for lost; a timeout after a timeout keeps the threshold of the first
		s->Timeouts++;
		for (UINT i = s->Una; i < s->Num; i++)
		{
			if (s->State[i] == LOSSYLINK_INFLIGHT)
			{
				s->State[i] = LOSSYLINK_LOST;
				s->Inflight -= s->Size[i];
			}
		}
		if (s->Backoff == 1)
		{
			s->Ssthresh = MAX(s->Cwnd * 7 / 10, 2ULL * s->Mss);
		}
		s->Cwnd = s->Mss;
		s->Backoff = MIN(s->Backoff * 2, 64);
		s->Recovery = false;
		s->NextLost = s->Una;
	}

	for (UINT i = s->NextLost; s->Inflight < s->Cwnd && i < s->Num; i++)
	{
		if (s->State[i] == LOSSYLINK_LOST)
		{
			LossyLinkSendOne(s, now, i);
		}
	}

	while (s->Inflight < s->Cwnd)
	{
		if (s->Num >= LOSSYLINK_MAX)
		{
			s->Sim->Full = true;
			break;
		}

		UINT size = s->New(s->Sim, s->Num);
		if (size == 0)
		{
			break;
		}
		s->Size[s->Num] = size;
		s->Sent[s->Num] = 0;
		s->State[s->Num] = LOSSYLINK_UNSENT;
		s->Retx[s->Num] = 0;
		s->Num++;
		LossyLinkSendOne(s, now, s->Num - 1);
	}

	while (s->NextLost < s->Num && s->State[s->NextLost] != LOSSYLINK_LOST)
	{
		s->NextLost++;
	}
}

// The receiver got the transmission of segment i that went at sent. A copy of a transmission before the last one gives
// no round-trip time and no RACK time (it is ambiguous); a copy of a segment acknowledged before changes nothing.
static void LossyLinkSenderAck(LOSSYLINK_SENDER *s, UINT64 now, UINT i, UINT64 sent)
{
	if (s->State[i] == LOSSYLINK_SACKED)
	{
		return;
	}
	if (s->State[i] == LOSSYLINK_INFLIGHT)
	{
		s->Inflight -= s->Size[i];
	}
	s->State[i] = LOSSYLINK_SACKED;

	bool fresh = (sent == s->Sent[i]);
	if (fresh && s->Retx[i] == 0)
	{
		UINT64 rtt = now - sent;

		if (s->MinRtt == 0 || rtt < s->MinRtt)
		{
			s->MinRtt = rtt;
		}
		if (s->Srtt == 0)
		{
			s->Srtt = rtt;
			s->Rttvar = rtt / 2;
		}
		else
		{
			UINT64 d = (s->Srtt > rtt ? s->Srtt - rtt : rtt - s->Srtt);

			s->Rttvar = (3 * s->Rttvar + d) / 4;
			s->Srtt = (7 * s->Srtt + rtt) / 8;
		}
		s->Rto = MAX(s->MinRto, s->Srtt + 4 * s->Rttvar);
	}
	s->Backoff = 1;
	if (fresh && sent > s->RackTime)
	{
		s->RackTime = sent;
	}

	while (s->Una < s->Num && s->State[s->Una] == LOSSYLINK_SACKED)
	{
		s->Una++;
	}
	if (s->Recovery && s->Una > s->RecoveryPoint)
	{
		s->Recovery = false;
	}
	if (s->Recovery == false)
	{
		if (s->Cwnd < s->Ssthresh)
		{
			s->Cwnd += s->Size[i];
		}
		else
		{
			s->Cwnd += (UINT64)s->Mss * s->Size[i] / s->Cwnd;
		}
	}

	// RACK: a segment in flight that went before the newest acknowledged one, by more than a quarter of the least
	// round-trip time, is lost; the first loss of a window starts its recovery
	UINT64 reorder = s->MinRtt / 4;
	bool lost = false;
	for (UINT j = s->Una; j < s->Num; j++)
	{
		if (s->State[j] == LOSSYLINK_INFLIGHT && s->Sent[j] + reorder < s->RackTime)
		{
			s->State[j] = LOSSYLINK_LOST;
			s->Inflight -= s->Size[j];
			lost = true;
			if (j < s->NextLost)
			{
				s->NextLost = j;
			}
		}
	}
	if (lost && s->Recovery == false)
	{
		s->Recovery = true;
		s->RecoveryPoint = s->Num - 1;
		s->Ssthresh = MAX(s->Cwnd * 7 / 10, 2ULL * s->Mss);
		s->Cwnd = s->Ssthresh;
	}
}

// The outer sender's new segment: the next bytes of the stream, at most a segment of them
static UINT LossyLinkOuterNew(LOSSYLINK_SIM *sim, UINT index)
{
	if (sim->Segmented >= sim->Appended)
	{
		return 0;
	}

	UINT size = (UINT)MIN((UINT64)LOSSYLINK_OUTER_MSS, sim->Appended - sim->Segmented);
	sim->SegStart[index] = sim->Segmented;
	sim->Segmented += size;

	return size;
}

// An outer segment goes to the bottleneck, which drops it when its queue is full
static void LossyLinkOuterTransmit(LOSSYLINK_SIM *sim, UINT64 now, UINT index, UINT size)
{
	if (sim->RouterBytes + size > LOSSYLINK_ROUTER)
	{
		sim->RouterDrops++;
		return;
	}

	LossyLinkPut(sim, &sim->Router, 0, index, now, size);
	sim->RouterBytes += size;
}

// The inner sender always has data
static UINT LossyLinkInnerNew(LOSSYLINK_SIM *sim, UINT index)
{
	return LOSSYLINK_INNER_MSS;
}

// An inner segment goes into the ingress queue as one record, which carries the segment and when it went
static void LossyLinkInnerTransmit(LOSSYLINK_SIM *sim, UINT64 now, UINT index, UINT size)
{
	LOSSYLINK_PAYLOAD p;

	Zero(sim->Record, LOSSYLINK_RECORD);
	Zero(&p, sizeof(p));
	p.Segment = index;
	p.Sent = now;
	Copy(sim->Record, &p, sizeof(p));
	TransportQueuePush(&sim->Queue, now, sim->Record, LOSSYLINK_RECORD);
}

// Whether the socket takes more: its bytes not acknowledged in order stay within the window and a little more
static bool LossyLinkSocketRoom(LOSSYLINK_SIM *sim)
{
	UINT64 acked = (sim->Outer.Una < sim->Outer.Num ? sim->SegStart[sim->Outer.Una] : sim->Segmented);

	return (sim->Appended - acked < sim->Outer.Cwnd + LOSSYLINK_SLACK);
}

// Append a record to the stream
static void LossyLinkAppend(LOSSYLINK_SIM *sim, UINT size, const LOSSYLINK_PAYLOAD *p)
{
	if (sim->NumRecords >= LOSSYLINK_MAX)
	{
		sim->Full = true;
		return;
	}

	sim->Appended += size;
	sim->RecordEnd[sim->NumRecords] = sim->Appended;
	sim->RecordPayload[sim->NumRecords] = *p;
	sim->NumRecords++;
}

// The writer of the ingress queue: records into the stream while the socket takes them. The outer TCP alone has a
// stream that never runs dry.
static void LossyLinkWriter(LOSSYLINK_SIM *sim, UINT64 now)
{
	LOSSYLINK_PAYLOAD p;
	UINT size = 0;

	// Splitting: the bytes that the server node granted again, a one-way delay after it wrote them to the destination
	while (sim->Mode == LOSSYLINK_SPLIT && sim->InnerAcks.Head < sim->InnerAcks.Num && sim->InnerAcks.Events[sim->InnerAcks.Head].Time <= now)
	{
		sim->SplitGranted += sim->InnerAcks.Events[sim->InnerAcks.Head++].Size;
	}

	while (sim->Full == false && LossyLinkSocketRoom(sim))
	{
		if (sim->Mode == LOSSYLINK_ALONE)
		{
			Zero(&p, sizeof(p));
			LossyLinkAppend(sim, LOSSYLINK_RECORD, &p);
			continue;
		}

		// Splitting: the application always has data, and the split flow sends a record within its window
		if (sim->Mode == LOSSYLINK_SPLIT)
		{
			if (sim->SplitAppended + LOSSYLINK_SPLIT_CHUNK > sim->SplitGranted + LOSSYLINK_SPLIT_WINDOW)
			{
				break;
			}
			Zero(&p, sizeof(p));
			LossyLinkAppend(sim, LOSSYLINK_SPLIT_RECORD, &p);
			sim->SplitAppended += LOSSYLINK_SPLIT_CHUNK;
			continue;
		}

		if (TransportQueuePop(&sim->Queue, now, sim->Record, LOSSYLINK_RECORD, &size) == false)
		{
			break;
		}
		Copy(&p, sim->Record, sizeof(p));
		if (now >= LOSSYLINK_MEASURE)
		{
			UINT tick = (UINT)MIN((now - p.Sent) / LOSSYLINK_TICK, (UINT64)LOSSYLINK_HISTOGRAM - 1);

			sim->Waits[tick]++;
			sim->NumWaits++;
		}
		LossyLinkAppend(sim, size, &p);
	}
}

// The link: the bottleneck sends one segment at a time at its rate and loses some; the others arrive a one-way delay
// later
static void LossyLinkStep(LOSSYLINK_SIM *sim, UINT64 now)
{
	while (true)
	{
		if (sim->LinkBusy)
		{
			if (sim->LinkFree > now)
			{
				return;
			}
			sim->LinkBusy = false;
			if ((LossyLinkRand(sim) % 10000) < sim->LossBp)
			{
				sim->LinkLosses++;
			}
			else
			{
				LossyLinkPut(sim, &sim->Forward, sim->LinkFree + LOSSYLINK_ONE_WAY, sim->LinkItem.Segment, sim->LinkItem.Sent, sim->LinkItem.Size);
			}
		}
		if (sim->Router.Head >= sim->Router.Num)
		{
			return;
		}

		sim->LinkItem = sim->Router.Events[sim->Router.Head++];
		sim->RouterBytes -= sim->LinkItem.Size;
		sim->LinkFree = MAX(sim->LinkFree, now) + (UINT64)sim->LinkItem.Size * LOSSYLINK_SER_NUM / LOSSYLINK_SER_DEN;
		sim->LinkBusy = true;
	}
}

// The inner receiver gets the record of an inner segment and acknowledges it
static void LossyLinkInnerReceive(LOSSYLINK_SIM *sim, UINT64 now, const LOSSYLINK_PAYLOAD *p)
{
	sim->InnerRcv[p->Segment] = true;
	while (sim->InnerRcvNext < sim->Inner.Num && sim->InnerRcv[sim->InnerRcvNext])
	{
		sim->InnerRcvNext++;
	}
	LossyLinkPut(sim, &sim->InnerAcks, now + LOSSYLINK_ONE_WAY, p->Segment, p->Sent, 0);
}

// The outer receiver: the segments that arrived; the records of the stream it has in order go to the inner receiver
static void LossyLinkOuterReceive(LOSSYLINK_SIM *sim, UINT64 now)
{
	while (sim->Forward.Head < sim->Forward.Num && sim->Forward.Events[sim->Forward.Head].Time <= now)
	{
		LOSSYLINK_EVENT e = sim->Forward.Events[sim->Forward.Head++];

		sim->RcvHave[e.Segment] = true;
		while (sim->RcvSeg < sim->Outer.Num && sim->RcvHave[sim->RcvSeg])
		{
			sim->RcvSeg++;
		}
		sim->RcvCum = (sim->RcvSeg < sim->Outer.Num ? sim->SegStart[sim->RcvSeg] : sim->Segmented);

		while (sim->RecordHead < sim->NumRecords && sim->RecordEnd[sim->RecordHead] <= sim->RcvCum)
		{
			const LOSSYLINK_PAYLOAD *p = &sim->RecordPayload[sim->RecordHead++];

			if (sim->Mode == LOSSYLINK_ALONE)
			{
				sim->AloneDelivered++;
			}
			else if (sim->Mode == LOSSYLINK_SPLIT)
			{
				// The server node writes the bytes of the record to the real destination at once, and grants them again
				sim->SplitDelivered += LOSSYLINK_SPLIT_CHUNK;
				LossyLinkPut(sim, &sim->InnerAcks, now + LOSSYLINK_ONE_WAY, 0, 0, LOSSYLINK_SPLIT_CHUNK);
			}
			else
			{
				LossyLinkInnerReceive(sim, now, p);
			}
		}

		LossyLinkPut(sim, &sim->OuterAcks, now + LOSSYLINK_ONE_WAY, e.Segment, e.Sent, 0);
	}
}

// The acknowledgements that arrived by now go to their sender
static void LossyLinkAcks(LOSSYLINK_FIFO *f, LOSSYLINK_SENDER *s, UINT64 now)
{
	while (f->Head < f->Num && f->Events[f->Head].Time <= now)
	{
		LOSSYLINK_EVENT e = f->Events[f->Head++];

		LossyLinkSenderAck(s, now, e.Segment, e.Sent);
	}
}

// The wait at percentile pct of the histogram (us): the wait of the record at that place in the order of the waits
static UINT64 LossyLinkPercentile(LOSSYLINK_SIM *sim, UINT pct)
{
	UINT64 place = (UINT64)sim->NumWaits * pct / 100;
	UINT64 seen = 0;

	if (sim->NumWaits == 0)
	{
		return 0;
	}

	for (UINT i = 0; i < LOSSYLINK_HISTOGRAM; i++)
	{
		seen += sim->Waits[i];
		if (seen > place)
		{
			return (UINT64)i * LOSSYLINK_TICK;
		}
	}

	return (UINT64)(LOSSYLINK_HISTOGRAM - 1) * LOSSYLINK_TICK;
}

// One run of a mode at a loss rate
static void LossyLinkRun(UINT mode, UINT loss_bp, LOSSYLINK_RESULT *r)
{
	LOSSYLINK_SIM *sim = ZeroMalloc(sizeof(LOSSYLINK_SIM));
	UINT64 mark_inner = 0, mark_alone = 0, mark_split = 0;
	bool marked = false;
	bool inner = (mode != LOSSYLINK_ALONE && mode != LOSSYLINK_SPLIT);

	sim->Mode = mode;
	sim->LossBp = loss_bp;
	sim->Rand = LOSSYLINK_SEED;
	sim->Record = ZeroMalloc(LOSSYLINK_RECORD);
	sim->RecordEnd = ZeroMalloc(sizeof(UINT64) * LOSSYLINK_MAX);
	sim->RecordPayload = ZeroMalloc(sizeof(LOSSYLINK_PAYLOAD) * LOSSYLINK_MAX);
	sim->SegStart = ZeroMalloc(sizeof(UINT64) * LOSSYLINK_MAX);
	sim->Router.Events = ZeroMalloc(sizeof(LOSSYLINK_EVENT) * LOSSYLINK_MAX);
	sim->Forward.Events = ZeroMalloc(sizeof(LOSSYLINK_EVENT) * LOSSYLINK_MAX);
	sim->OuterAcks.Events = ZeroMalloc(sizeof(LOSSYLINK_EVENT) * LOSSYLINK_MAX);
	sim->InnerAcks.Events = ZeroMalloc(sizeof(LOSSYLINK_EVENT) * LOSSYLINK_MAX);
	sim->RcvHave = ZeroMalloc(sizeof(bool) * LOSSYLINK_MAX);
	sim->InnerRcv = ZeroMalloc(sizeof(bool) * LOSSYLINK_MAX);
	sim->Waits = ZeroMalloc(sizeof(UINT) * LOSSYLINK_HISTOGRAM);
	TransportQueueInit(&sim->Queue, inner ? mode : TRANSPORT_QUEUE_FIFO);
	LossyLinkSenderInit(sim, &sim->Outer, LOSSYLINK_OUTER_MSS, LOSSYLINK_OUTER_RTO, LossyLinkOuterNew, LossyLinkOuterTransmit);
	LossyLinkSenderInit(sim, &sim->Inner, LOSSYLINK_INNER_MSS, LOSSYLINK_INNER_RTO, LossyLinkInnerNew, LossyLinkInnerTransmit);

	for (UINT64 now = 0; now < LOSSYLINK_RUN && sim->Full == false; now += LOSSYLINK_TICK)
	{
		if (inner)
		{
			LossyLinkAcks(&sim->InnerAcks, &sim->Inner, now);
			LossyLinkSenderStep(&sim->Inner, now);
		}
		LossyLinkWriter(sim, now);
		LossyLinkAcks(&sim->OuterAcks, &sim->Outer, now);
		LossyLinkSenderStep(&sim->Outer, now);
		LossyLinkStep(sim, now);
		LossyLinkOuterReceive(sim, now);

		if (marked == false && now >= LOSSYLINK_MEASURE)
		{
			mark_inner = sim->InnerRcvNext;
			mark_alone = sim->AloneDelivered;
			mark_split = sim->SplitDelivered;
			marked = true;
		}
	}

	UINT64 seconds = (LOSSYLINK_RUN - LOSSYLINK_MEASURE) / 1000000;
	UINT64 segments = (mode == LOSSYLINK_ALONE ? sim->AloneDelivered - mark_alone : sim->InnerRcvNext - mark_inner);
	UINT64 bytes = (mode == LOSSYLINK_SPLIT ? sim->SplitDelivered - mark_split : segments * LOSSYLINK_INNER_MSS);

	Zero(r, sizeof(LOSSYLINK_RESULT));
	r->Kbps = (UINT)(bytes * 8 / (seconds * 1000));
	r->Wait50 = LossyLinkPercentile(sim, 50);
	r->Wait95 = LossyLinkPercentile(sim, 95);
	r->Retransmits = sim->Inner.Retransmits;
	r->Timeouts = sim->Inner.Timeouts;
	r->Dropped = sim->Queue.NumDropped;
	r->Overflow = sim->Queue.NumOverflow;
	r->LinkLosses = sim->LinkLosses;
	r->Full = sim->Full;

	TransportQueueFree(&sim->Queue);
	LossyLinkSenderFree(&sim->Outer);
	LossyLinkSenderFree(&sim->Inner);
	Free(sim->Record);
	Free(sim->RecordEnd);
	Free(sim->RecordPayload);
	Free(sim->SegStart);
	Free(sim->Router.Events);
	Free(sim->Forward.Events);
	Free(sim->OuterAcks.Events);
	Free(sim->InnerAcks.Events);
	Free(sim->RcvHave);
	Free(sim->InnerRcv);
	Free(sim->Waits);
	Free(sim);
}

// The waits of a run, as text
static void LossyLinkWaits(char *str, UINT size, const LOSSYLINK_RESULT *r)
{
	Format(str, size, "waits %I64u.%I64u ms (median) and %I64u.%I64u ms (95th percentile)", r->Wait50 / 1000, r->Wait50 % 1000 / 100, r->Wait95 / 1000,
		r->Wait95 % 1000 / 100);
}

// The four runs at a loss rate: the outer TCP alone, the inner TCP over CoDel and over FIFO, and the inner TCP split
static void LossyLinkCase(LOSSYLINK_CTX *ctx, UINT loss_bp)
{
	LOSSYLINK_RESULT alone, codel, fifo, split;
	char waits[MAX_SIZE], what[MAX_SIZE];

	Print("[the lossy link: %u%% loss, 50 ms round trip, 10 Mbit/s]\n", loss_bp / 100);

	LossyLinkRun(LOSSYLINK_ALONE, loss_bp, &alone);
	LossyLinkRun(TRANSPORT_QUEUE_CODEL, loss_bp, &codel);
	LossyLinkRun(TRANSPORT_QUEUE_FIFO, loss_bp, &fifo);
	LossyLinkRun(LOSSYLINK_SPLIT, loss_bp, &split);

	UINT codel_pct = (alone.Kbps != 0 ? codel.Kbps * 100 / alone.Kbps : 0);
	UINT fifo_pct = (alone.Kbps != 0 ? fifo.Kbps * 100 / alone.Kbps : 0);
	UINT split_pct = (alone.Kbps != 0 ? split.Kbps * 100 / alone.Kbps : 0);

	Print("  the outer TCP alone carries %u kbit/s of records (%u segments lost)\n", alone.Kbps, alone.LinkLosses);
	LossyLinkWaits(waits, sizeof(waits), &codel);
	Print("  the inner TCP over the queue that CoDel runs: %u kbit/s (%u%%), %s, %u retransmissions, %u timeouts, %I64u dropped by CoDel\n",
		codel.Kbps, codel_pct, waits, codel.Retransmits, codel.Timeouts, codel.Dropped);
	LossyLinkWaits(waits, sizeof(waits), &fifo);
	Print("  the inner TCP over a FIFO queue: %u kbit/s (%u%%), %s, %u retransmissions, %u timeouts, %I64u dropped at the limit\n", fifo.Kbps,
		fifo_pct, waits, fifo.Retransmits, fifo.Timeouts, fifo.Overflow);

	Print("  the inner TCP split (CORE-P2-3): %u kbit/s (%u%%), its byte stream in records of %u bytes within a window of %u bytes\n", split.Kbps, split_pct,
		(UINT)LOSSYLINK_SPLIT_CHUNK, (UINT)LOSSYLINK_SPLIT_WINDOW);

	LossyLinkCheck(ctx, alone.Full == false && codel.Full == false && fifo.Full == false && split.Full == false && alone.Kbps != 0, "  the runs stay within their arrays",
		"a run went past them");
	Format(what, sizeof(what), "  no collapse with the active queue: the inner TCP keeps at least %u%% of what the link carries", (UINT)LOSSYLINK_FLOOR);
	LossyLinkCheck(ctx, codel_pct >= LOSSYLINK_FLOOR, what, "%u%%", codel_pct);
	LossyLinkCheck(ctx, codel.Wait50 < TRANSPORT_QUEUE_TARGET, "  the active queue keeps the median wait below its target of 5 ms", "%I64u us", codel.Wait50);

	// TCP splitting: clearly above the plain run and the run with the active queue alone, and no collapse
	Format(what, sizeof(what), "  splitting: the inner goodput is at least %u%% of the plain run (FIFO) and of the run with the active queue alone (CoDel)",
		(UINT)LOSSYLINK_SPLIT_GAIN);
	LossyLinkCheck(ctx, (UINT64)split.Kbps * 100 >= (UINT64)fifo.Kbps * LOSSYLINK_SPLIT_GAIN && (UINT64)split.Kbps * 100 >= (UINT64)codel.Kbps * LOSSYLINK_SPLIT_GAIN,
		what, "%u kbit/s split, %u plain, %u with CoDel", split.Kbps, fifo.Kbps, codel.Kbps);
	Format(what, sizeof(what), "  no collapse with splitting: the inner TCP keeps at least %u%% of what the link carries", (UINT)LOSSYLINK_FLOOR);
	LossyLinkCheck(ctx, split_pct >= LOSSYLINK_FLOOR, what, "%u%%", split_pct);
}

RANZ_TEST_TAGS("lossylink", lossylink_test, "core", "Lossy link: the ingress queue of the session layer (FIFO, CoDel's drops), and an inner TCP over the TLS-443 path on a simulated link of 1% and 2% loss and 50 ms round trip, over CoDel, over FIFO and split (CORE-P2-3): no collapse with CoDel, and splitting clearly above both.");
void lossylink_test(UINT num, char **arg)
{
	LOSSYLINK_CTX *ctx = ZeroMalloc(sizeof(LOSSYLINK_CTX));

	Print("Lossy link test: the ingress queue of the session layer, and an inner TCP over the TLS-443 path on a lossy link with and without CoDel\n");

	LossyLinkFifo(ctx);
	LossyLinkCodel(ctx);
	LossyLinkCase(ctx, 100);
	LossyLinkCase(ctx, 200);

	if (ctx->NumFailed == 0)
	{
		Print("LOSSYLINK TEST OK\n");
	}
	else
	{
		Print("LOSSYLINK TEST FAILED (%u of %u checks failed)\n", ctx->NumFailed, ctx->NumChecks);
	}

	Free(ctx);
}
