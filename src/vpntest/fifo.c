// fifo.c
// Named FIFO and queue test of vpntest ("fifo" command, FND-215 #174)
//
// WriteFifo grew a FIFO x3 whenever a write did not fit behind the bytes already read, and only
// ShrinkFifoMemory, from 640 KB on, moved the live bytes back to the front: a producer and a consumer
// that never fully drained a FIFO crept it to about 1 MB. WriteFifo now moves the live bytes to the
// front first when the bytes read in front of them are at least as many. QUEUE was a FIFO of pointers
// with a 4096-byte block; it is now a power-of-two ring of void * that starts at 16 slots, doubles when
// full and, above 512 slots, halves once a quarter or less of them is in use. The test pins the order
// and the memory: a standing 1000-byte backlog with 10,000 cycles of write 3000 / read 3000 bytes stays
// at or below 16 KiB and gives back every byte in order, the move and growth paths keep the order, and
// a queue gives back its items in insertion order across wrap-around, growth and shrink, NULL when
// empty, with a NULL item ignored.
// Prints "FIFO TEST OK" only when every check passes.

#include "Mayaqua/Memory.h"
#include "Mayaqua/Str.h"

#define	FIFO_TEST_BACKLOG		1000			// Standing bytes of the backlog case
#define	FIFO_TEST_CYCLE			3000			// Bytes written, then read, per cycle of the backlog case
#define	FIFO_TEST_NUM_CYCLES	10000			// Cycles of the backlog case
#define	FIFO_TEST_MAX_MEMSIZE	16384			// Largest buffer the backlog case may reach (the old code: about 1 MB)
#define	FIFO_TEST_BUF_SIZE		8192			// Largest single write or read of the test

// Item n of a queue case, as a pointer value (never NULL for n > 0)
#define	FIFO_TEST_ITEM(n)		((void *)(UINT_PTR)(n))

static UINT fifo_test_failed = 0;
static UCHAR fifo_test_buf[FIFO_TEST_BUF_SIZE];

// Record one check: print [PASS] or [FAIL] and the check
static void FifoTestCheck(bool ok, char *what)
{
	Print("  [%s] %s\n", ok ? "PASS" : "FAIL", what);
	if (ok == false)
	{
		fifo_test_failed++;
	}
}

// Byte n of the stream a case writes: 251 is prime, so the pattern does not repeat at a power of two
static UCHAR FifoTestByte(UINT n)
{
	return (UCHAR)(n % 251);
}

// Write the next size bytes of the stream, from byte *next on, in one WriteFifo
static void FifoTestWrite(FIFO *f, UINT *next, UINT size)
{
	for (UINT i = 0;i < size;i++)
	{
		fifo_test_buf[i] = FifoTestByte(*next + i);
	}

	WriteFifo(f, fifo_test_buf, size);
	*next += size;
}

// Read size bytes in one ReadFifo: true when all of them come back and are the stream from byte *next on
static bool FifoTestRead(FIFO *f, UINT *next, UINT size)
{
	bool ok;

	ok = (ReadFifo(f, fifo_test_buf, size) == size);

	for (UINT i = 0;i < size && ok;i++)
	{
		if (fifo_test_buf[i] != FifoTestByte(*next + i))
		{
			ok = false;
		}
	}

	*next += size;

	return ok;
}

// A producer and a consumer that never fully drain the FIFO
static void FifoTestBacklog()
{
	FIFO *f = NewFifo();
	UINT written = 0, read = 0, peak;
	bool order = true, direct = true;
	char what[MAX_SIZE];

	FifoTestWrite(f, &written, FIFO_TEST_BACKLOG);
	peak = f->memsize;

	for (UINT i = 0;i < FIFO_TEST_NUM_CYCLES;i++)
	{
		FifoTestWrite(f, &written, FIFO_TEST_CYCLE);
		peak = MAX(peak, f->memsize);

		// The next byte as Connection.c reads it, straight from p + pos
		if (((UCHAR *)f->p)[f->pos] != FifoTestByte(read))
		{
			direct = false;
		}

		if (FifoTestRead(f, &read, FIFO_TEST_CYCLE) == false)
		{
			order = false;
		}
	}

	Format(what, sizeof(what), "a standing %u-byte backlog with %u cycles of write %u / read %u bytes peaks at %u bytes, at most %u",
		FIFO_TEST_BACKLOG, FIFO_TEST_NUM_CYCLES, FIFO_TEST_CYCLE, FIFO_TEST_CYCLE, peak, FIFO_TEST_MAX_MEMSIZE);
	FifoTestCheck(peak <= FIFO_TEST_MAX_MEMSIZE, what);
	FifoTestCheck(order, "every byte of the backlog case comes back in order");
	FifoTestCheck(direct, "p + pos is the next byte to read before each ReadFifo, as Connection.c reads it");

	FifoTestCheck(FifoSize(f) == FIFO_TEST_BACKLOG, "the backlog is still in the FIFO after the cycles");
	order = FifoTestRead(f, &read, FIFO_TEST_BACKLOG);
	FifoTestCheck(order && FifoSize(f) == 0 && f->pos == 0, "the backlog comes back last, then the FIFO is empty");

	ReleaseFifo(f);
}

// The move and growth paths of WriteFifo keep the order
static void FifoTestGrowth()
{
	FIFO *f;
	UINT written, read, memsize;
	bool ok;

	// Fewer bytes read than live: the FIFO grows, the bytes stay where they are
	f = NewFifo();
	written = read = 0;
	FifoTestWrite(f, &written, 3000);
	ok = FifoTestRead(f, &read, 1000);
	FifoTestWrite(f, &written, 5000);
	ok = ok && f->memsize >= 7000 && FifoSize(f) == 7000;
	ok = ok && FifoTestRead(f, &read, 7000) && FifoSize(f) == 0;
	FifoTestCheck(ok, "a write that grows a FIFO with 1000 bytes read and 2000 live keeps the order");
	ReleaseFifo(f);

	// More bytes read than live, the write still too large: the live bytes move to the front, then it grows
	f = NewFifo();
	written = read = 0;
	FifoTestWrite(f, &written, 3000);
	ok = FifoTestRead(f, &read, 2000);
	FifoTestWrite(f, &written, 6000);
	ok = ok && f->pos == 0 && f->memsize >= 7000 && FifoSize(f) == 7000;
	ok = ok && FifoTestRead(f, &read, 7000) && FifoSize(f) == 0;
	FifoTestCheck(ok, "a write that moves 1000 live bytes to the front, then grows the FIFO, keeps the order");
	ReleaseFifo(f);

	// More bytes read than live, the write fits after the move: the FIFO keeps its size
	f = NewFifo();
	written = read = 0;
	memsize = f->memsize;
	FifoTestWrite(f, &written, 3000);
	ok = FifoTestRead(f, &read, 2500);
	FifoTestWrite(f, &written, 3000);
	ok = ok && f->pos == 0 && f->memsize == memsize && FifoSize(f) == 3500;
	ok = ok && FifoTestRead(f, &read, 3500) && FifoSize(f) == 0;
	FifoTestCheck(ok, "a write that fits once 500 live bytes moved to the front keeps the order and the FIFO size");
	ReleaseFifo(f);
}

// True when n is a power of two
static bool FifoTestPow2(UINT n)
{
	return n != 0 && (n & (n - 1)) == 0;
}

// Take the next item of the queue: true when it is item *next, which then moves on by one
static bool FifoTestGet(QUEUE *q, UINT *next)
{
	bool ok = (GetNext(q) == FIFO_TEST_ITEM(*next));

	(*next)++;

	return ok;
}

// The queue ring
static void FifoTestQueue()
{
	QUEUE *q = NewQueueFast();
	UINT next_in = 1, next_out = 1, max_reserved;
	bool ok, pow2;

	FifoTestCheck(GetNext(q) == NULL && GetQueueNum(q) == 0, "GetNext of an empty queue is NULL");
	InsertQueue(q, NULL);
	FifoTestCheck(GetQueueNum(q) == 0 && GetNext(q) == NULL, "InsertQueue of NULL adds nothing");

	// Wrap-around, then growth of a wrapped ring: 10 in, 5 out, then 20 more in
	ok = true;
	for (UINT i = 0;i < 10;i++)
	{
		InsertQueue(q, FIFO_TEST_ITEM(next_in++));
	}
	for (UINT i = 0;i < 5;i++)
	{
		if (FifoTestGet(q, &next_out) == false)
		{
			ok = false;
		}
	}
	for (UINT i = 0;i < 20;i++)
	{
		InsertQueue(q, FIFO_TEST_ITEM(next_in++));
	}
	ok = ok && GetQueueNum(q) == 25;
	for (UINT i = 0;i < 25;i++)
	{
		if (FifoTestGet(q, &next_out) == false)
		{
			ok = false;
		}
	}
	FifoTestCheck(ok && GetQueueNum(q) == 0 && GetNext(q) == NULL, "items come back in insertion order across wrap-around and growth of a wrapped ring");

	// A standing backlog of 100 items, then 100,000 cycles of insert one / take one
	ok = true;
	for (UINT i = 0;i < 100;i++)
	{
		InsertQueue(q, FIFO_TEST_ITEM(next_in++));
	}
	max_reserved = q->num_reserved;
	for (UINT i = 0;i < 100000;i++)
	{
		InsertQueue(q, FIFO_TEST_ITEM(next_in++));
		if (FifoTestGet(q, &next_out) == false)
		{
			ok = false;
		}
		max_reserved = MAX(max_reserved, q->num_reserved);
	}
	FifoTestCheck(ok && GetQueueNum(q) == 100, "a standing backlog of 100 items with 100,000 cycles of insert one / take one keeps the order");
	FifoTestCheck(max_reserved <= 128, "the ring of that backlog stays at 128 slots or fewer");
	ok = true;
	for (UINT i = 0;i < 100;i++)
	{
		if (FifoTestGet(q, &next_out) == false)
		{
			ok = false;
		}
	}
	FifoTestCheck(ok && GetQueueNum(q) == 0, "the backlog comes back last, in order");

	// A burst of 5000 items: the ring grows, then gives its slots back down to 512
	for (UINT i = 0;i < 5000;i++)
	{
		InsertQueue(q, FIFO_TEST_ITEM(next_in++));
	}
	FifoTestCheck(GetQueueNum(q) == 5000 && q->num_reserved >= 5000 && FifoTestPow2(q->num_reserved), "a burst of 5000 items grows the ring to a power of two");
	ok = true;
	pow2 = true;
	for (UINT i = 0;i < 5000;i++)
	{
		if (FifoTestGet(q, &next_out) == false)
		{
			ok = false;
		}
		pow2 = pow2 && FifoTestPow2(q->num_reserved) && q->num_reserved >= q->num_item;
	}
	FifoTestCheck(ok && GetQueueNum(q) == 0 && GetNext(q) == NULL, "the burst comes back in order");
	FifoTestCheck(pow2 && q->num_reserved <= 512, "while it drains, the ring stays a power of two and halves down to 512 slots");

	ReleaseQueue(q);

	// A locked queue, released with an item still in it: ReleaseQueue frees the ring, not the items
	q = NewQueue();
	LockQueue(q);
	{
		InsertQueue(q, FIFO_TEST_ITEM(7));
		InsertQueue(q, FIFO_TEST_ITEM(8));
	}
	UnlockQueue(q);
	next_out = 7;
	ok = FifoTestGet(q, &next_out);
	ok = FifoTestGet(q, &next_out) && ok;
	ok = (GetNext(q) == NULL) && ok;
	FifoTestCheck(ok, "a queue with a lock gives back its items in order");
	InsertQueue(q, FIFO_TEST_ITEM(9));
	ReleaseQueue(q);
}

void fifo_test(UINT num, char **arg)
{
	fifo_test_failed = 0;

	FifoTestBacklog();
	FifoTestGrowth();
	FifoTestQueue();

	if (fifo_test_failed == 0)
	{
		Print("FIFO TEST OK\n");
	}
	else
	{
		Print("FIFO TEST FAILED (%u checks failed)\n", fifo_test_failed);
	}
}
