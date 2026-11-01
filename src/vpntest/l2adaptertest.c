// l2adaptertest.c
// Named L2 adapter test of vpntest ("l2adapter" command, CORE-S3-2 #72)
//
// The L2 adapter of the node (Cedar/NodeL2.c) on backends of the test, which need no driver and no KM-TEST adapter, so
// that it runs on every runner; the kmtest test (kmtesttest.c) runs the adapter on a KM-TEST adapter with XDP and SeLow.
// - arm64 is L3 only: NodeL2Offered offers an L2 adapter to x64 alone, and on a host of another architecture NodeL2New
//   refuses one even with a backend that would bind. On such a host that is all the test checks.
// - The MAC address of an adapter: NodeL2Mac gives a unicast, locally administered address from the node's static key
//   and the Network id, which the test derives on its own: the same for the same pair, another for another Network or
//   another key.
// - The backend order: a backend that cannot bind is passed over for the next one; with none that binds there is no
//   adapter.
// - The capture ring (#72, risk R1): the frames that the drain thread of the backend captures reach the owner in order.
//   While the owner is paused the ring fills, the drain thread never waits (no call of NodeL2Capture takes
//   L2TEST_CAPTURE_LIMIT ms), the excess is dropped and counted, and once the owner goes on the frames reach it again.
// - Batching (ADR-0022 amendment of 2026-10-19): a burst reaches the backend in batches of at most Batch frames, in
//   fewer calls than frames, and a lone frame reaches it within L2TEST_LONE ms. A backend that takes frames slowly fills
//   the send ring, whose excess NodeL2Send drops and counts.
// - Recovery (#72, risk R3): NodeL2Recover detaches the backend and attaches it again; a backend that reports itself
//   broken is reattached by the health check, and after NODE_L2_RESETS failed checks in a row the owner resets the
//   adapter, after which the backend is attached again.
// - Shutdown (#72, risk R2): NodeL2Free stops the injector, then detaches the backend, within L2TEST_FREE ms.
// Prints "L2ADAPTER TEST OK" only when every check passes.

#include "testlist.h"

#include "Cedar/ConfigStore.h"
#include "Cedar/Node.h"
#include "Cedar/NodeL2.h"

#include "Mayaqua/Encrypt.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Kernel.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Str.h"

#include <stdio.h>

#define	L2TEST_BUDGET			120000		// The whole test ends within this time, or the watchdog ends the process (ms)
#define	L2TEST_BOUND			15000		// A bounded wait on observable state (ms)
#define	L2TEST_POLL				10			// Poll interval of observable state (ms)
#define	L2TEST_CAPTURE_LIMIT	500			// ms that no call of NodeL2Capture may take, even while the owner is paused (a runner may preempt the thread)
#define	L2TEST_LONE				500			// ms within which a lone frame reaches the backend
#define	L2TEST_FREE				3000		// ms within which NodeL2Free takes an adapter down
#define	L2TEST_SLOTS			256			// Frames of each ring of the adapters of the test
#define	L2TEST_FRAME			64			// Bytes of a frame of the test
#define	L2TEST_ETHERTYPE		0x88B5		// The local experimental EtherType of IEEE 802 for the frames of the test
#define	L2TEST_NETWORK			72			// The Network id of the MAC addresses of the test
#define	L2TEST_LABEL			"ranz l2 adapter"	// What the name of a MAC address begins with (NODE_L2_MAC_LABEL)
#define	L2TEST_LABEL_SIZE		15

// The checks of the test
typedef struct L2TEST_CTX
{
	UINT NumChecks;
	UINT NumFailed;
} L2TEST_CTX;

// The backend of the test: a drain thread that captures the frames that the test asks for, numbered, and an injection
// that counts what it gets. One adapter at a time uses it.
typedef struct L2TEST_FAKE
{
	volatile LONG FailAttaches;		// Attaches that fail on purpose before one succeeds
	volatile LONG Attaches;			// Attaches that succeeded
	volatile LONG Detaches;			// Detaches
	volatile LONG Broken;			// The backend reports its binding broken while this is set
	HANDLE Thread;					// The drain thread
	volatile LONG Halt;				// ... ends it
	NODE_L2 *Adapter;				// The adapter it is attached to
	volatile LONG Produce;			// Frames that the drain thread is still to capture
	volatile LONG Pace;				// It sleeps a millisecond after each burst while this is set, so the owner keeps up
	volatile LONG64 Sequence;		// The number of the last frame it captured
	volatile LONG64 Taken;			// Frames that NodeL2Capture took
	volatile LONG64 Refused;		// ... and refused
	volatile LONG64 Slowest;		// Microseconds of the slowest call of NodeL2Capture
	volatile LONG InjectDelay;		// ms that each injection waits: a slow backend
	volatile LONG64 Injected;		// Frames that it took for the host
	volatile LONG64 Calls;			// ... in this many calls
	volatile LONG MaxBatch;			// The largest batch of one call
	volatile LONG Resets;			// Times that the reset of the owner ran
} L2TEST_FAKE;

// The owner of an adapter: it counts the frames that it gets, checks their order, and waits while it is paused
typedef struct L2TEST_OWNER
{
	volatile LONG Paused;			// The owner waits for Resume while this is set
	HANDLE Resume;
	volatile LONG64 Delivered;		// Frames that it got
	UINT64 Last;					// The number of the last frame
	volatile LONG64 OutOfOrder;		// Frames whose number was not above the one before
} L2TEST_OWNER;

static L2TEST_FAKE l2test_fake;

static bool L2TestCheck(L2TEST_CTX *ctx, bool ok, char *what, char *fmt, ...) RANZ_PRINTF_FORMAT(4, 5);
static bool L2TestCheck(L2TEST_CTX *ctx, bool ok, char *what, char *fmt, ...)
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
static DWORD WINAPI L2TestWatchdog(LPVOID param)
{
	char msg[MAX_SIZE];
	DWORD written = 0;

	if (WaitForSingleObject((HANDLE)param, L2TEST_BUDGET) != WAIT_TIMEOUT)
	{
		return 0;
	}

	int len = snprintf(msg, sizeof(msg), "L2ADAPTER TEST FAILED (did not finish within %u ms)\n", L2TEST_BUDGET);
	if (len > 0)
	{
		WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), msg, (DWORD)MIN((UINT)len, (UINT)sizeof(msg) - 1), &written, NULL);
	}

	TerminateProcess(GetCurrentProcess(), 1);

	return 0;
}

// Wait up to L2TEST_BOUND ms until *value reaches at least want; false when it does not
static bool L2TestWait64(volatile LONG64 *value, LONG64 want)
{
	UINT64 end = GetTickCount64() + L2TEST_BOUND;

	while (ReadAcquire64(value) < want)
	{
		if (GetTickCount64() >= end)
		{
			return false;
		}
		Sleep(L2TEST_POLL);
	}

	return true;
}

// Wait up to L2TEST_BOUND ms until *value reaches at least want; false when it does not
static bool L2TestWait32(volatile LONG *value, LONG want)
{
	UINT64 end = GetTickCount64() + L2TEST_BOUND;

	while (ReadAcquire(value) < want)
	{
		if (GetTickCount64() >= end)
		{
			return false;
		}
		Sleep(L2TEST_POLL);
	}

	return true;
}

// Wait up to L2TEST_BOUND ms until the counter at offset of the status of an adapter reaches at least want
static bool L2TestWaitStatus(NODE_L2 *a, UINT offset, UINT64 want, NODE_L2_STATUS *st)
{
	UINT64 end = GetTickCount64() + L2TEST_BOUND;

	while (true)
	{
		NodeL2GetStatus(a, st);
		if (*(UINT64 *)((UCHAR *)st + offset) >= want)
		{
			return true;
		}
		if (GetTickCount64() >= end)
		{
			return false;
		}
		Sleep(L2TEST_POLL);
	}
}

// A frame of the test: to the broadcast address from a locally administered one, with the EtherType of the test and the
// number seq after the header
static void L2TestFrame(UCHAR *f, UINT64 seq)
{
	Zero(f, L2TEST_FRAME);
	memset(f, 0xFF, 6);
	f[6] = 0x02;
	f[11] = 0x01;
	f[12] = (UCHAR)(L2TEST_ETHERTYPE >> 8);
	f[13] = (UCHAR)L2TEST_ETHERTYPE;
	Copy(f + 14, &seq, sizeof(seq));
}

// The drain thread of the backend of the test: the frames that the test asks for, numbered from 1 on, through
// NodeL2Capture in bursts of up to 64, with the time of each call
static DWORD WINAPI L2TestFakeDrain(LPVOID param)
{
	UCHAR frame[L2TEST_FRAME];
	LARGE_INTEGER freq;

	QueryPerformanceFrequency(&freq);

	while (ReadAcquire(&l2test_fake.Halt) == 0)
	{
		UINT burst = 0;

		while (burst < 64 && ReadAcquire(&l2test_fake.Produce) > 0)
		{
			LARGE_INTEGER t0, t1;
			UINT64 seq = (UINT64)InterlockedIncrement64(&l2test_fake.Sequence);

			L2TestFrame(frame, seq);
			QueryPerformanceCounter(&t0);
			bool taken = NodeL2Capture(l2test_fake.Adapter, frame, sizeof(frame));
			QueryPerformanceCounter(&t1);

			LONG64 us = (LONG64)((t1.QuadPart - t0.QuadPart) * 1000000 / freq.QuadPart);
			if (us > ReadAcquire64(&l2test_fake.Slowest))
			{
				InterlockedExchange64(&l2test_fake.Slowest, us);
			}

			InterlockedIncrement64(taken ? &l2test_fake.Taken : &l2test_fake.Refused);
			InterlockedDecrement(&l2test_fake.Produce);
			burst++;
		}

		if (burst != 0)
		{
			NodeL2CaptureDone(l2test_fake.Adapter);
		}
		if (burst == 0 || ReadAcquire(&l2test_fake.Pace) != 0)
		{
			Sleep(1);
		}
	}

	return 0;
}

// Attach: fails while FailAttaches is above 0, else starts the drain thread
static bool L2TestFakeAttach(NODE_L2 *a, char *error, UINT error_size)
{
	if (l2test_fake.FailAttaches > 0)
	{
		l2test_fake.FailAttaches--;
		StrCpy(error, error_size, "the backend of the test refuses this attach on purpose");
		return false;
	}

	l2test_fake.Adapter = a;
	l2test_fake.Halt = 0;
	l2test_fake.Thread = CreateThread(NULL, 0, L2TestFakeDrain, NULL, 0, NULL);
	if (l2test_fake.Thread == NULL)
	{
		StrCpy(error, error_size, "the drain thread of the test could not start");
		return false;
	}

	InterlockedIncrement(&l2test_fake.Attaches);
	a->BackendState = &l2test_fake;

	return true;
}

static UINT L2TestFakeInject(NODE_L2 *a, const UCHAR **frames, const UINT *sizes, UINT num)
{
	LONG delay = ReadAcquire(&l2test_fake.InjectDelay);

	if (delay > 0)
	{
		Sleep((UINT)delay);
	}

	if ((LONG)num > ReadAcquire(&l2test_fake.MaxBatch))
	{
		InterlockedExchange(&l2test_fake.MaxBatch, (LONG)num);
	}
	InterlockedIncrement64(&l2test_fake.Calls);
	InterlockedAdd64(&l2test_fake.Injected, (LONG64)num);

	return num;
}

static bool L2TestFakeHealthy(NODE_L2 *a)
{
	return (ReadAcquire(&l2test_fake.Broken) == 0);
}

static bool L2TestFakeDetach(NODE_L2 *a, UINT timeout)
{
	if (a->BackendState == NULL)
	{
		return true;
	}

	a->BackendState = NULL;
	InterlockedExchange(&l2test_fake.Halt, 1);
	bool ok = (WaitForSingleObject(l2test_fake.Thread, timeout) == WAIT_OBJECT_0);
	CloseHandle(l2test_fake.Thread);
	l2test_fake.Thread = NULL;
	InterlockedIncrement(&l2test_fake.Detaches);

	return ok;
}

// A backend that never binds
static bool L2TestNeverAttach(NODE_L2 *a, char *error, UINT error_size)
{
	StrCpy(error, error_size, "this backend of the test never binds");
	return false;
}

static const NODE_L2_BACKEND l2test_fake_backend = {"fake", L2TestFakeAttach, L2TestFakeInject, L2TestFakeHealthy, L2TestFakeDetach};
static const NODE_L2_BACKEND l2test_never_backend = {"never", L2TestNeverAttach, L2TestFakeInject, L2TestFakeHealthy, L2TestFakeDetach};

// The reset of the owner: counts, and gives the index that the adapter had
static bool L2TestReset(void *param, UINT *if_index)
{
	InterlockedIncrement(&l2test_fake.Resets);
	return true;
}

// The owner: counts the frames, checks their numbers, and waits while it is paused
static void L2TestOwnerProc(NODE_L2 *a, void *param, const UCHAR *frame, UINT size)
{
	L2TEST_OWNER *o = (L2TEST_OWNER *)param;
	UINT64 seq = 0;

	if (ReadAcquire(&o->Paused) != 0)
	{
		WaitForSingleObject(o->Resume, L2TEST_BOUND);
	}

	if (size >= 14 + sizeof(seq))
	{
		Copy(&seq, frame + 14, sizeof(seq));
	}
	if (seq <= o->Last)
	{
		InterlockedIncrement64(&o->OutOfOrder);
	}
	o->Last = seq;

	InterlockedIncrement64(&o->Delivered);
}

// A new empty data directory under the temp directory of the process, with a configuration store: no role, one worker
static void L2TestNewDir(wchar_t *dir, UINT size)
{
	wchar_t tmp[MAX_PATH];
	wchar_t path[MAX_PATH];

	UniFormat(tmp, sizeof(tmp), L"l2adaptertest_%u", Rand32());
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
static void L2TestDeleteDir(wchar_t *dir)
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

// The configuration of an adapter of the test on the backends of list, with the owner o
static void L2TestConfig(NODE_L2_CONFIG *cfg, const NODE_L2_BACKEND *const *list, UINT num, L2TEST_OWNER *o)
{
	Zero(cfg, sizeof(NODE_L2_CONFIG));
	cfg->Proc = L2TestOwnerProc;
	cfg->Param = o;
	cfg->Reset = L2TestReset;
	cfg->Backends = list;
	cfg->NumBackends = num;
	cfg->Slots = L2TEST_SLOTS;
	cfg->NoProbe = true;
}

// The MAC address of an adapter, as the test derives it on its own: the first six bytes of the SHA-256 of the label, the
// key and the Network id (big-endian), unicast and locally administered
static void L2TestMac(UCHAR *mac, const UCHAR *key, UINT network_id)
{
	UCHAR name[L2TEST_LABEL_SIZE + PEER_KEY_SIZE + 4];
	UCHAR hash[SHA256_SIZE];

	Copy(name, L2TEST_LABEL, L2TEST_LABEL_SIZE);
	Copy(name + L2TEST_LABEL_SIZE, key, PEER_KEY_SIZE);
	name[L2TEST_LABEL_SIZE + PEER_KEY_SIZE] = (UCHAR)(network_id >> 24);
	name[L2TEST_LABEL_SIZE + PEER_KEY_SIZE + 1] = (UCHAR)(network_id >> 16);
	name[L2TEST_LABEL_SIZE + PEER_KEY_SIZE + 2] = (UCHAR)(network_id >> 8);
	name[L2TEST_LABEL_SIZE + PEER_KEY_SIZE + 3] = (UCHAR)network_id;
	Sha2_256(hash, name, sizeof(name));

	Copy(mac, hash, 6);
	mac[0] = (UCHAR)((mac[0] & 0xFC) | 0x02);
}

// The MAC address of an adapter
static void L2TestMacs(L2TEST_CTX *ctx)
{
	UCHAR key1[PEER_KEY_SIZE];
	UCHAR key2[PEER_KEY_SIZE];
	UCHAR mine[6], again[6], other_net[6], other_key[6], expected[6];

	memset(key1, 0x11, sizeof(key1));
	memset(key2, 0x22, sizeof(key2));

	NodeL2Mac(mine, key1, L2TEST_NETWORK);
	NodeL2Mac(again, key1, L2TEST_NETWORK);
	NodeL2Mac(other_net, key1, L2TEST_NETWORK + 1);
	NodeL2Mac(other_key, key2, L2TEST_NETWORK);
	L2TestMac(expected, key1, L2TEST_NETWORK);

	L2TestCheck(ctx, Cmp(mine, expected, 6) == 0, "NodeL2Mac derives the address from the label, the static key and the Network id",
		"%02X-%02X-%02X-%02X-%02X-%02X, not %02X-%02X-%02X-%02X-%02X-%02X", (UINT)mine[0], (UINT)mine[1], (UINT)mine[2], (UINT)mine[3], (UINT)mine[4], (UINT)mine[5],
		(UINT)expected[0], (UINT)expected[1], (UINT)expected[2], (UINT)expected[3], (UINT)expected[4], (UINT)expected[5]);
	L2TestCheck(ctx, (mine[0] & 0x01) == 0 && (mine[0] & 0x02) != 0, "the address is unicast and locally administered", "first byte %02X", (UINT)mine[0]);
	L2TestCheck(ctx, Cmp(mine, again, 6) == 0, "the same node and Network give the same address", "they differ");
	L2TestCheck(ctx, Cmp(mine, other_net, 6) != 0 && Cmp(mine, other_key, 6) != 0, "another Network or another node gives another address", "an address repeats");
}

// The backend order, the capture ring with a paused owner, batching, recovery and shutdown, on the running node n
static void L2TestAdapter(L2TEST_CTX *ctx, NODE *n)
{
	const NODE_L2_BACKEND *never_list[1];
	const NODE_L2_BACKEND *list[2];
	NODE_L2_CONFIG cfg;
	NODE_L2_STATUS st;
	L2TEST_OWNER owner;
	UCHAR frame[L2TEST_FRAME];

	Zero(&owner, sizeof(owner));
	owner.Resume = CreateEventW(NULL, TRUE, FALSE, NULL);
	never_list[0] = &l2test_never_backend;
	list[0] = &l2test_never_backend;
	list[1] = &l2test_fake_backend;

	// No backend binds: no adapter
	L2TestConfig(&cfg, never_list, 1, &owner);
	NODE_L2 *none = NodeL2New(n, &cfg);
	L2TestCheck(ctx, none == NULL, "with no backend that binds, NodeL2New gives no adapter", "it gave one");
	NodeL2Free(none);

	// The first backend that binds
	L2TestConfig(&cfg, list, 2, &owner);
	cfg.Batch = 16;
	cfg.FlushUs = 1000;
	NODE_L2 *a = NodeL2New(n, &cfg);
	NodeL2GetStatus(a, &st);
	if (L2TestCheck(ctx, a != NULL && StrCmp(st.Backend, "fake") == 0 && l2test_fake.Attaches == 1, "a backend that cannot bind is passed over for the next one", "%s, backend '%s', %u attaches", a != NULL ? "an adapter" : "no adapter", st.Backend, (UINT)l2test_fake.Attaches) == false)
	{
		NodeL2Free(a);
		CloseHandle(owner.Resume);
		return;
	}

	// The capture ring: in order, nothing dropped while the owner keeps up
	InterlockedExchange(&l2test_fake.Pace, 1);
	InterlockedExchange(&l2test_fake.Produce, 1000);
	bool all = L2TestWait64(&owner.Delivered, 1000);
	L2TestCheck(ctx, all && owner.OutOfOrder == 0 && l2test_fake.Refused == 0, "the frames that the backend captures reach the owner in order",
		"%I64u of 1000 delivered, %I64u out of order, %I64u refused", (UINT64)owner.Delivered, (UINT64)owner.OutOfOrder, (UINT64)l2test_fake.Refused);

	// A paused owner: the ring fills, the drain thread never waits, the excess is dropped and counted
	InterlockedExchange(&owner.Paused, 1);
	ResetEvent(owner.Resume);
	InterlockedExchange64(&l2test_fake.Slowest, 0);
	InterlockedExchange(&l2test_fake.Pace, 0);
	InterlockedExchange(&l2test_fake.Produce, 5000);
	for (UINT64 end = GetTickCount64() + L2TEST_BOUND; ReadAcquire(&l2test_fake.Produce) > 0 && GetTickCount64() < end;)
	{
		Sleep(L2TEST_POLL);
	}
	NodeL2GetStatus(a, &st);
	L2TestCheck(ctx, ReadAcquire(&l2test_fake.Produce) == 0 && l2test_fake.Refused > 0 && st.CaptureDrops == (UINT64)l2test_fake.Refused,
		"while the owner is paused the capture ring fills and the excess is dropped and counted, never pushed back",
		"%d frames still to capture, %I64u refused, %I64u counted as dropped", (int)l2test_fake.Produce, (UINT64)l2test_fake.Refused, st.CaptureDrops);
	L2TestCheck(ctx, l2test_fake.Slowest < L2TEST_CAPTURE_LIMIT * 1000, "the drain thread never waits for the owner",
		"the slowest NodeL2Capture took %I64u us", (UINT64)l2test_fake.Slowest);

	// The owner goes on: what the ring held reaches it, and so do the next frames, in order
	InterlockedExchange(&l2test_fake.Pace, 1);
	InterlockedExchange(&owner.Paused, 0);
	SetEvent(owner.Resume);
	InterlockedExchange(&l2test_fake.Produce, 500);
	for (UINT64 end = GetTickCount64() + L2TEST_BOUND; ReadAcquire(&l2test_fake.Produce) > 0 && GetTickCount64() < end;)
	{
		Sleep(L2TEST_POLL);
	}
	LONG64 taken = ReadAcquire64(&l2test_fake.Taken);
	all = L2TestWait64(&owner.Delivered, taken);
	L2TestCheck(ctx, all && owner.OutOfOrder == 0 && owner.Last == (UINT64)l2test_fake.Sequence,
		"once the owner goes on, every frame that the ring held and the next ones reach it, in order",
		"%I64u of %I64u delivered, %I64u out of order, the last %I64u of %I64u", (UINT64)owner.Delivered, (UINT64)taken, (UINT64)owner.OutOfOrder, owner.Last, (UINT64)l2test_fake.Sequence);

	// Batching: a burst in batches of at most 16 frames, sent a hundred at a time so that the ring never fills
	LONG64 injected_before = ReadAcquire64(&l2test_fake.Injected);
	LONG64 calls_before = ReadAcquire64(&l2test_fake.Calls);
	UINT sent = 0;
	all = true;
	for (UINT i = 0; i < 1000 && all; i++)
	{
		L2TestFrame(frame, i + 1);
		sent += (NodeL2Send(a, frame, sizeof(frame)) ? 1 : 0);
		if ((i % 100) == 99)
		{
			all = L2TestWait64(&l2test_fake.Injected, injected_before + sent);
		}
	}
	LONG64 calls = ReadAcquire64(&l2test_fake.Calls) - calls_before;
	L2TestCheck(ctx, all && sent == 1000 && l2test_fake.MaxBatch <= 16 && calls < 1000,
		"a burst of frames reaches the backend in batches of at most Batch frames, in fewer calls than frames",
		"%u of 1000 sent, %I64u injected, %I64u calls, the largest batch %d", sent, (UINT64)(ReadAcquire64(&l2test_fake.Injected) - injected_before), (UINT64)calls, (int)l2test_fake.MaxBatch);

	injected_before = ReadAcquire64(&l2test_fake.Injected);
	UINT64 t0 = GetTickCount64();
	L2TestFrame(frame, 1);
	NodeL2Send(a, frame, sizeof(frame));
	all = L2TestWait64(&l2test_fake.Injected, injected_before + 1);
	UINT64 lone = GetTickCount64() - t0;
	L2TestCheck(ctx, all && lone <= L2TEST_LONE, "a lone frame reaches the backend once the flush time passed", "after %I64u ms", lone);

	// A slow backend: the send ring fills, and NodeL2Send drops and counts the excess
	InterlockedExchange(&l2test_fake.InjectDelay, 20);
	UINT refused = 0;
	for (UINT i = 0; i < 5000; i++)
	{
		L2TestFrame(frame, i + 1);
		refused += (NodeL2Send(a, frame, sizeof(frame)) ? 0 : 1);
	}
	NodeL2GetStatus(a, &st);
	L2TestCheck(ctx, refused > 0 && st.SendDrops >= refused, "a full send ring drops the frames that do not fit and counts them",
		"%u refused, %I64u counted", refused, st.SendDrops);
	InterlockedExchange(&l2test_fake.InjectDelay, 0);

	// Recovery: asked for, then by the health check of a broken backend, then the reset of the owner
	LONG attaches = l2test_fake.Attaches;
	bool recovered = NodeL2Recover(a);
	NodeL2GetStatus(a, &st);
	L2TestCheck(ctx, recovered && l2test_fake.Attaches == attaches + 1 && st.Reattaches == 1 && StrCmp(st.Backend, "fake") == 0,
		"NodeL2Recover detaches the backend and attaches it again", "%s, %d attaches, %I64u reattaches, backend '%s'", recovered ? "true" : "false", (int)l2test_fake.Attaches, st.Reattaches, st.Backend);

	InterlockedExchange(&l2test_fake.Broken, 1);
	bool reattached = L2TestWaitStatus(a, (UINT)offsetof(NODE_L2_STATUS, Reattaches), 2, &st);
	InterlockedExchange(&l2test_fake.Broken, 0);
	L2TestCheck(ctx, reattached, "the health check reattaches a backend that reports its binding broken", "%I64u reattaches", st.Reattaches);

	InterlockedExchange(&l2test_fake.FailAttaches, 1000);
	InterlockedExchange(&l2test_fake.Broken, 1);
	UINT64 end = GetTickCount64() + L2TEST_BOUND;
	while (ReadAcquire(&l2test_fake.Resets) == 0 && GetTickCount64() < end)
	{
		Sleep(L2TEST_POLL);
	}
	NodeL2GetStatus(a, &st);
	L2TestCheck(ctx, l2test_fake.Resets == 1 && st.Resets == 1 && st.Reattaches >= 3,
		"after NODE_L2_RESETS failed checks in a row the owner resets the adapter", "%d resets of the owner, %I64u counted, %I64u reattaches", (int)l2test_fake.Resets, st.Resets, st.Reattaches);
	InterlockedExchange(&l2test_fake.FailAttaches, 0);
	InterlockedExchange(&l2test_fake.Broken, 0);
	attaches = l2test_fake.Attaches;
	bool back = L2TestWait32(&l2test_fake.Attaches, attaches + 1);
	NodeL2GetStatus(a, &st);
	L2TestCheck(ctx, back && StrCmp(st.Backend, "fake") == 0, "the backend is attached again once it binds", "backend '%s'", st.Backend);

	// Shutdown
	LONG detaches = l2test_fake.Detaches;
	t0 = GetTickCount64();
	bool freed = NodeL2Free(a);
	UINT64 took = GetTickCount64() - t0;
	L2TestCheck(ctx, freed && took <= L2TEST_FREE && l2test_fake.Detaches == detaches + 1 && l2test_fake.Thread == NULL,
		"NodeL2Free stops the injector and detaches the backend in time", "%s after %I64u ms, %d detaches", freed ? "true" : "false", took, (int)(l2test_fake.Detaches - detaches));

	CloseHandle(owner.Resume);
}

// l2adapter: the L2 adapter of the node on backends of the test (CORE-S3-2)
RANZ_TEST("l2adapter", l2adapter_test, "L2 adapter: the KM-TEST adapter of a Network on backends of the test: arm64 is L3 only, the MAC address of node and Network, the backend order, the capture ring with a paused owner, batching, recovery and shutdown.");
void l2adapter_test(UINT num, char **arg)
{
	L2TEST_CTX ctx;
	SYSTEM_INFO info;
	HANDLE done = CreateEventW(NULL, TRUE, FALSE, NULL);
	HANDLE watchdog = (done != NULL ? CreateThread(NULL, 0, L2TestWatchdog, done, 0, NULL) : NULL);
	wchar_t dir[MAX_PATH];
	wchar_t log_dir[MAX_PATH];

	Zero(&ctx, sizeof(ctx));
	Zero(&l2test_fake, sizeof(l2test_fake));
	Zero(&info, sizeof(info));
	GetNativeSystemInfo(&info);

	Print("L2 adapter test: the L2 adapter of the node on backends of the test\n");

	L2TestCheck(&ctx, NodeL2Offered(PROCESSOR_ARCHITECTURE_AMD64) && NodeL2Offered(PROCESSOR_ARCHITECTURE_ARM64) == false && NodeL2Offered(PROCESSOR_ARCHITECTURE_INTEL) == false,
		"an L2 adapter is offered on x64 alone: arm64 is L3 only", "x64 %d, arm64 %d, x86 %d", (int)NodeL2Offered(PROCESSOR_ARCHITECTURE_AMD64),
		(int)NodeL2Offered(PROCESSOR_ARCHITECTURE_ARM64), (int)NodeL2Offered(PROCESSOR_ARCHITECTURE_INTEL));
	L2TestMacs(&ctx);

	L2TestNewDir(dir, sizeof(dir));
	NODE *n = NewNode(dir);
	bool started = (n != NULL && NodeStart(n));

	if (L2TestCheck(&ctx, started, "a node without a role runs for the adapters", "NewNode or NodeStart failed"))
	{
		if (info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64)
		{
			L2TestAdapter(&ctx, n);
		}
		else
		{
			// This host is L3 only: not even a backend that would bind gives an adapter
			const NODE_L2_BACKEND *list[1];
			NODE_L2_CONFIG cfg;
			L2TEST_OWNER owner;

			Zero(&owner, sizeof(owner));
			list[0] = &l2test_fake_backend;
			L2TestConfig(&cfg, list, 1, &owner);
			NODE_L2 *a = NodeL2New(n, &cfg);
			L2TestCheck(&ctx, a == NULL && l2test_fake.Attaches == 0, "on this host (architecture %u) no L2 adapter is offered, whatever the backend",
				"an adapter with %d attaches", (int)l2test_fake.Attaches);
			NodeL2Free(a);
			Print("  architecture %u: L3 only, the adapter itself is not tested here\n", (UINT)info.wProcessorArchitecture);
		}
	}

	if (n != NULL)
	{
		NodeStop(n);
		FreeNode(n);
	}
	ConbinePathW(log_dir, sizeof(log_dir), dir, NODE_LOG_DIR_NAME);
	L2TestDeleteDir(log_dir);
	L2TestDeleteDir(dir);

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
		Print("L2ADAPTER TEST OK\n");
	}
	else
	{
		Print("L2ADAPTER TEST FAILED (%u of %u checks failed)\n", ctx.NumFailed, ctx.NumChecks);
	}
}
