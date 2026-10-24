// NodeL2.c
// The L2 adapter of a node (NodeL2.h; CORE-S3-2, #72): the rings between a backend and the owner of the adapter, the
// injector thread, the health of the backend with its recovery, and the MAC address of an adapter. The backends are
// NodeL2Xdp.c and NodeL2SeLow.c, the KM-TEST adapter is NodeKmTest.c.

#include "Node.h"

#include "Mayaqua/Encrypt.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Str.h"

#include "NodeInternal.h"
#include "NodeL2.h"

#include <iphlpapi.h>

// Bytes of the Neighbor Solicitation of a probe: an Ethernet header, an IPv6 header, the solicitation and its source
// link-layer address option
#define NODE_L2_PROBE_SIZE 86

// The MAC address of the probes, the last byte 0 or 1 by turns, and the link-local IPv6 address that they come from
static const UCHAR node_l2_probe_mac[6] = {0x02, 0x72, 0x61, 0x6E, 0x7A, 0x00};
static const UCHAR node_l2_probe_ip[16] = {0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0x72, 0x61, 0x6E, 0x7A, 0x6C, 0x32};

// One frame of a ring. Sequence is the position at which the slot is taken next: the producer that claims the slot
// publishes it with the position after its own, and the consumer gives it back with the position of its next round.
typedef struct NODE_L2_SLOT {
	volatile LONG64 Sequence;
	UINT Size;
	UCHAR Frame[NODE_L2_MAX_FRAME];
} NODE_L2_SLOT;

// A bounded ring of frames with any number of producers and one consumer, without a lock (the bounded queue of Dmitry
// Vyukov). A producer claims the slot at the tail with a compare-and-swap and publishes it with its sequence; the
// consumer reads the slots at the head in order and in place, and gives each back with its sequence. The tail and the
// head are on cache lines of their own.
struct NODE_L2_RING {
	NODE_L2_SLOT *Slots;
	UINT Mask;
	UCHAR Pad1[64];
	volatile LONG64 Tail;
	UCHAR Pad2[64];
	LONG64 Head;
	UCHAR Pad3[64];
};

// A ring of slots frames, a power of two
static NODE_L2_RING *NodeL2RingNew(UINT slots) {
	NODE_L2_RING *r = ZeroMalloc(sizeof(NODE_L2_RING));

	r->Slots = ZeroMalloc((UINT)(sizeof(NODE_L2_SLOT) * slots));
	r->Mask = slots - 1;
	for (UINT i = 0; i < slots; i++)
		r->Slots[i].Sequence = (LONG64)i;

	return r;
}

static void NodeL2RingFree(NODE_L2_RING *r) {
	if (r == NULL)
		return;

	Free(r->Slots);
	Free(r);
}

// Put a copy of a frame into the ring; false when the ring is full. Any thread; it never waits.
static bool NodeL2RingPush(NODE_L2_RING *r, const UCHAR *frame, UINT size) {
	LONG64 pos = ReadAcquire64(&r->Tail);

	while (true) {
		NODE_L2_SLOT *s = &r->Slots[(UINT64)pos & r->Mask];
		LONG64 seq = ReadAcquire64(&s->Sequence);

		// The slot still holds the frame of the round before: the ring is full
		if (seq < pos)
			return false;

		// Another producer took the slot: try again from the tail
		if (seq > pos) {
			pos = ReadAcquire64(&r->Tail);
			continue;
		}

		LONG64 seen = InterlockedCompareExchange64(&r->Tail, pos + 1, pos);
		if (seen == pos) {
			s->Size = size;
			Copy(s->Frame, frame, size);
			WriteRelease64(&s->Sequence, pos + 1);
			return true;
		}

		pos = seen;
	}
}

// The frame at offset i from the head of the ring, NULL when none is there yet. The consumer only; i is below the size
// of the ring.
static NODE_L2_SLOT *NodeL2RingPeek(NODE_L2_RING *r, UINT i) {
	LONG64 pos = r->Head + (LONG64)i;
	NODE_L2_SLOT *s = &r->Slots[(UINT64)pos & r->Mask];

	return (ReadAcquire64(&s->Sequence) == pos + 1 ? s : NULL);
}

// Give the num frames at the head of the ring back to the producers. The consumer only.
static void NodeL2RingRelease(NODE_L2_RING *r, UINT num) {
	for (UINT i = 0; i < num; i++) {
		LONG64 pos = r->Head + (LONG64)i;

		WriteRelease64(&r->Slots[(UINT64)pos & r->Mask].Sequence, pos + (LONG64)r->Mask + 1);
	}

	r->Head += (LONG64)num;
}

// Whether a host of the processor architecture machine (PROCESSOR_ARCHITECTURE_*, as GetNativeSystemInfo gives it) is
// offered an L2 adapter: x64 only. arm64 has no production-signed XDP runtime and no SeLow package (ADR-0022 amendment
// of 2026-10-21), so it is L3 only.
bool NodeL2Offered(UINT machine) {
	return (machine == PROCESSOR_ARCHITECTURE_AMD64);
}

// The MAC address of the L2 adapter of the Network network_id on the node of the static key key (PEER_KEY_SIZE bytes):
// the first six bytes of the SHA-256 of NODE_L2_MAC_LABEL, the key and the Network id (4 bytes, big-endian), made a
// unicast and locally administered address. The same node and Network give the same address on every start, so the
// host keeps its neighbours; another Network or another node gives another (ADR-0022, KM-TEST details).
void NodeL2Mac(UCHAR *mac, const UCHAR *key, UINT network_id) {
	UCHAR name[sizeof(NODE_L2_MAC_LABEL) - 1 + PEER_KEY_SIZE + 4];
	UCHAR hash[SHA256_SIZE];
	UINT label = (UINT)sizeof(NODE_L2_MAC_LABEL) - 1;

	if (mac == NULL || key == NULL)
		return;

	Copy(name, NODE_L2_MAC_LABEL, label);
	Copy(name + label, key, PEER_KEY_SIZE);
	name[label + PEER_KEY_SIZE] = (UCHAR)(network_id >> 24);
	name[label + PEER_KEY_SIZE + 1] = (UCHAR)(network_id >> 16);
	name[label + PEER_KEY_SIZE + 2] = (UCHAR)(network_id >> 8);
	name[label + PEER_KEY_SIZE + 3] = (UCHAR)network_id;
	Sha2_256(hash, name, sizeof(name));

	Copy(mac, hash, 6);
	mac[0] = (UCHAR)((mac[0] & 0xFC) | 0x02);
}

// The LUID, the GUID and the MAC address of the interface of the adapter, as Windows reports them
static void NodeL2ReadInterface(NODE_L2 *a) {
	MIB_IF_ROW2 row;

	if (a->IfIndex == 0)
		return;

	Zero(&row, sizeof(row));
	row.InterfaceIndex = a->IfIndex;
	if (GetIfEntry2(&row) != NO_ERROR)
		return;

	a->Luid = row.InterfaceLuid.Value;
	a->Guid = row.InterfaceGuid;
	if (row.PhysicalAddressLength == 6)
		Copy(a->Mac, row.PhysicalAddress, 6);
}

// Whether a frame that the host sent is its answer to a probe: to one of the two MAC addresses of the probes
static bool NodeL2IsProbeAnswer(const UCHAR *frame, UINT size) {
	return (size >= 6 && Cmp(frame, node_l2_probe_mac, 5) == 0 && frame[5] <= 1);
}

// The adapter queue: the frames of the capture ring to the owner, NODE_L2_DELIVER at most per run. A full run sets the
// event again, so that the I/O thread passes a quiescent point between two runs. The host's answers to the probes go
// nowhere.
static void NodeL2Deliver(NODE_QUEUE *q, void *param) {
	NODE_L2 *a = (NODE_L2 *)param;
	UINT num = 0;

	for (; num < NODE_L2_DELIVER; num++) {
		NODE_L2_SLOT *s = NodeL2RingPeek(a->Captures, 0);
		if (s == NULL)
			break;

		if (NodeL2IsProbeAnswer(s->Frame, s->Size) == false) {
			a->Proc(a, a->Param, s->Frame, s->Size);
			InterlockedIncrement64(&a->Delivered);
		}

		NodeL2RingRelease(a->Captures, 1);
	}

	if (num == NODE_L2_DELIVER)
		SetEvent(a->CaptureEvent);
}

// Take a frame that the host sent out of the adapter into the capture ring, on the drain thread of the backend. A
// frame that finds the ring full, or that no Ethernet frame of the adapter can be, is dropped and counted: the call
// never waits, takes no lock and allocates nothing. NodeL2CaptureDone wakes the adapter queue after a batch.
bool NodeL2Capture(NODE_L2 *a, const UCHAR *frame, UINT size) {
	if (size < NODE_L2_MIN_FRAME || size > NODE_L2_MAX_FRAME) {
		InterlockedIncrement64(&a->Oversize);
		return false;
	}

	if (NodeL2RingPush(a->Captures, frame, size) == false) {
		InterlockedIncrement64(&a->CaptureDrops);
		return false;
	}

	InterlockedIncrement64(&a->Captured);
	return true;
}

// Wake the adapter queue once a batch of NodeL2Capture is in, on the drain thread of the backend
void NodeL2CaptureDone(NODE_L2 *a) {
	SetEvent(a->CaptureEvent);
}

// Hand a frame to the host as a frame that came in on the adapter, from any thread: it goes into the send ring, which
// the injector hands to the backend. False when the ring is full (counted) or the frame no Ethernet frame of the adapter.
bool NodeL2Send(NODE_L2 *a, const UCHAR *frame, UINT size) {
	if (a == NULL || frame == NULL)
		return false;

	if (size < NODE_L2_MIN_FRAME || size > NODE_L2_MAX_FRAME) {
		InterlockedIncrement64(&a->Oversize);
		return false;
	}

	if (NodeL2RingPush(a->Sends, frame, size) == false) {
		InterlockedIncrement64(&a->SendDrops);
		return false;
	}

	InterlockedIncrement64(&a->Sent);

	// The compare-and-swap orders the frame before the look at the injector, which looks at the ring after it said it waits
	if (InterlockedCompareExchange(&a->SendIdle, 0, 1) == 1)
		SetEvent(a->SendEvent);

	return true;
}

// Microseconds since start, by the performance counter of frequency freq
static UINT64 NodeL2Micros(const LARGE_INTEGER *start, const LARGE_INTEGER *freq) {
	LARGE_INTEGER now;

	QueryPerformanceCounter(&now);

	return (UINT64)(now.QuadPart - start->QuadPart) * 1000000 / (UINT64)freq->QuadPart;
}

// The next batch of the send ring, in place: up to Batch frames. A batch that is not full waits up to FlushUs
// microseconds for more, so a burst goes in few batches and a lone frame waits no longer than that. Returns how many.
static UINT NodeL2Take(NODE_L2 *a, const UCHAR **frames, UINT *sizes) {
	LARGE_INTEGER freq;
	LARGE_INTEGER start;
	bool waiting = false;
	UINT num = 0;

	freq.QuadPart = 1;
	start.QuadPart = 0;

	while (num < a->Batch) {
		NODE_L2_SLOT *s = NodeL2RingPeek(a->Sends, num);

		if (s != NULL) {
			frames[num] = s->Frame;
			sizes[num] = s->Size;
			num++;
			continue;
		}

		if (num == 0 || a->FlushUs == 0)
			break;

		if (waiting == false) {
			QueryPerformanceFrequency(&freq);
			QueryPerformanceCounter(&start);
			waiting = true;
		} else if (NodeL2Micros(&start, &freq) >= a->FlushUs) {
			break;
		}

		YieldProcessor();
	}

	return num;
}

// The link-local IPv6 address of the adapter, once it is preferred; false when it has none, as IPv6 is off on it or its
// address is still tentative
static bool NodeL2LinkLocal(NODE_L2 *a, UCHAR *addr) {
	MIB_UNICASTIPADDRESS_TABLE *t = NULL;
	bool ret = false;

	if (a->Luid == 0 || GetUnicastIpAddressTable(AF_INET6, &t) != NO_ERROR)
		return false;

	for (ULONG i = 0; i < t->NumEntries && ret == false; i++) {
		MIB_UNICASTIPADDRESS_ROW *row = &t->Table[i];
		const UCHAR *p = row->Address.Ipv6.sin6_addr.u.Byte;

		if (row->InterfaceLuid.Value != a->Luid || row->DadState != IpDadStatePreferred || p[0] != 0xFE || (p[1] & 0xC0) != 0x80)
			continue;

		Copy(addr, p, 16);
		ret = true;
	}

	FreeMibTable(t);

	return ret;
}

// The Neighbor Solicitation of a probe into f: from the probe's address and the MAC address mac to the solicited-node
// address of target, which it asks for, with mac in its source link-layer address option. Returns its size.
static UINT NodeL2ProbeFrame(UCHAR *f, const UCHAR *mac, const UCHAR *target) {
	UCHAR *ip = f + 14;
	UCHAR *icmp = ip + 40;
	UINT sum = 0;

	Zero(f, NODE_L2_PROBE_SIZE);

	// Ethernet: to the multicast address of the solicited-node address
	f[0] = 0x33;
	f[1] = 0x33;
	f[2] = 0xFF;
	f[3] = target[13];
	f[4] = target[14];
	f[5] = target[15];
	Copy(f + 6, mac, 6);
	f[12] = 0x86;
	f[13] = 0xDD;

	// IPv6: 32 bytes of ICMPv6, hop limit 255, to ff02::1:ffXX:XXXX
	ip[0] = 0x60;
	ip[5] = 32;
	ip[6] = 58;
	ip[7] = 255;
	Copy(ip + 8, node_l2_probe_ip, 16);
	ip[24] = 0xFF;
	ip[25] = 0x02;
	ip[35] = 0x01;
	ip[36] = 0xFF;
	ip[37] = target[13];
	ip[38] = target[14];
	ip[39] = target[15];

	// The solicitation: type 135, the target, and the option of type 1 (source link-layer address), 8 bytes long
	icmp[0] = 135;
	Copy(icmp + 8, target, 16);
	icmp[24] = 1;
	icmp[25] = 1;
	Copy(icmp + 26, mac, 6);

	// The checksum over the pseudo-header (both addresses, the length and the next header) and the message
	for (UINT i = 0; i < 32; i += 2)
		sum += (UINT)((ip[8 + i] << 8) | ip[9 + i]);
	sum += 32 + 58;
	for (UINT i = 0; i < 32; i += 2)
		sum += (UINT)((icmp[i] << 8) | icmp[i + 1]);
	while ((sum >> 16) != 0)
		sum = (sum & 0xFFFF) + (sum >> 16);
	sum = ~sum & 0xFFFF;
	icmp[2] = (UCHAR)(sum >> 8);
	icmp[3] = (UCHAR)sum;

	return NODE_L2_PROBE_SIZE;
}

// Whether the host learnt the address of the last probe: its neighbour cache holds the probe's link-local address with
// the MAC address of that probe, which only a solicitation that the host received can have put there
static bool NodeL2ProbeLearnt(NODE_L2 *a) {
	MIB_IPNET_ROW2 row;

	Zero(&row, sizeof(row));
	row.InterfaceLuid.Value = a->Luid;
	row.Address.Ipv6.sin6_family = AF_INET6;
	Copy(&row.Address.Ipv6.sin6_addr, node_l2_probe_ip, 16);

	if (GetIpNetEntry2(&row) != NO_ERROR)
		return false;

	return (row.PhysicalAddressLength == 6 && Cmp(row.PhysicalAddress, a->ProbeMac, 6) == 0);
}

// Probe the receive path of the host, on the injector thread: a Neighbor Solicitation for the adapter's link-local
// address from the probe's address, whose MAC address changes with each probe, injected through the backend. An adapter
// without a preferred link-local address is not probed.
static void NodeL2SendProbe(NODE_L2 *a, UINT64 now) {
	UCHAR target[16];
	UCHAR frame[NODE_L2_PROBE_SIZE];
	const UCHAR *frames[1];
	UINT sizes[1];

	a->NextProbe = now + NODE_L2_PROBE;
	if (NodeL2LinkLocal(a, target) == false)
		return;

	a->ProbeNumber++;
	Copy(a->ProbeMac, node_l2_probe_mac, 6);
	a->ProbeMac[5] = (UCHAR)(a->ProbeNumber & 1);

	frames[0] = frame;
	sizes[0] = NodeL2ProbeFrame(frame, a->ProbeMac, target);
	a->Backend->Inject(a, frames, sizes, 1);

	a->ProbeSent = now;
	InterlockedExchange(&a->ProbeOutstanding, 1);
	InterlockedIncrement64(&a->Probes);
}

// Detach the backend and attach it again, on the injector thread: a failed health check (reset: the owner resets the
// adapter first) or NodeL2Recover. The recovery goes to the node log, the Event Log and the ETW provider of Debug(),
// with the counters. True when the backend is attached afterwards.
static bool NodeL2Reattach(NODE_L2 *a, const char *why, bool reset) {
	const NODE_L2_BACKEND *b = a->Backend;
	char error[MAX_SIZE];
	char msg[MAX_SIZE * 2];
	bool detached = true;
	bool was_reset = false;

	if (a->BackendState != NULL)
		detached = b->Detach(a, NODE_L2_STOP_WAIT);

	if (reset && a->Reset != NULL) {
		UINT if_index = a->IfIndex;

		was_reset = a->Reset(a->ResetParam, &if_index);
		if (was_reset) {
			a->IfIndex = if_index;
			NodeL2ReadInterface(a);
		}
		InterlockedIncrement64(&a->Resets);
	}

	StrCpy(error, sizeof(error), "");
	bool ok = b->Attach(a, error, sizeof(error));
	InterlockedIncrement64(&a->Reattaches);
	InterlockedExchange(&a->ProbeOutstanding, 0);
	a->NextProbe = GetTickCount64() + NODE_L2_HEALTH;

	Format(msg, sizeof(msg), "L2 adapter of interface %u: %s; the %s backend %s%s%s%s; captured %I64u (%I64u dropped), injected %I64u (%I64u dropped), %I64u probes (%I64u failed), %I64u reattaches, %I64u resets",
	       a->IfIndex, why, b->Name, detached ? "detached" : "did not detach in time", reset ? (was_reset ? ", the adapter reset" : ", the adapter not reset") : "",
	       ok ? " and attached again" : " and could not attach again: ", error,
	       (UINT64)ReadAcquire64(&a->Captured), (UINT64)ReadAcquire64(&a->CaptureDrops), (UINT64)ReadAcquire64(&a->Injected), (UINT64)ReadAcquire64(&a->InjectDrops),
	       (UINT64)ReadAcquire64(&a->Probes), (UINT64)ReadAcquire64(&a->ProbeFailures), (UINT64)ReadAcquire64(&a->Reattaches), (UINT64)ReadAcquire64(&a->Resets));
	NodeLog(a->Node, "%s", msg);
	Debug("%s\n", msg);
	MsWriteEventLog(NODE_L2_EVENT_SOURCE, ok ? EVENTLOG_WARNING_TYPE : EVENTLOG_ERROR_TYPE, NODE_L2_EVENT_RECOVERY, msg);

	return ok;
}

// The health check, on the injector thread once every NODE_L2_HEALTH ms: the backend says whether its binding works,
// and the probe of the receive path, when one is out, must be learnt within NODE_L2_STALL ms. A failure detaches the
// backend and attaches it again; the failure after NODE_L2_RESETS of them in a row resets the adapter too.
static void NodeL2Health(NODE_L2 *a, UINT64 now) {
	char why[MAX_SIZE];

	StrCpy(why, sizeof(why), "");

	if (a->BackendState == NULL) {
		StrCpy(why, sizeof(why), "no binding is attached");
	} else if (a->Backend->Healthy(a) == false) {
		StrCpy(why, sizeof(why), "the binding reports itself broken or stalled");
	} else if (a->NoProbe == false && ReadAcquire(&a->ProbeOutstanding) != 0) {
		if (NodeL2ProbeLearnt(a)) {
			InterlockedExchange(&a->ProbeOutstanding, 0);
		} else if (now - a->ProbeSent > NODE_L2_STALL) {
			InterlockedExchange(&a->ProbeOutstanding, 0);
			InterlockedIncrement64(&a->ProbeFailures);
			Format(why, sizeof(why), "the host did not take a probe within %u ms", NODE_L2_STALL);
		}
	} else if (a->NoProbe == false && now >= a->NextProbe) {
		NodeL2SendProbe(a, now);
	}

	if (IsEmptyStr(why)) {
		if (a->BackendState != NULL && ReadAcquire(&a->ProbeOutstanding) == 0)
			a->Failures = 0;
		return;
	}

	a->Failures++;
	bool reset = (a->Failures > NODE_L2_RESETS);
	if (reset)
		a->Failures = 0;

	NodeL2Reattach(a, why, reset);
}

// The injector: the batches of the send ring to the backend (NodeL2Take), the health check once every NODE_L2_HEALTH
// ms, and the recoveries that NodeL2Recover asks for. It waits for the send event while the ring is empty.
static DWORD WINAPI NodeL2InjectorThread(void *param) {
	NODE_L2 *a = (NODE_L2 *)param;
	const UCHAR *frames[NODE_L2_MAX_BATCH];
	UINT sizes[NODE_L2_MAX_BATCH];
	UINT64 next_health = GetTickCount64() + NODE_L2_HEALTH;

	while (ReadAcquire(&a->Halt) == 0) {
		UINT num = NodeL2Take(a, frames, sizes);
		UINT64 now = GetTickCount64();

		if (num != 0) {
			UINT taken = (a->BackendState != NULL ? a->Backend->Inject(a, frames, sizes, num) : 0);

			NodeL2RingRelease(a->Sends, num);
			InterlockedAdd64(&a->Injected, (LONG64)taken);
			InterlockedAdd64(&a->InjectDrops, (LONG64)(num - taken));
			InterlockedIncrement64(&a->Batches);
		} else {
			// Idle: NodeL2Send wakes the thread for the next frame. The ring is looked at again after the flag is set.
			InterlockedExchange(&a->SendIdle, 1);
			if (NodeL2RingPeek(a->Sends, 0) == NULL && ReadAcquire(&a->RecoverAsked) == 0 && now < next_health)
				WaitForSingleObject(a->SendEvent, (DWORD)(next_health - now));
			InterlockedExchange(&a->SendIdle, 0);
			now = GetTickCount64();
		}

		if (InterlockedExchange(&a->RecoverAsked, 0) != 0) {
			InterlockedExchange(&a->RecoverResult, NodeL2Reattach(a, "a recovery was asked for", false) ? 1 : 0);
			SetEvent(a->RecoverDone);
		}

		if (now >= next_health) {
			NodeL2Health(a, now);
			next_health = GetTickCount64() + NODE_L2_HEALTH;
		}
	}

	return 0;
}

// Free the rings, the events and the adapter, once no thread runs on them
static void NodeL2Release(NODE_L2 *a) {
	NodeL2RingFree(a->Captures);
	NodeL2RingFree(a->Sends);

	if (a->CaptureEvent != NULL)
		CloseHandle(a->CaptureEvent);
	if (a->SendEvent != NULL)
		CloseHandle(a->SendEvent);
	if (a->RecoverDone != NULL)
		CloseHandle(a->RecoverDone);

	Free(a);
}

// The L2 adapter of the KM-TEST adapter of cfg->IfIndex on the running node n: its adapter queue, the first backend of
// cfg->Backends (XDP, then SeLow, without) that binds, and the injector. NULL on a host that is L3 only (arm64), when
// no backend binds, or when a thread cannot start; the node log says why.
NODE_L2 *NodeL2New(NODE *n, const NODE_L2_CONFIG *cfg) {
	SYSTEM_INFO info;
	char name[MAX_SIZE];
	char error[MAX_SIZE];
	DWORD thread_id = 0;

	if (n == NULL || cfg == NULL || cfg->Proc == NULL)
		return NULL;

	Zero(&info, sizeof(info));
	GetNativeSystemInfo(&info);
	if (NodeL2Offered(info.wProcessorArchitecture) == false) {
		NodeLog(n, "L2 adapter of interface %u not offered: this host is L3 only, as its architecture (%u) has no XDP runtime and no SeLow package (ADR-0022)", cfg->IfIndex, (UINT)info.wProcessorArchitecture);
		return NULL;
	}

	UINT slots = (cfg->Slots == 0 ? NODE_L2_SLOTS : cfg->Slots);
	if (slots < NODE_L2_MAX_BATCH || (slots & (slots - 1)) != 0) {
		NodeLog(n, "L2 adapter of interface %u not created: rings of %u frames, not a power of two from %u on", cfg->IfIndex, slots, NODE_L2_MAX_BATCH);
		return NULL;
	}

	NODE_L2 *a = ZeroMalloc(sizeof(NODE_L2));
	a->Node = n;
	a->IfIndex = cfg->IfIndex;
	a->Proc = cfg->Proc;
	a->Param = cfg->Param;
	a->Reset = cfg->Reset;
	a->ResetParam = cfg->ResetParam;
	a->Batch = (cfg->Batch == 0 ? NODE_L2_BATCH : MIN(cfg->Batch, NODE_L2_MAX_BATCH));
	a->FlushUs = (cfg->FlushUs == 0 ? NODE_L2_FLUSH_US : (cfg->FlushUs == NODE_L2_NO_FLUSH ? 0 : cfg->FlushUs));
	a->BackendRing = cfg->BackendRing;
	a->NoProbe = cfg->NoProbe;
	a->NextProbe = GetTickCount64() + NODE_L2_HEALTH;

	if (cfg->Backends != NULL) {
		for (UINT i = 0; i < cfg->NumBackends && a->NumBackends < NODE_L2_MAX_BACKENDS; i++)
			if (cfg->Backends[i] != NULL)
				a->Backends[a->NumBackends++] = cfg->Backends[i];
	} else {
		a->Backends[a->NumBackends++] = NodeL2XdpBackend();
		a->Backends[a->NumBackends++] = NodeL2SeLowBackend();
	}

	NodeL2ReadInterface(a);

	a->Captures = NodeL2RingNew(slots);
	a->Sends = NodeL2RingNew(slots);
	a->CaptureEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
	a->SendEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
	a->RecoverDone = CreateEventW(NULL, FALSE, FALSE, NULL);

	Format(name, sizeof(name), "l2 interface %u", a->IfIndex);
	if (a->CaptureEvent != NULL && a->SendEvent != NULL && a->RecoverDone != NULL)
		a->Queue = NodeAddQueue(n, name, a->CaptureEvent, NodeL2Deliver, a);
	if (a->Queue == NULL) {
		NodeLog(n, "L2 adapter of interface %u not created: its adapter queue could not start", a->IfIndex);
		NodeL2Release(a);
		return NULL;
	}

	for (UINT i = 0; i < a->NumBackends && a->Backend == NULL; i++) {
		const NODE_L2_BACKEND *b = a->Backends[i];

		StrCpy(error, sizeof(error), "");
		if (b->Attach(a, error, sizeof(error)))
			a->Backend = b;
		else
			NodeLog(n, "L2 adapter of interface %u: the %s backend cannot bind: %s", a->IfIndex, b->Name, error);
	}

	if (a->Backend == NULL) {
		NodeLog(n, "L2 adapter of interface %u not up: no backend could bind", a->IfIndex);
		NodeDelQueue(n, a->Queue);
		NodeL2Release(a);
		return NULL;
	}

	a->Injector = CreateThread(NULL, 0, NodeL2InjectorThread, a, 0, &thread_id);
	if (a->Injector == NULL) {
		NodeLog(n, "L2 adapter of interface %u not up: its injector could not start (error %u)", a->IfIndex, (UINT)GetLastError());
		a->Backend->Detach(a, NODE_L2_STOP_WAIT);
		NodeDelQueue(n, a->Queue);
		NodeL2Release(a);
		return NULL;
	}

	NodeLog(n, "L2 adapter up: interface %u, MAC %02X-%02X-%02X-%02X-%02X-%02X, the %s backend on %u queue(s), rings of %u frames, batches of %u, flush %u us",
	        a->IfIndex, (UINT)a->Mac[0], (UINT)a->Mac[1], (UINT)a->Mac[2], (UINT)a->Mac[3], (UINT)a->Mac[4], (UINT)a->Mac[5], a->Backend->Name,
	        (UINT)ReadAcquire(&a->DriverQueues), slots, a->Batch, a->FlushUs);

	return a;
}

// Take an adapter down, each step within NODE_L2_STOP_WAIT ms (#72, risk R2): the injector stops, so that no frame goes
// to the backend any more; the backend waits for what it injected to complete, closes its binding and joins its drain
// thread; then the adapter queue goes. False when a step did not finish in time: the adapter is then left as it is, as
// a thread may still run on it.
bool NodeL2Free(NODE_L2 *a) {
	bool ok = true;

	if (a == NULL)
		return true;

	InterlockedExchange(&a->Halt, 1);
	SetEvent(a->SendEvent);
	if (WaitForSingleObject(a->Injector, NODE_L2_STOP_WAIT) != WAIT_OBJECT_0) {
		NodeLog(a->Node, "L2 adapter of interface %u: the injector did not stop within %u ms", a->IfIndex, NODE_L2_STOP_WAIT);
		return false;
	}
	CloseHandle(a->Injector);

	if (a->BackendState != NULL && a->Backend->Detach(a, NODE_L2_STOP_WAIT) == false) {
		NodeLog(a->Node, "L2 adapter of interface %u: a step of the %s backend did not finish within %u ms", a->IfIndex, a->Backend->Name, NODE_L2_STOP_WAIT);
		ok = false;
	}

	NodeDelQueue(a->Node, a->Queue);

	NodeLog(a->Node, "L2 adapter of interface %u down: %I64u frames of the host captured (%I64u dropped, %I64u dropped by the driver), %I64u handed to the owner; %I64u sent to the host (%I64u dropped), %I64u injected in %I64u batches; %I64u failed waits on the driver",
	        a->IfIndex, (UINT64)a->Captured, (UINT64)a->CaptureDrops, (UINT64)a->DriverDrops, (UINT64)a->Delivered, (UINT64)a->Sent, (UINT64)a->SendDrops, (UINT64)a->Injected,
	        (UINT64)a->Batches, (UINT64)a->DriverWaitFailures);

	if (ok)
		NodeL2Release(a);

	return ok;
}

// Detach the backend and attach it again now, as a failed health check does, and wait for it: the injector runs it
// between two batches. One caller at a time. True when the backend is attached afterwards.
bool NodeL2Recover(NODE_L2 *a) {
	if (a == NULL)
		return false;

	InterlockedExchange(&a->RecoverAsked, 1);
	SetEvent(a->SendEvent);

	if (WaitForSingleObject(a->RecoverDone, NODE_L2_STOP_WAIT * 3) != WAIT_OBJECT_0)
		return false;

	return (ReadAcquire(&a->RecoverResult) != 0);
}

// The status of an adapter: its backend, its interface and its counters
void NodeL2GetStatus(NODE_L2 *a, NODE_L2_STATUS *st) {
	if (st == NULL)
		return;

	Zero(st, sizeof(NODE_L2_STATUS));
	if (a == NULL)
		return;

	if (a->Backend != NULL && a->BackendState != NULL)
		StrCpy(st->Backend, sizeof(st->Backend), a->Backend->Name);
	st->IfIndex = a->IfIndex;
	Copy(st->Mac, a->Mac, 6);
	st->Captured = (UINT64)ReadAcquire64(&a->Captured);
	st->CaptureDrops = (UINT64)ReadAcquire64(&a->CaptureDrops);
	st->Delivered = (UINT64)ReadAcquire64(&a->Delivered);
	st->Sent = (UINT64)ReadAcquire64(&a->Sent);
	st->SendDrops = (UINT64)ReadAcquire64(&a->SendDrops);
	st->Injected = (UINT64)ReadAcquire64(&a->Injected);
	st->InjectDrops = (UINT64)ReadAcquire64(&a->InjectDrops);
	st->Batches = (UINT64)ReadAcquire64(&a->Batches);
	st->Oversize = (UINT64)ReadAcquire64(&a->Oversize);
	st->Probes = (UINT64)ReadAcquire64(&a->Probes);
	st->ProbeFailures = (UINT64)ReadAcquire64(&a->ProbeFailures);
	st->Reattaches = (UINT64)ReadAcquire64(&a->Reattaches);
	st->Resets = (UINT64)ReadAcquire64(&a->Resets);
	st->Queues = (UINT)ReadAcquire(&a->DriverQueues);
	st->BusyQueues = (UINT)ReadAcquire(&a->DriverBusyQueues);
	st->DriverDrops = (UINT64)ReadAcquire64(&a->DriverDrops);
	st->WaitFailures = (UINT64)ReadAcquire64(&a->DriverWaitFailures);
	st->WaitError = (UINT)ReadAcquire(&a->DriverWaitError);
}
