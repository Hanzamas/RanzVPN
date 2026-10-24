// PolicyTrack.c
// The conntrack table of a Network (PolicyInternal.h): its flows in shards chosen by a keyed hash of their keys, each
// shard a hash table with chains and a list of its flows by use, the most recently used first. The memory of a table is
// taken once, for its bound, so no traffic makes it grow: a full shard gives its least recently used flow to a new one.
// A table smaller than two shards of POLICY_TRACK_PER_SHARD flows has one shard, whose list orders every flow. The
// engine (Policy.c) holds the lock of a shard around each use of it.

#include "Core/PolicyInternal.h"

#include <bcrypt.h>

#include <string.h>

#define POLICY_TRACK_MAX_SHARDS 64 // Shards of a table at most
#define POLICY_TRACK_PER_SHARD  64 // Flows of a shard at least, while the table has more than one

// The hash takes the key as words
C_ASSERT(sizeof(POLICY_KEY) % sizeof(UINT64) == 0);

// The flow of a link of a shard: an index plus 1
static POLICY_FLOW *PolicyFlowAt(POLICY_SHARD *s, UINT link) {
	return &s->Flows[link - 1];
}

// The link of a flow of a shard
static UINT PolicyLinkOf(const POLICY_SHARD *s, const POLICY_FLOW *f) {
	return (UINT)(f - s->Flows) + 1;
}

// A conntrack table of max_flows flows at most, its memory taken now; NULL for a bound that is none, or when there is no
// memory
POLICY_TRACK *PolicyNewTrack(UINT max_flows) {
	if (max_flows == 0 || max_flows > POLICY_MAX_FLOWS)
		return NULL;

	POLICY_TRACK *t = (POLICY_TRACK *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(POLICY_TRACK));
	if (t == NULL)
		return NULL;

	// As many shards as keep POLICY_TRACK_PER_SHARD flows each, a power of 2; the first shards take the flows of the
	// bound that do not divide evenly, one each
	UINT shards = 1;
	UINT bits = 0;
	while (shards < POLICY_TRACK_MAX_SHARDS && max_flows / (shards * 2) >= POLICY_TRACK_PER_SHARD) {
		shards *= 2;
		bits++;
	}

	UINT per = max_flows / shards;
	UINT rest = max_flows % shards;
	UINT buckets = 1;
	while (buckets < per + (rest != 0 ? 1 : 0))
		buckets *= 2;

	t->MaxFlows = max_flows;
	t->NumShards = shards;
	t->ShardBits = bits;

	// From VirtualAlloc: zeroed, and committed by the pages that the flows use
	t->Shards = (POLICY_SHARD *)VirtualAlloc(NULL, sizeof(POLICY_SHARD) * shards, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	t->Flows = (POLICY_FLOW *)VirtualAlloc(NULL, sizeof(POLICY_FLOW) * max_flows, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	t->Buckets = (UINT *)VirtualAlloc(NULL, sizeof(UINT) * buckets * shards, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (t->Shards == NULL || t->Flows == NULL || t->Buckets == NULL ||
	    BCRYPT_SUCCESS(BCryptGenRandom(NULL, (PUCHAR)&t->Seed, sizeof(t->Seed), BCRYPT_USE_SYSTEM_PREFERRED_RNG)) == false) {
		PolicyFreeTrack(t);
		return NULL;
	}

	UINT first = 0;
	for (UINT i = 0; i < shards; i++) {
		POLICY_SHARD *s = &t->Shards[i];

		InitializeSRWLock(&s->Lock);
		s->Max = per + (i < rest ? 1 : 0);
		s->Mask = buckets - 1;
		s->Buckets = &t->Buckets[(SIZE_T)i * buckets];
		s->Flows = &t->Flows[first];
		first += s->Max;
	}

	return t;
}

// Free a conntrack table. No thread may use it any more.
void PolicyFreeTrack(POLICY_TRACK *t) {
	if (t == NULL)
		return;

	if (t->Shards != NULL)
		VirtualFree(t->Shards, 0, MEM_RELEASE);
	if (t->Flows != NULL)
		VirtualFree(t->Flows, 0, MEM_RELEASE);
	if (t->Buckets != NULL)
		VirtualFree(t->Buckets, 0, MEM_RELEASE);

	HeapFree(GetProcessHeap(), 0, t);
}

// The hash of a key under the random key of the table (the finaliser of SplitMix64 over each word of the key), so that
// the members of a Network cannot choose the shards and the buckets that their flows take
UINT64 PolicyTrackHash(const POLICY_TRACK *t, const POLICY_KEY *k) {
	UINT64 w[sizeof(POLICY_KEY) / sizeof(UINT64)];
	UINT64 h = t->Seed;

	CopyMemory(w, k, sizeof(w));
	for (UINT i = 0; i < sizeof(w) / sizeof(w[0]); i++) {
		h ^= w[i];
		h = (h ^ (h >> 30)) * 0xBF58476D1CE4E5B9ULL;
		h = (h ^ (h >> 27)) * 0x94D049BB133111EBULL;
		h ^= h >> 31;
	}

	return h;
}

// The shard of a hash: its top bits; the bucket is its low bits
POLICY_SHARD *PolicyTrackShard(POLICY_TRACK *t, UINT64 h) {
	if (t->ShardBits == 0)
		return &t->Shards[0];

	return &t->Shards[h >> (64 - t->ShardBits)];
}

// The flow of key k in shard s, NULL for none. The caller holds the lock of the shard.
POLICY_FLOW *PolicyTrackFind(POLICY_SHARD *s, const POLICY_KEY *k, UINT64 h) {
	UINT link = s->Buckets[h & s->Mask];

	while (link != 0) {
		POLICY_FLOW *f = PolicyFlowAt(s, link);

		if (memcmp(&f->Key, k, sizeof(POLICY_KEY)) == 0)
			return f;
		link = f->Next;
	}

	return NULL;
}

// Take a flow out of the list of its shard by use
static void PolicyUnlist(POLICY_SHARD *s, POLICY_FLOW *f) {
	if (f->Newer != 0)
		PolicyFlowAt(s, f->Newer)->Older = f->Older;
	else
		s->Newest = f->Older;

	if (f->Older != 0)
		PolicyFlowAt(s, f->Older)->Newer = f->Newer;
	else
		s->Oldest = f->Newer;

	f->Newer = 0;
	f->Older = 0;
}

// Put a flow at the head of the list of its shard: the most recently used
static void PolicyList(POLICY_SHARD *s, POLICY_FLOW *f) {
	UINT link = PolicyLinkOf(s, f);

	f->Newer = 0;
	f->Older = s->Newest;
	if (s->Newest != 0)
		PolicyFlowAt(s, s->Newest)->Newer = link;
	else
		s->Oldest = link;
	s->Newest = link;
}

// Take out flow f of shard s and free it. The caller holds the lock of the shard.
void PolicyTrackDel(POLICY_TRACK *t, POLICY_SHARD *s, POLICY_FLOW *f) {
	UINT64 h = PolicyTrackHash(t, &f->Key);
	UINT link = PolicyLinkOf(s, f);
	UINT *p = &s->Buckets[h & s->Mask];

	// Out of the chain of its bucket
	while (*p != 0) {
		if (*p == link) {
			*p = f->Next;
			break;
		}
		p = &PolicyFlowAt(s, *p)->Next;
	}

	PolicyUnlist(s, f);
	ZeroMemory(f, sizeof(POLICY_FLOW));

	// The free flows are chained by Next
	f->Next = s->Free;
	s->Free = link;
	s->Num--;
	InterlockedDecrement(&t->NumFlows);
}

// A new flow of key k, which shard s does not hold, at the head of its list: a free flow, or the least recently used
// one when the shard is full, which *left tells (POLICY_LEFT_*). The fields after the key are 0 but its time, now, and
// its links. NULL when the shard has no flow. The caller holds the lock of the shard.
POLICY_FLOW *PolicyTrackAdd(POLICY_TRACK *t, POLICY_SHARD *s, const POLICY_KEY *k, UINT64 h, UINT64 now, UINT *left) {
	POLICY_FLOW *f = NULL;

	*left = POLICY_LEFT_NONE;
	if (s->Num >= s->Max && s->Oldest != 0) {
		POLICY_FLOW *old = PolicyFlowAt(s, s->Oldest);

		*left = (now >= old->Last + old->Timeout ? POLICY_LEFT_EXPIRED : POLICY_LEFT_EVICTED);
		PolicyTrackDel(t, s, old);
	}

	if (s->Free != 0) {
		f = PolicyFlowAt(s, s->Free);
		s->Free = f->Next;
	} else if (s->Used < s->Max) {
		f = &s->Flows[s->Used];
		s->Used++;
	} else {
		return NULL;
	}

	ZeroMemory(f, sizeof(POLICY_FLOW));
	CopyMemory(&f->Key, k, sizeof(POLICY_KEY));
	f->Last = now;
	f->Next = s->Buckets[h & s->Mask];
	s->Buckets[h & s->Mask] = PolicyLinkOf(s, f);
	PolicyList(s, f);
	s->Num++;
	InterlockedIncrement(&t->NumFlows);

	return f;
}

// Flow f of shard s took a frame: it is the most recently used. The caller holds the lock of the shard.
void PolicyTrackTouch(POLICY_SHARD *s, POLICY_FLOW *f) {
	if (s->Newest == PolicyLinkOf(s, f))
		return;

	PolicyUnlist(s, f);
	PolicyList(s, f);
}

// Take out the flows of a table that expired at now; their number
UINT PolicyTrackAge(POLICY_TRACK *t, UINT64 now) {
	UINT num = 0;

	for (UINT i = 0; i < t->NumShards; i++) {
		POLICY_SHARD *s = &t->Shards[i];

		AcquireSRWLockExclusive(&s->Lock);
		UINT link = s->Oldest;
		while (link != 0) {
			POLICY_FLOW *f = PolicyFlowAt(s, link);

			// The next one before f is freed
			link = f->Newer;
			if (now >= f->Last + f->Timeout) {
				PolicyTrackDel(t, s, f);
				num++;
			}
		}
		ReleaseSRWLockExclusive(&s->Lock);
	}

	return num;
}
