// MemoryAlloc.c
// Memory allocation: Malloc, ReAlloc, Free, memory tags, the internal allocator and the canary

#include "Memory.h"

#include "Encrypt.h"
#include "FileIO.h"
#include "Tracking.h"
#include "Win32.h"

#include <intrin.h>
#include <stdlib.h>
#include <string.h>

#include <wincrypt.h>

#include <zlib.h>

#ifdef RANZ_ASAN
#include <sanitizer/asan_interface.h>
#define MEMTAG_SLACK(tag1)      (((UCHAR *)MEMTAG1_TO_POINTER(tag1)) + (tag1)->Size)
#define MEMTAG_SLACK_SIZE(tag1) (CALC_MALLOCSIZE((tag1)->Size) - sizeof(MEMTAG1) - (tag1)->Size)
#define MEMTAG_POISON(tag1)     __asan_poison_memory_region(MEMTAG_SLACK(tag1), MEMTAG_SLACK_SIZE(tag1))
#define MEMTAG_UNPOISON(tag1)   __asan_unpoison_memory_region(MEMTAG_SLACK(tag1), MEMTAG_SLACK_SIZE(tag1))
#else // RANZ_ASAN
#define MEMTAG_POISON(tag1)
#define MEMTAG_UNPOISON(tag1)
#endif // RANZ_ASAN
#include "MemoryInternal.h"

#define MEMORY_SLEEP_TIME 150
#define MEMORY_MAX_RETRY  30

static bool canary_inited = false;
typedef struct CANARY_RAND_DATA {
	UCHAR Data[CANARY_RAND_SIZE + 4];
} CANARY_RAND_DATA;

static CANARY_RAND_DATA canary_rand_data[NUM_CANARY_RAND] = {0};

static UINT64 canary_memtag_magic1 = 0;
static UINT64 canary_memtag_magic2 = 0;

UCHAR *GetCanaryRand(UINT id) {
	return &((canary_rand_data[id].Data)[0]);
}

void InitCanaryRand() {
	if (canary_inited) {
		return;
	}

	// From CNG (Rand): no seed, no state shared with the CRT generator
	for (UINT i = 0; i < NUM_CANARY_RAND; i++) {
		Rand(canary_rand_data[i].Data, CANARY_RAND_SIZE);
	}

	canary_memtag_magic1 = *((UINT64 *)(GetCanaryRand(CANARY_RAND_ID_MEMTAG_MAGIC) + 0));
	canary_memtag_magic2 = *((UINT64 *)(GetCanaryRand(CANARY_RAND_ID_MEMTAG_MAGIC) + 8));

	canary_inited = true;
}

void *Malloc(UINT size) {
	return MallocEx(size, false);
}
void *MallocEx(UINT size, bool zero_clear_when_free) {
	if (canary_inited == false) {
		InitCanaryRand();
	}

	if (size > MAX_MALLOC_MEM_SIZE) {
		AbortExitEx("MallocEx() error: too large size");
	}

	UINT real_size = CALC_MALLOCSIZE(size);

	MEMTAG1 *tag1 = InternalMalloc(real_size);

	tag1->Magic = canary_memtag_magic1 ^ ((UINT64)tag1 * GOLDEN_RATION_PRIME_U64);
	tag1->Size = size;
	tag1->ZeroFree = zero_clear_when_free;

	MEMTAG2 *tag2 = (MEMTAG2 *)(((UCHAR *)tag1) + CALC_MALLOCSIZE(tag1->Size) - sizeof(MEMTAG2));
	tag2->Magic = canary_memtag_magic2 ^ ((UINT64)tag2 * GOLDEN_RATION_PRIME_U64);
	MEMTAG_POISON(tag1);

	return MEMTAG1_TO_POINTER(tag1);
}

void *ReAlloc(void *addr, UINT size) {
	if (canary_inited == false) {
		InitCanaryRand();
	}

	if (size > MAX_MALLOC_MEM_SIZE) {
		AbortExitEx("ReAlloc() error: too large size");
	}

	if (IS_NULL_POINTER(addr)) {
		return NULL;
	}

	MEMTAG1 *tag1 = POINTER_TO_MEMTAG1(addr);
	CheckMemTag1(tag1);
	MEMTAG_UNPOISON(tag1);

	MEMTAG2 *tag2 = (MEMTAG2 *)(((UCHAR *)tag1) + CALC_MALLOCSIZE(tag1->Size) - sizeof(MEMTAG2));
	CheckMemTag2(tag2);

	bool zerofree = tag1->ZeroFree;

	if (tag1->Size == size) {
		MEMTAG_POISON(tag1);
		return addr;
	} else {
		if (zerofree) {
			// Zero-free block: copy to a new block so the old one is zeroed on Free
			void *new_p = MallocEx(size, true);

			if (tag1->Size <= size) {
				Copy(new_p, addr, tag1->Size);
			} else {
				Copy(new_p, addr, size);
			}

			Free(addr);

			return new_p;
		} else {
			tag1->Magic = 0;
			tag2->Magic = 0;

			MEMTAG1 *tag1_new = InternalReAlloc(tag1, CALC_MALLOCSIZE(size));

			tag1_new->Magic = canary_memtag_magic1 ^ ((UINT64)tag1_new * GOLDEN_RATION_PRIME_U64);
			tag1_new->Size = size;
			tag1_new->ZeroFree = 0;

			MEMTAG2 *tag2_new = (MEMTAG2 *)(((UCHAR *)tag1_new) + CALC_MALLOCSIZE(size) - sizeof(MEMTAG2));
			tag2_new->Magic = canary_memtag_magic2 ^ ((UINT64)tag2_new * GOLDEN_RATION_PRIME_U64);
			MEMTAG_POISON(tag1_new);

			return MEMTAG1_TO_POINTER(tag1_new);
		}
	}
}

void Free(void *addr) {
	if (IS_NULL_POINTER(addr)) {
		return;
	}

	if (canary_inited == false) {
		InitCanaryRand();
	}

	MEMTAG1 *tag1 = POINTER_TO_MEMTAG1(addr);
	CheckMemTag1(tag1);
	MEMTAG_UNPOISON(tag1);

	MEMTAG2 *tag2 = (MEMTAG2 *)(((UCHAR *)tag1) + CALC_MALLOCSIZE(tag1->Size) - sizeof(MEMTAG2));
	CheckMemTag2(tag2);

	if (tag1->ZeroFree) {
		Zero(addr, tag1->Size);
	}

	tag1->Magic = 0;
	tag2->Magic = 0;
	InternalFree(tag1);
}

void FreeSafe(void **addr) {
	Free(*addr);
	*addr = NULL;
}

void CheckMemTag1(MEMTAG1 *tag) {
	if (tag == NULL) {
		AbortExitEx("CheckMemTag1: tag1 == NULL");
		return;
	}

	if (tag->Magic != (canary_memtag_magic1 ^ ((UINT64)tag * GOLDEN_RATION_PRIME_U64))) {
		AbortExitEx("CheckMemTag1: tag1->Magic != canary_memtag_magic1");
		return;
	}
}

void CheckMemTag2(MEMTAG2 *tag) {
	if (tag == NULL) {
		AbortExitEx("CheckMemTag2: tag2 == NULL");
		return;
	}

	if (tag->Magic != (canary_memtag_magic2 ^ ((UINT64)tag * GOLDEN_RATION_PRIME_U64))) {
		AbortExitEx("CheckMemTag2: tag2->Magic != canary_memtag_magic2");
		return;
	}
}

void *ZeroMalloc(UINT size) {
	return ZeroMallocEx(size, false);
}
void *ZeroMallocEx(UINT size, bool zero_clear_when_free) {
	void *p = MallocEx(size, zero_clear_when_free);
	Zero(p, size);
	return p;
}

void *InternalMalloc(UINT size) {
	void *addr;
	UINT retry = 0;
	size = MORE(size, 1);

	KS_INC(KS_MALLOC_COUNT);
	KS_INC(KS_TOTAL_MEM_COUNT);
	KS_ADD(KS_TOTAL_MEM_SIZE, size);
	KS_INC(KS_CURRENT_MEM_COUNT);

	while (true) {
		if ((retry++) > MEMORY_MAX_RETRY) {
			AbortExitEx("InternalMalloc: error: malloc() failed.\n\n");
		}
		addr = Win32MemoryAlloc(size);
		if (addr != NULL) {
			break;
		}

		Sleep(MEMORY_SLEEP_TIME);
	}

	TrackNewObj(POINTER_TO_UINT64(addr), "MEM", size);

	return addr;
}

void InternalFree(void *addr) {
	if (addr == NULL) {
		return;
	}

	KS_DEC(KS_CURRENT_MEM_COUNT);
	KS_INC(KS_FREE_COUNT);

	TrackDeleteObj(POINTER_TO_UINT64(addr));

	Win32MemoryFree(addr);
}

void *InternalReAlloc(void *addr, UINT size) {
	void *new_addr;
	UINT retry = 0;
	size = MORE(size, 1);

	KS_INC(KS_REALLOC_COUNT);
	KS_ADD(KS_TOTAL_MEM_SIZE, size);

	while (true) {
		if ((retry++) > MEMORY_MAX_RETRY) {
			AbortExitEx("InternalReAlloc: error: realloc() failed.\n\n");
		}
		new_addr = Win32MemoryReAlloc(addr, size);
		if (new_addr != NULL) {
			break;
		}

		Sleep(MEMORY_SLEEP_TIME);
	}

	TrackChangeObjSize(POINTER_TO_UINT64(addr), size, POINTER_TO_UINT64(new_addr));

	return new_addr;
}
