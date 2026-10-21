// Memory.c
// Memory management program

#include "Memory.h"

#include "Encrypt.h"
#include "FileIO.h"
#include "Internat.h"
#include "Kernel.h"
#include "Mayaqua.h"
#include "Object.h"
#include "Str.h"
#include "Tick64.h"
#include "Tracking.h"
#include "Win32.h"

#include <intrin.h>
#include <stdlib.h>
#include <string.h>

#include <wincrypt.h>

#include <zlib.h>

#ifdef	RANZ_ASAN
// AddressSanitizer build only (RANZ_ASAN, cmake/RanzSanitizers.cmake): the slack after a
// block (the rounding up to 8 bytes and MEMTAG2) is poisoned while the block is in use, so that
// ASan reports any access past the size that was asked for. Manual poisoning interface:
// https://learn.microsoft.com/en-us/cpp/sanitizers/asan-runtime
// https://github.com/llvm/llvm-project/blob/llvmorg-20.1.8/compiler-rt/include/sanitizer/asan_interface.h
#include <sanitizer/asan_interface.h>
#define	MEMTAG_SLACK(tag1)			(((UCHAR *)MEMTAG1_TO_POINTER(tag1)) + (tag1)->Size)
#define	MEMTAG_SLACK_SIZE(tag1)		(CALC_MALLOCSIZE((tag1)->Size) - sizeof(MEMTAG1) - (tag1)->Size)
#define	MEMTAG_POISON(tag1)			__asan_poison_memory_region(MEMTAG_SLACK(tag1), MEMTAG_SLACK_SIZE(tag1))
#define	MEMTAG_UNPOISON(tag1)		__asan_unpoison_memory_region(MEMTAG_SLACK(tag1), MEMTAG_SLACK_SIZE(tag1))
#else	// RANZ_ASAN
#define	MEMTAG_POISON(tag1)
#define	MEMTAG_UNPOISON(tag1)
#endif	// RANZ_ASAN
#include "MemoryInternal.h"

#define	INIT_BUF_SIZE			10240

#define	FIFO_INIT_MEM_SIZE		4096
#define	FIFO_REALLOC_MEM_SIZE	(65536 * 10)	// Tuned value

#define	INIT_NUM_RESERVED		32

#define	QUEUE_INIT_NUM_RESERVED		16		// Slots of a new queue ring (a power of two)
#define	QUEUE_SHRINK_NUM_RESERVED	512		// A ring halves only above this, the 4096-byte block of the former queue FIFO

static UINT fifo_current_realloc_mem_size = FIFO_REALLOC_MEM_SIZE;

bool IsInHashListKey(const HASH_LIST *h, UINT key)
{
	if (h == NULL || key == 0)
	{
		return false;
	}

	if (HashListKeyToPointer(h, key) == NULL)
	{
		return false;
	}

	return true;
}

void *HashListKeyToPointer(const HASH_LIST *h, UINT key)
{
	UINT num, i;
	void **pp;
	void *ret = NULL;
	if (h == NULL || key == 0)
	{
		return NULL;
	}

	pp = HashListToArray(h, &num);
	if (pp == NULL)
	{
		return NULL;
	}

	for (i = 0;i < num;i++)
	{
		void *p = pp[i];

		if (POINTER_TO_KEY(p) == key)
		{
			ret = p;
		}
	}

	Free(pp);

	return ret;
}

void LockHashList(HASH_LIST *h)
{
	if (h == NULL)
	{
		return;
	}

	Lock(h->Lock);
}

void UnlockHashList(HASH_LIST *h)
{
	if (h == NULL)
	{
		return;
	}

	Unlock(h->Lock);
}

void **HashListToArray(const HASH_LIST *h, UINT *num)
{
	void **ret = NULL;
	UINT i;
	UINT n = 0;
	if (h == NULL || num == NULL)
	{
		if (num != NULL)
		{
			*num = 0;
		}
		return NULL;
	}

	ret = ZeroMalloc(sizeof(void *) * h->NumItems);

	for (i = 0;i < h->Size;i++)
	{
		LIST *o = h->Entries[i];

		if (o != NULL)
		{
			UINT j;

			for (j = 0;j < LIST_NUM(o);j++)
			{
				void *p = LIST_DATA(o, j);

				ret[n] = p;
				n++;
			}
		}
	}

	*num = n;

	return ret;
}

void *SearchHash(const HASH_LIST *h, void *t)
{
	UINT r;
	void *ret = NULL;
	if (h == NULL || t == NULL)
	{
		return NULL;
	}

	r = CalcHashForHashList(h, t);

	if (h->Entries[r] != NULL)
	{
		LIST *o = h->Entries[r];
		void *r = Search(o, t);

		if (r != NULL)
		{
			ret = r;
		}
	}

	return ret;
}

bool DeleteHash(HASH_LIST *h, void *p)
{
	UINT r;
	bool ret = false;
	if (h == NULL || p == NULL)
	{
		return false;
	}

	r = CalcHashForHashList(h, p);

	if (h->Entries[r] != NULL)
	{
		if (Delete(h->Entries[r], p))
		{
			ret = true;
			h->NumItems--;
		}

		if (LIST_NUM(h->Entries[r]) == 0)
		{
			ReleaseList(h->Entries[r]);
			h->Entries[r] = NULL;
		}
	}

	return ret;
}

// Take out every item for which proc returns true, in one pass over the buckets: no array copy and no search per
// item. The kept items keep their order. proc may free an item it takes out: the item is not touched after that.
// Returns the number of items taken out.
UINT DeleteHashIf(HASH_LIST *h, HASH_LIST_TAKE_PROC *proc, void *param)
{
	UINT i, num_taken = 0;
	if (h == NULL || proc == NULL)
	{
		return 0;
	}

	for (i = 0;i < h->Size;i++)
	{
		LIST *o = h->Entries[i];
		UINT j, num, num_kept = 0;

		if (o == NULL)
		{
			continue;
		}

		num = LIST_NUM(o);

		for (j = 0;j < num;j++)
		{
			void *p = LIST_DATA(o, j);

			if (proc(p, param) == false)
			{
				o->p[num_kept++] = p;
			}
		}

		o->num_item = num_kept;
		h->NumItems -= (num - num_kept);
		num_taken += (num - num_kept);

		if (num_kept == 0)
		{
			ReleaseList(o);
			h->Entries[i] = NULL;
		}
	}

	return num_taken;
}

void AddHash(HASH_LIST *h, void *p)
{
	UINT r;
	if (h == NULL || p == NULL)
	{
		return;
	}

	r = CalcHashForHashList(h, p);

	if (h->Entries[r] == NULL)
	{
		h->Entries[r] = NewListFast(h->CompareProc);
	}

	Insert(h->Entries[r], p);

	h->NumItems++;
}

UINT CalcHashForHashList(const HASH_LIST *h, void *p)
{
	UINT r;
	if (h == NULL || p == NULL)
	{
		return 0;
	}

	r = h->GetHashProc(p);

	return (r % h->Size);
}

HASH_LIST *NewHashList(GET_HASH *get_hash_proc, COMPARE *compare_proc, UINT bits)
{
	HASH_LIST *h;
	if (get_hash_proc == NULL || compare_proc == NULL)
	{
		return NULL;
	}
	if (bits == 0)
	{
		bits = 16;
	}

	bits = MIN(bits, 31);

	h = ZeroMalloc(sizeof(HASH_LIST));

	h->Size = 1U << bits;

	h->Lock = NewLock();

	h->Entries = ZeroMalloc(sizeof(LIST *) * h->Size);

	h->GetHashProc = get_hash_proc;
	h->CompareProc = compare_proc;

	return h;
}

void ReleaseHashList(HASH_LIST *h)
{
	if (h == NULL)
	{
		return;
	}

	CleanupHashList(h);
}
void CleanupHashList(HASH_LIST *h)
{
	UINT i;
	if (h == NULL)
	{
		return;
	}

	for (i = 0;i < h->Size;i++)
	{
		LIST *o = h->Entries[i];

		if (o != NULL)
		{
			ReleaseList(o);
		}
	}

	Free(h->Entries);

	DeleteLock(h->Lock);

	Free(h);
}

void AppendBufStr(BUF *b, const char *str)
{
	if (b == NULL || str == NULL)
	{
		return;
	}

	WriteBuf(b, str, StrLen(str));
}

void AppendBufUtf8(BUF *b, const wchar_t *str)
{
	UINT size;
	UCHAR *data;
	if (b == NULL || str == NULL)
	{
		return;
	}

	size = CalcUniToUtf8(str) + 1;
	data = ZeroMalloc(size);

	UniToUtf8(data, size, str);

	WriteBuf(b, data, size - 1);

	Free(data);
}

UINT SearchBin(const void *data, UINT data_size, const void *key, UINT key_size)
{
	UINT i;
	if (data == NULL || key == NULL || key_size == 0 || data_size == 0 || key_size > data_size)
	{
		return INFINITE;
	}

	for (i = 0;i < (data_size - key_size + 1);i++)
	{
		UCHAR *p = ((UCHAR *)data) + i;

		if (Cmp(p, key, key_size) == 0)
		{
			return i;
		}
	}

	return INFINITE;
}

// Ends the process at once with a fail-fast exception, which Windows Error Reporting records.
// Writing to a random address could hit valid memory and corrupt it instead of crashing.
void CrashNow()
{
	__fastfail(FAST_FAIL_FATAL_APP_EXIT);
}

bool IsZero(const void *data, UINT size)
{
	UINT i;
	UCHAR *c = (UCHAR *)data;
	if (data == NULL || size == 0)
	{
		return true;
	}

	for (i = 0;i < size;i++)
	{
		if (c[i] != 0)
		{
			return false;
		}
	}

	return true;
}

UINT Uncompress(void *dst, UINT dst_size, void *src, UINT src_size)
{
	unsigned long dst_size_long = dst_size;
	if (dst == NULL || dst_size_long == 0 || src == NULL)
	{
		return 0;
	}

	if (uncompress(dst, &dst_size_long, src, src_size) != Z_OK)
	{
		return 0;
	}

	return (UINT)dst_size_long;
}

UINT Compress(void *dst, UINT dst_size, void *src, UINT src_size)
{
	unsigned long dst_size_long = dst_size;
	if (dst == NULL || dst_size_long == 0 || src == NULL)
	{
		return 0;
	}

	if (compress2(dst, &dst_size_long, src, src_size, Z_DEFAULT_COMPRESSION) != Z_OK)
	{
		return 0;
	}

	return dst_size_long;
}

UINT CalcCompress(UINT src_size)
{
	return src_size * 2 + 256;
}

SK *NewSk()
{
	SK *s;

	s = Malloc(sizeof(SK));
	s->lock = NewLock();
	s->num_item = 0;
	s->num_reserved = INIT_NUM_RESERVED;
	s->p = Malloc(sizeof(void *) * s->num_reserved);

	KS_INC(KS_NEWSK_COUNT);

	return s;
}

void ReleaseSk(SK *s)
{
	if (s == NULL)
	{
		return;
	}

	CleanupSk(s);
}

void CleanupSk(SK *s)
{
	if (s == NULL)
	{
		return;
	}

	Free(s->p);
	DeleteLock(s->lock);
	Free(s);

	KS_INC(KS_FREESK_COUNT);
}

void LockSk(SK *s)
{
	if (s == NULL)
	{
		return;
	}

	Lock(s->lock);
}

void UnlockSk(SK *s)
{
	if (s == NULL)
	{
		return;
	}

	Unlock(s->lock);
}

void Push(SK *s, void *p)
{
	UINT i;
	if (s == NULL || p == NULL)
	{
		return;
	}

	i = s->num_item;
	s->num_item++;

	if (s->num_item > s->num_reserved)
	{
		s->num_reserved = s->num_reserved * 2;
		s->p = ReAlloc(s->p, sizeof(void *) * s->num_reserved);
	}
	s->p[i] = p;

	KS_INC(KS_PUSH_COUNT);
}

void *Pop(SK *s)
{
	void *ret;
	if (s == NULL)
	{
		return NULL;
	}
	if (s->num_item == 0)
	{
		return NULL;
	}
	ret = s->p[s->num_item - 1];
	s->num_item--;

	if ((s->num_item * 2) <= s->num_reserved)
	{
		if (s->num_reserved >= (INIT_NUM_RESERVED * 2))
		{
			s->num_reserved = s->num_reserved / 2;
			s->p = ReAlloc(s->p, sizeof(void *) * s->num_reserved);
		}
	}

	KS_INC(KS_POP_COUNT);

	return ret;
}

// Move the items of the ring into a new one of num_reserved slots (a power of two), the oldest item first
static void ResizeQueue(QUEUE *q, UINT num_reserved)
{
	void **p = Malloc(sizeof(void *) * num_reserved);
	UINT first = MIN(q->num_item, q->num_reserved - q->head);

	Copy(p, q->p + q->head, sizeof(void *) * first);
	Copy(p + first, q->p, sizeof(void *) * (q->num_item - first));

	Free(q->p);
	q->p = p;
	q->head = 0;
	q->num_reserved = num_reserved;
}

UINT GetQueueNum(const QUEUE *q)
{
	if (q == NULL)
	{
		return 0;
	}

	return q->num_item;
}

void *GetNext(QUEUE *q)
{
	void *p = NULL;
	if (q == NULL)
	{
		return NULL;
	}

	if (q->num_item == 0)
	{
		return NULL;
	}

	p = q->p[q->head];
	q->head = (q->head + 1) & (q->num_reserved - 1);
	q->num_item--;

	// A large ring gives back half its slots once a quarter or less of them is in use
	if (q->num_reserved > QUEUE_SHRINK_NUM_RESERVED && q->num_item <= (q->num_reserved / 4))
	{
		ResizeQueue(q, q->num_reserved / 2);
	}

	KS_INC(KS_GETNEXT_COUNT);

	return p;
}

void InsertQueueInt(QUEUE *q, UINT value)
{
	UINT *p;
	if (q == NULL)
	{
		return;
	}

	p = Clone(&value, sizeof(UINT));

	InsertQueue(q, p);
}

void InsertQueue(QUEUE *q, void *p)
{
	if (q == NULL || p == NULL)
	{
		return;
	}

	if (q->num_item == q->num_reserved)
	{
		ResizeQueue(q, q->num_reserved * 2);
	}

	q->p[(q->head + q->num_item) & (q->num_reserved - 1)] = p;

	q->num_item++;

	KS_INC(KS_INSERT_QUEUE_COUNT);
}

void LockQueue(QUEUE *q)
{
	if (q == NULL)
	{
		return;
	}

	Lock(q->lock);
}

void UnlockQueue(QUEUE *q)
{
	if (q == NULL)
	{
		return;
	}

	Unlock(q->lock);
}

void ReleaseQueue(QUEUE *q)
{
	if (q == NULL)
	{
		return;
	}

	CleanupQueue(q);
}

void CleanupQueue(QUEUE *q)
{
	if (q == NULL)
	{
		return;
	}

	Free(q->p);
	DeleteLock(q->lock);
	Free(q);

	KS_INC(KS_FREEQUEUE_COUNT);
}

QUEUE *NewQueue()
{
	QUEUE *q;

	q = ZeroMalloc(sizeof(QUEUE));
	q->lock = NewLock();
	q->num_item = 0;
	q->num_reserved = QUEUE_INIT_NUM_RESERVED;
	q->p = Malloc(sizeof(void *) * QUEUE_INIT_NUM_RESERVED);

	KS_INC(KS_NEWQUEUE_COUNT);

	return q;
}
QUEUE *NewQueueFast()
{
	QUEUE *q;

	q = ZeroMalloc(sizeof(QUEUE));
	q->lock = NULL;
	q->num_item = 0;
	q->num_reserved = QUEUE_INIT_NUM_RESERVED;
	q->p = Malloc(sizeof(void *) * QUEUE_INIT_NUM_RESERVED);

	KS_INC(KS_NEWQUEUE_COUNT);

	return q;
}

static void CopyToArray(LIST *o, void *p)
{
	if (o == NULL || p == NULL)
	{
		return;
	}

	KS_INC(KS_TOARRAY_COUNT);

	Copy(p, o->p, sizeof(void *) * o->num_item);
}

void *ToArray(LIST *o)
{
	return ToArrayEx(o, false);
}
void *ToArrayEx(LIST *o, bool fast)
{
	void *p;
	if (o == NULL)
	{
		return NULL;
	}

	if (fast == false)
	{
		p = Malloc(sizeof(void *) * LIST_NUM(o));
	}
	else
	{
		p = Malloc(sizeof(void *) * LIST_NUM(o));
	}
	CopyToArray(o, p);

	return p;
}

void *Search(LIST *o, const void *target)
{
	void **ret;
	if (o == NULL || target == NULL)
	{
		return NULL;
	}
	if (o->cmp == NULL)
	{
		return NULL;
	}

	if (o->sorted == false)
	{
		Sort(o);
	}

	ret = (void **)bsearch(&target, o->p, o->num_item, sizeof(void *),
		(int(*)(const void *, const void *))o->cmp);

	KS_INC(KS_SEARCH_COUNT);

	if (ret != NULL)
	{
		return *ret;
	}
	else
	{
		return NULL;
	}
}

void Insert(LIST *o, void *p)
{
	int low, high, middle;
	UINT pos;
	if (o == NULL || p == NULL)
	{
		return;
	}

	if (o->cmp == NULL)
	{
		Add(o, p);
		return;
	}

	if (o->sorted == false)
	{
		Sort(o);
	}

	low = 0;
	high = LIST_NUM(o) - 1;

	pos = INFINITE;

	while (low <= high)
	{
		int ret;

		middle = (low + high) / 2;
		ret = o->cmp(&(o->p[middle]), &p);

		if (ret == 0)
		{
			pos = middle;
			break;
		}
		else if (ret > 0)
		{
			high = middle - 1;
		}
		else
		{
			low = middle + 1;
		}
	}

	if (pos == INFINITE)
	{
		pos = low;
	}

	o->num_item++;
	if (o->num_item > o->num_reserved)
	{
		o->num_reserved *= 2;
		o->p = ReAlloc(o->p, sizeof(void *) * o->num_reserved);
	}

	memmove(&o->p[pos + 1], &o->p[pos], sizeof(void *) * (LIST_NUM(o) - 1 - pos));

	o->p[pos] = p;

	KS_INC(KS_INSERT_COUNT);
}

void Sort(LIST *o)
{
	if (o == NULL || o->cmp == NULL)
	{
		return;
	}

	qsort(o->p, o->num_item, sizeof(void *), (int(*)(const void *, const void *))o->cmp);
	o->sorted = true;

	KS_INC(KS_SORT_COUNT);
}

bool ReplaceListPointer(LIST *o, const void *oldptr, void *newptr)
{
	UINT i;
	if (o == NULL || oldptr == NULL || newptr == NULL)
	{
		return false;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		void *p = LIST_DATA(o, i);

		if (p == oldptr)
		{
			o->p[i] = newptr;
			return true;
		}
	}

	return false;
}

void *ListKeyToPointer(LIST *o, UINT key)
{
	UINT i;
	if (o == NULL || key == 0)
	{
		return NULL;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		void *p = LIST_DATA(o, i);

		if (POINTER_TO_KEY(p) == key)
		{
			return p;
		}
	}

	return NULL;
}

bool IsInListKey(LIST *o, UINT key)
{
	void *p;
	if (o == NULL || key == 0)
	{
		return false;
	}

	p = ListKeyToPointer(o, key);
	if (p == NULL)
	{
		return false;
	}

	return true;
}

bool IsInList(LIST *o, const void *p)
{
	UINT i;
	if (o == NULL || p == NULL)
	{
		return false;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		void *q = LIST_DATA(o, i);
		if (p == q)
		{
			return true;
		}
	}

	return false;
}

void Add(LIST *o, void *p)
{
	UINT i;
	if (o == NULL || p == NULL)
	{
		return;
	}

	i = o->num_item;
	o->num_item++;

	if (o->num_item > o->num_reserved)
	{
		o->num_reserved = o->num_reserved * 2;
		o->p = ReAlloc(o->p, sizeof(void *) * o->num_reserved);
	}

	o->p[i] = p;
	o->sorted = false;

	KS_INC(KS_INSERT_COUNT);
}

bool Delete(LIST *o, const void *p)
{
	UINT i;
	if (o == NULL || p == NULL)
	{
		return false;
	}

	for (i = 0;i < o->num_item;i++)
	{
		if (o->p[i] == p)
		{
			break;
		}
	}
	if (i == o->num_item)
	{
		return false;
	}

	memmove(&o->p[i], &o->p[i + 1], sizeof(void *) * (o->num_item - 1 - i));
	o->num_item--;
	if ((o->num_item * 2) <= o->num_reserved)
	{
		if (o->num_reserved > (INIT_NUM_RESERVED * 2))
		{
			o->num_reserved = o->num_reserved / 2;
			o->p = ReAlloc(o->p, sizeof(void *) * o->num_reserved);
		}
	}

	KS_INC(KS_DELETE_COUNT);

	return true;
}

// Removes and Free()s every item for which is_dead returns true, in one pass that keeps the order of the others,
// so a sorted list stays sorted. The caller holds the list lock; is_dead must not change the list.
// Returns the number of items removed
UINT DeleteAndFreeIf(LIST *o, bool (*is_dead)(void *p, void *param), void *param)
{
	UINT i, keep, num;
	if (o == NULL || is_dead == NULL)
	{
		return 0;
	}

	num = o->num_item;
	keep = 0;

	for (i = 0;i < num;i++)
	{
		void *p = o->p[i];

		if (is_dead(p, param))
		{
			Free(p);
		}
		else
		{
			o->p[keep++] = p;
		}
	}

	o->num_item = keep;

	if (keep != num)
	{
		UINT shrunk = o->num_reserved;

		while ((o->num_item * 2) <= shrunk && shrunk > (INIT_NUM_RESERVED * 2))
		{
			shrunk = shrunk / 2;
		}

		if (shrunk != o->num_reserved)
		{
			o->num_reserved = shrunk;
			o->p = ReAlloc(o->p, sizeof(void *) * o->num_reserved);
		}

		for (i = keep;i < num;i++)
		{
			KS_INC(KS_DELETE_COUNT);
		}
	}

	return num - keep;
}

void DeleteAll(LIST *o)
{
	if (o == NULL)
	{
		return;
	}

	o->num_item = 0;
	o->num_reserved = INIT_NUM_RESERVED;
	o->p = ReAlloc(o->p, sizeof(void *) * INIT_NUM_RESERVED);
}

void LockList(LIST *o)
{
	if (o == NULL)
	{
		return;
	}

	Lock(o->lock);
}

void UnlockList(LIST *o)
{
	if (o == NULL)
	{
		return;
	}

	Unlock(o->lock);
}

void ReleaseList(LIST *o)
{
	if (o == NULL)
	{
		return;
	}

	CleanupList(o);
}

void CleanupList(LIST *o)
{
	if (o == NULL)
	{
		return;
	}

	Free(o->p);
	if (o->lock != NULL)
	{
		DeleteLock(o->lock);
	}
	Free(o);

	KS_INC(KS_FREELIST_COUNT);
}

bool IsIntInList(LIST *o, UINT i)
{
	UINT j;
	if (o == NULL)
	{
		return false;
	}

	for (j = 0;j < LIST_NUM(o);j++)
	{
		UINT *p = LIST_DATA(o, j);

		if (*p == i)
		{
			return true;
		}
	}

	return false;
}
bool IsInt64InList(LIST *o, UINT64 i)
{
	UINT j;
	if (o == NULL)
	{
		return false;
	}

	for (j = 0;j < LIST_NUM(o);j++)
	{
		UINT64 *p = LIST_DATA(o, j);

		if (*p == i)
		{
			return true;
		}
	}

	return false;
}

void FreeListItems(LIST *o)
{
	UINT i;
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		Free(LIST_DATA(o, i));
	}

	ReleaseList(o);
}

void ReleaseIntList(LIST *o)
{
	FreeListItems(o);
}
void ReleaseInt64List(LIST *o)
{
	FreeListItems(o);
}

void DelInt(LIST *o, UINT i)
{
	LIST *o2 = NULL;
	UINT j;
	if (o == NULL)
	{
		return;
	}

	for (j = 0;j < LIST_NUM(o);j++)
	{
		UINT *p = LIST_DATA(o, j);

		if (*p == i)
		{
			if (o2 == NULL)
			{
				o2 = NewListFast(NULL);
			}
			Add(o2, p);
		}
	}

	for (j = 0;j < LIST_NUM(o2);j++)
	{
		UINT *p = LIST_DATA(o2, j);

		Delete(o, p);

		Free(p);
	}

	if (o2 != NULL)
	{
		ReleaseList(o2);
	}
}

LIST *NewIntList()
{
	return NewList(NULL);
}
LIST *NewInt64List()
{
	return NewList(NULL);
}

int CompareInt(void *p1, void *p2)
{
	UINT *v1, *v2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}

	v1 = *((UINT **)p1);
	v2 = *((UINT **)p2);
	if (v1 == NULL || v2 == NULL)
	{
		return 0;
	}

	return COMPARE_RET(*v1, *v2);
}
int CompareInt64(void *p1, void *p2)
{
	UINT64 *v1, *v2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}

	v1 = *((UINT64 **)p1);
	v2 = *((UINT64 **)p2);
	if (v1 == NULL || v2 == NULL)
	{
		return 0;
	}

	return COMPARE_RET(*v1, *v2);
}

static void AddInt(LIST *o, UINT i)
{
	if (o == NULL)
	{
		return;
	}

	Add(o, Clone(&i, sizeof(UINT)));
}
static void AddInt64(LIST *o, UINT64 i)
{
	if (o == NULL)
	{
		return;
	}

	Add(o, Clone(&i, sizeof(UINT64)));
}

void AddIntDistinct(LIST *o, UINT i)
{
	if (o == NULL)
	{
		return;
	}

	if (IsIntInList(o, i) == false)
	{
		AddInt(o, i);
	}
}
void AddInt64Distinct(LIST *o, UINT64 i)
{
	if (o == NULL)
	{
		return;
	}

	if (IsInt64InList(o, i) == false)
	{
		AddInt64(o, i);
	}
}

bool InsertStr(LIST *o, char *str)
{
	if (o == NULL || str == NULL)
	{
		return false;
	}

	if (Search(o, str) == NULL)
	{
		Insert(o, str);

		return true;
	}

	return false;
}

int CompareStr(void *p1, void *p2)
{
	char *s1, *s2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	s1 = *(char **)p1;
	s2 = *(char **)p2;

	return StrCmpi(s1, s2);
}

LIST *NewListFast(COMPARE *cmp)
{
	return NewListEx2(cmp, true);
}

LIST *NewList(COMPARE *cmp)
{
	return NewListEx2(cmp, false);
}
LIST *NewListEx2(COMPARE *cmp, bool fast)
{
	LIST *o = Malloc(sizeof(LIST));

	if (fast == false)
	{
		o->lock = NewLock();
	}
	else
	{
		o->lock = NULL;
	}
	o->num_item = 0;
	o->num_reserved = INIT_NUM_RESERVED;
	o->Param1 = 0;

	o->p = Malloc(sizeof(void *) * o->num_reserved);

	o->cmp = cmp;
	o->sorted = true;

	KS_INC(KS_NEWLIST_COUNT);

	return o;
}

UINT ReadFifo(FIFO *f, void *p, UINT size)
{
	UINT read_size;
	if (f == NULL || size == 0)
	{
		return 0;
	}

	read_size = MIN(size, f->size);
	if (read_size == 0)
	{
		return 0;
	}
	if (p != NULL)
	{
		Copy(p, (UCHAR *)f->p + f->pos, read_size);
	}
	f->pos += read_size;
	f->size -= read_size;

	if (f->size == 0)
	{
		f->pos = 0;
	}

	ShrinkFifoMemory(f);

	KS_INC(KS_READ_FIFO_COUNT);

	return read_size;
}

void ShrinkFifoMemory(FIFO *f)
{
	if (f == NULL)
	{
		return;
	}

	if (f->pos >= FIFO_INIT_MEM_SIZE && 
		f->memsize >= fifo_current_realloc_mem_size &&
		(f->memsize / 2) > f->size)
	{
		void *new_p;
		UINT new_size;

		new_size = MAX(f->memsize / 2, FIFO_INIT_MEM_SIZE);
		new_p = Malloc(new_size);
		Copy(new_p, (UCHAR *)f->p + f->pos, f->size);

		Free(f->p);

		f->memsize = new_size;
		f->p = new_p;
		f->pos = 0;
	}
}

void WriteFifo(FIFO *f, const void *p, UINT size)
{
	UINT i, need_size;
	bool realloc_flag;
	if (f == NULL || size == 0)
	{
		return;
	}

	i = f->size;
	f->size += size;
	need_size = f->pos + f->size;
	realloc_flag = false;

	// Compact before growing: when the write does not fit behind the live bytes and the bytes already read in
	// front of them are at least as many, move the live bytes to the front. Each byte moved is paid by a byte
	// read since the last move, and a producer and a consumer that never fully drain the FIFO keep it at its
	// size instead of growing it x3 at each wrap until ShrinkFifoMemory steps in
	if (need_size > f->memsize && f->pos != 0 && f->pos >= i)
	{
		Move(f->p, (UCHAR *)f->p + f->pos, i);
		f->pos = 0;
		need_size = f->size;
	}

	while (need_size > f->memsize)
	{
		f->memsize = MAX(f->memsize, FIFO_INIT_MEM_SIZE) * 3;
		realloc_flag = true;
	}

	if (realloc_flag)
	{
		f->p = ReAlloc(f->p, f->memsize);
	}

	if (p != NULL)
	{
		Copy((UCHAR *)f->p + f->pos + i, p, size);
	}

	KS_INC(KS_WRITE_FIFO_COUNT);
}

UINT FifoSize(const FIFO *f)
{
	if (f == NULL)
	{
		return 0;
	}

	return f->size;
}

void ReleaseFifo(FIFO *f)
{
	if (f == NULL)
	{
		return;
	}

	CleanupFifo(f);
}

void CleanupFifo(FIFO *f)
{
	if (f == NULL)
	{
		return;
	}

	Free(f->p);
	Free(f);

	KS_INC(KS_FREEFIFO_COUNT);
}

FIFO *NewFifo()
{
	return NewFifoEx2();
}
FIFO *NewFifoFast()
{
	return NewFifoEx2();
}
FIFO *NewFifoEx2()
{
	FIFO *f;

	f = ZeroMalloc(sizeof(FIFO));

	f->size = f->pos = 0;
	f->memsize = FIFO_INIT_MEM_SIZE;
	f->p = Malloc(FIFO_INIT_MEM_SIZE);

	KS_INC(KS_NEWFIFO_COUNT);

	return f;
}

void SetFifoCurrentReallocMemSize(UINT size)
{
	if (size == 0)
	{
		size = FIFO_REALLOC_MEM_SIZE;
	}

	fifo_current_realloc_mem_size = size;
}

BUF *FileToBuf(IO *o)
{
	UCHAR hash1[MD5_SIZE], hash2[MD5_SIZE];
	UINT size;
	void *buf;
	BUF *b;

	if (o == NULL)
	{
		return NULL;
	}

	if (FileRead(o, &size, sizeof(size)) == false)
	{
		return NULL;
	}
	size = Endian32(size);

	if (size > FileSize(o))
	{
		return NULL;
	}

	if (FileRead(o, hash1, sizeof(hash1)) == false)
	{
		return NULL;
	}

	buf = Malloc(size);
	if (FileRead(o, buf, size) == false)
	{
		Free(buf);
		return NULL;
	}

	Md5(hash2, buf, size);

	if (Cmp(hash1, hash2, sizeof(hash1)) != 0)
	{
		Free(buf);
		return NULL;
	}

	b = NewBuf();
	WriteBuf(b, buf, size);
	Free(buf);
	b->Current = 0;

	return b;
}

BUF *ReadDump(const char *filename)
{
	return ReadDumpWithMaxSize(filename, 0);
}
BUF *ReadDumpWithMaxSize(const char *filename, UINT max_size)
{
	wchar_t *filename_w;
	BUF *ret;
	if (filename == NULL)
	{
		return NULL;
	}

	filename_w = CopyStrToUni(filename);
	ret = ReadDumpExW(filename_w, true, max_size);
	Free(filename_w);

	return ret;
}
BUF *ReadDumpW(wchar_t *filename)
{
	return ReadDumpExW(filename, true, 0);
}
// Read a whole file; max_size 0 reads all of it, else at most max_size bytes
BUF *ReadDumpExW(wchar_t *filename, bool read_lock, UINT max_size)
{
	IO *o;
	BUF *b;
	UINT size;
	void *data;
	if (filename == NULL)
	{
		return NULL;
	}

	o = FileOpenExW(filename, false, read_lock);
	if (o == NULL)
	{
		return NULL;
	}

	size = FileSize(o);

	if (max_size != 0)
	{
		if (size > max_size)
		{
			size = max_size;
		}
	}

	data = Malloc(size);
	if (FileRead(o, data, size) == false)
	{
		FileClose(o);
		Free(data);
		return NULL;
	}
	FileClose(o);

	b = NewBuf();
	WriteBuf(b, data, size);
	b->Current = 0;
	Free(data);

	return b;
}

// Write the data to a new file; false when the create, the write or the close fails
bool DumpDataW(void *data, UINT size, wchar_t *filename)
{
	IO *o;
	bool ok;
	if (filename == NULL || (size != 0 && data == NULL))
	{
		return false;
	}

	o = FileCreateW(filename);
	if (o == NULL)
	{
		return false;
	}
	ok = (size == 0 || FileWrite(o, data, size));
	if (FileClose(o) == false)
	{
		ok = false;
	}

	return ok;
}

bool DumpBuf(BUF *b, const char *filename)
{
	wchar_t *filename_w;
	bool ret;
	if (b == NULL || filename == NULL)
	{
		return false;
	}

	filename_w = CopyStrToUni(filename);
	ret = DumpBufW(b, filename_w);
	Free(filename_w);

	return ret;
}
bool DumpBufW(BUF *b, wchar_t *filename)
{
	if (b == NULL)
	{
		return false;
	}

	return DumpDataW(b->Buf, b->Size, filename);
}

bool DumpBufWIfNecessary(BUF *b, wchar_t *filename)
{
	BUF *now;
	bool need = true;
	if (b == NULL || filename == NULL)
	{
		return false;
	}

	now = ReadDumpW(filename);

	if (now != NULL)
	{
		if (CompareBuf(now, b))
		{
			need = false;
		}

		FreeBuf(now);
	}

	if (need == false)
	{
		return true;
	}
	else
	{
		return DumpBufW(b, filename);
	}
}

bool BufToFile(const IO *o, BUF *b)
{
	UCHAR hash[MD5_SIZE];
	UINT size;

	if (o == NULL || b == NULL)
	{
		return false;
	}

	Md5(hash, b->Buf, b->Size);

	size = Endian32(b->Size);

	if (FileWrite(o, &size, sizeof(size)) == false)
	{
		return false;
	}

	if (FileWrite(o, hash, sizeof(hash)) == false)
	{
		return false;
	}

	if (FileWrite(o, b->Buf, b->Size) == false)
	{
		return false;
	}

	return true;
}

BUF *NewBufFromMemory(const void *buf, UINT size)
{
	BUF *b;
	if (buf == NULL && size != 0)
	{
		return NULL;
	}

	b = NewBuf();
	WriteBuf(b, buf, size);
	SeekBufToBegin(b);

	return b;
}

BUF *NewBuf()
{
	BUF *b;

	b = Malloc(sizeof(BUF));
	b->Buf = Malloc(INIT_BUF_SIZE);
	b->Size = 0;
	b->Current = 0;
	b->SizeReserved = INIT_BUF_SIZE;

	KS_INC(KS_NEWBUF_COUNT);
	KS_INC(KS_CURRENT_BUF_COUNT);

	return b;
}

void ClearBuf(BUF *b)
{
	if (b == NULL)
	{
		return;
	}

	b->Size = 0;
	b->Current = 0;
}

void WriteBuf(BUF *b, const void *buf, UINT size)
{
	UINT new_size;
	if (b == NULL || buf == NULL || size == 0)
	{
		return;
	}

	// Current + size must not wrap: a wrapped size would keep the block and copy past its end
	if (size > 0xFFFFFFFF - b->Current)
	{
		AbortExitEx("WriteBuf(): too large buffer size");
	}

	new_size = b->Current + size;
	if (new_size > b->Size)
	{
		AdjustBufSize(b, new_size);
	}
	if (b->Buf != NULL)
	{
		Copy((UCHAR *)b->Buf + b->Current, buf, size);
	}
	b->Current += size;
	// A write inside the buffer (after SeekBuf) keeps the bytes after it
	b->Size = MAX(b->Size, new_size);

	KS_INC(KS_WRITE_BUF_COUNT);
}

bool WriteBufStr(BUF *b, const char *str)
{
	UINT len;
	if (b == NULL || str == NULL)
	{
		return false;
	}

	len = StrLen(str);
	if (WriteBufInt(b, len + 1) == false)
	{
		return false;
	}

	WriteBuf(b, str, len);

	return true;
}

bool ReadBufStr(BUF *b, char *str, UINT size)
{
	UINT len;
	UINT read_size;
	if (b == NULL || str == NULL || size == 0)
	{
		return false;
	}

	len = ReadBufInt(b);
	if (len == 0)
	{
		return false;
	}
	len--;
	if (len <= (size - 1))
	{
		size = len + 1;
	}

	read_size = MIN(len, (size - 1));

	if (ReadBuf(b, str, read_size) != read_size)
	{
		return false;
	}
	str[read_size] = 0;

	// Skip the part that does not fit; it must be there too
	if (read_size < len)
	{
		if (ReadBuf(b, NULL, len - read_size) != (len - read_size))
		{
			return false;
		}
	}

	return true;
}

bool WriteBufInt64(BUF *b, UINT64 value)
{
	if (b == NULL)
	{
		return false;
	}

	value = Endian64(value);

	WriteBuf(b, &value, sizeof(UINT64));
	return true;
}

bool WriteBufInt(BUF *b, UINT value)
{
	if (b == NULL)
	{
		return false;
	}

	value = Endian32(value);

	WriteBuf(b, &value, sizeof(UINT));
	return true;
}

bool WriteBufChar(BUF *b, UCHAR uc)
{
	if (b == NULL)
	{
		return false;
	}

	WriteBuf(b, &uc, 1);

	return true;
}

UCHAR ReadBufChar(BUF *b)
{
	UCHAR uc;
	if (b == NULL)
	{
		return 0;
	}

	if (ReadBuf(b, &uc, 1) != 1)
	{
		return 0;
	}

	return uc;
}

UINT64 ReadBufInt64(BUF *b)
{
	UINT64 value;
	if (b == NULL)
	{
		return 0;
	}

	if (ReadBuf(b, &value, sizeof(UINT64)) != sizeof(UINT64))
	{
		return 0;
	}
	return Endian64(value);
}

UINT ReadBufInt(BUF *b)
{
	UINT value;
	if (b == NULL)
	{
		return 0;
	}

	if (ReadBuf(b, &value, sizeof(UINT)) != sizeof(UINT))
	{
		return 0;
	}
	return Endian32(value);
}

void WriteBufBuf(BUF *b, const BUF *bb)
{
	if (b == NULL || bb == NULL)
	{
		return;
	}

	WriteBuf(b, bb->Buf, bb->Size);
}

UINT ReadBuf(BUF *b, void *buf, UINT size)
{
	UINT size_read;
	if (b == NULL || size == 0)
	{
		return 0;
	}

	if (b->Buf == NULL)
	{
		Zero(buf, size);
		return 0;
	}
	size_read = size;
	// Against the bytes left: Current + size wraps for a size near 2^32
	if (size > ReadBufRemainSize(b))
	{
		size_read = ReadBufRemainSize(b);
		if (buf != NULL)
		{
			Zero((UCHAR *)buf + size_read, size - size_read);
		}
	}

	if (buf != NULL)
	{
		Copy(buf, (UCHAR *)b->Buf + b->Current, size_read);
	}

	b->Current += size_read;

	KS_INC(KS_READ_BUF_COUNT);

	return size_read;
}

// Bytes left to read from the current position; a reader bounds a length by it before it allocates
UINT ReadBufRemainSize(const BUF *b)
{
	if (b == NULL || b->Current >= b->Size)
	{
		return 0;
	}

	return b->Size - b->Current;
}

void AdjustBufSize(BUF *b, UINT new_size)
{
	if (b == NULL)
	{
		return;
	}

	if (b->SizeReserved >= new_size)
	{
		return;
	}

	while (b->SizeReserved < new_size)
	{
		if (b->SizeReserved > 0x7FFFFFFF)
		{
			AbortExitEx("AdjustBufSize(): too large buffer size");
		}
		b->SizeReserved = b->SizeReserved * 2;
	}
	b->Buf = ReAlloc(b->Buf, b->SizeReserved);

	KS_INC(KS_ADJUST_BUFSIZE_COUNT);
}

void SeekBufToBegin(BUF *b)
{
	if (b == NULL)
	{
		return;
	}

	SeekBuf(b, 0, 0);
}

void SeekBufToEnd(BUF *b)
{
	if (b == NULL)
	{
		return;
	}

	SeekBuf(b, b->Size, 0);
}

void SeekBuf(BUF *b, UINT offset, int mode)
{
	UINT new_pos;
	if (b == NULL)
	{
		return;
	}

	if (mode == 0)
	{
		new_pos = offset;
	}
	else
	{
		if (mode > 0)
		{
			new_pos = b->Current + offset;
		}
		else
		{
			if (b->Current >= offset)
			{
				new_pos = b->Current - offset;
			}
			else
			{
				new_pos = 0;
			}
		}
	}
	b->Current = MAKESURE(new_pos, 0, b->Size);

	KS_INC(KS_SEEK_BUF_COUNT);
}

void FreeBuf(BUF *b)
{
	if (b == NULL)
	{
		return;
	}

	Free(b->Buf);
	Free(b);

	KS_INC(KS_FREEBUF_COUNT);
	KS_DEC(KS_CURRENT_BUF_COUNT);
}

bool CompareBuf(const BUF *b1, const BUF *b2)
{
	if (b1 == NULL && b2 == NULL)
	{
		return true;
	}
	if (b1 == NULL || b2 == NULL)
	{
		return false;
	}

	if (b1->Size != b2->Size)
	{
		return false;
	}

	if (Cmp(b1->Buf, b2->Buf, b1->Size) != 0)
	{
		return false;
	}

	return true;
}

BUF *MemToBuf(const void *data, UINT size)
{
	BUF *b;
	if (data == NULL && size != 0)
	{
		return NULL;
	}

	b = NewBuf();
	WriteBuf(b, data, size);
	SeekBuf(b, 0, 0);

	return b;
}

void EndianUnicode(wchar_t *str)
{
	UINT i, len;
	if (str == NULL)
	{
		return;
	}
	len = UniStrLen(str);

	for (i = 0;i < len;i++)
	{
		str[i] = Endian16(str[i]);
	}
}

// Endian16/32/64 (MayaType.h) swap always: the build is for a little-endian target only
#if defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__)
_Static_assert(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__, "Ranz VPN needs a little-endian target");
#elif !defined(_M_X64) && !defined(_M_ARM64) && !defined(_M_IX86)
#error "Ranz VPN needs a little-endian target (x64, arm64)"
#endif

// Base64 on crypt32: CryptStringToBinaryA and CryptBinaryToStringA
// https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptstringtobinarya
// https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptbinarytostringa
void *Base64ToBin(UINT *out_size, const void *src, const UINT size)
{
	DWORD bin_size = 0;
	void *bin;
	if (src == NULL || size == 0)
	{
		return NULL;
	}

	if (CryptStringToBinaryA(src, size, CRYPT_STRING_BASE64, NULL, &bin_size, NULL, NULL) == false || bin_size == 0)
	{
		return NULL;
	}

	// One zero byte after the data, as before
	bin = ZeroMalloc(bin_size + 1);
	if (CryptStringToBinaryA(src, size, CRYPT_STRING_BASE64, bin, &bin_size, NULL, NULL) == false || bin_size == 0)
	{
		Free(bin);
		return NULL;
	}

	if (out_size != NULL)
	{
		*out_size = bin_size;
	}

	return bin;
}

void *Base64FromBin(UINT *out_size, const void *src, const UINT size)
{
	DWORD base64_size = 0;
	char *base64;
	if (src == NULL || size == 0)
	{
		return NULL;
	}

	// The first call gives the size with the terminator, the second the length without it
	if (CryptBinaryToStringA(src, size, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &base64_size) == false || base64_size == 0)
	{
		return NULL;
	}

	base64 = Malloc(base64_size);
	if (CryptBinaryToStringA(src, size, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, base64, &base64_size) == false)
	{
		Free(base64);
		return NULL;
	}

	// The size written, terminator included
	if (out_size != NULL)
	{
		*out_size = base64_size + 1;
	}

	return base64;
}

void *Clone(const void *addr, UINT size)
{
	void *ret;
	if (addr == NULL)
	{
		return NULL;
	}

	ret = Malloc(size);
	Copy(ret, addr, size);

	return ret;
}

void Copy(void *dst, const void *src, UINT size)
{
	if (dst == NULL || src == NULL || size == 0 || dst == src)
	{
		return;
	}

	KS_INC(KS_COPY_COUNT);

	memcpy(dst, src, size);
}

void Move(void *dst, const void *src, UINT size)
{
	if (dst == NULL || src == NULL || size == 0 || dst == src)
	{
		return;
	}

	KS_INC(KS_COPY_COUNT);

	memmove(dst, src, size);
}

int Cmp(const void *p1, const void *p2, UINT size)
{
	if (p1 == NULL || p2 == NULL || size == 0)
	{
		return 0;
	}

	return memcmp(p1, p2, (size_t)size);
}

int CmpCaseIgnore(const void *p1, const void *p2, UINT size)
{
	UINT i;
	if (p1 == NULL || p2 == NULL || size == 0)
	{
		return 0;
	}

	for (i = 0;i < size;i++)
	{
		char c1 = (char)(*(((UCHAR *)p1) + i));
		char c2 = (char)(*(((UCHAR *)p2) + i));

		c1 = ToUpper(c1);
		c2 = ToUpper(c2);

		if (c1 != c2)
		{
			return COMPARE_RET(c1, c2);
		}
	}

	return 0;
}

void Zero(void *addr, UINT size)
{
	if (addr == NULL || size == 0)
	{
		return;
	}

	KS_INC(KS_ZERO_COUNT);

	memset(addr, 0, size);
}

UINT HashPtrToUINT(void *p)
{
	UCHAR hash_data[SHA256_SIZE];
	UCHAR hash_src[CANARY_RAND_SIZE + sizeof(void *)];
	UINT ret;
	if (p == NULL)
	{
		return 0;
	}

	// The key names the block by its address: the pointer value, never the bytes it points to (blocks
	// with equal content must get different keys, and a key must not change with the content)
	Zero(hash_src, sizeof(hash_src));
	Copy(hash_src + 0, GetCanaryRand(CANARY_RAND_ID_PTR_KEY_HASH), CANARY_RAND_SIZE);
	Copy(hash_src + CANARY_RAND_SIZE, &p, sizeof(void *));

	Sha2_256(hash_data, hash_src, sizeof(hash_src));

	Copy(&ret, hash_data, sizeof(ret));

	return ret;
}
