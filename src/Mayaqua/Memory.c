// SoftEther VPN Source Code - Developer Edition Master Branch
// Mayaqua Kernel


// Memory.c
// Memory management program

#include "Memory.h"

#include "Encoding.h"
#include "Encrypt.h"
#include "FileIO.h"
#include "Internat.h"
#include "Kernel.h"
#include "Mayaqua.h"
#include "Object.h"
#include "OS.h"
#include "Str.h"
#include "Tick64.h"
#include "Tracking.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

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

#define	MEMORY_SLEEP_TIME		150
#define	MEMORY_MAX_RETRY		30
#define	INIT_BUF_SIZE			10240

#define	FIFO_INIT_MEM_SIZE		4096
#define	FIFO_REALLOC_MEM_SIZE	(65536 * 10)	// Tuned value

#define	INIT_NUM_RESERVED		32

static UINT fifo_current_realloc_mem_size = FIFO_REALLOC_MEM_SIZE;

static bool canary_inited = false;
typedef struct CANARY_RAND_DATA
{
	UCHAR Data[CANARY_RAND_SIZE + 4];
} CANARY_RAND_DATA;

static CANARY_RAND_DATA canary_rand_data[NUM_CANARY_RAND] = { 0 };

static UINT64 canary_memtag_magic1 = 0;
static UINT64 canary_memtag_magic2 = 0;

UCHAR *GetCanaryRand(UINT id)
{
	if (id >= NUM_CANARY_RAND)
	{
		id = NUM_CANARY_RAND - 1;
	}

	return &((canary_rand_data[id].Data)[0]);
}

void InitCanaryRand()
{
	SYSTEMTIME st = { 0 };
	char random_seed[1024] = { 0 };
	UINT64 t1 = 0, t2 = 0;
	if (canary_inited)
	{
		return;
	}

#ifdef OS_WIN32
	Win32GetSystemTime(&st);
	memcpy(&t1, ((UCHAR *)&st) + 0, 8);
	memcpy(&t2, ((UCHAR *)&st) + 8, 8);
#endif

	{
		UINT64 dos_rand = (UINT64)rand();
		UINT64 tick1 = TickHighresNano64(true);
		UINT64 tick2 = TickHighresNano64(true);

		UINT i;

		void *p1 = malloc(1);
		void *p2 = malloc(1);

		for (i = 0;i < NUM_CANARY_RAND;i++)
		{
			// using sprintf() here is safe.
			sprintf(random_seed,
				"%u "
				"%llu "
				"%llu "
				"%llu "
				"%llu "
				"%llu "
				"%llu "
				"%llu "
				"%llu "
				"%llu "
				"%llu "
				"%llu "
				"%u "
				,
				i,
				(UINT64)InitCanaryRand,
				(UINT64)&canary_inited,
				(UINT64) & ((canary_rand_data[0].Data)[0]),
				(UINT64)&random_seed[0],
				tick1,
				tick2,
				dos_rand,
				(UINT64)p1,
				(UINT64)p2,
				t1,
				t2,
				~i
			);

			Sha0(canary_rand_data[i].Data, random_seed, (UINT)strlen(random_seed));
		}

		free(p1);
		free(p2);

		canary_memtag_magic1 = *((UINT64 *)(GetCanaryRand(CANARY_RAND_ID_MEMTAG_MAGIC) + 0));
		canary_memtag_magic2 = *((UINT64 *)(GetCanaryRand(CANARY_RAND_ID_MEMTAG_MAGIC) + 8));

		canary_inited = true;
	}
}

bool IsInHashListKey(HASH_LIST *h, UINT key)
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

void *HashListKeyToPointer(HASH_LIST *h, UINT key)
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

void **HashListToArray(HASH_LIST *h, UINT *num)
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

	if (h->AllList != NULL)
	{
		*num = LIST_NUM(h->AllList);

		return ToArray(h->AllList);
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

void *SearchHash(HASH_LIST *h, void *t)
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

	if (ret)
	{
		if (h->AllList != NULL)
		{
			Delete(h->AllList, p);
		}
	}

	return ret;
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

	if (h->AllList != NULL)
	{
		Add(h->AllList, p);
	}

	h->NumItems++;
}

UINT CalcHashForHashList(HASH_LIST *h, void *p)
{
	UINT r;
	if (h == NULL || p == NULL)
	{
		return 0;
	}

	r = h->GetHashProc(p);

	return (r % h->Size);
}

HASH_LIST *NewHashList(GET_HASH *get_hash_proc, COMPARE *compare_proc, UINT bits, bool make_list)
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

	h->Size = Power(2, bits);

	h->Lock = NewLock();
	h->Ref = NewRef();

	h->Entries = ZeroMalloc(sizeof(LIST *) * h->Size);

	h->GetHashProc = get_hash_proc;
	h->CompareProc = compare_proc;

	if (make_list)
	{
		h->AllList = NewListFast(NULL);
	}

	return h;
}

void ReleaseHashList(HASH_LIST *h)
{
	if (h == NULL)
	{
		return;
	}

	if (Release(h->Ref) == 0)
	{
		CleanupHashList(h);
	}
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

	if (h->AllList != NULL)
	{
		ReleaseList(h->AllList);
	}

	Free(h);
}

void AppendBufStr(BUF *b, char *str)
{
	if (b == NULL || str == NULL)
	{
		return;
	}

	WriteBuf(b, str, StrLen(str));
}

void AppendBufUtf8(BUF *b, wchar_t *str)
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

UINT Power(UINT a, UINT b)
{
	UINT ret, i;
	if (a == 0)
	{
		return 0;
	}
	if (b == 0)
	{
		return 1;
	}

	ret = 1;
	for (i = 0;i < b;i++)
	{
		ret *= a;
	}

	return ret;
}

UINT SearchBin(void *data, UINT data_start, UINT data_size, void *key, UINT key_size)
{
	UINT i;
	if (data == NULL || key == NULL || key_size == 0 || data_size == 0 ||
		(data_start >= data_size) || (data_start + key_size > data_size))
	{
		return INFINITE;
	}

	for (i = data_start;i < (data_size - key_size + 1);i++)
	{
		UCHAR *p = ((UCHAR *)data) + i;

		if (Cmp(p, key, key_size) == 0)
		{
			return i;
		}
	}

	return INFINITE;
}

void CrashNow()
{
	while (true)
	{
		UINT r = Rand32();
		UCHAR *c = (UCHAR *)r;

		*c = Rand8();
	}
}

bool IsZero(void *data, UINT size)
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
	return CompressEx(dst, dst_size, src, src_size, Z_DEFAULT_COMPRESSION);
}

UINT CompressEx(void *dst, UINT dst_size, void *src, UINT src_size, UINT level)
{
	unsigned long dst_size_long = dst_size;
	if (dst == NULL || dst_size_long == 0 || src == NULL)
	{
		return 0;
	}

	if (compress2(dst, &dst_size_long, src, src_size, (int)level) != Z_OK)
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
	return NewSkEx(false);
}
SK *NewSkEx(bool no_compact)
{
	SK *s;

	s = Malloc(sizeof(SK));
	s->lock = NewLock();
	s->ref = NewRef();
	s->num_item = 0;
	s->num_reserved = INIT_NUM_RESERVED;
	s->p = Malloc(sizeof(void *) * s->num_reserved);
	s->no_compact = no_compact;

	KS_INC(KS_NEWSK_COUNT);

	return s;
}

void ReleaseSk(SK *s)
{
	if (s == NULL)
	{
		return;
	}

	if (Release(s->ref) == 0)
	{
		CleanupSk(s);
	}
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

	if (s->no_compact == false)
	{
		if ((s->num_item * 2) <= s->num_reserved)
		{
			if (s->num_reserved >= (INIT_NUM_RESERVED * 2))
			{
				s->num_reserved = s->num_reserved / 2;
				s->p = ReAlloc(s->p, sizeof(void *) * s->num_reserved);
			}
		}
	}

	KS_INC(KS_POP_COUNT);

	return ret;
}

UINT GetQueueNum(QUEUE *q)
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

	ReadFifo(q->fifo, &p, sizeof(void *));
	q->num_item--;

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

	WriteFifo(q->fifo, &p, sizeof(void *));

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

	if (q->ref == NULL || Release(q->ref) == 0)
	{
		CleanupQueue(q);
	}
}

void CleanupQueue(QUEUE *q)
{
	if (q == NULL)
	{
		return;
	}

	ReleaseFifo(q->fifo);
	DeleteLock(q->lock);
	Free(q);

	KS_INC(KS_FREEQUEUE_COUNT);
}

QUEUE *NewQueue()
{
	QUEUE *q;

	q = ZeroMalloc(sizeof(QUEUE));
	q->lock = NewLock();
	q->ref = NewRef();
	q->num_item = 0;
	q->fifo = NewFifo();

	KS_INC(KS_NEWQUEUE_COUNT);

	return q;
}
QUEUE *NewQueueFast()
{
	QUEUE *q;

	q = ZeroMalloc(sizeof(QUEUE));
	q->lock = NULL;
	q->ref = NULL;
	q->num_item = 0;
	q->fifo = NewFifoFast();

	KS_INC(KS_NEWQUEUE_COUNT);

	return q;
}

void CopyToArray(LIST *o, void *p)
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
		p = MallocFast(sizeof(void *) * LIST_NUM(o));
	}
	CopyToArray(o, p);

	return p;
}

void *Search(LIST *o, void *target)
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
	int i;
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

	if (LIST_NUM(o) >= 2)
	{
		for (i = (LIST_NUM(o) - 2);i >= (int)pos;i--)
		{
			o->p[i + 1] = o->p[i];
		}
	}

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

bool ReplaceListPointer(LIST *o, void *oldptr, void *newptr)
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

bool IsInList(LIST *o, void *p)
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

bool Delete(LIST *o, void *p)
{
	UINT i, n;
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

	n = i;
	for (i = n;i < (o->num_item - 1);i++)
	{
		o->p[i] = o->p[i + 1];
	}
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

	if (o->ref == NULL || Release(o->ref) == 0)
	{
		CleanupList(o);
	}
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

void ReleaseIntList(LIST *o)
{
	UINT i;
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		UINT *p = LIST_DATA(o, i);

		Free(p);
	}

	ReleaseList(o);
}
void ReleaseInt64List(LIST *o)
{
	UINT i;
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		UINT64 *p = LIST_DATA(o, i);

		Free(p);
	}

	ReleaseList(o);
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

LIST *NewIntList(bool sorted)
{
	LIST *o = NewList(sorted ? CompareInt : NULL);

	return o;
}
LIST *NewInt64List(bool sorted)
{
	LIST *o = NewList(sorted ? CompareInt64 : NULL);

	return o;
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

void AddInt(LIST *o, UINT i)
{
	if (o == NULL)
	{
		return;
	}

	Add(o, Clone(&i, sizeof(UINT)));
}
void AddInt64(LIST *o, UINT64 i)
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
	return NewListEx2(cmp, true, false);
}

LIST *NewList(COMPARE *cmp)
{
	return NewListEx2(cmp, false, false);
}
LIST *NewListEx2(COMPARE *cmp, bool fast, bool fast_malloc)
{
	LIST *o;

	if (fast_malloc == false)
	{
		o = Malloc(sizeof(LIST));
	}
	else
	{
		o = MallocFast(sizeof(LIST));
	}

	if (fast == false)
	{
		o->lock = NewLock();
		o->ref = NewRef();
	}
	else
	{
		o->lock = NULL;
		o->ref = NULL;
	}
	o->num_item = 0;
	o->num_reserved = INIT_NUM_RESERVED;
	o->Param1 = 0;

	if (fast_malloc == false)
	{
		o->p = Malloc(sizeof(void *) * o->num_reserved);
	}
	else
	{
		o->p = MallocFast(sizeof(void *) * o->num_reserved);
	}

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

	f->total_read_size += (UINT64)read_size;

	if (f->fixed == false)
	{
		if (f->size == 0)
		{
			f->pos = 0;
		}
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

	if (f->fixed)
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

void WriteFifo(FIFO *f, void *p, UINT size)
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

	f->total_write_size += (UINT64)size;

	KS_INC(KS_WRITE_FIFO_COUNT);
}

UINT FifoSize(FIFO *f)
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

	if (f->ref == NULL || Release(f->ref) == 0)
	{
		CleanupFifo(f);
	}
}

void CleanupFifo(FIFO *f)
{
	if (f == NULL)
	{
		return;
	}

	DeleteLock(f->lock);
	Free(f->p);
	Free(f);

	KS_INC(KS_FREEFIFO_COUNT);
}

void InitFifo()
{
	fifo_current_realloc_mem_size = FIFO_REALLOC_MEM_SIZE;
}

FIFO *NewFifo()
{
	return NewFifoEx2(false, false);
}
FIFO *NewFifoFast()
{
	return NewFifoEx2(true, false);
}
FIFO *NewFifoEx2(bool fast, bool fixed)
{
	FIFO *f;

	f = ZeroMalloc(sizeof(FIFO));

	if (fast == false)
	{
		f->lock = NewLock();
		f->ref = NewRef();
	}
	else
	{
		f->lock = NULL;
		f->ref = NULL;
	}

	f->size = f->pos = 0;
	f->memsize = FIFO_INIT_MEM_SIZE;
	f->p = Malloc(FIFO_INIT_MEM_SIZE);
	f->fixed = false;

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

BUF *ReadDump(char *filename)
{
	return ReadDumpWithMaxSize(filename, 0);
}
BUF *ReadDumpWithMaxSize(char *filename, UINT max_size)
{
	IO *o;
	BUF *b;
	UINT size;
	void *data;
	if (filename == NULL)
	{
		return NULL;
	}

	o = FileOpen(filename, false);
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
	FileRead(o, data, size);
	FileClose(o);

	b = NewBuf();
	WriteBuf(b, data, size);
	b->Current = 0;
	Free(data);

	return b;
}
BUF *ReadDumpW(wchar_t *filename)
{
	return ReadDumpExW(filename, true);
}
BUF *ReadDumpExW(wchar_t *filename, bool read_lock)
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
	data = Malloc(size);
	FileRead(o, data, size);
	FileClose(o);

	b = NewBuf();
	WriteBuf(b, data, size);
	b->Current = 0;
	Free(data);

	return b;
}

bool DumpDataW(void *data, UINT size, wchar_t *filename)
{
	IO *o;
	if (filename == NULL || (size != 0 && data == NULL))
	{
		return false;
	}

	o = FileCreateW(filename);
	if (o == NULL)
	{
		return false;
	}
	FileWrite(o, data, size);
	FileClose(o);

	return true;
}

bool DumpBuf(BUF *b, char *filename)
{
	IO *o;
	if (b == NULL || filename == NULL)
	{
		return false;
	}

	o = FileCreate(filename);
	if (o == NULL)
	{
		return false;
	}
	FileWrite(o, b->Buf, b->Size);
	FileClose(o);

	return true;
}
bool DumpBufW(BUF *b, wchar_t *filename)
{
	IO *o;
	if (b == NULL || filename == NULL)
	{
		return false;
	}

	o = FileCreateW(filename);
	if (o == NULL)
	{
		return false;
	}
	FileWrite(o, b->Buf, b->Size);
	FileClose(o);

	return true;
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

bool BufToFile(IO *o, BUF *b)
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

BUF *NewBufFromMemory(void *buf, UINT size)
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

void WriteBuf(BUF *b, void *buf, UINT size)
{
	UINT new_size;
	if (b == NULL || buf == NULL || size == 0)
	{
		return;
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
	b->Size = new_size;

	KS_INC(KS_WRITE_BUF_COUNT);
}

bool WriteBufStr(BUF *b, char *str)
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
	if (read_size < len)
	{
		ReadBuf(b, NULL, len - read_size);
	}
	str[read_size] = 0;

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

void WriteBufBuf(BUF *b, BUF *bb)
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
	if ((b->Current + size) >= b->Size)
	{
		size_read = b->Size - b->Current;
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

bool CompareBuf(BUF *b1, BUF *b2)
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

BUF *MemToBuf(void *data, UINT size)
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

USHORT Endian16(USHORT src)
{
	int x = 1;
	if (*((char *)&x))
	{
		return Swap16(src);
	}
	else
	{
		return src;
	}
}

UINT Endian32(UINT src)
{
	int x = 1;
	if (*((char *)&x))
	{
		return Swap32(src);
	}
	else
	{
		return src;
	}
}

UINT64 Endian64(UINT64 src)
{
	int x = 1;
	if (*((char *)&x))
	{
		return Swap64(src);
	}
	else
	{
		return src;
	}
}

UINT LittleEndian32(UINT src)
{
	int x = 0x01000000;
	if (*((char *)&x))
	{
		return Swap32(src);
	}
	else
	{
		return src;
	}
}

USHORT Swap16(USHORT value)
{
	USHORT r;
	((BYTE *)&r)[0] = ((BYTE *)&value)[1];
	((BYTE *)&r)[1] = ((BYTE *)&value)[0];
	return r;
}

UINT Swap32(UINT value)
{
	UINT r;
	((BYTE *)&r)[0] = ((BYTE *)&value)[3];
	((BYTE *)&r)[1] = ((BYTE *)&value)[2];
	((BYTE *)&r)[2] = ((BYTE *)&value)[1];
	((BYTE *)&r)[3] = ((BYTE *)&value)[0];
	return r;
}

UINT64 Swap64(UINT64 value)
{
	UINT64 r;
	((BYTE *)&r)[0] = ((BYTE *)&value)[7];
	((BYTE *)&r)[1] = ((BYTE *)&value)[6];
	((BYTE *)&r)[2] = ((BYTE *)&value)[5];
	((BYTE *)&r)[3] = ((BYTE *)&value)[4];
	((BYTE *)&r)[4] = ((BYTE *)&value)[3];
	((BYTE *)&r)[5] = ((BYTE *)&value)[2];
	((BYTE *)&r)[6] = ((BYTE *)&value)[1];
	((BYTE *)&r)[7] = ((BYTE *)&value)[0];
	return r;
}

void *Base64ToBin(UINT *out_size, const void *src, const UINT size)
{
	if (src == NULL || size == 0)
	{
		return NULL;
	}

	UINT bin_size = Base64Decode(NULL, src, size);
	if (bin_size == 0)
	{
		return NULL;
	}

	void *bin = ZeroMalloc(bin_size + 1);
	bin_size = Base64Decode(bin, src, size);
	if (bin_size == 0)
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
	if (src == NULL || size == 0)
	{
		return NULL;
	}

	UINT base64_size = Base64Encode(NULL, src, size);
	if (base64_size == 0)
	{
		return NULL;
	}

	void *base64 = Malloc(base64_size);
	base64_size = Base64Encode(base64, src, size);
	if (base64_size == 0)
	{
		Free(base64);
		return NULL;
	}

	if (out_size != NULL)
	{
		*out_size = base64_size;
	}

	return base64;
}

void *Malloc(UINT size)
{
	return MallocEx(size, false);
}
void *MallocEx(UINT size, bool zero_clear_when_free)
{
	MEMTAG1 *tag1;
	MEMTAG2 *tag2;
	UINT real_size;

	if (canary_inited == false)
	{
		InitCanaryRand();
	}

	if (size > MAX_MALLOC_MEM_SIZE)
	{
		AbortExitEx("MallocEx() error: too large size");
	}

	real_size = CALC_MALLOCSIZE(size);

	tag1 = InternalMalloc(real_size);

	tag1->Magic = canary_memtag_magic1 ^ ((UINT64)tag1 * GOLDEN_RATION_PRIME_U64);
	tag1->Size = size;
	tag1->ZeroFree = zero_clear_when_free;

	tag2 = (MEMTAG2 *)(((UCHAR *)tag1) + CALC_MALLOCSIZE(tag1->Size) - sizeof(MEMTAG2));
	tag2->Magic = canary_memtag_magic2 ^ ((UINT64)tag2 * GOLDEN_RATION_PRIME_U64);
	MEMTAG_POISON(tag1);

	return MEMTAG1_TO_POINTER(tag1);
}

void *ReAlloc(void *addr, UINT size)
{
	MEMTAG1 *tag1;
	MEMTAG2 *tag2;
	bool zerofree;

	if (canary_inited == false)
	{
		InitCanaryRand();
	}

	if (size > MAX_MALLOC_MEM_SIZE)
	{
		AbortExitEx("ReAlloc() error: too large size");
	}

	if (IS_NULL_POINTER(addr))
	{
		return NULL;
	}

	tag1 = POINTER_TO_MEMTAG1(addr);
	CheckMemTag1(tag1);
	MEMTAG_UNPOISON(tag1);

	tag2 = (MEMTAG2 *)(((UCHAR *)tag1) + CALC_MALLOCSIZE(tag1->Size) - sizeof(MEMTAG2));
	CheckMemTag2(tag2);

	zerofree = tag1->ZeroFree;

	if (tag1->Size == size)
	{
		MEMTAG_POISON(tag1);
		return addr;
	}
	else
	{
		if (zerofree)
		{
			// Zero-free block: copy to a new block so the old one is zeroed on Free
			void *new_p = MallocEx(size, true);

			if (tag1->Size <= size)
			{
				Copy(new_p, addr, tag1->Size);
			}
			else
			{
				Copy(new_p, addr, size);
			}

			Free(addr);

			return new_p;
		}
		else
		{
			MEMTAG1 *tag1_new;
			MEMTAG2 *tag2_new;

			tag1->Magic = 0;
			tag2->Magic = 0;

			tag1_new = InternalReAlloc(tag1, CALC_MALLOCSIZE(size));

			tag1_new->Magic = canary_memtag_magic1 ^ ((UINT64)tag1_new * GOLDEN_RATION_PRIME_U64);
			tag1_new->Size = size;
			tag1_new->ZeroFree = 0;

			tag2_new = (MEMTAG2 *)(((UCHAR *)tag1_new) + CALC_MALLOCSIZE(size) - sizeof(MEMTAG2));
			tag2_new->Magic = canary_memtag_magic2 ^ ((UINT64)tag2_new * GOLDEN_RATION_PRIME_U64);
			MEMTAG_POISON(tag1_new);

			return MEMTAG1_TO_POINTER(tag1_new);
		}
	}
}

void Free(void *addr)
{
	MEMTAG1 *tag1;
	MEMTAG2 *tag2;
	if (IS_NULL_POINTER(addr))
	{
		return;
	}

	if (canary_inited == false)
	{
		InitCanaryRand();
	}

	tag1 = POINTER_TO_MEMTAG1(addr);
	CheckMemTag1(tag1);
	MEMTAG_UNPOISON(tag1);

	tag2 = (MEMTAG2 *)(((UCHAR *)tag1) + CALC_MALLOCSIZE(tag1->Size) - sizeof(MEMTAG2));
	CheckMemTag2(tag2);

	if (tag1->ZeroFree)
	{
		Zero(addr, tag1->Size);
	}

	tag1->Magic = 0;
	tag2->Magic = 0;
	InternalFree(tag1);
}

void FreeSafe(void **addr)
{
	Free(*addr);
	*addr = NULL;
}

void CheckMemTag1(MEMTAG1 *tag)
{
	if (tag == NULL)
	{
		AbortExitEx("CheckMemTag1: tag1 == NULL");
		return;
	}

	if (tag->Magic != (canary_memtag_magic1 ^ ((UINT64)tag * GOLDEN_RATION_PRIME_U64)))
	{
		AbortExitEx("CheckMemTag1: tag1->Magic != canary_memtag_magic1");
		return;
	}
}

void CheckMemTag2(MEMTAG2 *tag)
{
	if (tag == NULL)
	{
		AbortExitEx("CheckMemTag2: tag2 == NULL");
		return;
	}

	if (tag->Magic != (canary_memtag_magic2 ^ ((UINT64)tag * GOLDEN_RATION_PRIME_U64)))
	{
		AbortExitEx("CheckMemTag2: tag2->Magic != canary_memtag_magic2");
		return;
	}
}

void *ZeroMalloc(UINT size)
{
	return ZeroMallocEx(size, false);
}
void *ZeroMallocEx(UINT size, bool zero_clear_when_free)
{
	void *p = MallocEx(size, zero_clear_when_free);
	Zero(p, size);
	return p;
}

void *InternalMalloc(UINT size)
{
	void *addr;
	UINT retry = 0;
	size = MORE(size, 1);

	KS_INC(KS_MALLOC_COUNT);
	KS_INC(KS_TOTAL_MEM_COUNT);
	KS_ADD(KS_TOTAL_MEM_SIZE, size);
	KS_INC(KS_CURRENT_MEM_COUNT);

	while (true)
	{
		if ((retry++) > MEMORY_MAX_RETRY)
		{
			AbortExitEx("InternalMalloc: error: malloc() failed.\n\n");
		}
		addr = OSMemoryAlloc(size);
		if (addr != NULL)
		{
			break;
		}

		OSSleep(MEMORY_SLEEP_TIME);
	}

	TrackNewObj(POINTER_TO_UINT64(addr), "MEM", size);

	return addr;
}

void InternalFree(void *addr)
{
	if (addr == NULL)
	{
		return;
	}

	KS_DEC(KS_CURRENT_MEM_COUNT);
	KS_INC(KS_FREE_COUNT);

	TrackDeleteObj(POINTER_TO_UINT64(addr));

	OSMemoryFree(addr);
}

void *InternalReAlloc(void *addr, UINT size)
{
	void *new_addr;
	UINT retry = 0;
	size = MORE(size, 1);

	KS_INC(KS_REALLOC_COUNT);
	KS_ADD(KS_TOTAL_MEM_SIZE, size);

	while (true)
	{
		if ((retry++) > MEMORY_MAX_RETRY)
		{
			AbortExitEx("InternalReAlloc: error: realloc() failed.\n\n");
		}
		new_addr = OSMemoryReAlloc(addr, size);
		if (new_addr != NULL)
		{
			break;
		}

		OSSleep(MEMORY_SLEEP_TIME);
	}

	TrackChangeObjSize(POINTER_TO_UINT64(addr), size, POINTER_TO_UINT64(new_addr));

	return new_addr;
}

void *Clone(void *addr, UINT size)
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

void Copy(void *dst, void *src, UINT size)
{
	if (dst == NULL || src == NULL || size == 0 || dst == src)
	{
		return;
	}

	KS_INC(KS_COPY_COUNT);

	memcpy(dst, src, size);
}

void Move(void *dst, void *src, UINT size)
{
	if (dst == NULL || src == NULL || size == 0 || dst == src)
	{
		return;
	}

	KS_INC(KS_COPY_COUNT);

	memmove(dst, src, size);
}

int Cmp(void *p1, void *p2, UINT size)
{
	if (p1 == NULL || p2 == NULL || size == 0)
	{
		return 0;
	}

	return memcmp(p1, p2, (size_t)size);
}

int CmpCaseIgnore(void *p1, void *p2, UINT size)
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
