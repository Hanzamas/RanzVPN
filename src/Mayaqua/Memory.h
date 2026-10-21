// Memory.h
// Header of Memory.c

#ifndef	MEMORY_H
#define	MEMORY_H

#include "MayaType.h"

#define MAX_MALLOC_MEM_SIZE					(0xffffffff - 64)

// Memory size that can be passed to the kernel at a time
#define	MAX_SEND_BUF_MEM_SIZE				(10 * 1024 * 1024)

#define	CALC_MALLOCSIZE(size)				(((MAX(size, 1) + 7) / 8) * 8 + sizeof(MEMTAG1) + sizeof(MEMTAG2))
#define	MEMTAG1_TO_POINTER(p)				((void *)(((UCHAR *)(p)) + sizeof(MEMTAG1)))
#define	POINTER_TO_MEMTAG1(p)				((MEMTAG1 *)(((UCHAR *)(p)) - sizeof(MEMTAG1)))
#define	IS_NULL_POINTER(p)					(((p) == NULL) || ((POINTER_TO_UINT64(p) == (UINT64)sizeof(MEMTAG1))))
#define	PTR_TO_PTR(p)						((void **)(&p))

// Golden ratio prime, from
// From https://github.com/torvalds/linux/blob/88c5083442454e5e8a505b11fa16f32d2879651e/include/linux/hash.h
#define GOLDEN_RATION_PRIME_U64				((UINT64)7046029254386353131ULL) // 0x61C8864680B583EB


struct MEMTAG1
{
	UINT64 Magic;
	UINT Size;
	bool ZeroFree;
};

struct MEMTAG2
{
	UINT64 Magic;
};

struct BUF
{
	void *Buf;
	UINT Size;
	UINT SizeReserved;
	UINT Current;
};

struct FIFO
{
	void *p;
	UINT pos, size, memsize;
};

struct LIST
{
	UINT num_item, num_reserved;
	void **p;
	LOCK *lock;
	COMPARE *cmp;
	bool sorted;
	UINT64 Param1;
};

// A ring of num_reserved slots (a power of two): the oldest of the num_item items is at p[head]
struct QUEUE
{
	UINT num_item;
	UINT head, num_reserved;
	void **p;
	LOCK *lock;
};

struct SK
{
	UINT num_item, num_reserved;
	void **p;
	LOCK *lock;
};

#define	LIST_DATA(o, i)		(((o) != NULL) ? ((o)->p[(i)]) : NULL)
#define	LIST_NUM(o)			(((o) != NULL) ? (o)->num_item : 0)
#define	HASH_LIST_NUM(o)	(((o) != NULL) ? (o)->NumItems : 0)

typedef UINT (GET_HASH)(void *p);
typedef bool (HASH_LIST_TAKE_PROC)(void *p, void *param);

struct HASH_LIST
{
	UINT Size;
	GET_HASH *GetHashProc;
	COMPARE *CompareProc;
	LOCK *Lock;
	LIST **Entries;
	UINT NumItems;
};

HASH_LIST *NewHashList(GET_HASH *get_hash_proc, COMPARE *compare_proc, UINT bits);
void ReleaseHashList(HASH_LIST *h);
void AddHash(HASH_LIST *h, void *p);
bool DeleteHash(HASH_LIST *h, void *p);
UINT DeleteHashIf(HASH_LIST *h, HASH_LIST_TAKE_PROC *proc, void *param);
void *SearchHash(const HASH_LIST *h, void *t);
void **HashListToArray(const HASH_LIST *h, UINT *num);
void LockHashList(HASH_LIST *h);
void UnlockHashList(HASH_LIST *h);
bool IsInHashListKey(const HASH_LIST *h, UINT key);
void *HashListKeyToPointer(const HASH_LIST *h, UINT key);

void *Malloc(UINT size);
void *MallocEx(UINT size, bool zero_clear_when_free);
void *ZeroMalloc(UINT size);
void *ZeroMallocEx(UINT size, bool zero_clear_when_free);
void *ReAlloc(void *addr, UINT size);
void Free(void *addr);
void FreeSafe(void **addr);

void Copy(void *dst, const void *src, UINT size);
void Move(void *dst, const void *src, UINT size);
int Cmp(const void *p1, const void *p2, UINT size);
int CmpCaseIgnore(const void *p1, const void *p2, UINT size);
void Zero(void *addr, UINT size);
void *Clone(const void *addr, UINT size);

void *Base64FromBin(UINT *out_size, const void *src, const UINT size);
void *Base64ToBin(UINT *out_size, const void *src, const UINT size);

void EndianUnicode(wchar_t *str);

BUF *NewBuf();
BUF *NewBufFromMemory(const void *buf, UINT size);
void ClearBuf(BUF *b);
void WriteBuf(BUF *b, const void *buf, UINT size);
void WriteBufBuf(BUF *b, const BUF *bb);
UINT ReadBuf(BUF *b, void *buf, UINT size);
UINT ReadBufRemainSize(const BUF *b);
void AdjustBufSize(BUF *b, UINT new_size);
void SeekBuf(BUF *b, UINT offset, int mode);
void SeekBufToEnd(BUF *b);
void SeekBufToBegin(BUF *b);
void FreeBuf(BUF *b);
UINT ReadBufInt(BUF *b);
UINT64 ReadBufInt64(BUF *b);
bool WriteBufInt(BUF *b, UINT value);
bool WriteBufInt64(BUF *b, UINT64 value);
bool WriteBufChar(BUF *b, UCHAR uc);
bool ReadBufStr(BUF *b, char *str, UINT size);
bool WriteBufStr(BUF *b, const char *str);
bool DumpBuf(BUF *b, const char *filename);
bool DumpBufW(BUF *b, wchar_t *filename);
bool DumpBufWIfNecessary(BUF *b, wchar_t *filename);
bool DumpDataW(void *data, UINT size, wchar_t *filename);
BUF *ReadDump(const char *filename);
BUF *ReadDumpWithMaxSize(const char *filename, UINT max_size);
BUF *ReadDumpW(wchar_t *filename);
BUF *ReadDumpExW(wchar_t *filename, bool read_lock, UINT max_size);
BUF *MemToBuf(const void *data, UINT size);
bool CompareBuf(const BUF *b1, const BUF *b2);

UINT ReadFifo(FIFO *f, void *p, UINT size);
void ShrinkFifoMemory(FIFO *f);
void WriteFifo(FIFO *f, const void *p, UINT size);
UINT FifoSize(const FIFO *f);
void ReleaseFifo(FIFO *f);
FIFO *NewFifo();
void SetFifoCurrentReallocMemSize(UINT size);

void *Search(LIST *o, const void *target);
void Sort(LIST *o);
void Add(LIST *o, void *p);
void Insert(LIST *o, void *p);
bool Delete(LIST *o, const void *p);
UINT DeleteAndFreeIf(LIST *o, bool (*is_dead)(void *p, void *param), void *param);
void DeleteAll(LIST *o);
void LockList(LIST *o);
void UnlockList(LIST *o);
void ReleaseList(LIST *o);
LIST *NewList(COMPARE *cmp);
LIST *NewListFast(COMPARE *cmp);
void *ToArray(LIST *o);
void *ToArrayEx(LIST *o, bool fast);
int CompareStr(void *p1, void *p2);
bool InsertStr(LIST *o, char *str);
bool IsInList(LIST *o, const void *p);
bool IsInListKey(LIST *o, UINT key);
void *ListKeyToPointer(LIST *o, UINT key);
void AddIntDistinct(LIST *o, UINT i);
void AddInt64Distinct(LIST *o, UINT64 i);
void DelInt(LIST *o, UINT i);
void FreeListItems(LIST *o);
void ReleaseIntList(LIST *o);
void ReleaseInt64List(LIST *o);
bool IsIntInList(LIST *o, UINT i);
bool IsInt64InList(LIST *o, UINT64 i);
LIST *NewIntList();
LIST *NewInt64List();

void *GetNext(QUEUE *q);
void InsertQueue(QUEUE *q, void *p);
void LockQueue(QUEUE *q);
void UnlockQueue(QUEUE *q);
void ReleaseQueue(QUEUE *q);
QUEUE *NewQueue();
QUEUE *NewQueueFast();
UINT GetQueueNum(const QUEUE *q);

SK *NewSk();
void ReleaseSk(SK *s);
void Push(SK *s, void *p);
void *Pop(SK *s);

UINT Uncompress(void *dst, UINT dst_size, void *src, UINT src_size);
UINT Compress(void *dst, UINT dst_size, void *src, UINT src_size);
UINT CalcCompress(UINT src_size);

bool IsZero(const void *data, UINT size);

UINT SearchBin(const void *data, UINT data_size, const void *key, UINT key_size);
void CrashNow();

void AppendBufUtf8(BUF *b, const wchar_t *str);
void AppendBufStr(BUF *b, const char *str);

#define NUM_CANARY_RAND					2
#define CANARY_RAND_ID_MEMTAG_MAGIC		0
#define CANARY_RAND_SIZE				20

#define CANARY_RAND_ID_PTR_KEY_HASH		1

void InitCanaryRand();

#endif

