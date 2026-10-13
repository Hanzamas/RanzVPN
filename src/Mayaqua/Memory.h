// SoftEther VPN Source Code - Developer Edition Master Branch
// Mayaqua Kernel


// Memory.h
// Header of Memory.c

#ifndef	MEMORY_H
#define	MEMORY_H

#include "MayaType.h"

// MallocFast (not implemented)
#define	MallocFast		Malloc
#define	ZeroMallocFast	ZeroMalloc

#define MAX_MALLOC_MEM_SIZE					(0xffffffff - 64)

// Memory size that can be passed to the kernel at a time
#define	MAX_SEND_BUF_MEM_SIZE				(10 * 1024 * 1024)

#define	CALC_MALLOCSIZE(size)				(((MAX(size, 1) + 7) / 8) * 8 + sizeof(MEMTAG1) + sizeof(MEMTAG2))
#define	MEMTAG1_TO_POINTER(p)				((void *)(((UCHAR *)(p)) + sizeof(MEMTAG1)))
#define	POINTER_TO_MEMTAG1(p)				((MEMTAG1 *)(((UCHAR *)(p)) - sizeof(MEMTAG1)))
#define	IS_NULL_POINTER(p)					(((p) == NULL) || ((POINTER_TO_UINT64(p) == (UINT64)sizeof(MEMTAG1))))
#define	PTR_TO_PTR(p)						((void **)(&p))

// Golden Ratio Prime
// From https://github.com/torvalds/linux/blob/88c5083442454e5e8a505b11fa16f32d2879651e/include/linux/hash.h
#define GOLDEN_RATION_PRIME_U32				((UINT32)0x61C88647)
#define GOLDEN_RATION_PRIME_U64				((UINT64)7046029254386353131ULL) // 0x61C8864680B583EB

// Fixed size of a block of memory pool
#define	MEMPOOL_MAX_SIZE					3000


// Memory tag 1
struct MEMTAG1
{
	UINT64 Magic;
	UINT Size;
	bool ZeroFree;
};

// Memory tag 2
struct MEMTAG2
{
	UINT64 Magic;
};

// Buffer
struct BUF
{
	void *Buf;
	UINT Size;
	UINT SizeReserved;
	UINT Current;
};

// FIFO
struct FIFO
{
	REF *ref;
	LOCK *lock;
	void *p;
	UINT pos, size, memsize;
	UINT64 total_read_size;
	UINT64 total_write_size;
	bool fixed;
};

// List
struct LIST
{
	REF *ref;
	UINT num_item, num_reserved;
	void **p;
	LOCK *lock;
	COMPARE *cmp;
	bool sorted;
	UINT64 Param1;
};

// Queue
struct QUEUE
{
	REF *ref;
	UINT num_item;
	FIFO *fifo;
	LOCK *lock;
};

// Stack
struct SK
{
	REF *ref;
	UINT num_item, num_reserved;
	void **p;
	LOCK *lock;
	bool no_compact;
};

// Candidate list
struct CANDIDATE
{
	wchar_t *Str;						// String
	UINT64 LastSelectedTime;			// Date and time last selected
};

struct STRMAP_ENTRY
{
	char *Name;
	void *Value;
};

// Shared buffer
struct SHARED_BUFFER
{
	REF *Ref;
	void *Data;
	UINT Size;
};

// Macro
#define	LIST_DATA(o, i)		(((o) != NULL) ? ((o)->p[(i)]) : NULL)
#define	LIST_NUM(o)			(((o) != NULL) ? (o)->num_item : 0)
#define	HASH_LIST_NUM(o)	(((o) != NULL) ? (o)->NumItems : 0)

// Function pointer type to get a hash function
typedef UINT (GET_HASH)(void *p);

// Hash list
struct HASH_LIST
{
	UINT Bits;
	UINT Size;
	GET_HASH *GetHashProc;
	COMPARE *CompareProc;
	LOCK *Lock;
	REF *Ref;
	LIST **Entries;
	UINT NumItems;
	LIST *AllList;
};

// PRAND
struct PRAND
{
	UCHAR Key[20];
	CRYPT *Rc4;
};

// Function prototype
HASH_LIST *NewHashList(GET_HASH *get_hash_proc, COMPARE *compare_proc, UINT bits, bool make_list);
void ReleaseHashList(HASH_LIST *h);
void AddHash(HASH_LIST *h, void *p);
bool DeleteHash(HASH_LIST *h, void *p);
void *SearchHash(HASH_LIST *h, void *t);
void **HashListToArray(HASH_LIST *h, UINT *num);
void LockHashList(HASH_LIST *h);
void UnlockHashList(HASH_LIST *h);
bool IsInHashListKey(HASH_LIST *h, UINT key);
void *HashListKeyToPointer(HASH_LIST *h, UINT key);

void *Malloc(UINT size);
void *MallocEx(UINT size, bool zero_clear_when_free);
void *ZeroMalloc(UINT size);
void *ZeroMallocEx(UINT size, bool zero_clear_when_free);
void *ReAlloc(void *addr, UINT size);
void Free(void *addr);
void FreeSafe(void **addr);

void Copy(void *dst, void *src, UINT size);
void Move(void *dst, void *src, UINT size);
int Cmp(void *p1, void *p2, UINT size);
int CmpCaseIgnore(void *p1, void *p2, UINT size);
void ZeroMem(void *addr, UINT size);
void Zero(void *addr, UINT size);
void *Clone(void *addr, UINT size);

void *Base64FromBin(UINT *out_size, const void *src, const UINT size);
void *Base64ToBin(UINT *out_size, const void *src, const UINT size);

USHORT Swap16(USHORT value);
UINT Swap32(UINT value);
USHORT Endian16(USHORT src);
UINT Endian32(UINT src);
UINT64 Endian64(UINT64 src);
UINT LittleEndian32(UINT src);
void EndianUnicode(wchar_t *str);

BUF *NewBuf();
BUF *NewBufFromMemory(void *buf, UINT size);
void ClearBuf(BUF *b);
void WriteBuf(BUF *b, void *buf, UINT size);
void WriteBufBuf(BUF *b, BUF *bb);
UINT ReadBuf(BUF *b, void *buf, UINT size);
void SeekBuf(BUF *b, UINT offset, int mode);
void SeekBufToEnd(BUF *b);
void SeekBufToBegin(BUF *b);
void FreeBuf(BUF *b);
bool BufToFile(IO *o, BUF *b);
BUF *FileToBuf(IO *o);
UINT ReadBufInt(BUF *b);
UINT64 ReadBufInt64(BUF *b);
UCHAR ReadBufChar(BUF *b);
bool WriteBufInt(BUF *b, UINT value);
bool WriteBufInt64(BUF *b, UINT64 value);
bool WriteBufChar(BUF *b, UCHAR uc);
bool ReadBufStr(BUF *b, char *str, UINT size);
bool WriteBufStr(BUF *b, char *str);
bool DumpBuf(BUF *b, char *filename);
bool DumpBufW(BUF *b, wchar_t *filename);
bool DumpBufWIfNecessary(BUF *b, wchar_t *filename);
bool DumpDataW(void *data, UINT size, wchar_t *filename);
BUF *ReadDump(char *filename);
BUF *ReadDumpWithMaxSize(char *filename, UINT max_size);
BUF *ReadDumpW(wchar_t *filename);
BUF *ReadDumpExW(wchar_t *filename, bool read_lock);
BUF *MemToBuf(void *data, UINT size);

UINT ReadFifo(FIFO *f, void *p, UINT size);
void ShrinkFifoMemory(FIFO *f);
void WriteFifo(FIFO *f, void *p, UINT size);
UINT FifoSize(FIFO *f);
void ReleaseFifo(FIFO *f);
FIFO *NewFifo();
void InitFifo();
void SetFifoCurrentReallocMemSize(UINT size);

void *Search(LIST *o, void *target);
void Sort(LIST *o);
void Add(LIST *o, void *p);
void Insert(LIST *o, void *p);
bool Delete(LIST *o, void *p);
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
bool IsInList(LIST *o, void *p);
bool IsInListKey(LIST *o, UINT key);
void *ListKeyToPointer(LIST *o, UINT key);
bool ReplaceListPointer(LIST *o, void *oldptr, void *newptr);
void AddIntDistinct(LIST *o, UINT i);
void AddInt64Distinct(LIST *o, UINT64 i);
void DelInt(LIST *o, UINT i);
void ReleaseIntList(LIST *o);
void ReleaseInt64List(LIST *o);
bool IsIntInList(LIST *o, UINT i);
bool IsInt64InList(LIST *o, UINT64 i);
LIST *NewIntList(bool sorted);
LIST *NewInt64List(bool sorted);

void *GetNext(QUEUE *q);
void InsertQueue(QUEUE *q, void *p);
void InsertQueueInt(QUEUE *q, UINT value);
void LockQueue(QUEUE *q);
void UnlockQueue(QUEUE *q);
void ReleaseQueue(QUEUE *q);
QUEUE *NewQueue();
QUEUE *NewQueueFast();
UINT GetQueueNum(QUEUE *q);

SK *NewSk();
void ReleaseSk(SK *s);
void LockSk(SK *s);
void UnlockSk(SK *s);
void Push(SK *s, void *p);
void *Pop(SK *s);

UINT Uncompress(void *dst, UINT dst_size, void *src, UINT src_size);
UINT Compress(void *dst, UINT dst_size, void *src, UINT src_size);
UINT CalcCompress(UINT src_size);

bool IsZero(void *data, UINT size);

UINT SearchBin(void *data, UINT data_start, UINT data_size, void *key, UINT key_size);
void CrashNow();

void AppendBufUtf8(BUF *b, wchar_t *str);
void AppendBufStr(BUF *b, char *str);

#define NUM_CANARY_RAND					32
#define CANARY_RAND_ID_MEMTAG_MAGIC		0
#define CANARY_RAND_SIZE				20

#define CANARY_RAND_ID_PTR_KEY_HASH		1

void InitCanaryRand();
UCHAR *GetCanaryRand(UINT id);

#endif	// MEMORY_H

