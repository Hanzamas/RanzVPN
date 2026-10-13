// MemoryInternal.h
// Module-internal declarations of the Memory module: only its own files include this header

#ifndef	MEMORY_INTERNAL_H
#define	MEMORY_INTERNAL_H

void CleanupHashList(HASH_LIST *h);
UINT CalcHashForHashList(HASH_LIST *h, void *p);
void CheckMemTag1(MEMTAG1 *tag);
void CheckMemTag2(MEMTAG2 *tag);
void *InternalMalloc(UINT size);
void *InternalReAlloc(void *addr, UINT size);
void InternalFree(void *addr);
USHORT Swap16(USHORT value);
UINT64 Swap64(UINT64 value);
void AdjustBufSize(BUF *b, UINT new_size);
bool CompareBuf(BUF *b1, BUF *b2);
void CleanupFifo(FIFO *f);
FIFO *NewFifoFast();
FIFO *NewFifoEx2(bool fast, bool fixed);
void CleanupList(LIST *o);
LIST *NewListEx2(COMPARE *cmp, bool fast, bool fast_malloc);
void CopyToArray(LIST *o, void *p);
void AddInt(LIST *o, UINT i);
void AddInt64(LIST *o, UINT64 i);
int CompareInt(void *p1, void *p2);
int CompareInt64(void *p1, void *p2);
void CleanupQueue(QUEUE *q);
SK *NewSkEx(bool no_compact);
void CleanupSk(SK *s);
UINT CompressEx(void *dst, UINT dst_size, void *src, UINT src_size, UINT level);
UINT Power(UINT a, UINT b);

#endif	// MEMORY_INTERNAL_H
