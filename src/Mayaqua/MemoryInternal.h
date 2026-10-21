// MemoryInternal.h
// Module-internal declarations of the Memory module: only its own files include this header

#ifndef MEMORY_INTERNAL_H
#define MEMORY_INTERNAL_H

void CleanupHashList(HASH_LIST *h);
UINT CalcHashForHashList(const HASH_LIST *h, void *p);
void CheckMemTag1(MEMTAG1 *tag);
void CheckMemTag2(MEMTAG2 *tag);
void *InternalMalloc(UINT size);
void *InternalReAlloc(void *addr, UINT size);
void InternalFree(void *addr);
bool BufToFile(const IO *o, BUF *b);
BUF *FileToBuf(IO *o);
UCHAR ReadBufChar(BUF *b);
void CleanupFifo(FIFO *f);
FIFO *NewFifoFast();
FIFO *NewFifoEx2();
void CleanupList(LIST *o);
LIST *NewListEx2(COMPARE *cmp, bool fast);
int CompareInt(void *p1, void *p2);
int CompareInt64(void *p1, void *p2);
void InsertQueueInt(QUEUE *q, UINT value);
void CleanupQueue(QUEUE *q);
void CleanupSk(SK *s);
void LockSk(SK *s);
void UnlockSk(SK *s);
UCHAR *GetCanaryRand(UINT id);

#endif // MEMORY_INTERNAL_H
