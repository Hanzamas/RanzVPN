// Mayaqua.h
// Mayaqua Kernel header file

#ifndef	MAYAQUA_H
#define	MAYAQUA_H

#include "Kernel.h"

#include <stdio.h>

void InitProcessCallOnce();

#ifdef VPN_EXE
int main(int argc, char *argv[]);
int PASCAL WinMain(HINSTANCE hInst, HINSTANCE hPrev, char *CmdLine, int CmdShow)
{
	char *argv[] = { CmdLine, };
	InitProcessCallOnce();
	return main(1, argv);
}
#endif

#define	STRTABLE_ID					"SE_VPN_20121007"

#define	IsBigEndian()		(g_little_endian ? false : true)
#define	IsLittleEndian()	(g_little_endian)

extern bool g_memcheck;
extern bool g_debug;
extern char *cmdline;
extern bool g_little_endian;

#define	NUM_KERNEL_STATUS	128
extern volatile LONG64 kernel_status[NUM_KERNEL_STATUS];
extern volatile LONG64 kernel_status_max[NUM_KERNEL_STATUS];
extern bool kernel_status_inited;

// The kernel status counters and the object tracker run in debug or memcheck mode, from
// InitKernelStatus() on
static inline bool IsTrackingEnabled(void)
{
	return (g_debug || g_memcheck) && kernel_status_inited;
}

// Adds n to a kernel status counter and raises its peak. Interlocked, so no lock is taken; the
// peak compares unsigned, as it did when the counters were UINT64
static inline void KsAdd(UINT id, LONG64 n)
{
	LONG64 now, peak;

	if (IsTrackingEnabled() == false)
	{
		return;
	}

	now = InterlockedAdd64(&kernel_status[id], n);
	peak = kernel_status_max[id];
	while ((UINT64)now > (UINT64)peak)
	{
		LONG64 seen = InterlockedCompareExchange64(&kernel_status_max[id], now, peak);
		if (seen == peak)
		{
			break;
		}
		peak = seen;
	}
}

#define	KS_GET64(id)	((UINT64)kernel_status[(id)])
#define	KS_GET(id)		((UINT)KS_GET64(id))
#define	KS_GETMAX64(id)	((UINT64)kernel_status_max[(id)])
#define	KS_GETMAX(id)	((UINT)KS_GETMAX64(id))

// Each one is a single function call, safe as the body of an unbraced if or else
#define	KS_INC(id)		KsAdd((id), 1)
#define	KS_DEC(id)		KsAdd((id), -1)
#define	KS_ADD(id, n)	KsAdd((id), (LONG64)(n))
#define	KS_SUB(id, n)	KsAdd((id), -(LONG64)(n))

#define	KS_STRCPY_COUNT			0
#define	KS_STRLEN_COUNT			1
#define	KS_STRCHECK_COUNT		2
#define	KS_STRCAT_COUNT			3
#define	KS_FORMAT_COUNT			4
#define	KS_MALLOC_COUNT			5
#define	KS_REALLOC_COUNT		6
#define	KS_FREE_COUNT			7
#define	KS_TOTAL_MEM_SIZE		8
#define	KS_CURRENT_MEM_COUNT	9
#define	KS_TOTAL_MEM_COUNT		10
#define	KS_ZERO_COUNT			11
#define	KS_COPY_COUNT			12
#define	KS_NEWLOCK_COUNT		13
#define	KS_DELETELOCK_COUNT		14
#define	KS_LOCK_COUNT			15
#define	KS_UNLOCK_COUNT			16
#define	KS_CURRENT_LOCK_COUNT	17
#define	KS_CURRENT_LOCKED_COUNT	18
#define	KS_NEW_COUNTER_COUNT	19
#define	KS_DELETE_COUNTER_COUNT	20
#define	KS_INC_COUNT			21
#define	KS_DEC_COUNT			22
#define	KS_CURRENT_COUNT		23
#define	KS_NEWREF_COUNT			24
#define	KS_FREEREF_COUNT		72
#define	KS_ADDREF_COUNT			25
#define	KS_RELEASE_COUNT		26
#define	KS_CURRENT_REF_COUNT	27
#define	KS_CURRENT_REFED_COUNT	28
#define	KS_NEWBUF_COUNT			29
#define	KS_FREEBUF_COUNT		30
#define	KS_CURRENT_BUF_COUNT	31
#define	KS_READ_BUF_COUNT		32
#define	KS_WRITE_BUF_COUNT		33
#define	KS_ADJUST_BUFSIZE_COUNT	34
#define	KS_SEEK_BUF_COUNT		35
#define	KS_NEWFIFO_COUNT		36
#define	KS_FREEFIFO_COUNT		37
#define	KS_READ_FIFO_COUNT		38
#define	KS_WRITE_FIFO_COUNT		39
#define	KS_NEWLIST_COUNT		41
#define	KS_FREELIST_COUNT		42
#define	KS_INSERT_COUNT			43
#define	KS_DELETE_COUNT			44
#define	KS_SORT_COUNT			45
#define	KS_SEARCH_COUNT			46
#define	KS_TOARRAY_COUNT		47
#define	KS_NEWQUEUE_COUNT		48
#define	KS_FREEQUEUE_COUNT		49
#define	KS_PUSH_COUNT			50
#define	KS_POP_COUNT			51
#define	KS_NEWSK_COUNT			52
#define	KS_FREESK_COUNT			53
#define	KS_INSERT_QUEUE_COUNT	54
#define	KS_GETNEXT_COUNT		55
#define	KS_GETTIME_COUNT		56
#define	KS_GETTICK_COUNT		57
#define	KS_NEWTHREAD_COUNT		58
#define	KS_FREETHREAD_COUNT		59
#define	KS_WAITFORTHREAD_COUNT	60
#define	KS_NEWEVENT_COUNT		61
#define	KS_FREEEVENT_COUNT		62
#define	KS_WAIT_COUNT			63
#define	KS_SLEEPTHREAD_COUNT	64
#define	KS_IO_OPEN_COUNT		65
#define	KS_IO_CREATE_COUNT		66
#define	KS_IO_CLOSE_COUNT		67
#define	KS_IO_READ_COUNT		68
#define	KS_IO_WRITE_COUNT		69
#define	KS_IO_TOTAL_READ_SIZE	70
#define	KS_IO_TOTAL_WRITE_SIZE	71
#define	KS_MEMPOOL_MALLOC_COUNT	75
#define	KS_MEMPOOL_CURRENT_NUM	74
#define	KS_MEMPOOL_REALLOC_COUNT	76


#define	IsDebug()		(g_debug)
#define	IsMemCheck()	(g_memcheck)

void InitMayaqua(bool memcheck, bool debug, int argc, char **argv);
void FreeMayaqua();
void InitKernelStatus();
void FreeKernelStatus();
void PrintDebugInformation();
void PrintKernelStatus();
void InitCommandLineStr(int argc, char **argv);
void FreeCommandLineStr();
void SetCommandLineStr(char *str);
void SetCommandLineUniStr(wchar_t *str);
wchar_t *GetCommandLineUniStr();
void FreeCommandLineTokens();
TOKEN_LIST *GetCommandLineToken();
void InitOsInfo();
void FreeOsInfo();
void Alert(char *msg, char *caption);
OS_INFO *GetOsInfo();
void EnableProbe(bool enable);

// Test hooks (harness and fuzzer only)
void SetHamMode();
bool IsHamMode();
void MayaquaMinimalMode();
bool MayaquaIsMinimalMode();


#endif
