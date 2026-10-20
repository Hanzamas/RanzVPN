// Mayaqua.c
// Mayaqua Kernel program

#include "Mayaqua.h"

#include "Encrypt.h"
#include "FileIO.h"
#include "GlobalConst.h"
#include "Internat.h"
#include "Memory.h"
#include "Microsoft.h"
#include "Network.h"
#include "Object.h"
#include "OS.h"
#include "Str.h"
#include "Table.h"
#include "Tick64.h"
#include "Trace.h"
#include "Tracking.h"

#include <locale.h>
#include <stdlib.h>

bool g_memcheck;
bool g_debug;
volatile LONG64 kernel_status[NUM_KERNEL_STATUS];
volatile LONG64 kernel_status_max[NUM_KERNEL_STATUS];
bool kernel_status_inited = false;
bool g_little_endian = true;

static OS_INFO *os_info = NULL;
static UINT init_mayaqua_counter = 0;
static BUF *probe_buf = NULL;
static LOCK *probe_lock = NULL;
static UINT64 probe_start = 0;
static bool probe_enabled = false;

// Call once, as early as possible after the process starts
static bool init_proc_once_flag = false;
void InitProcessCallOnce()
{
	if (init_proc_once_flag == false)
	{
		init_proc_once_flag = true;

		// The DLL search order first, before anything can load a DLL
		MsInitProcessCallOnce();

		InitCanaryRand();
	}
}

static void InitProbe()
{
	probe_buf = NewBuf();
	probe_lock = NewLock();
	probe_enabled = false;

	probe_start = 0;

	probe_start = MsGetHiResCounter();
}

static void FreeProbe()
{
	if (probe_buf->Size >= 1)
	{
		SYSTEMTIME st;
		char filename[MAX_SIZE];

		MakeDirEx("@probe_log");

		LocalTime(&st);

		snprintf(filename, sizeof(filename), "@probe_log/%04u%02u%02u_%02u%02u%02u.log",
			st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

		DumpBuf(probe_buf, filename);
	}

	FreeBuf(probe_buf);
	DeleteLock(probe_lock);
}

void EnableProbe(bool enable)
{
	probe_enabled = enable;
}

// Test hooks: set only by the test harness (ham mode) and the fuzzer (minimal mode),
// never by the shipped binaries.
static bool is_ham_mode = false;
static bool minimal_mode = false;

// vpntest: the server starts without registering itself in the Windows firewall
void SetHamMode()
{
	is_ham_mode = true;
}

bool IsHamMode()
{
	return is_ham_mode;
}

// fuzzer: start without the hamcore archive and the string table
void MayaquaMinimalMode()
{
	minimal_mode = true;
}

bool MayaquaIsMinimalMode()
{
	return minimal_mode;
}

static void CheckEndian()
{
	unsigned short test;
	UCHAR *buf;

	test = 0x1234;
	buf = (UCHAR *)&test;
	if (buf[0] == 0x12)
	{
		g_little_endian = false;
	}
	else
	{
		g_little_endian = true;
	}
}

void InitMayaqua(bool memcheck, bool debug)
{
	wchar_t tmp[MAX_PATH];
	UCHAR hash[SHA1_SIZE];

	if ((init_mayaqua_counter++) > 0)
	{
		return;
	}

	InitProcessCallOnce();

	g_memcheck = memcheck;
	g_debug = debug;
	setbuf(stdout, NULL);

	CheckEndian();

	_configthreadlocale(_DISABLE_PER_THREAD_LOCALE);

	setlocale(LC_ALL, "");

	OSInit();

	// The ETW provider of Debug() (Trace.c), registered first so that it sees the whole start
	InitTrace();

	srand((UINT)SystemTime64());

	InitFifo();

	InitKernelStatus();

	if (IsTrackingEnabled())
	{
		InitTracking();
	}

	InitThreading();

	InitStringLibrary();

	SetLocale(NULL);

	InitCryptLibrary();

	InitTick64();

	InitNetwork();

	InitGetExeName();

	InitOsInfo();

	MsInit();

	if (OSIsSupportedOs() == false)
	{
		MayaFatalExit(1, CEDAR_PRODUCT_STR " VPN doesn't support this Windows Operating System.\r\n"
			CEDAR_PRODUCT_STR " VPN requires " SUPPORTED_WINDOWS_LIST ".\r\n\r\n"
			"Please contact your system administrator.");
	}

	InitHamcore();

	InitTable();

	// Quit if the executable's own file is not found (started from an odd path)
	GetExeNameW(tmp, sizeof(tmp));
	if (IsFileExistsW(tmp) == false)
	{
		char msg[MAX_SIZE];

		Format(msg, sizeof(msg),
			"Error: Executable binary file \"%S\" not found.\r\n\r\n"
			"Please execute program with full path.",
			tmp);

		MayaFatalExit(1, msg);
	}

	InitProbe();

	GetCurrentMachineIpProcessHash(hash);

	LoadPrivateIPFile();
}

void FreeMayaqua()
{
	if ((--init_mayaqua_counter) > 0)
	{
		return;
	}

	FreePrivateIPFile();

	FreeProbe();

	FreeTable();

	MsFree();

	FreeOsInfo();

	FreeHamcore();

	FreeNetwork();

	FreeTick64();

	FreeStringLibrary();

	FreeThreading();

	FreeCryptLibrary();

	if (IsTrackingEnabled())
	{
		if (g_debug)
		{
			PrintKernelStatus();
		}

		if (g_memcheck)
		{
			PrintDebugInformation();
		}

		FreeTracking();
	}

	FreeKernelStatus();

	FreeTrace();

	OSFree();
}

// Whether a person can see a message box: a visible window station (not a service), and either
// no standard error (a GUI program) or a console with a visible window. A redirected standard
// error (a CI job, a pipe) gets the message there and never a box that waits for a click.
static bool FatalExitCanShowBox()
{
	HWINSTA station = GetProcessWindowStation();
	USEROBJECTFLAGS flags;
	HANDLE err = GetStdHandle(STD_ERROR_HANDLE);
	HWND console;

	Zero(&flags, sizeof(flags));
	if (station == NULL || GetUserObjectInformationW(station, UOI_FLAGS, &flags, sizeof(flags), NULL) == FALSE ||
		(flags.dwFlags & WSF_VISIBLE) == 0)
	{
		return false;
	}

	if (err == NULL || err == INVALID_HANDLE_VALUE)
	{
		return true;
	}

	console = GetConsoleWindow();

	return GetFileType(err) == FILE_TYPE_CHAR && console != NULL && IsWindowVisible(console);
}

// End the process on an error it cannot run past. The message goes to standard error, to the
// Application event log and, only when a person can see it, to a message box (never
// MB_SERVICE_NOTIFICATION, which puts a service's box on the user's desktop and blocks it).
// Exits with code (1 when code is 0) without CRT clean-up, as other threads may still run.
// Plain CRT and Win32 calls only: it may run before InitMayaqua() is done.
void MayaFatalExit(UINT code, char *msg)
{
	if (msg == NULL)
	{
		msg = "Unknown Error";
	}
	if (code == 0)
	{
		code = 1;
	}

	fputs(msg, stderr);
	fputs("\n", stderr);
	fflush(stderr);

	MsWriteEventLog(CEDAR_PRODUCT_STR " VPN", EVENTLOG_ERROR_TYPE, MS_EVENT_FATAL_ERROR, msg);

	if (FatalExitCanShowBox())
	{
		MessageBoxA(NULL, msg, CEDAR_PRODUCT_STR " VPN Kernel", MB_SETFOREGROUND | MB_TOPMOST | MB_OK | MB_ICONERROR);
	}

	_exit((int)code);
}

OS_INFO *GetOsInfo()
{
	return os_info;
}

void InitOsInfo()
{
	if (os_info != NULL)
	{
		return;
	}

	os_info = ZeroMalloc(sizeof(OS_INFO));

	OSGetOsInfo(os_info);
}

void FreeOsInfo()
{
	if (os_info == NULL)
	{
		return;
	}

	Free(os_info->OsSystemName);
	Free(os_info->OsProductName);
	Free(os_info->OsVendorName);
	Free(os_info->OsVersion);
	Free(os_info->KernelName);
	Free(os_info->KernelVersion);
	Free(os_info);

	os_info = NULL;
}

void PrintKernelStatus()
{
	bool leaked = false;

	Print("\n");
	Print(
		"     --------- Mayaqua Kernel Status ---------\n"
		"        Malloc Count ............... %u\n"
		"        ReAlloc Count .............. %u\n"
		"        Free Count ................. %u\n"
		"        Total Memory Size .......... %I64u bytes\n"
		"      * Current Memory Blocks ...... %u Blocks (Peek: %u)\n"
		"        Total Memory Blocks ........ %u Blocks\n"
		"      * Current MemPool Blocks ..... %u Blocks (Peek: %u)\n"
		"        Total MemPool Mallocs ...... %u Mallocs\n"
		"        Total MemPool ReAllocs ..... %u ReAllocs\n"
		"        NewLock Count .............. %u\n"
		"        DeleteLock Count ........... %u\n"
		"      * Current Lock Objects ....... %u Objects\n"
		"      * Current Locked Objects ..... %u Objects\n"
		"        NewRef Count ............... %u\n"
		"        FreeRef Count .............. %u\n"
		"      * Current Ref Objects ........ %u Objects\n"
		"      * Current Ref Count .......... %u Refs\n"
		"        GetTime Count .............. %u\n"
		"        GetTick Count .............. %u\n"
		"        NewThread Count ............ %u\n"
		"        FreeThread Count ........... %u\n"
		"      * Current Threads ............ %u Threads\n"
		"        Wait For Event Count ....... %u\n\n",
		KS_GET(KS_MALLOC_COUNT),
		KS_GET(KS_REALLOC_COUNT),
		KS_GET(KS_FREE_COUNT),
		KS_GET64(KS_TOTAL_MEM_SIZE),
		KS_GET(KS_CURRENT_MEM_COUNT),
		KS_GETMAX(KS_CURRENT_MEM_COUNT),
		KS_GET(KS_TOTAL_MEM_COUNT),
		KS_GET(KS_MEMPOOL_CURRENT_NUM),
		KS_GETMAX(KS_MEMPOOL_CURRENT_NUM),
		KS_GET(KS_MEMPOOL_MALLOC_COUNT),
		KS_GET(KS_MEMPOOL_REALLOC_COUNT),
		KS_GET(KS_NEWLOCK_COUNT),
		KS_GET(KS_DELETELOCK_COUNT),
		KS_GET(KS_CURRENT_LOCK_COUNT),
		KS_GET(KS_CURRENT_LOCKED_COUNT),
		KS_GET(KS_NEWREF_COUNT),
		KS_GET(KS_FREEREF_COUNT),
		KS_GET(KS_CURRENT_REF_COUNT),
		KS_GET(KS_CURRENT_REFED_COUNT),
		KS_GET(KS_GETTIME_COUNT),
		KS_GET(KS_GETTICK_COUNT),
		KS_GET(KS_NEWTHREAD_COUNT),
		KS_GET(KS_FREETHREAD_COUNT),
		KS_GET(KS_NEWTHREAD_COUNT) - KS_GET(KS_FREETHREAD_COUNT),
		KS_GET(KS_WAIT_COUNT)
		);

	if (KS_GET(KS_CURRENT_MEM_COUNT) != 0 || KS_GET(KS_CURRENT_LOCK_COUNT) != 0 ||
		KS_GET(KS_MEMPOOL_CURRENT_NUM) != 0 ||
		KS_GET(KS_CURRENT_LOCKED_COUNT) != 0 || KS_GET(KS_CURRENT_REF_COUNT) != 0)
	{
		leaked = true;
	}

	if (leaked)
	{
		Print("      !!! MEMORY LEAKS DETECTED !!!\n\n");
		if (g_memcheck == false)
		{
			if (IsHamMode())
			{
				Print("    Enable /memcheck startup option to see the leaking memory heap.\n");
				Print("    Press Enter key to exit the process.\n");
			}
			GetLine(NULL, 0);
		}
	}
	else
	{
		Print("        @@@ NO MEMORY LEAKS @@@\n\n");
	}
}

void InitKernelStatus()
{
	UINT i;

	for (i = 0;i < NUM_KERNEL_STATUS;i++)
	{
		kernel_status[i] = 0;
		kernel_status_max[i] = 0;
	}

	kernel_status_inited = true;
}

void FreeKernelStatus()
{
	kernel_status_inited = false;
}

void PrintDebugInformation()
{
	MEMORY_STATUS memory_status;
	GetMemoryStatus(&memory_status);

	Print("====== " CEDAR_PRODUCT_STR " VPN System Debug Information ======\n");

	Print(" <Memory Status>\n"
		"       Number of Allocated Memory Blocks: %u\n"
		"   Total Size of Allocated Memory Blocks: %u bytes\n",
		memory_status.MemoryBlocksNum, memory_status.MemorySize);

	Print("====================================================\n");

	if (KS_GET(KS_CURRENT_MEM_COUNT) != 0 || KS_GET(KS_CURRENT_LOCK_COUNT) != 0 ||
		KS_GET(KS_CURRENT_LOCKED_COUNT) != 0 || KS_GET(KS_CURRENT_REF_COUNT) != 0)
	{
		// Memory leaks are suspected: show the debug menu
		MemoryDebugMenu();
	}
}

