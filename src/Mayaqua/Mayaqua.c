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
#include "Str.h"
#include "Table.h"
#include "Tick64.h"
#include "Trace.h"
#include "Tracking.h"
#include "Win32.h"

#include <locale.h>
#include <stdlib.h>

bool g_memcheck;
bool g_debug;
UINT64 kernel_status[NUM_KERNEL_STATUS];
UINT64 kernel_status_max[NUM_KERNEL_STATUS];
static LOCK *kernel_status_lock[NUM_KERNEL_STATUS];
bool kernel_status_inited = false;
bool g_little_endian = true;
char *cmdline = NULL;
static wchar_t *uni_cmdline = NULL;

static char *exename = NULL;
static wchar_t *exename_w = NULL;
static TOKEN_LIST *cmdline_token = NULL;
static UNI_TOKEN_LIST *cmdline_uni_token = NULL;
static OS_INFO *os_info = NULL;
static bool dot_net_mode = false;
static bool minimal_mode = false;
static bool is_ham_mode = false;
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

void SetHamMode()
{
	is_ham_mode = true;
}

bool IsHamMode()
{
	return is_ham_mode;
}

bool MayaquaIsDotNetMode()
{
	return dot_net_mode;
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

void MayaquaMinimalMode()
{
	minimal_mode = true;
}
bool MayaquaIsMinimalMode()
{
	return minimal_mode;
}

void InitMayaqua(bool memcheck, bool debug, int argc, char **argv)
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
	cmdline = NULL;
	if (dot_net_mode == false)
	{
		// This fails in .NET mode
		setbuf(stdout, NULL);
	}

	CheckEndian();

	_configthreadlocale(_DISABLE_PER_THREAD_LOCALE);

	setlocale(LC_ALL, "");

	Win32Init();

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

	InitGetExeName(argc >= 1 ? argv[0] : NULL);

	InitCommandLineStr(argc, argv);

	InitOsInfo();

	MsInit();

	if (Win32IsSupportedOs() == false)
	{
		exit(0);
	}

	if (RsaCheckEx() == false)
	{
		Win32Alert("OpenSSL Library Init Failed. (too old?)\nPlease install the latest version of OpenSSL.\n\n", "RsaCheck()");
		exit(0);
	}

	InitHamcore();

	InitTable();

	if (exename == NULL)
	{
		exename = CopyStr("unknown");
	}

	// Quit if the executable's own file is not found (started from an odd path)
	GetExeNameW(tmp, sizeof(tmp));
	if (IsFileExistsW(tmp) == false)
	{
		wchar_t tmp2[MAX_SIZE];

		UniFormat(tmp2, sizeof(tmp2),
			L"Error: Executable binary file \"%s\" not found.\r\n\r\n"
			L"Please execute program with full path.\r\n",
			tmp);

		Win32AlertW(tmp2, NULL);
		_exit(0);
	}

	CheckUnixTempDir();

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

	FreeCommandLineStr();

	FreeCommandLineTokens();

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

	Win32Free();
}

void CheckUnixTempDir()
{
	if (OS_IS_UNIX(GetOsInfo()->OsType))
	{
		char tmp[128], tmp2[64];
		UINT64 now = SystemTime64();
		IO *o;

		MakeDir("/tmp");

		Format(tmp2, sizeof(tmp2), "%I64u", now);

		Format(tmp, sizeof(tmp), "/tmp/.%s", tmp2);

		o = FileCreate(tmp);
		if (o == NULL)
		{
			o = FileOpen(tmp, false);
			if (o == NULL)
			{
				Print("Unable to use /tmp.\n\n");
				exit(0);
			}
		}

		FileClose(o);

		FileDelete(tmp);
	}
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

	Win32GetOsInfo(os_info);
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

TOKEN_LIST *GetCommandLineToken()
{
	if (cmdline_token == NULL)
	{
		return NullToken();
	}
	else
	{
		return CopyToken(cmdline_token);
	}
}

static void ParseCommandLineTokens()
{
	if (cmdline_token != NULL)
	{
		FreeToken(cmdline_token);
	}
	cmdline_token = ParseCmdLine(cmdline);

	if (cmdline_uni_token != NULL)
	{
		UniFreeToken(cmdline_uni_token);
	}
	cmdline_uni_token = UniParseCmdLine(uni_cmdline);
}

void FreeCommandLineTokens()
{
	if (cmdline_token != NULL)
	{
		FreeToken(cmdline_token);
	}
	cmdline_token = NULL;

	if (cmdline_uni_token != NULL)
	{
		UniFreeToken(cmdline_uni_token);
	}
	cmdline_uni_token = NULL;
}

void InitCommandLineStr(int argc, char **argv)
{
	if (argc >= 1)
	{
		exename = CopyStr(argv[0]);
		exename_w = CopyStrToUni(exename);
	}
	if (argc < 2 || argv == NULL)
	{
		SetCommandLineStr(NULL);
	}
	else
	{
		int i, total_len = 1;
		char *tmp;

		for (i = 1;i < argc;i++)
		{
			total_len += StrLen(argv[i]) * 2 + 32;
		}
		tmp = ZeroMalloc(total_len);

		for (i = 1;i < argc;i++)
		{
			UINT s_size = StrLen(argv[i]) * 2;
			char *s = ZeroMalloc(s_size);
			bool dq = (SearchStrEx(argv[i], " ", 0, true) != INFINITE);
			ReplaceStrEx(s, s_size, argv[i], "\"", "\"\"", true);
			if (dq)
			{
				StrCat(tmp, total_len, "\"");
			}
			StrCat(tmp, total_len, s);
			if (dq)
			{
				StrCat(tmp, total_len, "\"");
			}
			StrCat(tmp, total_len, " ");
			Free(s);
		}

		Trim(tmp);
		SetCommandLineStr(tmp);
		Free(tmp);
	}
}

void FreeCommandLineStr()
{
	SetCommandLineStr(NULL);

	if (exename != NULL)
	{
		Free(exename);
		exename = NULL;
	}

	if (exename_w != NULL)
	{
		Free(exename_w);
		exename_w = NULL;
	}
}

wchar_t *GetCommandLineUniStr()
{
	if (uni_cmdline == NULL)
	{
		return UniCopyStr(L"");
	}
	else
	{
		return UniCopyStr(uni_cmdline);
	}
}

void SetCommandLineUniStr(wchar_t *str)
{
	if (uni_cmdline != NULL)
	{
		Free(uni_cmdline);
	}
	if (str == NULL)
	{
		uni_cmdline = NULL;
	}
	else
	{
		uni_cmdline = CopyUniStr(str);
	}

	ParseCommandLineTokens();
}

void SetCommandLineStr(char *str)
{
	if (str == NULL)
	{
		if (cmdline != NULL)
		{
			Free(cmdline);
		}
		cmdline = NULL;
	}
	else
	{
		if (cmdline != NULL)
		{
			Free(cmdline);
		}
		cmdline = CopyStr(str);
	}

	if (cmdline == NULL)
	{
		if (uni_cmdline != NULL)
		{
			Free(uni_cmdline);
			uni_cmdline = NULL;
		}
	}
	else
	{
		if (uni_cmdline != NULL)
		{
			Free(uni_cmdline);
		}
		uni_cmdline = CopyStrToUni(cmdline);
	}

	ParseCommandLineTokens();
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

	Zero(kernel_status, sizeof(kernel_status));
	Zero(kernel_status_max, sizeof(kernel_status_max));

	for (i = 0;i < NUM_KERNEL_STATUS;i++)
	{
		kernel_status_lock[i] = NewRawLock();
	}

	kernel_status_inited = true;
}

void FreeKernelStatus()
{
	UINT i;

	kernel_status_inited = false;

	for (i = 0;i < NUM_KERNEL_STATUS;i++)
	{
		DeleteRawLock(kernel_status_lock[i]);
	}
}

void LockKernelStatus(UINT id)
{
	if (id >= NUM_KERNEL_STATUS)
	{
		return;
	}

	RawLock(kernel_status_lock[id]);
}

void UnlockKernelStatus(UINT id)
{
	if (id >= NUM_KERNEL_STATUS)
	{
		return;
	}

	RawUnlock(kernel_status_lock[id]);
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

