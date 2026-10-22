// ranzguard.c
// The hardened licence-gate and key-handling binary of SEC-4 (#282, ADR-0036). It is the release-only
// obfuscated build variant: a small, self-contained executable that carries the anti-debug and anti-RE
// cover so the server and vpncmd never have to. It is built only when RANZ_HARDENED is on, x64 only.
//
// Freestanding by design: no CRT, no import table. The entry point is RanzGuardMain (the linker's
// /ENTRY), and every Windows API is resolved at run time by hashing the export name, so the import
// table is empty (the property that CI asserts and that a disassembler keys on). It allocates no
// memory, keeps no RWX page, performs no self-modifying code and never writes into ntdll, so it does
// not trip HVCI / Memory Integrity or EDR heuristics.
//
// Anti-debug is passive and the response is degrade or deceive, never a crash: on any detection the
// licence gate silently returns a locked result and key handling returns a wrong key, so the failure
// surfaces later and far from the check. A clean run prints "RANZGUARD UNLOCKED"; a run under a
// debugger prints "RANZGUARD LOCKED". The harden self-test of vpntest drives both paths.
//
// VMProtect virtualization is applied selectively, through the RANZ_VMP_BEGIN / RANZ_VMP_END markers,
// to the licence-gate and key-handling routines only, never main and never the whole binary. The
// markers expand to the VMProtect SDK calls when the SDK is present at the release step and to nothing
// otherwise, so CI builds this variant without the paid tool.

#if !defined(_M_X64)
#error "ranzguard is the x64-only hardened variant (ADR-0036); arm64 ships the clean build"
#endif

#include <intrin.h>
#include <stddef.h>

// Minimal fixed-width typedefs: ranzguard includes no Windows header, so that no header-injected
// #pragma comment(lib, ...) pulls a default library back into the empty import table.
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long ulong32;
typedef unsigned long long u64;
typedef void *handle_t;

#define RG_NULL ((void *)0)

// VMProtect markers. Only the SDK build (the release step) turns these into real virtualization; CI
// builds without the SDK, where they are nothing. They must appear in licence_gate and key_handling
// only (harden-check.py --markers asserts it).
#ifdef RANZ_VMPROTECT_SDK
#include "VMProtectSDK.h"
#define RANZ_VMP_BEGIN(name) VMProtectBeginVirtualization(name)
#define RANZ_VMP_END() VMProtectEnd()
#else
#define RANZ_VMP_BEGIN(name) ((void)(name))
#define RANZ_VMP_END() ((void)0)
#endif

// Freestanding memory helpers. clang recognises a hand-written copy or fill loop and would emit a call
// to memset / memcpy, which with /NODEFAULTLIB is unresolved; defining them here supplies the symbols.
// optnone stops the compiler turning each one's own loop into a call to itself.
__attribute__((optnone)) void *memset(void *dst, int val, size_t len)
{
	u8 *p = (u8 *)dst;
	for (size_t i = 0; i < len; i++)
	{
		p[i] = (u8)val;
	}
	return dst;
}

__attribute__((optnone)) void *memcpy(void *dst, const void *src, size_t len)
{
	u8 *d = (u8 *)dst;
	const u8 *s = (const u8 *)src;
	for (size_t i = 0; i < len; i++)
	{
		d[i] = s[i];
	}
	return dst;
}

__attribute__((optnone)) void *memmove(void *dst, const void *src, size_t len)
{
	u8 *d = (u8 *)dst;
	const u8 *s = (const u8 *)src;
	if (d < s)
	{
		for (size_t i = 0; i < len; i++)
		{
			d[i] = s[i];
		}
	}
	else
	{
		for (size_t i = len; i != 0; i--)
		{
			d[i - 1] = s[i - 1];
		}
	}
	return dst;
}

__attribute__((optnone)) int memcmp(const void *a, const void *b, size_t len)
{
	const u8 *x = (const u8 *)a;
	const u8 *y = (const u8 *)b;
	for (size_t i = 0; i < len; i++)
	{
		if (x[i] != y[i])
		{
			return (int)x[i] - (int)y[i];
		}
	}
	return 0;
}

// Read helpers over the loaded images, by byte offset, so no IMAGE_* struct layout can be miscounted.
static u16 rd16(const u8 *base, u32 off)
{
	u16 v;
	memcpy(&v, base + off, sizeof(v));
	return v;
}

static u32 rd32(const u8 *base, u32 off)
{
	u32 v;
	memcpy(&v, base + off, sizeof(v));
	return v;
}

static u64 rdptr(const u8 *base, u32 off)
{
	u64 v;
	memcpy(&v, base + off, sizeof(v));
	return v;
}

// FNV-1a over the bytes of an export name; the needle is hashed the same way at the call site, so
// resolution is by hash, not by string compare.
#define FNV64_OFFSET 1469598103934665603ULL
#define FNV64_PRIME 1099511628211ULL

static u64 hash_ascii(const char *s)
{
	u64 h = FNV64_OFFSET;
	while (*s != 0)
	{
		h ^= (u8)(*s);
		h *= FNV64_PRIME;
		s++;
	}
	return h;
}

// The export of the given module whose name hashes to needle, or NULL. A forwarder (its address falls
// inside the export directory) is skipped, so the caller keeps looking in the module that really
// implements the function; on Windows 10 and later most kernel32 exports forward to kernelbase.
static void *export_by_hash(const u8 *base, u64 needle)
{
	u32 e_lfanew = rd32(base, 0x3C);
	// Optional header follows the 4-byte PE signature and the 20-byte file header; for PE32+ the data
	// directory starts at optional-header offset 0x70, and entry 0 is the export directory
	u32 opt = e_lfanew + 4 + 20;
	u32 exp_rva = rd32(base, opt + 0x70);
	u32 exp_size = rd32(base, opt + 0x74);
	if (exp_rva == 0 || exp_size == 0)
	{
		return RG_NULL;
	}

	u32 num_names = rd32(base, exp_rva + 0x18);
	u32 funcs_rva = rd32(base, exp_rva + 0x1C);
	u32 names_rva = rd32(base, exp_rva + 0x20);
	u32 ords_rva = rd32(base, exp_rva + 0x24);

	for (u32 i = 0; i < num_names; i++)
	{
		u32 name_rva = rd32(base, names_rva + i * 4);
		if (hash_ascii((const char *)(base + name_rva)) != needle)
		{
			continue;
		}
		u16 ord = rd16(base, ords_rva + i * 2);
		u32 func_rva = rd32(base, funcs_rva + ord * 4);
		if (func_rva >= exp_rva && func_rva < exp_rva + exp_size)
		{
			// A forwarder, not code: let another module answer
			return RG_NULL;
		}
		return (void *)(base + func_rva);
	}
	return RG_NULL;
}

// Resolve by walking the loader's in-load-order module list (PEB->Ldr) and taking the first module
// that exports a non-forwarder with the wanted name hash. No module name is read, so no UNICODE_STRING
// offset can be wrong.
static void *resolve(u64 needle)
{
	u64 peb = __readgsqword(0x60);
	u64 ldr = rdptr((const u8 *)peb, 0x18);
	u64 head = ldr + 0x10; // InLoadOrderModuleList (LIST_ENTRY)
	u64 cur = rdptr((const u8 *)head, 0x00);

	while (cur != head)
	{
		// InLoadOrderLinks is the first field of the entry, so the node is the entry
		u64 dll_base = rdptr((const u8 *)cur, 0x30);
		if (dll_base != 0)
		{
			void *fn = export_by_hash((const u8 *)dll_base, needle);
			if (fn != RG_NULL)
			{
				return fn;
			}
		}
		cur = rdptr((const u8 *)cur, 0x00);
	}
	return RG_NULL;
}

// The APIs ranzguard resolves. ntdll holds the Nt* and Rtl*; kernelbase holds the Win32 ones that
// kernel32 forwards to. Calling conventions collapse to one ABI on x64.
typedef long(*fn_NtQueryInformationProcess)(handle_t, u32, void *, ulong32, ulong32 *);
typedef long(*fn_NtSetInformationThread)(handle_t, u32, void *, ulong32);
typedef void(*fn_RtlExitUserProcess)(u32);
typedef void *(*fn_RtlAddVectoredExceptionHandler)(ulong32, void *);
typedef u32(*fn_RtlRemoveVectoredExceptionHandler)(void *);
typedef handle_t(*fn_GetStdHandle)(ulong32);
typedef int(*fn_WriteFile)(handle_t, const void *, ulong32, ulong32 *, void *);
typedef int(*fn_QueryPerformanceCounter)(u64 *);
typedef int(*fn_GetThreadContext)(handle_t, void *);
typedef handle_t(*fn_OpenProcess)(ulong32, int, ulong32);
typedef int(*fn_QueryFullProcessImageNameW)(handle_t, ulong32, u16 *, ulong32 *);
typedef int(*fn_CloseHandle)(handle_t);

typedef struct GUARD_API
{
	fn_NtQueryInformationProcess NtQueryInformationProcess;
	fn_NtSetInformationThread NtSetInformationThread;
	fn_RtlExitUserProcess RtlExitUserProcess;
	fn_RtlAddVectoredExceptionHandler RtlAddVectoredExceptionHandler;
	fn_RtlRemoveVectoredExceptionHandler RtlRemoveVectoredExceptionHandler;
	fn_GetStdHandle GetStdHandle;
	fn_WriteFile WriteFile;
	fn_QueryPerformanceCounter QueryPerformanceCounter;
	fn_GetThreadContext GetThreadContext;
	fn_OpenProcess OpenProcess;
	fn_QueryFullProcessImageNameW QueryFullProcessImageNameW;
	fn_CloseHandle CloseHandle;
} GUARD_API;

static void load_api(GUARD_API *a)
{
	a->NtQueryInformationProcess = (fn_NtQueryInformationProcess)resolve(hash_ascii("NtQueryInformationProcess"));
	a->NtSetInformationThread = (fn_NtSetInformationThread)resolve(hash_ascii("NtSetInformationThread"));
	a->RtlExitUserProcess = (fn_RtlExitUserProcess)resolve(hash_ascii("RtlExitUserProcess"));
	a->RtlAddVectoredExceptionHandler = (fn_RtlAddVectoredExceptionHandler)resolve(hash_ascii("RtlAddVectoredExceptionHandler"));
	a->RtlRemoveVectoredExceptionHandler = (fn_RtlRemoveVectoredExceptionHandler)resolve(hash_ascii("RtlRemoveVectoredExceptionHandler"));
	a->GetStdHandle = (fn_GetStdHandle)resolve(hash_ascii("GetStdHandle"));
	a->WriteFile = (fn_WriteFile)resolve(hash_ascii("WriteFile"));
	a->QueryPerformanceCounter = (fn_QueryPerformanceCounter)resolve(hash_ascii("QueryPerformanceCounter"));
	a->GetThreadContext = (fn_GetThreadContext)resolve(hash_ascii("GetThreadContext"));
	a->OpenProcess = (fn_OpenProcess)resolve(hash_ascii("OpenProcess"));
	a->QueryFullProcessImageNameW = (fn_QueryFullProcessImageNameW)resolve(hash_ascii("QueryFullProcessImageNameW"));
	a->CloseHandle = (fn_CloseHandle)resolve(hash_ascii("CloseHandle"));
}

// NtQueryInformationProcess information classes and the related constants
#define ProcessBasicInformation 0
#define ProcessDebugPort 7
#define ProcessDebugObjectHandle 0x1E
#define ProcessDebugFlags 0x1F
#define ThreadHideFromDebugger 0x11

#define STD_OUTPUT_HANDLE ((ulong32)-11)
#define CURRENT_THREAD ((handle_t)(long long)(-2))
#define CURRENT_PROCESS ((handle_t)(long long)(-1))
#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000
#define EXCEPTION_BREAKPOINT 0x80000003UL
#define EXCEPTION_CONTINUE_EXECUTION (-1L)
#define EXCEPTION_CONTINUE_SEARCH 0L

// x64 CONTEXT offsets, used both to ask for the debug registers and to step over the breakpoint in
// the vectored handler. A generous aligned buffer holds the whole CONTEXT so GetThreadContext cannot
// write past it.
#define CTX_FLAGS 0x30
#define CTX_DR0 0x48
#define CTX_DR3 0x60
#define CTX_DR7 0x70
#define CTX_RIP 0xF8
#define CONTEXT_AMD64_DEBUG_REGISTERS 0x00100010UL

// Set by the vectored handler when it, and not a debugger, took the breakpoint
static volatile long g_veh_took;

static long __stdcall veh_breakpoint(void *info)
{
	// EXCEPTION_POINTERS: ExceptionRecord* at 0x00, ContextRecord* at 0x08
	u64 rec = rdptr((const u8 *)info, 0x00);
	u64 ctx = rdptr((const u8 *)info, 0x08);
	u32 code = rd32((const u8 *)rec, 0x00); // ExceptionRecord->ExceptionCode

	if (code == EXCEPTION_BREAKPOINT)
	{
		g_veh_took = 1;
		// Step the instruction pointer over the one-byte int3 and resume
		u64 rip = rdptr((const u8 *)ctx, CTX_RIP);
		rip += 1;
		memcpy((u8 *)ctx + CTX_RIP, &rip, sizeof(rip));
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	return EXCEPTION_CONTINUE_SEARCH;
}

// A minimal case-folding wide-char compare of the tail of path against name (both lower-cased on the
// fly). Used only for the parent-process check.
static int wtail_is(const u16 *path, u32 path_len, const char *name)
{
	u32 nlen = 0;
	while (name[nlen] != 0)
	{
		nlen++;
	}
	if (path_len < nlen)
	{
		return 0;
	}
	const u16 *tail = path + (path_len - nlen);
	for (u32 i = 0; i < nlen; i++)
	{
		u16 c = tail[i];
		if (c >= 'A' && c <= 'Z')
		{
			c = (u16)(c + 32);
		}
		if (c != (u16)name[i])
		{
			return 0;
		}
	}
	return 1;
}

// Each check returns 1 when it sees a debugger, 0 otherwise. None of them crashes or allocates.

static int chk_peb_flags(void)
{
	u64 peb = __readgsqword(0x60);
	u8 being = *(volatile u8 *)(peb + 0x02);		   // PEB->BeingDebugged
	u32 ntglobal = *(volatile u32 *)(peb + 0xBC);	   // PEB->NtGlobalFlag
	// FLG_HEAP_ENABLE_TAIL_CHECK | FREE_CHECK | VALIDATE_PARAMETERS: the heap flags a debugger sets
	u32 heap_debug = 0x70;
	if (being != 0)
	{
		return 1;
	}
	if ((ntglobal & heap_debug) != 0)
	{
		return 1;
	}
	return 0;
}

static int chk_debug_port(GUARD_API *a)
{
	if (a->NtQueryInformationProcess == RG_NULL)
	{
		return 0;
	}
	u64 port = 0;
	ulong32 flags = 0;
	u64 obj = 0;
	long st;

	st = a->NtQueryInformationProcess(CURRENT_PROCESS, ProcessDebugPort, &port, sizeof(port), RG_NULL);
	if (st == 0 && port != 0)
	{
		return 1;
	}

	st = a->NtQueryInformationProcess(CURRENT_PROCESS, ProcessDebugObjectHandle, &obj, sizeof(obj), RG_NULL);
	if (st == 0 && obj != 0)
	{
		return 1;
	}

	st = a->NtQueryInformationProcess(CURRENT_PROCESS, ProcessDebugFlags, &flags, sizeof(flags), RG_NULL);
	if (st == 0 && flags == 0)
	{
		// ProcessDebugFlags is 0 when the process is being debugged (debug-inherit cleared)
		return 1;
	}
	return 0;
}

static int chk_hardware_bp(GUARD_API *a)
{
	if (a->GetThreadContext == RG_NULL)
	{
		return 0;
	}
	__declspec(align(16)) u8 ctx[0x500];
	memset(ctx, 0, sizeof(ctx));
	u32 want = CONTEXT_AMD64_DEBUG_REGISTERS;
	memcpy(ctx + CTX_FLAGS, &want, sizeof(want));

	if (a->GetThreadContext(CURRENT_THREAD, ctx) == 0)
	{
		return 0;
	}
	for (u32 off = CTX_DR0; off <= CTX_DR3; off += 8)
	{
		if (rdptr(ctx, off) != 0)
		{
			return 1;
		}
	}
	if (rdptr(ctx, CTX_DR7) != 0)
	{
		return 1;
	}
	return 0;
}

static int chk_int3_in_routine(void)
{
	// A software breakpoint replaces the first byte of a function with 0xCC. The protected routines
	// never start with 0xCC under clang-cl, so a 0xCC entry byte is a breakpoint.
	extern int licence_gate(int suspicious);
	extern u64 key_handling(int suspicious);
	const u8 *gate = (const u8 *)&licence_gate;
	const u8 *key = (const u8 *)&key_handling;
	if (gate[0] == 0xCC || key[0] == 0xCC)
	{
		return 1;
	}
	return 0;
}

static int chk_timing(GUARD_API *a)
{
	// The minimum of several deltas across an empty section. A context switch inflates one sample but
	// not the minimum; a debugger that pauses between the reads inflates every sample. The threshold
	// is far above any scheduling jitter, so a clean run never trips it.
	u64 best_tsc = ~0ULL;
	for (int i = 0; i < 8; i++)
	{
		u64 t0 = __rdtsc();
		u64 t1 = __rdtsc();
		u64 d = t1 - t0;
		if (d < best_tsc)
		{
			best_tsc = d;
		}
	}
	if (best_tsc > 5000000ULL)
	{
		return 1;
	}

	if (a->QueryPerformanceCounter != RG_NULL)
	{
		u64 best_qpc = ~0ULL;
		for (int i = 0; i < 8; i++)
		{
			u64 q0 = 0, q1 = 0;
			a->QueryPerformanceCounter(&q0);
			a->QueryPerformanceCounter(&q1);
			u64 d = q1 - q0;
			if (d < best_qpc)
			{
				best_qpc = d;
			}
		}
		if (best_qpc > 1000000ULL)
		{
			return 1;
		}
	}
	return 0;
}

static int chk_parent(GUARD_API *a)
{
	if (a->NtQueryInformationProcess == RG_NULL || a->OpenProcess == RG_NULL ||
		a->QueryFullProcessImageNameW == RG_NULL || a->CloseHandle == RG_NULL)
	{
		return 0;
	}
	u8 pbi[0x40];
	memset(pbi, 0, sizeof(pbi));
	long st = a->NtQueryInformationProcess(CURRENT_PROCESS, ProcessBasicInformation, pbi, 0x30, RG_NULL);
	if (st != 0)
	{
		return 0;
	}
	// PROCESS_BASIC_INFORMATION->InheritedFromUniqueProcessId at offset 0x28
	u64 parent_pid = rdptr(pbi, 0x28);
	if (parent_pid == 0)
	{
		return 0;
	}

	handle_t hp = a->OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, (ulong32)parent_pid);
	if (hp == RG_NULL)
	{
		return 0;
	}
	u16 path[260];
	memset(path, 0, sizeof(path));
	ulong32 len = 260;
	int ok = a->QueryFullProcessImageNameW(hp, 0, path, &len);
	a->CloseHandle(hp);
	if (ok == 0 || len == 0)
	{
		return 0;
	}

	const char *debuggers[] = {"windbg.exe", "x64dbg.exe", "x32dbg.exe", "ollydbg.exe", "ida.exe",
							   "ida64.exe", "devenv.exe", "vsjitdebugger.exe", "cdb.exe", "ntsd.exe",
							   "dbgview.exe", "immunitydebugger.exe"};
	u32 count = (u32)(sizeof(debuggers) / sizeof(debuggers[0]));
	for (u32 i = 0; i < count; i++)
	{
		if (wtail_is(path, len, debuggers[i]))
		{
			return 1;
		}
	}
	return 0;
}

static int chk_veh(GUARD_API *a)
{
	// Register first, and only then raise the breakpoint, so a run where registration fails never
	// executes an int3 that would otherwise terminate a clean process.
	if (a->RtlAddVectoredExceptionHandler == RG_NULL || a->RtlRemoveVectoredExceptionHandler == RG_NULL)
	{
		return 0;
	}
	void *h = a->RtlAddVectoredExceptionHandler(1, (void *)&veh_breakpoint);
	if (h == RG_NULL)
	{
		return 0;
	}
	g_veh_took = 0;
	__debugbreak();
	int suspicious = (g_veh_took == 0) ? 1 : 0; // a debugger swallowed the breakpoint
	a->RtlRemoveVectoredExceptionHandler(h);
	return suspicious;
}

// The whole passive sweep. ThreadHideFromDebugger is set as part of it; detection is the OR of the
// independent signals, so one reliable signal (the debug port) carries the verdict even if a softer
// one stays quiet.
static int debugger_present(GUARD_API *a)
{
	int seen = 0;
	if (a->NtSetInformationThread != RG_NULL)
	{
		a->NtSetInformationThread(CURRENT_THREAD, ThreadHideFromDebugger, RG_NULL, 0);
	}
	seen |= chk_peb_flags();
	seen |= chk_debug_port(a);
	seen |= chk_hardware_bp(a);
	seen |= chk_int3_in_routine();
	seen |= chk_timing(a);
	seen |= chk_parent(a);
	seen |= chk_veh(a);
	return seen;
}

// The protected routines. VMProtect virtualizes exactly these two (and nothing else) at the release
// step. The response to a detected debugger is to deceive: the gate reports locked and key handling
// returns a wrong key, with no crash.
#define LICENCE_UNLOCKED 0x4F4B4159 // "AYOK"
#define LICENCE_LOCKED 0x00000000

__attribute__((noinline)) int licence_gate(int suspicious)
{
	RANZ_VMP_BEGIN("ranzguard.licence_gate");
	int status;
	if (suspicious)
	{
		status = LICENCE_LOCKED;
	}
	else
	{
		status = LICENCE_UNLOCKED;
	}
	RANZ_VMP_END();
	return status;
}

__attribute__((noinline)) u64 key_handling(int suspicious)
{
	RANZ_VMP_BEGIN("ranzguard.key_handling");
	// A stand-in key schedule. Under a debugger it returns a wrong key, the data-deceive response.
	u64 key = 0x0123456789ABCDEFULL;
	if (suspicious)
	{
		key ^= 0xFFFFFFFFFFFFFFFFULL;
	}
	RANZ_VMP_END();
	return key;
}

static void write_line(GUARD_API *a, const char *s, u32 len)
{
	if (a->GetStdHandle == RG_NULL || a->WriteFile == RG_NULL)
	{
		return;
	}
	handle_t out = a->GetStdHandle(STD_OUTPUT_HANDLE);
	ulong32 written = 0;
	a->WriteFile(out, s, len, &written, RG_NULL);
}

// The linker entry point (/ENTRY:RanzGuardMain). It never returns: it exits through RtlExitUserProcess.
void RanzGuardMain(void)
{
	GUARD_API api;
	memset(&api, 0, sizeof(api));
	load_api(&api);

	int suspicious = debugger_present(&api);
	int status = licence_gate(suspicious);
	u64 key = key_handling(suspicious);

	// Fold the key in so the release build cannot fold key_handling away; the token still only depends
	// on the gate status, which is what the harden self-test checks.
	int unlocked = (status == LICENCE_UNLOCKED) && (key == 0x0123456789ABCDEFULL);

	if (unlocked)
	{
		write_line(&api, "RANZGUARD UNLOCKED\n", 19);
	}
	else
	{
		write_line(&api, "RANZGUARD LOCKED\n", 17);
	}

	if (api.RtlExitUserProcess != RG_NULL)
	{
		api.RtlExitUserProcess(0);
	}
	// RtlExitUserProcess does not return; the loop is only so RanzGuardMain never falls off its end
	for (;;)
	{
	}
}
