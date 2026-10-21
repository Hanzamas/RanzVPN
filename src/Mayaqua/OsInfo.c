// OsInfo.c
// Windows version, OS type and CPU count of the Win32 layer (declared in Win32.h)

#include "Win32.h"

#include "Microsoft.h"
#include "Memory.h"
#include "Str.h"

#include <intrin.h>

// InitMayaqua() ends the process through MayaFatalExit() when this is false
bool Win32IsSupportedOs() {
	return Win32GetOsType() != 0;
}

UINT Win32GetNumberOfCpuInner() {
	UINT ret = 0;
	SYSTEM_INFO info;

	Zero(&info, sizeof(info));

	GetSystemInfo(&info);

	if (info.dwNumberOfProcessors >= 1 && info.dwNumberOfProcessors <= 128)
		ret = info.dwNumberOfProcessors;

	return ret;
}

// A Windows release: Windows 10 and later all report version 10.0, so only the build number tells them apart
typedef struct WIN32_OS_RELEASE {
	UINT Build;  // First build number of the release
	bool Server; // Windows Server (product type other than VER_NT_WORKSTATION)
	UINT OsType; // OSTYPE_* of the release
	char *Name;  // Product name
} WIN32_OS_RELEASE;

// Windows releases, newest first within each product type; the build 0 rows catch every older build
static const WIN32_OS_RELEASE win32_os_releases[] =
    {
        {26100, true, OSTYPE_WINDOWS_SERVER_11, "Windows Server 2025"},
        {20348, true, OSTYPE_WINDOWS_SERVER_11, "Windows Server 2022"},
        {17763, true, OSTYPE_WINDOWS_SERVER_11, "Windows Server 2019"},
        {0, true, OSTYPE_WINDOWS_SERVER_10, "Windows Server 2016"},
        {22000, false, OSTYPE_WINDOWS_11, "Windows 11"},
        {0, false, OSTYPE_WINDOWS_10, "Windows 10"},
};

// OS type and product name of a Windows version: 0 and "Unsupported OS by Ranz VPN" when it is older
// than Windows 10 (a failed version query reads as 0.0). name may be NULL.
UINT Win32ClassifyOs(UINT major, UINT build, bool server, char **name) {
	if (major >= 10) {
		for (UINT i = 0; i < sizeof(win32_os_releases) / sizeof(win32_os_releases[0]); i++) {
			const WIN32_OS_RELEASE *r = &win32_os_releases[i];

			if (r->Server == server && build >= r->Build) {
				if (name != NULL)
					*name = r->Name;

				return r->OsType;
			}
		}
	}

	if (name != NULL)
		*name = "Unsupported OS by Ranz VPN";

	return 0;
}

// The real OS version, read once per process. RtlGetVersion is not subject to the GetVersionEx
// compatibility shim, so it needs no manifest and no registry workaround.
static INIT_ONCE os_version_once = INIT_ONCE_STATIC_INIT;
static OSVERSIONINFOEXW os_version;

// INIT_ONCE callback of Win32GetOsVersion(); a failed query leaves the version zero (unsupported)
static BOOL CALLBACK Win32ReadOsVersion(PINIT_ONCE once, PVOID param, PVOID *context) {
	LONG(WINAPI * rtl_get_version)(OSVERSIONINFOEXW *) =
	    (LONG(WINAPI *)(OSVERSIONINFOEXW *))
	        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion");

	os_version.dwOSVersionInfoSize = sizeof(os_version);

	if (rtl_get_version == NULL || rtl_get_version(&os_version) != 0)
		Zero(&os_version, sizeof(os_version));

	return TRUE;
}

const OSVERSIONINFOEXW *Win32GetOsVersion() {
	InitOnceExecuteOnce(&os_version_once, Win32ReadOsVersion, NULL, NULL);

	return &os_version;
}

void Win32GetOsInfo(OS_INFO *info) {
	const OSVERSIONINFOEXW *os = Win32GetOsVersion();
	char *keyname = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
	char *product_name;
	char tmp[MAX_SIZE];
	if (info == NULL)
		return;

	char *current_type = MsRegReadStr(REG_LOCAL_MACHINE, keyname, "CurrentType");
	char *build_lab = MsRegReadStr(REG_LOCAL_MACHINE, keyname, "BuildLab");

	info->OsType = Win32ClassifyOs(os->dwMajorVersion, os->dwBuildNumber,
	                               os->wProductType != VER_NT_WORKSTATION, &product_name);
	info->OsServicePack = os->wServicePackMajor;
	info->OsSystemName = CopyStr("Windows NT");
	info->OsProductName = CopyStr(product_name);
	info->OsVendorName = CopyStr("Microsoft Corporation");
	info->KernelName = CopyStr("NTOS Kernel");

	// "Build <n>, <CurrentType> (<BuildLab>)"
	Format(tmp, sizeof(tmp), "Build %u", (UINT)os->dwBuildNumber);
	if (current_type != NULL) {
		StrCat(tmp, sizeof(tmp), ", ");
		StrCat(tmp, sizeof(tmp), current_type);
	}
	if (build_lab != NULL) {
		StrCat(tmp, sizeof(tmp), " (");
		StrCat(tmp, sizeof(tmp), build_lab);
		StrCat(tmp, sizeof(tmp), ")");
	}
	info->OsVersion = CopyStr(tmp);

	// "Build <n> <CurrentType>"
	Format(tmp, sizeof(tmp), "Build %u", (UINT)os->dwBuildNumber);
	if (current_type != NULL) {
		StrCat(tmp, sizeof(tmp), " ");
		StrCat(tmp, sizeof(tmp), current_type);
	}
	info->KernelVersion = CopyStr(tmp);

	Free(current_type);
	Free(build_lab);
}

// OS type of the running Windows; 0 when it is older than Windows 10 or the version query failed
UINT Win32GetOsType() {
	const OSVERSIONINFOEXW *os = Win32GetOsVersion();

	return Win32ClassifyOs(os->dwMajorVersion, os->dwBuildNumber, os->wProductType != VER_NT_WORKSTATION, NULL);
}

bool IsAesNiSupported() {
	bool supported = false;

	// OpenSSL has no API to detect AES-NI
#if defined(_M_X64)
	int regs[4]; // EAX, EBX, ECX, EDX
	__cpuid(regs, 1);
	supported = (regs[2] >> 25) & 1;
#elif defined(_M_ARM64)
	return IsProcessorFeaturePresent(PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE);
#endif

	return supported;
}
