// osinfo.c
// Named OS information test of vpntest ("osinfo" command, FND-203 #166)
//
// Windows 10 and later all report version 10.0, so Win32ClassifyOs tells Windows 10 from 11 and
// Server 2016 from 2019, 2022 and 2025 by build number. The test pins the known answers of the
// classification and checks the running system: GetOsInfo() names it as the classification does,
// and a GitHub-hosted runner (Windows Server 2022 or later, Windows 11 on Arm) is named as such,
// not Windows 10 or Server 2016. Prints "OSINFO TEST OK" only when every check passes.

#include "Mayaqua/Kernel.h"
#include "Mayaqua/Mayaqua.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Win32.h"

#define	OSINFO_UNSUPPORTED		"Unsupported OS by Ranz VPN"

// A known answer of Win32ClassifyOs
typedef struct OSINFO_CASE
{
	UINT Major;							// dwMajorVersion
	UINT Build;							// dwBuildNumber
	bool Server;						// Product type other than VER_NT_WORKSTATION
	UINT OsType;						// Expected OS type
	char *Name;							// Expected product name
} OSINFO_CASE;

static const OSINFO_CASE osinfo_cases[] =
{
	{10, 19045, false, OSTYPE_WINDOWS_10, "Windows 10"},
	{10, 22000, false, OSTYPE_WINDOWS_11, "Windows 11"},
	{10, 26100, false, OSTYPE_WINDOWS_11, "Windows 11"},
	{10, 14393, true, OSTYPE_WINDOWS_SERVER_10, "Windows Server 2016"},
	{10, 17763, true, OSTYPE_WINDOWS_SERVER_11, "Windows Server 2019"},
	{10, 20348, true, OSTYPE_WINDOWS_SERVER_11, "Windows Server 2022"},
	{10, 26100, true, OSTYPE_WINDOWS_SERVER_11, "Windows Server 2025"},
	{6, 9600, false, 0, OSINFO_UNSUPPORTED},
	{0, 0, true, 0, OSINFO_UNSUPPORTED},
};

// True on a GitHub-hosted runner: GitHub Actions without RUNNER_ENVIRONMENT=self-hosted
static bool OsInfoIsGitHubHosted()
{
	char tmp[MAX_SIZE];

	if (GetEnv("GITHUB_ACTIONS", tmp, sizeof(tmp)) == false || StrCmpi(tmp, "true") != 0)
	{
		return false;
	}

	return GetEnv("RUNNER_ENVIRONMENT", tmp, sizeof(tmp)) == false || StrCmpi(tmp, "self-hosted") != 0;
}

// osinfo: known answers of Win32ClassifyOs, GetOsInfo() of this system, the name on a GitHub-hosted runner
void osinfo_test(UINT num, char **arg)
{
	const OSVERSIONINFOEXW *os = Win32GetOsVersion();
	OS_INFO *info = GetOsInfo();
	char *name = NULL;
	UINT failed = 0;
	UINT type;
	UINT i;

	Print("OS information test (Win32ClassifyOs, GetOsInfo)\n");

	for (i = 0; i < sizeof(osinfo_cases) / sizeof(osinfo_cases[0]); i++)
	{
		const OSINFO_CASE *c = &osinfo_cases[i];

		type = Win32ClassifyOs(c->Major, c->Build, c->Server, &name);
		if (type != c->OsType || StrCmp(name, c->Name) != 0)
		{
			Print("  [FAIL] %u.0 build %u server %u: %u \"%s\", expected %u \"%s\"\n",
				c->Major, c->Build, c->Server, type, name, c->OsType, c->Name);
			failed++;
		}
	}

	type = Win32ClassifyOs(os->dwMajorVersion, os->dwBuildNumber, os->wProductType != VER_NT_WORKSTATION, &name);
	Print("  This system: %u.%u build %u, product type %u: OsType %u \"%s\"\n", (UINT)os->dwMajorVersion,
		(UINT)os->dwMinorVersion, (UINT)os->dwBuildNumber, os->wProductType, info->OsType, info->OsProductName);
	if (info->OsType != type || StrCmp(info->OsProductName, name) != 0)
	{
		Print("  [FAIL] GetOsInfo() differs from Win32ClassifyOs: %u \"%s\"\n", type, name);
		failed++;
	}

	if (OsInfoIsGitHubHosted())
	{
		if (StrCmp(info->OsProductName, "Windows Server 2022") != 0 && StrCmp(info->OsProductName, "Windows Server 2025") != 0 &&
			StrCmp(info->OsProductName, "Windows 11") != 0)
		{
			Print("  [FAIL] A GitHub-hosted runner is Windows Server 2022 or later or Windows 11\n");
			failed++;
		}
	}
	else
	{
		Print("  [SKIP] Not a GitHub-hosted runner: the name of this system is not checked\n");
	}

	if (failed == 0)
	{
		Print("OSINFO TEST OK\n");
	}
	else
	{
		Print("OSINFO TEST FAILED (%u checks failed)\n", failed);
	}
}
