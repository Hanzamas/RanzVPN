// MicrosoftProcess.c
// Windows processes and tokens: thread priority, process arguments, logon check

#define MICROSOFT_C

#include "Microsoft.h"

#include "Internat.h"
#include "Memory.h"

#define SECURITY_WIN32

#define NO_SHLWAPI_STRFCNS
#define NO_SHLWAPI_REG
#define NO_SHLWAPI_STREAM
#define NO_SHLWAPI_HTTP
#define NO_SHLWAPI_ISOS
#define NO_SHLWAPI_GDI

#include <AclAPI.h>
#include <iphlpapi.h>
#include <mmsystem.h>
#include <nb30.h>
#include <sddl.h>
#include <security.h>
#include <SetupAPI.h>
#include <shellapi.h>
#include <ShlObj.h>
#include <Shlwapi.h> // PathGetArgsW() of MsCopyProcessArgsW
#include <SoftPub.h>

#if defined(_M_X64) || defined(_M_IX86)
#include <intrin.h> // __cpuid() of the VM detection
#endif              // defined(_M_X64) || defined(_M_IX86)
#include "MicrosoftInternal.h"

void MsSetThreadPriorityIdle() {
	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_IDLE);
}

void MsSetThreadPriorityRealtime() {
	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
}

void MsRestoreThreadPriority() {
	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_NORMAL);
}

bool MsCheckLogon(wchar_t *username, char *password) {
	wchar_t password_unicode[MAX_SIZE];
	HANDLE h;
	if (username == NULL || password == NULL)
		return false;

	StrToUni(password_unicode, sizeof(password_unicode), password);

	if (LogonUserW(username, NULL, password_unicode, LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, &h) == false)
		return false;

	CloseHandle(h);

	return true;
}

// The arguments of this process: its command line (GetCommandLineW) without the program name,
// quoted or not, and the one space after it. The caller frees the copy.
wchar_t *MsCopyProcessArgsW() {
	wchar_t *line = CopyUniStr(GetCommandLineW());

	UniTrim(line);
	wchar_t *args = CopyUniStr(PathGetArgsW(line));
	Free(line);

	return args;
}
