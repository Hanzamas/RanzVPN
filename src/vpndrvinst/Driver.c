#include "Driver.h"

#include "Dialog.h"
#include "Str.h"

#include <stdlib.h>

#include <Hamcore.h>

#ifndef WIN32_LEAN_AND_MEAN
#	define WIN32_LEAN_AND_MEAN
#endif

#include <Windows.h>

const char *GetArch()
{
	SYSTEM_INFO info;
	GetNativeSystemInfo(&info);
	switch (info.wProcessorArchitecture)
	{
	case PROCESSOR_ARCHITECTURE_AMD64:
		return "x64";
	case PROCESSOR_ARCHITECTURE_INTEL:
		return "x86";
	case PROCESSOR_ARCHITECTURE_ARM64:
		return "arm64";
	case PROCESSOR_ARCHITECTURE_ARM:
		return "arm";
	case PROCESSOR_ARCHITECTURE_IA64:
		return "ia64";
	}

	return NULL;
}

const char *GetDriverPath()
{
	static char path[MAX_PATH];

	static bool set = false;
	if (set)
	{
		return path;
	}

	snprintf(path, sizeof(path), "DriverPackages/Neo6_Win10/%s/", GetArch());

	set = true;
	return path;
}

const char *GetTmpPath()
{
	static char path[MAX_PATH];

	static bool set = false;
	if (set)
	{
		return path;
	}

	if (!GetTempPath(sizeof(path), path))
	{
		ShowWarning("GetTmpPath()", "GetTempPath() failed with error %lu!", GetLastError());
		return NULL;
	}

	set = true;
	return path;
}

void GetCatPath(char *dst, const size_t size, const char *instance)
{
	if (!dst || size == 0)
	{
		return;
	}

	if (!instance)
	{
		return;
	}

	snprintf(dst, size, "%sNeo6_%s_%s.cat", GetDriverPath(), GetArch(), instance);
}

void GetInfPath(char *dst, const size_t size, const char *instance)
{
	if (!dst || size == 0)
	{
		return;
	}

	if (!instance)
	{
		return;
	}

	snprintf(dst, size, "%sNeo6_%s_%s.inf", GetDriverPath(), GetArch(), instance);
}

void GetSysPath(char *dst, const size_t size, const char *instance)
{
	if (!dst || size == 0)
	{
		return;
	}

	if (!instance)
	{
		return;
	}

	snprintf(dst, size, "%sNeo6_%s_%s.sys", GetDriverPath(), GetArch(), instance);
}

bool IsInstanceNameOK(HAMCORE *hamcore, const char *instance)
{
	if (!hamcore || !instance)
	{
		return false;
	}

	char path[MAX_PATH];
	GetInfPath(path, sizeof(path), instance);

	const HAMCORE_FILE *file = HamcoreFind(hamcore, path);
	return file ? true : false;
}

bool IsMacAddressManual()
{
	return true;
}

bool PrepareCat(HAMCORE *hamcore, char *dst, const size_t size, const char *instance)
{
	if (!hamcore || !dst || size == 0 || !instance)
	{
		return false;
	}

	char src[MAX_PATH];
	GetCatPath(src, sizeof(src), instance);

	const HAMCORE_FILE *hamcore_file = HamcoreFind(hamcore, src);
	if (!hamcore_file)
	{
		ShowWarning("PrepareCat()", "%s not found in hamcore archive!", src);
		return false;
	}

	void *buf = malloc(hamcore_file->OriginalSize);
	if (!HamcoreRead(hamcore, buf, hamcore_file))
	{
		ShowWarning("PrepareCat()", "Failed to read %s from hamcore archive!", src);
		free(buf);
		return false;
	}

	snprintf(dst, size, "%s%s", GetTmpPath(), PathFileName(src, false));

	bool ok = false;

	HANDLE file = CreateFile(dst, GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE)
	{
		ShowWarning("PrepareCat()", "CreateFile() failed to open \"%s\" with error %lu!", dst, GetLastError());
		goto FINAL;
	}

	DWORD processed;
	ok = WriteFile(file, buf, (DWORD)hamcore_file->OriginalSize, &processed, NULL);
	CloseHandle(file);

	if (!ok)
	{
		ShowWarning("PrepareCat()", "WriteFile() failed with error %lu!", src, GetLastError());
		DeleteFile(dst);
	}
FINAL:
	free(buf);
	return ok;
}

bool PrepareInf(HAMCORE *hamcore, char *dst, const size_t size, const char *instance, const char *sys, const char *mac)
{
	if (!hamcore || !dst || size == 0 || !instance || !sys || !mac)
	{
		return false;
	}

	char src[MAX_PATH];
	GetInfPath(src, sizeof(src), instance);

	const HAMCORE_FILE *hamcore_file = HamcoreFind(hamcore, src);
	if (!hamcore_file)
	{
		ShowWarning("PrepareInf()", "%s not found in hamcore archive!", src);
		return false;
	}

	size_t buf_size = hamcore_file->OriginalSize;
	char *buf = malloc(buf_size);

	if (!HamcoreRead(hamcore, buf, hamcore_file))
	{
		ShowWarning("PrepareInf()", "Failed to read %s from hamcore archive!", src);
		free(buf);
		return false;
	}

	snprintf(dst, size, "%s%s", GetTmpPath(), PathFileName(src, false));

	bool ok = false;

	HANDLE file = CreateFile(dst, GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE)
	{
		ShowWarning("PrepareInf()", "CreateFile() failed to open \"%s\" with error %lu!", dst, GetLastError());
		goto FINAL;
	}

	DWORD processed;
	ok = WriteFile(file, buf, (DWORD)buf_size, &processed, NULL);
	CloseHandle(file);

	if (!ok)
	{
		ShowWarning("PrepareInf()", "WriteFile() failed with error %lu!", src, GetLastError());
		DeleteFile(dst);
	}
FINAL:
	free(buf);
	return ok;
}

bool PrepareSys(HAMCORE *hamcore, char *dst, const size_t size, const char *instance)
{
	if (!hamcore || !dst || size == 0 || !instance)
	{
		return false;
	}

	char src[MAX_PATH];
	GetSysPath(src, sizeof(src), instance);

	const HAMCORE_FILE *hamcore_file = HamcoreFind(hamcore, src);
	if (!hamcore_file)
	{
		ShowWarning("PrepareSys()", "%s not found in hamcore archive!", src);
		return false;
	}

	void *buf = malloc(hamcore_file->OriginalSize);
	if (!HamcoreRead(hamcore, buf, hamcore_file))
	{
		ShowWarning("PrepareSys()", "Failed to read %s from hamcore archive!", src);
		free(buf);
		return false;
	}

	snprintf(dst, size, "%s%s", GetTmpPath(), PathFileName(src, false));

	bool ok = false;

	HANDLE file = CreateFile(dst, GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE)
	{
		ShowWarning("PrepareSys()", "CreateFile() failed to open \"%s\" with error %lu!", dst, GetLastError());
		goto FINAL;
	}

	DWORD processed;
	ok = WriteFile(file, buf, (DWORD)hamcore_file->OriginalSize, &processed, NULL);
	CloseHandle(file);

	if (!ok)
	{
		ShowWarning("PrepareSys()", "WriteFile() failed with error %lu!", src, GetLastError());
		DeleteFile(dst);
	}
FINAL:
	free(buf);
	return ok;
}
