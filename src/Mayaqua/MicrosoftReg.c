// MicrosoftReg.c
// Windows registry (MsReg*)

#define	MICROSOFT_C

#include "Microsoft.h"

#include "Internat.h"
#include "Memory.h"
#include "Str.h"

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
#include <Shlwapi.h>		// PathGetArgsW() of MsCopyProcessArgsW
#include <SoftPub.h>

#if defined(_M_X64) || defined(_M_IX86)
#include <intrin.h>		// __cpuid() of the VM detection
#endif	// defined(_M_X64) || defined(_M_IX86)
#include "MicrosoftInternal.h"

// Access mask that forces the 32-bit registry view. The process is 64-bit (x64 or arm64), so
// without it the key opens in the 64-bit view.
static UINT MsRegViewMask(bool force32bit)
{
	return force32bit ? KEY_WOW64_32KEY : 0;
}

bool MsRegDeleteValue(UINT root, char *keyname, char *valuename)
{
	return MsRegDeleteValueEx2(root, keyname, valuename, false);
}
bool MsRegDeleteValueEx2(UINT root, char *keyname, char *valuename, bool force32bit)
{
	HKEY h;
	bool ret;
	if (keyname == NULL)
	{
		return false;
	}

	// RegDeleteValue needs KEY_SET_VALUE only
	if (RegOpenKeyEx(MsGetRootKeyFromInt(root), keyname, 0, KEY_SET_VALUE | MsRegViewMask(force32bit), &h) != ERROR_SUCCESS)
	{
		return false;
	}

	if (RegDeleteValue(h, valuename) != ERROR_SUCCESS)
	{
		ret = false;
	}
	else
	{
		ret = true;
	}

	RegCloseKey(h);

	return ret;
}

bool MsRegDeleteKeyEx2(UINT root, char *keyname, bool force32bit)
{
	if (keyname == NULL)
	{
		return false;
	}

	if (RegDeleteKeyExA(MsGetRootKeyFromInt(root), keyname, MsRegViewMask(force32bit), 0) != ERROR_SUCCESS)
	{
		return false;
	}

	return true;
}

TOKEN_LIST *MsRegEnumKey(UINT root, char *keyname)
{
	return MsRegEnumKeyEx2(root, keyname, false);
}
TOKEN_LIST *MsRegEnumKeyEx2(UINT root, char *keyname, bool force32bit)
{
	HKEY h;
	UINT i;
	TOKEN_LIST *t;
	LIST *o;

	if (keyname == NULL)
	{
		h = MsGetRootKeyFromInt(root);
	}
	else
	{
		if (RegOpenKeyEx(MsGetRootKeyFromInt(root), keyname, 0, KEY_READ | MsRegViewMask(force32bit), &h) != ERROR_SUCCESS)
		{
			return NULL;
		}
	}

	o = NewListFast(CompareStr);

	for (i = 0;;i++)
	{
		char tmp[MAX_SIZE];
		UINT ret;
		DWORD size = sizeof(tmp);
		FILETIME ft;

		Zero(tmp, sizeof(tmp));
		ret = RegEnumKeyEx(h, i, tmp, &size, NULL, NULL, NULL, &ft);
		if (ret == ERROR_NO_MORE_ITEMS)
		{
			break;
		}
		else if (ret != ERROR_SUCCESS)
		{
			break;
		}

		Add(o, CopyStr(tmp));
	}

	Sort(o);

	t = ZeroMalloc(sizeof(TOKEN_LIST));
	t->NumTokens = LIST_NUM(o);
	t->Token = ZeroMalloc(sizeof(char *) * t->NumTokens);
	for (i = 0;i < t->NumTokens;i++)
	{
		t->Token[i] = LIST_DATA(o, i);
	}

	ReleaseList(o);

	if (keyname != NULL)
	{
		RegCloseKey(h);
	}

	return t;
}

bool MsRegWriteInt(UINT root, char *keyname, char *valuename, UINT value)
{
	return MsRegWriteIntEx2(root, keyname, valuename, value, false);
}
bool MsRegWriteIntEx2(UINT root, char *keyname, char *valuename, UINT value, bool force32bit)
{
	if (keyname == NULL)
	{
		return false;
	}

	return MsRegWriteValueEx2(root, keyname, valuename, REG_DWORD, &value, sizeof(UINT), force32bit);
}

bool MsRegWriteStr(UINT root, char *keyname, char *valuename, char *str)
{
	return MsRegWriteStrEx2(root, keyname, valuename, str, false);
}
bool MsRegWriteStrEx2(UINT root, char *keyname, char *valuename, char *str, bool force32bit)
{
	if (keyname == NULL || str == NULL)
	{
		return false;
	}

	return MsRegWriteValueEx2(root, keyname, valuename, REG_SZ, str, StrSize(str), force32bit);
}

bool MsRegWriteValueEx2(UINT root, char *keyname, char *valuename, UINT type, void *data, UINT size, bool force32bit)
{
	HKEY h;
	if (keyname == NULL || (size != 0 && data == NULL))
	{
		return false;
	}

	MsRegNewKeyEx2(root, keyname, force32bit);

	// RegSetValueEx needs KEY_SET_VALUE only
	if (RegOpenKeyEx(MsGetRootKeyFromInt(root), keyname, 0, KEY_SET_VALUE | MsRegViewMask(force32bit), &h) != ERROR_SUCCESS)
	{
		return false;
	}

	if (RegSetValueEx(h, valuename, 0, type, data, size) != ERROR_SUCCESS)
	{
		RegCloseKey(h);
		return false;
	}

	RegCloseKey(h);

	return true;
}

// Read a value into a new buffer (*data, freed by the caller), with its type and size in bytes: through
// RegQueryValueExW when wide (the data of a string value is then UTF-16), else RegQueryValueExA
static bool MsRegReadValueCore(UINT root, char *keyname, char *valuename, void **data, DWORD *type, DWORD *size, bool force32bit, bool wide)
{
	HKEY h;
	UINT ret;
	wchar_t *valuename_w = NULL;
	if (keyname == NULL || data == NULL || type == NULL || size == NULL)
	{
		return false;
	}
	*type = 0;
	*size = 0;

	if (RegOpenKeyEx(MsGetRootKeyFromInt(root), keyname, 0, KEY_QUERY_VALUE | MsRegViewMask(force32bit), &h) != ERROR_SUCCESS)
	{
		return false;
	}

	if (wide)
	{
		valuename_w = CopyStrToUni(valuename);
	}

	*data = ZeroMalloc(*size);
	ret = wide ? RegQueryValueExW(h, valuename_w, 0, type, *data, size) : RegQueryValueEx(h, valuename, 0, type, *data, size);

	if (ret == ERROR_MORE_DATA)
	{
		// Again with the size the first query gave
		*data = ReAlloc(*data, *size);
		ret = wide ? RegQueryValueExW(h, valuename_w, 0, type, *data, size) : RegQueryValueEx(h, valuename, 0, type, *data, size);
	}

	Free(valuename_w);

	RegCloseKey(h);

	if (ret != ERROR_SUCCESS)
	{
		// Also when the value grew or went away between the two queries: no data, no success
		Free(*data);
		*data = NULL;
		return false;
	}

	return true;
}

UINT MsRegReadInt(UINT root, char *keyname, char *valuename)
{
	return MsRegReadIntEx2(root, keyname, valuename, false);
}
UINT MsRegReadIntEx2(UINT root, char *keyname, char *valuename, bool force32bit)
{
	char *ret;
	DWORD type, size;
	UINT value;
	if (keyname == NULL || valuename == NULL)
	{
		return 0;
	}

	if (MsRegReadValueCore(root, keyname, valuename, (void **)&ret, &type, &size, force32bit, false) == false)
	{
		return 0;
	}

	if (type != REG_DWORD && type != REG_DWORD_BIG_ENDIAN)
	{
		Free(ret);
		return 0;
	}

	if (size != sizeof(UINT))
	{
		Free(ret);
		return 0;
	}

	Copy(&value, ret, sizeof(UINT));

	Free(ret);

	// The host is little-endian: only a REG_DWORD_BIG_ENDIAN value needs a swap
	if (type == REG_DWORD_BIG_ENDIAN)
	{
		value = Endian32(value);
	}

	return value;
}

char *MsRegReadStr(UINT root, char *keyname, char *valuename)
{
	return MsRegReadStrEx2(root, keyname, valuename, false);
}
char *MsRegReadStrEx2(UINT root, char *keyname, char *valuename, bool force32bit)
{
	char *ret;
	DWORD type, size;
	if (keyname == NULL || valuename == NULL)
	{
		return NULL;
	}

	if (MsRegReadValueCore(root, keyname, valuename, (void **)&ret, &type, &size, force32bit, false) == false)
	{
		return NULL;
	}

	// A REG_MULTI_SZ reads as its first string: the buffer ends with a terminator (checked below)
	// and the first string ends at its first one
	if (type != REG_SZ && type != REG_EXPAND_SZ && type != REG_MULTI_SZ)
	{
		Free(ret);
		return NULL;
	}

	if (size == 0)
	{
		Free(ret);

		return CopyStr("");
	}

	if (ret[size - 1] != 0)
	{
		Free(ret);
		return NULL;
	}

	return ret;
}
wchar_t *MsRegReadStrEx2W(UINT root, char *keyname, char *valuename, bool force32bit)
{
	wchar_t *ret;
	DWORD type, size;
	if (keyname == NULL || valuename == NULL)
	{
		return NULL;
	}

	if (MsRegReadValueCore(root, keyname, valuename, (void **)&ret, &type, &size, force32bit, true) == false)
	{
		return NULL;
	}

	if (type != REG_SZ && type != REG_EXPAND_SZ)
	{
		Free(ret);

		return NULL;
	}

	if (size < sizeof(wchar_t))
	{
		// An empty value, or one byte: no whole character, and no last character to test below
		Free(ret);

		return CopyUniStr(L"");
	}

	if (ret[size / sizeof(wchar_t) - 1] != 0)
	{
		Free(ret);
		return NULL;
	}

	return ret;
}

bool MsRegIsValue(UINT root, char *keyname, char *valuename)
{
	return MsRegIsValueEx2(root, keyname, valuename, false);
}
bool MsRegIsValueEx2(UINT root, char *keyname, char *valuename, bool force32bit)
{
	HKEY h;
	DWORD type, size;
	UINT ret;
	if (keyname == NULL)
	{
		return false;
	}

	if (RegOpenKeyEx(MsGetRootKeyFromInt(root), keyname, 0, KEY_QUERY_VALUE | MsRegViewMask(force32bit), &h) != ERROR_SUCCESS)
	{
		return false;
	}

	size = 0;
	ret = RegQueryValueEx(h, valuename, 0, &type, NULL, &size);

	if (ret == ERROR_SUCCESS || ret == ERROR_MORE_DATA)
	{
		RegCloseKey(h);
		return true;
	}

	RegCloseKey(h);

	return false;
}

bool MsRegNewKeyEx2(UINT root, char *keyname, bool force32bit)
{
	HKEY h;
	if (keyname == NULL)
	{
		return false;
	}

	if (MsRegIsKeyEx2(root, keyname, force32bit))
	{
		return true;
	}

	// The handle is closed at once, so it asks for little. Creating the key needs KEY_CREATE_SUB_KEY
	// on the parent key, which RegCreateKeyEx checks by itself.
	if (RegCreateKeyEx(MsGetRootKeyFromInt(root), keyname, 0, NULL, REG_OPTION_NON_VOLATILE,
		KEY_QUERY_VALUE | MsRegViewMask(force32bit), NULL, &h, NULL) != ERROR_SUCCESS)
	{
		return false;
	}

	RegCloseKey(h);

	return true;
}

bool MsRegIsKeyEx2(UINT root, char *name, bool force32bit)
{
	HKEY h;
	if (name == NULL)
	{
		return false;
	}

	if (RegOpenKeyEx(MsGetRootKeyFromInt(root), name, 0, KEY_READ | MsRegViewMask(force32bit), &h) != ERROR_SUCCESS)
	{
		return false;
	}

	RegCloseKey(h);

	return true;
}

HKEY MsGetRootKeyFromInt(UINT root)
{
	switch (root)
	{
	case REG_CLASSES_ROOT:
		return HKEY_CLASSES_ROOT;

	case REG_LOCAL_MACHINE:
		return HKEY_LOCAL_MACHINE;

	case REG_CURRENT_USER:
		return HKEY_CURRENT_USER;

	case REG_USERS:
		return HKEY_USERS;
	}

	return NULL;
}
