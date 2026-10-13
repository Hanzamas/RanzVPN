// SoftEther VPN Source Code - Developer Edition Master Branch
// Mayaqua Kernel


// MicrosoftReg.c
// Windows registry (MsReg*)

#ifdef OS_WIN32

#define	MICROSOFT_C

#include "Microsoft.h"

#include "Cfg.h"
#include "FileIO.h"
#include "GlobalConst.h"
#include "Internat.h"
#include "Memory.h"
#include "Object.h"
#include "Str.h"
#include "Table.h"
#include "Tick64.h"
#include "Win32.h"

#define SECURITY_WIN32

#include <AclAPI.h>
#include <DbgHelp.h>
#include <dwmapi.h>
#include <iphlpapi.h>
#include <mmsystem.h>
#include <Msi.h>
#include <nb30.h>
#include <NTSecAPI.h>
#include <Psapi.h>
#include <sddl.h>
#include <security.h>
#include <shellapi.h>
#include <ShlObj.h>
#include <SoftPub.h>
#include <WtsApi32.h>

// Generate an access mask to force accessing to the 32 bit registry key for 64 bit application
UINT MsRegAccessMaskFor64BitEx(bool force32bit, bool force64bit)
{
	if (MsIs64BitWindows() == false)
	{
		return 0;
	}
	if (force32bit)
	{
		return KEY_WOW64_32KEY;
	}
	if (force64bit)
	{
		return KEY_WOW64_64KEY;
	}

	return 0;
}

// Load the hive
bool MsRegLoadHive(UINT root, wchar_t *keyname, wchar_t *filename)
{
	LONG ret;
	if (keyname == NULL || filename == NULL)
	{
		WHERE;
		return false;
	}
	ret = RegLoadKeyW(MsGetRootKeyFromInt(root), keyname, filename);

	if (ret != ERROR_SUCCESS)
	{
		Debug("RegLoadKeyW: %S %S %u\n", keyname, filename, GetLastError());
		return false;
	}
	WHERE;

	return true;
}

// Delete the value
bool MsRegDeleteValue(UINT root, char *keyname, char *valuename)
{
	return MsRegDeleteValueEx(root, keyname, valuename, false);
}

bool MsRegDeleteValueEx(UINT root, char *keyname, char *valuename, bool force32bit)
{
	return MsRegDeleteValueEx2(root, keyname, valuename, force32bit, false);
}

bool MsRegDeleteValueEx2(UINT root, char *keyname, char *valuename, bool force32bit, bool force64bit)
{
	HKEY h;
	bool ret;
	// Validate arguments
	if (keyname == NULL)
	{
		return false;
	}

	if (RegOpenKeyEx(MsGetRootKeyFromInt(root), keyname, 0, KEY_ALL_ACCESS | MsRegAccessMaskFor64BitEx(force32bit, force64bit), &h) != ERROR_SUCCESS)
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

// Delete the key
bool MsRegDeleteKey(UINT root, char *keyname)
{
	return MsRegDeleteKeyEx(root, keyname, false);
}

bool MsRegDeleteKeyEx(UINT root, char *keyname, bool force32bit)
{
	return MsRegDeleteKeyEx2(root, keyname, force32bit, false);
}

bool MsRegDeleteKeyEx2(UINT root, char *keyname, bool force32bit, bool force64bit)
{
	// Validate arguments
	if (keyname == NULL)
	{
		return false;
	}

	if (RegDeleteKeyExA(MsGetRootKeyFromInt(root), keyname, MsRegAccessMaskFor64BitEx(force32bit, force64bit), 0) != ERROR_SUCCESS)
	{
		return false;
	}

	return true;
}

// Enumeration of the keys
TOKEN_LIST *MsRegEnumKey(UINT root, char *keyname)
{
	return MsRegEnumKeyEx(root, keyname, false);
}

TOKEN_LIST *MsRegEnumKeyEx(UINT root, char *keyname, bool force32bit)
{
	return MsRegEnumKeyEx2(root, keyname, force32bit, false);
}

TOKEN_LIST *MsRegEnumKeyEx2(UINT root, char *keyname, bool force32bit, bool force64bit)
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
		if (RegOpenKeyEx(MsGetRootKeyFromInt(root), keyname, 0, KEY_READ | MsRegAccessMaskFor64BitEx(force32bit, force64bit), &h) != ERROR_SUCCESS)
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

// Set the integer value
bool MsRegWriteInt(UINT root, char *keyname, char *valuename, UINT value)
{
	return MsRegWriteIntEx(root, keyname, valuename, value, false);
}

bool MsRegWriteIntEx(UINT root, char *keyname, char *valuename, UINT value, bool force32bit)
{
	return MsRegWriteIntEx2(root, keyname, valuename, value, force32bit, false);
}

bool MsRegWriteIntEx2(UINT root, char *keyname, char *valuename, UINT value, bool force32bit, bool force64bit)
{
	// Validate arguments
	if (keyname == NULL)
	{
		return false;
	}

	// Endian correction
	if (IsBigEndian())
	{
		value = Swap32(value);
	}

	return MsRegWriteValueEx2(root, keyname, valuename, REG_DWORD_LITTLE_ENDIAN, &value, sizeof(UINT), force32bit, force64bit);
}

bool MsRegWriteStr(UINT root, char *keyname, char *valuename, char *str)
{
	return MsRegWriteStrEx(root, keyname, valuename, str, false);
}

bool MsRegWriteStrEx(UINT root, char *keyname, char *valuename, char *str, bool force32bit)
{
	return MsRegWriteStrEx2(root, keyname, valuename, str, force32bit, false);
}

bool MsRegWriteStrEx2(UINT root, char *keyname, char *valuename, char *str, bool force32bit, bool force64bit)
{
	// Validate arguments
	if (keyname == NULL || str == NULL)
	{
		return false;
	}

	return MsRegWriteValueEx2(root, keyname, valuename, REG_SZ, str, StrSize(str), force32bit, force64bit);
}

// Set the value
bool MsRegWriteValueEx2(UINT root, char *keyname, char *valuename, UINT type, void *data, UINT size, bool force32bit, bool force64bit)
{
	HKEY h;
	// Validate arguments
	if (keyname == NULL || (size != 0 && data == NULL))
	{
		return false;
	}

	// Create a key
	MsRegNewKeyEx2(root, keyname, force32bit, force64bit);

	// Open the key
	if (RegOpenKeyEx(MsGetRootKeyFromInt(root), keyname, 0, KEY_ALL_ACCESS | MsRegAccessMaskFor64BitEx(force32bit, force64bit), &h) != ERROR_SUCCESS)
	{
		return false;
	}

	// Write the value
	if (RegSetValueEx(h, valuename, 0, type, data, size) != ERROR_SUCCESS)
	{
		RegCloseKey(h);
		return false;
	}

	// Close the key
	RegCloseKey(h);

	return true;
}

// Get an integer value
UINT MsRegReadInt(UINT root, char *keyname, char *valuename)
{
	return MsRegReadIntEx(root, keyname, valuename, false);
}

UINT MsRegReadIntEx(UINT root, char *keyname, char *valuename, bool force32bit)
{
	return MsRegReadIntEx2(root, keyname, valuename, force32bit, false);
}

UINT MsRegReadIntEx2(UINT root, char *keyname, char *valuename, bool force32bit, bool force64bit)
{
	char *ret;
	DWORD type, size;
	UINT value;
	// Validate arguments
	if (keyname == NULL || valuename == NULL)
	{
		return 0;
	}

	// Read the value
	if (MsRegReadValueEx2(root, keyname, valuename, (void **)&ret, &type, &size, force32bit, force64bit) == false)
	{
		return 0;
	}

	// Check the type
	if (type != REG_DWORD_LITTLE_ENDIAN && type != REG_DWORD_BIG_ENDIAN)
	{
		// It is not a DWORD
		Free(ret);
		return 0;
	}

	// Check the size
	if (size != sizeof(UINT))
	{
		Free(ret);
		return 0;
	}

	Copy(&value, ret, sizeof(UINT));

	Free(ret);

	// Endian conversion
	if (IsLittleEndian())
	{
#ifdef	REG_DWORD_BIG_ENDIAN
		if (type == REG_DWORD_BIG_ENDIAN)
		{
			value = Swap32(value);
		}
#endif	// REG_DWORD_BIG_ENDIAN
	}
	else
	{
#ifdef	REG_DWORD_LITTLE_ENDIAN_FLAG
		if (type == REG_DWORD_LITTLE_ENDIAN_FLAG)
		{
			value = Swap32(value);
		}
#endif	// REG_DWORD_LITTLE_ENDIAN_FLAG
	}

	return value;
}

// Get a string list
LIST *MsRegReadStrList(UINT root, char *keyname, char *valuename)
{
	return MsRegReadStrListEx(root, keyname, valuename, false);
}

LIST *MsRegReadStrListEx(UINT root, char *keyname, char *valuename, bool force32bit)
{
	return MsRegReadStrListEx2(root, keyname, valuename, force32bit, false);
}

LIST *MsRegReadStrListEx2(UINT root, char *keyname, char *valuename, bool force32bit, bool force64bit)
{
	LIST *o;
	char *ret;
	DWORD type, size;
	// Validate arguments
	if (keyname == NULL || valuename == NULL)
	{
		return NULL;
	}

	// Read the value
	if (MsRegReadValueEx2(root, keyname, valuename, (void **)&ret, &type, &size, force32bit, force64bit) == false)
	{
		return NULL;
	}

	// Check the type
	if (type != REG_MULTI_SZ)
	{
		// It is not a string list
		Free(ret);
		return NULL;
	}

	if (size < 2)
	{
		// Invalid size
		Free(ret);
		return NULL;
	}

	if (ret[size - 1] != 0)
	{
		// Invalid data
		Free(ret);
		return NULL;
	}

	// Creating a list
	o = StrToStrList(ret, size);

	Free(ret);

	return o;
}

// Get a string
char *MsRegReadStr(UINT root, char *keyname, char *valuename)
{
	return MsRegReadStrEx(root, keyname, valuename, false);
}

char *MsRegReadStrEx(UINT root, char *keyname, char *valuename, bool force32bit)
{
	return MsRegReadStrEx2(root, keyname, valuename, force32bit, false);
}

char *MsRegReadStrEx2(UINT root, char *keyname, char *valuename, bool force32bit, bool force64bit)
{
	char *ret;
	DWORD type, size;
	// Validate arguments
	if (keyname == NULL || valuename == NULL)
	{
		return NULL;
	}

	// Read the value
	if (MsRegReadValueEx2(root, keyname, valuename, (void **)&ret, &type, &size, force32bit, force64bit) == false)
	{
		return NULL;
	}

	// Check the type
	if (type != REG_SZ && type != REG_EXPAND_SZ && type != REG_MULTI_SZ)
	{
		// It is not a string
		Free(ret);

		if (type == REG_MULTI_SZ)
		{
			// It is a string list
			LIST *o = MsRegReadStrList(root, keyname, valuename);
			if (o != NULL)
			{
				if (LIST_NUM(o) >= 1)
				{
					ret = CopyStr(LIST_DATA(o, 0));
					FreeStrList(o);
					return ret;
				}
			}
		}
		return NULL;
	}

	if (size == 0)
	{
		// Invalid size
		Free(ret);

		return CopyStr("");
	}

	if (ret[size - 1] != 0)
	{
		// Invalid data
		Free(ret);
		return NULL;
	}

	return ret;
}

wchar_t *MsRegReadStrW(UINT root, char *keyname, char *valuename)
{
	return MsRegReadStrExW(root, keyname, valuename, false);
}

wchar_t *MsRegReadStrExW(UINT root, char *keyname, char *valuename, bool force32bit)
{
	return MsRegReadStrEx2W(root, keyname, valuename, force32bit, false);
}

wchar_t *MsRegReadStrEx2W(UINT root, char *keyname, char *valuename, bool force32bit, bool force64bit)
{
	wchar_t *ret;
	DWORD type, size;
	// Validate arguments
	if (keyname == NULL || valuename == NULL)
	{
		return NULL;
	}

	// Read the value
	if (MsRegReadValueEx2W(root, keyname, valuename, (void **)&ret, &type, &size, force32bit, force64bit) == false)
	{
		return NULL;
	}

	// Check the type
	if (type != REG_SZ && type != REG_EXPAND_SZ)
	{
		// It is not a string
		Free(ret);

		return NULL;
	}

	if (ret[size / sizeof(wchar_t) - 1] != 0)
	{
		// Invalid data
		Free(ret);
		return NULL;
	}

	return ret;
}

// Read the value
bool MsRegReadValueEx2(UINT root, char *keyname, char *valuename, void **data, DWORD *type, DWORD *size, bool force32bit, bool force64bit)
{
	HKEY h;
	UINT ret;
	// Validate arguments
	if (keyname == NULL || data == NULL || type == NULL || size == NULL)
	{
		return false;
	}
	*type = 0;
	*size = 0;

	// Open the key
	if (RegOpenKeyEx(MsGetRootKeyFromInt(root), keyname, 0, KEY_READ | MsRegAccessMaskFor64BitEx(force32bit, force64bit), &h) != ERROR_SUCCESS)
	{
		return false;
	}

	// Open up the value
	*data = ZeroMalloc(*size);
	ret = RegQueryValueEx(h, valuename, 0, type, *data, size);

	if (ret == ERROR_SUCCESS)
	{
		// Reading is complete
		RegCloseKey(h);
		return true;
	}

	if (ret != ERROR_MORE_DATA)
	{
		// Strange error occurs
		Free(*data);
		*data = NULL;
		RegCloseKey(h);
		return false;
	}

	// Get the data by re-allocating memory
	*data = ReAlloc(*data, *size);
	ret = RegQueryValueEx(h, valuename, 0, type, *data, size);
	if (ret != ERROR_SUCCESS)
	{
		// An error has occured
		Free(*data);
		*data = NULL;
		RegCloseKey(h);
	}

	RegCloseKey(h);

	return true;
}

bool MsRegReadValueEx2W(UINT root, char *keyname, char *valuename, void **data, DWORD *type, DWORD *size, bool force32bit, bool force64bit)
{
	HKEY h;
	UINT ret;
	wchar_t *valuename_w;
	// Validate arguments
	if (keyname == NULL || data == NULL || type == NULL || size == NULL)
	{
		return false;
	}
	*type = 0;
	*size = 0;

	// Open the key
	if (RegOpenKeyEx(MsGetRootKeyFromInt(root), keyname, 0, KEY_READ | MsRegAccessMaskFor64BitEx(force32bit, force64bit), &h) != ERROR_SUCCESS)
	{
		return false;
	}

	valuename_w = CopyStrToUni(valuename);

	// Open up the value
	*data = ZeroMalloc(*size);
	ret = RegQueryValueExW(h, valuename_w, 0, type, *data, size);

	if (ret == ERROR_SUCCESS)
	{
		// Reading is complete
		RegCloseKey(h);
		Free(valuename_w);
		return true;
	}

	if (ret != ERROR_MORE_DATA)
	{
		// Strange error occurs
		Free(*data);
		*data = NULL;
		Free(valuename_w);
		RegCloseKey(h);
		return false;
	}

	// Get the data by re-allocating memory
	*data = ReAlloc(*data, *size);
	ret = RegQueryValueExW(h, valuename_w, 0, type, *data, size);
	if (ret != ERROR_SUCCESS)
	{
		// An error has occured
		Free(*data);
		*data = NULL;
		Free(valuename_w);
		RegCloseKey(h);
	}

	Free(valuename_w);

	RegCloseKey(h);

	return true;
}

// Confirm that the specified value exists on the registry
bool MsRegIsValue(UINT root, char *keyname, char *valuename)
{
	return MsRegIsValueEx(root, keyname, valuename, false);
}

bool MsRegIsValueEx(UINT root, char *keyname, char *valuename, bool force32bit)
{
	return MsRegIsValueEx2(root, keyname, valuename, force32bit, false);
}

bool MsRegIsValueEx2(UINT root, char *keyname, char *valuename, bool force32bit, bool force64bit)
{
	HKEY h;
	DWORD type, size;
	UINT ret;
	// Validate arguments
	if (keyname == NULL)
	{
		return false;
	}

	// Open the key
	if (RegOpenKeyEx(MsGetRootKeyFromInt(root), keyname, 0, KEY_READ | MsRegAccessMaskFor64BitEx(force32bit, force64bit), &h) != ERROR_SUCCESS)
	{
		return false;
	}

	// Open up the value
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

// Create a key in the registry
bool MsRegNewKeyEx2(UINT root, char *keyname, bool force32bit, bool force64bit)
{
	HKEY h;
	// Validate arguments
	if (keyname == NULL)
	{
		return false;
	}

	// Confirm whether there is the key  
	if (MsRegIsKeyEx2(root, keyname, force32bit, force64bit))
	{
		// Already exists
		return true;
	}

	// Create a key
	if (RegCreateKeyEx(MsGetRootKeyFromInt(root), keyname, 0, NULL, REG_OPTION_NON_VOLATILE,
		KEY_ALL_ACCESS | MsRegAccessMaskFor64BitEx(force32bit, force64bit), NULL, &h, NULL) != ERROR_SUCCESS)
	{
		// Failed
		return false;
	}

	RegCloseKey(h);

	return true;
}

// Confirm the specified key exists on the registry
bool MsRegIsKeyEx2(UINT root, char *name, bool force32bit, bool force64bit)
{
	HKEY h;
	// Validate arguments
	if (name == NULL)
	{
		return false;
	}

	if (RegOpenKeyEx(MsGetRootKeyFromInt(root), name, 0, KEY_READ | MsRegAccessMaskFor64BitEx(force32bit, force64bit), &h) != ERROR_SUCCESS)
	{
		return false;
	}

	RegCloseKey(h);

	return true;
}

// Getting root key handle
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

#endif	// WIN32

