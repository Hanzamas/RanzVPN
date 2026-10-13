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

// Access mask that forces the 32-bit or 64-bit registry view
UINT MsRegAccessMaskFor64BitEx(bool force32bit, bool force64bit)
{
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

bool MsRegLoadHive(UINT root, wchar_t *keyname, wchar_t *filename)
{
	LONG ret;
	if (keyname == NULL || filename == NULL)
	{
		return false;
	}
	ret = RegLoadKeyW(MsGetRootKeyFromInt(root), keyname, filename);

	if (ret != ERROR_SUCCESS)
	{
		return false;
	}

	return true;
}

bool MsRegDeleteValue(UINT root, char *keyname, char *valuename)
{
	return MsRegDeleteValueEx2(root, keyname, valuename, false, false);
}

bool MsRegDeleteValueEx2(UINT root, char *keyname, char *valuename, bool force32bit, bool force64bit)
{
	HKEY h;
	bool ret;
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

bool MsRegDeleteKeyEx2(UINT root, char *keyname, bool force32bit, bool force64bit)
{
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

TOKEN_LIST *MsRegEnumKey(UINT root, char *keyname)
{
	return MsRegEnumKeyEx2(root, keyname, false, false);
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

bool MsRegWriteInt(UINT root, char *keyname, char *valuename, UINT value)
{
	return MsRegWriteIntEx2(root, keyname, valuename, value, false, false);
}

bool MsRegWriteIntEx2(UINT root, char *keyname, char *valuename, UINT value, bool force32bit, bool force64bit)
{
	if (keyname == NULL)
	{
		return false;
	}

	if (IsBigEndian())
	{
		value = Swap32(value);
	}

	return MsRegWriteValueEx2(root, keyname, valuename, REG_DWORD_LITTLE_ENDIAN, &value, sizeof(UINT), force32bit, force64bit);
}

bool MsRegWriteStr(UINT root, char *keyname, char *valuename, char *str)
{
	return MsRegWriteStrEx2(root, keyname, valuename, str, false, false);
}

bool MsRegWriteStrEx2(UINT root, char *keyname, char *valuename, char *str, bool force32bit, bool force64bit)
{
	if (keyname == NULL || str == NULL)
	{
		return false;
	}

	return MsRegWriteValueEx2(root, keyname, valuename, REG_SZ, str, StrSize(str), force32bit, force64bit);
}

bool MsRegWriteValueEx2(UINT root, char *keyname, char *valuename, UINT type, void *data, UINT size, bool force32bit, bool force64bit)
{
	HKEY h;
	if (keyname == NULL || (size != 0 && data == NULL))
	{
		return false;
	}

	MsRegNewKeyEx2(root, keyname, force32bit, force64bit);

	if (RegOpenKeyEx(MsGetRootKeyFromInt(root), keyname, 0, KEY_ALL_ACCESS | MsRegAccessMaskFor64BitEx(force32bit, force64bit), &h) != ERROR_SUCCESS)
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

UINT MsRegReadInt(UINT root, char *keyname, char *valuename)
{
	return MsRegReadIntEx2(root, keyname, valuename, false, false);
}

UINT MsRegReadIntEx2(UINT root, char *keyname, char *valuename, bool force32bit, bool force64bit)
{
	char *ret;
	DWORD type, size;
	UINT value;
	if (keyname == NULL || valuename == NULL)
	{
		return 0;
	}

	if (MsRegReadValueEx2(root, keyname, valuename, (void **)&ret, &type, &size, force32bit, force64bit) == false)
	{
		return 0;
	}

	if (type != REG_DWORD_LITTLE_ENDIAN && type != REG_DWORD_BIG_ENDIAN)
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

LIST *MsRegReadStrListEx2(UINT root, char *keyname, char *valuename, bool force32bit, bool force64bit)
{
	LIST *o;
	char *ret;
	DWORD type, size;
	if (keyname == NULL || valuename == NULL)
	{
		return NULL;
	}

	if (MsRegReadValueEx2(root, keyname, valuename, (void **)&ret, &type, &size, force32bit, force64bit) == false)
	{
		return NULL;
	}

	if (type != REG_MULTI_SZ)
	{
		Free(ret);
		return NULL;
	}

	if (size < 2)
	{
		Free(ret);
		return NULL;
	}

	if (ret[size - 1] != 0)
	{
		Free(ret);
		return NULL;
	}

	o = StrToStrList(ret, size);

	Free(ret);

	return o;
}

char *MsRegReadStr(UINT root, char *keyname, char *valuename)
{
	return MsRegReadStrEx2(root, keyname, valuename, false, false);
}

char *MsRegReadStrEx2(UINT root, char *keyname, char *valuename, bool force32bit, bool force64bit)
{
	char *ret;
	DWORD type, size;
	if (keyname == NULL || valuename == NULL)
	{
		return NULL;
	}

	if (MsRegReadValueEx2(root, keyname, valuename, (void **)&ret, &type, &size, force32bit, force64bit) == false)
	{
		return NULL;
	}

	if (type != REG_SZ && type != REG_EXPAND_SZ && type != REG_MULTI_SZ)
	{
		Free(ret);

		if (type == REG_MULTI_SZ)
		{
			LIST *o = MsRegReadStrListEx2(root, keyname, valuename, false, false);
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

wchar_t *MsRegReadStrEx2W(UINT root, char *keyname, char *valuename, bool force32bit, bool force64bit)
{
	wchar_t *ret;
	DWORD type, size;
	if (keyname == NULL || valuename == NULL)
	{
		return NULL;
	}

	if (MsRegReadValueEx2W(root, keyname, valuename, (void **)&ret, &type, &size, force32bit, force64bit) == false)
	{
		return NULL;
	}

	if (type != REG_SZ && type != REG_EXPAND_SZ)
	{
		Free(ret);

		return NULL;
	}

	if (ret[size / sizeof(wchar_t) - 1] != 0)
	{
		Free(ret);
		return NULL;
	}

	return ret;
}

bool MsRegReadValueEx2(UINT root, char *keyname, char *valuename, void **data, DWORD *type, DWORD *size, bool force32bit, bool force64bit)
{
	HKEY h;
	UINT ret;
	if (keyname == NULL || data == NULL || type == NULL || size == NULL)
	{
		return false;
	}
	*type = 0;
	*size = 0;

	if (RegOpenKeyEx(MsGetRootKeyFromInt(root), keyname, 0, KEY_READ | MsRegAccessMaskFor64BitEx(force32bit, force64bit), &h) != ERROR_SUCCESS)
	{
		return false;
	}

	*data = ZeroMalloc(*size);
	ret = RegQueryValueEx(h, valuename, 0, type, *data, size);

	if (ret == ERROR_SUCCESS)
	{
		RegCloseKey(h);
		return true;
	}

	if (ret != ERROR_MORE_DATA)
	{
		Free(*data);
		*data = NULL;
		RegCloseKey(h);
		return false;
	}

	*data = ReAlloc(*data, *size);
	ret = RegQueryValueEx(h, valuename, 0, type, *data, size);
	if (ret != ERROR_SUCCESS)
	{
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
	if (keyname == NULL || data == NULL || type == NULL || size == NULL)
	{
		return false;
	}
	*type = 0;
	*size = 0;

	if (RegOpenKeyEx(MsGetRootKeyFromInt(root), keyname, 0, KEY_READ | MsRegAccessMaskFor64BitEx(force32bit, force64bit), &h) != ERROR_SUCCESS)
	{
		return false;
	}

	valuename_w = CopyStrToUni(valuename);

	*data = ZeroMalloc(*size);
	ret = RegQueryValueExW(h, valuename_w, 0, type, *data, size);

	if (ret == ERROR_SUCCESS)
	{
		RegCloseKey(h);
		Free(valuename_w);
		return true;
	}

	if (ret != ERROR_MORE_DATA)
	{
		Free(*data);
		*data = NULL;
		Free(valuename_w);
		RegCloseKey(h);
		return false;
	}

	*data = ReAlloc(*data, *size);
	ret = RegQueryValueExW(h, valuename_w, 0, type, *data, size);
	if (ret != ERROR_SUCCESS)
	{
		Free(*data);
		*data = NULL;
		Free(valuename_w);
		RegCloseKey(h);
	}

	Free(valuename_w);

	RegCloseKey(h);

	return true;
}

bool MsRegIsValue(UINT root, char *keyname, char *valuename)
{
	return MsRegIsValueEx2(root, keyname, valuename, false, false);
}

bool MsRegIsValueEx2(UINT root, char *keyname, char *valuename, bool force32bit, bool force64bit)
{
	HKEY h;
	DWORD type, size;
	UINT ret;
	if (keyname == NULL)
	{
		return false;
	}

	if (RegOpenKeyEx(MsGetRootKeyFromInt(root), keyname, 0, KEY_READ | MsRegAccessMaskFor64BitEx(force32bit, force64bit), &h) != ERROR_SUCCESS)
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

bool MsRegNewKeyEx2(UINT root, char *keyname, bool force32bit, bool force64bit)
{
	HKEY h;
	if (keyname == NULL)
	{
		return false;
	}

	if (MsRegIsKeyEx2(root, keyname, force32bit, force64bit))
	{
		return true;
	}

	if (RegCreateKeyEx(MsGetRootKeyFromInt(root), keyname, 0, NULL, REG_OPTION_NON_VOLATILE,
		KEY_ALL_ACCESS | MsRegAccessMaskFor64BitEx(force32bit, force64bit), NULL, &h, NULL) != ERROR_SUCCESS)
	{
		return false;
	}

	RegCloseKey(h);

	return true;
}

bool MsRegIsKeyEx2(UINT root, char *name, bool force32bit, bool force64bit)
{
	HKEY h;
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

