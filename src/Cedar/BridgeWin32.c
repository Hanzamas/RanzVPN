// BridgeWin32.c
// Ethernet Bridge Program (Win32)

#define BRIDGE_C

#include "BridgeWin32.h"

#include "Admin.h"
#include "Connection.h"
#include "SeLowUser.h"

#include "Mayaqua/Cfg.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Tick64.h"

#include <Ws2tcpip.h>

static RPC_ENUM_ETH_VLAN_ITEM *FindEthVLanItem(RPC_ENUM_ETH_VLAN *t, char *name);
static ETH *OpenEthInternal(char *name, bool local, bool tapmode, char *tapaddr);
static void Win32EthMakeCombinedName(char *dst, UINT dst_size, char *nicname, char *guid);
static UINT Win32EthGenIdFromGuid(char *guid);
static TOKEN_LIST *GetEthListEx(UINT *total_num_including_hidden, bool enum_normal, bool enum_rawip);
static LIST *GetEthAdapterListInternal();
static void InitEthAdaptersList();
static void FreeEthAdaptersList();

static LIST *eth_list = NULL;

static LOCK *eth_list_lock = NULL;
static bool is_using_selow = false;
static bool enable_selow = true;

static bool g_bridge_win32_show_all_if = false;

void Win32SetEnableSeLow(bool b)
{
	enable_selow = b;
}

bool Win32GetEnableSeLow()
{
	return enable_selow;
}

void Win32EthSetShowAllIf(bool b)
{
	g_bridge_win32_show_all_if = b;
}

bool Win32EthGetShowAllIf()
{
	return g_bridge_win32_show_all_if;
}

static int CmpRpcEnumEthVLan(void *p1, void *p2)
{
	RPC_ENUM_ETH_VLAN_ITEM *v1, *v2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	v1 = *((RPC_ENUM_ETH_VLAN_ITEM **)p1);
	v2 = *((RPC_ENUM_ETH_VLAN_ITEM **)p2);
	if (v1 == NULL || v2 == NULL)
	{
		return 0;
	}

	return StrCmpi(v1->DeviceName, v2->DeviceName);
}

bool SetVLanEnableStatus(char *title, bool enable)
{
	RPC_ENUM_ETH_VLAN t;
	RPC_ENUM_ETH_VLAN_ITEM *e;
	bool ret = false;
	char key[MAX_SIZE];
	char tcpkey[MAX_SIZE];
	char short_key[MAX_SIZE];
	if (title == NULL)
	{
		return false;
	}

	Zero(&t, sizeof(t));
	if (EnumEthVLanWin32(&t) == false)
	{
		return false;
	}

	e = FindEthVLanItem(&t, title);

	if (e != NULL)
	{
		if (GetClassRegKeyWin32(key, sizeof(key), short_key, sizeof(short_key), e->Guid))
		{
			if (StrCmpi(e->DriverType, "Intel") == 0)
			{
				if (enable)
				{
					MsRegWriteStr(REG_LOCAL_MACHINE, key, "VlanFiltering", "0");
					MsRegWriteStr(REG_LOCAL_MACHINE, key, "TaggingMode", "0");
					MsRegWriteInt(REG_LOCAL_MACHINE, key, "MonitorMode", 1);
					MsRegWriteInt(REG_LOCAL_MACHINE, key, "MonitorModeEnabled", 1);
				}
				else
				{
					if (MsRegReadInt(REG_LOCAL_MACHINE, key, "TaggingMode") == 0)
					{
						MsRegDeleteValue(REG_LOCAL_MACHINE, key, "TaggingMode");
					}

					if (MsRegReadInt(REG_LOCAL_MACHINE, key, "MonitorMode") == 1)
					{
						MsRegDeleteValue(REG_LOCAL_MACHINE, key, "MonitorMode");
					}

					if (MsRegReadInt(REG_LOCAL_MACHINE, key, "MonitorModeEnabled") == 1)
					{
						MsRegDeleteValue(REG_LOCAL_MACHINE, key, "MonitorModeEnabled");
					}
				}

				ret = true;
			}
			else if (StrCmpi(e->DriverType, "Broadcom") == 0)
			{
				if (enable)
				{
					MsRegWriteStr(REG_LOCAL_MACHINE, key, "PreserveVlanInfoInRxPacket", "1");
				}
				else
				{
					MsRegDeleteValue(REG_LOCAL_MACHINE, key, "PreserveVlanInfoInRxPacket");
				}

				ret = true;
			}
			else if (StrCmpi(e->DriverType, "Marvell") == 0)
			{
				if (enable)
				{
					MsRegWriteInt(REG_LOCAL_MACHINE, key, "SkDisableVlanStrip", 1);
				}
				else
				{
					MsRegDeleteValue(REG_LOCAL_MACHINE, key, "SkDisableVlanStrip");
				}

				ret = true;
			}

			Format(tcpkey, sizeof(tcpkey),
				"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\%s",
				e->Guid);

			if (enable)
			{
				if (MsRegIsValue(REG_LOCAL_MACHINE, tcpkey, "MTU") == false)
				{
					MsRegWriteInt(REG_LOCAL_MACHINE, tcpkey, "MTU", 1500);
				}
			}
			else
			{
				UINT mtu = MsRegReadInt(REG_LOCAL_MACHINE, tcpkey, "MTU");
				if (mtu == 1500)
				{
					MsRegDeleteValue(REG_LOCAL_MACHINE, tcpkey, "MTU");
				}
			}
		}
	}

	FreeRpcEnumEthVLan(&t);

	return ret;
}

static RPC_ENUM_ETH_VLAN_ITEM *FindEthVLanItem(RPC_ENUM_ETH_VLAN *t, char *name)
{
	UINT i;
	if (t == NULL || name == NULL)
	{
		return NULL;
	}

	for (i = 0;i < t->NumItem;i++)
	{
		if (StrCmpi(t->Items[i].DeviceName, name) == 0)
		{
			return &t->Items[i];
		}
	}

	return NULL;
}

static void GetVLanEnableStatus(RPC_ENUM_ETH_VLAN_ITEM *e)
{
	char key[MAX_SIZE];
	char short_key[MAX_SIZE];
	char tcpkey[MAX_SIZE];
	if (e == NULL)
	{
		return;
	}

	e->Enabled = false;

	if (e->Support == false)
	{
		return;
	}

	if (GetClassRegKeyWin32(key, sizeof(key), short_key, sizeof(short_key), e->Guid) == false)
	{
		return;
	}

	Format(tcpkey, sizeof(tcpkey),
		"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\%s",
		e->Guid);

	if (StrCmpi(e->DriverType, "Intel") == 0)
	{
		char *VlanFiltering = MsRegReadStr(REG_LOCAL_MACHINE, key, "VlanFiltering");
		UINT MonitorMode = MsRegReadInt(REG_LOCAL_MACHINE, key, "MonitorMode");
		UINT MonitorModeEnabled = MsRegReadInt(REG_LOCAL_MACHINE, key, "MonitorModeEnabled");
		char *TaggingMode = MsRegReadStr(REG_LOCAL_MACHINE, key, "TaggingMode");

		if (StrCmpi(VlanFiltering, "0") == 0 &&
			MonitorMode == 1 &&
			MonitorModeEnabled == 1 &&
			StrCmpi(TaggingMode, "0") == 0)
		{
			e->Enabled = true;
		}

		Free(VlanFiltering);
		Free(TaggingMode);
	}
	else if (StrCmpi(e->DriverType, "Broadcom") == 0)
	{
		char *PreserveVlanInfoInRxPacket = MsRegReadStr(REG_LOCAL_MACHINE,
			key, "PreserveVlanInfoInRxPacket");

		if (StrCmpi(PreserveVlanInfoInRxPacket, "1") == 0)
		{
			e->Enabled = true;
		}

		Free(PreserveVlanInfoInRxPacket);
	}
	else if (StrCmpi(e->DriverType, "Marvell") == 0)
	{
		DWORD SkDisableVlanStrip = MsRegReadInt(REG_LOCAL_MACHINE,
			key, "SkDisableVlanStrip");

		if (SkDisableVlanStrip == 1)
		{
			e->Enabled = true;
		}
	}

	if (MsRegIsValue(REG_LOCAL_MACHINE, tcpkey, "MTU") == false)
	{
		e->Enabled = false;
	}
}

static void GetVLanSupportStatus(RPC_ENUM_ETH_VLAN_ITEM *e)
{
	BUF *b;
	char filename[MAX_SIZE];
	void *wow;
	if (e == NULL)
	{
		return;
	}

	wow = MsDisableWow64FileSystemRedirection();

	ConbinePath(filename, sizeof(filename), MsGetSystem32Dir(), "drivers");
	ConbinePath(filename, sizeof(filename), filename, e->DriverName);

	b = ReadDump(filename);

	if (b != NULL)
	{
		char intel1[] = "VlanFiltering";
		char intel2[] = "V\0l\0a\0n\0F\0i\0l\0t\0e\0r\0i\0n\0g";
		char intel3[] = "MonitorMode";
		char intel4[] = "M\0o\0n\0i\0t\0o\0r\0M\0o\0d\0e";
		char intel5[] = "TaggingMode";
		char intel6[] = "T\0a\0g\0g\0i\0n\0g\0M\0o\0d\0e";
		char broadcom1[] = "PreserveVlanInfoInRxPacket";
		char broadcom2[] = "P\0r\0e\0s\0e\0r\0v\0e\0V\0l\0a\0n\0I\0n\0f\0o\0I\0n\0R\0x\0P\0a\0c\0k\0e\0t";
		char marvell1[] = "SkDisableVlanStrip";
		char marvell2[] = "S\0k\0D\0i\0s\0a\0b\0l\0e\0V\0l\0a\0n\0S\0t\0r\0i\0p";
		char *driver_type = "";

		if (SearchBin(b->Buf, 0, b->Size, intel1, sizeof(intel1)) != INFINITE
			|| SearchBin(b->Buf, 0, b->Size, intel2, sizeof(intel2)) != INFINITE
			|| SearchBin(b->Buf, 0, b->Size, intel3, sizeof(intel3)) != INFINITE
			|| SearchBin(b->Buf, 0, b->Size, intel4, sizeof(intel4)) != INFINITE
			|| SearchBin(b->Buf, 0, b->Size, intel5, sizeof(intel5)) != INFINITE
			|| SearchBin(b->Buf, 0, b->Size, intel6, sizeof(intel6)) != INFINITE)
		{
			driver_type = "Intel";
		}
		else if (SearchBin(b->Buf, 0, b->Size, broadcom1, sizeof(broadcom1)) != INFINITE
			|| SearchBin(b->Buf, 0, b->Size, broadcom2, sizeof(broadcom2)) != INFINITE)
		{
			driver_type = "Broadcom";
		}
		else if (SearchBin(b->Buf, 0, b->Size, marvell1, sizeof(marvell1)) != INFINITE
			|| SearchBin(b->Buf, 0, b->Size, marvell2, sizeof(marvell2)) != INFINITE)
		{
			driver_type = "Marvell";
		}

		if (IsEmptyStr(driver_type) == false)
		{
			StrCpy(e->DriverType, sizeof(e->DriverType), driver_type);
			e->Support = true;
		}

		FreeBuf(b);
	}

	MsRestoreWow64FileSystemRedirection(wow);
}

static char *SearchDeviceInstanceIdFromShortKey(char *short_key)
{
	char *ret = NULL;
	TOKEN_LIST *t1;
	if (short_key == NULL)
	{
		return NULL;
	}

	t1 = MsRegEnumKey(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Enum");

	if (t1 != NULL)
	{
		TOKEN_LIST *t2;
		char tmp[MAX_SIZE];
		UINT i;

		for (i = 0;i < t1->NumTokens;i++)
		{
			Format(tmp, sizeof(tmp), "SYSTEM\\CurrentControlSet\\Enum\\%s", t1->Token[i]);

			t2 = MsRegEnumKey(REG_LOCAL_MACHINE, tmp);

			if (t2 != NULL)
			{
				TOKEN_LIST *t3;
				UINT i;

				for (i = 0;i < t2->NumTokens;i++)
				{
					char tmp2[MAX_SIZE];

					Format(tmp2, sizeof(tmp2), "%s\\%s", tmp, t2->Token[i]);

					t3 = MsRegEnumKey(REG_LOCAL_MACHINE, tmp2);

					if (t3 != NULL)
					{
						UINT i;

						for (i = 0;i < t3->NumTokens;i++)
						{
							char tmp3[MAX_SIZE];
							char *s;

							Format(tmp3, sizeof(tmp3), "%s\\%s", tmp2, t3->Token[i]);

							s = MsRegReadStr(REG_LOCAL_MACHINE, tmp3, "Driver");

							if (s != NULL)
							{
								if (StrCmpi(s, short_key) == 0)
								{
									if (ret != NULL)
									{
										Free(ret);
									}

									ret = CopyStr(tmp3 + StrLen("SYSTEM\\CurrentControlSet\\Enum\\"));
								}

								Free(s);
							}
						}

						FreeToken(t3);
					}
				}

				FreeToken(t2);
			}
		}

		FreeToken(t1);
	}

	return ret;
}

bool EnumEthVLanWin32(RPC_ENUM_ETH_VLAN *t)
{
	UINT i;
	LIST *o;
	if (t == NULL)
	{
		return false;
	}

	Zero(t, sizeof(RPC_ENUM_ETH_VLAN));

	if (Win32EthIsSuSupported() == false)
	{
		return false;
	}

	Lock(eth_list_lock);

	InitEthAdaptersList();

	o = NewListFast(CmpRpcEnumEthVLan);

	for (i = 0;i < LIST_NUM(eth_list);i++)
	{
		WP_ADAPTER *a = LIST_DATA(eth_list, i);

		if (IsEmptyStr(a->Guid) == false)
		{
			char class_key[MAX_SIZE];
			char short_key[MAX_SIZE];

			if (GetClassRegKeyWin32(class_key, sizeof(class_key),
				short_key, sizeof(short_key), a->Guid))
			{
				char *device_instance_id = MsRegReadStr(REG_LOCAL_MACHINE, class_key, "DeviceInstanceID");

				if (IsEmptyStr(device_instance_id))
				{
					Free(device_instance_id);
					device_instance_id = SearchDeviceInstanceIdFromShortKey(short_key);
				}

				if (IsEmptyStr(device_instance_id) == false)
				{
					char device_key[MAX_SIZE];
					char *service_name;

					Format(device_key, sizeof(device_key), "SYSTEM\\CurrentControlSet\\Enum\\%s",
						device_instance_id);

					service_name = MsRegReadStr(REG_LOCAL_MACHINE, device_key, "Service");
					if (IsEmptyStr(service_name) == false)
					{
						char service_key[MAX_SIZE];
						char *sys;

						Format(service_key, sizeof(service_key),
							"SYSTEM\\CurrentControlSet\\services\\%s",
							service_name);

						sys = MsRegReadStr(REG_LOCAL_MACHINE, service_key, "ImagePath");

						if (IsEmptyStr(sys) == false)
						{
							char sysname[MAX_PATH];

							GetFileNameFromFilePath(sysname, sizeof(sysname), sys);

							Trim(sysname);

							if (EndWith(sysname, ".sys"))
							{
								RPC_ENUM_ETH_VLAN_ITEM *e = ZeroMalloc(sizeof(RPC_ENUM_ETH_VLAN_ITEM));

								StrCpy(e->DeviceName, sizeof(e->DeviceName), a->Title);
								StrCpy(e->Guid, sizeof(e->Guid), a->Guid);
								StrCpy(e->DeviceInstanceId, sizeof(e->DeviceInstanceId), device_instance_id);
								StrCpy(e->DriverName, sizeof(e->DriverName), sysname);

								GetVLanSupportStatus(e);

								GetVLanEnableStatus(e);

								Insert(o, e);
							}
						}

						Free(sys);
					}

					Free(service_name);
				}

				Free(device_instance_id);
			}
		}
	}

	t->NumItem = LIST_NUM(o);
	t->Items = ZeroMalloc(sizeof(RPC_ENUM_ETH_VLAN_ITEM) * i);

	for (i = 0;i < LIST_NUM(o);i++)
	{
		RPC_ENUM_ETH_VLAN_ITEM *e = LIST_DATA(o, i);

		Copy(&t->Items[i], e, sizeof(RPC_ENUM_ETH_VLAN_ITEM));

		Free(e);
	}

	ReleaseList(o);

	Unlock(eth_list_lock);

	return true;
}

bool GetClassRegKeyWin32(char *key, UINT key_size, char *short_key, UINT short_key_size, char *guid)
{
	TOKEN_LIST *t;
	bool ret = false;
	UINT i;
	if (key == NULL || short_key == NULL || guid == NULL)
	{
		return false;
	}

	t = MsRegEnumKey(REG_LOCAL_MACHINE,
		"SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}");
	if (t == NULL)
	{
		return false;
	}

	for (i = 0;i < t->NumTokens;i++)
	{
		char keyname[MAX_SIZE];
		char *value;

		Format(keyname, sizeof(keyname),
			"SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\%s",
			t->Token[i]);

		value = MsRegReadStr(REG_LOCAL_MACHINE, keyname, "NetCfgInstanceId");

		if (StrCmpi(value, guid) == 0)
		{
			ret = true;

			StrCpy(key, key_size, keyname);

			Format(short_key, short_key_size, "{4D36E972-E325-11CE-BFC1-08002BE10318}\\%s",
				t->Token[i]);
		}

		Free(value);
	}

	FreeToken(t);

	return ret;
}

void EthPutPackets(ETH *e, UINT num, void **datas, UINT *sizes)
{
	UINT i;
	bool ok = true;
	if (e == NULL || num == 0 || datas == NULL || sizes == NULL)
	{
		return;
	}
	if (e->HasFatalError)
	{
		return;
	}

	for (i = 0;i < num;i++)
	{
		UCHAR *data = datas[i];
		UINT size = sizes[i];

		if (ok)
		{
			ok = SuPutPacket(e->SuAdapter, data, size);
		}

		if (ok == false)
		{
			Free(data);
		}
	}

	if (ok)
	{
		ok = SuPutPacket(e->SuAdapter, NULL, 0);
	}

	if (ok == false)
	{
		e->HasFatalError = true;
	}
}

UINT EthGetPacket(ETH *e, void **data)
{
	UINT size;
	if (e == NULL || data == NULL)
	{
		return INFINITE;
	}
	if (e->HasFatalError)
	{
		return INFINITE;
	}

	if (SuGetNextPacket(e->SuAdapter, data, &size) == false)
	{
		e->HasFatalError = true;
		return INFINITE;
	}

	return size;
}

// Frames EthGetPacket can return without waiting for the cancel event
bool EthHasPendingFrames(ETH *e)
{
	if (e == NULL || e->HasFatalError)
	{
		return false;
	}

	return SuHasPendingPackets(e->SuAdapter);
}

CANCEL *EthGetCancel(ETH *e)
{
	if (e == NULL)
	{
		return NULL;
	}

	AddRef(e->Cancel->ref);

	return e->Cancel;
}

void CloseEth(ETH *e)
{
	if (e == NULL)
	{
		return;
	}

	ReleaseCancel(e->Cancel);

	SuCloseAdapter(e->SuAdapter);
	SuFree(e->Su);

	Free(e->Name);
	Free(e->Title);

	Free(e);
}

static struct WP_ADAPTER *Win32EthSearch(char *name)
{
	UINT i;
	UINT id;
	char simple_name[MAX_SIZE];
	WP_ADAPTER *ret = NULL;

	id = Win32EthGetNameAndIdFromCombinedName(simple_name, sizeof(simple_name), name);

	if (id != 0)
	{
		UINT num_match = 0;
		for (i = 0;i < LIST_NUM(eth_list);i++)
		{
			WP_ADAPTER *a = LIST_DATA(eth_list, i);

			if (a->Id != 0 && a->Id == id)
			{
				ret = a;
				num_match++;
			}
		}

		if (num_match >= 2)
		{
			for (i = 0;i < LIST_NUM(eth_list);i++)
			{
				WP_ADAPTER *a = LIST_DATA(eth_list, i);

				if (a->Id != 0 && a->Id == id)
				{
					if (StrCmpi(a->Title, name) == 0)
					{
						ret = a;
						break;
					}
				}
			}
		}
	}
	else
	{
		for (i = 0;i < LIST_NUM(eth_list);i++)
		{
			WP_ADAPTER *a = LIST_DATA(eth_list, i);

			if (StrCmpi(a->Title, name) == 0)
			{
				ret = a;
				break;
			}
		}
	}

	return ret;
}

ETH *OpenEth(char *name, bool local, bool tapmode, char *tapaddr)
{
	ETH *ret;
	void *p;

	p = MsDisableWow64FileSystemRedirection();

	ret = OpenEthInternal(name, local, tapmode, tapaddr);

	MsRestoreWow64FileSystemRedirection(p);

	return ret;
}
static ETH *OpenEthInternal(char *name, bool local, bool tapmode, char *tapaddr)
{
	WP_ADAPTER *t;
	ETH *e;
	HANDLE h;
	CANCEL *c;
	char name_with_id[MAX_SIZE];
	SU *su = NULL;
	SU_ADAPTER *su_adapter = NULL;
	if (name == NULL || Win32EthInstallSu() == false)
	{
		return NULL;
	}

	if (tapmode)
	{
		return NULL;
	}

	Lock(eth_list_lock);

	InitEthAdaptersList();

	t = Win32EthSearch(name);

	if (t == NULL)
	{
		Unlock(eth_list_lock);
		return NULL;
	}

	su = SuInitEx(0);
	if (su == NULL)
	{
		Unlock(eth_list_lock);
		return NULL;
	}

	su_adapter = SuOpenAdapter(su, t->Name);

	if (su_adapter == NULL)
	{
		SuFree(su);
		Unlock(eth_list_lock);
		return NULL;
	}

	is_using_selow = true;

	e = ZeroMalloc(sizeof(ETH));
	e->Name = CopyStr(t->Name);

	Win32EthMakeCombinedName(name_with_id, sizeof(name_with_id), t->Title, t->Guid);
	e->Title = CopyStr(name_with_id);

	e->SuAdapter = su_adapter;
	e->Su = su;

	h = e->SuAdapter->hEvent;

	c = NewCancelSpecial(h);
	e->Cancel = c;

	Copy(e->MacAddress, t->MacAddress, sizeof(e->MacAddress));

	Unlock(eth_list_lock);

	return e;
}

static void Win32EthMakeCombinedName(char *dst, UINT dst_size, char *nicname, char *guid)
{
	if (dst == NULL || nicname == NULL || guid == NULL)
	{
		return;
	}

	if (IsEmptyStr(guid) == false)
	{
		Format(dst, dst_size, "%s(ID=%010u)", nicname, Win32EthGenIdFromGuid(guid));
	}
	else
	{
		StrCpy(dst, dst_size, nicname);
	}
}

UINT Win32EthGetNameAndIdFromCombinedName(char *name, UINT name_size, char *str)
{
	UINT ret = 0;
	char id_str[MAX_SIZE];
	UINT len;
	ClearStr(name, name_size);
	StrCpy(name, name_size, str);
	if (name == NULL || str == NULL)
	{
		return 0;
	}

	len = StrLen(str);

	if (len >= 15)
	{
		StrCpy(id_str, sizeof(id_str), str + len - 15);

		if (StartWith(id_str, "(ID="))
		{
			if (EndWith(id_str, ")"))
			{
				char num[MAX_SIZE];

				Zero(num, sizeof(num));
				StrCpy(num, sizeof(num), id_str + 4);

				num[StrLen(num) - 1] = 0;

				ret = ToInt(num);

				if (ret != 0)
				{
					name[len - 15] = 0;
				}
			}
		}
	}

	return ret;
}

static UINT Win32EthGenIdFromGuid(char *guid)
{
	char tmp[MAX_SIZE];
	UCHAR hash[SHA1_SIZE];
	UINT i;
	if (guid == NULL)
	{
		return 0;
	}

	StrCpy(tmp, sizeof(tmp), guid);
	Trim(tmp);
	StrUpper(tmp);

	Sha1(hash, tmp, StrLen(tmp));

	Copy(&i, hash, sizeof(UINT));

	i = Endian32(i);

	if (i == 0)
	{
		i = 1;
	}

	return i;
}

TOKEN_LIST *GetEthList()
{
	UINT v;

	return GetEthListEx(&v, true, false);
}
static TOKEN_LIST *GetEthListEx(UINT *total_num_including_hidden, bool enum_normal, bool enum_rawip)
{
	TOKEN_LIST *ret;
	UINT i;
	UINT j;
	UINT dummy_int;
	MS_ADAPTER_LIST *adapter_list;

	// Listing the devices for a Local Bridge is the first step of creating one: install SeLow when needed
	if (Win32EthInstallSu() == false)
	{
		return NULL;
	}

	if (enum_normal == false)
	{
		return NullToken();
	}

	if (total_num_including_hidden == NULL)
	{
		total_num_including_hidden = &dummy_int;
	}

	*total_num_including_hidden = 0;

	Lock(eth_list_lock);

	InitEthAdaptersList();

	adapter_list = MsCreateAdapterList();

	ret = ZeroMalloc(sizeof(TOKEN_LIST));
	ret->NumTokens = LIST_NUM(eth_list);
	ret->Token = ZeroMalloc(sizeof(char *) * ret->NumTokens);
	j = 0;
	for (i = 0;i < ret->NumTokens;i++)
	{
		char tmp[MAX_SIZE];
		WP_ADAPTER *a = LIST_DATA(eth_list, i);
		MS_ADAPTER *msa = NULL;
		bool show = true;

		if (Win32EthGetShowAllIf() == false)
		{
			msa = MsGetAdapterByGuidFromList(adapter_list, a->Guid);

			if (InStr(a->Title, "vpn client adapter"))
			{
				show = false;
			}

			if (InStr(a->Title, "tunnel adapter"))
			{
				show = false;
			}

			if (InStr(a->Title, "teredo tunnel"))
			{
				show = false;
			}

			if (InStr(a->Title, "MS Tunnel Interface"))
			{
				show = false;
			}

			if (InStr(a->Title, "pseudo-interface"))
			{
				show = false;
			}
		}

		if (msa != NULL)
		{
			if (msa->IsNotEthernetLan)
			{
				show = false;
			}

			MsFreeAdapter(msa);
		}

		Win32EthMakeCombinedName(tmp, sizeof(tmp), a->Title, a->Guid);

		if (show)
		{
			ret->Token[j++] = CopyStr(tmp);
		}
	}

	*total_num_including_hidden = ret->NumTokens;

	ret->NumTokens = j;

	Unlock(eth_list_lock);

	MsFreeAdapterList(adapter_list);

	return ret;
}

static int CompareWpAdapter(void *p1, void *p2)
{
	int i;
	WP_ADAPTER *a1, *a2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	a1 = *(WP_ADAPTER **)p1;
	a2 = *(WP_ADAPTER **)p2;
	if (a1 == NULL || a2 == NULL)
	{
		return 0;
	}
	i = StrCmpi(a1->Title, a2->Title);
	return i;
}

bool Win32IsUsingSeLow()
{
	return is_using_selow;
}

static LIST *GetEthAdapterList()
{
	void *p;
	LIST *o;

	p = MsDisableWow64FileSystemRedirection();

	o = GetEthAdapterListInternal();

	MsRestoreWow64FileSystemRedirection(p);

	return o;
}
static LIST *GetEthAdapterListInternal()
{
	LIST *o;
	LIST *ret;
	UINT i, j;
	char *qos_tag = "(Microsoft's Packet Scheduler)";
	SU *su = NULL;
	LIST *su_adapter_list = NULL;

	if (enable_selow)
	{
		su = SuInitEx(0);
	}

	o = NewListFast(CompareWpAdapter);

	if (su != NULL)
	{
		su_adapter_list = SuGetAdapterList(su);

		if (su_adapter_list == NULL)
		{
			SuFree(su);
			su = NULL;
			is_using_selow = false;
		}
		else
		{
			is_using_selow = true;
		}
	}
	else
	{
		is_using_selow = false;
	}

	if (su_adapter_list != NULL)
	{
		UINT i;

		for (i = 0;i < LIST_NUM(su_adapter_list);i++)
		{
			SU_ADAPTER_LIST *t = LIST_DATA(su_adapter_list, i);
			WP_ADAPTER *a = ZeroMalloc(sizeof(WP_ADAPTER));

			StrCpy(a->Name, sizeof(a->Name), t->Name);
			StrCpy(a->Guid, sizeof(a->Guid), t->Guid);
			StrCpy(a->Title, sizeof(a->Title), t->Info.FriendlyName);
			Copy(a->MacAddress, t->Info.MacAddress, sizeof(a->MacAddress));

			TrimCrlf(a->Title);
			Trim(a->Title);
			TrimCrlf(a->Title);
			Trim(a->Title);

			if (EndWith(a->Title, qos_tag))
			{
				a->Title[StrLen(a->Title) - StrLen(qos_tag)] = 0;
				TrimCrlf(a->Title);
				Trim(a->Title);
				TrimCrlf(a->Title);
				Trim(a->Title);
			}

			Add(o, a);
		}
	}

	if (su_adapter_list != NULL)
	{
		// SeLow already returns the adapter list sorted
		Sort(o);
	}

	ret = NewListFast(CompareWpAdapter);

	for (i = 0;i < LIST_NUM(o);i++)
	{
		WP_ADAPTER *a = LIST_DATA(o, i);
		bool is_ethernet = false;
		bool ok = false;

		if (SearchStrEx(a->Title, "ppp", 0, false) != INFINITE ||
			SearchStrEx(a->Title, "wan", 0, false) != INFINITE ||
			SearchStrEx(a->Title, "dialup", 0, false) != INFINITE ||
			SearchStrEx(a->Title, "pptp", 0, false) != INFINITE ||
			SearchStrEx(a->Title, "telepho", 0, false) != INFINITE ||
			SearchStrEx(a->Title, "modem", 0, false) != INFINITE ||
			SearchStrEx(a->Title, "ras", 0, false) != INFINITE)
		{
			Free(a);
			continue;
		}

		is_ethernet = true;

		if (is_ethernet)
		{
			char tmp[MAX_SIZE];
			UINT k;

			StrCpy(tmp, sizeof(tmp), a->Title);

			for (k = 0;;k++)
			{
				if (k == 0)
				{
					StrCpy(tmp, sizeof(tmp), a->Title);
				}
				else
				{
					Format(tmp, sizeof(tmp), "%s(%u)", a->Title, k + 1);
				}

				ok = true;
				for (j = 0;j < LIST_NUM(ret);j++)
				{
					WP_ADAPTER *aa = LIST_DATA(ret, j);
					if (StrCmpi(aa->Title, tmp) == 0)
					{
						ok = false;
					}
				}

				if (ok)
				{
					break;
				}
			}

			StrCpy(a->Title, sizeof(a->Title), tmp);
			a->Id = Win32EthGenIdFromGuid(a->Guid);
			Add(ret, a);
		}

		if (ok == false)
		{
			Free(a);
		}
	}

	Sort(ret);

	ReleaseList(o);

	if (su != NULL)
	{
		SuFreeAdapterList(su_adapter_list);

		SuFree(su);
	}

	return ret;
}

static void InitEthAdaptersList()
{
	if (eth_list != NULL)
	{
		FreeEthAdaptersList();
		eth_list = NULL;
	}
	eth_list = GetEthAdapterList();
}

static void FreeEthAdaptersList()
{
	UINT i;
	if (eth_list == NULL)
	{
		return;
	}
	for (i = 0;i < LIST_NUM(eth_list);i++)
	{
		WP_ADAPTER *a = LIST_DATA(eth_list, i);
		Free(a);
	}
	ReleaseList(eth_list);
	eth_list = NULL;
}

// Whether SeLow is usable now. Read-only: never starts the SeLow service or installs the driver,
// so the capability queries (caps, BridgeSupport, BridgeList) change nothing (FIX-2 #98)
bool Win32EthIsSuSupported()
{
	bool ret = false;
	SU *su = SuInitEx(0);

	if (su != NULL)
	{
		ret = true;
	}

	SuFree(su);

	return ret;
}

// Make SeLow usable for a Local Bridge: start the SeLow service or install the driver when needed
// (at most once per process), then report whether SeLow is usable. Only for creating a Local
// Bridge (OpenEth, the AddLocalBridge RPC) and for listing the devices for one (the EnumEthernet RPC)
bool Win32EthInstallSu()
{
	bool ret = false;
	SU *su = SuInitInstall();

	if (su != NULL)
	{
		ret = true;
	}

	SuFree(su);

	return ret;
}

void InitEth()
{
	if (eth_list_lock != NULL)
	{
		return;
	}

	eth_list_lock = NewLock();
}

void FreeEth()
{
	if (eth_list_lock == NULL)
	{
		return;
	}

	FreeEthAdaptersList();

	DeleteLock(eth_list_lock);
	eth_list_lock = NULL;
}

void GetEthNetworkConnectionName(wchar_t *dst, UINT size, char *device_name)
{
	WP_ADAPTER *t;
	char guid[MAX_SIZE];
	wchar_t *ncname = NULL;

	UniStrCpy(dst, size, L"");

	if (device_name == NULL || Win32EthIsSuSupported() == false)
	{
		return;
	}

	Lock(eth_list_lock);

	InitEthAdaptersList();

	t = Win32EthSearch(device_name);

	if (t == NULL)
	{
		Unlock(eth_list_lock);
		return;
	}

	StrCpy(guid, sizeof(guid), t->Guid);
	Unlock(eth_list_lock);

	ncname = MsGetNetworkConnectionName(guid);
	if(ncname != NULL)
	{
		UniStrCpy(dst, size, ncname);
	}
	Free(ncname);
}
