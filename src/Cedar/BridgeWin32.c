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
static bool EnumEthVLanMain(RPC_ENUM_ETH_VLAN *t, LIST *netclass);
static ETH *OpenEthInternal(char *name);
static void Win32EthMakeCombinedName(char *dst, UINT dst_size, char *nicname, char *guid);
static UINT Win32EthGenIdFromGuid(char *guid);
static LIST *GetEthAdapterListInternal(SU *su, LIST *netclass);
static void InitEthAdaptersList(SU *su, LIST *netclass);
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
	char tcpkey[MAX_SIZE];
	LIST *netclass;
	if (title == NULL)
	{
		return false;
	}

	// One net-class pass for the VLAN enumeration and for the Class key of the adapter
	netclass = MsNetClassEnum();

	Zero(&t, sizeof(t));
	if (EnumEthVLanMain(&t, netclass) == false)
	{
		MsNetClassFree(netclass);
		return false;
	}

	e = FindEthVLanItem(&t, title);

	if (e != NULL)
	{
		MS_NETCLASS_DEVICE *d = MsNetClassFind(netclass, e->Guid);

		if (d != NULL)
		{
			char *key = d->ClassKey;

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

	MsNetClassFree(netclass);

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

// key: the Class key of the adapter (MS_NETCLASS_DEVICE.ClassKey)
static void GetVLanEnableStatus(RPC_ENUM_ETH_VLAN_ITEM *e, char *key)
{
	char tcpkey[MAX_SIZE];
	if (e == NULL)
	{
		return;
	}

	e->Enabled = false;

	if (e->Support == false || key == NULL)
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

		if (SearchBin(b->Buf, b->Size, intel1, sizeof(intel1)) != INFINITE
			|| SearchBin(b->Buf, b->Size, intel2, sizeof(intel2)) != INFINITE
			|| SearchBin(b->Buf, b->Size, intel3, sizeof(intel3)) != INFINITE
			|| SearchBin(b->Buf, b->Size, intel4, sizeof(intel4)) != INFINITE
			|| SearchBin(b->Buf, b->Size, intel5, sizeof(intel5)) != INFINITE
			|| SearchBin(b->Buf, b->Size, intel6, sizeof(intel6)) != INFINITE)
		{
			driver_type = "Intel";
		}
		else if (SearchBin(b->Buf, b->Size, broadcom1, sizeof(broadcom1)) != INFINITE
			|| SearchBin(b->Buf, b->Size, broadcom2, sizeof(broadcom2)) != INFINITE)
		{
			driver_type = "Broadcom";
		}
		else if (SearchBin(b->Buf, b->Size, marvell1, sizeof(marvell1)) != INFINITE
			|| SearchBin(b->Buf, b->Size, marvell2, sizeof(marvell2)) != INFINITE)
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

// The VLAN items of the SeLow adapters. netclass is the net-class table of the caller (MsNetClassEnum):
// one SetupAPI pass gives the device instance id, the driver file and the Class key of every adapter.
// One SeLow probe, which also reads the adapter list
static bool EnumEthVLanMain(RPC_ENUM_ETH_VLAN *t, LIST *netclass)
{
	UINT i;
	LIST *o;
	SU *su;
	if (t == NULL)
	{
		return false;
	}

	Zero(t, sizeof(RPC_ENUM_ETH_VLAN));

	su = SuInitEx(0);
	if (su == NULL)
	{
		return false;
	}

	Lock(eth_list_lock);

	InitEthAdaptersList(su, netclass);

	o = NewListFast(CmpRpcEnumEthVLan);

	for (i = 0;i < LIST_NUM(eth_list);i++)
	{
		WP_ADAPTER *a = LIST_DATA(eth_list, i);
		MS_NETCLASS_DEVICE *d = MsNetClassFind(netclass, a->Guid);

		if (d != NULL && IsEmptyStr(d->DeviceInstanceId) == false && EndWith(d->DriverFileName, ".sys"))
		{
			RPC_ENUM_ETH_VLAN_ITEM *e = ZeroMalloc(sizeof(RPC_ENUM_ETH_VLAN_ITEM));

			StrCpy(e->DeviceName, sizeof(e->DeviceName), a->Title);
			StrCpy(e->Guid, sizeof(e->Guid), a->Guid);
			StrCpy(e->DeviceInstanceId, sizeof(e->DeviceInstanceId), d->DeviceInstanceId);
			StrCpy(e->DriverName, sizeof(e->DriverName), d->DriverFileName);

			GetVLanSupportStatus(e);

			GetVLanEnableStatus(e, d->ClassKey);

			Insert(o, e);
		}
	}

	t->NumItem = LIST_NUM(o);
	t->Items = ZeroMalloc(sizeof(RPC_ENUM_ETH_VLAN_ITEM) * t->NumItem);

	for (i = 0;i < LIST_NUM(o);i++)
	{
		RPC_ENUM_ETH_VLAN_ITEM *e = LIST_DATA(o, i);

		Copy(&t->Items[i], e, sizeof(RPC_ENUM_ETH_VLAN_ITEM));

		Free(e);
	}

	ReleaseList(o);

	Unlock(eth_list_lock);

	SuFree(su);

	return true;
}

bool EnumEthVLanWin32(RPC_ENUM_ETH_VLAN *t)
{
	LIST *netclass = MsNetClassEnum();
	bool ret = EnumEthVLanMain(t, netclass);

	MsNetClassFree(netclass);

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

ETH *OpenEth(char *name)
{
	ETH *ret;
	void *p;

	p = MsDisableWow64FileSystemRedirection();

	ret = OpenEthInternal(name);

	MsRestoreWow64FileSystemRedirection(p);

	return ret;
}
static ETH *OpenEthInternal(char *name)
{
	WP_ADAPTER *t;
	ETH *e;
	HANDLE h;
	CANCEL *c;
	char name_with_id[MAX_SIZE];
	SU *su = NULL;
	SU_ADAPTER *su_adapter = NULL;
	LIST *netclass;
	if (name == NULL)
	{
		return NULL;
	}

	// One SeLow open per OpenEth: it installs SeLow when needed (creating a Local Bridge), reads the
	// adapter list and opens the adapter, and the ETH keeps it
	su = SuInitInstall();
	if (su == NULL)
	{
		return NULL;
	}

	netclass = MsNetClassEnum();

	Lock(eth_list_lock);

	InitEthAdaptersList(su, netclass);

	MsNetClassFree(netclass);

	t = Win32EthSearch(name);

	if (t == NULL)
	{
		Unlock(eth_list_lock);
		SuFree(su);
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
	RPC_ENUM_ETH t;
	TOKEN_LIST *ret;
	UINT i;

	if (EnumEthWin32(&t) == false)
	{
		return NULL;
	}

	ret = ZeroMalloc(sizeof(TOKEN_LIST));
	ret->NumTokens = t.NumItem;
	ret->Token = ZeroMalloc(sizeof(char *) * ret->NumTokens);

	for (i = 0;i < t.NumItem;i++)
	{
		ret->Token[i] = CopyStr(t.Items[i].DeviceName);
	}

	FreeRpcEnumEth(&t);

	return ret;
}

// The devices for a Local Bridge and their network connection names (the EnumEthernet RPC): one
// SeLow probe, one net-class pass, one adapter-list build and one IP Helper interface table. The
// connection name is the interface alias that IP Helper reports. False when SeLow is not usable
bool EnumEthWin32(RPC_ENUM_ETH *t)
{
	SU *su;
	LIST *netclass;
	LIST *o;
	MS_ADAPTER_LIST *adapter_list;
	UINT i;
	if (t == NULL)
	{
		return false;
	}

	Zero(t, sizeof(RPC_ENUM_ETH));

	// Listing the devices for a Local Bridge is the first step of creating one: install SeLow when needed
	su = SuInitInstall();
	if (su == NULL)
	{
		return false;
	}

	netclass = MsNetClassEnum();
	adapter_list = MsCreateAdapterList();
	o = NewListFast(NULL);

	Lock(eth_list_lock);

	InitEthAdaptersList(su, netclass);

	for (i = 0;i < LIST_NUM(eth_list);i++)
	{
		WP_ADAPTER *a = LIST_DATA(eth_list, i);
		MS_ADAPTER *msa = MsGetAdapterByGuidFromList(adapter_list, a->Guid);

		// Hidden by the interface type that the OS reports, not by words in the title; an
		// adapter that the OS does not list cannot be classified and stays listed
		if (Win32EthGetShowAllIf() || msa == NULL || msa->IsBridgeable)
		{
			RPC_ENUM_ETH_ITEM *e = ZeroMalloc(sizeof(RPC_ENUM_ETH_ITEM));

			Win32EthMakeCombinedName(e->DeviceName, sizeof(e->DeviceName), a->Title, a->Guid);

			if (msa != NULL)
			{
				UniStrCpy(e->NetworkConnectionName, sizeof(e->NetworkConnectionName), msa->Alias);
			}

			Add(o, e);
		}

		MsFreeAdapter(msa);
	}

	Unlock(eth_list_lock);

	t->NumItem = LIST_NUM(o);
	t->Items = ZeroMalloc(sizeof(RPC_ENUM_ETH_ITEM) * t->NumItem);

	for (i = 0;i < LIST_NUM(o);i++)
	{
		RPC_ENUM_ETH_ITEM *e = LIST_DATA(o, i);

		Copy(&t->Items[i], e, sizeof(RPC_ENUM_ETH_ITEM));

		Free(e);
	}

	ReleaseList(o);
	MsFreeAdapterList(adapter_list);
	MsNetClassFree(netclass);
	SuFree(su);

	return true;
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
	if (i != 0)
	{
		return i;
	}

	// Same title: the GUID fixes the order, so the "(2)" numbering of identically named NICs is
	// the same on every run
	return StrCmpi(a1->Guid, a2->Guid);
}

bool Win32IsUsingSeLow()
{
	return is_using_selow;
}

static LIST *GetEthAdapterList(SU *su, LIST *netclass)
{
	void *p;
	LIST *o;

	p = MsDisableWow64FileSystemRedirection();

	o = GetEthAdapterListInternal(su, netclass);

	MsRestoreWow64FileSystemRedirection(p);

	return o;
}
// The adapters of the SeLow device su, which the caller opened and frees; empty when su is NULL or
// SeLow is turned off. netclass: the net-class table of the caller (MsNetClassEnum)
static LIST *GetEthAdapterListInternal(SU *su, LIST *netclass)
{
	LIST *o;
	LIST *ret;
	UINT i, j;
	char *qos_tag = "(Microsoft's Packet Scheduler)";
	LIST *su_adapter_list = NULL;

	o = NewListFast(CompareWpAdapter);

	if (su != NULL && enable_selow)
	{
		su_adapter_list = SuGetAdapterList(su, netclass);
	}

	is_using_selow = (su_adapter_list != NULL);

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
		// Sort by title, then GUID: the numbering below follows this order
		Sort(o);
	}

	ret = NewListFast(CompareWpAdapter);

	for (i = 0;i < LIST_NUM(o);i++)
	{
		WP_ADAPTER *a = LIST_DATA(o, i);
		char tmp[MAX_SIZE];
		UINT k;

		// Every SeLow adapter is listed here; EnumEthWin32 hides the ones that are no wired LAN
		for (k = 0;;k++)
		{
			bool ok;

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

	Sort(ret);

	ReleaseList(o);

	SuFreeAdapterList(su_adapter_list);

	return ret;
}

// Rebuild eth_list from the SeLow device su and the net-class table netclass of the caller, which
// holds eth_list_lock. One rebuild per operation
static void InitEthAdaptersList(SU *su, LIST *netclass)
{
	if (eth_list != NULL)
	{
		FreeEthAdaptersList();
		eth_list = NULL;
	}
	eth_list = GetEthAdapterList(su, netclass);
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
