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

static void Win32EthMakeCombinedName(char *dst, UINT dst_size, char *nicname, const char *guid);
static UINT Win32EthGenIdFromGuid(const char *guid);
static void InitEthAdaptersList(SU *su, LIST *netclass);
static void FreeEthAdaptersList();

static LIST *eth_list = NULL;

static LOCK *eth_list_lock = NULL;
// The shared SeLow flags below are read and written by Local Bridge session threads and RPC
// threads at the same time, so they are LONGs accessed only through the Interlocked functions
// The last adapter enumeration listed the SeLow adapters (the b_using_selow_driver cap)
static volatile LONG is_using_selow = 0;
// EnableSoftEtherKernelModeDriver: zero turns the Local Bridge off. SeLow then reports
// unsupported and is never opened or installed
static volatile LONG enable_selow = 1;

static volatile LONG g_bridge_win32_show_all_if = 0;

// Atomic read of a shared flag
static bool Win32ReadFlag(volatile LONG *flag) {
	return InterlockedCompareExchange(flag, 0, 0) != 0;
}

void Win32SetEnableSeLow(bool b) {
	InterlockedExchange(&enable_selow, b ? 1 : 0);
}

bool Win32GetEnableSeLow() {
	return Win32ReadFlag(&enable_selow);
}

void Win32EthSetShowAllIf(bool b) {
	InterlockedExchange(&g_bridge_win32_show_all_if, b ? 1 : 0);
}

bool Win32EthGetShowAllIf() {
	return Win32ReadFlag(&g_bridge_win32_show_all_if);
}

void EthPutPackets(ETH *e, UINT num, void **datas, UINT *sizes) {
	bool ok = true;
	if (e == NULL || num == 0 || datas == NULL || sizes == NULL)
		return;
	if (e->HasFatalError)
		return;

	for (UINT i = 0; i < num; i++) {
		UCHAR *data = datas[i];
		UINT size = sizes[i];

		if (ok)
			ok = SuPutPacket(e->SuAdapter, data, size);

		if (ok == false)
			Free(data);
	}

	if (ok)
		ok = SuPutPacket(e->SuAdapter, NULL, 0);

	if (ok == false)
		e->HasFatalError = true;
}

UINT EthGetPacket(ETH *e, void **data) {
	UINT size;
	if (e == NULL || data == NULL)
		return INFINITE;
	if (e->HasFatalError)
		return INFINITE;

	if (SuGetNextPacket(e->SuAdapter, data, &size) == false) {
		e->HasFatalError = true;
		return INFINITE;
	}

	return size;
}

// Frames EthGetPacket can return without waiting for the cancel event
bool EthHasPendingFrames(ETH *e) {
	if (e == NULL || e->HasFatalError)
		return false;

	return SuHasPendingPackets(e->SuAdapter);
}

CANCEL *EthGetCancel(ETH *e) {
	if (e == NULL)
		return NULL;

	AddRef(e->Cancel->ref);

	return e->Cancel;
}

void CloseEth(ETH *e) {
	if (e == NULL)
		return;

	ReleaseCancel(e->Cancel);

	SuCloseAdapter(e->SuAdapter);
	SuFree(e->Su);

	Free(e->Name);
	Free(e->Title);

	Free(e);
}

static struct WP_ADAPTER *Win32EthSearch(char *name) {
	char simple_name[MAX_SIZE];
	WP_ADAPTER *ret = NULL;

	UINT id = Win32EthGetNameAndIdFromCombinedName(simple_name, sizeof(simple_name), name);

	if (id != 0) {
		UINT num_match = 0;
		for (UINT i = 0; i < LIST_NUM(eth_list); i++) {
			WP_ADAPTER *a = LIST_DATA(eth_list, i);

			if (a->Id != 0 && a->Id == id) {
				ret = a;
				num_match++;
			}
		}

		if (num_match >= 2) {
			for (UINT i = 0; i < LIST_NUM(eth_list); i++) {
				WP_ADAPTER *a = LIST_DATA(eth_list, i);

				if (a->Id != 0 && a->Id == id) {
					if (StrCmpi(a->Title, name) == 0) {
						ret = a;
						break;
					}
				}
			}
		}
	} else {
		for (UINT i = 0; i < LIST_NUM(eth_list); i++) {
			WP_ADAPTER *a = LIST_DATA(eth_list, i);

			if (StrCmpi(a->Title, name) == 0) {
				ret = a;
				break;
			}
		}
	}

	return ret;
}

ETH *OpenEth(char *name) {
	char name_with_id[MAX_SIZE];
	SU *su = NULL;
	SU_ADAPTER *su_adapter = NULL;
	if (name == NULL || Win32GetEnableSeLow() == false)
		return NULL;

	// One SeLow open per OpenEth: it installs SeLow when needed (creating a Local Bridge), reads the
	// adapter list and opens the adapter, and the ETH keeps it
	su = SuInitInstall();
	if (su == NULL)
		return NULL;

	LIST *netclass = MsNetClassEnum();

	Lock(eth_list_lock);

	InitEthAdaptersList(su, netclass);

	MsNetClassFree(netclass);

	WP_ADAPTER *t = Win32EthSearch(name);

	if (t == NULL) {
		Unlock(eth_list_lock);
		SuFree(su);
		return NULL;
	}

	su_adapter = SuOpenAdapter(t->Name);

	if (su_adapter == NULL) {
		SuFree(su);
		Unlock(eth_list_lock);
		return NULL;
	}

	ETH *e = ZeroMalloc(sizeof(ETH));
	e->Name = CopyStr(t->Name);

	Win32EthMakeCombinedName(name_with_id, sizeof(name_with_id), t->Title, t->Guid);
	e->Title = CopyStr(name_with_id);

	e->SuAdapter = su_adapter;
	e->Su = su;

	HANDLE h = e->SuAdapter->hEvent;

	CANCEL *c = NewCancelSpecial(h);
	e->Cancel = c;

	Copy(e->MacAddress, t->MacAddress, sizeof(e->MacAddress));

	Unlock(eth_list_lock);

	return e;
}

static void Win32EthMakeCombinedName(char *dst, UINT dst_size, char *nicname, const char *guid) {
	if (dst == NULL || nicname == NULL || guid == NULL)
		return;

	if (IsEmptyStr(guid) == false)
		Format(dst, dst_size, "%s(ID=%010u)", nicname, Win32EthGenIdFromGuid(guid));
	else
		StrCpy(dst, dst_size, nicname);
}

UINT Win32EthGetNameAndIdFromCombinedName(char *name, UINT name_size, char *str) {
	UINT ret = 0;
	char id_str[MAX_SIZE];
	if (name == NULL)
		return 0;
	ClearStr(name, name_size);
	if (str == NULL)
		return 0;
	StrCpy(name, name_size, str);

	UINT len = StrLen(str);

	if (len >= 15) {
		StrCpy(id_str, sizeof(id_str), str + len - 15);

		if (StartWith(id_str, "(ID=")) {
			if (EndWith(id_str, ")")) {
				char num[MAX_SIZE];

				Zero(num, sizeof(num));
				StrCpy(num, sizeof(num), id_str + 4);

				num[StrLen(num) - 1] = 0;

				ret = ToInt(num);

				if (ret != 0)
					name[len - 15] = 0;
			}
		}
	}

	return ret;
}

static UINT Win32EthGenIdFromGuid(const char *guid) {
	char tmp[MAX_SIZE];
	UCHAR hash[SHA1_SIZE];
	UINT i;
	if (guid == NULL)
		return 0;

	StrCpy(tmp, sizeof(tmp), guid);
	Trim(tmp);
	StrUpper(tmp);

	Sha1(hash, tmp, StrLen(tmp));

	Copy(&i, hash, sizeof(UINT));

	i = Endian32(i);

	if (i == 0)
		i = 1;

	return i;
}

// The devices for a Local Bridge and their network connection names (the EnumEthernet RPC): one
// SeLow probe, one net-class pass, one adapter-list build and one IP Helper interface table. The
// connection name is the interface alias that IP Helper reports. False when SeLow is not usable
bool EnumEthWin32(RPC_ENUM_ETH *t) {
	if (t == NULL)
		return false;

	Zero(t, sizeof(RPC_ENUM_ETH));

	// SeLow turned off (EnableSoftEtherKernelModeDriver): no Local Bridge, never open or install SeLow
	if (Win32GetEnableSeLow() == false)
		return false;

	// Listing the devices for a Local Bridge is the first step of creating one: install SeLow when needed
	SU *su = SuInitInstall();
	if (su == NULL)
		return false;

	LIST *netclass = MsNetClassEnum();
	MS_ADAPTER_LIST *adapter_list = MsCreateAdapterList();
	LIST *o = NewListFast(NULL);

	Lock(eth_list_lock);

	InitEthAdaptersList(su, netclass);

	for (UINT i = 0; i < LIST_NUM(eth_list); i++) {
		WP_ADAPTER *a = LIST_DATA(eth_list, i);
		MS_ADAPTER *msa = MsGetAdapterByGuidFromList(adapter_list, a->Guid);

		// Hidden by the interface type that the OS reports, not by words in the title; an
		// adapter that the OS does not list cannot be classified and stays listed
		if (Win32EthGetShowAllIf() || msa == NULL || msa->IsBridgeable) {
			RPC_ENUM_ETH_ITEM *e = ZeroMalloc(sizeof(RPC_ENUM_ETH_ITEM));

			Win32EthMakeCombinedName(e->DeviceName, sizeof(e->DeviceName), a->Title, a->Guid);

			if (msa != NULL)
				UniStrCpy(e->NetworkConnectionName, sizeof(e->NetworkConnectionName), msa->Alias);

			Add(o, e);
		}

		MsFreeAdapter(msa);
	}

	Unlock(eth_list_lock);

	t->NumItem = LIST_NUM(o);
	t->Items = ZeroMalloc(sizeof(RPC_ENUM_ETH_ITEM) * t->NumItem);

	for (UINT i = 0; i < LIST_NUM(o); i++) {
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

static int CompareWpAdapter(void *p1, void *p2) {
	if (p1 == NULL || p2 == NULL)
		return 0;
	WP_ADAPTER *a1 = *(WP_ADAPTER **)p1;
	WP_ADAPTER *a2 = *(WP_ADAPTER **)p2;
	if (a1 == NULL || a2 == NULL)
		return 0;
	int i = StrCmpi(a1->Title, a2->Title);
	if (i != 0)
		return i;

	// Same title: the GUID fixes the order, so the "(2)" numbering of identically named NICs is
	// the same on every run
	return StrCmpi(a1->Guid, a2->Guid);
}

bool Win32IsUsingSeLow() {
	return Win32ReadFlag(&is_using_selow);
}

// Strip line breaks and blanks from both ends of an adapter title
static void Win32EthTrimTitle(char *title) {
	TrimCrlf(title);
	Trim(title);
	TrimCrlf(title);
	Trim(title);
}

// The adapters of the SeLow device su, which the caller opened and frees; empty when su is NULL or
// SeLow is turned off. netclass: the net-class table of the caller (MsNetClassEnum)
static LIST *GetEthAdapterList(SU *su, LIST *netclass) {
	char *qos_tag = "(Microsoft's Packet Scheduler)";
	LIST *su_adapter_list = NULL;

	LIST *o = NewListFast(CompareWpAdapter);

	if (su != NULL && Win32GetEnableSeLow())
		su_adapter_list = SuGetAdapterList(su, netclass);

	InterlockedExchange(&is_using_selow, su_adapter_list != NULL ? 1 : 0);

	if (su_adapter_list != NULL) {
		for (UINT i = 0; i < LIST_NUM(su_adapter_list); i++) {
			SU_ADAPTER_LIST *t = LIST_DATA(su_adapter_list, i);
			WP_ADAPTER *a = ZeroMalloc(sizeof(WP_ADAPTER));

			StrCpy(a->Name, sizeof(a->Name), t->Name);
			StrCpy(a->Guid, sizeof(a->Guid), t->Guid);
			StrCpy(a->Title, sizeof(a->Title), t->FriendlyName);
			Copy(a->MacAddress, t->MacAddress, sizeof(a->MacAddress));

			Win32EthTrimTitle(a->Title);

			if (EndWith(a->Title, qos_tag)) {
				a->Title[StrLen(a->Title) - StrLen(qos_tag)] = 0;
				Win32EthTrimTitle(a->Title);
			}

			Add(o, a);
		}

		// Sort by title, then GUID: the numbering below follows this order
		Sort(o);

		SuFreeAdapterList(su_adapter_list);
	}

	LIST *ret = NewListFast(CompareWpAdapter);

	for (UINT i = 0; i < LIST_NUM(o); i++) {
		WP_ADAPTER *a = LIST_DATA(o, i);
		char tmp[MAX_SIZE];

		// Every SeLow adapter is listed here; EnumEthWin32 hides the ones that are no wired LAN
		for (UINT k = 0;; k++) {
			if (k == 0)
				StrCpy(tmp, sizeof(tmp), a->Title);
			else
				Format(tmp, sizeof(tmp), "%s(%u)", a->Title, k + 1);

			bool ok = true;
			for (UINT j = 0; j < LIST_NUM(ret); j++) {
				WP_ADAPTER *aa = LIST_DATA(ret, j);
				if (StrCmpi(aa->Title, tmp) == 0)
					ok = false;
			}

			if (ok)
				break;
		}

		StrCpy(a->Title, sizeof(a->Title), tmp);
		a->Id = Win32EthGenIdFromGuid(a->Guid);
		Add(ret, a);
	}

	Sort(ret);

	ReleaseList(o);

	return ret;
}

// Rebuild eth_list from the SeLow device su and the net-class table netclass of the caller, which
// holds eth_list_lock. One rebuild per operation
static void InitEthAdaptersList(SU *su, LIST *netclass) {
	if (eth_list != NULL) {
		FreeEthAdaptersList();
		eth_list = NULL;
	}
	eth_list = GetEthAdapterList(su, netclass);
}

static void FreeEthAdaptersList() {
	if (eth_list == NULL)
		return;
	for (UINT i = 0; i < LIST_NUM(eth_list); i++) {
		WP_ADAPTER *a = LIST_DATA(eth_list, i);
		Free(a);
	}
	ReleaseList(eth_list);
	eth_list = NULL;
}

// Whether SeLow is usable now. Read-only: never starts the SeLow service or installs the driver,
// so the capability queries (caps, BridgeSupport, BridgeList) change nothing (FIX-2 #98)
bool Win32EthIsSuSupported() {
	bool ret = false;

	if (Win32GetEnableSeLow() == false)
		return false;

	SU *su = SuInitEx(0);

	if (su != NULL)
		ret = true;

	SuFree(su);

	return ret;
}

// Make SeLow usable for a Local Bridge: start the SeLow service or install the driver when needed
// (at most once per process), then report whether SeLow is usable. Only for creating a Local
// Bridge (OpenEth, the AddLocalBridge RPC) and for listing the devices for one (the EnumEthernet RPC)
bool Win32EthInstallSu() {
	bool ret = false;

	if (Win32GetEnableSeLow() == false)
		return false;

	SU *su = SuInitInstall();

	if (su != NULL)
		ret = true;

	SuFree(su);

	return ret;
}

void InitEth() {
	if (eth_list_lock != NULL)
		return;

	eth_list_lock = NewLock();
}

void FreeEth() {
	if (eth_list_lock == NULL)
		return;

	FreeEthAdaptersList();

	DeleteLock(eth_list_lock);
	eth_list_lock = NULL;
}

UINT GetEthDeviceHash() {
	MS_ADAPTER_LIST *a = MsCreateAdapterList();
	UINT num;
	char tmp[4096];
	UCHAR hash[SHA1_SIZE];

	tmp[0] = 0;
	if (a != NULL)
		for (UINT i = 0; i < a->Num; i++)
			StrCat(tmp, sizeof(tmp), a->Adapters[i]->Title);
	MsFreeAdapterList(a);

	Sha0(hash, tmp, StrLen(tmp));

	Copy(&num, hash, sizeof(UINT));

	return num;
}

// Whether this machine can run a Local Bridge. SeLow must exist for this OS and architecture
// (SuIsSupportedOs: no claim where no SeLow driver package exists, such as arm64), and then be
// usable now or installable by this elevated process (FND-173)
bool IsBridgeSupported() {
	if (SuIsSupportedOs() == false)
		return false;

	return Win32EthIsSuSupported() || MsIsAdmin();
}
