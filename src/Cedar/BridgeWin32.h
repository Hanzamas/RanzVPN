// BridgeWin32.h
// Header of BridgeWin32.c

#ifdef OS_WIN32

#ifndef	BRIDGEWIN32_H
#define	BRIDGEWIN32_H

#include "Bridge.h"

#ifdef BRIDGE_C

typedef struct WP_ADAPTER
{
	char Name[MAX_SIZE];
	char Title[MAX_SIZE];
	char Guid[MAX_SIZE];
	UINT Id;
} WP_ADAPTER;

void InitEthAdaptersList();
void FreeEthAdaptersList();
int CompareWpAdapter(void *p1, void *p2);
LIST *GetEthAdapterList();
LIST *GetEthAdapterListInternal();

#endif

struct ETH
{
	char *Name;
	char *Title;
	CANCEL *Cancel;
	UCHAR MacAddress[6];
	bool HasFatalError;

	SU *Su;
	SU_ADAPTER *SuAdapter;

};

void InitEth();
void FreeEth();
TOKEN_LIST *GetEthList();
TOKEN_LIST *GetEthListEx(UINT *total_num_including_hidden, bool enum_normal, bool enum_rawip);
ETH *OpenEth(char *name, bool local, bool tapmode, char *tapaddr);
ETH *OpenEthInternal(char *name, bool local, bool tapmode, char *tapaddr);
void CloseEth(ETH *e);
CANCEL *EthGetCancel(ETH *e);
UINT EthGetPacket(ETH *e, void **data);
void EthPutPackets(ETH *e, UINT num, void **datas, UINT *sizes);
void GetEthNetworkConnectionName(wchar_t *dst, UINT size, char *device_name);
UINT EthGetMtu(ETH *e);
bool EthSetMtu(ETH *e, UINT mtu);
bool EthIsChangeMtuSupported(ETH *e);

bool Win32EthIsSuSupported();

void Win32EthSetShowAllIf(bool b);
bool Win32EthGetShowAllIf();

bool EnumEthVLanWin32(RPC_ENUM_ETH_VLAN *t);
bool GetClassRegKeyWin32(char *key, UINT key_size, char *short_key, UINT short_key_size, char *guid);
int CmpRpcEnumEthVLan(void *p1, void *p2);
void GetVLanSupportStatus(RPC_ENUM_ETH_VLAN_ITEM *e);
void GetVLanEnableStatus(RPC_ENUM_ETH_VLAN_ITEM *e);
bool SetVLanEnableStatus(char *title, bool enable);
RPC_ENUM_ETH_VLAN_ITEM *FindEthVLanItem(RPC_ENUM_ETH_VLAN *t, char *name);
char *SearchDeviceInstanceIdFromShortKey(char *short_key);
void Win32EthMakeCombinedName(char *dst, UINT dst_size, char *nicname, char *guid);
UINT Win32EthGenIdFromGuid(char *guid);
UINT Win32EthGetNameAndIdFromCombinedName(char *name, UINT name_size, char *str);

struct WP_ADAPTER *Win32EthSearch(char *name);
bool Win32IsUsingSeLow();
void Win32SetEnableSeLow(bool b);
bool Win32GetEnableSeLow();

#endif

#endif
