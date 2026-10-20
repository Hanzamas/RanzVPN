// BridgeWin32.h
// Header of BridgeWin32.c

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
	UCHAR MacAddress[6];			// Current MAC address reported by SeLow
} WP_ADAPTER;

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
TOKEN_LIST *GetEthList(void);
ETH *OpenEth(char *name, bool local, bool tapmode, char *tapaddr);
void CloseEth(ETH *e);
CANCEL *EthGetCancel(ETH *e);
UINT EthGetPacket(ETH *e, void **data);
bool EthHasPendingFrames(ETH *e);
void EthPutPackets(ETH *e, UINT num, void **datas, UINT *sizes);
void GetEthNetworkConnectionName(wchar_t *dst, UINT size, char *device_name);

bool Win32EthIsSuSupported();
bool Win32EthInstallSu();

void Win32EthSetShowAllIf(bool b);
bool Win32EthGetShowAllIf();

bool EnumEthVLanWin32(RPC_ENUM_ETH_VLAN *t);
bool GetClassRegKeyWin32(char *key, UINT key_size, char *short_key, UINT short_key_size, char *guid);
bool SetVLanEnableStatus(char *title, bool enable);
UINT Win32EthGetNameAndIdFromCombinedName(char *name, UINT name_size, char *str);

bool Win32IsUsingSeLow();
void Win32SetEnableSeLow(bool b);
bool Win32GetEnableSeLow();

#endif
