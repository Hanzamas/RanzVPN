// Bridge.h
// Header of Bridge.c

#ifndef	BRIDGE_H
#define	BRIDGE_H

#include "Cedar.h"

struct BRIDGE
{
	bool Active;
	CEDAR *Cedar;
	HUB *Hub;
	SESSION *Session;
	POLICY *Policy;
	ETH *Eth;
	char Name[MAX_SIZE];
	UINT64 LastBridgeTry;
	bool Local;
	bool TapMode;
	bool LimitBroadcast;
	UCHAR TapMacAddress[6];
	UINT LastNumDevice;
	UINT64 LastNumDeviceCheck;
	LOCALBRIDGE *ParentLocalBridge;
};

struct LOCALBRIDGE
{
	char HubName[MAX_HUBNAME_LEN + 1];
	char DeviceName[MAX_SIZE];
	bool Local;
	bool Monitor;
	bool TapMode;
	bool LimitBroadcast;
	UCHAR TapMacAddress[6];
	BRIDGE *Bridge;
};

BRIDGE *BrNewBridge(HUB *h, char *name, POLICY *p, bool local, bool monitor, bool tapmode, const UCHAR *tapaddr, bool limit_broadcast, LOCALBRIDGE *parent_local_bridge);
void BrFreeBridge(BRIDGE *b);
void InitLocalBridgeList(CEDAR *c);
void FreeLocalBridgeList(CEDAR *c);
void AddLocalBridge(CEDAR *c, char *hubname, char *devicename, bool local, bool monitor, bool tapmode, const UCHAR *tapaddr, bool limit_broadcast);
bool DeleteLocalBridge(CEDAR *c, char *hubname, char *devicename);
bool IsBridgeSupported();
UINT GetEthDeviceHash();

#endif	// BRIDGE_H



