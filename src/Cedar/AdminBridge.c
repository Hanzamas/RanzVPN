// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// AdminBridge.c
// Admin RPC area: Local Bridge

#include "Admin.h"

#include "Account.h"
#include "BridgeWin32.h"
#include "Connection.h"
#include "Link.h"
#include "Listener.h"
#include "MsChapV2.h"
#include "Remote.h"
#include "Protocol.h"
#include "Sam.h"
#include "Server.h"
#include "Session.h"
#include "Wpc.h"

#include "Mayaqua/Cfg.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/HTTP.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Pack.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Table.h"
#include "Mayaqua/Tick64.h"
#include "AdminInternal.h"

// Get availability to localbridge function
UINT StGetBridgeSupport(ADMIN *a, RPC_BRIDGE_SUPPORT *t)
{
	Zero(t, sizeof(RPC_BRIDGE_SUPPORT));

	t->IsBridgeSupportedOs = IsBridgeSupported();

	return ERR_NO_ERROR;
}

// Enumerate Ethernet devices
UINT StEnumEthernet(ADMIN *a, RPC_ENUM_ETH *t)
{
	TOKEN_LIST *o;
	UINT i;
	char tmp[MAX_SIZE];

	SERVER_ADMIN_ONLY;

	o = GetEthList();
	if (o == NULL)
	{
		return ERR_NOT_SUPPORTED;
	}

	FreeRpcEnumEth(t);
	Zero(t, sizeof(RPC_ENUM_ETH));

	t->NumItem = o->NumTokens;
	t->Items = ZeroMalloc(sizeof(RPC_ENUM_ETH_ITEM) * t->NumItem);

	for (i = 0;i < t->NumItem;i++)
	{
		RPC_ENUM_ETH_ITEM *e = &t->Items[i];

		StrCpy(e->DeviceName, sizeof(e->DeviceName), o->Token[i]);

		StrCpy(tmp, sizeof(tmp), e->DeviceName);

#ifdef OS_WIN32
		GetEthNetworkConnectionName(e->NetworkConnectionName, sizeof(e->NetworkConnectionName), e->DeviceName);
#endif
	}

	FreeToken(o);

	return ERR_NO_ERROR;
}

// Add a new local bridge
UINT StAddLocalBridge(ADMIN *a, RPC_LOCALBRIDGE *t)
{
	if (IsEmptyStr(t->DeviceName) || IsEmptyStr(t->HubName))
	{
		return ERR_INVALID_PARAMETER;
	}

	SERVER_ADMIN_ONLY;


	if (IsEthSupported() == false)
	{
		return ERR_LOCAL_BRIDGE_UNSUPPORTED;
	}

#ifdef	OS_WIN32
	if (true)
	{
		char tmp[MAX_SIZE];
		UINT id = Win32EthGetNameAndIdFromCombinedName(tmp, sizeof(tmp), t->DeviceName);

		if (id == 0)
		{
			// If a ID is not specified in Win32, adding will fail
			return ERR_OBJECT_NOT_FOUND;
		}
	}
#endif	// OS_WIN32

	ALog(a, NULL, "LA_ADD_BRIDGE", t->HubName, t->DeviceName);

	AddLocalBridge(a->Server->Cedar, t->HubName, t->DeviceName, false, false, t->TapMode, NULL, false);

	IncrementServerConfigRevision(a->Server);

	return ERR_NO_ERROR;
}

// Delete a local bridge
UINT StDeleteLocalBridge(ADMIN *a, RPC_LOCALBRIDGE *t)
{
	if (IsEmptyStr(t->DeviceName) || IsEmptyStr(t->HubName))
	{
		return ERR_INVALID_PARAMETER;
	}

	SERVER_ADMIN_ONLY;

	ALog(a, NULL, "LA_DELETE_BRIDGE", t->HubName, t->DeviceName);

	if (DeleteLocalBridge(a->Server->Cedar, t->HubName, t->DeviceName) == false)
	{
		return ERR_OBJECT_NOT_FOUND;
	}

	IncrementServerConfigRevision(a->Server);

	return ERR_NO_ERROR;
}

// Enumerate local bridges
UINT StEnumLocalBridge(ADMIN *a, RPC_ENUM_LOCALBRIDGE *t)
{
	UINT i;
	CEDAR *c;

	if (IsEthSupported() == false)
	{
		return ERR_LOCAL_BRIDGE_UNSUPPORTED;
	}

	FreeRpcEnumLocalBridge(t);
	Zero(t, sizeof(RPC_ENUM_LOCALBRIDGE));

	c = a->Server->Cedar;

	LockList(c->LocalBridgeList);
	{
		t->NumItem = LIST_NUM(c->LocalBridgeList);
		t->Items = ZeroMalloc(sizeof(RPC_LOCALBRIDGE) * t->NumItem);

		for (i = 0;i < t->NumItem;i++)
		{
			RPC_LOCALBRIDGE *e = &t->Items[i];
			LOCALBRIDGE *br = LIST_DATA(c->LocalBridgeList, i);

			if (br->Bridge == false)
			{
				e->Online = e->Active = false;
			}
			else
			{
				e->Online = true;
				if (br->Bridge->Active)
				{
					e->Active = true;
				}
				else
				{
					e->Active = false;
				}
			}
			StrCpy(e->DeviceName, sizeof(e->DeviceName), br->DeviceName);
			StrCpy(e->HubName, sizeof(e->HubName), br->HubName);

			e->TapMode = br->TapMode;
		}
	}
	UnlockList(c->LocalBridgeList);

	return ERR_NO_ERROR;
}
