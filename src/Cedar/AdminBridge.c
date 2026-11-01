// AdminBridge.c
// Admin RPC area: Local Bridge

#include "Admin.h"

#include "BridgeWin32.h"
#include "Connection.h"
#include "Link.h"
#include "Listener.h"
#include "RpcField.h"
#include "Protocol.h"
#include "Server.h"

#include "Mayaqua/Cfg.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Str.h"
#include "AdminInternal.h"

UINT StEnumEthernet(ADMIN *a, RPC_ENUM_ETH *t) {
	RPC_ENUM_ETH ret;

	SERVER_ADMIN_ONLY;

	// One SeLow probe and one adapter-list build for the devices and their connection names
	if (EnumEthWin32(&ret) == false)
		return ERR_NOT_SUPPORTED;

	FreeRpcEnumEth(t);
	Copy(t, &ret, sizeof(RPC_ENUM_ETH));

	return ERR_NO_ERROR;
}

UINT StAddLocalBridge(ADMIN *a, RPC_LOCALBRIDGE *t) {
	char tmp[MAX_SIZE];

	if (IsEmptyStr(t->DeviceName) || IsEmptyStr(t->HubName))
		return ERR_INVALID_PARAMETER;

	SERVER_ADMIN_ONLY;


	// Creating a Local Bridge installs SeLow when needed (FIX-2 #98)
	if (Win32EthInstallSu() == false)
		return ERR_LOCAL_BRIDGE_UNSUPPORTED;

	if (Win32EthGetNameAndIdFromCombinedName(tmp, sizeof(tmp), t->DeviceName) == 0) {
		// On Win32, adding fails when no device ID is given
		return ERR_OBJECT_NOT_FOUND;
	}

	// The RPC TapMode field is ignored: there is no TAP device on Windows
	AddLocalBridge(a->Server->Cedar, t->HubName, t->DeviceName, false, false, false);

	ALog(a, NULL, "LA_ADD_BRIDGE", t->HubName, t->DeviceName);

	IncrementServerConfigRevision(a->Server);

	return ERR_NO_ERROR;
}

UINT StDeleteLocalBridge(ADMIN *a, RPC_LOCALBRIDGE *t) {
	if (IsEmptyStr(t->DeviceName) || IsEmptyStr(t->HubName))
		return ERR_INVALID_PARAMETER;

	SERVER_ADMIN_ONLY;

	if (DeleteLocalBridge(a->Server->Cedar, t->HubName, t->DeviceName) == false)
		return ERR_OBJECT_NOT_FOUND;

	ALog(a, NULL, "LA_DELETE_BRIDGE", t->HubName, t->DeviceName);

	IncrementServerConfigRevision(a->Server);

	return ERR_NO_ERROR;
}

UINT StEnumLocalBridge(ADMIN *a, RPC_ENUM_LOCALBRIDGE *t) {
	SERVER_ADMIN_ONLY;

	if (Win32EthIsSuSupported() == false)
		return ERR_LOCAL_BRIDGE_UNSUPPORTED;

	FreeRpcEnumLocalBridge(t);
	Zero(t, sizeof(RPC_ENUM_LOCALBRIDGE));

	CEDAR *c = a->Server->Cedar;

	LockList(c->LocalBridgeList);
	{
		t->NumItem = LIST_NUM(c->LocalBridgeList);
		t->Items = ZeroMalloc(sizeof(RPC_LOCALBRIDGE) * t->NumItem);

		for (UINT i = 0; i < t->NumItem; i++) {
			RPC_LOCALBRIDGE *e = &t->Items[i];
			LOCALBRIDGE *br = LIST_DATA(c->LocalBridgeList, i);

			e->Online = (br->Bridge != NULL);
			e->Active = (br->Bridge != NULL && br->Bridge->Active);
			StrCpy(e->DeviceName, sizeof(e->DeviceName), br->DeviceName);
			StrCpy(e->HubName, sizeof(e->HubName), br->HubName);

			// TapMode stays false (zeroed above): no TAP device on Windows
		}
	}
	UnlockList(c->LocalBridgeList);

	return ERR_NO_ERROR;
}

TOKEN_LIST *GetEthList(void) {
	RPC_ENUM_ETH t;

	if (EnumEthWin32(&t) == false)
		return NULL;

	TOKEN_LIST *ret = ZeroMalloc(sizeof(TOKEN_LIST));
	ret->NumTokens = t.NumItem;
	ret->Token = ZeroMalloc(sizeof(char *) * ret->NumTokens);

	for (UINT i = 0; i < t.NumItem; i++)
		ret->Token[i] = CopyStr(t.Items[i].DeviceName);

	FreeRpcEnumEth(&t);

	return ret;
}
