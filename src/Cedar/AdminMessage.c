// AdminMessage.c
// Admin RPC area: hub and admin messages, maintenance (flush, crash, reboot, certificate regeneration) and Ethernet VLAN

#include "Admin.h"

#include "BridgeWin32.h"
#include "Connection.h"
#include "Link.h"
#include "Listener.h"
#include "Protocol.h"
#include "Server.h"

#include "Mayaqua/Internat.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Pack.h"
#include "Mayaqua/Str.h"
#include "AdminInternal.h"

UINT StRegenerateServerCert(ADMIN *a, RPC_TEST *t) {
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	X *x;
	K *k;

	SERVER_ADMIN_ONLY;

	if (SiGenerateDefaultCertEx(&x, &k, t->StrValue) == false) {
		SLog(c, "LS_DEFAULT_CERT_FAILED");
		return ERR_INTERNAL_ERROR;
	}

	SetCedarCertAndChain(c, x, k, NULL);

	ALog(a, NULL, "LA_REGENERATE_SERVER_CERT", t->StrValue);

	IncrementServerConfigRevision(s);

	FreeX(x);
	FreeK(k);

	return ERR_NO_ERROR;
}

UINT StSetHubMsg(ADMIN *a, RPC_MSG *t) {
	SERVER *s = a->Server;
	UINT err;

	CHECK_RIGHT;
	if (UniStrLen(t->Msg) > HUB_MAXMSG_LEN)
		return ERR_MEMORY_NOT_ENOUGH;

	HUB *h = AdminGetHub(a, t->HubName, "no_change_msg", &err);
	if (h == NULL)
		return err;

	SetHubMsg(h, t->Msg);

	IncrementServerConfigRevision(s);

	ReleaseHub(h);

	return ERR_NO_ERROR;
}

UINT StGetHubMsg(ADMIN *a, RPC_MSG *t) {
	UINT err;

	CHECK_RIGHT;

	HUB *h = AdminGetHub(a, t->HubName, NULL, &err);
	if (h == NULL)
		return err;

	FreeRpcMsg(t);
	Zero(t, sizeof(RPC_MSG));

	t->Msg = GetHubMsg(h);

	ReleaseHub(h);

	return ERR_NO_ERROR;
}

UINT StFlush(ADMIN *a, RPC_TEST *t) {
	SERVER *s = a->Server;

	SERVER_ADMIN_ONLY;

	UINT size = SiWriteConfigurationFile(s);

	t->IntValue = size;

	return ERR_NO_ERROR;
}

UINT StCrash(ADMIN *a, RPC_TEST *t) {
	SERVER_ADMIN_ONLY;

	CrashNow();

	return ERR_NO_ERROR;
}

UINT StGetAdminMsg(ADMIN *a, RPC_MSG *t) {
	wchar_t winver_msg_client[3800];

	FreeRpcMsg(t);
	Zero(t, sizeof(RPC_MSG));

	FormatUnsupportedWinVerMsg(winver_msg_client, sizeof(winver_msg_client), &a->ClientWinVer);

	UINT tmpsize = UniStrSize(winver_msg_client) + 10000;

	wchar_t *tmp = ZeroMalloc(tmpsize);

	UniStrCat(tmp, tmpsize, winver_msg_client);

	t->Msg = tmp;

	return ERR_NO_ERROR;
}

UINT StEnumEthVLan(ADMIN *a, RPC_ENUM_ETH_VLAN *t) {
	UINT ret = ERR_NO_ERROR;

	SERVER_ADMIN_ONLY;

	FreeRpcEnumEthVLan(t);
	Zero(t, sizeof(RPC_ENUM_ETH_VLAN));

	if (EnumEthVLanWin32(t) == false)
		ret = ERR_INTERNAL_ERROR;

	return ret;
}

UINT StSetEnableEthVLan(ADMIN *a, RPC_TEST *t) {
	UINT ret = ERR_NO_ERROR;

	SERVER_ADMIN_ONLY;

	if (MsIsAdmin() == false)
		ret = ERR_NOT_ENOUGH_RIGHT;
	else if (SetVLanEnableStatus(t->StrValue, INT_TO_BOOL(t->IntValue)) == false)
		ret = ERR_INTERNAL_ERROR;

	return ret;
}

UINT StRebootServer(ADMIN *a, RPC_TEST *t) {
	SERVER_ADMIN_ONLY;

	ALog(a, NULL, "LA_REBOOT_SERVER");

	SiRebootServerEx(t->IntValue);

	return ERR_NO_ERROR;
}
