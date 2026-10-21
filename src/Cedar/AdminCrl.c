// AdminCrl.c
// Admin RPC area: certificate revocation list of a Virtual Hub

#include "Admin.h"

#include "BridgeWin32.h"
#include "Connection.h"
#include "Link.h"
#include "Listener.h"
#include "Remote.h"
#include "RpcField.h"
#include "Protocol.h"
#include "Server.h"

#include "Mayaqua/Cfg.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Str.h"
#include "AdminInternal.h"

UINT StSetCrl(ADMIN *a, RPC_CRL *t) {
	SERVER *s = a->Server;
	UINT ret = ERR_NO_ERROR;

	CHECK_RIGHT;

	HUB *h = AdminGetHub(a, t->HubName, "no_change_crl_list", &ret);
	if (h == NULL)
		return ret;

	LockList(h->HubDb->CrlList);
	{
		CRL *crl = ListKeyToPointer(h->HubDb->CrlList, t->Key);

		if (crl == NULL) {
			ret = ERR_OBJECT_NOT_FOUND;
		} else {
			CRL *new_crl = CopyCrl(t->Crl);
			if (ReplaceListPointer(h->HubDb->CrlList, crl, new_crl)) {
				ALog(a, h, "LA_SET_CRL");
				FreeCrl(crl);

				IncrementServerConfigRevision(s);
			}
		}
	}
	UnlockList(h->HubDb->CrlList);

	ReleaseHub(h);

	return ret;
}

UINT StGetCrl(ADMIN *a, RPC_CRL *t) {
	UINT ret = ERR_NO_ERROR;
	char hubname[MAX_HUBNAME_LEN + 1];

	CHECK_RIGHT;
	StrCpy(hubname, sizeof(hubname), t->HubName);
	UINT key = t->Key;

	FreeRpcCrl(t);
	Zero(t, sizeof(RPC_CRL));
	StrCpy(t->HubName, sizeof(t->HubName), hubname);
	t->Key = key;

	HUB *h = AdminGetHub(a, hubname, NULL, &ret);
	if (h == NULL)
		return ret;

	LockList(h->HubDb->CrlList);
	{
		CRL *crl = ListKeyToPointer(h->HubDb->CrlList, t->Key);

		if (crl == NULL)
			ret = ERR_OBJECT_NOT_FOUND;
		else
			t->Crl = CopyCrl(crl);
	}
	UnlockList(h->HubDb->CrlList);

	ReleaseHub(h);

	return ret;
}

UINT StDelCrl(ADMIN *a, RPC_CRL *t) {
	SERVER *s = a->Server;
	UINT ret = ERR_NO_ERROR;

	CHECK_RIGHT;

	HUB *h = AdminGetHub(a, t->HubName, "no_change_crl_list", &ret);
	if (h == NULL)
		return ret;

	LockList(h->HubDb->CrlList);
	{
		CRL *crl = ListKeyToPointer(h->HubDb->CrlList, t->Key);

		if (crl == NULL) {
			ret = ERR_OBJECT_NOT_FOUND;
		} else {
			ALog(a, h, "LA_DEL_CRL");
			FreeCrl(crl);
			Delete(h->HubDb->CrlList, crl);

			IncrementServerConfigRevision(s);
		}
	}
	UnlockList(h->HubDb->CrlList);

	ReleaseHub(h);

	return ret;
}

UINT StAddCrl(ADMIN *a, RPC_CRL *t) {
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	UINT err;

	CHECK_RIGHT;

	HUB *h = AdminGetHub(a, t->HubName, "no_change_crl_list", &err);
	if (h == NULL)
		return err;

	LockList(h->HubDb->CrlList);
	{
		if (LIST_NUM(h->HubDb->CrlList) < MAX_HUB_CRLS) {
			CRL *crl = CopyCrl(t->Crl);

			Insert(h->HubDb->CrlList, crl);

			ALog(a, h, "LA_ADD_CRL");

			IncrementServerConfigRevision(s);
		}
	}
	UnlockList(h->HubDb->CrlList);

	ReleaseHub(h);

	return ERR_NO_ERROR;
}

UINT StEnumCrl(ADMIN *a, RPC_ENUM_CRL *t) {
	UINT ret = ERR_NO_ERROR;
	char hubname[MAX_HUBNAME_LEN + 1];

	CHECK_RIGHT;
	StrCpy(hubname, sizeof(hubname), t->HubName);
	FreeRpcEnumCrl(t);
	Zero(t, sizeof(RPC_ENUM_CRL));

	StrCpy(t->HubName, sizeof(t->HubName), hubname);

	HUB *h = AdminGetHub(a, hubname, NULL, &ret);
	if (h == NULL)
		return ret;

	LockList(h->HubDb->CrlList);
	{
		t->NumItem = LIST_NUM(h->HubDb->CrlList);
		t->Items = ZeroMalloc(sizeof(RPC_ENUM_CRL_ITEM) * t->NumItem);

		for (UINT i = 0; i < LIST_NUM(h->HubDb->CrlList); i++) {
			CRL *crl = LIST_DATA(h->HubDb->CrlList, i);
			wchar_t *info = GenerateCrlStr(crl);

			UniStrCpy(t->Items[i].CrlInfo, sizeof(t->Items[i].CrlInfo), info);
			Free(info);

			t->Items[i].Key = POINTER_TO_KEY(crl);
		}
	}
	UnlockList(h->HubDb->CrlList);

	ReleaseHub(h);

	return ret;
}
