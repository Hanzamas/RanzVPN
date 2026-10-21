// AdminCa.c
// Admin RPC area: trusted CA certificates of a Virtual Hub

#include "Admin.h"

#include "BridgeWin32.h"
#include "Connection.h"
#include "Link.h"
#include "Listener.h"
#include "Remote.h"
#include "RpcField.h"
#include "Protocol.h"
#include "Server.h"

#include "Mayaqua/Memory.h"
#include "Mayaqua/Str.h"
#include "AdminInternal.h"

UINT StDeleteCa(ADMIN *a, RPC_HUB_DELETE_CA *t)
{
	SERVER *s = a->Server;
	HUB *h;
	UINT err;
	UINT ret = ERR_NO_ERROR;

	h = AdminGetHub(a, t->HubName, "no_change_cert_list", &err);
	if (h == NULL)
	{
		return err;
	}

	LockList(h->HubDb->RootCertList);
	{
		if (IsInListKey(h->HubDb->RootCertList, t->Key))
		{
			X *x = ListKeyToPointer(h->HubDb->RootCertList, t->Key);
			Delete(h->HubDb->RootCertList, x);
			FreeX(x);

			ALog(a, h, "LA_DELETE_CA");

			IncrementServerConfigRevision(s);
		}
		else
		{
			ret = ERR_OBJECT_NOT_FOUND;
		}
	}
	UnlockList(h->HubDb->RootCertList);

	ReleaseHub(h);

	return ret;
}

UINT StGetCa(ADMIN *a, RPC_HUB_GET_CA *t)
{
	HUB *h;
	UINT err;
	UINT ret = ERR_NO_ERROR;
	char hubname[MAX_HUBNAME_LEN + 1];
	UINT key;

	StrCpy(hubname, sizeof(hubname), t->HubName);
	key = t->Key;

	FreeRpcHubGetCa(t);
	Zero(t, sizeof(RPC_HUB_GET_CA));
	t->Key = key;
	StrCpy(t->HubName, sizeof(t->HubName), hubname);

	h = AdminGetHub(a, t->HubName, NULL, &err);
	if (h == NULL)
	{
		return err;
	}

	LockList(h->HubDb->RootCertList);
	{
		if (IsInListKey(h->HubDb->RootCertList, key))
		{
			X *x = ListKeyToPointer(h->HubDb->RootCertList, key);

			t->Cert = CloneX(x);
		}
		else
		{
			ret = ERR_OBJECT_NOT_FOUND;
		}
	}
	UnlockList(h->HubDb->RootCertList);

	ReleaseHub(h);

	return ret;
}

UINT StEnumCa(ADMIN *a, RPC_HUB_ENUM_CA *t)
{
	HUB *h;
	UINT err;
	char hubname[MAX_HUBNAME_LEN + 1];
	UINT i;

	StrCpy(hubname, sizeof(hubname), t->HubName);

	FreeRpcHubEnumCa(t);
	Zero(t, sizeof(RPC_HUB_ENUM_CA));

	StrCpy(t->HubName, sizeof(t->HubName), hubname);
	h = AdminGetHub(a, t->HubName, NULL, &err);
	if (h == NULL)
	{
		return err;
	}

	LockList(h->HubDb->RootCertList);
	{
		t->NumCa = LIST_NUM(h->HubDb->RootCertList);
		t->Ca = ZeroMalloc(sizeof(RPC_HUB_ENUM_CA_ITEM) * t->NumCa);

		for (i = 0;i < t->NumCa;i++)
		{
			RPC_HUB_ENUM_CA_ITEM *e = &t->Ca[i];
			X *x = LIST_DATA(h->HubDb->RootCertList, i);

			e->Key = POINTER_TO_KEY(x);
			GetAllNameFromNameEx(e->SubjectName, sizeof(e->SubjectName), x->subject_name);
			GetAllNameFromNameEx(e->IssuerName, sizeof(e->IssuerName), x->issuer_name);
			e->Expires = x->notAfter;
		}
	}
	UnlockList(h->HubDb->RootCertList);

	ReleaseHub(h);

	return ERR_NO_ERROR;
}

UINT StAddCa(ADMIN *a, RPC_HUB_ADD_CA *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	UINT err;

	if (t->Cert == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	h = AdminGetHub(a, t->HubName, "no_change_cert_list", &err);
	if (h == NULL)
	{
		return err;
	}

	// The hub ignores a certificate it already trusts and one over MAX_HUB_CERTS; the call still succeeds
	if (AddRootCert(h, t->Cert))
	{
		ALog(a, h, "LA_ADD_CA");

		IncrementServerConfigRevision(s);
	}

	ReleaseHub(h);

	return ERR_NO_ERROR;
}
