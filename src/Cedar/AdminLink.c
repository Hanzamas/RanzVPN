// AdminLink.c
// Admin RPC area: cascade connections

#include "Admin.h"

#include "BridgeWin32.h"
#include "Connection.h"
#include "Link.h"
#include "Listener.h"
#include "RpcField.h"
#include "Protocol.h"
#include "Server.h"

#include "Mayaqua/Cfg.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Tick64.h"
#include "AdminInternal.h"

UINT StRenameLink(ADMIN *a, RPC_RENAME_LINK *t)
{
	SERVER *s = a->Server;
	UINT ret = ERR_NO_ERROR;
	LINK *k;

	if (UniIsEmptyStr(t->OldAccountName) || UniIsEmptyStr(t->NewAccountName))
	{
		return ERR_INVALID_PARAMETER;
	}

	CHECK_RIGHT;

	if (UniStrCmpi(t->NewAccountName, t->OldAccountName) == 0)
	{
		return ERR_NO_ERROR;
	}

	HUB *h = AdminGetHub(a, t->HubName, "no_cascade", &ret);
	if (h == NULL)
	{
		return ret;
	}

	// The list stays locked (the lock is recursive), so the name check and the rename are one step
	LockList(h->LinkList);
	{
		k = FindLinkByAccountName(h, t->OldAccountName);

		if (k != NULL)
		{
			LINK *same = FindLinkByAccountName(h, t->NewAccountName);

			if (same != NULL)
			{
				ReleaseLink(same);
				ret = ERR_LINK_ALREADY_EXISTS;
			}
			else
			{
				UniStrCpy(k->Option->AccountName, sizeof(k->Option->AccountName), t->NewAccountName);

				ALog(a, h, "LA_RENAME_LINK", t->OldAccountName, t->NewAccountName);

				IncrementServerConfigRevision(s);
			}
		}
	}
	UnlockList(h->LinkList);

	if (k == NULL)
	{
		ReleaseHub(h);
		return ERR_OBJECT_NOT_FOUND;
	}

	ReleaseLink(k);

	ReleaseHub(h);

	return ret;
}

UINT StDeleteLink(ADMIN *a, RPC_LINK *t)
{
	SERVER *s = a->Server;
	UINT err;
	UINT ret = ERR_NO_ERROR;
	wchar_t accountname[MAX_ACCOUNT_NAME_LEN + 1];

	if (UniIsEmptyStr(t->AccountName))
	{
		return ERR_INVALID_PARAMETER;
	}

	HUB *h = AdminGetHub(a, t->HubName, "no_cascade", &err);
	if (h == NULL)
	{
		return err;
	}

	UniStrCpy(accountname, sizeof(accountname), t->AccountName);
	LINK *k = FindLinkByAccountName(h, accountname);

	if (k == NULL)
	{
		ReleaseHub(h);

		return ERR_OBJECT_NOT_FOUND;
	}

	k->NoOnline = true;

	ALog(a, h, "LA_DELETE_LINK", t->AccountName);

	SetLinkOffline(k);

	IncrementServerConfigRevision(s);

	DelLink(h, k);

	ReleaseLink(k);
	ReleaseHub(h);

	return ret;
}

UINT StSetLinkOffline(ADMIN *a, RPC_LINK *t)
{
	SERVER *s = a->Server;
	UINT err;
	UINT ret = ERR_NO_ERROR;
	wchar_t accountname[MAX_ACCOUNT_NAME_LEN + 1];


	if (UniIsEmptyStr(t->AccountName))
	{
		return ERR_INVALID_PARAMETER;
	}

	HUB *h = AdminGetHub(a, t->HubName, "no_cascade", &err);
	if (h == NULL)
	{
		return err;
	}

	UniStrCpy(accountname, sizeof(accountname), t->AccountName);
	LINK *k = FindLinkByAccountName(h, accountname);

	if (k == NULL)
	{
		ReleaseHub(h);

		return ERR_OBJECT_NOT_FOUND;
	}

	ALog(a, h, "LA_SET_LINK_OFFLINE", t->AccountName);

	SetLinkOffline(k);

	IncrementServerConfigRevision(s);

	ReleaseLink(k);
	ReleaseHub(h);

	return ret;
}

UINT StSetLinkOnline(ADMIN *a, RPC_LINK *t)
{
	SERVER *s = a->Server;
	UINT err;
	UINT ret = ERR_NO_ERROR;
	wchar_t accountname[MAX_ACCOUNT_NAME_LEN + 1];


	if (UniIsEmptyStr(t->AccountName))
	{
		return ERR_INVALID_PARAMETER;
	}

	HUB *h = AdminGetHub(a, t->HubName, "no_cascade", &err);
	if (h == NULL)
	{
		return err;
	}

	UniStrCpy(accountname, sizeof(accountname), t->AccountName);
	LINK *k = FindLinkByAccountName(h, accountname);

	if (k == NULL)
	{
		ReleaseHub(h);

		return ERR_OBJECT_NOT_FOUND;
	}

	ALog(a, h, "LA_SET_LINK_ONLINE", t->AccountName);

	SetLinkOnline(k);

	ReleaseLink(k);
	ReleaseHub(h);

	IncrementServerConfigRevision(s);

	return ret;
}

UINT StGetLinkStatus(ADMIN *a, RPC_LINK_STATUS *t)
{
	UINT err;
	UINT ret = ERR_NO_ERROR;
	char hubname[MAX_HUBNAME_LEN + 1];
	wchar_t accountname[MAX_ACCOUNT_NAME_LEN + 1];
	SESSION *sess;

	if (UniIsEmptyStr(t->AccountName))
	{
		return ERR_INVALID_PARAMETER;
	}

	HUB *h = AdminGetHub(a, t->HubName, NULL, &err);
	if (h == NULL)
	{
		return err;
	}

	StrCpy(hubname, sizeof(hubname), t->HubName);
	UniStrCpy(accountname, sizeof(accountname), t->AccountName);
	FreeRpcLinkStatus(t);
	Zero(t, sizeof(RPC_LINK_STATUS));
	StrCpy(t->HubName, sizeof(t->HubName), hubname);
	UniStrCpy(t->AccountName, sizeof(t->AccountName), accountname);

	LINK *k = FindLinkByAccountName(h, accountname);

	if (k == NULL)
	{
		ReleaseHub(h);

		return ERR_OBJECT_NOT_FOUND;
	}

	Lock(k->lock);
	{
		sess = k->ClientSession;
		if (sess != NULL)
		{
			AddRef(sess->ref);
		}
	}
	Unlock(k->lock);

	if (sess != NULL && k->Offline == false)
	{
		CiGetSessionStatus(&t->Status, sess);
	}
	else
	{
		ret = ERR_LINK_IS_OFFLINE;
	}
	ReleaseSession(sess);

	ReleaseLink(k);
	ReleaseHub(h);

	return ret;
}

UINT StEnumLink(ADMIN *a, RPC_ENUM_LINK *t)
{
	UINT err;
	char hubname[MAX_HUBNAME_LEN + 1];

	HUB *h = AdminGetHub(a, t->HubName, NULL, &err);
	if (h == NULL)
	{
		return err;
	}

	StrCpy(hubname, sizeof(hubname), t->HubName);
	FreeRpcEnumLink(t);
	Zero(t, sizeof(RPC_ENUM_LINK));
	StrCpy(t->HubName, sizeof(t->HubName), hubname);

	LockList(h->LinkList);
	{
		t->NumLink = LIST_NUM(h->LinkList);
		t->Links = ZeroMalloc(sizeof(RPC_ENUM_LINK_ITEM) * t->NumLink);

		for (UINT i = 0;i < LIST_NUM(h->LinkList);i++)
		{
			LINK *k = LIST_DATA(h->LinkList, i);
			RPC_ENUM_LINK_ITEM *e = &t->Links[i];

			Lock(k->lock);
			{
				UniStrCpy(e->AccountName, sizeof(e->AccountName), k->Option->AccountName);
				StrCpy(e->Hostname, sizeof(e->Hostname), k->Option->Hostname);
				StrCpy(e->HubName, sizeof(e->HubName), k->Option->HubName);
				e->Online = k->Offline ? false : true;

				if (e->Online)
				{
					if (k->ClientSession != NULL)
					{
						e->ConnectedTime = Tick64ToTime64(k->ClientSession->CurrentConnectionEstablishTime);
						e->Connected = (k->ClientSession->ClientStatus == CLIENT_STATUS_ESTABLISHED);
						e->LastError = k->ClientSession->Err;
					}
				}
			}
			Unlock(k->lock);
		}
	}
	UnlockList(h->LinkList);

	ReleaseHub(h);

	return ERR_NO_ERROR;
}

UINT StGetLink(ADMIN *a, RPC_CREATE_LINK *t)
{
	UINT err;
	UINT ret = ERR_NO_ERROR;
	char hubname[MAX_SIZE];

	HUB *h = AdminGetHub(a, t->HubName, NULL, &err);
	if (h == NULL)
	{
		return err;
	}

	LINK *k = FindLinkByAccountName(h, t->ClientOption->AccountName);

	if (k == NULL)
	{
		ReleaseHub(h);
		return ERR_OBJECT_NOT_FOUND;
	}

	StrCpy(hubname, sizeof(hubname), t->HubName);
	FreeRpcCreateLink(t);
	Zero(t, sizeof(RPC_CREATE_LINK));
	StrCpy(t->HubName, sizeof(t->HubName), hubname);

	Lock(k->lock);
	{
		t->Online = k->Offline ? false : true;
		t->ClientOption = ClientOptionClone(k->Option);
		t->ClientAuth = ClientAuthClone(k->Auth);
		Copy(&t->Policy, k->Policy, sizeof(POLICY));

		t->CheckServerCert = k->CheckServerCert;
		t->AddDefaultCA = k->AddDefaultCA;
		t->ServerCert = CloneX(k->ServerCert);
	}
	Unlock(k->lock);

	ReleaseLink(k);
	ReleaseHub(h);

	return ret;
}

UINT StSetLink(ADMIN *a, RPC_CREATE_LINK *t)
{
	SERVER *s = a->Server;
	UINT err;
	UINT ret = ERR_NO_ERROR;

	// The checks of NewLink: a supported authentication type, and the policy fields every cascade has
	if (LinkValidateAuthAndPolicy(t->ClientAuth, &t->Policy) == false)
	{
		return ERR_INVALID_PARAMETER;
	}

	HUB *h = AdminGetHub(a, t->HubName, "no_cascade", &err);
	if (h == NULL)
	{
		return err;
	}

	LINK *k = FindLinkByAccountName(h, t->ClientOption->AccountName);

	if (k == NULL)
	{
		ReleaseHub(h);
		return ERR_OBJECT_NOT_FOUND;
	}

	ALog(a, h, "LA_SET_LINK", t->ClientOption->AccountName);

	Lock(k->lock);
	{
		if (k->ServerCert != NULL)
		{
			FreeX(k->ServerCert);
			k->ServerCert = NULL;
		}

		Copy(k->Option, t->ClientOption, sizeof(CLIENT_OPTION));
		NormalizeLinkOption(k->Option);
		ClientAuthFree(k->Auth);
		k->Auth = ClientAuthClone(t->ClientAuth);

		if (t->Policy.Ver3 == false)
		{
			Copy(k->Policy, &t->Policy, POLICY_VER2_SIZE);
		}
		else
		{
			Copy(k->Policy, &t->Policy, sizeof(POLICY));
		}

		k->CheckServerCert = t->CheckServerCert;
		k->AddDefaultCA = t->AddDefaultCA;
		k->ServerCert = CloneX(t->ServerCert);
	}
	Unlock(k->lock);

	IncrementServerConfigRevision(s);

	ReleaseLink(k);
	ReleaseHub(h);

	return ret;
}

UINT StCreateLink(ADMIN *a, RPC_CREATE_LINK *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	UINT err;
	UINT ret = ERR_NO_ERROR;

	HUB *h = AdminGetHub(a, t->HubName, "no_cascade", &err);
	if (h == NULL)
	{
		return err;
	}

	LINK *k = FindLinkByAccountName(h, t->ClientOption->AccountName);

	if (k != NULL)
	{
		ReleaseLink(k);
		ReleaseHub(h);
		return ERR_LINK_ALREADY_EXISTS;
	}

	ALog(a, h, "LA_CREATE_LINK", t->ClientOption->AccountName);

	k = NewLink(c, h, t->ClientOption, t->ClientAuth, &t->Policy);

	if (k == NULL)
	{
		ret = ERR_INTERNAL_ERROR;
	}
	else
	{
		k->CheckServerCert = t->CheckServerCert;
		k->AddDefaultCA = t->AddDefaultCA;
		k->ServerCert = CloneX(t->ServerCert);

		k->Offline = false;
		SetLinkOffline(k);
		ReleaseLink(k);

		IncrementServerConfigRevision(s);
	}

	ReleaseHub(h);

	return ret;
}
