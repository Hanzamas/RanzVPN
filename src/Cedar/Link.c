// Link.c
// Inter-HUB Link

#include "Link.h"

#include "Account.h"
#include "Connection.h"
#include "Hub.h"
#include "HubLog.h"
#include "Protocol.h"
#include "Session.h"

#include "Mayaqua/Internat.h"
#include "Mayaqua/Kernel.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"

static void LinkServerSessionThread(THREAD *t, void *param) {
	LINK *k = (LINK *)param;
	wchar_t name[MAX_SIZE];
	if (t == NULL || param == NULL)
		return;

	CONNECTION *c = NewServerConnection(k->Cedar, NULL, t);
	c->Protocol = CONNECTION_HUB_LINK_SERVER;

	POLICY *policy = ZeroMalloc(sizeof(POLICY));
	Copy(policy, k->Policy, sizeof(POLICY));

	SESSION *s = NewServerSession(k->Cedar, c, k->Hub, LINK_USER_NAME, policy);
	s->LinkModeServer = true;
	s->Link = k;
	c->Session = s;
	ReleaseConnection(c);

	s->Username = CopyStr(LINK_USER_NAME_PRINT);

	k->ServerSession = s;
	AddRef(k->ServerSession->ref);

	NoticeThreadInit(t);

	UniStrCpy(name, sizeof(name), k->Option->AccountName);
	HLog(s->Hub, "LH_LINK_START", name, s->Name);

	SessionMain(s);

	HLog(s->Hub, "LH_LINK_STOP", name);

	ReleaseSession(s);
}

static bool LinkPaInit(SESSION *s) {
	LINK *k;
	if (s == NULL || (k = (LINK *)s->PacketAdapter->Param) == NULL)
		return false;

	if (k->Halting || (*k->StopAllLinkFlag))
		return false;

	k->SendPacketQueue = NewQueue();

	THREAD *t = NewThread(LinkServerSessionThread, (void *)k);
	WaitThreadInit(t);

	k->LastServerConnectionReceivedBlocksNum = 0;

	ReleaseThread(t);

	return true;
}

static CANCEL *LinkPaGetCancel(SESSION *s) {
	return NULL;
}

static UINT LinkPaGetNextPacket(SESSION *s, void **data) {
	LINK *k;
	UINT ret = 0;
	if (s == NULL || data == NULL || (k = (LINK *)s->PacketAdapter->Param) == NULL)
		return INFINITE;

	if (k->Halting || (*k->StopAllLinkFlag))
		return INFINITE;
	LockQueue(k->SendPacketQueue);
	{
		BLOCK *block = GetNext(k->SendPacketQueue);

		if (block != NULL) {
			*data = block->Buf;
			ret = block->Size;

			Free(block);
		}
	}
	UnlockQueue(k->SendPacketQueue);

	return ret;
}

static bool LinkPaPutPacket(SESSION *s, void *data, UINT size) {
	LINK *k;
	BLOCK *block = NULL;
	bool ret = true;
	bool halting = false;
	if (s == NULL || (k = (LINK *)s->PacketAdapter->Param) == NULL)
		return false;

	halting = (k->Halting || (*k->StopAllLinkFlag));

	// k->ServerSession is pinned by the link's ref until LinkPaFree, which runs on this thread;
	// the server session never clears its Connection, so take a ref on it for this call
	SESSION *server_session = k->ServerSession;
	CONNECTION *server_connection = server_session->Connection;
	AddRef(server_connection->ref);

	k->Flag1++;
	if ((k->Flag1 % 32) == 0) {
		// Only every 32nd call, for speed
		CedarSyncQueueBudget(k->Cedar, GetQueueNum(server_connection->ReceivedBlocks), &k->LastServerConnectionReceivedBlocksNum);
	}

	// The packet came from the link destination HUB,
	// so deliver it to the server session's ReceivedBlocks
	if (data != NULL) {
		if (halting == false)
			block = NewBlock(data, size, 0);

		if (k->LockFlag == false) {
			k->LockFlag = true;
			LockQueue(server_connection->ReceivedBlocks);

			CedarSyncQueueBudget(k->Cedar, GetQueueNum(server_connection->ReceivedBlocks), &k->LastServerConnectionReceivedBlocksNum);
		}

		if (halting == false) {
			if (CedarGetFifoBudgetBalance(k->Cedar) == 0)
				FreeBlock(block);
			else
				InsertReceivedBlockToQueue(server_connection, block);
		}
	} else {
		CedarSyncQueueBudget(k->Cedar, GetQueueNum(server_connection->ReceivedBlocks), &k->LastServerConnectionReceivedBlocksNum);

		if (k->LockFlag) {
			k->LockFlag = false;
			UnlockQueue(server_connection->ReceivedBlocks);
		}

		// data == NULL means all packets are stored, so issue the Cancel
		Cancel(server_session->Cancel1);

		if (k->Hub->Option->YieldAfterStorePacket)
			YieldCpu();
	}

	if (halting)
		ret = false;

	ReleaseConnection(server_connection);

	return ret;
}

static void LinkPaFree(SESSION *s) {
	LINK *k;
	if (s == NULL || (k = (LINK *)s->PacketAdapter->Param) == NULL)
		return;

	CedarSyncQueueBudget(k->Cedar, 0, &k->LastServerConnectionReceivedBlocksNum);

	StopSession(k->ServerSession);
	ReleaseSession(k->ServerSession);

	FreeBlockQueue(k->SendPacketQueue);
}

static PACKET_ADAPTER *LinkGetPacketAdapter() {
	return NewPacketAdapter(LinkPaInit, LinkPaGetCancel, LinkPaGetNextPacket,
	                        LinkPaPutPacket, LinkPaFree);
}

void ReleaseAllLink(HUB *h) {
	LINK **kk;
	UINT num;
	if (h == NULL)
		return;

	LockList(h->LinkList);
	{
		num = LIST_NUM(h->LinkList);
		kk = ToArray(h->LinkList);
		DeleteAll(h->LinkList);
	}
	UnlockList(h->LinkList);

	for (UINT i = 0; i < num; i++) {
		LINK *k = kk[i];

		ReleaseLink(k);
	}

	Free(kk);
}

void ReleaseLink(LINK *k) {
	if (k == NULL)
		return;

	if (Release(k->ref) == 0)
		CleanupLink(k);
}

void CleanupLink(LINK *k) {
	if (k == NULL)
		return;

	DeleteLock(k->lock);
	if (k->ClientSession)
		ReleaseSession(k->ClientSession);
	Free(k->Option);
	ClientAuthFree(k->Auth);
	Free(k->Policy);

	if (k->ServerCert != NULL)
		FreeX(k->ServerCert);

	Free(k);
}

void SetLinkOnline(LINK *k) {
	if (k == NULL)
		return;

	if (k->NoOnline)
		return;

	if (k->Offline == false)
		return;

	k->Offline = false;
	StartLink(k);
}

void SetLinkOffline(LINK *k) {
	if (k == NULL)
		return;

	if (k->Offline)
		return;

	StopLink(k);
	k->Offline = true;
}

void DelLink(HUB *hub, LINK *k) {
	if (hub == NULL || k == NULL)
		return;

	LockList(hub->LinkList);
	{
		if (Delete(hub->LinkList, k))
			ReleaseLink(k);
	}
	UnlockList(hub->LinkList);
}

void StartAllLink(HUB *h) {
	if (h == NULL)
		return;

	LockList(h->LinkList);
	{
		for (UINT i = 0; i < LIST_NUM(h->LinkList); i++) {
			LINK *k = (LINK *)LIST_DATA(h->LinkList, i);

			if (k->Offline == false)
				StartLink(k);
		}
	}
	UnlockList(h->LinkList);
}

void StopAllLink(HUB *h) {
	LINK **link_list;
	UINT num_link;
	if (h == NULL)
		return;

	h->StopAllLinkFlag = true;

	LockList(h->LinkList);
	{
		link_list = ToArray(h->LinkList);
		num_link = LIST_NUM(h->LinkList);
		for (UINT i = 0; i < num_link; i++)
			AddRef(link_list[i]->ref);
	}
	UnlockList(h->LinkList);

	for (UINT i = 0; i < num_link; i++) {
		StopLink(link_list[i]);
		ReleaseLink(link_list[i]);
	}

	Free(link_list);

	h->StopAllLinkFlag = false;
}

void StartLink(LINK *k) {
	if (k == NULL)
		return;

	LockLink(k);
	{
		if (k->Started || k->Halting) {
			UnlockLink(k);
			return;
		}
		k->Started = true;

		Inc(k->Cedar->CurrentActiveLinks);
	}
	UnlockLink(k);

	PACKET_ADAPTER *pa = LinkGetPacketAdapter();
	pa->Param = (void *)k;
	LockLink(k);
	{
		k->ClientSession = NewClientSession(k->Cedar, k->Option, k->Auth, pa);
	}
	UnlockLink(k);
}

void StopLink(LINK *k) {
	SESSION *s;
	if (k == NULL)
		return;

	// Read k->ClientSession and take a ref under the link lock, then stop the session
	// outside it (lock order: see StopSessionEx in Session.c)
	LockLink(k);
	{
		if (k->Started == false) {
			UnlockLink(k);
			return;
		}
		k->Started = false;
		k->Halting = true;

		Dec(k->Cedar->CurrentActiveLinks);

		s = k->ClientSession;
		if (s != NULL)
			AddRef(s->ref);
	}
	UnlockLink(k);

	if (s != NULL) {
		StopSession(s);

		LockLink(k);
		{
			if (k->ClientSession == s) {
				ReleaseSession(k->ClientSession);
				k->ClientSession = NULL;
			}
		}
		UnlockLink(k);

		ReleaseSession(s);
	}

	LockLink(k);
	{
		k->Halting = false;
	}
	UnlockLink(k);
}

void LockLink(LINK *k) {
	if (k == NULL)
		return;

	Lock(k->lock);
}

void UnlockLink(LINK *k) {
	if (k == NULL)
		return;

	Unlock(k->lock);
}

static void NormalizeLinkPolicy(POLICY *p) {
	if (p == NULL)
		return;

	p->Access = true;
	p->NoBridge = p->NoRouting = p->MonitorPort = false;
	p->MaxConnection = 32;
	p->TimeOut = 20;
	p->FixPassword = false;
}

// Check the authentication type of a cascade and set the policy fields every cascade has, in place.
// NewLink and the SetLink admin RPC call it; false for an authentication type a cascade cannot use
bool LinkValidateAuthAndPolicy(CLIENT_AUTH *auth, POLICY *policy) {
	if (auth == NULL || policy == NULL)
		return false;

	if (auth->AuthType != CLIENT_AUTHTYPE_ANONYMOUS && auth->AuthType != CLIENT_AUTHTYPE_PASSWORD &&
	    auth->AuthType != CLIENT_AUTHTYPE_PLAIN_PASSWORD && auth->AuthType != CLIENT_AUTHTYPE_CERT)
		return false;

	NormalizeLinkPolicy(policy);

	return true;
}

// Set the client option fields every cascade has, in place.
// NewLink and the SetLink admin RPC call it
void NormalizeLinkOption(CLIENT_OPTION *option) {
	if (option == NULL)
		return;

	StrCpy(option->DeviceName, sizeof(option->DeviceName), LINK_DEVICE_NAME);

	option->RequireBridgeRoutingMode = true;
	option->RequireMonitorMode = false;

	option->NumRetry = INFINITE;
	option->RetryInterval = 10; // seconds
	option->NoRoutingTracking = true;
}

// Find the cascade of a hub by its account name. Returns the link with its reference count raised, or NULL
LINK *FindLinkByAccountName(HUB *hub, wchar_t *account_name) {
	LINK *found = NULL;

	if (hub == NULL || account_name == NULL)
		return NULL;

	LockList(hub->LinkList);
	{
		for (UINT i = 0; i < LIST_NUM(hub->LinkList); i++) {
			LINK *k = LIST_DATA(hub->LinkList, i);

			Lock(k->lock);
			{
				if (UniStrCmpi(k->Option->AccountName, account_name) == 0) {
					found = k;
					AddRef(k->ref);
				}
			}
			Unlock(k->lock);

			if (found != NULL)
				break;
		}
	}
	UnlockList(hub->LinkList);

	return found;
}

LINK *NewLink(CEDAR *cedar, HUB *hub, CLIENT_OPTION *option, CLIENT_AUTH *auth, POLICY *policy) {
	POLICY link_policy;
	bool added = false;
	if (cedar == NULL || hub == NULL || option == NULL || auth == NULL || policy == NULL)
		return NULL;
	if (hub->Halt)
		return NULL;

	if (UniIsEmptyStr(option->AccountName))
		return NULL;

	Copy(&link_policy, policy, sizeof(POLICY));
	if (LinkValidateAuthAndPolicy(auth, &link_policy) == false)
		return NULL;

	CLIENT_OPTION *o = ClientOptionClone(option);
	NormalizeLinkOption(o);

	CLIENT_AUTH *a = ClientAuthClone(auth);

	LINK *k = ZeroMalloc(sizeof(LINK));

	k->StopAllLinkFlag = &hub->StopAllLinkFlag;

	k->lock = NewLock();
	k->ref = NewRef();

	k->Cedar = cedar;
	k->Option = o;
	k->Auth = a;
	k->Hub = hub;

	k->Policy = ZeroMalloc(sizeof(POLICY));
	Copy(k->Policy, &link_policy, sizeof(POLICY));

	// Check MAX_HUB_LINKS under the list lock, where the link is added
	LockList(hub->LinkList);
	{
		if (LIST_NUM(hub->LinkList) < MAX_HUB_LINKS) {
			Add(hub->LinkList, k);
			AddRef(k->ref);
			added = true;
		}
	}
	UnlockList(hub->LinkList);

	if (added == false) {
		ReleaseLink(k);
		return NULL;
	}

	return k;
}

