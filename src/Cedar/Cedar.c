// Cedar.c
// Cedar Communication Module

#include "Cedar.h"

#include "Admin.h"
#include "Bridge.h"
#include "BuildInfo.h"
#include "Connection.h"
#include "HubLog.h"
#include "Link.h"
#include "Listener.h"
#include "Protocol.h"
#include "Sam.h"
#include "Session.h"
#include "WaterMark.h"

#include "Mayaqua/Cfg.h"
#include "Mayaqua/Encrypt.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/HTTP.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Mayaqua.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Platform.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Table.h"
#include "Mayaqua/Tick64.h"

static void DeleteOldNoSsl(CEDAR *c);
static void MakeRoomInNoSslList(CEDAR *c);
static NON_SSL *SearchNoSslList(CEDAR *c, const IP *ip);
static void FreeNetSvcList(CEDAR *cedar);

static UINT init_cedar_counter = 0;

static bool IsSupportedWinVer(const RPC_WINVER *v) {
	if (v == NULL)
		return false;

	if (v->IsWindows == false)
		return true;

	if (v->IsNT == false)
		return true;

	if (v->IsBeta)
		return true;

	if (v->VerMajor <= 4) {
		// Windows NT
		return true;
	}

	if (v->VerMajor == 5 && v->VerMinor == 0) {
		// Windows 2000
		if (v->ServicePack <= 4)
			return true;
	}

	if (v->VerMajor == 5 && v->VerMinor == 1) {
		// Windows XP x86
		if (v->ServicePack <= 3)
			return true;
	}

	if (v->VerMajor == 5 && v->VerMinor == 2) {
		// Windows XP x64, Windows Server 2003
		if (v->ServicePack <= 2)
			return true;
	}

	if (v->VerMajor == 6 && v->VerMinor == 0) {
		// Windows Vista, Server 2008
		if (v->ServicePack <= 2)
			return true;
	}

	if (v->VerMajor == 6 && v->VerMinor == 1) {
		// Windows 7, Server 2008 R2
		if (v->ServicePack <= 1)
			return true;
	}

	if (v->VerMajor == 6 && v->VerMinor == 2) {
		// Windows 8, Server 2012
		if (v->ServicePack <= 0)
			return true;
	}

	if (v->VerMajor == 6 && v->VerMinor == 3) {
		// Windows 8.1, Server 2012 R2
		if (v->ServicePack <= 0)
			return true;
	}

	if ((v->VerMajor == 6 && v->VerMinor == 4) || (v->VerMajor == 10 && v->VerMinor == 0)) {
		// Windows 10 or Windows Server 2016
		if (v->ServicePack <= 0)
			return true;
	}

	return false;
}

// Message for a peer that runs an unsupported Windows version (empty for any other peer)
void FormatUnsupportedWinVerMsg(wchar_t *buf, UINT size, RPC_WINVER *peer) {
	SYSTEMTIME st;

	if (buf == NULL || size == 0)
		return;

	Zero(buf, size);

	if (peer == NULL || IsSupportedWinVer(peer))
		return;

	LocalTime(&st);

	UniFormat(buf, size, _UU("WINVER_ERROR_FORMAT"),
	          _UU("WINVER_ERROR_PC_LOCAL"),
	          peer->Title,
	          _UU("WINVER_ERROR_VPNSERVER"),
	          SUPPORTED_WINDOWS_LIST,
	          _UU("WINVER_ERROR_PC_LOCAL"),
	          _UU("WINVER_ERROR_VPNSERVER"),
	          _UU("WINVER_ERROR_VPNSERVER"),
	          _UU("WINVER_ERROR_VPNSERVER"),
	          st.wYear, st.wMonth);
}

void GetWinVer(RPC_WINVER *v) {
	const OSVERSIONINFOEXW *os = Win32GetOsVersion();

	if (v == NULL)
		return;

	Zero(v, sizeof(RPC_WINVER));

	v->IsWindows = true;
	v->IsNT = true;
	v->Build = os->dwBuildNumber;
	v->ServicePack = os->wServicePackMajor;
	v->IsServer = (os->wProductType != VER_NT_WORKSTATION);
	v->VerMajor = os->dwMajorVersion;
	v->VerMinor = os->dwMinorVersion;

	// Windows 10 and later have no service packs
	StrCpy(v->Title, sizeof(v->Title), GetOsInfo()->OsProductName);
	Trim(v->Title);

	if (InStr(GetOsInfo()->OsVersion, "rc") ||
	    InStr(GetOsInfo()->OsVersion, "beta"))
		v->IsBeta = true;
}

void FreeTinyLog(TINY_LOG *t) {
	if (t == NULL)
		return;

	FileClose(t->io);
	DeleteLock(t->Lock);
	Free(t);
}

void WriteTinyLog(TINY_LOG *t, char *str) {
	char dt[MAX_PATH];
	if (t == NULL)
		return;

	GetDateTimeStrMilli64(dt, sizeof(dt), LocalTime64());
	StrCat(dt, sizeof(dt), ": ");

	BUF *b = NewBuf();

	WriteBuf(b, dt, StrLen(dt));
	WriteBuf(b, str, StrLen(str));
	WriteBuf(b, "\r\n", 2);

	Lock(t->Lock);
	{
		FileWrite(t->io, b->Buf, b->Size);
	}
	Unlock(t->Lock);

	FreeBuf(b);
}

TINY_LOG *NewTinyLog() {
	char name[MAX_PATH];
	SYSTEMTIME st;

	LocalTime(&st);

	MakeDir(TINY_LOG_DIRNAME);

	Format(name, sizeof(name), TINY_LOG_FILENAME,
	       st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

	TINY_LOG *t = ZeroMalloc(sizeof(TINY_LOG));

	StrCpy(t->FileName, sizeof(t->FileName), name);
	t->io = FileCreate(name);
	t->Lock = NewLock();

	return t;
}

static int CompareNoSslList(void *p1, void *p2) {
	if (p1 == NULL || p2 == NULL)
		return 0;
	NON_SSL *n1 = *(NON_SSL **)p1;
	NON_SSL *n2 = *(NON_SSL **)p2;
	if (n1 == NULL || n2 == NULL)
		return 0;
	return CmpIpAddr(&n1->IpAddress, &n2->IpAddress);
}

void DecrementNoSsl(CEDAR *c, IP *ip, UINT num_dec) {
	if (c == NULL || ip == NULL)
		return;

	LockList(c->NonSslList);
	{
		NON_SSL *n = SearchNoSslList(c, ip);

		if (n != NULL) {
			if (n->Count >= num_dec)
				n->Count -= num_dec;
		}
	}
	UnlockList(c->NonSslList);
}

bool IsInNoSsl(CEDAR *c, IP *ip) {
	bool ret = false;
	if (c == NULL || ip == NULL)
		return false;

	LockList(c->NonSslList);
	{
		NON_SSL *n = SearchNoSslList(c, ip);

		if (n != NULL) {
			if (n->EntryExpires > Tick64() && n->Count > NON_SSL_MIN_COUNT) {
				n->EntryExpires = Tick64() + (UINT64)NON_SSL_ENTRY_EXPIRES;
				ret = true;
			}
		}
	}
	UnlockList(c->NonSslList);

	return ret;
}

bool AddNoSsl(CEDAR *c, IP *ip) {
	NON_SSL *n;
	bool ret = true;
	if (c == NULL || ip == NULL)
		return true;

	LockList(c->NonSslList);
	{
		DeleteOldNoSsl(c);

		n = SearchNoSslList(c, ip);

		if (n == NULL) {
			if (LIST_NUM(c->NonSslList) >= RATE_LIMIT_TABLE_MAX)
				MakeRoomInNoSslList(c);

			n = ZeroMalloc(sizeof(NON_SSL));
			GetRateLimitKey(&n->IpAddress, ip);
			n->Count = 0;

			Insert(c->NonSslList, n);
		}

		n->EntryExpires = Tick64() + (UINT64)NON_SSL_ENTRY_EXPIRES;

		n->Count++;

		if (n->Count > NON_SSL_MIN_COUNT)
			ret = false;
	}
	UnlockList(c->NonSslList);

	return ret;
}

static bool IsNoSslExpired(void *p, void *param) {
	NON_SSL *n = p;

	return (n->EntryExpires <= *(UINT64 *)param);
}

static void DeleteOldNoSsl(CEDAR *c) {
	if (c == NULL)
		return;

	UINT64 now = Tick64();

	DeleteAndFreeIf(c->NonSslList, IsNoSslExpired, &now);
}

// NonSslList is full after DeleteOldNoSsl: drop the least recently seen entry; log the first time
static void MakeRoomInNoSslList(CEDAR *c) {
	NON_SSL *oldest = NULL;

	for (UINT i = 0; i < LIST_NUM(c->NonSslList); i++) {
		NON_SSL *n = LIST_DATA(c->NonSslList, i);

		if (oldest == NULL || n->EntryExpires < oldest->EntryExpires)
			oldest = n;
	}

	if (oldest != NULL) {
		Delete(c->NonSslList, oldest);
		Free(oldest);
	}

	if (c->NonSslListFullLogged == false) {
		c->NonSslListFullLogged = true;
		SLog(c, "LS_NON_SSL_TABLE_FULL", (UINT)RATE_LIMIT_TABLE_MAX);
	}
}

static NON_SSL *SearchNoSslList(CEDAR *c, const IP *ip) {
	NON_SSL t;
	if (c == NULL || ip == NULL)
		return NULL;

	Zero(&t, sizeof(t));
	GetRateLimitKey(&t.IpAddress, ip);

	NON_SSL *n = Search(c->NonSslList, &t);

	if (n == NULL)
		return NULL;

	return n;
}

static void InitNoSslList(CEDAR *c) {
	if (c == NULL)
		return;

	c->NonSslList = NewList(CompareNoSslList);
}

static void FreeNoSslList(CEDAR *c) {
	if (c == NULL)
		return;

	for (UINT i = 0; i < LIST_NUM(c->NonSslList); i++) {
		NON_SSL *n = LIST_DATA(c->NonSslList, i);

		Free(n);
	}

	ReleaseList(c->NonSslList);
	c->NonSslList = NULL;
}

UINT64 GetTrafficPacketSize(TRAFFIC *t) {
	if (t == NULL)
		return 0;

	return t->Recv.BroadcastBytes + t->Recv.UnicastBytes +
	       t->Send.BroadcastBytes + t->Send.UnicastBytes;
}

UINT64 GetTrafficPacketNum(TRAFFIC *t) {
	if (t == NULL)
		return 0;

	return t->Recv.BroadcastCount + t->Recv.UnicastCount +
	       t->Send.BroadcastCount + t->Send.UnicastCount;
}

void DelConnection(CEDAR *cedar, CONNECTION *c) {
	if (cedar == NULL || c == NULL)
		return;

	LockList(cedar->ConnectionList);
	{
		if (Delete(cedar->ConnectionList, c))
			ReleaseConnection(c);
	}
	UnlockList(cedar->ConnectionList);
}

UINT GetUnestablishedConnections(CEDAR *cedar) {
	if (cedar == NULL)
		return 0;

	UINT ret = 0;

	LockList(cedar->ConnectionList);
	{
		for (UINT i = 0; i < LIST_NUM(cedar->ConnectionList); i++) {
			CONNECTION *c = LIST_DATA(cedar->ConnectionList, i);

			switch (c->Type) {
			case CONNECTION_TYPE_CLIENT:
			case CONNECTION_TYPE_INIT:
			case CONNECTION_TYPE_LOGIN:
			case CONNECTION_TYPE_ADDITIONAL:
				switch (c->Status) {
				case CONNECTION_STATUS_ACCEPTED:
				case CONNECTION_STATUS_NEGOTIATION:
				case CONNECTION_STATUS_USERAUTH:
					ret++;
					break;
				}
				break;
			}
		}
	}
	UnlockList(cedar->ConnectionList);

	return ret + Count(cedar->AcceptingSockets);
}

void AddConnection(CEDAR *cedar, CONNECTION *c) {
	char tmp[MAX_SIZE];
	if (cedar == NULL || c == NULL)
		return;

	UINT i = Inc(cedar->ConnectionIncrement);
	Format(tmp, sizeof(tmp), "CID-%u", i);

	Lock(c->lock);
	{
		Free(c->Name);
		c->Name = CopyStr(tmp);
	}
	Unlock(c->lock);

	LockList(cedar->ConnectionList);
	{
		Add(cedar->ConnectionList, c);
		AddRef(c->ref);
	}
	UnlockList(cedar->ConnectionList);
}

static void StopAllConnection(CEDAR *c) {
	UINT num;
	CONNECTION **connections;
	if (c == NULL)
		return;

	LockList(c->ConnectionList);
	{
		connections = ToArray(c->ConnectionList);
		num = LIST_NUM(c->ConnectionList);
		DeleteAll(c->ConnectionList);
	}
	UnlockList(c->ConnectionList);

	for (UINT i = 0; i < num; i++) {
		StopConnection(connections[i], false);
		ReleaseConnection(connections[i]);
	}
	Free(connections);
}

void DelHub(CEDAR *c, HUB *h) {
	if (c == NULL || h == NULL)
		return;

	LockHubList(c);

	if (Delete(c->HubList, h))
		ReleaseHub(h);

	UnlockHubList(c);
}

void AddHub(CEDAR *c, HUB *h) {
	if (c == NULL || h == NULL)
		return;

	LockHubList(c);
	{
		if (IsHub(c, h->Name)) {
			UnlockHubList(c);
			return;
		}

		Insert(c->HubList, h);
		AddRef(h->ref);
	}
	UnlockHubList(c);
}

static void StopAllHub(CEDAR *c) {
	HUB **hubs;
	UINT num;
	if (c == NULL)
		return;

	LockHubList(c);
	{
		hubs = ToArray(c->HubList);
		num = LIST_NUM(c->HubList);
		DeleteAll(c->HubList);
	}
	UnlockHubList(c);

	for (UINT i = 0; i < num; i++) {
		StopHub(hubs[i]);
		ReleaseHub(hubs[i]);
	}

	Free(hubs);
}

void AddListener(CEDAR *c, LISTENER *r) {
	if (c == NULL || r == NULL)
		return;

	LockList(c->ListenerList);
	{
		Add(c->ListenerList, r);
		AddRef(r->ref);
	}
	UnlockList(c->ListenerList);
}

static void StopAllListener(CEDAR *c) {
	LISTENER **array;
	UINT num;
	if (c == NULL)
		return;

	LockList(c->ListenerList);
	{
		array = ToArray(c->ListenerList);
		num = LIST_NUM(c->ListenerList);
		DeleteAll(c->ListenerList);
	}
	UnlockList(c->ListenerList);

	for (UINT i = 0; i < num; i++) {
		StopListener(array[i]);
		ReleaseListener(array[i]);
	}
	Free(array);
}

// Both budgets are plain counters shared by every connection and link of the Cedar, so one atomic add
// replaces the lock each of them had. Callers keep the queue budget in step through CedarSyncQueueBudget
static void CedarAddQueueBudget(CEDAR *c, int diff) {
	if (c == NULL || diff == 0)
		return;

	InterlockedExchangeAdd((volatile LONG *)&c->QueueBudget, (LONG)diff);
}
// Moves the queue budget by how much one queue's block count changed since its last sync, and records
// the new count. A count of 0 hands back everything that queue still holds in the budget
void CedarSyncQueueBudget(CEDAR *c, UINT current, UINT *last) {
	if (last == NULL)
		return;

	CedarAddQueueBudget(c, (int)current - (int)(*last));
	*last = current;
}
void CedarAddFifoBudget(CEDAR *c, int diff) {
	if (c == NULL || diff == 0)
		return;

	InterlockedExchangeAdd((volatile LONG *)&c->FifoBudget, (LONG)diff);
}
UINT CedarGetQueueBudgetConsuming(CEDAR *c) {
	if (c == NULL)
		return 0;

	// Barrier read of the atomically changed counter
	return (UINT)InterlockedCompareExchange((volatile LONG *)&c->QueueBudget, 0, 0);
}
UINT CedarGetFifoBudgetConsuming(CEDAR *c) {
	if (c == NULL)
		return 0;

	// Barrier read of the atomically changed counter
	return (UINT)InterlockedCompareExchange((volatile LONG *)&c->FifoBudget, 0, 0);
}
UINT CedarGetQueueBudgetBalance(CEDAR *c) {
	UINT current = CedarGetQueueBudgetConsuming(c);
	UINT budget = QUEUE_BUDGET;

	if (current <= budget)
		return budget - current;
	else
		return 0;
}
UINT CedarGetFifoBudgetBalance(CEDAR *c) {
	UINT current = CedarGetFifoBudgetConsuming(c);
	UINT budget = FIFO_BUDGET;

	if (current <= budget)
		return budget - current;
	else
		return 0;
}

void CedarAddCurrentTcpQueueSize(CEDAR *c, int diff) {
	if (c == NULL || diff == 0)
		return;

	// One atomic add instead of a Cedar-wide lock: every flooded copy calls this on enqueue and again on
	// dequeue, from all sessions of all hubs, and nothing else shares the counter. Readers read it unlocked
	InterlockedExchangeAdd((volatile LONG *)&c->CurrentTcpQueueSize, (LONG)diff);
}

UINT CedarGetCurrentTcpQueueSize(CEDAR *c) {
	if (c == NULL)
		return 0;

	return c->CurrentTcpQueueSize;
}

void StopCedar(CEDAR *c) {
	if (c == NULL)
		return;

	StopAllListener(c);
	StopAllConnection(c);
	StopAllHub(c);
}

static void CleanupCedar(CEDAR *c) {
	if (c == NULL)
		return;

	ReleaseList(c->ListenerList);
	ReleaseList(c->HubList);
	ReleaseList(c->ConnectionList);
	DeleteLock(c->lock);
	DeleteCounter(c->ConnectionIncrement);
	DeleteCounter(c->CurrentSessions);

	if (c->ServerX)
		FreeX(c->ServerX);
	if (c->ServerK)
		FreeK(c->ServerK);
	if (c->ServerChain)
		FreeXList(c->ServerChain);

	if (c->CipherList)
		Free(c->CipherList);

	FreeSSLCtx(c->ServerSslCtx);

	Free(c->ServerStr);

	Free(c->HttpUserAgent);

	FreeTraffic(c->Traffic);

	DeleteLock(c->TrafficLock);

	FreeNetSvcList(c);

	Free(c->VerString);
	Free(c->BuildInfo);

	FreeLocalBridgeList(c);

	DeleteCounter(c->AssignedBridgeLicense);
	DeleteCounter(c->AssignedClientLicense);

	FreeNoSslList(c);

	DeleteLock(c->CedarSuperLock);

	DeleteCounter(c->AcceptingSockets);

	ReleaseIntList(c->UdpPortList);

	DeleteCounter(c->CurrentActiveLinks);

	Free(c);
}

void ReleaseCedar(CEDAR *c) {
	if (c == NULL)
		return;

	if (Release(c->ref) == 0)
		CleanupCedar(c);
}

// Release the shared server SSL_CTX: the next accepted connection builds it again. Connections that already
// have it keep it until they end (reference count). c->lock is held
static void ResetCedarServerSslCtx(CEDAR *c) {
	FreeSSLCtx(c->ServerSslCtx);
	c->ServerSslCtx = NULL;
}

// The server SSL_CTX shared by all accepted connections: certificate, key, chain, cipher list and the
// SslAcceptSettings are applied once, when it is built. It is built again when one of them changed
// (SetCedarCertAndChain, SetCedarCipherList, SslAcceptSettings) or, with no ServerChain, when the chain_certs
// folder changed. The caller releases the reference it gets with FreeSSLCtx
struct ssl_ctx_st *GetCedarServerSslCtx(CEDAR *c) {
	struct ssl_ctx_st *ret;
	UINT chain_gen = 0;

	if (c == NULL)
		return NULL;

	Lock(c->lock);
	{
		if (c->ServerChain == NULL)
			chain_gen = GetChainCertGeneration();

		if (c->ServerSslCtx != NULL &&
		    (Cmp(&c->ServerSslCtxSettings, &c->SslAcceptSettings, sizeof(SSL_ACCEPT_SETTINGS)) != 0 ||
		     (c->ServerChain == NULL && c->ServerSslCtxChainGen != chain_gen)))
			ResetCedarServerSslCtx(c);

		if (c->ServerSslCtx == NULL) {
			c->ServerSslCtx = NewServerSSLCtx(c->ServerX, c->ServerK, c->ServerChain, c->CipherList, &c->SslAcceptSettings);
			Copy(&c->ServerSslCtxSettings, &c->SslAcceptSettings, sizeof(SSL_ACCEPT_SETTINGS));
			c->ServerSslCtxChainGen = chain_gen;
		}

		ret = c->ServerSslCtx;
		ShareSSLCtx(ret);
	}
	Unlock(c->lock);

	return ret;
}

void SetCedarCipherList(CEDAR *cedar, char *name) {
	if (cedar == NULL)
		return;

	Lock(cedar->lock);
	{
		if (cedar->CipherList != NULL)
			Free(cedar->CipherList);
		if (name != NULL)
			cedar->CipherList = CopyStr(name);
		else
			cedar->CipherList = NULL;

		ResetCedarServerSslCtx(cedar);
	}
	Unlock(cedar->lock);
}

static int CompareNetSvc(void *p1, void *p2) {
	if (p1 == NULL || p2 == NULL)
		return 0;
	NETSVC *n1 = *(NETSVC **)p1;
	NETSVC *n2 = *(NETSVC **)p2;
	if (n1 == NULL || n2 == NULL)
		return 0;
	if (n1->Port > n2->Port)
		return 1;
	else if (n1->Port < n2->Port)
		return -1;
	else if (n1->Udp > n2->Udp)
		return 1;
	else if (n1->Udp < n2->Udp)
		return -1;
	return 0;
}

static void InitNetSvcList(CEDAR *cedar) {
	char filename[MAX_PATH] = "/etc/services";
	if (cedar == NULL)
		return;

	Format(filename, sizeof(filename), "%s\\drivers\\etc\\services", MsGetSystem32Dir());

	cedar->NetSvcList = NewList(CompareNetSvc);

	BUF *b = ReadDump(filename);
	if (b == NULL)
		return;

	while (true) {
		char *s = CfgReadNextLine(b);
		if (s == NULL)
			break;

		Trim(s);
		if (s[0] != '#') {
			TOKEN_LIST *t = ParseToken(s, " \t/");
			if (t->NumTokens >= 3) {
				NETSVC *n = ZeroMalloc(sizeof(NETSVC));
				n->Name = CopyStr(t->Token[0]);
				n->Udp = (StrCmpi(t->Token[2], "udp") == 0 ? true : false);
				n->Port = ToInt(t->Token[1]);
				Add(cedar->NetSvcList, n);
			}
			FreeToken(t);
		}
		Free(s);
	}

	FreeBuf(b);
}

char *GetSvcName(CEDAR *cedar, bool udp, UINT port) {
	char *ret = NULL;
	NETSVC t;
	if (cedar == NULL)
		return NULL;

	t.Udp = (udp == 0 ? false : true);
	t.Port = port;

	LockList(cedar->NetSvcList);
	{
		NETSVC *n = Search(cedar->NetSvcList, &t);
		if (n != NULL)
			ret = n->Name;
	}
	UnlockList(cedar->NetSvcList);

	return ret;
}

static void FreeNetSvcList(CEDAR *cedar) {
	if (cedar == NULL)
		return;

	for (UINT i = 0; i < LIST_NUM(cedar->NetSvcList); i++) {
		NETSVC *n = LIST_DATA(cedar->NetSvcList, i);
		Free(n->Name);
		Free(n);
	}
	ReleaseList(cedar->NetSvcList);
}

void SetCedarCertAndChain(CEDAR *c, X *server_x, K *server_k, LIST *server_chain) {
	if (server_x == NULL || server_k == NULL)
		return;

	Lock(c->lock);
	{
		if (c->ServerX != NULL)
			FreeX(c->ServerX);

		if (c->ServerK != NULL)
			FreeK(c->ServerK);

		if (c->ServerChain != NULL)
			FreeXList(c->ServerChain);

		c->ServerX = CloneX(server_x);
		c->ServerK = CloneK(server_k);
		c->ServerChain = CloneXList(server_chain);

		ResetCedarServerSslCtx(c);
	}
	Unlock(c->lock);
}

CEDAR *NewCedar(X *server_x, K *server_k) {
	char tmp[MAX_SIZE];

	CEDAR *c = ZeroMalloc(sizeof(CEDAR));

	c->CurrentActiveLinks = NewCounter();

	c->AcceptingSockets = NewCounter();

	c->CedarSuperLock = NewLock();

	InitNoSslList(c);

	c->AssignedBridgeLicense = NewCounter();
	c->AssignedClientLicense = NewCounter();

	Rand(c->UniqueId, sizeof(c->UniqueId));

	// Machine identity (FIX-5): a fresh salt; a server replaces it with the salt of its config file
	{
		UCHAR salt[MACHINE_ID_SALT_SIZE];

		Rand(salt, sizeof(salt));
		SetCedarMachineIdSalt(c, salt);
	}

	c->lock = NewLock();
	c->ref = NewRef();

	c->CurrentTcpConnections = GetNumTcpConnectionsCounter();

	c->ListenerList = NewList(CompareListener);
	c->HubList = NewList(CompareHub);
	c->ConnectionList = NewList(CompareConnection);

	c->ConnectionIncrement = NewCounter();
	c->CurrentSessions = NewCounter();

	if (server_k && server_x) {
		c->ServerK = CloneK(server_k);
		c->ServerX = CloneX(server_x);
	}

	c->Version = CEDAR_WIRE_VER;
	c->Build = CEDAR_WIRE_BUILD;
	c->ServerStr = CopyStr(CEDAR_SERVER_STR);

	c->HttpUserAgent = CopyStr(DEFAULT_USER_AGENT);

	c->Traffic = NewTraffic();
	c->TrafficLock = NewLock();

	SetCedarCipherList(c, SERVER_DEFAULT_CIPHER_NAME);

	c->UdpPortList = NewIntList();

	c->DhParamBits = DH_PARAM_BITS_DEFAULT;

	InitNetSvcList(c);

	InitLocalBridgeList(c);

	Format(tmp, sizeof(tmp), "Version %u.%u.%u (%s)",
	       CEDAR_VERSION_MAJOR, CEDAR_VERSION_MINOR, CEDAR_VERSION_BUILD,
	       _SS("LANGSTR"));
	Trim(tmp);

	c->VerString = CopyStr(tmp);

	Format(tmp, sizeof(tmp), "Compiled %04u/%02u/%02u %02u:%02u:%02u by %s at %s",
	       BUILD_DATE_Y, BUILD_DATE_M, BUILD_DATE_D, BUILD_DATE_HO, BUILD_DATE_MI, BUILD_DATE_SE, BUILDER_NAME, BUILD_PLACE);

	c->BuildInfo = CopyStr(tmp);

	return c;
}

void AddTraffic(TRAFFIC *dst, TRAFFIC *diff) {
	if (dst == NULL || diff == NULL)
		return;

	dst->Recv.BroadcastBytes += diff->Recv.BroadcastBytes;
	dst->Recv.BroadcastCount += diff->Recv.BroadcastCount;
	dst->Recv.UnicastBytes += diff->Recv.UnicastBytes;
	dst->Recv.UnicastCount += diff->Recv.UnicastCount;

	dst->Send.BroadcastBytes += diff->Send.BroadcastBytes;
	dst->Send.BroadcastCount += diff->Send.BroadcastCount;
	dst->Send.UnicastBytes += diff->Send.UnicastBytes;
	dst->Send.UnicastCount += diff->Send.UnicastCount;
}

// dst = a - b
void SubTraffic(TRAFFIC *dst, TRAFFIC *a, TRAFFIC *b) {
	if (dst == NULL || a == NULL || b == NULL)
		return;

	dst->Send.BroadcastBytes = a->Send.BroadcastBytes - b->Send.BroadcastBytes;
	dst->Send.BroadcastCount = a->Send.BroadcastCount - b->Send.BroadcastCount;
	dst->Send.UnicastBytes = a->Send.UnicastBytes - b->Send.UnicastBytes;
	dst->Send.UnicastCount = a->Send.UnicastCount - b->Send.UnicastCount;

	dst->Recv.BroadcastBytes = a->Recv.BroadcastBytes - b->Recv.BroadcastBytes;
	dst->Recv.BroadcastCount = a->Recv.BroadcastCount - b->Recv.BroadcastCount;
	dst->Recv.UnicastBytes = a->Recv.UnicastBytes - b->Recv.UnicastBytes;
	dst->Recv.UnicastCount = a->Recv.UnicastCount - b->Recv.UnicastCount;
}

// Counts one Ethernet frame as broadcast or unicast; a frame shorter than an Ethernet header is not counted
void TrafficCountFrame(TRAFFIC_ENTRY *e, UCHAR *buf, UINT size) {
	if (e == NULL || buf == NULL || size < 14)
		return;

	if (buf[0] & 0x01) {
		e->BroadcastCount++;
		e->BroadcastBytes += (UINT64)size;
	} else {
		e->UnicastCount++;
		e->UnicastBytes += (UINT64)size;
	}
}

TRAFFIC *NewTraffic() {
	TRAFFIC *t = ZeroMalloc(sizeof(TRAFFIC));
	return t;
}

void FreeTraffic(TRAFFIC *t) {
	if (t == NULL)
		return;

	Free(t);
}

void InitCedar() {
	if ((init_cedar_counter++) > 0)
		return;

	InitWaterMark();
}

void FreeCedar() {
	if ((--init_cedar_counter) > 0)
		return;

	FreeWaterMark();
}

// Machine identity (FIX-5, #101): the first SHA1_SIZE bytes of SHA-256 over MACHINE_ID_LABEL with its
// terminator, the MachineGuid of Windows (trimmed, lower case) with its terminator, and the salt. Host
// name, IP addresses and OS version are no input. An unreadable MachineGuid is the empty string, so the
// salt alone still tells two servers apart.
void ComputeMachineUniqueHash(void *data, char *machine_guid, void *salt, UINT salt_size) {
	char guid[MAX_SIZE];
	UCHAR hash[SHA256_SIZE];
	if (data == NULL || (salt == NULL && salt_size != 0))
		return;

	StrCpy(guid, sizeof(guid), machine_guid);
	Trim(guid);
	StrLower(guid);

	BUF *b = NewBuf();
	WriteBuf(b, MACHINE_ID_LABEL, StrSize(MACHINE_ID_LABEL));
	WriteBuf(b, guid, StrSize(guid));
	WriteBuf(b, salt, salt_size);

	Sha2_256(hash, b->Buf, b->Size);

	FreeBuf(b);

	Copy(data, hash, SHA1_SIZE);
}

// HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid in the 64-bit registry view, or "" when it cannot be read
static void GetMachineGuid(char *guid, UINT size) {
	if (guid == NULL)
		return;

	char *s = MsRegReadStrEx2(REG_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography", "MachineGuid", false);

	StrCpy(guid, size, s);

	Free(s);
}

// Set the machine identity salt of a CEDAR (NewCedar: a random one; SiLoadMachineIdCfg: the one of the
// config file) and derive its machine identity. Called before the hubs and listeners exist, so readers
// of the identity need no lock.
void SetCedarMachineIdSalt(CEDAR *c, void *salt) {
	char guid[MAX_SIZE];
	if (c == NULL || salt == NULL)
		return;

	Copy(c->MachineIdSalt, salt, sizeof(c->MachineIdSalt));

	GetMachineGuid(guid, sizeof(guid));

	ComputeMachineUniqueHash(c->MachineUniqueHash, guid, c->MachineIdSalt, sizeof(c->MachineIdSalt));
}

// The machine identity of a server (SHA1_SIZE bytes): virtual hub MAC address and address, Cascade unique_id
void GenerateMachineUniqueHash(CEDAR *c, void *data) {
	if (c == NULL || data == NULL)
		return;

	Copy(data, c->MachineUniqueHash, SHA1_SIZE);
}

