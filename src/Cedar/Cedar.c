// Cedar.c
// Cedar Communication Module

#include "Cedar.h"

#include "BuildInfo.h"
#include "Connection.h"
#include "Hub.h"
#include "HubLog.h"
#include "Sam.h"
#include "Session.h"

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

static void FreeNetSvcList(CEDAR *cedar);

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

// Stop the connections and the Hubs of c
void StopCedar(CEDAR *c) {
	if (c == NULL)
		return;

	StopAllConnection(c);
	StopAllHub(c);
}

static void CleanupCedar(CEDAR *c) {
	if (c == NULL)
		return;

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

	DeleteLock(c->CedarSuperLock);

	DeleteCounter(c->AcceptingSockets);

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

	c->AcceptingSockets = NewCounter();

	c->CedarSuperLock = NewLock();

	Rand(c->UniqueId, sizeof(c->UniqueId));

	// Machine identity (FIX-5): a fresh salt
	{
		UCHAR salt[MACHINE_ID_SALT_SIZE];

		Rand(salt, sizeof(salt));
		SetCedarMachineIdSalt(c, salt);
	}

	c->lock = NewLock();
	c->ref = NewRef();

	c->CurrentTcpConnections = GetNumTcpConnectionsCounter();

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

	c->DhParamBits = DH_PARAM_BITS_DEFAULT;

	InitNetSvcList(c);

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

// Cedar has nothing of its own to start or end for the process
void InitCedar() {
}

void FreeCedar() {
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

// Set the machine identity salt of a CEDAR (NewCedar: a random one) and derive its machine identity.
// Called before the hubs exist, so readers of the identity need no lock.
void SetCedarMachineIdSalt(CEDAR *c, void *salt) {
	char guid[MAX_SIZE];
	if (c == NULL || salt == NULL)
		return;

	Copy(c->MachineIdSalt, salt, sizeof(c->MachineIdSalt));

	GetMachineGuid(guid, sizeof(guid));

	ComputeMachineUniqueHash(c->MachineUniqueHash, guid, c->MachineIdSalt, sizeof(c->MachineIdSalt));
}

// The machine identity of a server (SHA1_SIZE bytes): the MAC address and the address of a virtual hub
void GenerateMachineUniqueHash(CEDAR *c, void *data) {
	if (c == NULL || data == NULL)
		return;

	Copy(data, c->MachineUniqueHash, SHA1_SIZE);
}

