// Cedar.c
// Cedar Communication Module

#include "Cedar.h"

#include "Admin.h"
#include "Bridge.h"
#include "BuildInfo.h"
#include "Connection.h"
#include "Link.h"
#include "Listener.h"
#include "Logging.h"
#include "Protocol.h"
#include "Sam.h"
#include "Session.h"
#include "WaterMark.h"

#include "Mayaqua/Cfg.h"
#include "Mayaqua/Encrypt.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/HTTP.h"
#include "Mayaqua/Mayaqua.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Table.h"
#include "Mayaqua/Tick64.h"
#include "Mayaqua/Win32.h"

static void DeleteOldNoSsl(CEDAR *c);
static void MakeRoomInNoSslList(CEDAR *c);
static NON_SSL *SearchNoSslList(CEDAR *c, IP *ip);
static void FreeNetSvcList(CEDAR *cedar);

static UINT init_cedar_counter = 0;
static REF *cedar_log_ref = NULL;
static LOG *cedar_log;

bool IsSupportedWinVer(RPC_WINVER *v)
{
	if (v == NULL)
	{
		return false;
	}

	if (v->IsWindows == false)
	{
		return true;
	}

	if (v->IsNT == false)
	{
		return true;
	}

	if (v->IsBeta)
	{
		return true;
	}

	if (v->VerMajor <= 4)
	{
		// Windows NT
		return true;
	}

	if (v->VerMajor == 5 && v->VerMinor == 0)
	{
		// Windows 2000
		if (v->ServicePack <= 4)
		{
			return true;
		}
	}

	if (v->VerMajor == 5 && v->VerMinor == 1)
	{
		// Windows XP x86
		if (v->ServicePack <= 3)
		{
			return true;
		}
	}

	if (v->VerMajor == 5 && v->VerMinor == 2)
	{
		// Windows XP x64, Windows Server 2003
		if (v->ServicePack <= 2)
		{
			return true;
		}
	}

	if (v->VerMajor == 6 && v->VerMinor == 0)
	{
		// Windows Vista, Server 2008
		if (v->ServicePack <= 2)
		{
			return true;
		}
	}

	if (v->VerMajor == 6 && v->VerMinor == 1)
	{
		// Windows 7, Server 2008 R2
		if (v->ServicePack <= 1)
		{
			return true;
		}
	}

	if (v->VerMajor == 6 && v->VerMinor == 2)
	{
		// Windows 8, Server 2012
		if (v->ServicePack <= 0)
		{
			return true;
		}
	}

	if (v->VerMajor == 6 && v->VerMinor == 3)
	{
		// Windows 8.1, Server 2012 R2
		if (v->ServicePack <= 0)
		{
			return true;
		}
	}

	if ((v->VerMajor == 6 && v->VerMinor == 4) || (v->VerMajor == 10 && v->VerMinor == 0))
	{
		// Windows 10 or Windows Server 2016
		if (v->ServicePack <= 0)
		{
			return true;
		}
	}

	return false;
}

static void Win32GetWinVer(RPC_WINVER *v)
{
	if (v == NULL)
	{
		return;
	}

	Zero(v, sizeof(RPC_WINVER));

	v->IsWindows = true;

	if (true)
	{
		OSVERSIONINFOEX os;
		Zero(&os, sizeof(os));
		os.dwOSVersionInfoSize = sizeof(os);
		Win32GetVersionExInternal((LPOSVERSIONINFOA)&os);

		v->IsNT = true;
		v->Build = os.dwBuildNumber;
		v->ServicePack = os.wServicePackMajor;

		if (os.wProductType != VER_NT_WORKSTATION)
		{
			v->IsServer = true;
		}
		v->VerMajor = os.dwMajorVersion;
		v->VerMinor = os.dwMinorVersion;

		if (GetOsInfo()->OsServicePack == 0)
		{
			StrCpy(v->Title, sizeof(v->Title), GetOsInfo()->OsProductName);
		}
		else
		{
			Format(v->Title, sizeof(v->Title), "%s Service Pack %u",
				GetOsInfo()->OsProductName,
				GetOsInfo()->OsServicePack);
		}
		Trim(v->Title);

		if (InStr(GetOsInfo()->OsVersion, "rc") ||
			InStr(GetOsInfo()->OsVersion, "beta"))
		{
			v->IsBeta = true;
		}
	}
}

void GetWinVer(RPC_WINVER *v)
{
	if (v == NULL)
	{
		return;
	}

	Win32GetWinVer(v);
}

void FreeTinyLog(TINY_LOG *t)
{
	if (t == NULL)
	{
		return;
	}

	FileClose(t->io);
	DeleteLock(t->Lock);
	Free(t);
}

void WriteTinyLog(TINY_LOG *t, char *str)
{
	BUF *b;
	char dt[MAX_PATH];
	if (t == NULL)
	{
		return;
	}

	GetDateTimeStrMilli64(dt, sizeof(dt), LocalTime64());
	StrCat(dt, sizeof(dt), ": ");

	b = NewBuf();

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

TINY_LOG *NewTinyLog()
{
	char name[MAX_PATH];
	SYSTEMTIME st;
	TINY_LOG *t;

	LocalTime(&st);

	MakeDir(TINY_LOG_DIRNAME);

	Format(name, sizeof(name), TINY_LOG_FILENAME,
		st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

	t = ZeroMalloc(sizeof(TINY_LOG));

	StrCpy(t->FileName, sizeof(t->FileName), name);
	t->io = FileCreate(name);
	t->Lock = NewLock();

	return t;
}

static int CompareNoSslList(void *p1, void *p2)
{
	NON_SSL *n1, *n2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	n1 = *(NON_SSL **)p1;
	n2 = *(NON_SSL **)p2;
	if (n1 == NULL || n2 == NULL)
	{
		return 0;
	}
	return CmpIpAddr(&n1->IpAddress, &n2->IpAddress);
}

void DecrementNoSsl(CEDAR *c, IP *ip, UINT num_dec)
{
	if (c == NULL || ip == NULL)
	{
		return;
	}

	LockList(c->NonSslList);
	{
		NON_SSL *n = SearchNoSslList(c, ip);

		if (n != NULL)
		{
			if (n->Count >= num_dec)
			{
				n->Count -= num_dec;
			}
		}
	}
	UnlockList(c->NonSslList);
}

bool IsInNoSsl(CEDAR *c, IP *ip)
{
	bool ret = false;
	if (c == NULL || ip == NULL)
	{
		return false;
	}

	LockList(c->NonSslList);
	{
		NON_SSL *n = SearchNoSslList(c, ip);

		if (n != NULL)
		{
			if (n->EntryExpires > Tick64() && n->Count > NON_SSL_MIN_COUNT)
			{
				n->EntryExpires = Tick64() + (UINT64)NON_SSL_ENTRY_EXPIRES;
				ret = true;
			}
		}
	}
	UnlockList(c->NonSslList);

	return ret;
}

bool AddNoSsl(CEDAR *c, IP *ip)
{
	NON_SSL *n;
	bool ret = true;
	if (c == NULL || ip == NULL)
	{
		return true;
	}

	LockList(c->NonSslList);
	{
		DeleteOldNoSsl(c);

		n = SearchNoSslList(c, ip);

		if (n == NULL)
		{
			if (LIST_NUM(c->NonSslList) >= RATE_LIMIT_TABLE_MAX)
			{
				MakeRoomInNoSslList(c);
			}

			n = ZeroMalloc(sizeof(NON_SSL));
			GetRateLimitKey(&n->IpAddress, ip);
			n->Count = 0;

			Add(c->NonSslList, n);
		}

		n->EntryExpires = Tick64() + (UINT64)NON_SSL_ENTRY_EXPIRES;

		n->Count++;

		if (n->Count > NON_SSL_MIN_COUNT)
		{
			ret = false;
		}
	}
	UnlockList(c->NonSslList);

	return ret;
}

static void DeleteOldNoSsl(CEDAR *c)
{
	UINT i;
	LIST *o;
	if (c == NULL)
	{
		return;
	}

	o = NewListFast(NULL);

	for (i = 0;i < LIST_NUM(c->NonSslList);i++)
	{
		NON_SSL *n = LIST_DATA(c->NonSslList, i);

		if (n->EntryExpires <= Tick64())
		{
			Add(o, n);
		}
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		NON_SSL *n = LIST_DATA(o, i);

		Delete(c->NonSslList, n);
		Free(n);
	}

	ReleaseList(o);
}

// NonSslList is full after DeleteOldNoSsl: drop the least recently seen entry; log the first time
static void MakeRoomInNoSslList(CEDAR *c)
{
	NON_SSL *oldest = NULL;
	UINT i;

	for (i = 0;i < LIST_NUM(c->NonSslList);i++)
	{
		NON_SSL *n = LIST_DATA(c->NonSslList, i);

		if (oldest == NULL || n->EntryExpires < oldest->EntryExpires)
		{
			oldest = n;
		}
	}

	if (oldest != NULL)
	{
		Delete(c->NonSslList, oldest);
		Free(oldest);
	}

	if (c->NonSslListFullLogged == false)
	{
		c->NonSslListFullLogged = true;
		SLog(c, "LS_NON_SSL_TABLE_FULL", (UINT)RATE_LIMIT_TABLE_MAX);
	}
}

static NON_SSL *SearchNoSslList(CEDAR *c, IP *ip)
{
	NON_SSL *n, t;
	if (c == NULL || ip == NULL)
	{
		return NULL;
	}

	Zero(&t, sizeof(t));
	GetRateLimitKey(&t.IpAddress, ip);

	n = Search(c->NonSslList, &t);

	if (n == NULL)
	{
		return NULL;
	}

	return n;
}

static void InitNoSslList(CEDAR *c)
{
	if (c == NULL)
	{
		return;
	}

	c->NonSslList = NewList(CompareNoSslList);
}

static void FreeNoSslList(CEDAR *c)
{
	UINT i;
	if (c == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(c->NonSslList);i++)
	{
		NON_SSL *n = LIST_DATA(c->NonSslList, i);

		Free(n);
	}

	ReleaseList(c->NonSslList);
	c->NonSslList = NULL;
}

void StopCedarLog()
{
	if (cedar_log_ref == NULL)
	{
		return;
	}

	if (Release(cedar_log_ref) == 0)
	{
		FreeLog(cedar_log);
		cedar_log = NULL;
		cedar_log_ref = NULL;
	}
}

UINT64 GetTrafficPacketSize(TRAFFIC *t)
{
	if (t == NULL)
	{
		return 0;
	}

	return t->Recv.BroadcastBytes + t->Recv.UnicastBytes +
		t->Send.BroadcastBytes + t->Send.UnicastBytes;
}

UINT64 GetTrafficPacketNum(TRAFFIC *t)
{
	if (t == NULL)
	{
		return 0;
	}

	return t->Recv.BroadcastCount + t->Recv.UnicastCount +
		t->Send.BroadcastCount + t->Send.UnicastCount;
}

void DelConnection(CEDAR *cedar, CONNECTION *c)
{
	if (cedar == NULL || c == NULL)
	{
		return;
	}

	LockList(cedar->ConnectionList);
	{
		if (Delete(cedar->ConnectionList, c))
		{
			ReleaseConnection(c);
		}
	}
	UnlockList(cedar->ConnectionList);
}

UINT GetUnestablishedConnections(CEDAR *cedar)
{
	UINT i, ret;
	if (cedar == NULL)
	{
		return 0;
	}

	ret = 0;

	LockList(cedar->ConnectionList);
	{
		for (i = 0;i < LIST_NUM(cedar->ConnectionList);i++)
		{
			CONNECTION *c = LIST_DATA(cedar->ConnectionList, i);

			switch (c->Type)
			{
			case CONNECTION_TYPE_CLIENT:
			case CONNECTION_TYPE_INIT:
			case CONNECTION_TYPE_LOGIN:
			case CONNECTION_TYPE_ADDITIONAL:
				switch (c->Status)
				{
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

void AddConnection(CEDAR *cedar, CONNECTION *c)
{
	char tmp[MAX_SIZE];
	UINT i;
	if (cedar == NULL || c == NULL)
	{
		return;
	}

	i = Inc(cedar->ConnectionIncrement);
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

static void StopAllConnection(CEDAR *c)
{
	UINT num;
	UINT i;
	CONNECTION **connections;
	if (c == NULL)
	{
		return;
	}

	LockList(c->ConnectionList);
	{
		connections = ToArray(c->ConnectionList);
		num = LIST_NUM(c->ConnectionList);
		DeleteAll(c->ConnectionList);
	}
	UnlockList(c->ConnectionList);

	for (i = 0;i < num;i++)
	{
		StopConnection(connections[i], false);
		ReleaseConnection(connections[i]);
	}
	Free(connections);
}

void DelHub(CEDAR *c, HUB *h)
{
	if (c == NULL || h == NULL)
	{
		return;
	}

	LockHubList(c);

	if (Delete(c->HubList, h))
	{
		ReleaseHub(h);
	}

	UnlockHubList(c);
}

void AddHub(CEDAR *c, HUB *h)
{
	if (c == NULL || h == NULL)
	{
		return;
	}

	LockHubList(c);
	{
		if (IsHub(c, h->Name))
		{
			UnlockHubList(c);
			return;
		}

		Insert(c->HubList, h);
		AddRef(h->ref);
	}
	UnlockHubList(c);
}

static void StopAllHub(CEDAR *c)
{
	HUB **hubs;
	UINT i, num;
	if (c == NULL)
	{
		return;
	}

	LockHubList(c);
	{
		hubs = ToArray(c->HubList);
		num = LIST_NUM(c->HubList);
		DeleteAll(c->HubList);
	}
	UnlockHubList(c);

	for (i = 0;i < num;i++)
	{
		StopHub(hubs[i]);
		ReleaseHub(hubs[i]);
	}

	Free(hubs);
}

void AddListener(CEDAR *c, LISTENER *r)
{
	if (c == NULL || r == NULL)
	{
		return;
	}

	LockList(c->ListenerList);
	{
		Add(c->ListenerList, r);
		AddRef(r->ref);
	}
	UnlockList(c->ListenerList);
}

static void StopAllListener(CEDAR *c)
{
	LISTENER **array;
	UINT i, num;
	if (c == NULL)
	{
		return;
	}

	LockList(c->ListenerList);
	{
		array = ToArray(c->ListenerList);
		num = LIST_NUM(c->ListenerList);
		DeleteAll(c->ListenerList);
	}
	UnlockList(c->ListenerList);

	for (i = 0;i < num;i++)
	{
		StopListener(array[i]);
		ReleaseListener(array[i]);
	}
	Free(array);
}

// Both budgets are plain counters shared by every connection and link of the Cedar, so one atomic add
// replaces the lock each of them had. Callers keep the queue budget in step through CedarSyncQueueBudget
static void CedarAddQueueBudget(CEDAR *c, int diff)
{
	if (c == NULL || diff == 0)
	{
		return;
	}

	InterlockedExchangeAdd((volatile LONG *)&c->QueueBudget, (LONG)diff);
}
// Moves the queue budget by how much one queue's block count changed since its last sync, and records
// the new count. A count of 0 hands back everything that queue still holds in the budget
void CedarSyncQueueBudget(CEDAR *c, UINT current, UINT *last)
{
	if (last == NULL)
	{
		return;
	}

	CedarAddQueueBudget(c, (int)current - (int)(*last));
	*last = current;
}
void CedarAddFifoBudget(CEDAR *c, int diff)
{
	if (c == NULL || diff == 0)
	{
		return;
	}

	InterlockedExchangeAdd((volatile LONG *)&c->FifoBudget, (LONG)diff);
}
UINT CedarGetQueueBudgetConsuming(CEDAR *c)
{
	if (c == NULL)
	{
		return 0;
	}

	// Barrier read of the atomically changed counter
	return (UINT)InterlockedCompareExchange((volatile LONG *)&c->QueueBudget, 0, 0);
}
UINT CedarGetFifoBudgetConsuming(CEDAR *c)
{
	if (c == NULL)
	{
		return 0;
	}

	// Barrier read of the atomically changed counter
	return (UINT)InterlockedCompareExchange((volatile LONG *)&c->FifoBudget, 0, 0);
}
UINT CedarGetQueueBudgetBalance(CEDAR *c)
{
	UINT current = CedarGetQueueBudgetConsuming(c);
	UINT budget = QUEUE_BUDGET;

	if (current <= budget)
	{
		return budget - current;
	}
	else
	{
		return 0;
	}
}
UINT CedarGetFifoBudgetBalance(CEDAR *c)
{
	UINT current = CedarGetFifoBudgetConsuming(c);
	UINT budget = FIFO_BUDGET;

	if (current <= budget)
	{
		return budget - current;
	}
	else
	{
		return 0;
	}
}

void CedarAddCurrentTcpQueueSize(CEDAR *c, int diff)
{
	if (c == NULL || diff == 0)
	{
		return;
	}

	// One atomic add instead of a Cedar-wide lock: every flooded copy calls this on enqueue and again on
	// dequeue, from all sessions of all hubs, and nothing else shares the counter. Readers read it unlocked
	InterlockedExchangeAdd((volatile LONG *)&c->CurrentTcpQueueSize, (LONG)diff);
}

UINT CedarGetCurrentTcpQueueSize(CEDAR *c)
{
	if (c == NULL)
	{
		return 0;
	}

	return c->CurrentTcpQueueSize;
}

void StopCedar(CEDAR *c)
{
	if (c == NULL)
	{
		return;
	}

	StopAllListener(c);
	StopAllConnection(c);
	StopAllHub(c);
}

static void CleanupCedar(CEDAR *c)
{
	UINT i;
	if (c == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(c->CaList);i++)
	{
		X *x = LIST_DATA(c->CaList, i);
		FreeX(x);
	}
	ReleaseList(c->CaList);

	ReleaseList(c->ListenerList);
	ReleaseList(c->HubList);
	ReleaseList(c->ConnectionList);
	DeleteLock(c->lock);
	DeleteCounter(c->ConnectionIncrement);
	DeleteCounter(c->CurrentSessions);

	if (c->DebugLog != NULL)
	{
		FreeLog(c->DebugLog);
	}

	if (c->ServerX)
	{
		FreeX(c->ServerX);
	}
	if (c->ServerK)
	{
		FreeK(c->ServerK);
	}
	if (c->ServerChain)
	{
		FreeXList(c->ServerChain);
	}

	if (c->CipherList)
	{
		Free(c->CipherList);
	}

	Free(c->ServerStr);
	Free(c->MachineName);

	Free(c->HttpUserAgent);
	Free(c->HttpAccept);
	Free(c->HttpAcceptLanguage);
	Free(c->HttpAcceptEncoding);

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

	DeleteLock(c->CurrentRegionLock);

	DeleteCounter(c->CurrentActiveLinks);

	Free(c);
}

void ReleaseCedar(CEDAR *c)
{
	if (c == NULL)
	{
		return;
	}

	if (Release(c->ref) == 0)
	{
		CleanupCedar(c);
	}
}

void SetCedarCipherList(CEDAR *cedar, char *name)
{
	if (cedar == NULL)
	{
		return;
	}

	if (cedar->CipherList != NULL)
	{
		Free(cedar->CipherList);
	}
	if (name != NULL)
	{
		cedar->CipherList = CopyStr(name);
	}
	else
	{
		cedar->CipherList = NULL;
	}
}

static int CompareNetSvc(void *p1, void *p2)
{
	NETSVC *n1, *n2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	n1 = *(NETSVC **)p1;
	n2 = *(NETSVC **)p2;
	if (n1 == NULL || n2 == NULL)
	{
		return 0;
	}
	if (n1->Port > n2->Port)
	{
		return 1;
	}
	else if (n1->Port < n2->Port)
	{
		return -1;
	}
	else if (n1->Udp > n2->Udp)
	{
		return 1;
	}
	else if (n1->Udp < n2->Udp)
	{
		return -1;
	}
	return 0;
}

static void InitNetSvcList(CEDAR *cedar)
{
	char filename[MAX_PATH] = "/etc/services";
	BUF *b;
	if (cedar == NULL)
	{
		return;
	}

	Format(filename, sizeof(filename), "%s\\drivers\\etc\\services", MsGetSystem32Dir());

	cedar->NetSvcList = NewList(CompareNetSvc);

	b = ReadDump(filename);
	if (b == NULL)
	{
		return;
	}

	while (true)
	{
		char *s = CfgReadNextLine(b);
		if (s == NULL)
		{
			break;
		}

		Trim(s);
		if (s[0] != '#')
		{
			TOKEN_LIST *t = ParseToken(s, " \t/");
			if (t->NumTokens >= 3)
			{
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

char *GetSvcName(CEDAR *cedar, bool udp, UINT port)
{
	char *ret = NULL;
	NETSVC t;
	if (cedar == NULL)
	{
		return NULL;
	}

	t.Udp = (udp == 0 ? false : true);
	t.Port = port;

	LockList(cedar->NetSvcList);
	{
		NETSVC *n = Search(cedar->NetSvcList, &t);
		if (n != NULL)
		{
			ret = n->Name;
		}
	}
	UnlockList(cedar->NetSvcList);

	return ret;
}

static void FreeNetSvcList(CEDAR *cedar)
{
	UINT i;
	if (cedar == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(cedar->NetSvcList);i++)
	{
		NETSVC *n = LIST_DATA(cedar->NetSvcList, i);
		Free(n->Name);
		Free(n);
	}
	ReleaseList(cedar->NetSvcList);
}

void SetCedarCertAndChain(CEDAR *c, X *server_x, K *server_k, LIST *server_chain)
{
	if (server_x == NULL || server_k == NULL)
	{
		return;
	}

	Lock(c->lock);
	{
		if (c->ServerX != NULL)
		{
			FreeX(c->ServerX);
		}

		if (c->ServerK != NULL)
		{
			FreeK(c->ServerK);
		}

		if (c->ServerChain != NULL)
		{
			FreeXList(c->ServerChain);
		}

		c->ServerX = CloneX(server_x);
		c->ServerK = CloneK(server_k);
		c->ServerChain = CloneXList(server_chain);
	}
	Unlock(c->lock);
}

void SetCedarVpnBridge(CEDAR *c)
{
	if (c == NULL)
	{
		return;
	}

	c->Bridge = true;

	Free(c->ServerStr);
	c->ServerStr = CopyStr(CEDAR_BRIDGE_STR);
}

void RegistWindowsFirewallAll()
{
	char exedir[MAX_SIZE];

	GetExeDir(exedir, sizeof(exedir));

	MsRegistWindowsFirewallEx2(CEDAR_SERVER_STR, "vpnserver.exe", exedir);
	MsRegistWindowsFirewallEx2(CEDAR_CUI_STR, "vpncmd.exe", exedir);
	MsRegistWindowsFirewallEx2(CEDAR_PRODUCT_STR, "vpntest.exe", exedir);
}

static void CedarForceLink()
{
}

UINT GetCedarVersionNumber()
{
	return CEDAR_WIRE_VER;
}

CEDAR *NewCedar(X *server_x, K *server_k)
{
	CEDAR *c;
	char tmp[MAX_SIZE];
	char tmp2[MAX_SIZE];
	char *beta_str;

	CedarForceLink();

	c = ZeroMalloc(sizeof(CEDAR));

	c->CurrentActiveLinks = NewCounter();

	c->AcceptingSockets = NewCounter();

	c->CedarSuperLock = NewLock();

	c->CurrentRegionLock = NewLock();

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

	c->CreatedTick = Tick64();

	c->lock = NewLock();
	c->ref = NewRef();

	c->CurrentTcpConnections = GetNumTcpConnectionsCounter();

	c->ListenerList = NewList(CompareListener);
	c->HubList = NewList(CompareHub);
	c->ConnectionList = NewList(CompareConnection);

	c->ConnectionIncrement = NewCounter();
	c->CurrentSessions = NewCounter();

	if (server_k && server_x)
	{
		c->ServerK = CloneK(server_k);
		c->ServerX = CloneX(server_x);
	}

	c->Version = GetCedarVersionNumber();
	c->Build = CEDAR_WIRE_BUILD;
	c->ServerStr = CopyStr(CEDAR_SERVER_STR);

	GetMachineName(tmp, sizeof(tmp));
	c->MachineName = CopyStr(tmp);

	c->HttpUserAgent = CopyStr(DEFAULT_USER_AGENT);
	c->HttpAccept = CopyStr(DEFAULT_ACCEPT);
	c->HttpAcceptLanguage = CopyStr("ja");
	c->HttpAcceptEncoding = CopyStr(DEFAULT_ENCODING);

	c->Traffic = NewTraffic();
	c->TrafficLock = NewLock();
	c->CaList = NewList(CompareCert);

	SetCedarCipherList(c, SERVER_DEFAULT_CIPHER_NAME);

	c->ClientId = _II("CLIENT_ID");

	c->UdpPortList = NewIntList(false);

	c->DhParamBits = DH_PARAM_BITS_DEFAULT;

	InitNetSvcList(c);

	InitLocalBridgeList(c);

	beta_str = "Release Candidate";

	Format(tmp2, sizeof(tmp2), " %s %u ", beta_str, c->Beta);

	Format(tmp, sizeof(tmp),
		"Version %u.%u.%u"
		"%s"
		"(%s)",
		CEDAR_VERSION_MAJOR, CEDAR_VERSION_MINOR, CEDAR_VERSION_BUILD,
		c->Beta == 0 ? " " : tmp2,
		_SS("LANGSTR"));
	Trim(tmp);

	if (true)
	{
		SYSTEMTIME st;
		Zero(&st, sizeof(st));

		st.wYear = BUILD_DATE_Y;
		st.wMonth = BUILD_DATE_M;
		st.wDay = BUILD_DATE_D;

		c->BuiltDate = SystemToUINT64(&st);
	}

	c->VerString = CopyStr(tmp);

	Format(tmp, sizeof(tmp), "Compiled %04u/%02u/%02u %02u:%02u:%02u by %s at %s",
		BUILD_DATE_Y, BUILD_DATE_M, BUILD_DATE_D, BUILD_DATE_HO, BUILD_DATE_MI, BUILD_DATE_SE, BUILDER_NAME, BUILD_PLACE);

	c->BuildInfo = CopyStr(tmp);

	return c;
}

void AddTraffic(TRAFFIC *dst, TRAFFIC *diff)
{
	if (dst == NULL || diff == NULL)
	{
		return;
	}

	dst->Recv.BroadcastBytes += diff->Recv.BroadcastBytes;
	dst->Recv.BroadcastCount += diff->Recv.BroadcastCount;
	dst->Recv.UnicastBytes += diff->Recv.UnicastBytes;
	dst->Recv.UnicastCount += diff->Recv.UnicastCount;

	dst->Send.BroadcastBytes += diff->Send.BroadcastBytes;
	dst->Send.BroadcastCount += diff->Send.BroadcastCount;
	dst->Send.UnicastBytes += diff->Send.UnicastBytes;
	dst->Send.UnicastCount += diff->Send.UnicastCount;
}

TRAFFIC *NewTraffic()
{
	TRAFFIC *t;

	t = ZeroMalloc(sizeof(TRAFFIC));
	return t;
}

void FreeTraffic(TRAFFIC *t)
{
	if (t == NULL)
	{
		return;
	}

	Free(t);
}

void InitCedar()
{
	if ((init_cedar_counter++) > 0)
	{
		return;
	}

	InitWaterMark();
}

void FreeCedar()
{
	if ((--init_cedar_counter) > 0)
	{
		return;
	}

	FreeWaterMark();
}

