// Hub.c
// Virtual HUB module

#include "Hub.h"

#include "Admin.h"
#include "Bridge.h"
#include "Connection.h"
#include "Link.h"
#include "Protocol.h"
#include "Server.h"

#include "Mayaqua/Cfg.h"
#include "Mayaqua/DNS.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Table.h"
#include "Mayaqua/TcpIp.h"
#include "Mayaqua/Tick64.h"
#include "HubInternal.h"

static UCHAR broadcast[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};


void StartHubWatchDog(HUB *h)
{
	THREAD *t;
	if (h == NULL)
	{
		return;
	}

	h->HaltWatchDog = false;
	h->WatchDogEvent = NewEvent();

	t = NewThread(HubWatchDogThread, h);
	WaitThreadInit(t);
	ReleaseThread(t);
}

void StopHubWatchDog(HUB *h)
{
	if (h == NULL)
	{
		return;
	}

	h->HaltWatchDog = true;
	Set(h->WatchDogEvent);

	WaitThread(h->WatchDogThread, INFINITE);
	ReleaseThread(h->WatchDogThread);
	h->WatchDogThread = NULL;
	h->HaltWatchDog = false;

	ReleaseEvent(h->WatchDogEvent);
	h->WatchDogEvent = NULL;
}

void HubWatchDogThread(THREAD *t, void *param)
{
	UINT num_packets_v4 = 0;
	UINT num_packets_v6 = 0;
	HUB *hub;
	if (t == NULL || param == NULL)
	{
		return;
	}

	hub = (HUB *)param;

	hub->WatchDogThread = t;
	AddRef(t->ref);

	NoticeThreadInit(t);

	while (true)
	{
		LIST *o;
		LIST *o2;
		UINT i, num;
		UINT interval;
		UINT wait_time = 100;
		if (hub->HaltWatchDog)
		{
			break;
		}

		o = NewListFast(NULL);
		o2 = NewListFast(NULL);

		LockHashList(hub->MacHashTable);
		{
			num = LIST_NUM(hub->IpTable);
			for (i = 0;i < LIST_NUM(hub->IpTable);i++)
			{
				IP_TABLE_ENTRY *e = LIST_DATA(hub->IpTable, i);

				if (e == NULL) continue;

				if ((e->UpdatedTime + (UINT64)(IP_TABLE_EXPIRE_TIME)) > Tick64())
				{
					if (e->MacAddress[0] != 0xff || e->MacAddress[1] != 0xff || e->MacAddress[2] != 0xff ||
						e->MacAddress[3] != 0xff || e->MacAddress[4] != 0xff || e->MacAddress[5] != 0xff)
					{
						if (hub->Option != NULL && hub->Option->NoArpPolling == false)
						{
							if (IsIP4(&e->Ip))
							{
								MAC_HEADER *mac = ZeroMalloc(sizeof(MAC_HEADER) + sizeof(ARPV4_HEADER));
								ARPV4_HEADER *p = (ARPV4_HEADER *)(((UCHAR *)mac) + sizeof(MAC_HEADER));

								Copy(mac->DestAddress, e->MacAddress, 6);
								Copy(mac->SrcAddress, hub->HubMacAddr, 6);
								mac->Protocol = Endian16(MAC_PROTO_ARPV4);

								p->HardwareType = Endian16(ARP_HARDWARE_TYPE_ETHERNET);
								p->ProtocolType = Endian16(MAC_PROTO_IPV4);
								p->HardwareSize = 6;
								p->ProtocolSize = 4;
								p->Operation = Endian16(ARP_OPERATION_REQUEST);
								Copy(p->SrcAddress, hub->HubMacAddr, 6);
								p->SrcIP = IPToUINT(&hub->HubIp);
								p->TargetAddress[0] =
									p->TargetAddress[1] =
									p->TargetAddress[2] =
									p->TargetAddress[3] =
									p->TargetAddress[4] =
									p->TargetAddress[5] = 0x00;
								p->TargetIP = IPToUINT(&e->Ip);
								Insert(o, mac);
							}
						}

						if (hub->Option != NULL && hub->Option->NoIPv6AddrPolling == false)
						{
							if (IsIP6(&e->Ip))
							{
								BUF *buf;
								IPV6_ADDR ip6addr;

								if (IPToIPv6Addr(&ip6addr, &e->Ip))
								{
									buf = BuildICMPv6NeighborSoliciation(&hub->HubIpV6,
										&ip6addr,
										hub->HubMacAddr, ++hub->HubIP6Id, false);

									if (buf != NULL)
									{
										BUF *buf2 = NewBuf();
										MAC_HEADER mac;

										Zero(&mac, sizeof(mac));

										Copy(mac.DestAddress, e->MacAddress, 6);
										Copy(mac.SrcAddress, hub->HubMacAddr, 6);
										mac.Protocol = Endian16(MAC_PROTO_IPV6);

										WriteBuf(buf2, &mac, sizeof(MAC_HEADER));

										WriteBuf(buf2, buf->Buf, buf->Size);

										FreeBuf(buf);

										Insert(o2, buf2);
									}
								}
							}
						}
					}
				}
			}
		}
		UnlockHashList(hub->MacHashTable);

		if ((LIST_NUM(o) + LIST_NUM(o2)) != 0)
		{
			interval = HUB_ARP_SEND_INTERVAL / (LIST_NUM(o) + LIST_NUM(o2));
		}
		else
		{
			interval = HUB_ARP_SEND_INTERVAL;
		}

		for (i = 0;i < LIST_NUM(o);i++)
		{
			PKT *packet;
			void *p = LIST_DATA(o, i);

			Wait(hub->WatchDogEvent, interval);
			if (hub->HaltWatchDog)
			{
				for (;i < LIST_NUM(o);i++)
				{
					Free(LIST_DATA(o, i));
				}
				ReleaseList(o);

				for (i = 0;i < LIST_NUM(o2);i++)
				{
					FreeBuf(LIST_DATA(o2, i));
				}
				ReleaseList(o2);
				goto ESCAPE;
			}

			packet = ParsePacket((UCHAR *)p, sizeof(MAC_HEADER) + sizeof(ARPV4_HEADER));
			if (packet != NULL)
			{
				StorePacket(hub, NULL, packet);
				num_packets_v4++;
			}
			else
			{
				Free(p);
			}
		}

		for (i = 0;i < LIST_NUM(o2);i++)
		{
			PKT *packet;
			BUF *buf = LIST_DATA(o2, i);

			Wait(hub->WatchDogEvent, interval);
			if (hub->HaltWatchDog)
			{
				ReleaseList(o);

				for (;i < LIST_NUM(o2);i++)
				{
					FreeBuf(LIST_DATA(o2, i));
				}
				ReleaseList(o2);
				goto ESCAPE;
			}

			packet = ParsePacket(buf->Buf, buf->Size);
			if (packet != NULL)
			{
				StorePacket(hub, NULL, packet);
				num_packets_v6++;
			}
			else
			{
				Free(buf->Buf);
			}

			Free(buf);
		}

		ReleaseList(o);
		ReleaseList(o2);

		if (num == 0)
		{
			wait_time = HUB_ARP_SEND_INTERVAL;
		}

		Wait(hub->WatchDogEvent, wait_time);
	}
ESCAPE:
	return;
}

void MakeSimpleUsernameRemoveNtDomain(char *dst, UINT dst_size, char *src)
{
	char tmp1[MAX_SIZE];
	char tmp2[MAX_SIZE];
	if (dst == NULL || src == NULL)
	{
		return;
	}

	ParseNtUsername(src, tmp1, sizeof(tmp1), tmp2, sizeof(tmp2), false);

	StrCpy(dst, dst_size, tmp1);
}

UINT64 UsernameToInt64(char *name)
{
	UCHAR hash[SHA1_SIZE];
	UINT64 ret;
	char tmp[MAX_USERNAME_LEN + 1];
	if (name == 0 || IsEmptyStr(name))
	{
		return 0;
	}

	if (StartWith(name, ACCESS_LIST_INCLUDED_PREFIX) || StartWith(name, ACCESS_LIST_EXCLUDED_PREFIX))
	{
		return Rand64();
	}

	MakeSimpleUsernameRemoveNtDomain(tmp, sizeof(tmp), name);
	Trim(tmp);
	StrUpper(tmp);

	if (StrLen(tmp) == 0)
	{
		return 0;
	}

	Sha0(hash, tmp, StrLen(tmp));
	Copy(&ret, hash, sizeof(ret));

	return ret;
}

SESSION *GetSessionByName(HUB *hub, char *name)
{
	if (hub == NULL || name == NULL)
	{
		return NULL;
	}

	LockList(hub->SessionList);
	{
		UINT i;
		for (i = 0;i < LIST_NUM(hub->SessionList);i++)
		{
			SESSION *s = LIST_DATA(hub->SessionList, i);
			if (StrCmpi(s->Name, name) == 0)
			{
				AddRef(s->ref);
				UnlockList(hub->SessionList);
				return s;
			}
		}
	}
	UnlockList(hub->SessionList);

	return NULL;
}


void StopAllSession(HUB *h)
{
	SESSION **s;
	UINT i, num;
	if (h == NULL)
	{
		return;
	}

	LockList(h->SessionList);
	{
		num = LIST_NUM(h->SessionList);
		s = ToArray(h->SessionList);
		DeleteAll(h->SessionList);
	}
	UnlockList(h->SessionList);

	for (i = 0;i < num;i++)
	{
		StopSession(s[i]);
		ReleaseSession(s[i]);
	}

	Free(s);
}

void DelSession(HUB *h, SESSION *s)
{
	if (h == NULL || s == NULL)
	{
		return;
	}

	LockList(h->SessionList);
	{
		if (Delete(h->SessionList, s))
		{
			ReleaseSession(s);
		}
	}
	UnlockList(h->SessionList);
}

void AddSession(HUB *h, SESSION *s)
{
	if (h == NULL || s == NULL)
	{
		return;
	}

	LockList(h->SessionList);
	{
		Insert(h->SessionList, s);
		AddRef(s->ref);
	}
	UnlockList(h->SessionList);
}

void StopHub(HUB *h)
{
	bool old_status = false;
	if (h == NULL)
	{
		return;
	}

	old_status = h->Offline;
	h->HubIsOnlineButHalting = true;

	SetHubOffline(h);

	if (h->Halt == false)
	{
		SLog(h->Cedar, "LS_HUB_STOP", h->Name);
		h->Halt = true;
	}

	h->Offline = old_status;
	h->HubIsOnlineButHalting = false;
}

void SetHubOnline(HUB *h)
{
	if (h == NULL)
	{
		return;
	}

	Lock(h->lock_online);
	{
		if (h->Offline == false)
		{
			Unlock(h->lock_online);
			return;
		}
		HLog(h, "LH_ONLINE");

		StartAllLink(h);

		LockList(h->Cedar->LocalBridgeList);
		{
			UINT i;
			for (i = 0;i < LIST_NUM(h->Cedar->LocalBridgeList);i++)
			{
				LOCALBRIDGE *br = LIST_DATA(h->Cedar->LocalBridgeList, i);

				if (StrCmpi(br->HubName, h->Name) == 0)
				{
					if (br->Bridge == NULL)
					{
						br->Bridge = BrNewBridge(h, br->DeviceName, NULL, br->Local, br->Monitor,
							br->TapMode, br->TapMacAddress, br->LimitBroadcast, br);
					}
				}
			}
		}
		UnlockList(h->Cedar->LocalBridgeList);

		h->Offline = false;
	}
	Unlock(h->lock_online);
}

void SetHubOffline(HUB *h)
{
	UINT i;
	if (h == NULL)
	{
		return;
	}

	Lock(h->lock_online);
	{
		if (h->Offline || h->Halt)
		{
			Unlock(h->lock_online);
			return;
		}

		HLog(h, "LH_OFFLINE");

		StopAllLink(h);

		LockList(h->Cedar->LocalBridgeList);
		{
			for (i = 0;i < LIST_NUM(h->Cedar->LocalBridgeList);i++)
			{
				LOCALBRIDGE *br = LIST_DATA(h->Cedar->LocalBridgeList, i);

				if (StrCmpi(br->HubName, h->Name) == 0)
				{
					BrFreeBridge(br->Bridge);
					br->Bridge = NULL;
				}
			}
		}
		UnlockList(h->Cedar->LocalBridgeList);

		h->Offline = true;

		StopAllSession(h);
	}
	Unlock(h->lock_online);
}

bool IsHub(CEDAR *cedar, char *name)
{
	HUB *h;
	if (cedar == NULL || name == NULL)
	{
		return false;
	}

	h = GetHub(cedar, name);
	if (h == NULL)
	{
		return false;
	}

	ReleaseHub(h);

	return true;
}

HUB *GetHub(CEDAR *cedar, char *name)
{
	HUB *h, t;
	if (cedar == NULL || name == NULL)
	{
		return NULL;
	}

	LockHubList(cedar);

	t.Name = name;
	h = Search(cedar->HubList, &t);
	if (h == NULL)
	{
		UnlockHubList(cedar);
		return NULL;
	}

	AddRef(h->ref);

	UnlockHubList(cedar);

	return h;
}

void LockHubList(CEDAR *cedar)
{
	if (cedar == NULL)
	{
		return;
	}

	LockList(cedar->HubList);
}

void UnlockHubList(CEDAR *cedar)
{
	if (cedar == NULL)
	{
		return;
	}

	UnlockList(cedar->HubList);
}

void ReleaseHub(HUB *h)
{
	if (h == NULL)
	{
		return;
	}

	if (Release(h->ref) == 0)
	{
		CleanupHub(h);
	}
}

void CleanupHub(HUB *h)
{
	UINT i;
	char name[MAX_SIZE];
	if (h == NULL)
	{
		return;
	}

	StrCpy(name, sizeof(name), h->Name);

	if (h->WatchDogStarted)
	{
		StopHubWatchDog(h);
	}

	FreeAccessList(h);

	ReleaseAllLink(h);
	DeleteHubDb(h->HubDb);
	ReleaseCedar(h->Cedar);
	DeleteLock(h->lock);
	DeleteLock(h->lock_online);
	Free(h->Name);
	ReleaseList(h->SessionList);
	ReleaseHashList(h->MacHashTable);
	ReleaseList(h->IpTable);
	ReleaseList(h->MonitorList);
	ReleaseList(h->LinkList);
	DeleteCounter(h->NumSessions);
	DeleteCounter(h->NumSessionsClient);
	DeleteCounter(h->NumSessionsBridge);
	DeleteCounter(h->SessionCounter);
	FreeTraffic(h->Traffic);
	Free(h->Option);

	DeleteLock(h->TrafficLock);

	FreeLog(h->PacketLogger);
	FreeLog(h->SecurityLogger);

	for (i = 0;i < LIST_NUM(h->AdminOptionList);i++)
	{
		Free(LIST_DATA(h->AdminOptionList, i));
	}
	ReleaseList(h->AdminOptionList);

	if (h->Msg != NULL)
	{
		Free(h->Msg);
	}

	FreeUserList(h->UserList);

	Free(h);
}

int CompareHub(void *p1, void *p2)
{
	HUB *h1, *h2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	h1 = *(HUB **)p1;
	h2 = *(HUB **)p2;
	if (h1 == NULL || h2 == NULL)
	{
		return 0;
	}
	return StrCmpi(h1->Name, h2->Name);
}

bool IsHubMacAddress(UCHAR *mac)
{
	if (mac == NULL)
	{
		return false;
	}

	if (mac[0] == 0x00 && mac[1] == SE_HUB_MAC_ADDR_SIGN)
	{
		return true;
	}

	return false;
}

bool IsHubIpAddress32(UINT ip32)
{
	IP ip;

	UINTToIP(&ip, ip32);

	return IsHubIpAddress(&ip);
}
bool IsHubIpAddress(IP *ip)
{
	if (ip == NULL)
	{
		return false;
	}

	const BYTE *ipv4 = IPV4(ip->address);

	if (ipv4[0] == 172 && ipv4[1] == 31)
	{
		if (ipv4[2] >= 1 && ipv4[2] <= 254)
		{
			if (ipv4[3] >= 1 && ipv4[3] <= 254)
			{
				return true;
			}
		}
	}

	return false;
}
bool IsHubIpAddress64(IPV6_ADDR *addr)
{
	if (addr == NULL)
	{
		return false;
	}

	if (addr->Value[0] == 0xfe && addr->Value[1] == 0x80 &&
		addr->Value[2] == 0 &&
		addr->Value[3] == 0 &&
		addr->Value[4] == 0 &&
		addr->Value[5] == 0 &&
		addr->Value[6] == 0 &&
		addr->Value[7] == 0 &&
		addr->Value[8] == 0x02 && addr->Value[9] == 0xae && 
		addr->Value[11] == 0xff && addr->Value[12] == 0xfe)
	{
		return true;
	}

	return false;
}

void GenHubIpAddress(IP *ip, char *name)
{
	char tmp1[MAX_SIZE];
	char tmp2[MAX_SIZE];
	UCHAR hash[SHA1_SIZE];
	if (ip == NULL || name == NULL)
	{
		return;
	}

	StrCpy(tmp1, sizeof(tmp1), name);
	Trim(tmp1);
	GenerateMachineUniqueHash(hash);
	BinToStr(tmp2, sizeof(tmp2), hash, sizeof(hash));
	StrCat(tmp2, sizeof(tmp2), tmp1);
	StrUpper(tmp2);

	Sha0(hash, tmp2, StrLen(tmp2));

	SetIP(ip, 172, 31, hash[0] % 254 + 1, hash[0] % 254 + 1);
}

void GenHubMacAddress(UCHAR *mac, char *name)
{
	char tmp1[MAX_SIZE];
	char tmp2[MAX_SIZE];
	UCHAR hash[SHA1_SIZE];
	if (mac == NULL || name == NULL)
	{
		return;
	}

	StrCpy(tmp1, sizeof(tmp1), name);
	Trim(tmp1);
	GenerateMachineUniqueHash(hash);
	BinToStr(tmp2, sizeof(tmp2), hash, sizeof(hash));
	StrCat(tmp2, sizeof(tmp2), tmp1);
	StrUpper(tmp2);

	Sha0(hash, tmp2, StrLen(tmp2));

	mac[0] = 0x00;
	mac[1] = SE_HUB_MAC_ADDR_SIGN;
	mac[2] = hash[0];
	mac[3] = hash[1];
	mac[4] = hash[2];
	mac[5] = hash[3];
}

HUB *NewHub(CEDAR *cedar, char *HubName, HUB_OPTION *option)
{
	HUB *h;
	char packet_logger_name[MAX_SIZE];
	char tmp[MAX_SIZE];
	char safe_hub_name[MAX_HUBNAME_LEN + 1];
	UCHAR hash[SHA1_SIZE];
	IP ip6;
	if (cedar == NULL || option == NULL || HubName == NULL)
	{
		return NULL;
	}

	h = ZeroMalloc(sizeof(HUB));
	Sha0(h->HashedPassword, "", 0);
	HashPassword(h->SecurePassword, ADMINISTRATOR_USERNAME, "");
	h->lock = NewLock();
	h->lock_online = NewLock();
	h->ref = NewRef();
	h->Cedar = cedar;
	AddRef(h->Cedar->ref);

	ConvertSafeFileName(safe_hub_name, sizeof(safe_hub_name), HubName);
	h->Name = CopyStr(safe_hub_name);


	h->AdminOptionList = NewList(CompareAdminOption);
	AddHubAdminOptionsDefaults(h, true);

	h->LastCommTime = SystemTime64();
	h->LastLoginTime = SystemTime64();
	h->NumLogin = 0;

	h->TrafficLock = NewLock();

	h->HubDb = NewHubDb();

	h->SessionList = NewList(NULL);
	h->SessionCounter = NewCounter();
	h->NumSessions = NewCounter();
	h->NumSessionsClient = NewCounter();
	h->NumSessionsBridge = NewCounter();
	h->MacHashTable = NewHashList(GetHashOfMacTable, CompareMacTable, 8, false);
	h->IpTable = NewList(CompareIpTable);
	h->MonitorList = NewList(NULL);
	h->LinkList = NewList(NULL);

	h->Traffic = NewTraffic();

	h->Option = ZeroMalloc(sizeof(HUB_OPTION));
	Copy(h->Option, option, sizeof(HUB_OPTION));

	if (h->Option->VlanTypeId == 0)
	{
		h->Option->VlanTypeId = MAC_PROTO_TAGVLAN;
	}

	h->Option->DropBroadcastsInPrivacyFilterMode = true;
	h->Option->DropArpInPrivacyFilterMode = true;
	h->Option->AllowSameUserInPrivacyFilterMode = false;

	Rand(h->HubSignature, sizeof(h->HubSignature));

	GenerateMachineUniqueHash(hash);
	GenHubMacAddress(h->HubMacAddr, h->Name);
	GenHubIpAddress(&h->HubIp, h->Name);

	GenerateEui64LocalAddress(&ip6, h->HubMacAddr);
	IPToIPv6Addr(&h->HubIpV6, &ip6);

	InitAccessList(h);

	h->UserList = NewUserList();

	h->LogSetting.SavePacketLog = h->LogSetting.SaveSecurityLog = true;
	h->LogSetting.PacketLogConfig[PACKET_LOG_TCP_CONN] =
		h->LogSetting.PacketLogConfig[PACKET_LOG_DHCP] = PACKET_LOG_HEADER;
	h->LogSetting.SecurityLogSwitchType = LOG_SWITCH_DAY;
	h->LogSetting.PacketLogSwitchType = LOG_SWITCH_DAY;

	MakeDir(HUB_SECURITY_LOG_DIR_NAME);
	MakeDir(HUB_PACKET_LOG_DIR_NAME);

	Format(packet_logger_name, sizeof(packet_logger_name), HUB_PACKET_LOG_FILE_NAME, h->Name);
	h->PacketLogger = NewLog(packet_logger_name, HUB_PACKET_LOG_PREFIX, h->LogSetting.PacketLogSwitchType);

	Format(tmp, sizeof(tmp), HUB_SECURITY_LOG_FILE_NAME, h->Name);
	h->SecurityLogger = NewLog(tmp, HUB_SECURITY_LOG_PREFIX, h->LogSetting.SecurityLogSwitchType);

	SetHubOnline(h);

	if (h->Cedar->Bridge)
	{
		h->Option->NoArpPolling = true;
	}

	if (h->Option->NoArpPolling == false && h->Option->NoIpTable == false)
	{
		StartHubWatchDog(h);
		h->WatchDogStarted = true;
	}

	SLog(h->Cedar, "LS_HUB_START", h->Name);

	MacToStr(tmp, sizeof(tmp), h->HubMacAddr);
	SLog(h->Cedar, "LS_HUB_MAC", h->Name, tmp);

	return h;
}

void DeleteHubDb(HUBDB *d)
{
	if (d == NULL)
	{
		return;
	}

	LockList(d->UserList);
	{
		LockList(d->GroupList);
		{
			UINT i;
			USER **users;
			USERGROUP **groups;

			users = ToArray(d->UserList);
			groups = ToArray(d->GroupList);

			for (i = 0;i < LIST_NUM(d->UserList);i++)
			{
				ReleaseUser(users[i]);
			}
			for (i = 0;i < LIST_NUM(d->GroupList);i++)
			{
				ReleaseGroup(groups[i]);
			}

			Free(users);
			Free(groups);
		}
		UnlockList(d->GroupList);
	}
	UnlockList(d->UserList);

	LockList(d->RootCertList);
	{
		UINT i;
		for (i = 0;i < LIST_NUM(d->RootCertList);i++)
		{
			X *x = LIST_DATA(d->RootCertList, i);
			FreeX(x);
		}
	}
	UnlockList(d->RootCertList);

	LockList(d->CrlList);
	{
		UINT i;
		for (i = 0;i < LIST_NUM(d->CrlList);i++)
		{
			CRL *crl = LIST_DATA(d->CrlList, i);
			FreeCrl(crl);
		}
	}
	UnlockList(d->CrlList);

	FreeAcList(d->AcList);

	ReleaseList(d->GroupList);
	ReleaseList(d->UserList);
	ReleaseList(d->RootCertList);
	ReleaseList(d->CrlList);
	Free(d);
}

HUBDB *NewHubDb()
{
	HUBDB *d = ZeroMalloc(sizeof(HUBDB));

	d->GroupList = NewList(CompareGroupName);
	d->UserList = NewList(CompareUserName);
	d->RootCertList = NewList(CompareCert);
	d->CrlList = NewList(NULL);
	d->AcList = NewList(CmpAc);

	return d;
}


