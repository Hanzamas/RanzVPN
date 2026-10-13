// Hub.h
// Header of Hub.c

#ifndef	HUB_H
#define	HUB_H

#include "Account.h"
#include "Logging.h"

#define	ACCESS_LIST_INCLUDED_PREFIX		"include:"
#define	ACCESS_LIST_EXCLUDED_PREFIX		"exclude:"

#define	ACCESS_LIST_INCLUDE_FILE_CACHE_LIFETIME		30

#define	ACCESS_LIST_INCLUDE_FILE_MAX_SIZE			(1024 * 1024)

#define	ACCESS_LIST_URL_INFO_TAG					"<INFO>"

#define	OLD_MAC_ADDRESS_ENTRY_FLUSH_INTERVAL		1000

#define	DEFAULT_FLOODING_QUEUE_LENGTH				(32 * 1024 * 1024)

#define	DEFAULT_DHCP_DISCOVER_TIMEOUT				(5 * 1000)

struct HUBDB
{
	LIST *UserList;
	LIST *GroupList;
	LIST *RootCertList;
	LIST *CrlList;
	LIST *AcList;
};

struct TRAFFIC_LIMITER
{
	UINT64 LastTime;
	UINT64 Value;
};

struct STORM
{
	UCHAR MacAddress[6];
	UCHAR Padding[2];
	IP SrcIp;
	IP DestIp;
	UINT64 CheckStartTick;
	UINT CurrentBroadcastNum;
	UINT DiscardValue;
	bool StrictMode;
};

struct HUB_PA
{
	CANCEL *Cancel;
	QUEUE *PacketQueue;
	bool MonitorPort;
	UINT64 Now;
	TRAFFIC_LIMITER UploadLimiter;
	TRAFFIC_LIMITER DownloadLimiter;
	SESSION *Session;
	LIST *StormList;
	UINT64 UsernameHash;
	UINT64 UsernameHashSimple;
	UINT64 GroupnameHash;
};

struct HUB_OPTION
{
	UINT MaxSession;
	bool NoEnum;
	bool NoArpPolling;
	bool NoIPv6AddrPolling;
	bool NoIpTable;
	bool NoMacAddressLog;
	bool ManageOnlyPrivateIP;
	bool ManageOnlyLocalUnicastIPv6;
	bool DisableIPParsing;
	bool YieldAfterStorePacket;
	bool NoSpinLockForPacketDelay;
	UINT BroadcastStormDetectionThreshold;
	bool FilterPPPoE;
	bool FilterOSPF;
	bool FilterIPv4;
	bool FilterIPv6;
	bool FilterNonIP;
	bool FilterBPDU;
	UINT ClientMinimumRequiredBuild;
	bool NoIPv6DefaultRouterInRAWhenIPv6;
	bool NoIPv4PacketLog;
	bool NoIPv6PacketLog;
	bool NoLookBPDUBridgeId;
	bool NoManageVlanId;
	UINT VlanTypeId;
	bool FixForDLinkBPDU;
	UINT RequiredClientId;
	UINT AdjustTcpMssValue;
	bool DisableAdjustTcpMss;
	bool NoDhcpPacketLogOutsideHub;
	bool DisableHttpParsing;
	bool DisableUdpAcceleration;
	bool DisableUdpFilterForLocalBridgeNic;
	bool ApplyIPv4AccessListOnArpPacket;
	bool RemoveDefGwOnDhcpForLocalhost;
	UINT AccessListIncludeFileCacheLifetime;
	bool DisableCheckMacOnLocalBridge;
	bool DisableCorrectIpOffloadChecksum;
	bool BroadcastLimiterStrictMode;
	UINT MaxLoggedPacketsPerMinute;
	bool DoNotSaveHeavySecurityLogs;
	bool DropBroadcastsInPrivacyFilterMode;
	bool DropArpInPrivacyFilterMode;
	bool AllowSameUserInPrivacyFilterMode;
	bool SuppressClientUpdateNotification;
	UINT FloodingSendQueueBufferQuota;
	UINT DetectDormantSessionInterval;
	bool NoPhysicalIPOnPacketLog;
	bool UseHubNameAsDhcpUserClassOption;
	bool AllowEapMatchUserByCert;
	UINT DhcpDiscoverTimeoutMs;
};

struct MAC_TABLE_ENTRY
{
	UCHAR MacAddress[6];
	UCHAR Padding[2];
	UINT VlanId;
	SESSION *Session;
	HUB_PA *HubPa;
	UINT64 CreatedTime;
	UINT64 UpdatedTime;
};

struct IP_TABLE_ENTRY
{
	IP Ip;
	SESSION *Session;
	bool DhcpAllocated;
	UINT64 CreatedTime;
	UINT64 UpdatedTime;
	UCHAR MacAddress[6];
};

struct ACCESS
{
	UINT Id;
	wchar_t Note[MAX_ACCESSLIST_NOTE_LEN + 1];

	bool Active;
	UINT Priority;
	bool Discard;
	UINT SrcIpAddress;
	UINT SrcSubnetMask;
	UINT DestIpAddress;
	UINT DestSubnetMask;
	UINT Protocol;
	UINT SrcPortStart;
	UINT SrcPortEnd;
	UINT DestPortStart;
	UINT DestPortEnd;
	UINT64 SrcUsernameHash;
	bool IsSrcUsernameIncludeOrExclude;
	char SrcUsername[MAX_USERNAME_LEN + 1];
	bool IsDestUsernameIncludeOrExclude;
	UINT64 DestUsernameHash;
	char DestUsername[MAX_USERNAME_LEN + 1];
	bool CheckSrcMac;
	UCHAR SrcMacAddress[6];
	UCHAR SrcMacMask[6];
	bool CheckDstMac;
	UCHAR DstMacAddress[6];
	UCHAR DstMacMask[6];
	bool CheckTcpState;
	bool Established;
	UINT Delay;
	UINT Jitter;
	UINT Loss;
	char RedirectUrl[MAX_REDIRECT_URL_LEN + 1];

	bool IsIPv6;
	IPV6_ADDR SrcIpAddress6;
	IPV6_ADDR SrcSubnetMask6;
	IPV6_ADDR DestIpAddress6;
	IPV6_ADDR DestSubnetMask6;


	UINT UniqueId;
};

struct ADMIN_OPTION
{
	char Name[MAX_ADMIN_OPTION_NAME_LEN + 1];
	UINT Value;
	wchar_t Descrption[MAX_SIZE];
};

struct CRL
{
	X_SERIAL *Serial;
	NAME *Name;
	UCHAR DigestMD5[MD5_SIZE];
	UCHAR DigestSHA1[SHA1_SIZE];
};

struct AC
{
	UINT Id;
	UINT Priority;
	bool Deny;
	bool Masked;
	IP IpAddress;
	IP SubnetMask;
};

struct USERLIST
{
	char Filename[MAX_PATH];
	LIST *UserHashList;
};

struct HUB
{
	LOCK *lock;
	LOCK *lock_online;
	REF *ref;
	CEDAR *Cedar;
	HUBDB *HubDb;
	char *Name;
	volatile bool Halt;
	bool Offline;
	LIST *SessionList;
	COUNTER *SessionCounter;
	TRAFFIC *Traffic;
	LOCK *TrafficLock;
	COUNTER *NumSessions;
	COUNTER *NumSessionsClient;
	COUNTER *NumSessionsBridge;
	HUB_OPTION *Option;
	HASH_LIST *MacHashTable;
	LIST *IpTable;
	LIST *MonitorList;
	LIST *LinkList;
	UCHAR HubSignature[16];
	UCHAR HubMacAddr[6];
	IP HubIp;
	IPV6_ADDR HubIpV6;
	UINT HubIP6Id;
	UCHAR Padding[2];
	LIST *AccessList;
	HUB_LOG LogSetting;
	LOG *PacketLogger;
	LOG *SecurityLogger;
	UCHAR HashedPassword[SHA1_SIZE];
	UCHAR SecurePassword[SHA1_SIZE];
	THREAD *WatchDogThread;
	EVENT *WatchDogEvent;
	bool WatchDogStarted;
	volatile bool HaltWatchDog;
	LIST *AdminOptionList;
	UINT64 CreatedTime;
	UINT64 LastCommTime;
	UINT64 LastLoginTime;
	UINT NumLogin;
	bool HubIsOnlineButHalting;
	wchar_t *Msg;
	LIST *UserList;
	UINT64 LastFlushTick;
	bool StopAllLinkFlag;
	bool ForceDisableComm;
};


extern ADMIN_OPTION admin_options[];
extern UINT num_admin_options;


HUB *NewHub(CEDAR *cedar, char *HubName, HUB_OPTION *option);
void SetHubMsg(HUB *h, wchar_t *msg);
wchar_t *GetHubMsg(HUB *h);
void ReleaseHub(HUB *h);
int CompareHub(void *p1, void *p2);
void LockHubList(CEDAR *cedar);
void UnlockHubList(CEDAR *cedar);
HUB *GetHub(CEDAR *cedar, char *name);
bool IsHub(CEDAR *cedar, char *name);
void StopHub(HUB *h);
void AddSession(HUB *h, SESSION *s);
void DelSession(HUB *h, SESSION *s);
PACKET_ADAPTER *GetHubPacketAdapter();
void SetHubOnline(HUB *h);
void SetHubOffline(HUB *h);
SESSION *GetSessionByName(HUB *hub, char *name);
void AddRootCert(HUB *hub, X *x);
void AddAccessListEx(HUB *hub, ACCESS *a, bool no_sort, bool no_reassign_id);
void GetAccessListStr(char *str, UINT size, ACCESS *a);
int CompareCert(void *p1, void *p2);
void GetHubLogSetting(HUB *h, HUB_LOG *setting);
void SetHubLogSettingEx(HUB *h, HUB_LOG *setting, bool no_change_switch_type);
UINT GetHubAdminOption(HUB *h, char *name);
void DeleteAllHubAdminOption(HUB *h, bool lock);
void AddHubAdminOptionsDefaults(HUB *h, bool lock);
wchar_t *GenerateCrlStr(CRL *crl);
bool IsValidCertInHub(HUB *h, X *x);
void FreeCrl(CRL *crl);
CRL *CopyCrl(CRL *crl);
int CmpAc(void *p1, void *p2);
void AddAc(LIST *o, AC *ac);
void SetAcList(LIST *o, LIST *src);
bool IsIpDeniedByAcList(IP *ip, LIST *o);
char *GenerateAcStr(AC *ac);
void FreeAcList(LIST *o);
wchar_t *GetHubAdminOptionHelpString(char *name);
void HubOptionStructToData(RPC_ADMIN_OPTION *ao, HUB_OPTION *o, char *hub_name);
void DataToHubOptionStruct(HUB_OPTION *o, RPC_ADMIN_OPTION *ao);
bool IsURLMsg(wchar_t *str, char *url, UINT url_size);
void DeleteAllUserListCache(LIST *o);
bool CheckMaxLoggedPacketsPerMinute(SESSION *s, UINT max_packets, UINT64 now);

#endif


