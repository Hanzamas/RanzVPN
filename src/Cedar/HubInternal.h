// HubInternal.h
// Module-internal declarations of the Hub module: only its own files include this header

#ifndef HUB_INTERNAL_H
#define HUB_INTERNAL_H

HUBDB *NewHubDb();
void DeleteHubDb(HUBDB *d);
bool IsHubIpAddress(IP *ip);
bool IsHubIpAddress32(UINT ip32);
bool IsHubIpAddress64(IPV6_ADDR *addr);
bool IsHubMacAddress(UCHAR *mac);
void CleanupHub(HUB *h);
void StorePacket(HUB *hub, SESSION *s, PKT *packet);
bool StorePacketFilter(SESSION *s, PKT *packet);
void StorePacketToHubPa(HUB_PA *dest, SESSION *src, void *data, UINT size, PKT *packet, bool from_flood);
void DeleteIPv6DefaultRouterInRA(PKT *p);
void IntoTrafficLimiter(TRAFFIC_LIMITER *tr, PKT *p);
bool IsMostHighestPriorityPacket(SESSION *s, PKT *p);
STORM *AddStormList(HUB_PA *pa, UCHAR *mac_address, IP *src_ip, IP *dest_ip, bool strict);
int CmpAccessList(void *p1, void *p2);
UINT64 UsernameToInt64(char *name);
void MakeSimpleUsernameRemoveNtDomain(char *dst, UINT dst_size, char *src);
UINT HubMacTableNum(HUB *h);
MAC_TABLE_ENTRY *MacTableLookup(HUB *h, UCHAR *mac, UINT vlan_id);
MAC_TABLE_ENTRY *MacTableLearn(HUB *h, SESSION *s, UCHAR *mac, UINT vlan_id, UINT64 now);
void MacTableFlushSession(HUB *h, SESSION *s);
IP_TABLE_ENTRY *IpTableLookup(HUB *h, IP *ip);
void IpTableAddEntry(HUB *h, SESSION *s, IP *ip, UCHAR *mac, bool dhcp_allocated, UINT64 now);
void IpTableExpiryNote(IP_TABLE_EXPIRY *x, IP_TABLE_ENTRY *e);
bool IpTableExpiryDue(IP_TABLE_EXPIRY *x, UINT64 now);
UINT CountSessionIps(HUB *h, SESSION *s, bool v6);
void LogIpConflict(HUB *h, SESSION *s, IP *ip, IP_TABLE_ENTRY *e, UINT64 now);
void IpTableFlushSession(HUB *h, SESSION *s);
int CompareCert(void *p1, void *p2);
void DeleteExpiredMacTableEntry(HASH_LIST *h);
void HubWatchDogThread(THREAD *t, void *param);
bool IsCertMatchCrl(X *x, CRL *crl);
bool IsCertMatchCrlList(X *x, LIST *o);
void DelAllAc(LIST *o);
void NormalizeAcList(LIST *o);
bool IsIpMaskedByAc(IP *ip, AC *ac);
bool IsIPManagementTargetForHUB(IP *ip, HUB *hub);
void FreeUserListEntry(USERLIST *u);
int CompareUserList(void *p1, void *p2);
USERLIST *LoadUserList(LIST *o, char *filename);
USERLIST *FindUserList(LIST *o, char *filename);
bool IsUserMatchInUserList(LIST *o, char *filename, UINT64 user_hash);

#endif // HUB_INTERNAL_H
