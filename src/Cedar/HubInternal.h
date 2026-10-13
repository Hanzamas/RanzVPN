// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// HubInternal.h
// Module-internal declarations of the Hub module: only its own files include this header

#ifndef	HUB_INTERNAL_H
#define	HUB_INTERNAL_H

// Function prototype
HUBDB *NewHubDb();
void DeleteHubDb(HUBDB *d);
void GenHubMacAddress(UCHAR *mac, char *name);
void GenHubIpAddress(IP *ip, char *name);
bool IsHubIpAddress(IP *ip);
bool IsHubIpAddress32(UINT ip32);
bool IsHubIpAddress64(IPV6_ADDR *addr);
bool IsHubMacAddress(UCHAR *mac);
void CleanupHub(HUB *h);
void StopAllSession(HUB *h);
bool HubPaInit(SESSION *s);
void HubPaFree(SESSION *s);
CANCEL *HubPaGetCancel(SESSION *s);
UINT HubPaGetNextPacket(SESSION *s, void **data);
bool HubPaPutPacket(SESSION *s, void *data, UINT size);
int CompareMacTable(void *p1, void *p2);
UINT GetHashOfMacTable(void *p);
void StorePacket(HUB *hub, SESSION *s, PKT *packet);
bool StorePacketFilter(SESSION *s, PKT *packet);
void StorePacketToHubPa(HUB_PA *dest, SESSION *src, void *data, UINT size, PKT *packet, bool is_flooding, bool no_check_acl);
int CompareIpTable(void *p1, void *p2);
bool StorePacketFilterByPolicy(SESSION *s, PKT *p);
bool DeleteIPv6DefaultRouterInRA(PKT *p);
bool StorePacketFilterByTrafficLimiter(SESSION *s, PKT *p);
void IntoTrafficLimiter(TRAFFIC_LIMITER *tr, PKT *p);
bool IsMostHighestPriorityPacket(SESSION *s, PKT *p);
int CompareStormList(void *p1, void *p2);
STORM *SearchStormList(HUB_PA *pa, UCHAR *mac_address, IP *src_ip, IP *dest_ip, bool strict);
STORM *AddStormList(HUB_PA *pa, UCHAR *mac_address, IP *src_ip, IP *dest_ip, bool strict);
bool CheckBroadcastStorm(HUB *hub, SESSION *s, PKT *p);
int CmpAccessList(void *p1, void *p2);
void InitAccessList(HUB *hub);
void FreeAccessList(HUB *hub);
bool IsTcpPacketNcsiHttpAccess(PKT *p);
UINT64 UsernameToInt64(char *name);
void MakeSimpleUsernameRemoveNtDomain(char *dst, UINT dst_size, char *src);
bool ApplyAccessListToStoredPacket(HUB *hub, SESSION *s, PKT *p);
void ForceRedirectToUrl(HUB *hub, SESSION *src_session, PKT *p, char *redirect_url);
BUF *BuildRedirectToUrlPayload(HUB *hub, SESSION *s, char *redirect_url);
bool ApplyAccessListToForwardPacket(HUB *hub, SESSION *src_session, SESSION *dest_session, PKT *p);
bool IsPacketMaskedByAccessList(SESSION *s, PKT *p, ACCESS *a, UINT64 dest_username, UINT64 dest_groupname, SESSION *dest_session);
void DeleteOldIpTableEntry(LIST *o);
void DeleteExpiredIpTableEntry(LIST *o);
void DeleteExpiredMacTableEntry(HASH_LIST *h);
void StartHubWatchDog(HUB *h);
void StopHubWatchDog(HUB *h);
void HubWatchDogThread(THREAD *t, void *param);
int CompareAdminOption(void *p1, void *p2);
UINT GetHubAdminOptionEx(HUB *h, char *name, UINT default_value);
bool IsCertMatchCrl(X *x, CRL *crl);
bool IsCertMatchCrlList(X *x, LIST *o);
int CmpAc(void *p1, void *p2);
void DelAllAc(LIST *o);
void NormalizeAcList(LIST *o);
bool IsIpMaskedByAc(IP *ip, AC *ac);
bool IsIPManagementTargetForHUB(IP *ip, HUB *hub);
ADMIN_OPTION *NewAdminOption(char *name, UINT value);
UINT GetHubAdminOptionData(RPC_ADMIN_OPTION *ao, char *name);
LIST *NewUserList();
void FreeUserList(LIST *o);
void FreeUserListEntry(USERLIST *u);
int CompareUserList(void *p1, void *p2);
USERLIST *LoadUserList(LIST *o, char *filename);
USERLIST *FindUserList(LIST *o, char *filename);
bool IsUserMatchInUserList(LIST *o, char *filename, UINT64 user_hash);
bool IsUserMatchInUserListWithCacheExpires(LIST *o, char *filename, UINT64 user_hash, UINT64 lifetime);
bool IsUserMatchInUserListWithCacheExpiresAcl(LIST *o, char *name_in_acl, UINT64 user_hash, UINT64 lifetime);

#endif	// HUB_INTERNAL_H
