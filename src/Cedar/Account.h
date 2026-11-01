// Account.h
// Header of Account.c

#ifndef ACCOUNT_H
#define ACCOUNT_H

#include "CedarType.h"
#include "Session.h"

#include "Mayaqua/Encrypt.h"

struct POLICY_ITEM {
	UINT Index;
	bool TypeInt;
	bool AllowZero;
	UINT MinValue;
	UINT MaxValue;
	UINT DefaultValue;
	char *FormatStr;
	UINT Offset;
	char *Name;      // Name in the config file and in the Pack ("policy:" prefix)
	bool Ver3;       // Added in Ver 3.0
	bool CascadeCmd; // Can be set from the cascade commands
	bool CascadeCfg; // Written to the config of a cascade connection
};

struct POLICY {
	// Ver 2.0 fields
	bool Access;
	bool DHCPFilter;
	bool DHCPNoServer;
	bool DHCPForce;
	bool NoBridge;
	bool NoRouting;
	bool CheckMac;
	bool CheckIP;
	bool ArpDhcpOnly; // Allow only ARP, DHCP and ICMPv6 broadcasts
	bool PrivacyFilter;
	bool NoServer;
	bool NoBroadcastLimiter; // Do not limit the number of broadcasts
	bool MonitorPort;
	UINT MaxConnection;
	UINT TimeOut;
	UINT MaxMac;
	UINT MaxIP;
	UINT MaxUpload;
	UINT MaxDownload;
	bool FixPassword;
	UINT MultiLogins;
	bool NoQoS;

	// Ver 3.0 fields
	bool RSandRAFilter;
	bool RAFilter;
	bool DHCPv6Filter;
	bool DHCPv6NoServer;
	bool NoRoutingV6;
	bool CheckIPv6;
	bool NoServerV6;
	UINT MaxIPv6;
	bool NoSavePassword;
	UINT AutoDisconnect;
	bool FilterIPv4;
	bool FilterIPv6;
	bool FilterNonIP;
	bool NoIPv6DefaultRouterInRA;         // Remove the default router from IPv6 router advertisements
	bool NoIPv6DefaultRouterInRAWhenIPv6; // Same, but only when IPv6 is enabled
	UINT VLanId;

	bool Ver3; // Whether version 3.0
};

struct USERGROUP {
	LOCK *lock;
	REF *ref;
	char *Name;
	wchar_t *RealName;
	wchar_t *Note;
	POLICY *Policy;
	TRAFFIC *Traffic;
};

struct USER {
	LOCK *lock;
	REF *ref;
	char *Name;
	wchar_t *RealName;
	wchar_t *Note;
	char *GroupName;
	USERGROUP *Group;
	UINT AuthType;
	void *AuthData;
	UINT64 CreatedTime;
	UINT64 UpdatedTime;
	UINT64 ExpireTime;
	UINT64 LastLoginTime;
	UINT NumLogin;
	POLICY *Policy;
	TRAFFIC *Traffic;
};

struct AUTHPASSWORD {
	UCHAR HashedKey[SHA1_SIZE];
	UCHAR NtLmSecureHash[MD5_SIZE];
};

struct AUTHUSERCERT {
	X *UserX;
};

struct AUTHROOTCERT {
	X_SERIAL *Serial;
	wchar_t *CommonName;
};

struct AUTHNT {
	wchar_t *NtUsername;
};


#define NUM_POLICY_ITEM 38

// Size of the Ver 2.0 part of POLICY: the Ver 3.0 fields start at RSandRAFilter
#define POLICY_VER2_SIZE offsetof(POLICY, RSandRAFilter)

extern POLICY_ITEM policy_item[];


int CompareUserName(void *p1, void *p2);
int CompareGroupName(void *p1, void *p2);
void AcLock(HUB *h);
void AcUnlock(HUB *h);
USERGROUP *NewGroup(char *name, wchar_t *realname, wchar_t *note);
void ReleaseGroup(USERGROUP *g);
USER *NewUser(char *name, wchar_t *realname, wchar_t *note, UINT authtype, void *authdata);
void ReleaseUser(USER *u);
void FreeAuthData(UINT authtype, void *authdata);
bool AcAddUser(HUB *h, USER *u);
bool AcAddGroup(HUB *h, USERGROUP *g);
USER *AcGetUser(HUB *h, char *name);
USERGROUP *AcGetGroup(HUB *h, char *name);
bool AcIsUser(HUB *h, char *name);
bool AcIsGroup(HUB *h, char *name);
bool AcDeleteUser(HUB *h, char *name);
bool AcDeleteGroup(HUB *h, char *name);
void JoinUserToGroup(USER *u, USERGROUP *g);
void SetUserTraffic(USER *u, TRAFFIC *t);
void SetGroupTraffic(USERGROUP *g, TRAFFIC *t);
void SetUserAuthData(USER *u, UINT authtype, void *authdata);
void *NewPasswordAuthData(char *username, char *password);
void *NewPasswordAuthDataRaw(UCHAR *hashed_password, UCHAR *ntlm_secure_hash);
void *NewUserCertAuthData(X *x);
void *NewRootCertAuthData(X_SERIAL *serial, wchar_t *common_name);
void *NewNTAuthData(wchar_t *username);
void HashPassword(void *dst, char *username, char *password);
void GenerateNtPasswordHash(UCHAR *dst, char *password);
void SecurePassword(void *secure_password, void *password, void *random);
POLICY *GetDefaultPolicy();
POLICY *ClonePolicy(POLICY *policy);
void SetUserPolicy(USER *u, POLICY *policy);
void SetGroupPolicy(USERGROUP *g, POLICY *policy);
POLICY *GetGroupPolicy(USERGROUP *g);
bool IsUserName(char *name);
UINT CheckUserAuthData(UINT auth_type, void *auth_data);
void *CopyAuthData(void *authdata, UINT authtype);
UINT PolicyNum();
bool PolicyIsSupportedForCascade(UINT i);
UINT PolicyStrToId(char *name);
char *PolicyIdToStr(UINT i);
POLICY_ITEM *GetPolicyItem(UINT id);
UINT GetPolicyValue(POLICY *p, UINT id);
void SetPolicyValue(POLICY *p, UINT id, UINT value);
void GetPolicyValueRangeStr(wchar_t *str, UINT size, UINT id);
void FormatPolicyValue(wchar_t *str, UINT size, UINT id, UINT value);


struct RPC_CLIENT_GET_CONNECTION_STATUS {
	wchar_t AccountName[MAX_ACCOUNT_NAME_LEN + 1];
	bool Active;
	bool Connected;
	UINT SessionStatus;
	char ServerName[MAX_HOST_NAME_LEN + 1];
	UINT ServerPort;
	char ServerProductName[MAX_SIZE];
	UINT ServerProductVer;
	UINT ServerProductBuild;
	X *ServerX;
	X *ClientX;
	UINT64 StartTime;
	/* !!! Do not correct the spelling to keep the backward protocol compatibility !!!  */
	UINT64 FirstConnectionEstablisiedTime;
	UINT64 CurrentConnectionEstablishTime;
	UINT NumConnectionsEstablished;
	bool HalfConnection;
	bool QoS;
	UINT MaxTcpConnections;
	UINT NumTcpConnections;
	UINT NumTcpConnectionsUpload;
	UINT NumTcpConnectionsDownload;
	bool UseEncrypt;
	char CipherName[32];
	char ProtocolName[64];
	bool UseCompress;
	char UnderlayProtocol[64];
	char ProtocolDetails[256];
	bool IsUdpAccelerationEnabled;
	bool IsUsingUdpAcceleration;
	char SessionName[MAX_SESSION_NAME_LEN + 1];
	char ConnectionName[MAX_CONNECTION_NAME_LEN + 1];
	UCHAR SessionKey[SHA1_SIZE];
	POLICY Policy;
	UINT64 TotalSendSize;
	UINT64 TotalRecvSize;
	UINT64 TotalSendSizeReal;
	UINT64 TotalRecvSizeReal;
	TRAFFIC Traffic;
	bool IsBridgeMode;
	bool IsMonitorMode;
	UINT VLanId;
};

void CiGetSessionStatus(RPC_CLIENT_GET_CONNECTION_STATUS *st, SESSION *s);
CLIENT_OPTION *CiLoadClientOption(FOLDER *f);
CLIENT_AUTH *CiLoadClientAuth(FOLDER *f);
void CiWriteClientOption(FOLDER *f, CLIENT_OPTION *o);
void CiWriteClientAuth(FOLDER *f, CLIENT_AUTH *a);
void CiFreeClientGetConnectionStatus(RPC_CLIENT_GET_CONNECTION_STATUS *st);
void ClientAuthFree(CLIENT_AUTH *auth);
CLIENT_AUTH *ClientAuthClone(CLIENT_AUTH *a);
CLIENT_OPTION *ClientOptionClone(CLIENT_OPTION *o);

#endif
