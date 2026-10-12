// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// Account.h
// Header of Account.c

#ifndef	ACCOUNT_H
#define	ACCOUNT_H

#include "CedarType.h"
#include "Session.h"

#include "Mayaqua/Encrypt.h"

// Policy item
struct POLICY_ITEM
{
	UINT Index;
	bool TypeInt;
	bool AllowZero;
	UINT MinValue;
	UINT MaxValue;
	UINT DefaultValue;
	char *FormatStr;
	UINT Offset;
};

// Policy
struct POLICY
{
	// For Ver 2.0
	bool Access;					// Grant access
	bool DHCPFilter;				// Filter DHCP packets (IPv4)
	bool DHCPNoServer;				// Prohibit the behavior of the DHCP server (IPv4)
	bool DHCPForce;					// Force DHCP-assigned IP address (IPv4)
	bool NoBridge;					// Prohibit the bridge behavior
	bool NoRouting;					// Prohibit the router behavior (IPv4)
	bool CheckMac;					// Prohibit the duplicate MAC address
	bool CheckIP;					// Prohibit a duplicate IP address (IPv4)
	bool ArpDhcpOnly;				// Prohibit the broadcast other than ARP, DHCP, ICMPv6
	bool PrivacyFilter;				// Privacy filter mode
	bool NoServer;					// Prohibit to operate as a TCP/IP server (IPv4)
	bool NoBroadcastLimiter;		// Not to limit the number of broadcast
	bool MonitorPort;				// Allow monitoring mode
	UINT MaxConnection;				// Maximum number of TCP connections
	UINT TimeOut;					// Communication time-out period
	UINT MaxMac;					// Maximum number of MAC address
	UINT MaxIP;						// Maximum number of IP address (IPv4)
	UINT MaxUpload;					// Upload bandwidth
	UINT MaxDownload;				// Download bandwidth
	bool FixPassword;				// User can not change password
	UINT MultiLogins;				// Multiple logins limit
	bool NoQoS;						// Prohibit the use of VoIP / QoS features

	// For Ver 3.0
	bool RSandRAFilter;				// Filter the Router Solicitation / Advertising packet (IPv6)
	bool RAFilter;					// Filter the router advertisement packet (IPv6)
	bool DHCPv6Filter;				// Filter DHCP packets (IPv6)
	bool DHCPv6NoServer;			// Prohibit the behavior of the DHCP server (IPv6)
	bool NoRoutingV6;				// Prohibit the router behavior (IPv6)
	bool CheckIPv6;					// Prohibit the duplicate IP address (IPv6)
	bool NoServerV6;				// Prohibit to operate as a TCP/IP server (IPv6)
	UINT MaxIPv6;					// Maximum number of IP address (IPv6)
	bool NoSavePassword;			// Prohibit to save the password in the VPN Client
	UINT AutoDisconnect;			// Disconnect the VPN Client automatically at a certain period of time
	bool FilterIPv4;				// Filter all IPv4 packets
	bool FilterIPv6;				// Filter all IPv6 packets
	bool FilterNonIP;				// Filter all non-IP packets
	bool NoIPv6DefaultRouterInRA;	// Delete the default router specification from the IPv6 router advertisement
	bool NoIPv6DefaultRouterInRAWhenIPv6;	// Delete the default router specification from the IPv6 router advertisement (Enable IPv6 connection)
	UINT VLanId;					// Specify the VLAN ID

	bool Ver3;						// Whether version 3.0
};

// Group
struct USERGROUP
{
	LOCK *lock;						// Lock
	REF *ref;						// Reference counter
	char *Name;						// Group name
	wchar_t *RealName;				// Display name
	wchar_t *Note;					// Note
	POLICY *Policy;					// Policy
	TRAFFIC *Traffic;				// Traffic data
};

// User
struct USER
{
	LOCK *lock;						// Lock
	REF *ref;						// Reference counter
	char *Name;						// User name
	wchar_t *RealName;				// Real name
	wchar_t *Note;					// Note
	char *GroupName;				// Group name
	USERGROUP *Group;				// Group
	UINT AuthType;					// Authentication type
	void *AuthData;					// Authentication data
	UINT64 CreatedTime;				// Creation date and time
	UINT64 UpdatedTime;				// Updating date
	UINT64 ExpireTime;				// Expiration date
	UINT64 LastLoginTime;			// Last login time
	UINT NumLogin;					// Total number of logins
	POLICY *Policy;					// Policy
	TRAFFIC *Traffic;				// Traffic data
};

// Password authentication data
struct AUTHPASSWORD
{
	UCHAR HashedKey[SHA1_SIZE];		// Hashed passwords
	UCHAR NtLmSecureHash[MD5_SIZE];	// Encrypted password for the NTLM
};

// User certificate authentication data
struct AUTHUSERCERT
{
	X *UserX;						// X509 certificate for the user
};

// Root certification authority authentication data
struct AUTHROOTCERT
{
	X_SERIAL *Serial;				// Serial number
	wchar_t *CommonName;			// CommonName
};

// Windows NT authentication data
struct AUTHNT
{
	wchar_t *NtUsername;			// User name on NT
};



// Macro
#define	POLICY_CURRENT_VERSION		3
#define	NUM_POLICY_ITEM_FOR_VER2	22
#define	NUM_POLICY_ITEM_FOR_VER3	38
#define	NUM_POLICY_ITEM				NUM_POLICY_ITEM_FOR_VER3

#define	IS_POLICY_FOR_VER2(index)	(((index) >= 0) && ((index) < NUM_POLICY_ITEM_FOR_VER2))
#define	IS_POLICY_FOR_VER3(index)	(((index) >= 0) && ((index) < NUM_POLICY_ITEM_FOR_VER3))

#define	IS_POLICY_FOR_CURRENT_VER(index, ver)	((ver) >= 3 ? IS_POLICY_FOR_VER3(index) : IS_POLICY_FOR_VER2(index))

#define	POLICY_BOOL(p, i)	(*(bool *)((char *)p + policy_item[i].Offset))
#define	POLICY_INT(p, i)	(*(UINT *)((char *)p + policy_item[i].Offset))

extern POLICY_ITEM policy_item[];




// Function prototype
int CompareUserName(void *p1, void *p2);
int CompareGroupName(void *p1, void *p2);
void AcLock(HUB *h);
void AcUnlock(HUB *h);
USERGROUP *NewGroup(char *name, wchar_t *realname, wchar_t *note);
void ReleaseGroup(USERGROUP *g);
void CleanupGroup(USERGROUP *g);
USER *NewUser(char *name, wchar_t *realname, wchar_t *note, UINT authtype, void *authdata);
void ReleaseUser(USER *u);
void CleanupUser(USER *u);
void FreeAuthData(UINT authtype, void *authdata);
bool AcAddUser(HUB *h, USER *u);
bool AcAddGroup(HUB *h, USERGROUP *g);
USER *AcGetUser(HUB *h, char *name);
USER* AcGetUserByCert(HUB* h, X *cert);
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
POLICY *GetDefaultPolicy();
POLICY *ClonePolicy(POLICY *policy);
void SetUserPolicy(USER *u, POLICY *policy);
void OverwritePolicy(POLICY **target, POLICY *p);
void SetGroupPolicy(USERGROUP *g, POLICY *policy);
POLICY *GetGroupPolicy(USERGROUP *g);
wchar_t *GetPolicyTitle(UINT id);
wchar_t *GetPolicyDescription(UINT id);
bool IsUserName(char *name);
void *CopyAuthData(void *authdata, UINT authtype);
UINT PolicyNum();
bool PolicyIsSupportedForCascade(UINT i);
UINT PolicyStrToId(char *name);
char *PolicyIdToStr(UINT i);
POLICY_ITEM *GetPolicyItem(UINT id);
void GetPolicyValueRangeStr(wchar_t *str, UINT size, UINT id);
void FormatPolicyValue(wchar_t *str, UINT size, UINT id, UINT value);

// ----------------------------------------------------------------------
// Client-side account data (cascade connections)
// ----------------------------------------------------------------------

// Account
struct ACCOUNT
{
	// Static data
	CLIENT_OPTION *ClientOption;			// Client Option
	CLIENT_AUTH *ClientAuth;				// Client authentication data
	bool CheckServerCert;					// Check the server certificate
	bool RetryOnServerCert;					// Retry on invalid server certificate
	bool AddDefaultCA;						// Use default trust store
	X *ServerCert;							// Server certificate
	bool StartupAccount;					// Start-up account
	UCHAR ShortcutKey[SHA1_SIZE];			// Key
	UINT64 CreateDateTime;					// Creation date and time
	UINT64 UpdateDateTime;					// Updating date
	UINT64 LastConnectDateTime;				// Last connection date and time

	// Dynamic data
	LOCK *lock;								// Lock
	SESSION *ClientSession;					// Client session
	CLIENT_STATUS_PRINTER *StatusPrinter;	// Status indicator
};

// Get the Connection status
struct RPC_CLIENT_GET_CONNECTION_STATUS
{
	wchar_t AccountName[MAX_ACCOUNT_NAME_LEN + 1];	// Account name
	bool Active;							// Operation flag
	bool Connected;							// Connected flag
	UINT SessionStatus;						// Session status
	char ServerName[MAX_HOST_NAME_LEN + 1];	// Server name
	UINT ServerPort;						// Port number of the server
	char ServerProductName[MAX_SIZE];		// Server product name
	UINT ServerProductVer;					// Server product version
	UINT ServerProductBuild;				// Server product build number
	X *ServerX;								// Server certificate
	X *ClientX;								// Client certificate
	UINT64 StartTime;						// Connection start time
	/* !!! Do not correct the spelling to keep the backward protocol compatibility !!!  */
	UINT64 FirstConnectionEstablisiedTime;	// Connection completion time of the first connection
	UINT64 CurrentConnectionEstablishTime;	// Connection completion time of this connection
	UINT NumConnectionsEstablished;			// Number of connections have been established so far
	bool HalfConnection;					// Half-connection
	bool QoS;								// VoIP / QoS
	UINT MaxTcpConnections;					// Maximum number of the TCP connections
	UINT NumTcpConnections;					// Number of current TCP connections
	UINT NumTcpConnectionsUpload;			// Number of inbound connections
	UINT NumTcpConnectionsDownload;			// Number of outbound connections
	bool UseEncrypt;						// Use of encryption
	char CipherName[32];					// Cipher algorithm name
	char ProtocolName[64];					// Protocol name
	bool UseCompress;						// Use of compression
	char UnderlayProtocol[64];				// Physical communication protocol
	char ProtocolDetails[256];				// Protocol details
	bool IsUdpAccelerationEnabled;			// The UDP acceleration is enabled
	bool IsUsingUdpAcceleration;			// Using the UDP acceleration function
	char SessionName[MAX_SESSION_NAME_LEN + 1];	// Session name
	char ConnectionName[MAX_CONNECTION_NAME_LEN + 1];	// Connection name
	UCHAR SessionKey[SHA1_SIZE];			// Session key
	POLICY Policy;							// Policy
	UINT64 TotalSendSize;					// Total transmitted data size
	UINT64 TotalRecvSize;					// Total received data size
	UINT64 TotalSendSizeReal;				// Total transmitted data size (no compression)
	UINT64 TotalRecvSizeReal;				// Total received data size (no compression)
	TRAFFIC Traffic;						// Traffic data
	bool IsBridgeMode;						// Bridge Mode
	bool IsMonitorMode;						// Monitor mode
	UINT VLanId;							// VLAN ID
};

void CiGetSessionStatus(RPC_CLIENT_GET_CONNECTION_STATUS *st, SESSION *s);
CLIENT_OPTION *CiLoadClientOption(FOLDER *f);
CLIENT_AUTH *CiLoadClientAuth(FOLDER *f);
void CiWriteClientOption(FOLDER *f, CLIENT_OPTION *o);
void CiWriteClientAuth(FOLDER *f, CLIENT_AUTH *a);
void CiFreeClientGetConnectionStatus(RPC_CLIENT_GET_CONNECTION_STATUS *st);
void CiFreeClientAuth(CLIENT_AUTH *auth);
BUF *EncryptPassword(char *password);
char *DecryptPassword(BUF *b);
void InRpcClientOption(CLIENT_OPTION *c, PACK *p);
void OutRpcClientOption(PACK *p, CLIENT_OPTION *c);
void InRpcClientAuth(CLIENT_AUTH *c, PACK *p);
void OutRpcClientAuth(PACK *p, CLIENT_AUTH *c);
void InRpcPolicy(POLICY *o, PACK *p);
void OutRpcPolicy(PACK *p, POLICY *o);
void InRpcClientGetConnectionStatus(RPC_CLIENT_GET_CONNECTION_STATUS *s, PACK *p);
void OutRpcClientGetConnectionStatus(PACK *p, RPC_CLIENT_GET_CONNECTION_STATUS *c);
void InRpcTraffic(TRAFFIC *t, PACK *p);
void OutRpcTraffic(PACK *p, TRAFFIC *t);
void InRpcTrafficEx(TRAFFIC *t, PACK *p, UINT i);
void OutRpcTrafficEx(TRAFFIC *t, PACK *p, UINT i, UINT num);

#endif	// ACCOUNT_H
