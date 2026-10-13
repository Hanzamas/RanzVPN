// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// Admin.h
// Header of Admin.c

#ifndef	ADMIN_H
#define	ADMIN_H

#include "Account.h"
#include "Cedar.h"
#include "Hub.h"
#include "Logging.h"
#include "Wpc.h"

#include "Mayaqua/Kernel.h"

// Windows version
struct RPC_WINVER
{
	bool IsWindows;
	bool IsNT;
	bool IsServer;
	bool IsBeta;
	UINT VerMajor;
	UINT VerMinor;
	UINT Build;
	UINT ServicePack;
	char Title[128];
};

// Server-side structure
struct ADMIN
{
	SERVER *Server;				// Server
	bool ServerAdmin;			// Server Administrator
	char *HubName;				// HUB name that can be managed
	RPC *Rpc;					// RPC
	LIST *LogFileList;			// Accessible log file list
	UINT ClientBuild;			// Build number of the client
	RPC_WINVER ClientWinVer;	// Windows version of client
	char dummy1[MAX_HUBNAME_LEN + 1];	// hubname buffer (dummy)
};

// Test
struct RPC_TEST
{
	UINT IntValue;
	UINT64 Int64Value;
	char StrValue[1024];
	wchar_t UniStrValue[1024];
};

// Server Information *
struct RPC_SERVER_INFO
{
	char ServerProductName[128];		// Server product name
	char ServerVersionString[128];		// Server version string
	char ServerBuildInfoString[128];	// Server build information string
	UINT ServerVerInt;					// Server version integer value
	UINT ServerBuildInt;				// Server build number integer value
	char ServerHostName[MAX_HOST_NAME_LEN + 1];	// Server host name
	UINT64 ServerBuildDate;				// Build date and time of the server
	OS_INFO OsInfo;						// OS information
};

// Server status
struct RPC_SERVER_STATUS
{
	UINT NumTcpConnections;				// Total number of TCP connections
	UINT NumTcpConnectionsLocal;		// Number of Local TCP connections
	UINT NumHubTotal;					// Total number of HUBs
	UINT NumHubStandalone;				// Number of stand-alone HUB
	UINT NumSessionsTotal;				// Total number of sessions
	UINT NumSessionsLocal;				// Number of Local sessions (only controller)
	UINT NumMacTables;					// Number of MAC table entries
	UINT NumIpTables;					// Number of IP table entries
	UINT NumUsers;						// Number of users
	UINT NumGroups;						// Number of groups
	UINT AssignedBridgeLicenses;		// Number of assigned bridge licenses
	UINT AssignedClientLicenses;		// Number of assigned client licenses
	UINT AssignedBridgeLicensesTotal;	// Number of Assigned bridge license (cluster-wide)
	UINT AssignedClientLicensesTotal;	// Number of assigned client licenses (cluster-wide)
	TRAFFIC Traffic;					// Traffic information
	UINT64 CurrentTime;					// Current time
	UINT64 CurrentTick;					// Current tick
	UINT64 StartTime;					// Start-up time
	MEMINFO MemInfo;					// Memory information
};

// Listener
struct RPC_LISTENER
{
	UINT Port;							// Port number
	bool Enable;						// Active state
};

// List of listeners *
struct RPC_LISTENER_LIST
{
	UINT NumPort;						// Number of ports
	UINT *Ports;						// Port List
	bool *Enables;						// Effective state
	bool *Errors;						// An error occurred
};

// String *
struct RPC_STR
{
	char *String;						// String
};

// Integer
struct RPC_INT
{
	UINT IntValue;						// Integer
};

// Set Password
struct RPC_SET_PASSWORD
{
	UCHAR HashedPassword[SHA1_SIZE];	// Hashed password (for traditional RPC)
	char PlainTextPassword[MAX_SIZE];	// Plaintext password (for JSON-RPC)
};

// Key pair
struct RPC_KEY_PAIR
{
	X *Cert;							// Certificate
	LIST *Chain;						// Trust chain
	K *Key;								// Secret key
	UINT Flag1;							// Flag1
};

// HUB option
struct RPC_HUB_OPTION
{
	UINT MaxSession;					// Maximum number of sessions
	bool NoEnum;						// Not listed
};

// Specify the HUB
struct RPC_HUB
{
	char HubName[MAX_HUBNAME_LEN + 1];	// HUB Name
};

// Create a HUB
struct RPC_CREATE_HUB
{
	char HubName[MAX_HUBNAME_LEN + 1];	// HUB Name
	UCHAR HashedPassword[SHA1_SIZE];	// Administrative password
	UCHAR SecurePassword[SHA1_SIZE];	// Administrator password
	char AdminPasswordPlainText[MAX_SIZE];	// Password (plaintext)
	bool Online;						// Online flag
	RPC_HUB_OPTION HubOption;			// HUB options
};

// Enumeration items of HUB
struct RPC_ENUM_HUB_ITEM
{
	char HubName[MAX_HUBNAME_LEN + 1];	// HUB Name
	bool Online;						// Online
	UINT NumUsers;						// Number of users
	UINT NumGroups;						// Number of groups
	UINT NumSessions;					// Number of sessions
	UINT NumMacTables;					// Number of MAC table entries
	UINT NumIpTables;					// Number of IP table entries
	UINT64 LastCommTime;				// Last communication date and time
	UINT64 LastLoginTime;				// Last login date and time
	UINT64 CreatedTime;					// Creation date and time
	UINT NumLogin;						// Number of logins
	bool IsTrafficFilled;				// Whether the traffic information exists
	TRAFFIC Traffic;					// Traffic
};

// Enumeration of HUB
struct RPC_ENUM_HUB
{
	UINT NumHub;						// Number of HUBs
	RPC_ENUM_HUB_ITEM *Hubs;			// HUB
};

// Delete the HUB
struct RPC_DELETE_HUB
{
	char HubName[MAX_HUBNAME_LEN + 1];	// HUB Name
};

// Connection enumeration items
struct RPC_ENUM_CONNECTION_ITEM
{
	char Name[MAX_SIZE];				// Connection name
	char Hostname[MAX_SIZE];			// Host name
	UINT Ip;							// IP address
	UINT Port;							// Port number
	UINT64 ConnectedTime;				// Connected time
	UINT Type;							// Type
};

// Connection enumeration
struct RPC_ENUM_CONNECTION
{
	UINT NumConnection;					// Number of connections
	RPC_ENUM_CONNECTION_ITEM *Connections;	// Connection list
};

// Disconnection
struct RPC_DISCONNECT_CONNECTION
{
	char Name[MAX_SIZE];				// Connection name
};

// Connection information
struct RPC_CONNECTION_INFO
{
	char Name[MAX_SIZE];				// Connection name
	UINT Type;							// Type
	char Hostname[MAX_SIZE];			// Host name
	UINT Ip;							// IP address
	UINT Port;							// Port number
	UINT64 ConnectedTime;				// Connected time
	char ServerStr[MAX_SERVER_STR_LEN + 1];	// Server string
	UINT ServerVer;						// Server version
	UINT ServerBuild;					// Server build number
	char ClientStr[MAX_CLIENT_STR_LEN + 1];	// Client string
	UINT ClientVer;						// Client version
	UINT ClientBuild;					// Client build number
};

// Online or offline the HUB
struct RPC_SET_HUB_ONLINE
{
	char HubName[MAX_HUBNAME_LEN + 1];	// HUB Name
	bool Online;						// Online / offline flag
};

// Get the state HUB
struct RPC_HUB_STATUS
{
	char HubName[MAX_HUBNAME_LEN + 1];	// HUB Name
	bool Online;						// Online
	UINT NumSessions;					// Number of sessions
	UINT NumSessionsClient;				// Number of sessions (client)
	UINT NumSessionsBridge;				// Number of sessions (bridge)
	UINT NumAccessLists;				// Number of Access list entries
	UINT NumUsers;						// Number of users
	UINT NumGroups;						// Number of groups
	UINT NumMacTables;					// Number of MAC table entries
	UINT NumIpTables;					// Number of IP table entries
	TRAFFIC Traffic;					// Traffic
	UINT64 LastCommTime;				// Last communication date and time
	UINT64 LastLoginTime;				// Last login date and time
	UINT64 CreatedTime;					// Creation date and time
	UINT NumLogin;						// Number of logins
};

// HUB log settings
struct RPC_HUB_LOG
{
	char HubName[MAX_HUBNAME_LEN + 1];	// HUB Name
	HUB_LOG LogSetting;					// Log Settings
};

// Add CA to HUB *
struct RPC_HUB_ADD_CA
{
	char HubName[MAX_HUBNAME_LEN + 1];	// HUB Name
	X *Cert;							// Certificate
};

// CA enumeration items of HUB
struct RPC_HUB_ENUM_CA_ITEM
{
	UINT Key;								// Certificate key
	wchar_t SubjectName[MAX_SIZE];			// Issued to
	wchar_t IssuerName[MAX_SIZE];			// Issuer
	UINT64 Expires;							// Expiration date
};

// CA enumeration of HUB *
struct RPC_HUB_ENUM_CA
{
	char HubName[MAX_HUBNAME_LEN + 1];	// HUB Name
	UINT NumCa;								// CA number
	RPC_HUB_ENUM_CA_ITEM *Ca;				// CA
};

// Get the CA of HUB *
struct RPC_HUB_GET_CA
{
	char HubName[MAX_HUBNAME_LEN + 1];	// HUB Name
	UINT Key;							// Certificate key
	X *Cert;							// Certificate
};

// Delete the CA of HUB
struct RPC_HUB_DELETE_CA
{
	char HubName[MAX_HUBNAME_LEN + 1];	// HUB Name
	UINT Key;							// Certificate key to be deleted
};

// Create and set of link *
struct RPC_CREATE_LINK
{
	char HubName[MAX_HUBNAME_LEN + 1];	// HUB Name
	bool Online;						// Online flag
	CLIENT_OPTION *ClientOption;		// Client Option
	CLIENT_AUTH *ClientAuth;			// Client authentication data
	POLICY Policy;						// Policy
	bool CheckServerCert;				// Validate the server certificate
	bool AddDefaultCA;					// Use default trust store
	X *ServerCert;						// Server certificate
};

// Enumeration items of link
struct RPC_ENUM_LINK_ITEM
{
	wchar_t AccountName[MAX_ACCOUNT_NAME_LEN + 1];	// Account name
	bool Online;									// Online flag
	bool Connected;									// Connection completion flag
	UINT LastError;									// The error that last occurred
	UINT64 ConnectedTime;							// Connection completion time
	char Hostname[MAX_HOST_NAME_LEN + 1];			// Host name
	char HubName[MAX_HUBNAME_LEN + 1];				// HUB Name
};

// Enumeration of the link *
struct RPC_ENUM_LINK
{
	char HubName[MAX_HUBNAME_LEN + 1];				// HUB Name
	UINT NumLink;									// Number of links
	RPC_ENUM_LINK_ITEM *Links;						// Link List
};

// Get the link state *
struct RPC_LINK_STATUS
{
	char HubName[MAX_HUBNAME_LEN + 1];				// HUB Name
	wchar_t AccountName[MAX_ACCOUNT_NAME_LEN + 1];	// Account name
	RPC_CLIENT_GET_CONNECTION_STATUS Status;		// Status
};

// Specify the Link
struct RPC_LINK
{
	char HubName[MAX_HUBNAME_LEN + 1];				// HUB Name
	wchar_t AccountName[MAX_ACCOUNT_NAME_LEN + 1];	// Account name
};

// Rename link
struct RPC_RENAME_LINK
{
	char HubName[MAX_HUBNAME_LEN + 1];				// HUB Name
	wchar_t OldAccountName[MAX_ACCOUNT_NAME_LEN + 1];	// Old account name
	wchar_t NewAccountName[MAX_ACCOUNT_NAME_LEN + 1];	// New account name
};

// Enumeration of the access list *
struct RPC_ENUM_ACCESS_LIST
{
	char HubName[MAX_HUBNAME_LEN + 1];				// HUB Name
	UINT NumAccess;									// Number of Access list entries
	ACCESS *Accesses;								// Access list
};

// Add to Access List
struct RPC_ADD_ACCESS
{
	char HubName[MAX_HUBNAME_LEN + 1];				// HUB Name
	ACCESS Access;									// Access list
};

// Delete the access list
struct RPC_DELETE_ACCESS
{
	char HubName[MAX_HUBNAME_LEN + 1];				// HUB Name
	UINT Id;										// ID
};

// Create, configure, and get the user *
struct RPC_SET_USER
{
	char HubName[MAX_HUBNAME_LEN + 1];				// HUB Name
	char Name[MAX_USERNAME_LEN + 1];				// User name
	char GroupName[MAX_USERNAME_LEN + 1];			// Group name
	wchar_t Realname[MAX_SIZE];						// Real name
	wchar_t Note[MAX_SIZE];							// Note
	UINT64 CreatedTime;								// Creation date and time
	UINT64 UpdatedTime;								// Updating date
	UINT64 ExpireTime;								// Expiration date
	UINT AuthType;									// Authentication method
	void *AuthData;									// Authentication data
	UINT NumLogin;									// Number of logins
	TRAFFIC Traffic;								// Traffic data
	POLICY *Policy;									// Policy
};

// Enumeration item of user
struct RPC_ENUM_USER_ITEM
{
	char Name[MAX_USERNAME_LEN + 1];				// User name
	char GroupName[MAX_USERNAME_LEN + 1];			// Group name
	wchar_t Realname[MAX_SIZE];						// Real name
	wchar_t Note[MAX_SIZE];							// Note
	UINT AuthType;									// Authentication method
	UINT NumLogin;									// Number of logins
	UINT64 LastLoginTime;							// Last login date and time
	bool DenyAccess;								// Access denied
	bool IsTrafficFilled;							// Flag of whether the traffic variable is set
	TRAFFIC Traffic;								// Traffic
	bool IsExpiresFilled;							// Flag of whether expiration date variable is set
	UINT64 Expires;									// Expiration date
};

// Enumeration of user
struct RPC_ENUM_USER
{
	char HubName[MAX_HUBNAME_LEN + 1];				// HUB Name
	UINT NumUser;									// Number of users
	RPC_ENUM_USER_ITEM *Users;						// User
};

// Create, configure, and get the group *
struct RPC_SET_GROUP
{
	char HubName[MAX_HUBNAME_LEN + 1];				// HUB Name
	char Name[MAX_USERNAME_LEN + 1];				// User name
	wchar_t Realname[MAX_SIZE];						// Real name
	wchar_t Note[MAX_SIZE];							// Note
	TRAFFIC Traffic;								// Traffic data
	POLICY *Policy;									// Policy
};

// Enumeration items in the group
struct RPC_ENUM_GROUP_ITEM
{
	char Name[MAX_USERNAME_LEN + 1];				// User name
	wchar_t Realname[MAX_SIZE];						// Real name
	wchar_t Note[MAX_SIZE];							// Note
	UINT NumUsers;									// Number of users
	bool DenyAccess;								// Access denied
};

// Group enumeration
struct RPC_ENUM_GROUP
{
	char HubName[MAX_HUBNAME_LEN + 1];				// HUB Name
	UINT NumGroup;									// Number of groups
	RPC_ENUM_GROUP_ITEM *Groups;					// Group
};

// Deleting a user or group
struct RPC_DELETE_USER
{
	char HubName[MAX_HUBNAME_LEN + 1];				// HUB Name
	char Name[MAX_USERNAME_LEN + 1];				// User or group name
};

// Enumeration items of session
struct RPC_ENUM_SESSION_ITEM
{
	char Name[MAX_SESSION_NAME_LEN + 1];			// Session name
	char Username[MAX_USERNAME_LEN + 1];			// User name
	UINT Ip;										// IP address (IPv4)
	IP ClientIP;									// IP address (IPv4 / IPv6)
	char Hostname[MAX_HOST_NAME_LEN	+ 1];			// Host name
	UINT MaxNumTcp;									// Maximum number of TCP connections
	UINT CurrentNumTcp;								// Number of currentl TCP connections
	UINT64 PacketSize;								// Packet size
	UINT64 PacketNum;								// Number of packets
	bool LinkMode;									// Link mode
	bool BridgeMode;								// Bridge mode
	bool Client_BridgeMode;							// Client is bridge mode
	bool Client_MonitorMode;						// Client is monitoring mode
	UINT VLanId;									// VLAN ID
	UCHAR UniqueId[16];								// Unique ID
	bool IsDormantEnabled;							// Is the dormant state enabled
	bool IsDormant;									// Is in the dormant state
	UINT64 LastCommDormant;							// Last comm interval in the dormant state
	UINT64 CreatedTime;								// Creation date and time
	UINT64 LastCommTime;							// Last communication date and time
};

// Disconnect the session
struct RPC_DELETE_SESSION
{
	char HubName[MAX_HUBNAME_LEN + 1];				// HUB Name
	char Name[MAX_SESSION_NAME_LEN + 1];			// Session name
};

// Enumeration items of the MAC table
struct RPC_ENUM_MAC_TABLE_ITEM
{
	UINT Key;										// Key
	char SessionName[MAX_SESSION_NAME_LEN + 1];		// Session name
	UCHAR MacAddress[6];							// MAC address
	UCHAR Padding[2];
	UINT64 CreatedTime;								// Creation date and time
	UINT64 UpdatedTime;								// Updating date
	UINT VlanId;									// VLAN ID
};

// Enumeration of the MAC table
struct RPC_ENUM_MAC_TABLE
{
	char HubName[MAX_HUBNAME_LEN + 1];				// HUB Name
	UINT NumMacTable;								// Number of tables
	RPC_ENUM_MAC_TABLE_ITEM *MacTables;				// MAC table
};

// Enumeration items of IP table
struct RPC_ENUM_IP_TABLE_ITEM
{
	UINT Key;										// Key
	char SessionName[MAX_SESSION_NAME_LEN + 1];		// Session name
	UINT Ip;										// IPv4 address
	IP IpV6;										// IPv6 address
	IP IpAddress;									// IPv4 / IPv6 Address
	bool DhcpAllocated;								// Assigned by the DHCP
	UINT64 CreatedTime;								// Creation date and time
	UINT64 UpdatedTime;								// Updating date
};

// Enumeration of IP table
struct RPC_ENUM_IP_TABLE
{
	char HubName[MAX_HUBNAME_LEN + 1];				// HUB Name
	UINT NumIpTable;								// Number of tables
	RPC_ENUM_IP_TABLE_ITEM *IpTables;				// MAC table
};

// Delete the table
struct RPC_DELETE_TABLE
{
	char HubName[MAX_HUBNAME_LEN + 1];				// HUB Name
	UINT Key;										// Key
};

// Ethernet enumeration item
struct RPC_ENUM_ETH_ITEM
{
	char DeviceName[MAX_SIZE];				// Device name
	wchar_t NetworkConnectionName[MAX_SIZE];// Network connection name
};

// Ethernet enumeration
struct RPC_ENUM_ETH
{
	UINT NumItem;							// Number of items
	RPC_ENUM_ETH_ITEM *Items;				// Item
};

// Bridge item
struct RPC_LOCALBRIDGE
{
	char DeviceName[MAX_SIZE];				// Device name
	char HubName[MAX_HUBNAME_LEN + 1];		// HUB Name
	bool Online;							// Online flag
	bool Active;							// Running flag
	bool TapMode;							// Tap mode
};

// Bridge enumeration
struct RPC_ENUM_LOCALBRIDGE
{
	UINT NumItem;							// Number of items
	RPC_LOCALBRIDGE *Items;					// Item
};

// Bridge support information
struct RPC_BRIDGE_SUPPORT
{
	bool IsBridgeSupportedOs;				// Whether the OS supports the bridge
};

// Config operation
struct RPC_CONFIG
{
	char FileName[MAX_PATH];				// File name
	char *FileData;							// File data
};

// Administration options list
struct RPC_ADMIN_OPTION
{
	char HubName[MAX_HUBNAME_LEN + 1];		// Virtual HUB name
	UINT NumItem;							// Count
	ADMIN_OPTION *Items;					// Data
};

// CRL entry
struct RPC_CRL
{
	char HubName[MAX_HUBNAME_LEN + 1];		// HUB Name
	UINT Key;								// Key
	CRL *Crl;								// CRL body
};

// CRL enumeration
struct RPC_ENUM_CRL_ITEM
{
	UINT Key;								// Key
	wchar_t CrlInfo[MAX_SIZE];				// Information
};
struct RPC_ENUM_CRL
{
	char HubName[MAX_HUBNAME_LEN + 1];		// HUB Name
	UINT NumItem;							// Number of items
	RPC_ENUM_CRL_ITEM *Items;				// List
};

// AC list
struct RPC_AC_LIST
{
	char HubName[MAX_HUBNAME_LEN + 1];		// HUB Name
	LIST *o;								// List body
	bool InternalFlag1;
};

// Log file enumeration
struct RPC_ENUM_LOG_FILE_ITEM
{
	char FilePath[MAX_PATH];				// File Path
	UINT FileSize;							// File size
	UINT64 UpdatedTime;						// Updating date
};
struct RPC_ENUM_LOG_FILE
{
	UINT NumItem;							// Number of items
	RPC_ENUM_LOG_FILE_ITEM *Items;			// List
};

// Read a Log file
struct RPC_READ_LOG_FILE
{
	char FilePath[MAX_PATH];				// File Path
	UINT Offset;							// Offset
	BUF *Buffer;							// Buffer
};

// Download information
struct DOWNLOAD_PROGRESS
{
	void *Param;							// User define data
	UINT TotalSize;							// The total file size
	UINT CurrentSize;						// Size which has loaded
	UINT ProgressPercent;					// Percent Complete
};

// Enumerate the license keys
struct RPC_ENUM_LICENSE_KEY_ITEM
{
	UINT Id;								// ID
	char LicenseKey[LICENSE_KEYSTR_LEN + 1];	// License key
	char LicenseId[LICENSE_LICENSEID_STR_LEN + 1];	// License ID
	char LicenseName[LICENSE_MAX_PRODUCT_NAME_LEN + 1];	// License name
	UINT64 Expires;							// Expiration date
	UINT Status;							// Situation
	UINT ProductId;							// Product ID
	UINT64 SystemId;						// System ID
	UINT SerialId;							// Serial ID
};
struct RPC_ENUM_LICENSE_KEY
{
	UINT NumItem;							// Number of items
	RPC_ENUM_LICENSE_KEY_ITEM *Items;		// List
};

// License status of the server
struct RPC_LICENSE_STATUS
{
	UINT EditionId;							// Edition ID
	char EditionStr[LICENSE_MAX_PRODUCT_NAME_LEN + 1];	// Edition name
	UINT64 SystemId;						// System ID
	UINT64 SystemExpires;					// System expiration date
	UINT NumClientConnectLicense;			// Maximum number of concurrent client connections
	UINT NumBridgeConnectLicense;			// Available number of concurrent bridge connections

	// v3.0
	bool NeedSubscription;					// Subscription system is enabled
	UINT64 SubscriptionExpires;				// Subscription expiration date
	bool IsSubscriptionExpired;				// Whether the subscription is expired
	UINT NumUserCreationLicense;			// Maximum number of users
	bool AllowEnterpriseFunction;			// Operation of the enterprise function
	UINT64 ReleaseDate;						// Release date
};

// Enumeration of VLAN support status of physical LAN card
struct RPC_ENUM_ETH_VLAN_ITEM
{
	char DeviceName[MAX_SIZE];				// Device name
	char Guid[MAX_SIZE];					// GUID
	char DeviceInstanceId[MAX_SIZE];		// Device Instance ID
	char DriverName[MAX_SIZE];				// Driver file name
	char DriverType[MAX_SIZE];				// Type of driver
	bool Support;							// Check whether it is supported
	bool Enabled;							// Whether it is enabled
};
struct RPC_ENUM_ETH_VLAN
{
	UINT NumItem;							// Number of items
	RPC_ENUM_ETH_VLAN_ITEM *Items;			// List
};

// Message
struct RPC_MSG
{
	char HubName[MAX_HUBNAME_LEN + 1];		// HUB Name
	wchar_t *Msg;							// Message
};


// Function prototype
UINT AdminAccept(CONNECTION *c, PACK *p);
RPC *AdminConnectEx(CEDAR *cedar, CLIENT_OPTION *o, char *hubname, void *hashed_password, UINT *err, char *client_name);
void AdminDisconnect(RPC *rpc);
UINT AdminReconnect(RPC *rpc);
CAPSLIST *ScGetCapsEx(RPC *rpc);
typedef bool (DOWNLOAD_PROC)(DOWNLOAD_PROGRESS *progress);
BUF *DownloadFileFromServer(RPC *r, char *filepath, UINT total_size, DOWNLOAD_PROC *proc, void *param);
void SiEnumSessionMain(SERVER *s, RPC_ENUM_SESSION *t);

UINT ScGetServerInfo(RPC *r, RPC_SERVER_INFO *t);
UINT ScGetServerStatus(RPC *r, RPC_SERVER_STATUS *t);
UINT ScCreateListener(RPC *r, RPC_LISTENER *t);
UINT ScEnumListener(RPC *r, RPC_LISTENER_LIST *t);
UINT ScDeleteListener(RPC *r, RPC_LISTENER *t);
UINT ScEnableListener(RPC *r, RPC_LISTENER *t);
UINT ScSetServerPassword(RPC *r, RPC_SET_PASSWORD *t);
UINT ScSetServerCert(RPC *r, RPC_KEY_PAIR *t);
UINT ScGetServerCert(RPC *r, RPC_KEY_PAIR *t);
UINT ScGetServerCipherList(RPC *r, RPC_STR *t);
UINT ScGetServerCipher(RPC *r, RPC_STR *t);
UINT ScSetServerCipher(RPC *r, RPC_STR *t);
UINT ScCreateHub(RPC *r, RPC_CREATE_HUB *t);
UINT ScSetHub(RPC *r, RPC_CREATE_HUB *t);
UINT ScGetHub(RPC *r, RPC_CREATE_HUB *t);
UINT ScEnumHub(RPC *r, RPC_ENUM_HUB *t);
UINT ScDeleteHub(RPC *r, RPC_DELETE_HUB *t);
UINT ScEnumConnection(RPC *r, RPC_ENUM_CONNECTION *t);
UINT ScDisconnectConnection(RPC *r, RPC_DISCONNECT_CONNECTION *t);
UINT ScGetConnectionInfo(RPC *r, RPC_CONNECTION_INFO *t);
UINT ScSetHubOnline(RPC *r, RPC_SET_HUB_ONLINE *t);
UINT ScGetHubStatus(RPC *r, RPC_HUB_STATUS *t);
UINT ScSetHubLog(RPC *r, RPC_HUB_LOG *t);
UINT ScGetHubLog(RPC *r, RPC_HUB_LOG *t);
UINT ScAddCa(RPC *r, RPC_HUB_ADD_CA *t);
UINT ScEnumCa(RPC *r, RPC_HUB_ENUM_CA *t);
UINT ScGetCa(RPC *r, RPC_HUB_GET_CA *t);
UINT ScDeleteCa(RPC *r, RPC_HUB_DELETE_CA *t);
UINT ScCreateLink(RPC *r, RPC_CREATE_LINK *t);
UINT ScEnumLink(RPC *r, RPC_ENUM_LINK *t);
UINT ScGetLinkStatus(RPC *r, RPC_LINK_STATUS *t);
UINT ScSetLinkOnline(RPC *r, RPC_LINK *t);
UINT ScSetLinkOffline(RPC *r, RPC_LINK *t);
UINT ScDeleteLink(RPC *r, RPC_LINK *t);
UINT ScRenameLink(RPC *r, RPC_RENAME_LINK *t);
UINT ScAddAccess(RPC *r, RPC_ADD_ACCESS *t);
UINT ScDeleteAccess(RPC *r, RPC_DELETE_ACCESS *t);
UINT ScEnumAccess(RPC *r, RPC_ENUM_ACCESS_LIST *t);
UINT ScCreateUser(RPC *r, RPC_SET_USER *t);
UINT ScSetUser(RPC *r, RPC_SET_USER *t);
UINT ScGetUser(RPC *r, RPC_SET_USER *t);
UINT ScDeleteUser(RPC *r, RPC_DELETE_USER *t);
UINT ScEnumUser(RPC *r, RPC_ENUM_USER *t);
UINT ScCreateGroup(RPC *r, RPC_SET_GROUP *t);
UINT ScSetGroup(RPC *r, RPC_SET_GROUP *t);
UINT ScGetGroup(RPC *r, RPC_SET_GROUP *t);
UINT ScDeleteGroup(RPC *r, RPC_DELETE_USER *t);
UINT ScEnumGroup(RPC *r, RPC_ENUM_GROUP *t);
UINT ScEnumSession(RPC *r, RPC_ENUM_SESSION *t);
UINT ScGetSessionStatus(RPC *r, RPC_SESSION_STATUS *t);
UINT ScDeleteSession(RPC *r, RPC_DELETE_SESSION *t);
UINT ScEnumMacTable(RPC *r, RPC_ENUM_MAC_TABLE *t);
UINT ScDeleteMacTable(RPC *r, RPC_DELETE_TABLE *t);
UINT ScEnumIpTable(RPC *r, RPC_ENUM_IP_TABLE *t);
UINT ScDeleteIpTable(RPC *r, RPC_DELETE_TABLE *t);
UINT ScGetLink(RPC *a, RPC_CREATE_LINK *t);
UINT ScSetLink(RPC *a, RPC_CREATE_LINK *t);
UINT ScSetAccessList(RPC *r, RPC_ENUM_ACCESS_LIST *t);
UINT ScEnumEthernet(RPC *r, RPC_ENUM_ETH *t);
UINT ScAddLocalBridge(RPC *r, RPC_LOCALBRIDGE *t);
UINT ScDeleteLocalBridge(RPC *r, RPC_LOCALBRIDGE *t);
UINT ScEnumLocalBridge(RPC *r, RPC_ENUM_LOCALBRIDGE *t);
UINT ScRebootServer(RPC *r, RPC_TEST *t);
UINT ScGetConfig(RPC *r, RPC_CONFIG *t);
UINT ScSetConfig(RPC *r, RPC_CONFIG *t);
UINT ScGetHubAdminOptions(RPC *r, RPC_ADMIN_OPTION *t);
UINT ScSetHubAdminOptions(RPC *r, RPC_ADMIN_OPTION *t);
UINT ScGetHubExtOptions(RPC *r, RPC_ADMIN_OPTION *t);
UINT ScSetHubExtOptions(RPC *r, RPC_ADMIN_OPTION *t);
UINT ScEnumCrl(RPC *r, RPC_ENUM_CRL *t);
UINT ScAddCrl(RPC *r, RPC_CRL *t);
UINT ScDelCrl(RPC *r, RPC_CRL *t);
UINT ScGetCrl(RPC *r, RPC_CRL *t);
UINT ScSetAcList(RPC *r, RPC_AC_LIST *t);
UINT ScGetAcList(RPC *r, RPC_AC_LIST *t);
UINT ScEnumLogFile(RPC *r, RPC_ENUM_LOG_FILE *t);
UINT ScAddLicenseKey(RPC *r, RPC_TEST *t);
UINT ScDelLicenseKey(RPC *r, RPC_TEST *t);
UINT ScEnumLicenseKey(RPC *r, RPC_ENUM_LICENSE_KEY *t);
UINT ScGetLicenseStatus(RPC *r, RPC_LICENSE_STATUS *t);
UINT ScSetSysLog(RPC *r, SYSLOG_SETTING *t);
UINT ScGetSysLog(RPC *r, SYSLOG_SETTING *t);
UINT ScCrash(RPC *r, RPC_TEST *t);
UINT ScFlush(RPC *r, RPC_TEST *t);
UINT ScDebug(RPC *r, RPC_TEST *t);
UINT ScRegenerateServerCert(RPC *r, RPC_TEST *t);

void FreeRpcTest(RPC_TEST *t);
void FreeRpcServerInfo(RPC_SERVER_INFO *t);
void FreeRpcListenerList(RPC_LISTENER_LIST *t);
void FreeRpcStr(RPC_STR *t);
void FreeRpcEnumHub(RPC_ENUM_HUB *t);
void FreeRpcEnumConnection(RPC_ENUM_CONNECTION *t);
void FreeRpcHubAddCa(RPC_HUB_ADD_CA *t);
void FreeRpcHubEnumCa(RPC_HUB_ENUM_CA *t);
void FreeRpcHubGetCa(RPC_HUB_GET_CA *t);
void FreeRpcCreateLink(RPC_CREATE_LINK *t);
void FreeRpcEnumLink(RPC_ENUM_LINK *t);
void FreeRpcLinkStatus(RPC_LINK_STATUS *t);
void FreeRpcEnumAccessList(RPC_ENUM_ACCESS_LIST *a);
void FreeRpcSetUser(RPC_SET_USER *t);
void FreeRpcEnumUser(RPC_ENUM_USER *t);
void FreeRpcEnumGroup(RPC_ENUM_GROUP *t);
void InRpcEnumSession(RPC_ENUM_SESSION *t, PACK *p);
void OutRpcEnumSession(PACK *p, RPC_ENUM_SESSION *t);
void FreeRpcEnumSession(RPC_ENUM_SESSION *t);
void InRpcNodeInfo(NODE_INFO *t, PACK *p);
void OutRpcNodeInfo(PACK *p, NODE_INFO *t);
void FreeRpcSessionStatus(RPC_SESSION_STATUS *t);
void FreeRpcEnumMacTable(RPC_ENUM_MAC_TABLE *t);
void FreeRpcEnumIpTable(RPC_ENUM_IP_TABLE *t);
void FreeRpcKeyPair(RPC_KEY_PAIR *t);
void FreeRpcSetGroup(RPC_SET_GROUP *t);
void FreeRpcEnumEth(RPC_ENUM_ETH *t);
void FreeRpcEnumLocalBridge(RPC_ENUM_LOCALBRIDGE *t);
void FreeRpcConfig(RPC_CONFIG *t);
void FreeRpcAdminOption(RPC_ADMIN_OPTION *t);
void FreeRpcCrl(RPC_CRL *t);
void FreeRpcEnumCrl(RPC_ENUM_CRL *t);
void FreeRpcAcList(RPC_AC_LIST *t);
void FreeRpcEnumLogFile(RPC_ENUM_LOG_FILE *t);
void FreeRpcEnumLicenseKey(RPC_ENUM_LICENSE_KEY *t);
void FreeRpcEnumEthVLan(RPC_ENUM_ETH_VLAN *t);
void InRpcWinVer(RPC_WINVER *t, PACK *p);
void OutRpcWinVer(PACK *p, RPC_WINVER *t);

#endif	// ADMIN_H


