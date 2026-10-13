// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// Session.h
// Header of Session.c

#ifndef	SESSION_H
#define	SESSION_H

#include "Cedar.h"

// Interval to increment the number of logins after the connection
#define	NUM_LOGIN_INCREMENT_INTERVAL		(30 * 1000)

// Packet adapter function
typedef bool (PA_INIT)(SESSION *s);
typedef CANCEL *(PA_GETCANCEL)(SESSION *s);
typedef UINT (PA_GETNEXTPACKET)(SESSION *s, void **data);
typedef bool (PA_PUTPACKET)(SESSION *s, void *data, UINT size);
typedef void (PA_FREE)(SESSION *s);

// Client related function
typedef void (CLIENT_STATUS_PRINTER)(SESSION *s, wchar_t *status);

// Node information
struct NODE_INFO
{
	char ClientProductName[64];		// Client product name
	UINT ClientProductVer;			// Client version
	UINT ClientProductBuild;		// Client build number
	char ServerProductName[64];		// Server product name
	UINT ServerProductVer;			// Server version
	UINT ServerProductBuild;		// Server build number
	char ClientOsName[64];			// Client OS name
	char ClientOsVer[128];			// Client OS version
	char ClientOsProductId[64];		// Client OS Product ID
	char ClientHostname[64];		// Client host name
	UINT ClientIpAddress;			// Client IP address
	UINT ClientPort;				// Client port number
	char ServerHostname[64];		// Server host name
	UINT ServerIpAddress;			// Server IP address
	UINT ServerPort;				// Server port number
	char ProxyHostname[64];			// Proxy host name
	UINT ProxyIpAddress;			// Proxy Server IP Address
	UINT ProxyPort;					// Proxy port number
	char HubName[64];				// HUB name
	UCHAR UniqueId[16];				// Unique ID
	// The following is for IPv6 support
	UCHAR ClientIpAddress6[16];		// Client IPv6 address
	UCHAR ServerIpAddress6[16];		// Server IP address
	UCHAR ProxyIpAddress6[16];		// Proxy Server IP Address
	char Padding[304 - (16 * 3)];	// Padding
};

// Packet adapter
struct PACKET_ADAPTER
{
	PA_INIT *Init;
	PA_GETCANCEL *GetCancel;
	PA_GETNEXTPACKET *GetNextPacket;
	PA_PUTPACKET *PutPacket;
	PA_FREE *Free;
	void *Param;
	UINT Id;
};


// Session structure
struct SESSION
{
	LOCK *lock;						// Lock
	REF *ref;						// Reference counter
	CEDAR *Cedar;					// Cedar
	bool LocalHostSession;			// Local host session
	bool ServerMode;				// Server mode session
	bool NormalClient;				// Connecting session from a regular client (not such as localbridge)
	bool LinkModeClient;			// Link mode client
	bool LinkModeServer;			// Link mode server
	bool BridgeMode;				// Bridge session
	bool BridgeIsEthLoopbackBlock;	// Loopback is disabled on the Ethernet level
	THREAD *Thread;					// Management thread
	CONNECTION *Connection;			// Connection
	char ClientIP[64];				// Client IP
	CLIENT_OPTION *ClientOption;	// Client connection options
	CLIENT_AUTH *ClientAuth;		// Client authentication data
	SSL_VERIFY_OPTION *SslOption;	// SSL verification option
	volatile bool Halt;				// Halting flag
	volatile bool CancelConnect;	// Cancel the connection
	EVENT *HaltEvent;				// Halting event
	UINT Err;						// Error value
	HUB *Hub;						// HUB
	CANCEL *Cancel1;				// Cancel object 1
	CANCEL *Cancel2;				// Cancel object 2
	PACKET_ADAPTER *PacketAdapter;	// Packet adapter
	UCHAR UdpSendKey[16];			// UDP encryption key for transmission
	UCHAR UdpRecvKey[16];			// UDP encryption key for reception
	UINT ClientStatus;				// Client Status
	bool RetryFlag;					// Retry flag (client)
	bool ForceStopFlag;				// Forced stop flag (client)
	UINT CurrentRetryCount;			// Current retry counter (client)
	UINT RetryInterval;				// Retry interval (client)
	bool ConnectSucceed;			// Connection success flag (client)
	bool SessionTimeOuted;			// Session times out
	UINT Timeout;					// Time-out period
	UINT64 NextConnectionTime;		// Time to put next additional connection
	IP ServerIP;					// IP address of the server
	LOCK *TrafficLock;				// Traffic data lock
	LINK *Link;						// A reference to the link object
	BRIDGE *Bridge;					// A reference to the Bridge object
	NODE_INFO NodeInfo;				// Node information
	UINT64 LastIncrementTraffic;	// Last time that updated the traffic data of the user
	bool AdministratorMode;			// Administrator mode
	LIST *CancelList;				// Cancellation list
	bool IPv6Session;				// IPv6 session (Physical communication is IPv6)
	UINT VLanId;					// VLAN ID

	IP ServerIP_CacheForNextConnect;	// Server IP, cached for next connect
	IP LocalIP_CacheForNextConnect;		// Local  IP, cached for next connect (2nd and subsequent), assigned by first outgoing connection

	UINT64 CreatedTime;				// Creation date and time
	UINT64 LastCommTime;			// Last communication date and time
	UINT64 LastCommTimeForDormant;	// Last communication date and time (for dormant)
	TRAFFIC *Traffic;				// Traffic data
	TRAFFIC *OldTraffic;			// Old traffic data
	UINT64 TotalSendSize;			// Total transmitted data size
	UINT64 TotalRecvSize;			// Total received data size
	UINT64 TotalSendSizeReal;		// Total transmitted data size (no compression)
	UINT64 TotalRecvSizeReal;		// Total received data size (no compression)
	char *Name;						// Session name
	char *Username;					// User name
	char UserNameReal[MAX_USERNAME_LEN + 1];	// User name (real)
	char GroupName[MAX_USERNAME_LEN + 1];	// Group name
	POLICY *Policy;					// Policy
	UCHAR SessionKey[SHA1_SIZE];	// Session key
	UINT SessionKey32;				// 32bit session key
	char SessionKeyStr[64];			// Session key string
	UINT MaxConnection;				// Maximum number of concurrent TCP connections
	bool UseEncrypt;				// Use encrypted communication
	bool UseCompress;				// Use data compression
	bool HalfConnection;			// Half connection mode
	bool QoS;						// VoIP / QoS
	bool NoSendSignature;			// Do not send a signature
	UINT NumDisconnected;			// Number of socket disconnection
	bool NoReconnectToSession;		// Disable to reconnect to the session
	char UnderlayProtocol[64];		// Physical communication protocol
	char ProtocolDetails[256];		// Protocol details
	/* !!! Do not correct the spelling to keep the backward protocol compatibility !!!  */
	UINT64 FirstConnectionEstablisiedTime;	// Connection completion time of the first connection
	UINT64 CurrentConnectionEstablishTime;	// Completion time of this connection
	UINT NumConnectionsEstablished;	// Number of connections established so far
	UINT AdjustMss;					// MSS adjustment value

	bool UseUdpAcceleration;		// Use of UDP acceleration mode
	UINT UdpAccelerationVersion;	// UDP acceleration version
	bool UseHMacOnUdpAcceleration;	// Use the HMAC in the UDP acceleration mode
	UDP_ACCEL *UdpAccel;			// UDP acceleration
	bool IsUsingUdpAcceleration;	// Flag of whether the UDP acceleration is used
	UINT UdpAccelMss;				// MSS value to be applied while the UDP acceleration is used
	bool UdpAccelFastDisconnectDetect;	// Fast disconnection detection is enabled

	ACCOUNT *Account;				// Client account
	UINT VLanDeviceErrorCount;		// Number of times that the error occurred in the virtual LAN card
	bool UserCanceled;				// Canceled by the user
	UINT64 LastTryAddConnectTime;	// Last time that attempted to add a connection

	bool IsMonitorMode;				// Whether the monitor mode
	bool IsBridgeMode;				// Whether the bridge mode
	bool UseClientLicense;			// Number of assigned client licenses
	bool UseBridgeLicense;			// Number of assigned bridge licenses

	COUNTER *LoggingRecordCount;	// Counter for the number of logging records


	wchar_t *Client_Message;		// Message that has been sent from the server

	LIST *DelayedPacketList;		// Delayed packet list
	UINT Flag1;

	USER *NumLoginIncrementUserObject;	// User objects to increment the number of logins
	HUB *NumLoginIncrementHubObject;	// Virtual HUB object to increment the number of logins
	UINT64 NumLoginIncrementTick;		// Time to perform increment a number of log

	bool FirstTimeHttpRedirect;		// Redirect HTTP only for the first time
	char FirstTimeHttpRedirectUrl[128];	// URL for redirection only the first time
	UINT FirstTimeHttpAccessCheckIp;	// IP address for access checking

	// To examine the maximum number of allowed logging target packets per minute
	UINT64 MaxLoggedPacketsPerMinuteStartTick;	// Inspection start time
	UINT CurrentNumPackets;				// Current number of packets

	// Measures for D-Link bug
	UINT64 LastDLinkSTPPacketSendTick;	// Last D-Link STP packet transmission time
	UCHAR LastDLinkSTPPacketDataHash[MD5_SIZE];	// Last D-Link STP packet hash
};


// Function prototype
SESSION *NewClientSessionEx(CEDAR *cedar, CLIENT_OPTION *option, CLIENT_AUTH *auth, PACKET_ADAPTER *pa, struct ACCOUNT *account);
SESSION *NewClientSession(CEDAR *cedar, CLIENT_OPTION *option, CLIENT_AUTH *auth, PACKET_ADAPTER *pa);
SESSION *NewRpcSessionEx2(CEDAR *cedar, CLIENT_OPTION *option, UINT *err, char *client_str, void *hWnd);
SESSION *NewServerSession(CEDAR *cedar, CONNECTION *c, HUB *h, char *username, POLICY *policy);
void ClientThread(THREAD *t, void *param);
void ReleaseSession(SESSION *s);
void CleanupSession(SESSION *s);
void StopSession(SESSION *s);
void StopSessionEx(SESSION *s, bool no_wait);
bool SessionConnect(SESSION *s);
bool ClientConnect(CONNECTION *c);
PACKET_ADAPTER *NewPacketAdapter(PA_INIT *init, PA_GETCANCEL *getcancel, PA_GETNEXTPACKET *getnext,
								 PA_PUTPACKET *put, PA_FREE *free);
void FreePacketAdapter(PACKET_ADAPTER *pa);
void SessionMain(SESSION *s);
void NewSessionKey(CEDAR *cedar, UCHAR *session_key, UINT *session_key_32);
SESSION *GetSessionFromKey(CEDAR *cedar, UCHAR *session_key);
void ClientAdditionalConnectChance(SESSION *s);
void SessionAdditionalConnect(SESSION *s);
void ClientAdditionalThread(THREAD *t, void *param);
void PrintSessionTotalDataSize(SESSION *s);
void AddTrafficForSession(SESSION *s, TRAFFIC *t);
void IncrementUserTraffic(HUB *hub, char *username, SESSION *s);
void PrintStatus(SESSION *s, wchar_t *str);
void ReleaseCancelList(LIST *o);
void AddCancelList(LIST *o, CANCEL *c);
void CancelList(LIST *o);
bool IsPriorityHighestPacketForQoS(void *data, UINT size);
UINT GetNextDelayedPacketTickDiff(SESSION *s);

#endif	// SESSION_H



