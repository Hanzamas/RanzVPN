// Session.h
// Header of Session.c

#ifndef SESSION_H
#define SESSION_H

#include "Cedar.h"

// Interval to increment the number of logins after the connection
#define NUM_LOGIN_INCREMENT_INTERVAL (30 * 1000)

typedef bool(PA_INIT)(SESSION *s);
typedef CANCEL *(PA_GETCANCEL)(SESSION * s);
typedef UINT(PA_GETNEXTPACKET)(SESSION *s, void **data);
typedef bool(PA_PUTPACKET)(SESSION *s, void *data, UINT size);
typedef void(PA_FREE)(SESSION *s);

struct NODE_INFO {
	char ClientProductName[64];
	UINT ClientProductVer;
	UINT ClientProductBuild;
	char ServerProductName[64];
	UINT ServerProductVer;
	UINT ServerProductBuild;
	char ClientOsName[64];
	char ClientOsVer[128];
	char ClientOsProductId[64];
	char ClientHostname[64];
	UINT ClientIpAddress;
	UINT ClientPort;
	char ServerHostname[64];
	UINT ServerIpAddress;
	UINT ServerPort;
	char ProxyHostname[64];
	UINT ProxyIpAddress;
	UINT ProxyPort;
	char HubName[64];
	UCHAR UniqueId[16];
	UCHAR ClientIpAddress6[16];
	UCHAR ServerIpAddress6[16];
	UCHAR ProxyIpAddress6[16];
	char Padding[304 - (16 * 3)];
};

struct PACKET_ADAPTER {
	PA_INIT *Init;
	PA_GETCANCEL *GetCancel;
	PA_GETNEXTPACKET *GetNextPacket;
	PA_PUTPACKET *PutPacket;
	PA_FREE *Free;
	void *Param;
};

struct SESSION {
	LOCK *lock;
	REF *ref;
	CEDAR *Cedar;
	bool LocalHostSession;
	bool ServerMode;
	bool NormalClient;
	bool LinkModeClient;
	bool LinkModeServer;
	bool BridgeMode;
	THREAD *Thread;
	CONNECTION *Connection;
	char ClientIP[64];
	CLIENT_OPTION *ClientOption;
	CLIENT_AUTH *ClientAuth;
	SSL_VERIFY_OPTION *SslOption;
	volatile bool Halt;
	EVENT *HaltEvent;
	UINT Err;
	HUB *Hub;
	CANCEL *Cancel1;
	CANCEL *Cancel2;
	PACKET_ADAPTER *PacketAdapter;
	UINT ClientStatus;
	bool RetryFlag;
	bool ForceStopFlag;
	UINT CurrentRetryCount;
	UINT RetryInterval;
	bool ConnectSucceed;
	bool SessionTimeOuted;
	UINT Timeout;
	UINT64 NextConnectionTime;
	IP ServerIP;
	LOCK *TrafficLock;
	NODE_INFO NodeInfo;
	UINT64 LastIncrementTraffic;
	LIST *CancelList;
	bool IPv6Session;
	UINT VLanId;

	IP ServerIP_CacheForNextConnect;
	IP LocalIP_CacheForNextConnect;

	UINT64 CreatedTime;
	UINT64 LastCommTime;
	UINT64 LastCommTimeForDormant;
	TRAFFIC *Traffic;
	TRAFFIC *OldTraffic;
	UINT64 TotalSendSize;
	UINT64 TotalRecvSize;
	UINT64 TotalSendSizeReal;
	UINT64 TotalRecvSizeReal;
	char *Name;
	char *Username;
	char UserNameReal[MAX_USERNAME_LEN + 1];
	char GroupName[MAX_USERNAME_LEN + 1];
	POLICY *Policy;
	UCHAR SessionKey[SHA1_SIZE];
	UINT SessionKey32;
	UINT MaxConnection;
	bool UseEncrypt;
	bool UseCompress;
	bool HalfConnection;
	bool QoS;
	bool NoSendSignature;
	char UnderlayProtocol[64];
	char ProtocolDetails[256];
	/* !!! Do not correct the spelling to keep the backward protocol compatibility !!!  */
	UINT64 FirstConnectionEstablisiedTime;
	UINT64 CurrentConnectionEstablishTime;
	UINT NumConnectionsEstablished;
	UINT AdjustMss;

	bool UseUdpAcceleration;
	bool IsUsingUdpAcceleration;
	UINT UdpAccelMss;
	bool UdpAccelFastDisconnectDetect;

	UINT VLanDeviceErrorCount;
	bool UserCanceled;
	UINT64 LastTryAddConnectTime;

	bool IsMonitorMode;
	bool IsBridgeMode;

	COUNTER *LoggingRecordCount;

	wchar_t *Client_Message;

	LIST *DelayedPacketList;
	UINT Flag1;

	USER *NumLoginIncrementUserObject;
	HUB *NumLoginIncrementHubObject;
	UINT64 NumLoginIncrementTick;

	UINT64 MaxLoggedPacketsPerMinuteStartTick;
	UINT CurrentNumPackets;

	// Workaround for a D-Link STP bug
	UINT64 LastDLinkSTPPacketSendTick;
	UCHAR LastDLinkSTPPacketDataHash[MD5_SIZE];
};

SESSION *NewSessionBase(CEDAR *cedar, bool server_mode);
SESSION *NewServerSession(CEDAR *cedar, CONNECTION *c, HUB *h, char *username, POLICY *policy);
void ReleaseSession(SESSION *s);
void StopSession(SESSION *s);
void StopSessionEx(SESSION *s, bool no_wait);
PACKET_ADAPTER *NewPacketAdapter(PA_INIT *init, PA_GETCANCEL *getcancel, PA_GETNEXTPACKET *getnext,
                                 PA_PUTPACKET *put, PA_FREE *free);
void SessionMain(SESSION *s);
SESSION *GetSessionFromKey(CEDAR *cedar, UCHAR *session_key);
void AddTrafficForSession(SESSION *s, TRAFFIC *t);
void IncrementUserTraffic(HUB *hub, char *username, SESSION *s);
void ReleaseCancelList(LIST *o);
void AddCancelList(LIST *o, CANCEL *c);
void CancelList(LIST *o);
bool IsPriorityHighestPacketForQoS(void *data, UINT size);
UINT GetNextDelayedPacketTickDiff(SESSION *s);

#endif

