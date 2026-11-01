// Connection.h
// Header of Connection.c

#ifndef CONNECTION_H
#define CONNECTION_H

#include "Cedar.h"

#include "Mayaqua/Encrypt.h"
#include "Mayaqua/Proxy.h"

#define UPDATE_LAST_COMM_TIME(v, n)  \
	{                                \
		if ((v) <= (n)) { v = (n); } \
	}

struct CLIENT_OPTION {
	wchar_t AccountName[MAX_ACCOUNT_NAME_LEN + 1];
	char Hostname[MAX_HOST_NAME_LEN + 1];
	UINT Port;
	UINT ProxyType;
	char ProxyName[MAX_HOST_NAME_LEN + 1];
	UINT ProxyPort;
	char ProxyUsername[PROXY_MAX_USERNAME_LEN + 1];
	char ProxyPassword[PROXY_MAX_PASSWORD_LEN + 1];
	UINT NumRetry;
	UINT RetryInterval;
	char HubName[MAX_HUBNAME_LEN + 1];
	UINT MaxConnection;
	bool UseEncrypt;
	bool UseCompress;
	bool HalfConnection;
	bool NoRoutingTracking;
	char DeviceName[MAX_DEVICE_NAME_LEN + 1];
	UINT AdditionalConnectionInterval;
	UINT ConnectionDisconnectSpan;
	bool RequireMonitorMode;
	bool RequireBridgeRoutingMode;
	bool DisableQoS;
	bool NoUdpAcceleration;
	char CustomHttpHeader[HTTP_CUSTOM_HEADER_MAX_SIZE];
	IP BindLocalIP;
	UINT BindLocalPort;
};

struct CLIENT_AUTH {
	UINT AuthType;
	char Username[MAX_USERNAME_LEN + 1];
	UCHAR HashedPassword[SHA1_SIZE];
	char PlainPassword[MAX_PASSWORD_LEN + 1];
	X *ClientX;
	K *ClientK;
};

struct TCPSOCK {
	SOCK *Sock;
	FIFO *RecvFifo;
	FIFO *SendFifo;
	UINT Mode;
	UINT WantSize;
	UINT NextBlockNum;
	UINT NextBlockSize;
	UINT CurrentPacketNum;
	UINT64 LastCommTime;
	UINT LateCount;
	UINT Direction;
	UINT64 NextKeepAliveTime;
	UINT64 DisconnectTick;
};

struct TCP {
	LIST *TcpSockList;
};

struct BLOCK {
	bool Compressed;
	UINT Size;
	UINT SizeofData;
	UCHAR *Buf;
	bool PriorityQoS;
	bool IsFlooding;
};

struct CONNECTION {
	LOCK *lock;
	REF *ref;
	CEDAR *Cedar;
	struct SESSION *Session;
	UINT Protocol;
	SOCK *FirstSock;
	TCP *Tcp;
	bool ServerMode;
	UINT Status;
	char *Name;
	THREAD *Thread;
	volatile bool Halt; // Only through FlagRead and FlagWrite (Native.h)
	UCHAR Random[SHA1_SIZE];
	UINT ServerVer;
	UINT ServerBuild;
	UINT ClientVer;
	UINT ClientBuild;
	char ServerStr[MAX_SERVER_STR_LEN + 1];
	char ClientStr[MAX_CLIENT_STR_LEN + 1];
	UINT Err;
	QUEUE *ReceivedBlocks;
	QUEUE *SendBlocks;
	QUEUE *SendBlocks2;
	COUNTER *CurrentNumConnection;
	LIST *ConnectingThreads;
	LIST *ConnectingSocks;
	bool flag1;
	UCHAR *RecvBuf;
	char ServerName[MAX_HOST_NAME_LEN + 1];
	UINT ServerPort;
	UINT CurrentSendQueueSize;
	X *ServerX;
	X *ClientX;
	char *CipherName;
	char *SslVersion;
	UINT64 ConnectedTick;
	IP ClientIp;
	char ClientHostname[MAX_HOST_NAME_LEN + 1];
	UINT Type;
	UINT AdditionalConnectionFailedCounter;
	UINT64 LastCounterResetTick;
	UINT LastTcpQueueSize;
	UINT LastPacketQueueSize;
	UINT LastRecvFifoTotalSize;
	UINT LastRecvBlocksNum;
	TUNNEL *Tunnel; // CONNECTION_NOISE: the Tunnel that the connection carries (ConnectionTunnel.c)
};

// What the admin RPCs report about one connection, copied by ConnectionGetInfo under the connection's lock
struct CONNECTION_INFO {
	char Name[MAX_SIZE];
	UINT Type;
	UINT64 ConnectedTick;
	IP RemoteIp; // The remote end of the first socket; zero without one
	UINT RemotePort;
	char RemoteHostname[MAX_SIZE];
	char ServerStr[MAX_SERVER_STR_LEN + 1];
	UINT ServerVer;
	UINT ServerBuild;
	char ClientStr[MAX_CLIENT_STR_LEN + 1];
	UINT ClientVer;
	UINT ClientBuild;
};

// The Tunnel of a Connection of type CONNECTION_NOISE (ConnectionTunnel.c; CORE-S1-2, #68): the Noise sessions
// of the new core between one client node and the server role, whose data records carry the Ethernet frames of the
// Connection's Session. The type of a Noise session is in Core/Transport.h.
#define TUNNEL_MAX_CONNECTIONS 16 // The connections of a Tunnel at most: NOISE_TUNNEL_MAX_CONNECTIONS of Core/Noise.h

struct TRANSPORT_NOISE;

// What TunnelGetStatus reports about the Tunnel of a Connection
struct TUNNEL_STATUS {
	UINT NumConnections;                     // Its connections that are up
	UINT64 Received[TUNNEL_MAX_CONNECTIONS]; // The frames received on connection i
	UINT64 Sent[TUNNEL_MAX_CONNECTIONS];     // The frames sent on connection i
};


CONNECTION *NewClientConnectionEx(SESSION *s, char *client_str);
CONNECTION *NewServerConnection(CEDAR *cedar, SOCK *s, THREAD *t);
void GetServerProductName(SERVER *s, char *name, UINT size);
void ReleaseConnection(CONNECTION *c);
int CompareConnection(void *p1, void *p2);
void StopConnection(CONNECTION *c, bool no_wait);
UINT TlsErrToCedarErr(UINT tls_err);
void StartTunnelingMode(CONNECTION *c);
void EndTunnelingMode(CONNECTION *c);
void DisconnectTcpSockets(CONNECTION *c);
void ConnectionReceive(CONNECTION *c, CANCEL *c1, CANCEL *c2);
void ConnectionSend(CONNECTION *c, UINT64 now);
TCPSOCK *NewTcpSock(SOCK *s);
void FreeTcpSock(TCPSOCK *ts);
BLOCK *NewBlock(void *data, UINT size, int compress);
void FreeBlock(BLOCK *b);
void FreeBlockQueue(QUEUE *q);
void StopAllAdditionalConnectThread(CONNECTION *c);
UINT GenNextKeepAliveSpan(CONNECTION *c);
void InsertReceivedBlockToQueue(CONNECTION *c, BLOCK *block);
void ConnectionGetInfo(CONNECTION *c, CONNECTION_INFO *info);
bool TunnelStart(CONNECTION *c, struct TRANSPORT_NOISE *first);
bool TunnelJoin(CONNECTION *c, const UCHAR *id, struct TRANSPORT_NOISE *n);
void TunnelStop(CONNECTION *c);
void TunnelGetStatus(CONNECTION *c, TUNNEL_STATUS *st);


#endif
