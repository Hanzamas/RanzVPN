// Connection.h
// Header of Connection.c

#ifndef	CONNECTION_H
#define	CONNECTION_H

#include "Cedar.h"

#include "Mayaqua/Encrypt.h"
#include "Mayaqua/Proxy.h"

#define	UPDATE_LAST_COMM_TIME(v, n)		{if ((v) <= (n)) { v = (n); } }

struct CLIENT_OPTION
{
	wchar_t AccountName[MAX_ACCOUNT_NAME_LEN + 1];
	char Hostname[MAX_HOST_NAME_LEN + 1];
	UINT Port;
	UINT PortUDP;											// UDP port number (0: Use only TCP)
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
	bool HideStatusWindow;
	bool HideNicInfoWindow;
	bool RequireMonitorMode;
	bool RequireBridgeRoutingMode;
	bool DisableQoS;
	bool FromAdminPack;
	bool NoUdpAcceleration;
	UCHAR HostUniqueKey[SHA1_SIZE];
	char CustomHttpHeader[HTTP_CUSTOM_HEADER_MAX_SIZE];
	IP   BindLocalIP;
	UINT BindLocalPort;
};

struct CLIENT_AUTH
{
	UINT AuthType;
	char Username[MAX_USERNAME_LEN + 1];
	UCHAR HashedPassword[SHA1_SIZE];
	char PlainPassword[MAX_PASSWORD_LEN + 1];
	X *ClientX;
	K *ClientK;
	char OpensslEnginePrivateKeyName[MAX_SECURE_DEVICE_FILE_LEN + 1];
	char OpensslEngineName[MAX_SECURE_DEVICE_FILE_LEN + 1];
};

struct TCPSOCK
{
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

struct TCP
{
	LIST *TcpSockList;
};

struct BLOCK
{
	bool Compressed;
	UINT Size;
	UINT SizeofData;
	UCHAR *Buf;
	bool PriorityQoS;
	bool IsFlooding;
};

struct CONNECTION
{
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
	volatile bool Halt;					// Only through FlagRead and FlagWrite (Native.h)
	UCHAR Random[SHA1_SIZE];
	UINT ServerVer;
	UINT ServerBuild;
	UINT ClientVer;
	UINT ClientBuild;
	char ServerStr[MAX_SERVER_STR_LEN + 1];
	char ClientStr[MAX_CLIENT_STR_LEN + 1];
	UINT Err;
	bool ClientConnectError_NoSavePassword;
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
	bool RestoreServerNameAndPort;
	UINT CurrentSendQueueSize;
	X *ServerX;
	X *ClientX;
	char *CipherName;
	char *SslVersion;
	UINT64 ConnectedTick;
	IP ClientIp;
	char ClientHostname[MAX_HOST_NAME_LEN + 1];
	UINT Type;
	void *hWndForUI;
	UINT AdditionalConnectionFailedCounter;
	UINT64 LastCounterResetTick;
	UINT LastTcpQueueSize;
	UINT LastPacketQueueSize;
	UINT LastRecvFifoTotalSize;
	UINT LastRecvBlocksNum;
};


CONNECTION *NewClientConnectionEx(SESSION *s, char *client_str);
CONNECTION *NewServerConnection(CEDAR *cedar, SOCK *s, THREAD *t);
void ReleaseConnection(CONNECTION *c);
int CompareConnection(void *p1, void *p2);
void StopConnection(CONNECTION *c, bool no_wait);
void ConnectionAccept(CONNECTION *c);
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


#endif
