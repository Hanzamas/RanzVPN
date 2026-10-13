// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module
// © 2020 Nokia

// Connection.h
// Header of Connection.c

#ifndef	CONNECTION_H
#define	CONNECTION_H

#include "Cedar.h"

#include "Mayaqua/Encrypt.h"
#include "Mayaqua/Proxy.h"

#define	UPDATE_LAST_COMM_TIME(v, n)		{if ((v) <= (n)) { v = (n); } }

typedef bool (CHECK_CERT_PROC)(SESSION *s, CONNECTION *c, X *server_x, bool *expired);

// Do not change item size or order and only add new items at the end!
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
	char pad1[3];
	bool UseCompress;
	char pad2[3];
	bool HalfConnection;
	char pad3[3];
	bool NoRoutingTracking;
	char pad4[3];
	char DeviceName[MAX_DEVICE_NAME_LEN + 1];
	UINT AdditionalConnectionInterval;
	UINT ConnectionDisconnectSpan;
	bool HideStatusWindow;
	char pad5[3];
	bool HideNicInfoWindow;
	char pad6[3];
	bool RequireMonitorMode;
	char pad7[3];
	bool RequireBridgeRoutingMode;
	char pad8[3];
	bool DisableQoS;
	char pad9[3];
	bool FromAdminPack;
	char pad10[3];
	char pad11[4];											// Removed bool
	bool NoUdpAcceleration;
	char pad12[3];
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
	CHECK_CERT_PROC *CheckCertProc;
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
	UINT64 LastRecvTime;
	UINT LateCount;
	UINT Direction;
	UINT64 NextKeepAliveTime;
	CRYPT *SendKey;
	CRYPT *RecvKey;
	UINT64 DisconnectTick;
	UINT64 EstablishedTick;
};

struct TCP
{
	LIST *TcpSockList;
};

struct UDP
{
	SOCK *s;
	IP ip;
	UINT port;
	UINT64 NextKeepAliveTime;
	UINT64 Seq;
	UINT64 RecvSeq;
	QUEUE *BufferQueue;
};

struct BLOCK
{
	bool Compressed;
	UINT Size;
	UINT SizeofData;
	UCHAR *Buf;
	bool PriorityQoS;
	UINT Param1;
	bool IsFlooding;
	UCHAR RawFlagRetUdpAccel;
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
	UDP *Udp;
	bool ServerMode;
	UINT Status;
	char *Name;
	THREAD *Thread;
	volatile bool Halt;
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
	UCHAR CToken_Hash[SHA1_SIZE];
	UINT LastTcpQueueSize;
	UINT LastPacketQueueSize;
	UINT LastRecvFifoTotalSize;
	UINT LastRecvBlocksNum;
	LISTENER *Listener;
};


CONNECTION *NewClientConnection(SESSION *s);
CONNECTION *NewClientConnectionEx(SESSION *s, char *client_str, UINT client_ver, UINT client_build);
CONNECTION *NewServerConnection(CEDAR *cedar, SOCK *s, THREAD *t);
void ReleaseConnection(CONNECTION *c);
void CleanupConnection(CONNECTION *c);
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
void StopAllAdditionalConnectThread(CONNECTION *c);
UINT GenNextKeepAliveSpan(CONNECTION *c);
void SendKeepAlive(CONNECTION *c, TCPSOCK *ts);
void DisconnectUDPSockets(CONNECTION *c);
void PutUDPPacketData(CONNECTION *c, void *data, UINT size);
void SendDataWithUDP(SOCK *s, CONNECTION *c);
void InsertReceivedBlockToQueue(CONNECTION *c, BLOCK *block, bool no_lock);
void WriteSendFifo(SESSION *s, TCPSOCK *ts, void *data, UINT size);
void WriteRecvFifo(SESSION *s, TCPSOCK *ts, void *data, UINT size);
CLIENT_AUTH *CopyClientAuth(CLIENT_AUTH *a);
void NormalizeEthMtu(BRIDGE *b, CONNECTION *c, UINT packet_size);
UINT GetMachineRand();


#endif
