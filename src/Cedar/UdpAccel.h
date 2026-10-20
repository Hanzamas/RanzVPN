// UdpAccel.h
// Header of UdpAccel.c

#ifndef	UDPACCEL_H
#define	UDPACCEL_H

#include "CedarType.h"

#include "Mayaqua/Network.h"

#define	UDP_ACCELERATION_COMMON_KEY_SIZE_V1	20
#define	UDP_ACCELERATION_PACKET_KEY_SIZE_V1	20
#define	UDP_ACCELERATION_PACKET_IV_SIZE_V1	20

#define	UDP_ACCELERATION_COMMON_KEY_SIZE_V2	128
#define	UDP_ACCELERATION_PACKET_IV_SIZE_V2	12
#define	UDP_ACCELERATION_PACKET_MAC_SIZE_V2	16

#define	UDP_ACCELERATION_TMP_BUF_SIZE		2048
#define	UDP_ACCELERATION_WINDOW_SIZE_MSEC	(30 * 1000)

#define	UDP_ACCELERATION_MAX_PADDING_SIZE	32

// Cookie, my tick, your tick, data size and flag: the part of every packet before the data
#define	UDP_ACCELERATION_PACKET_HEADER_SIZE	(sizeof(UINT) + sizeof(UINT64) + sizeof(UINT64) + sizeof(USHORT) + sizeof(UCHAR))

// Receive budget: a flood to the UDP port must not hold the session thread. The datagrams over
// the budget stay in the socket for the next call (per poll) or the next tick (per tick).
#define	UDP_ACCELERATION_MAX_RECV_PER_POLL	256		// Datagrams that one UdpAccelPoll() call reads at most
#define	UDP_ACCELERATION_MAX_RECV_PER_TICK	4096	// Datagrams that the calls of one tick (UdpAccelSetTick()) read at most

#define	UDP_ACCELERATION_DROP_LOG_INTERVAL	(60 * 1000)	// Least time between two log entries of the drop counters

#define	UDP_ACCELERATION_REQUIRE_CONTINUOUS	(10 * 1000)	// Do not use until communication has been stable for this long

#define	UDP_ACCELERATION_KEEPALIVE_INTERVAL_MIN	(1 * 1000)
#define	UDP_ACCELERATION_KEEPALIVE_INTERVAL_MAX	(3 * 1000)
#define	UDP_ACCELERATION_KEEPALIVE_TIMEOUT		(9 * 1000)	// Disconnect after this long without traffic

#define	UDP_ACCELERATION_KEEPALIVE_INTERVAL_MIN_FAST	(500)
#define	UDP_ACCELERATION_KEEPALIVE_INTERVAL_MAX_FAST	(1000)
#define	UDP_ACCELERATION_KEEPALIVE_TIMEOUT_FAST			(2100)	// Disconnect after this long without traffic

#define	UDP_SERVER_PORT_LOWER				40000
#define	UDP_SERVER_PORT_HIGHER				44999

struct UDP_ACCEL
{
	CEDAR *Cedar;
	bool IsInCedarPortList;
	UINT64 Now;
	CIPHER *CipherEncrypt;
	CIPHER *CipherDecrypt;
	UCHAR MyKey[UDP_ACCELERATION_COMMON_KEY_SIZE_V1];
	UCHAR YourKey[UDP_ACCELERATION_COMMON_KEY_SIZE_V1];
	SOCK *UdpSock;
	IP MyIp;
	USHORT MyPort;
	IP YourIp;
	IP YourIpReported;
	USHORT YourPort;
	USHORT YourPortReported;
	bool IsIPv6;
	UCHAR TmpBuf[UDP_ACCELERATION_TMP_BUF_SIZE];
	UINT64 LastRecvYourTick;
	UINT64 LastRecvMyTick;
	QUEUE *RecvBlockQueue;
	bool UseHMac;
	bool PlainTextMode;
	UINT64 LastSetSrcIpAndPortTick;
	UINT64 LastRecvTick;
	UINT64 NextSendKeepAlive;
	UCHAR NextIv[UDP_ACCELERATION_PACKET_IV_SIZE_V1];
	UINT MyCookie;
	UINT YourCookie;
	bool Inited;
	UINT MaxUdpPacketSize;
	bool FatalError;
	UINT64 CreatedTick;
	bool FastDetect;
	UINT64 FirstStableReceiveTick;
	UINT Version;
	UCHAR MyKey_V2[UDP_ACCELERATION_COMMON_KEY_SIZE_V2];
	UCHAR NextIv_V2[UDP_ACCELERATION_PACKET_IV_SIZE_V2];
	bool ReadRawFlagMode;
	bool UseStun;
	IP StunIp;
	USHORT StunPort;
	UINT64 RecvTick;					// Tick (Now) of the per-tick receive budget
	UINT RecvNumInTick;					// Datagrams read in RecvTick
	UINT64 NumDropShort;				// Datagrams dropped before decryption: shorter than the smallest packet
	UINT64 NumDropInvalid;				// Datagrams dropped for failed decryption, cookie, format or window checks
	UINT64 NumRecvLimit;				// Polls that stopped at the receive budget
	UINT64 LogDropTick;					// Now of the last log entry of the drop counters, 0 before the first
	UINT64 LogDropNum;					// Dropped datagrams (NumDropShort + NumDropInvalid) at the last log entry
};

UDP_ACCEL *NewUdpAccel(CEDAR *cedar, IP *ip, bool client_mode, bool random_port);
void UdpAccelNewCookies(UINT *my_cookie, UINT *your_cookie, UINT (*rand32)(void));
void FreeUdpAccel(UDP_ACCEL *a);
bool UdpAccelInitClient(UDP_ACCEL *a, UCHAR *key, IP *detected_ip, IP *reported_ip, USHORT port, UINT cookie, UINT my_cookie);
bool UdpAccelInitServer(UDP_ACCEL *a, UCHAR *key, IP *detected_ip, IP *reported_ip, USHORT port);
void UdpAccelPoll(UDP_ACCEL *a);
void UdpAccelSetTick(UDP_ACCEL *a, UINT64 tick64);
BLOCK *UdpAccelProcessRecvPacket(UDP_ACCEL *a, UCHAR *buf, UINT size, IP *src_ip, UINT src_port);
void UdpAccelCalcKeyV1(UCHAR *key, UCHAR *common_key, UCHAR *iv);
bool UdpAccelIsSendReady(UDP_ACCEL *a, bool check_keepalive);
void UdpAccelSend(UDP_ACCEL *a, UCHAR *data, UINT data_size, UCHAR flag, UINT max_size);
void UdpAccelSendBlock(UDP_ACCEL *a, BLOCK *b);
UINT UdpAccelCalcMss(UDP_ACCEL *a);
void UdpAccelQueryStun(UDP_ACCEL *a, IP *peer_ip);
bool UdpAccelLogDrops(UDP_ACCEL *a, HUB *h, char *session_name, bool final);
bool UdpAccelIsRecvBudgetSpent(UDP_ACCEL *a);

#endif
