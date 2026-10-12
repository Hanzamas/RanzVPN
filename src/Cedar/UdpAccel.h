// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// UdpAccel.h
// Header of UdpAccel.c

#ifndef	UDPACCEL_H
#define	UDPACCEL_H

#include "CedarType.h"

#include "Mayaqua/Network.h"

// Constants
#define	UDP_ACCELERATION_COMMON_KEY_SIZE_V1	20			// V1: Common key size
#define	UDP_ACCELERATION_PACKET_KEY_SIZE_V1	20			// V1: Key size for the packet
#define	UDP_ACCELERATION_PACKET_IV_SIZE_V1	20			// V1: IV size for the packet

#define	UDP_ACCELERATION_COMMON_KEY_SIZE_V2	128			// V2: Common key size
#define	UDP_ACCELERATION_PACKET_IV_SIZE_V2	12			// V2: IV size for the packet
#define	UDP_ACCELERATION_PACKET_MAC_SIZE_V2	16			// V2: MAC size for the packet

#define	UDP_ACCELERATION_TMP_BUF_SIZE		2048		// Temporary buffer size
#define	UDP_ACCELERATION_WINDOW_SIZE_MSEC	(30 * 1000)	// Receive window size (in milliseconds)

#define	UDP_ACCELERATION_SUPPORTED_MAX_PAYLOAD_SIZE	1600	// Maximum supported payload size
#define	UDP_ACCELERATION_MAX_PADDING_SIZE	32			// Maximum padding size

#define	UDP_ACCELERATION_REQUIRE_CONTINUOUS	(10 * 1000)	// Not to use if stable communication is not continued at least for this time

// Time constant for Build 8534 or earlier
#define	UDP_ACCELERATION_KEEPALIVE_INTERVAL_MIN	(1 * 1000)	// Keep Alive Interval (minimum)
#define	UDP_ACCELERATION_KEEPALIVE_INTERVAL_MAX	(3 * 1000)	// Keep Alive Interval (maximum)
#define	UDP_ACCELERATION_KEEPALIVE_TIMEOUT		(9 * 1000)	// Time to disconnect time by non-communication

// Time constant for Build 8535 or later
#define	UDP_ACCELERATION_KEEPALIVE_INTERVAL_MIN_FAST	(500)	// Keep Alive Interval (minimum)
#define	UDP_ACCELERATION_KEEPALIVE_INTERVAL_MAX_FAST	(1000)	// Keep Alive Interval (maximum)
#define	UDP_ACCELERATION_KEEPALIVE_TIMEOUT_FAST			(2100)	// Time to disconnect time by non-communication

// Range of port numbers
#define	UDP_SERVER_PORT_LOWER				40000		// Minimum port
#define	UDP_SERVER_PORT_HIGHER				44999		// Maximum port

// UDP Acceleration Mode
struct UDP_ACCEL
{
	CEDAR *Cedar;										// Cedar
	bool ClientMode;									// Whether client mode
	bool IsInCedarPortList;								// Whether included in the port list of the Cedar
	UINT64 Now;											// Current time
	CIPHER *CipherEncrypt;								// Encryption context
	CIPHER *CipherDecrypt;								// Decryption context
	UCHAR MyKey[UDP_ACCELERATION_COMMON_KEY_SIZE_V1];	// Send-direction common key
	UCHAR YourKey[UDP_ACCELERATION_COMMON_KEY_SIZE_V1];	// Receive-direction common key
	SOCK *UdpSock;										// UDP socket
	IP MyIp;											// My IP address
	USHORT MyPort;										// My port number
	IP YourIp;											// IP address of the peer (current)
	IP YourIpReported;									// IP address of the peer (reported)
	USHORT YourPort;									// Port number of the peer (current)
	USHORT YourPortReported;							// Port number of the peer (reported)
	bool IsIPv6;										// Whether it's an IPv6
	UCHAR TmpBuf[UDP_ACCELERATION_TMP_BUF_SIZE];		// Temporary buffer
	UINT64 LastRecvYourTick;							// Opponent's tick value of the last reception
	UINT64 LastRecvMyTick;								// My tick value of the last reception
	QUEUE *RecvBlockQueue;								// Reception block queue
	bool UseHMac;										// Flag to use the HMAC
	bool PlainTextMode;									// No encryption
	UINT64 LastSetSrcIpAndPortTick;						// Opponent's tick ??value at the time of storing the IP address and port number of the opponent at the end
	UINT64 LastRecvTick;								// Tick when data has received at the end
	UINT64 NextSendKeepAlive;							// Next time to send a KeepAlive packet
	UCHAR NextIv[UDP_ACCELERATION_PACKET_IV_SIZE_V1];	// IV to be used next
	UINT MyCookie;										// My cookie
	UINT YourCookie;									// Cookie of the other party
	bool Inited;										// Initialized flag
	UINT Mss;											// Optimal MSS
	UINT MaxUdpPacketSize;								// Get the maximum transmittable UDP size
	bool FatalError;									// A fatal error occurred
	bool IsReachedOnce;									// It is true if it succeeds in mutual transmission and reception of packets at least once
	UINT64 CreatedTick;									// Object creation time
	bool FastDetect;									// Fast disconnection detection mode
	UINT64 FirstStableReceiveTick;						// Start time of current stable continued receivable period
	UINT Version;										// Version
	UCHAR MyKey_V2[UDP_ACCELERATION_COMMON_KEY_SIZE_V2];	// Send-direction common key (version 2)
	UCHAR NextIv_V2[UDP_ACCELERATION_PACKET_IV_SIZE_V2];	// IV to be used next (version 2)
	bool ReadRawFlagMode;								// Read raw flag mode
	bool UseStun;										// Whether the public endpoint was learned by STUN
	IP StunIp;											// Public IP address learned by STUN
	USHORT StunPort;									// Public port number learned by STUN
};

// Function prototype
UDP_ACCEL *NewUdpAccel(CEDAR *cedar, IP *ip, bool client_mode, bool random_port);
void FreeUdpAccel(UDP_ACCEL *a);
bool UdpAccelInitClient(UDP_ACCEL *a, UCHAR *key, IP *detected_ip, IP *reported_ip, USHORT port, UINT cookie, UINT my_cookie);
bool UdpAccelInitServer(UDP_ACCEL *a, UCHAR *key, IP *detected_ip, IP *reported_ip, USHORT port);
void UdpAccelPoll(UDP_ACCEL *a);
void UdpAccelSetTick(UDP_ACCEL *a, UINT64 tick64);
BLOCK *UdpAccelProcessRecvPacket(UDP_ACCEL *a, UCHAR *buf, UINT size, IP *src_ip, UINT src_port);
void UdpAccelCalcKeyV1(UCHAR *key, UCHAR *common_key, UCHAR *iv);
bool UdpAccelIsSendReady(UDP_ACCEL *a, bool check_keepalive);
void UdpAccelSend(UDP_ACCEL *a, UCHAR *data, UINT data_size, UCHAR flag, UINT max_size, bool high_priority);
void UdpAccelSendBlock(UDP_ACCEL *a, BLOCK *b);
UINT UdpAccelCalcMss(UDP_ACCEL *a);
void UdpAccelQueryStun(UDP_ACCEL *a, IP *peer_ip);

#endif	// UDPACCEL_H
