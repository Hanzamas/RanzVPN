// SoftEther VPN Source Code - Developer Edition Master Branch
// Mayaqua Kernel


// Network.h
// Header of Network.c

#ifndef	NETWORK_H
#define	NETWORK_H

#include "Encrypt.h"
#include "Mayaqua.h"

#include <openssl/ssl.h> // This is needed only for the SSL/TLS version defines

// Dynamic Value
struct DYN_VALUE
{
	char Name[256];								// Name
	UINT64 Value;								// Value
};

#define	DYN64(id, default_value)	( (UINT64)GetDynValueOrDefaultSafe ( #id , (UINT64)( default_value )))
#define	DYN32(id, default_value)	(UINT)DYN64(id, (UINT)default_value)

#define	MAX_HOST_NAME_LEN			255		// Maximum length of the host name

#define	TIMEOUT_INFINITE			(0x7fffffff)
#define	TIMEOUT_TCP_PORT_CHECK		(10 * 1000)
#define	TIMEOUT_SSL_CONNECT			(15 * 1000)

#define	TIMEOUT_NETBIOS_HOSTNAME	(100)

#define	SOCKET_BUFFER_SIZE			0x10000000

#define	UDP_MAX_MSG_SIZE_DEFAULT	65507

#define	MAX_NUM_IGNORE_ERRORS		1024

#define	DEFAULT_CIPHER_LIST			"ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:ECDHE+AES256:DHE+AES256:RSA+AES"

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#define PQ_GROUP_LIST				"X25519MLKEM768:p521_kyber1024:x25519_kyber768:P-521:X25519:P-256"
#endif

// SSL logging function
//#define	ENABLE_SSL_LOGGING
#define	SSL_LOGGING_DIRNAME			"@ssl_log"

// Private IP list file
#define	PRIVATE_IP_TXT_FILENAME		"$private_ip.txt"

// Start range of the random UDP port
#define	RAND_UDP_PORT_START			5000
#define	RAND_UDP_PORT_END			65530
#define	RAND_UDP_PORT_DEFAULT_NUM_RETRY	64

// Special Port
#define	MAKE_SPECIAL_PORT(p)		(UINT)((UINT)0x10000 | (UINT)(p))
#define	IS_SPECIAL_PORT(p)			(MAKEBOOL((p) & (UINT)0x10000))
#define	GET_SPECIAL_PORT(p)			(UINT)((UINT)(p) & (UINT)0xffff)

// UDP buffer size
#define	UDP_MAX_BUFFER_SIZE			11911168

// Expiration of the cache acquired from the IP address list of the host
#define	HOST_IP_ADDRESS_LIST_CACHE	(5 * 1000)

// IP address
struct IP
{
	BYTE address[16];   // IP address (RFC 3493 format used for IPv4)
	UINT ipv6_scope_id; // IPv6 scope ID
};

// Pointer to the beginning of the IPv4 address
#define	IPV4(address)				(&address[12])
#define	IPV4_SIZE					(4)

#define	CmpIpAddr(ip1, ip2)			(Cmp((ip1)->address, (ip2)->address, sizeof((ip1)->address)))

#define	IsIP6(ip)					(ip && IsIP4(ip) == false)
#define	IsZeroIp(ip)				(IsZeroIP(ip))

// IPv6 address (different format)
struct IPV6_ADDR
{
	UCHAR Value[16];				// Value
} GCC_PACKED;

// IPv6 Address Types
#define IPV6_ADDR_UNICAST						1	// Unicast
#define IPV6_ADDR_LOCAL_UNICAST					2	// Local unicast
#define IPV6_ADDR_GLOBAL_UNICAST				4	// Global Unicast
#define IPV6_ADDR_MULTICAST						8	// Multicast
#define IPV6_ADDR_ALL_NODE_MULTICAST			16	// All-nodes multicast
#define IPV6_ADDR_ALL_ROUTER_MULTICAST			32	// All routers multicast
#define IPV6_ADDR_SOLICIATION_MULTICAST			64	// Solicited-node multicast
#define	IPV6_ADDR_ZERO							128	// All zeros
#define	IPV6_ADDR_LOOPBACK						256	// Loop-back

// Client list
struct IP_CLIENT
{
	IP IpAddress;					// IP address
	UINT NumConnections;			// The number of connections
};

// Socket event
struct SOCK_EVENT
{
	REF *ref;						// Reference counter
#ifdef	OS_WIN32
	void *hEvent;					// Pointer to a Win32 event handle
#endif	// OS_WIN32
};

// Type of socket
#define	SOCK_TCP				1
#define	SOCK_UDP				2

// SSL Accept Settings
struct SSL_ACCEPT_SETTINGS
{
	bool Tls_Disable1_0;
	bool Tls_Disable1_1;
	bool Tls_Disable1_2;
	bool Tls_Disable1_3;
	bool Override_Security_Level;
	UINT Override_Security_Level_Value;
};

// Socket
struct SOCK
{
	REF *ref;					// Reference counter
	LOCK *lock;					// Lock
	LOCK *ssl_lock;				// Lock related to the SSL
	LOCK *disconnect_lock;		// Disconnection lock
	SOCKET socket;				// Socket number
	SSL *ssl;					// SSL object
	struct ssl_ctx_st *ssl_ctx;	// SSL_CTX
	char SniHostname[256];		// SNI host name
	UINT Type;					// Type of socket
	bool Connected;				// Connecting flag
	bool ServerMode;			// Server mode
	bool AsyncMode;				// Asynchronous mode
	bool SecureMode;			// SSL communication mode
	bool ListenMode;			// In listening
	BUF *SendBuf;				// Transmission buffer
	bool IpClientAdded;			// Whether it has been added to the list IP_CLIENT
	bool LocalOnly;				// Only local
	bool EnableConditionalAccept;	// Conditional Accept is Enabled
	IP RemoteIP;				// IP address of the remote host
	IP LocalIP;					// IP address of the local host
	char *RemoteHostname;		// Remote host name
	UINT RemotePort;			// Port number of the remote side
	UINT LocalPort;				// Port number of the local side
	UINT64 SendSize;			// Total size of the sent data
	UINT64 RecvSize;			// Total size of received data
	UINT64 SendNum;				// Number of sent data blocks
	UINT64 RecvNum;				// Number of received data blocks
	X *RemoteX;					// Certificate of the remote host
	X *LocalX;					// Certificate of the local host
	char *CipherName;			// Cipher algorithm name
	char *WaitToUseCipher;		// Set the algorithm name to want to use
	bool IgnoreRecvErr;			// Whether the RecvFrom error is ignorable
	bool IgnoreSendErr;			// Whether the SendTo error is ignorable
	UINT TimeOut;				// Time-out value
	SOCK_EVENT *SockEvent;		// Associated socket-event
	bool CancelAccept;			// Cancel flag of the Accept
	bool AcceptCanceled;		// Flag which shows canceling of the Accept
	bool WriteBlocked;			// Previous write is blocked
	bool NoNeedToRead;			// Is not required to read
	bool Disconnecting;			// Disconnecting
	bool UdpBroadcast;			// UDP broadcast mode
	void *Param;				// Any parameters
	bool IPv6;					// IPv6
	bool IsRawSocket;			// Whether it is a raw socket
	const char *SslVersion;		// SSL version
	UINT RawSocketIPProtocol;	// IP protocol number if it's a raw socket
	UINT UdpMaxMsgSize;			// Maximum transmitting and receiving size at a time on UDP
	int CurrentTos;				// Current ToS value
	bool IsTtlSupported;		// Whether the TTL value is supported
	UINT CurrentTtl;			// Current TTL value
	char UnderlayProtocol[64];	// Underlying protocol
	char ProtocolDetails[256];	// Protocol details
	UCHAR Ssl_Init_Async_SendAlert[2];	// Initial state of SSL send_alert
	SSL_ACCEPT_SETTINGS SslAcceptSettings;	// SSL Accept Settings
	bool RawIP_HeaderIncludeFlag;

#ifdef	ENABLE_SSL_LOGGING
	// SSL Logging (for debug)
	bool IsSslLoggingEnabled;	// Flag
	IO *SslLogging_Recv;		// for Recv
	IO *SslLogging_Send;		// for Send
	LOCK *SslLogging_Lock;		// Locking
#endif	// ENABLE_SSL_LOGGING

	void *hAcceptEvent;			// Event for Accept

#ifdef	OS_WIN32
	void *hEvent;				// Event for asynchronous mode
#endif	// OS_WIN32
};

// Underlying protocol description string of socket
#define	SOCK_UNDERLAY_NATIVE_V6		"Standard TCP/IP (IPv6)"
#define	SOCK_UNDERLAY_NATIVE_V4		"Standard TCP/IP (IPv4)"

// Constant of the return value
#define	SOCK_LATER	(0xffffffff)	// In blocking

// Socket Set
#define	MAX_SOCKSET_NUM		60		// Number of sockets that can be stored in a socket set
struct SOCKSET
{
	UINT NumSocket;					// The number of sockets
	SOCK *Sock[MAX_SOCKSET_NUM];	// Array of pointers to the socket
};

// Cancel object
struct CANCEL
{
	REF *ref;						// Reference counter
	bool SpecialFlag;				// Special flag (associated to the event which is generated by Win32 driver)
#ifdef	OS_WIN32
	void *hEvent;					// Pointer to a Win32 event handle
#endif	// OS_WIN32
};

// Routing table entry
struct ROUTE_ENTRY
{
	IP DestIP;
	IP DestMask;
	IP GatewayIP;
	bool LocalRouting;
	bool PPPConnection;
	UINT Metric;
	UINT IfMetric;
	UINT InterfaceID;
	UINT64 InnerScore;
	bool Active;
};

// Routing table
struct ROUTE_TABLE
{
	UINT NumEntry;
	UINT HashedValue;
	ROUTE_ENTRY **Entry;
};

// ICMP response result
struct ICMP_RESULT
{
	bool Ok;										// Whether a correct response returned
	bool Timeout;									// Whether a time-out is occurred
	UCHAR Type;										// Message type
	UCHAR Code;										// Message code
	UCHAR Ttl;										// TTL
	UCHAR *Data;									// Data body
	UINT DataSize;									// Data size
	UINT Rtt;										// Round Trip Time
	IP IpAddress;									// IP address
};

// NETBIOS name requests
typedef struct NBTREQUEST
{
	USHORT TransactionId;
	USHORT Flags;
	USHORT NumQuestions;
	USHORT AnswerRRs;
	USHORT AuthorityRRs;
	USHORT AdditionalRRs;
	UCHAR Query[38];
} NBTREQUEST;

// NETBIOS name response
typedef struct NBTRESPONSE
{
	USHORT TransactionId;
	USHORT Flags;
	USHORT NumQuestions;
	USHORT AnswerRRs;
	USHORT AuthorityRRs;
	USHORT AdditionalRRs;
	UCHAR Response[61];
} NBTRESPONSE;

// Socket list
typedef struct SOCKLIST
{
	LIST *SockList;
} SOCKLIST;


// Parameters for the IP address release thread
struct WIN32_RELEASEADDRESS_THREAD_PARAM
{
	REF *Ref;
	char Guid[MAX_SIZE];
	UINT Timeout;
	bool Ok;
	bool Renew;
};

// TCP table entry
typedef struct TCPTABLE
{
	UINT Status;
	IP LocalIP;
	UINT LocalPort;
	IP RemoteIP;
	UINT RemotePort;
	UINT ProcessId;
} TCPTABLE;

// State of TCP
#define	TCP_STATE_CLOSED				1
#define	TCP_STATE_LISTEN				2
#define	TCP_STATE_SYN_SENT				3
#define	TCP_STATE_SYN_RCVD				4
#define	TCP_STATE_ESTAB					5
#define	TCP_STATE_FIN_WAIT1				6
#define	TCP_STATE_FIN_WAIT2				7
#define	TCP_STATE_CLOSE_WAIT			8
#define	TCP_STATE_CLOSING				9
#define	TCP_STATE_LAST_ACK				10
#define	TCP_STATE_TIME_WAIT				11
#define	TCP_STATE_DELETE_TCB			12

// Routing table changing notification
struct ROUTE_CHANGE
{
	ROUTE_CHANGE_DATA *Data;
};

// UDP packet
struct UDPPACKET
{
	IP SrcIP;							// Source IP address
	IP DstIP;							// Destination IP address
	UINT SrcPort;						// Source port
	UINT DestPort;						// Destination port
	UINT Size;							// Data size
	void *Data;							// Data body
	UINT Type;							// Type
};

// Interrupt management
struct INTERRUPT_MANAGER
{
	LIST *TickList;						// Time list
};

// SSL BIO
struct SSL_BIO
{
	BIO *bio;							// BIO
	FIFO *SendFifo;						// Transmission FIFO
	FIFO *RecvFifo;						// Reception FIFO
	bool IsDisconnected;				// Disconnected
	bool NoFree;						// Not to release the BIO
};

// SSL pipe
struct SSL_PIPE
{
	bool ServerMode;					// Whether it's in the server mode
	bool IsDisconnected;				// Disconnected
	int SslVersion;
	SSL *ssl;							// SSL object
	struct ssl_ctx_st *ssl_ctx;			// SSL_CTX
	SSL_BIO *SslInOut;					// I/O BIO for the data in the SSL tunnel
	SSL_BIO *RawIn, *RawOut;			// Input and output BIO of the data flowing through the physical network
};

// IP address block list
struct IPBLOCK
{
	IP Ip;							// IP address
	IP Mask;						// Subnet mask
};


// ICMP protocol number
#define	IP_PROTO_ICMPV4		0x01	// ICMPv4 protocol
#define	IP_PROTO_ICMPV6		0x3a	// ICMPv6 protocol

// Data for the thread for serial connection attempts to a list of addresses
struct CONNECT_SERIAL_PARAM
{
	LIST *IpList;
	UINT LocalPort;						// Local port number to bind
	IP   *LocalIP;						// Local IP address to bind. NULL address allowed to use.
	IP   LocalIP_Cache;					// Local IP address to bind
	UINT Port;
	UINT Timeout;
	char Hostname[MAX_SIZE];
	bool No_Get_Hostname;
	bool *CancelFlag;
	bool *NoDelayFlag;
	SOCK *Sock;
	bool Finished;
	bool Ok;
	UINT64 FinishedTick;
	EVENT *FinishEvent;
	UINT Delay;
	UINT RetryDelay;
	IP *Ret_Ip;
};

struct SSL_VERIFY_OPTION
{
	bool VerifyPeer;				// Whether to verify SSL peer
	bool PromptOnVerifyFail;		// Prompt on verification failure (Windows)
	bool AddDefaultCA;				// Use default trust store
	bool VerifyHostname;			// Verify server hostname
	LIST *CaList;					// Trusted CA list
	X *SavedCert;					// Saved server certificate
};

// NIC adapter entry
struct NIC_ENTRY
{
	char IfName[MAX_SIZE];
	UCHAR MacAddress[6];
};

int GetCurrentTimezone();

bool GetSniNameFromSslPacket(UCHAR *packet_buf, UINT packet_size, char *sni, UINT sni_size);

void SetDhParam(DH_CTX *dh);

#ifdef	OS_WIN32
int GetCurrentTimezoneWin32();
#endif	// OS_WIN32

UINT GetErrorFromPack(PACK *p);
PACK *PackError(UINT error);

void CreateDummyValue(PACK *p);

char *RecvLine(SOCK *s, UINT max_size);

void GetCurrentMachineIpProcessHash(void *hash);
void ParseNtUsername(char *src_username, char *dst_username, UINT dst_username_size, char *dst_domain, UINT dst_domain_size, bool do_not_parse_atmark);

#ifdef OS_WIN32

// Function prototype for Win32
void Win32InitSocketLibrary();
void Win32FreeSocketLibrary();
void Win32Select(SOCKSET *set, UINT timeout, CANCEL *c1, CANCEL *c2);
void Win32InitAsyncSocket(SOCK *sock);
void Win32JoinSockToSockEvent(SOCK *sock, SOCK_EVENT *event);
void Win32FreeAsyncSocket(SOCK *sock);
void Win32Cancel(CANCEL *c);
void Win32CleanupCancel(CANCEL *c);
CANCEL *Win32NewCancel();
SOCK_EVENT *Win32NewSockEvent();
void Win32SetSockEvent(SOCK_EVENT *event);
void Win32CleanupSockEvent(SOCK_EVENT *event);
bool Win32WaitSockEvent(SOCK_EVENT *event, UINT timeout);
int CompareIpAdapterIndexMap(void *p1, void *p2);
SOCKET Win32Accept(SOCK *sock, SOCKET s, struct sockaddr *addr, int *addrlen, bool ipv6);

#endif	// OS_WIN32

// Function prototype
void InitNetwork();
void FreeNetwork();

void InAddrToIP(IP *ip, struct in_addr *addr);
void InAddrToIP6(IP *ip, struct in6_addr *addr);
void IPToInAddr6(struct in6_addr *addr, IP *ip);
bool StrToIP(IP *ip, char *str);
void IPToStr(char *str, UINT size, IP *ip);
void IPToStr32(char *str, UINT size, UINT ip);
void IPToStr4or6(char *str, UINT size, UINT ip_4_uint, UCHAR *ip_6_bytes);
void GetMachineName(char *name, UINT size);
void UINTToIP(IP *ip, UINT value);
UINT IPToUINT(IP *ip);
void ReleaseSock(SOCK *s);
SOCK *Connect(char *hostname, UINT port);
SOCK *ConnectEx4(char *hostname, UINT port, UINT timeout, bool *cancel_flag, bool no_get_hostname, IP *ret_ip);

// New function named with prefix "Bind" binds outgoing connection to a specific address. New one is wrapped in original one.
#define	BIND_LOCALIP_NULL			NULL		// NULL IP address specifies no binding
#define	BIND_LOCALPORT_NULL			0			// NULL port number specifies no binding
SOCK *BindConnectEx4(IP *localIP, UINT localport, char *hostname, UINT port, UINT timeout, bool *cancel_flag, bool no_get_hostname, IP *ret_ip);

void Disconnect(SOCK *sock);
SOCK *Listen(UINT port);
SOCK *ListenEx(UINT port, bool local_only);
SOCK *ListenEx2(UINT port, bool local_only, bool enable_ca, IP *listen_ip);
SOCK *ListenEx6(UINT port, bool local_only);
SOCK *ListenEx63(UINT port, bool local_only, bool enable_ca, IP *listen_ip);
SOCK *Accept(SOCK *sock);
UINT Send(SOCK *sock, void *data, UINT size, bool secure);
UINT Recv(SOCK *sock, void *data, UINT size, bool secure);
bool StartSSL(SOCK *sock, X *x, K *priv);
bool StartSSLEx(SOCK *sock, X *x, K *priv, UINT ssl_timeout, char *sni_hostname);
bool StartSSLEx3(SOCK *sock, X *x, K *priv, LIST *chain, UINT ssl_timeout, char *sni_hostname, SSL_VERIFY_OPTION *ssl_option, UINT *ssl_err);
bool SendAll(SOCK *sock, void *data, UINT size, bool secure);
void SendAdd(SOCK *sock, void *data, UINT size);
bool SendNow(SOCK *sock, int secure);
bool RecvAll(SOCK *sock, void *data, UINT size, bool secure);
bool RecvAllEx(SOCK *sock, void **data_new_ptr, UINT size, bool secure);
void InitSockSet(SOCKSET *set);
void AddSockSet(SOCKSET *set, SOCK *sock);
CANCEL *NewCancel();
CANCEL *NewCancelSpecial(void *hEvent);
void ReleaseCancel(CANCEL *c);
void Cancel(CANCEL *c);
void Select(SOCKSET *set, UINT timeout, CANCEL *c1, CANCEL *c2);
void SetWantToUseCipher(SOCK *sock, char *name);
SOCK *NewUDP(UINT port);
SOCK *NewUDPEx2(UINT port, bool ipv6, IP *ip);
SOCK *NewUDPEx3(UINT port, IP *ip);
UINT SendTo(SOCK *sock, IP *dest_addr, UINT dest_port, void *data, UINT size);
UINT RecvFrom(SOCK *sock, IP *src_addr, UINT *src_port, void *data, UINT size);
void SetTimeout(SOCK *sock, UINT timeout);
void JoinSockToSockEvent(SOCK *sock, SOCK_EVENT *event);
SOCK_EVENT *NewSockEvent();
void SetSockEvent(SOCK_EVENT *event);
bool WaitSockEvent(SOCK_EVENT *event, UINT timeout);
void ReleaseSockEvent(SOCK_EVENT *event);
void SetIP(IP *ip, UCHAR a1, UCHAR a2, UCHAR a3, UCHAR a4);
void AcceptInit(SOCK *s);
void AcceptInitEx(SOCK *s, bool no_lookup_hostname);
void DisableGetHostNameWhenAcceptInit();
TOKEN_LIST *GetCipherList();
COUNTER *GetNumTcpConnectionsCounter();
void AddWaitThread(THREAD *t);
void DelWaitThread(THREAD *t);
bool IsZeroIP(IP *ip);
bool IsZeroIP6Addr(IPV6_ADDR *addr);
void IntToSubnetMask4(IP *ip, UINT i);
bool IsIPv6Supported();
bool HasIPv6Address();
void SetSockHighPriority(SOCK *s, bool flag);
UINT GetNumIpClient(IP *ip);
void SetLinuxArpFilter();
void AddProtocolDetailsStr(char *dst, UINT dst_size, char *str);
void AddProtocolDetailsKeyValueInt(char *dst, UINT dst_size, char *key, UINT value);

#ifdef	ENABLE_SSL_LOGGING
void SockEnableSslLogging(SOCK *s);
void SockWriteSslLog(SOCK *s, void *send_data, UINT send_size, void *recv_data, UINT recv_size);
void SockCloseSslLogging(SOCK *s);
#endif	// ENABLE_SSL_LOGGING

void CopyIP(IP *dst, IP *src);
bool IsIP4(IP *ip);
void IPv6AddrToIP(IP *ip, IPV6_ADDR *addr);
bool IPToIPv6Addr(IPV6_ADDR *addr, IP *ip);
void SetIP6(IP *ip, UCHAR *value);
void GetLocalHostIP6(IP *ip);
void GetLocalHostIP4(IP *ip);
bool IsLocalHostIP(IP *ip);
void ZeroIP4(IP *ip);
void IP6AddrToStr(char *str, UINT size, IPV6_ADDR *addr);
void IPAnd6(IP *dst, IP *a, IP *b);
UINT GetIPAddrType6(IP *ip);
UINT GetIPv6AddrType(IPV6_ADDR *addr);
void GenerateEui64LocalAddress(IP *a, UCHAR *mac);
UINT SubnetMaskToInt6(IP *a);
bool IsStrIPv6Address(char *str);
void IPAnd4(IP *dst, IP *a, IP *b);

// Utility functions about IP and MAC address types
bool IsValidUnicastIPAddress4(IP *ip);
bool IsValidUnicastIPAddress6(IP *ip);

bool ParseIpAndMask4(char *src, UINT *ip, UINT *mask);
bool ParseIpAndMask6(char *src, IP *ip, IP *mask);
bool ParseIpAndMask46(char *src, IP *ip, IP *mask);
void MaskToStr(char *str, UINT size, IP *mask);
void Mask6AddrToStr(char *str, UINT size, IPV6_ADDR *mask);
void MaskToStr32(char *str, UINT size, UINT mask);

LIST *CloneIPAddressList(LIST *o);
void FreeHostIPAddressList(LIST *o);
void AddHostIPAddressToList(LIST *o, IP *ip);
UINT64 GetHostIPAddressListHash();

#define PREVERIFY_ERR_MESSAGE_SIZE 100
// Info on client certificate collected during TLS handshake
struct SslClientCertInfo {
	int PreverifyErr;
	char PreverifyErrMessage[PREVERIFY_ERR_MESSAGE_SIZE];
	X *X;
};

bool IsIPPrivate(IP *ip);
bool IsIPMyHost(IP *ip);
void LoadPrivateIPFile();
void FreePrivateIPFile();

bool IsMacAddressLocalFast(void *addr);
void RefreshLocalMacAddressList();

UINT GetOSSecurityLevel();

#ifdef	OS_WIN32
LIST *Win32GetNicList();
#endif	// OS_WIN32


UINT64 GetDynValueOrDefaultSafe(char *name, UINT64 default_value);


#endif	// NETWORK_H

