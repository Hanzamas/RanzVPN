// Cedar.h
// Header of Cedar.c

#ifndef CEDAR_H
#define CEDAR_H

#include "CedarType.h"
#include "GlobalConst.h"
#include "Tunables.h"

#include "Mayaqua/Network.h"
#include "Mayaqua/Proxy.h" // PROXY_DIRECT, PROXY_HTTP, PROXY_SOCKS, PROXY_SOCKS5

// The version in BuildInfo.h (major.minor.build) is for display only. Peers
// receive and compare these fixed values instead (hello/welcome packs, node
// info, admin RPC, server caps), kept at the last SoftEther VPN 5.02 build
// 5187 so that existing peers keep gating features the same way.
#define CEDAR_WIRE_VER   502 // Major * 100 + minor
#define CEDAR_WIRE_BUILD 5187

#define MAX_ACCOUNT_NAME_LEN      255
#define MAX_USERNAME_LEN          255
#define MAX_PASSWORD_LEN          255
#define MAX_SERVER_STR_LEN        255
#define MAX_CLIENT_STR_LEN        255
#define MAX_HUBNAME_LEN           255
#define MAX_SESSION_NAME_LEN      255
#define MAX_CONNECTION_NAME_LEN   255
#define MAX_DEVICE_NAME_LEN       31
#define MAX_ACCESSLIST_NOTE_LEN   255
#define MAX_ADMIN_OPTION_NAME_LEN 63
#define MAX_REDIRECT_URL_LEN      255


#define SERVER_MAX_SESSIONS   100000
#define MAX_ACCESSLISTS       (4096 * 8)
#define MAX_USERS             10000
#define MAX_GROUPS            10000
#define MAX_MAC_TABLES        VPN_GP(GP_MAX_MAC_TABLES)
#define MAX_IP_TABLES         VPN_GP(GP_MAX_IP_TABLES)
#define MAX_HUB_CERTS         4096
#define MAX_HUB_CRLS          4096
#define MAX_HUB_ACS           4096
#define MAX_HUB_LINKS         VPN_GP(GP_MAX_HUB_LINKS)
#define MAX_HUB_ADMIN_OPTIONS 4096

#define QUEUE_BUDGET VPN_GP(GP_QUEUE_BUDGET)
#define FIFO_BUDGET  VPN_GP(GP_FIFO_BUDGET)

#define MAX_PACKET_SIZE 1600

#define MAX_SEND_SOCKET_QUEUE_SIZE VPN_GP(GP_MAX_SEND_SOCKET_QUEUE_SIZE)
#define MIN_SEND_SOCKET_QUEUE_SIZE VPN_GP(GP_MIN_SEND_SOCKET_QUEUE_SIZE)
#define MAX_STORED_QUEUE_NUM       VPN_GP(GP_MAX_STORED_QUEUE_NUM)
#define MAX_BUFFERING_PACKET_SIZE  VPN_GP(GP_MAX_BUFFERING_PACKET_SIZE)

#define MAX_SEND_SOCKET_QUEUE_NUM VPN_GP(GP_MAX_SEND_SOCKET_QUEUE_NUM)
#define MAX_TCP_CONNECTION        32
#define SELECT_TIME               VPN_GP(GP_SELECT_TIME)

#define TIMEOUT_MIN            (5 * 1000)
#define TIMEOUT_MAX            (60 * 1000)
#define TIMEOUT_DEFAULT        (30 * 1000)
#define CONNECTING_TIMEOUT     (15 * 1000)
#define MIN_RETRY_INTERVAL     (5 * 1000)
#define MAX_RETRY_INTERVAL     (300 * 1000)
#define RETRY_INTERVAL_SPECIAL (60 * 1000)

#define ADDITIONAL_CONNECTION_COUNTER_RESET_INTERVAL (30 * 60 * 1000)

#define MAC_MIN_LIMIT_COUNT         3
#define IP_MIN_LIMIT_COUNT          4
#define IP_MIN_LIMIT_COUNT_V6       5
#define IP_LIMIT_WHEN_NO_ROUTING_V6 15

#define MAC_TABLE_EXCLUSIVE_TIME  (13 * 1000)
#define IP_TABLE_EXCLUSIVE_TIME   (13 * 1000)
#define MAC_TABLE_EXPIRE_TIME     VPN_GP(GP_MAC_TABLE_EXPIRE_TIME)
#define IP_TABLE_EXPIRE_TIME      VPN_GP(GP_IP_TABLE_EXPIRE_TIME)
#define IP_TABLE_EXPIRE_TIME_DHCP VPN_GP(GP_IP_TABLE_EXPIRE_TIME_DHCP)
#define HUB_ARP_SEND_INTERVAL     VPN_GP(GP_HUB_ARP_SEND_INTERVAL)

#define LIMITER_SAMPLING_SPAN 1000

#define STORM_CHECK_SPAN          VPN_GP(GP_STORM_CHECK_SPAN)
#define STORM_DISCARD_VALUE_START VPN_GP(GP_STORM_DISCARD_VALUE_START)
#define STORM_DISCARD_VALUE_END   VPN_GP(GP_STORM_DISCARD_VALUE_END)




#define DH_PARAM_BITS_DEFAULT 2048


#define INCREMENT_TRAFFIC_INTERVAL (10 * 1000)

#define CLIENT_STATUS_CONNECTING  0
#define CLIENT_STATUS_NEGOTIATION 1
#define CLIENT_STATUS_AUTH        2
#define CLIENT_STATUS_ESTABLISHED 3
#define CLIENT_STATUS_RETRY       4
#define CLIENT_STATUS_IDLE        5

#define FTP_BLOCK_SIZE (640 * 1024)

#define SYSLOG_NONE                        0
#define SYSLOG_SERVER_AND_HUB_SECURITY_LOG 2
#define SYSLOG_SERVER_AND_HUB_ALL_LOG      3

#define RECV_BUF_SIZE 65536

#define TCP_BOTH             0
#define TCP_SERVER_TO_CLIENT 1
#define TCP_CLIENT_TO_SERVER 2

#define CONNECTION_TYPE_CLIENT     0
#define CONNECTION_TYPE_INIT       1
#define CONNECTION_TYPE_LOGIN      2
#define CONNECTION_TYPE_ADDITIONAL 3
#define CONNECTION_TYPE_ADMIN_RPC  5
#define CONNECTION_TYPE_ENUM_HUB   6
#define CONNECTION_TYPE_PASSWORD   7

#define CONNECTION_TCP             0
#define CONNECTION_HUB_BRIDGE      7
#define CONNECTION_HUB_LINK_SERVER 9
#define CONNECTION_NOISE           10 // The Tunnel of Noise sessions of a node of the new core (ConnectionTunnel.c)


#define CONNECTION_STATUS_ACCEPTED    0
#define CONNECTION_STATUS_NEGOTIATION 1
#define CONNECTION_STATUS_USERAUTH    2
#define CONNECTION_STATUS_ESTABLISHED 3
#define CONNECTION_STATUS_CONNECTING  0

// Magic number of KeepAlive packet
#define KEEP_ALIVE_MAGIC   0xffffffff
#define MAX_KEEPALIVE_SIZE 512



#define SE_HUB_MAC_ADDR_SIGN 0xAE // Second byte of a virtual HUB MAC address (00:AE:...)

#define MACHINE_ID_SALT_SIZE 32 // Bytes of the machine identity salt (FIX-5)

// Fixed first input of the machine identity hash (ComputeMachineUniqueHash, FIX-5 #101)
#define MACHINE_ID_LABEL "RanzVPN machine identity v1"

#define HUB_ACCESSLIST_DELAY_MAX  10000
#define HUB_ACCESSLIST_JITTER_MAX 100
#define HUB_ACCESSLIST_LOSS_MAX   100

#define HUB_MAXMSG_LEN 20000



#define AUTHTYPE_ANONYMOUS 0
#define AUTHTYPE_PASSWORD  1
#define AUTHTYPE_USERCERT  2
#define AUTHTYPE_ROOTCERT  3
#define AUTHTYPE_NT        5

#define CLIENT_AUTHTYPE_ANONYMOUS      0
#define CLIENT_AUTHTYPE_PASSWORD       1
#define CLIENT_AUTHTYPE_PLAIN_PASSWORD 2
#define CLIENT_AUTHTYPE_CERT           3



#define LISTEN_RETRY_TIME         (2 * 1000)
#define LISTENER_BIND_WAIT_TIME   (5 * 1000)  // ListenerCreate / ListenerEnable wait at most this for the bind attempt
#define ACCEPT_RETRY_TIME         100         // Back-off of a TCP listener after a transient accept() error
#define ACCEPT_ERROR_LOG_INTERVAL (60 * 1000) // A TCP listener logs transient accept() errors at most once per interval

#define DOS_TABLE_EXPIRES_FIRST    250
#define DOS_TABLE_EXPIRES_MAX      1000
#define DOS_TABLE_REFRESH_INTERVAL (10 * 1000)
#define DOS_TABLE_MAX_LIMIT_PER_IP 16
#define DOS_TABLE_EXPIRES_TOTAL    (3000 * 1000)


#define LISTENER_TCP 0
// The HTTP listener: the redirect to HTTPS and ACME HTTP-01 (HttpListener.c)
#define LISTENER_HTTP 1

#define LISTENER_STATUS_TRYING    0
#define LISTENER_STATUS_LISTENING 1

#define UDP_PACKET_SIZE 65536

#define DEFAULT_MAX_CONNECTIONS_PER_IP 256
#define MIN_MAX_CONNECTIONS_PER_IP     10

#define DEFAULT_MAX_UNESTABLISHED_CONNECTIONS 1000


// These placeholders will be replaced in InnerFilePathW().
// @ - placeholder for LogDir
// $ - placeholder for DbDir (config directory)
#define SERVER_LOG_DIR      "server_log"
#define SERVER_LOG_DIR_NAME "@" SERVER_LOG_DIR
#define SERVER_LOG_PERFIX   "vpn"

#define HUB_SECURITY_LOG_DIR       "security_log"
#define HUB_SECURITY_LOG_DIR_NAME  "@" HUB_SECURITY_LOG_DIR
#define HUB_SECURITY_LOG_FILE_NAME HUB_SECURITY_LOG_DIR_NAME "/%s"
#define HUB_SECURITY_LOG_PREFIX    "sec"
#define HUB_PACKET_LOG_DIR         "packet_log"
#define HUB_PACKET_LOG_DIR_NAME    "@" HUB_PACKET_LOG_DIR
#define HUB_PACKET_LOG_FILE_NAME   HUB_PACKET_LOG_DIR_NAME "/%s"
#define HUB_PACKET_LOG_PREFIX      "pkt"

#define NUM_PACKET_LOG      16
#define PACKET_LOG_TCP_CONN 0
#define PACKET_LOG_TCP      1
#define PACKET_LOG_DHCP     2
#define PACKET_LOG_UDP      3
#define PACKET_LOG_ICMP     4
#define PACKET_LOG_IP       5
#define PACKET_LOG_ARP      6
#define PACKET_LOG_ETHERNET 7

#define PACKET_LOG_NONE   0
#define PACKET_LOG_HEADER 1
#define PACKET_LOG_ALL    2

#define TINY_LOG_DIRNAME  "@tiny_log"
#define TINY_LOG_FILENAME "@tiny_log/%04u%02u%02u_%02u%02u%02u.log"


#define ADMINISTRATOR_USERNAME "administrator"
#define ADMINIP_TXT            "$adminip.txt"

#define NON_SSL_MIN_COUNT     60
#define NON_SSL_ENTRY_EXPIRES (10 * 60 * 1000)

#define LINK_DEVICE_NAME     "_SEHUBLINKCLI_"
#define LINK_USER_NAME       "link"
#define LINK_USER_NAME_PRINT "Cascade"



#define BRIDGE_USER_NAME       "localbridge"
#define BRIDGE_USER_NAME_PRINT "Local Bridge"



#define ERR_NO_ERROR                             0
#define ERR_CONNECT_FAILED                       1
#define ERR_SERVER_IS_NOT_VPN                    2
#define ERR_DISCONNECTED                         3
#define ERR_PROTOCOL_ERROR                       4
#define ERR_CLIENT_IS_NOT_VPN                    5
#define ERR_USER_CANCEL                          6
#define ERR_AUTHTYPE_NOT_SUPPORTED               7
#define ERR_HUB_NOT_FOUND                        8
#define ERR_AUTH_FAILED                          9
#define ERR_HUB_STOPPING                         10
#define ERR_SESSION_REMOVED                      11
#define ERR_ACCESS_DENIED                        12
#define ERR_SESSION_TIMEOUT                      13
#define ERR_INVALID_PROTOCOL                     14
#define ERR_TOO_MANY_CONNECTION                  15
#define ERR_HUB_IS_BUSY                          16
#define ERR_PROXY_CONNECT_FAILED                 17
#define ERR_PROXY_ERROR                          18
#define ERR_PROXY_AUTH_FAILED                    19
#define ERR_TOO_MANY_USER_SESSION                20
#define ERR_LICENSE_ERROR                        21
#define ERR_DEVICE_DRIVER_ERROR                  22
#define ERR_INTERNAL_ERROR                       23
#define ERR_OBJECT_NOT_FOUND                     29
#define ERR_NOT_SUPPORTED                        33
#define ERR_INVALID_PARAMETER                    38
#define ERR_NULL_PASSWORD_LOCAL_ONLY             51
#define ERR_NOT_ENOUGH_RIGHT                     52
#define ERR_LISTENER_NOT_FOUND                   53
#define ERR_LISTENER_ALREADY_EXISTS              54
#define ERR_HUB_ALREADY_EXISTS                   57
#define ERR_TOO_MANY_HUBS                        58
#define ERR_LINK_ALREADY_EXISTS                  59
#define ERR_LINK_IS_OFFLINE                      61
#define ERR_TOO_MANY_ACCESS_LIST                 62
#define ERR_TOO_MANY_USER                        63
#define ERR_TOO_MANY_GROUP                       64
#define ERR_GROUP_NOT_FOUND                      65
#define ERR_USER_ALREADY_EXISTS                  66
#define ERR_GROUP_ALREADY_EXISTS                 67
#define ERR_USER_AUTHTYPE_NOT_PASSWORD           68
#define ERR_OLD_PASSWORD_WRONG                   69
#define ERR_LINK_CANT_DISCONNECT                 73
#define ERR_NOT_RSA_1024                         77
#define ERR_BRIDGE_CANT_DISCONNECT               82
#define ERR_LOCAL_BRIDGE_UNSUPPORTED             84
#define ERR_CERT_NOT_TRUSTED                     85
#define ERR_VERSION_INVALID                      87
#define ERR_SERVER_CANT_ACCEPT                   105
#define ERR_SERVER_CERT_EXPIRES                  106
#define ERR_MONITOR_MODE_DENIED                  107
#define ERR_BRIDGE_MODE_DENIED                   108
#define ERR_IP_ADDRESS_DENIED                    109
#define ERR_TOO_MANT_ITEMS                       110
#define ERR_MEMORY_NOT_ENOUGH                    111
#define ERR_OBJECT_EXISTS                        112
#define ERR_BAD_COMMAND_OR_PARAM                 117
#define ERR_NOT_ADMINPACK_SERVER                 121
#define ERR_BRANDED_C_TO_S                       124
#define ERR_BRANDED_C_FROM_S                     125
#define ERR_AUTO_DISCONNECTED                    126 // Policy AutoDisconnect ended the session; it does not reconnect
#define ERR_CLIENT_ID_REQUIRED                   127
#define ERR_TOO_MANY_USERS_CREATED               128
#define ERR_NOT_SUPPORTED_AUTH_ON_OPENSOURCE     143
#define ERR_NOT_SUPPORTED_FUNCTION_ON_OPENSOURCE 147
#define ERR_HOSTNAME_MISMATCH                    149
#define ERR_SSL_PROTOCOL_VERSION                 150 // No TLS version both sides support
#define ERR_SSL_SHARED_CIPHER                    151 // No cipher both sides support
#define ERR_SSL_HANDSHAKE                        152 // The TLS handshake has failed
#define ERR_LISTENER_BIND_FAILED                 153 // Listener registered, but its TCP port is not bound (it keeps retrying)


typedef struct NETSVC {
	bool Udp; // false=TCP, true=UDP
	UINT Port;
	char *Name;
} NETSVC;

typedef struct TRAFFIC_ENTRY {
	UINT64 BroadcastCount;
	UINT64 BroadcastBytes;
	UINT64 UnicastCount;
	UINT64 UnicastBytes;
} TRAFFIC_ENTRY;

struct TRAFFIC {
	TRAFFIC_ENTRY Send;
	TRAFFIC_ENTRY Recv;
};

typedef struct NON_SSL {
	IP IpAddress; // Rate-limit key of the source (GetRateLimitKey)
	UINT64 EntryExpires;
	UINT Count;
} NON_SSL;

typedef struct TINY_LOG {
	char FileName[MAX_PATH];
	IO *io;
	LOCK *Lock;
} TINY_LOG;

struct CEDAR {
	LOCK *lock;
	REF *ref;
	COUNTER *AcceptingSockets;
	LIST *ListenerList;
	LIST *HubList;
	LIST *ConnectionList;
	COUNTER *ConnectionIncrement;
	X *ServerX;
	K *ServerK;
	LIST *ServerChain;
	char *CipherList;
	UINT Version;
	UINT Build;
	char *ServerStr;
	char *HttpUserAgent;
	TRAFFIC *Traffic;
	LOCK *TrafficLock;
	COUNTER *CurrentSessions;
	COUNTER *CurrentTcpConnections;
	LIST *NetSvcList;
	char *VerString;
	char *BuildInfo;
	struct SERVER *Server;
	UCHAR UniqueId[16];
	LIST *LocalBridgeList;
	COUNTER *AssignedClientLicense;
	COUNTER *AssignedBridgeLicense;
	LIST *NonSslList;
	bool NonSslListFullLogged; // MakeRoomInNoSslList has logged that NonSslList reached RATE_LIMIT_TABLE_MAX
	LOCK *CedarSuperLock;
	bool DisableIPv6Listener;
	LIST *UdpPortList;
	UINT CurrentTcpQueueSize; // Changed only with InterlockedExchangeAdd
	COUNTER *CurrentActiveLinks;
	UINT QueueBudget; // Changed only with InterlockedExchangeAdd
	UINT FifoBudget;  // Changed only with InterlockedExchangeAdd
	SSL_ACCEPT_SETTINGS SslAcceptSettings;
	struct ssl_ctx_st *ServerSslCtx;          // The one server SSL_CTX of all accepted connections (GetCedarServerSslCtx), NULL until the first one
	SSL_ACCEPT_SETTINGS ServerSslCtxSettings; // SslAcceptSettings that ServerSslCtx was built with
	UINT ServerSslCtxChainGen;                // Generation of the chain_certs folder that ServerSslCtx was built with (ServerChain NULL)
	UINT DhParamBits;
	char StunServer[MAX_HOST_NAME_LEN + 1];    // STUN server (host[:port]) for UDP acceleration, empty = STUN disabled
	UCHAR MachineIdSalt[MACHINE_ID_SALT_SIZE]; // Machine identity salt: random from NewCedar, then the one of the config file
	UCHAR MachineUniqueHash[SHA1_SIZE];        // Machine identity from MachineGuid and MachineIdSalt (SetCedarMachineIdSalt)
	UINT64 MaxLogSize;                         // Maximum size of a log file of the server and its hubs (LoggerMaxLogSize), 0 for MAX_LOG_SIZE_DEFAULT
};

// The SE-VPN code of the slim fork that the Hub and Session code of Cedar still calls: the cascades of a Hub
// (Link.c), the additional connections of a client Session (ProtocolClient.c) and the UDP Acceleration of a Session
// (UdpAccel.c). A program that runs that code fills these hooks with InitSeVpn (Server.c) before it starts any of it:
// vpntest, whose in-process oracle is that code. ranz-node never does, so it links none of that code (CORE-S8-2,
// #576): its Hubs have no cascade and its Sessions are server Sessions without a UDP_ACCEL, so the Hub and Session
// code skips the hooks of the cascades and of the client Sessions while they are NULL, and reaches the UDP
// Acceleration hooks only for a Session that has a UDP_ACCEL, which only that code creates. CORE-S8-3 (#577) deletes
// them with that code.
typedef struct SEVPN_HOOKS {
	void (*StartAllLink)(HUB *h);                       // SetHubOnline
	void (*StopAllLink)(HUB *h);                        // SetHubOffline
	void (*ReleaseAllLink)(HUB *h);                     // CleanupHub
	void (*ClientAdditionalConnectChance)(SESSION *s); // SessionMain of a client Session
	void (*UdpAccelSetTick)(UDP_ACCEL *a, UINT64 tick64);
	void (*UdpAccelPoll)(UDP_ACCEL *a);
	UINT (*UdpAccelCalcMss)(UDP_ACCEL *a);
	bool (*UdpAccelIsSendReady)(UDP_ACCEL *a, bool check_keepalive);
	void (*UdpAccelSendBlock)(UDP_ACCEL *a, BLOCK *b);
	bool (*UdpAccelIsRecvBudgetSpent)(UDP_ACCEL *a);
	bool (*UdpAccelLogDrops)(UDP_ACCEL *a, HUB *h, char *session_name, bool final);
} SEVPN_HOOKS;

extern SEVPN_HOOKS SeVpnHooks;

TRAFFIC *NewTraffic();
void FreeTraffic(TRAFFIC *t);
CEDAR *NewCedar(X *server_x, K *server_k);
void SetCedarCertAndChain(CEDAR *c, X *server_x, K *server_k, LIST *server_chain);
void ReleaseCedar(CEDAR *c);
void StopCedar(CEDAR *c);
void AddTraffic(TRAFFIC *dst, TRAFFIC *diff);
void SubTraffic(TRAFFIC *dst, TRAFFIC *a, TRAFFIC *b);
void TrafficCountFrame(TRAFFIC_ENTRY *e, UCHAR *buf, UINT size);
void AddHub(CEDAR *c, HUB *h);
void DelHub(CEDAR *c, HUB *h);
void AddConnection(CEDAR *cedar, CONNECTION *c);
UINT GetUnestablishedConnections(CEDAR *cedar);
void DelConnection(CEDAR *cedar, CONNECTION *c);
// An invalid cipher spec makes the server fall back to its built-in list of modern ciphers.
#define SERVER_DEFAULT_CIPHER_NAME "~DEFAULT~"
void SetCedarCipherList(CEDAR *cedar, char *name);
struct ssl_ctx_st *GetCedarServerSslCtx(CEDAR *c);
void InitCedar();
void FreeCedar();
void GenerateMachineUniqueHash(CEDAR *c, void *data);
void SetCedarMachineIdSalt(CEDAR *c, void *salt);
void ComputeMachineUniqueHash(void *data, char *machine_guid, void *salt, UINT salt_size);
char *GetSvcName(CEDAR *cedar, bool udp, UINT port);
UINT64 GetTrafficPacketSize(TRAFFIC *t);
UINT64 GetTrafficPacketNum(TRAFFIC *t);
bool AddNoSsl(CEDAR *c, IP *ip);
void DecrementNoSsl(CEDAR *c, IP *ip, UINT num_dec);
bool IsInNoSsl(CEDAR *c, IP *ip);
void FreeTinyLog(TINY_LOG *t);
void WriteTinyLog(TINY_LOG *t, char *str);
TINY_LOG *NewTinyLog();
void GetWinVer(RPC_WINVER *v);
void FormatUnsupportedWinVerMsg(wchar_t *buf, UINT size, RPC_WINVER *peer);
void CedarAddCurrentTcpQueueSize(CEDAR *c, int diff);
UINT CedarGetCurrentTcpQueueSize(CEDAR *c);
void CedarSyncQueueBudget(CEDAR *c, UINT current, UINT *last);
void CedarAddFifoBudget(CEDAR *c, int diff);
UINT CedarGetQueueBudgetConsuming(CEDAR *c);
UINT CedarGetFifoBudgetConsuming(CEDAR *c);
UINT CedarGetQueueBudgetBalance(CEDAR *c);
UINT CedarGetFifoBudgetBalance(CEDAR *c);



#endif

