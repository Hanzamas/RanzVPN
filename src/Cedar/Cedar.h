// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module
// © 2020 Nokia

// Cedar.h
// Header of Cedar.c

#ifndef	CEDAR_H
#define	CEDAR_H

#include "CedarType.h"
#include "GlobalConst.h"

#include "Mayaqua/Network.h"

//////////////////////////////////////////////////////////////////////
// 
// Products related constants
// 
//////////////////////////////////////////////////////////////////////

// Version number
#ifndef	CEDAR_VERSION_MAJOR
#define	CEDAR_VERSION_MAJOR		0
#endif	// CEDAR_VERSION_MAJOR

#ifndef	CEDAR_VERSION_MINOR
#define	CEDAR_VERSION_MINOR		0
#endif	// CEDAR_VER_MINOR

// Build number
#ifndef	CEDAR_VERSION_BUILD
#define	CEDAR_VERSION_BUILD		0
#endif	// CEDAR_VERSION_BUILD

// The version above (major.minor.build) is for display only. Peers receive
// and compare these fixed values instead (hello/welcome packs, node info,
// admin RPC, server caps), kept at the last SoftEther VPN 5.02 build 5187
// so that existing peers keep gating features the same way.
#define	CEDAR_WIRE_VER			502		// Major * 100 + minor
#define	CEDAR_WIRE_BUILD		5187

// RC or not
#define	RELEASE_CANDIDATE

// Specify the name of the person in charge building
#ifndef	BUILDER_NAME
#define	BUILDER_NAME			"Unknown"
#endif	// BUILDER_NAME

// Specify the location to build
#ifndef	BUILD_PLACE
#define	BUILD_PLACE				"Unknown"
#endif	// BUILD_PLACE

// Specifies the build date
#ifndef	BUILD_DATE_Y
#define	BUILD_DATE_Y			1970
#endif	// BUILD_DATE_Y

#ifndef	BUILD_DATE_M
#define	BUILD_DATE_M			1
#endif	// BUILD_DATE_M

#ifndef	BUILD_DATE_D
#define	BUILD_DATE_D			1
#endif	// BUILD_DATE_D

#ifndef	BUILD_DATE_HO
#define	BUILD_DATE_HO			0
#endif	// BUILD_DATE_HO

#ifndef	BUILD_DATE_MI
#define	BUILD_DATE_MI			0
#endif	// BUILD_DATE_MI

#ifndef	BUILD_DATE_SE
#define	BUILD_DATE_SE			0
#endif	// BUILD_DATE_SE


// Configuration of communication related control switch
#define	USE_DOS_ATTACK_DETECTION		// Enable the DOS attack detection

// Default separator character for the hub name in the username
#define	DEFAULT_USERNAME_HUB_SEPARATOR	'@'


//////////////////////////////////////////////////////////////////////
// 
// Definition of the maximum length of various string
// 
//////////////////////////////////////////////////////////////////////

#define	MAX_ACCOUNT_NAME_LEN		255		// Maximum account name length
#define	MAX_USERNAME_LEN			255		// User name maximum length
#define	MAX_PASSWORD_LEN			255		// Password name maximum length
#define	MAX_SERVER_STR_LEN			255		// Maximum length of server string
#define	MAX_CLIENT_STR_LEN			255		// Maximum length of client string
#define	MAX_HUBNAME_LEN				255		// Maximum length of HUB name
#define	MAX_SESSION_NAME_LEN		255		// Session name maximum length
#define	MAX_CONNECTION_NAME_LEN		255		// Maximum length of connection name
#define	MAX_DEVICE_NAME_LEN			31		// Device name maximum length
#define	MAX_ACCESSLIST_NOTE_LEN		255		// Maximum length of the note of access list entry
#define	MAX_SECURE_DEVICE_FILE_LEN	255		// Secure device file name maximum length
#define	MAX_ADMIN_OPTION_NAME_LEN	63		// Management option name
#define	MAX_REDIRECT_URL_LEN		255		// URL length to redirect


//////////////////////////////////////////////////////////////////////
// 
// Server and session management related constants
// 
//////////////////////////////////////////////////////////////////////

#define SERVER_MAX_SESSIONS_FOR_CARRIER_EDITION	100000	// Maximum number of sessions that the server supports (Carrier Edition)
#define	MAX_HUBS					4096	// The maximum number of virtual HUB
#define	MAX_ACCESSLISTS				(4096 * 8)	// Maximum number of access list entries
#define	MAX_USERS					10000	// The maximum number of users
#define	MAX_GROUPS					10000	// Maximum number of groups
#define	MAX_MAC_TABLES				VPN_GP(GP_MAX_MAC_TABLES, 65536)	// Maximum number of MAC address table entries
#define	MAX_IP_TABLES				VPN_GP(GP_MAX_IP_TABLES, 65536)	// Maximum number of IP address table entries
#define	MAX_HUB_CERTS				4096	// Maximum number of Root CA that can be registered
#define	MAX_HUB_CRLS				4096	// Maximum number of CRL that can be registered
#define	MAX_HUB_ACS					4096	// Maximum number of AC that can be registered
#define	MAX_HUB_LINKS				VPN_GP(GP_MAX_HUB_LINKS, 1024)	// Maximum number of Cascade that can be registered
#define	MAX_HUB_ADMIN_OPTIONS		4096	// Maximum number of Virtual HUB management options that can be registered

#define	MEM_FIFO_REALLOC_MEM_SIZE	VPN_GP(GP_MEM_FIFO_REALLOC_MEM_SIZE, (65536 * 10))
#define	QUEUE_BUDGET				VPN_GP(GP_QUEUE_BUDGET, 2048)
#define	FIFO_BUDGET					VPN_GP(GP_FIFO_BUDGET, 1600 * 1600 * 4)

#define	MAX_PACKET_SIZE				1600	// Maximum packet size
#define	UDP_BUF_SIZE				(32 * 1024) // Aim of the UDP packet size

#define	MAX_SEND_SOCKET_QUEUE_SIZE	VPN_GP(GP_MAX_SEND_SOCKET_QUEUE_SIZE, (1600 * 1600 * 1))	// Maximum transmit queue size
#define	MIN_SEND_SOCKET_QUEUE_SIZE	VPN_GP(GP_MIN_SEND_SOCKET_QUEUE_SIZE, (1600 * 200 * 1))	// Minimum transmit queue size
#define	MAX_STORED_QUEUE_NUM		VPN_GP(GP_MAX_STORED_QUEUE_NUM, 1024)		// The number of queues that can be stored in each session
#define	MAX_BUFFERING_PACKET_SIZE	VPN_GP(GP_MAX_BUFFERING_PACKET_SIZE, (1600 * 1600))	// Maximum packet size can be buffered

#define	MAX_SEND_SOCKET_QUEUE_NUM	VPN_GP(GP_MAX_SEND_SOCKET_QUEUE_NUM, 128)		// Maximum number of transmission queue items per processing
#define	MAX_TCP_CONNECTION			32		// The maximum number of TCP connections
#define	SELECT_TIME					VPN_GP(GP_SELECT_TIME, 256)
#define	SELECT_TIME_FOR_NAT			VPN_GP(GP_SELECT_TIME_FOR_NAT, 30)

#define	TIMEOUT_MIN					(5 * 1000)	// Minimum timeout in seconds
#define	TIMEOUT_MAX					(60 * 1000)	// Maximum timeout in seconds
#define	TIMEOUT_DEFAULT				(30 * 1000) // Default number of seconds to timeout
#define	CONNECTING_TIMEOUT			(15 * 1000)	// Timeout in seconds of being connected
#define	CONNECTING_POOLING_SPAN		(3 * 1000) // Polling interval of connected
#define	MIN_RETRY_INTERVAL			(5 * 1000)		// Minimum retry interval
#define	MAX_RETRY_INTERVAL			(300 * 1000)	// Maximum retry interval
#define	RETRY_INTERVAL_SPECIAL		(60 * 1000)		// Reconnection interval of a special case

#define	ADDITIONAL_CONNECTION_COUNTER_RESET_INTERVAL	(30 * 60 * 1000)	// Reset period of additional connection failure counter

#define	MAC_MIN_LIMIT_COUNT			3		// Minimum number of MAC addresses
#define	IP_MIN_LIMIT_COUNT			4		// Number of IPv4 addresses minimum
#define	IP_MIN_LIMIT_COUNT_V6		5		// Number of IPv6 addresses minimum
#define	IP_LIMIT_WHEN_NO_ROUTING_V6	15		// Maximum number of IPv6 addresses when NoRouting policy is enabled

#define	MAC_TABLE_EXCLUSIVE_TIME	(13 * 1000)			// Period that can occupy the MAC address
#define	IP_TABLE_EXCLUSIVE_TIME		(13 * 1000)			// Period that can occupy the IP address
#define	MAC_TABLE_EXPIRE_TIME		VPN_GP(GP_MAC_TABLE_EXPIRE_TIME, (600 * 1000))			// MAC address table expiration time
#define	IP_TABLE_EXPIRE_TIME		VPN_GP(GP_IP_TABLE_EXPIRE_TIME, (60 * 1000))			// IP address table expiration time
#define	IP_TABLE_EXPIRE_TIME_DHCP	VPN_GP(GP_IP_TABLE_EXPIRE_TIME_DHCP, (5 * 60 * 1000))		// IP address table expiration time (In the case of DHCP)
#define	HUB_ARP_SEND_INTERVAL		VPN_GP(GP_HUB_ARP_SEND_INTERVAL, (5 * 1000))			// ARP packet transmission interval (alive check)

#define	LIMITER_SAMPLING_SPAN		1000	// Sampling interval of the traffic limiting device

#define	STORM_CHECK_SPAN			VPN_GP(GP_STORM_CHECK_SPAN, 500)		// Broadcast storm check interval
#define	STORM_DISCARD_VALUE_START	VPN_GP(GP_STORM_DISCARD_VALUE_START, 3)		// Broadcast packet discard value start value
#define	STORM_DISCARD_VALUE_END		VPN_GP(GP_STORM_DISCARD_VALUE_END, 1024)	// Broadcast packet discard value end value




#define DH_PARAM_BITS_DEFAULT		2048		// Bits of Diffie-Hellman Parameters


#define	SE_UDP_SIGN			"SE2P"		// Not used (only old UDP mode)

// Traffic information update interval
#define	INCREMENT_TRAFFIC_INTERVAL		(10 * 1000)

// State of the client session
#define	CLIENT_STATUS_CONNECTING	0		// Connecting
#define	CLIENT_STATUS_NEGOTIATION	1		// Negotiating
#define	CLIENT_STATUS_AUTH			2		// During user authentication
#define	CLIENT_STATUS_ESTABLISHED	3		// Connection complete
#define	CLIENT_STATUS_RETRY			4		// Wait to retry
#define	CLIENT_STATUS_IDLE			5		// Idle state

// Blocks to be transmitted at one during the file transfer
#define	FTP_BLOCK_SIZE				(640 * 1024)

// Syslog configuration
#define SYSLOG_NONE							0		// Do not use syslog
#define SYSLOG_SERVER_AND_HUB_SECURITY_LOG	2		// Server and Virtual HUB security log
#define SYSLOG_SERVER_AND_HUB_ALL_LOG		3		// Server, Virtual HUB security, and packet log

#define SYSLOG_PORT					514			// Syslog port number
#define SYSLOG_POLL_IP_INTERVAL		(UINT64)(3600 * 1000)	// Interval to examine the IP address
#define	SYSLOG_POLL_IP_INTERVAL_NG	(UINT64)(60 * 1000)	// Interval to examine the IP address (previous failure)

//////////////////////////////////////////////////////////////////////
// 
// Connection-related constant
// 
//////////////////////////////////////////////////////////////////////

// Constants
#define	RECV_BUF_SIZE				65536			// Buffer size to be received at a time

// Type of proxy
#define	PROXY_DIRECT			0	// Direct TCP connection
#define	PROXY_HTTP				1	// Connection via HTTP proxy server
#define	PROXY_SOCKS				2	// Connection via SOCKS4 proxy server
#define	PROXY_SOCKS5			3	// Connection via SOCKS5 proxy server

// Direction of data flow
#define	TCP_BOTH				0	// Bi-directional
#define	TCP_SERVER_TO_CLIENT	1	// Only server -> client direction
#define	TCP_CLIENT_TO_SERVER	2	// Only client -> server direction

// Type of connection
#define	CONNECTION_TYPE_CLIENT			0	// Client
#define	CONNECTION_TYPE_INIT			1	// During initialization
#define	CONNECTION_TYPE_LOGIN			2	// Login connection
#define	CONNECTION_TYPE_ADDITIONAL		3	// Additional connection
#define	CONNECTION_TYPE_ADMIN_RPC		5	// RPC for Management
#define	CONNECTION_TYPE_ENUM_HUB		6	// HUB enumeration
#define	CONNECTION_TYPE_PASSWORD		7	// Password change

// Protocol
#define	CONNECTION_TCP					0	// TCP protocol
#define	CONNECTION_UDP					1	// UDP protocol
#define	CONNECTION_HUB_BRIDGE			7	// Bridge session
#define	CONNECTION_HUB_LINK_SERVER		9	// HUB link session


// Status
#define	CONNECTION_STATUS_ACCEPTED		0	// The connection is accepted (client side)
#define	CONNECTION_STATUS_NEGOTIATION	1	// Negotiating
#define	CONNECTION_STATUS_USERAUTH		2	// During user authentication
#define	CONNECTION_STATUS_ESTABLISHED	3	// Connection has been established
#define	CONNECTION_STATUS_CONNECTING	0	// Connecting (client side)

// Magic number of KeepAlive packet
#define	KEEP_ALIVE_MAGIC				0xffffffff
#define	MAX_KEEPALIVE_SIZE				512



//////////////////////////////////////////////////////////////////////
// 
// Virtual HUB-related constant
// 
//////////////////////////////////////////////////////////////////////

#define	SE_HUB_MAC_ADDR_SIGN				0xAE					// Sign virtual HUB MAC address

// Related to delay, jitter, packet loss in the access list
#define	HUB_ACCESSLIST_DELAY_MAX	10000		// Maximum delay
#define	HUB_ACCESSLIST_JITTER_MAX	100			// Maximum jitter
#define	HUB_ACCESSLIST_LOSS_MAX		100			// Maximum packet loss

// Message related
#define	HUB_MAXMSG_LEN				20000		// The maximum number of characters in a message



//////////////////////////////////////////////////////////////////////
// 
// Type of user authentication
// 
//////////////////////////////////////////////////////////////////////

// Constant in the server-side
#define	AUTHTYPE_ANONYMOUS				0			// Anonymous authentication
#define	AUTHTYPE_PASSWORD				1			// Password authentication
#define	AUTHTYPE_USERCERT				2			// User certificate authentication
#define	AUTHTYPE_ROOTCERT				3			// Root certificate which is issued by trusted Certificate Authority
#define	AUTHTYPE_NT						5			// Windows NT authentication
#define AUTHTYPE_EXTERNAL				96			// External authentication (completed)

// Constant of the client side
#define	CLIENT_AUTHTYPE_ANONYMOUS		0			// Anonymous authentication
#define	CLIENT_AUTHTYPE_PASSWORD		1			// Password authentication
#define	CLIENT_AUTHTYPE_PLAIN_PASSWORD	2			// Plain password authentication
#define	CLIENT_AUTHTYPE_CERT			3			// Certificate authentication
#define	CLIENT_AUTHTYPE_OPENSSLENGINE			5			// Openssl engine authentication



//////////////////////////////////////////////////////////////////////
// 
// TCP listener related constants
// 
//////////////////////////////////////////////////////////////////////

// Retries in case it fails to Listen
#define	LISTEN_RETRY_TIME			(2 * 1000)		// If fail to Listen normally
#define LISTEN_RETRY_TIME_NOIPV6	(60 * 1000)		// If IPv6 support is disabled

#define	DOS_TABLE_EXPIRES_FIRST		250				// Initial value of the expiration date of DOS attack list
#define	DOS_TABLE_EXPIRES_MAX		1000			// Maximum value of the expiration date of DOS attack list
#define	DOS_TABLE_REFRESH_INTERVAL	(10 * 1000)		// Interval to update the DOS attack list
#define	DOS_TABLE_MAX_LIMIT_PER_IP	16				// Accessible number per an IP
#define	DOS_TABLE_EXPIRES_TOTAL		(3000 * 1000)	// Time to force delete the entry


// Protocol to be used for the listener
#define	LISTENER_TCP				0		// TCP/IP
#define	LISTENER_UDP				1		// UDP/IP (not being used)

// Status of the listener
#define	LISTENER_STATUS_TRYING		0		// While attempting
#define	LISTENER_STATUS_LISTENING	1		// Listening

// Largest packet size of UDP
#define	UDP_PACKET_SIZE				65536

// Number of standard connections per IP address
#define DEFAULT_MAX_CONNECTIONS_PER_IP	256
#define MIN_MAX_CONNECTIONS_PER_IP	10		// Minimum value

// Allowed number of outstanding connections
#define	DEFAULT_MAX_UNESTABLISHED_CONNECTIONS	1000


//////////////////////////////////////////////////////////////////////
// 
// Log related constant
// 
//////////////////////////////////////////////////////////////////////

#define	LOG_ENGINE_SAVE_START_CACHE_COUNT	100000		// Number to start saving forcibly
#define	LOG_ENGINE_BUFFER_CACHE_SIZE_MAX	(10 * 1024 * 1024)	// Write cache size

// Constant such as a file name
//
// These placeholders will be replaced in InnerFilePathW().
//
// @ - placeholder for LogDir
// $ - placeholder for DbDir (config directory)
//
#define	SERVER_LOG_DIR				"server_log"
#define	SERVER_LOG_DIR_NAME			"@"SERVER_LOG_DIR
#define	BRIDGE_LOG_DIR_NAME			SERVER_LOG_DIR_NAME
#define	SERVER_LOG_PERFIX			"vpn"

#define	HUB_SECURITY_LOG_DIR		"security_log"
#define	HUB_SECURITY_LOG_DIR_NAME	"@"HUB_SECURITY_LOG_DIR
#define	HUB_SECURITY_LOG_FILE_NAME	HUB_SECURITY_LOG_DIR_NAME"/%s"
#define	HUB_SECURITY_LOG_PREFIX		"sec"
#define	HUB_PACKET_LOG_DIR		"packet_log"
#define	HUB_PACKET_LOG_DIR_NAME		"@"HUB_PACKET_LOG_DIR
#define	HUB_PACKET_LOG_FILE_NAME	HUB_PACKET_LOG_DIR_NAME"/%s"
#define	HUB_PACKET_LOG_PREFIX		"pkt"

// Packet log settings
#define	NUM_PACKET_LOG				16
#define	PACKET_LOG_TCP_CONN			0		// TCP connection log
#define	PACKET_LOG_TCP				1		// TCP packet log
#define	PACKET_LOG_DHCP				2		// DHCP Log
#define	PACKET_LOG_UDP				3		// UDP log
#define	PACKET_LOG_ICMP				4		// ICMP log
#define	PACKET_LOG_IP				5		// IP log
#define	PACKET_LOG_ARP				6		// ARP log
#define	PACKET_LOG_ETHERNET			7		// Ethernet log

#define	PACKET_LOG_NONE				0		// Not save
#define	PACKET_LOG_HEADER			1		// Only header
#define	PACKET_LOG_ALL				2		// Store also data

// Timing of log switching
#define	LOG_SWITCH_NO				0		// No switching
#define	LOG_SWITCH_SECOND			1		// Secondly basis
#define	LOG_SWITCH_MINUTE			2		// Minutely basis
#define	LOG_SWITCH_HOUR				3		// Hourly basis
#define	LOG_SWITCH_DAY				4		// Daily basis
#define	LOG_SWITCH_MONTH			5		// Monthly basis

// Minimum amount of free disk space
#define	DISK_FREE_SPACE_MIN			1048576	// 1 MBytes
#define	DISK_FREE_SPACE_DEFAULT		(DISK_FREE_SPACE_MIN * 100)	// 100 Mbytes
#define	DISK_FREE_SPACE_DEFAULT_WINDOWS	((UINT64)(8ULL * 1024ULL * 1024ULL * 1024ULL))	// 8GBytes

// Interval to check the free space
#define	DISK_FREE_CHECK_INTERVAL_DEFAULT	(5 * 60 * 1000)

// Simple log
#define TINY_LOG_DIRNAME			"@tiny_log"
#define TINY_LOG_FILENAME			"@tiny_log/%04u%02u%02u_%02u%02u%02u.log"


//////////////////////////////////////////////////////////////////////
// 
// Communication protocol related constant
// 
//////////////////////////////////////////////////////////////////////

// Administrator Username
#define	ADMINISTRATOR_USERNAME		"administrator"
// Management allowed IP address list file name
#define	ADMINIP_TXT					"$adminip.txt"

#define NON_SSL_MIN_COUNT			60
#define NON_SSL_ENTRY_EXPIRES		(10 * 60 * 1000)

//////////////////////////////////////////////////////////////////////
// 
// The cascade related constants
// 
//////////////////////////////////////////////////////////////////////

#define	LINK_DEVICE_NAME		"_SEHUBLINKCLI_"
#define	LINK_USER_NAME			"link"
#define	LINK_USER_NAME_PRINT	"Cascade"



//////////////////////////////////////////////////////////////////////
// 
// Constant related to bridge connection
// 
//////////////////////////////////////////////////////////////////////

#define	BRIDGE_DEVICE_NAME				"_SEHUBBRIDGE_"
#define	BRIDGE_USER_NAME				"localbridge"
#define	BRIDGE_USER_NAME_PRINT			"Local Bridge"
#define	BRIDGE_TRY_SPAN					1000
#define	BRIDGE_NUM_DEVICE_CHECK_SPAN	(5 * 60 * 1000)



//////////////////////////////////////////////////////////////////////
// 
// Constant related to the virtual IP stack
// 
//////////////////////////////////////////////////////////////////////



#define	LICENSE_EDITION_VPN3_NO_LICENSE					0		// Without license

#define	LICENSE_MAX_PRODUCT_NAME_LEN	255				// Maximum length of license product name
#define	LICENSE_KEYSTR_LEN				41				// Length of the license key
#define	LICENSE_LICENSEID_STR_LEN		33				// Length of the license ID

#define	LICENSE_STATUS_OK				0		// Enabled
#define	LICENSE_STATUS_EXPIRED			1		// Invalid (expired)
#define	LICENSE_STATUS_ID_DIFF			2		// Invalid (System ID mismatch)
#define	LICENSE_STATUS_DUP				3		// Invalid (duplicated)
#define	LICENSE_STATUS_INSUFFICIENT		4		// Invalid (other necessary license shortage)
#define	LICENSE_STATUS_COMPETITION		5		// Invalid (conflict with other licenses)
#define	LICENSE_STATUS_NONSENSE			6		// Invalid (meaningless in the current edition)
#define	LICENSE_STATUS_CPU				7		// Invalid (CPU type mismatch)



//////////////////////////////////////////////////////////////////////
// 
// Error code
// 
//////////////////////////////////////////////////////////////////////

#define	ERR_NO_ERROR					0	// No error
#define	ERR_CONNECT_FAILED				1	// Connection to the server has failed
#define	ERR_SERVER_IS_NOT_VPN			2	// The destination server is not a VPN server
#define	ERR_DISCONNECTED				3	// The connection has been interrupted
#define	ERR_PROTOCOL_ERROR				4	// Protocol error
#define	ERR_CLIENT_IS_NOT_VPN			5	// Connecting client is not a VPN client
#define	ERR_USER_CANCEL					6	// User cancel
#define	ERR_AUTHTYPE_NOT_SUPPORTED		7	// Specified authentication method is not supported
#define	ERR_HUB_NOT_FOUND				8	// The HUB does not exist
#define	ERR_AUTH_FAILED					9	// Authentication failure
#define	ERR_HUB_STOPPING				10	// HUB is stopped
#define	ERR_SESSION_REMOVED				11	// Session has been deleted
#define	ERR_ACCESS_DENIED				12	// Access denied
#define	ERR_SESSION_TIMEOUT				13	// Session times out
#define	ERR_INVALID_PROTOCOL			14	// Protocol is invalid
#define	ERR_TOO_MANY_CONNECTION			15	// Too many connections
#define	ERR_HUB_IS_BUSY					16	// Too many sessions of the HUB
#define	ERR_PROXY_CONNECT_FAILED		17	// Connection to the proxy server fails
#define	ERR_PROXY_ERROR					18	// Proxy Error
#define	ERR_PROXY_AUTH_FAILED			19	// Failed to authenticate on the proxy server
#define	ERR_TOO_MANY_USER_SESSION		20	// Too many sessions of the same user
#define	ERR_LICENSE_ERROR				21	// License error
#define	ERR_DEVICE_DRIVER_ERROR			22	// Device driver error
#define	ERR_INTERNAL_ERROR				23	// Internal error
#define	ERR_OBJECT_NOT_FOUND			29	// Specified object can not be found
#define	ERR_NOT_SUPPORTED				33	// Unsupported
#define	ERR_INVALID_PARAMETER			38	// Parameter is invalid
#define	ERR_NULL_PASSWORD_LOCAL_ONLY	51	// Accepting only local connections for an empty password
#define	ERR_NOT_ENOUGH_RIGHT			52	// Right is insufficient
#define	ERR_LISTENER_NOT_FOUND			53	// Listener can not be found
#define	ERR_LISTENER_ALREADY_EXISTS		54	// Listener already exists
#define	ERR_HUB_ALREADY_EXISTS			57	// HUB already exists
#define	ERR_TOO_MANY_HUBS				58	// Too many HUBs
#define	ERR_LINK_ALREADY_EXISTS			59	// Link already exists
#define	ERR_LINK_IS_OFFLINE				61	// Link is off-line
#define	ERR_TOO_MANY_ACCESS_LIST		62	// Too many access list
#define	ERR_TOO_MANY_USER				63	// Too many users
#define	ERR_TOO_MANY_GROUP				64	// Too many Groups
#define	ERR_GROUP_NOT_FOUND				65	// Group can not be found
#define	ERR_USER_ALREADY_EXISTS			66	// User already exists
#define	ERR_GROUP_ALREADY_EXISTS		67	// Group already exists
#define	ERR_USER_AUTHTYPE_NOT_PASSWORD	68	// Authentication method of the user is not a password authentication
#define	ERR_OLD_PASSWORD_WRONG			69	// The user does not exist or the old password is wrong
#define	ERR_LINK_CANT_DISCONNECT		73	// Cascade session cannot be disconnected
#define	ERR_NOT_RSA_1024				77	// The certificate is not RSA 1024bit
#define	ERR_BRIDGE_CANT_DISCONNECT		82	// Bridge session can not be disconnected
#define	ERR_LOCAL_BRIDGE_UNSUPPORTED	84	// Bridge feature is not supported
#define	ERR_CERT_NOT_TRUSTED			85	// Certificate of the destination server can not be trusted
#define	ERR_VERSION_INVALID				87	// Version is different
#define	ERR_SERVER_CANT_ACCEPT			105	// Not Accept on the technical issues
#define	ERR_SERVER_CERT_EXPIRES			106	// Destination VPN server has expired
#define	ERR_MONITOR_MODE_DENIED			107	// Monitor port mode was rejected
#define	ERR_BRIDGE_MODE_DENIED			108	// Bridge-mode or Routing-mode was rejected
#define	ERR_IP_ADDRESS_DENIED			109	// Client IP address is denied
#define	ERR_TOO_MANT_ITEMS				110	// Too many items
#define	ERR_MEMORY_NOT_ENOUGH			111	// Out of memory
#define	ERR_OBJECT_EXISTS				112	// Object already exists
#define	ERR_BAD_COMMAND_OR_PARAM		117	// Command or parameter is invalid
#define ERR_NOT_ADMINPACK_SERVER		121	// Not trying to connect to a server with the Administrator Pack license
#define ERR_BRANDED_C_TO_S				124 // Branding string of connection limit is different (Authentication on the server side)
#define ERR_BRANDED_C_FROM_S			125	// Branding string of connection limit is different (Authentication for client-side)
#define	ERR_CLIENT_ID_REQUIRED			127	// Client ID does not match
#define	ERR_TOO_MANY_USERS_CREATED		128	// Too many created users
#define	ERR_MSCHAP2_PASSWORD_NEED_RESET	138	// Necessary that password is changed
#define	ERR_NOT_SUPPORTED_AUTH_ON_OPENSOURCE	143	// It is the type of user authentication that are not supported in the open source version
#define	ERR_NOT_SUPPORTED_FUNCTION_ON_OPENSOURCE	147	// It is a feature that is not supported in the open source version
#define ERR_HOSTNAME_MISMATCH			149	// SSL hostname mismatch
#define ERR_SSL_PROTOCOL_VERSION		150 // SSL version not supported
#define ERR_SSL_SHARED_CIPHER			151 // Can't find common cipher
#define ERR_SSL_HANDSHAKE				152 // Other SSL handshake error


////////////////////////////
// Generally used structure

// Network Services
typedef struct NETSVC
{
	bool Udp;						// false=TCP, true=UDP
	UINT Port;						// Port number
	char *Name;						// Name
} NETSVC;

// Traffic data entry
typedef struct TRAFFIC_ENTRY
{
	UINT64 BroadcastCount;			// Number of broadcast packets
	UINT64 BroadcastBytes;			// Broadcast bytes
	UINT64 UnicastCount;			// Unicast count
	UINT64 UnicastBytes;			// Unicast bytes
} TRAFFIC_ENTRY;

// Traffic data
struct TRAFFIC
{
	TRAFFIC_ENTRY Send;				// Transmitted data
	TRAFFIC_ENTRY Recv;				// Received data
};

// Non-SSL connection source
typedef struct NON_SSL
{
	IP IpAddress;					// IP address
	UINT64 EntryExpires;			// Expiration date of entry
	UINT Count;						// Number of connection count
} NON_SSL;

// Simple log storage
typedef struct TINY_LOG
{
	char FileName[MAX_PATH];		// File name
	IO *io;							// File
	LOCK *Lock;						// Lock
} TINY_LOG;

// CEDAR structure
struct CEDAR
{
	LOCK *lock;						// Lock
	REF *ref;						// Reference counter
	COUNTER *AcceptingSockets;		// Number of sockets in Accept
	UINT Type;						// Type
	LIST *ListenerList;				// Listener list
	LIST *HubList;					// HUB list
	LIST *ConnectionList;			// Negotiating connection list
	LIST *CaList;					// List of CA
	volatile bool Halt;				// Halt flag
	COUNTER *ConnectionIncrement;	// Connection increment counter
	X *ServerX;						// Server certificate
	K *ServerK;						// Private key of the server certificate
	LIST *ServerChain;				// Server trust chain
	char UsernameHubSeparator;		// Character which separates the username from the hub name
	char *CipherList;				// List of encryption algorithms
	UINT Version;					// Version information
	UINT Build;						// Build Number
	char *ServerStr;				// Server string
	char *MachineName;				// Computer name
	char *HttpUserAgent;			// HTTP user agent
	char *HttpAccept;				// HTTP Accept
	char *HttpAcceptLanguage;		// HTTP Accept Language
	char *HttpAcceptEncoding;		// HTTP Accept Encoding
	TRAFFIC *Traffic;				// Traffic information
	LOCK *TrafficLock;				// Traffic information lock
	LIST *UDPEntryList;				// UDP entry list
	COUNTER *CurrentSessions;		// The current number of sessions
	COUNTER *CurrentTcpConnections;	// Number of current TCP connections
	LIST *NetSvcList;				// Network service list
	char *VerString;				// Version string
	char *BuildInfo;				// Build Information
	struct SERVER *Server;			// Server
	UINT64 CreatedTick;				// Generation date and time
	bool CheckExpires;				// Check the expiration date
	struct LOG *DebugLog;			// Debug log
	UCHAR UniqueId[16];				// Unique ID
	LIST *LocalBridgeList;			// Local bridge list
	bool Bridge;					// Bridge version
	COUNTER *AssignedClientLicense;	// Number of assigned client licenses
	COUNTER *AssignedBridgeLicense;	// Number of assigned bridge licenses
	LIST *NonSslList;				// Non-SSL connection list
	UINT Beta;						// Beta number
	LOCK *CedarSuperLock;			// Cedar super lock!
	bool DisableIPv6Listener;		// Disable IPv6 listener
	UINT ClientId;					// Client ID
	UINT64 BuiltDate;				// Build Date
	LIST *UdpPortList;				// UDP port list in use
	LOCK *CurrentRegionLock;		// Current region lock
	char CurrentRegion[128];		// Current region
	LOCK *CurrentTcpQueueSizeLock;	// Current TCP send queue size lock
	UINT CurrentTcpQueueSize;		// Current TCP send queue size
	COUNTER *CurrentActiveLinks;	// Current active cascade connections
	LOCK *QueueBudgetLock;			// Queue budget lock
	UINT QueueBudget;				// Queue budget
	LOCK *FifoBudgetLock;			// Fifo budget lock
	UINT FifoBudget;				// Fifo budget
	SSL_ACCEPT_SETTINGS SslAcceptSettings;	// SSL Accept Settings
	UINT DhParamBits;  // Bits of Diffie-Hellman parameters
	char StunServer[MAX_HOST_NAME_LEN + 1];	// STUN server (host[:port]) for UDP acceleration, empty = STUN disabled
};

////////////////////////////
// Function prototype

TRAFFIC *NewTraffic();
void FreeTraffic(TRAFFIC *t);
CEDAR *NewCedar(X *server_x, K *server_k);
void CedarForceLink();
void RegistWindowsFirewallAll();
void SetCedarVpnBridge(CEDAR *c);
void SetCedarCert(CEDAR *c, X *server_x, K *server_k);
void SetCedarCertAndChain(CEDAR *c, X *server_x, K *server_k, LIST *server_chain);
void ReleaseCedar(CEDAR *c);
void CleanupCedar(CEDAR *c);
void StopCedar(CEDAR *c);
void AddListener(CEDAR *c, LISTENER *r);
void StopAllListener(CEDAR *c);
void AddTraffic(TRAFFIC *dst, TRAFFIC *diff);
void AddHub(CEDAR *c, HUB *h);
void DelHub(CEDAR *c, HUB *h);
void DelHubEx(CEDAR *c, HUB *h, bool no_lock);
void StopAllHub(CEDAR *c);
void StopAllConnection(CEDAR *c);
void AddConnection(CEDAR *cedar, CONNECTION *c);
UINT GetUnestablishedConnections(CEDAR *cedar);
void DelConnection(CEDAR *cedar, CONNECTION *c);
void SetCedarCipherList(CEDAR *cedar, char *name);
void InitCedar();
void FreeCedar();
void AddCa(CEDAR *cedar, X *x);
bool DeleteCa(CEDAR *cedar, UINT ptr);
void InitNetSvcList(CEDAR *cedar);
void FreeNetSvcList(CEDAR *cedar);
int CompareNetSvc(void *p1, void *p2);
char *GetSvcName(CEDAR *cedar, bool udp, UINT port);
UINT64 GetTrafficPacketSize(TRAFFIC *t);
UINT64 GetTrafficPacketNum(TRAFFIC *t);
void StopCedarLog();
int CompareNoSslList(void *p1, void *p2);
void InitNoSslList(CEDAR *c);
void FreeNoSslList(CEDAR *c);
bool AddNoSsl(CEDAR *c, IP *ip);
void DecrementNoSsl(CEDAR *c, IP *ip, UINT num_dec);
void DeleteOldNoSsl(CEDAR *c);
NON_SSL *SearchNoSslList(CEDAR *c, IP *ip);
bool IsInNoSsl(CEDAR *c, IP *ip);
void FreeTinyLog(TINY_LOG *t);
void WriteTinyLog(TINY_LOG *t, char *str);
TINY_LOG *NewTinyLog();
void GetWinVer(RPC_WINVER *v);
void Win32GetWinVer(RPC_WINVER *v);
bool IsSupportedWinVer(RPC_WINVER *v);
UINT GetCedarVersionNumber();
void CedarAddCurrentTcpQueueSize(CEDAR *c, int diff);
UINT CedarGetCurrentTcpQueueSize(CEDAR *c);
void CedarAddQueueBudget(CEDAR *c, int diff);
void CedarAddFifoBudget(CEDAR *c, int diff);
UINT CedarGetQueueBudgetConsuming(CEDAR *c);
UINT CedarGetFifoBudgetConsuming(CEDAR *c);
UINT CedarGetQueueBudgetBalance(CEDAR *c);
UINT CedarGetFifoBudgetBalance(CEDAR *c);



#endif	// CEDAR_H

