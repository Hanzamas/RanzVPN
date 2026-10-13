// MayaType.h
// Mayaqua Kernel type declaration header file

#ifndef	MAYATYPE_H
#define	MAYATYPE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#ifndef NTDDI_VERSION
#define	NTDDI_VERSION NTDDI_VISTA
#endif

#ifndef _WIN32_WINNT
#define _WIN32_WINNT _WIN32_WINNT_VISTA
#endif

#include <WinSock2.h>
#include <ws2ipdef.h>

#define	STD_SIZE			512
#define	MAX_SIZE			512

#define	SUPPORTED_WINDOWS_LIST		"Windows 10 / 11 / Server 2016 / Server 2019 / Server 2022"

#ifndef	INFINITE
#define	INFINITE			(0xFFFFFFFF)
#endif


#ifndef	MAX_PATH
#define	MAX_PATH			260
#endif

#ifndef	FILE_BEGIN
#define	FILE_BEGIN	SEEK_SET
#endif
#ifndef	FILE_END
#define	FILE_END	SEEK_END
#endif
#ifndef	FILE_CURRENT
#define	FILE_CURRENT	SEEK_CUR
#endif

#ifndef	INVALID_SOCKET
#define	INVALID_SOCKET		(-1)
#endif

#ifndef	SOCKET_ERROR
#define	SOCKET_ERROR		(-1)
#endif

typedef int (COMPARE)(void *p1, void *p2);


#ifdef	MAX
#undef	MAX
#endif

#ifdef	MIN
#undef	MIN
#endif

#define	MIN(a, b)			((a) >= (b) ? (b) : (a))
#define	MAX(a, b)			((a) >= (b) ? (a) : (b))

#define	INT_TO_BOOL(i)		(((i) == 0) ? false : true)
#define	MAKEBOOL(i)			INT_TO_BOOL(i)

#define	NEGATIVE_BOOL(i)	(((i) == false) ? true : false)

#define	LESS(a, max_value)	((a) <= (max_value) ? (a) : (max_value))
#define	MORE(a, min_value)	((a) >= (min_value) ? (a) : (min_value))
#define	INNER(a, b, c)		(((b) <= (c) && (a) >= (b) && (a) <= (c)) || ((b) >= (c) && (a) >= (c) && (a) <= (b)))
#define	OUTER(a, b, c)		(!INNER((a), (b), (c)))
#define	MAKESURE(a, b, c)		(((b) <= (c)) ? (MORE(LESS((a), (c)), (b))) : (MORE(LESS((a), (b)), (c))))
#define COMPARE_RET(a, b)	(((a) == (b)) ? 0 : (((a) > (b)) ? 1 : -1))
#define	EQUAL_BOOL(a, b)	(((a) && (b)) || ((!(a)) && (!(b))))

#define	POINTER_TO_KEY(p)		(HashPtrToUINT(p))

#define	POINTER_TO_UINT64(p)	(UINT64)(p)

#define	UINT64_TO_POINTER(i)	(void *)(i)

// Big-endian reads that work on unaligned buffers
#define	READ_USHORT(buf)		(USHORT)((((USHORT)((UCHAR *)(buf))[0]) << 8) | (((USHORT)((UCHAR *)(buf))[1])))
#define	READ_UINT(buf)			(UINT)((((UINT)((UCHAR *)(buf))[0]) << 24) | (((UINT)((UCHAR *)(buf))[1]) << 16) | (((UINT)((UCHAR *)(buf))[2]) << 8) | (((UINT)((UCHAR *)(buf))[3])))
#define	READ_UINT64(buf)		(UINT64)((((UINT64)((UCHAR *)(buf))[0]) << 56) | (((UINT64)((UCHAR *)(buf))[1]) << 48) | (((UINT64)((UCHAR *)(buf))[2]) << 40) | (((UINT64)((UCHAR *)(buf))[3]) << 32) | (((UINT64)((UCHAR *)(buf))[4]) << 24) | (((UINT64)((UCHAR *)(buf))[5]) << 16) | (((UINT64)((UCHAR *)(buf))[6]) << 8) | (((UINT64)((UCHAR *)(buf))[7])))

// Big-endian writes that work on unaligned buffers
#define	WRITE_USHORT(buf, i)	(((UCHAR *)(buf))[0]) = ((((USHORT)(i)) >> 8) & 0xFF); (((UCHAR *)(buf))[1]) = ((((USHORT)(i))) & 0xFF)
#define	WRITE_UINT(buf, i)		(((UCHAR *)(buf))[0]) = ((((UINT)(i)) >> 24) & 0xFF); (((UCHAR *)(buf))[1]) = ((((UINT)(i)) >> 16) & 0xFF); (((UCHAR *)(buf))[2]) = ((((UINT)(i)) >> 8) & 0xFF); (((UCHAR *)(buf))[3]) = ((((UINT)(i))) & 0xFF)
#define	WRITE_UINT64(buf, i)	(((UCHAR *)(buf))[0]) = ((((UINT64)(i)) >> 56) & 0xFF); (((UCHAR *)(buf))[1]) = ((((UINT64)(i)) >> 48) & 0xFF); (((UCHAR *)(buf))[2]) = ((((UINT64)(i)) >> 40) & 0xFF); (((UCHAR *)(buf))[3]) = ((((UINT64)(i)) >> 32) & 0xFF); (((UCHAR *)(buf))[4]) = ((((UINT64)(i)) >> 24) & 0xFF); (((UCHAR *)(buf))[5]) = ((((UINT64)(i)) >> 16) & 0xFF); (((UCHAR *)(buf))[6]) = ((((UINT64)(i)) >> 8) & 0xFF); (((UCHAR *)(buf))[7]) = ((((UINT64)(i))) & 0xFF)

typedef int64_t time_64t;

#define	OSTYPE_WINDOWS_10						2702
#define	OSTYPE_WINDOWS_SERVER_10				2712
#define	OSTYPE_WINDOWS_11						2800
#define	OSTYPE_WINDOWS_SERVER_11				2810
#define	OSTYPE_UNIX_UNKNOWN						3000
#define	OSTYPE_LINUX							3100
#define	OSTYPE_SOLARIS							3200
#define	OSTYPE_CYGWIN							3300
#define	OSTYPE_BSD								3400
#define	OSTYPE_MACOS_X							3500


#define	GET_KETA(t, i)			(((t) % (i * 10)) / i)
#define	OS_IS_WINDOWS(t)		((GET_KETA(t, 1000) == 1) || (GET_KETA(t, 1000) == 2))
#define	OS_IS_UNIX(t)			(GET_KETA(t, 1000) == 3)


typedef struct OS_INFO
{
	UINT OsType;
	UINT OsServicePack;
	char *OsSystemName;
	char *OsProductName;
	char *OsVendorName;
	char *OsVersion;
	char *KernelName;
	char *KernelVersion;
} OS_INFO;

typedef struct LOCK LOCK;
typedef struct COUNTER COUNTER;
typedef struct REF REF;
typedef struct EVENT EVENT;
typedef struct DEADCHECK DEADCHECK;

typedef struct CALLSTACK_DATA CALLSTACK_DATA;
typedef struct TRACKING_OBJECT TRACKING_OBJECT;
typedef struct MEMORY_STATUS MEMORY_STATUS;
typedef struct TRACKING_LIST TRACKING_LIST;

typedef struct IO IO;

typedef struct MEMTAG1 MEMTAG1;
typedef struct MEMTAG2 MEMTAG2;
typedef struct BUF BUF;
typedef struct FIFO FIFO;
typedef struct LIST LIST;
typedef struct QUEUE QUEUE;
typedef struct SK SK;
typedef struct CANDIDATE CANDIDATE;
typedef struct STRMAP_ENTRY STRMAP_ENTRY;
typedef struct SHARED_BUFFER SHARED_BUFFER;
typedef struct HASH_LIST HASH_LIST;
typedef struct PRAND PRAND;

typedef struct TOKEN_LIST TOKEN_LIST;
typedef struct INI_ENTRY INI_ENTRY;

typedef struct UNI_TOKEN_LIST UNI_TOKEN_LIST;

typedef struct CRYPT CRYPT;
typedef struct NAME NAME;
typedef struct X_SERIAL X_SERIAL;
typedef struct X X;
typedef struct K K;
typedef struct P12 P12;
typedef struct X_CRL X_CRL;
typedef struct DES_KEY_VALUE DES_KEY_VALUE;
typedef struct DES_KEY DES_KEY;
typedef struct DH_CTX DH_CTX;
typedef struct AES_KEY_VALUE AES_KEY_VALUE;
typedef struct CIPHER CIPHER;
typedef struct MD MD;

typedef struct MEMINFO MEMINFO;
typedef struct LOCALE LOCALE;
typedef struct THREAD THREAD;
typedef struct THREAD_POOL_DATA THREAD_POOL_DATA;
typedef struct INSTANCE INSTANCE;

typedef struct VALUE VALUE;
typedef struct ELEMENT ELEMENT;
typedef struct PACK PACK;

typedef struct FOLDER FOLDER;
typedef struct ITEM ITEM;
typedef struct CFG_RW CFG_RW;
typedef struct CFG_ENUM_PARAM CFG_ENUM_PARAM;

typedef struct TABLE TABLE;
typedef struct LANGLIST LANGLIST;

typedef struct IP IP;
typedef struct SOCK_EVENT SOCK_EVENT;
typedef struct SOCK SOCK;
typedef struct SOCKSET SOCKSET;
typedef struct CANCEL CANCEL;
typedef struct ROUTE_ENTRY ROUTE_ENTRY;
typedef struct ROUTE_TABLE ROUTE_TABLE;
typedef struct IP_CLIENT IP_CLIENT;
typedef struct ROUTE_CHANGE ROUTE_CHANGE;
typedef struct ROUTE_CHANGE_DATA ROUTE_CHANGE_DATA;
typedef struct WIN32_RELEASEADDRESS_THREAD_PARAM WIN32_RELEASEADDRESS_THREAD_PARAM;
typedef struct IPV6_ADDR IPV6_ADDR;
typedef struct UDPPACKET UDPPACKET;
typedef struct INTERRUPT_MANAGER INTERRUPT_MANAGER;
typedef struct ICMP_RESULT ICMP_RESULT;
typedef struct SSL_PIPE SSL_PIPE;
typedef struct SSL_BIO SSL_BIO;
typedef struct CONNECT_SERIAL_PARAM CONNECT_SERIAL_PARAM;
typedef struct SSL_VERIFY_OPTION SSL_VERIFY_OPTION;
typedef struct NIC_ENTRY NIC_ENTRY;
typedef struct HTTP_VALUE HTTP_VALUE;
typedef struct HTTP_HEADER HTTP_HEADER;
typedef struct IPBLOCK IPBLOCK;
typedef struct DYN_VALUE DYN_VALUE;
typedef struct SSL_ACCEPT_SETTINGS SSL_ACCEPT_SETTINGS;

typedef struct ADJUST_TIME ADJUST_TIME;
typedef struct TICK64 TICK64;

typedef struct DIRENT DIRENT;
typedef struct DIRLIST DIRLIST;
typedef struct ZIP_DATA_HEADER ZIP_DATA_HEADER;
typedef struct ZIP_DATA_FOOTER ZIP_DATA_FOOTER;
typedef struct ZIP_DIR_HEADER ZIP_DIR_HEADER;
typedef struct ZIP_END_HEADER ZIP_END_HEADER;
typedef struct ZIP_FILE ZIP_FILE;
typedef struct ZIP_PACKER ZIP_PACKER;

typedef struct MAC_HEADER MAC_HEADER;
typedef struct ARPV4_HEADER ARPV4_HEADER;
typedef struct IPV4_HEADER IPV4_HEADER;
typedef struct TAGVLAN_HEADER TAGVLAN_HEADER;
typedef struct UDP_HEADER UDP_HEADER;
typedef struct UDPV4_PSEUDO_HEADER UDPV4_PSEUDO_HEADER;
typedef struct IPV4_PSEUDO_HEADER IPV4_PSEUDO_HEADER;
typedef struct TCP_HEADER TCP_HEADER;
typedef struct ICMP_HEADER ICMP_HEADER;
typedef struct ICMP_ECHO ICMP_ECHO;
typedef struct DHCPV4_HEADER DHCPV4_HEADER;
typedef struct DNSV4_HEADER DNSV4_HEADER;
typedef struct BPDU_HEADER BPDU_HEADER;
typedef struct LLC_HEADER LLC_HEADER;
typedef struct PKT PKT;
typedef struct IPV6_HEADER_PACKET_INFO IPV6_HEADER_PACKET_INFO;
typedef struct IPV6_HEADER IPV6_HEADER;
typedef struct IPV6_OPTION_HEADER IPV6_OPTION_HEADER;
typedef struct IPV6_FRAGMENT_HEADER IPV6_FRAGMENT_HEADER;
typedef struct IPV6_PSEUDO_HEADER IPV6_PSEUDO_HEADER;
typedef struct ICMPV6_ROUTER_SOLICIATION_HEADER ICMPV6_ROUTER_SOLICIATION_HEADER;
typedef struct ICMPV6_ROUTER_ADVERTISEMENT_HEADER ICMPV6_ROUTER_ADVERTISEMENT_HEADER;
typedef struct ICMPV6_NEIGHBOR_SOLICIATION_HEADER ICMPV6_NEIGHBOR_SOLICIATION_HEADER;
typedef struct ICMPV6_NEIGHBOR_ADVERTISEMENT_HEADER ICMPV6_NEIGHBOR_ADVERTISEMENT_HEADER;
typedef struct ICMPV6_OPTION_LIST ICMPV6_OPTION_LIST;
typedef struct ICMPV6_OPTION ICMPV6_OPTION;
typedef struct ICMPV6_OPTION_LINK_LAYER ICMPV6_OPTION_LINK_LAYER;
typedef struct ICMPV6_OPTION_PREFIX ICMPV6_OPTION_PREFIX;
typedef struct ICMPV6_OPTION_MTU ICMPV6_OPTION_MTU;
typedef struct IPV6_HEADER_INFO IPV6_HEADER_INFO;
typedef struct ICMPV6_HEADER_INFO ICMPV6_HEADER_INFO;
typedef struct DHCPV4_DATA DHCPV4_DATA;
typedef struct DHCP_OPTION DHCP_OPTION;
typedef struct DHCP_OPTION_LIST DHCP_OPTION_LIST;
typedef struct DHCP_CLASSLESS_ROUTE DHCP_CLASSLESS_ROUTE;
typedef struct DHCP_CLASSLESS_ROUTE_TABLE DHCP_CLASSLESS_ROUTE_TABLE;
typedef struct HTTPLOG HTTPLOG;
typedef struct DHCP_MODIFY_OPTION DHCP_MODIFY_OPTION;
typedef struct NBTDG_HEADER NBTDG_HEADER;
typedef struct IKE_HEADER IKE_HEADER;

typedef struct HTTP_MIME_TYPE HTTP_MIME_TYPE;

typedef struct PROXY_PARAM_IN PROXY_PARAM_IN;
typedef struct PROXY_PARAM_OUT PROXY_PARAM_OUT;

typedef struct DNS_CACHE DNS_CACHE;
typedef struct DNS_CACHE_REVERSE DNS_CACHE_REVERSE;
typedef struct DNS_RESOLVER DNS_RESOLVER;
typedef struct DNS_RESOLVER_REVERSE DNS_RESOLVER_REVERSE;

#include "Crypto/Types.h"

#endif
