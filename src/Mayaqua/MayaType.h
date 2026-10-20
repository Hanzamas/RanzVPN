// MayaType.h
// Mayaqua Kernel type declaration header file

#ifndef	MAYATYPE_H
#define	MAYATYPE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// The Windows API level comes from the build, once: ranz_options (cmake/RanzOptions.cmake) sets
// Windows 10 version 1607 / Windows Server 2016 and WIN32_LEAN_AND_MEAN
#if !defined(_WIN32_WINNT) || (_WIN32_WINNT < 0x0A00) || !defined(NTDDI_VERSION) || (NTDDI_VERSION < 0x0A000002)
#error "Ranz VPN needs the Windows 10 version 1607 API level (_WIN32_WINNT 0x0A00, NTDDI_VERSION 0x0A000002), which the CMake target ranz_options sets"
#endif

#include <WinSock2.h>
#include <ws2ipdef.h>

#define	MAX_SIZE			512

#define	SUPPORTED_WINDOWS_LIST		"Windows 10 / 11 / Server 2016 / Server 2019 / Server 2022"

typedef int (COMPARE)(void *p1, void *p2);


#ifdef	MAX
#undef	MAX
#endif

#ifdef	MIN
#undef	MIN
#endif

// MIN/MAX (and LESS, MORE, MAKESURE, COMPARE_RET below) evaluate an argument twice: never
// pass one with a side effect (++, --, an assignment or a call that changes state)
#define	MIN(a, b)			((a) >= (b) ? (b) : (a))
#define	MAX(a, b)			((a) >= (b) ? (a) : (b))

#define	INT_TO_BOOL(i)		(((i) == 0) ? false : true)

#define	NEGATIVE_BOOL(i)	(((i) == false) ? true : false)

#define	LESS(a, max_value)	((a) <= (max_value) ? (a) : (max_value))
#define	MORE(a, min_value)	((a) >= (min_value) ? (a) : (min_value))
#define	MAKESURE(a, b, c)		(((b) <= (c)) ? (MORE(LESS((a), (c)), (b))) : (MORE(LESS((a), (b)), (c))))
#define COMPARE_RET(a, b)	(((a) == (b)) ? 0 : (((a) > (b)) ? 1 : -1))

#define	POINTER_TO_KEY(p)		(HashPtrToUINT(p))

#define	POINTER_TO_UINT64(p)	(UINT64)(p)

#define	UINT64_TO_POINTER(i)	(void *)(i)

// Byte order. Ranz VPN builds for little-endian Windows only (x64, arm64; Memory.c asserts it at
// compile time), so host and network order differ on every target: Endian16/32/64 swap always,
// on the compiler intrinsics (one bswap or rev instruction). Each one converts host to big-endian
// (network) order and back.
static inline USHORT Endian16(USHORT src)
{
	return _byteswap_ushort(src);
}
static inline UINT Endian32(UINT src)
{
	return (UINT)_byteswap_ulong(src);
}
static inline UINT64 Endian64(UINT64 src)
{
	return _byteswap_uint64(src);
}

// Big-endian loads and stores that work on unaligned buffers: one memcpy load or store plus a swap
static inline USHORT ReadBigEndian16(const void *buf)
{
	USHORT v;
	memcpy(&v, buf, sizeof(v));
	return Endian16(v);
}
static inline UINT ReadBigEndian32(const void *buf)
{
	UINT v;
	memcpy(&v, buf, sizeof(v));
	return Endian32(v);
}
static inline UINT64 ReadBigEndian64(const void *buf)
{
	UINT64 v;
	memcpy(&v, buf, sizeof(v));
	return Endian64(v);
}
static inline void WriteBigEndian16(void *buf, USHORT i)
{
	USHORT v = Endian16(i);
	memcpy(buf, &v, sizeof(v));
}
static inline void WriteBigEndian32(void *buf, UINT i)
{
	UINT v = Endian32(i);
	memcpy(buf, &v, sizeof(v));
}
static inline void WriteBigEndian64(void *buf, UINT64 i)
{
	UINT64 v = Endian64(i);
	memcpy(buf, &v, sizeof(v));
}

#define	READ_USHORT(buf)		ReadBigEndian16(buf)
#define	READ_UINT(buf)			ReadBigEndian32(buf)
#define	READ_UINT64(buf)		ReadBigEndian64(buf)

#define	WRITE_USHORT(buf, i)	WriteBigEndian16((buf), (USHORT)(i))
#define	WRITE_UINT(buf, i)		WriteBigEndian32((buf), (UINT)(i))
#define	WRITE_UINT64(buf, i)	WriteBigEndian64((buf), (UINT64)(i))

typedef int64_t time_64t;

#define	OSTYPE_WINDOWS_10						2702
#define	OSTYPE_WINDOWS_SERVER_10				2712
#define	OSTYPE_WINDOWS_11						2800
#define	OSTYPE_WINDOWS_SERVER_11				2810


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
typedef struct HASH_LIST HASH_LIST;

typedef struct TOKEN_LIST TOKEN_LIST;

typedef struct UNI_TOKEN_LIST UNI_TOKEN_LIST;

typedef struct CRYPT CRYPT;
typedef struct NAME NAME;
typedef struct X_SERIAL X_SERIAL;
typedef struct X X;
typedef struct K K;
typedef struct DH_CTX DH_CTX;
typedef struct CIPHER CIPHER;

typedef struct MEMINFO MEMINFO;
typedef struct LOCALE LOCALE;
typedef struct THREAD THREAD;
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
typedef struct IP_CLIENT IP_CLIENT;
typedef struct IPV6_ADDR IPV6_ADDR;
typedef struct CONNECT_SERIAL_PARAM CONNECT_SERIAL_PARAM;
typedef struct SSL_VERIFY_OPTION SSL_VERIFY_OPTION;
typedef struct NIC_ENTRY NIC_ENTRY;
typedef struct HTTP_VALUE HTTP_VALUE;
typedef struct HTTP_HEADER HTTP_HEADER;
typedef struct DYN_VALUE DYN_VALUE;
typedef struct SSL_ACCEPT_SETTINGS SSL_ACCEPT_SETTINGS;

typedef struct ADJUST_TIME ADJUST_TIME;
typedef struct TICK64 TICK64;

typedef struct DIRENT DIRENT;
typedef struct DIRLIST DIRLIST;

typedef struct MAC_HEADER MAC_HEADER;
typedef struct ARPV4_HEADER ARPV4_HEADER;
typedef struct IPV4_HEADER IPV4_HEADER;
typedef struct TAGVLAN_HEADER TAGVLAN_HEADER;
typedef struct UDP_HEADER UDP_HEADER;
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
typedef struct ICMPV6_HEADER_INFO ICMPV6_HEADER_INFO;
typedef struct DHCP_OPTION DHCP_OPTION;
typedef struct HTTPLOG HTTPLOG;
typedef struct DHCP_MODIFY_OPTION DHCP_MODIFY_OPTION;
typedef struct IKE_HEADER IKE_HEADER;

typedef struct PROXY_PARAM_IN PROXY_PARAM_IN;
typedef struct PROXY_PARAM_OUT PROXY_PARAM_OUT;

typedef struct DNS_CACHE DNS_CACHE;
typedef struct DNS_CACHE_REVERSE DNS_CACHE_REVERSE;
typedef struct DNS_RESOLVER DNS_RESOLVER;
typedef struct DNS_RESOLVER_REVERSE DNS_RESOLVER_REVERSE;

#include "Crypto/Types.h"

#endif
