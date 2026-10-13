// SoftEther VPN Source Code - Developer Edition Master Branch
// Mayaqua Kernel


// Network.c
// Network communication module

#include "Network.h"

#include "Cfg.h"
#include "DNS.h"
#include "FileIO.h"
#include "HTTP.h"
#include "Internat.h"
#include "Memory.h"
#include "Microsoft.h"
#include "Object.h"
#include "Pack.h"
#include "Str.h"
#include "TcpIp.h"
#include "Tick64.h"

#include <string.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#ifdef OS_WIN32
#include <iphlpapi.h>
#include <WS2tcpip.h>
#include <wincrypt.h>
#include <IcmpAPI.h>

struct ROUTE_CHANGE_DATA {
	HANDLE Handle;
	UINT NumCalled;
	bool Changed;
};
#endif

// HTTP constant
static char http_detect_server_startwith[] = "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\r\n<HTML><HEAD>\r\n<TITLE>403 Forbidden</TITLE>\r\n</HEAD><BODY>\r\n<H1>Forbidden</H1>\r\nYou don't have permission to access ";
static char http_detect_server_tag_future[] = "9C37197CA7C2428388C2E6E59B829B30";

// Lock related
static LOCK *machine_name_lock = NULL;
static LOCK *disconnect_function_lock = NULL;
extern LOCK *openssl_lock;
static COUNTER *num_tcp_connections = NULL;
static LIST *WaitThreadList = NULL;
static UCHAR machine_ip_process_hash[SHA1_SIZE];
static LOCK *machine_ip_process_hash_lock = NULL;
static LOCK *current_global_ip_lock = NULL;
static bool current_global_ip_set = false;
static IP current_glocal_ipv4 = {0};
static IP current_glocal_ipv6 = {0};
static LOCK *host_ip_address_list_cache_lock = NULL;
static UINT64 host_ip_address_list_cache_last = 0;
static LIST *host_ip_address_cache = NULL;
static bool disable_gethostname_by_accept = false;


static LIST *ip_clients = NULL;

static LIST *local_mac_list = NULL;
static LOCK *local_mac_list_lock = NULL;


static bool g_use_privateip_file = false;

static DH_CTX *dh_param = NULL;

typedef struct PRIVATE_IP_SUBNET {
	UINT Ip, Mask, Ip2;
} PRIVATE_IP_SUBNET;

static LIST *g_private_ip_list = NULL;


static LIST *g_dyn_value_list = NULL;




// Get a value from a dynamic value list (Returns a default value if the value is not found)
UINT64 GetDynValueOrDefault(char *name, UINT64 default_value, UINT64 min_value, UINT64 max_value) {
	UINT64 ret = GetDynValue(name);

	if (ret == 0) {
		return default_value;
	}

	if (ret < min_value) {
		ret = min_value;
	}

	if (ret > max_value) {
		ret = max_value;
	}

	return ret;
}

// Get a value from a dynamic value list (Returns a default value if the value is not found)
// The value is limited to 1/5 to 50 times of the default value for safety
UINT64 GetDynValueOrDefaultSafe(char *name, UINT64 default_value) {
	return GetDynValueOrDefault(name, default_value, default_value / (UINT64)5, default_value * (UINT64)50);
}

// Get a value from a dynamic value list
UINT64 GetDynValue(char *name) {
	UINT64 ret = 0;
	// Validate arguments
	if (name == NULL) {
		return 0;
	}

	if (g_dyn_value_list == NULL) {
		return 0;
	}

	LockList(g_dyn_value_list);
	{
		UINT i;

		for (i = 0; i < LIST_NUM(g_dyn_value_list); i++) {
			DYN_VALUE *vv = LIST_DATA(g_dyn_value_list, i);

			if (StrCmpi(vv->Name, name) == 0) {
				ret = vv->Value;
				break;
			}
		}
	}
	UnlockList(g_dyn_value_list);

	return ret;
}

// Initialization of the dynamic value list
void InitDynList() {
	g_dyn_value_list = NewList(NULL);
}

// Solution of dynamic value list
void FreeDynList() {
	UINT i;
	if (g_dyn_value_list == NULL) {
		return;
	}

	for (i = 0; i < LIST_NUM(g_dyn_value_list); i++) {
		DYN_VALUE *d = LIST_DATA(g_dyn_value_list, i);

		Free(d);
	}

	ReleaseList(g_dyn_value_list);

	g_dyn_value_list = NULL;
}

// Get the current time zone
int GetCurrentTimezone() {
	int ret = 0;

#ifdef OS_WIN32
	ret = GetCurrentTimezoneWin32();
#endif // OS_WIN32

	return ret;
}

#ifdef OS_WIN32
// Get the current time zone (Win32)
int GetCurrentTimezoneWin32() {
	TIME_ZONE_INFORMATION info;
	Zero(&info, sizeof(info));

	if (GetTimeZoneInformation(&info) == TIME_ZONE_ID_INVALID) {
		return 0;
	}

	return info.Bias;
}
#endif // OS_WIN32

// Check whether the specified MAC address exists on the local host (high speed)
bool IsMacAddressLocalFast(void *addr) {
	bool ret = false;
	// Validate arguments
	if (addr == NULL) {
		return false;
	}

	Lock(local_mac_list_lock);
	{
		if (local_mac_list == NULL) {
			// First enumeration
			RefreshLocalMacAddressList();
		}

		ret = IsMacAddressLocalInner(local_mac_list, addr);
	}
	Unlock(local_mac_list_lock);

	return ret;
}

// Update the local MAC address list
void RefreshLocalMacAddressList() {
	Lock(local_mac_list_lock);
	{
		if (local_mac_list != NULL) {
			FreeNicList(local_mac_list);
		}

		local_mac_list = GetNicList();
	}
	Unlock(local_mac_list_lock);
}

// Check whether the specified MAC address exists on the local host
bool IsMacAddressLocalInner(LIST *o, void *addr) {
	bool ret = false;
	UINT i;
	// Validate arguments
	if (o == NULL || addr == NULL) {
		return false;
	}

	for (i = 0; i < LIST_NUM(o); i++) {
		NIC_ENTRY *e = LIST_DATA(o, i);

		if (Cmp(e->MacAddress, addr, 6) == 0) {
			ret = true;
			break;
		}
	}

	return ret;
}

// Get a list of the NICs on the computer
LIST *GetNicList() {
	LIST *o = NULL;

#ifdef OS_WIN32
	o = Win32GetNicList();

	if (o != NULL) {
		return o;
	}

#endif // OS_WIN32

	return NewListFast(NULL);
}

#ifdef OS_WIN32
LIST *Win32GetNicList() {
	UINT i;
	LIST *o = NewListFast(NULL);
	MS_ADAPTER_LIST *al = MsCreateAdapterList();

	if (al == NULL) {
		return NULL;
	}

	for (i = 0; i < al->Num; i++) {
		MS_ADAPTER *a = al->Adapters[i];

		if (a->Type == 6 && a->AddressSize == 6) {
			// If the connection state of the interface is unknown, then exclude it.
			// Unknown means that the device is not plugged into the local host.
			if (a->MediaConnectState == MediaConnectStateUnknown) {
				continue;
			}

			NIC_ENTRY *e = ZeroMalloc(sizeof(NIC_ENTRY));

			StrCpy(e->IfName, sizeof(e->IfName), a->Title);
			Copy(e->MacAddress, a->Address, 6);

			Add(o, e);
		}
	}

	MsFreeAdapterList(al);

	return o;
}
#endif // OS_WIN32

// Release the NIC list
void FreeNicList(LIST *o) {
	UINT i;
	// Validate arguments
	if (o == NULL) {
		return;
	}

	for (i = 0; i < LIST_NUM(o); i++) {
		NIC_ENTRY *e = LIST_DATA(o, i);

		Free(e);
	}

	ReleaseList(o);
}

// Parse the user name of the NT
void ParseNtUsername(char *src_username, char *dst_username, UINT dst_username_size, char *dst_domain, UINT dst_domain_size, bool do_not_parse_atmark) {
	char tmp_username[MAX_SIZE];
	char tmp_domain[MAX_SIZE];
	TOKEN_LIST *t;

	if (src_username != dst_username) {
		ClearStr(dst_username, dst_username_size);
	}

	ClearStr(dst_domain, dst_domain_size);
	// Validate arguments
	if (src_username == NULL || dst_username == NULL || dst_domain == NULL) {
		return;
	}

	StrCpy(tmp_username, sizeof(tmp_username), src_username);
	ClearStr(tmp_domain, sizeof(tmp_domain));

	// Analysis of username@domain.name format
	if (do_not_parse_atmark == false) {
		t = ParseTokenWithNullStr(tmp_username, "@");
		if (t->NumTokens >= 1) {
			StrCpy(tmp_username, sizeof(tmp_username), t->Token[0]);
		}
		if (t->NumTokens >= 2) {
			StrCpy(tmp_domain, sizeof(tmp_domain), t->Token[1]);
		}
		FreeToken(t);
	}

	// If the username part is in "domain\username" format, split it
	t = ParseTokenWithNullStr(tmp_username, "\\");
	if (t->NumTokens >= 2) {
		if (IsEmptyStr(tmp_domain)) {
			StrCpy(tmp_domain, sizeof(tmp_domain), t->Token[0]);
		}

		StrCpy(tmp_username, sizeof(tmp_username), t->Token[1]);
	}
	FreeToken(t);

	StrCpy(dst_username, dst_username_size, tmp_username);
	StrCpy(dst_domain, dst_domain_size, tmp_domain);
}

// Generate a hash from the current computer name and the process name
void GetCurrentMachineIpProcessHash(void *hash) {
	// Validate arguments
	if (hash == NULL) {
		return;
	}

	Lock(machine_ip_process_hash_lock);
	{
		if (IsZero(machine_ip_process_hash, SHA1_SIZE)) {
			GetCurrentMachineIpProcessHashInternal(machine_ip_process_hash);
		}

		Copy(hash, machine_ip_process_hash, SHA1_SIZE);
	}
	Unlock(machine_ip_process_hash_lock);
}
void GetCurrentMachineIpProcessHashInternal(void *hash) {
	BUF *b;
	LIST *ip_list;
	char machine_name[MAX_SIZE];
	wchar_t exe_path[MAX_PATH];
	char *product_id = NULL;
	// Validate arguments
	if (hash == NULL) {
		return;
	}

#ifdef OS_WIN32
	product_id = MsRegReadStr(REG_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "ProductId");
	if (product_id == NULL) {
		product_id = MsRegReadStr(REG_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion", "ProductId");
	}
#endif // OS_WIN32

	b = NewBuf();

	GetMachineHostName(machine_name, sizeof(machine_name));
	Trim(machine_name);
	StrUpper(machine_name);

	GetExeNameW(exe_path, sizeof(exe_path));
	UniTrim(exe_path);
	UniStrUpper(exe_path);

	WriteBuf(b, machine_name, StrSize(machine_name));
	WriteBuf(b, exe_path, UniStrSize(exe_path));
	WriteBuf(b, product_id, StrSize(product_id));

	ip_list = GetHostIPAddressList();
	if (ip_list != NULL) {
		UINT i;
		for (i = 0; i < LIST_NUM(ip_list); i++) {
			IP *ip = LIST_DATA(ip_list, i);

			WriteBuf(b, ip, sizeof(IP));
		}
	}
	FreeHostIPAddressList(ip_list);

	Sha1(hash, b->Buf, b->Size);

	FreeBuf(b);

	Free(product_id);
}

#ifdef OS_WIN32

typedef struct WIN32_ACCEPT_CHECK_DATA {
	bool IsIPv6;
	bool Rejected;
} WIN32_ACCEPT_CHECK_DATA;

int CALLBACK Win32AcceptCheckCallback(LPWSABUF lpCallerId, LPWSABUF lpCallerData, LPQOS pQos,
                                      LPQOS lpGQOS, LPWSABUF lpCalleeId, LPWSABUF lpCalleeData,
                                      GROUP FAR *g, DWORD_PTR dwCallbackData) {
	return CF_ACCEPT;
}

// Accept function for Win32
SOCKET Win32Accept(SOCK *sock, SOCKET s, struct sockaddr *addr, int *addrlen, bool ipv6) {
	SOCKET ret;
	WIN32_ACCEPT_CHECK_DATA d;
	UINT err;
	int initial_addrlen = *addrlen;
	UINT num_error = 0;
	UINT zero = 0;
	UINT tmp = 0;
	DWORD ret_size = 0;
	// Validate arguments
	if (sock == NULL || s == INVALID_SOCKET) {
		return INVALID_SOCKET;
	}

	if (sock->hAcceptEvent == NULL) {
		sock->hAcceptEvent = CreateEvent(NULL, FALSE, FALSE, NULL);

		WSAEventSelect(s, sock->hAcceptEvent, FD_ACCEPT | FD_CLOSE);
	}

L_LOOP:

	if (sock->CancelAccept) {
		return INVALID_SOCKET;
	}

	Zero(&d, sizeof(d));

	d.IsIPv6 = ipv6;

	*addrlen = initial_addrlen;
	Zero(addr, initial_addrlen);
	ret = WSAAccept(s, addr, addrlen, Win32AcceptCheckCallback, (DWORD_PTR)&d);

	if (ret == INVALID_SOCKET) {
		err = WSAGetLastError();

		if (err == WSAEWOULDBLOCK) {
			//Debug("!!! WSAAccept: WSAEWOULDBLOCK\n");
			UINT wait_ret = WaitForSingleObject(sock->hAcceptEvent, 1234);

			if (wait_ret == WAIT_OBJECT_0 || wait_ret == WAIT_TIMEOUT) {
				goto L_LOOP;
			}

			Debug("!!! WaitForSingleObject Error. ret=%u GetLastError=%u\n", wait_ret, GetLastError());
		}

		num_error++;

		Debug("!!! WSAAccept Error: %u  rej=%u  num=%u  tick=%I64u\n", err, d.Rejected, num_error, Tick64());

		if (d.Rejected && err == WSAECONNREFUSED) {
			goto L_LOOP;
		}

		if (err == WSAETIMEDOUT) {
			goto L_LOOP;
		}
	} else {
		// Remove a new socket from the event
		WSAEventSelect(ret, sock->hAcceptEvent, 0);

		// Restore the new socket to synchronized
		WSAIoctl(ret, FIONBIO, &zero, sizeof(zero), &tmp, sizeof(tmp), &ret_size, NULL, NULL);
	}

	return ret;
}

#endif // OS_WIN32

#define USE_OLD_GETIP

// Set the arp_filter in Linux
void SetLinuxArpFilter() {
	char *filename = "/proc/sys/net/ipv4/conf/all/arp_filter";
	char *data = "1\n";
	IO *o;

	o = FileCreate(filename);
	if (o == NULL) {
		return;
	}

	FileWrite(o, data, StrLen(data));
	FileFlush(o);

	FileClose(o);
}

// Determine whether the string is a IPv6 address
bool IsStrIPv6Address(char *str) {
	IP ip;
	// Validate arguments
	if (str == NULL) {
		return false;
	}

	if (StrToIP6(&ip, str) == false) {
		return false;
	}

	return true;
}

// Convert the subnet mask to an integer
UINT SubnetMaskToInt6(IP *a) {
	UINT i;
	// Validate arguments
	if (IsIP6(a) == false) {
		return 0;
	}

	for (i = 0; i <= 128; i++) {
		IP tmp;

		IntToSubnetMask6(&tmp, i);

		if (CmpIpAddr(a, &tmp) == 0) {
			return i;
		}
	}

	return 0;
}
UINT SubnetMaskToInt4(IP *a) {
	UINT i;
	// Validate arguments
	if (IsIP4(a) == false) {
		return 0;
	}

	for (i = 0; i <= 32; i++) {
		IP tmp;

		IntToSubnetMask4(&tmp, i);

		if (CmpIpAddr(a, &tmp) == 0) {
			return i;
		}
	}

	return 0;
}
UINT SubnetMaskToInt(IP *a) {
	if (IsIP6(a)) {
		return SubnetMaskToInt6(a);
	} else {
		return SubnetMaskToInt4(a);
	}
}

// Determine whether the specified IP address is a subnet mask
bool IsSubnetMask6(IP *a) {
	UINT i;
	// Validate arguments
	if (IsIP6(a) == false) {
		return false;
	}

	for (i = 0; i <= 128; i++) {
		IP tmp;

		IntToSubnetMask6(&tmp, i);

		if (CmpIpAddr(a, &tmp) == 0) {
			return true;
		}
	}

	return false;
}

// Generate a local address from the MAC address
void GenerateEui64LocalAddress(IP *a, UCHAR *mac) {
	// Validate arguments
	if (a == NULL || mac == NULL) {
		return;
	}

	Zero(a, sizeof(IP));

	UCHAR tmp[8];
	GenerateEui64Address6(tmp, mac);

	a->address[0] = 0xfe;
	a->address[1] = 0x80;

	Copy(&a->address[8], tmp, sizeof(tmp));
}

// Generate the EUI-64 address from the MAC address
void GenerateEui64Address6(UCHAR *dst, UCHAR *mac) {
	// Validate arguments
	if (dst == NULL || mac == NULL) {
		return;
	}

	Copy(dst, mac, 3);
	Copy(dst + 5, mac, 3);

	dst[3] = 0xff;
	dst[4] = 0xfe;
	dst[0] = ((~(dst[0] & 0x02)) & 0x02) | (dst[0] & 0xfd);
}

// Get the prefix address
void GetPrefixAddress6(IP *dst, IP *ip, IP *subnet) {
	// Validate arguments
	if (dst == NULL || ip == NULL || subnet == NULL) {
		return;
	}

	IPAnd6(dst, ip, subnet);

	dst->ipv6_scope_id = ip->ipv6_scope_id;
}

// Get the type of the IPv6 address
UINT GetIPv6AddrType(IPV6_ADDR *addr) {
	IP ip;
	// Validate arguments
	if (addr == NULL) {
		return 0;
	}

	IPv6AddrToIP(&ip, addr);

	return GetIPAddrType6(&ip);
}
UINT GetIPAddrType6(IP *ip) {
	UINT ret = 0;
	// Validate arguments
	if (IsIP6(ip) == false) {
		return 0;
	}

	if (ip->address[0] == 0xff) {
		IP all_node, all_router;

		GetAllNodeMulticaseAddress6(&all_node);

		GetAllRouterMulticastAddress6(&all_router);

		ret |= IPV6_ADDR_MULTICAST;

		if (CmpIpAddr(ip, &all_node) == 0) {
			ret |= IPV6_ADDR_ALL_NODE_MULTICAST;
		} else if (CmpIpAddr(ip, &all_router) == 0) {
			ret |= IPV6_ADDR_ALL_ROUTER_MULTICAST;
		} else {
			if (ip->address[1] == 0x02 && ip->address[2] == 0 && ip->address[3] == 0 &&
			    ip->address[4] == 0 && ip->address[5] == 0 && ip->address[6] == 0 &&
			    ip->address[7] == 0 && ip->address[8] == 0 && ip->address[9] == 0 &&
			    ip->address[10] == 0 && ip->address[11] == 0x01 && ip->address[12] == 0xff) {
				ret |= IPV6_ADDR_SOLICIATION_MULTICAST;
			}
		}
	} else {
		ret |= IPV6_ADDR_UNICAST;

		if (ip->address[0] == 0xfe && (ip->address[1] & 0xc0) == 0x80) {
			ret |= IPV6_ADDR_LOCAL_UNICAST;
		} else {
			ret |= IPV6_ADDR_GLOBAL_UNICAST;

			if (IsZero(&ip->address, sizeof(ip->address))) {
				ret |= IPV6_ADDR_ZERO;
			} else {
				IP loopback;

				GetLoopbackAddress6(&loopback);

				if (Cmp(ip->address, loopback.address, sizeof(ip->address)) == 0) {
					ret |= IPV6_ADDR_LOOPBACK;
				}
			}
		}
	}

	return ret;
}

// Loopback address
void GetLoopbackAddress6(IP *ip) {
	// Validate arguments
	if (ip == NULL) {
		return;
	}

	Zero(ip, sizeof(IP));

	ip->address[15] = 0x01;
}

// All-nodes multicast address
void GetAllNodeMulticaseAddress6(IP *ip) {
	// Validate arguments
	if (ip == NULL) {
		return;
	}

	Zero(ip, sizeof(IP));

	ip->address[0] = 0xff;
	ip->address[1] = 0x02;
	ip->address[15] = 0x01;
}

// All-routers multicast address
void GetAllRouterMulticastAddress6(IP *ip) {
	// Validate arguments
	if (ip == NULL) {
		return;
	}

	Zero(ip, sizeof(IP));

	ip->address[0] = 0xff;
	ip->address[1] = 0x02;
	ip->address[15] = 0x02;
}

// Logical operation of the IPv4 address
void IPAnd4(IP *dst, IP *a, IP *b) {
	// Validate arguments
	if (dst == NULL || a == NULL || b == NULL || IsIP4(a) == false || IsIP4(b) == false) {
		ZeroIP4(dst);
		return;
	}

	UINTToIP(dst, IPToUINT(a) & IPToUINT(b));
}

// Logical operation of the IPv6 address
void IPAnd6(IP *dst, IP *a, IP *b) {
	Zero(dst, sizeof(IP));

	// Validate arguments
	if (dst == NULL || IsIP6(a) == false || IsIP6(b) == false) {
		return;
	}

	for (BYTE i = 0; i < sizeof(dst->address); ++i) {
		dst->address[i] = a->address[i] & b->address[i];
	}
}

// Creating a subnet mask
void IntToSubnetMask6(IP *ip, UINT i) {
	UINT j = i / 8;
	UINT k = i % 8;
	UINT z;
	IP a;

	Zero(&a, sizeof(IP));

	for (z = 0; z < sizeof(a.address); ++z) {
		if (z < j) {
			a.address[z] = 0xff;
		} else if (z == j) {
			a.address[z] = ~(0xff >> k);
		}
	}

	Copy(ip, &a, sizeof(IP));
}

// Convert the IP address to a string
void IP6AddrToStr(char *str, UINT size, IPV6_ADDR *addr) {
	// Validate arguments
	if (str == NULL || addr == NULL) {
		return;
	}

	IPToStr6Array(str, size, addr->Value);
}
void IPToStr6Array(char *str, UINT size, UCHAR *bytes) {
	IP ip;
	// Validate arguments
	if (str == NULL || bytes == NULL) {
		return;
	}

	SetIP6(&ip, bytes);

	IPToStr6(str, size, &ip);
}
void IPToStr6(char *str, UINT size, IP *ip) {
	char tmp[MAX_SIZE];

	IPToStr6Inner(tmp, ip);

	StrCpy(str, size, tmp);
}
void IPToStr6Inner(char *str, IP *ip) {
	UINT i;
	USHORT values[8];
	UINT zero_started_index;
	UINT max_zero_len;
	UINT max_zero_start;
	IP a;
	// Validate arguments
	if (str == NULL || ip == NULL) {
		return;
	}

	Copy(&a, ip, sizeof(IP));

	for (i = 0; i < 8; i++) {
		Copy(&values[i], &a.address[i * 2], sizeof(USHORT));
		values[i] = Endian16(values[i]);
	}

	// Search for omittable part
	zero_started_index = INFINITE;
	max_zero_len = 0;
	max_zero_start = INFINITE;
	for (i = 0; i < 9; i++) {
		USHORT v = (i != 8 ? values[i] : 1);

		if (v == 0) {
			if (zero_started_index == INFINITE) {
				zero_started_index = i;
			}
		} else {
			UINT zero_len;

			if (zero_started_index != INFINITE) {
				zero_len = i - zero_started_index;
				if (zero_len >= 2) {
					if (max_zero_len < zero_len) {
						max_zero_start = zero_started_index;
						max_zero_len = zero_len;
					}
				}

				zero_started_index = INFINITE;
			}
		}
	}

	// Format a string
	StrCpy(str, 0, "");
	for (i = 0; i < 8; i++) {
		char tmp[16];

		ToHex(tmp, values[i]);
		StrLower(tmp);

		if (i == max_zero_start) {
			if (i == 0) {
				StrCat(str, 0, "::");
			} else {
				StrCat(str, 0, ":");
			}
			i += max_zero_len - 1;
		} else {
			StrCat(str, 0, tmp);
			if (i != 7) {
				StrCat(str, 0, ":");
			}
		}
	}

	// Scope ID
	if (ip->ipv6_scope_id != 0) {
		char tmp[64];

		StrCat(str, 0, "%");
		ToStr(tmp, ip->ipv6_scope_id);

		StrCat(str, 0, tmp);
	}
}

// Convert the string to an IP address
bool StrToIP6(IP *ip, char *str) {
	TOKEN_LIST *t;
	char tmp[MAX_PATH];
	IP a;
	UINT i;
	UINT scope_id = 0;
	// Validate arguments
	if (str == NULL || ip == NULL) {
		return false;
	}

	Zero(&a, sizeof(a));

	StrCpy(tmp, sizeof(tmp), str);
	Trim(tmp);

	if (StartWith(tmp, "[") && EndWith(tmp, "]")) {
		// If the string is enclosed in square brackets, remove brackets
		StrCpyAllowOverlap(tmp, sizeof(tmp), &tmp[1]);

		if (StrLen(tmp) >= 1) {
			tmp[StrLen(tmp) - 1] = 0;
		}
	}

	// Remove the scope ID by analyzing if there is it
	i = SearchStrEx(tmp, "%", 0, false);
	if (i != INFINITE) {
		char ss[MAX_PATH];

		StrCpy(ss, sizeof(ss), &tmp[i + 1]);

		tmp[i] = 0;

		Trim(tmp);

		Trim(ss);

		scope_id = ToInt(ss);
	}

	// Tokenize
	t = ParseTokenWithNullStr(tmp, ":");
	if (t->NumTokens >= 3 && t->NumTokens <= 8) {
		UINT i, n;
		bool b = true;
		UINT k = 0;

		n = 0;

		for (i = 0; i < t->NumTokens; i++) {
			char *str = t->Token[i];

			if (i != 0 && i != (t->NumTokens - 1) && StrLen(str) == 0) {
				n++;
				if (n == 1) {
					k += 2 * (8 - t->NumTokens + 1);
				} else {
					b = false;
					break;
				}
			} else {
				UCHAR chars[2];

				if (CheckIPItemStr6(str) == false) {
					b = false;
					break;
				}

				IPItemStrToChars6(chars, str);

				a.address[k++] = chars[0];
				a.address[k++] = chars[1];
			}
		}

		if (n != 0 && n != 1) {
			b = false;
		} else if (n == 0 && t->NumTokens != 8) {
			b = false;
		}

		if (b == false) {
			FreeToken(t);
			return false;
		}
	} else {
		FreeToken(t);
		return false;
	}

	FreeToken(t);

	Copy(ip, &a, sizeof(IP));

	ip->ipv6_scope_id = scope_id;

	return true;
}

// Convert an IP address character to the UCHAR type
void IPItemStrToChars6(UCHAR *chars, char *str) {
	char tmp[5];
	BUF *b;
	UINT len;
	// Validate arguments
	if (chars == NULL) {
		return;
	}

	Zero(tmp, sizeof(tmp));

	len = StrLen(str);
	switch (len) {
	case 0:
		tmp[0] = tmp[1] = tmp[2] = tmp[3] = '0';
		break;

	case 1:
		tmp[0] = tmp[1] = tmp[2] = '0';
		tmp[3] = str[0];
		break;

	case 2:
		tmp[0] = tmp[1] = '0';
		tmp[2] = str[0];
		tmp[3] = str[1];
		break;

	case 3:
		tmp[0] = '0';
		tmp[1] = str[0];
		tmp[2] = str[1];
		tmp[3] = str[2];
		break;

	case 4:
		tmp[0] = str[0];
		tmp[1] = str[1];
		tmp[2] = str[2];
		tmp[3] = str[3];
		break;
	}

	b = StrToBin(tmp);

	chars[0] = ((UCHAR *)b->Buf)[0];
	chars[1] = ((UCHAR *)b->Buf)[1];

	FreeBuf(b);
}

// Check whether invalid characters are included in the element string of the IP address
bool CheckIPItemStr6(char *str) {
	UINT i, len;
	// Validate arguments
	if (str == NULL) {
		return false;
	}

	len = StrLen(str);
	if (len >= 5) {
		// Invalid length
		return false;
	}

	for (i = 0; i < len; i++) {
		char c = str[i];

		if ((c >= 'a' && c <= 'f') ||
		    (c >= 'A' && c <= 'F') ||
		    (c >= '0' && c <= '9')) {
		} else {
			return false;
		}
	}

	return true;
}

// Create an IPv4 address of all zero
void ZeroIP4(IP *ip) {
	// Validate arguments
	if (ip == NULL) {
		return;
	}

	Zero(ip, sizeof(IP));

	ip->address[10] = 0xff;
	ip->address[11] = 0xff;
}

// Get the IP address of the localhost
void GetLocalHostIP6(IP *ip) {
	// Validate arguments
	if (ip == NULL) {
		return;
	}

	Zero(ip, sizeof(IP));

	ip->address[15] = 1;
}
void GetLocalHostIP4(IP *ip) {
	// Validate arguments
	if (ip == NULL) {
		return;
	}

	SetIP(ip, 127, 0, 0, 1);
}

// Check whether the specified address is a localhost
bool IsLocalHostIP6(IP *ip) {
	IP local;
	// Validate arguments
	if (ip == NULL) {
		return false;
	}
	if (IsIP6(ip) == false) {
		return false;
	}

	GetLocalHostIP6(&local);

	if (CmpIpAddr(&local, ip) == 0) {
		return true;
	}

	return false;
}
bool IsLocalHostIP4(IP *ip) {
	// Validate arguments
	if (ip == NULL) {
		return false;
	}
	if (IsIP4(ip) == false) {
		return false;
	}

	if (IPV4(ip->address)[0] == 127) {
		return true;
	}

	return false;
}
bool IsLocalHostIP(IP *ip) {
	// Validate arguments
	if (ip == NULL) {
		return false;
	}

	if (IsIP4(ip)) {
		return IsLocalHostIP4(ip);
	} else {
		return IsLocalHostIP6(ip);
	}
}

// Convert the IPV6_ADDR to an IP
void IPv6AddrToIP(IP *ip, IPV6_ADDR *addr) {
	// Validate arguments
	if (ip == NULL || addr == NULL) {
		return;
	}

	SetIP6(ip, addr->Value);
}

// Convert the IP to an IPV6_ADDR
bool IPToIPv6Addr(IPV6_ADDR *addr, IP *ip) {
	UINT i;
	// Validate arguments
	if (addr == NULL || ip == NULL) {
		Zero(addr, sizeof(IPV6_ADDR));
		return false;
	}

	if (IsIP6(ip) == false) {
		Zero(addr, sizeof(IPV6_ADDR));
		return false;
	}

	for (i = 0; i < sizeof(addr->Value); ++i) {
		addr->Value[i] = ip->address[i];
	}

	return true;
}

// Set an IPv6 address
void SetIP6(IP *ip, UCHAR *value) {
	// Validate arguments
	if (ip == NULL || value == NULL) {
		return;
	}

	Zero(ip, sizeof(IP));

	for (BYTE i = 0; i < sizeof(ip->address); ++i) {
		ip->address[i] = value[i];
	}
}

// Check whether the specified address is IPv4
bool IsIP4(IP *ip) {
	// Validate arguments
	if (ip == NULL) {
		return false;
	}

	if (IsZero(ip->address, 10) == false) {
		return false;
	}

	if (ip->address[10] != 0xff || ip->address[11] != 0xff) {
		return false;
	}

	return true;
}

// Copy the IP address
void CopyIP(IP *dst, IP *src) {
	Copy(dst, src, sizeof(IP));
}

// Utility functions about IP and MAC address types
// Identify whether the IP address is a normal unicast address
bool IsValidUnicastIPAddress4(IP *ip) {
	// Validate arguments
	if (IsIP4(ip) == false) {
		return false;
	}

	if (IsZeroIP(ip)) {
		return false;
	}

	const BYTE *ipv4 = IPV4(ip->address);

	if (ipv4[0] >= 224 && ipv4[0] <= 239) {
		// IPv4 Multicast
		return false;
	}

	/// TODO: this is kinda incorrect, but for the correct parsing we need the netmask anyway
	for (BYTE i = 0; i < IPV4_SIZE; ++i) {
		if (ipv4[i] != 255) {
			return true;
		}
	}

	return false;
}

bool IsValidUnicastIPAddress6(IP *ip) {
	UINT ipv6Type;

	if (!IsIP6(ip)) {
		return false;
	}

	if (IsZeroIP(ip)) {
		return false;
	}

	ipv6Type = GetIPAddrType6(ip);

	if (!(ipv6Type & IPV6_ADDR_LOCAL_UNICAST) &&
	    !(ipv6Type & IPV6_ADDR_GLOBAL_UNICAST)) {
		return false;
	}

	return true;
}

// Get the number of clients connected from the specified IP address
UINT GetNumIpClient(IP *ip) {
	IP_CLIENT *c;
	UINT ret = 0;
	// Validate arguments
	if (ip == NULL) {
		return 0;
	}

	LockList(ip_clients);
	{
		c = SearchIpClient(ip);

		if (c != NULL) {
			ret = c->NumConnections;
		}
	}
	UnlockList(ip_clients);

	return ret;
}

// Add to the IP client entry
void AddIpClient(IP *ip) {
	IP_CLIENT *c;
	// Validate arguments
	if (ip == NULL) {
		return;
	}

	LockList(ip_clients);
	{
		c = SearchIpClient(ip);

		if (c == NULL) {
			c = ZeroMallocFast(sizeof(IP_CLIENT));
			Copy(&c->IpAddress, ip, sizeof(IP));
			c->NumConnections = 0;

			Add(ip_clients, c);
		}

		c->NumConnections++;
	}
	UnlockList(ip_clients);

	//Debug("AddIpClient: %r\n", ip);
}

// Remove from the IP client list
void DelIpClient(IP *ip) {
	IP_CLIENT *c;
	// Validate arguments
	if (ip == NULL) {
		return;
	}

	LockList(ip_clients);
	{
		c = SearchIpClient(ip);

		if (c != NULL) {
			c->NumConnections--;

			if (c->NumConnections == 0) {
				Delete(ip_clients, c);
				Free(c);
			}
		}
	}
	UnlockList(ip_clients);

	//Debug("DelIpClient: %r\n", ip);
}

// Search for the IP client entry
IP_CLIENT *SearchIpClient(IP *ip) {
	IP_CLIENT t;
	// Validate arguments
	if (ip == NULL) {
		return NULL;
	}

	Zero(&t, sizeof(t));
	Copy(&t.IpAddress, ip, sizeof(IP));

	return Search(ip_clients, &t);
}

// Initialization of the client list
void InitIpClientList() {
	ip_clients = NewList(CompareIpClientList);
}

// Release of the client list
void FreeIpClientList() {
	UINT i;

	for (i = 0; i < LIST_NUM(ip_clients); i++) {
		IP_CLIENT *c = LIST_DATA(ip_clients, i);

		Free(c);
	}

	ReleaseList(ip_clients);
	ip_clients = NULL;
}

// Comparison of the client list entries
int CompareIpClientList(void *p1, void *p2) {
	IP_CLIENT *c1, *c2;
	if (p1 == NULL || p2 == NULL) {
		return 0;
	}
	c1 = *(IP_CLIENT **)p1;
	c2 = *(IP_CLIENT **)p2;
	if (c1 == NULL || c2 == NULL) {
		return 0;
	}

	return CmpIpAddr(&c1->IpAddress, &c2->IpAddress);
}

// Identify whether the IP address is empty
bool IsZeroIP(IP *ip) {
	// Validate arguments
	if (ip == NULL) {
		return true;
	}

	if (IsZero(ip->address, sizeof(ip->address))) {
		return true;
	}

	if (IsIP4(ip)) {
		return IsZero(IPV4(ip->address), IPV4_SIZE);
	}

	return false;
}
bool IsZeroIP6Addr(IPV6_ADDR *addr) {
	// Validate arguments
	if (addr == NULL) {
		return true;
	}

	return IsZero(addr, sizeof(IPV6_ADDR));
}

// Convert the integer to a subnet mask
UINT IntToSubnetMask32(UINT i) {
	UINT ret = 0xFFFFFFFF;

	switch (i) {
	case 0:
		ret = 0x00000000;
		break;
	case 1:
		ret = 0x80000000;
		break;
	case 2:
		ret = 0xC0000000;
		break;
	case 3:
		ret = 0xE0000000;
		break;
	case 4:
		ret = 0xF0000000;
		break;
	case 5:
		ret = 0xF8000000;
		break;
	case 6:
		ret = 0xFC000000;
		break;
	case 7:
		ret = 0xFE000000;
		break;
	case 8:
		ret = 0xFF000000;
		break;
	case 9:
		ret = 0xFF800000;
		break;
	case 10:
		ret = 0xFFC00000;
		break;
	case 11:
		ret = 0xFFE00000;
		break;
	case 12:
		ret = 0xFFF00000;
		break;
	case 13:
		ret = 0xFFF80000;
		break;
	case 14:
		ret = 0xFFFC0000;
		break;
	case 15:
		ret = 0xFFFE0000;
		break;
	case 16:
		ret = 0xFFFF0000;
		break;
	case 17:
		ret = 0xFFFF8000;
		break;
	case 18:
		ret = 0xFFFFC000;
		break;
	case 19:
		ret = 0xFFFFE000;
		break;
	case 20:
		ret = 0xFFFFF000;
		break;
	case 21:
		ret = 0xFFFFF800;
		break;
	case 22:
		ret = 0xFFFFFC00;
		break;
	case 23:
		ret = 0xFFFFFE00;
		break;
	case 24:
		ret = 0xFFFFFF00;
		break;
	case 25:
		ret = 0xFFFFFF80;
		break;
	case 26:
		ret = 0xFFFFFFC0;
		break;
	case 27:
		ret = 0xFFFFFFE0;
		break;
	case 28:
		ret = 0xFFFFFFF0;
		break;
	case 29:
		ret = 0xFFFFFFF8;
		break;
	case 30:
		ret = 0xFFFFFFFC;
		break;
	case 31:
		ret = 0xFFFFFFFE;
		break;
	case 32:
		ret = 0xFFFFFFFF;
		break;
	}

	if (IsLittleEndian()) {
		ret = Swap32(ret);
	}

	return ret;
}
void IntToSubnetMask4(IP *ip, UINT i) {
	UINT m;
	// Validate arguments
	if (ip == NULL) {
		return;
	}

	m = IntToSubnetMask32(i);

	UINTToIP(ip, m);
}

// Examine whether the specified IP address is a subnet mask
bool IsSubnetMask(IP *ip) {
	if (IsIP6(ip)) {
		return IsSubnetMask6(ip);
	} else {
		return IsSubnetMask4(ip);
	}
}
bool IsSubnetMask4(IP *ip) {
	UINT i;
	// Validate arguments
	if (ip == NULL) {
		return false;
	}

	if (IsIP6(ip)) {
		return false;
	}

	i = IPToUINT(ip);

	if (IsLittleEndian()) {
		i = Swap32(i);
	}

	switch (i) {
	case 0x00000000:
	case 0x80000000:
	case 0xC0000000:
	case 0xE0000000:
	case 0xF0000000:
	case 0xF8000000:
	case 0xFC000000:
	case 0xFE000000:
	case 0xFF000000:
	case 0xFF800000:
	case 0xFFC00000:
	case 0xFFE00000:
	case 0xFFF00000:
	case 0xFFF80000:
	case 0xFFFC0000:
	case 0xFFFE0000:
	case 0xFFFF0000:
	case 0xFFFF8000:
	case 0xFFFFC000:
	case 0xFFFFE000:
	case 0xFFFFF000:
	case 0xFFFFF800:
	case 0xFFFFFC00:
	case 0xFFFFFE00:
	case 0xFFFFFF00:
	case 0xFFFFFF80:
	case 0xFFFFFFC0:
	case 0xFFFFFFE0:
	case 0xFFFFFFF0:
	case 0xFFFFFFF8:
	case 0xFFFFFFFC:
	case 0xFFFFFFFE:
	case 0xFFFFFFFF:
		return true;
	}

	return false;
}

#ifdef OS_WIN32 // Code for Windows

// Comparison of IP_ADAPTER_INDEX_MAP
int CompareIpAdapterIndexMap(void *p1, void *p2) {
	IP_ADAPTER_INDEX_MAP *a1, *a2;
	if (p1 == NULL || p2 == NULL) {
		return 0;
	}
	a1 = *(IP_ADAPTER_INDEX_MAP **)p1;
	a2 = *(IP_ADAPTER_INDEX_MAP **)p2;
	if (a1 == NULL || a2 == NULL) {
		return 0;
	}

	if (a1->Index > a2->Index) {
		return 1;
	} else if (a1->Index < a2->Index) {
		return -1;
	} else {
		return 0;
	}
}

// Initializing the socket library
void Win32InitSocketLibrary() {
	WSADATA data;
	Zero(&data, sizeof(data));
	WSAStartup(MAKEWORD(2, 2), &data);
}

// Release of the socket library
void Win32FreeSocketLibrary() {
	WSACleanup();
}

// Cancel
void Win32Cancel(CANCEL *c) {
	// Validate arguments
	if (c == NULL) {
		return;
	}

	SetEvent((HANDLE)c->hEvent);
}

// Cleanup of the cancel object
void Win32CleanupCancel(CANCEL *c) {
	// Validate arguments
	if (c == NULL) {
		return;
	}

	if (c->SpecialFlag == false) {
		CloseHandle(c->hEvent);
	}

	Free(c);
}

// New cancel object
CANCEL *Win32NewCancel() {
	CANCEL *c = ZeroMallocFast(sizeof(CANCEL));
	c->ref = NewRef();
	c->SpecialFlag = false;
	c->hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);

	return c;
}

// Waiting for a socket event
bool Win32WaitSockEvent(SOCK_EVENT *event, UINT timeout) {
	// Validate arguments
	if (event == NULL || timeout == 0) {
		return false;
	}

	if (WaitForSingleObject((HANDLE)event->hEvent, timeout) == WAIT_OBJECT_0) {
		return true;
	} else {
		return false;
	}
}

// Clean-up of the socket event
void Win32CleanupSockEvent(SOCK_EVENT *event) {
	// Validate arguments
	if (event == NULL) {
		return;
	}

	CloseHandle((HANDLE)event->hEvent);

	Free(event);
}

// Set of the socket event
void Win32SetSockEvent(SOCK_EVENT *event) {
	// Validate arguments
	if (event == NULL) {
		return;
	}

	SetEvent((HANDLE)event->hEvent);
}

// Creating a socket event
SOCK_EVENT *Win32NewSockEvent() {
	SOCK_EVENT *e = ZeroMallocFast(sizeof(SOCK_EVENT));

	e->ref = NewRef();
	e->hEvent = (void *)CreateEvent(NULL, FALSE, FALSE, NULL);

	return e;
}

// Associate the socket with socket event and set it to asynchronous mode
void Win32JoinSockToSockEvent(SOCK *sock, SOCK_EVENT *event) {
	HANDLE hEvent;
	// Validate arguments
	if (sock == NULL || event == NULL || sock->AsyncMode) {
		return;
	}
	if (sock->ListenMode != false || (sock->Type != SOCK_UDP && sock->Connected == false)) {
		return;
	}

	sock->AsyncMode = true;

	hEvent = event->hEvent;

	// Association
	WSAEventSelect(sock->socket, hEvent, FD_READ | FD_WRITE | FD_CLOSE);

	// Increase the reference count of the SOCK_EVENT
	AddRef(event->ref);
	sock->SockEvent = event;
}

// Set the socket to asynchronous mode
void Win32InitAsyncSocket(SOCK *sock) {
	// Validate arguments
	if (sock == NULL) {
		return;
	}
	if (sock->AsyncMode) {
		// This socket is already in asynchronous mode
		return;
	}
	if (sock->ListenMode || (sock->Type == SOCK_TCP && sock->Connected == false)) {
		return;
	}

	sock->AsyncMode = true;

	// Creating an Event
	sock->hEvent = (void *)CreateEvent(NULL, FALSE, FALSE, NULL);

	// Association
	WSAEventSelect(sock->socket, sock->hEvent, FD_READ | FD_WRITE | FD_CLOSE);
}

// Release the asynchronous socket
void Win32FreeAsyncSocket(SOCK *sock) {
	// Validate arguments
	if (sock == NULL) {
		return;
	}

	// Asynchronous socket
	if (sock->hEvent != NULL) {
		CloseHandle((HANDLE)sock->hEvent);
	}
	sock->hEvent = NULL;
	sock->AsyncMode = false;

	// Socket event
	if (sock->SockEvent != NULL) {
		ReleaseSockEvent(sock->SockEvent);
		sock->SockEvent = NULL;
	}
}

// Select function for Win32
void Win32Select(SOCKSET *set, UINT timeout, CANCEL *c1, CANCEL *c2) {
	HANDLE array[MAXIMUM_WAIT_OBJECTS];
	UINT n, i;
	SOCK *s;
	// Initialization of array
	Zero(array, sizeof(array));
	n = 0;

	// Setting the event array
	if (set != NULL) {
		for (i = 0; i < set->NumSocket; i++) {
			s = set->Sock[i];
			if (s != NULL) {
				Win32InitAsyncSocket(s);
				if (s->hEvent != NULL) {
					array[n++] = (HANDLE)s->hEvent;
				}
			}
		}
	}
	if (c1 != NULL && c1->hEvent != NULL) {
		array[n++] = c1->hEvent;
	}
	if (c2 != NULL && c2->hEvent != NULL) {
		array[n++] = c2->hEvent;
	}

	if (timeout == 0) {
		return;
	}

	if (n == 0) {
		// Call normal waiting function if no events to wait are registered
		SleepThread(timeout);
	} else {
		// Wait for the event if events are registered at least one
		if (n == 1) {
			// Calling a lightweight version If the event is only one
			WaitForSingleObject(array[0], timeout);
		} else {
			// In case of multiple events
			WaitForMultipleObjects(n, array, false, timeout);
		}
	}
}

#endif // OS_WIN32

// Check whether the IPv6 is supported
bool IsIPv6Supported() {
#ifdef NO_IPV6
	return false;
#else  // NO_IPV6
	SOCKET s;

	s = socket(AF_INET6, SOCK_STREAM, 0);
	if (s == INVALID_SOCKET) {
		return false;
	}

	closesocket(s);

	return true;
#endif // NO_IPV6
}

// Check whether an IPv6 address is configured on any interface
bool HasIPv6Address() {
	LIST *o;
	UINT i;
	bool ret = false;

	o = GetHostIPAddressList();

	ret = false;

	for (i = 0; i < LIST_NUM(o); i++) {
		IP *p = LIST_DATA(o, i);

		if (IsIP6(p)) {
			UINT type = GetIPAddrType6(p);
			if ((type & IPV6_ADDR_GLOBAL_UNICAST) && ((type & IPV6_ADDR_ZERO) == 0) && ((type & IPV6_ADDR_LOOPBACK) == 0)) {
				ret = true;
				break;
			}
		}
	}

	FreeHostIPAddressList(o);

	return ret;
}

// Add the thread to the thread waiting list
void AddWaitThread(THREAD *t) {
	// Validate arguments
	if (t == NULL) {
		return;
	}

	AddRef(t->ref);

	LockList(WaitThreadList);
	{
		Add(WaitThreadList, t);
	}
	UnlockList(WaitThreadList);
}

// Remove the thread from the waiting list
void DelWaitThread(THREAD *t) {
	// Validate arguments
	if (t == NULL) {
		return;
	}

	LockList(WaitThreadList);
	{
		if (Delete(WaitThreadList, t)) {
			ReleaseThread(t);
		}
	}
	UnlockList(WaitThreadList);
}

// Creating a thread waiting list
void InitWaitThread() {
	WaitThreadList = NewList(NULL);
}

// Release of the thread waiting list
void FreeWaitThread() {
	UINT i, num;
	THREAD **threads;

	LockList(WaitThreadList);
	{
		num = LIST_NUM(WaitThreadList);
		threads = ToArray(WaitThreadList);
		DeleteAll(WaitThreadList);
	}
	UnlockList(WaitThreadList);

	for (i = 0; i < num; i++) {
		THREAD *t = threads[i];
		WaitThread(t, INFINITE);
		ReleaseThread(t);
	}

	Free(threads);

	ReleaseList(WaitThreadList);
	WaitThreadList = NULL;
}

// Creating a socket event
SOCK_EVENT *NewSockEvent() {
#ifdef OS_WIN32
	return Win32NewSockEvent();
#endif // OS_WIN32
}

// Set of the socket event
void SetSockEvent(SOCK_EVENT *event) {
#ifdef OS_WIN32
	Win32SetSockEvent(event);
#endif // OS_WIN32
}

// Clean-up of the socket event
void CleanupSockEvent(SOCK_EVENT *event) {
#ifdef OS_WIN32
	Win32CleanupSockEvent(event);
#endif // OS_WIN32
}

// Waiting for the socket event
bool WaitSockEvent(SOCK_EVENT *event, UINT timeout) {
	bool ret = false;
#ifdef OS_WIN32
	ret = Win32WaitSockEvent(event, timeout);
#endif // OS_WIN32
	return ret;
}

// Release of the socket event
void ReleaseSockEvent(SOCK_EVENT *event) {
	// Validate arguments
	if (event == NULL) {
		return;
	}

	if (Release(event->ref) == 0) {
		CleanupSockEvent(event);
	}
}

// Let belonging the socket to the socket event
void JoinSockToSockEvent(SOCK *sock, SOCK_EVENT *event) {
	// Validate arguments
	if (sock == NULL || event == NULL) {
		return;
	}

#ifdef OS_WIN32
	Win32JoinSockToSockEvent(sock, event);
#endif // OS_WIN32
}

// New special cancel object
CANCEL *NewCancelSpecial(void *hEvent) {
	CANCEL *c;
	// Validate arguments
	if (hEvent == NULL) {
		return NULL;
	}

	c = ZeroMalloc(sizeof(CANCEL));
	c->ref = NewRef();
	c->SpecialFlag = true;

#ifdef OS_WIN32
	c->hEvent = (HANDLE)hEvent;
#endif // OS_WIN32

	return c;
}

// Creating a cancel object
CANCEL *NewCancel() {
	CANCEL *c = NULL;
#ifdef OS_WIN32
	c = Win32NewCancel();
#endif // OS_WIN32
	return c;
}

// Release of the cancel object
void ReleaseCancel(CANCEL *c) {
	// Validate arguments
	if (c == NULL) {
		return;
	}

	if (Release(c->ref) == 0) {
		CleanupCancel(c);
	}
}

// Clean up of the cancel object
void CleanupCancel(CANCEL *c) {
#ifdef OS_WIN32
	Win32CleanupCancel(c);
#endif
}

// Cancellation triggered
void Cancel(CANCEL *c) {
#ifdef OS_WIN32
	Win32Cancel(c);
#endif
}

// UDP receiving
UINT RecvFrom(SOCK *sock, IP *src_addr, UINT *src_port, void *data, UINT size) {
	struct sockaddr_in addr;
	int ret = 0;
#ifdef OS_WIN32
	int socklen = sizeof(addr);
#endif

	// Validate arguments
	if (sock != NULL) {
		if (sock->IPv6) {
			return RecvFrom6(sock, src_addr, src_port, data, size);
		}

		sock->IgnoreRecvErr = false;
	} else {
		return 0;
	}

	if (src_addr == NULL || src_port == NULL || data == NULL || size == 0) {
		return 0;
	}

	if (sock->Type != SOCK_UDP || sock->socket == INVALID_SOCKET) {
		return 0;
	}

	ret = recvfrom(sock->socket, data, size, 0, (struct sockaddr *)&addr, &socklen);
	if (ret > 0) {
		InAddrToIP(src_addr, &addr.sin_addr);
		*src_port = (UINT)ntohs(addr.sin_port);
		if (sock->IsRawSocket) {
			*src_port = sock->LocalPort;
		}

		Lock(sock->lock);
		{
			sock->RecvNum++;
			sock->RecvSize += (UINT64)ret;
		}
		Unlock(sock->lock);

		return (UINT)ret;
	} else if (ret == 0) {
		return SOCK_LATER;
	} else {
#ifdef OS_WIN32
		if (WSAGetLastError() == WSAECONNRESET || WSAGetLastError() == WSAENETRESET || WSAGetLastError() == WSAEMSGSIZE || WSAGetLastError() == WSAENETUNREACH ||
		    WSAGetLastError() == WSAENOBUFS || WSAGetLastError() == WSAEHOSTUNREACH || WSAGetLastError() == WSAEUSERS || WSAGetLastError() == WSAEADDRNOTAVAIL || WSAGetLastError() == WSAEADDRNOTAVAIL) {
			sock->IgnoreRecvErr = true;
		} else if (WSAGetLastError() == WSAEWOULDBLOCK || WSAGetLastError() == WSAEINPROGRESS) {
			return SOCK_LATER;
		} else {
			Debug("RecvFrom(): recvfrom() failed with error: %u\n", WSAGetLastError());
		}
#endif
		return 0;
	}
}
UINT RecvFrom6(SOCK *sock, IP *src_addr, UINT *src_port, void *data, UINT size) {
	struct sockaddr_in6 addr;
	int ret = 0;
#ifdef OS_WIN32
	int socklen = sizeof(addr);
#endif

	// Validate arguments
	if (sock != NULL) {
		sock->IgnoreRecvErr = false;
	} else {
		return 0;
	}

	if (src_addr == NULL || src_port == NULL || data == NULL || size == 0) {
		return 0;
	}

	if (sock->Type != SOCK_UDP || sock->socket == INVALID_SOCKET) {
		return 0;
	}


	ret = recvfrom(sock->socket, data, size, 0, (struct sockaddr *)&addr, &socklen);
	if (ret > 0) {
		InAddrToIP6(src_addr, &addr.sin6_addr);
		src_addr->ipv6_scope_id = addr.sin6_scope_id;
		*src_port = (UINT)ntohs(addr.sin6_port);
		if (sock->IsRawSocket) {
			*src_port = sock->LocalPort;
		}

		Lock(sock->lock);
		{
			sock->RecvNum++;
			sock->RecvSize += (UINT64)ret;
		}
		Unlock(sock->lock);

		return (UINT)ret;
	} else if (ret == 0) {
		return SOCK_LATER;
	} else {
#ifdef OS_WIN32
		if (WSAGetLastError() == WSAECONNRESET || WSAGetLastError() == WSAENETRESET || WSAGetLastError() == WSAEMSGSIZE || WSAGetLastError() == WSAENETUNREACH ||
		    WSAGetLastError() == WSAENOBUFS || WSAGetLastError() == WSAEHOSTUNREACH || WSAGetLastError() == WSAEUSERS || WSAGetLastError() == WSAEADDRNOTAVAIL || WSAGetLastError() == WSAEADDRNOTAVAIL) {
			sock->IgnoreRecvErr = true;
		} else if (WSAGetLastError() == WSAEWOULDBLOCK || WSAGetLastError() == WSAEINPROGRESS) {
			return SOCK_LATER;
		} else {
			Debug("RecvFrom(): recvfrom() failed with error: %u\n", WSAGetLastError());
		}
#endif
		return 0;
	}
}

// UDP transmission
UINT SendTo(SOCK *sock, IP *dest_addr, UINT dest_port, void *data, UINT size) {
	return SendToEx(sock, dest_addr, dest_port, data, size, false);
}
UINT SendToEx(SOCK *sock, IP *dest_addr, UINT dest_port, void *data, UINT size, bool broadcast) {
	SOCKET s;
	int ret;
	struct sockaddr_in addr;
	// Validate arguments
	if (sock != NULL) {
		sock->IgnoreSendErr = false;
	}
	if (sock == NULL || dest_addr == NULL || (sock->IsRawSocket == false && dest_port == 0) || data == NULL) {
		return 0;
	}
	if (dest_port >= 65536 && sock->IsRawSocket == false) {
		return 0;
	}
	if (sock->Type != SOCK_UDP || sock->socket == INVALID_SOCKET) {
		return 0;
	}
	if (size == 0) {
		return 0;
	}

	if (sock->IPv6) {
		return SendTo6Ex(sock, dest_addr, dest_port, data, size, broadcast);
	}

	if (IsIP4(dest_addr) == false) {
		return 0;
	}

	s = sock->socket;
	Zero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	if (sock->IsRawSocket == false) {
		addr.sin_port = htons((USHORT)dest_port);
	}
	IPToInAddr(&addr.sin_addr, dest_addr);

	const BYTE *ipv4 = IPV4(dest_addr->address);
	if ((ipv4[0] == 255 && ipv4[1] == 255 && ipv4[2] == 255 && ipv4[3] == 255) ||
	    (ipv4[0] >= 224 && ipv4[0] <= 239) ||
	    broadcast) {
		if (sock->UdpBroadcast == false) {
			UINT yes = 1;

			sock->UdpBroadcast = true;

			(void)setsockopt(s, SOL_SOCKET, SO_BROADCAST, (char *)&yes, sizeof(yes));
		}
	}

	ret = sendto(s, data, size, 0, (struct sockaddr *)&addr, sizeof(addr));
	if (ret != (int)size) {
		sock->IgnoreSendErr = false;

#ifdef OS_WIN32
		if (WSAGetLastError() == WSAECONNRESET || WSAGetLastError() == WSAENETRESET || WSAGetLastError() == WSAEMSGSIZE || WSAGetLastError() == WSAENETUNREACH ||
		    WSAGetLastError() == WSAENOBUFS || WSAGetLastError() == WSAEHOSTUNREACH || WSAGetLastError() == WSAEUSERS || WSAGetLastError() == WSAEINVAL || WSAGetLastError() == WSAEADDRNOTAVAIL) {
			sock->IgnoreSendErr = true;
		} else if (WSAGetLastError() == WSAEWOULDBLOCK || WSAGetLastError() == WSAEINPROGRESS) {
			return SOCK_LATER;
		} else {
			UINT e = WSAGetLastError();
			Debug("SendTo Error; %u\n", e);
		}
#endif // OS_WIN32
		return 0;
	}

	Lock(sock->lock);
	{
		sock->SendSize += (UINT64)size;
		sock->SendNum++;
	}
	Unlock(sock->lock);

	return ret;
}
UINT SendTo6Ex(SOCK *sock, IP *dest_addr, UINT dest_port, void *data, UINT size, bool broadcast) {
	SOCKET s;
	int ret;
	struct sockaddr_in6 addr;
	UINT type;
	// Validate arguments
	if (sock != NULL) {
		sock->IgnoreSendErr = false;
	}
	if (sock == NULL || dest_addr == NULL || (sock->IsRawSocket == false && dest_port == 0) || data == NULL) {
		return 0;
	}
	if (dest_port >= 65536 && sock->IsRawSocket == false) {
		return 0;
	}
	if (sock->Type != SOCK_UDP || sock->socket == INVALID_SOCKET) {
		return 0;
	}
	if (size == 0) {
		return 0;
	}

	if (IsIP6(dest_addr) == false) {
		return 0;
	}

	s = sock->socket;
	Zero(&addr, sizeof(addr));
	addr.sin6_family = AF_INET6;
	if (sock->IsRawSocket == false) {
		addr.sin6_port = htons((USHORT)dest_port);
	}
	IPToInAddr6(&addr.sin6_addr, dest_addr);
	addr.sin6_scope_id = dest_addr->ipv6_scope_id;

	type = GetIPAddrType6(dest_addr);

	if ((type & IPV6_ADDR_MULTICAST) || broadcast) {
		if (sock->UdpBroadcast == false) {
			UINT yes = 1;

			sock->UdpBroadcast = true;

			(void)setsockopt(s, SOL_SOCKET, SO_BROADCAST, (char *)&yes, sizeof(yes));
		}
	}

	ret = sendto(s, data, size, 0, (struct sockaddr *)&addr, sizeof(addr));
	if (ret != (int)size) {
		sock->IgnoreSendErr = false;

#ifdef OS_WIN32
		if (WSAGetLastError() == WSAECONNRESET || WSAGetLastError() == WSAENETRESET || WSAGetLastError() == WSAEMSGSIZE || WSAGetLastError() == WSAENETUNREACH ||
		    WSAGetLastError() == WSAENOBUFS || WSAGetLastError() == WSAEHOSTUNREACH || WSAGetLastError() == WSAEUSERS || WSAGetLastError() == WSAEINVAL || WSAGetLastError() == WSAEADDRNOTAVAIL) {
			sock->IgnoreSendErr = true;
		} else if (WSAGetLastError() == WSAEWOULDBLOCK || WSAGetLastError() == WSAEINPROGRESS) {
			return SOCK_LATER;
		}
#endif // OS_WIN32
		return 0;
	}

	Lock(sock->lock);
	{
		sock->SendSize += (UINT64)size;
		sock->SendNum++;
	}
	Unlock(sock->lock);

	return ret;
}

// Create and initialize the UDP socket
// If port is specified as 0, system assigns a certain port.
SOCK *NewUDP(UINT port) {
	return NewUDPEx(port, false);
}
SOCK *NewUDPEx(UINT port, bool ipv6) {
	return NewUDPEx2(port, ipv6, NULL);
}
SOCK *NewUDPEx2(UINT port, bool ipv6, IP *ip) {
	if (ipv6 == false) {
		return NewUDP4(port, ip);
	} else {
		return NewUDP6(port, ip);
	}
}
SOCK *NewUDPEx3(UINT port, IP *ip) {
	// Validate arguments
	if (ip == NULL) {
		return NewUDPEx2(port, false, NULL);
	}

	if (IsIP4(ip)) {
		return NewUDPEx2(port, false, ip);
	} else {
		return NewUDPEx2(port, true, ip);
	}
}
SOCK *NewUDP4(UINT port, IP *ip) {
	SOCK *sock;
	SOCKET s;
	struct sockaddr_in addr;
	// Validate arguments
	if (ip != NULL && IsIP4(ip) == false) {
		return NULL;
	}

	if (IS_SPECIAL_PORT(port) == false) {
		s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	} else {
		s = socket(AF_INET, SOCK_RAW, GET_SPECIAL_PORT(port));
	}
	if (s == INVALID_SOCKET) {
		return NULL;
	}

	Zero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;

	if (ip == NULL || IsZeroIP(ip)) {
		addr.sin_addr.s_addr = htonl(INADDR_ANY);
	} else {
		IPToInAddr(&addr.sin_addr, ip);
	}

	if (port == 0 || IS_SPECIAL_PORT(port)) {
		addr.sin_port = 0;
	} else {
		addr.sin_port = htons((USHORT)port);
	}

	if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
		// Failure
		if (port != 0) {
			UINT true_flag = 1;
			(void)setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *)&true_flag, sizeof(true_flag));
			if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
				UINT false_flag = 0;
				(void)setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *)&false_flag, sizeof(false_flag));
#ifdef SO_EXCLUSIVEADDRUSE
				(void)setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (char *)&true_flag, sizeof(true_flag));
#endif // SO_EXCLUSIVEADDRUSE
				if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
					closesocket(s);
					return NULL;
				}
			}
		} else {
			closesocket(s);
			return NULL;
		}
	}

	sock = NewSock();

	sock->Type = SOCK_UDP;
	sock->Connected = false;
	sock->AsyncMode = false;
	sock->ServerMode = false;
	if (port != 0) {
		sock->ServerMode = true;
	}

	sock->socket = s;

	InitUdpSocketBufferSize((int)s);

	if (IS_SPECIAL_PORT(port)) {
		UINT no = 0;
		(void)setsockopt(sock->socket, IPPROTO_IP, IP_HDRINCL, (char *)&no, sizeof(no));

		sock->IsRawSocket = true;
		sock->RawSocketIPProtocol = GET_SPECIAL_PORT(port);
	}

	QuerySocketInformation(sock);

	return sock;
}
SOCK *NewUDP6(UINT port, IP *ip) {
	SOCK *sock;
	SOCKET s;
	struct sockaddr_in6 addr;
	// Validate arguments
	if (ip != NULL && IsIP6(ip) == false) {
		return NULL;
	}

	if (IS_SPECIAL_PORT(port) == false) {
		s = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	} else {
		s = socket(AF_INET6, SOCK_RAW, GET_SPECIAL_PORT(port));
	}
	if (s == INVALID_SOCKET) {
		return NULL;
	}

	Zero(&addr, sizeof(addr));
	addr.sin6_family = AF_INET6;
	if (port == 0) {
		addr.sin6_port = 0;
	} else {
		addr.sin6_port = htons((USHORT)port);
	}

	if (ip != NULL && IsZeroIP(ip) == false) {
		IPToInAddr6(&addr.sin6_addr, ip);
		addr.sin6_scope_id = ip->ipv6_scope_id;
	}

	UINT true_flag = 1;
	UINT false_flag = 0;

	if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
		// Failure
		if (port != 0) {
			(void)setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *)&true_flag, sizeof(true_flag));
			if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
				(void)setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *)&false_flag, sizeof(false_flag));
#ifdef SO_EXCLUSIVEADDRUSE
				(void)setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (char *)&true_flag, sizeof(true_flag));
#endif // SO_EXCLUSIVEADDRUSE
				if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
					closesocket(s);
					return NULL;
				}
			}
		} else {
			closesocket(s);
			return NULL;
		}
	}

	sock = NewSock();

	sock->Type = SOCK_UDP;
	sock->Connected = false;
	sock->AsyncMode = false;
	sock->ServerMode = false;
	sock->IPv6 = true;
	if (port != 0) {
		sock->ServerMode = true;
	}

	sock->socket = s;

	InitUdpSocketBufferSize(s);

	if (IS_SPECIAL_PORT(port)) {
		UINT no = 0;
#ifdef IPV6_HDRINCL
		(void)setsockopt(sock->socket, IPPROTO_IP, IPV6_HDRINCL, (char *)&no, sizeof(no));
#endif // IPV6_HDRINCL
		(void)setsockopt(sock->socket, IPPROTO_IP, IP_HDRINCL, (char *)&no, sizeof(no));

		sock->IsRawSocket = true;
		sock->RawSocketIPProtocol = GET_SPECIAL_PORT(port);
	}

	QuerySocketInformation(sock);

	return sock;
}

// Select function
void Select(SOCKSET *set, UINT timeout, CANCEL *c1, CANCEL *c2) {
#ifdef OS_WIN32
	Win32Select(set, timeout, c1, c2);
#endif // OS_WIN32
}

// Add a socket to the socket set
void AddSockSet(SOCKSET *set, SOCK *sock) {
	// Validate arguments
	if (set == NULL || sock == NULL) {
		return;
	}
	if (sock->Type == SOCK_TCP && sock->Connected == false) {
		return;
	}

	if (set->NumSocket >= MAX_SOCKSET_NUM) {
		// Upper limit
		return;
	}
	set->Sock[set->NumSocket++] = sock;
}

// Initializing the socket set
void InitSockSet(SOCKSET *set) {
	// Validate arguments
	if (set == NULL) {
		return;
	}

	Zero(set, sizeof(SOCKSET));
}

// Receive all by TCP
bool RecvAll(SOCK *sock, void *data, UINT size, bool secure) {
	UINT recv_size, sz, ret;
	// Validate arguments
	if (sock == NULL || data == NULL) {
		return false;
	}
	if (size == 0) {
		return true;
	}
	if (sock->AsyncMode) {
		return false;
	}

	recv_size = 0;

	while (true) {
		sz = size - recv_size;
		ret = Recv(sock, (UCHAR *)data + recv_size, sz, secure);
		if (ret == 0) {
			return false;
		}
		if (ret == SOCK_LATER) {
			// I suppose that this is safe because the RecvAll() function is used only
			// if the sock->AsyncMode == true. And the Recv() function may return
			// SOCK_LATER only if the sock->AsyncMode == false. Therefore the call of
			// Recv() function in the RecvAll() function never returns SOCK_LATER.
			return false;
		}
		recv_size += ret;
		if (recv_size >= size) {
			return true;
		}
	}
}

// Send the TCP send buffer
bool SendNow(SOCK *sock, int secure) {
	bool ret;
	// Validate arguments
	if (sock == NULL || sock->AsyncMode != false) {
		return false;
	}
	if (sock->SendBuf->Size == 0) {
		return true;
	}

	ret = SendAll(sock, sock->SendBuf->Buf, sock->SendBuf->Size, secure);
	ClearBuf(sock->SendBuf);

	return ret;
}

// Append to the TCP send buffer
void SendAdd(SOCK *sock, void *data, UINT size) {
	// Validate arguments
	if (sock == NULL || data == NULL || size == 0 || sock->AsyncMode != false) {
		return;
	}

	WriteBuf(sock->SendBuf, data, size);
}

// Send all by TCP
bool SendAll(SOCK *sock, void *data, UINT size, bool secure) {
	UCHAR *buf;
	UINT sent_size;
	UINT ret;
	// Validate arguments
	if (sock == NULL || data == NULL) {
		return false;
	}
	if (sock->AsyncMode) {
		return false;
	}
	if (size == 0) {
		return true;
	}

	buf = (UCHAR *)data;
	sent_size = 0;

	while (true) {
		ret = Send(sock, buf, size - sent_size, secure);
		if (ret == 0) {
			return false;
		}
		sent_size += ret;
		buf += ret;
		if (sent_size >= size) {
			return true;
		}
	}
}

// Set the cipher algorithm name to want to use
void SetWantToUseCipher(SOCK *sock, char *name) {
	// Validate arguments
	if (sock == NULL || name == NULL) {
		return;
	}

	if (sock->WaitToUseCipher) {
		Free(sock->WaitToUseCipher);
	}

	sock->WaitToUseCipher = CopyStr(name);
}

// Add all the chain certificates in the chain_certs directory
void AddChainSslCertOnDirectory(struct ssl_ctx_st *ctx) {
	wchar_t dirname[MAX_SIZE];
	wchar_t exedir[MAX_SIZE];
	wchar_t txtname[MAX_SIZE];
	DIRLIST *dir;
	LIST *o;
	UINT i;

	// Validate arguments
	if (ctx == NULL) {
		return;
	}

	o = NewListFast(NULL);

	GetDbDirW(exedir, sizeof(exedir));

	CombinePathW(dirname, sizeof(dirname), exedir, L"chain_certs");

	MakeDirExW(dirname);

	CombinePathW(txtname, sizeof(txtname), dirname, L"Readme_Chain_Certs.txt");

	if (IsFileExistsW(txtname) == false) {
		FileCopyW(L"|chain_certs.txt", txtname);
	}

	dir = EnumDirW(dirname);

	if (dir != NULL) {
		for (i = 0; i < dir->NumFiles; i++) {
			DIRENT *e = dir->File[i];

			if (e->Folder == false) {
				wchar_t tmp[MAX_SIZE];
				X *x;

				CombinePathW(tmp, sizeof(tmp), dirname, e->FileNameW);

				x = FileToXW(tmp);

				if (x != NULL) {
					UINT j;
					bool exists = false;
					UCHAR hash[SHA1_SIZE];

					GetXDigest(x, hash, true);

					for (j = 0; j < LIST_NUM(o); j++) {
						UCHAR *hash2 = LIST_DATA(o, j);

						if (Cmp(hash, hash2, SHA1_SIZE) == 0) {
							exists = true;
						}
					}

					if (exists == false) {
						AddChainSslCert(ctx, x);

						Add(o, Clone(hash, SHA1_SIZE));
					}

					FreeX(x);
				}
			}
		}

		FreeDir(dir);
	}

	for (i = 0; i < LIST_NUM(o); i++) {
		UCHAR *hash = LIST_DATA(o, i);

		Free(hash);
	}

	ReleaseList(o);
}

// Add the chain certificate
bool AddChainSslCert(struct ssl_ctx_st *ctx, X *x) {
	bool ret = false;
	X *x_copy;
	// Validate arguments
	if (ctx == NULL || x == NULL) {
		return ret;
	}

	x_copy = CloneX(x);

	if (x_copy != NULL) {
		SSL_CTX_add_extra_chain_cert(ctx, x_copy->x509);
		x_copy->do_not_free = true;

		ret = true;

		FreeX(x_copy);
	}

	return ret;
}

// Start a TCP-SSL communication
bool StartSSL(SOCK *sock, X *x, K *priv) {
	return StartSSLEx(sock, x, priv, 0, NULL);
}
bool StartSSLEx(SOCK *sock, X *x, K *priv, UINT ssl_timeout, char *sni_hostname) {
	return StartSSLEx2(sock, x, priv, NULL, ssl_timeout, sni_hostname);
}
bool StartSSLEx2(SOCK *sock, X *x, K *priv, LIST *chain, UINT ssl_timeout, char *sni_hostname) {
	return StartSSLEx3(sock, x, priv, chain, ssl_timeout, sni_hostname, NULL, NULL);
}
bool StartSSLEx3(SOCK *sock, X *x, K *priv, LIST *chain, UINT ssl_timeout, char *sni_hostname, SSL_VERIFY_OPTION *ssl_option, UINT *ssl_err) {
	X509 *x509;
	EVP_PKEY *key;
	UINT prev_timeout = 1024;
	SSL_CTX *ssl_ctx;
	UINT dummy_err = 0;
	long ssl_verify_err;

	// Validate arguments
	if (sock == NULL) {
		Debug("StartSSL Error: #0\n");
		return false;
	}
	if (ssl_err == NULL) {
		ssl_err = &dummy_err;
	}
	if (sock->Connected == false || sock->socket == INVALID_SOCKET ||
	    sock->ListenMode != false) {
		Debug("StartSSL Error: #1\n");
		return false;
	}
	if (x != NULL && priv == NULL) {
		Debug("StartSSL Error: #2\n");
		return false;
	}
	if (ssl_timeout == 0) {
		ssl_timeout = TIMEOUT_SSL_CONNECT;
	}

	if (sock->SecureMode) {
		//Debug("StartSSL Error: #3\n");
		// SSL communication has already started
		return true;
	}

	Lock(sock->ssl_lock);
	if (sock->SecureMode) {
		//Debug("StartSSL Error: #4\n");
		// SSL communication has already started
		Unlock(sock->ssl_lock);
		return true;
	}

	ssl_ctx = NewSSLCtx(sock->ServerMode);
	if (ssl_ctx == NULL) {
		return false;
	}

	Lock(openssl_lock);
	{
		if (sock->ServerMode) {
#ifdef SSL_OP_NO_TLSv1
			if (sock->SslAcceptSettings.Tls_Disable1_0) {
				SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_TLSv1);
			}
#endif // SSL_OP_NO_TLSv1

#ifdef SSL_OP_NO_TLSv1_1
			if (sock->SslAcceptSettings.Tls_Disable1_1) {
				SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_TLSv1_1);
			}
#endif // SSL_OP_NO_TLSv1_1

#ifdef SSL_OP_NO_TLSv1_2
			if (sock->SslAcceptSettings.Tls_Disable1_2) {
				SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_TLSv1_2);
			}
#endif // SSL_OP_NO_TLSv1_2

#ifdef SSL_OP_NO_TLSv1_3
			if (sock->SslAcceptSettings.Tls_Disable1_3) {
				SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_TLSv1_3);
			}
#endif // SSL_OP_NO_TLSv1_3

			Unlock(openssl_lock);
			if (chain == NULL) {
				AddChainSslCertOnDirectory(ssl_ctx);
			} else {
				UINT i;
				X *x;
				LockList(chain);
				{
					for (i = 0; i < LIST_NUM(chain); i++) {
						x = LIST_DATA(chain, i);
						AddChainSslCert(ssl_ctx, x);
					}
				}
				UnlockList(chain);
			}
			Lock(openssl_lock);
		} else {
			// Client mode
			if (ssl_option != NULL && ssl_option->VerifyPeer) {
				// Add default trust store
				X509_STORE *store = SSL_CTX_get_cert_store(ssl_ctx);
				if (ssl_option->AddDefaultCA) {
#ifdef OS_WIN32
					HCERTSTORE hStore = CertOpenSystemStore(0, "ROOT");
					if (hStore != NULL) {
						PCCERT_CONTEXT pContext = NULL;
						while ((pContext = CertEnumCertificatesInStore(hStore, pContext))) {
							X509 *x509 = d2i_X509(NULL, (const unsigned char **)&pContext->pbCertEncoded, pContext->cbCertEncoded);
							if (x509 != NULL) {
								X509_STORE_add_cert(store, x509);
								X509_free(x509);
							}
						}
						CertCloseStore(hStore, 0);
					}
#endif
				}

				// Add trust CA specified by user
				UINT i;
				for (i = 0; i < LIST_NUM(ssl_option->CaList); ++i) {
					X *ca = LIST_DATA(ssl_option->CaList, i);
					X509_STORE_add_cert(store, ca->x509);
				}

				// Allow intermediate CA to be trusted
				X509_VERIFY_PARAM *vpm = SSL_CTX_get0_param(ssl_ctx);
				X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_PARTIAL_CHAIN);

				// Enable hostname verification (by default CN is only checked if SAN is not available)
				if (ssl_option->VerifyHostname && IsEmptyStr(sni_hostname) == false) {
					X509_VERIFY_PARAM_set1_host(vpm, sni_hostname, StrLen(sni_hostname));
				}
			}
		}

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER)) || LIBRESSL_VERSION_NUMBER >= 0x3060000L
		if (sock->SslAcceptSettings.Override_Security_Level) {
			SSL_CTX_set_security_level(ssl_ctx, sock->SslAcceptSettings.Override_Security_Level_Value);
		}
#endif

		sock->ssl = SSL_new(ssl_ctx);

		if (sock->ssl == NULL) {
			return false;
		}

		SSL_set_fd(sock->ssl, (int)sock->socket);

#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
		if (sock->ServerMode == false) {
			if (IsEmptyStr(sni_hostname) == false) {
				// Set the SNI host name
				SSL_set_tlsext_host_name(sock->ssl, sni_hostname);
			}
		}
#endif // SSL_CTRL_SET_TLSEXT_HOSTNAME
	}
	Unlock(openssl_lock);

	if (x != NULL) {
		// Check the certificate and the private key
		if (CheckXandK(x, priv)) {
			// Use the certificate
			x509 = x->x509;
			key = priv->pkey;

			Lock(openssl_lock);
			{
				SSL_use_certificate(sock->ssl, x509);
				SSL_use_PrivateKey(sock->ssl, key);
			}
			Unlock(openssl_lock);
		}
	}

	if (sock->WaitToUseCipher != NULL) {
		// Set the cipher algorithm name to want to use
		Lock(openssl_lock);
		{
			if (SSL_set_cipher_list(sock->ssl, sock->WaitToUseCipher) == 0)
				SSL_set_cipher_list(sock->ssl, DEFAULT_CIPHER_LIST);
		}
		Unlock(openssl_lock);
	}

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	SSL_set1_groups_list(sock->ssl, PQ_GROUP_LIST);
#endif

	if (sock->ServerMode) {
		//		Lock(ssl_connect_lock);

		// Server mode
		if (SSL_accept(sock->ssl) <= 0) {

			//			Unlock(ssl_connect_lock);
			// SSL-Accept failure
			Lock(openssl_lock);
			{
				unsigned long err;
				while (err = ERR_get_error()) {
					Debug("SSL_accept error %X: %s\n", err, ERR_reason_error_string(err));
					if (ERR_GET_LIB(err) == ERR_LIB_SSL) {
						switch (ERR_GET_REASON(err)) {
						case SSL_R_UNSUPPORTED_PROTOCOL:
						case SSL_R_VERSION_TOO_LOW:
#if defined(SSL_R_VERSION_TOO_HIGH)
						case SSL_R_VERSION_TOO_HIGH:
#endif
							*ssl_err = 150; // ERR_SSL_PROTOCOL_VERSION
							break;
						case SSL_R_NO_SHARED_CIPHER:
							*ssl_err = 151; // ERR_SSL_SHARED_CIPHER
							break;
						default:
							*ssl_err = 152; // ERR_SSL_HANDSHAKE
						}
					}
				}
				SSL_free(sock->ssl);
				sock->ssl = NULL;
			}
			Unlock(openssl_lock);

			Unlock(sock->ssl_lock);
			Debug("StartSSL Error: #5\n");
			FreeSSLCtx(ssl_ctx);
			return false;
		}

#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
#ifdef TLSEXT_NAMETYPE_host_name
		if (true) {
			// Get the SNI host name
			const char *sni_recv_hostname = SSL_get_servername(sock->ssl, TLSEXT_NAMETYPE_host_name);

			if (IsEmptyStr((char *)sni_recv_hostname) == false) {
				StrCpy(sock->SniHostname, sizeof(sock->SniHostname), (char *)sni_recv_hostname);
			}
		}
#endif // TLSEXT_NAMETYPE_host_name
#endif // SSL_CTRL_SET_TLSEXT_HOSTNAME

		//		Unlock(ssl_connect_lock);
	} else {
		prev_timeout = GetTimeout(sock);
		SetTimeout(sock, ssl_timeout);
		// Client mode
		if (SSL_connect(sock->ssl) <= 0) {
			// SSL-connect failure
			Lock(openssl_lock);
			{
				unsigned long err;
				while (err = ERR_get_error()) {
					Debug("SSL_connect error %X: %s\n", err, ERR_reason_error_string(err));
					if (ERR_GET_LIB(err) == ERR_LIB_SSL) {
						switch (ERR_GET_REASON(err)) {
						case SSL_R_UNSUPPORTED_PROTOCOL:
						case SSL_R_VERSION_TOO_LOW:
#if defined(SSL_R_VERSION_TOO_HIGH)
						case SSL_R_VERSION_TOO_HIGH:
#endif
						case SSL_R_TLSV1_ALERT_PROTOCOL_VERSION:
							*ssl_err = 150; // ERR_SSL_PROTOCOL_VERSION
							break;
						default:
							*ssl_err = 152; // ERR_SSL_HANDSHAKE
						}
					}
				}
				SSL_free(sock->ssl);
				sock->ssl = NULL;
			}
			Unlock(openssl_lock);

			Unlock(sock->ssl_lock);
			Debug("StartSSL Error: #5\n");
			SetTimeout(sock, prev_timeout);
			FreeSSLCtx(ssl_ctx);
			return false;
		}
		SetTimeout(sock, prev_timeout);
	}

	// SSL communication is initiated
	sock->SecureMode = true;

	// Get the certificate of the remote host
	Lock(openssl_lock);
	{
		x509 = SSL_get_peer_certificate(sock->ssl);
		ssl_verify_err = SSL_get_verify_result(sock->ssl);
		sock->SslVersion = SSL_get_version(sock->ssl);
	}
	Unlock(openssl_lock);

	if (x509 == NULL) {
		// The certificate does not exist on the remote host
		sock->RemoteX = NULL;
	} else {
		// Got a certificate
		sock->RemoteX = X509ToX(x509);
	}

	// Check verification error
	if (ssl_option != NULL && ssl_option->VerifyPeer) {
		if (ssl_verify_err != X509_V_OK) {
			// Clear any error if matching saved certificate and not expired
			if (ssl_option->SavedCert != NULL && sock->RemoteX != NULL && CheckXDateNow(sock->RemoteX) && CompareX(ssl_option->SavedCert, sock->RemoteX)) {
				ssl_verify_err = X509_V_OK;
			} else {
				Debug("StartSSL: SSL verification error %d\n", ssl_verify_err);
				switch (ssl_verify_err) {
				case X509_V_ERR_CERT_HAS_EXPIRED:
					*ssl_err = 106; // ERR_SERVER_CERT_EXPIRES
					break;
				case X509_V_ERR_HOSTNAME_MISMATCH:
					*ssl_err = 149; // ERR_HOSTNAME_MISMATCH
					break;
				default:
					*ssl_err = 85; // ERR_CERT_NOT_TRUSTED
				}

				if (ssl_option->PromptOnVerifyFail == false) {
					// SSL verify failure
					Lock(openssl_lock);
					{
						SSL_free(sock->ssl);
						sock->ssl = NULL;
					}
					Unlock(openssl_lock);

					Unlock(sock->ssl_lock);
					FreeSSLCtx(ssl_ctx);
					return false;
				}
			}
		}
	}

	// Get the certificate of local host
	Lock(openssl_lock);
	{
		x509 = SSL_get_certificate(sock->ssl);
	}
	Unlock(openssl_lock);

	if (x509 == NULL) {
		// The certificate does not exist on the remote host
		sock->LocalX = NULL;
	} else {
		X *local_x;
		// Got a certificate
		local_x = X509ToX(x509);
		local_x->do_not_free = true;
		sock->LocalX = CloneX(local_x);
		FreeX(local_x);
	}

	// Automatic retry mode
	SSL_set_mode(sock->ssl, SSL_MODE_AUTO_RETRY);

	// Strange flag
	SSL_set_mode(sock->ssl, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

	sock->ssl_ctx = ssl_ctx;

	// Get the algorithm name used to encrypt
	Lock(openssl_lock);
	{
		sock->CipherName = CopyStr((char *)SSL_get_cipher(sock->ssl));
	}
	Unlock(openssl_lock);

	Unlock(sock->ssl_lock);

#ifdef ENABLE_SSL_LOGGING
	if (sock->ServerMode) {
		SockEnableSslLogging(sock);
	}
#endif // ENABLE_SSL_LOGGING

	return true;
}



#ifdef ENABLE_SSL_LOGGING

// Enable SSL logging
void SockEnableSslLogging(SOCK *s) {
	char dirname[MAX_PATH];
	char tmp[MAX_PATH];
	char dtstr[MAX_PATH];
	char fn1[MAX_PATH], fn2[MAX_PATH];
	// Validate arguments
	if (s == NULL) {
		return;
	}

	if (s->IsSslLoggingEnabled) {
		return;
	}

	s->IsSslLoggingEnabled = true;

	GetDateTimeStrMilli64ForFileName(dtstr, sizeof(dtstr), LocalTime64());
	Format(tmp, sizeof(tmp), "%s__%r_%u__%r_%u", dtstr,
	       &s->LocalIP, s->LocalPort, &s->RemoteIP, s->RemotePort);

	CombinePath(dirname, sizeof(dirname), SSL_LOGGING_DIRNAME, tmp);

	MakeDirEx(dirname);

	CombinePath(fn1, sizeof(fn1), dirname, "send.c");
	CombinePath(fn2, sizeof(fn2), dirname, "recv.c");

	s->SslLogging_Send = FileCreate(fn1);
	s->SslLogging_Recv = FileCreate(fn2);

	s->SslLogging_Lock = NewLock();
}

// Close SSL logging
void SockCloseSslLogging(SOCK *s) {
	// Validate arguments
	if (s == NULL) {
		return;
	}

	if (s->IsSslLoggingEnabled == false) {
		return;
	}

	s->IsSslLoggingEnabled = false;

	FileClose(s->SslLogging_Recv);
	s->SslLogging_Recv = NULL;

	FileClose(s->SslLogging_Send);
	s->SslLogging_Send = NULL;

	DeleteLock(s->SslLogging_Lock);
	s->SslLogging_Lock = NULL;
}

// Write SSL log
void SockWriteSslLog(SOCK *s, void *send_data, UINT send_size, void *recv_data, UINT recv_size) {
	// Validate arguments
	if (s == NULL) {
		return;
	}

	if (s->IsSslLoggingEnabled == false) {
		return;
	}

	Lock(s->SslLogging_Lock);
	{
		if (s->SslLogging_Send != NULL) {
			if (send_size >= 1 && send_data != NULL) {
				FileWrite(s->SslLogging_Send, send_data, send_size);
			}
		}

		if (s->SslLogging_Recv != NULL) {
			if (recv_size >= 1 && recv_data != NULL) {
				FileWrite(s->SslLogging_Recv, recv_data, recv_size);
			}
		}
	}
	Unlock(s->SslLogging_Lock);
}

#endif // ENABLE_SSL_LOGGING

// TCP-SSL receive
UINT SecureRecv(SOCK *sock, void *data, UINT size) {
	int ret, e = SSL_ERROR_NONE;
	SSL *ssl;

	ssl = sock->ssl;

	if (sock->AsyncMode) {
		// Confirm whether the data is readable even 1 byte in the case of asynchronous mode.
		// To read data results blocking, if there is no readable data.
		// We must avoid blocking.
		char c;
		Lock(sock->ssl_lock);
		{
			if (sock->Connected == false) {
				Unlock(sock->ssl_lock);
				Debug("%s %u SecureRecv() Disconnect\n", __FILE__, __LINE__);
				return 0;
			}
			ERR_clear_error();
			ret = SSL_peek(ssl, &c, sizeof(c));
		}
		Unlock(sock->ssl_lock);
#if OPENSSL_VERSION_NUMBER < 0x30000000L
		// 2021/09/10: After OpenSSL 3.x.x, both 0 and negative values might mean retryable.
		// See: https://github.com/openssl/openssl/blob/435981cbadad2c58c35bacd30ca5d8b4c9bea72f/doc/man3/SSL_read.pod
		// > Old documentation indicated a difference between 0 and -1, and that -1 was retryable.
		// > You should instead call SSL_get_error() to find out if it's retryable.
		if (ret == 0) {
			// The communication have been disconnected
			Disconnect(sock);
			Debug("%s %u SecureRecv() Disconnect\n", __FILE__, __LINE__);
			return 0;
		}
#endif
		if (ret <= 0) {
			// An error has occurred
			e = SSL_get_error(ssl, ret);
			if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE || e == SSL_ERROR_SSL) {
				if (e == SSL_ERROR_SSL
#if OPENSSL_VERSION_NUMBER < 0x10100000L
				    &&
				    sock->ssl->s3->send_alert[0] == SSL3_AL_FATAL &&
				    sock->ssl->s3->send_alert[0] != sock->Ssl_Init_Async_SendAlert[0] &&
				    sock->ssl->s3->send_alert[1] != sock->Ssl_Init_Async_SendAlert[1]
#endif
				) {
					UINT ssl_err_no;
					while (ssl_err_no = ERR_get_error()) {
						Debug("%s %u SSL_ERROR_SSL on ASYNC socket !!! ssl_err_no = %u: '%s'\n", __FILE__, __LINE__, ssl_err_no, ERR_error_string(ssl_err_no, NULL));
					};

					Disconnect(sock);
					return 0;
				}
				// Packet has not arrived yet, that is not to be read
				return SOCK_LATER;
			}
		}
	}

	// Receive
	Lock(sock->ssl_lock);
	{
		if (sock->Connected == false) {
			Unlock(sock->ssl_lock);
			Debug("%s %u SecureRecv() Disconnect\n", __FILE__, __LINE__);
			return 0;
		}

		ERR_clear_error();
		ret = SSL_read(ssl, data, size);

#if OPENSSL_VERSION_NUMBER < 0x30000000L
		if (ret < 0) // OpenSSL version < 3.0.0
#else
		if (ret <= 0) // OpenSSL version >= 3.0.0
#endif
		{
			e = SSL_get_error(ssl, ret);
		}
	}
	Unlock(sock->ssl_lock);

#ifdef ENABLE_SSL_LOGGING
	if (ret > 0) {
		SockWriteSslLog(sock, NULL, 0, data, ret);
	}
#endif // ENABLE_SSL_LOGGING

	if (ret > 0) {
		// Successful reception
		sock->RecvSize += (UINT64)ret;
		sock->RecvNum++;

		return (UINT)ret;
	}

#if OPENSSL_VERSION_NUMBER < 0x30000000L
	// 2021/09/10: After OpenSSL 3.x.x, both 0 and negative values might mean retryable.
	// See: https://github.com/openssl/openssl/blob/435981cbadad2c58c35bacd30ca5d8b4c9bea72f/doc/man3/SSL_read.pod
	// > Old documentation indicated a difference between 0 and -1, and that -1 was retryable.
	// > You should instead call SSL_get_error() to find out if it's retryable.
	if (ret == 0) {
		// Disconnect the communication
		Disconnect(sock);
		//Debug("%s %u SecureRecv() Disconnect\n", __FILE__, __LINE__);
		return 0;
	}
#endif

	if (sock->AsyncMode) {
		if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE || e == SSL_ERROR_SSL) {
			if (e == SSL_ERROR_SSL
#if OPENSSL_VERSION_NUMBER < 0x10100000L
			    &&
			    sock->ssl->s3->send_alert[0] == SSL3_AL_FATAL &&
			    sock->ssl->s3->send_alert[0] != sock->Ssl_Init_Async_SendAlert[0] &&
			    sock->ssl->s3->send_alert[1] != sock->Ssl_Init_Async_SendAlert[1]
#endif
			) {
				UINT ssl_err_no;
				while (ssl_err_no = ERR_get_error()) {
					Debug("%s %u SSL_ERROR_SSL on ASYNC socket !!! ssl_err_no = %u: '%s'\n", __FILE__, __LINE__, ssl_err_no, ERR_error_string(ssl_err_no, NULL));
				};

				Disconnect(sock);
				return 0;
			}

			// Packet has not yet arrived
			return SOCK_LATER;
		}
	}
	Debug("%s %u e=%u SecureRecv() Disconnect\n", __FILE__, __LINE__, e);
	Disconnect(sock);
	return 0;
}

// TCP-SSL transmission
UINT SecureSend(SOCK *sock, void *data, UINT size) {
	int ret, e = SSL_ERROR_NONE;
	SSL *ssl;
	ssl = sock->ssl;

	if (sock->AsyncMode) {
		// Asynchronous mode
		SSL_set_mode(ssl, SSL_MODE_ENABLE_PARTIAL_WRITE);
	}

	// Transmission
	Lock(sock->ssl_lock);
	{
		if (sock->Connected == false) {
			Unlock(sock->ssl_lock);
			Debug("%s %u SecureSend() Disconnect\n", __FILE__, __LINE__);
			return 0;
		}

		ERR_clear_error();
		ret = SSL_write(ssl, data, size);
#if OPENSSL_VERSION_NUMBER < 0x30000000L
		if (ret < 0) // OpenSSL version < 3.0.0
#else
		if (ret <= 0) // OpenSSL version >= 3.0.0
#endif
		{
			e = SSL_get_error(ssl, ret);
		}
	}
	Unlock(sock->ssl_lock);

#ifdef ENABLE_SSL_LOGGING
	if (ret > 0) {
		SockWriteSslLog(sock, data, ret, NULL, 0);
	}
#endif // ENABLE_SSL_LOGGING

	if (ret > 0) {
		// Successful transmission
		sock->SendSize += (UINT64)ret;
		sock->SendNum++;
		sock->WriteBlocked = false;
		return (UINT)ret;
	}

#if OPENSSL_VERSION_NUMBER < 0x30000000L
	if (ret == 0) {
		// Disconnect
		Debug("%s %u SecureSend() Disconnect\n", __FILE__, __LINE__);
		Disconnect(sock);
		return 0;
	}
#endif

	if (sock->AsyncMode) {
		// Confirmation of the error value
		if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE || e == SSL_ERROR_SSL) {
			if (e == SSL_ERROR_SSL) {
				UINT ssl_err_no;
				while (ssl_err_no = ERR_get_error()) {
					Debug("%s %u SSL_ERROR_SSL on ASYNC socket !!! ssl_err_no = %u: '%s'\n", __FILE__, __LINE__, ssl_err_no, ERR_error_string(ssl_err_no, NULL));
				};

				Disconnect(sock);
				return 0;
			}

			sock->WriteBlocked = true;
			return SOCK_LATER;
		}
	}
	Debug("%s %u e=%u SecureSend() Disconnect\n", __FILE__, __LINE__, e);
	Disconnect(sock);
	return 0;
}

// Peep the TCP
UINT Peek(SOCK *sock, void *data, UINT size) {
	SOCKET s;
	int ret;

	// Validate arguments
	if (sock == NULL || data == NULL || size == 0) {
		return 0;
	}
	if (sock->Type != SOCK_TCP || sock->Connected == false || sock->ListenMode != false ||
	    sock->socket == INVALID_SOCKET) {
		return 0;
	}
	if (sock->AsyncMode) {
		return 0;
	}

	// Receive
	s = sock->socket;

	ret = recv(s, data, size, MSG_PEEK);

	//Debug("Peek: %u\n", ret);

	if (ret > 0) {
		return ret;
	}

	return 0;
}

// TCP receive
UINT Recv(SOCK *sock, void *data, UINT size, bool secure) {
	SOCKET s;
	int ret;

	// Validate arguments
	if (sock == NULL || data == NULL || size == 0) {
		return 0;
	}

	sock->NoNeedToRead = false;

	if (sock->Type != SOCK_TCP || sock->Connected == false || sock->ListenMode != false ||
	    sock->socket == INVALID_SOCKET) {
		return 0;
	}
	if (secure != false && sock->SecureMode == false) {
		return 0;
	}

	if (secure) {
		return SecureRecv(sock, data, size);
	}

	// Receive
	s = sock->socket;

	ret = recv(s, data, size, 0);

	if (ret > 0) {
		// Successful reception
		Lock(sock->lock);
		{
			sock->RecvSize += (UINT64)ret;
			sock->SendNum++;
		}
		Unlock(sock->lock);
		return (UINT)ret;
	}

	// Transmission failure
	if (sock->AsyncMode) {
		// In asynchronous mode, examine the error
		if (ret == SOCKET_ERROR) {
#ifdef OS_WIN32
			if (WSAGetLastError() == WSAEWOULDBLOCK) {
				// In blocking
				return SOCK_LATER;
			} else {
				//Debug("Socket Error: %u\n", WSAGetLastError());
			}
#endif // OS_WIN32
		}
	}

	// Disconnected
	Disconnect(sock);
	return 0;
}

// TCP transmission
UINT Send(SOCK *sock, void *data, UINT size, bool secure) {
	SOCKET s;
	int ret;
	// Validate arguments
	if (sock == NULL || data == NULL || size == 0) {
		return 0;
	}
	size = MIN(size, MAX_SEND_BUF_MEM_SIZE);
	if (sock->Type != SOCK_TCP || sock->Connected == false || sock->ListenMode != false ||
	    sock->socket == INVALID_SOCKET) {
		return 0;
	}
	if (secure != false && sock->SecureMode == false) {
		return 0;
	}

	if (secure) {
		return SecureSend(sock, data, size);
	}

	// Transmission
	s = sock->socket;
	ret = send(s, data, size, 0);
	if (ret > 0) {
		// Successful transmission
		Lock(sock->lock);
		{
			sock->SendSize += (UINT64)ret;
			sock->SendNum++;
		}
		Unlock(sock->lock);
		sock->WriteBlocked = false;
		return (UINT)ret;
	}

	// Transmission failure
	if (sock->AsyncMode) {
		// In asynchronous mode, examine the error
		if (ret == SOCKET_ERROR) {
#ifdef OS_WIN32
			if (WSAGetLastError() == WSAEWOULDBLOCK) {
				// In blocking
				sock->WriteBlocked = true;
				return SOCK_LATER;
			} else {
				//Debug("Socket Error: %u\n", WSAGetLastError());
			}
#endif // OS_WIN32
		}
	}

	// Disconnected
	Disconnect(sock);
	return 0;
}

// Get the time-out value (in milliseconds)
UINT GetTimeout(SOCK *sock) {
	// Validate arguments
	if (sock == NULL) {
		return INFINITE;
	}
	if (sock->Type != SOCK_TCP) {
		return INFINITE;
	}

	return sock->TimeOut;
}

// Setting the time-out value (in milliseconds)
void SetTimeout(SOCK *sock, UINT timeout) {
	// Validate arguments
	if (sock == NULL) {
		return;
	}
	if (sock->Type == SOCK_UDP) {
		return;
	}

	if (timeout == INFINITE) {
		timeout = TIMEOUT_INFINITE;
	}

	sock->TimeOut = timeout;

	//	Debug("SetTimeout(%u)\n",timeout);

#ifdef OS_WIN32
	setsockopt(sock->socket, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(UINT));
	setsockopt(sock->socket, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(UINT));
#endif
}

// Disable GetHostName call by accepting new TCP connection
void DisableGetHostNameWhenAcceptInit() {
	disable_gethostname_by_accept = true;
}

// Initialize the connection acceptance
void AcceptInit(SOCK *s) {
	AcceptInitEx(s, false);
}
void AcceptInitEx(SOCK *s, bool no_lookup_hostname) {
	char tmp[MAX_SIZE];
	// Validate arguments
	if (s == NULL) {
		return;
	}

	Zero(tmp, sizeof(tmp));

	if (disable_gethostname_by_accept == false && no_lookup_hostname == false) {
		if (GetHostName(tmp, sizeof(tmp), &s->RemoteIP) == false ||
		    IsEmptyStr(tmp)) {
			IPToStr(tmp, sizeof(tmp), &s->RemoteIP);
		}
	} else {
		IPToStr(tmp, sizeof(tmp), &s->RemoteIP);
	}

	if (s->RemoteHostname != NULL) {
		Free(s->RemoteHostname);
	}

	s->RemoteHostname = CopyStr(tmp);
}

// TCP connection acceptance (IPv4)
SOCK *Accept(SOCK *sock) {
	SOCK *ret;
	SOCKET s, new_socket;
	int size;
	struct sockaddr_in addr;
	UINT true_flag = 1;
	// Validate arguments
	if (sock == NULL) {
		return NULL;
	}
	if (sock->ListenMode == false || sock->Type != SOCK_TCP || sock->ServerMode == false) {
		return NULL;
	}
	if (sock->CancelAccept) {
		return NULL;
	}
	if (sock->IPv6) {
		return Accept6(sock);
	}

	s = sock->socket;
	if (s == INVALID_SOCKET) {
		return NULL;
	}
	Zero(&addr, sizeof(addr));
	size = sizeof(addr);

#ifdef OS_WIN32
	if (sock->EnableConditionalAccept) {
		new_socket = Win32Accept(sock, s, (struct sockaddr *)&addr, (int *)&size, false);
	} else {
		new_socket = accept(s, (struct sockaddr *)&addr, (int *)&size);
	}
#endif // OS_WIN32

	if (new_socket == INVALID_SOCKET) {
		if (sock->CancelAccept) {
			sock->AcceptCanceled = true;
		}
		return NULL;
	}
	if (sock->CancelAccept) {
		sock->AcceptCanceled = true;
		closesocket(new_socket);
		return NULL;
	}

	ret = NewSock();
	ret->socket = new_socket;
	ret->Connected = true;
	ret->AsyncMode = false;
	ret->Type = SOCK_TCP;
	ret->ServerMode = true;
	ret->SecureMode = false;

	// Configuring the TCP options
	(void)setsockopt(ret->socket, IPPROTO_TCP, TCP_NODELAY, (char *)&true_flag, sizeof(true_flag));

	// Initialization of the time-out value
	SetTimeout(ret, TIMEOUT_INFINITE);

	// Socket information
	QuerySocketInformation(ret);

	if (IsLocalHostIP(&ret->RemoteIP) == false) {
		ret->IpClientAdded = true;
		AddIpClient(&ret->RemoteIP);
	}

	if (IsZeroIp(&sock->LocalIP) == false && IsLocalHostIP(&sock->LocalIP) == false) {
		IP current_ip;

		if (GetCurrentGlobalIP(&current_ip, false) == false) {
			SetCurrentGlobalIP(&sock->LocalIP, false);
		}
	}

	StrCpy(ret->UnderlayProtocol, sizeof(ret->UnderlayProtocol), SOCK_UNDERLAY_NATIVE_V4);

	AddProtocolDetailsStr(ret->ProtocolDetails, sizeof(ret->ProtocolDetails), "IPv4");

	return ret;
}

// TCP connection acceptance (IPv6)
SOCK *Accept6(SOCK *sock) {
	SOCK *ret;
	SOCKET s, new_socket;
	int size;
	struct sockaddr_in6 addr;
	// Validate arguments
	if (sock == NULL) {
		return NULL;
	}
	if (sock->ListenMode == false || sock->Type != SOCK_TCP || sock->ServerMode == false) {
		return NULL;
	}
	if (sock->CancelAccept) {
		return NULL;
	}
	if (sock->IPv6 == false) {
		return NULL;
	}

	s = sock->socket;
	if (s == INVALID_SOCKET) {
		return NULL;
	}
	Zero(&addr, sizeof(addr));
	size = sizeof(addr);

#ifdef OS_WIN32
	if (sock->EnableConditionalAccept) {
		new_socket = Win32Accept(sock, s, (struct sockaddr *)&addr, (int *)&size, true);
	} else {
		new_socket = accept(s, (struct sockaddr *)&addr, (int *)&size);
	}
#endif // OS_WIN32

	if (new_socket == INVALID_SOCKET) {
		if (sock->CancelAccept) {
			sock->AcceptCanceled = true;
		}
		return NULL;
	}
	if (sock->CancelAccept) {
		sock->AcceptCanceled = true;
		closesocket(new_socket);
		return NULL;
	}

	ret = NewSock();
	ret->socket = new_socket;
	ret->Connected = true;
	ret->AsyncMode = false;
	ret->Type = SOCK_TCP;
	ret->ServerMode = true;
	ret->SecureMode = false;

	// Configuring the TCP options
	UINT true_flag = 1;
	(void)setsockopt(ret->socket, IPPROTO_TCP, TCP_NODELAY, (char *)&true_flag, sizeof(true_flag));

	// Initialize the time-out value
	SetTimeout(ret, TIMEOUT_INFINITE);

	// Socket information
	QuerySocketInformation(ret);

	if (IsLocalHostIP(&ret->RemoteIP) == false) {
		ret->IpClientAdded = true;
		AddIpClient(&ret->RemoteIP);
	}
	if (IsZeroIp(&sock->LocalIP) == false && IsLocalHostIP(&sock->LocalIP) == false) {
		IP current_ip;

		if (GetCurrentGlobalIP(&current_ip, true) == false) {
			SetCurrentGlobalIP(&sock->LocalIP, true);
		}
	}

	StrCpy(ret->UnderlayProtocol, sizeof(ret->UnderlayProtocol), SOCK_UNDERLAY_NATIVE_V6);

	AddProtocolDetailsStr(ret->ProtocolDetails, sizeof(ret->ProtocolDetails), "IPv6");

	return ret;
}

// Standby for TCP (IPv6)
SOCK *ListenEx6(UINT port, bool local_only) {
	return ListenEx62(port, local_only, false);
}
SOCK *ListenEx62(UINT port, bool local_only, bool enable_ca) {
	return ListenEx63(port, local_only, enable_ca, NULL);
}
SOCK *ListenEx63(UINT port, bool local_only, bool enable_ca, IP *listen_ip) {
	SOCKET s;
	SOCK *sock;
	struct sockaddr_in6 addr;
	struct in6_addr in;
	IP localhost;
	UINT backlog = SOMAXCONN;
	// Validate arguments
	if (port == 0 || port >= 65536) {
		return NULL;
	}

	// Initialization
	Zero(&addr, sizeof(addr));
	Zero(&in, sizeof(in));
	GetLocalHostIP6(&localhost);

	addr.sin6_port = htons((UINT)port);
	if (listen_ip == NULL || IsZeroIP(listen_ip)) {
		addr.sin6_addr = in6addr_any;
	} else if (IsIP6(listen_ip)) {
		IPToInAddr6(&addr.sin6_addr, listen_ip);
	} else {
		return NULL;
	}
	addr.sin6_family = AF_INET6;

	if (local_only) {
		IPToInAddr6(&addr.sin6_addr, &localhost);

		enable_ca = false;
	}

	// Creating a socket
	s = socket(AF_INET6, SOCK_STREAM, 0);
	if (s == INVALID_SOCKET) {
		return NULL;
	}

	UINT true_flag = 1;

	if (bind(s, (struct sockaddr *)&addr, sizeof(struct sockaddr_in6)) != 0) {
		// Bind failure
		closesocket(s);
		return NULL;
	}

#ifdef OS_WIN32
	if (enable_ca) {
		backlog = 1;
	}
#endif

	if (listen(s, backlog)) {
		// Listen failure
		closesocket(s);
		return NULL;
	}

	// Success
	sock = NewSock();
	sock->Connected = false;
	sock->AsyncMode = false;
	sock->ServerMode = true;
	sock->Type = SOCK_TCP;
	sock->socket = s;
	sock->ListenMode = true;
	sock->SecureMode = false;
	sock->LocalPort = port;
	sock->IPv6 = true;
	sock->LocalOnly = local_only;
	sock->EnableConditionalAccept = enable_ca;

	return sock;
}

// Standby for the TCP
SOCK *Listen(UINT port) {
	return ListenEx(port, false);
}
SOCK *ListenEx(UINT port, bool local_only) {
	return ListenEx2(port, local_only, false, NULL);
}
SOCK *ListenEx2(UINT port, bool local_only, bool enable_ca, IP *listen_ip) {
	SOCKET s;
	SOCK *sock;
	struct sockaddr_in addr;
	struct in_addr in;
	IP localhost;
	UINT backlog = SOMAXCONN;
	// Validate arguments
	if (port == 0 || port >= 65536) {
		return NULL;
	}

	// Initialization
	Zero(&addr, sizeof(addr));
	Zero(&in, sizeof(in));
	SetIP(&localhost, 127, 0, 0, 1);

	addr.sin_port = htons((UINT)port);
	if (listen_ip == NULL || IsZeroIP(listen_ip)) {
		*((UINT *)&addr.sin_addr) = htonl(INADDR_ANY);
	} else if (IsIP4(listen_ip)) {
		IPToInAddr(&addr.sin_addr, listen_ip);
	} else {
		return NULL;
	}
	addr.sin_family = AF_INET;

	if (local_only) {
		IPToInAddr(&addr.sin_addr, &localhost);

		enable_ca = false;
	}

	// Creating a socket
	s = socket(AF_INET, SOCK_STREAM, 0);
	if (s == INVALID_SOCKET) {
		return NULL;
	}

	UINT true_flag = 1;

	if (bind(s, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) != 0) {
		// Bind failure
		closesocket(s);
		return NULL;
	}

#ifdef OS_WIN32
	if (enable_ca) {
		setsockopt(s, SOL_SOCKET, SO_CONDITIONAL_ACCEPT, (char *)&true_flag, sizeof(true_flag));
		backlog = 1;
	}
#endif // OS_WIN32

	if (listen(s, backlog)) {
		// Listen failure
		closesocket(s);
		return NULL;
	}

	// Success
	sock = NewSock();
	sock->Connected = false;
	sock->AsyncMode = false;
	sock->ServerMode = true;
	sock->Type = SOCK_TCP;
	sock->socket = s;
	sock->ListenMode = true;
	sock->SecureMode = false;
	sock->LocalPort = port;
	sock->LocalOnly = local_only;
	sock->EnableConditionalAccept = enable_ca;

	return sock;
}

// TCP disconnect
void Disconnect(SOCK *sock) {
	SOCKET s;
	// Validate arguments
	if (sock == NULL) {
		return;
	}

	sock->Disconnecting = true;

#ifdef ENABLE_SSL_LOGGING
	SockCloseSslLogging(sock);
#endif // ENABLE_SSL_LOGGING

	if (sock->Type == SOCK_TCP && sock->ListenMode) {
		bool no_tcp_check_port = false;

		// Connect to localhost if the socket is in listening
		sock->CancelAccept = true;

#ifdef OS_WIN32
		if (sock->hAcceptEvent != NULL) {
			SetEvent(sock->hAcceptEvent);

			no_tcp_check_port = true;
		}
#endif // OS_WIN32

		if (sock->AcceptCanceled == false) {
			if (no_tcp_check_port == false) {
				if (sock->IPv6 == false) {
					CheckTCPPort("127.0.0.1", sock->LocalPort);
				} else {
					CheckTCPPort("::1", sock->LocalPort);
				}
			}
		}
	}

	Lock(disconnect_function_lock);

	Lock(sock->disconnect_lock);

	if (sock->Type == SOCK_TCP) {
		if (sock->socket != INVALID_SOCKET) {
			// Forced disconnection flag
#ifdef SO_DONTLINGER
			UINT true_flag = 1;
			(void)setsockopt(sock->socket, SOL_SOCKET, SO_DONTLINGER, (char *)&true_flag, sizeof(true_flag));
#else       // SO_DONTLINGER
			UINT false_flag = 0;
			(void)setsockopt(sock->socket, SOL_SOCKET, SO_LINGER, (char *)&false_flag, sizeof(false_flag));
#endif      // SO_DONTLINGER
			//			setsockopt(sock->socket, SOL_SOCKET, SO_REUSEADDR, (char *)&true_flag, sizeof(true_flag));
		}

		// TCP socket
		Lock(sock->lock);
		{
			if (sock->socket == INVALID_SOCKET) {
				Unlock(sock->lock);
				Unlock(sock->disconnect_lock);
				Unlock(disconnect_function_lock);
				return;
			}
			s = sock->socket;

			if (sock->Connected) {
				struct linger ling;
				Zero(&ling, sizeof(ling));


#if 0
				// SSL disconnect
				Lock(sock->ssl_lock);
				{
					if (sock->SecureMode)
					{
						SSL_shutdown(sock->ssl);
					}
				}
				Unlock(sock->ssl_lock);
#endif
				// Disconnect
				shutdown(s, 2);
			}

			// Close the socket
			closesocket(s);

			// Release the SSL
			Lock(sock->ssl_lock);
			{
				if (sock->SecureMode) {
					if (sock->ssl != NULL) {
						Lock(openssl_lock);
						{
							SSL_free(sock->ssl);
							FreeSSLCtx(sock->ssl_ctx);
						}
						Unlock(openssl_lock);
						sock->ssl = NULL;
						sock->ssl_ctx = NULL;
					}
					sock->Connected = false;
					sock->SecureMode = false;
				}
			}
			Unlock(sock->ssl_lock);

			// Initialization
			sock->socket = INVALID_SOCKET;
			sock->Type = 0;
			sock->AsyncMode = false;
			sock->Connected = false;
			sock->ListenMode = false;
			sock->SecureMode = false;

			if (sock->IpClientAdded) {
				DelIpClient(&sock->RemoteIP);
				sock->IpClientAdded = false;
			}
		}
		Unlock(sock->lock);
	} else if (sock->Type == SOCK_UDP) {
		// UDP socket
		Lock(sock->lock);
		{
			if (sock->socket == INVALID_SOCKET) {
				Unlock(sock->lock);
				Unlock(sock->disconnect_lock);
				Unlock(disconnect_function_lock);
				return;
			}

			s = sock->socket;

			// Close the socket
			closesocket(s);

			// Initialization
			sock->socket = INVALID_SOCKET;
			sock->Type = 0;
			sock->AsyncMode = false;
			sock->Connected = false;
			sock->ListenMode = false;
			sock->SecureMode = false;
		}
		Unlock(sock->lock);
	}
	Unlock(sock->disconnect_lock);

	Unlock(disconnect_function_lock);
}

typedef struct TCP_PORT_CHECK {
	REF *ref;
	char hostname[MAX_SIZE];
	UINT port;
	bool ok;
} TCP_PORT_CHECK;

// Check whether the TCP port can be connected
bool CheckTCPPortEx(char *hostname, UINT port, UINT timeout) {
	SOCK *s;
	// Validate arguments
	if (hostname == NULL || port == 0 || port >= 65536) {
		return false;
	}

	if (timeout == 0) {
		timeout = TIMEOUT_TCP_PORT_CHECK;
	}

	s = ConnectEx(hostname, port, timeout);
	if (s == NULL) {
		return false;
	} else {
		Disconnect(s);
		ReleaseSock(s);
		return true;
	}
}
bool CheckTCPPort(char *hostname, UINT port) {
	return CheckTCPPortEx(hostname, port, TIMEOUT_TCP_PORT_CHECK);
}

#if 0
LPSTR PrintError(int ErrorCode)
{
	static char Message[1024];

	// If this program was multithreaded, we'd want to use
	// FORMAT_MESSAGE_ALLOCATE_BUFFER instead of a static buffer here.
	// (And of course, free the buffer when we were done with it)

	FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS |
		FORMAT_MESSAGE_MAX_WIDTH_MASK, NULL, ErrorCode,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPSTR)Message, 1024, NULL);
	return Message;
}
#else
char *PrintError(int ErrorCode) {
	char *Message;
	switch (ErrorCode) {
	case WSAEFAULT:
		Message = "Bad address.";
		break;

	case WSAEWOULDBLOCK:
		Message = "Resource temporarily unavailable.";
		break;

	case WSAEINPROGRESS:
		Message = "Operation now in progress.";
		break;

	case WSAEALREADY:
		Message = "Operation already in progress.";
		break;

	case WSAEAFNOSUPPORT:
		Message = "Address family not supported by protocol family.";
		break;

	case WSAEADDRINUSE:
		Message = "Address already in use.";
		break;

	case WSAEADDRNOTAVAIL:
		Message = "Cannot assign requested address.";
		break;

	case WSAEISCONN:
		Message = "Socket is already connected."; // Added on AUG.10, 2023
		break;

	case WSAEINVAL:
		Message = "Invalid argument."; // Added on AUG.10, 2023
		break;

	default:
		Message = "";
		break;
	}
	return Message;
}
#endif

// Connection with timeout (Win32 version)
int connect_timeout(SOCKET s, struct sockaddr *addr, int size, int timeout, bool *cancel_flag) {
	UINT64 start_time;
	bool ok = false;
	bool timeouted = false;
	WSAEVENT hEvent;
	UINT zero = 0;
	UINT tmp = 0;
	DWORD ret_size = 0;
	// Validate arguments
	if (s == INVALID_SOCKET || addr == NULL) {
		return -1;
	}
	if (timeout == 0) {
		timeout = TIMEOUT_TCP_PORT_CHECK;
	}

	// Create an event
	hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);

	// Associate the socket with the event
	WSAEventSelect(s, hEvent, FD_CONNECT);

	start_time = Tick64();

	while (true) {
		int ret;

		ret = connect(s, addr, size);

		if (ret == 0) {
			ok = true;
			break;
		} else {
			int err = WSAGetLastError();
			//Debug("err=%u\n", err);
			//Debug("cancel_flag=%u\n", *cancel_flag);
			if (timeouted && err == WSAEALREADY) {
				// Time-out
				ok = false;
				break;
			}
			if (*cancel_flag) {
				// Cancel
				ok = false;
				break;
			}
			if (err == WSAEISCONN || err == WSAEINVAL) {
				ok = true;
				break;
			}
			if (((start_time + (UINT64)timeout) <= Tick64()) || (err != WSAEWOULDBLOCK && err != WSAEALREADY)) {
				// Failure (timeout)
				break;
			} else {
				SleepThread(10);
				// Connecting
				if (WaitForSingleObject(hEvent, 100) == WAIT_OBJECT_0) {
					timeouted = true;
				}
			}
		}
	}

	// Remove the socket from the event
	WSAEventSelect(s, hEvent, 0);

	// Restore to synchronized socket
	WSAIoctl(s, FIONBIO, &zero, sizeof(zero), &tmp, sizeof(tmp), &ret_size, NULL, NULL);

	// Close the event
	CloseHandle(hEvent);

	if (ok) {
		return 0;
	} else {
		return -1;
	}
}

// Set the TOS value of the socket
void SetSockTos(SOCK *s, int tos) {
	// Validate arguments
	if (s == NULL) {
		return;
	}

	if (s->CurrentTos == tos) {
		return;
	}

#ifdef IP_TOS
	(void)setsockopt(s->socket, IPPROTO_IP, IP_TOS, (char *)&tos, sizeof(int));
#endif // IP_TOS

	s->CurrentTos = tos;
}

// Set the priority of the socket
void SetSockHighPriority(SOCK *s, bool flag) {
	// Validate arguments
	if (s == NULL) {
		return;
	}

	SetSockTos(s, (flag ? 16 : 0));
}

// Bind the socket to IPv4 or IPV6 address
int bind_sock(SOCKET sock, IP *ip, UINT port) {
	//char tmp[MAX_HOST_NAME_LEN + 1];
	//memset(tmp, 0, sizeof(tmp));
	//IPToStr(tmp, sizeof(tmp), ip);
	//Debug("bind_sock(): Binding... IP address %s:%d\n", tmp, port);

	if (IsIP4(ip)) {
		// Declare variables
		struct sockaddr_in sockaddr_in;

		Zero(&sockaddr_in, sizeof(sockaddr_in));

		// Set up the sockaddr structure
		sockaddr_in.sin_family = AF_INET;
		IPToInAddr(&sockaddr_in.sin_addr, ip);
		sockaddr_in.sin_port = htons((USHORT)port);
		//inet_pton(AF_INET, tmp, &addr_in.sin_addr.s_addr);

		UINT true_flag = 1;
		// This only have enabled for UNIX system since there is a bug
		// in the implementation of REUSEADDR in Windows OS
		(void)setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *)&true_flag, sizeof(true_flag));

		// Bind the socket using the information in the sockaddr structure
		return (bind(sock, (struct sockaddr *)&sockaddr_in, sizeof(sockaddr_in)));
	} else {
		// Declare variables
		struct sockaddr_in6 sockaddr_in;

		Zero(&sockaddr_in, sizeof(sockaddr_in));

		// Set up the sockaddr structure
		sockaddr_in.sin6_family = AF_INET6;
		IPToInAddr6(&sockaddr_in.sin6_addr, ip);
		sockaddr_in.sin6_scope_id = ip->ipv6_scope_id;
		sockaddr_in.sin6_port = htons((USHORT)port);
		//inet_pton(AF_INET6, tmp, &sockaddr_in.sin6_addr.s6_bytes);

		UINT true_flag = 1;
		// This only have enabled for UNIX system since there is a bug
		// in the implementation of REUSEADDR in Windows OS
		(void)setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *)&true_flag, sizeof(true_flag));

		// Bind the socket using the information in the sockaddr structure
		return (bind(sock, (struct sockaddr *)&sockaddr_in, sizeof(sockaddr_in)));
	}
}

// Connect to the IPv4 host using a socket
SOCKET BindConnectTimeoutIPv4(IP *localIP, UINT localport, IP *ip, UINT port, UINT timeout, bool *cancel_flag) {
	SOCKET s;
	struct sockaddr_in sockaddr4;
	struct in_addr addr4;

	Zero(&sockaddr4, sizeof(sockaddr4));
	Zero(&addr4, sizeof(addr4));

	// Generate a sockaddr_in
	IPToInAddr(&addr4, ip);
	sockaddr4.sin_port = htons((USHORT)port);
	sockaddr4.sin_family = AF_INET;
	sockaddr4.sin_addr.s_addr = addr4.s_addr;

	// Socket creation
	s = socket(AF_INET, SOCK_STREAM, 0);

	// Top of Bind outgoing connection
	if (s != INVALID_SOCKET) {
		int ier;
		IP tmpIP;
		IP *tmpIP2;

		if (localIP == BIND_LOCALIP_NULL) {
			StrToIP(&tmpIP, "0.0.0.0"); // A NULL address for the argument "localIP" is treated as if "0.0.0.0" in IPV4 was specified.
			tmpIP2 = &tmpIP;
		} else {
			tmpIP2 = localIP;
		}

		if ((IsZeroIP(tmpIP2) == false) || (localport != 0)) {

			// Bind the socket
			if (bind_sock(s, tmpIP2, localport) != 0) {
#ifdef OS_WIN32
				ier = WSAGetLastError();
				Debug("IPv4 bind() failed with error: %d %s\n", ier, PrintError(ier));
#endif
				closesocket(s);
				s = INVALID_SOCKET;
			}
		}
	}
	// Bottom of Bind outgoing connection

	if (s != INVALID_SOCKET) {
		// Connection
		if (connect_timeout(s, (struct sockaddr *)&sockaddr4, sizeof(struct sockaddr_in), timeout, cancel_flag) != 0) {
			// Connection failure
			closesocket(s);
			s = INVALID_SOCKET;
		}
	}

	return s;
}

// IPv4 connection thread (multiple protocols, multiple addresses)
//void ConnectThreadForIPv4(THREAD* thread, void* param)
void BindConnectThreadForIPv4(THREAD *thread, void *param) {
	SOCKET s = INVALID_SOCKET;
	IP current_ip;
	UINT i;
	CONNECT_SERIAL_PARAM *p = (CONNECT_SERIAL_PARAM *)param;
	if (thread == NULL || p == NULL) {
		return;
	}

	// Delay before start
	if (p->Delay >= 1) {
		WaitEx(NULL, p->Delay, p->NoDelayFlag);
	}

	Zero(&current_ip, sizeof(current_ip));

	for (i = 0; i < LIST_NUM(p->IpList); ++i) {
		IP *ip = LIST_DATA(p->IpList, i);

		if (IsZeroIp(ip)) {
			continue;
		}

		// Delay before retry
		if (i > 0 && p->RetryDelay >= 1) {
			WaitEx(NULL, p->RetryDelay, p->CancelFlag);
		}

		if (*p->CancelFlag) {
			// Cancel by the user
			break;
		}

		// Normal connection
		//			s = ConnectTimeoutIPv4(ip, p->Port, p->Timeout, p->CancelFlag);
		s = BindConnectTimeoutIPv4(p->LocalIP, p->LocalPort, ip, p->Port, p->Timeout, p->CancelFlag);

		if (s != INVALID_SOCKET) {
			Copy(&current_ip, ip, sizeof(IP));

			Copy(p->Ret_Ip, ip, sizeof(IP));
		}

		if (s != INVALID_SOCKET) {
			p->Sock = CreateTCPSock(s, false, &current_ip, p->No_Get_Hostname, p->Hostname);
			break;
		}
	}

	p->Ok = (p->Sock == NULL ? false : true);
	p->FinishedTick = Tick64();
	p->Finished = true;

	Set(p->FinishEvent);
}

// IPv6 connection thread (multiple addresses)
//void ConnectThreadForIPv6(THREAD *thread, void *param)
void BindConnectThreadForIPv6(THREAD *thread, void *param) {
	SOCKET s = INVALID_SOCKET;
	IP current_ip;
	UINT i;
	CONNECT_SERIAL_PARAM *p = (CONNECT_SERIAL_PARAM *)param;
	if (thread == NULL || p == NULL) {
		return;
	}

	// Delay before start
	if (p->Delay >= 1) {
		WaitEx(NULL, p->Delay, p->NoDelayFlag);
	}

	Zero(&current_ip, sizeof(current_ip));

	for (i = 0; i < LIST_NUM(p->IpList); ++i) {
		IP *ip = LIST_DATA(p->IpList, i);

		if (IsZeroIp(ip)) {
			continue;
		}

		// Delay before retry
		if (i > 0 && p->RetryDelay >= 1) {
			WaitEx(NULL, p->RetryDelay, p->CancelFlag);
		}

		if (*p->CancelFlag) {
			// Cancel by the user
			break;
		}

		struct sockaddr_in6 sockaddr6;
		struct in6_addr addr6;

		Zero(&sockaddr6, sizeof(sockaddr6));
		Zero(&addr6, sizeof(addr6));

		// Generation of the sockaddr_in6
		IPToInAddr6(&addr6, ip);
		sockaddr6.sin6_port = htons((USHORT)p->Port);
		sockaddr6.sin6_family = AF_INET6;
		sockaddr6.sin6_scope_id = ip->ipv6_scope_id;
		Copy(&sockaddr6.sin6_addr, &addr6, sizeof(addr6));

		// Socket creation
		s = socket(AF_INET6, SOCK_STREAM, 0);

		// Top of Bind outgoing connection
		if (s != INVALID_SOCKET) {
			int ier;
			IP tmpIP;
			IP *tmpIP2;

			if (p->LocalIP == BIND_LOCALIP_NULL) {
				StrToIP(&tmpIP, "0::0"); // A NULL address for the argument "p->LocalIP" is treated as if "0::0" in IPV6 was specified.
				tmpIP2 = &tmpIP;
			} else {
				tmpIP2 = p->LocalIP;
			}

			if ((IsZeroIP(tmpIP2) == false) || (p->LocalPort != 0)) {

				// Bind the socket
				if (bind_sock(s, tmpIP2, p->LocalPort) != 0) {
#ifdef OS_WIN32
					ier = WSAGetLastError();
					Debug("IPv6 bind() failed with error: %d %s\n", ier, PrintError(ier));
#endif
					closesocket(s);
					s = INVALID_SOCKET;
				}
			}
		}
		// Bottom of Bind outgoing connection

		if (s != INVALID_SOCKET) {
			// Connection
			if (connect_timeout(s, (struct sockaddr *)&sockaddr6, sizeof(struct sockaddr_in6), p->Timeout, p->CancelFlag) != 0) {
				// Connection failure
				closesocket(s);
				s = INVALID_SOCKET;
			} else {
				Copy(&current_ip, ip, sizeof(IP));

				Copy(p->Ret_Ip, ip, sizeof(IP));
			}
		}

		if (s != INVALID_SOCKET) {
			p->Sock = CreateTCPSock(s, true, &current_ip, p->No_Get_Hostname, p->Hostname);
			break;
		}
	}

	p->Ok = (p->Sock == NULL ? false : true);
	p->FinishedTick = Tick64();
	p->Finished = true;

	Set(p->FinishEvent);
}

// Creating a TCP SOCK from a SOCKET
SOCK *CreateTCPSock(SOCKET s, bool is_ipv6, IP *current_ip, bool no_get_hostname, char *hostname_original) {
	struct linger ling;
	char tmp[MAX_SIZE];
	SOCK *sock;

	if (s == INVALID_SOCKET) {
		return NULL;
	}

	// Creating a SOCK
	sock = NewSock();
	sock->socket = s;
	sock->Type = SOCK_TCP;
	sock->ServerMode = false;

	StrCpy(sock->UnderlayProtocol, sizeof(sock->UnderlayProtocol), is_ipv6 ? SOCK_UNDERLAY_NATIVE_V6 : SOCK_UNDERLAY_NATIVE_V4);
	AddProtocolDetailsStr(sock->ProtocolDetails, sizeof(sock->ProtocolDetails), is_ipv6 ? "IPv6" : "IPv4");

	// Host name resolution
	if (no_get_hostname || (GetHostName(tmp, sizeof(tmp), current_ip) == false)) {
		StrCpy(tmp, sizeof(tmp), hostname_original);
	}

	//Debug("PTR: %s\n", tmp);

	sock->RemoteHostname = CopyStr(tmp);

	//	Debug("new socket: %u\n", s);

	Zero(&ling, sizeof(ling));

	UINT true_flag = 1;
	// Forced disconnection flag
#ifdef SO_DONTLINGER
	(void)setsockopt(sock->socket, SOL_SOCKET, SO_DONTLINGER, (char *)&true_flag, sizeof(true_flag));
#else  // SO_DONTLINGER
	UINT false_flag = 0;
	(void)setsockopt(sock->socket, SOL_SOCKET, SO_LINGER, (char *)&false_flag, sizeof(false_flag));
#endif // SO_DONTLINGER
	   //	setsockopt(sock->socket, SOL_SOCKET, SO_REUSEADDR, (char *)&true_flag, sizeof(true_flag));

	// Configuring TCP options
	(void)setsockopt(sock->socket, IPPROTO_TCP, TCP_NODELAY, (char *)&true_flag, sizeof(true_flag));

	// Initialization of the time-out value
	SetTimeout(sock, TIMEOUT_INFINITE);

	// Get the socket information
	QuerySocketInformation(sock);

	if (IsZeroIp(&sock->LocalIP) == false && IsLocalHostIP(&sock->LocalIP) == false) {
		IP current_ip;

		if (GetCurrentGlobalIP(&current_ip, is_ipv6) == false) {
			SetCurrentGlobalIP(&sock->LocalIP, is_ipv6);
		}
	}

	sock->Connected = true;
	sock->AsyncMode = false;
	sock->SecureMode = false;
	sock->IPv6 = is_ipv6;

	return sock;
}

// TCP connection
SOCK *Connect(char *hostname, UINT port) {
	return ConnectEx(hostname, port, 0);
}
SOCK *ConnectEx(char *hostname, UINT port, UINT timeout) {
	return ConnectEx2(hostname, port, timeout, NULL);
}
SOCK *ConnectEx2(char *hostname, UINT port, UINT timeout, bool *cancel_flag) {
	return ConnectEx3(hostname, port, timeout, cancel_flag, true);
}
SOCK *ConnectEx3(char *hostname, UINT port, UINT timeout, bool *cancel_flag, bool no_get_hostname) {
	return ConnectEx4(hostname, port, timeout, cancel_flag, no_get_hostname, NULL);
}
SOCK *ConnectEx4(char *hostname, UINT port, UINT timeout, bool *cancel_flag, bool no_get_hostname, IP *ret_ip) {
	return BindConnectEx4(BIND_LOCALIP_NULL, BIND_LOCALPORT_NULL, hostname, port, timeout, cancel_flag, no_get_hostname, ret_ip);
}

//SOCK* ConnectEx4(char* hostname, UINT port, UINT timeout, bool* cancel_flag, bool no_get_hostname, IP* ret_ip)
SOCK *BindConnectEx4(IP *localIP, UINT localport, char *hostname, UINT port, UINT timeout, bool *cancel_flag, bool no_get_hostname, IP *ret_ip) {
	bool dummy = false;
	IP dummy_ret_ip;
	// Validate arguments
	if (hostname == NULL || port == 0 || port >= 65536 || IsEmptyStr(hostname)) {
		return NULL;
	}
	if (timeout == 0) {
		timeout = TIMEOUT_TCP_PORT_CHECK;
	}
	if (cancel_flag == NULL) {
		cancel_flag = &dummy;
	}

	Zero(&dummy_ret_ip, sizeof(IP));
	if (ret_ip == NULL) {
		ret_ip = &dummy_ret_ip;
	}

	LIST *iplist_v6 = NULL;
	LIST *iplist_v4 = NULL;

	if (IsZeroIp(ret_ip) == false) {
		// Skip name resolution
		if (IsIP6(ret_ip)) {
			iplist_v6 = NewListFast(NULL);
			AddHostIPAddressToList(iplist_v6, ret_ip);
		} else {
			iplist_v4 = NewListFast(NULL);
			AddHostIPAddressToList(iplist_v4, ret_ip);
		}

		//Debug("Using cached IP address: %s = %r\n", hostname_original, ret_ip);
	} else {
		// Forward resolution
		if (DnsResolveEx(&iplist_v6, &iplist_v4, hostname, 0, cancel_flag) == false) {
			return NULL;
		}
	}

	CONNECT_SERIAL_PARAM p4, p6;
	EVENT *finish_event;
	THREAD *t4 = NULL;
	THREAD *t6 = NULL;
	bool cancel_flag2 = false;
	bool no_delay_flag = false;
	IP ret_ip4, ret_ip6;

	finish_event = NewEvent();

	Zero(&p4, sizeof(p4));
	Zero(&p6, sizeof(p6));

	// IPv6 connection thread
	if (LIST_NUM(iplist_v6) > 0) {
		p6.IpList = iplist_v6;

		if (localIP == BIND_LOCALIP_NULL) {
			p6.LocalIP = BIND_LOCALIP_NULL; // Make the NULL address passing through
		} else {
			CopyIP(&p6.LocalIP_Cache, localIP);
			p6.LocalIP = &p6.LocalIP_Cache;
		}
		p6.LocalPort = localport;

		p6.Port = port;
		p6.Timeout = timeout;
		StrCpy(p6.Hostname, sizeof(p6.Hostname), hostname);
		p6.No_Get_Hostname = no_get_hostname;
		p6.CancelFlag = &cancel_flag2;
		p6.NoDelayFlag = &no_delay_flag;
		p6.FinishEvent = finish_event;
		p6.Ret_Ip = &ret_ip6;
		p6.RetryDelay = 250;
		p6.Delay = 0;
		//		t6 = NewThread(ConnectThreadForIPv6, &p6);
		t6 = NewThread(BindConnectThreadForIPv6, &p6); // For binding a socket
	}

	// IPv4 connection thread
	if (LIST_NUM(iplist_v4) > 0) {
		p4.IpList = iplist_v4;

		if (localIP == BIND_LOCALIP_NULL) {
			p4.LocalIP = BIND_LOCALIP_NULL; // Make the NULL address passing through
		} else {
			CopyIP(&p4.LocalIP_Cache, localIP);
			p4.LocalIP = &p4.LocalIP_Cache;
		}
		p4.LocalPort = localport;

		p4.Port = port;
		p4.Timeout = timeout;
		StrCpy(p4.Hostname, sizeof(p4.Hostname), hostname);
		p4.No_Get_Hostname = no_get_hostname;
		p4.CancelFlag = &cancel_flag2;
		p4.NoDelayFlag = &no_delay_flag;
		p4.FinishEvent = finish_event;
		p4.Ret_Ip = &ret_ip4;
		p4.RetryDelay = 250;
		p4.Delay = 250;                                // Delay by 250ms to prioritize IPv6 (RFC 6555 recommends 150-250ms, Chrome uses 300ms)
		                                               //		t4 = NewThread(ConnectThreadForIPv4, &p4);
		t4 = NewThread(BindConnectThreadForIPv4, &p4); // For binding a socket
	}

	if (t6 == NULL || t4 == NULL) {
		// No need to delay if there is only one thread
		no_delay_flag = true;
	}

	while (true) {
		if (*cancel_flag) {
			break;
		}

		if ((t6 == NULL || p6.Finished) && (t4 == NULL || p4.Finished)) {
			break;
		}

		if ((p6.Finished && p6.Ok) || (p4.Finished && p4.Ok)) {
			break;
		}

		// This check must be placed last to avoid race condition with cancel flag
		if (no_delay_flag == false && (p6.Finished || p4.Finished)) {
			no_delay_flag = true;
		}

		Wait(finish_event, 25);
	}

	cancel_flag2 = true;
	no_delay_flag = true;

	WaitThread(t6, INFINITE);
	WaitThread(t4, INFINITE);
	ReleaseThread(t6);
	ReleaseThread(t4);
	ReleaseEvent(finish_event);
	FreeHostIPAddressList(iplist_v6);
	FreeHostIPAddressList(iplist_v4);

	if (*cancel_flag) {
		// Abandon all the results because the user canceled
		Disconnect(p6.Sock);
		ReleaseSock(p6.Sock);
		Disconnect(p4.Sock);
		ReleaseSock(p4.Sock);

		return NULL;
	}

	if (p6.Ok) {
		Disconnect(p4.Sock);
		ReleaseSock(p4.Sock);
		Copy(ret_ip, &ret_ip6, sizeof(IP));
		return p6.Sock;
	}

	if (p4.Ok) {
		Disconnect(p6.Sock);
		ReleaseSock(p6.Sock);
		Copy(ret_ip, &ret_ip4, sizeof(IP));
		return p4.Sock;
	}

	return NULL;
}

// Add a protocol details strings
void AddProtocolDetailsStr(char *dst, UINT dst_size, char *str) {
	TOKEN_LIST *t1, *t2;
	UINT i, j;
	if (dst == NULL || str == NULL) {
		return;
	}

	t1 = ParseTokenWithoutNullStr(dst, " ");
	t2 = ParseTokenWithoutNullStr(str, " ");

	for (i = 0; i < t2->NumTokens; i++) {
		bool exists = false;
		for (j = 0; j < t1->NumTokens; j++) {
			if (StrCmpi(t1->Token[j], t2->Token[i]) == 0) {
				exists = true;
				break;
			}
		}

		if (exists == false) {
			StrCat(dst, dst_size, t2->Token[i]);
			StrCat(dst, dst_size, " ");
		}
	}

	FreeToken(t1);
	FreeToken(t2);
}

void AddProtocolDetailsKeyValueStr(char *dst, UINT dst_size, char *key, char *value) {
	char tmp[128];
	StrCpy(tmp, sizeof(tmp), key);
	StrCat(tmp, sizeof(tmp), "=");
	StrCat(tmp, sizeof(tmp), value);
	AddProtocolDetailsStr(dst, dst_size, tmp);
}

void AddProtocolDetailsKeyValueInt(char *dst, UINT dst_size, char *key, UINT value) {
	char tmp[128];
	ToStr(tmp, value);
	AddProtocolDetailsKeyValueStr(dst, dst_size, key, tmp);
}


// Setting the buffer size of the socket
bool SetSocketBufferSize(SOCKET s, bool send, UINT size) {
	int value = (int)size;
	// Validate arguments
	if (s == INVALID_SOCKET) {
		return false;
	}

	if (setsockopt(s, SOL_SOCKET, (send ? SO_SNDBUF : SO_RCVBUF), (char *)&value, sizeof(int)) != 0) {
		return false;
	}

	return true;
}
UINT SetSocketBufferSizeWithBestEffort(SOCKET s, bool send, UINT size) {
	// Validate arguments
	if (s == INVALID_SOCKET) {
		return 0;
	}

	while (true) {
		if (SetSocketBufferSize(s, send, size)) {
			return size;
		}

		size = (UINT)((double)size / 1.5);

		if (size <= 32767) {
			return 0;
		}
	}
}

// Initialize the buffer size of the UDP socket
void InitUdpSocketBufferSize(SOCKET s) {
	SetSocketBufferSizeWithBestEffort(s, true, UDP_MAX_BUFFER_SIZE);
	SetSocketBufferSizeWithBestEffort(s, false, UDP_MAX_BUFFER_SIZE);
}

// Get the socket information
void QuerySocketInformation(SOCK *sock) {
	// Validate arguments
	if (sock == NULL) {
		return;
	}

	Lock(sock->lock);
	{
		struct sockaddr_in6 sockaddr6;
		struct in6_addr *addr6;
		int size;
		UINT dw;
		UINT opt_value = 0;

		if (sock->Type == SOCK_TCP) {
			// Get the information of the remote host
			size = sizeof(sockaddr6);
			if (getpeername(sock->socket, (struct sockaddr *)&sockaddr6, (int *)&size) == 0) {
				if (size >= sizeof(struct sockaddr_in6)) {
					sock->RemotePort = (UINT)ntohs(sockaddr6.sin6_port);
					addr6 = &sockaddr6.sin6_addr;
					InAddrToIP6(&sock->RemoteIP, addr6);
					sock->RemoteIP.ipv6_scope_id = sockaddr6.sin6_scope_id;
				} else {
					struct sockaddr_in *sockaddr;
					struct in_addr *addr;

					sockaddr = (struct sockaddr_in *)&sockaddr6;
					sock->RemotePort = (UINT)ntohs(sockaddr->sin_port);
					addr = &sockaddr->sin_addr;
					InAddrToIP(&sock->RemoteIP, addr);
				}
			}
		}

		// Get the local host information
		size = sizeof(sockaddr6);
		if (getsockname(sock->socket, (struct sockaddr *)&sockaddr6, (int *)&size) == 0) {
			if (size >= sizeof(struct sockaddr_in6)) {
				sock->LocalPort = (UINT)ntohs(sockaddr6.sin6_port);
				addr6 = &sockaddr6.sin6_addr;
				InAddrToIP6(&sock->LocalIP, addr6);
				sock->LocalIP.ipv6_scope_id = sockaddr6.sin6_scope_id;
			} else {
				struct sockaddr_in *sockaddr;
				struct in_addr *addr;

				sockaddr = (struct sockaddr_in *)&sockaddr6;
				sock->LocalPort = (UINT)ntohs(sockaddr->sin_port);
				addr = &sockaddr->sin_addr;
				InAddrToIP(&sock->LocalIP, addr);
			}
		}

		if (sock->IsRawSocket) {
			sock->LocalPort = sock->RemotePort = MAKE_SPECIAL_PORT(sock->RawSocketIPProtocol);
		}

		if (sock->Type == SOCK_UDP) {
			sock->UdpMaxMsgSize = UDP_MAX_MSG_SIZE_DEFAULT;

#ifdef OS_WIN32
			if (true) {
				// Get the buffer size that can be transmitted and received at once
				UINT max_value = 0;
				int len = sizeof(UINT);

				if (getsockopt(sock->socket, SOL_SOCKET, SO_MAX_MSG_SIZE, (char *)&max_value, &len) == 0) {
					sock->UdpMaxMsgSize = max_value;
				}
			}
#endif // OS_WIN32
		}

		if (sock->IPv6) {
#ifdef IPV6_UNICAST_HOPS
			opt_value = IPV6_UNICAST_HOPS;
#endif // IPV6_UNICAST_HOPS
		} else {
#ifdef IP_TTL
			opt_value = IP_TTL;
#endif // IP_TTL
		}

		// Support of the TTL value
		size = sizeof(UINT);
		if (opt_value == 0 ||
		    getsockopt(sock->socket, (sock->IPv6 ? IPPROTO_IPV6 : IPPROTO_IP), opt_value, (char *)&dw, &size) != 0) {
			sock->IsTtlSupported = false;
		} else {
			sock->IsTtlSupported = true;
			sock->CurrentTtl = dw;
		}
	}
	Unlock(sock->lock);
}

// Release of the socket
void ReleaseSock(SOCK *s) {
	// Validate arguments
	if (s == NULL) {
		return;
	}

	if (Release(s->ref) == 0) {
		if (s->ListenMode == false && s->ServerMode) {
			Print("");
		}
		CleanupSock(s);
	}
}

// Clean-up of the socket
void CleanupSock(SOCK *s) {
	// Validate arguments
	if (s == NULL) {
		return;
	}

	//	{Debug("CleanupSock: Disconnect() Called: %s %u\n", __FILE__, __LINE__);Disconnect(s);}
	Disconnect(s);

#ifdef OS_WIN32
	Win32FreeAsyncSocket(s);
#endif // OS_WIN32

	FreeBuf(s->SendBuf);
	if (s->socket != INVALID_SOCKET) {
#ifdef OS_WIN32
		closesocket(s->socket);
#endif // OS_WIN32
	}
	Free(s->RemoteHostname);

#ifdef OS_WIN32
	if (s->hAcceptEvent != NULL) {
		CloseHandle(s->hAcceptEvent);
	}
#endif // OS_WIN32

	// Release the certificate
	if (s->RemoteX != NULL) {
		FreeX(s->RemoteX);
		s->RemoteX = NULL;
	}
	if (s->LocalX != NULL) {
		FreeX(s->LocalX);
		s->LocalX = NULL;
	}

	// Cipher algorithm name
	if (s->CipherName != NULL) {
		Free(s->CipherName);
		s->CipherName = NULL;
	}

	Free(s->WaitToUseCipher);
	DeleteLock(s->lock);
	DeleteLock(s->ssl_lock);
	DeleteLock(s->disconnect_lock);

	Dec(num_tcp_connections);

	Free(s);
}

// Creating a new socket
SOCK *NewSock() {
	SOCK *s = ZeroMallocFast(sizeof(SOCK));

	s->ref = NewRef();
	s->lock = NewLock();
	s->SendBuf = NewBuf();
	s->socket = INVALID_SOCKET;
	s->ssl_lock = NewLock();
	s->disconnect_lock = NewLock();

	Inc(num_tcp_connections);

	return s;
}

// Convert the IP to UINT
UINT IPToUINT(IP *ip) {
	// Validate arguments
	if (ip == NULL || IsIP6(ip)) {
		return 0;
	}

	UINT value;

	for (BYTE i = 0; i < IPV4_SIZE; ++i) {
		((BYTE *)&value)[i] = IPV4(ip->address)[i];
	}

	return value;
}

// Convert UINT to IP
void UINTToIP(IP *ip, UINT value) {
	// Validate arguments
	if (ip == NULL) {
		return;
	}

	ZeroIP4(ip);

	for (BYTE i = 0; i < IPV4_SIZE; ++i) {
		IPV4(ip->address)
		[i] = ((BYTE *)&value)[i];
	}
}

// Get the host name of the computer
void GetMachineHostName(char *name, UINT size) {
	char tmp[MAX_SIZE];
	UINT i, len;
	// Validate arguments
	if (name == NULL) {
		return;
	}

	GetMachineName(tmp, sizeof(tmp));

	len = StrLen(tmp);
	for (i = 0; i < len; i++) {
		if (tmp[i] == '.') {
			tmp[i] = 0;
		}
	}

	ConvertSafeFileName(name, size, tmp);
}

// Get the computer name from 'hosts'
bool GetMachineNameFromHosts(char *name, UINT size) {
	bool ret = false;
	char *s;
	BUF *b;
	// Validate arguments
	if (name == NULL) {
		return false;
	}

	b = ReadDump("/etc/hosts");
	if (b == NULL) {
		return false;
	}

	while (true) {
		s = CfgReadNextLine(b);
		if (s == NULL) {
			break;
		} else {
			TOKEN_LIST *t = ParseToken(s, " \t");

			if (t != NULL) {
				if (t->NumTokens >= 2) {
					if (StrCmpi(t->Token[0], "127.0.0.1") == 0) {
						UINT i;

						for (i = 1; i < t->NumTokens; i++) {
							if (StartWith(t->Token[i], "localhost") == false) {
								StrCpy(name, size, t->Token[i]);
								ret = true;
							}
						}
					}
				}
			}
			FreeToken(t);
		}

		Free(s);
	}

	FreeBuf(b);

	return ret;
}

// Get the computer name of this computer
void GetMachineName(char *name, UINT size) {
	GetMachineNameEx(name, size, false);
}
void GetMachineNameEx(char *name, UINT size, bool no_load_hosts) {
	static char name_cache[MAX_SIZE];
	static bool name_cached = false;
	char tmp[MAX_SIZE];
	char tmp2[MAX_SIZE];
	// Validate arguments
	if (name == NULL) {
		return;
	}

	Lock(machine_name_lock);
	{
		if (name_cached != false) {
			StrCpy(name, size, name_cache);
			Unlock(machine_name_lock);
			return;
		}
		ClearStr(tmp, sizeof(tmp));
		if (gethostname(tmp, MAX_SIZE) != 0) {
			StrCpy(name, size, "Unknown");
			Unlock(machine_name_lock);
			return;
		}
		ClearStr(name, size);
		StrCpy(name, size, tmp);
		if (IsEmptyStr(name) || StartWith(name, "localhost")) {
#ifdef OS_WIN32
			ClearStr(name, size);
			MsGetComputerName(name, size);
#endif // OS_WIN32
		}
		if (IsEmptyStr(name) || StartWith(name, "localhost")) {
			if (no_load_hosts == false && OS_IS_UNIX(GetOsInfo()->OsType)) {
				if (GetMachineNameFromHosts(tmp2, sizeof(tmp2))) {
					StrCpy(name, size, tmp2);
				}
			}
		}

		StrCpy(name_cache, sizeof(name_cache), name);
		name_cached = true;
	}
	Unlock(machine_name_lock);
}

// Get the host name
bool GetHostName(char *hostname, UINT size, IP *ip) {
	if (hostname == NULL || size == 0 || ip == NULL) {
		return false;
	}

	if (DnsResolveReverse(hostname, size, ip, 0, NULL)) {
		return true;
	}

	if (IsIP4(ip) && GetNetBiosName(hostname, size, ip)) {
		DnsCacheReverseUpdate(ip, hostname);
		return true;
	}

	return false;
}

#define NUM_NBT_QUERYS_SEND 3

// Get the NetBIOS name of the machine from the IP address
bool GetNetBiosName(char *name, UINT size, IP *ip) {
	SOCK *s;
	UINT i, j;
	bool flag = false;
	bool ok = false;
	NBTREQUEST req;
	UCHAR buf[1024];
	USHORT tran_id[NUM_NBT_QUERYS_SEND];
	UINT64 timeout_tick;
	// Validate arguments
	if (name == NULL || ip == NULL) {
		return false;
	}

	IPToStr(name, size, ip);

	for (i = 0; i < NUM_NBT_QUERYS_SEND; i++) {
		tran_id[i] = Rand16();
	}

	s = NewUDP(0);
	if (s == NULL) {
		return false;
	}

	for (j = 0; j < NUM_NBT_QUERYS_SEND; j++) {
		Zero(&req, sizeof(req));
		req.TransactionId = Endian16(tran_id[j]);
		req.NumQuestions = Endian16(1);
		req.Query[0] = 0x20;
		req.Query[1] = 0x43;
		req.Query[2] = 0x4b;
		for (i = 3; i <= 32; i++) {
			req.Query[i] = 0x41;
		}
		req.Query[35] = 0x21;
		req.Query[37] = 0x01;

		if (SendTo(s, ip, 137, &req, sizeof(req)) == 0) {
			ReleaseSock(s);
			return false;
		}
	}

	timeout_tick = Tick64() + (UINT64)TIMEOUT_NETBIOS_HOSTNAME;

	while (1) {
		UINT ret;
		IP src_ip;
		UINT src_port;
		SOCKSET set;
		if (Tick64() >= timeout_tick) {
			break;
		}
		InitSockSet(&set);
		AddSockSet(&set, s);
		Select(&set, 100, NULL, NULL);

		if (flag == false) {
			flag = true;
		} else {
			SleepThread(10);
		}

		ret = RecvFrom(s, &src_ip, &src_port, buf, sizeof(buf));

		if (ret == SOCK_LATER) {
			continue;
		} else if (ret == 0) {
			break;
		} else {
			if (ret >= sizeof(NBTRESPONSE)) {
				NBTRESPONSE *r = (NBTRESPONSE *)buf;
				bool b = false;
				UINT i;
				USHORT id = Endian16(r->TransactionId);
				for (i = 0; i < NUM_NBT_QUERYS_SEND; i++) {
					if (id == tran_id[i]) {
						b = true;
						break;
					}
				}
				if (b) {
					if (r->Flags != 0 && r->NumQuestions == 0 && r->AnswerRRs >= 1) {
						if (r->Response[0] == 0x20 && r->Response[1] == 0x43 &&
						    r->Response[2] == 0x4b) {
							if (r->Response[34] == 0x00 && r->Response[35] == 0x21 &&
							    r->Response[36] == 0x00 && r->Response[37] == 0x01) {
								char *a = (char *)(&r->Response[45]);
								if (StrCheckLen(a, 15)) {
									if (IsEmptyStr(a) == false) {
										StrCpy(name, size, a);
										Trim(name);
										ok = true;
									} else {
										ok = false;
										break;
									}
								}
							}
						}
					}
				}
			}
		}
	}

	ReleaseSock(s);
	return ok;
}

// Set the IP address
void SetIP(IP *ip, UCHAR a1, UCHAR a2, UCHAR a3, UCHAR a4) {
	// Validate arguments
	if (ip == NULL) {
		return;
	}

	ZeroIP4(ip);

	ip->address[12] = a1;
	ip->address[13] = a2;
	ip->address[14] = a3;
	ip->address[15] = a4;
}

// Convert the IP to a string (32bit UINT)
void IPToStr32(char *str, UINT size, UINT ip) {
	IP ip_st;
	// Validate arguments
	if (str == NULL) {
		return;
	}

	UINTToIP(&ip_st, ip);
	IPToStr(str, size, &ip_st);
}

// Convert IPv4 or IPv6 to a string
void IPToStr4or6(char *str, UINT size, UINT ip_4_uint, UCHAR *ip_6_bytes) {
	IP ip4;
	IP ip6;
	IP ip;
	// Validate arguments
	if (str == NULL) {
		return;
	}

	Zero(&ip, sizeof(ip));

	UINTToIP(&ip4, ip_4_uint);
	SetIP6(&ip6, ip_6_bytes);

	if (IsIP6(&ip4) || (IsZeroIp(&ip4) && (IsZeroIp(&ip6) == false))) {
		Copy(&ip, &ip6, sizeof(IP));
	} else {
		Copy(&ip, &ip4, sizeof(IP));
	}

	IPToStr(str, size, &ip);
}

// Convert the IP to a string
void IPToStr(char *str, UINT size, IP *ip) {
	// Validate arguments
	if (str == NULL || ip == NULL) {
		return;
	}

	if (IsIP6(ip)) {
		IPToStr6(str, size, ip);
	} else {
		const BYTE *ipv4 = IPV4(ip->address);
		Format(str, size, "%hhu.%hhu.%hhu.%hhu", ipv4[0], ipv4[1], ipv4[2], ipv4[3]);
	}
}

// Convert the string to an IP
bool StrToIP(IP *ip, char *str) {
	TOKEN_LIST *token;
	char *tmp;
	// Validate arguments
	if (ip == NULL || str == NULL) {
		return false;
	}

	if (StrToIP6(ip, str)) {
		return true;
	}

	ZeroIP4(ip);

	tmp = CopyStr(str);
	Trim(tmp);
	token = ParseToken(tmp, ".");
	Free(tmp);

	if (token->NumTokens != 4) {
		FreeToken(token);
		return false;
	}
	for (BYTE i = 0; i < IPV4_SIZE; ++i) {
		char *s = token->Token[i];
		if (s[0] < '0' || s[0] > '9' ||
		    (ToInt(s) >= 256)) {
			FreeToken(token);
			return false;
		}
	}

	for (BYTE i = 0; i < IPV4_SIZE; ++i) {
		IPV4(ip->address)
		[i] = (BYTE)ToInt(token->Token[i]);
	}

	FreeToken(token);

	return true;
}

// Convert the IP to the in_addr
void IPToInAddr(struct in_addr *addr, IP *ip) {
	UINT i;
	// Validate arguments
	if (addr == NULL || IsIP4(ip) == false) {
		return;
	}

	Zero(addr, sizeof(struct in_addr));

	const BYTE *ipv4 = IPV4(ip->address);
	for (i = 0; i < IPV4_SIZE; ++i) {
		((BYTE *)addr)[i] = ipv4[i];
	}
}

// Convert the IP to the in6_addr
void IPToInAddr6(struct in6_addr *addr, IP *ip) {
	// Validate arguments
	if (addr == NULL || ip == NULL) {
		return;
	}

	Zero(addr, sizeof(struct in6_addr));

	for (BYTE i = 0; i < sizeof(ip->address); ++i) {
		((BYTE *)addr)[i] = ip->address[i];
	}
}

// Convert the in_addr to the IP
void InAddrToIP(IP *ip, struct in_addr *addr) {
	if (ip == NULL || addr == NULL) {
		return;
	}

	ZeroIP4(ip);

	BYTE *ipv4 = IPV4(ip->address);

	for (BYTE i = 0; i < IPV4_SIZE; ++i) {
		ipv4[i] = ((UCHAR *)addr)[i];
	}
}

// Convert the in6_addr to the IP
void InAddrToIP6(IP *ip, struct in6_addr *addr) {
	// Validate arguments
	if (ip == NULL || addr == NULL) {
		return;
	}

	Zero(ip, sizeof(IP));

	for (BYTE i = 0; i < sizeof(ip->address); ++i) {
		ip->address[i] = ((UCHAR *)addr)[i];
	}
}

// DH temp key callback
DH *TmpDhCallback(SSL *ssl, int is_export, int keylength) {
	DH *ret = NULL;

	if (dh_param != NULL) {
		ret = dh_param->dh;
	}

	return ret;
}

// Log SSL keys
void keylog_cb_func(const SSL *ssl, const char *line) {
	Debug("SSL_KEYLOG_BEGIN\n");
	Debug(line);
	Debug("\nSSL_KEYLOG_END\n");
}

// Create the SSL_CTX
struct ssl_ctx_st *NewSSLCtx(bool server_mode) {
	struct ssl_ctx_st *ctx = SSL_CTX_new(SSLv23_method());
	if (ctx == NULL) {
		return NULL;
	}
	// It resets some parameters.
	if (server_mode) {
		SSL_CTX_set_ssl_version(ctx, SSLv23_server_method());
	} else {
		SSL_CTX_set_ssl_version(ctx, SSLv23_client_method());
	}

#ifdef SSL_OP_NO_SSLv3
	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv3);
#endif // SSL_OP_NO_SSLv3

#ifdef SSL_OP_NO_TICKET
	SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);
#endif // SSL_OP_NO_TICKET

#ifdef SSL_OP_CIPHER_SERVER_PREFERENCE
	if (server_mode) {
		SSL_CTX_set_options(ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);
	}
#endif // SSL_OP_CIPHER_SERVER_PREFERENCE

	SSL_CTX_set_tmp_dh_callback(ctx, TmpDhCallback);

#ifdef SSL_CTX_set_ecdh_auto
	SSL_CTX_set_ecdh_auto(ctx, 1);
#endif // SSL_CTX_set_ecdh_auto

	SSL_CTX_set_keylog_callback(ctx, &keylog_cb_func);

	return ctx;
}

// Release of the SSL_CTX
void FreeSSLCtx(struct ssl_ctx_st *ctx) {
	// Validate arguments
	if (ctx == NULL) {
		return;
	}

	SSL_CTX_free(ctx);
}

// Get OS (maximum) Security Level
UINT GetOSSecurityLevel() {
	UINT security_level_new = 0, security_level_set_ssl_version = 0;
	struct ssl_ctx_st *ctx = SSL_CTX_new(SSLv23_method());

	if (ctx == NULL) {
		return security_level_new;
	}


#if (OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER)) || LIBRESSL_VERSION_NUMBER >= 0x3060000L
	security_level_new = SSL_CTX_get_security_level(ctx);
#endif

	security_level_set_ssl_version = SSL_CTX_set_ssl_version(ctx, SSLv23_server_method());

	FreeSSLCtx(ctx);

	if (security_level_new >= security_level_set_ssl_version) {
		return security_level_new;
	}

	return security_level_set_ssl_version;
}

// Initialize the network communication module
void InitNetwork() {
	disable_gethostname_by_accept = false;


	InitDynList();


	host_ip_address_list_cache_lock = NewLock();
	host_ip_address_list_cache_last = 0;

	num_tcp_connections = NewCounter();

	// Initialization of client list
	InitIpClientList();

	// Thread related initialization
	InitWaitThread();

#ifdef OS_WIN32
	// Initializing the socket library
	Win32InitSocketLibrary();
#endif // OS_WIN32

	DnsInit();

	// Locking initialization
	machine_name_lock = NewLock();
	disconnect_function_lock = NewLock();
	machine_ip_process_hash_lock = NewLock();
	local_mac_list_lock = NewLock();

	current_global_ip_lock = NewLock();
	current_global_ip_set = false;
}

// Get the cipher algorithm list
TOKEN_LIST *GetCipherList() {
	UINT i;
	SSL *ssl;
	SSL_CTX *ctx;
	const char *name;
	STACK_OF(SSL_CIPHER) * sk;

	TOKEN_LIST *ciphers = ZeroMalloc(sizeof(TOKEN_LIST));

	ctx = NewSSLCtx(true);
	if (ctx == NULL) {
		return ciphers;
	}

	ssl = SSL_new(ctx);
	if (ssl == NULL) {
		FreeSSLCtx(ctx);
		return ciphers;
	}

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER)) || LIBRESSL_VERSION_NUMBER >= 0x2090100L
	sk = SSL_get1_supported_ciphers(ssl);
#else
	sk = SSL_get_ciphers(ssl);
#endif

	for (i = 0; i < (UINT)sk_SSL_CIPHER_num(sk); i++) {
		const SSL_CIPHER *c = sk_SSL_CIPHER_value(sk, i);

		name = SSL_CIPHER_get_name(c);
		if (IsEmptyStr((char *)name)) {
			break;
		}

		ciphers->NumTokens++;

		if (ciphers->Token != NULL) {
			ciphers->Token = ReAlloc(ciphers->Token, sizeof(char *) * ciphers->NumTokens);
		} else {
			ciphers->Token = Malloc(sizeof(char *));
		}

		ciphers->Token[i] = CopyStr((char *)name);
	}

	sk_SSL_CIPHER_free(sk);
	SSL_free(ssl);

	return ciphers;
}

// Get the TCP connections counter
COUNTER *GetNumTcpConnectionsCounter() {
	return num_tcp_connections;
}

// Get the current global IP address
bool GetCurrentGlobalIP(IP *ip, bool ipv6) {
	bool ret = false;
	// Validate arguments
	if (ip == NULL) {
		return false;
	}

	Zero(ip, sizeof(IP));

	Lock(current_global_ip_lock);
	{
		if (ipv6 == false) {
			Copy(ip, &current_glocal_ipv4, sizeof(IP));
		} else {
			Copy(ip, &current_glocal_ipv6, sizeof(IP));
		}

		ret = current_global_ip_set;
	}
	Unlock(current_global_ip_lock);

	return ret;
}

// Check whether the specified IP address is assigned to the local host
bool IsIPMyHost(IP *ip) {
	LIST *o;
	UINT i;
	bool ret = false;
	// Validate arguments
	if (ip == NULL) {
		return false;
	}

	if (IsZeroIp(ip)) {
		return false;
	}

	// Search to check whether it matches to any of the IP of the local host
	o = GetHostIPAddressList();

	for (i = 0; i < LIST_NUM(o); i++) {
		IP *p = LIST_DATA(o, i);

		if (CmpIpAddr(p, ip) == 0) {
			// Matched
			ret = true;
			break;
		}
	}

	FreeHostIPAddressList(o);

	if (ret == false) {
		if (IsLocalHostIP(ip)) {
			// localhost IP addresses
			ret = true;
		}
	}

	return ret;
}

// Check whether the specified IP address is a private IP address
bool IsIPPrivate(IP *ip) {
	// Validate arguments
	if (IsIP4(ip) == false) {
		return false;
	}

	const BYTE *ipv4 = IPV4(ip->address);

	// RFC 1918 defines 10.0.0.0/8
	if (ipv4[0] == 10) {
		return true;
	}

	// RFC 1918 defines 172.16.0.0/12
	if (ipv4[0] == 172) {
		if (ipv4[1] >= 16 && ipv4[1] <= 31) {
			return true;
		}
	}

	// RFC 1918 defines 192.168.0.0/16
	if (ipv4[0] == 192 && ipv4[1] == 168) {
		return true;
	}

	// RFC 3927 defines 169.254.0.0/16
	if (ipv4[0] == 169 && ipv4[1] == 254) {
		return true;
	}

	// RFC 6598 defines 100.64.0.0/10
	if (ipv4[0] == 100) {
		if (ipv4[1] >= 64 && ipv4[1] <= 127) {
			return true;
		}
	}

	if (g_private_ip_list != NULL) {
		return IsOnPrivateIPFile(IPToUINT(ip));
	}

	return false;
}

// Read a private IP list file
void LoadPrivateIPFile() {
	BUF *b = ReadDump(PRIVATE_IP_TXT_FILENAME);
	LIST *o;
	if (b == NULL) {
		return;
	}

	o = NewList(NULL);

	while (true) {
		char *line = CfgReadNextLine(b);
		if (line == NULL) {
			break;
		}

		Trim(line);

		if (IsEmptyStr(line) == false) {
			UINT ip = 0, mask = 0;

			if (ParseIpAndSubnetMask4(line, &ip, &mask)) {
				PRIVATE_IP_SUBNET *p = ZeroMalloc(sizeof(PRIVATE_IP_SUBNET));

				p->Ip = ip;
				p->Mask = mask;
				p->Ip2 = ip & mask;

				Add(o, p);
			}
		}

		Free(line);
	}

	g_private_ip_list = o;
	g_use_privateip_file = true;

	FreeBuf(b);
}

// Examine whether the specified IP address is in the private IP file
bool IsOnPrivateIPFile(UINT ip) {
	bool ret = false;

	if (g_private_ip_list != NULL) {
		LIST *o = g_private_ip_list;
		UINT i;

		for (i = 0; i < LIST_NUM(o); i++) {
			PRIVATE_IP_SUBNET *p = LIST_DATA(o, i);

			if ((ip & p->Mask) == p->Ip2) {
				ret = true;
			}
		}
	}

	return ret;
}

// Free the private IP file
void FreePrivateIPFile() {
	if (g_private_ip_list != NULL) {
		LIST *o = g_private_ip_list;
		UINT i;

		g_private_ip_list = NULL;

		for (i = 0; i < LIST_NUM(o); i++) {
			PRIVATE_IP_SUBNET *p = LIST_DATA(o, i);

			Free(p);
		}

		ReleaseList(o);
	}

	g_use_privateip_file = false;
}

// Record the current global IP address
void SetCurrentGlobalIP(IP *ip, bool ipv6) {
	// Validate arguments
	if (ip == NULL) {
		return;
	}

	if (IsZeroIp(ip)) {
		return;
	}

	Lock(current_global_ip_lock);
	{
		if (ipv6 == false) {
			Copy(&current_glocal_ipv4, ip, sizeof(IP));
		} else {
			Copy(&current_glocal_ipv6, ip, sizeof(IP));
		}

		current_global_ip_set = true;
	}
	Unlock(current_global_ip_lock);
}

// Release of the network communication module
void FreeNetwork() {

	if (dh_param != NULL) {
		DhFree(dh_param);
		dh_param = NULL;
	}

	// Release of thread-related
	FreeWaitThread();

	// Release the locks
	DeleteLock(machine_name_lock);
	DeleteLock(disconnect_function_lock);
	DeleteLock(machine_ip_process_hash_lock);
	machine_name_lock = disconnect_function_lock = machine_ip_process_hash_lock = NULL;

	DnsFree();

#ifdef OS_WIN32
	// Release of the socket library
	Win32FreeSocketLibrary();
#endif // OS_WIN32

	DeleteCounter(num_tcp_connections);
	num_tcp_connections = NULL;

	// Release of client list
	FreeIpClientList();

	DeleteLock(current_global_ip_lock);
	current_global_ip_lock = NULL;

	// Release of the local MAC list
	if (local_mac_list != NULL) {
		FreeNicList(local_mac_list);
		local_mac_list = NULL;
	}

	DeleteLock(local_mac_list_lock);
	local_mac_list_lock = NULL;

	DeleteLock(host_ip_address_list_cache_lock);
	host_ip_address_list_cache_lock = NULL;

	FreeHostIPAddressList(host_ip_address_cache);
	host_ip_address_cache = NULL;

	FreeDynList();
}

// Parse the IP address and subnet mask
bool ParseIpAndSubnetMask46(char *src, IP *ip, IP *mask) {
	// Validate arguments
	if (src == NULL || ip == NULL || mask == NULL) {
		return false;
	}

	if (ParseIpAndMask46(src, ip, mask) == false) {
		return false;
	}

	if (IsIP4(ip)) {
		return IsSubnetMask4(mask);
	} else {
		return IsSubnetMask6(mask);
	}
}
bool ParseIpAndSubnetMask4(char *src, UINT *ip, UINT *mask) {
	IP ip2, mask2;
	// Validate arguments
	if (src == NULL) {
		return false;
	}

	if (ParseIpAndSubnetMask46(src, &ip2, &mask2) == false) {
		return false;
	}

	if (IsIP4(&ip2) == false) {
		return false;
	}

	if (ip != NULL) {
		*ip = IPToUINT(&ip2);
	}

	if (mask != NULL) {
		*mask = IPToUINT(&mask2);
	}

	return true;
}


// Parse the IP address and the mask
bool ParseIpAndMask46(char *src, IP *ip, IP *mask) {
	TOKEN_LIST *t;
	char *ipstr;
	char *subnetstr;
	bool ret = false;
	IP ip2;
	IP mask2;
	// Validate arguments
	if (src == NULL || ip == NULL || mask == NULL) {
		return false;
	}

	Zero(&ip2, sizeof(IP));
	Zero(&mask2, sizeof(IP));

	t = ParseToken(src, "/");
	if (t->NumTokens != 2) {
		FreeToken(t);
		return false;
	}

	ipstr = t->Token[0];
	subnetstr = t->Token[1];
	Trim(ipstr);
	Trim(subnetstr);

	if (StrToIP(&ip2, ipstr)) {
		if (StrToIP(&mask2, subnetstr)) {
			// Compare the kind of the mask part and the IP address part to confirm same
			if (IsIP6(&ip2) && IsIP6(&mask2)) {
				// Both are IPv6
				ret = true;
				Copy(ip, &ip2, sizeof(IP));
				Copy(mask, &mask2, sizeof(IP));
			} else if (IsIP4(&ip2) && IsIP4(&mask2)) {
				// Both are IPv4
				ret = true;
				Copy(ip, &ip2, sizeof(IP));
				Copy(mask, &mask2, sizeof(IP));
			}
		} else {
			if (IsNum(subnetstr)) {
				UINT i = ToInt(subnetstr);
				// Mask part is a number
				if (IsIP6(&ip2) && i <= 128) {
					ret = true;
					Copy(ip, &ip2, sizeof(IP));
					IntToSubnetMask6(mask, i);
				} else if (i <= 32) {
					ret = true;
					Copy(ip, &ip2, sizeof(IP));
					IntToSubnetMask4(mask, i);
				}
			}
		}
	}

	FreeToken(t);

	return ret;
}
bool ParseIpAndMask4(char *src, UINT *ip, UINT *mask) {
	IP ip_ip, ip_mask;
	if (ParseIpAndMask46(src, &ip_ip, &ip_mask) == false) {
		return false;
	}

	if (IsIP4(&ip_ip) == false) {
		return false;
	}

	if (ip != NULL) {
		*ip = IPToUINT(&ip_ip);
	}

	if (mask != NULL) {
		*mask = IPToUINT(&ip_mask);
	}

	return true;
}
bool ParseIpAndMask6(char *src, IP *ip, IP *mask) {
	if (ParseIpAndMask46(src, ip, mask) == false) {
		return false;
	}

	if (IsIP6(ip) == false) {
		return false;
	}

	return true;
}


// Convert the IPv4 / IPv6 mask to a string
void MaskToStr(char *str, UINT size, IP *mask) {
	MaskToStrEx(str, size, mask, false);
}
void MaskToStrEx(char *str, UINT size, IP *mask, bool always_full_address) {
	// Validate arguments
	if (str == NULL || mask == NULL) {
		return;
	}

	if (always_full_address == false && IsSubnetMask(mask)) {
		ToStr(str, SubnetMaskToInt(mask));
	} else {
		IPToStr(str, size, mask);
	}
}
void MaskToStr32(char *str, UINT size, UINT mask) {
	MaskToStr32Ex(str, size, mask, false);
}
void MaskToStr32Ex(char *str, UINT size, UINT mask, bool always_full_address) {
	IP ip;

	UINTToIP(&ip, mask);

	MaskToStrEx(str, size, &ip, always_full_address);
}
void Mask6AddrToStrEx(char *str, UINT size, IPV6_ADDR *mask, bool always_full_address) {
	IP ip;

	// Validate arguments
	if (str == NULL || mask == NULL) {
		StrCpy(str, size, "");
		return;
	}

	IPv6AddrToIP(&ip, mask);

	MaskToStrEx(str, size, &ip, always_full_address);
}
void Mask6AddrToStr(char *str, UINT size, IPV6_ADDR *mask) {
	Mask6AddrToStrEx(str, size, mask, false);
}

// Release of the IP address list of the host
void FreeHostIPAddressList(LIST *o) {
	UINT i;
	// Validate arguments
	if (o == NULL) {
		return;
	}

	for (i = 0; i < LIST_NUM(o); i++) {
		IP *ip = LIST_DATA(o, i);

		Free(ip);
	}

	ReleaseList(o);
}

// Add the IP address to the list
void AddHostIPAddressToList(LIST *o, IP *ip) {
	IP *r = NULL;
	// Validate arguments
	if (o == NULL || ip == NULL) {
		return;
	}

	if (o->cmp != NULL) {
		r = Search(o, ip);
	} else {
		UINT i;
		for (i = 0; i < LIST_NUM(o); i++) {
			IP *a = LIST_DATA(o, i);

			if (CmpIpAddr(ip, a) == 0) {
				r = ip;
				break;
			}
		}
	}

	if (r != NULL) {
		return;
	}

	Insert(o, Clone(ip, sizeof(IP)));
}

// Comparison of the IP address list items
int CmpIpAddressList(void *p1, void *p2) {
	IP *ip1, *ip2;
	UINT r;
	// Validate arguments
	if (p1 == NULL || p2 == NULL) {
		return 0;
	}
	ip1 = *(IP **)p1;
	ip2 = *(IP **)p2;
	if (ip1 == NULL || ip2 == NULL) {
		return 0;
	}

	// IPv4 < IPv6
	r = COMPARE_RET(IsIP6(ip1), IsIP6(ip2));
	if (r != 0) {
		return r;
	}

	// any > specified IP
	if (IsZeroIP(ip1) && IsZeroIP(ip2) == false) {
		return 1;
	}
	if (IsZeroIP(ip1) == false && IsZeroIP(ip2)) {
		return -1;
	}

	// local > others
	if (IsLocalHostIP(ip1) && IsLocalHostIP(ip2) == false) {
		return 1;
	}
	if (IsLocalHostIP(ip1) == false && IsLocalHostIP(ip2)) {
		return -1;
	}

	// ip address
	r = CmpIpAddr(ip1, ip2);
	if (r != 0) {
		return r;
	}

	// interface index
	if (IsIP6(ip1)) {
		r = COMPARE_RET(ip1->ipv6_scope_id, ip2->ipv6_scope_id);
	} else {
		r = 0;
	}

	return r;
}

// Get the IP address list hash of the host
UINT64 GetHostIPAddressListHash() {
	UINT i;
	LIST *o;
	BUF *buf = NewBuf();
	UCHAR hash[SHA1_SIZE];
	UINT64 ret = 0;

	o = GetHostIPAddressList();

	if (o != NULL) {
		for (i = 0; i < LIST_NUM(o); i++) {
			IP *ip = LIST_DATA(o, i);
			char tmp[128];

			Zero(tmp, sizeof(tmp));
			IPToStr(tmp, sizeof(tmp), ip);

			WriteBufStr(buf, tmp);
		}

		FreeHostIPAddressList(o);
	}

	WriteBufStr(buf, "test");

	Sha1(hash, buf->Buf, buf->Size);

	FreeBuf(buf);

	Copy(&ret, hash, sizeof(UINT64));

	ret = Endian64(ret);

	return ret;
}

// Get the IP address list of the host (using cache)
LIST *GetHostIPAddressList() {
	LIST *o = NULL;
	if (host_ip_address_list_cache_lock == NULL) {
		return GetHostIPAddressListInternal();
	}

	Lock(host_ip_address_list_cache_lock);
	{
		UINT64 now = Tick64();

		if (host_ip_address_list_cache_last == 0 ||
		    ((host_ip_address_list_cache_last + (UINT64)HOST_IP_ADDRESS_LIST_CACHE) < now) ||
		    host_ip_address_cache == NULL) {
			if (host_ip_address_cache != NULL) {
				FreeHostIPAddressList(host_ip_address_cache);
			}

			host_ip_address_cache = GetHostIPAddressListInternal();

			host_ip_address_list_cache_last = now;
		}

		o = CloneIPAddressList(host_ip_address_cache);
	}
	Unlock(host_ip_address_list_cache_lock);

	if (o == NULL) {
		o = GetHostIPAddressListInternal();
	}

	return o;
}

// Copy of the IP address list
LIST *CloneIPAddressList(LIST *o) {
	LIST *ret;
	UINT i;
	// Validate arguments
	if (o == NULL) {
		return NULL;
	}

	ret = NewListFast(o->cmp);

	for (i = 0; i < LIST_NUM(o); i++) {
		IP *ip = LIST_DATA(o, i);

		if (ip != NULL) {
			ip = Clone(ip, sizeof(IP));

			Add(ret, ip);
		}
	}

	return ret;
}

// Get an IP address list of the host
LIST *GetHostIPAddressListInternal() {
	char hostname[MAX_SIZE];
	LIST *o;
	IP any6, any4;
	IP local6, local4;
	bool is_v6_supported = IsIPv6Supported();

	GetLocalHostIP4(&local4);
	GetLocalHostIP6(&local6);

	ZeroIP4(&any4);
	Zero(&any6, sizeof(any6));

	Zero(hostname, sizeof(hostname));

	gethostname(hostname, sizeof(hostname));

	o = NewListFast(CmpIpAddressList);

	// any
	AddHostIPAddressToList(o, &any4);
	if (is_v6_supported) {
		AddHostIPAddressToList(o, &any6);
	}

	// localhost
	AddHostIPAddressToList(o, &local4);
	if (is_v6_supported) {
		AddHostIPAddressToList(o, &local6);
	}

	// IPv4
	if (true) {
		struct sockaddr_in in;
		struct in_addr addr;
		struct addrinfo hint;
		struct addrinfo *info;

		Zero(&hint, sizeof(hint));
		hint.ai_family = AF_INET;
		hint.ai_socktype = SOCK_DGRAM;
		hint.ai_protocol = IPPROTO_UDP;
		info = NULL;

		if (getaddrinfo(hostname, NULL, &hint, &info) == 0) {
			if (info->ai_family == AF_INET) {
				struct addrinfo *current = info;
				while (current != NULL) {
					IP ip;

					Copy(&in, current->ai_addr, sizeof(in));
					Copy(&addr, &in.sin_addr, sizeof(addr));

					InAddrToIP(&ip, &addr);
					AddHostIPAddressToList(o, &ip);

					current = current->ai_next;
				}
			}

			freeaddrinfo(info);
		}
	}

	// IPv6
	if (is_v6_supported) {
		struct sockaddr_in6 in;
		struct in6_addr addr;
		struct addrinfo hint;
		struct addrinfo *info;

		Zero(&hint, sizeof(hint));
		hint.ai_family = AF_INET6;
		hint.ai_socktype = SOCK_DGRAM;
		hint.ai_protocol = IPPROTO_UDP;
		info = NULL;

		if (getaddrinfo(hostname, NULL, &hint, &info) == 0) {
			if (info->ai_family == AF_INET6) {
				struct addrinfo *current = info;
				while (current != NULL) {
					IP ip;

					Copy(&in, current->ai_addr, sizeof(in));
					Copy(&addr, &in.sin6_addr, sizeof(addr));

					InAddrToIP6(&ip, &addr);
					ip.ipv6_scope_id = in.sin6_scope_id;

					AddHostIPAddressToList(o, &ip);

					current = current->ai_next;
				}
			}

			freeaddrinfo(info);
		}
	}

	return o;
}

// Store the error value into PACK
PACK *PackError(UINT error) {
	PACK *p;

	p = NewPack();
	PackAddInt(p, "error", error);

	return p;
}

// Get the error value from PACK
UINT GetErrorFromPack(PACK *p) {
	// Validate arguments
	if (p == NULL) {
		return 0;
	}

	return PackGetInt(p, "error");
}

// Create an entry to PACK for the dummy
void CreateDummyValue(PACK *p) {
	UINT size;
	UCHAR *buf;
	// Validate arguments
	if (p == NULL) {
		return;
	}

	size = Rand32() % HTTP_PACK_RAND_SIZE_MAX;
	buf = Malloc(size);
	Rand(buf, size);

	PackAddData(p, "pencore", buf, size);

	Free(buf);
}

// Receive a line
char *RecvLine(SOCK *s, UINT max_size) {
	BUF *b;
	char c;
	char *str;
	// Validate arguments
	if (s == NULL || max_size == 0) {
		return NULL;
	}

	b = NewBuf();
	while (true) {
		UCHAR *buf;
		if (RecvAll(s, &c, sizeof(c), s->SecureMode) == false) {
			FreeBuf(b);
			return NULL;
		}
		WriteBuf(b, &c, sizeof(c));
		buf = (UCHAR *)b->Buf;
		if (b->Size > max_size) {
			FreeBuf(b);
			return NULL;
		}
		if (b->Size >= 1) {
			if (buf[b->Size - 1] == '\n') {
				b->Size--;
				if (b->Size >= 1) {
					if (buf[b->Size - 1] == '\r') {
						b->Size--;
					}
				}
				str = Malloc(b->Size + 1);
				Copy(str, b->Buf, b->Size);
				str[b->Size] = 0;
				FreeBuf(b);

				return str;
			}
		}
	}
}

// Get SNI name from the SSL packet
bool GetSniNameFromSslPacket(UCHAR *packet_buf, UINT packet_size, char *sni, UINT sni_size) {
	BUF *buf;
	bool ret = false;
	UCHAR content_type;
	USHORT version;
	USHORT handshake_length;

	// Validate arguments
	if (packet_buf == NULL || packet_size <= 11) {
		return false;
	}

	if (!(packet_buf[0] == 0x16 && packet_buf[1] >= 0x03 &&
	      packet_buf[5] == 0x01 && packet_buf[6] == 0x00 &&
	      packet_buf[9] >= 0x03)) {
		return false;
	}

	buf = NewBufFromMemory(packet_buf, packet_size);

	if (ReadBuf(buf, &content_type, sizeof(UCHAR)) == sizeof(UCHAR) &&
	    ReadBuf(buf, &version, sizeof(USHORT)) == sizeof(USHORT) &&
	    ReadBuf(buf, &handshake_length, sizeof(USHORT)) == sizeof(USHORT)) {
		version = Endian16(version);
		handshake_length = Endian16(handshake_length);

		if (content_type == 0x16 && version >= 0x0301) {
			UCHAR *handshake_data = Malloc(handshake_length);

			if (ReadBuf(buf, handshake_data, handshake_length) == handshake_length) {
				BUF *buf2 = NewBufFromMemory(handshake_data, handshake_length);
				USHORT handshake_type;
				USHORT handshake_length_2;

				if (ReadBuf(buf2, &handshake_type, sizeof(USHORT)) == sizeof(USHORT) &&
				    ReadBuf(buf2, &handshake_length_2, sizeof(USHORT)) == sizeof(USHORT)) {
					handshake_type = Endian16(handshake_type);
					handshake_length_2 = Endian16(handshake_length_2);

					if (handshake_type == 0x0100 && handshake_length_2 <= (handshake_length - 4)) {
						USHORT version2;

						if (ReadBuf(buf2, &version2, sizeof(USHORT)) == sizeof(USHORT)) {
							version2 = Endian16(version2);

							if (version2 >= 0x0301) {
								UCHAR rand[32];

								if (ReadBuf(buf2, rand, sizeof(rand)) == sizeof(rand)) {
									UCHAR session_id_len;

									if (ReadBuf(buf2, &session_id_len, sizeof(UCHAR)) == sizeof(UCHAR)) {
										if (ReadBuf(buf2, NULL, session_id_len) == session_id_len) {
											USHORT cipher_len;

											if (ReadBuf(buf2, &cipher_len, sizeof(USHORT)) == sizeof(USHORT)) {
												cipher_len = Endian16(cipher_len);

												if (ReadBuf(buf2, NULL, cipher_len) == cipher_len) {
													UCHAR comps_len;

													if (ReadBuf(buf2, &comps_len, sizeof(UCHAR)) == sizeof(UCHAR)) {
														if (ReadBuf(buf2, NULL, comps_len) == comps_len) {
															USHORT ext_length;

															if (ReadBuf(buf2, &ext_length, sizeof(USHORT)) == sizeof(USHORT)) {
																UCHAR *ext_buf;

																ext_length = Endian16(ext_length);

																ext_buf = Malloc(ext_length);

																if (ReadBuf(buf2, ext_buf, ext_length) == ext_length) {
																	BUF *ebuf = NewBufFromMemory(ext_buf, ext_length);

																	while (ret == false) {
																		USHORT type;
																		USHORT data_len;
																		UCHAR *data;

																		if (ReadBuf(ebuf, &type, sizeof(USHORT)) != sizeof(USHORT)) {
																			break;
																		}

																		if (ReadBuf(ebuf, &data_len, sizeof(USHORT)) != sizeof(USHORT)) {
																			break;
																		}

																		type = Endian16(type);
																		data_len = Endian16(data_len);

																		data = Malloc(data_len);

																		if (ReadBuf(ebuf, data, data_len) != data_len) {
																			Free(data);
																			break;
																		}

																		if (type == 0x0000) {
																			BUF *dbuf = NewBufFromMemory(data, data_len);

																			USHORT total_len;

																			if (ReadBuf(dbuf, &total_len, sizeof(USHORT)) == sizeof(USHORT)) {
																				UCHAR c;
																				total_len = Endian16(total_len);

																				if (ReadBuf(dbuf, &c, sizeof(UCHAR)) == sizeof(UCHAR)) {
																					if (c == 0) {
																						USHORT name_len;

																						if (ReadBuf(dbuf, &name_len, sizeof(USHORT)) == sizeof(USHORT)) {
																							char *name_buf;
																							name_len = Endian16(name_len);

																							name_buf = ZeroMalloc(name_len + 1);

																							if (ReadBuf(dbuf, name_buf, name_len) == name_len) {
																								if (StrLen(name_buf) >= 1) {
																									ret = true;

																									StrCpy(sni, sni_size, name_buf);
																								}
																							}

																							Free(name_buf);
																						}
																					}
																				}
																			}

																			FreeBuf(dbuf);
																		}

																		Free(data);
																	}

																	FreeBuf(ebuf);
																}

																Free(ext_buf);
															}
														}
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}

				FreeBuf(buf2);
			}

			Free(handshake_data);
		}
	}

	FreeBuf(buf);

	if (ret) {
		Trim(sni);

		if (IsEmptyStr(sni)) {
			ret = false;
		}
	}

	return ret;
}

void SetDhParam(DH_CTX *dh) {
	if (dh_param) {
		DhFree(dh_param);
	}

	dh_param = dh;
}
