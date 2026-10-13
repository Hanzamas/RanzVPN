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

struct ROUTE_CHANGE_DATA
{
	HANDLE Handle;
	UINT NumCalled;
	bool Changed;
};
#endif
#include "NetworkInternal.h"

// HTTP constant
static char http_detect_server_startwith[] = "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\r\n<HTML><HEAD>\r\n<TITLE>403 Forbidden</TITLE>\r\n</HEAD><BODY>\r\n<H1>Forbidden</H1>\r\nYou don't have permission to access ";
static char http_detect_server_tag_future[] = "9C37197CA7C2428388C2E6E59B829B30";

// Lock related
static LOCK *machine_name_lock = NULL;
static LOCK *disconnect_function_lock = NULL;
static COUNTER *num_tcp_connections = NULL;
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

typedef struct PRIVATE_IP_SUBNET
{
	UINT Ip, Mask, Ip2;
} PRIVATE_IP_SUBNET;

static LIST *g_private_ip_list = NULL;


static LIST *g_dyn_value_list = NULL;




// Get a value from a dynamic value list (Returns a default value if the value is not found)
UINT64 GetDynValueOrDefault(char *name, UINT64 default_value, UINT64 min_value, UINT64 max_value)
{
	UINT64 ret = GetDynValue(name);

	if (ret == 0)
	{
		return default_value;
	}

	if (ret < min_value)
	{
		ret = min_value;
	}

	if (ret > max_value)
	{
		ret = max_value;
	}

	return ret;
}

// Get a value from a dynamic value list (Returns a default value if the value is not found)
// The value is limited to 1/5 to 50 times of the default value for safety
UINT64 GetDynValueOrDefaultSafe(char *name, UINT64 default_value)
{
	return GetDynValueOrDefault(name, default_value, default_value / (UINT64)5, default_value * (UINT64)50);
}

// Get a value from a dynamic value list
UINT64 GetDynValue(char *name)
{
	UINT64 ret = 0;
	// Validate arguments
	if (name == NULL)
	{
		return 0;
	}

	if (g_dyn_value_list == NULL)
	{
		return 0;
	}

	LockList(g_dyn_value_list);
	{
		UINT i;

		for (i = 0; i < LIST_NUM(g_dyn_value_list); i++)
		{
			DYN_VALUE *vv = LIST_DATA(g_dyn_value_list, i);

			if (StrCmpi(vv->Name, name) == 0)
			{
				ret = vv->Value;
				break;
			}
		}
	}
	UnlockList(g_dyn_value_list);

	return ret;
}

// Initialization of the dynamic value list
void InitDynList()
{
	g_dyn_value_list = NewList(NULL);
}

// Solution of dynamic value list
void FreeDynList()
{
	UINT i;
	if (g_dyn_value_list == NULL)
	{
		return;
	}

	for (i = 0; i < LIST_NUM(g_dyn_value_list); i++)
	{
		DYN_VALUE *d = LIST_DATA(g_dyn_value_list, i);

		Free(d);
	}

	ReleaseList(g_dyn_value_list);

	g_dyn_value_list = NULL;
}

// Get the current time zone
int GetCurrentTimezone()
{
	int ret = 0;

#ifdef	OS_WIN32
	ret = GetCurrentTimezoneWin32();
#endif	// OS_WIN32

	return ret;
}

#ifdef	OS_WIN32
// Get the current time zone (Win32)
int GetCurrentTimezoneWin32()
{
	TIME_ZONE_INFORMATION info;
	Zero(&info, sizeof(info));

	if (GetTimeZoneInformation(&info) == TIME_ZONE_ID_INVALID)
	{
		return 0;
	}

	return info.Bias;
}
#endif	// OS_WIN32

// Check whether the specified MAC address exists on the local host (high speed)
bool IsMacAddressLocalFast(void *addr)
{
	bool ret = false;
	// Validate arguments
	if (addr == NULL)
	{
		return false;
	}

	Lock(local_mac_list_lock);
	{
		if (local_mac_list == NULL)
		{
			// First enumeration
			RefreshLocalMacAddressList();
		}

		ret = IsMacAddressLocalInner(local_mac_list, addr);
	}
	Unlock(local_mac_list_lock);

	return ret;
}

// Update the local MAC address list
void RefreshLocalMacAddressList()
{
	Lock(local_mac_list_lock);
	{
		if (local_mac_list != NULL)
		{
			FreeNicList(local_mac_list);
		}

		local_mac_list = GetNicList();
	}
	Unlock(local_mac_list_lock);
}

// Check whether the specified MAC address exists on the local host
bool IsMacAddressLocalInner(LIST *o, void *addr)
{
	bool ret = false;
	UINT i;
	// Validate arguments
	if (o == NULL || addr == NULL)
	{
		return false;
	}

	for (i = 0; i < LIST_NUM(o); i++)
	{
		NIC_ENTRY *e = LIST_DATA(o, i);

		if (Cmp(e->MacAddress, addr, 6) == 0)
		{
			ret = true;
			break;
		}
	}

	return ret;
}

// Get a list of the NICs on the computer
LIST *GetNicList()
{
	LIST *o = NULL;

#ifdef	OS_WIN32
	o = Win32GetNicList();

	if (o != NULL)
	{
		return o;
	}

#endif	// OS_WIN32

	return NewListFast(NULL);
}

#ifdef	OS_WIN32
LIST *Win32GetNicList()
{
	UINT i;
	LIST *o = NewListFast(NULL);
	MS_ADAPTER_LIST *al = MsCreateAdapterList();

	if (al == NULL)
	{
		return NULL;
	}

	for (i = 0; i < al->Num; i++)
	{
		MS_ADAPTER *a = al->Adapters[i];

		if (a->Type == 6 && a->AddressSize == 6)
		{
			// If the connection state of the interface is unknown, then exclude it.
			// Unknown means that the device is not plugged into the local host.
			if (a->MediaConnectState == MediaConnectStateUnknown)
			{
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
#endif	// OS_WIN32

// Release the NIC list
void FreeNicList(LIST *o)
{
	UINT i;
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	for (i = 0; i < LIST_NUM(o); i++)
	{
		NIC_ENTRY *e = LIST_DATA(o, i);

		Free(e);
	}

	ReleaseList(o);
}

// Parse the user name of the NT
void ParseNtUsername(char *src_username, char *dst_username, UINT dst_username_size, char *dst_domain, UINT dst_domain_size, bool do_not_parse_atmark)
{
	char tmp_username[MAX_SIZE];
	char tmp_domain[MAX_SIZE];
	TOKEN_LIST *t;

	if (src_username != dst_username)
	{
		ClearStr(dst_username, dst_username_size);
	}

	ClearStr(dst_domain, dst_domain_size);
	// Validate arguments
	if (src_username == NULL || dst_username == NULL || dst_domain == NULL)
	{
		return;
	}

	StrCpy(tmp_username, sizeof(tmp_username), src_username);
	ClearStr(tmp_domain, sizeof(tmp_domain));

	// Analysis of username@domain.name format
	if (do_not_parse_atmark == false)
	{
		t = ParseTokenWithNullStr(tmp_username, "@");
		if (t->NumTokens >= 1)
		{
			StrCpy(tmp_username, sizeof(tmp_username), t->Token[0]);
		}
		if (t->NumTokens >= 2)
		{
			StrCpy(tmp_domain, sizeof(tmp_domain), t->Token[1]);
		}
		FreeToken(t);
	}

	// If the username part is in "domain\username" format, split it
	t = ParseTokenWithNullStr(tmp_username, "\\");
	if (t->NumTokens >= 2)
	{
		if (IsEmptyStr(tmp_domain))
		{
			StrCpy(tmp_domain, sizeof(tmp_domain), t->Token[0]);
		}

		StrCpy(tmp_username, sizeof(tmp_username), t->Token[1]);
	}
	FreeToken(t);

	StrCpy(dst_username, dst_username_size, tmp_username);
	StrCpy(dst_domain, dst_domain_size, tmp_domain);
}

// Generate a hash from the current computer name and the process name
void GetCurrentMachineIpProcessHash(void *hash)
{
	// Validate arguments
	if (hash == NULL)
	{
		return;
	}

	Lock(machine_ip_process_hash_lock);
	{
		if (IsZero(machine_ip_process_hash, SHA1_SIZE))
		{
			GetCurrentMachineIpProcessHashInternal(machine_ip_process_hash);
		}

		Copy(hash, machine_ip_process_hash, SHA1_SIZE);
	}
	Unlock(machine_ip_process_hash_lock);
}
void GetCurrentMachineIpProcessHashInternal(void *hash)
{
	BUF *b;
	LIST *ip_list;
	char machine_name[MAX_SIZE];
	wchar_t exe_path[MAX_PATH];
	char *product_id = NULL;
	// Validate arguments
	if (hash == NULL)
	{
		return;
	}

#ifdef	OS_WIN32
	product_id = MsRegReadStr(REG_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "ProductId");
	if (product_id == NULL)
	{
		product_id = MsRegReadStr(REG_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion", "ProductId");
	}
#endif	// OS_WIN32

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
	if (ip_list != NULL)
	{
		UINT i;
		for (i = 0; i < LIST_NUM(ip_list); i++)
		{
			IP *ip = LIST_DATA(ip_list, i);

			WriteBuf(b, ip, sizeof(IP));
		}
	}
	FreeHostIPAddressList(ip_list);

	Sha1(hash, b->Buf, b->Size);

	FreeBuf(b);

	Free(product_id);
}

#define	USE_OLD_GETIP

// Set the arp_filter in Linux
void SetLinuxArpFilter()
{
	char *filename = "/proc/sys/net/ipv4/conf/all/arp_filter";
	char *data = "1\n";
	IO *o;

	o = FileCreate(filename);
	if (o == NULL)
	{
		return;
	}

	FileWrite(o, data, StrLen(data));
	FileFlush(o);

	FileClose(o);
}

// Determine whether the string is a IPv6 address
bool IsStrIPv6Address(char *str)
{
	IP ip;
	// Validate arguments
	if (str == NULL)
	{
		return false;
	}

	if (StrToIP6(&ip, str) == false)
	{
		return false;
	}

	return true;
}

// Convert the subnet mask to an integer
UINT SubnetMaskToInt6(IP *a)
{
	UINT i;
	// Validate arguments
	if (IsIP6(a) == false)
	{
		return 0;
	}

	for (i = 0; i <= 128; i++)
	{
		IP tmp;

		IntToSubnetMask6(&tmp, i);

		if (CmpIpAddr(a, &tmp) == 0)
		{
			return i;
		}
	}

	return 0;
}
UINT SubnetMaskToInt4(IP *a)
{
	UINT i;
	// Validate arguments
	if (IsIP4(a) == false)
	{
		return 0;
	}

	for (i = 0; i <= 32; i++)
	{
		IP tmp;

		IntToSubnetMask4(&tmp, i);

		if (CmpIpAddr(a, &tmp) == 0)
		{
			return i;
		}
	}

	return 0;
}
UINT SubnetMaskToInt(IP *a)
{
	if (IsIP6(a))
	{
		return SubnetMaskToInt6(a);
	}
	else
	{
		return SubnetMaskToInt4(a);
	}
}

// Determine whether the specified IP address is a subnet mask
bool IsSubnetMask6(IP *a)
{
	UINT i;
	// Validate arguments
	if (IsIP6(a) == false)
	{
		return false;
	}

	for (i = 0; i <= 128; i++)
	{
		IP tmp;

		IntToSubnetMask6(&tmp, i);

		if (CmpIpAddr(a, &tmp) == 0)
		{
			return true;
		}
	}

	return false;
}

// Generate a local address from the MAC address
void GenerateEui64LocalAddress(IP *a, UCHAR *mac)
{
	// Validate arguments
	if (a == NULL || mac == NULL)
	{
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
void GenerateEui64Address6(UCHAR *dst, UCHAR *mac)
{
	// Validate arguments
	if (dst == NULL || mac == NULL)
	{
		return;
	}

	Copy(dst, mac, 3);
	Copy(dst + 5, mac, 3);

	dst[3] = 0xff;
	dst[4] = 0xfe;
	dst[0] = ((~(dst[0] & 0x02)) & 0x02) | (dst[0] & 0xfd);
}

// Get the prefix address
void GetPrefixAddress6(IP *dst, IP *ip, IP *subnet)
{
	// Validate arguments
	if (dst == NULL || ip == NULL || subnet == NULL)
	{
		return;
	}

	IPAnd6(dst, ip, subnet);

	dst->ipv6_scope_id = ip->ipv6_scope_id;
}

// Get the type of the IPv6 address
UINT GetIPv6AddrType(IPV6_ADDR *addr)
{
	IP ip;
	// Validate arguments
	if (addr == NULL)
	{
		return 0;
	}

	IPv6AddrToIP(&ip, addr);

	return GetIPAddrType6(&ip);
}
UINT GetIPAddrType6(IP *ip)
{
	UINT ret = 0;
	// Validate arguments
	if (IsIP6(ip) == false)
	{
		return 0;
	}

	if (ip->address[0] == 0xff)
	{
		IP all_node, all_router;

		GetAllNodeMulticaseAddress6(&all_node);

		GetAllRouterMulticastAddress6(&all_router);

		ret |= IPV6_ADDR_MULTICAST;

		if (CmpIpAddr(ip, &all_node) == 0)
		{
			ret |= IPV6_ADDR_ALL_NODE_MULTICAST;
		}
		else if (CmpIpAddr(ip, &all_router) == 0)
		{
			ret |= IPV6_ADDR_ALL_ROUTER_MULTICAST;
		}
		else
		{
			if (ip->address[1] == 0x02 && ip->address[2] == 0 && ip->address[3] == 0 &&
			        ip->address[4] == 0 && ip->address[5] == 0 && ip->address[6] == 0 &&
			        ip->address[7] == 0 && ip->address[8] == 0 && ip->address[9] == 0 &&
			        ip->address[10] == 0 && ip->address[11] == 0x01 && ip->address[12] == 0xff)
			{
				ret |= IPV6_ADDR_SOLICIATION_MULTICAST;
			}
		}
	}
	else
	{
		ret |= IPV6_ADDR_UNICAST;

		if (ip->address[0] == 0xfe && (ip->address[1] & 0xc0) == 0x80)
		{
			ret |= IPV6_ADDR_LOCAL_UNICAST;
		}
		else
		{
			ret |= IPV6_ADDR_GLOBAL_UNICAST;

			if (IsZero(&ip->address, sizeof(ip->address)))
			{
				ret |= IPV6_ADDR_ZERO;
			}
			else
			{
				IP loopback;

				GetLoopbackAddress6(&loopback);

				if (Cmp(ip->address, loopback.address, sizeof(ip->address)) == 0)
				{
					ret |= IPV6_ADDR_LOOPBACK;
				}
			}
		}
	}

	return ret;
}

// Loopback address
void GetLoopbackAddress6(IP *ip)
{
	// Validate arguments
	if (ip == NULL)
	{
		return;
	}

	Zero(ip, sizeof(IP));

	ip->address[15] = 0x01;
}

// All-nodes multicast address
void GetAllNodeMulticaseAddress6(IP *ip)
{
	// Validate arguments
	if (ip == NULL)
	{
		return;
	}

	Zero(ip, sizeof(IP));

	ip->address[0] = 0xff;
	ip->address[1] = 0x02;
	ip->address[15] = 0x01;
}

// All-routers multicast address
void GetAllRouterMulticastAddress6(IP *ip)
{
	// Validate arguments
	if (ip == NULL)
	{
		return;
	}

	Zero(ip, sizeof(IP));

	ip->address[0] = 0xff;
	ip->address[1] = 0x02;
	ip->address[15] = 0x02;
}

// Logical operation of the IPv4 address
void IPAnd4(IP *dst, IP *a, IP *b)
{
	// Validate arguments
	if (dst == NULL || a == NULL || b == NULL || IsIP4(a) == false || IsIP4(b) == false)
	{
		ZeroIP4(dst);
		return;
	}

	UINTToIP(dst, IPToUINT(a) & IPToUINT(b));
}

// Logical operation of the IPv6 address
void IPAnd6(IP *dst, IP *a, IP *b)
{
	Zero(dst, sizeof(IP));

	// Validate arguments
	if (dst == NULL || IsIP6(a) == false || IsIP6(b) == false)
	{
		return;
	}

	for (BYTE i = 0; i < sizeof(dst->address); ++i)
	{
		dst->address[i] = a->address[i] & b->address[i];
	}
}

// Creating a subnet mask
void IntToSubnetMask6(IP *ip, UINT i)
{
	UINT j = i / 8;
	UINT k = i % 8;
	UINT z;
	IP a;

	Zero(&a, sizeof(IP));

	for (z = 0; z < sizeof(a.address); ++z)
	{
		if (z < j)
		{
			a.address[z] = 0xff;
		}
		else if (z == j)
		{
			a.address[z] = ~(0xff >> k);
		}
	}

	Copy(ip, &a, sizeof(IP));
}

// Convert the IP address to a string
void IP6AddrToStr(char *str, UINT size, IPV6_ADDR *addr)
{
	// Validate arguments
	if (str == NULL || addr == NULL)
	{
		return;
	}

	IPToStr6Array(str, size, addr->Value);
}
void IPToStr6Array(char *str, UINT size, UCHAR *bytes)
{
	IP ip;
	// Validate arguments
	if (str == NULL || bytes == NULL)
	{
		return;
	}

	SetIP6(&ip, bytes);

	IPToStr6(str, size, &ip);
}
void IPToStr6(char *str, UINT size, IP *ip)
{
	char tmp[MAX_SIZE];

	IPToStr6Inner(tmp, ip);

	StrCpy(str, size, tmp);
}
void IPToStr6Inner(char *str, IP *ip)
{
	UINT i;
	USHORT values[8];
	UINT zero_started_index;
	UINT max_zero_len;
	UINT max_zero_start;
	IP a;
	// Validate arguments
	if (str == NULL || ip == NULL)
	{
		return;
	}

	Copy(&a, ip, sizeof(IP));

	for (i = 0; i < 8; i++)
	{
		Copy(&values[i], &a.address[i * 2], sizeof(USHORT));
		values[i] = Endian16(values[i]);
	}

	// Search for omittable part
	zero_started_index = INFINITE;
	max_zero_len = 0;
	max_zero_start = INFINITE;
	for (i = 0; i < 9; i++)
	{
		USHORT v = (i != 8 ? values[i] : 1);

		if (v == 0)
		{
			if (zero_started_index == INFINITE)
			{
				zero_started_index = i;
			}
		}
		else
		{
			UINT zero_len;

			if (zero_started_index != INFINITE)
			{
				zero_len = i - zero_started_index;
				if (zero_len >= 2)
				{
					if (max_zero_len < zero_len)
					{
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
	for (i = 0; i < 8; i++)
	{
		char tmp[16];

		ToHex(tmp, values[i]);
		StrLower(tmp);

		if (i == max_zero_start)
		{
			if (i == 0)
			{
				StrCat(str, 0, "::");
			}
			else
			{
				StrCat(str, 0, ":");
			}
			i += max_zero_len - 1;
		}
		else
		{
			StrCat(str, 0, tmp);
			if (i != 7)
			{
				StrCat(str, 0, ":");
			}
		}
	}

	// Scope ID
	if (ip->ipv6_scope_id != 0)
	{
		char tmp[64];

		StrCat(str, 0, "%");
		ToStr(tmp, ip->ipv6_scope_id);

		StrCat(str, 0, tmp);
	}
}

// Convert the string to an IP address
bool StrToIP6(IP *ip, char *str)
{
	TOKEN_LIST *t;
	char tmp[MAX_PATH];
	IP a;
	UINT i;
	UINT scope_id = 0;
	// Validate arguments
	if (str == NULL || ip == NULL)
	{
		return false;
	}

	Zero(&a, sizeof(a));

	StrCpy(tmp, sizeof(tmp), str);
	Trim(tmp);

	if (StartWith(tmp, "[") && EndWith(tmp, "]"))
	{
		// If the string is enclosed in square brackets, remove brackets
		StrCpyAllowOverlap(tmp, sizeof(tmp), &tmp[1]);

		if (StrLen(tmp) >= 1)
		{
			tmp[StrLen(tmp) - 1] = 0;
		}
	}

	// Remove the scope ID by analyzing if there is it
	i = SearchStrEx(tmp, "%", 0, false);
	if (i != INFINITE)
	{
		char ss[MAX_PATH];

		StrCpy(ss, sizeof(ss), &tmp[i + 1]);

		tmp[i] = 0;

		Trim(tmp);

		Trim(ss);

		scope_id = ToInt(ss);
	}

	// Tokenize
	t = ParseTokenWithNullStr(tmp, ":");
	if (t->NumTokens >= 3 && t->NumTokens <= 8)
	{
		UINT i, n;
		bool b = true;
		UINT k = 0;

		n = 0;

		for (i = 0; i < t->NumTokens; i++)
		{
			char *str = t->Token[i];

			if (i != 0 && i != (t->NumTokens - 1) && StrLen(str) == 0)
			{
				n++;
				if (n == 1)
				{
					k += 2 * (8 - t->NumTokens + 1);
				}
				else
				{
					b = false;
					break;
				}
			}
			else
			{
				UCHAR chars[2];

				if (CheckIPItemStr6(str) == false)
				{
					b = false;
					break;
				}

				IPItemStrToChars6(chars, str);

				a.address[k++] = chars[0];
				a.address[k++] = chars[1];
			}
		}

		if (n != 0 && n != 1)
		{
			b = false;
		}
		else if (n == 0 && t->NumTokens != 8)
		{
			b = false;
		}

		if (b == false)
		{
			FreeToken(t);
			return false;
		}
	}
	else
	{
		FreeToken(t);
		return false;
	}

	FreeToken(t);

	Copy(ip, &a, sizeof(IP));

	ip->ipv6_scope_id = scope_id;

	return true;
}

// Convert an IP address character to the UCHAR type
void IPItemStrToChars6(UCHAR *chars, char *str)
{
	char tmp[5];
	BUF *b;
	UINT len;
	// Validate arguments
	if (chars == NULL)
	{
		return;
	}

	Zero(tmp, sizeof(tmp));

	len = StrLen(str);
	switch (len)
	{
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
bool CheckIPItemStr6(char *str)
{
	UINT i, len;
	// Validate arguments
	if (str == NULL)
	{
		return false;
	}

	len = StrLen(str);
	if (len >= 5)
	{
		// Invalid length
		return false;
	}

	for (i = 0; i < len; i++)
	{
		char c = str[i];

		if ((c >= 'a' && c <= 'f') ||
		        (c >= 'A' && c <= 'F') ||
		        (c >= '0' && c <= '9'))
		{
		}
		else
		{
			return false;
		}
	}

	return true;
}

// Create an IPv4 address of all zero
void ZeroIP4(IP *ip)
{
	// Validate arguments
	if (ip == NULL)
	{
		return;
	}

	Zero(ip, sizeof(IP));

	ip->address[10] = 0xff;
	ip->address[11] = 0xff;
}

// Get the IP address of the localhost
void GetLocalHostIP6(IP *ip)
{
	// Validate arguments
	if (ip == NULL)
	{
		return;
	}

	Zero(ip, sizeof(IP));

	ip->address[15] = 1;
}
void GetLocalHostIP4(IP *ip)
{
	// Validate arguments
	if (ip == NULL)
	{
		return;
	}

	SetIP(ip, 127, 0, 0, 1);
}

// Check whether the specified address is a localhost
bool IsLocalHostIP6(IP *ip)
{
	IP local;
	// Validate arguments
	if (ip == NULL)
	{
		return false;
	}
	if (IsIP6(ip) == false)
	{
		return false;
	}

	GetLocalHostIP6(&local);

	if (CmpIpAddr(&local, ip) == 0)
	{
		return true;
	}

	return false;
}
bool IsLocalHostIP4(IP *ip)
{
	// Validate arguments
	if (ip == NULL)
	{
		return false;
	}
	if (IsIP4(ip) == false)
	{
		return false;
	}

	if (IPV4(ip->address)[0] == 127)
	{
		return true;
	}

	return false;
}
bool IsLocalHostIP(IP *ip)
{
	// Validate arguments
	if (ip == NULL)
	{
		return false;
	}

	if (IsIP4(ip))
	{
		return IsLocalHostIP4(ip);
	}
	else
	{
		return IsLocalHostIP6(ip);
	}
}

// Convert the IPV6_ADDR to an IP
void IPv6AddrToIP(IP *ip, IPV6_ADDR *addr)
{
	// Validate arguments
	if (ip == NULL || addr == NULL)
	{
		return;
	}

	SetIP6(ip, addr->Value);
}

// Convert the IP to an IPV6_ADDR
bool IPToIPv6Addr(IPV6_ADDR *addr, IP *ip)
{
	UINT i;
	// Validate arguments
	if (addr == NULL || ip == NULL)
	{
		Zero(addr, sizeof(IPV6_ADDR));
		return false;
	}

	if (IsIP6(ip) == false)
	{
		Zero(addr, sizeof(IPV6_ADDR));
		return false;
	}

	for (i = 0; i < sizeof(addr->Value); ++i)
	{
		addr->Value[i] = ip->address[i];
	}

	return true;
}

// Set an IPv6 address
void SetIP6(IP *ip, UCHAR *value)
{
	// Validate arguments
	if (ip == NULL || value == NULL)
	{
		return;
	}

	Zero(ip, sizeof(IP));

	for (BYTE i = 0; i < sizeof(ip->address); ++i)
	{
		ip->address[i] = value[i];
	}
}

// Check whether the specified address is IPv4
bool IsIP4(IP *ip)
{
	// Validate arguments
	if (ip == NULL)
	{
		return false;
	}

	if (IsZero(ip->address, 10) == false)
	{
		return false;
	}

	if (ip->address[10] != 0xff || ip->address[11] != 0xff)
	{
		return false;
	}

	return true;
}

// Copy the IP address
void CopyIP(IP *dst, IP *src)
{
	Copy(dst, src, sizeof(IP));
}

// Utility functions about IP and MAC address types
// Identify whether the IP address is a normal unicast address
bool IsValidUnicastIPAddress4(IP *ip)
{
	// Validate arguments
	if (IsIP4(ip) == false)
	{
		return false;
	}

	if (IsZeroIP(ip))
	{
		return false;
	}

	const BYTE *ipv4 = IPV4(ip->address);

	if (ipv4[0] >= 224 && ipv4[0] <= 239)
	{
		// IPv4 Multicast
		return false;
	}

	/// TODO: this is kinda incorrect, but for the correct parsing we need the netmask anyway
	for (BYTE i = 0; i < IPV4_SIZE; ++i)
	{
		if (ipv4[i] != 255)
		{
			return true;
		}
	}

	return false;
}

bool IsValidUnicastIPAddress6(IP *ip)
{
	UINT ipv6Type;

	if (!IsIP6(ip))
	{
		return false;
	}

	if (IsZeroIP(ip))
	{
		return false;
	}

	ipv6Type = GetIPAddrType6(ip);

	if (!(ipv6Type & IPV6_ADDR_LOCAL_UNICAST) &&
	        !(ipv6Type & IPV6_ADDR_GLOBAL_UNICAST))
	{
		return false;
	}

	return true;
}

// Get the number of clients connected from the specified IP address
UINT GetNumIpClient(IP *ip)
{
	IP_CLIENT *c;
	UINT ret = 0;
	// Validate arguments
	if (ip == NULL)
	{
		return 0;
	}

	LockList(ip_clients);
	{
		c = SearchIpClient(ip);

		if (c != NULL)
		{
			ret = c->NumConnections;
		}
	}
	UnlockList(ip_clients);

	return ret;
}

// Add to the IP client entry
void AddIpClient(IP *ip)
{
	IP_CLIENT *c;
	// Validate arguments
	if (ip == NULL)
	{
		return;
	}

	LockList(ip_clients);
	{
		c = SearchIpClient(ip);

		if (c == NULL)
		{
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
void DelIpClient(IP *ip)
{
	IP_CLIENT *c;
	// Validate arguments
	if (ip == NULL)
	{
		return;
	}

	LockList(ip_clients);
	{
		c = SearchIpClient(ip);

		if (c != NULL)
		{
			c->NumConnections--;

			if (c->NumConnections == 0)
			{
				Delete(ip_clients, c);
				Free(c);
			}
		}
	}
	UnlockList(ip_clients);

	//Debug("DelIpClient: %r\n", ip);
}

// Search for the IP client entry
IP_CLIENT *SearchIpClient(IP *ip)
{
	IP_CLIENT t;
	// Validate arguments
	if (ip == NULL)
	{
		return NULL;
	}

	Zero(&t, sizeof(t));
	Copy(&t.IpAddress, ip, sizeof(IP));

	return Search(ip_clients, &t);
}

// Initialization of the client list
void InitIpClientList()
{
	ip_clients = NewList(CompareIpClientList);
}

// Release of the client list
void FreeIpClientList()
{
	UINT i;

	for (i = 0; i < LIST_NUM(ip_clients); i++)
	{
		IP_CLIENT *c = LIST_DATA(ip_clients, i);

		Free(c);
	}

	ReleaseList(ip_clients);
	ip_clients = NULL;
}

// Comparison of the client list entries
int CompareIpClientList(void *p1, void *p2)
{
	IP_CLIENT *c1, *c2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	c1 = *(IP_CLIENT **)p1;
	c2 = *(IP_CLIENT **)p2;
	if (c1 == NULL || c2 == NULL)
	{
		return 0;
	}

	return CmpIpAddr(&c1->IpAddress, &c2->IpAddress);
}

// Identify whether the IP address is empty
bool IsZeroIP(IP *ip)
{
	// Validate arguments
	if (ip == NULL)
	{
		return true;
	}

	if (IsZero(ip->address, sizeof(ip->address)))
	{
		return true;
	}

	if (IsIP4(ip))
	{
		return IsZero(IPV4(ip->address), IPV4_SIZE);
	}

	return false;
}
bool IsZeroIP6Addr(IPV6_ADDR *addr)
{
	// Validate arguments
	if (addr == NULL)
	{
		return true;
	}

	return IsZero(addr, sizeof(IPV6_ADDR));
}

// Convert the integer to a subnet mask
UINT IntToSubnetMask32(UINT i)
{
	UINT ret = 0xFFFFFFFF;

	switch (i)
	{
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

	if (IsLittleEndian())
	{
		ret = Swap32(ret);
	}

	return ret;
}
void IntToSubnetMask4(IP *ip, UINT i)
{
	UINT m;
	// Validate arguments
	if (ip == NULL)
	{
		return;
	}

	m = IntToSubnetMask32(i);

	UINTToIP(ip, m);
}

// Examine whether the specified IP address is a subnet mask
bool IsSubnetMask(IP *ip)
{
	if (IsIP6(ip))
	{
		return IsSubnetMask6(ip);
	}
	else
	{
		return IsSubnetMask4(ip);
	}
}
bool IsSubnetMask4(IP *ip)
{
	UINT i;
	// Validate arguments
	if (ip == NULL)
	{
		return false;
	}

	if (IsIP6(ip))
	{
		return false;
	}

	i = IPToUINT(ip);

	if (IsLittleEndian())
	{
		i = Swap32(i);
	}

	switch (i)
	{
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

// Check whether the IPv6 is supported
bool IsIPv6Supported()
{
#ifdef	NO_IPV6
	return false;
#else	// NO_IPV6
	SOCKET s;

	s = socket(AF_INET6, SOCK_STREAM, 0);
	if (s == INVALID_SOCKET)
	{
		return false;
	}

	closesocket(s);

	return true;
#endif	// NO_IPV6
}

// Check whether an IPv6 address is configured on any interface
bool HasIPv6Address()
{
	LIST *o;
	UINT i;
	bool ret = false;

	o = GetHostIPAddressList();

	ret = false;

	for (i = 0; i < LIST_NUM(o); i++)
	{
		IP *p = LIST_DATA(o, i);

		if (IsIP6(p))
		{
			UINT type = GetIPAddrType6(p);
			if ((type & IPV6_ADDR_GLOBAL_UNICAST) && ((type & IPV6_ADDR_ZERO) == 0) && ((type & IPV6_ADDR_LOOPBACK) == 0))
			{
				ret = true;
				break;
			}

		}
	}

	FreeHostIPAddressList(o);

	return ret;
}



// Disable GetHostName call by accepting new TCP connection
void DisableGetHostNameWhenAcceptInit()
{
	disable_gethostname_by_accept = true;
}

void AcceptInitEx(SOCK *s, bool no_lookup_hostname)
{
	char tmp[MAX_SIZE];
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	Zero(tmp, sizeof(tmp));

	if (disable_gethostname_by_accept == false && no_lookup_hostname == false)
	{
		if (GetHostName(tmp, sizeof(tmp), &s->RemoteIP) == false ||
		        IsEmptyStr(tmp))
		{
			IPToStr(tmp, sizeof(tmp), &s->RemoteIP);
		}
	}
	else
	{
		IPToStr(tmp, sizeof(tmp), &s->RemoteIP);
	}

	if (s->RemoteHostname != NULL)
	{
		Free(s->RemoteHostname);
	}

	s->RemoteHostname = CopyStr(tmp);
}

// TCP disconnect
void Disconnect(SOCK *sock)
{
	SOCKET s;
	// Validate arguments
	if (sock == NULL)
	{
		return;
	}

	sock->Disconnecting = true;

#ifdef	ENABLE_SSL_LOGGING
	SockCloseSslLogging(sock);
#endif	// ENABLE_SSL_LOGGING

	if (sock->Type == SOCK_TCP && sock->ListenMode)
	{
		bool no_tcp_check_port = false;

		// Connect to localhost if the socket is in listening
		sock->CancelAccept = true;

#ifdef	OS_WIN32
		if (sock->hAcceptEvent != NULL)
		{
			SetEvent(sock->hAcceptEvent);

			no_tcp_check_port = true;
		}
#endif	// OS_WIN32

		if (sock->AcceptCanceled == false)
		{
			if (no_tcp_check_port == false)
			{
				if (sock->IPv6 == false)
				{
					CheckTCPPort("127.0.0.1", sock->LocalPort);
				}
				else
				{
					CheckTCPPort("::1", sock->LocalPort);
				}
			}
		}
	}

	Lock(disconnect_function_lock);

	Lock(sock->disconnect_lock);

	if (sock->Type == SOCK_TCP)
	{
		if (sock->socket != INVALID_SOCKET)
		{
			// Forced disconnection flag
#ifdef	SO_DONTLINGER
			UINT true_flag = 1;
			(void)setsockopt(sock->socket, SOL_SOCKET, SO_DONTLINGER, (char *)&true_flag, sizeof(true_flag));
#else	// SO_DONTLINGER
			UINT false_flag = 0;
			(void)setsockopt(sock->socket, SOL_SOCKET, SO_LINGER, (char *)&false_flag, sizeof(false_flag));
#endif	// SO_DONTLINGER
//			setsockopt(sock->socket, SOL_SOCKET, SO_REUSEADDR, (char *)&true_flag, sizeof(true_flag));
		}

		// TCP socket
		Lock(sock->lock);
		{
			if (sock->socket == INVALID_SOCKET)
			{
				Unlock(sock->lock);
				Unlock(sock->disconnect_lock);
				Unlock(disconnect_function_lock);
				return;
			}
			s = sock->socket;

			if (sock->Connected)
			{
				struct linger ling;
				Zero(&ling, sizeof(ling));


#if	0
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
				if (sock->SecureMode)
				{
					if (sock->ssl != NULL)
					{
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

			if (sock->IpClientAdded)
			{
				DelIpClient(&sock->RemoteIP);
				sock->IpClientAdded = false;
			}
		}
		Unlock(sock->lock);
	}
	else if (sock->Type == SOCK_UDP)
	{
		// UDP socket
		Lock(sock->lock);
		{
			if (sock->socket == INVALID_SOCKET)
			{
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

typedef struct TCP_PORT_CHECK
{
	REF *ref;
	char hostname[MAX_SIZE];
	UINT port;
	bool ok;
} TCP_PORT_CHECK;


// Clean-up of the socket
void CleanupSock(SOCK *s)
{
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

//	{Debug("CleanupSock: Disconnect() Called: %s %u\n", __FILE__, __LINE__);Disconnect(s);}
	Disconnect(s);

#ifdef	OS_WIN32
	Win32FreeAsyncSocket(s);
#endif	// OS_WIN32

	FreeBuf(s->SendBuf);
	if (s->socket != INVALID_SOCKET)
	{
#ifdef	OS_WIN32
		closesocket(s->socket);
#endif	// OS_WIN32
	}
	Free(s->RemoteHostname);

#ifdef	OS_WIN32
	if (s->hAcceptEvent != NULL)
	{
		CloseHandle(s->hAcceptEvent);
	}
#endif	// OS_WIN32

	// Release the certificate
	if (s->RemoteX != NULL)
	{
		FreeX(s->RemoteX);
		s->RemoteX = NULL;
	}
	if (s->LocalX != NULL)
	{
		FreeX(s->LocalX);
		s->LocalX = NULL;
	}

	// Cipher algorithm name
	if (s->CipherName != NULL)
	{
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
SOCK *NewSock()
{
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
UINT IPToUINT(IP *ip)
{
	// Validate arguments
	if (ip == NULL || IsIP6(ip))
	{
		return 0;
	}

	UINT value;

	for (BYTE i = 0; i < IPV4_SIZE; ++i)
	{
		((BYTE *)&value)[i] = IPV4(ip->address)[i];
	}

	return value;
}

// Convert UINT to IP
void UINTToIP(IP *ip, UINT value)
{
	// Validate arguments
	if (ip == NULL)
	{
		return;
	}

	ZeroIP4(ip);

	for (BYTE i = 0; i < IPV4_SIZE; ++i)
	{
		IPV4(ip->address)[i] = ((BYTE *)&value)[i];
	}
}

void GetMachineNameEx(char *name, UINT size, bool no_load_hosts)
{
	static char name_cache[MAX_SIZE];
	static bool name_cached = false;
	char tmp[MAX_SIZE];
	char tmp2[MAX_SIZE];
	// Validate arguments
	if (name == NULL)
	{
		return;
	}

	Lock(machine_name_lock);
	{
		if (name_cached != false)
		{
			StrCpy(name, size, name_cache);
			Unlock(machine_name_lock);
			return;
		}
		ClearStr(tmp, sizeof(tmp));
		if (gethostname(tmp, MAX_SIZE) != 0)
		{
			StrCpy(name, size, "Unknown");
			Unlock(machine_name_lock);
			return;
		}
		ClearStr(name, size);
		StrCpy(name, size, tmp);
		if (IsEmptyStr(name) || StartWith(name, "localhost"))
		{
#ifdef	OS_WIN32
			ClearStr(name, size);
			MsGetComputerName(name, size);
#endif	// OS_WIN32
		}
		if (IsEmptyStr(name) || StartWith(name, "localhost"))
		{
			if (no_load_hosts == false && OS_IS_UNIX(GetOsInfo()->OsType))
			{
				if (GetMachineNameFromHosts(tmp2, sizeof(tmp2)))
				{
					StrCpy(name, size, tmp2);
				}
			}
		}

		StrCpy(name_cache, sizeof(name_cache), name);
		name_cached = true;
	}
	Unlock(machine_name_lock);
}

// Set the IP address
void SetIP(IP *ip, UCHAR a1, UCHAR a2, UCHAR a3, UCHAR a4)
{
	// Validate arguments
	if (ip == NULL)
	{
		return;
	}

	ZeroIP4(ip);

	ip->address[12] = a1;
	ip->address[13] = a2;
	ip->address[14] = a3;
	ip->address[15] = a4;
}

// Convert the IP to a string (32bit UINT)
void IPToStr32(char *str, UINT size, UINT ip)
{
	IP ip_st;
	// Validate arguments
	if (str == NULL)
	{
		return;
	}

	UINTToIP(&ip_st, ip);
	IPToStr(str, size, &ip_st);
}

// Convert IPv4 or IPv6 to a string
void IPToStr4or6(char *str, UINT size, UINT ip_4_uint, UCHAR *ip_6_bytes)
{
	IP ip4;
	IP ip6;
	IP ip;
	// Validate arguments
	if (str == NULL)
	{
		return;
	}

	Zero(&ip, sizeof(ip));

	UINTToIP(&ip4, ip_4_uint);
	SetIP6(&ip6, ip_6_bytes);

	if (IsIP6(&ip4) || (IsZeroIp(&ip4) && (IsZeroIp(&ip6) == false)))
	{
		Copy(&ip, &ip6, sizeof(IP));
	}
	else
	{
		Copy(&ip, &ip4, sizeof(IP));
	}

	IPToStr(str, size, &ip);
}

// Convert the IP to a string
void IPToStr(char *str, UINT size, IP *ip)
{
	// Validate arguments
	if (str == NULL || ip == NULL)
	{
		return;
	}

	if (IsIP6(ip))
	{
		IPToStr6(str, size, ip);
	}
	else
	{
		const BYTE *ipv4 = IPV4(ip->address);
		Format(str, size, "%hhu.%hhu.%hhu.%hhu", ipv4[0], ipv4[1], ipv4[2], ipv4[3]);
	}
}

// Convert the string to an IP
bool StrToIP(IP *ip, char *str)
{
	TOKEN_LIST *token;
	char *tmp;
	// Validate arguments
	if (ip == NULL || str == NULL)
	{
		return false;
	}

	if (StrToIP6(ip, str))
	{
		return true;
	}

	ZeroIP4(ip);

	tmp = CopyStr(str);
	Trim(tmp);
	token = ParseToken(tmp, ".");
	Free(tmp);

	if (token->NumTokens != 4)
	{
		FreeToken(token);
		return false;
	}
	for (BYTE i = 0; i < IPV4_SIZE; ++i)
	{
		char *s = token->Token[i];
		if (s[0] < '0' || s[0] > '9' ||
		        (ToInt(s) >= 256))
		{
			FreeToken(token);
			return false;
		}
	}

	for (BYTE i = 0; i < IPV4_SIZE; ++i)
	{
		IPV4(ip->address)[i] = (BYTE)ToInt(token->Token[i]);
	}

	FreeToken(token);

	return true;
}

// Convert the IP to the in_addr
void IPToInAddr(struct in_addr *addr, IP *ip)
{
	UINT i;
	// Validate arguments
	if (addr == NULL || IsIP4(ip) == false)
	{
		return;
	}

	Zero(addr, sizeof(struct in_addr));

	const BYTE *ipv4 = IPV4(ip->address);
	for (i = 0; i < IPV4_SIZE; ++i)
	{
		((BYTE *)addr)[i] = ipv4[i];
	}
}

// Convert the IP to the in6_addr
void IPToInAddr6(struct in6_addr *addr, IP *ip)
{
	// Validate arguments
	if (addr == NULL || ip == NULL)
	{
		return;
	}

	Zero(addr, sizeof(struct in6_addr));

	for (BYTE i = 0; i < sizeof(ip->address); ++i)
	{
		((BYTE *)addr)[i] = ip->address[i];
	}
}

// Convert the in_addr to the IP
void InAddrToIP(IP *ip, struct in_addr *addr)
{
	if (ip == NULL || addr == NULL)
	{
		return;
	}

	ZeroIP4(ip);

	BYTE *ipv4 = IPV4(ip->address);

	for (BYTE i = 0; i < IPV4_SIZE; ++i)
	{
		ipv4[i] = ((UCHAR *)addr)[i];
	}
}

// Convert the in6_addr to the IP
void InAddrToIP6(IP *ip, struct in6_addr *addr)
{
	// Validate arguments
	if (ip == NULL || addr == NULL)
	{
		return;
	}

	Zero(ip, sizeof(IP));

	for (BYTE i = 0; i < sizeof(ip->address); ++i)
	{
		ip->address[i] = ((UCHAR *)addr)[i];
	}
}

// DH temp key callback
DH *TmpDhCallback(SSL *ssl, int is_export, int keylength)
{
	DH *ret = NULL;

	if (dh_param != NULL)
	{
		ret = dh_param->dh;
	}

	return ret;
}

// Log SSL keys
void keylog_cb_func(const SSL* ssl, const char* line)
{
	Debug("SSL_KEYLOG_BEGIN\n");
	Debug(line);
	Debug("\nSSL_KEYLOG_END\n");
}

// Create the SSL_CTX
struct ssl_ctx_st *NewSSLCtx(bool server_mode)
{
	struct ssl_ctx_st *ctx = SSL_CTX_new(SSLv23_method());
	if(ctx == NULL)
	{
		return NULL;
	}
	// It resets some parameters.
	if (server_mode)
	{
		SSL_CTX_set_ssl_version(ctx, SSLv23_server_method());
	}
	else
	{
		SSL_CTX_set_ssl_version(ctx, SSLv23_client_method());
	}

#ifdef	SSL_OP_NO_SSLv3
	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv3);
#endif	// SSL_OP_NO_SSLv3

#ifdef	SSL_OP_NO_TICKET
	SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);
#endif	// SSL_OP_NO_TICKET

#ifdef	SSL_OP_CIPHER_SERVER_PREFERENCE
	if (server_mode)
	{
		SSL_CTX_set_options(ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);
	}
#endif	// SSL_OP_CIPHER_SERVER_PREFERENCE

	SSL_CTX_set_tmp_dh_callback(ctx, TmpDhCallback);

#ifdef	SSL_CTX_set_ecdh_auto
	SSL_CTX_set_ecdh_auto(ctx, 1);
#endif	// SSL_CTX_set_ecdh_auto

	SSL_CTX_set_keylog_callback(ctx, &keylog_cb_func);

	return ctx;
}

// Initialize the network communication module
void InitNetwork()
{
	disable_gethostname_by_accept = false;


	InitDynList();


	host_ip_address_list_cache_lock = NewLock();
	host_ip_address_list_cache_last = 0;

	num_tcp_connections = NewCounter();

	// Initialization of client list
	InitIpClientList();

	// Thread related initialization
	InitWaitThread();

#ifdef	OS_WIN32
	// Initializing the socket library
	Win32InitSocketLibrary();
#endif	// OS_WIN32

	DnsInit();

	// Locking initialization
	machine_name_lock = NewLock();
	disconnect_function_lock = NewLock();
	machine_ip_process_hash_lock = NewLock();
	local_mac_list_lock = NewLock();

	current_global_ip_lock = NewLock();
	current_global_ip_set = false;
}

// Get the TCP connections counter
COUNTER *GetNumTcpConnectionsCounter()
{
	return num_tcp_connections;
}

// Get the current global IP address
bool GetCurrentGlobalIP(IP *ip, bool ipv6)
{
	bool ret = false;
	// Validate arguments
	if (ip == NULL)
	{
		return false;
	}

	Zero(ip, sizeof(IP));

	Lock(current_global_ip_lock);
	{
		if (ipv6 == false)
		{
			Copy(ip, &current_glocal_ipv4, sizeof(IP));
		}
		else
		{
			Copy(ip, &current_glocal_ipv6, sizeof(IP));
		}

		ret = current_global_ip_set;
	}
	Unlock(current_global_ip_lock);

	return ret;
}

// Check whether the specified IP address is assigned to the local host
bool IsIPMyHost(IP *ip)
{
	LIST *o;
	UINT i;
	bool ret = false;
	// Validate arguments
	if (ip == NULL)
	{
		return false;
	}

	if (IsZeroIp(ip))
	{
		return false;
	}

	// Search to check whether it matches to any of the IP of the local host
	o = GetHostIPAddressList();

	for (i = 0; i < LIST_NUM(o); i++)
	{
		IP *p = LIST_DATA(o, i);

		if (CmpIpAddr(p, ip) == 0)
		{
			// Matched
			ret = true;
			break;
		}
	}

	FreeHostIPAddressList(o);

	if (ret == false)
	{
		if (IsLocalHostIP(ip))
		{
			// localhost IP addresses
			ret = true;
		}
	}

	return ret;
}

// Check whether the specified IP address is a private IP address
bool IsIPPrivate(IP *ip)
{
	// Validate arguments
	if (IsIP4(ip) == false)
	{
		return false;
	}

	const BYTE *ipv4 = IPV4(ip->address);

	// RFC 1918 defines 10.0.0.0/8
	if (ipv4[0] == 10)
	{
		return true;
	}

	// RFC 1918 defines 172.16.0.0/12
	if (ipv4[0] == 172)
	{
		if (ipv4[1] >= 16 && ipv4[1] <= 31)
		{
			return true;
		}
	}

	// RFC 1918 defines 192.168.0.0/16
	if (ipv4[0] == 192 && ipv4[1] == 168)
	{
		return true;
	}

	// RFC 3927 defines 169.254.0.0/16
	if (ipv4[0] == 169 && ipv4[1] == 254)
	{
		return true;
	}

	// RFC 6598 defines 100.64.0.0/10
	if (ipv4[0] == 100)
	{
		if (ipv4[1] >= 64 && ipv4[1] <= 127)
		{
			return true;
		}
	}

	if (g_private_ip_list != NULL)
	{
		return IsOnPrivateIPFile(IPToUINT(ip));
	}

	return false;
}

// Read a private IP list file
void LoadPrivateIPFile()
{
	BUF *b = ReadDump(PRIVATE_IP_TXT_FILENAME);
	LIST *o;
	if (b == NULL)
	{
		return;
	}

	o = NewList(NULL);

	while (true)
	{
		char *line = CfgReadNextLine(b);
		if (line == NULL)
		{
			break;
		}

		Trim(line);

		if (IsEmptyStr(line) == false)
		{
			UINT ip = 0, mask = 0;

			if (ParseIpAndSubnetMask4(line, &ip, &mask))
			{
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
bool IsOnPrivateIPFile(UINT ip)
{
	bool ret = false;

	if (g_private_ip_list != NULL)
	{
		LIST *o = g_private_ip_list;
		UINT i;

		for (i = 0; i < LIST_NUM(o); i++)
		{
			PRIVATE_IP_SUBNET *p = LIST_DATA(o, i);

			if ((ip & p->Mask) == p->Ip2)
			{
				ret = true;
			}
		}
	}

	return ret;
}

// Free the private IP file
void FreePrivateIPFile()
{
	if (g_private_ip_list != NULL)
	{
		LIST *o = g_private_ip_list;
		UINT i;

		g_private_ip_list = NULL;

		for (i = 0; i < LIST_NUM(o); i++)
		{
			PRIVATE_IP_SUBNET *p = LIST_DATA(o, i);

			Free(p);
		}

		ReleaseList(o);
	}

	g_use_privateip_file = false;
}

// Record the current global IP address
void SetCurrentGlobalIP(IP *ip, bool ipv6)
{
	// Validate arguments
	if (ip == NULL)
	{
		return;
	}

	if (IsZeroIp(ip))
	{
		return;
	}

	Lock(current_global_ip_lock);
	{
		if (ipv6 == false)
		{
			Copy(&current_glocal_ipv4, ip, sizeof(IP));
		}
		else
		{
			Copy(&current_glocal_ipv6, ip, sizeof(IP));
		}

		current_global_ip_set = true;
	}
	Unlock(current_global_ip_lock);
}

// Release of the network communication module
void FreeNetwork()
{

	if (dh_param != NULL)
	{
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

#ifdef	OS_WIN32
	// Release of the socket library
	Win32FreeSocketLibrary();
#endif	// OS_WIN32

	DeleteCounter(num_tcp_connections);
	num_tcp_connections = NULL;

	// Release of client list
	FreeIpClientList();

	DeleteLock(current_global_ip_lock);
	current_global_ip_lock = NULL;

	// Release of the local MAC list
	if (local_mac_list != NULL)
	{
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
bool ParseIpAndSubnetMask46(char *src, IP *ip, IP *mask)
{
	// Validate arguments
	if (src == NULL || ip == NULL || mask == NULL)
	{
		return false;
	}

	if (ParseIpAndMask46(src, ip, mask) == false)
	{
		return false;
	}

	if (IsIP4(ip))
	{
		return IsSubnetMask4(mask);
	}
	else
	{
		return IsSubnetMask6(mask);
	}
}
bool ParseIpAndSubnetMask4(char *src, UINT *ip, UINT *mask)
{
	IP ip2, mask2;
	// Validate arguments
	if (src == NULL)
	{
		return false;
	}

	if (ParseIpAndSubnetMask46(src, &ip2, &mask2) == false)
	{
		return false;
	}

	if (IsIP4(&ip2) == false)
	{
		return false;
	}

	if (ip != NULL)
	{
		*ip = IPToUINT(&ip2);
	}

	if (mask != NULL)
	{
		*mask = IPToUINT(&mask2);
	}

	return true;
}


// Parse the IP address and the mask
bool ParseIpAndMask46(char *src, IP *ip, IP *mask)
{
	TOKEN_LIST *t;
	char *ipstr;
	char *subnetstr;
	bool ret = false;
	IP ip2;
	IP mask2;
	// Validate arguments
	if (src == NULL || ip == NULL || mask == NULL)
	{
		return false;
	}

	Zero(&ip2, sizeof(IP));
	Zero(&mask2, sizeof(IP));

	t = ParseToken(src, "/");
	if (t->NumTokens != 2)
	{
		FreeToken(t);
		return false;
	}

	ipstr = t->Token[0];
	subnetstr = t->Token[1];
	Trim(ipstr);
	Trim(subnetstr);

	if (StrToIP(&ip2, ipstr))
	{
		if (StrToIP(&mask2, subnetstr))
		{
			// Compare the kind of the mask part and the IP address part to confirm same
			if (IsIP6(&ip2) && IsIP6(&mask2))
			{
				// Both are IPv6
				ret = true;
				Copy(ip, &ip2, sizeof(IP));
				Copy(mask, &mask2, sizeof(IP));
			}
			else if (IsIP4(&ip2) && IsIP4(&mask2))
			{
				// Both are IPv4
				ret = true;
				Copy(ip, &ip2, sizeof(IP));
				Copy(mask, &mask2, sizeof(IP));
			}
		}
		else
		{
			if (IsNum(subnetstr))
			{
				UINT i = ToInt(subnetstr);
				// Mask part is a number
				if (IsIP6(&ip2) && i <= 128)
				{
					ret = true;
					Copy(ip, &ip2, sizeof(IP));
					IntToSubnetMask6(mask, i);
				}
				else if (i <= 32)
				{
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
bool ParseIpAndMask4(char *src, UINT *ip, UINT *mask)
{
	IP ip_ip, ip_mask;
	if (ParseIpAndMask46(src, &ip_ip, &ip_mask) == false)
	{
		return false;
	}

	if (IsIP4(&ip_ip) == false)
	{
		return false;
	}

	if (ip != NULL)
	{
		*ip = IPToUINT(&ip_ip);
	}

	if (mask != NULL)
	{
		*mask = IPToUINT(&ip_mask);
	}

	return true;
}
bool ParseIpAndMask6(char *src, IP *ip, IP *mask)
{
	if (ParseIpAndMask46(src, ip, mask) == false)
	{
		return false;
	}

	if (IsIP6(ip) == false)
	{
		return false;
	}

	return true;
}


// Convert the IPv4 / IPv6 mask to a string
void MaskToStr(char *str, UINT size, IP *mask)
{
	MaskToStrEx(str, size, mask, false);
}
void MaskToStrEx(char *str, UINT size, IP *mask, bool always_full_address)
{
	// Validate arguments
	if (str == NULL || mask == NULL)
	{
		return;
	}

	if (always_full_address == false && IsSubnetMask(mask))
	{
		ToStr(str, SubnetMaskToInt(mask));
	}
	else
	{
		IPToStr(str, size, mask);
	}
}
void MaskToStr32(char *str, UINT size, UINT mask)
{
	MaskToStr32Ex(str, size, mask, false);
}
void MaskToStr32Ex(char *str, UINT size, UINT mask, bool always_full_address)
{
	IP ip;

	UINTToIP(&ip, mask);

	MaskToStrEx(str, size, &ip, always_full_address);
}
void Mask6AddrToStrEx(char *str, UINT size, IPV6_ADDR *mask, bool always_full_address)
{
	IP ip;

	// Validate arguments
	if (str == NULL || mask == NULL)
	{
		StrCpy(str, size, "");
		return;
	}

	IPv6AddrToIP(&ip, mask);

	MaskToStrEx(str, size, &ip, always_full_address);
}
void Mask6AddrToStr(char *str, UINT size, IPV6_ADDR *mask)
{
	Mask6AddrToStrEx(str, size, mask, false);
}

// Release of the IP address list of the host
void FreeHostIPAddressList(LIST *o)
{
	UINT i;
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	for (i = 0; i < LIST_NUM(o); i++)
	{
		IP *ip = LIST_DATA(o, i);

		Free(ip);
	}

	ReleaseList(o);
}

// Add the IP address to the list
void AddHostIPAddressToList(LIST *o, IP *ip)
{
	IP *r = NULL;
	// Validate arguments
	if (o == NULL || ip == NULL)
	{
		return;
	}

	if (o->cmp != NULL)
	{
		r = Search(o, ip);
	}
	else
	{
		UINT i;
		for (i = 0; i < LIST_NUM(o); i++)
		{
			IP *a = LIST_DATA(o, i);

			if (CmpIpAddr(ip, a) == 0)
			{
				r = ip;
				break;
			}
		}
	}

	if (r != NULL)
	{
		return;
	}

	Insert(o, Clone(ip, sizeof(IP)));
}

// Comparison of the IP address list items
int CmpIpAddressList(void *p1, void *p2)
{
	IP *ip1, *ip2;
	UINT r;
	// Validate arguments
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	ip1 = *(IP **)p1;
	ip2 = *(IP **)p2;
	if (ip1 == NULL || ip2 == NULL)
	{
		return 0;
	}

	// IPv4 < IPv6
	r = COMPARE_RET(IsIP6(ip1), IsIP6(ip2));
	if (r != 0)
	{
		return r;
	}

	// any > specified IP
	if (IsZeroIP(ip1) && IsZeroIP(ip2) == false)
	{
		return 1;
	}
	if (IsZeroIP(ip1) == false && IsZeroIP(ip2))
	{
		return -1;
	}

	// local > others
	if (IsLocalHostIP(ip1) && IsLocalHostIP(ip2) == false)
	{
		return 1;
	}
	if (IsLocalHostIP(ip1) == false && IsLocalHostIP(ip2))
	{
		return -1;
	}

	// ip address
	r = CmpIpAddr(ip1, ip2);
	if (r != 0)
	{
		return r;
	}

	// interface index
	if (IsIP6(ip1))
	{
		r = COMPARE_RET(ip1->ipv6_scope_id, ip2->ipv6_scope_id);
	}
	else
	{
		r = 0;
	}

	return r;
}

// Get the IP address list hash of the host
UINT64 GetHostIPAddressListHash()
{
	UINT i;
	LIST *o;
	BUF *buf = NewBuf();
	UCHAR hash[SHA1_SIZE];
	UINT64 ret = 0;

	o = GetHostIPAddressList();

	if (o != NULL)
	{
		for (i = 0; i < LIST_NUM(o); i++)
		{
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
LIST *GetHostIPAddressList()
{
	LIST *o = NULL;
	if (host_ip_address_list_cache_lock == NULL)
	{
		return GetHostIPAddressListInternal();
	}

	Lock(host_ip_address_list_cache_lock);
	{
		UINT64 now = Tick64();

		if (host_ip_address_list_cache_last == 0 ||
		        ((host_ip_address_list_cache_last + (UINT64)HOST_IP_ADDRESS_LIST_CACHE) < now) ||
		        host_ip_address_cache == NULL)
		{
			if (host_ip_address_cache != NULL)
			{
				FreeHostIPAddressList(host_ip_address_cache);
			}

			host_ip_address_cache = GetHostIPAddressListInternal();

			host_ip_address_list_cache_last = now;
		}

		o = CloneIPAddressList(host_ip_address_cache);
	}
	Unlock(host_ip_address_list_cache_lock);

	if (o == NULL)
	{
		o = GetHostIPAddressListInternal();
	}

	return o;
}

// Copy of the IP address list
LIST *CloneIPAddressList(LIST *o)
{
	LIST *ret;
	UINT i;
	// Validate arguments
	if (o == NULL)
	{
		return NULL;
	}

	ret = NewListFast(o->cmp);

	for (i = 0; i < LIST_NUM(o); i++)
	{
		IP *ip = LIST_DATA(o, i);

		if (ip != NULL)
		{
			ip = Clone(ip, sizeof(IP));

			Add(ret, ip);
		}
	}

	return ret;
}

// Get an IP address list of the host
LIST *GetHostIPAddressListInternal()
{
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
	if (is_v6_supported)
	{
		AddHostIPAddressToList(o, &any6);
	}

	// localhost
	AddHostIPAddressToList(o, &local4);
	if (is_v6_supported)
	{
		AddHostIPAddressToList(o, &local6);
	}

	// IPv4
	if (true)
	{
		struct sockaddr_in in;
		struct in_addr addr;
		struct addrinfo hint;
		struct addrinfo *info;

		Zero(&hint, sizeof(hint));
		hint.ai_family = AF_INET;
		hint.ai_socktype = SOCK_DGRAM;
		hint.ai_protocol = IPPROTO_UDP;
		info = NULL;

		if (getaddrinfo(hostname, NULL, &hint, &info) == 0)
		{
			if (info->ai_family == AF_INET)
			{
				struct addrinfo *current = info;
				while (current != NULL)
				{
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
	if (is_v6_supported)
	{
		struct sockaddr_in6 in;
		struct in6_addr addr;
		struct addrinfo hint;
		struct addrinfo *info;

		Zero(&hint, sizeof(hint));
		hint.ai_family = AF_INET6;
		hint.ai_socktype = SOCK_DGRAM;
		hint.ai_protocol = IPPROTO_UDP;
		info = NULL;

		if (getaddrinfo(hostname, NULL, &hint, &info) == 0)
		{
			if (info->ai_family == AF_INET6)
			{
				struct addrinfo *current = info;
				while (current != NULL)
				{
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
PACK *PackError(UINT error)
{
	PACK *p;

	p = NewPack();
	PackAddInt(p, "error", error);

	return p;
}

// Get the error value from PACK
UINT GetErrorFromPack(PACK *p)
{
	// Validate arguments
	if (p == NULL)
	{
		return 0;
	}

	return PackGetInt(p, "error");
}

// Create an entry to PACK for the dummy
void CreateDummyValue(PACK *p)
{
	UINT size;
	UCHAR *buf;
	// Validate arguments
	if (p == NULL)
	{
		return;
	}

	size = Rand32() % HTTP_PACK_RAND_SIZE_MAX;
	buf = Malloc(size);
	Rand(buf, size);

	PackAddData(p, "pencore", buf, size);

	Free(buf);
}

void SetDhParam(DH_CTX *dh)
{
	if (dh_param)
	{
		DhFree(dh_param);
	}

	dh_param = dh;
}
