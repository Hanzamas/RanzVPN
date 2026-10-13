// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// ServerCaps.c
// VPN Server capabilities: the caps list, the server caps cache and the global server flags

#include "Server.h"

#include "Admin.h"
#include "BridgeWin32.h"
#include "Connection.h"
#include "Link.h"
#include "Listener.h"
#include "Protocol.h"
#include "Sam.h"

#include "Mayaqua/Cfg.h"
#include "Mayaqua/DNS.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/OS.h"
#include "Mayaqua/Pack.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Table.h"
#include "Mayaqua/TcpIp.h"
#include "Mayaqua/Tick64.h"
#include "Mayaqua/Win32.h"
#include "ServerInternal.h"

static volatile UINT global_server_flags[NUM_GLOBAL_SERVER_FLAGS] = {0};

// Get the Caps of the server
UINT GetServerCapsInt(SERVER *s, char *name)
{
	CAPSLIST t;
	UINT ret;
	// Validate arguments
	if (s == NULL || name == NULL)
	{
		return 0;
	}


	Lock(s->CapsCacheLock);
	{
		Zero(&t, sizeof(t));
		GetServerCaps(s, &t);

		ret = GetCapsInt(&t, name);
	}
	Unlock(s->CapsCacheLock);

	return ret;
}

bool GetServerCapsBool(SERVER *s, char *name)
{
	return (GetServerCapsInt(s, name) == 0) ? false : true;
}

// Initialize the Caps cache of the server
void InitServerCapsCache(SERVER *s)
{
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	s->CapsCacheLock = NewLock();
	s->CapsListCache = NULL;
}

// Release the Caps cache of the server
void FreeServerCapsCache(SERVER *s)
{
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	if (s->CapsListCache != NULL)
	{
		FreeCapsList(s->CapsListCache);
		s->CapsListCache = NULL;
	}
	DeleteLock(s->CapsCacheLock);
}

// Dispose the Caps cache of the server
void DestroyServerCapsCache(SERVER *s)
{
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	Lock(s->CapsCacheLock);
	{
		if (s->CapsListCache != NULL)
		{
			FreeCapsList(s->CapsListCache);
			s->CapsListCache = NULL;
		}
	}
	Unlock(s->CapsCacheLock);
}

// Flush the Caps list for this server
void FlushServerCaps(SERVER *s)
{
	CAPSLIST t;
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	Lock(s->CapsCacheLock);
	{
		DestroyServerCapsCache(s);

		Zero(&t, sizeof(t));
		GetServerCaps(s, &t);
	}
	Unlock(s->CapsCacheLock);
}

// Get the Caps list for this server
void GetServerCaps(SERVER *s, CAPSLIST *t)
{
	// Validate arguments
	if (s == NULL || t == NULL)
	{
		return;
	}

	Lock(s->CapsCacheLock);
	{

		if (s->CapsListCache == NULL)
		{
			s->CapsListCache = ZeroMalloc(sizeof(CAPSLIST));
			GetServerCapsMain(s, s->CapsListCache);
		}

		Copy(t, s->CapsListCache, sizeof(CAPSLIST));
	}
	Unlock(s->CapsCacheLock);
}

// Update the global server flags
void UpdateGlobalServerFlags(SERVER *s, CAPSLIST *t)
{
	bool is_restricted = false;
	// Validate arguments
	if (s == NULL || t == NULL)
	{
		return;
	}

	is_restricted = SiIsEnterpriseFunctionsRestrictedOnOpenSource(s->Cedar);

	SetGlobalServerFlag(GSF_DISABLE_RADIUS_AUTH, is_restricted);
	SetGlobalServerFlag(GSF_DISABLE_CERT_AUTH, is_restricted);
	SetGlobalServerFlag(GSF_DISABLE_DEEP_LOGGING, is_restricted);
	SetGlobalServerFlag(GSF_DISABLE_AC, is_restricted);
	SetGlobalServerFlag(GSF_DISABLE_SYSLOG, is_restricted);
}

// Set a global server flag
void SetGlobalServerFlag(UINT index, UINT value)
{
	// Validate arguments
	if (index >= NUM_GLOBAL_SERVER_FLAGS)
	{
		return;
	}

	global_server_flags[index] = value;
}

// Get a global server flag
UINT GetGlobalServerFlag(UINT index)
{
	// Validate arguments
	if (index >= NUM_GLOBAL_SERVER_FLAGS)
	{
		return 0;
	}

	return global_server_flags[index];
}

// Main of the acquisition of Caps of the server
void GetServerCapsMain(SERVER *s, CAPSLIST *t)
{
	// Validate arguments
	if (s == NULL || t == NULL)
	{
		return;
	}

	// Initialize
	InitCapsList(t);

	// Maximum Ethernet packet size
	AddCapsInt(t, "i_max_packet_size", MAX_PACKET_SIZE);

	if (s->Cedar->Bridge == false)
	{
		UINT max_sessions, max_clients, max_bridges, max_user_creations;

		max_clients = INFINITE;
		max_bridges = INFINITE;
		max_sessions = SERVER_MAX_SESSIONS_FOR_CARRIER_EDITION;
		max_user_creations = INFINITE;

		// Maximum number of virtual HUBs
		AddCapsInt(t, "i_max_hubs", SERVER_MAX_SESSIONS_FOR_CARRIER_EDITION);

		// The maximum number of concurrent sessions
		AddCapsInt(t, "i_max_sessions", max_sessions);

		// Maximum number of creatable users
		AddCapsInt(t, "i_max_user_creation", max_user_creations);

		// Maximum number of clients
		AddCapsInt(t, "i_max_clients", max_clients);

		// Maximum number of bridges
		AddCapsInt(t, "i_max_bridges", max_bridges);

		// Maximum number of registrable users / Virtual HUB
		AddCapsInt(t, "i_max_users_per_hub", MAX_USERS);

		// Maximum number of registrable groups / Virtual HUB
		AddCapsInt(t, "i_max_groups_per_hub", MAX_GROUPS);

		// Maximum number of registrable access list entries / Virtual HUB
		AddCapsInt(t, "i_max_access_lists", MAX_ACCESSLISTS);

		// The policy related to multiple logins
		AddCapsBool(t, "b_support_limit_multilogin", true);

		// QoS / VoIP
		AddCapsBool(t, "b_support_qos", true);

		// syslog
		AddCapsBool(t, "b_support_syslog", true);
	}
	else
	{
		// Maximum number of virtual HUBs
		AddCapsInt(t, "i_max_hubs", 0);

		// The maximum number of concurrent sessions
		AddCapsInt(t, "i_max_sessions", 0);

		// Maximum number of clients
		AddCapsInt(t, "i_max_clients", 0);

		// Maximum number of bridges
		AddCapsInt(t, "i_max_bridges", 0);

		// Maximum number of registrable users / Virtual HUB
		AddCapsInt(t, "i_max_users_per_hub", 0);

		// Maximum number of registrable groups / Virtual HUB
		AddCapsInt(t, "i_max_groups_per_hub", 0);

		// Maximum number of registrable access list entries / Virtual HUB
		AddCapsInt(t, "i_max_access_lists", 0);

		// QoS / VoIP
		AddCapsBool(t, "b_support_qos", true);

		// syslog
		AddCapsBool(t, "b_support_syslog", true);
	}

	// Maximum MAC address table  size / Virtual HUB
	AddCapsInt(t, "i_max_mac_tables", MAX_MAC_TABLES);

	// Maximum IP address table  size / Virtual HUB
	AddCapsInt(t, "i_max_ip_tables", MAX_IP_TABLES);

	// Cascade connection
	AddCapsBool(t, "b_support_cascade", true);

	if (s->Cedar->Bridge)
	{
		// Bridge mode
		AddCapsBool(t, "b_bridge", true);
	}
	else
	{
		// Stand-alone mode
		AddCapsBool(t, "b_standalone", true);
	}

	// Virtual HUB is modifiable
	AddCapsBool(t, "b_support_config_hub", s->Cedar->Bridge == false);

	// VPN client can be connected
	AddCapsBool(t, "b_vpn_client_connect", s->Cedar->Bridge == false ? true : false);

	// Local-bridge function is available
	AddCapsBool(t, "b_local_bridge", IsBridgeSupported());

	if (IsBridgeSupported())
	{
		// TUN / TAP device availability (Linux and BSD)
		const UINT OsType = GetOsInfo()->OsType;
		AddCapsBool(t, "b_tap_supported", OsType == OSTYPE_LINUX || OsType == OSTYPE_BSD);
	}

	// Cascade connection
	AddCapsBool(t, "b_support_cascade", true);

	// Server authentication can be used in cascade connection
	AddCapsBool(t, "b_support_cascade_cert", true);

	//  the log file settings is modifiable
	AddCapsBool(t, "b_support_config_log", true);

	// Automatic deletion of log file is available
	AddCapsBool(t, "b_support_autodelete", true);

	// Config file operation is available
	AddCapsBool(t, "b_support_config_rw", true);

	// Attribute of each Virtual HUB can be set
	AddCapsBool(t, "b_support_hub_admin_option", true);

	// Client certificate can be set in a cascade connection
	AddCapsBool(t, "b_support_cascade_client_cert", true);

	// Virtual HUB can be hidden
	AddCapsBool(t, "b_support_hide_hub", true);

	// Flag of open-source version
	AddCapsBool(t, "b_is_softether", true);

	if (s->Cedar->Bridge == false)
	{
		// Support for CRL
		AddCapsBool(t, "b_support_crl", true);

		// Supports AC
		AddCapsBool(t, "b_support_ac", true);
	}

	// Supports downloading a log file
	AddCapsBool(t, "b_support_read_log", true);

	// Cascade connection can be renamed
	AddCapsBool(t, "b_support_rename_cascade", true);


	if (s->Cedar->Beta)
	{
		// Beta version
		AddCapsBool(t, "b_beta_version", true);
	}

	// VM discrimination
	AddCapsBool(t, "b_is_in_vm", s->IsInVm);

	// Support for display name of the network connection for the local bridge
#ifdef	OS_WIN32
	if (IsBridgeSupported())
	{
		AddCapsBool(t, "b_support_network_connection_name", true);
	}
#endif	// OS_WIN32

	// Support for MAC address filtering
	AddCapsBool(t, "b_support_check_mac", true);

	// Support for status check of the TCP connection
	AddCapsBool(t, "b_support_check_tcp_state", true);

	// Can manage the ID of the tagged VLAN in the MAC address table
	AddCapsBool(t, "b_support_vlan", true);

	// Support for Virtual HUB extended options
	if (s->Cedar->Bridge == false)
	{
		AddCapsBool(t, "b_support_hub_ext_options", true);
	}
	else
	{
		AddCapsBool(t, "b_support_hub_ext_options", false);
	}

	// Support for Security Policy version 3.0
	AddCapsBool(t, "b_support_policy_ver_3", true);

	// Support for IPv6 access list
	AddCapsBool(t, "b_support_ipv6_acl", true);

	// Support for setting of delay, jitter and packet loss in the access list
	AddCapsBool(t, "b_support_ex_acl", true);

	// Support for URL redirection in the access list
	AddCapsBool(t, "b_support_redirect_url_acl", true);

	// Supports the specification by the group name in the access list
	AddCapsBool(t, "b_support_acl_group", true);

	// Support for IPv6 in connection source IP restriction list
	AddCapsBool(t, "b_support_ipv6_ac", true);

	// Support for VLAN tagged packet transmission configuration tool
	AddCapsBool(t, "b_support_eth_vlan", true);

	// Support for the message display function when the VPN connect to the Virtual HUB
	AddCapsBool(t, "b_support_msg", true);

	// UDP acceleration feature
	AddCapsBool(t, "b_support_udp_acceleration", true);

	// AES acceleration function
	AddCapsBool(t, "b_support_aes_ni", IsAesNiSupported());

#ifdef	OS_WIN32
	// SeLow driver
	AddCapsBool(t, "b_using_selow_driver", Win32IsUsingSeLow());
#endif	// OS_WIN32

	// VPN3
	AddCapsBool(t, "b_vpn3", true);

	// VPN4
	AddCapsBool(t, "b_vpn4", true);


	UpdateGlobalServerFlags(s, t);
}

// CAPSLIST
void InitCapsList(CAPSLIST *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	Zero(t, sizeof(CAPSLIST));
	t->CapsList = NewListFast(NULL);
}

void InRpcCapsList(CAPSLIST *t, PACK *p)
{
	UINT i;
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(CAPSLIST));
	t->CapsList = NewListFast(CompareCaps);

	for (i = 0;i < LIST_NUM(p->elements);i++)
	{
		ELEMENT *e = LIST_DATA(p->elements, i);

		if (StartWith(e->name, "caps_") && e->type == VALUE_INT && e->num_value == 1)
		{
			CAPS *c = NewCaps(e->name + 5, e->values[0]->IntValue);
			Insert(t->CapsList, c);
		}
	}
}

void OutRpcCapsList(PACK *p, CAPSLIST *t)
{
	UINT i;
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(t->CapsList);i++)
	{
		char tmp[MAX_SIZE];
		char ct_key[MAX_PATH];
		wchar_t ct_description[MAX_PATH];
		wchar_t *w;
		CAPS *c = LIST_DATA(t->CapsList, i);

		Format(tmp, sizeof(tmp), "caps_%s", c->Name);

		Format(ct_key, sizeof(ct_key), "CT_%s", c->Name);

		Zero(ct_description, sizeof(ct_description));
		w = _UU(ct_key);
		if (UniIsEmptyStr(w) == false)
		{
			UniStrCpy(ct_description, sizeof(ct_description), w);
		}
		else
		{
			StrToUni(ct_description, sizeof(ct_description), c->Name);
		}

		PackAddInt(p, tmp, c->Value);

		PackAddStrEx(p, "CapsName", c->Name, i, LIST_NUM(t->CapsList));
		PackAddIntEx(p, "CapsValue", c->Value, i, LIST_NUM(t->CapsList));
		PackAddUniStrEx(p, "CapsDescrption", ct_description, i, LIST_NUM(t->CapsList));
	}
}

void FreeRpcCapsList(CAPSLIST *t)
{
	UINT i;
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(t->CapsList);i++)
	{
		CAPS *c = LIST_DATA(t->CapsList, i);

		FreeCaps(c);
	}

	ReleaseList(t->CapsList);
}

// Add a bool type to Caps list
void AddCapsBool(CAPSLIST *caps, char *name, bool b)
{
	CAPS *c;
	// Validate arguments
	if (caps == NULL || name == NULL)
	{
		return;
	}

	c = NewCaps(name, b == false ? 0 : 1);
	AddCaps(caps, c);
}

// Add the int type to Caps list
void AddCapsInt(CAPSLIST *caps, char *name, UINT i)
{
	CAPS *c;
	// Validate arguments
	if (caps == NULL || name == NULL)
	{
		return;
	}

	c = NewCaps(name, i);
	AddCaps(caps, c);
}

// Get the int type from the Caps list
UINT GetCapsInt(CAPSLIST *caps, char *name)
{
	CAPS *c;
	// Validate arguments
	if (caps == NULL || name == NULL)
	{
		return 0;
	}

	c = GetCaps(caps, name);
	if (c == NULL)
	{
		return 0;
	}

	return c->Value;
}

// Get bool type from the Caps list
bool GetCapsBool(CAPSLIST *caps, char *name)
{
	CAPS *c;
	// Validate arguments
	if (caps == NULL || name == NULL)
	{
		return false;
	}

	c = GetCaps(caps, name);
	if (c == NULL)
	{
		return false;
	}

	return c->Value == 0 ? false : true;
}

// Release the Caps list
void FreeCapsList(CAPSLIST *caps)
{
	UINT i;
	// Validate arguments
	if (caps == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(caps->CapsList);i++)
	{
		CAPS *c = LIST_DATA(caps->CapsList, i);

		FreeCaps(c);
	}

	ReleaseList(caps->CapsList);
	Free(caps);
}

// Get the Caps
CAPS *GetCaps(CAPSLIST *caps, char *name)
{
	UINT i;
	// Validate arguments
	if (caps == NULL || name == NULL)
	{
		return NULL;
	}

	for (i = 0;i < LIST_NUM(caps->CapsList);i++)
	{
		CAPS *c = LIST_DATA(caps->CapsList, i);

		if (StrCmpi(c->Name, name) == 0)
		{
			return c;
		}
	}

	return NULL;
}

// Add to the Caps
void AddCaps(CAPSLIST *caps, CAPS *c)
{
	// Validate arguments
	if (caps == NULL || c == NULL)
	{
		return;
	}

	Insert(caps->CapsList, c);
}

// Comparison of Caps
int CompareCaps(void *p1, void *p2)
{
	CAPS *c1, *c2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	c1 = *(CAPS **)p1;
	c2 = *(CAPS **)p2;
	if (c1 == NULL || c2 == NULL)
	{
		return 0;
	}

	return StrCmpi(c1->Name, c2->Name);
}

// Create a Caps list
CAPSLIST *NewCapsList()
{
	CAPSLIST *caps = ZeroMalloc(sizeof(CAPSLIST));

	caps->CapsList = NewListFast(CompareCaps);

	return caps;
}

// Release the Caps
void FreeCaps(CAPS *c)
{
	// Validate arguments
	if (c == NULL)
	{
		return;
	}

	Free(c->Name);
	Free(c);
}

// Create a Caps
CAPS *NewCaps(char *name, UINT value)
{
	CAPS *c;
	// Validate arguments
	if (name == NULL)
	{
		return NULL;
	}

	c = ZeroMalloc(sizeof(CAPS));
	c->Name = CopyStr(name);
	c->Value = value;

	return c;
}
