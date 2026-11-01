// ServerCaps.c
// VPN Server capabilities: the caps list and its RPC marshalling, the server caps and the global server flags

#include "Server.h"

#include "Admin.h"
#include "BridgeWin32.h"
#include "Connection.h"
#include "RpcField.h"

#include "Mayaqua/Cfg.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Pack.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Table.h"

#include <stdlib.h>
#include "ServerInternal.h"

void GetServerCapsMain(SERVER *s, CAPSLIST *t) {
	if (s == NULL || t == NULL)
		return;

	InitCapsList(t);

	AddCapsInt(t, "i_max_packet_size", MAX_PACKET_SIZE);

	AddCapsInt(t, "i_max_hubs", SERVER_MAX_SESSIONS);

	AddCapsInt(t, "i_max_sessions", SERVER_MAX_SESSIONS);

	AddCapsInt(t, "i_max_user_creation", INFINITE);

	AddCapsInt(t, "i_max_clients", INFINITE);

	AddCapsInt(t, "i_max_bridges", INFINITE);

	AddCapsInt(t, "i_max_users_per_hub", MAX_USERS);

	AddCapsInt(t, "i_max_groups_per_hub", MAX_GROUPS);

	AddCapsInt(t, "i_max_access_lists", MAX_ACCESSLISTS);

	AddCapsBool(t, "b_support_limit_multilogin", true);

	AddCapsBool(t, "b_support_qos", true);

	AddCapsBool(t, "b_support_syslog", true);

	AddCapsInt(t, "i_max_mac_tables", MAX_MAC_TABLES);

	AddCapsInt(t, "i_max_ip_tables", MAX_IP_TABLES);

	AddCapsBool(t, "b_standalone", true);

	AddCapsBool(t, "b_support_config_hub", true);

	AddCapsBool(t, "b_vpn_client_connect", true);

	AddCapsBool(t, "b_local_bridge", IsBridgeSupported());

	// No TAP device on Windows; the cap is reported on every architecture so that admin clients
	// read the same caps set whether or not the local bridge is supported (b_local_bridge above
	// already reports bridge support, which is x64 only)
	AddCapsBool(t, "b_tap_supported", false);

	AddCapsBool(t, "b_support_cascade", true);

	AddCapsBool(t, "b_support_cascade_cert", true);

	AddCapsBool(t, "b_support_config_log", true);

	AddCapsBool(t, "b_support_autodelete", true);

	AddCapsBool(t, "b_support_config_rw", true);

	AddCapsBool(t, "b_support_hub_admin_option", true);

	AddCapsBool(t, "b_support_cascade_client_cert", true);

	AddCapsBool(t, "b_support_hide_hub", true);

	AddCapsBool(t, "b_is_softether", true);

	AddCapsBool(t, "b_support_crl", true);

	AddCapsBool(t, "b_support_ac", true);

	AddCapsBool(t, "b_support_read_log", true);

	AddCapsBool(t, "b_support_rename_cascade", true);

	AddCapsBool(t, "b_is_in_vm", s->IsInVm);

	// Reported on every architecture, with its value tracking bridge support, so the caps set is
	// the same on x64 and arm64 (the live harness golden is one shared file)
	AddCapsBool(t, "b_support_network_connection_name", IsBridgeSupported());

	AddCapsBool(t, "b_support_check_mac", true);

	AddCapsBool(t, "b_support_check_tcp_state", true);

	AddCapsBool(t, "b_support_vlan", true);

	AddCapsBool(t, "b_support_hub_ext_options", true);

	AddCapsBool(t, "b_support_policy_ver_3", true);

	AddCapsBool(t, "b_support_ipv6_acl", true);

	AddCapsBool(t, "b_support_ex_acl", true);

	AddCapsBool(t, "b_support_redirect_url_acl", true);

	AddCapsBool(t, "b_support_acl_group", true);

	AddCapsBool(t, "b_support_ipv6_ac", true);

	AddCapsBool(t, "b_support_udp_acceleration", true);

	AddCapsBool(t, "b_support_aes_ni", IsAesNiSupported());

	AddCapsBool(t, "b_using_selow_driver", Win32IsUsingSeLow());

	AddCapsBool(t, "b_vpn3", true);

	AddCapsBool(t, "b_vpn4", true);
}

void InitCapsList(CAPSLIST *t) {
	if (t == NULL)
		return;

	Zero(t, sizeof(CAPSLIST));
	t->CapsList = NewListFast(NULL);
}
void InRpcCapsList(CAPSLIST *t, PACK *p) {
	if (t == NULL || p == NULL)
		return;

	Zero(t, sizeof(CAPSLIST));
	t->CapsList = NewListFast(CompareCaps);

	for (UINT i = 0; i < LIST_NUM(p->elements); i++) {
		ELEMENT *e = LIST_DATA(p->elements, i);

		if (StartWith(e->name, "caps_") && e->type == VALUE_INT && e->num_value == 1) {
			CAPS *c = NewCaps(e->name + 5, e->values[0]->IntValue);
			Insert(t->CapsList, c);
		}
	}
}
void OutRpcCapsList(PACK *p, CAPSLIST *t) {
	if (t == NULL || p == NULL)
		return;

	for (UINT i = 0; i < LIST_NUM(t->CapsList); i++) {
		char tmp[MAX_SIZE];
		char ct_key[MAX_PATH];
		wchar_t ct_description[MAX_PATH];
		CAPS *c = LIST_DATA(t->CapsList, i);

		Format(tmp, sizeof(tmp), "caps_%s", c->Name);

		Format(ct_key, sizeof(ct_key), "CT_%s", c->Name);

		Zero(ct_description, sizeof(ct_description));
		wchar_t *w = _UU(ct_key);
		if (UniIsEmptyStr(w) == false)
			UniStrCpy(ct_description, sizeof(ct_description), w);
		else
			StrToUni(ct_description, sizeof(ct_description), c->Name);

		PackAddInt(p, tmp, c->Value);

		PackAddStrEx(p, "CapsName", c->Name, i, LIST_NUM(t->CapsList));
		PackAddIntEx(p, "CapsValue", c->Value, i, LIST_NUM(t->CapsList));
		PackAddUniStrEx(p, "CapsDescrption", ct_description, i, LIST_NUM(t->CapsList));
	}
}
void FreeRpcCapsList(CAPSLIST *t) {
	if (t == NULL)
		return;

	for (UINT i = 0; i < LIST_NUM(t->CapsList); i++) {
		CAPS *c = LIST_DATA(t->CapsList, i);

		FreeCaps(c);
	}

	ReleaseList(t->CapsList);
}

void AddCapsBool(CAPSLIST *caps, char *name, bool b) {
	if (caps == NULL || name == NULL)
		return;

	CAPS *c = NewCaps(name, b == false ? 0 : 1);
	AddCaps(caps, c);
}

void AddCapsInt(CAPSLIST *caps, char *name, UINT i) {
	if (caps == NULL || name == NULL)
		return;

	CAPS *c = NewCaps(name, i);
	AddCaps(caps, c);
}

UINT GetCapsInt(CAPSLIST *caps, char *name) {
	if (caps == NULL || name == NULL)
		return 0;

	CAPS *c = GetCaps(caps, name);
	if (c == NULL)
		return 0;

	return c->Value;
}

bool GetCapsBool(CAPSLIST *caps, char *name) {
	if (caps == NULL || name == NULL)
		return false;

	CAPS *c = GetCaps(caps, name);
	if (c == NULL)
		return false;

	return c->Value == 0 ? false : true;
}

void FreeCapsList(CAPSLIST *caps) {
	if (caps == NULL)
		return;

	for (UINT i = 0; i < LIST_NUM(caps->CapsList); i++) {
		CAPS *c = LIST_DATA(caps->CapsList, i);

		FreeCaps(c);
	}

	ReleaseList(caps->CapsList);
	Free(caps);
}

CAPS *GetCaps(CAPSLIST *caps, char *name) {
	if (caps == NULL || name == NULL)
		return NULL;

	for (UINT i = 0; i < LIST_NUM(caps->CapsList); i++) {
		CAPS *c = LIST_DATA(caps->CapsList, i);

		if (StrCmpi(c->Name, name) == 0)
			return c;
	}

	return NULL;
}

void AddCaps(CAPSLIST *caps, CAPS *c) {
	if (caps == NULL || c == NULL)
		return;

	Insert(caps->CapsList, c);
}

int CompareCaps(void *p1, void *p2) {
	if (p1 == NULL || p2 == NULL)
		return 0;
	CAPS *c1 = *(CAPS **)p1;
	CAPS *c2 = *(CAPS **)p2;
	if (c1 == NULL || c2 == NULL)
		return 0;

	return StrCmpi(c1->Name, c2->Name);
}

CAPSLIST *NewCapsList() {
	CAPSLIST *caps = ZeroMalloc(sizeof(CAPSLIST));

	caps->CapsList = NewListFast(CompareCaps);

	return caps;
}

void FreeCaps(CAPS *c) {
	if (c == NULL)
		return;

	Free(c->Name);
	Free(c);
}

CAPS *NewCaps(char *name, UINT value) {
	if (name == NULL)
		return NULL;

	CAPS *c = ZeroMalloc(sizeof(CAPS));
	c->Name = CopyStr(name);
	c->Value = value;

	return c;
}
