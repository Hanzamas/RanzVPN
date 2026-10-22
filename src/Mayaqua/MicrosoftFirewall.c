// MicrosoftFirewall.c
// Windows Firewall: the inbound rule of a service program, which vpnserver /install adds and /uninstall deletes

// COBJMACROS: the INetFwPolicy2_*, INetFwRules_* and INetFwRule_* call macros of netfw.h (the COM
// interfaces are C structs here)
#define COBJMACROS

#include "Microsoft.h"

#include "Str.h"

#include <objbase.h>
#include <oleauto.h>
#include <netfw.h>
#include "MicrosoftInternal.h"

// The classes and interfaces of the firewall policy. netfw.h only declares their CLSID_ and IID_
// constants; this file defines its own copies, so it needs no library that defines them.
static const CLSID ms_clsid_net_fw_policy2 = {0xE2B3C97F, 0x6AE1, 0x41AC, {0x81, 0x7A, 0xF6, 0xF9, 0x21, 0x66, 0xD7, 0xDD}};
static const IID ms_iid_net_fw_policy2 = {0x98325047, 0xC671, 0x4174, {0x8D, 0x81, 0xDE, 0xFC, 0xD3, 0xF0, 0x31, 0x86}};
static const CLSID ms_clsid_net_fw_rule = {0x2C5BC43E, 0x3369, 0x4C33, {0xAB, 0x0C, 0xBE, 0x94, 0x69, 0x67, 0x7A, 0xF4}};
static const IID ms_iid_net_fw_rule = {0xAF230D27, 0xBABA, 0x4E42, {0xAC, 0xED, 0xF5, 0x24, 0xF2, 0x2C, 0xFC, 0xE2}};

// Most rules of one name that a delete removes, so that a collection that keeps reporting a rule
// cannot hold the call in a loop
#define MS_FIREWALL_DELETE_MAX 1000

// Report a failed step of the firewall rule calls and its HRESULT to the debug log
static void MsFirewallDebugHr(char *step, HRESULT hr) {
	Debug("Windows Firewall: %s failed, HRESULT 0x%X\n", step, (UINT)hr);
}

// Open the rule collection of the firewall policy (INetFwPolicy2::get_Rules), with COM initialized
// for the call: S_OK and S_FALSE both take a reference that MsFirewallClose returns through
// *com_initialized. RPC_E_CHANGED_MODE means the thread already runs in another apartment, which
// stays as it is. NULL on failure.
static INetFwRules *MsFirewallOpen(bool *com_initialized) {
	INetFwPolicy2 *policy;
	INetFwRules *rules = NULL;

	*com_initialized = false;

	HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
	if (SUCCEEDED(hr)) {
		*com_initialized = true;
	} else if (hr != RPC_E_CHANGED_MODE) {
		MsFirewallDebugHr("CoInitializeEx", hr);
		return NULL;
	}

	hr = CoCreateInstance(&ms_clsid_net_fw_policy2, NULL, CLSCTX_INPROC_SERVER, &ms_iid_net_fw_policy2, (void **)&policy);
	if (SUCCEEDED(hr)) {
		hr = INetFwPolicy2_get_Rules(policy, &rules);
		if (FAILED(hr)) {
			MsFirewallDebugHr("INetFwPolicy2::get_Rules", hr);
			rules = NULL;
		}

		INetFwPolicy2_Release(policy);
	} else {
		MsFirewallDebugHr("CoCreateInstance(NetFwPolicy2)", hr);
	}

	if (rules == NULL && *com_initialized) {
		CoUninitialize();
		*com_initialized = false;
	}

	return rules;
}

static void MsFirewallClose(INetFwRules *rules, bool com_initialized) {
	if (rules != NULL)
		INetFwRules_Release(rules);

	if (com_initialized)
		CoUninitialize();
}

// Delete every rule named name from the collection. INetFwRules::Remove deletes the rules of a name
// one by one and also succeeds when there is none, so the loop stops when INetFwRules::Item finds no
// rule of that name any more.
static bool MsFirewallRemoveAll(INetFwRules *rules, BSTR name) {
	for (UINT i = 0; i < MS_FIREWALL_DELETE_MAX; i++) {
		INetFwRule *rule = NULL;

		// Item fails when no rule has the name
		if (FAILED(INetFwRules_Item(rules, name, &rule)) || rule == NULL)
			return true;

		INetFwRule_Release(rule);

		HRESULT hr = INetFwRules_Remove(rules, name);
		if (FAILED(hr)) {
			MsFirewallDebugHr("INetFwRules::Remove", hr);
			return false;
		}
	}

	return false;
}

// Add the inbound allow rule name for the program exe to Windows Firewall, through its COM interface
// (INetFwPolicy2): all protocols and ports, enabled on all profiles. The rules of that name that are
// there already are deleted first, so exactly one rule of the name is left.
bool MsAddFirewallRule(wchar_t *name, wchar_t *exe) {
	bool ret = false;
	bool com_initialized;
	if (name == NULL || exe == NULL)
		return false;

	INetFwRules *rules = MsFirewallOpen(&com_initialized);
	if (rules == NULL)
		return false;

	BSTR name_b = SysAllocString(name);
	BSTR exe_b = SysAllocString(exe);

	if (name_b != NULL && exe_b != NULL && MsFirewallRemoveAll(rules, name_b)) {
		INetFwRule *rule;

		HRESULT hr = CoCreateInstance(&ms_clsid_net_fw_rule, NULL, CLSCTX_INPROC_SERVER, &ms_iid_net_fw_rule, (void **)&rule);
		if (SUCCEEDED(hr)) {
			hr = INetFwRule_put_Name(rule, name_b);
			if (SUCCEEDED(hr))
				hr = INetFwRule_put_Description(rule, name_b);
			if (SUCCEEDED(hr))
				hr = INetFwRule_put_ApplicationName(rule, exe_b);
			if (SUCCEEDED(hr))
				hr = INetFwRule_put_Protocol(rule, NET_FW_IP_PROTOCOL_ANY);
			if (SUCCEEDED(hr))
				hr = INetFwRule_put_Direction(rule, NET_FW_RULE_DIR_IN);
			if (SUCCEEDED(hr))
				hr = INetFwRule_put_Profiles(rule, NET_FW_PROFILE2_ALL);
			if (SUCCEEDED(hr))
				hr = INetFwRule_put_Action(rule, NET_FW_ACTION_ALLOW);
			if (SUCCEEDED(hr))
				hr = INetFwRule_put_Enabled(rule, VARIANT_TRUE);

			if (SUCCEEDED(hr)) {
				hr = INetFwRules_Add(rules, rule);
				if (SUCCEEDED(hr))
					ret = true;
				else
					MsFirewallDebugHr("INetFwRules::Add", hr);
			} else {
				MsFirewallDebugHr("INetFwRule::put_*", hr);
			}

			INetFwRule_Release(rule);
		} else {
			MsFirewallDebugHr("CoCreateInstance(NetFwRule)", hr);
		}
	}

	SysFreeString(exe_b);
	SysFreeString(name_b);

	MsFirewallClose(rules, com_initialized);

	return ret;
}

// Delete every rule named name from Windows Firewall; true also when there is none
bool MsDeleteFirewallRule(wchar_t *name) {
	bool ret = false;
	bool com_initialized;
	if (name == NULL)
		return false;

	INetFwRules *rules = MsFirewallOpen(&com_initialized);
	if (rules == NULL)
		return false;

	BSTR name_b = SysAllocString(name);
	if (name_b != NULL)
		ret = MsFirewallRemoveAll(rules, name_b);

	SysFreeString(name_b);

	MsFirewallClose(rules, com_initialized);

	return ret;
}
