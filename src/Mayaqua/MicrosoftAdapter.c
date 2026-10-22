// MicrosoftAdapter.c
// Windows network adapters and network configuration: adapter list, net-class table

#define MICROSOFT_C

#include "Microsoft.h"

#include "Cfg.h"
#include "FileIO.h"
#include "GlobalConst.h"
#include "Internat.h"
#include "Memory.h"
#include "Str.h"
#include "Win32.h"

#define SECURITY_WIN32

#define NO_SHLWAPI_STRFCNS
#define NO_SHLWAPI_REG
#define NO_SHLWAPI_STREAM
#define NO_SHLWAPI_HTTP
#define NO_SHLWAPI_ISOS
#define NO_SHLWAPI_GDI

#include <AclAPI.h>
#include <iphlpapi.h>
#include <mmsystem.h>
#include <nb30.h>
#include <sddl.h>
#include <security.h>
#include <SetupAPI.h>
#include <shellapi.h>
#include <ShlObj.h>
#include <Shlwapi.h> // PathGetArgsW() of MsCopyProcessArgsW
#include <SoftPub.h>

#if defined(_M_X64) || defined(_M_IX86)
#include <intrin.h> // __cpuid() of the VM detection
#endif              // defined(_M_X64) || defined(_M_IX86)
#include "MicrosoftInternal.h"

MS_ADAPTER *MsGetAdapterByGuidFromList(MS_ADAPTER_LIST *o, char *guid) {
	MS_ADAPTER *ret = NULL;
	if (o == NULL || guid == NULL)
		return NULL;

	for (UINT i = 0; i < o->Num; i++) {
		if (StrCmpi(o->Adapters[i]->Guid, guid) == 0) {
			ret = MsCloneAdapter(o->Adapters[i]);
			break;
		}
	}

	return ret;
}

// Whether an interface is a wired Ethernet LAN, the kind that the Local Bridge lists unless it
// shows every interface. Decided from the MIB_IF_ROW2 type data, not from words in the adapter
// title, which are localized and also appear in unrelated names: an Ethernet interface type on
// 802.3 media whose physical medium is 802.3, or is unspecified on a hardware NIC. Tunnels, PPP
// and dial-up, loopback and wireless interfaces are not, and neither are software interfaces
// that do not report their physical medium, such as the WAN Miniport interfaces of RAS
bool MsIsBridgeableIf(UINT type, UINT media_type, UINT physical_medium_type, bool hardware_interface) {
	if (type != IF_TYPE_ETHERNET_CSMACD || media_type != NdisMedium802_3)
		return false;

	if (physical_medium_type == NdisPhysicalMedium802_3)
		return true;

	return physical_medium_type == NdisPhysicalMediumUnspecified && hardware_interface;
}

MS_ADAPTER *MsCloneAdapter(MS_ADAPTER *a) {
	if (a == NULL)
		return NULL;

	MS_ADAPTER *ret = ZeroMalloc(sizeof(MS_ADAPTER));
	Copy(ret, a, sizeof(MS_ADAPTER));

	return ret;
}

MS_ADAPTER_LIST *MsCreateAdapterList() {
	PMIB_IF_TABLE2 table;

	UINT retcode = GetIfTable2(&table);
	if (retcode != NO_ERROR || table == NULL)
		return ZeroMalloc(sizeof(MS_ADAPTER_LIST));

	LIST *o = NewListFast(NULL);

	for (UINT i = 0; i < table->NumEntries; i++) {
		MIB_IF_ROW2 *r = &table->Table[i];
		wchar_t title[MAX_PATH];
		MS_ADAPTER *a;

		{
			{
				for (UINT j = 1;; j++) {
					if (j == 1)
						UniStrCpy(title, sizeof(title), r->Description);
					else
						UniFormat(title, sizeof(title), L"%s (%u)", r->Description, j);

					bool exists = false;

					for (UINT k = 0; k < LIST_NUM(o); k++) {
						MS_ADAPTER *a = LIST_DATA(o, k);

						if (UniStrCmpi(a->TitleW, title) == 0) {
							exists = true;
							break;
						}
					}

					if (exists == false)
						break;
				}

				a = ZeroMalloc(sizeof(MS_ADAPTER));

				UniStrCpy(a->TitleW, sizeof(a->TitleW), title);
				UniToStr(a->Title, sizeof(a->Title), title);
				a->Index = r->InterfaceIndex;
				a->MediaConnectState = r->MediaConnectState;
				a->Type = r->Type;
				a->AddressSize = MIN(sizeof(a->Address), r->PhysicalAddressLength);
				Copy(a->Address, r->PhysicalAddress, a->AddressSize);

				// Same "{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}" form as the SeLow and NDIS adapter
				// names; every interface gets one, with or without an IPv4 binding
				Format(a->Guid, sizeof(a->Guid), "{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
				       (UINT)r->InterfaceGuid.Data1, (UINT)r->InterfaceGuid.Data2, (UINT)r->InterfaceGuid.Data3,
				       (UINT)r->InterfaceGuid.Data4[0], (UINT)r->InterfaceGuid.Data4[1],
				       (UINT)r->InterfaceGuid.Data4[2], (UINT)r->InterfaceGuid.Data4[3],
				       (UINT)r->InterfaceGuid.Data4[4], (UINT)r->InterfaceGuid.Data4[5],
				       (UINT)r->InterfaceGuid.Data4[6], (UINT)r->InterfaceGuid.Data4[7]);

				a->IsBridgeable = MsIsBridgeableIf(r->Type, r->MediaType, r->PhysicalMediumType,
				                                   r->InterfaceAndOperStatusFlags.HardwareInterface);

				UniStrCpy(a->Alias, sizeof(a->Alias), r->Alias);

				Add(o, a);
			}
		}
	}

	MS_ADAPTER_LIST *ret = ZeroMalloc(sizeof(MS_ADAPTER_LIST));
	ret->Num = LIST_NUM(o);
	ret->Adapters = ToArray(o);

	ReleaseList(o);
	FreeMibTable(table);

	return ret;
}

void MsFreeAdapterList(MS_ADAPTER_LIST *o) {
	if (o == NULL)
		return;

	for (UINT i = 0; i < o->Num; i++)
		MsFreeAdapter(o->Adapters[i]);
	Free(o->Adapters);

	Free(o);
}

void MsFreeAdapter(MS_ADAPTER *a) {
	if (a == NULL)
		return;

	Free(a);
}

// GUID_DEVCLASS_NET of devguid.h: the setup class of the network adapters
static const GUID ms_netclass_guid = {0x4d36e972, 0xe325, 0x11ce, {0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18}};

static int MsNetClassCmp(void *p1, void *p2) {
	if (p1 == NULL || p2 == NULL)
		return 0;
	MS_NETCLASS_DEVICE *d1 = *(MS_NETCLASS_DEVICE **)p1;
	MS_NETCLASS_DEVICE *d2 = *(MS_NETCLASS_DEVICE **)p2;
	if (d1 == NULL || d2 == NULL)
		return 0;

	return StrCmpi(d1->Guid, d2->Guid);
}

// A string registry property of a SetupAPI device into dst; empty when the device has none
static void MsNetClassGetProperty(char *dst, UINT size, HDEVINFO h, SP_DEVINFO_DATA *d, DWORD property) {
	wchar_t tmp[MAX_SIZE];
	DWORD type = 0;

	ClearStr(dst, size);
	Zero(tmp, sizeof(tmp));

	if (SetupDiGetDeviceRegistryPropertyW(h, d, property, &type, (BYTE *)tmp, sizeof(tmp) - sizeof(wchar_t), NULL) &&
	    type == REG_SZ)
		UniToStr(dst, size, tmp);
}

// The present devices of the network adapter setup class in one SetupAPI pass, keyed by their
// NetCfgInstanceId (FND-174). Each entry has the Class key and short key of its driver and its device
// instance id. A device without a
// NetCfgInstanceId or a driver key is left out, and so are the class keys of devices that are not
// present (phantom devices). Free the table with MsNetClassFree
LIST *MsNetClassEnum() {
	LIST *o = NewList(MsNetClassCmp);
	HDEVINFO h;

	h = SetupDiGetClassDevsW(&ms_netclass_guid, NULL, NULL, DIGCF_PRESENT);
	if (h == INVALID_HANDLE_VALUE)
		return o;

	for (UINT i = 0;; i++) {
		SP_DEVINFO_DATA d;
		wchar_t tmp[MAX_SIZE];

		Zero(&d, sizeof(d));
		d.cbSize = sizeof(d);

		if (SetupDiEnumDeviceInfo(h, i, &d) == false)
			break;

		MS_NETCLASS_DEVICE *e = ZeroMalloc(sizeof(MS_NETCLASS_DEVICE));

		// NetCfgInstanceId of the driver key: the adapter GUID of NDIS, SeLow and IP Helper
		HKEY key = SetupDiOpenDevRegKey(h, &d, DICS_FLAG_GLOBAL, 0, DIREG_DRV, KEY_READ);
		if (key != INVALID_HANDLE_VALUE) {
			DWORD type = 0;
			DWORD size = sizeof(tmp) - sizeof(wchar_t);

			Zero(tmp, sizeof(tmp));
			if (RegQueryValueExW(key, L"NetCfgInstanceId", NULL, &type, (BYTE *)tmp, &size) == ERROR_SUCCESS &&
			    type == REG_SZ)
				UniToStr(e->Guid, sizeof(e->Guid), tmp);

			RegCloseKey(key);
		}

		// The driver key below the Class key, in capitals as the Class subkey enumeration spelled it
		MsNetClassGetProperty(e->ShortKey, sizeof(e->ShortKey), h, &d, SPDRP_DRIVER);
		StrUpper(e->ShortKey);

		if (IsEmptyStr(e->Guid) || IsEmptyStr(e->ShortKey)) {
			Free(e);
			continue;
		}

		Format(e->ClassKey, sizeof(e->ClassKey), "SYSTEM\\CurrentControlSet\\Control\\Class\\%s", e->ShortKey);

		Zero(tmp, sizeof(tmp));
		if (SetupDiGetDeviceInstanceIdW(h, &d, tmp, MAX_SIZE - 1, NULL))
			UniToStr(e->DeviceInstanceId, sizeof(e->DeviceInstanceId), tmp);

		Insert(o, e);
	}

	SetupDiDestroyDeviceInfoList(h);

	return o;
}

// The device of the network adapter GUID guid in the table of MsNetClassEnum, or NULL
MS_NETCLASS_DEVICE *MsNetClassFind(LIST *o, char *guid) {
	MS_NETCLASS_DEVICE t;
	if (o == NULL || guid == NULL)
		return NULL;

	Zero(&t, sizeof(t));
	StrCpy(t.Guid, sizeof(t.Guid), guid);

	return Search(o, &t);
}

void MsNetClassFree(LIST *o) {
	if (o == NULL)
		return;

	for (UINT i = 0; i < LIST_NUM(o); i++)
		Free(LIST_DATA(o, i));

	ReleaseList(o);
}
