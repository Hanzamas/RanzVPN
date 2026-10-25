// NodeKmTest.c
// The KM-TEST adapters of a node (NodeL2.h; CORE-S3-2, #72): the inbox Microsoft KM-TEST Loopback Adapter of
// %windir%\inf\netloop.inf (hardware id *MSLOOP), the L2 adapter of ADR-0018 decision 4, one per Network. Every
// adapter of that driver has the MAC address 02-00-4C-4F-4F-50 unless its NetworkAddress is set, so the node sets the
// address that NodeL2Mac derives from its static key and the Network id, and finds the adapter again by that address at
// its next start. A new adapter is created as devcon install does it, through SetupAPI: a root-enumerated device of
// *MSLOOP, registered, and the driver of netloop.inf installed for the devices of *MSLOOP that have none, so the other
// adapters of the node keep running. The MAC address takes effect when the device restarts (DIF_PROPERTYCHANGE), which
// is also how the health check of the L2 adapter resets one (NodeKmTestReset). arm64 is L3 only (NodeL2Offered): no
// adapter is created there.

#include "Node.h"

#include "Mayaqua/Memory.h"
#include "Mayaqua/Str.h"

#include "NodeInternal.h"
#include "NodeL2.h"

#include <cfgmgr32.h>
#include <iphlpapi.h>
#include <newdev.h>
#include <objbase.h>
#include <setupapi.h>
#include <wchar.h>

// The hardware id of the KM-TEST Loopback Adapter and the INF of its inbox driver
#define NODE_KMTEST_HWID L"*MSLOOP"
#define NODE_KMTEST_INF  L"%windir%\\inf\\netloop.inf"
// The value of the driver key that sets the MAC address of an adapter, and the one that names its interface
#define NODE_KMTEST_ADDRESS  L"NetworkAddress"
#define NODE_KMTEST_INSTANCE L"NetCfgInstanceId"
// ms that the node waits for the interface of a new or restarted adapter, and between two looks at it
#define NODE_KMTEST_WAIT 30000
#define NODE_KMTEST_POLL 100

// A KM-TEST adapter of the node
struct NODE_KMTEST {
	NODE *Node;
	// The device instance id, for SetupAPI
	wchar_t InstanceId[MAX_DEVICE_ID_LEN];
	// The MAC address that the node set, and as the value of NetworkAddress
	UCHAR Mac[6];
	wchar_t Address[16];
	// The interface: its GUID (NetCfgInstanceId) and its index
	GUID Guid;
	UINT IfIndex;
};

// The class of the KM-TEST adapter, as its INF names it, with the path of the INF
static bool NodeKmTestClass(GUID *class_guid, wchar_t *class_name, wchar_t *inf) {
	if (ExpandEnvironmentStringsW(NODE_KMTEST_INF, inf, MAX_PATH) == 0)
		return false;

	return (SetupDiGetINFClassW(inf, class_guid, class_name, MAX_CLASS_NAME_LEN, NULL) != FALSE);
}

// The device of instance id instance in a set of its own, which the caller destroys; INVALID_HANDLE_VALUE when it is gone
static HDEVINFO NodeKmTestOpen(const wchar_t *instance, SP_DEVINFO_DATA *dev) {
	HDEVINFO set = SetupDiCreateDeviceInfoList(NULL, NULL);

	if (set == INVALID_HANDLE_VALUE)
		return set;

	Zero(dev, sizeof(SP_DEVINFO_DATA));
	dev->cbSize = sizeof(SP_DEVINFO_DATA);
	if (SetupDiOpenDeviceInfoW(set, instance, NULL, 0, dev) == FALSE) {
		SetupDiDestroyDeviceInfoList(set);
		return INVALID_HANDLE_VALUE;
	}

	return set;
}

// Whether a device is a KM-TEST adapter: its first hardware id is *MSLOOP
static bool NodeKmTestIsLoop(HDEVINFO set, SP_DEVINFO_DATA *dev) {
	wchar_t ids[512];
	DWORD type = 0;

	Zero(ids, sizeof(ids));
	if (SetupDiGetDeviceRegistryPropertyW(set, dev, SPDRP_HARDWAREID, &type, (BYTE *)ids, sizeof(ids) - 2 * sizeof(wchar_t), NULL) == FALSE)
		return false;

	return (_wcsicmp(ids, NODE_KMTEST_HWID) == 0);
}

// A string value of the driver key of a device; size in bytes. False when the device has no driver key yet or no such value.
static bool NodeKmTestValue(HDEVINFO set, SP_DEVINFO_DATA *dev, const wchar_t *name, wchar_t *value, UINT size) {
	DWORD type = 0;
	DWORD len = size - sizeof(wchar_t);

	Zero(value, size);

	HKEY key = SetupDiOpenDevRegKey(set, dev, DICS_FLAG_GLOBAL, 0, DIREG_DRV, KEY_QUERY_VALUE);
	if (key == INVALID_HANDLE_VALUE)
		return false;

	LONG err = RegQueryValueExW(key, name, NULL, &type, (BYTE *)value, &len);
	RegCloseKey(key);

	return (err == ERROR_SUCCESS && type == REG_SZ);
}

// Restart a device, as a change of its properties does (DICS_PROPCHANGE): the driver reads its NetworkAddress again
static bool NodeKmTestRestart(HDEVINFO set, SP_DEVINFO_DATA *dev) {
	SP_PROPCHANGE_PARAMS p;

	Zero(&p, sizeof(p));
	p.ClassInstallHeader.cbSize = sizeof(SP_CLASSINSTALL_HEADER);
	p.ClassInstallHeader.InstallFunction = DIF_PROPERTYCHANGE;
	p.StateChange = DICS_PROPCHANGE;
	p.Scope = DICS_FLAG_CONFIGSPECIFIC;
	p.HwProfile = 0;

	if (SetupDiSetClassInstallParamsW(set, dev, &p.ClassInstallHeader, sizeof(p)) == FALSE)
		return false;

	return (SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, set, dev) != FALSE);
}

// The present KM-TEST adapter whose NetworkAddress is the address of k, into k->InstanceId; false when there is none
static bool NodeKmTestFind(NODE_KMTEST *k) {
	wchar_t inf[MAX_PATH];
	wchar_t class_name[MAX_CLASS_NAME_LEN];
	wchar_t value[64];
	GUID class_guid;
	bool found = false;

	if (NodeKmTestClass(&class_guid, class_name, inf) == false)
		return false;

	HDEVINFO set = SetupDiGetClassDevsW(&class_guid, NULL, NULL, DIGCF_PRESENT);
	if (set == INVALID_HANDLE_VALUE)
		return false;

	for (DWORD i = 0; found == false; i++) {
		SP_DEVINFO_DATA dev;

		Zero(&dev, sizeof(dev));
		dev.cbSize = sizeof(dev);
		if (SetupDiEnumDeviceInfo(set, i, &dev) == FALSE)
			break;

		if (NodeKmTestIsLoop(set, &dev) == false || NodeKmTestValue(set, &dev, NODE_KMTEST_ADDRESS, value, sizeof(value)) == false || _wcsicmp(value, k->Address) != 0)
			continue;

		found = (SetupDiGetDeviceInstanceIdW(set, &dev, k->InstanceId, MAX_DEVICE_ID_LEN, NULL) != FALSE);
	}

	SetupDiDestroyDeviceInfoList(set);

	return found;
}

// Remove the device of k, when it is a KM-TEST adapter
static bool NodeKmTestRemove(NODE_KMTEST *k) {
	SP_DEVINFO_DATA dev;
	SP_REMOVEDEVICE_PARAMS p;

	HDEVINFO set = NodeKmTestOpen(k->InstanceId, &dev);
	if (set == INVALID_HANDLE_VALUE)
		return false;

	bool ok = NodeKmTestIsLoop(set, &dev);
	if (ok) {
		Zero(&p, sizeof(p));
		p.ClassInstallHeader.cbSize = sizeof(SP_CLASSINSTALL_HEADER);
		p.ClassInstallHeader.InstallFunction = DIF_REMOVE;
		p.Scope = DI_REMOVEDEVICE_GLOBAL;
		p.HwProfile = 0;
		ok = (SetupDiSetClassInstallParamsW(set, &dev, &p.ClassInstallHeader, sizeof(p)) != FALSE && SetupDiCallClassInstaller(DIF_REMOVE, set, &dev) != FALSE);
	}

	SetupDiDestroyDeviceInfoList(set);

	return ok;
}

// Create a KM-TEST adapter, as devcon install does: a root-enumerated device of *MSLOOP, registered, then the driver of
// netloop.inf installed for the devices of *MSLOOP that have none, which is the new one. Without INSTALLFLAG_FORCE the
// adapters that have the driver already are left alone. Its instance id goes to k->InstanceId.
static bool NodeKmTestCreate(NODE_KMTEST *k, char *error, UINT error_size) {
	static const wchar_t hwid[] = NODE_KMTEST_HWID L"\0";
	wchar_t inf[MAX_PATH];
	wchar_t class_name[MAX_CLASS_NAME_LEN];
	GUID class_guid;
	SP_DEVINFO_DATA dev;
	BOOL reboot = FALSE;

	if (NodeKmTestClass(&class_guid, class_name, inf) == false) {
		Format(error, error_size, "the class of %S cannot be read (error %u)", NODE_KMTEST_INF, (UINT)GetLastError());
		return false;
	}

	HDEVINFO set = SetupDiCreateDeviceInfoList(&class_guid, NULL);
	if (set == INVALID_HANDLE_VALUE) {
		Format(error, error_size, "SetupDiCreateDeviceInfoList failed (error %u)", (UINT)GetLastError());
		return false;
	}

	Zero(&dev, sizeof(dev));
	dev.cbSize = sizeof(dev);
	bool ok = (SetupDiCreateDeviceInfoW(set, class_name, &class_guid, NULL, NULL, DICD_GENERATE_ID, &dev) != FALSE);
	ok = ok && SetupDiSetDeviceRegistryPropertyW(set, &dev, SPDRP_HARDWAREID, (const BYTE *)hwid, sizeof(hwid)) != FALSE;
	ok = ok && SetupDiCallClassInstaller(DIF_REGISTERDEVICE, set, &dev) != FALSE;
	ok = ok && SetupDiGetDeviceInstanceIdW(set, &dev, k->InstanceId, MAX_DEVICE_ID_LEN, NULL) != FALSE;
	if (ok == false)
		Format(error, error_size, "the device could not be registered (error %u)", (UINT)GetLastError());

	SetupDiDestroyDeviceInfoList(set);
	if (ok == false)
		return false;

	if (UpdateDriverForPlugAndPlayDevicesW(NULL, NODE_KMTEST_HWID, inf, 0, &reboot) == FALSE) {
		Format(error, error_size, "the driver of %S could not be installed (error %u)", inf, (UINT)GetLastError());
		NodeKmTestRemove(k);
		return false;
	}

	return true;
}

// Set the MAC address of the adapter of k as its NetworkAddress and restart it, once its driver key exists
static bool NodeKmTestSetAddress(NODE_KMTEST *k) {
	SP_DEVINFO_DATA dev;
	bool ok = false;

	for (UINT64 end = GetTickCount64() + NODE_KMTEST_WAIT; ok == false && GetTickCount64() < end;) {
		HDEVINFO set = NodeKmTestOpen(k->InstanceId, &dev);
		if (set == INVALID_HANDLE_VALUE)
			return false;

		HKEY key = SetupDiOpenDevRegKey(set, &dev, DICS_FLAG_GLOBAL, 0, DIREG_DRV, KEY_SET_VALUE);
		if (key != INVALID_HANDLE_VALUE) {
			DWORD size = (DWORD)((wcslen(k->Address) + 1) * sizeof(wchar_t));

			ok = (RegSetValueExW(key, NODE_KMTEST_ADDRESS, 0, REG_SZ, (const BYTE *)k->Address, size) == ERROR_SUCCESS);
			RegCloseKey(key);
			ok = ok && NodeKmTestRestart(set, &dev);
		}

		SetupDiDestroyDeviceInfoList(set);
		if (ok == false)
			Sleep(NODE_KMTEST_POLL);
	}

	return ok;
}

// The interface of the adapter of k, once it is up with the address of k: its GUID from the driver key, then its index
static bool NodeKmTestReadInterface(NODE_KMTEST *k) {
	SP_DEVINFO_DATA dev;
	wchar_t guid[64];
	NET_LUID luid;
	NET_IFINDEX index = 0;
	MIB_IF_ROW2 row;

	HDEVINFO set = NodeKmTestOpen(k->InstanceId, &dev);
	if (set == INVALID_HANDLE_VALUE)
		return false;

	bool ok = NodeKmTestValue(set, &dev, NODE_KMTEST_INSTANCE, guid, sizeof(guid));
	SetupDiDestroyDeviceInfoList(set);
	if (ok == false || CLSIDFromString(guid, &k->Guid) != NOERROR)
		return false;

	if (ConvertInterfaceGuidToLuid(&k->Guid, &luid) != NO_ERROR || ConvertInterfaceLuidToIndex(&luid, &index) != NO_ERROR)
		return false;

	Zero(&row, sizeof(row));
	row.InterfaceLuid = luid;
	if (GetIfEntry2(&row) != NO_ERROR || row.PhysicalAddressLength != 6 || Cmp(row.PhysicalAddress, k->Mac, 6) != 0)
		return false;

	k->IfIndex = (UINT)index;

	return true;
}

// Wait up to NODE_KMTEST_WAIT ms for the interface of the adapter of k to be up with its address
static bool NodeKmTestWaitInterface(NODE_KMTEST *k) {
	UINT64 end = GetTickCount64() + NODE_KMTEST_WAIT;

	while (NodeKmTestReadInterface(k) == false) {
		if (GetTickCount64() >= end)
			return false;
		Sleep(NODE_KMTEST_POLL);
	}

	return true;
}

// The KM-TEST adapter of the MAC address mac (NodeL2Mac) on the node n: the present adapter of that address, or a new one
// with it. NULL on a host that is L3 only, or when the adapter or its interface does not come up; the node log says why.
NODE_KMTEST *NodeKmTestNew(NODE *n, const UCHAR *mac) {
	SYSTEM_INFO info;
	char error[MAX_SIZE];

	if (n == NULL || mac == NULL)
		return NULL;

	Zero(&info, sizeof(info));
	GetNativeSystemInfo(&info);
	if (NodeL2Offered(info.wProcessorArchitecture) == false) {
		NodeLog(n, "KM-TEST adapter not created: this host is L3 only, as its architecture (%u) has no XDP runtime and no SeLow package (ADR-0022)", (UINT)info.wProcessorArchitecture);
		return NULL;
	}

	NODE_KMTEST *k = ZeroMalloc(sizeof(NODE_KMTEST));
	k->Node = n;
	Copy(k->Mac, mac, 6);
	swprintf(k->Address, sizeof(k->Address) / sizeof(wchar_t), L"%02X%02X%02X%02X%02X%02X", (UINT)mac[0], (UINT)mac[1], (UINT)mac[2], (UINT)mac[3], (UINT)mac[4], (UINT)mac[5]);

	bool found = NodeKmTestFind(k);
	if (found == false) {
		StrCpy(error, sizeof(error), "");
		if (NodeKmTestCreate(k, error, sizeof(error)) == false) {
			NodeLog(n, "KM-TEST adapter %S not created: %s", k->Address, error);
			Free(k);
			return NULL;
		}

		if (NodeKmTestSetAddress(k) == false) {
			NodeLog(n, "KM-TEST adapter %S: its MAC address could not be set (error %u)", k->Address, (UINT)GetLastError());
			NodeKmTestRemove(k);
			Free(k);
			return NULL;
		}
	}

	if (NodeKmTestWaitInterface(k) == false) {
		NodeLog(n, "KM-TEST adapter %S: its interface did not come up with that MAC address within %u ms", k->Address, NODE_KMTEST_WAIT);
		if (found == false)
			NodeKmTestRemove(k);
		Free(k);
		return NULL;
	}

	NodeLog(n, "KM-TEST adapter %S %s: device %S, interface %u", k->Address, found ? "found" : "created", k->InstanceId, k->IfIndex);

	return k;
}

// Let go of a KM-TEST adapter, and with remove take its device off the machine
void NodeKmTestFree(NODE_KMTEST *k, bool remove) {
	if (k == NULL)
		return;

	if (remove) {
		bool ok = NodeKmTestRemove(k);
		NodeLog(k->Node, "KM-TEST adapter %S %s", k->Address, ok ? "removed" : "could not be removed");
	}

	Free(k);
}

// The index of the interface of a KM-TEST adapter, 0 for none
UINT NodeKmTestIndex(NODE_KMTEST *k) {
	return (k != NULL ? k->IfIndex : 0);
}

// Reset a KM-TEST adapter (param, NODE_L2_RESET_PROC of the L2 adapter): its device restarts, and if_index gets the index
// of its interface once that is up again
bool NodeKmTestReset(void *param, UINT *if_index) {
	NODE_KMTEST *k = (NODE_KMTEST *)param;
	SP_DEVINFO_DATA dev;

	if (k == NULL)
		return false;

	HDEVINFO set = NodeKmTestOpen(k->InstanceId, &dev);
	if (set == INVALID_HANDLE_VALUE)
		return false;

	bool ok = NodeKmTestRestart(set, &dev);
	SetupDiDestroyDeviceInfoList(set);

	ok = ok && NodeKmTestWaitInterface(k);
	NodeLog(k->Node, "KM-TEST adapter %S reset: %s, interface %u", k->Address, ok ? "up again" : "not up again", k->IfIndex);

	if (ok && if_index != NULL)
		*if_index = k->IfIndex;

	return ok;
}
