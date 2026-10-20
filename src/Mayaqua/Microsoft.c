// Microsoft.c
// For Microsoft Windows code

#define	MICROSOFT_C

#include "Microsoft.h"

#include "Cfg.h"
#include "Encrypt.h"
#include "FileIO.h"
#include "GlobalConst.h"
#include "Internat.h"
#include "Kernel.h"
#include "Memory.h"
#include "Object.h"
#include "Str.h"
#include "Table.h"
#include "Tick64.h"
#include "Win32.h"

#define SECURITY_WIN32

// Shlwapi.h only for its path functions: its string macros (StrCpy, StrCat, ...) would replace ours
#define NO_SHLWAPI_STRFCNS
#define NO_SHLWAPI_REG
#define NO_SHLWAPI_STREAM
#define NO_SHLWAPI_HTTP
#define NO_SHLWAPI_ISOS
#define NO_SHLWAPI_GDI

#include <AclAPI.h>
#include <DbgHelp.h>
#include <dwmapi.h>
#include <iphlpapi.h>
#include <mmsystem.h>
#include <nb30.h>
#include <sddl.h>
#include <security.h>
#include <shellapi.h>
#include <ShlObj.h>
#include <Shlwapi.h>		// PathGetArgsA/W() of MsInit
#include <SoftPub.h>
#include <WtsApi32.h>

#if defined(_M_X64) || defined(_M_IX86)
#include <intrin.h>		// __cpuid() of the VM detection
#endif	// defined(_M_X64) || defined(_M_IX86)

static MS *ms = NULL;

static SERVICE_STATUS_HANDLE ssh = NULL;
static SERVICE_STATUS status = { 0 };
// The control handler and the service thread both report the status: status_lock guards status
static CRITICAL_SECTION status_lock;
static HANDLE service_stop_event = NULL;
static char g_service_name[MAX_SIZE];
static SERVICE_FUNCTION *g_start, *g_stop;
static bool exiting = false;
static bool wnd_end;
static bool is_usermode = false;

void MsInitProcessCallOnce()
{
	// Mitigate DLL injection attacks
	// A dynamic load of a DLL named without a path searches the directory of the executable, the
	// directories added with AddDllDirectory and System32: never the current directory, the Windows
	// directory or PATH. LOAD_LIBRARY_SEARCH_SYSTEM32 alone would drop the directory of the
	// executable. Statically imported DLLs (the ASan runtime) were loaded before this runs.
	SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
	// SetDllDirectory("") also keeps the current directory out of the orders the default directories do not
	// govern: the standard order of child processes (cscript.exe, Win32Run) and the alternate order of
	// LoadLibraryEx with LOAD_WITH_ALTERED_SEARCH_PATH. Empty, it adds no directory to the default ones.
	SetDllDirectoryW(L"");
}

// Raw SMBIOS table of GetSystemFirmwareTable
#define	MS_SMBIOS_PROVIDER			0x52534D42		// Firmware table provider 'RSMB'
#define	MS_SMBIOS_HEADER_SIZE		8				// Header before the structures
#define	MS_SMBIOS_TYPE_SYSTEM		1				// Structure type: system information
#define	MS_SMBIOS_TYPE_BASEBOARD	2				// Structure type: baseboard information
#define	MS_SMBIOS_TYPE_END			127				// Structure type: end of the table

#if defined(_M_X64) || defined(_M_IX86)
// True when CPUID reports a hypervisor that runs this OS as a guest. The hypervisor-present bit
// (leaf 1, ECX bit 31) is also set in the root partition of Hyper-V, which is the host OS of a
// physical machine that runs Hyper-V or virtualization-based security: that partition holds the
// CreatePartitions privilege (leaf 0x40000003, EBX bit 0) and is not a guest.
static bool MsIsHypervisorGuest()
{
	int regs[4];	// EAX, EBX, ECX, EDX
	char vendor[13];

	__cpuid(regs, 1);
	if (((UINT)regs[2] & 0x80000000) == 0)
	{
		return false;
	}

	// Highest hypervisor leaf in EAX, vendor signature in EBX, ECX and EDX
	__cpuid(regs, 0x40000000);
	Copy(vendor, &regs[1], 12);
	vendor[12] = 0;

	if (StrCmp(vendor, "Microsoft Hv") == 0 && (UINT)regs[0] >= 0x40000003)
	{
		__cpuid(regs, 0x40000003);
		if (((UINT)regs[1] & 1) != 0)
		{
			return false;
		}
	}

	return true;
}
#endif	// defined(_M_X64) || defined(_M_IX86)

// Append string number index (1 is the first, 0 is none) of an SMBIOS string set to dst, after a space
static void MsSmbiosAddString(char *dst, UINT dst_size, UCHAR *str_set, UINT str_set_size, UINT index)
{
	UINT pos = 0;
	UINT i;

	for (i = 1; index != 0 && pos < str_set_size; i++)
	{
		UINT len = 0;

		while (pos + len < str_set_size && str_set[pos + len] != 0)
		{
			len++;
		}

		if (len == 0 || pos + len >= str_set_size)
		{
			// End of the set, or a string without its terminator
			return;
		}

		if (i == index)
		{
			StrCat(dst, dst_size, " ");
			StrCat(dst, dst_size, (char *)str_set + pos);
			return;
		}

		pos += len + 1;
	}
}

// True when the SMBIOS manufacturer or product name of the system (structure type 1) or of the
// baseboard (type 2) names a virtual machine. The raw SMBIOS table of GetSystemFirmwareTable is
// a header of 8 bytes (the table length at offset 4), then the structures: type, length of the
// formatted area, handle and the rest of the area, then a string set that ends with two zero bytes.
static bool MsIsVmFirmware()
{
	// Lower case; "virtual" covers Hyper-V and Azure ("Virtual Machine"), VirtualBox and Virtual PC.
	// "microsoft corporation", "hvm", "domu", "xvm" and "oracle vm" are kept from the old WMI list:
	// the manufacturer "microsoft corporation" names Hyper-V and Azure guests (the arm64 CI runner
	// included) and also physical Microsoft hardware, as before.
	static char *vm_names[] =
	{
		"microsoft corporation", "virtual", "vmware", "innotek", "qemu", "kvm", "xen", "parallels", "bochs", "bhyve",
		"hvm", "domu", "xvm", "oracle vm", "amazon ec2", "google compute engine",
	};
	char names[MAX_SIZE];
	UCHAR *buf;
	UINT size;
	UINT table_size;
	UINT end;
	UINT pos;
	UINT i;
	bool ret = false;

	size = GetSystemFirmwareTable(MS_SMBIOS_PROVIDER, 0, NULL, 0);
	if (size <= MS_SMBIOS_HEADER_SIZE)
	{
		return false;
	}

	buf = ZeroMalloc(size);
	if (GetSystemFirmwareTable(MS_SMBIOS_PROVIDER, 0, buf, size) != size)
	{
		Free(buf);
		return false;
	}

	table_size = (UINT)buf[4] | ((UINT)buf[5] << 8) | ((UINT)buf[6] << 16) | ((UINT)buf[7] << 24);
	end = MS_SMBIOS_HEADER_SIZE + MIN(table_size, size - MS_SMBIOS_HEADER_SIZE);

	names[0] = 0;
	pos = MS_SMBIOS_HEADER_SIZE;

	while (pos + 4 <= end)
	{
		UINT type = buf[pos];
		UINT len = buf[pos + 1];
		UINT str_set = pos + len;
		UINT next = str_set;

		if (len < 4 || str_set > end)
		{
			break;
		}

		while (next + 1 < end && (buf[next] != 0 || buf[next + 1] != 0))
		{
			next++;
		}
		if (next + 1 >= end)
		{
			break;
		}
		next += 2;

		if (type == MS_SMBIOS_TYPE_END)
		{
			break;
		}

		if ((type == MS_SMBIOS_TYPE_SYSTEM || type == MS_SMBIOS_TYPE_BASEBOARD) && len > 5)
		{
			// Manufacturer at offset 4 and product name at offset 5 of the formatted area
			MsSmbiosAddString(names, sizeof(names), buf + str_set, next - str_set, buf[pos + 4]);
			MsSmbiosAddString(names, sizeof(names), buf + str_set, next - str_set, buf[pos + 5]);
		}

		pos = next;
	}

	Free(buf);

	for (i = 0; i < sizeof(vm_names) / sizeof(vm_names[0]); i++)
	{
		if (InStrEx(names, vm_names[i], false))
		{
			ret = true;
			break;
		}
	}

	return ret;
}

// True when this OS runs in a virtual machine: CPUID reports a hypervisor that runs it as a guest
// (x64), or the SMBIOS strings name a virtual machine (the only check on arm64, which has no CPUID).
// Writes no file and starts no process.
static bool MsIsInVmMain()
{
#if defined(_M_X64) || defined(_M_IX86)
	if (MsIsHypervisorGuest())
	{
		return true;
	}
#endif	// defined(_M_X64) || defined(_M_IX86)

	return MsIsVmFirmware();
}
bool MsIsInVm()
{
	static bool flag_detected = false;
	static bool flag_is_vm = false;

	if (flag_detected == false)
	{
		flag_is_vm = MsIsInVmMain();

		flag_detected = true;
	}

	return flag_is_vm;
}

UINT MsGetUserLocaleId()
{
	static UINT lcid_cache = 0;

	if (lcid_cache == 0)
	{
		lcid_cache = (UINT)GetUserDefaultLCID();
	}

	return lcid_cache;
}

double MsGetHiResTimeSpan(UINT64 diff)
{
	LARGE_INTEGER t;
	UINT64 freq;

	if (QueryPerformanceFrequency(&t) == false)
	{
		freq = 1000ULL;
	}
	else
	{
		Copy(&freq, &t, sizeof(UINT64));
	}

	return (double)diff / (double)freq;
}

UINT64 MsGetHiResCounter()
{
	LARGE_INTEGER t;
	UINT64 ret;

	if (QueryPerformanceCounter(&t) == false)
	{
		return Tick64();
	}

	Copy(&ret, &t, sizeof(UINT64));

	return ret;
}

static void MsUniMakeDirEx(wchar_t *name)
{
	UINT wp;
	wchar_t *tmp;
	UINT i, len;
	if (name == NULL)
	{
		return;
	}

	tmp = ZeroMalloc(UniStrSize(name) * 2);
	wp = 0;
	len = UniStrLen(name);
	for (i = 0;i < len;i++)
	{
		wchar_t c = name[i];

		if (c == '\\')
		{
			if (UniStrCmpi(tmp, L"\\\\") != 0 && UniStrCmpi(tmp, L"\\") != 0)
			{
				MsUniMakeDir(tmp);
			}
		}

		tmp[wp++] = c;
	}

	Free(tmp);

	MsUniMakeDir(name);
}

bool MsUniMakeDir(wchar_t *name)
{
	if (name == NULL)
	{
		return false;
	}

	return CreateDirectoryW(name, NULL);
}

static wchar_t ms_computer_name_full_cache[MAX_SIZE] = {0};

void MsGetComputerNameFullEx(wchar_t *name, UINT size, bool with_cache)
{
	DWORD size2;
	if (name == NULL || size < sizeof(wchar_t))
	{
		return;
	}

	UniStrCpy(name, size, L"");

	// size counts bytes; GetComputerNameExW counts wide characters
	size2 = size / sizeof(wchar_t);

	if (with_cache)
	{
		if (UniIsEmptyStr(ms_computer_name_full_cache) == false)
		{
			UniStrCpy(name, size, ms_computer_name_full_cache);
			return;
		}
	}

	if (GetComputerNameExW(ComputerNameDnsFullyQualified, name, &size2) == false)
	{
		char tmp[MAX_SIZE];

		MsGetComputerName(tmp, sizeof(tmp));

		StrToUni(name, size, tmp);
	}

	if (with_cache)
	{
		UniStrCpy(ms_computer_name_full_cache, sizeof(ms_computer_name_full_cache), name);
	}
}

void MsGetComputerName(char *name, UINT size)
{
	DWORD sz;
	if (name == NULL)
	{
		return;
	}

	sz = size;
	GetComputerName(name, &sz);
}

void *MsDisableWow64FileSystemRedirection()
{
	void *p = NULL;
	if (Wow64DisableWow64FsRedirection(&p) == false)
	{
		return NULL;
	}

	if (p == NULL)
	{
		p = (void *)0x12345678;
	}

	return p;
}

void MsRestoreWow64FileSystemRedirection(void *p)
{
	if (p == NULL)
	{
		return;
	}
	if (p == (void *)0x12345678)
	{
		p = NULL;
	}

	Wow64RevertWow64FsRedirection(p);
}

void MsRegistWindowsFirewallEx2(char *title, char *exe, char *dir)
{
	char tmp[MAX_PATH];
	if (title == NULL || exe == NULL)
	{
		return;
	}
	if (dir == NULL || IsEmptyStr(dir))
	{
		dir = MsGetExeDirName();
	}

	ConbinePath(tmp, sizeof(tmp), dir, exe);

	if (IsFileExists(tmp) == false)
	{
		return;
	}

	MsRegistWindowsFirewallEx(title, tmp);
}
void MsRegistWindowsFirewallEx(char *title, char *exe)
{
	char *data;
	char *tmp;
	UINT tmp_size;
	char filename[MAX_PATH];
	char cscript[MAX_PATH];
	char arg[MAX_PATH];
	IO *o;
	char hash[MAX_PATH];
	UCHAR hashbin[SHA1_SIZE];
	UCHAR file_hash_bin[SHA1_SIZE];
	char file_hash_str[MAX_SIZE];
	if (title == NULL || exe == NULL)
	{
		return;
	}

	if (MsIsAdmin() == false)
	{
		return;
	}

	data = "Option Explicit\r\n\r\nConst PROFILES_ALL = 7\r\nConst NET_FW_ACTION_ALLOWNET_FW_ACTION_ALLOW = 1\r\n"
		"\r\nDim policy2\r\nDim rules\r\nDim new_rule\r\n\r\nOn Error Resume Next\r\n\r\n"
		"Set policy2 = CreateObject(\"HNetCfg.FwPolicy2\")\r\nSet rules = policy2.Rules\r\n"
		"Set new_rule = CreateObject(\"HNetCfg.FWRule\")\r\nnew_rule.Name = \"$TITLE$\"\r\n"
		"new_rule.Description = \"$TITLE$\"\r\nnew_rule.ApplicationName = \"$PATH$\"\r\n"
		"new_rule.Enabled = TRUE\r\nnew_rule.Profiles = PROFILES_ALL\r\nnew_rule.Action = "
		"NET_FW_ACTION_ALLOWNET_FW_ACTION_ALLOW\r\nrules.Add new_rule\r\n\r\n";

	tmp_size = StrLen(data) * 4;
	tmp = ZeroMalloc(tmp_size);

	Sha1(hashbin, exe, StrLen(exe));
	BinToStr(hash, sizeof(hash), hashbin, 6);

	ReplaceStrEx(tmp, tmp_size, data, "$TITLE$", title, false);
	ReplaceStrEx(tmp, tmp_size, tmp, "$PATH$", exe, false);

	Sha1(file_hash_bin, tmp, StrLen(tmp));
	BinToStr(file_hash_str, sizeof(file_hash_str), file_hash_bin, sizeof(file_hash_bin));

	if (MsRegReadIntEx2(REG_LOCAL_MACHINE, SOFTETHER_FW_SCRIPT_HASH, file_hash_str, false, true) == 0)
	{
		Format(filename, sizeof(filename), "%s\\winfire_%s.vbs", MsGetMyTempDir(), hash);
		o = FileCreate(filename);
		FileWrite(o, tmp, StrLen(tmp));
		FileClose(o);

		Format(cscript, sizeof(cscript), "%s\\cscript.exe", MsGetSystem32Dir());
		Format(arg, sizeof(arg), "\"%s\"", filename);

		if (Run(cscript, arg, true, false))
		{
			MsRegWriteIntEx2(REG_LOCAL_MACHINE, SOFTETHER_FW_SCRIPT_HASH, file_hash_str, 1, false, true);
		}
	}

	Free(tmp);
}

UINT MsGetConsoleWidth()
{
	HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
	CONSOLE_SCREEN_BUFFER_INFO info;

	if (h == INVALID_HANDLE_VALUE)
	{
		return 80;
	}

	Zero(&info, sizeof(info));
	if (GetConsoleScreenBufferInfo(h, &info) == false)
	{
		return 80;
	}

	return info.dwSize.X;
}

MS_ADAPTER *MsGetAdapterByGuidFromList(MS_ADAPTER_LIST *o, char *guid)
{
	MS_ADAPTER *ret = NULL;
	UINT i;
	if (o == NULL || guid == NULL)
	{
		return NULL;
	}

	for (i = 0;i < o->Num;i++)
	{
		if (StrCmpi(o->Adapters[i]->Guid, guid) == 0)
		{
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
bool MsIsBridgeableIf(UINT type, UINT media_type, UINT physical_medium_type, bool hardware_interface)
{
	if (type != IF_TYPE_ETHERNET_CSMACD || media_type != NdisMedium802_3)
	{
		return false;
	}

	if (physical_medium_type == NdisPhysicalMedium802_3)
	{
		return true;
	}

	return physical_medium_type == NdisPhysicalMediumUnspecified && hardware_interface;
}

MS_ADAPTER *MsCloneAdapter(MS_ADAPTER *a)
{
	MS_ADAPTER *ret;
	if (a == NULL)
	{
		return NULL;
	}

	ret = ZeroMalloc(sizeof(MS_ADAPTER));
	Copy(ret, a, sizeof(MS_ADAPTER));

	return ret;
}

MS_ADAPTER_LIST *MsCreateAdapterList()
{
	LIST *o;
	UINT i;
	UINT retcode;
	PMIB_IF_TABLE2 table;
	MS_ADAPTER_LIST *ret;

	retcode = GetIfTable2(&table);
	if (retcode != NO_ERROR || table == NULL)
	{
		return ZeroMalloc(sizeof(MS_ADAPTER_LIST));
	}

	o = NewListFast(NULL);

	for (i = 0;i < table->NumEntries;i++)
	{
		MIB_IF_ROW2 *r = &table->Table[i];
		wchar_t title[MAX_PATH];
		MS_ADAPTER *a;
		UINT j;

		{
			{
				for (j = 1;;j++)
				{
					UINT k;
					bool exists;
					if (j == 1)
					{
						UniStrCpy(title, sizeof(title), r->Description);
					}
					else
					{
						UniFormat(title, sizeof(title), L"%s (%u)", r->Description, j);
					}

					exists = false;

					for (k = 0;k < LIST_NUM(o);k++)
					{
						MS_ADAPTER *a = LIST_DATA(o, k);

						if (UniStrCmpi(a->TitleW, title) == 0)
						{
							exists = true;
							break;
						}
					}

					if (exists == false)
					{
						break;
					}
				}

				a = ZeroMalloc(sizeof(MS_ADAPTER));

				UniStrCpy(a->TitleW, sizeof(a->TitleW), title);
				UniToStr(a->Title, sizeof(a->Title), title);
				a->Index = r->InterfaceIndex;
				a->MediaConnectState = r->MediaConnectState;
				a->Type = r->Type;
				a->Status = ConvertMidStatusVistaToXp(r->OperStatus);
				a->Mtu = r->Mtu;
				a->Speed = MAX((UINT)r->TransmitLinkSpeed, (UINT)r->ReceiveLinkSpeed);
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

				Add(o, a);
			}
		}
	}

	ret = ZeroMalloc(sizeof(MS_ADAPTER_LIST));
	ret->Num = LIST_NUM(o);
	ret->Adapters = ToArray(o);

	ReleaseList(o);
	FreeMibTable(table);

	return ret;
}

UINT ConvertMidStatusVistaToXp(UINT st)
{
	switch (st)
	{
	case IfOperStatusUp:
		return MIB_IF_OPER_STATUS_CONNECTED;

	case IfOperStatusDown:
		return MIB_IF_OPER_STATUS_DISCONNECTED;
	}

	return MIB_IF_OPER_STATUS_NON_OPERATIONAL;
}

void MsFreeAdapterList(MS_ADAPTER_LIST *o)
{
	UINT i;
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < o->Num;i++)
	{
		MsFreeAdapter(o->Adapters[i]);
	}
	Free(o->Adapters);

	Free(o);
}

void MsFreeAdapter(MS_ADAPTER *a)
{
	if (a == NULL)
	{
		return;
	}

	Free(a);
}

static LRESULT CALLBACK MsUserModeWindowProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_ENDSESSION:
		if (wParam == false)
		{
			break;
		}
	case WM_CREATE:
		exiting = false;
		g_start();
		break;
	case WM_QUERYENDSESSION:
		if (exiting == false)
		{
			exiting = true;
			g_stop();
			DestroyWindow(hWnd);
		}
		return TRUE;
	case WM_CLOSE:
		if (exiting == false)
		{
			exiting = true;
			g_stop();
			DestroyWindow(hWnd);
		}
		break;
	case WM_DESTROY:
		wnd_end = true;
		break;
	}
	return DefWindowProc(hWnd, msg, wParam, lParam);
}

bool MsIsUserMode()
{
	return is_usermode;
}

static void MsUserModeW(wchar_t *title, SERVICE_FUNCTION *start, SERVICE_FUNCTION *stop)
{
	WNDCLASS wc;
	HWND hWnd;
	MSG msg;
	INSTANCE *inst;
	char title_a[MAX_PATH];
	wchar_t msg_str[MAX_SIZE];
	if (title == NULL || start == NULL || stop == NULL)
	{
		return;
	}

	UniToStr(title_a, sizeof(title_a), title);

	is_usermode = true;
	g_start = start;
	g_stop = stop;

	inst = NewSingleInstance(NULL);
	if (inst == NULL)
	{
		UniFormat(msg_str, sizeof(msg_str), _UU("SVC_USERMODE_MUTEX"), ms->ExeFileNameW);
		UniPrint(L"%s\n", msg_str);
		return;
	}

	Zero(&wc, sizeof(wc));
	wc.hbrBackground = (HBRUSH)GetStockObject(WHITE_BRUSH);
	wc.hCursor = LoadCursor(NULL,IDC_ARROW);
	wc.hInstance = ms->hInst;
	wc.lpfnWndProc = MsUserModeWindowProc;
	wc.lpszClassName = title_a;
	if (RegisterClass(&wc) == 0)
	{
		return;
	}

	hWnd = CreateWindow(title_a, title_a, WS_OVERLAPPEDWINDOW,
		CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
		NULL, NULL, ms->hInst, NULL);

	if (hWnd == NULL)
	{
		return;
	}

	wnd_end = false;
	while (wnd_end == false)
	{
		GetMessage(&msg, NULL, 0, 0);
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}

	FreeSingleInstance(inst);

	_exit(0);
}

// Write one entry to the Application event log, with the message as its only insertion string;
// type is an EVENTLOG_*_TYPE value. Plain Win32 calls only, so that the service code can write
// entries before InitMayaqua().
bool MsWriteEventLog(char *source, UINT type, UINT event_id, char *message)
{
	HANDLE h;
	LPCSTR strings[1];
	BOOL ret;
	if (source == NULL || message == NULL)
	{
		return false;
	}

	h = RegisterEventSourceA(NULL, source);
	if (h == NULL)
	{
		return false;
	}

	strings[0] = message;
	ret = ReportEventA(h, (WORD)type, 0, event_id, NULL, 1, 0, strings, NULL);

	DeregisterEventSource(h);

	return ret ? true : false;
}

// Write a service entry (MS_EVENT_SERVICE_*) under the service name: "Service <name> <what>.",
// with the Win32 error code when it is not 0
static void MsWriteServiceEvent(UINT type, UINT event_id, char *what, UINT error)
{
	char msg[MAX_SIZE];

	if (error == 0)
	{
		snprintf(msg, sizeof(msg), "Service %s %s.", g_service_name, what);
	}
	else
	{
		snprintf(msg, sizeof(msg), "Service %s %s (error %u).", g_service_name, what, error);
	}

	MsWriteEventLog(g_service_name, type, event_id, msg);
}

// Report the state to the SCM under status_lock. A pending state advances the checkpoint and accepts
// no control; the running service accepts STOP and PRESHUTDOWN.
static void MsSetServiceState(DWORD state, DWORD wait_hint, DWORD exit_code)
{
	EnterCriticalSection(&status_lock);

	status.dwCurrentState = state;
	status.dwWin32ExitCode = exit_code;
	status.dwWaitHint = wait_hint;

	if (state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING)
	{
		status.dwCheckPoint++;
		status.dwControlsAccepted = 0;
	}
	else
	{
		status.dwCheckPoint = 0;
		status.dwControlsAccepted = (state == SERVICE_RUNNING ? SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_PRESHUTDOWN : 0);
	}

	SetServiceStatus(ssh, &status);

	LeaveCriticalSection(&status_lock);
}

static void MsServiceStoperMainThread(THREAD *t, void *p)
{
	g_stop();
}

static bool MsServiceStopProc()
{
	THREAD *thread;
	bool ret = true;
	UINT64 selfkill_timeout = Tick64() + SVC_SELFKILL_TIMEOUT;

	thread = NewThread(MsServiceStoperMainThread, NULL);

	while (WaitThread(thread, 250) == false)
	{
		if (Tick64() >= selfkill_timeout)
		{
			ret = false;
			break;
		}
		MsSetServiceState(SERVICE_STOP_PENDING, 100000, NO_ERROR);
	}

	// The entry goes out before SERVICE_STOPPED: once that is reported, the process may end at any time
	if (ret)
	{
		MsWriteServiceEvent(EVENTLOG_INFORMATION_TYPE, MS_EVENT_SERVICE_STOPPED, "stopped", 0);
	}
	else
	{
		MsWriteServiceEvent(EVENTLOG_ERROR_TYPE, MS_EVENT_SERVICE_FAILED,
			"did not stop within the self-kill timeout and is terminated", 0);
	}

	MsSetServiceState(SERVICE_STOPPED, 0, ret ? NO_ERROR : ERROR_TIMEOUT);

	if (ret == false)
	{
		// The self-kill timeout fired: force an exit
		_exit(-1);
	}
	else
	{
		ReleaseThread(thread);
	}

	return ret;
}

// Control handler (HandlerEx), run on the thread of StartServiceCtrlDispatcherW. STOP and PRESHUTDOWN
// both stop the server, and g_stop() saves the configuration: PRESHUTDOWN gives that the pre-shutdown
// window of an OS shutdown instead of the short SHUTDOWN one.
static DWORD WINAPI MsServiceHandler(DWORD control, DWORD event_type, LPVOID event_data, LPVOID context)
{
	switch (control)
	{
	case SERVICE_CONTROL_STOP:
	case SERVICE_CONTROL_PRESHUTDOWN:
		MsSetServiceState(SERVICE_STOP_PENDING, 100000, NO_ERROR);
		SetEvent(service_stop_event);
		return NO_ERROR;

	case SERVICE_CONTROL_INTERROGATE:
		return NO_ERROR;
	}

	return ERROR_CALL_NOT_IMPLEMENTED;
}

// Service main, run on its own thread by StartServiceCtrlDispatcherW. The service is START_PENDING
// while Mayaqua and the server start and RUNNING once g_start() has returned; no control is accepted
// before that, so the handler never sees a NULL service_stop_event.
static void WINAPI MsServiceDispatcher(DWORD argc, LPWSTR *argv)
{
	// An own-process service may register under any name; argv[0] is the one the SCM started
	ssh = RegisterServiceCtrlHandlerExW(argc >= 1 ? argv[0] : L"", MsServiceHandler, NULL);

	if (ssh == NULL)
	{
		MsWriteServiceEvent(EVENTLOG_ERROR_TYPE, MS_EVENT_SERVICE_FAILED,
			"could not start: RegisterServiceCtrlHandlerExW() failed", GetLastError());
		return;
	}

	status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
	MsSetServiceState(SERVICE_START_PENDING, 300000, NO_ERROR);

	service_stop_event = CreateEventW(NULL, true, false, NULL);
	if (service_stop_event == NULL)
	{
		DWORD error = GetLastError();

		MsWriteServiceEvent(EVENTLOG_ERROR_TYPE, MS_EVENT_SERVICE_FAILED,
			"could not start: CreateEventW() failed", error);
		MsSetServiceState(SERVICE_STOPPED, 0, error);
		return;
	}

#ifdef	_DEBUG	// Debug configuration: the debug CRT (/MTd) defines _DEBUG
	// memcheck = true logs every malloc/realloc/free to find leaks, but is very slow.
	InitMayaqua(false, true, 0, NULL);
#else
	InitMayaqua(false, false, 0, NULL);
#endif

	MsSetServiceState(SERVICE_START_PENDING, 300000, NO_ERROR);

	g_start();

	// RUNNING goes out before the entry: whoever waits for "started" can stop the service at once
	MsSetServiceState(SERVICE_RUNNING, 0, NO_ERROR);
	MsWriteServiceEvent(EVENTLOG_INFORMATION_TYPE, MS_EVENT_SERVICE_STARTED, "started", 0);
	MsUpdateServiceConfig(g_service_name);

	WaitForSingleObject(service_stop_event, INFINITE);

	MsServiceStopProc();
}

static void MsTestModeW(wchar_t *title, SERVICE_FUNCTION *start, SERVICE_FUNCTION *stop)
{
	INSTANCE *inst;
	wchar_t msg[MAX_SIZE];
	if (title == NULL || start == NULL || stop == NULL)
	{
		return;
	}

	is_usermode = true;

	inst = NewSingleInstance(NULL);
	if (inst == NULL)
	{
		UniFormat(msg, sizeof(msg), _UU("SVC_TEST_MUTEX"), ms->ExeFileNameW);
		UniPrint(L"%s\n", msg);
		return;
	}

	start();

	UniFormat(msg, sizeof(msg), _UU("SVC_TEST_MSG"), title);
	UniPrint(L"%s\n", msg);
	GetLine(NULL, 0);

	stop();

	FreeSingleInstance(inst);
}

static void MsWriteCallingServiceManagerProcessId(char *svcname, UINT pid)
{
	char tmp[MAX_PATH];

	Format(tmp, sizeof(tmp), SVC_CALLING_SM_PROCESS_ID_KEY, svcname);

	if (pid != 0)
	{
		MsRegWriteInt(REG_LOCAL_MACHINE, tmp, SVC_CALLING_SM_PROCESS_ID_VALUE, pid);
		MsRegWriteInt(REG_CURRENT_USER, tmp, SVC_CALLING_SM_PROCESS_ID_VALUE, pid);
	}
	else
	{
		MsRegDeleteValue(REG_LOCAL_MACHINE, tmp, SVC_CALLING_SM_PROCESS_ID_VALUE);
		MsRegDeleteKeyEx2(REG_LOCAL_MACHINE, tmp, false, false);

		MsRegDeleteValue(REG_CURRENT_USER, tmp, SVC_CALLING_SM_PROCESS_ID_VALUE);
		MsRegDeleteKeyEx2(REG_CURRENT_USER, tmp, false, false);
	}
}

// Print the string table message id, formatted with the arguments, on a line of its own; nothing
// when silent
static void MsSvcMsg(bool silent, char *id, ...)
{
	wchar_t msg[MAX_SIZE * 4];
	va_list args;

	if (silent)
	{
		return;
	}

	va_start(args, id);
	UniFormatArgs(msg, sizeof(msg), _UU(id), args);
	va_end(args);

	UniPrint(L"%s\n", msg);
}

UINT MsService(char *name, SERVICE_FUNCTION *start, SERVICE_FUNCTION *stop, char *cmd_line)
{
	UINT mode;
	UINT ret = 0;
	char *arg;
	TOKEN_LIST *t = NULL;
	char *service_name;
	wchar_t *service_title;
	wchar_t *service_description;
	char tmp[MAX_SIZE];
	bool restoreReg = false;
	bool silent = false;
	if (name == NULL || start == NULL || stop == NULL)
	{
		return ret;
	}

	g_start = start;
	g_stop = stop;
	StrCpy(g_service_name, sizeof(g_service_name), name);
	StrLower(g_service_name);

	if (cmd_line != NULL && lstrcmpiA(cmd_line, SVC_ARG_SERVICE) == 0)
	{
		// An own-process service: the name in the table is ignored, but must not be NULL
		SERVICE_TABLE_ENTRYW dispatch_table[] =
		{
			{L"", MsServiceDispatcher},
			{NULL, NULL},
		};

		SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
		InitializeCriticalSection(&status_lock);

		if (StartServiceCtrlDispatcherW(dispatch_table) == false)
		{
			// Not started by the SCM (for example /service from a console): nothing ran, so exit 1
			MsWriteServiceEvent(EVENTLOG_ERROR_TYPE, MS_EVENT_SERVICE_FAILED,
				"could not start: StartServiceCtrlDispatcherW() failed", GetLastError());
			return 1;
		}

		MsUpdateServiceConfig(g_service_name);

		_exit(0);
		return 0;
	}

#ifdef	_DEBUG	// Debug configuration: the debug CRT (/MTd) defines _DEBUG
	// memcheck = true logs every malloc/realloc/free to find leaks, but is very slow.
	InitMayaqua(false, true, 0, NULL);
#else
	InitMayaqua(false, false, 0, NULL);
#endif

	Format(tmp, sizeof(tmp), SVC_NAME, name);
	service_name = _SS(tmp);
	Format(tmp, sizeof(tmp), SVC_TITLE, name);
	service_title = _UU(tmp);
	Format(tmp, sizeof(tmp), SVC_DESCRIPT, name);
	service_description = _UU(tmp);

	if (StrLen(service_name) == 0 || UniStrLen(service_title) == 0)
	{
		MsSvcMsg(false, "SVC_NOT_FOUND", name);
	}
	else
	{
		wchar_t path[MAX_SIZE];
		mode = SVC_MODE_NONE;

		t = GetCommandLineToken();
		arg = NULL;

		if (t->NumTokens >= 1)
		{
			arg = t->Token[0];
		}
		if(t->NumTokens >= 2)
		{
			if(StrCmpi(t->Token[1], SVC_ARG_SILENT) == 0)
			{
				silent = true;
			}
		}

		if (arg != NULL)
		{
			if (StrCmpi(arg, SVC_ARG_INSTALL) == 0)
			{
				mode = SVC_MODE_INSTALL;
			}
			if (StrCmpi(arg, SVC_ARG_UNINSTALL) == 0)
			{
				mode = SVC_MODE_UNINSTALL;
			}
			if (StrCmpi(arg, SVC_ARG_START) == 0)
			{
				mode = SVC_MODE_START;
			}
			if (StrCmpi(arg, SVC_ARG_STOP) == 0)
			{
				mode = SVC_MODE_STOP;
			}
			if (StrCmpi(arg, SVC_ARG_TEST) == 0)
			{
				mode = SVC_MODE_TEST;
			}
			if (StrCmpi(arg, SVC_ARG_USERMODE) == 0)
			{
				mode = SVC_MODE_USERMODE;
			}
			if (StrCmpi(arg, SVC_ARG_SETUP_INSTALL) == 0)
			{
				mode = SVC_MODE_SETUP_INSTALL;
			}
			if (StrCmpi(arg, SVC_ARG_SETUP_UNINSTALL) == 0)
			{
				mode = SVC_MODE_SETUP_UNINSTALL;
			}
			if (StrCmpi(arg, SVC_ARG_USERMODE_SHOWTRAY) == 0 || StrCmpi(arg, SVC_ARG_USERMODE_HIDETRAY) == 0)
			{
				// Legacy arguments: there is no task tray icon any more, so these are the same as /usermode
				mode = SVC_MODE_USERMODE;
			}
			if (StrCmpi(arg, SVC_ARG_SERVICE) == 0)
			{
				mode = SVC_MODE_SERVICE;
			}
		}

		UniFormat(path, sizeof(path), SVC_RUN_COMMANDLINE, ms->ExeFileNameW);

		if ((mode == SVC_MODE_INSTALL || mode == SVC_MODE_UNINSTALL || mode == SVC_MODE_START ||
			mode == SVC_MODE_STOP || mode == SVC_MODE_SERVICE) &&
			(ms->IsAdmin == false))
		{
			UniPrint(L"%s\n", _UU("SVC_NOT_ADMIN"));
		}
		else
		{
			switch (mode)
			{
			case SVC_MODE_NONE:
				MsSvcMsg(false, "SVC_HELP",
					service_title, service_name, service_title, service_title, service_name, service_title, service_name, service_title, service_name, service_title, service_name, service_title, service_title);
				break;

			case SVC_MODE_SETUP_INSTALL:
				MsWriteCallingServiceManagerProcessId(service_name, MsGetCurrentProcessId());
				restoreReg = true;

				if (MsIsServiceInstalled(service_name))
				{
					if (MsIsServiceRunning(service_name))
					{
						MsStopService(service_name);
					}
					MsUninstallService(service_name);
				}
				if (MsInstallServiceExW(service_name, service_title, service_description, path) == false)
				{
					ret = 1;
				}
				MsStartService(service_name);
				MsWriteCallingServiceManagerProcessId(service_name, 0);
				break;

			case SVC_MODE_SETUP_UNINSTALL:
				MsWriteCallingServiceManagerProcessId(service_name, MsGetCurrentProcessId());
				restoreReg = true;

				if (MsIsServiceInstalled(service_name))
				{
					if (MsIsServiceRunning(service_name))
					{
						MsStopService(service_name);
					}
					if (MsUninstallService(service_name) == false)
					{
						ret = 1;
					}
				}
				break;

			case SVC_MODE_INSTALL:
				MsWriteCallingServiceManagerProcessId(service_name, MsGetCurrentProcessId());
				restoreReg = true;

				if (MsIsServiceInstalled(service_name))
				{
					if(silent == true)
					{
						break;
					}
					// The operator explicitly requested /install, so uninstall and then re-install
					MsSvcMsg(silent, "SVC_ALREADY_INSTALLED", service_title, service_name);

					if (MsIsServiceRunning(service_name))
					{
						if (MsStopService(service_name) == false)
						{
							MsSvcMsg(silent, "SVC_STOP_FAILED", service_title, service_name);
							break;
						}
					}
					if (MsUninstallService(service_name) == false)
					{
						MsSvcMsg(silent, "SVC_UNINSTALL_FAILED", service_title, service_name);
						break;
					}
				}

				if (MsInstallServiceExW(service_name, service_title, service_description, path) == false)
				{
					MsSvcMsg(silent, "SVC_INSTALL_FAILED", service_title, service_name);
					break;
				}

				if (MsStartService(service_name) == false)
				{
					MsSvcMsg(silent, "SVC_INSTALL_FAILED_2", service_title, service_name, path);
					break;
				}

				MsSvcMsg(silent, "SVC_INSTALL_OK", service_title, service_name, path);
				break;

			case SVC_MODE_UNINSTALL:
				MsWriteCallingServiceManagerProcessId(service_name, MsGetCurrentProcessId());
				restoreReg = true;

				if (MsIsServiceInstalled(service_name) == false)
				{
					MsSvcMsg(silent, "SVC_NOT_INSTALLED", service_title, service_name, path);
					break;
				}

				if (MsIsServiceRunning(service_name))
				{
					if (MsStopService(service_name) == false)
					{
						MsSvcMsg(silent, "SVC_STOP_FAILED", service_title, service_name);
						break;
					}
				}

				if (MsUninstallService(service_name) == false)
				{
					MsSvcMsg(silent, "SVC_UNINSTALL_FAILED", service_title, service_name);
					break;
				}

				MsSvcMsg(silent, "SVC_UNINSTALL_OK", service_title, service_name);
				break;

			case SVC_MODE_START:
				MsWriteCallingServiceManagerProcessId(service_name, MsGetCurrentProcessId());
				restoreReg = true;

				if (MsIsServiceInstalled(service_name) == false)
				{
					MsSvcMsg(silent, "SVC_NOT_INSTALLED", service_title, service_name);
					break;
				}

				if (MsIsServiceRunning(service_name))
				{
					MsSvcMsg(silent, "SVR_ALREADY_START", service_title, service_name);
					break;
				}

				if (MsStartService(service_name) == false)
				{
					MsSvcMsg(silent, "SVC_START_FAILED", service_title, service_name);
					break;
				}

				MsSvcMsg(silent, "SVC_START_OK", service_title, service_name);
				break;

			case SVC_MODE_STOP:
				MsWriteCallingServiceManagerProcessId(service_name, MsGetCurrentProcessId());
				restoreReg = true;

				if (MsIsServiceInstalled(service_name) == false)
				{
					MsSvcMsg(silent, "SVC_NOT_INSTALLED", service_title, service_name);
					break;
				}

				if (MsIsServiceRunning(service_name) == false)
				{
					MsSvcMsg(silent, "SVC_ALREADY_STOP", service_title, service_name);
					break;
				}
				if (MsStopService(service_name) == false)
				{
					MsSvcMsg(silent, "SVC_STOP_FAILED", service_title, service_name);
					break;
				}

				MsSvcMsg(silent, "SVC_STOP_OK", service_title, service_name);
				break;

			case SVC_MODE_TEST:
				MsTestModeW(service_title, start, stop);
				break;
			case SVC_MODE_USERMODE:
				MsUserModeW(service_title, start, stop);
				break;
			case SVC_MODE_SERVICE:
				break;
			}

		}
		FreeToken(t);

		if (restoreReg)
		{
			MsWriteCallingServiceManagerProcessId(service_name, 0);
		}
	}

	FreeMayaqua();

	return ret;
}

// Wait up to 10 s, polling every 250 ms, until the service is running (running == true) or no longer
// running (running == false)
static void MsWaitServiceState(char *name, bool running)
{
	UINT64 end = Tick64() + 10000ULL;

	while (Tick64() < end)
	{
		if (MsIsServiceRunning(name) == running)
		{
			break;
		}

		SleepThread(250);
	}
}

bool MsStopService(char *name)
{
	SC_HANDLE sc, service;
	bool ret = false;
	if (name == NULL)
	{
		return false;
	}

	sc = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (sc == NULL)
	{
		return false;
	}

	service = OpenService(sc, name, SERVICE_ALL_ACCESS);
	if (service != NULL)
	{
		SERVICE_STATUS st;
		ret = ControlService(service, SERVICE_CONTROL_STOP, &st);

		CloseServiceHandle(service);
	}

	if (ret)
	{
		MsWaitServiceState(name, false);
	}

	CloseServiceHandle(sc);
	return ret;
}

bool MsStartService(char *name)
{
	SC_HANDLE sc, service;
	bool ret = false;
	if (name == NULL)
	{
		return false;
	}

	sc = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (sc == NULL)
	{
		return false;
	}

	service = OpenService(sc, name, SERVICE_ALL_ACCESS);
	if (service != NULL)
	{
		ret = StartService(service, 0, NULL);

		CloseServiceHandle(service);
	}

	if (ret)
	{
		MsWaitServiceState(name, true);
	}

	CloseServiceHandle(sc);
	return ret;
}

bool MsIsServiceRunning(char *name)
{
	SC_HANDLE sc, service;
	bool ret = false;
	if (name == NULL || IsEmptyStr(name))
	{
		return false;
	}

	sc = OpenSCManager(NULL, NULL, GENERIC_READ);
	if (sc == NULL)
	{
		return false;
	}

	service = OpenService(sc, name, GENERIC_READ);
	if (service != NULL)
	{
		SERVICE_STATUS st;
		Zero(&st, sizeof(st));
		if (QueryServiceStatus(service, &st))
		{
			switch (st.dwCurrentState)
			{
			case SERVICE_CONTINUE_PENDING:
			case SERVICE_PAUSE_PENDING:
			case SERVICE_PAUSED:
			case SERVICE_RUNNING:
			case SERVICE_START_PENDING:
			case SERVICE_STOP_PENDING:
				ret = true;
				break;
			}
		}

		CloseServiceHandle(service);
	}

	CloseServiceHandle(sc);
	return ret;
}

bool MsUninstallService(char *name)
{
	SC_HANDLE sc, service;
	bool ret = false;
	if (name == NULL)
	{
		return false;
	}

	MsStopService(name);

	sc = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (sc == NULL)
	{
		return false;
	}

	service = OpenService(sc, name, SERVICE_ALL_ACCESS);
	if (service != NULL)
	{
		if (DeleteService(service))
		{
			ret = true;
		}
		CloseServiceHandle(service);
	}

	CloseServiceHandle(sc);

	if (ret)
	{
		SleepThread(2000);
	}

	return ret;
}

// Recovery of the service: restart it 10 s after each of its first three failures, and count the
// failures from zero again after a day without one. The handle needs SERVICE_CHANGE_CONFIG, and
// SERVICE_START for the restart actions.
static void MsSetServiceRecovery(SC_HANDLE service)
{
	SERVICE_FAILURE_ACTIONS action;
	SC_ACTION e[3];
	UINT i;

	Zero(&action, sizeof(action));
	action.dwResetPeriod = 1 * 60 * 60 * 24;
	action.cActions = (DWORD)(sizeof(e) / sizeof(e[0]));
	action.lpsaActions = e;

	for (i = 0;i < action.cActions;i++)
	{
		e[i].Type = SC_ACTION_RESTART;
		e[i].Delay = 10000;
	}

	ChangeServiceConfig2(service, SERVICE_CONFIG_FAILURE_ACTIONS, &action);
}

bool MsUpdateServiceConfig(char *name)
{
	SC_HANDLE sc, service;
	if (name == NULL)
	{
		return false;
	}

	// Shortly after Windows startup (prevents a deadlock)
	if (timeGetTime() <= (60 * 30 * 1000))
	{
		if (MsRegReadInt(REG_LOCAL_MACHINE, "Software\\" GC_REG_COMPANY_NAME "\\Update Service Config", name) != 0)
		{
			return false;
		}
	}

	sc = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
	if (sc == NULL)
	{
		return false;
	}

	// ChangeServiceConfig2 needs SERVICE_CHANGE_CONFIG, and SERVICE_START for the restart actions
	service = OpenService(sc, name, SERVICE_CHANGE_CONFIG | SERVICE_START);
	if (service != NULL)
	{
		SERVICE_DESCRIPTIONW d;
		wchar_t *description;
		char dname[MAX_SIZE];

		MsSetServiceRecovery(service);

		MsRegWriteInt(REG_LOCAL_MACHINE, "Software\\" GC_REG_COMPANY_NAME "\\Update Service Config", name, 1);

		Format(dname, sizeof(dname), "SVC_%s_DESCRIPT", name);

		description = _UU(dname);

		if (UniIsEmptyStr(description) == false)
		{
			Zero(&d, sizeof(d));
			d.lpDescription = description;
			ChangeServiceConfig2(service, SERVICE_CONFIG_DESCRIPTION, &d);
		}

		CloseServiceHandle(service);
	}

	CloseServiceHandle(sc);

	return true;
}

bool MsInstallServiceExW(char *name, wchar_t *title, wchar_t *description, wchar_t *path)
{
	SC_HANDLE sc, service;
	bool ret = false;
	wchar_t name_w[MAX_SIZE];
	if (name == NULL || title == NULL || path == NULL)
	{
		return false;
	}

	StrToUni(name_w, sizeof(name_w), name);

	sc = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (sc == NULL)
	{
		return false;
	}

	service = CreateServiceW(sc, name_w, title, SERVICE_ALL_ACCESS,
		SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START,
		SERVICE_ERROR_NORMAL, path, NULL, NULL, NULL, NULL, NULL);

	if (service != NULL)
	{
		SERVICE_DESCRIPTIONW d;

		ret = true;

		Zero(&d, sizeof(d));
		d.lpDescription = description;
		ChangeServiceConfig2(service, SERVICE_CONFIG_DESCRIPTION, &d);

		MsSetServiceRecovery(service);

		CloseServiceHandle(service);
	}

	CloseServiceHandle(sc);

	if (ret)
	{
		SleepThread(2000);
	}

	return ret;
}

bool MsIsServiceInstalled(char *name)
{
	SC_HANDLE sc;
	SC_HANDLE service;
	bool ret = false;
	if (name == NULL)
	{
		return false;
	}

	sc = OpenSCManager(NULL, NULL, GENERIC_READ);
	if (sc == NULL)
	{
		return false;
	}

	service = OpenService(sc, name, GENERIC_READ);
	if (service != NULL)
	{
		ret = true;
	}

	CloseServiceHandle(service);
	CloseServiceHandle(sc);

	return ret;
}

void MsSetThreadPriorityIdle()
{
	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_IDLE);
}

void MsSetThreadPriorityRealtime()
{
	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
}

void MsRestoreThreadPriority()
{
	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_NORMAL);
}

// Temp directory of the process: %TEMP%\VPN_ and 16 hex digits of the CNG generator (64 bits),
// so the name cannot be guessed and created first. The protected DACL inherits nothing from
// %TEMP% (C:\Windows\Temp for the service, where every user can add files and folders): full
// access for SYSTEM, Administrators and the owner of the directory (the user who runs the
// process), nothing for anyone else.
#define	MS_TEMP_DIR_RANDOM_SIZE	8
#define	MS_TEMP_DIR_NAME_LEN	(4 + MS_TEMP_DIR_RANDOM_SIZE * 2)	// "VPN_" and the hex digits
#define	MS_TEMP_DIR_SDDL		L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;OW)"

// Delete the temp directories that earlier processes left in %TEMP% (no lock file, or one no process
// holds). A reparse point named like one (a junction or a symbolic link, which anyone who can write
// to %TEMP% can make) is no temp directory of this program: it is left alone and never followed.
static void MsDeleteTempDir()
{
	HANDLE h;
	wchar_t dir_mask[MAX_PATH];
	WIN32_FIND_DATAW data_w;

	Zero(&data_w, sizeof(data_w));

	UniFormat(dir_mask, sizeof(dir_mask), L"%s\\*", ms->TempDirW);

	h = FindFirstFileW(dir_mask, &data_w);

	if (h != INVALID_HANDLE_VALUE)
	{
		bool b = true;

		do
		{
			if (UniStrCmpi(data_w.cFileName, L".") != 0 &&
				UniStrCmpi(data_w.cFileName, L"..") != 0)
			{
				if ((data_w.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
					(data_w.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0)
				{
					if (UniStartWith(data_w.cFileName, L"VPN_") && UniStrLen(data_w.cFileName) == MS_TEMP_DIR_NAME_LEN)
					{
						wchar_t lock_file_name[MAX_PATH];
						wchar_t dir_name[MAX_PATH];
						bool delete_now = false;
						IO *io;

						UniFormat(dir_name, sizeof(dir_name), L"%s\\%s",
							ms->TempDirW, data_w.cFileName);
						MsGenLockFile(lock_file_name, sizeof(lock_file_name), dir_name);

						io = FileOpenExW(lock_file_name, false, false);
						if (io != NULL)
						{
							FileClose(io);
							io = FileOpenW(lock_file_name, true);
							if (io != NULL)
							{
								delete_now = true;
								FileClose(io);
							}
						}
						else
						{
							DIRLIST *d;

							delete_now = true;

							d = EnumDirW(dir_name);
							if (d != NULL)
							{
								UINT i;

								for (i = 0;i < d->NumFiles;i++)
								{
									wchar_t full_path[MAX_PATH];

									UniFormat(full_path, sizeof(full_path), L"%s\\%s", dir_name, d->File[i]->FileNameW);

									io = FileOpenW(full_path, true);
									if (io != NULL)
									{
										delete_now = true;
										FileClose(io);
									}
								}
								FreeDir(d);
							}
						}
						if (delete_now)
						{
							MsDeleteAllFileW(dir_name);

							Win32DeleteDirW(dir_name);
						}
					}
				}
			}


			Zero(&data_w, sizeof(data_w));

			b = FindNextFileW(h, &data_w);
		}
		while (b);

		FindClose(h);
	}
}

// Delete the files and subdirectories of dir, never through a reparse point. dir is opened without
// following a reparse point and left alone when it is one. A junction or a symbolic link in it goes
// as a link: RemoveDirectoryW and DeleteFileW remove the link, not its target. dir stays open
// without delete or write sharing while its entries go, so that it cannot be renamed or replaced
// in the meantime.
void MsDeleteAllFileW(wchar_t *dir)
{
	HANDLE h;
	HANDLE dir_handle;
	BY_HANDLE_FILE_INFORMATION info;
	wchar_t file_mask[MAX_PATH];
	WIN32_FIND_DATAW data;
	if (dir == NULL || UniIsEmptyStr(dir))
	{
		return;
	}

	dir_handle = CreateFileW(dir, FILE_LIST_DIRECTORY, FILE_SHARE_READ, NULL, OPEN_EXISTING,
		FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
	if (dir_handle == INVALID_HANDLE_VALUE)
	{
		return;
	}

	Zero(&info, sizeof(info));
	if (GetFileInformationByHandle(dir_handle, &info) == FALSE ||
		(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
		(info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
	{
		CloseHandle(dir_handle);
		return;
	}

	UniFormat(file_mask, sizeof(file_mask), L"%s\\*.*", dir);

	h = FindFirstFileW(file_mask, &data);
	if (h != INVALID_HANDLE_VALUE)
	{
		do
		{
			if (UniStrCmpi(data.cFileName, L".") != 0 &&
				UniStrCmpi(data.cFileName, L"..") != 0)
			{
				wchar_t fullpath[MAX_PATH];

				UniFormat(fullpath, sizeof(fullpath), L"%s\\%s", dir, data.cFileName);

				if ((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
				{
					DeleteFileW(fullpath);
				}
				else
				{
					if ((data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0)
					{
						MsDeleteAllFileW(fullpath);
					}

					RemoveDirectoryW(fullpath);
				}
			}
		}
		while (FindNextFileW(h, &data));

		FindClose(h);
	}

	CloseHandle(dir_handle);
}

static void MsInitTempDir()
{
	wchar_t tmp[MAX_PATH];
	wchar_t tmp2[MS_TEMP_DIR_RANDOM_SIZE * 2 + 1];
	UCHAR random[MS_TEMP_DIR_RANDOM_SIZE];
	wchar_t lockfilename[MAX_PATH];
	SECURITY_ATTRIBUTES sa;
	PSECURITY_DESCRIPTOR sd = NULL;
	UINT num = 0;

	MsDeleteTempDir();

	if (ConvertStringSecurityDescriptorToSecurityDescriptorW(MS_TEMP_DIR_SDDL, SDDL_REVISION_1, &sd, NULL) == FALSE)
	{
		AbortExitEx("MsInitTempDir(): ConvertStringSecurityDescriptorToSecurityDescriptorW() failed");
	}

	Zero(&sa, sizeof(sa));
	sa.nLength = sizeof(sa);
	sa.lpSecurityDescriptor = sd;
	sa.bInheritHandle = FALSE;

	while (true)
	{
		Rand(random, sizeof(random));
		BinToStrW(tmp2, sizeof(tmp2), random, sizeof(random));

		UniFormat(tmp, sizeof(tmp), L"%s\\VPN_%s", ms->TempDirW, tmp2);

		// Fails when the name exists, so the directory is always a new one made here
		if (CreateDirectoryW(tmp, &sa))
		{
			break;
		}

		if ((num++) >= 100)
		{
			char msg[MAX_SIZE];
			Format(msg, sizeof(msg),
				"Couldn't create Temporary Directory: %s\r\n\r\n"
				"Please contact your system administrator.",
				tmp);
			exit(0);
		}
	}

	LocalFree(sd);

	ms->MyTempDirW = CopyUniStr(tmp);
	ms->MyTempDir = CopyUniToStr(tmp);

	MsGenLockFile(lockfilename, sizeof(lockfilename), ms->MyTempDirW);
	ms->LockFile = FileCreateW(lockfilename);
}

static void MsFreeTempDir()
{
	wchar_t lock_file_name[MAX_SIZE];

	MsGenLockFile(lock_file_name, sizeof(lock_file_name), ms->MyTempDirW);
	FileClose(ms->LockFile);

	Free(ms->MyTempDir);
	Free(ms->MyTempDirW);
	ms->MyTempDir = NULL;
	ms->MyTempDirW = NULL;

	MsDeleteTempDir();
}

void MsGenLockFile(wchar_t *name, UINT size, wchar_t *temp_dir)
{
	if (name == NULL || temp_dir == NULL)
	{
		return;
	}

	UniFormat(name, size, L"%s\\VPN_Lock.dat", temp_dir);
}

wchar_t *MsGetNetworkConnectionName(char *guid)
{
	wchar_t *ncname = NULL;
	char tmp[MAX_SIZE];
	if (guid == NULL)
	{
		return NULL;
	}

	Format(tmp, sizeof(tmp), "SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\%s\\Connection", guid);
	ncname = MsRegReadStrEx2W(REG_LOCAL_MACHINE, tmp, "Name", false, false);

	return ncname;
}

bool MsCheckLogon(wchar_t *username, char *password)
{
	wchar_t password_unicode[MAX_SIZE];
	HANDLE h;
	if (username == NULL || password == NULL)
	{
		return false;
	}

	StrToUni(password_unicode, sizeof(password_unicode), password);

	if (LogonUserW(username, NULL, password_unicode, LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, &h) == false)
	{
		return false;
	}

	CloseHandle(h);

	return true;
}

bool MsEnablePrivilege(char *name, bool enable)
{
	HANDLE hToken;
	LUID luid;
	TOKEN_PRIVILEGES *tp;
	bool ret;
	if (name == NULL)
	{
		return false;
	}

	if (OpenProcessToken(ms->hCurrentProcess, TOKEN_ADJUST_PRIVILEGES, &hToken) == false)
	{
		return false;
	}

	if (LookupPrivilegeValue(NULL, name, &luid) == FALSE)
	{
		CloseHandle(hToken);
		return false;
	}

	tp = ZeroMalloc(sizeof(TOKEN_PRIVILEGES));
	tp->PrivilegeCount = 1;
	tp->Privileges[0].Attributes = enable ? SE_PRIVILEGE_ENABLED : 0;
	Copy(&tp->Privileges[0].Luid, &luid, sizeof(LUID));

	// AdjustTokenPrivileges also succeeds when the token does not hold the privilege; it then sets
	// ERROR_NOT_ALL_ASSIGNED
	ret = AdjustTokenPrivileges(hToken, false, tp, sizeof(TOKEN_PRIVILEGES), 0, 0) && GetLastError() == ERROR_SUCCESS;

	Free(tp);
	CloseHandle(hToken);

	return ret;
}

bool MsIsAdmin()
{
	return ms->IsAdmin;
}

// Access mask that forces the 32-bit or 64-bit registry view
static UINT MsRegAccessMaskFor64BitEx(bool force32bit, bool force64bit)
{
	if (force32bit)
	{
		return KEY_WOW64_32KEY;
	}
	if (force64bit)
	{
		return KEY_WOW64_64KEY;
	}

	return 0;
}

bool MsRegLoadHive(UINT root, wchar_t *keyname, wchar_t *filename)
{
	LONG ret;
	if (keyname == NULL || filename == NULL)
	{
		return false;
	}
	ret = RegLoadKeyW(MsGetRootKeyFromInt(root), keyname, filename);

	if (ret != ERROR_SUCCESS)
	{
		return false;
	}

	return true;
}

bool MsRegDeleteValue(UINT root, char *keyname, char *valuename)
{
	return MsRegDeleteValueEx2(root, keyname, valuename, false, false);
}
bool MsRegDeleteValueEx2(UINT root, char *keyname, char *valuename, bool force32bit, bool force64bit)
{
	HKEY h;
	bool ret;
	if (keyname == NULL)
	{
		return false;
	}

	// RegDeleteValue needs KEY_SET_VALUE only
	if (RegOpenKeyEx(MsGetRootKeyFromInt(root), keyname, 0, KEY_SET_VALUE | MsRegAccessMaskFor64BitEx(force32bit, force64bit), &h) != ERROR_SUCCESS)
	{
		return false;
	}

	if (RegDeleteValue(h, valuename) != ERROR_SUCCESS)
	{
		ret = false;
	}
	else
	{
		ret = true;
	}

	RegCloseKey(h);

	return ret;
}

bool MsRegDeleteKeyEx2(UINT root, char *keyname, bool force32bit, bool force64bit)
{
	if (keyname == NULL)
	{
		return false;
	}

	if (RegDeleteKeyExA(MsGetRootKeyFromInt(root), keyname, MsRegAccessMaskFor64BitEx(force32bit, force64bit), 0) != ERROR_SUCCESS)
	{
		return false;
	}

	return true;
}

TOKEN_LIST *MsRegEnumKey(UINT root, char *keyname)
{
	return MsRegEnumKeyEx2(root, keyname, false, false);
}
TOKEN_LIST *MsRegEnumKeyEx2(UINT root, char *keyname, bool force32bit, bool force64bit)
{
	HKEY h;
	UINT i;
	TOKEN_LIST *t;
	LIST *o;

	if (keyname == NULL)
	{
		h = MsGetRootKeyFromInt(root);
	}
	else
	{
		if (RegOpenKeyEx(MsGetRootKeyFromInt(root), keyname, 0, KEY_READ | MsRegAccessMaskFor64BitEx(force32bit, force64bit), &h) != ERROR_SUCCESS)
		{
			return NULL;
		}
	}

	o = NewListFast(CompareStr);

	for (i = 0;;i++)
	{
		char tmp[MAX_SIZE];
		UINT ret;
		DWORD size = sizeof(tmp);
		FILETIME ft;

		Zero(tmp, sizeof(tmp));
		ret = RegEnumKeyEx(h, i, tmp, &size, NULL, NULL, NULL, &ft);
		if (ret == ERROR_NO_MORE_ITEMS)
		{
			break;
		}
		else if (ret != ERROR_SUCCESS)
		{
			break;
		}

		Add(o, CopyStr(tmp));
	}

	Sort(o);

	t = ZeroMalloc(sizeof(TOKEN_LIST));
	t->NumTokens = LIST_NUM(o);
	t->Token = ZeroMalloc(sizeof(char *) * t->NumTokens);
	for (i = 0;i < t->NumTokens;i++)
	{
		t->Token[i] = LIST_DATA(o, i);
	}

	ReleaseList(o);

	if (keyname != NULL)
	{
		RegCloseKey(h);
	}

	return t;
}

bool MsRegWriteInt(UINT root, char *keyname, char *valuename, UINT value)
{
	return MsRegWriteIntEx2(root, keyname, valuename, value, false, false);
}
bool MsRegWriteIntEx2(UINT root, char *keyname, char *valuename, UINT value, bool force32bit, bool force64bit)
{
	if (keyname == NULL)
	{
		return false;
	}

	if (IsBigEndian())
	{
		value = Swap32(value);
	}

	return MsRegWriteValueEx2(root, keyname, valuename, REG_DWORD_LITTLE_ENDIAN, &value, sizeof(UINT), force32bit, force64bit);
}

bool MsRegWriteStr(UINT root, char *keyname, char *valuename, char *str)
{
	return MsRegWriteStrEx2(root, keyname, valuename, str, false, false);
}
bool MsRegWriteStrEx2(UINT root, char *keyname, char *valuename, char *str, bool force32bit, bool force64bit)
{
	if (keyname == NULL || str == NULL)
	{
		return false;
	}

	return MsRegWriteValueEx2(root, keyname, valuename, REG_SZ, str, StrSize(str), force32bit, force64bit);
}

bool MsRegWriteValueEx2(UINT root, char *keyname, char *valuename, UINT type, void *data, UINT size, bool force32bit, bool force64bit)
{
	HKEY h;
	if (keyname == NULL || (size != 0 && data == NULL))
	{
		return false;
	}

	MsRegNewKeyEx2(root, keyname, force32bit, force64bit);

	// RegSetValueEx needs KEY_SET_VALUE only
	if (RegOpenKeyEx(MsGetRootKeyFromInt(root), keyname, 0, KEY_SET_VALUE | MsRegAccessMaskFor64BitEx(force32bit, force64bit), &h) != ERROR_SUCCESS)
	{
		return false;
	}

	if (RegSetValueEx(h, valuename, 0, type, data, size) != ERROR_SUCCESS)
	{
		RegCloseKey(h);
		return false;
	}

	RegCloseKey(h);

	return true;
}

UINT MsRegReadInt(UINT root, char *keyname, char *valuename)
{
	return MsRegReadIntEx2(root, keyname, valuename, false, false);
}
UINT MsRegReadIntEx2(UINT root, char *keyname, char *valuename, bool force32bit, bool force64bit)
{
	char *ret;
	DWORD type, size;
	UINT value;
	if (keyname == NULL || valuename == NULL)
	{
		return 0;
	}

	if (MsRegReadValueEx2(root, keyname, valuename, (void **)&ret, &type, &size, force32bit, force64bit) == false)
	{
		return 0;
	}

	if (type != REG_DWORD_LITTLE_ENDIAN && type != REG_DWORD_BIG_ENDIAN)
	{
		Free(ret);
		return 0;
	}

	if (size != sizeof(UINT))
	{
		Free(ret);
		return 0;
	}

	Copy(&value, ret, sizeof(UINT));

	Free(ret);

	if (IsLittleEndian())
	{
#ifdef	REG_DWORD_BIG_ENDIAN
		if (type == REG_DWORD_BIG_ENDIAN)
		{
			value = Swap32(value);
		}
#endif	// REG_DWORD_BIG_ENDIAN
	}
	else
	{
#ifdef	REG_DWORD_LITTLE_ENDIAN_FLAG
		if (type == REG_DWORD_LITTLE_ENDIAN_FLAG)
		{
			value = Swap32(value);
		}
#endif	// REG_DWORD_LITTLE_ENDIAN_FLAG
	}

	return value;
}

char *MsRegReadStr(UINT root, char *keyname, char *valuename)
{
	return MsRegReadStrEx2(root, keyname, valuename, false, false);
}
char *MsRegReadStrEx2(UINT root, char *keyname, char *valuename, bool force32bit, bool force64bit)
{
	char *ret;
	DWORD type, size;
	if (keyname == NULL || valuename == NULL)
	{
		return NULL;
	}

	if (MsRegReadValueEx2(root, keyname, valuename, (void **)&ret, &type, &size, force32bit, force64bit) == false)
	{
		return NULL;
	}

	// A REG_MULTI_SZ reads as its first string: the buffer ends with a terminator (checked below)
	// and the first string ends at its first one
	if (type != REG_SZ && type != REG_EXPAND_SZ && type != REG_MULTI_SZ)
	{
		Free(ret);
		return NULL;
	}

	if (size == 0)
	{
		Free(ret);

		return CopyStr("");
	}

	if (ret[size - 1] != 0)
	{
		Free(ret);
		return NULL;
	}

	return ret;
}
wchar_t *MsRegReadStrEx2W(UINT root, char *keyname, char *valuename, bool force32bit, bool force64bit)
{
	wchar_t *ret;
	DWORD type, size;
	if (keyname == NULL || valuename == NULL)
	{
		return NULL;
	}

	if (MsRegReadValueEx2W(root, keyname, valuename, (void **)&ret, &type, &size, force32bit, force64bit) == false)
	{
		return NULL;
	}

	if (type != REG_SZ && type != REG_EXPAND_SZ)
	{
		Free(ret);

		return NULL;
	}

	if (size < sizeof(wchar_t))
	{
		// An empty value, or one byte: no whole character, and no last character to test below
		Free(ret);

		return CopyUniStr(L"");
	}

	if (ret[size / sizeof(wchar_t) - 1] != 0)
	{
		Free(ret);
		return NULL;
	}

	return ret;
}

bool MsRegReadValueEx2(UINT root, char *keyname, char *valuename, void **data, DWORD *type, DWORD *size, bool force32bit, bool force64bit)
{
	HKEY h;
	UINT ret;
	if (keyname == NULL || data == NULL || type == NULL || size == NULL)
	{
		return false;
	}
	*type = 0;
	*size = 0;

	if (RegOpenKeyEx(MsGetRootKeyFromInt(root), keyname, 0, KEY_QUERY_VALUE | MsRegAccessMaskFor64BitEx(force32bit, force64bit), &h) != ERROR_SUCCESS)
	{
		return false;
	}

	*data = ZeroMalloc(*size);
	ret = RegQueryValueEx(h, valuename, 0, type, *data, size);

	if (ret == ERROR_MORE_DATA)
	{
		// Again with the size the first query gave
		*data = ReAlloc(*data, *size);
		ret = RegQueryValueEx(h, valuename, 0, type, *data, size);
	}

	RegCloseKey(h);

	if (ret != ERROR_SUCCESS)
	{
		// Also when the value grew or went away between the two queries: no data, no success
		Free(*data);
		*data = NULL;
		return false;
	}

	return true;
}
bool MsRegReadValueEx2W(UINT root, char *keyname, char *valuename, void **data, DWORD *type, DWORD *size, bool force32bit, bool force64bit)
{
	HKEY h;
	UINT ret;
	wchar_t *valuename_w;
	if (keyname == NULL || data == NULL || type == NULL || size == NULL)
	{
		return false;
	}
	*type = 0;
	*size = 0;

	if (RegOpenKeyEx(MsGetRootKeyFromInt(root), keyname, 0, KEY_QUERY_VALUE | MsRegAccessMaskFor64BitEx(force32bit, force64bit), &h) != ERROR_SUCCESS)
	{
		return false;
	}

	valuename_w = CopyStrToUni(valuename);

	*data = ZeroMalloc(*size);
	ret = RegQueryValueExW(h, valuename_w, 0, type, *data, size);

	if (ret == ERROR_MORE_DATA)
	{
		// Again with the size the first query gave
		*data = ReAlloc(*data, *size);
		ret = RegQueryValueExW(h, valuename_w, 0, type, *data, size);
	}

	Free(valuename_w);

	RegCloseKey(h);

	if (ret != ERROR_SUCCESS)
	{
		// Also when the value grew or went away between the two queries: no data, no success
		Free(*data);
		*data = NULL;
		return false;
	}

	return true;
}

bool MsRegIsValue(UINT root, char *keyname, char *valuename)
{
	return MsRegIsValueEx2(root, keyname, valuename, false, false);
}
bool MsRegIsValueEx2(UINT root, char *keyname, char *valuename, bool force32bit, bool force64bit)
{
	HKEY h;
	DWORD type, size;
	UINT ret;
	if (keyname == NULL)
	{
		return false;
	}

	if (RegOpenKeyEx(MsGetRootKeyFromInt(root), keyname, 0, KEY_QUERY_VALUE | MsRegAccessMaskFor64BitEx(force32bit, force64bit), &h) != ERROR_SUCCESS)
	{
		return false;
	}

	size = 0;
	ret = RegQueryValueEx(h, valuename, 0, &type, NULL, &size);

	if (ret == ERROR_SUCCESS || ret == ERROR_MORE_DATA)
	{
		RegCloseKey(h);
		return true;
	}

	RegCloseKey(h);

	return false;
}

bool MsRegNewKeyEx2(UINT root, char *keyname, bool force32bit, bool force64bit)
{
	HKEY h;
	if (keyname == NULL)
	{
		return false;
	}

	if (MsRegIsKeyEx2(root, keyname, force32bit, force64bit))
	{
		return true;
	}

	// The handle is closed at once, so it asks for little. Creating the key needs KEY_CREATE_SUB_KEY
	// on the parent key, which RegCreateKeyEx checks by itself.
	if (RegCreateKeyEx(MsGetRootKeyFromInt(root), keyname, 0, NULL, REG_OPTION_NON_VOLATILE,
		KEY_QUERY_VALUE | MsRegAccessMaskFor64BitEx(force32bit, force64bit), NULL, &h, NULL) != ERROR_SUCCESS)
	{
		return false;
	}

	RegCloseKey(h);

	return true;
}

bool MsRegIsKeyEx2(UINT root, char *name, bool force32bit, bool force64bit)
{
	HKEY h;
	if (name == NULL)
	{
		return false;
	}

	if (RegOpenKeyEx(MsGetRootKeyFromInt(root), name, 0, KEY_READ | MsRegAccessMaskFor64BitEx(force32bit, force64bit), &h) != ERROR_SUCCESS)
	{
		return false;
	}

	RegCloseKey(h);

	return true;
}

HKEY MsGetRootKeyFromInt(UINT root)
{
	switch (root)
	{
	case REG_CLASSES_ROOT:
		return HKEY_CLASSES_ROOT;

	case REG_LOCAL_MACHINE:
		return HKEY_LOCAL_MACHINE;

	case REG_CURRENT_USER:
		return HKEY_CURRENT_USER;

	case REG_USERS:
		return HKEY_USERS;
	}

	return NULL;
}

UINT MsGetCurrentProcessId()
{
	return ms->CurrentProcessId;
}

char *MsGetExeDirName()
{
	return ms->ExeFileDir;
}

static char *MsGetSpecialDir(int id)
{
	LPITEMIDLIST t = NULL;
	char tmp[MAX_PATH];

	if (SHGetSpecialFolderLocation(NULL, id, &t) != S_OK)
	{
		return CopyStr(ms->ExeFileDir);
	}

	if (SHGetPathFromIDList(t, tmp) == false)
	{
		return CopyStr(ms->ExeFileDir);
	}

	Win32NukuEn(tmp, sizeof(tmp), tmp);

	return CopyStr(tmp);
}
static wchar_t *MsGetSpecialDirW(int id)
{
	LPITEMIDLIST t = NULL;
	wchar_t tmp[MAX_PATH];

	if (SHGetSpecialFolderLocation(NULL, id, &t) != S_OK)
	{
		return UniCopyStr(ms->ExeFileDirW);
	}

	if (SHGetPathFromIDListW(t, tmp) == false)
	{
		return UniCopyStr(ms->ExeFileDirW);
	}

	Win32NukuEnW(tmp, sizeof(tmp), tmp);

	return UniCopyStr(tmp);
}

static void MsGetSpecialDirs()
{
	char tmp[MAX_PATH];

	GetSystemDirectory(tmp, sizeof(tmp));
	Win32NukuEn(tmp, sizeof(tmp), tmp);
	ms->System32Dir = CopyStr(tmp);
	ms->System32DirW = CopyStrToUni(tmp);

	// The Windows directory is parent of the System32 directory
	Win32GetDirFromPath(tmp, sizeof(tmp), tmp);
	Win32NukuEn(tmp, sizeof(tmp), tmp);
	ms->WindowsDir = CopyStr(tmp);
	ms->WindowsDirW = CopyStrToUni(tmp);

	Format(tmp, sizeof(tmp), "%s\\Temp", ms->WindowsDir);
	ms->WinTempDir = CopyStr(tmp);
	ms->WinTempDirW = CopyStrToUni(tmp);
	MsUniMakeDirEx(ms->WinTempDirW);

	tmp[2] = 0;
	ms->WindowsDrive = CopyStr(tmp);
	ms->WindowsDriveW = CopyStrToUni(tmp);

	GetTempPath(MAX_PATH, tmp);
	Win32NukuEn(tmp, sizeof(tmp), tmp);
	ms->TempDir = CopyStr(tmp);

	{
		wchar_t tmp_w[MAX_PATH];

		GetTempPathW(MAX_PATH, tmp_w);
		Win32NukuEnW(tmp_w, sizeof(tmp_w), tmp_w);

		ms->TempDirW = CopyUniStr(tmp_w);
	}
	MakeDirExW(ms->TempDirW);
	MakeDirEx(ms->TempDir);

	ms->ProgramFilesDir = MsGetSpecialDir(CSIDL_PROGRAM_FILES);
	if (StrCmpi(ms->ProgramFilesDir, ms->ExeFileDir) == 0)
	{
		char tmp[MAX_PATH];
		Format(tmp, sizeof(tmp), "%s\\Program Files", ms->WindowsDrive);

		Free(ms->ProgramFilesDir);
		ms->ProgramFilesDir = CopyStr(tmp);
	}

	ms->ProgramFilesDirW = MsGetSpecialDirW(CSIDL_PROGRAM_FILES);
	if (UniStrCmpi(ms->ProgramFilesDirW, ms->ExeFileDirW) == 0)
	{
		wchar_t tmp[MAX_PATH];
		UniFormat(tmp, sizeof(tmp), L"%s\\Program Files", ms->WindowsDriveW);

		Free(ms->ProgramFilesDirW);
		ms->ProgramFilesDirW = UniCopyStr(tmp);
	}

	ms->ProgramFilesDirX86 = MsGetSpecialDir(CSIDL_PROGRAM_FILESX86);
	if (StrCmpi(ms->ProgramFilesDirX86, ms->ExeFileDir) == 0)
	{
		char tmp[MAX_PATH];
		Format(tmp, sizeof(tmp), "%s\\Program Files (x86)", ms->WindowsDrive);

		Free(ms->ProgramFilesDirX86);
		ms->ProgramFilesDirX86 = CopyStr(tmp);
	}

	ms->ProgramFilesDirX86W = MsGetSpecialDirW(CSIDL_PROGRAM_FILESX86);
	if (UniStrCmpi(ms->ProgramFilesDirX86W, ms->ExeFileDirW) == 0)
	{
		wchar_t tmp[MAX_PATH];
		UniFormat(tmp, sizeof(tmp), L"%s\\Program Files (x86)", ms->WindowsDriveW);

		Free(ms->ProgramFilesDirX86W);
		ms->ProgramFilesDirX86W = UniCopyStr(tmp);
	}

	ms->ProgramFilesDirX64 = CopyStr(ms->ProgramFilesDir);
	ms->ProgramFilesDirX64W = CopyUniStr(ms->ProgramFilesDirW);

	ms->CommonStartMenuDir = MsGetSpecialDir(CSIDL_COMMON_STARTMENU);
	ms->CommonStartMenuDirW = MsGetSpecialDirW(CSIDL_COMMON_STARTMENU);

	ms->CommonProgramsDir = MsGetSpecialDir(CSIDL_COMMON_PROGRAMS);
	ms->CommonProgramsDirW = MsGetSpecialDirW(CSIDL_COMMON_PROGRAMS);

	ms->CommonStartupDir = MsGetSpecialDir(CSIDL_COMMON_STARTUP);
	ms->CommonStartupDirW = MsGetSpecialDirW(CSIDL_COMMON_STARTUP);

	ms->CommonAppDataDir = MsGetSpecialDir(CSIDL_COMMON_APPDATA);
	ms->CommonAppDataDirW = MsGetSpecialDirW(CSIDL_COMMON_APPDATA);

	ms->CommonDesktopDir = MsGetSpecialDir(CSIDL_COMMON_DESKTOPDIRECTORY);
	ms->CommonDesktopDirW = MsGetSpecialDirW(CSIDL_COMMON_DESKTOPDIRECTORY);

	ms->LocalAppDataDir = MsGetSpecialDir(CSIDL_LOCAL_APPDATA);
	ms->LocalAppDataDirW = MsGetSpecialDirW(CSIDL_LOCAL_APPDATA);
}

// True when the process token is elevated: an elevated administrator or LocalSystem, not a standard
// user or an administrator filtered by UAC. Reads the token only; writes nothing.
static bool MsCheckIsAdmin()
{
	HANDLE token;
	TOKEN_ELEVATION elevation;
	DWORD size = 0;
	bool ret = false;

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token) == false)
	{
		return false;
	}

	Zero(&elevation, sizeof(elevation));
	if (GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size))
	{
		ret = (elevation.TokenIsElevated != 0);
	}

	CloseHandle(token);

	return ret;
}

void MsInit()
{
	char *str_ansi;
	wchar_t *str_unicode;
	char tmp[MAX_SIZE];
	DWORD size;
	if (ms != NULL)
	{
		return;
	}

	ms = ZeroMalloc(sizeof(MS));

	ms->hInst = GetModuleHandle(NULL);

	ms->hKernel32 = LoadLibrary("kernel32.dll");

	str_ansi = CopyStr(GetCommandLineA());
	Trim(str_ansi);
	str_unicode = UniCopyStr(GetCommandLineW());
	UniTrim(str_unicode);

	// PathGetArgs skips the program name, quoted or not, and the one space after it
	SetCommandLineStr(PathGetArgsA(str_ansi));
	SetCommandLineUniStr(PathGetArgsW(str_unicode));

	Free(str_unicode);
	Free(str_ansi);

	ms->IsAdmin = MsCheckIsAdmin();

	ms->hCurrentProcess = GetCurrentProcess();
	ms->CurrentProcessId = GetCurrentProcessId();

	GetModuleFileName(NULL, tmp, sizeof(tmp));
	ms->ExeFileName = CopyStr(tmp);
	Win32GetDirFromPath(tmp, sizeof(tmp), tmp);
	ms->ExeFileDir = CopyStr(tmp);

	{
		wchar_t tmp_w[MAX_SIZE];

		// The wide APIs below count wide characters, not bytes
		Win32GetExeNameW(tmp_w, ARRAYSIZE(tmp_w));
		ms->ExeFileNameW = CopyUniStr(tmp_w);

		Win32GetDirFromPathW(tmp_w, sizeof(tmp_w), tmp_w);
		ms->ExeFileDirW = CopyUniStr(tmp_w);
	}

	MsGetSpecialDirs();

	MsInitTempDir();

	size = sizeof(tmp);
	if (GetUserName(tmp, &size) == false)
	{
		tmp[0] = 0;
	}
	ms->UserName = CopyStr(tmp);

	wchar_t tmp_w[MAX_SIZE];

	size = ARRAYSIZE(tmp_w);
	if (GetUserNameW(tmp_w, &size) == false)
	{
		tmp_w[0] = 0;
	}
	ms->UserNameW = CopyUniStr(tmp_w);

	size = sizeof(tmp);
	if (GetUserNameExA(NameSamCompatible, tmp, &size))
	{
		ms->UserNameEx = CopyStr(tmp);
	}

	size = ARRAYSIZE(tmp_w);
	if (GetUserNameExW(NameSamCompatible, tmp_w, &size))
	{
		ms->UserNameExW = CopyUniStr(tmp_w);
	}

	if (ms->UserNameEx == NULL)
	{
		ms->UserNameEx = CopyStr(ms->UserName);
	}
	if (ms->UserNameExW == NULL)
	{
		ms->UserNameExW = CopyUniStr(ms->UserNameW);
	}

	if (true)
	{
		wchar_t tmp[MAX_PATH];
		if (MsIsAdmin())
		{
			CombinePathW(tmp, sizeof(tmp), ms->ExeFileDirW, L"vpn_debug\\dump");
		}
		else
		{
			CombinePathW(tmp, sizeof(tmp), ms->TempDirW, L"vpn_debug\\dump");
		}
		ms->MinidumpBaseFileNameW = CopyUniStr(tmp);
	}

	MsSetEnableMinidump(true);
	SetUnhandledExceptionFilter(MsExceptionHandler);
}

void MsSetEnableMinidump(bool enabled)
{
	ms->MiniDumpEnabled = enabled;
}

void MsWriteMinidump(wchar_t *filename, void *ex)
{
	wchar_t tmp[MAX_PATH];
	wchar_t dir[MAX_PATH];
	HANDLE h;
	MINIDUMP_EXCEPTION_INFORMATION info;
	struct _EXCEPTION_POINTERS *exp = (struct _EXCEPTION_POINTERS *)ex;

	if (filename != NULL)
	{
		UniStrCpy(tmp, sizeof(tmp), filename);
	}
	else
	{
		SYSTEMTIME tm;

		Zero(&tm, sizeof(tm));
		GetLocalTime(&tm);

		UniFormat(tmp, sizeof(tmp), L"%s_%04u%02u%02u_%02u%02u%02u.dmp",
			ms->MinidumpBaseFileNameW,
			tm.wYear, tm.wMonth, tm.wDay, tm.wHour, tm.wMinute, tm.wSecond);
	}

	GetDirNameFromFilePathW(dir, sizeof(dir), tmp);

	CreateDirectoryW(dir, NULL);

	Zero(&info, sizeof(info));

	if (exp != NULL)
	{
		info.ThreadId = GetCurrentThreadId();
		info.ExceptionPointers = exp;
		info.ClientPointers = true;
	}

	h = CreateFileW(tmp, GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (h != INVALID_HANDLE_VALUE)
	{
		MiniDumpWriteDump(ms->hCurrentProcess, ms->CurrentProcessId,
			h,
			MiniDumpNormal | MiniDumpWithFullMemory | MiniDumpWithDataSegs |
			MiniDumpWithHandleData
			,
			info.ThreadId == 0 ? NULL : &info, NULL, NULL);

		FlushFileBuffers(h);
		CloseHandle(h);
	}
}

LONG CALLBACK MsExceptionHandler(struct _EXCEPTION_POINTERS *ExceptionInfo)
{
	if (ms->MiniDumpEnabled)
	{
		MsWriteMinidump(NULL, ExceptionInfo);
	}

	return EXCEPTION_CONTINUE_SEARCH;
}

void MsFree()
{
	if (ms == NULL)
	{
		return;
	}

	MsFreeTempDir();

	Free(ms->WindowsDir);
	Free(ms->System32Dir);
	Free(ms->TempDir);
	Free(ms->WinTempDir);
	Free(ms->WindowsDrive);
	Free(ms->ProgramFilesDir);
	Free(ms->CommonStartMenuDir);
	Free(ms->CommonProgramsDir);
	Free(ms->CommonStartupDir);
	Free(ms->CommonAppDataDir);
	Free(ms->CommonDesktopDir);
	Free(ms->PersonalStartMenuDir);
	Free(ms->PersonalProgramsDir);
	Free(ms->PersonalStartupDir);
	Free(ms->PersonalAppDataDir);
	Free(ms->PersonalDesktopDir);
	Free(ms->MyDocumentsDir);
	Free(ms->ExeFileDir);
	Free(ms->ExeFileName);
	Free(ms->UserName);
	Free(ms->UserNameEx);
	Free(ms->LocalAppDataDir);
	Free(ms->ProgramFilesDirX86);
	Free(ms->ProgramFilesDirX64);
	Free(ms->WindowsDirW);
	Free(ms->System32DirW);
	Free(ms->TempDirW);
	Free(ms->WinTempDirW);
	Free(ms->WindowsDriveW);
	Free(ms->ProgramFilesDirW);
	Free(ms->CommonStartMenuDirW);
	Free(ms->CommonProgramsDirW);
	Free(ms->CommonStartupDirW);
	Free(ms->CommonAppDataDirW);
	Free(ms->CommonDesktopDirW);
	Free(ms->PersonalStartMenuDirW);
	Free(ms->PersonalProgramsDirW);
	Free(ms->PersonalStartupDirW);
	Free(ms->PersonalAppDataDirW);
	Free(ms->PersonalDesktopDirW);
	Free(ms->MyDocumentsDirW);
	Free(ms->ExeFileDirW);
	Free(ms->ExeFileNameW);
	Free(ms->UserNameW);
	Free(ms->UserNameExW);
	Free(ms->LocalAppDataDirW);
	Free(ms->MinidumpBaseFileNameW);
	Free(ms->ProgramFilesDirX86W);
	Free(ms->ProgramFilesDirX64W);

	Free(ms);
	ms = NULL;
}

wchar_t *MsGetWindowsDirW()
{
	return ms->WindowsDirW;
}
char *MsGetSystem32Dir()
{
	return ms->System32Dir;
}
char *MsGetTempDir()
{
	return ms->TempDir;
}
char *MsGetMyTempDir()
{
	return ms->MyTempDir;
}

wchar_t *MsGetExeFileNameW()
{
	return ms == NULL ? L"Unknown" : ms->ExeFileNameW;
}
wchar_t *MsGetSystem32DirW()
{
	return ms->System32DirW;
}
wchar_t *MsGetMyTempDirW()
{
	return ms->MyTempDirW;
}
wchar_t *MsGetUserNameW()
{
	return ms->UserNameW;
}

