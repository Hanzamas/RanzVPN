// MicrosoftSystem.c
// Windows system information: VM detection, user locale, computer name, console width

#define	MICROSOFT_C

#include "Microsoft.h"

#include "Internat.h"
#include "Memory.h"
#include "Str.h"

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
#include <Shlwapi.h>		// PathGetArgsW() of MsCopyProcessArgsW
#include <SoftPub.h>

#if defined(_M_X64) || defined(_M_IX86)
#include <intrin.h>		// __cpuid() of the VM detection
#endif	// defined(_M_X64) || defined(_M_IX86)
#include "MicrosoftInternal.h"

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

	for (UINT i = 1; index != 0 && pos < str_set_size; i++)
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

	for (UINT i = 0; i < sizeof(vm_names) / sizeof(vm_names[0]); i++)
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
