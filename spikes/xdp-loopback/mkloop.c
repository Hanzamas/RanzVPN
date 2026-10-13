//
// Creates or removes one root-enumerated Microsoft KM-TEST Loopback Adapter
// (*MSLOOP) from %windir%\inf\netloop.inf. Same steps as "devcon install
// netloop.inf *MSLOOP" and "devcon remove": SetupDiCreateDeviceInfo +
// DIF_REGISTERDEVICE + UpdateDriverForPlugAndPlayDevices, and DIF_REMOVE.
// Spike code, never merged.
//
//   mkloop.exe                       install one adapter, print
//                                    "mkloop: instance=<InstanceId>"
//   mkloop.exe remove <InstanceId>   remove that device, only when its first
//                                    hardware ID is *MSLOOP
//

#include <windows.h>
#include <setupapi.h>
#include <cfgmgr32.h>
#include <newdev.h>
#include <stdio.h>
#include <wchar.h>

#ifndef MAX_CLASS_NAME_LEN
#define MAX_CLASS_NAME_LEN 32
#endif
#ifndef MAX_DEVICE_ID_LEN
#define MAX_DEVICE_ID_LEN 200
#endif

static int Install(void)
{
    WCHAR Inf[MAX_PATH];
    WCHAR ClassName[MAX_CLASS_NAME_LEN];
    WCHAR InstanceId[MAX_DEVICE_ID_LEN];
    WCHAR HwId[] = L"*MSLOOP\0";
    GUID ClassGuid;
    HDEVINFO Set;
    SP_DEVINFO_DATA Dev = {sizeof(Dev)};
    BOOL Reboot = FALSE;

    ExpandEnvironmentStringsW(L"%windir%\inf\netloop.inf", Inf, MAX_PATH);
    if (!SetupDiGetINFClassW(Inf, &ClassGuid, ClassName, MAX_CLASS_NAME_LEN, NULL)) {
        printf("mkloop: SetupDiGetINFClass(%ls) failed: %lu\n", Inf, GetLastError());
        return 1;
    }
    Set = SetupDiCreateDeviceInfoList(&ClassGuid, NULL);
    if (Set == INVALID_HANDLE_VALUE) {
        printf("mkloop: SetupDiCreateDeviceInfoList failed: %lu\n", GetLastError());
        return 1;
    }
    if (!SetupDiCreateDeviceInfoW(Set, ClassName, &ClassGuid, NULL, NULL, DICD_GENERATE_ID, &Dev)) {
        printf("mkloop: SetupDiCreateDeviceInfo failed: %lu\n", GetLastError());
        return 1;
    }
    if (!SetupDiSetDeviceRegistryPropertyW(Set, &Dev, SPDRP_HARDWAREID, (BYTE *)HwId, sizeof(HwId))) {
        printf("mkloop: SetupDiSetDeviceRegistryProperty failed: %lu\n", GetLastError());
        return 1;
    }
    if (!SetupDiCallClassInstaller(DIF_REGISTERDEVICE, Set, &Dev)) {
        printf("mkloop: DIF_REGISTERDEVICE failed: %lu\n", GetLastError());
        return 1;
    }
    //
    // Print the instance ID as soon as the device node exists, so a caller can
    // still remove it when the driver install below fails.
    //
    if (SetupDiGetDeviceInstanceIdW(Set, &Dev, InstanceId, ARRAYSIZE(InstanceId), NULL)) {
        printf("mkloop: instance=%ls\n", InstanceId);
        fflush(stdout);
    }
    if (!UpdateDriverForPlugAndPlayDevicesW(NULL, L"*MSLOOP", Inf, INSTALLFLAG_FORCE, &Reboot)) {
        printf("mkloop: UpdateDriverForPlugAndPlayDevices failed: %lu\n", GetLastError());
        return 1;
    }
    printf("mkloop: *MSLOOP installed from %ls (reboot=%d)\n", Inf, Reboot);
    SetupDiDestroyDeviceInfoList(Set);
    return 0;
}

static int Remove(const WCHAR *InstanceId)
{
    WCHAR Inf[MAX_PATH];
    WCHAR ClassName[MAX_CLASS_NAME_LEN];
    WCHAR HwIds[512];
    GUID ClassGuid;
    HDEVINFO Set;
    SP_DEVINFO_DATA Dev = {sizeof(Dev)};
    SP_REMOVEDEVICE_PARAMS Rp;
    SP_DEVINSTALL_PARAMS_W Ip;
    DWORD Type = 0;
    BOOL Reboot = FALSE;

    ExpandEnvironmentStringsW(L"%windir%\inf\netloop.inf", Inf, MAX_PATH);
    if (!SetupDiGetINFClassW(Inf, &ClassGuid, ClassName, MAX_CLASS_NAME_LEN, NULL)) {
        printf("mkloop: SetupDiGetINFClass(%ls) failed: %lu\n", Inf, GetLastError());
        return 1;
    }
    Set = SetupDiCreateDeviceInfoList(&ClassGuid, NULL);
    if (Set == INVALID_HANDLE_VALUE) {
        printf("mkloop: SetupDiCreateDeviceInfoList failed: %lu\n", GetLastError());
        return 1;
    }
    if (!SetupDiOpenDeviceInfoW(Set, InstanceId, NULL, 0, &Dev)) {
        printf("mkloop: SetupDiOpenDeviceInfo(%ls) failed: %lu\n", InstanceId, GetLastError());
        SetupDiDestroyDeviceInfoList(Set);
        return 1;
    }
    memset(HwIds, 0, sizeof(HwIds));
    if (!SetupDiGetDeviceRegistryPropertyW(
            Set, &Dev, SPDRP_HARDWAREID, &Type, (BYTE *)HwIds, sizeof(HwIds) - 2 * sizeof(WCHAR), NULL)) {
        printf("mkloop: read hardware ID of %ls failed: %lu\n", InstanceId, GetLastError());
        SetupDiDestroyDeviceInfoList(Set);
        return 1;
    }
    if (_wcsicmp(HwIds, L"*MSLOOP") != 0) {
        printf("mkloop: refusing to remove %ls: hardware ID is %ls, not *MSLOOP\n", InstanceId, HwIds);
        SetupDiDestroyDeviceInfoList(Set);
        return 1;
    }

    memset(&Rp, 0, sizeof(Rp));
    Rp.ClassInstallHeader.cbSize = sizeof(SP_CLASSINSTALL_HEADER);
    Rp.ClassInstallHeader.InstallFunction = DIF_REMOVE;
    Rp.Scope = DI_REMOVEDEVICE_GLOBAL;
    Rp.HwProfile = 0;
    if (!SetupDiSetClassInstallParamsW(Set, &Dev, &Rp.ClassInstallHeader, sizeof(Rp))) {
        printf("mkloop: SetupDiSetClassInstallParams failed: %lu\n", GetLastError());
        SetupDiDestroyDeviceInfoList(Set);
        return 1;
    }
    if (!SetupDiCallClassInstaller(DIF_REMOVE, Set, &Dev)) {
        printf("mkloop: DIF_REMOVE failed: %lu\n", GetLastError());
        SetupDiDestroyDeviceInfoList(Set);
        return 1;
    }
    memset(&Ip, 0, sizeof(Ip));
    Ip.cbSize = sizeof(Ip);
    if (SetupDiGetDeviceInstallParamsW(Set, &Dev, &Ip) && (Ip.Flags & (DI_NEEDRESTART | DI_NEEDREBOOT))) {
        Reboot = TRUE;
    }
    printf("mkloop: removed %ls (reboot=%d)\n", InstanceId, Reboot);
    SetupDiDestroyDeviceInfoList(Set);
    return 0;
}

int __cdecl wmain(int argc, WCHAR **argv)
{
    if (argc == 1) {
        return Install();
    }
    if (argc == 3 && _wcsicmp(argv[1], L"remove") == 0) {
        return Remove(argv[2]);
    }
    printf("usage: mkloop.exe                      install one KM-TEST Loopback Adapter\n");
    printf("       mkloop.exe remove <InstanceId>  remove one (hardware ID must be *MSLOOP)\n");
    return 2;
}
