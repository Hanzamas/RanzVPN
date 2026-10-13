//
// Creates one root-enumerated Microsoft KM-TEST Loopback Adapter (*MSLOOP)
// from %windir%\inf\netloop.inf. Same steps as "devcon install netloop.inf
// *MSLOOP": SetupDiCreateDeviceInfo + DIF_REGISTERDEVICE +
// UpdateDriverForPlugAndPlayDevices. Spike code, never merged.
//

#include <windows.h>
#include <setupapi.h>
#include <newdev.h>
#include <stdio.h>

#ifndef MAX_CLASS_NAME_LEN
#define MAX_CLASS_NAME_LEN 32
#endif

int __cdecl wmain(void)
{
    WCHAR Inf[MAX_PATH];
    WCHAR ClassName[MAX_CLASS_NAME_LEN];
    WCHAR HwId[] = L"*MSLOOP\0";
    GUID ClassGuid;
    HDEVINFO Set;
    SP_DEVINFO_DATA Dev = {sizeof(Dev)};
    BOOL Reboot = FALSE;

    ExpandEnvironmentStringsW(L"%windir%\\inf\\netloop.inf", Inf, MAX_PATH);
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
    if (!UpdateDriverForPlugAndPlayDevicesW(NULL, L"*MSLOOP", Inf, INSTALLFLAG_FORCE, &Reboot)) {
        printf("mkloop: UpdateDriverForPlugAndPlayDevices failed: %lu\n", GetLastError());
        return 1;
    }
    printf("mkloop: *MSLOOP installed from %ls (reboot=%d)\n", Inf, Reboot);
    SetupDiDestroyDeviceInfoList(Set);
    return 0;
}
