// MicrosoftInternal.h
// Module-internal declarations of the Microsoft module: only its own files include this header

#ifndef MICROSOFT_INTERNAL_H
#define MICROSOFT_INTERNAL_H

bool MsRegIsValueEx2(UINT root, char *keyname, char *valuename, bool force32bit);
bool MsRegNewKeyEx2(UINT root, char *keyname, bool force32bit);
bool MsRegWriteValueEx2(UINT root, char *keyname, char *valuename, UINT type, void *data, UINT size, bool force32bit);
bool MsRegWriteStrEx2(UINT root, char *keyname, char *valuename, char *str, bool force32bit);
TOKEN_LIST *MsRegEnumKey(UINT root, char *keyname);
TOKEN_LIST *MsRegEnumKeyEx2(UINT root, char *keyname, bool force32bit);
bool MsRegDeleteKeyEx2(UINT root, char *keyname, bool force32bit);
bool MsRegDeleteValueEx2(UINT root, char *keyname, char *valuename, bool force32bit);
char *MsGetExeDirName();
void MsGenLockFile(wchar_t *name, UINT size, wchar_t *temp_dir);
wchar_t *MsGetExeFileNameW();
wchar_t *MsGetUserNameW();
bool MsInstallServiceExW(char *name, wchar_t *title, wchar_t *description, wchar_t *path, bool virtual_account);
bool MsUpdateServiceConfig(char *name);
bool MsUninstallService(char *name);
bool MsStopService(char *name);
MS_ADAPTER *MsCloneAdapter(MS_ADAPTER *a);
void MsRegistWindowsFirewallEx(char *title, char *exe);
void MsGetComputerName(char *name, UINT size);

#endif // MICROSOFT_INTERNAL_H
