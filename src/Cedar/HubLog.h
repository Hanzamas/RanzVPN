// HubLog.h
// Header of HubLog.c

#ifndef HUBLOG_H
#define HUBLOG_H

#include "Cedar.h"

struct HUB_LOG {
	bool SaveSecurityLog;
	UINT SecurityLogSwitchType;
	bool SavePacketLog;
	UINT PacketLogSwitchType;
	UINT PacketLogConfig[NUM_PACKET_LOG];
};

struct LOG_FILE {
	char Path[MAX_PATH];
	UINT FileSize;
	UINT64 UpdatedTime;
};

void SetDefaultHubLog(HUB_LOG *g);
void SLog(CEDAR *c, char *name, ...);
void WriteHubLog(HUB *h, wchar_t *str);
void HLog(HUB *h, char *name, ...);
void WriteServerLog(CEDAR *c, wchar_t *str);
void ALog(ADMIN *a, HUB *h, char *name, ...);
int CmpLogFile(void *p1, void *p2);
LIST *EnumLogFile(char *hubname);
void EnumLogFileDir(LIST *o, char *dirname);
void FreeEnumLogFile(LIST *o);
bool CheckLogFileNameFromEnumList(LIST *o, char *name);
void ServerLogDir(char *dir, UINT size);
void HubSecurityLogDir(char *dir, UINT size, char *hubname);
void HubPacketLogDir(char *dir, UINT size, char *hubname);
void SiGetSysLogSetting(SERVER *s, SYSLOG_SETTING *setting);
void SiWriteSysLog(SERVER *s, char *typestr, char *hubname, wchar_t *message);
UINT SiGetSysLogSaveStatus(SERVER *s);

#endif
