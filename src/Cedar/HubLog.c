// HubLog.c
// Log API of Cedar: the server log and the security logs of the Virtual Hubs, to their files or to syslog

#include "HubLog.h"

#include "Admin.h"
#include "LogWriter.h"
#include "Server.h"

#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Table.h"

// The log setting of a new hub: security and packet logs on, switched daily, TCP connection and DHCP packets logged by header
void SetDefaultHubLog(HUB_LOG *g) {
	if (g == NULL)
		return;

	Zero(g, sizeof(HUB_LOG));
	g->SaveSecurityLog = true;
	g->SecurityLogSwitchType = LOG_SWITCH_DAY;
	g->SavePacketLog = true;
	g->PacketLogSwitchType = LOG_SWITCH_DAY;
	g->PacketLogConfig[PACKET_LOG_TCP_CONN] =
	    g->PacketLogConfig[PACKET_LOG_DHCP] = PACKET_LOG_HEADER;
}

void SLog(CEDAR *c, char *name, ...) {
	wchar_t buf[MAX_SIZE * 2];
	va_list args;
	if (name == NULL)
		return;

	va_start(args, name);
	LogFormat(buf, sizeof(buf), name, args);

	WriteServerLog(c, buf);
	va_end(args);
}

void ALog(ADMIN *a, HUB *h, char *name, ...) {
	wchar_t buf[MAX_SIZE * 2];
	wchar_t tmp[MAX_SIZE * 2];
	va_list args;
	if (a == NULL || name == NULL)
		return;

	va_start(args, name);
	LogFormat(buf, sizeof(buf), name, args);

	if (h == NULL)
		UniFormat(tmp, sizeof(tmp), _UU("LA_TAG_1"), a->Tag);
	else
		UniFormat(tmp, sizeof(tmp), _UU("LA_TAG_2"), a->Tag, h->Name);

	UniStrCat(tmp, sizeof(tmp), buf);

	if (h == NULL)
		WriteServerLog(a->Server->Cedar, tmp);
	else
		WriteHubLog(h, tmp);
	va_end(args);
}
void HLog(HUB *h, char *name, ...) {
	wchar_t buf[MAX_SIZE * 2];
	va_list args;
	if (name == NULL)
		return;

	va_start(args, name);
	LogFormat(buf, sizeof(buf), name, args);

	WriteHubLog(h, buf);
	va_end(args);
}

void WriteHubLog(HUB *h, wchar_t *str) {
	wchar_t buf[MAX_SIZE * 2];
	if (h == NULL || str == NULL)
		return;

	SERVER *s = h->Cedar->Server;
	UINT syslog_status = SiGetSysLogSaveStatus(s);

	UniFormat(buf, sizeof(buf), L"[HUB \"%S\"] %s", h->Name, str);

	if (syslog_status == SYSLOG_NONE)
		WriteServerLog(h->Cedar, buf);

	if (h->LogSetting.SaveSecurityLog == false)
		return;

	if (syslog_status == SYSLOG_SERVER_AND_HUB_SECURITY_LOG || syslog_status == SYSLOG_SERVER_AND_HUB_ALL_LOG)
		SiWriteSysLog(s, "SECURITY_LOG", h->Name, str);
	else
		InsertUnicodeRecord(h->SecurityLogger, str);
}

void WriteServerLog(CEDAR *c, wchar_t *str) {
	if (c == NULL || str == NULL)
		return;

	SERVER *s = c->Server;
	if (s == NULL)
		return;

	if (IsDebug())
		UniPrint(L"LOG: %s\n", str);

	if (SiGetSysLogSaveStatus(s) != SYSLOG_NONE)
		SiWriteSysLog(s, "SERVER_LOG", NULL, str);
	else
		InsertUnicodeRecord(s->Logger, str);
}

bool CheckLogFileNameFromEnumList(LIST *o, char *name) {
	LOG_FILE t;
	if (o == NULL || name == NULL)
		return false;

	Zero(&t, sizeof(t));
	StrCpy(t.Path, sizeof(t.Path), name);

	if (Search(o, &t) == NULL)
		return false;

	return true;
}

void FreeEnumLogFile(LIST *o) {
	if (o == NULL)
		return;

	for (UINT i = 0; i < LIST_NUM(o); i++) {
		LOG_FILE *f = LIST_DATA(o, i);

		Free(f);
	}

	ReleaseList(o);
}

// Enumerate the log files of one log directory tree (packet log or security log):
// every hub subdirectory when hubname is NULL, otherwise only the hub's one.
static void EnumLogFileSubdirs(LIST *o, char *exe_dir, char *base_dir, char *hubname) {
	char tmp[MAX_PATH];

	if (hubname == NULL) {
		Format(tmp, sizeof(tmp), "%s/%s", exe_dir, base_dir);

		DIRLIST *dir = EnumDir(tmp);
		for (UINT i = 0; i < dir->NumFiles; i++) {
			DIRENT *e = dir->File[i];

			if (e->Folder) {
				Format(tmp, sizeof(tmp), "%s/%s", base_dir, e->FileName);
				EnumLogFileDir(o, tmp);
			}
		}

		FreeDir(dir);
	} else {
		Format(tmp, sizeof(tmp), "%s/%s", base_dir, hubname);
		EnumLogFileDir(o, tmp);
	}
}

LIST *EnumLogFile(char *hubname) {
	char exe_dir[MAX_PATH];
	char dir[MAX_PATH];
	LIST *o = NewListFast(CmpLogFile);

	if (StrLen(hubname) == 0)
		hubname = NULL;

	GetExeDir(exe_dir, sizeof(exe_dir));

	if (hubname == NULL) {
		ServerLogDir(dir, sizeof(dir));
		EnumLogFileDir(o, dir);
	}

	HubPacketLogDir(dir, sizeof(dir), NULL);
	EnumLogFileSubdirs(o, exe_dir, dir, hubname);
	HubSecurityLogDir(dir, sizeof(dir), NULL);
	EnumLogFileSubdirs(o, exe_dir, dir, hubname);

	return o;
}

void EnumLogFileDir(LIST *o, char *dirname) {
	char exe_dir[MAX_PATH];
	char dir_full_path[MAX_PATH];
	if (o == NULL || dirname == NULL)
		return;

	GetExeDir(exe_dir, sizeof(exe_dir));
	Format(dir_full_path, sizeof(dir_full_path), "%s/%s", exe_dir, dirname);

	DIRLIST *dir = EnumDir(dir_full_path);

	for (UINT i = 0; i < dir->NumFiles; i++) {
		DIRENT *e = dir->File[i];

		if (e->Folder == false && e->FileSize > 0) {
			char file_path[MAX_PATH];

			Format(file_path, sizeof(file_path), "%s/%s", dirname, e->FileName);

			if (EndWith(file_path, ".log")) {
				LOG_FILE *f = ZeroMalloc(sizeof(LOG_FILE));

				StrCpy(f->Path, sizeof(f->Path), file_path);
				f->FileSize = (UINT)(MIN(e->FileSize, 0xffffffffUL));
				f->UpdatedTime = e->UpdateDate;

				Insert(o, f);
			}
		}
	}

	FreeDir(dir);
}

int CmpLogFile(void *p1, void *p2) {
	if (p1 == NULL || p2 == NULL)
		return 0;
	LOG_FILE *f1 = *(LOG_FILE **)p1;
	LOG_FILE *f2 = *(LOG_FILE **)p2;
	if (f1 == NULL || f2 == NULL)
		return 0;

	return StrCmpi(f1->Path, f2->Path);
}

// LogPaths: the directory of a log, relative to the directory of the executable (a log file path names it after an
// "@", see InnerFilePathW). NewHub, EnumLogFile and the eraser of the server take the directories from here
void ServerLogDir(char *dir, UINT size) {
	StrCpy(dir, size, SERVER_LOG_DIR);
}

// The directory of a security or packet log: the one of the hub hubname, or with hubname NULL or empty the one
// that holds the logs of every hub
static void HubLogDir(char *dir, UINT size, char *base, char *hubname) {
	if (IsEmptyStr(hubname))
		StrCpy(dir, size, base);
	else
		Format(dir, size, "%s/%s", base, hubname);
}

void HubSecurityLogDir(char *dir, UINT size, char *hubname) {
	HubLogDir(dir, size, HUB_SECURITY_LOG_DIR, hubname);
}

void HubPacketLogDir(char *dir, UINT size, char *hubname) {
	HubLogDir(dir, size, HUB_PACKET_LOG_DIR, hubname);
}

UINT SiGetSysLogSaveStatus(SERVER *s) {
	SYSLOG_SETTING set;
	if (s == NULL)
		return SYSLOG_NONE;

	SiGetSysLogSetting(s, &set);

	return set.SaveType;
}

void SiWriteSysLog(SERVER *s, char *typestr, char *hubname, wchar_t *message) {
	wchar_t tmp[1024];
	char machinename[MAX_HOST_NAME_LEN + 1];
	char datetime[MAX_PATH];
	SYSTEMTIME st;
	if (s == NULL || typestr == NULL || message == NULL)
		return;

	GetMachineName(machinename, sizeof(machinename));

	LocalTime(&st);
	if (s->StrictSyslogDatetimeFormat)
		GetDateTimeStrRFC3339(datetime, sizeof(datetime), &st, GetCurrentTimezone());
	else
		GetDateTimeStrMilli(datetime, sizeof(datetime), &st);

	if (IsEmptyStr(hubname) == false)
		UniFormat(tmp, sizeof(tmp), L"[%S/VPN/%S] (%S) <%S>: %s",
		          machinename, hubname, datetime, typestr, message);
	else
		UniFormat(tmp, sizeof(tmp), L"[%S/VPN] (%S) <%S>: %s",
		          machinename, datetime, typestr, message);

	SendSysLog(s->Syslog, tmp);
}

void SiGetSysLogSetting(SERVER *s, SYSLOG_SETTING *setting) {
	if (s == NULL || setting == NULL)
		return;

	Copy(setting, &s->SyslogSetting, sizeof(SYSLOG_SETTING));
}
