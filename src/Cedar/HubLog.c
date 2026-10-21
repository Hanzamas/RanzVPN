// HubLog.c
// Log API of Cedar: the server log and the security logs of the Virtual Hubs, to their files or to syslog

#include "Logging.h"

#include "Admin.h"
#include "Server.h"

#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Table.h"

// The log setting of a new hub: security and packet logs on, switched daily, TCP connection and DHCP packets logged by header
void SetDefaultHubLog(HUB_LOG *g)
{
	if (g == NULL)
	{
		return;
	}

	Zero(g, sizeof(HUB_LOG));
	g->SaveSecurityLog = true;
	g->SecurityLogSwitchType = LOG_SWITCH_DAY;
	g->SavePacketLog = true;
	g->PacketLogSwitchType = LOG_SWITCH_DAY;
	g->PacketLogConfig[PACKET_LOG_TCP_CONN] =
		g->PacketLogConfig[PACKET_LOG_DHCP] = PACKET_LOG_HEADER;
}

void SLog(CEDAR *c, char *name, ...)
{
	wchar_t buf[MAX_SIZE * 2];
	va_list args;
	if (name == NULL)
	{
		return;
	}

	va_start(args, name);
	LogFormat(buf, sizeof(buf), name, args);

	WriteServerLog(c, buf);
	va_end(args);
}

void ALog(ADMIN *a, HUB *h, char *name, ...)
{
	wchar_t buf[MAX_SIZE * 2];
	wchar_t tmp[MAX_SIZE * 2];
	va_list args;
	if (a == NULL || name == NULL)
	{
		return;
	}

	va_start(args, name);
	LogFormat(buf, sizeof(buf), name, args);

	if (h == NULL)
	{
		UniFormat(tmp, sizeof(tmp), _UU("LA_TAG_1"), a->Tag);
	}
	else
	{
		UniFormat(tmp, sizeof(tmp), _UU("LA_TAG_2"), a->Tag, h->Name);
	}

	UniStrCat(tmp, sizeof(tmp), buf);

	if (h == NULL)
	{
		WriteServerLog(a->Server->Cedar, tmp);
	}
	else
	{
		WriteHubLog(h, tmp);
	}
	va_end(args);
}
void HLog(HUB *h, char *name, ...)
{
	wchar_t buf[MAX_SIZE * 2];
	va_list args;
	if (name == NULL)
	{
		return;
	}

	va_start(args, name);
	LogFormat(buf, sizeof(buf), name, args);

	WriteHubLog(h, buf);
	va_end(args);
}

void WriteHubLog(HUB *h, wchar_t *str)
{
	wchar_t buf[MAX_SIZE * 2];
	UINT syslog_status;
	SERVER *s;
	if (h == NULL || str == NULL)
	{
		return;
	}

	s = h->Cedar->Server;
	syslog_status = SiGetSysLogSaveStatus(s);

	UniFormat(buf, sizeof(buf), L"[HUB \"%S\"] %s", h->Name, str);

	if (syslog_status == SYSLOG_NONE)
	{
		WriteServerLog(h->Cedar, buf);
	}

	if (h->LogSetting.SaveSecurityLog == false)
	{
		return;
	}

	if (syslog_status == SYSLOG_SERVER_AND_HUB_SECURITY_LOG
	        || syslog_status == SYSLOG_SERVER_AND_HUB_ALL_LOG)
	{
		SiWriteSysLog(s, "SECURITY_LOG", h->Name, str);
	}
	else
	{
		InsertUnicodeRecord(h->SecurityLogger, str);
	}
}

void WriteServerLog(CEDAR *c, wchar_t *str)
{
	SERVER *s;
	if (c == NULL || str == NULL)
	{
		return;
	}

	s = c->Server;
	if (s == NULL)
	{
		return;
	}

	if (IsDebug())
	{
		UniPrint(L"LOG: %s\n", str);
	}

	if (SiGetSysLogSaveStatus(s) != SYSLOG_NONE)
	{
		SiWriteSysLog(s, "SERVER_LOG", NULL, str);
	}
	else
	{
		InsertUnicodeRecord(s->Logger, str);
	}
}
