// AdminSyslog.c
// Admin RPC area: syslog settings

#include "Admin.h"

#include "Account.h"
#include "BridgeWin32.h"
#include "Connection.h"
#include "Link.h"
#include "Listener.h"
#include "MsChapV2.h"
#include "Remote.h"
#include "Protocol.h"
#include "Sam.h"
#include "Server.h"
#include "Session.h"
#include "Wpc.h"

#include "Mayaqua/Cfg.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/HTTP.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Pack.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Table.h"
#include "Mayaqua/Tick64.h"
#include "AdminInternal.h"

UINT StSetSysLog(ADMIN *a, SYSLOG_SETTING *t)
{
	SERVER *s = a->Server;

	SERVER_ADMIN_ONLY;

	if (GetGlobalServerFlag(GSF_DISABLE_SYSLOG) != 0 && t->SaveType != SYSLOG_NONE)
	{
		return ERR_NOT_SUPPORTED_FUNCTION_ON_OPENSOURCE;
	}

	if (GetServerCapsBool(s, "b_support_syslog") == false)
	{
		return ERR_NOT_SUPPORTED;
	}

	SiSetSysLogSetting(s, t);

	IncrementServerConfigRevision(s);
	ALog(a, NULL, "LA_SET_SYSLOG");

	return ERR_NO_ERROR;
}

UINT StGetSysLog(ADMIN *a, SYSLOG_SETTING *t)
{
	SERVER *s = a->Server;

	SiGetSysLogSetting(s, t);

	if (a->ServerAdmin == false)
	{
		// Hide the server name from non-administrators
		if (t->SaveType == SYSLOG_NONE)
		{
			StrCpy(t->Hostname, sizeof(t->Hostname), "");
			t->Port = 0;
		}
		else
		{
			StrCpy(t->Hostname, sizeof(t->Hostname), "Secret");
			t->Port = 0;
		}
	}

	return ERR_NO_ERROR;
}
