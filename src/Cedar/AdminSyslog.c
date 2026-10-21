// AdminSyslog.c
// Admin RPC area: syslog settings

#include "Admin.h"

#include "Connection.h"
#include "Listener.h"
#include "Server.h"

#include "Mayaqua/Str.h"
#include "AdminInternal.h"

UINT StSetSysLog(ADMIN *a, SYSLOG_SETTING *t) {
	SERVER *s = a->Server;

	SERVER_ADMIN_ONLY;

	SiSetSysLogSetting(s, t);

	IncrementServerConfigRevision(s);
	ALog(a, NULL, "LA_SET_SYSLOG");

	return ERR_NO_ERROR;
}

UINT StGetSysLog(ADMIN *a, SYSLOG_SETTING *t) {
	SERVER *s = a->Server;

	SiGetSysLogSetting(s, t);

	if (a->ServerAdmin == false) {
		// Hide the server name from non-administrators
		if (t->SaveType == SYSLOG_NONE) {
			StrCpy(t->Hostname, sizeof(t->Hostname), "");
			t->Port = 0;
		} else {
			StrCpy(t->Hostname, sizeof(t->Hostname), "Secret");
			t->Port = 0;
		}
	}

	return ERR_NO_ERROR;
}
