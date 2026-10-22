// AdminHttpListener.c
// Admin RPC area: the HTTP listener (the redirect to HTTPS and ACME HTTP-01 on port 80 by default)

#include "Admin.h"

#include "Server.h"

#include "Mayaqua/Memory.h"
#include "AdminInternal.h"

UINT StGetHttpListener(ADMIN *a, RPC_HTTP_LISTENER *t) {
	SERVER_ADMIN_ONLY;

	Zero(t, sizeof(RPC_HTTP_LISTENER));

	SiGetHttpListener(a->Server, &t->Enabled, &t->Port, &t->Listening);

	return ERR_NO_ERROR;
}

// Turn the HTTP listener on or off; the answer is the setting that results
UINT StSetHttpListener(ADMIN *a, RPC_HTTP_LISTENER *t) {
	SERVER_ADMIN_ONLY;

	if (t->Port > 65535)
		return ERR_INVALID_PARAMETER;

	UINT ret = SiSetHttpListener(a->Server, t->Enabled, t->Port);
	if (ret != ERR_NO_ERROR)
		return ret;

	StGetHttpListener(a, t);

	if (t->Enabled)
		ALog(a, NULL, "LA_ENABLE_HTTP_LISTENER", t->Port);
	else
		ALog(a, NULL, "LA_DISABLE_HTTP_LISTENER");

	IncrementServerConfigRevision(a->Server);

	return ERR_NO_ERROR;
}
