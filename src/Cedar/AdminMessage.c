// AdminMessage.c
// Admin RPC area: maintenance (flush, crash, reboot, certificate regeneration)

#include "Admin.h"

#include "Connection.h"
#include "Link.h"
#include "Listener.h"
#include "Protocol.h"
#include "Server.h"

#include "Mayaqua/Internat.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Pack.h"
#include "Mayaqua/Str.h"
#include "AdminInternal.h"

UINT StRegenerateServerCert(ADMIN *a, RPC_TEST *t) {
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	X *x;
	K *k;

	SERVER_ADMIN_ONLY;

	if (SiGenerateDefaultCertEx(&x, &k, t->StrValue) == false) {
		SLog(c, "LS_DEFAULT_CERT_FAILED");
		return ERR_INTERNAL_ERROR;
	}

	SetCedarCertAndChain(c, x, k, NULL);

	ALog(a, NULL, "LA_REGENERATE_SERVER_CERT", t->StrValue);

	IncrementServerConfigRevision(s);

	FreeX(x);
	FreeK(k);

	return ERR_NO_ERROR;
}

UINT StFlush(ADMIN *a, RPC_TEST *t) {
	SERVER *s = a->Server;

	SERVER_ADMIN_ONLY;

	UINT size = SiWriteConfigurationFile(s);

	t->IntValue = size;

	return ERR_NO_ERROR;
}

UINT StCrash(ADMIN *a, RPC_TEST *t) {
	SERVER_ADMIN_ONLY;

	CrashNow();

	return ERR_NO_ERROR;
}

UINT StRebootServer(ADMIN *a, RPC_TEST *t) {
	SERVER_ADMIN_ONLY;

	ALog(a, NULL, "LA_REBOOT_SERVER");

	SiRebootServerEx(t->IntValue);

	return ERR_NO_ERROR;
}
