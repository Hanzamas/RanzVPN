// vpnserver.c
// VPN Server service program

#define	VPN_EXE

#include "Cedar/Server.h"

#include "Mayaqua/Mayaqua.h"
#include "Mayaqua/Microsoft.h"

static void StartProcess()
{
	InitCedar();
	StInit();
	StStartServer(false);
}

static void StopProcess()
{
	StStopServer();
	StFree();
	FreeCedar();
}

int main(int argc, char *argv[])
{
	InitProcessCallOnce();

	return MsService(GC_SVC_NAME_VPNSERVER, StartProcess, StopProcess, 0, argv[0]);
}

