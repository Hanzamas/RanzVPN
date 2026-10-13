// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// vpnserver.c
// VPN Server service program

#define	VPN_EXE

#include "Cedar/Server.h"

#include "Mayaqua/Mayaqua.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Win32.h"

void StartProcess()
{
	InitCedar();
	StInit();
	StStartServer(false);
}

void StopProcess()
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

