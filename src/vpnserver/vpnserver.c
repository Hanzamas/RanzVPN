// vpnserver.c
// VPN Server service program

#include "Cedar/Server.h"

#include "Mayaqua/Mayaqua.h"
#include "Mayaqua/Microsoft.h"

static void StartProcess() {
	InitCedar();
	StInit();
	StStartServer();
}

static void StopProcess() {
	StStopServer();
	StFree();
	FreeCedar();
}

// The GUI-subsystem entry point: CmdLine holds the arguments without the program name. /install adds
// the inbound rule "Ranz VPN Server" of Windows Firewall for this program and /uninstall deletes it.
int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, char *CmdLine, int CmdShow) {
	InitProcessCallOnce();

	return MsService(GC_SVC_NAME_VPNSERVER, StartProcess, StopProcess, CmdLine, L"" CEDAR_SERVER_STR);
}

