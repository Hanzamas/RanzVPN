// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// Protocol.h
// Header of Protocol.c

#ifndef	PROTOCOL_H
#define	PROTOCOL_H

#include "Connection.h"

// The parameters that will be passed to the certificate confirmation thread
struct CHECK_CERT_THREAD_PROC
{
	CONNECTION *Connection;
	X *ServerX;
	CHECK_CERT_PROC *CheckCertProc;
	bool UserSelected;
	bool Expired;
	bool Ok;
};

// Signature sending thread parameters
struct SEND_SIGNATURE_PARAM
{
	char Hostname[MAX_PATH];		// Host name
	UINT Port;						// Port number
	BUF *Buffer;					// Packet contents
};

// Dynamic root cert fetch function
#define	CERT_HTTP_DOWNLOAD_MAXSIZE	65536
#define	CERT_HTTP_DOWNLOAD_TIMEOUT	(10 * 1000)
#define	ROOT_CERTS_FILENAME			"|root_certs.dat"
#define	AUTO_DOWNLOAD_CERTS_PREFIX	L".autodownload_"
#define	FIND_CERT_CHAIN_MAX_DEPTH	16

// Function prototype
bool ServerAccept(CONNECTION *c);
bool ClientConnect(CONNECTION *c);
SOCK *ClientConnectToServer(CONNECTION *c);

bool ClientUploadSignature(SOCK *s);
bool ClientDownloadHello(CONNECTION *c, SOCK *s);
SOCK *TcpConnectEx3(char *hostname, UINT port, UINT timeout, bool *cancel_flag, void *hWnd, IP *ret_ip);

UINT ProxyCodeToCedar(UINT code);

void InitProtocol();
void FreeProtocol();

POLICY *PackGetPolicy(PACK *p);
void PackAddPolicy(PACK *p, POLICY *y);


bool ClientAdditionalConnect(CONNECTION *c, THREAD *t);

void PackAddClientVersion(PACK *p, CONNECTION *c);
void GenerateMachineUniqueHash(void *data);

bool DownloadAndSaveIntermediateCertificatesIfNecessary(X *x);

#endif	// PROTOCOL_H
