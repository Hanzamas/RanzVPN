// Protocol.h
// Header of Protocol.c

#ifndef	PROTOCOL_H
#define	PROTOCOL_H

#include "Connection.h"

struct CHECK_CERT_THREAD_PROC
{
	CONNECTION *Connection;
	X *ServerX;
	CHECK_CERT_PROC *CheckCertProc;
	bool UserSelected;
	bool Expired;
	bool Ok;
};

#define	CERT_HTTP_DOWNLOAD_MAXSIZE	65536
#define	CERT_HTTP_DOWNLOAD_TIMEOUT	(10 * 1000)
#define	ROOT_CERTS_FILENAME			"|root_certs.dat"
#define	AUTO_DOWNLOAD_CERTS_PREFIX	L".autodownload_"
#define	FIND_CERT_CHAIN_MAX_DEPTH	16

bool ServerAccept(CONNECTION *c);
bool ClientConnect(CONNECTION *c);
SOCK *ClientConnectToServer(CONNECTION *c);

bool ClientUploadSignature(SOCK *s);
bool ClientDownloadHello(CONNECTION *c, SOCK *s);

UINT ProxyCodeToCedar(UINT code);


POLICY *PackGetPolicy(PACK *p);
void PackAddPolicy(PACK *p, POLICY *y);


bool ClientAdditionalConnect(CONNECTION *c, THREAD *t);

void PackAddClientVersion(PACK *p, CONNECTION *c);
void GenerateMachineUniqueHash(void *data);

bool DownloadAndSaveIntermediateCertificatesIfNecessary(X *x);

#endif
