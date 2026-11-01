// Protocol.h
// Header of Protocol.c

#ifndef PROTOCOL_H
#define PROTOCOL_H

#include "Connection.h"
#include "Session.h"
#include "UdpAccel.h"

#define CERT_HTTP_DOWNLOAD_MAXSIZE 65536
#define CERT_HTTP_DOWNLOAD_TIMEOUT (10 * 1000)
#define ROOT_CERTS_FILENAME        "|root_certs.dat"
#define AUTO_DOWNLOAD_CERTS_PREFIX L".autodownload_"
#define FIND_CERT_CHAIN_MAX_DEPTH  16

// Largest Pack that the client reads from the server it connects to. The hello and the answer to an
// additional connection get HTTP_PACK_MAX_SIZE (64 KiB), the cap of the server side before the
// authentication. The welcome Pack gets 4 times that: its "Msg" holds the hub message (HUB_MAXMSG_LEN
// characters, up to 3 bytes each in UTF-8) and the notices of ServerAccept: under 90 KB in all.
#define CLIENT_WELCOME_PACK_MAX_SIZE (256 * 1024)

// Fields of the client's "login" PACK that the hub-side login steps and the new session use
// (ParseLoginRequest). The credentials stay in the PACK for the authentication.
struct LOGIN_REQ {
	UINT AuthType; // CLIENT_AUTHTYPE_*
	char HubName[MAX_SIZE];
	char Username[MAX_SIZE];
	NODE_INFO NodeInfo;
	bool UseEncrypt;
	bool UseCompress;
	UINT MaxConnection; // as sent; the policy bounds it
	bool HalfConnection;
	bool QoS; // false when monitor mode is requested
	UINT ClientId;
	UINT AdjustMss;
	bool UseUdpAcceleration; // false when the client address or port is missing
	UINT UdpAccelMaxVersion; // at least 1
	bool UseHMacOnUdpAcceleration;
	bool UdpAccelFastDisconnectDetect;
	UCHAR UdpAccelClientKey[UDP_ACCELERATION_COMMON_KEY_SIZE_V1];
	UCHAR UdpAccelClientKeyV2[UDP_ACCELERATION_COMMON_KEY_SIZE_V2];
	IP UdpAccelClientIp; // zero: the client lets the server use the socket's address
	UINT UdpAccelClientPort;
	bool RequireBridgeRoutingMode;
	bool RequireMonitorMode;
	UCHAR UniqueId[SHA1_SIZE]; // zero unless the client sent SHA1_SIZE bytes
};

// The hub's decision on an authenticated login (HubResolveSessionPolicy, HubAdmitSession)
struct HUB_LOGIN {
	POLICY *Policy;              // policy of the new session; NewLoginSession hands it to the session
	USER *User;                  // logged-in user object, reference held; NULL for the administrator
	bool AdminMode;              // the hub administrator logged in
	char UserNameReal[MAX_SIZE]; // name of the user object ("*" for a wildcard login)
	char GroupName[MAX_SIZE];
	bool QoS;              // QoS after the policy and the hub's admin options
	bool LocalHostSession; // the client runs on this host
};

// Session counters that an admitted login holds on its hub and Cedar. HubAdmitSession takes the session
// counters, HubAssignSessionLicense the licence counters; HubReleaseSessionSlot gives all of them back.
struct HUB_SESSION_SLOT {
	HUB *Hub; // NULL: no slot held. The caller holds the hub reference.
	bool UseClientLicense;
	bool UseBridgeLicense;
	bool LicenseAssigned;
};

// Settings of a new login session (NewLoginSession), from the login request and the hub's decision
struct SERVER_SESSION_PARAMS {
	char *Username; // login name, lower case
	char *UserNameReal;
	char *GroupName;
	POLICY *Policy; // the session takes it over
	bool LocalHostSession;
	UINT MaxConnection;
	UINT Timeout; // in ms
	bool UseEncrypt;
	bool UseCompress;
	bool HalfConnection;
	bool QoS;
	UINT AdjustMss;
	bool IPv6Session;
	bool UseUdpAcceleration; // requested by the client; the hub option can still disable it
	UINT UdpAccelVersion;
	bool UseHMacOnUdpAcceleration;
	bool UdpAccelFastDisconnectDetect;
	UCHAR *UdpAccelClientKey; // the client's key of UdpAccelVersion
	IP UdpAccelClientIp;
	UINT UdpAccelClientPort;
};

// A login that ServerAccept admitted, handed to ServerRunSession
struct SERVER_LOGIN {
	SESSION *Session;
	HUB *Hub;   // reference held
	USER *User; // reference held, NULL for the administrator
	HUB_SESSION_SLOT Slot;
	bool NoSavePassword; // "no_save_password" of the last PACK
};

bool ParseLoginRequest(PACK *p, LOGIN_REQ *req);
bool ServerAccept(CONNECTION *c, SERVER_LOGIN *login);
void ServerRunSession(CONNECTION *c, SERVER_LOGIN *login);
void ConnectionAccept(CONNECTION *c);
bool ClientConnect(CONNECTION *c);
SOCK *ClientConnectToServer(CONNECTION *c);

bool ClientUploadSignature(SOCK *s);
bool ClientDownloadHello(CONNECTION *c, SOCK *s);


POLICY *PackGetPolicy(PACK *p);
void PackAddPolicy(PACK *p, POLICY *y);
PACK *PackHello(void *random, UINT ver, UINT build, char *server_str);
bool GetHello(PACK *p, void *random, UINT *ver, UINT *build, char *server_str, UINT server_str_size);


bool ClientAdditionalConnect(CONNECTION *c);
SESSION *NewClientSession(CEDAR *cedar, CLIENT_OPTION *option, CLIENT_AUTH *auth, PACKET_ADAPTER *pa);
SESSION *NewRpcSession(CEDAR *cedar, CLIENT_OPTION *option, UINT *err, char *client_str);
void ClientAdditionalConnectChance(SESSION *s);
void SessionAdditionalConnect(SESSION *s);

void PackAddClientVersion(PACK *p, CONNECTION *c);

bool DownloadAndSaveIntermediateCertificatesIfNecessary(X *x);

#endif
