// ProtocolInternal.h
// Module-internal declarations of the Protocol module: only its own files include this header

#ifndef PROTOCOL_INTERNAL_H
#define PROTOCOL_INTERNAL_H

UINT HubResolveSessionPolicy(HUB *hub, CONNECTION *c, LOGIN_REQ *req, HUB_LOGIN *login);
UINT HubAdmitSession(HUB *hub, CONNECTION *c, LOGIN_REQ *req, HUB_LOGIN *login, HUB_SESSION_SLOT *slot);
void HubAssignSessionLicense(HUB_SESSION_SLOT *slot);
void HubReleaseSessionSlot(HUB_SESSION_SLOT *slot);
SESSION *NewLoginSession(CONNECTION *c, HUB *hub, SERVER_SESSION_PARAMS *prm, HUB_SESSION_SLOT *slot);
// Bind* functions bind the outgoing connection to a specific local address.
SOCK *BindTcpIpConnectEx(IP *localIP, UINT localport, char *hostname, UINT port, bool *cancel_flag, IP *ret_ip);
bool ServerDownloadSignature(CONNECTION *c);
bool ServerUploadHello(CONNECTION *c);
bool ClientUploadAuth(CONNECTION *c);
SOCK *ClientConnectGetSocket(CONNECTION *c, bool additional_connect);
UINT ProxyCodeToCedar(UINT code);
PACK *PackWelcome(SESSION *s);
PACK *PackLoginWithAnonymous(char *hubname, char *username);
PACK *PackLoginWithPassword(char *hubname, char *username, void *secure_password);
PACK *PackLoginWithPlainPassword(char *hubname, char *username, void *plain_password);
PACK *PackLoginWithCert(char *hubname, char *username, X *x, void *sign, UINT sign_size);
bool GetMethodFromPack(PACK *p, char *method, UINT size);
bool GetHubnameAndUsernameFromPack(PACK *p, char *username, UINT username_size,
                                   char *hubname, UINT hubname_size);
PACK *PackAdditionalConnect(UCHAR *session_key);
UINT GetAuthTypeFromPack(PACK *p);
UINT GetProtocolFromPack(PACK *p);
bool ParseWelcomeFromPack(PACK *p, char *session_name, UINT session_name_size,
                          char *connection_name, UINT connection_name_size,
                          POLICY **policy);
bool ClientUploadAuth2(CONNECTION *c, SOCK *s);
bool GetSessionKeyFromPack(PACK *p, UCHAR *session_key, UINT *session_key_32);
LIST *NewCertList(bool load_root_and_chain);
void FreeCertList(LIST *o);
bool IsXInCertList(LIST *o, X *x);
void AddAllRootCertsToCertList(LIST *o);
void AddAllChainCertsToCertList(LIST *o);
X *DownloadCert(char *url);
X *FindCertIssuerFromCertList(LIST *o, X *x);
bool TryGetRootCertChain(LIST *o, X *x, bool auto_save, X **found_root_x);
bool TryGetParentCertFromCertList(LIST *o, X *x, LIST *found_chain);

#endif // PROTOCOL_INTERNAL_H
