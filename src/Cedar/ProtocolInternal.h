// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module
// © 2020 Nokia

// ProtocolInternal.h
// Module-internal declarations of the Protocol module: only its own files include this header

#ifndef	PROTOCOL_INTERNAL_H
#define	PROTOCOL_INTERNAL_H

// New function named with prefix "Bind" binds outgoing connection to a specific address.
SOCK* BindTcpIpConnectEx(IP *localIP, UINT localport, char *hostname, UINT port, bool *cancel_flag, void *hWnd, IP *ret_ip);
bool ServerDownloadSignature(CONNECTION *c, char **error_detail_str);
bool ServerUploadHello(CONNECTION *c);
bool ClientUploadAuth(CONNECTION *c);
SOCK *ClientConnectGetSocket(CONNECTION *c, bool additional_connect);
// New function named with prefix "Bind" binds outgoing connection to a specific address. New one is wrapped in original one.
SOCK* BindTcpConnectEx3(IP *localIP, UINT localport, char *hostname, UINT port, UINT timeout, bool *cancel_flag, void *hWnd, IP *ret_ip);
PACK *PackWelcome(SESSION *s);
PACK *PackHello(void *random, UINT ver, UINT build, char *server_str);
bool GetHello(PACK *p, void *random, UINT *ver, UINT *build, char *server_str, UINT server_str_size);
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
SOCK *ClientAdditionalConnectToServer(CONNECTION *c);
bool ClientUploadAuth2(CONNECTION *c, SOCK *s);
bool GetSessionKeyFromPack(PACK *p, UCHAR *session_key, UINT *session_key_32);
void CreateNodeInfo(NODE_INFO *info, CONNECTION *c);
bool ClientCheckServerCert(CONNECTION *c, bool *expired);
void ClientCheckServerCertThread(THREAD *thread, void *param);
TOKEN_LIST *EnumHub(SESSION *s);
UINT ChangePasswordAccept(CONNECTION *c, PACK *p);
void NodeInfoToStr(wchar_t *str, UINT size, NODE_INFO *info);
LIST *NewCertList(bool load_root_and_chain);
void FreeCertList(LIST *o);
bool IsXInCertList(LIST *o, X *x);
void AddXToCertList(LIST *o, X *x);
void AddAllRootCertsToCertList(LIST *o);
void AddAllChainCertsToCertList(LIST *o);
X *DownloadCert(char *url);
X *FindCertIssuerFromCertList(LIST *o, X *x);
bool TryGetRootCertChain(LIST *o, X *x, bool auto_save, X **found_root_x);
bool TryGetParentCertFromCertList(LIST *o, X *x, LIST *found_chain);

#endif	// PROTOCOL_INTERNAL_H
