// NetworkInternal.h
// Module-internal declarations of the Network module: only its own files include this header

#ifndef NETWORK_INTERNAL_H
#define NETWORK_INTERNAL_H

#define PQ_GROUP_LIST "X25519MLKEM768:p521_kyber1024:x25519_kyber768:P-521:X25519:P-256"

SOCK *CreateTCPSock(SOCKET s, bool is_ipv6, char *hostname_original);
bool GetHostName(char *hostname, UINT size, const IP *ip);
SOCK *NewSock();
void CleanupSock(SOCK *s);
void InitUdpSocketBufferSize(SOCKET s);
void QuerySocketInformation(SOCK *sock);
bool AddChainSslCert(struct ssl_ctx_st *ctx, X *x);
SOCK *NewUDP(UINT port);
bool GetNetBiosName(char *name, UINT size, const IP *ip);
bool IsIPv6Supported();
int CompareIpClientList(void *p1, void *p2);
IP_CLIENT *SearchIpClient(const IP *ip);
LIST *GetHostIPAddressListInternal();
LIST *GetHostIPAddressList();
bool IsOnPrivateIPFile(UINT ip);
LIST *GetNicList();
void FreeNicList(LIST *o);
bool IsMacAddressLocalInner(LIST *o, void *addr);
LIST *Win32GetNicList();

#endif // NETWORK_INTERNAL_H
