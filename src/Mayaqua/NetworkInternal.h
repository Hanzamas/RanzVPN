// SoftEther VPN Source Code - Developer Edition Master Branch
// Mayaqua Kernel


// NetworkInternal.h
// Module-internal declarations of the Network module: only its own files include this header

#ifndef	NETWORK_INTERNAL_H
#define	NETWORK_INTERNAL_H

extern LOCK *openssl_lock;

void BindConnectThreadForIPv4(THREAD *thread, void *param);
void BindConnectThreadForIPv6(THREAD *thread, void *param);
SOCK *CreateTCPSock(SOCKET s, bool is_ipv6, IP *current_ip, bool no_get_hostname, char *hostname_original);
void GetCurrentMachineIpProcessHashInternal(void *hash);
void IPToInAddr(struct in_addr *addr, IP *ip);
bool GetHostName(char *hostname, UINT size, IP *ip);
void GetMachineNameEx(char *name, UINT size, bool no_load_hosts);
bool GetMachineNameFromHosts(char *name, UINT size);
void GetMachineHostName(char *name, UINT size);
SOCK *NewSock();
void CleanupSock(SOCK *s);
SOCK *ConnectEx(char *hostname, UINT port, UINT timeout);
SOCK *ConnectEx2(char *hostname, UINT port, UINT timeout, bool *cancel_flag);
SOCK *ConnectEx3(char *hostname, UINT port, UINT timeout, bool *cancel_flag, bool no_get_hostname);
SOCKET BindConnectTimeoutIPv4(IP *localIP, UINT localport, IP *ip, UINT port, UINT timeout, bool *cancel_flag);
bool SetSocketBufferSize(SOCKET s, bool send, UINT size);
UINT SetSocketBufferSizeWithBestEffort(SOCKET s, bool send, UINT size);
void InitUdpSocketBufferSize(SOCKET s);
void QuerySocketInformation(SOCK *sock);
SOCK *ListenEx62(UINT port, bool local_only, bool enable_ca);
SOCK *Accept6(SOCK *sock);
UINT Peek(SOCK *sock, void *data, UINT size);
UINT SecureSend(SOCK *sock, void *data, UINT size);
UINT SecureRecv(SOCK *sock, void *data, UINT size);
bool StartSSLEx2(SOCK *sock, X *x, K *priv, LIST *chain, UINT ssl_timeout, char *sni_hostname);
bool AddChainSslCert(struct ssl_ctx_st *ctx, X *x);
void AddChainSslCertOnDirectory(struct ssl_ctx_st *ctx);
void CleanupCancel(CANCEL *c);
SOCK *NewUDPEx(UINT port, bool ipv6);
SOCK *NewUDP4(UINT port, IP *ip);
SOCK *NewUDP6(UINT port, IP *ip);
UINT SendToEx(SOCK *sock, IP *dest_addr, UINT dest_port, void *data, UINT size, bool broadcast);
UINT SendTo6Ex(SOCK *sock, IP *dest_addr, UINT dest_port, void *data, UINT size, bool broadcast);
UINT RecvFrom6(SOCK *sock, IP *src_addr, UINT *src_port, void *data, UINT size);
UINT GetTimeout(SOCK *sock);
bool CheckTCPPort(char *hostname, UINT port);
bool CheckTCPPortEx(char *hostname, UINT port, UINT timeout);
void CleanupSockEvent(SOCK_EVENT *event);
void InitWaitThread();
void FreeWaitThread();
bool IsSubnetMask(IP *ip);
bool IsSubnetMask4(IP *ip);
UINT IntToSubnetMask32(UINT i);
bool GetNetBiosName(char *name, UINT size, IP *ip);
void SetSockTos(SOCK *s, int tos);
void InitIpClientList();
void FreeIpClientList();
int CompareIpClientList(void *p1, void *p2);
void AddIpClient(IP *ip);
void DelIpClient(IP *ip);
IP_CLIENT *SearchIpClient(IP *ip);
int connect_timeout(SOCKET s, struct sockaddr *addr, int size, int timeout, bool *cancel_flag);
void AddProtocolDetailsKeyValueStr(char *dst, UINT dst_size, char *key, char *value);
bool IsLocalHostIP6(IP *ip);
bool IsLocalHostIP4(IP *ip);
bool CheckIPItemStr6(char *str);
void IPItemStrToChars6(UCHAR *chars, char *str);
bool StrToIP6(IP *ip, char *str);
void IPToStr6(char *str, UINT size, IP *ip);
void IPToStr6Array(char *str, UINT size, UCHAR *bytes);
void IPToStr6Inner(char *str, IP *ip);
void IntToSubnetMask6(IP *ip, UINT i);
void GetAllRouterMulticastAddress6(IP *ip);
void GetAllNodeMulticaseAddress6(IP *ip);
void GetLoopbackAddress6(IP *ip);
void GetPrefixAddress6(IP *dst, IP *ip, IP *subnet);
void GenerateEui64Address6(UCHAR *dst, UCHAR *mac);
bool IsSubnetMask6(IP *a);
UINT SubnetMaskToInt(IP *a);
UINT SubnetMaskToInt4(IP *a);
bool ParseIpAndSubnetMask4(char *src, UINT *ip, UINT *mask);
bool ParseIpAndSubnetMask46(char *src, IP *ip, IP *mask);
void Mask6AddrToStrEx(char *str, UINT size, IPV6_ADDR *mask, bool always_full_address);
void MaskToStr32Ex(char *str, UINT size, UINT mask, bool always_full_address);
void MaskToStrEx(char *str, UINT size, IP *mask, bool always_full_address);
LIST *GetHostIPAddressListInternal();
LIST *GetHostIPAddressList();
int CmpIpAddressList(void *p1, void *p2);
void SetCurrentGlobalIP(IP *ip, bool ipv6);
bool GetCurrentGlobalIP(IP *ip, bool ipv6);
bool IsOnPrivateIPFile(UINT ip);
LIST *GetNicList();
void FreeNicList(LIST *o);
bool IsMacAddressLocalInner(LIST *o, void *addr);
struct ssl_ctx_st *NewSSLCtx(bool server_mode);
void FreeSSLCtx(struct ssl_ctx_st *ctx);
void InitDynList();
void FreeDynList();
UINT64 GetDynValue(char *name);
UINT64 GetDynValueOrDefault(char *name, UINT64 default_value, UINT64 min_value, UINT64 max_value);

#endif	// NETWORK_INTERNAL_H
