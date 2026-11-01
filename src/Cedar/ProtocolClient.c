// ProtocolClient.c
// SE-VPN protocol, client-connect side: ClientConnect, additional connections, node info, hello, authentication and signature upload, login PACKs, socket and proxy connect (used by cascade connections)

#include "Protocol.h"

#include "Account.h"
#include "Admin.h"
#include "Link.h"
#include "Sam.h"
#include "Server.h"
#include "WaterMark.h"

#include "Mayaqua/Cfg.h"
#include "Mayaqua/DNS.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Pack.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Table.h"
#include "Mayaqua/Tick64.h"

#include <winhttp.h>
#include "ProtocolInternal.h"

// An address goes into the IPv4 field of a NODE_INFO, or into its IPv6 field when it is an IPv6 address
static void NodeInfoSetIp(UINT *ip4, UCHAR *ip6, IP *ip) {
	if (IsIP6(ip) == false)
		*ip4 = IPToUINT(ip);
	else
		Copy(ip6, ip->address, sizeof(ip->address));
}

static void CreateNodeInfo(NODE_INFO *info, CONNECTION *c) {
	IP ip;
	wchar_t namew[256];
	char namea[256];
	if (c == NULL)
		return;

	SESSION *s = c->Session;
	OS_INFO *os = GetOsInfo();


	Zero(info, sizeof(NODE_INFO));

	StrCpy(info->ClientProductName, sizeof(info->ClientProductName), c->ClientStr);
	info->ClientProductVer = Endian32(c->ClientVer);
	info->ClientProductBuild = Endian32(c->ClientBuild);

	StrCpy(info->ServerProductName, sizeof(info->ServerProductName), c->ServerStr);
	info->ServerProductVer = Endian32(c->ServerVer);
	info->ServerProductBuild = Endian32(c->ServerBuild);

	StrCpy(info->ClientOsName, sizeof(info->ClientOsName), os->OsProductName);
	StrCpy(info->ClientOsVer, sizeof(info->ClientOsVer), os->OsVersion);
	StrCpy(info->ClientOsProductId, sizeof(info->ClientOsProductId), "--");

	Zero(namew, sizeof(namew));
	MsGetComputerNameFullEx(namew, sizeof(namew), true);

	Zero(namea, sizeof(namea));
	UniToStr(namea, sizeof(namea), namew);

	if (IsEmptyStr(namea))
		GetMachineName(namea, sizeof(namea));

	StrCpy(info->ClientHostname, sizeof(info->ClientHostname), namea);

	NodeInfoSetIp(&info->ClientIpAddress, info->ClientIpAddress6, &c->FirstSock->LocalIP);
	info->ClientPort = Endian32(c->FirstSock->LocalPort);

	StrCpy(info->ServerHostname, sizeof(info->ServerHostname), c->ServerName);
	if (s->ClientOption->ProxyType == PROXY_DIRECT)
		NodeInfoSetIp(&info->ServerIpAddress, info->ServerIpAddress6, &c->FirstSock->RemoteIP);
	else if (GetIP(&ip, info->ServerHostname))
		NodeInfoSetIp(&info->ServerIpAddress, info->ServerIpAddress6, &ip);
	info->ServerPort = Endian32(c->ServerPort);

	if (s->ClientOption->ProxyType == PROXY_SOCKS || s->ClientOption->ProxyType == PROXY_HTTP) {
		StrCpy(info->ProxyHostname, sizeof(info->ProxyHostname), s->ClientOption->ProxyName);

		NodeInfoSetIp(&info->ProxyIpAddress, info->ProxyIpAddress6, &c->FirstSock->RemoteIP);

		info->ProxyPort = Endian32(c->FirstSock->RemotePort);
	}

	StrCpy(info->HubName, sizeof(info->HubName), s->ClientOption->HubName);

	Copy(info->UniqueId, c->Cedar->UniqueId, sizeof(info->UniqueId));
}

// Take s off c->ConnectingSocks (dropping the ref the list holds) and drop the caller's own ref of s
static void ConnectingSockRemove(CONNECTION *c, SOCK *s) {
	LockList(c->ConnectingSocks);
	{
		if (Delete(c->ConnectingSocks, s))
			ReleaseSock(s);
	}
	UnlockList(c->ConnectingSocks);
	ReleaseSock(s);
}

static SOCK *ClientAdditionalConnectToServer(CONNECTION *c) {
	if (c == NULL)
		return NULL;

	SOCK *s = ClientConnectGetSocket(c, true);
	if (s == NULL)
		return NULL;

	LockList(c->ConnectingSocks);
	{
		Add(c->ConnectingSocks, s);
		AddRef(s->ref);
	}
	UnlockList(c->ConnectingSocks);

	if (c->Session->Halt) {
		Disconnect(s);
		ConnectingSockRemove(c, s);
		return NULL;
	}

	SetTimeout(s, CONNECTING_TIMEOUT);

	if (StartSSLEx(s, NULL, NULL, c->ServerName) == false) {
		Disconnect(s);
		ConnectingSockRemove(c, s);
		return NULL;
	}

	if (CompareX(s->RemoteX, c->ServerX) == false) {
		// The server of an additional connection presents another certificate than the
		// first one: drop the socket and fail, like the other failures above
		Disconnect(s);
		c->Session->SessionTimeOuted = true;
		ConnectingSockRemove(c, s);
		return NULL;
	}

	return s;
}

bool ClientAdditionalConnect(CONNECTION *c) {
	SOCK *s;
	PACK *p;
	TCPSOCK *ts;
	UINT err;
	UINT direction;

	if (c == NULL)
		return false;

	s = ClientAdditionalConnectToServer(c);
	if (s == NULL)
		return false;

	if (FlagRead(&c->Halt))
		goto CLEANUP;

	if (ClientUploadSignature(s) == false)
		goto CLEANUP;

	if (FlagRead(&c->Halt))
		goto CLEANUP;

	if (ClientDownloadHello(c, s) == false)
		goto CLEANUP;

	if (FlagRead(&c->Halt))
		goto CLEANUP;

	if (ClientUploadAuth2(c, s) == false)
		goto CLEANUP;

	p = HttpClientRecvEx(s, HTTP_PACK_MAX_SIZE);
	if (p == NULL)
		goto CLEANUP;

	err = GetErrorFromPack(p);
	direction = PackGetInt(p, "direction");

	FreePack(p);
	p = NULL;

	if (err != 0) {
		if (err == ERR_SESSION_TIMEOUT || err == ERR_INVALID_PROTOCOL)
			c->Session->SessionTimeOuted = true;
		goto CLEANUP;
	}


	ts = NewTcpSock(s);

	if (c->ServerMode == false) {
		if (c->Session->ClientOption->ConnectionDisconnectSpan != 0)
			ts->DisconnectTick = Tick64() + c->Session->ClientOption->ConnectionDisconnectSpan * (UINT64)1000;
	}

	LockList(c->Tcp->TcpSockList);
	{
		ts->Direction = direction;
		Add(c->Tcp->TcpSockList, ts);
	}
	UnlockList(c->Tcp->TcpSockList);

	Cancel(c->Session->Cancel1);

	ConnectingSockRemove(c, s);
	return true;

CLEANUP:
	Disconnect(s);
	ConnectingSockRemove(c, s);
	return false;
}

bool ClientConnect(CONNECTION *c) {
	bool ret = false;
	UINT err;
	SOCK *s;
	PACK *p = NULL;
	UINT session_key_32;
	SESSION *sess;
	char session_name[MAX_SESSION_NAME_LEN + 1];
	char connection_name[MAX_CONNECTION_NAME_LEN + 1];
	UCHAR session_key[SHA1_SIZE];
	POLICY *policy;
	UINT utf_size;
	char *utf;
	wchar_t *msg;
	if (c == NULL)
		return false;

	sess = c->Session;

	c->Status = CONNECTION_STATUS_CONNECTING;
	c->Session->ClientStatus = CLIENT_STATUS_CONNECTING;

	s = ClientConnectToServer(c);
	if (s == NULL) {
		// Do not retry if untrusted or hostname mismatched
		if (c->Session->LinkModeClient == false && (c->Err == ERR_CERT_NOT_TRUSTED || c->Err == ERR_HOSTNAME_MISMATCH))
			c->Session->ForceStopFlag = true;
		return false;
	}

	if (FlagRead(&c->Halt)) {
		c->Err = ERR_USER_CANCEL;
		goto CLEANUP;
	}

	c->Session->ClientStatus = CLIENT_STATUS_NEGOTIATION;

	if (sess->ClientOption != NULL && sess->ClientOption->NoUdpAcceleration == false) {
		if (sess->ClientOption->ProxyType == PROXY_DIRECT) {
			if (s->Type == SOCK_TCP) {
				if (sess->UdpAccel == NULL) {
					sess->UdpAccel = NewUdpAccel(c->Cedar, &s->LocalIP, true);

					UdpAccelQueryStun(sess->UdpAccel, &s->RemoteIP);
				}
			}
		}
	}

	if (ClientUploadSignature(s) == false) {
		c->Err = ERR_DISCONNECTED;
		goto CLEANUP;
	}

	if (FlagRead(&c->Halt)) {
		c->Err = ERR_USER_CANCEL;
		goto CLEANUP;
	}

	if (ClientDownloadHello(c, s) == false)
		goto CLEANUP;

	if (FlagRead(&c->Halt)) {
		c->Err = ERR_USER_CANCEL;
		goto CLEANUP;
	}


	c->Session->ClientStatus = CLIENT_STATUS_AUTH;

	if (ClientUploadAuth(c) == false)
		goto CLEANUP;

	if (FlagRead(&c->Halt)) {
		c->Err = ERR_USER_CANCEL;
		goto CLEANUP;
	}

	p = HttpClientRecvEx(s, CLIENT_WELCOME_PACK_MAX_SIZE);
	if (p == NULL) {
		c->Err = ERR_DISCONNECTED;
		goto CLEANUP;
	}

	err = GetErrorFromPack(p);
	if (err != 0) {
		c->Err = err;
		goto CLEANUP;
	}

	utf_size = PackGetDataSize(p, "Msg");
	utf = ZeroMalloc(utf_size + 8);
	PackGetData(p, "Msg", utf);

	msg = CopyUtfToUni(utf);

	if (UniIsEmptyStr(msg) == false) {
		if (c->Session->Client_Message != NULL)
			Free(c->Session->Client_Message);

		c->Session->Client_Message = msg;
	} else {
		Free(msg);
	}

	Free(utf);

	if (ParseWelcomeFromPack(p, session_name, sizeof(session_name),
	                         connection_name, sizeof(connection_name), &policy) == false) {
		c->Err = ERR_PROTOCOL_ERROR;
		goto CLEANUP;
	}

	if (GetSessionKeyFromPack(p, session_key, &session_key_32) == false) {
		Free(policy);
		policy = NULL;
		c->Err = ERR_PROTOCOL_ERROR;
		goto CLEANUP;
	}

	Copy(c->Session->SessionKey, session_key, SHA1_SIZE);
	c->Session->SessionKey32 = session_key_32;


	Lock(c->Session->lock);
	{
		c->Session->MaxConnection = PackGetInt(p, "max_connection");
		c->Session->MaxConnection = MIN(c->Session->MaxConnection, c->Session->ClientOption->MaxConnection);
		c->Session->MaxConnection = MIN(c->Session->MaxConnection, MAX_TCP_CONNECTION);
		c->Session->MaxConnection = MAX(c->Session->MaxConnection, 1);
		c->Session->UseCompress = PackGetInt(p, "use_compress") == 0 ? false : true;
		c->Session->UseEncrypt = PackGetInt(p, "use_encrypt") == 0 ? false : true;
		c->Session->NoSendSignature = PackGetBool(p, "no_send_signature");
		c->Session->HalfConnection = PackGetInt(p, "half_connection") == 0 ? false : true;
		c->Session->Timeout = PackGetInt(p, "timeout");
		// Clamped to the bounds of ServerAccept: the server chooses it, and GenNextKeepAliveSpan divides it by 2
		c->Session->Timeout = MIN(c->Session->Timeout, TIMEOUT_MAX);
		c->Session->Timeout = MAX(c->Session->Timeout, TIMEOUT_MIN);
		c->Session->QoS = PackGetInt(p, "qos") == 0 ? false : true;
		if (c->Session->QoS)
			c->Session->MaxConnection = MAX(c->Session->MaxConnection, (UINT)(c->Session->HalfConnection ? 4 : 2));
		c->Session->VLanId = PackGetInt(p, "vlan_id");

		StrCpy(c->Session->UnderlayProtocol, sizeof(c->Session->UnderlayProtocol), s->UnderlayProtocol);

		AddProtocolDetailsStr(c->Session->ProtocolDetails, sizeof(c->Session->ProtocolDetails), s->ProtocolDetails);

		sess->UseUdpAcceleration = false;
		sess->IsUsingUdpAcceleration = false;

		if (sess->UdpAccel != NULL) {
			sess->UdpAccel->UseHMac = false;

			sess->UdpAccelFastDisconnectDetect = false;

			if (PackGetBool(p, "use_udp_acceleration")) {
				UINT udp_acceleration_version = PackGetInt(p, "udp_acceleration_version");
				IP udp_acceleration_server_ip;

				if (udp_acceleration_version == 0)
					udp_acceleration_version = 1;

				sess->UdpAccelFastDisconnectDetect = PackGetBool(p, "udp_accel_fast_disconnect_detect");

				if (PackGetIp(p, "udp_acceleration_server_ip", &udp_acceleration_server_ip)) {
					UINT udp_acceleration_server_port = PackGetInt(p, "udp_acceleration_server_port");

					if (IsZeroIP(&udp_acceleration_server_ip))
						Copy(&udp_acceleration_server_ip, &s->RemoteIP, sizeof(IP));

					if (udp_acceleration_server_port != 0) {
						UCHAR udp_acceleration_server_key[UDP_ACCELERATION_COMMON_KEY_SIZE_V1];
						UCHAR udp_acceleration_server_key_v2[UDP_ACCELERATION_COMMON_KEY_SIZE_V2];
						UINT server_cookie = PackGetInt(p, "udp_acceleration_server_cookie");
						UINT client_cookie = PackGetInt(p, "udp_acceleration_client_cookie");
						bool encryption = PackGetBool(p, "udp_acceleration_use_encryption");

						Zero(udp_acceleration_server_key, sizeof(udp_acceleration_server_key));
						Zero(udp_acceleration_server_key_v2, sizeof(udp_acceleration_server_key_v2));

						PackGetData2(p, "udp_acceleration_server_key", udp_acceleration_server_key, UDP_ACCELERATION_COMMON_KEY_SIZE_V1);
						PackGetData2(p, "udp_acceleration_server_key_v2", udp_acceleration_server_key_v2, UDP_ACCELERATION_COMMON_KEY_SIZE_V2);

						if (server_cookie != 0 && client_cookie != 0) {
							IP remote_ip;

							Copy(&remote_ip, &s->RemoteIP, sizeof(IP));

							sess->UdpAccel->Version = 1;
							if (udp_acceleration_version == 2)
								sess->UdpAccel->Version = 2;

							if (UdpAccelInitClient(sess->UdpAccel,
							                       sess->UdpAccel->Version == 2 ? udp_acceleration_server_key_v2 : udp_acceleration_server_key,
							                       &remote_ip, &udp_acceleration_server_ip, udp_acceleration_server_port,
							                       server_cookie, client_cookie)) {
								sess->UseUdpAcceleration = true;

								sess->UdpAccel->FastDetect = sess->UdpAccelFastDisconnectDetect;

								sess->UdpAccel->PlainTextMode = !encryption;

								sess->UdpAccel->UseHMac = PackGetBool(p, "use_hmac_on_udp_acceleration");

								UdpAccelAddProtocolDetails(sess->UdpAccel, sess->ProtocolDetails, sizeof(sess->ProtocolDetails));
							}
						}
					}
				}
			}
		}
	}
	Unlock(c->Session->lock);


	if (sess->UseUdpAcceleration == false) {
		if (sess->UdpAccel != NULL) {
			FreeUdpAccel(sess->UdpAccel);
			sess->UdpAccel = NULL;
		}
	}

	Lock(c->lock);
	{
		if (c->Name != NULL)
			Free(c->Name);
		c->Name = CopyStr(connection_name);

		if (c->CipherName != NULL)
			Free(c->CipherName);

		c->CipherName = CopyStr(c->FirstSock->CipherName);

		if (c->SslVersion != NULL)
			Free(c->SslVersion);

		c->SslVersion = CopyStr(c->FirstSock->SslVersion);
	}
	Unlock(c->lock);

	Lock(c->Session->lock);
	{
		if (c->Session->Name != NULL)
			Free(c->Session->Name);
		c->Session->Name = CopyStr(session_name);

		c->Session->Policy = policy;
	}
	Unlock(c->Session->lock);

	FreePack(p);
	p = NULL;


	c->Session->ClientStatus = CLIENT_STATUS_ESTABLISHED;

	if (c->ServerX == NULL)
		c->ServerX = CloneX(c->FirstSock->RemoteX);

	StartTunnelingMode(c);
	s = NULL;

	if (c->Session->HalfConnection) {
		TCPSOCK *ts = (TCPSOCK *)LIST_DATA(c->Tcp->TcpSockList, 0);
		ts->Direction = TCP_CLIENT_TO_SERVER;
	}

	if (c->Session->LinkModeClient && c->Session->Link != NULL)
		HLog(c->Session->Link->Hub, "LH_CONNECT_2", c->Session->ClientOption->AccountName, session_name);

	SessionMain(c->Session);

	if (c->Err == ERR_USER_CANCEL)
		ret = true;

CLEANUP:
	// StopConnection reads c->FirstSock and takes its ref under c->lock
	Lock(c->lock);
	{
		c->FirstSock = NULL;
	}
	Unlock(c->lock);

	if (sess->UdpAccel != NULL) {
		FreeUdpAccel(sess->UdpAccel);
		sess->UdpAccel = NULL;
	}

	if (p != NULL)
		FreePack(p);

	Disconnect(s);
	ReleaseSock(s);

	return ret;
}

bool ClientUploadAuth(CONNECTION *c) {
	PACK *p = NULL;
	NODE_INFO info;
	UCHAR secure_password[SHA1_SIZE];
	UCHAR sign[4096 / 8];
	UCHAR unique[SHA1_SIZE];
	RPC_WINVER v;
	if (c == NULL)
		return false;

	Zero(sign, sizeof(sign));

	CLIENT_AUTH *a = c->Session->ClientAuth;
	CLIENT_OPTION *o = c->Session->ClientOption;

	switch (a->AuthType) {
	case CLIENT_AUTHTYPE_ANONYMOUS:
		p = PackLoginWithAnonymous(o->HubName, a->Username);
		break;

	case CLIENT_AUTHTYPE_PASSWORD:
		SecurePassword(secure_password, a->HashedPassword, c->Random);
		p = PackLoginWithPassword(o->HubName, a->Username, secure_password);
		break;

	case CLIENT_AUTHTYPE_PLAIN_PASSWORD:
		p = PackLoginWithPlainPassword(o->HubName, a->Username, a->PlainPassword);
		break;

	case CLIENT_AUTHTYPE_CERT:
		if (a->ClientX != NULL && a->ClientX->is_compatible_bit &&
		    a->ClientX->bits != 0 && (a->ClientX->bits / 8) <= sizeof(sign)) {
			if (RsaSignEx(sign, sizeof(sign), c->Random, SHA1_SIZE, a->ClientK)) {
				p = PackLoginWithCert(o->HubName, a->Username, a->ClientX, sign, a->ClientX->bits / 8);
				c->ClientX = CloneX(a->ClientX);
			}
		}
		break;
	}

	if (p == NULL) {
		c->Err = ERR_PROTOCOL_ERROR;
		return false;
	}

	PackAddClientVersion(p, c);

	PackAddInt(p, "protocol", c->Protocol);

	PackAddStr(p, "hello", c->ClientStr);
	PackAddInt(p, "version", c->ClientVer);
	PackAddInt(p, "build", c->ClientBuild);
	PackAddInt(p, "client_id", 0);

	PackAddInt(p, "max_connection", o->MaxConnection);
	PackAddInt(p, "use_encrypt", o->UseEncrypt == false ? 0 : 1);
	PackAddInt(p, "use_compress", o->UseCompress == false ? 0 : 1);
	PackAddInt(p, "half_connection", o->HalfConnection == false ? 0 : 1);

	PackAddBool(p, "require_bridge_routing_mode", o->RequireBridgeRoutingMode);

	PackAddBool(p, "require_monitor_mode", o->RequireMonitorMode);

	PackAddBool(p, "qos", o->DisableQoS ? false : true);

	GenerateMachineUniqueHash(c->Cedar, unique);
	PackAddData(p, "unique_id", unique, SHA1_SIZE);

	if (o->NoUdpAcceleration == false && c->Session->UdpAccel != NULL) {
		PackAddBool(p, "use_udp_acceleration", true);

		PackAddInt(p, "udp_acceleration_version", c->Session->UdpAccel->Version);

		IP my_ip;
		UINT my_port = c->Session->UdpAccel->MyPort;
		if (c->Session->UdpAccel->UseStun) {
			Copy(&my_ip, &c->Session->UdpAccel->StunIp, sizeof(my_ip));
			my_port = c->Session->UdpAccel->StunPort;
		} else if (IsLocalHostIP(&c->Session->UdpAccel->MyIp) == false) {
			Copy(&my_ip, &c->Session->UdpAccel->MyIp, sizeof(my_ip));
		} else {
			Zero(&my_ip, sizeof(my_ip));
		}

		PackAddIp(p, "udp_acceleration_client_ip", &my_ip);
		PackAddInt(p, "udp_acceleration_client_port", my_port);
		PackAddData(p, "udp_acceleration_client_key", c->Session->UdpAccel->MyKey, UDP_ACCELERATION_COMMON_KEY_SIZE_V1);
		PackAddData(p, "udp_acceleration_client_key_v2", c->Session->UdpAccel->MyKey_V2, UDP_ACCELERATION_COMMON_KEY_SIZE_V2);
		PackAddBool(p, "support_hmac_on_udp_acceleration", true);
		PackAddBool(p, "support_udp_accel_fast_disconnect_detect", true);
		PackAddInt(p, "udp_acceleration_max_version", 2);
	}

	CreateNodeInfo(&info, c);
	OutRpcNodeInfo(p, &info);

	GetWinVer(&v);
	OutRpcWinVer(p, &v);

	bool ret = HttpClientSend(c->FirstSock, p);
	if (ret == false)
		c->Err = ERR_DISCONNECTED;

	FreePack(p);

	return ret;
}

bool ParseWelcomeFromPack(PACK *p, char *session_name, UINT session_name_size,
                          char *connection_name, UINT connection_name_size,
                          POLICY **policy) {
	if (p == NULL || session_name == NULL || connection_name == NULL || policy == NULL)
		return false;

	if (PackGetStr(p, "session_name", session_name, session_name_size) == false)
		return false;

	if (PackGetStr(p, "connection_name", connection_name, connection_name_size) == false)
		return false;

	*policy = PackGetPolicy(p);
	if (*policy == NULL)
		return false;

	return true;
}

POLICY *PackGetPolicy(PACK *p) {
	if (p == NULL)
		return NULL;

	POLICY *y = ZeroMalloc(sizeof(POLICY));

	for (UINT i = 0; i < NUM_POLICY_ITEM; i++) {
		POLICY_ITEM *item = &policy_item[i];
		char name[MAX_SIZE];

		Format(name, sizeof(name), "policy:%s", item->Name);

		SetPolicyValue(y, i, item->TypeInt ? PackGetInt(p, name) : PackGetBool(p, name));
	}

	// Ver 3 flag
	y->Ver3 = PackGetBool(p, "policy:Ver3");

	return y;
}

bool ClientUploadAuth2(CONNECTION *c, SOCK *s) {
	PACK *p = NULL;
	if (c == NULL)
		return false;

	p = PackAdditionalConnect(c->Session->SessionKey);

	PackAddClientVersion(p, c);

	if (HttpClientSend(s, p) == false) {
		FreePack(p);
		return false;
	}
	FreePack(p);

	return true;
}

void PackAddClientVersion(PACK *p, CONNECTION *c) {
	if (p == NULL || c == NULL)
		return;

	PackAddStr(p, "client_str", c->ClientStr);
	PackAddInt(p, "client_ver", c->ClientVer);
	PackAddInt(p, "client_build", c->ClientBuild);
}

bool ClientDownloadHello(CONNECTION *c, SOCK *s) {
	UINT err;
	UCHAR random[SHA1_SIZE];
	if (c == NULL)
		return false;

	PACK *p = HttpClientRecvEx(s, HTTP_PACK_MAX_SIZE);
	if (p == NULL) {
		c->Err = ERR_SERVER_IS_NOT_VPN;
		return false;
	}

	if (err = GetErrorFromPack(p)) {
		c->Err = err;
		FreePack(p);
		return false;
	}

	if (GetHello(p, random, &c->ServerVer, &c->ServerBuild, c->ServerStr, sizeof(c->ServerStr)) == false) {
		c->Err = ERR_SERVER_IS_NOT_VPN;
		FreePack(p);
		return false;
	}

	if (c->FirstSock == s)
		Copy(c->Random, random, SHA1_SIZE);

	FreePack(p);

	return true;
}

bool ClientUploadSignature(SOCK *s) {
	char ip_str[128];
	if (s == NULL)
		return false;

	IPToStr(ip_str, sizeof(ip_str), &s->RemoteIP);

	HTTP_HEADER *h = NewHttpHeader("POST", HTTP_VPN_TARGET2, "HTTP/1.1");
	AddHttpValue(h, NewHttpValue("Host", ip_str));
	AddHttpValue(h, NewHttpValue("Content-Type", HTTP_CONTENT_TYPE3));
	AddHttpValue(h, NewHttpValue("Connection", "Keep-Alive"));


	UINT rand_size = Rand32() % (HTTP_PACK_RAND_SIZE_MAX * 2);
	UINT water_size = WaterMarkSize + rand_size;
	UCHAR *water = Malloc(water_size);
	Copy(water, WaterMark, WaterMarkSize);
	Rand(&water[WaterMarkSize], rand_size);

	if (PostHttp(s, h, water, water_size) == false) {
		Free(water);
		FreeHttpHeader(h);
		return false;
	}

	Free(water);
	FreeHttpHeader(h);

	return true;
}

// Set c->FirstSock under c->lock, where StopConnection reads it and takes its ref
static void ClientSetFirstSock(CONNECTION *c, SOCK *s) {
	Lock(c->lock);
	{
		c->FirstSock = s;
	}
	Unlock(c->lock);
}

SOCK *ClientConnectToServer(CONNECTION *c) {
	SOCK *s = NULL;
	if (c == NULL)
		return NULL;

	if (FlagRead(&c->Halt)) {
		c->Err = ERR_USER_CANCEL;
		return NULL;
	}

	s = ClientConnectGetSocket(c, false);
	if (s == NULL)
		return NULL;

	// StopConnection reads c->FirstSock and takes its ref under c->lock
	ClientSetFirstSock(c, s);

	if (FlagRead(&c->Halt)) {
		c->Err = ERR_USER_CANCEL;
		ClientSetFirstSock(c, NULL);
		ReleaseSock(s);
		return NULL;
	}

	SetTimeout(s, CONNECTING_TIMEOUT);

	UINT ssl_err = TLS_ERR_NONE;
	if (StartSSLEx3(s, NULL, NULL, NULL, c->ServerName, c->Session->SslOption, &ssl_err) == false) {
		UINT err = TlsErrToCedarErr(ssl_err);

		Disconnect(s);
		ClientSetFirstSock(c, NULL);
		ReleaseSock(s);
		if (err != ERR_NO_ERROR)
			c->Err = err;
		else
			c->Err = ERR_SERVER_IS_NOT_VPN;
		return NULL;
	}

	if (s->RemoteX == NULL) {
		Disconnect(s);
		ClientSetFirstSock(c, NULL);
		ReleaseSock(s);
		c->Err = ERR_SERVER_IS_NOT_VPN;
		return NULL;
	}

	return s;
}

SOCK *ClientConnectGetSocket(CONNECTION *c, bool additional_connect) {
	volatile bool *cancel_flag = NULL;
	char hostname[MAX_HOST_NAME_LEN];

	bool save_resolved_ip = false;
	SOCK *sock = NULL;
	IP resolved_ip;
	IP *bind_ip;
	UINT bind_port;
	if (c == NULL || c->Session == NULL || c->Session->ClientOption == NULL)
		return NULL;

	cancel_flag = &c->Halt;
	SESSION *sess = c->Session;
	CLIENT_OPTION *o = c->Session->ClientOption;

	Zero(&resolved_ip, sizeof(resolved_ip));

	// The local address and port to bind, the same for a direct and a proxy connection
	if (additional_connect == false) {
		if (o->NoRoutingTracking == false || IsZeroIP(&o->BindLocalIP)) {
			bind_ip = BIND_LOCALIP_NULL;
		} else {
			// A nonzero address is the source IP address to bind, a zero address does not bind
			bind_ip = &o->BindLocalIP;
		}
	} else {
		// Bind to the local IP address of the first TCP/IP connection
		bind_ip = &sess->LocalIP_CacheForNextConnect;
	}

	if (o->BindLocalPort == 0)
		bind_port = BIND_LOCALPORT_NULL;
	else
		bind_port = o->BindLocalPort + Count(sess->Connection->CurrentNumConnection) - 1;

	if (additional_connect && IsZeroIP(&sess->ServerIP_CacheForNextConnect) == false) {
		IPToStr(hostname, sizeof(hostname), &sess->ServerIP_CacheForNextConnect);
	} else {
		IP tmp;

		StrCpy(hostname, sizeof(hostname), o->ProxyType == PROXY_DIRECT ? c->ServerName : o->ProxyName);

		if (StrToIP(&tmp, hostname) == false)
			save_resolved_ip = true;
	}

	if (o->ProxyType == PROXY_DIRECT) {
		sock = BindTcpIpConnectEx(bind_ip, bind_port, hostname, c->ServerPort,
		                          (bool *)cancel_flag, &resolved_ip);

		if (sock == NULL) {
			c->Err = ERR_CONNECT_FAILED;

			return NULL;
		}
	} else {
		PROXY_PARAM_OUT out;
		PROXY_PARAM_IN in;

		Zero(&in, sizeof(in));

		in.Timeout = 0;

		StrCpy(in.TargetHostname, sizeof(in.TargetHostname), c->ServerName);
		in.TargetPort = c->ServerPort;

		StrCpy(in.Hostname, sizeof(in.Hostname), IsEmptyStr(hostname) ? o->ProxyName : hostname);
		in.Port = o->ProxyPort;

		StrCpy(in.Username, sizeof(in.Username), o->ProxyUsername);
		StrCpy(in.Password, sizeof(in.Password), o->ProxyPassword);

		StrCpy(in.HttpCustomHeader, sizeof(in.HttpCustomHeader), o->CustomHttpHeader);
		StrCpy(in.HttpUserAgent, sizeof(in.HttpUserAgent), c->Cedar->HttpUserAgent);

		in.BindLocalIP = bind_ip;
		in.BindLocalPort = bind_port;

		// An unknown proxy type gives PROXY_ERROR_PARAMETER, which is ERR_INTERNAL_ERROR
		UINT ret = ProxyConnect(o->ProxyType, &out, &in, cancel_flag);

		c->Err = ProxyCodeToCedar(ret);

		if (c->Err != ERR_NO_ERROR)
			return NULL;

		sock = out.Sock;

		CopyIP(&resolved_ip, &out.ResolvedIp);
	}

	if (additional_connect == false || IsZeroIP(&sock->RemoteIP)) {
		if (IsZeroIP(&sock->RemoteIP) == false || (sock->IPv6 && GetIP6(&c->Session->ServerIP, hostname) == false) || (sock->IPv6 == false && GetIP4(&c->Session->ServerIP, hostname) == false))
			Copy(&c->Session->ServerIP, &sock->RemoteIP, sizeof(c->Session->ServerIP));
	}

	if (save_resolved_ip && IsZeroIP(&resolved_ip) == false)
		Copy(&c->Session->ServerIP_CacheForNextConnect, &resolved_ip, sizeof(c->Session->ServerIP_CacheForNextConnect));

	if (additional_connect == false)
		c->Session->LocalIP_CacheForNextConnect = sock->LocalIP;

	return sock;
}

UINT ProxyCodeToCedar(UINT code) {
	switch (code) {
	case PROXY_ERROR_SUCCESS:
		return ERR_NO_ERROR;
	case PROXY_ERROR_GENERIC:
	case PROXY_ERROR_VERSION:
		return ERR_PROXY_ERROR;
	case PROXY_ERROR_CANCELED:
		return ERR_USER_CANCEL;
	case PROXY_ERROR_CONNECTION:
		return ERR_PROXY_CONNECT_FAILED;
	case PROXY_ERROR_TARGET:
		return ERR_CONNECT_FAILED;
	case PROXY_ERROR_DISCONNECTED:
		return ERR_DISCONNECTED;
	case PROXY_ERROR_AUTHENTICATION:
		return ERR_PROXY_AUTH_FAILED;
	default:
		return ERR_INTERNAL_ERROR;
	}
}

SOCK *BindTcpIpConnectEx(IP *localIP, UINT localport, char *hostname, UINT port, bool *cancel_flag, IP *ret_ip) {
	SOCK *s = NULL;
	if (hostname == NULL || port == 0)
		return NULL;

	s = BindConnectEx4(localIP, localport, hostname, port, 0, cancel_flag, ret_ip);
	if (s == NULL)
		return NULL;

	return s;
}

bool GetHello(PACK *p, void *random, UINT *ver, UINT *build, char *server_str, UINT server_str_size) {
	if (p == NULL || random == NULL || ver == NULL || server_str == NULL)
		return false;

	if (PackGetStr(p, "hello", server_str, server_str_size) == false)
		return false;
	*ver = PackGetInt(p, "version");
	*build = PackGetInt(p, "build");
	if (PackGetDataSize(p, "random") != SHA1_SIZE)
		return false;
	if (PackGetData(p, "random", random) == false)
		return false;

	return true;
}

PACK *PackLoginWithCert(char *hubname, char *username, X *x, void *sign, UINT sign_size) {
	if (hubname == NULL || username == NULL)
		return NULL;

	PACK *p = NewPack();
	PackAddStr(p, "method", "login");
	PackAddStr(p, "hubname", hubname);
	PackAddStr(p, "username", username);
	PackAddInt(p, "authtype", CLIENT_AUTHTYPE_CERT);

	BUF *b = XToBuf(x, false);
	PackAddData(p, "cert", b->Buf, b->Size);
	FreeBuf(b);

	PackAddData(p, "sign", sign, sign_size);

	return p;
}

PACK *PackLoginWithPlainPassword(char *hubname, char *username, void *plain_password) {
	if (hubname == NULL || username == NULL)
		return NULL;

	PACK *p = NewPack();
	PackAddStr(p, "method", "login");
	PackAddStr(p, "hubname", hubname);
	PackAddStr(p, "username", username);
	PackAddInt(p, "authtype", CLIENT_AUTHTYPE_PLAIN_PASSWORD);
	PackAddStr(p, "plain_password", plain_password);

	return p;
}

PACK *PackLoginWithPassword(char *hubname, char *username, void *secure_password) {
	if (hubname == NULL || username == NULL)
		return NULL;

	PACK *p = NewPack();
	PackAddStr(p, "method", "login");
	PackAddStr(p, "hubname", hubname);
	PackAddStr(p, "username", username);
	PackAddInt(p, "authtype", CLIENT_AUTHTYPE_PASSWORD);
	PackAddData(p, "secure_password", secure_password, SHA1_SIZE);

	return p;
}

PACK *PackLoginWithAnonymous(char *hubname, char *username) {
	if (hubname == NULL || username == NULL)
		return NULL;

	PACK *p = NewPack();
	PackAddStr(p, "method", "login");
	PackAddStr(p, "hubname", hubname);
	PackAddStr(p, "username", username);
	PackAddInt(p, "authtype", CLIENT_AUTHTYPE_ANONYMOUS);

	return p;
}

PACK *PackAdditionalConnect(UCHAR *session_key) {
	if (session_key == NULL)
		return NULL;

	PACK *p = NewPack();
	PackAddStr(p, "method", "additional_connect");
	PackAddData(p, "session_key", session_key, SHA1_SIZE);

	return p;
}

void ClientAdditionalConnectChance(SESSION *s) {
	if (s == NULL)
		return;

	if (s->ServerMode)
		return;
	if (s->Connection->Protocol != CONNECTION_TCP)
		return;
	while (true) {
		if (s->Halt)
			return;
		if (Count(s->Connection->CurrentNumConnection) < s->MaxConnection) {
			UINT64 now = Tick64();

			if (s->NextConnectionTime == 0 ||
			    s->ClientOption->AdditionalConnectionInterval == 0 ||
			    (s->NextConnectionTime <= now)) {
				s->NextConnectionTime = now + ((UINT64)s->ClientOption->AdditionalConnectionInterval * (UINT64)1000);
				SessionAdditionalConnect(s);
			} else {
				break;
			}
		} else {
			break;
		}
	}
}

static void ClientAdditionalThread(THREAD *t, void *param) {
	if (t == NULL || param == NULL)
		return;

	SESSION *s = (SESSION *)param;

	s->LastTryAddConnectTime = Tick64();

	CONNECTION *c = s->Connection;
	Inc(c->CurrentNumConnection);
	LockList(c->ConnectingThreads);
	{
		Add(c->ConnectingThreads, t);
		AddRef(t->ref);
	}
	UnlockList(c->ConnectingThreads);

	NoticeThreadInit(t);

	if (ClientAdditionalConnect(c) == false) {
		Dec(c->CurrentNumConnection);

		if (c->AdditionalConnectionFailedCounter == 0)
			c->LastCounterResetTick = Tick64();

		c->AdditionalConnectionFailedCounter++;

		if ((c->LastCounterResetTick + (UINT64)ADDITIONAL_CONNECTION_COUNTER_RESET_INTERVAL) <= Tick64()) {
			c->AdditionalConnectionFailedCounter = 0;
			c->LastCounterResetTick = Tick64();
		}
	} else {
		s->LastTryAddConnectTime = Tick64();
		c->AdditionalConnectionFailedCounter = 0;
		c->LastCounterResetTick = Tick64();
	}

	LockList(c->ConnectingThreads);
	{
		if (Delete(c->ConnectingThreads, t))
			ReleaseThread(t);
	}
	UnlockList(c->ConnectingThreads);
	ReleaseSession(s);
}

void SessionAdditionalConnect(SESSION *s) {
	if (s == NULL)
		return;

	AddRef(s->ref);
	THREAD *t = NewThread(ClientAdditionalThread, (void *)s);
	WaitThreadInit(t);
	ReleaseThread(t);
}

static bool SessionConnect(SESSION *s) {
	bool ret = false;
	if (s == NULL)
		return false;

	s->ClientStatus = CLIENT_STATUS_CONNECTING;

	Lock(s->lock);
	{
		s->Err = ERR_NO_ERROR;
		if (s->Policy != NULL) {
			Free(s->Policy);
			s->Policy = NULL;
		}
	}
	Unlock(s->lock);

	CONNECTION *c = NewClientConnectionEx(s, NULL);

	// StopSessionEx reads s->Connection and takes its ref under s->lock
	Lock(s->lock);
	{
		s->Connection = c;
	}
	Unlock(s->lock);

	ret = ClientConnect(c);
	s->Err = c->Err;

	Lock(s->lock);
	{
		s->Connection = NULL;
	}
	Unlock(s->lock);
	ReleaseConnection(c);

	Lock(s->lock);
	{
		if (s->Policy != NULL) {
			Free(s->Policy);
			s->Policy = NULL;
		}
	}
	Unlock(s->lock);

	return ret;
}

static void ClientThread(THREAD *t, void *param) {
	if (t == NULL || param == NULL)
		return;

	SESSION *s = (SESSION *)param;
	AddRef(s->ref);
	s->Thread = t;
	AddRef(t->ref);

	NoticeThreadInit(t);

	s->ClientStatus = CLIENT_STATUS_CONNECTING;
	s->RetryFlag = true;
	s->CurrentRetryCount = 0;

	while (true) {
		Zero(&s->ServerIP_CacheForNextConnect, sizeof(IP));
		Zero(&s->LocalIP_CacheForNextConnect, sizeof(IP));
		Zero(s->UnderlayProtocol, sizeof(s->UnderlayProtocol));
		Zero(s->ProtocolDetails, sizeof(s->ProtocolDetails));

		if (s->Link != NULL && ((*s->Link->StopAllLinkFlag) || s->Link->Halting)) {
			s->Err = ERR_USER_CANCEL;
			break;
		}

		if (s->LinkModeClient && s->Link != NULL)
			HLog(s->Link->Hub, "LH_CONNECT_1", s->ClientOption->AccountName, s->CurrentRetryCount + 1);

		s->NextConnectionTime = 0;

		s->ClientStatus = CLIENT_STATUS_CONNECTING;
		s->Halt = false;
		SessionConnect(s);
		if (s->UserCanceled)
			s->Err = ERR_USER_CANCEL;

		if (s->LinkModeClient && s->Link != NULL)
			HLog(s->Link->Hub, "LH_CONNECT_ERROR", s->ClientOption->AccountName,
			     GetUniErrorStr(s->Err), s->Err);

		s->ClientStatus = CLIENT_STATUS_RETRY;

		if (s->Link != NULL)
			((LINK *)s->Link)->LastError = s->Err;

		if (s->Halt && (s->RetryFlag == false) || s->ForceStopFlag)
			break;
		UINT retry_interval = s->RetryInterval;

		if (s->LinkModeClient) {
			UINT current_num_links = Count(s->Cedar->CurrentActiveLinks);
			UINT max_retry_interval = MAX(1000 * current_num_links, retry_interval);

			retry_interval += retry_interval * MIN(s->CurrentRetryCount, 1000);
			retry_interval = MIN(retry_interval, max_retry_interval);

			if (retry_interval >= 1000 && retry_interval <= (60 * 60 * 1000))
				retry_interval = (retry_interval * 8 / 10) + (Rand32() % (retry_interval * 4 / 10));
		}

		if (s->Err == ERR_HUB_IS_BUSY || s->Err == ERR_LICENSE_ERROR ||
		    s->Err == ERR_HUB_STOPPING || s->Err == ERR_TOO_MANY_USER_SESSION)
			retry_interval = RETRY_INTERVAL_SPECIAL;

		if (s->CurrentRetryCount >= s->ClientOption->NumRetry)
			break;

		Wait(s->HaltEvent, retry_interval);

		if (s->ConnectSucceed == false)
			s->CurrentRetryCount++;

		if (s->ForceStopFlag)
			break;
	}

	s->ClientStatus = CLIENT_STATUS_IDLE;

	ReleaseSession(s);
}

SESSION *NewRpcSession(CEDAR *cedar, CLIENT_OPTION *option, UINT *err, char *client_str) {
	if (cedar == NULL || option == NULL) {
		if (err != NULL)
			*err = ERR_INTERNAL_ERROR;
		return NULL;
	}

	SESSION *s = NewSessionBase(cedar, false);

	s->Name = CopyStr("CLIENT_RPC_SESSION");

	s->ClientOption = ClientOptionClone(option);

	s->MaxConnection = option->MaxConnection;
	s->UseEncrypt = option->UseEncrypt;
	s->UseCompress = option->UseCompress;

	CONNECTION *c = s->Connection = NewClientConnectionEx(s, client_str);

	SOCK *sock = ClientConnectToServer(c);
	if (sock == NULL) {
		if (err != NULL)
			*err = c->Err;
		ReleaseSession(s);
		return NULL;
	}

	if (ClientUploadSignature(sock) == false) {
		// ClientUploadSignature has no connection to set the error of: the socket broke
		c->Err = ERR_DISCONNECTED;
		if (err != NULL)
			*err = c->Err;
		ReleaseSession(s);
		return NULL;
	}

	if (ClientDownloadHello(c, sock) == false) {
		if (err != NULL)
			*err = c->Err;
		ReleaseSession(s);
		return NULL;
	}

	return s;
}

SESSION *NewClientSession(CEDAR *cedar, CLIENT_OPTION *option, CLIENT_AUTH *auth, PACKET_ADAPTER *pa) {
	if (cedar == NULL || option == NULL || auth == NULL || pa == NULL)
		return NULL;

	SESSION *s = NewSessionBase(cedar, false);

	s->Name = CopyStr("CLIENT_SESSION");
	s->PacketAdapter = pa;
	s->OldTraffic = NewTraffic();
	s->CancelList = NewList(NULL);

	s->ClientOption = ClientOptionClone(option);

	if (GetGlobalServerFlag(GSF_DISABLE_SESSION_RECONNECT)) {
		s->ClientOption->DisableQoS = true;
		s->ClientOption->MaxConnection = 1;
		s->ClientOption->HalfConnection = false;
	}

	s->MaxConnection = option->MaxConnection;
	s->UseEncrypt = option->UseEncrypt;
	s->UseCompress = option->UseCompress;

	s->RetryInterval = MAKESURE(option->RetryInterval, 0, 4000000) * 1000;
	s->RetryInterval = MAKESURE(s->RetryInterval, MIN_RETRY_INTERVAL, MAX_RETRY_INTERVAL);

	s->ClientOption->AdditionalConnectionInterval = MAX(s->ClientOption->AdditionalConnectionInterval, 1);

	s->ClientAuth = ClientAuthClone(auth);

	if (StrCmpi(s->ClientOption->DeviceName, LINK_DEVICE_NAME) == 0) {
		s->LinkModeClient = true;
		s->Link = (LINK *)s->PacketAdapter->Param;
		if (s->Link != NULL && s->Link->CheckServerCert && s->Link->Hub->HubDb != NULL) {
			s->SslOption = ZeroMalloc(sizeof(SSL_VERIFY_OPTION));
			s->SslOption->VerifyPeer = true;
			s->SslOption->AddDefaultCA = s->Link->AddDefaultCA;
			s->SslOption->VerifyHostname = true;
			s->SslOption->SavedCert = CloneX(s->Link->ServerCert);

			LIST *o = s->Link->Hub->HubDb->RootCertList;
			s->SslOption->CaList = CloneXList(o);
		}
	}

	THREAD *t = NewThread(ClientThread, (void *)s);
	WaitThreadInit(t);
	ReleaseThread(t);

	return s;
}
