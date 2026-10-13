// ProtocolClient.c
// SE-VPN protocol, client-connect side: ClientConnect, additional connections, hello, authentication and signature upload, socket and proxy connect (used by cascade connections)

#include "Protocol.h"

#include "Account.h"
#include "Admin.h"
#include "Hub.h"
#include "Link.h"
#include "Logging.h"
#include "MsChapV2.h"
#include "Sam.h"
#include "Server.h"
#include "UdpAccel.h"
#include "WaterMark.h"
#include "Wpc.h"

#include "Mayaqua/Cfg.h"
#include "Mayaqua/DNS.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/OS.h"
#include "Mayaqua/Pack.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Table.h"
#include "Mayaqua/Tick64.h"
#include "ProtocolInternal.h"

TOKEN_LIST *EnumHub(SESSION *s)
{
	SOCK *sock;
	TOKEN_LIST *ret;
	PACK *p;
	UINT num;
	UINT i;
	if (s == NULL || s->Connection == NULL)
	{
		return NULL;
	}

	sock = s->Connection->FirstSock;
	if (sock == NULL)
	{
		return NULL;
	}

	SetTimeout(sock, 10000);

	p = NewPack();
	PackAddStr(p, "method", "enum_hub");

	PackAddClientVersion(p, s->Connection);

	if (HttpClientSend(sock, p) == false)
	{
		FreePack(p);
		return NULL;
	}
	FreePack(p);

	p = HttpClientRecv(sock);
	if (p == NULL)
	{
		return NULL;
	}

	num = PackGetInt(p, "NumHub");
	ret = ZeroMalloc(sizeof(TOKEN_LIST));
	ret->NumTokens = num;
	ret->Token = ZeroMalloc(sizeof(char *) * num);
	for (i = 0;i < num;i++)
	{
		char tmp[MAX_SIZE];
		if (PackGetStrEx(p, "HubName", tmp, sizeof(tmp), i))
		{
			ret->Token[i] = CopyStr(tmp);
		}
	}
	FreePack(p);

	return ret;
}

void CreateNodeInfo(NODE_INFO *info, CONNECTION *c)
{
	SESSION *s;
	OS_INFO *os;
	char *product_id;
	IP ip;
	if (c == NULL)
	{
		return;
	}

	s = c->Session;
	os = GetOsInfo();


	Zero(info, sizeof(NODE_INFO));

	StrCpy(info->ClientProductName, sizeof(info->ClientProductName), c->ClientStr);
	info->ClientProductVer = Endian32(c->ClientVer);
	info->ClientProductBuild = Endian32(c->ClientBuild);

	StrCpy(info->ServerProductName, sizeof(info->ServerProductName), c->ServerStr);
	info->ServerProductVer = Endian32(c->ServerVer);
	info->ServerProductBuild = Endian32(c->ServerBuild);

	StrCpy(info->ClientOsName, sizeof(info->ClientOsName), os->OsProductName);
	StrCpy(info->ClientOsVer, sizeof(info->ClientOsVer), os->OsVersion);
	product_id = OSGetProductId();
	StrCpy(info->ClientOsProductId, sizeof(info->ClientOsProductId), product_id);
	Free(product_id);

	if (true)
	{
		wchar_t namew[256];
		char namea[256];

		Zero(namew, sizeof(namew));
		MsGetComputerNameFullEx(namew, sizeof(namew), true);

		Zero(namea, sizeof(namea));
		UniToStr(namea, sizeof(namea), namew);

		if (IsEmptyStr(namea))
		{
			GetMachineName(namea, sizeof(namea));
		}

		StrCpy(info->ClientHostname, sizeof(info->ClientHostname), namea);

	}
	if (IsIP6(&c->FirstSock->LocalIP) == false)
	{
		info->ClientIpAddress = IPToUINT(&c->FirstSock->LocalIP);
	}
	else
	{
		Copy(info->ClientIpAddress6, c->FirstSock->LocalIP.address, sizeof(info->ClientIpAddress6));
	}
	info->ClientPort = Endian32(c->FirstSock->LocalPort);

	StrCpy(info->ServerHostname, sizeof(info->ServerHostname), c->ServerName);
	if (s->ClientOption->ProxyType == PROXY_DIRECT)
	{
		if (IsIP6(&c->FirstSock->RemoteIP) == false)
		{
			info->ServerIpAddress = IPToUINT(&c->FirstSock->RemoteIP);
		}
		else
		{
			Copy(info->ServerIpAddress6, c->FirstSock->RemoteIP.address, sizeof(info->ServerIpAddress6));
		}
	}
	else if (GetIP(&ip, info->ServerHostname))
	{
		if (IsIP6(&ip) == false)
		{
			info->ServerIpAddress = IPToUINT(&ip);
		}
		else
		{
			Copy(info->ServerIpAddress6, ip.address, sizeof(info->ServerIpAddress6));
		}
	}
	info->ServerPort = Endian32(c->ServerPort);

	if (s->ClientOption->ProxyType == PROXY_SOCKS || s->ClientOption->ProxyType == PROXY_HTTP)
	{
		StrCpy(info->ProxyHostname, sizeof(info->ProxyHostname), s->ClientOption->ProxyName);

		if (IsIP6(&c->FirstSock->RemoteIP) == false)
		{
			info->ProxyIpAddress = IPToUINT(&c->FirstSock->RemoteIP);
		}
		else
		{
			Copy(&info->ProxyIpAddress6, c->FirstSock->RemoteIP.address, sizeof(info->ProxyIpAddress6));
		}

		info->ProxyPort = Endian32(c->FirstSock->RemotePort);
	}

	StrCpy(info->HubName, sizeof(info->HubName), s->ClientOption->HubName);

	Copy(info->UniqueId, c->Cedar->UniqueId, sizeof(info->UniqueId));
}

SOCK *ClientAdditionalConnectToServer(CONNECTION *c)
{
	SOCK *s;
	if (c == NULL)
	{
		return NULL;
	}

	s = ClientConnectGetSocket(c, true);
	if (s == NULL)
	{
		return NULL;
	}

	LockList(c->ConnectingSocks);
	{
		Add(c->ConnectingSocks, s);
		AddRef(s->ref);
	}
	UnlockList(c->ConnectingSocks);

	if (c->Session->Halt)
	{
		Disconnect(s);
		LockList(c->ConnectingSocks);
		{
			if (Delete(c->ConnectingSocks, s))
			{
				ReleaseSock(s);
			}
		}
		UnlockList(c->ConnectingSocks);
		ReleaseSock(s);
		return NULL;
	}

	SetTimeout(s, CONNECTING_TIMEOUT);

	if (StartSSLEx(s, NULL, NULL, 0, c->ServerName) == false)
	{
		Disconnect(s);
		LockList(c->ConnectingSocks);
		{
			if (Delete(c->ConnectingSocks, s))
			{
				ReleaseSock(s);
			}
		}
		UnlockList(c->ConnectingSocks);
		ReleaseSock(s);
		return NULL;
	}

	if (CompareX(s->RemoteX, c->ServerX) == false)
	{
		Disconnect(s);
		c->Session->SessionTimeOuted = true;
	}

	return s;
}

bool ClientAdditionalConnect(CONNECTION *c, THREAD *t)
{
	SOCK *s;
	PACK *p;
	TCPSOCK *ts;
	UINT err;
	UINT direction;

	if (c == NULL)
	{
		return false;
	}

	s = ClientAdditionalConnectToServer(c);
	if (s == NULL)
	{
		return false;
	}

	if (c->Halt)
	{
		goto CLEANUP;
	}

	if (ClientUploadSignature(s) == false)
	{
		goto CLEANUP;
	}

	if (c->Halt)
	{
		goto CLEANUP;
	}

	if (ClientDownloadHello(c, s) == false)
	{
		goto CLEANUP;
	}

	if (c->Halt)
	{
		goto CLEANUP;
	}

	if (ClientUploadAuth2(c, s) == false)
	{
		goto CLEANUP;
	}

	p = HttpClientRecv(s);
	if (p == NULL)
	{
		goto CLEANUP;
	}

	err = GetErrorFromPack(p);
	direction = PackGetInt(p, "direction");

	FreePack(p);
	p = NULL;

	if (err != 0)
	{
		if (err == ERR_SESSION_TIMEOUT || err == ERR_INVALID_PROTOCOL)
		{
			c->Session->SessionTimeOuted = true;
		}
		goto CLEANUP;
	}


	ts = NewTcpSock(s);

	if (c->ServerMode == false)
	{
		if (c->Session->ClientOption->ConnectionDisconnectSpan != 0)
		{
			ts->DisconnectTick = Tick64() + c->Session->ClientOption->ConnectionDisconnectSpan * (UINT64)1000;
		}
	}

	LockList(c->Tcp->TcpSockList);
	{
		ts->Direction = direction;
		Add(c->Tcp->TcpSockList, ts);
	}
	UnlockList(c->Tcp->TcpSockList);

	if (c->Session->HalfConnection)
	{
	}

	Cancel(c->Session->Cancel1);

	LockList(c->ConnectingSocks);
	{
		if (Delete(c->ConnectingSocks, s))
		{
			ReleaseSock(s);
		}
	}
	UnlockList(c->ConnectingSocks);
	ReleaseSock(s);
	return true;

CLEANUP:
	Disconnect(s);
	LockList(c->ConnectingSocks);
	{
		if (Delete(c->ConnectingSocks, s))
		{
			ReleaseSock(s);

		}
	}
	UnlockList(c->ConnectingSocks);
	ReleaseSock(s);
	return false;
}

void ClientCheckServerCertThread(THREAD *thread, void *param)
{
	CHECK_CERT_THREAD_PROC *p = (CHECK_CERT_THREAD_PROC *)param;
	if (thread == NULL || param == NULL)
	{
		return;
	}

	NoticeThreadInit(thread);

	p->Ok = p->CheckCertProc(p->Connection->Session, p->Connection, p->ServerX, &p->Expired);
	p->UserSelected = true;
}

bool ClientCheckServerCert(CONNECTION *c, bool *expired)
{
	CLIENT_AUTH *auth;
	X *x;
	CHECK_CERT_THREAD_PROC *p;
	THREAD *thread;
	bool ret;
	UINT64 start;
	if (c == NULL)
	{
		return false;
	}

	if (expired != NULL)
	{
		*expired = false;
	}

	auth = c->Session->ClientAuth;

	if (auth->CheckCertProc == NULL)
	{
		return false;
	}

	x = CloneX(c->FirstSock->RemoteX);
	if (x == NULL)
	{
		return false;
	}

	p = ZeroMalloc(sizeof(CHECK_CERT_THREAD_PROC));
	p->ServerX = x;
	p->CheckCertProc = auth->CheckCertProc;
	p->Connection = c;

	thread = NewThread(ClientCheckServerCertThread, p);
	WaitThreadInit(thread);

	start = Tick64();
	while (true)
	{
		if ((Tick64() - start) > CONNECTING_POOLING_SPAN)
		{
			start = Tick64();
			// No NOOP here: the user is asked before the signature is sent.
		}
		if (p->UserSelected)
		{
			break;
		}
		WaitThread(thread, 500);
	}

	if (expired != NULL)
	{
		*expired = p->Expired;
	}

	ret = p->Ok;
	FreeX(p->ServerX);
	Free(p);
	ReleaseThread(thread);

	return ret;
}

bool ClientConnect(CONNECTION *c)
{
	bool ret = false;
	bool ok = false;
	UINT err;
	SOCK *s;
	PACK *p = NULL;
	UINT session_key_32;
	SESSION *sess;
	char session_name[MAX_SESSION_NAME_LEN + 1];
	char connection_name[MAX_CONNECTION_NAME_LEN + 1];
	UCHAR session_key[SHA1_SIZE];
	POLICY *policy;
	bool expired = false;
	IP server_ip;
	if (c == NULL)
	{
		return false;
	}

	sess = c->Session;

	PrintStatus(sess, L"init");
	PrintStatus(sess, _UU("STATUS_1"));

	c->Status = CONNECTION_STATUS_CONNECTING;
	c->Session->ClientStatus = CLIENT_STATUS_CONNECTING;

	s = ClientConnectToServer(c);
	if (s == NULL)
	{
		// Do not retry if untrusted or hostname mismatched
		if (c->Session->LinkModeClient == false && (c->Err == ERR_CERT_NOT_TRUSTED || c->Err == ERR_HOSTNAME_MISMATCH)
			&& (c->Session->Account == NULL || ! c->Session->Account->RetryOnServerCert))
		{
			c->Session->ForceStopFlag = true;
		}
		PrintStatus(sess, L"free");
		return false;
	}

	PrintStatus(sess, _UU("STATUS_5"));

	// Prompt user whether to continue on verification errors
	if ((c->Err == ERR_CERT_NOT_TRUSTED || c->Err == ERR_HOSTNAME_MISMATCH || c->Err == ERR_SERVER_CERT_EXPIRES) && ClientCheckServerCert(c, &expired) == false)
	{
		if (expired)
		{
			c->Err = ERR_SERVER_CERT_EXPIRES;
		}

		// Do not retry if untrusted or hostname mismatched
		if (c->Session->LinkModeClient == false && (c->Err == ERR_CERT_NOT_TRUSTED || c->Err == ERR_HOSTNAME_MISMATCH)
			&& (c->Session->Account == NULL || ! c->Session->Account->RetryOnServerCert))
		{
			c->Session->ForceStopFlag = true;
		}

		goto CLEANUP;
	}

	Copy(&server_ip, &s->RemoteIP, sizeof(IP));

	if (c->Halt)
	{
		c->Err = ERR_USER_CANCEL;
		goto CLEANUP;
	}

	c->Session->ClientStatus = CLIENT_STATUS_NEGOTIATION;

	if (sess->ClientOption != NULL && sess->ClientOption->NoUdpAcceleration == false)
	{
		if (sess->ClientOption->ProxyType == PROXY_DIRECT)
		{
			if (s->Type == SOCK_TCP)
			{
				if (sess->UdpAccel == NULL)
				{
					sess->UdpAccel = NewUdpAccel(c->Cedar, &s->LocalIP, true, true);

					UdpAccelQueryStun(sess->UdpAccel, &s->RemoteIP);
				}
			}
		}
	}

	if (ClientUploadSignature(s) == false)
	{
		c->Err = ERR_DISCONNECTED;
		goto CLEANUP;
	}

	if (c->Halt)
	{
		c->Err = ERR_USER_CANCEL;
		goto CLEANUP;
	}

	if (ClientDownloadHello(c, s) == false)
	{
		goto CLEANUP;
	}

	if (c->Session->ClientOption != NULL && c->Session->ClientOption->FromAdminPack)
	{
		if (IsAdminPackSupportedServerProduct(c->ServerStr) == false)
		{
			c->Err = ERR_NOT_ADMINPACK_SERVER;
			goto CLEANUP;
		}
	}

	if (c->Halt)
	{
		c->Err = ERR_USER_CANCEL;
		goto CLEANUP;
	}


	c->Session->ClientStatus = CLIENT_STATUS_AUTH;

	PrintStatus(sess, _UU("STATUS_6"));

	if (ClientUploadAuth(c) == false)
	{
		goto CLEANUP;
	}

	if (c->Halt)
	{
		c->Err = ERR_USER_CANCEL;
		goto CLEANUP;
	}

	p = HttpClientRecv(s);
	if (p == NULL)
	{
		c->Err = ERR_DISCONNECTED;
		goto CLEANUP;
	}

	err = GetErrorFromPack(p);
	if (err != 0)
	{
		c->Err = err;
		c->ClientConnectError_NoSavePassword = PackGetBool(p, "no_save_password");
		goto CLEANUP;
	}

	{
		char tmp[20];
		char *branded_cfroms = _SS("BRANDED_C_FROM_S");
		PackGetStr(p, "branded_cfroms", tmp, sizeof(tmp));

		if(StrLen(branded_cfroms) > 0 && StrCmpi(branded_cfroms, tmp) != 0)
		{
			c->Err = ERR_BRANDED_C_FROM_S;
			goto CLEANUP;
		}
	}

	if (true)
	{
		UINT utf_size;
		char *utf;
		wchar_t *msg;

		utf_size = PackGetDataSize(p, "Msg");
		utf = ZeroMalloc(utf_size + 8);
		PackGetData(p, "Msg", utf);

		msg = CopyUtfToUni(utf);

		if (IsEmptyUniStr(msg) == false)
		{
			if (c->Session->Client_Message != NULL)
			{
				Free(c->Session->Client_Message);
			}

			c->Session->Client_Message = msg;
		}
		else
		{
			Free(msg);
		}

		Free(utf);
	}

	PrintStatus(sess, _UU("STATUS_7"));

	if (ParseWelcomeFromPack(p, session_name, sizeof(session_name),
		connection_name, sizeof(connection_name), &policy) == false)
	{
		c->Err = ERR_PROTOCOL_ERROR;
		goto CLEANUP;
	}

	if (GetSessionKeyFromPack(p, session_key, &session_key_32) == false)
	{
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
		c->Session->QoS = PackGetInt(p, "qos") == 0 ? false : true;
		if (c->Session->QoS)
		{
			c->Session->MaxConnection = MAX(c->Session->MaxConnection, (UINT)(c->Session->HalfConnection ? 4 : 2));
		}
		c->Session->VLanId = PackGetInt(p, "vlan_id");

		StrCpy(c->Session->UnderlayProtocol, sizeof(c->Session->UnderlayProtocol), s->UnderlayProtocol);

		AddProtocolDetailsStr(c->Session->ProtocolDetails, sizeof(c->Session->ProtocolDetails), s->ProtocolDetails);

		if (c->Protocol == CONNECTION_UDP)
		{
			if (PackGetDataSize(p, "udp_send_key") == sizeof(c->Session->UdpSendKey))
			{
				PackGetData(p, "udp_send_key", c->Session->UdpSendKey);
			}

			if (PackGetDataSize(p, "udp_recv_key") == sizeof(c->Session->UdpRecvKey))
			{
				PackGetData(p, "udp_recv_key", c->Session->UdpRecvKey);
			}
		}

		sess->UseUdpAcceleration = false;
		sess->IsUsingUdpAcceleration = false;
		sess->UseHMacOnUdpAcceleration = false;

		if (sess->UdpAccel != NULL)
		{
			sess->UdpAccel->UseHMac = false;

			sess->UdpAccelFastDisconnectDetect = false;

			if (PackGetBool(p, "use_udp_acceleration"))
			{
				UINT udp_acceleration_version = PackGetInt(p, "udp_acceleration_version");
				IP udp_acceleration_server_ip;

				if (udp_acceleration_version == 0)
				{
					udp_acceleration_version = 1;
				}

				sess->UdpAccelFastDisconnectDetect = PackGetBool(p, "udp_accel_fast_disconnect_detect");

				if (PackGetIp(p, "udp_acceleration_server_ip", &udp_acceleration_server_ip))
				{
					UINT udp_acceleration_server_port = PackGetInt(p, "udp_acceleration_server_port");

					if (IsZeroIp(&udp_acceleration_server_ip))
					{
						Copy(&udp_acceleration_server_ip, &s->RemoteIP, sizeof(IP));
					}

					if (udp_acceleration_server_port != 0)
					{
						UCHAR udp_acceleration_server_key[UDP_ACCELERATION_COMMON_KEY_SIZE_V1];
						UCHAR udp_acceleration_server_key_v2[UDP_ACCELERATION_COMMON_KEY_SIZE_V2];
						UINT server_cookie = PackGetInt(p, "udp_acceleration_server_cookie");
						UINT client_cookie = PackGetInt(p, "udp_acceleration_client_cookie");
						bool encryption = PackGetBool(p, "udp_acceleration_use_encryption");

						Zero(udp_acceleration_server_key, sizeof(udp_acceleration_server_key));
						Zero(udp_acceleration_server_key_v2, sizeof(udp_acceleration_server_key_v2));

						PackGetData2(p, "udp_acceleration_server_key", udp_acceleration_server_key, UDP_ACCELERATION_COMMON_KEY_SIZE_V1);
						PackGetData2(p, "udp_acceleration_server_key_v2", udp_acceleration_server_key_v2, UDP_ACCELERATION_COMMON_KEY_SIZE_V2);

						if (server_cookie != 0 && client_cookie != 0)
						{
							IP remote_ip;

							Copy(&remote_ip, &s->RemoteIP, sizeof(IP));

							sess->UdpAccel->Version = 1;
							if (udp_acceleration_version == 2)
							{
								sess->UdpAccel->Version = 2;
							}

							if (UdpAccelInitClient(sess->UdpAccel,
								sess->UdpAccel->Version == 2 ? udp_acceleration_server_key_v2 : udp_acceleration_server_key,
								&remote_ip, &udp_acceleration_server_ip, udp_acceleration_server_port,
								server_cookie, client_cookie) == false)
							{
							}
							else
							{
								sess->UseUdpAcceleration = true;

								sess->UdpAccel->FastDetect = sess->UdpAccelFastDisconnectDetect;

								sess->UdpAccel->PlainTextMode = !encryption;

								sess->UseHMacOnUdpAcceleration = PackGetBool(p, "use_hmac_on_udp_acceleration");

								if (sess->UseHMacOnUdpAcceleration)
								{
									sess->UdpAccel->UseHMac = true;
								}

								AddProtocolDetailsKeyValueInt(sess->ProtocolDetails, sizeof(sess->ProtocolDetails), "UDPAccel_Ver", sess->UdpAccel->Version);

								AddProtocolDetailsStr(sess->ProtocolDetails, sizeof(sess->ProtocolDetails), sess->UdpAccel->Version > 1 ? "ChaCha20-Poly1305" : "RC4");

								AddProtocolDetailsKeyValueInt(sess->ProtocolDetails, sizeof(sess->ProtocolDetails), "UDPAccel_MSS", UdpAccelCalcMss(sess->UdpAccel));
							}
						}
					}
				}
			}
		}
	}
	Unlock(c->Session->lock);


	if (sess->UseUdpAcceleration == false)
	{
		if (sess->UdpAccel != NULL)
		{
			FreeUdpAccel(sess->UdpAccel);
			sess->UdpAccel = NULL;
		}
	}

	Lock(c->lock);
	{
		if (c->Name != NULL)
		{
			Free(c->Name);
		}
		c->Name = CopyStr(connection_name);

		if (c->CipherName != NULL)
		{
			Free(c->CipherName);
		}

		c->CipherName = CopyStr(c->FirstSock->CipherName);

		if (c->SslVersion != NULL)
		{
			Free(c->SslVersion);
		}

		c->SslVersion = CopyStr(c->FirstSock->SslVersion);
	}
	Unlock(c->lock);

	Lock(c->Session->lock);
	{
		if (c->Session->Name != NULL)
		{
			Free(c->Session->Name);
		}
		c->Session->Name = CopyStr(session_name);

		c->Session->Policy = policy;
	}
	Unlock(c->Session->lock);

	FreePack(p);
	p = NULL;


	c->Session->ClientStatus = CLIENT_STATUS_ESTABLISHED;

	if (c->ServerX == NULL)
	{
		c->ServerX = CloneX(c->FirstSock->RemoteX);
	}

	PrintStatus(sess, _UU("STATUS_9"));
	StartTunnelingMode(c);
	s = NULL;

	if (c->Session->HalfConnection)
	{
		TCPSOCK *ts = (TCPSOCK *)LIST_DATA(c->Tcp->TcpSockList, 0);
		ts->Direction = TCP_CLIENT_TO_SERVER;
	}

	PrintStatus(sess, L"free");

	if (c->Session->LinkModeClient && c->Session->Link != NULL)
	{
		HLog(c->Session->Link->Hub, "LH_CONNECT_2", c->Session->ClientOption->AccountName, session_name);
	}

	SessionMain(c->Session);

	ok = true;

	if (c->Err == ERR_USER_CANCEL)
	{
		ret = true;
	}

CLEANUP:
	c->FirstSock = NULL;

	if (sess->UdpAccel != NULL)
	{
		FreeUdpAccel(sess->UdpAccel);
		sess->UdpAccel = NULL;
	}

	if (p != NULL)
	{
		FreePack(p);
	}

	Disconnect(s);
	ReleaseSock(s);


	if (ok == false)
	{
		PrintStatus(sess, L"free");
	}

	return ret;
}

bool ParseWelcomeFromPack(PACK *p, char *session_name, UINT session_name_size,
						  char *connection_name, UINT connection_name_size,
						  POLICY **policy)
{
	if (p == NULL || session_name == NULL || connection_name == NULL || policy == NULL)
	{
		return false;
	}

	if (PackGetStr(p, "session_name", session_name, session_name_size) == false)
	{
		return false;
	}

	if (PackGetStr(p, "connection_name", connection_name, connection_name_size) == false)
	{
		return false;
	}

	*policy = PackGetPolicy(p);
	if (*policy == NULL)
	{
		return false;
	}

	return true;
}

#define	PACK_GET_POLICY_BOOL(name, value)	\
	y->value = (PackGetBool(p, "policy:" name))

#define	PACK_GET_POLICY_UINT(name, value)	\
	y->value = PackGetInt(p, "policy:" name)

POLICY *PackGetPolicy(PACK *p)
{
	POLICY *y;
	if (p == NULL)
	{
		return NULL;
	}

	y = ZeroMalloc(sizeof(POLICY));

	// Ver 2
	PACK_GET_POLICY_BOOL("Access", Access);
	PACK_GET_POLICY_BOOL("DHCPFilter", DHCPFilter);
	PACK_GET_POLICY_BOOL("DHCPNoServer", DHCPNoServer);
	PACK_GET_POLICY_BOOL("DHCPForce", DHCPForce);
	PACK_GET_POLICY_BOOL("NoBridge", NoBridge);
	PACK_GET_POLICY_BOOL("NoRouting", NoRouting);
	PACK_GET_POLICY_BOOL("PrivacyFilter", PrivacyFilter);
	PACK_GET_POLICY_BOOL("NoServer", NoServer);
	PACK_GET_POLICY_BOOL("CheckMac", CheckMac);
	PACK_GET_POLICY_BOOL("CheckIP", CheckIP);
	PACK_GET_POLICY_BOOL("ArpDhcpOnly", ArpDhcpOnly);
	PACK_GET_POLICY_BOOL("MonitorPort", MonitorPort);
	PACK_GET_POLICY_BOOL("NoBroadcastLimiter", NoBroadcastLimiter);
	PACK_GET_POLICY_BOOL("FixPassword", FixPassword);
	PACK_GET_POLICY_BOOL("NoQoS", NoQoS);
	// Ver 3
	PACK_GET_POLICY_BOOL("RSandRAFilter", RSandRAFilter);
	PACK_GET_POLICY_BOOL("RAFilter", RAFilter);
	PACK_GET_POLICY_BOOL("DHCPv6Filter", DHCPv6Filter);
	PACK_GET_POLICY_BOOL("DHCPv6NoServer", DHCPv6NoServer);
	PACK_GET_POLICY_BOOL("NoRoutingV6", NoRoutingV6);
	PACK_GET_POLICY_BOOL("CheckIPv6", CheckIPv6);
	PACK_GET_POLICY_BOOL("NoServerV6", NoServerV6);
	PACK_GET_POLICY_BOOL("NoSavePassword", NoSavePassword);
	PACK_GET_POLICY_BOOL("FilterIPv4", FilterIPv4);
	PACK_GET_POLICY_BOOL("FilterIPv6", FilterIPv6);
	PACK_GET_POLICY_BOOL("FilterNonIP", FilterNonIP);
	PACK_GET_POLICY_BOOL("NoIPv6DefaultRouterInRA", NoIPv6DefaultRouterInRA);
	PACK_GET_POLICY_BOOL("NoIPv6DefaultRouterInRAWhenIPv6", NoIPv6DefaultRouterInRAWhenIPv6);

	// Ver 2
	PACK_GET_POLICY_UINT("MaxConnection", MaxConnection);
	PACK_GET_POLICY_UINT("TimeOut", TimeOut);
	PACK_GET_POLICY_UINT("MaxMac", MaxMac);
	PACK_GET_POLICY_UINT("MaxIP", MaxIP);
	PACK_GET_POLICY_UINT("MaxUpload", MaxUpload);
	PACK_GET_POLICY_UINT("MaxDownload", MaxDownload);
	PACK_GET_POLICY_UINT("MultiLogins", MultiLogins);
	// Ver 3
	PACK_GET_POLICY_UINT("MaxIPv6", MaxIPv6);
	PACK_GET_POLICY_UINT("AutoDisconnect", AutoDisconnect);
	PACK_GET_POLICY_UINT("VLanId", VLanId);

	// Ver 3 flag
	PACK_GET_POLICY_BOOL("Ver3", Ver3);

	return y;
}

bool ClientUploadAuth2(CONNECTION *c, SOCK *s)
{
	PACK *p = NULL;
	if (c == NULL)
	{
		return false;
	}

	p = PackAdditionalConnect(c->Session->SessionKey);

	PackAddClientVersion(p, c);

	if (HttpClientSend(s, p) == false)
	{
		FreePack(p);
		return false;
	}
	FreePack(p);

	return true;
}

void PackAddClientVersion(PACK *p, CONNECTION *c)
{
	if (p == NULL || c == NULL)
	{
		return;
	}

	PackAddStr(p, "client_str", c->ClientStr);
	PackAddInt(p, "client_ver", c->ClientVer);
	PackAddInt(p, "client_build", c->ClientBuild);
}

bool ClientUploadAuth(CONNECTION *c)
{
	PACK *p = NULL;
	CLIENT_AUTH *a;
	CLIENT_OPTION *o;
	bool ret;
	NODE_INFO info;
	UCHAR secure_password[SHA1_SIZE];
	UCHAR sign[4096 / 8];
	UCHAR unique[SHA1_SIZE];
	RPC_WINVER v;
	if (c == NULL)
	{
		return false;
	}

	Zero(sign, sizeof(sign));

	a = c->Session->ClientAuth;
	o = c->Session->ClientOption;

	switch (a->AuthType)
	{
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
			a->ClientX->bits != 0 && (a->ClientX->bits / 8) <= sizeof(sign))
		{
			if (RsaSignEx(sign, c->Random, SHA1_SIZE, a->ClientK, a->ClientX->bits))
			{
				p = PackLoginWithCert(o->HubName, a->Username, a->ClientX, sign, a->ClientX->bits / 8);
				c->ClientX = CloneX(a->ClientX);
			}
		}
		break;

	case CLIENT_AUTHTYPE_OPENSSLENGINE:
		if (a->ClientX != NULL && a->ClientX->is_compatible_bit &&
			a->ClientX->bits != 0 && (a->ClientX->bits / 8) <= sizeof(sign))
		{
			if (RsaSignEx(sign, c->Random, SHA1_SIZE, a->ClientK, a->ClientX->bits))
			{
				p = PackLoginWithCert(o->HubName, a->Username, a->ClientX, sign, a->ClientX->bits / 8);
				c->ClientX = CloneX(a->ClientX);
			}
		}
		break;
	}

	if (p == NULL)
	{
		c->Err = ERR_PROTOCOL_ERROR;
		return false;
	}

	PackAddClientVersion(p, c);

	PackAddInt(p, "protocol", c->Protocol);

	PackAddStr(p, "hello", c->ClientStr);
	PackAddInt(p, "version", c->ClientVer);
	PackAddInt(p, "build", c->ClientBuild);
	PackAddInt(p, "client_id", c->Cedar->ClientId);

	PackAddInt(p, "max_connection", o->MaxConnection);
	PackAddInt(p, "use_encrypt", o->UseEncrypt == false ? 0 : 1);
	PackAddInt(p, "use_compress", o->UseCompress == false ? 0 : 1);
	PackAddInt(p, "half_connection", o->HalfConnection == false ? 0 : 1);

	PackAddBool(p, "require_bridge_routing_mode", o->RequireBridgeRoutingMode);

	PackAddBool(p, "require_monitor_mode", o->RequireMonitorMode);

	PackAddBool(p, "qos", o->DisableQoS ? false : true);

	GenerateMachineUniqueHash(unique);
	PackAddData(p, "unique_id", unique, SHA1_SIZE);

	if (o->NoUdpAcceleration == false && c->Session->UdpAccel != NULL)
	{
		PackAddBool(p, "use_udp_acceleration", true);

		PackAddInt(p, "udp_acceleration_version", c->Session->UdpAccel->Version);

		IP my_ip;
		UINT my_port = c->Session->UdpAccel->MyPort;
		if (c->Session->UdpAccel->UseStun)
		{
			Copy(&my_ip, &c->Session->UdpAccel->StunIp, sizeof(my_ip));
			my_port = c->Session->UdpAccel->StunPort;
		}
		else if (IsLocalHostIP(&c->Session->UdpAccel->MyIp) == false)
		{
			Copy(&my_ip, &c->Session->UdpAccel->MyIp, sizeof(my_ip));
		}
		else
		{
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

	{
		char *branded_ctos = _SS("BRANDED_C_TO_S");
		if(StrLen(branded_ctos) > 0)
		{
			PackAddStr(p, "branded_ctos", branded_ctos);
		}
	}

	CreateNodeInfo(&info, c);
	OutRpcNodeInfo(p, &info);

	GetWinVer(&v);
	OutRpcWinVer(p, &v);

	ret = HttpClientSend(c->FirstSock, p);
	if (ret == false)
	{
		c->Err = ERR_DISCONNECTED;
	}

	FreePack(p);

	return ret;
}

bool ClientDownloadHello(CONNECTION *c, SOCK *s)
{
	PACK *p;
	UINT err;
	UCHAR random[SHA1_SIZE];
	if (c == NULL)
	{
		return false;
	}

	p = HttpClientRecv(s);
	if (p == NULL)
	{
		c->Err = ERR_SERVER_IS_NOT_VPN;
		return false;
	}

	if (err = GetErrorFromPack(p))
	{
		c->Err = err;
		FreePack(p);
		return false;
	}

	if (GetHello(p, random, &c->ServerVer, &c->ServerBuild, c->ServerStr, sizeof(c->ServerStr)) == false)
	{
		c->Err = ERR_SERVER_IS_NOT_VPN;
		FreePack(p);
		return false;
	}

	if (c->FirstSock == s)
	{
		Copy(c->Random, random, SHA1_SIZE);
	}

	FreePack(p);

	return true;
}

bool ClientUploadSignature(SOCK *s)
{
	HTTP_HEADER *h;
	UINT water_size, rand_size;
	UCHAR *water;
	char ip_str[128];
	if (s == NULL)
	{
		return false;
	}

	IPToStr(ip_str, sizeof(ip_str), &s->RemoteIP);

	h = NewHttpHeader("POST", HTTP_VPN_TARGET2, "HTTP/1.1");
	AddHttpValue(h, NewHttpValue("Host", ip_str));
	AddHttpValue(h, NewHttpValue("Content-Type", HTTP_CONTENT_TYPE3));
	AddHttpValue(h, NewHttpValue("Connection", "Keep-Alive"));


	rand_size = Rand32() % (HTTP_PACK_RAND_SIZE_MAX * 2);
	water_size = WaterMarkSize + rand_size;
	water = Malloc(water_size);
	Copy(water, WaterMark, WaterMarkSize);
	Rand(&water[WaterMarkSize], rand_size);

	if (PostHttp(s, h, water, water_size) == false)
	{
		Free(water);
		FreeHttpHeader(h);
		return false;
	}

	Free(water);
	FreeHttpHeader(h);

	return true;
}

SOCK *ClientConnectToServer(CONNECTION *c)
{
	SOCK *s = NULL;
	X *x = NULL;
	K *k = NULL;
	if (c == NULL)
	{
		return NULL;
	}

	if (c->Halt)
	{
		c->Err = ERR_USER_CANCEL;
		return NULL;
	}

	s = ClientConnectGetSocket(c, false);
	if (s == NULL)
	{
		return NULL;
	}

	c->FirstSock = s;

	if (c->Halt)
	{
		c->Err = ERR_USER_CANCEL;
		ReleaseSock(s);
		c->FirstSock = NULL;
		return NULL;
	}

	SetTimeout(s, CONNECTING_TIMEOUT);

	UINT err = 0;
	if (StartSSLEx3(s, x, k, NULL, 0, c->ServerName, c->Session->SslOption, &err) == false)
	{
		Disconnect(s);
		ReleaseSock(s);
		c->FirstSock = NULL;
		if (err != 0)
		{
			c->Err = err;
		}
		else
		{
			c->Err = ERR_SERVER_IS_NOT_VPN;
		}
		return NULL;
	}

	if (err != 0)
	{
		c->Err = err;
	}

	if (s->RemoteX == NULL)
	{
		Disconnect(s);
		ReleaseSock(s);
		c->FirstSock = NULL;
		c->Err = ERR_SERVER_IS_NOT_VPN;
		return NULL;
	}

	return s;
}

SOCK *ClientConnectGetSocket(CONNECTION *c, bool additional_connect)
{
	volatile bool *cancel_flag = NULL;
	char hostname[MAX_HOST_NAME_LEN];
	char localaddr[MAX_HOST_NAME_LEN];

	bool save_resolved_ip = false;
	CLIENT_OPTION *o;
	SESSION *sess;
	SOCK *sock = NULL;
	IP resolved_ip;
	if (c == NULL || c->Session == NULL || c->Session->ClientOption == NULL)
	{
		return NULL;
	}

	cancel_flag = &c->Halt;
	sess = c->Session;
	o = c->Session->ClientOption;

	Zero(&resolved_ip, sizeof(resolved_ip));

	if (additional_connect == false && c->RestoreServerNameAndPort)
	{
		// RestoreServerNameAndPort is currently never true.
		c->RestoreServerNameAndPort = false;

		if (StrCmpi(c->ServerName, o->Hostname) != 0)
		{
			StrCpy(c->ServerName, sizeof(c->ServerName), o->Hostname);
		}

		c->ServerPort = o->Port;
	}

	if (additional_connect && IsZeroIP(&sess->ServerIP_CacheForNextConnect) == false)
	{
		IPToStr(hostname, sizeof(hostname), &sess->ServerIP_CacheForNextConnect);
	}
	else
	{
		IP tmp;

		StrCpy(hostname, sizeof(hostname), o->ProxyType == PROXY_DIRECT ? c->ServerName : o->ProxyName);

		if (StrToIP(&tmp, hostname) == false)
		{
			save_resolved_ip = true;
		}
	}

	if (o->ProxyType == PROXY_DIRECT)
	{
		wchar_t tmp[MAX_SIZE];
		UniFormat(tmp, sizeof(tmp), _UU("STATUS_4"), hostname);
		PrintStatus(sess, tmp);

		{
			IP		*localIP;
			UINT	localport;


			if (additional_connect == false) {
				if (sess->ClientOption->NoRoutingTracking == false) {
					localIP = BIND_LOCALIP_NULL;
				}
				else {
					// Nonzero address is for source IP address to bind. Zero address is for dummy not to bind.
					if (IsZeroIP(&sess->ClientOption->BindLocalIP) == true) {
						localIP = BIND_LOCALIP_NULL;
					}
					else {
						localIP = &sess->ClientOption->BindLocalIP;
					}
				}
			}
			else {
				// Bind to the local IP address of the first TCP/IP connection.
				localIP = &sess->LocalIP_CacheForNextConnect;
			}
			if (sess->ClientOption->BindLocalPort == 0) {
				localport = BIND_LOCALPORT_NULL;
			}
			else {
				localport = sess->ClientOption->BindLocalPort + Count(sess->Connection->CurrentNumConnection) - 1;
			}

			sock = BindTcpIpConnectEx(localIP, localport, hostname, c->ServerPort,
				(bool *)cancel_flag, c->hWndForUI, &resolved_ip);
		}

		if (sock == NULL)
		{
			c->Err = ERR_CONNECT_FAILED;

			return NULL;
		}
	}
	else
	{
		wchar_t tmp[MAX_SIZE];
		PROXY_PARAM_OUT out;
		PROXY_PARAM_IN in;
		UINT ret;

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

		if (additional_connect == false) {
			if (sess->ClientOption->NoRoutingTracking == false) {
				in.BindLocalIP = BIND_LOCALIP_NULL;
			}
			else {
				if (IsZeroIP(&sess->ClientOption->BindLocalIP) == true) {
					in.BindLocalIP = BIND_LOCALIP_NULL;
				}
				else {
					in.BindLocalIP = &sess->ClientOption->BindLocalIP;
				}
			}
		}
		else {
			in.BindLocalIP = &sess->LocalIP_CacheForNextConnect;
		}
		if (sess->ClientOption->BindLocalPort == 0) {
			in.BindLocalPort = BIND_LOCALPORT_NULL;
		}
		else {
			in.BindLocalPort = sess->ClientOption->BindLocalPort + Count(sess->Connection->CurrentNumConnection) - 1;
		}

		in.Hwnd = c->hWndForUI;

		UniFormat(tmp, sizeof(tmp), _UU("STATUS_2"), in.TargetHostname, in.Hostname);
		PrintStatus(sess, tmp);

		switch (o->ProxyType)
		{
		case PROXY_HTTP:
			ret = BindProxyHttpConnect(&out, &in, cancel_flag);
			break;
		case PROXY_SOCKS:
			ret = BindProxySocks4Connect(&out, &in, cancel_flag);
			break;
		case PROXY_SOCKS5:
			ret = BindProxySocks5Connect(&out, &in, cancel_flag);
			break;
		default:
			c->Err = ERR_INTERNAL_ERROR;
			return NULL;
		}

		c->Err = ProxyCodeToCedar(ret);

		if (c->Err != ERR_NO_ERROR)
		{
			return NULL;
		}

		sock = out.Sock;

		CopyIP(&resolved_ip, &out.ResolvedIp);
	}

	if (additional_connect == false || IsZeroIP(&sock->RemoteIP))
	{
		if (IsZeroIP(&sock->RemoteIP) == false || (sock->IPv6 && GetIP6(&c->Session->ServerIP, hostname) == false) || (sock->IPv6 == false && GetIP4(&c->Session->ServerIP, hostname) == false))
		{
			Copy(&c->Session->ServerIP, &sock->RemoteIP, sizeof(c->Session->ServerIP));
		}
	}

	if (save_resolved_ip && IsZeroIP(&resolved_ip) == false)
	{
		Copy(&c->Session->ServerIP_CacheForNextConnect, &resolved_ip, sizeof(c->Session->ServerIP_CacheForNextConnect));
	}

	IPToStr(localaddr, sizeof(localaddr), &sock->LocalIP);

	if (additional_connect == false) {
		c->Session->LocalIP_CacheForNextConnect = sock->LocalIP;
	}
	else {
		if (memcmp(sock->LocalIP.address, c->Session->LocalIP_CacheForNextConnect.address, sizeof(sock->LocalIP.address)) == 0) {
		}
		else {
		}
	}

	return sock;
}

UINT ProxyCodeToCedar(UINT code)
{
	switch (code)
	{
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

SOCK *BindTcpIpConnectEx(IP *localIP, UINT localport, char *hostname, UINT port, bool *cancel_flag, void *hWnd, IP *ret_ip)
{
	SOCK *s = NULL;
	if (hostname == NULL || port == 0)
	{
		return NULL;
	}

	s = BindConnectEx4(localIP, localport, hostname, port, 0, cancel_flag, true, ret_ip);
	if (s == NULL)
	{
		return NULL;
	}

	return s;
}

bool GetHello(PACK *p, void *random, UINT *ver, UINT *build, char *server_str, UINT server_str_size)
{
	if (p == NULL || random == NULL || ver == NULL || server_str == NULL)
	{
		return false;
	}

	if (PackGetStr(p, "hello", server_str, server_str_size) == false)
	{
		return false;
	}
	*ver = PackGetInt(p, "version");
	*build = PackGetInt(p, "build");
	if (PackGetDataSize(p, "random") != SHA1_SIZE)
	{
		return false;
	}
	if (PackGetData(p, "random", random) == false)
	{
		return false;
	}

	return true;
}

PACK *PackLoginWithCert(char *hubname, char *username, X *x, void *sign, UINT sign_size)
{
	PACK *p;
	BUF *b;
	if (hubname == NULL || username == NULL)
	{
		return NULL;
	}

	p = NewPack();
	PackAddStr(p, "method", "login");
	PackAddStr(p, "hubname", hubname);
	PackAddStr(p, "username", username);
	PackAddInt(p, "authtype", CLIENT_AUTHTYPE_CERT);

	b = XToBuf(x, false);
	PackAddData(p, "cert", b->Buf, b->Size);
	FreeBuf(b);

	PackAddData(p, "sign", sign, sign_size);

	return p;
}

PACK *PackLoginWithPlainPassword(char *hubname, char *username, void *plain_password)
{
	PACK *p;
	if (hubname == NULL || username == NULL)
	{
		return NULL;
	}

	p = NewPack();
	PackAddStr(p, "method", "login");
	PackAddStr(p, "hubname", hubname);
	PackAddStr(p, "username", username);
	PackAddInt(p, "authtype", CLIENT_AUTHTYPE_PLAIN_PASSWORD);
	PackAddStr(p, "plain_password", plain_password);

	return p;
}

PACK *PackLoginWithPassword(char *hubname, char *username, void *secure_password)
{
	PACK *p;
	if (hubname == NULL || username == NULL)
	{
		return NULL;
	}

	p = NewPack();
	PackAddStr(p, "method", "login");
	PackAddStr(p, "hubname", hubname);
	PackAddStr(p, "username", username);
	PackAddInt(p, "authtype", CLIENT_AUTHTYPE_PASSWORD);
	PackAddData(p, "secure_password", secure_password, SHA1_SIZE);

	return p;
}

PACK *PackLoginWithAnonymous(char *hubname, char *username)
{
	PACK *p;
	if (hubname == NULL || username == NULL)
	{
		return NULL;
	}

	p = NewPack();
	PackAddStr(p, "method", "login");
	PackAddStr(p, "hubname", hubname);
	PackAddStr(p, "username", username);
	PackAddInt(p, "authtype", CLIENT_AUTHTYPE_ANONYMOUS);

	return p;
}

PACK *PackAdditionalConnect(UCHAR *session_key)
{
	PACK *p;
	if (session_key == NULL)
	{
		return NULL;
	}

	p = NewPack();
	PackAddStr(p, "method", "additional_connect");
	PackAddData(p, "session_key", session_key, SHA1_SIZE);

	return p;
}
