// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module
// © 2020 Nokia

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

// Enumerate HUBs
TOKEN_LIST *EnumHub(SESSION *s)
{
	SOCK *sock;
	TOKEN_LIST *ret;
	PACK *p;
	UINT num;
	UINT i;
	// Validate arguments
	if (s == NULL || s->Connection == NULL)
	{
		return NULL;
	}

	sock = s->Connection->FirstSock;
	if (sock == NULL)
	{
		return NULL;
	}

	// Set the Timeout
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

// Create a Node information
void CreateNodeInfo(NODE_INFO *info, CONNECTION *c)
{
	SESSION *s;
	OS_INFO *os;
	char *product_id;
	IP ip;
	// Validate arguments
	if (c == NULL)
	{
		return;
	}

	s = c->Session;
	os = GetOsInfo();



	Zero(info, sizeof(NODE_INFO));

	// Client product name
	StrCpy(info->ClientProductName, sizeof(info->ClientProductName), c->ClientStr);
	// Client version
	info->ClientProductVer = Endian32(c->ClientVer);
	// Client build number
	info->ClientProductBuild = Endian32(c->ClientBuild);

	// Server product name
	StrCpy(info->ServerProductName, sizeof(info->ServerProductName), c->ServerStr);
	// Server version
	info->ServerProductVer = Endian32(c->ServerVer);
	// Server build number
	info->ServerProductBuild = Endian32(c->ServerBuild);

	// Client OS name
	StrCpy(info->ClientOsName, sizeof(info->ClientOsName), os->OsProductName);
	// Client OS version
	StrCpy(info->ClientOsVer, sizeof(info->ClientOsVer), os->OsVersion);
	// Client OS Product ID
	product_id = OSGetProductId();
	StrCpy(info->ClientOsProductId, sizeof(info->ClientOsProductId), product_id);
	Free(product_id);

	// Client host name
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
	// Client IP address
	if (IsIP6(&c->FirstSock->LocalIP) == false)
	{
		info->ClientIpAddress = IPToUINT(&c->FirstSock->LocalIP);
	}
	else
	{
		Copy(info->ClientIpAddress6, c->FirstSock->LocalIP.address, sizeof(info->ClientIpAddress6));
	}
	// Client port number
	info->ClientPort = Endian32(c->FirstSock->LocalPort);

	// Server host name
	StrCpy(info->ServerHostname, sizeof(info->ServerHostname), c->ServerName);
	// Server IP address
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
	// Server port number
	info->ServerPort = Endian32(c->ServerPort);

	if (s->ClientOption->ProxyType == PROXY_SOCKS || s->ClientOption->ProxyType == PROXY_HTTP)
	{
		// Proxy host name
		StrCpy(info->ProxyHostname, sizeof(info->ProxyHostname), s->ClientOption->ProxyName);

		// Proxy Server IP Address
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

	// HUB name
	StrCpy(info->HubName, sizeof(info->HubName), s->ClientOption->HubName);

	// Unique ID
	Copy(info->UniqueId, c->Cedar->UniqueId, sizeof(info->UniqueId));
}

// Connect a socket additionally
SOCK *ClientAdditionalConnectToServer(CONNECTION *c)
{
	SOCK *s;
	// Validate arguments
	if (c == NULL)
	{
		return NULL;
	}

	// Socket connection
	s = ClientConnectGetSocket(c, true);
	if (s == NULL)
	{
		// Connection failure
		return NULL;
	}

	// Add the socket to the list
	LockList(c->ConnectingSocks);
	{
		Add(c->ConnectingSocks, s);
		AddRef(s->ref);
	}
	UnlockList(c->ConnectingSocks);

	if (c->Session->Halt)
	{
		// Stop
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

	// Time-out
	SetTimeout(s, CONNECTING_TIMEOUT);

	// Start the SSL communication
	if (StartSSLEx(s, NULL, NULL, 0, c->ServerName) == false)
	{
		// SSL communication failure
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

	// Check the certificate
	if (CompareX(s->RemoteX, c->ServerX) == false)
	{
		// The certificate is invalid
		Disconnect(s);
		c->Session->SessionTimeOuted = true;
	}

	return s;
}

// Client connects to the server additionally
bool ClientAdditionalConnect(CONNECTION *c, THREAD *t)
{
	SOCK *s;
	PACK *p;
	TCPSOCK *ts;
	UINT err;
	UINT direction;

	// Validate arguments
	if (c == NULL)
	{
		return false;
	}

	// Socket connection to the server
	s = ClientAdditionalConnectToServer(c);
	if (s == NULL)
	{
		// Failed to connect socket
		return false;
	}

	if (c->Halt)
	{
		goto CLEANUP;
	}

	// Send a signature
	Debug("Uploading Signature...\n");
	if (ClientUploadSignature(s) == false)
	{
		goto CLEANUP;
	}

	if (c->Halt)
	{
		// Stop
		goto CLEANUP;
	}

	// Receive a Hello packet
	Debug("Downloading Hello...\n");
	if (ClientDownloadHello(c, s) == false)
	{
		goto CLEANUP;
	}

	if (c->Halt)
	{
		// Stop
		goto CLEANUP;
	}

	// Send a authentication data for the additional connection
	if (ClientUploadAuth2(c, s) == false)
	{
		// Disconnected
		goto CLEANUP;
	}

	// Receive a response
	p = HttpClientRecv(s);
	if (p == NULL)
	{
		// Disconnected
		goto CLEANUP;
	}

	err = GetErrorFromPack(p);
	direction = PackGetInt(p, "direction");

	FreePack(p);
	p = NULL;

	if (err != 0)
	{
		// Error has occurred
		Debug("Additional Connect Error: %u\n", err);
		if (err == ERR_SESSION_TIMEOUT || err == ERR_INVALID_PROTOCOL)
		{
			// We shall re-connection because it is a fatal error
			c->Session->SessionTimeOuted = true;
		}
		goto CLEANUP;
	}

	Debug("Additional Connect Succeed!\n");

	// Success the additional connection
	// Add to the TcpSockList of the connection
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
	Debug("TCP Connection Incremented: %u\n", Count(c->CurrentNumConnection));

	if (c->Session->HalfConnection)
	{
		Debug("New Half Connection: %s\n",
			direction == TCP_SERVER_TO_CLIENT ? "TCP_SERVER_TO_CLIENT" : "TCP_CLIENT_TO_SERVER"
			);
	}

	// Issue the Cancel to the session
	Cancel(c->Session->Cancel1);

	// Remove the socket from the socket list of connected
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
	// Disconnection process
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

// Server certificate confirmation thread
void ClientCheckServerCertThread(THREAD *thread, void *param)
{
	CHECK_CERT_THREAD_PROC *p = (CHECK_CERT_THREAD_PROC *)param;
	// Validate arguments
	if (thread == NULL || param == NULL)
	{
		return;
	}

	// Notify the completion of initialization
	NoticeThreadInit(thread);

	// Query for the selection to the user
	p->Ok = p->CheckCertProc(p->Connection->Session, p->Connection, p->ServerX, &p->Expired);
	p->UserSelected = true;
}

// Client verify the certificate of the server
bool ClientCheckServerCert(CONNECTION *c, bool *expired)
{
	CLIENT_AUTH *auth;
	X *x;
	CHECK_CERT_THREAD_PROC *p;
	THREAD *thread;
	bool ret;
	UINT64 start;
	// Validate arguments
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
		// Strange error occurs
		return false;
	}

	p = ZeroMalloc(sizeof(CHECK_CERT_THREAD_PROC));
	p->ServerX = x;
	p->CheckCertProc = auth->CheckCertProc;
	p->Connection = c;

	// Create a thread
	thread = NewThread(ClientCheckServerCertThread, p);
	WaitThreadInit(thread);

	// Poll at 0.5-second intervals until the user selects whether the connection
	start = Tick64();
	while (true)
	{
		if ((Tick64() - start) > CONNECTING_POOLING_SPAN)
		{
			// Send a NOOP periodically for disconnection prevention
			start = Tick64();
			// Do not send because we now ask for user permission before sending signature
			//ClientUploadNoop(c);
		}
		if (p->UserSelected)
		{
			// User-selected
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

// Client connects to the server
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
	// Validate arguments
	if (c == NULL)
	{
		return false;
	}

	sess = c->Session;

	PrintStatus(sess, L"init");
	PrintStatus(sess, _UU("STATUS_1"));

	// [Connecting]
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
		// Stop
		c->Err = ERR_USER_CANCEL;
		goto CLEANUP;
	}

	// [Negotiating]
	c->Session->ClientStatus = CLIENT_STATUS_NEGOTIATION;

	// Initialize the UDP acceleration function
	if (sess->ClientOption != NULL && sess->ClientOption->NoUdpAcceleration == false)
	{
		if (sess->ClientOption->ProxyType == PROXY_DIRECT)
		{
			if (s->Type == SOCK_TCP)
			{
				if (sess->UdpAccel == NULL)
				{
					sess->UdpAccel = NewUdpAccel(c->Cedar, &s->LocalIP, true, true);

					// Learn the public endpoint of the UDP acceleration socket by STUN (only if configured and the peer is not local)
					UdpAccelQueryStun(sess->UdpAccel, &s->RemoteIP);
				}
			}
		}
	}

	// Send a signature
	Debug("Uploading Signature...\n");
	if (ClientUploadSignature(s) == false)
	{
		c->Err = ERR_DISCONNECTED;
		goto CLEANUP;
	}

	if (c->Halt)
	{
		// Stop
		c->Err = ERR_USER_CANCEL;
		goto CLEANUP;
	}

	// Receive a Hello packet
	Debug("Downloading Hello...\n");
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
		// Stop
		c->Err = ERR_USER_CANCEL;
		goto CLEANUP;
	}

	Debug("Server Version : %u\n"
		"Server String  : %s\n"
		"Server Build   : %u\n"
		"Client Version : %u\n"
		"Client String  : %s\n"
		"Client Build   : %u\n",
		c->ServerVer, c->ServerStr, c->ServerBuild,
		c->ClientVer, c->ClientStr, c->ClientBuild);

	// During user authentication
	c->Session->ClientStatus = CLIENT_STATUS_AUTH;

	PrintStatus(sess, _UU("STATUS_6"));

	// Send the authentication data
	if (ClientUploadAuth(c) == false)
	{
		goto CLEANUP;
	}

	if (c->Halt)
	{
		// Stop
		c->Err = ERR_USER_CANCEL;
		goto CLEANUP;
	}

	// Receive a Welcome packet
	p = HttpClientRecv(s);
	if (p == NULL)
	{
		c->Err = ERR_DISCONNECTED;
		goto CLEANUP;
	}

	// Error checking
	err = GetErrorFromPack(p);
	if (err != 0)
	{
		// An error has occured
		c->Err = err;
		c->ClientConnectError_NoSavePassword = PackGetBool(p, "no_save_password");
		goto CLEANUP;
	}

	// Branding string check for the connection limit
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
		// Message retrieval
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

	// Parse the Welcome packet
	if (ParseWelcomeFromPack(p, session_name, sizeof(session_name),
		connection_name, sizeof(connection_name), &policy) == false)
	{
		// Parsing failure
		c->Err = ERR_PROTOCOL_ERROR;
		goto CLEANUP;
	}

	// Get the session key
	if (GetSessionKeyFromPack(p, session_key, &session_key_32) == false)
	{
		// Acquisition failure
		Free(policy);
		policy = NULL;
		c->Err = ERR_PROTOCOL_ERROR;
		goto CLEANUP;
	}

	Copy(c->Session->SessionKey, session_key, SHA1_SIZE);
	c->Session->SessionKey32 = session_key_32;

	// Save the contents of the Welcome packet
	Debug("session_name: %s, connection_name: %s\n",
		session_name, connection_name);

	Lock(c->Session->lock);
	{
		// Deploy and update connection parameters
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

		// Physical communication protocol
		StrCpy(c->Session->UnderlayProtocol, sizeof(c->Session->UnderlayProtocol), s->UnderlayProtocol);

		AddProtocolDetailsStr(c->Session->ProtocolDetails, sizeof(c->Session->ProtocolDetails), s->ProtocolDetails);

		if (c->Protocol == CONNECTION_UDP)
		{
			// In the case of UDP protocol, receive the key from the server
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
								Debug("UdpAccelInitClient failed.\n");
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

	Debug("UseUdpAcceleration = %u\n", sess->UseUdpAcceleration);

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

		// Save the name of a cryptographic algorithm
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

	// Discard the Welcome packet
	FreePack(p);
	p = NULL;


	// Connection establishment
	c->Session->ClientStatus = CLIENT_STATUS_ESTABLISHED;

	// Save the server certificate
	if (c->ServerX == NULL)
	{
		c->ServerX = CloneX(c->FirstSock->RemoteX);
	}

	PrintStatus(sess, _UU("STATUS_9"));
	// Shift the connection to the tunneling mode
	StartTunnelingMode(c);
	s = NULL;

	if (c->Session->HalfConnection)
	{
		// Processing in the case of half-connection
		TCPSOCK *ts = (TCPSOCK *)LIST_DATA(c->Tcp->TcpSockList, 0);
		ts->Direction = TCP_CLIENT_TO_SERVER;
	}

	PrintStatus(sess, L"free");

	if (c->Session->LinkModeClient && c->Session->Link != NULL)
	{
		HLog(c->Session->Link->Hub, "LH_CONNECT_2", c->Session->ClientOption->AccountName, session_name);
	}

	// Main routine of the session
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

	Debug("Error: %u\n", c->Err);

	if (ok == false)
	{
		PrintStatus(sess, L"free");
	}

	return ret;
}

// Parse the Welcome packet
bool ParseWelcomeFromPack(PACK *p, char *session_name, UINT session_name_size,
						  char *connection_name, UINT connection_name_size,
						  POLICY **policy)
{
	// Validate arguments
	if (p == NULL || session_name == NULL || connection_name == NULL || policy == NULL)
	{
		return false;
	}

	// Session name
	if (PackGetStr(p, "session_name", session_name, session_name_size) == false)
	{
		return false;
	}

	// Connection name
	if (PackGetStr(p, "connection_name", connection_name, connection_name_size) == false)
	{
		return false;
	}

	// Policy
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

// Get the policy from the PACK
POLICY *PackGetPolicy(PACK *p)
{
	POLICY *y;
	// Validate arguments
	if (p == NULL)
	{
		return NULL;
	}

	y = ZeroMalloc(sizeof(POLICY));

	// Bool value
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

	// UINT value
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

// Upload the authentication data for the additional connection
bool ClientUploadAuth2(CONNECTION *c, SOCK *s)
{
	PACK *p = NULL;
	// Validate arguments
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

// Add client version information to the PACK
void PackAddClientVersion(PACK *p, CONNECTION *c)
{
	// Validate arguments
	if (p == NULL || c == NULL)
	{
		return;
	}

	PackAddStr(p, "client_str", c->ClientStr);
	PackAddInt(p, "client_ver", c->ClientVer);
	PackAddInt(p, "client_build", c->ClientBuild);
}

// Upload the certificate data for the new connection
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
	// Validate arguments
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
		// Anonymous authentication
		p = PackLoginWithAnonymous(o->HubName, a->Username);
		break;

	case CLIENT_AUTHTYPE_PASSWORD:
		// Password authentication
		SecurePassword(secure_password, a->HashedPassword, c->Random);
		p = PackLoginWithPassword(o->HubName, a->Username, secure_password);
		break;

	case CLIENT_AUTHTYPE_PLAIN_PASSWORD:
		// Plaintext password authentication
		p = PackLoginWithPlainPassword(o->HubName, a->Username, a->PlainPassword);
		break;

	case CLIENT_AUTHTYPE_CERT:
		// Certificate authentication
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
		// Certificate authentication
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
		// Error
		c->Err = ERR_PROTOCOL_ERROR;
		return false;
	}

	PackAddClientVersion(p, c);

	// Protocol
	PackAddInt(p, "protocol", c->Protocol);

	// Version, etc.
	PackAddStr(p, "hello", c->ClientStr);
	PackAddInt(p, "version", c->ClientVer);
	PackAddInt(p, "build", c->ClientBuild);
	PackAddInt(p, "client_id", c->Cedar->ClientId);

	// The maximum number of connections
	PackAddInt(p, "max_connection", o->MaxConnection);
	// Flag to use of cryptography
	PackAddInt(p, "use_encrypt", o->UseEncrypt == false ? 0 : 1);
	// Data compression flag
	PackAddInt(p, "use_compress", o->UseCompress == false ? 0 : 1);
	// Half connection flag
	PackAddInt(p, "half_connection", o->HalfConnection == false ? 0 : 1);

	// Bridge / routing mode flag
	PackAddBool(p, "require_bridge_routing_mode", o->RequireBridgeRoutingMode);

	// Monitor mode flag
	PackAddBool(p, "require_monitor_mode", o->RequireMonitorMode);

	// VoIP / QoS flag
	PackAddBool(p, "qos", o->DisableQoS ? false : true);

	// Unique ID
	GenerateMachineUniqueHash(unique);
	PackAddData(p, "unique_id", unique, SHA1_SIZE);

	// UDP acceleration function using flag
	if (o->NoUdpAcceleration == false && c->Session->UdpAccel != NULL)
	{
		PackAddBool(p, "use_udp_acceleration", true);

		PackAddInt(p, "udp_acceleration_version", c->Session->UdpAccel->Version);

		IP my_ip;
		UINT my_port = c->Session->UdpAccel->MyPort;
		if (c->Session->UdpAccel->UseStun)
		{
			// Public endpoint learned by STUN
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

	// Brand string for the connection limit
	{
		char *branded_ctos = _SS("BRANDED_C_TO_S");
		if(StrLen(branded_ctos) > 0)
		{
			PackAddStr(p, "branded_ctos", branded_ctos);
		}
	}

	// Node information
	CreateNodeInfo(&info, c);
	OutRpcNodeInfo(p, &info);

	// OS information
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

// Download the Hello packet
bool ClientDownloadHello(CONNECTION *c, SOCK *s)
{
	PACK *p;
	UINT err;
	UCHAR random[SHA1_SIZE];
	// Validate arguments
	if (c == NULL)
	{
		return false;
	}

	// Data reception
	p = HttpClientRecv(s);
	if (p == NULL)
	{
		c->Err = ERR_SERVER_IS_NOT_VPN;
		return false;
	}

	if (err = GetErrorFromPack(p))
	{
		// An error has occured
		c->Err = err;
		FreePack(p);
		return false;
	}

	// Packet interpretation
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

// Upload a signature
bool ClientUploadSignature(SOCK *s)
{
	HTTP_HEADER *h;
	UINT water_size, rand_size;
	UCHAR *water;
	char ip_str[128];
	// Validate arguments
	if (s == NULL)
	{
		return false;
	}

	IPToStr(ip_str, sizeof(ip_str), &s->RemoteIP);

	h = NewHttpHeader("POST", HTTP_VPN_TARGET2, "HTTP/1.1");
	AddHttpValue(h, NewHttpValue("Host", ip_str));
	AddHttpValue(h, NewHttpValue("Content-Type", HTTP_CONTENT_TYPE3));
	AddHttpValue(h, NewHttpValue("Connection", "Keep-Alive"));



	// Generate a watermark
	rand_size = Rand32() % (HTTP_PACK_RAND_SIZE_MAX * 2);
	water_size = WaterMarkSize + rand_size;
	water = Malloc(water_size);
	Copy(water, WaterMark, WaterMarkSize);
	Rand(&water[WaterMarkSize], rand_size);

	// Upload the watermark data
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

// Establish a connection to the server
SOCK *ClientConnectToServer(CONNECTION *c)
{
	SOCK *s = NULL;
	X *x = NULL;
	K *k = NULL;
	// Validate arguments
	if (c == NULL)
	{
		return NULL;
	}

	if (c->Halt)
	{
		c->Err = ERR_USER_CANCEL;
		return NULL;
	}

	// Get the socket by connecting
	s = ClientConnectGetSocket(c, false);
	if (s == NULL)
	{
		// Connection failure
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

	// Time-out
	SetTimeout(s, CONNECTING_TIMEOUT);

	// Start the SSL communication
	UINT err = 0;
	if (StartSSLEx3(s, x, k, NULL, 0, c->ServerName, c->Session->SslOption, &err) == false)
	{
		// SSL communication start failure
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
		// SSL communication start failure
		Disconnect(s);
		ReleaseSock(s);
		c->FirstSock = NULL;
		c->Err = ERR_SERVER_IS_NOT_VPN;
		return NULL;
	}

	return s;
}

// Return a socket by connecting to the server
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
	// Validate arguments
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
		// Update server name and port number.
		// At the time of writing this comment RestoreServerNameAndPort is never true.
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
		Debug("ClientConnectGetSocket(): Using cached IP address %s\n", hostname);
	}
	else
	{
		IP tmp;

		StrCpy(hostname, sizeof(hostname), o->ProxyType == PROXY_DIRECT ? c->ServerName : o->ProxyName);

		if (StrToIP(&tmp, hostname) == false)
		{
			// The hostname is not an IP address
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

			// Top of Bind outgoing connection
			// Decide the binding operation which is explicitly executed on the client-side

			// In the case of first TCP/IP connection
			if (additional_connect == false) {
				if (sess->ClientOption->NoRoutingTracking == false) {
					localIP = BIND_LOCALIP_NULL;	// Specify not to bind
				}
				else {
					// Nonzero address is for source IP address to bind. Zero address is for dummy not to bind.
					if (IsZeroIP(&sess->ClientOption->BindLocalIP) == true) {
						localIP = BIND_LOCALIP_NULL;
					}
					else {
						localIP = &sess->ClientOption->BindLocalIP;
					}
					Debug("ClientConnectGetSocket(): Source IP address %r and source port number %d for binding\n"
						, &sess->ClientOption->BindLocalIP, sess->ClientOption->BindLocalPort);
				}
			}
			// In the case of second and subsequent TCP/IP connections
			else {
				// Bind the socket to the actual local IP address of first TCP / IP connection
				localIP = &sess->LocalIP_CacheForNextConnect;
				//localIP = BIND_LOCALIP_NULL;	// Specify not to bind for test
			}
			if (sess->ClientOption->BindLocalPort == 0) {
				localport = BIND_LOCALPORT_NULL;
			}
			else {
				localport = sess->ClientOption->BindLocalPort + Count(sess->Connection->CurrentNumConnection) - 1;
				Debug("ClientConnectGetSocket(): Additional source port number %u\n", localport);
			}
			// Bottom of Bind outgoing connection

			sock = BindTcpIpConnectEx(localIP, localport, hostname, c->ServerPort,
				(bool *)cancel_flag, c->hWndForUI, &resolved_ip);
		}

		if (sock == NULL)
		{
			// Connection failure
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

		// Top of Bind outgoing connection
		// In the case of first TCP/IP connection
		if (additional_connect == false) {
			if (sess->ClientOption->NoRoutingTracking == false) {
				in.BindLocalIP = BIND_LOCALIP_NULL;	// Specify not to bind
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
		// In the case of second and subsequent TCP/IP connections
		else {
			in.BindLocalIP = &sess->LocalIP_CacheForNextConnect;
		}
		if (sess->ClientOption->BindLocalPort == 0) {
			in.BindLocalPort = BIND_LOCALPORT_NULL;
		}
		else {
			in.BindLocalPort = sess->ClientOption->BindLocalPort + Count(sess->Connection->CurrentNumConnection) - 1;
		}
		// Bottom of Bind outgoing connection

#ifdef OS_WIN32
		in.Hwnd = c->hWndForUI;
#endif

		UniFormat(tmp, sizeof(tmp), _UU("STATUS_2"), in.TargetHostname, in.Hostname);
		PrintStatus(sess, tmp);

		switch (o->ProxyType)
		{
		case PROXY_HTTP:
//			ret = ProxyHttpConnect(&out, &in, cancel_flag);
			ret = BindProxyHttpConnect(&out, &in, cancel_flag);		// Bind outgoing connection
			break;
		case PROXY_SOCKS:
//			ret = ProxySocks4Connect(&out, &in, cancel_flag);
			ret = BindProxySocks4Connect(&out, &in, cancel_flag);	// Bind outgoing connection
			break;
		case PROXY_SOCKS5:
//			ret = ProxySocks5Connect(&out, &in, cancel_flag);
			ret = BindProxySocks5Connect(&out, &in, cancel_flag);	// Bind outgoing connection
			break;
		default:
			c->Err = ERR_INTERNAL_ERROR;
			Debug("ClientConnectGetSocket(): Unknown proxy type: %u!\n", o->ProxyType);
			return NULL;
		}

		c->Err = ProxyCodeToCedar(ret);

		if (c->Err != ERR_NO_ERROR)
		{
			Debug("ClientConnectGetSocket(): Connection via proxy server failed with error %u\n", ret);
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
		Debug("ClientConnectGetSocket(): Saved %s IP address %r for future connections.\n", hostname, &resolved_ip);
	}

	// Top of Bind outgoing connection
	IPToStr(localaddr, sizeof(localaddr), &sock->LocalIP);

	// In the case of first TCP/IP connection, save the local IP address
	if (additional_connect == false) {
		c->Session->LocalIP_CacheForNextConnect = sock->LocalIP;
		Debug("ClientConnectGetSocket(): Saved local IP address %r for future connections.\n", &sock->LocalIP);
	}
	// In the case of second and subsequent TCP/IP connections, check to see whether or not the local IP address is same as the first one
	else {
		if (memcmp(sock->LocalIP.address, c->Session->LocalIP_CacheForNextConnect.address, sizeof(sock->LocalIP.address)) == 0) {
			Debug("ClientConnectGetSocket(): Binded local IP address %s OK\n", localaddr);
		}
		else {
			Debug("ClientConnectGetSocket(): Binded local IP address %s NG\n", localaddr);
		}
	}
	// Bottom of Bind outgoing connection

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

// TCP connection function
SOCK *TcpConnectEx3(char *hostname, UINT port, UINT timeout, bool *cancel_flag, void *hWnd, IP *ret_ip)
{
	return BindTcpConnectEx3(BIND_LOCALIP_NULL, BIND_LOCALPORT_NULL, hostname, port, timeout, cancel_flag, hWnd, ret_ip);
}

// TCP connection function
//SOCK* TcpConnectEx3(char* hostname, UINT port, UINT timeout, bool* cancel_flag, void* hWnd, IP* ret_ip)
SOCK *BindTcpConnectEx3(IP *localIP, UINT localport, char *hostname, UINT port, UINT timeout, bool *cancel_flag, void *hWnd, IP *ret_ip)
{
//	return ConnectEx4(hostname, port, timeout, cancel_flag, true, ret_ip);
	return BindConnectEx4(localIP, localport, hostname, port, timeout, cancel_flag, true, ret_ip);
}

// Connect with TCP/IP
//SOCK *TcpIpConnectEx(char *hostname, UINT port, bool *cancel_flag, void *hWnd, IP *ret_ip)
SOCK *BindTcpIpConnectEx(IP *localIP, UINT localport, char *hostname, UINT port, bool *cancel_flag, void *hWnd, IP *ret_ip)
{
	SOCK *s = NULL;
	// Validate arguments
	if (hostname == NULL || port == 0)
	{
		return NULL;
	}

//	s = TcpConnectEx3(hostname, port, 0, cancel_flag, hWnd, ret_ip);
	s = BindTcpConnectEx3(localIP, localport, hostname, port, 0, cancel_flag, hWnd, ret_ip);
	if (s == NULL)
	{
		return NULL;
	}

	return s;
}

// Interpret the Hello packet
bool GetHello(PACK *p, void *random, UINT *ver, UINT *build, char *server_str, UINT server_str_size)
{
	// Validate arguments
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

// Generate a packet of certificate authentication login
PACK *PackLoginWithCert(char *hubname, char *username, X *x, void *sign, UINT sign_size)
{
	PACK *p;
	BUF *b;
	// Validate arguments
	if (hubname == NULL || username == NULL)
	{
		return NULL;
	}

	p = NewPack();
	PackAddStr(p, "method", "login");
	PackAddStr(p, "hubname", hubname);
	PackAddStr(p, "username", username);
	PackAddInt(p, "authtype", CLIENT_AUTHTYPE_CERT);

	// Certificate
	b = XToBuf(x, false);
	PackAddData(p, "cert", b->Buf, b->Size);
	FreeBuf(b);

	// Signature data
	PackAddData(p, "sign", sign, sign_size);

	return p;
}

// Generate a packet of plain text password authentication login
PACK *PackLoginWithPlainPassword(char *hubname, char *username, void *plain_password)
{
	PACK *p;
	// Validate arguments
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

// Create a packet of password authentication login
PACK *PackLoginWithPassword(char *hubname, char *username, void *secure_password)
{
	PACK *p;
	// Validate arguments
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

// Create a packet for anonymous login
PACK *PackLoginWithAnonymous(char *hubname, char *username)
{
	PACK *p;
	// Validate arguments
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

// Create a packet for the additional connection
PACK *PackAdditionalConnect(UCHAR *session_key)
{
	PACK *p;
	// Validate arguments
	if (session_key == NULL)
	{
		return NULL;
	}

	p = NewPack();
	PackAddStr(p, "method", "additional_connect");
	PackAddData(p, "session_key", session_key, SHA1_SIZE);

	return p;
}
