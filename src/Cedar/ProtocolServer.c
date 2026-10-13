// ProtocolServer.c
// SE-VPN protocol, server-accept side: ServerAccept, ChangePasswordAccept, the server hello, signature check and welcome

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

void NodeInfoToStr(wchar_t *str, UINT size, NODE_INFO *info)
{
	char client_ip[128], server_ip[128], proxy_ip[128], unique_id[128];
	if (str == NULL || info == NULL)
	{
		return;
	}

	IPToStr4or6(client_ip, sizeof(client_ip), info->ClientIpAddress, info->ClientIpAddress6);
	IPToStr4or6(server_ip, sizeof(server_ip), info->ServerIpAddress, info->ServerIpAddress6);
	IPToStr4or6(proxy_ip, sizeof(proxy_ip), info->ProxyIpAddress, info->ProxyIpAddress6);
	BinToStr(unique_id, sizeof(unique_id), info->UniqueId, sizeof(info->UniqueId));

	UniFormat(str, size, _UU("LS_NODE_INFO_TAG"), info->ClientProductName,
		Endian32(info->ClientProductVer), Endian32(info->ClientProductBuild),
		info->ServerProductName, Endian32(info->ServerProductVer), Endian32(info->ServerProductBuild),
		info->ClientOsName, info->ClientOsVer, info->ClientOsProductId,
		info->ClientHostname, client_ip, Endian32(info->ClientPort),
		info->ServerHostname, server_ip, Endian32(info->ServerPort),
		info->ProxyHostname, proxy_ip, Endian32(info->ProxyPort),
		info->HubName, unique_id);
}

UINT ChangePasswordAccept(CONNECTION *c, PACK *p)
{
	CEDAR *cedar;
	UCHAR random[SHA1_SIZE];
	char hubname[MAX_HUBNAME_LEN + 1];
	char username[MAX_USERNAME_LEN + 1];
	UCHAR secure_old_password[SHA1_SIZE];
	UCHAR new_password[SHA1_SIZE];
	UCHAR new_password_ntlm[SHA1_SIZE];
	UCHAR check_secure_old_password[SHA1_SIZE];
	UINT ret = ERR_NO_ERROR;
	HUB *hub;
	if (c == NULL || p == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	Copy(random, c->Random, SHA1_SIZE);
	if (PackGetStr(p, "hubname", hubname, sizeof(hubname)) == false ||
		PackGetStr(p, "username", username, sizeof(username)) == false ||
		PackGetData2(p, "secure_old_password", secure_old_password, sizeof(secure_old_password)) == false ||
		PackGetData2(p, "new_password", new_password, sizeof(new_password)) == false)
	{
		return ERR_PROTOCOL_ERROR;
	}

	if (PackGetData2(p, "new_password_ntlm", new_password_ntlm, MD5_SIZE) == false)
	{
		Zero(new_password_ntlm, sizeof(new_password_ntlm));
	}

	cedar = c->Cedar;

	LockHubList(cedar);
	{
		hub = GetHub(cedar, hubname);
	}
	UnlockHubList(cedar);

	if (hub == NULL)
	{
		ret = ERR_HUB_NOT_FOUND;
	}
	else
	{
		char tmp[MAX_SIZE];

		if (GetHubAdminOption(hub, "deny_change_user_password") != 0)
		{
			ReleaseHub(hub);
			return ERR_NOT_ENOUGH_RIGHT;
		}

		IPToStr(tmp, sizeof(tmp), &c->FirstSock->RemoteIP);
		HLog(hub, "LH_CHANGE_PASSWORD_1", c->Name, tmp);

		AcLock(hub);
		{
			USER *u = AcGetUser(hub, username);
			if (u == NULL)
			{
				HLog(hub, "LH_CHANGE_PASSWORD_2", c->Name, username);
				ret = ERR_OLD_PASSWORD_WRONG;
			}
			else
			{
				Lock(u->lock);
				{
					if (u->AuthType	!= AUTHTYPE_PASSWORD)
					{
						HLog(hub, "LH_CHANGE_PASSWORD_3", c->Name, username);
						ret = ERR_USER_AUTHTYPE_NOT_PASSWORD;
					}
					else
					{
						bool fix_password = false;
						if (u->Policy != NULL)
						{
							fix_password = u->Policy->FixPassword;
						}
						else
						{
							if (u->Group != NULL)
							{
								if (u->Group->Policy != NULL)
								{
									fix_password = u->Group->Policy->FixPassword;
								}
							}
						}
						if (fix_password == false)
						{
							AUTHPASSWORD *pw = (AUTHPASSWORD *)u->AuthData;

							SecurePassword(check_secure_old_password, pw->HashedKey, random);
							if (Cmp(check_secure_old_password, secure_old_password, SHA1_SIZE) != 0)
							{
								ret = ERR_OLD_PASSWORD_WRONG;
								HLog(hub, "LH_CHANGE_PASSWORD_4", c->Name, username);
							}
							else
							{
								if (Cmp(pw->HashedKey, new_password, SHA1_SIZE) != 0 || IsZero(pw->NtLmSecureHash, MD5_SIZE))
								{
									Copy(pw->HashedKey, new_password, SHA1_SIZE);
									Copy(pw->NtLmSecureHash, new_password_ntlm, MD5_SIZE);
									IncrementServerConfigRevision(cedar->Server);
								}
								HLog(hub, "LH_CHANGE_PASSWORD_5", c->Name, username);
							}
						}
						else
						{
							ret = ERR_NOT_ENOUGH_RIGHT;
						}
					}
				}
				Unlock(u->lock);

				ReleaseUser(u);
			}
		}
		AcUnlock(hub);
		ReleaseHub(hub);
	}

	return ret;
}

bool ServerAccept(CONNECTION *c)
{
	bool ret = false;
	UINT err;
	PACK *p;
	char username_real[MAX_SIZE];
	char method[MAX_SIZE];
	char hubname[MAX_SIZE];
	char username[MAX_SIZE];
	char groupname[MAX_SIZE];
	UCHAR session_key[SHA1_SIZE];
	UINT authtype;
	POLICY *policy;
	HUB *hub;
	SESSION *s = NULL;
	UINT64 user_expires = 0;
	bool use_encrypt;
	bool use_compress;
	bool half_connection;
	UINT adjust_mss;
	bool use_udp_acceleration_client;
	UINT client_udp_acceleration_max_version = 1;
	UINT udp_acceleration_version = 1;
	bool support_hmac_on_udp_acceleration_client = false;
	bool support_udp_accel_fast_disconnect_detect;
	bool use_hmac_on_udp_acceleration = false;
	bool supress_return_pack_error = false;
	IP udp_acceleration_client_ip;
	UCHAR udp_acceleration_client_key[UDP_ACCELERATION_COMMON_KEY_SIZE_V1];
	UCHAR udp_acceleration_client_key_v2[UDP_ACCELERATION_COMMON_KEY_SIZE_V2];
	UINT udp_acceleration_client_port;
	bool admin_mode = false;
	UINT direction;
	UINT max_connection;
	UINT timeout;
	bool no_reconnect_to_session = false;
	bool require_bridge_routing_mode;
	bool require_monitor_mode;
	bool use_client_license = false, use_bridge_license = false;
	bool local_host_session = false;
	char sessionname[MAX_SESSION_NAME_LEN + 1];
	bool is_server_or_bridge = false;
	bool qos = false;
	bool no_save_password = false;
	NODE_INFO node;
	wchar_t *msg = NULL;
	bool suppress_client_update_notification = false;
	USER *loggedin_user_object = NULL;
	SERVER *server = NULL;
	UCHAR unique[SHA1_SIZE], unique2[SHA1_SIZE];
	CEDAR *cedar;
	RPC_WINVER winver;
	UINT client_id;
	bool no_more_users_in_server = false;
	UCHAR mschap_v2_server_response_20[20];
	UINT ms_chap_error = 0;
	bool is_empty_password = false;
	char *error_detail = NULL;
	char *error_detail_2 = NULL;
	char ctoken_hash_str[64];

	if (c == NULL)
	{
		return false;
	}

	GenerateMachineUniqueHash(unique2);

	Zero(ctoken_hash_str, sizeof(ctoken_hash_str));

	Zero(mschap_v2_server_response_20, sizeof(mschap_v2_server_response_20));

	Zero(&udp_acceleration_client_ip, sizeof(udp_acceleration_client_ip));
	udp_acceleration_client_port = 0;
	Zero(udp_acceleration_client_key, sizeof(udp_acceleration_client_key));
	Zero(udp_acceleration_client_key_v2, sizeof(udp_acceleration_client_key_v2));

	Zero(&winver, sizeof(winver));

	StrCpy(groupname, sizeof(groupname), "");
	StrCpy(sessionname, sizeof(sessionname), "");

	if (IsZero(c->CToken_Hash, SHA1_SIZE) == false)
	{
		BinToStr(ctoken_hash_str, sizeof(ctoken_hash_str), c->CToken_Hash, SHA1_SIZE);
	}

	cedar = c->Cedar;


	no_more_users_in_server = SiTooManyUserObjectsInServer(cedar->Server, true);

	c->Status = CONNECTION_STATUS_NEGOTIATION;

	if (c->Cedar->Server != NULL)
	{
		server = c->Cedar->Server;
	}

	error_detail_2 = NULL;
	if (ServerDownloadSignature(c, &error_detail_2) == false)
	{
		if (c->Type == CONNECTION_TYPE_ADMIN_RPC)
		{
			c->Err = ERR_NO_ERROR;
		}

		if (error_detail_2 == NULL)
		{
			error_detail = "ServerDownloadSignature";
		}
		else
		{
			error_detail = error_detail_2;
		}

		supress_return_pack_error = true;

		goto CLEANUP;
	}

	if (ServerUploadHello(c) == false)
	{
		error_detail = "ServerUploadHello";
		goto CLEANUP;
	}


	p = HttpServerRecv(c->FirstSock);
	if (p == NULL)
	{
		c->Err = ERR_DISCONNECTED;
		error_detail = "RecvAuth1";
		goto CLEANUP;
	}

	if (err = GetErrorFromPack(p))
	{
		FreePack(p);
		c->Err = err;
		error_detail = "RecvAuth2";
		goto CLEANUP;
	}

	if (GetMethodFromPack(p, method, sizeof(method)) == false)
	{
		FreePack(p);
		c->Err = ERR_PROTOCOL_ERROR;
		error_detail = "GetMethodFromPack";
		goto CLEANUP;
	}

	{
		char tmp[20];
		char *branded_ctos = _SS("BRANDED_C_TO_S");
		PackGetStr(p, "branded_ctos", tmp, sizeof(tmp));

		if(StrCmpi(method, "login") == 0 && StrLen(branded_ctos) > 0 && StrCmpi(branded_ctos, tmp) != 0)
		{
			FreePack(p);
			c->Err = ERR_BRANDED_C_TO_S;
			goto CLEANUP;
		}
	}

	PackGetStr(p, "client_str", c->ClientStr, sizeof(c->ClientStr));
	c->ClientVer = PackGetInt(p, "client_ver");
	c->ClientBuild = PackGetInt(p, "client_build");

	if (SearchStrEx(c->ClientStr, "server", 0, false) != INFINITE ||
		SearchStrEx(c->ClientStr, "bridge", 0, false) != INFINITE)
	{
		is_server_or_bridge = true;
	}

	InRpcWinVer(&winver, p);

	DecrementNoSsl(c->Cedar, &c->FirstSock->RemoteIP, 2);

	if (StrCmpi(method, "login") == 0)
	{
		bool auth_ret = false;

		c->Status = CONNECTION_STATUS_USERAUTH;

		c->Type = CONNECTION_TYPE_LOGIN;

		if (no_more_users_in_server)
		{
			FreePack(p);
			c->Err = ERR_TOO_MANY_USER;
			error_detail = "ERR_TOO_MANY_USER";
			goto CLEANUP;
		}

		if (PackGetStr(p, "hello", c->ClientStr, sizeof(c->ClientStr)) == false)
		{
			StrCpy(c->ClientStr, sizeof(c->ClientStr), "Unknown");
		}
		c->ServerVer = GetCedarVersionNumber();
		c->ServerBuild = CEDAR_WIRE_BUILD;

		Zero(&node, sizeof(node));
		InRpcNodeInfo(&node, p);

		c->Protocol = GetProtocolFromPack(p);
		if (c->Protocol == CONNECTION_UDP)
		{
			if (c->Tcp)
			{
				ReleaseList(c->Tcp->TcpSockList);
				Free(c->Tcp);
			}
		}

		if (GetServerCapsBool(c->Cedar->Server, "b_vpn_client_connect") == false)
		{
			FreePack(p);
			c->Err = ERR_NOT_SUPPORTED;
			goto CLEANUP;
		}

		authtype = GetAuthTypeFromPack(p);
		if (GetHubnameAndUsernameFromPack(p, username, sizeof(username), hubname, sizeof(hubname)) == false)
		{
			FreePack(p);
			c->Err = ERR_PROTOCOL_ERROR;
			error_detail = "GetHubnameAndUsernameFromPack";
			goto CLEANUP;
		}

		LockHubList(c->Cedar);
		{
			hub = GetHub(c->Cedar, hubname);
		}
		UnlockHubList(c->Cedar);
		if (hub == NULL)
		{
			FreePack(p);
			c->Err = ERR_HUB_NOT_FOUND;
			SLog(c->Cedar, "LS_HUB_NOT_FOUND", c->Name, hubname);
			error_detail = "ERR_HUB_NOT_FOUND";
			goto CLEANUP;
		}

		if (hub->ForceDisableComm)
		{
			FreePack(p);
			c->Err = ERR_SERVER_CANT_ACCEPT;
			error_detail = "ERR_COMM_DISABLED";
			ReleaseHub(hub);
			goto CLEANUP;
		}

		if (GetGlobalServerFlag(GSF_DISABLE_AC) == 0)
		{
			if (hub->HubDb != NULL && c->FirstSock != NULL)
			{
				IP ip;

				Copy(&ip, &c->FirstSock->RemoteIP, sizeof(IP));

				if (IsIpDeniedByAcList(&ip, hub->HubDb->AcList))
				{
					char ip_str[64];
					ReleaseHub(hub);
					hub = NULL;
					FreePack(p);
					c->Err = ERR_IP_ADDRESS_DENIED;
					IPToStr(ip_str, sizeof(ip_str), &ip);
					SLog(c->Cedar, "LS_IP_DENIED", c->Name, ip_str);
					goto CLEANUP;
				}
			}
		}

		Lock(hub->lock);
		{
			UINT cert_size = 0;
			void *cert_buf = NULL;
			USER *user;
			USERGROUP *group;
			char plain_password[MAX_PASSWORD_LEN + 1];

			if (hub->Halt || hub->Offline)
			{
				FreePack(p);
				Unlock(hub->lock);
				ReleaseHub(hub);
				c->Err = ERR_HUB_STOPPING;
				goto CLEANUP;
			}

			use_encrypt = PackGetInt(p, "use_encrypt") == 0 ? false : true;
			use_compress = PackGetInt(p, "use_compress") == 0 ? false : true;
			max_connection = PackGetInt(p, "max_connection");
			half_connection = PackGetInt(p, "half_connection") == 0 ? false : true;
			qos = PackGetInt(p, "qos") ? true : false;
			client_id = PackGetInt(p, "client_id");
			adjust_mss = PackGetInt(p, "adjust_mss");
			use_udp_acceleration_client = PackGetBool(p, "use_udp_acceleration");
			client_udp_acceleration_max_version = PackGetInt(p, "udp_acceleration_max_version");
			if (client_udp_acceleration_max_version == 0)
			{
				client_udp_acceleration_max_version = 1;
			}
			support_hmac_on_udp_acceleration_client = PackGetBool(p, "support_hmac_on_udp_acceleration");
			support_udp_accel_fast_disconnect_detect = PackGetBool(p, "support_udp_accel_fast_disconnect_detect");

			if (c->CipherName != NULL)
			{
				Free(c->CipherName);
			}
			c->CipherName = NULL;

			if (c->SslVersion != NULL)
			{
				Free(c->SslVersion);
			}
			c->SslVersion = NULL;

			if (c->FirstSock != NULL && IsEmptyStr(c->FirstSock->CipherName) == false)
			{
				c->CipherName = CopyStr(c->FirstSock->CipherName);
			}

			if (c->FirstSock != NULL && IsEmptyStr(c->FirstSock->SslVersion) == false)
			{
				c->SslVersion = CopyStr(c->FirstSock->SslVersion);
			}

			if (use_udp_acceleration_client)
			{
				PackGetData2(p, "udp_acceleration_client_key", udp_acceleration_client_key, UDP_ACCELERATION_COMMON_KEY_SIZE_V1);
				PackGetData2(p, "udp_acceleration_client_key_v2", udp_acceleration_client_key_v2, UDP_ACCELERATION_COMMON_KEY_SIZE_V2);

				if (PackGetIp(p, "udp_acceleration_client_ip", &udp_acceleration_client_ip) == false)
				{
					use_udp_acceleration_client = false;
				}
				else
				{
					if (IsZeroIp(&udp_acceleration_client_ip))
					{
						Copy(&udp_acceleration_client_ip, &c->FirstSock->RemoteIP, sizeof(IP));
					}
					udp_acceleration_client_port = PackGetInt(p, "udp_acceleration_client_port");
					if (udp_acceleration_client_port == 0)
					{
						use_udp_acceleration_client = false;
					}
				}

				use_hmac_on_udp_acceleration = support_hmac_on_udp_acceleration_client;
			}


			require_bridge_routing_mode = PackGetBool(p, "require_bridge_routing_mode");
			require_monitor_mode = PackGetBool(p, "require_monitor_mode");
			if (require_monitor_mode)
			{
				qos = false;
			}

			if (is_server_or_bridge)
			{
				require_bridge_routing_mode = true;
			}

			Zero(unique, sizeof(unique));
			if (PackGetDataSize(p, "unique_id") == SHA1_SIZE)
			{
				PackGetData(p, "unique_id", unique);
			}

			if (1)
			{
				char ip1[64], ip2[64], verstr[64];
				wchar_t *authtype_str = _UU("LH_AUTH_UNKNOWN");
				switch (authtype)
				{
				case CLIENT_AUTHTYPE_ANONYMOUS:
					authtype_str = _UU("LH_AUTH_ANONYMOUS");
					break;
				case CLIENT_AUTHTYPE_PASSWORD:
					authtype_str = _UU("LH_AUTH_PASSWORD");
					break;
				case CLIENT_AUTHTYPE_PLAIN_PASSWORD:
					authtype_str = _UU("LH_AUTH_PLAIN_PASSWORD");
					break;
				case CLIENT_AUTHTYPE_CERT:
					authtype_str = _UU("LH_AUTH_CERT");
					break;
				case AUTHTYPE_EXTERNAL:
					authtype_str = _UU("LH_AUTH_EXTERNAL");
					break;
				}
				IPToStr(ip1, sizeof(ip1), &c->FirstSock->RemoteIP);
				IPToStr(ip2, sizeof(ip2), &c->FirstSock->LocalIP);

				Format(verstr, sizeof(verstr), "%u.%02u", c->ClientVer / 100, c->ClientVer % 100);

				HLog(hub, "LH_CONNECT_CLIENT", c->Name, ip1, c->FirstSock->RemoteHostname, c->FirstSock->RemotePort,
					c->ClientStr, verstr, c->ClientBuild, authtype_str, username);
			}

			auth_ret = SamAuthUserByAnonymous(hub, username);
			if (auth_ret)
			{
				is_empty_password = true;
			}

			if (auth_ret == false)
			{
				switch (authtype)
				{
				case CLIENT_AUTHTYPE_ANONYMOUS:
					break;

				case AUTHTYPE_EXTERNAL:
					auth_ret = true;
					break;

				case CLIENT_AUTHTYPE_PASSWORD:
					if (PackGetDataSize(p, "secure_password") == SHA1_SIZE)
					{
						POLICY *pol = NULL;
						UCHAR secure_password[SHA1_SIZE];
						Zero(secure_password, sizeof(secure_password));
						if (PackGetDataSize(p, "secure_password") == SHA1_SIZE)
						{
							PackGetData(p, "secure_password", secure_password);
						}
						auth_ret = SamAuthUserByPassword(hub, username, c->Random, secure_password, NULL, NULL, NULL);

						pol = SamGetUserPolicy(hub, username);
						if (pol != NULL)
						{
							no_save_password = pol->NoSavePassword;
							Free(pol);
						}

						if(auth_ret){
							UCHAR hashed_empty_password[SHA1_SIZE];
							UCHAR secure_empty_password[SHA1_SIZE];
							HashPassword(hashed_empty_password, username, "");
							SecurePassword(secure_empty_password, hashed_empty_password, c->Random);
							if(Cmp(secure_password, secure_empty_password, SHA1_SIZE)==0){
								is_empty_password = true;
							}
						}
					}
					break;

				case CLIENT_AUTHTYPE_PLAIN_PASSWORD:
					{
						POLICY *pol = NULL;

						Zero(plain_password, sizeof(plain_password));
						PackGetStr(p, "plain_password", plain_password, sizeof(plain_password));
						if (StartWith(plain_password, IPC_PASSWORD_MSCHAPV2_TAG))
						{
							// Do not allow the MS-CHAPv2 authentication (it was only available to IPC sessions)
							Zero(plain_password, sizeof(plain_password));
						}

						if (auth_ret == false)
						{
							UCHAR secure_password[SHA1_SIZE];
							UCHAR hash_password[SHA1_SIZE];
							bool is_mschap = StartWith(plain_password, IPC_PASSWORD_MSCHAPV2_TAG);

							HashPassword(hash_password, username, plain_password);
							SecurePassword(secure_password, hash_password, c->Random);

							if (is_mschap == false)
							{
								auth_ret = SamAuthUserByPassword(hub, username, c->Random, secure_password, NULL, NULL, NULL);
							}
							else
							{
								auth_ret = SamAuthUserByPassword(hub, username, c->Random, secure_password,
									plain_password, mschap_v2_server_response_20, &ms_chap_error);
							}

							if (auth_ret && pol == NULL)
							{
								pol = SamGetUserPolicy(hub, username);
							}
						}

						if (auth_ret == false)
						{
							bool fail_ext_user_auth = false;
							if (GetGlobalServerFlag(GSF_DISABLE_RADIUS_AUTH) != 0)
							{
								fail_ext_user_auth = true;
							}

							if (fail_ext_user_auth == false)
							{
								auth_ret = SamAuthUserByPlainPassword(c, hub, username, plain_password, true);
							}

							if (auth_ret && pol == NULL)
							{
								pol = SamGetUserPolicy(hub, username);
							}
						}

						if (pol != NULL)
						{
							no_save_password = pol->NoSavePassword;
							Free(pol);
						}

						if(auth_ret){
							if(IsEmptyStr(plain_password)){
								is_empty_password = true;
							}
						}
					}
					break;

				case CLIENT_AUTHTYPE_CERT:
					if (GetGlobalServerFlag(GSF_DISABLE_CERT_AUTH) == 0)
					{
						cert_size = PackGetDataSize(p, "cert");
						if (cert_size >= 1 && cert_size <= 100000)
						{
							cert_buf = ZeroMalloc(cert_size);
							if (PackGetData(p, "cert", cert_buf))
							{
								UCHAR sign[4096 / 8];
								UINT sign_size = PackGetDataSize(p, "sign");
								if (sign_size <= sizeof(sign) && sign_size >= 1)
								{
									if (PackGetData(p, "sign", sign))
									{
										BUF *b = NewBuf();
										X *x;
										WriteBuf(b, cert_buf, cert_size);
										x = BufToX(b, false);
										if (x != NULL && x->is_compatible_bit &&
											sign_size == (x->bits / 8))
										{
											K *k = GetKFromX(x);
											if (RsaVerifyEx(c->Random, SHA1_SIZE, sign, k, x->bits))
											{
												// A matching signature proves the client holds this certificate.
												auth_ret = SamAuthUserByCert(hub, username, x);
												if (auth_ret)
												{
													c->ClientX = CloneX(x);
												}
											}
											else
											{
											}
											FreeK(k);
										}
										FreeX(x);
										FreeBuf(b);
									}
								}
							}
							Free(cert_buf);
						}
					}
					else
					{
						// Certificate authentication is not supported in the open source version
						HLog(hub, "LH_AUTH_CERT_NOT_SUPPORT_ON_OPEN_SOURCE", c->Name, username);
						Unlock(hub->lock);
						ReleaseHub(hub);
						FreePack(p);
						c->Err = ERR_AUTHTYPE_NOT_SUPPORTED;
						goto CLEANUP;
					}
					break;

				default:
					Unlock(hub->lock);
					ReleaseHub(hub);
					FreePack(p);
					c->Err = ERR_AUTHTYPE_NOT_SUPPORTED;
					error_detail = "ERR_AUTHTYPE_NOT_SUPPORTED";
					goto CLEANUP;
				}
			}

			if (auth_ret == false)
			{
				char ip[64];
				IPToStr(ip, sizeof(ip), &c->FirstSock->RemoteIP);
				HLog(hub, "LH_AUTH_NG", c->Name, username, ip);

				Unlock(hub->lock);
				ReleaseHub(hub);
				FreePack(p);
				c->Err = ERR_AUTH_FAILED;
				if (ms_chap_error != 0)
				{
					c->Err = ms_chap_error;
				}
				error_detail = "ERR_AUTH_FAILED";
				goto CLEANUP;
			}
			else
			{
				if (is_empty_password)
				{
					const SOCK *s = c->FirstSock;
					if (s != NULL && IsLocalHostIP(&s->RemoteIP) == false)
					{
						if (StrCmpi(username, ADMINISTRATOR_USERNAME) == 0 || GetHubAdminOption(hub, "deny_empty_password") != 0)
						{
							// Reject remote logins with an empty password.
							HLog(hub, "LH_LOCAL_ONLY", c->Name, username);

							Unlock(hub->lock);
							ReleaseHub(hub);
							FreePack(p);
							c->Err = ERR_NULL_PASSWORD_LOCAL_ONLY;
							error_detail = "ERR_NULL_PASSWORD_LOCAL_ONLY";
							goto CLEANUP;
						}
					}
				}

				HLog(hub, "LH_AUTH_OK", c->Name, username);
			}

			policy = NULL;

			FreePack(p);

			if (StrCmpi(username, ADMINISTRATOR_USERNAME) != 0)
			{
				user = AcGetUser(hub, username);
				if (user == NULL)
				{
					user = AcGetUser(hub, "*");
					if (user == NULL)
					{
						Unlock(hub->lock);
						ReleaseHub(hub);
						c->Err = ERR_ACCESS_DENIED;
						error_detail = "AcGetUser";
						goto CLEANUP;
					}
				}

				policy = NULL;

				Lock(user->lock);
				{
					user_expires = user->ExpireTime;

					StrCpy(username_real, sizeof(username_real), user->Name);
					group = user->Group;
					if (group != NULL)
					{
						AddRef(group->ref);

						Lock(group->lock);
						{
							StrCpy(groupname, sizeof(groupname), group->Name);
						}
						Unlock(group->lock);
					}

					if (user->Policy != NULL)
					{
						policy = ClonePolicy(user->Policy);
					}
					else
					{
						if (group)
						{
							Lock(group->lock);
							{
								if (group->Policy != NULL)
								{
									policy = ClonePolicy(group->Policy);
								}
							}
							Unlock(group->lock);
						}
					}

					if (group != NULL)
					{
						ReleaseGroup(group);
					}
				}
				Unlock(user->lock);
				loggedin_user_object = user;
			}
			else
			{
				admin_mode = true;
				StrCpy(username_real, sizeof(username_real), ADMINISTRATOR_USERNAME);

				policy = ClonePolicy(GetDefaultPolicy());
				policy->NoBroadcastLimiter = true;
				policy->MonitorPort = true;
			}

			if (policy == NULL)
			{
				policy = ClonePolicy(GetDefaultPolicy());
			}

			if (policy->MaxConnection == 0)
			{
				policy->MaxConnection = MAX_TCP_CONNECTION;
			}

			if (policy->TimeOut == 0)
			{
				policy->TimeOut = 20;
			}

			if (qos)
			{
				if (policy->NoQoS)
				{
					qos = false;
				}
				if (GetServerCapsBool(c->Cedar->Server, "b_support_qos") == false)
				{
					qos = false;
					policy->NoQoS = true;
				}
				if (GetHubAdminOption(hub, "deny_qos") != 0)
				{
					qos = false;
					policy->NoQoS = true;
				}
			}

			if (GetHubAdminOption(hub, "max_bitrates_download") != 0)
			{
				if (policy->MaxDownload == 0)
				{
					policy->MaxDownload = GetHubAdminOption(hub, "max_bitrates_download");
				}
				else
				{
					UINT r = GetHubAdminOption(hub, "max_bitrates_download");
					policy->MaxDownload = MIN(policy->MaxDownload, r);
				}
			}

			if (GetHubAdminOption(hub, "max_bitrates_upload") != 0)
			{
				if (policy->MaxUpload == 0)
				{
					policy->MaxUpload = GetHubAdminOption(hub, "max_bitrates_upload");
				}
				else
				{
					UINT r = GetHubAdminOption(hub, "max_bitrates_upload");
					policy->MaxUpload = MIN(policy->MaxUpload, r);
				}
			}

			if (GetHubAdminOption(hub, "deny_bridge") != 0)
			{
				policy->NoBridge = true;
			}

			if (GetHubAdminOption(hub, "deny_routing") != 0)
			{
				policy->NoRouting = true;
			}

			if (hub->Option->ClientMinimumRequiredBuild > c->ClientBuild &&
				 InStrEx(c->ClientStr, "client", false))
			{
				HLog(hub, "LH_CLIENT_VERSION_OLD", c->Name, c->ClientBuild, hub->Option->ClientMinimumRequiredBuild);

				Unlock(hub->lock);
				ReleaseHub(hub);
				c->Err = ERR_VERSION_INVALID;
				Free(policy);
				error_detail = "ERR_VERSION_INVALID";
				goto CLEANUP;
			}

			if (hub->Option->RequiredClientId != 0 &&
				hub->Option->RequiredClientId != client_id && 
				InStrEx(c->ClientStr, "client", false))
			{
				HLog(hub, "LH_CLIENT_ID_REQUIRED", c->Name, client_id, hub->Option->RequiredClientId);

				Unlock(hub->lock);
				ReleaseHub(hub);
				c->Err = ERR_CLIENT_ID_REQUIRED;
				error_detail = "ERR_CLIENT_ID_REQUIRED";
				Free(policy);
				goto CLEANUP;
			}

			if (user_expires != 0 && user_expires <= SystemTime64())
			{
				HLog(hub, "LH_USER_EXPIRES", c->Name, username);

				Unlock(hub->lock);
				ReleaseHub(hub);
				c->Err = ERR_ACCESS_DENIED;
				error_detail = "LH_USER_EXPIRES";
				Free(policy);
				goto CLEANUP;
			}

			if (policy->Access == false)
			{
				HLog(hub, "LH_POLICY_ACCESS_NG", c->Name, username);

				Unlock(hub->lock);
				ReleaseHub(hub);
				error_detail = "LH_POLICY_ACCESS_NG";
				c->Err = ERR_ACCESS_DENIED;
				Free(policy);
				goto CLEANUP;
			}

			if (require_monitor_mode && policy->MonitorPort == false)
			{
				HLog(hub, "LH_POLICY_MONITOR_MODE", c->Name);

				Unlock(hub->lock);
				ReleaseHub(hub);
				c->Err = ERR_MONITOR_MODE_DENIED;
				Free(policy);
				error_detail = "ERR_MONITOR_MODE_DENIED";
				goto CLEANUP;
			}

			if (policy->MonitorPort)
			{
				if (require_monitor_mode == false)
				{
					policy->MonitorPort = false;
				}
			}

			if (policy->MonitorPort)
			{
				qos = false;
			}

			if (require_bridge_routing_mode &&
				(policy->NoBridge && policy->NoRouting))
			{
				HLog(hub, "LH_POLICY_BRIDGE_MODE", c->Name);

				Unlock(hub->lock);
				ReleaseHub(hub);
				c->Err = ERR_BRIDGE_MODE_DENIED;
				error_detail = "ERR_BRIDGE_MODE_DENIED";
				Free(policy);
				goto CLEANUP;
			}

			if (require_bridge_routing_mode == false)
			{
				policy->NoBridge = true;
				policy->NoRouting = true;
			}

			if (Cmp(unique, unique2, SHA1_SIZE) == 0)
			{
				local_host_session = true;
			}

			if (local_host_session == false)
			{
				SOCK *s = c->FirstSock;

				if (s != NULL)
				{
					if (IsIPMyHost(&s->RemoteIP))
					{
						local_host_session = true;
					}
				}
			}

			if (local_host_session)
			{
				policy->NoBridge = false;
				policy->NoRouting = false;
			}

			if (local_host_session == false)
			{

				if (policy->NoBridge == false || policy->NoRouting == false)
				{
					use_bridge_license = true;
				}
				else
				{
					use_client_license = true;
				}
			}


			if (server != NULL && policy != NULL)
			{
				if (GetServerCapsBool(hub->Cedar->Server, "b_support_limit_multilogin"))
				{
					RPC_ENUM_SESSION t;
					UINT i, num;
					UINT max_logins = policy->MultiLogins;
					UINT ao = GetHubAdminOption(hub, "max_multilogins_per_user");

					if (ao != 0)
					{
						if (max_logins != 0)
						{
							max_logins = MIN(max_logins, ao);
						}
						else
						{
							max_logins = ao;
						}
					}

					if (max_logins != 0)
					{
						Zero(&t, sizeof(t));
						StrCpy(t.HubName, sizeof(t.HubName), hub->Name);

						Unlock(hub->lock);

						SiEnumSessionMain(server, &t);

						Lock(hub->lock);

						num = 0;

						for (i = 0;i < t.NumSession;i++)
						{
							RPC_ENUM_SESSION_ITEM *e = &t.Sessions[i];

							if (e->BridgeMode == false && e->LinkMode == false && e->CurrentNumTcp != 0)
							{
								if (StrCmpi(e->Username, username) == 0 &&
									(IsZero(e->UniqueId, 16) || Cmp(e->UniqueId, node.UniqueId, 16) != 0))
								{
									num++;
								}
							}
						}

						FreeRpcEnumSession(&t);

						if (num >= max_logins)
						{
							Unlock(hub->lock);

							HLog(hub, "LH_TOO_MANY_MULTILOGINS",
								c->Name,
								username, max_logins, num);

							ReleaseHub(hub);
							c->Err = ERR_TOO_MANY_USER_SESSION;
							Free(policy);
							goto CLEANUP;
						}
					}
				}
			}

			if (loggedin_user_object != NULL)
			{
				Lock(loggedin_user_object->lock);
				{
					loggedin_user_object->LastLoginTime = SystemTime64();
				}
				Unlock(loggedin_user_object->lock);
			}

			hub->LastCommTime = hub->LastLoginTime = SystemTime64();

			if (admin_mode == false)
			{
				if (hub->Option->MaxSession != 0 &&
					hub->Option->MaxSession <= Count(hub->NumSessions))
				{
					Unlock(hub->lock);

					HLog(hub, "LH_MAX_SESSION", c->Name, hub->Option->MaxSession);

					ReleaseHub(hub);
					c->Err = ERR_HUB_IS_BUSY;
					Free(policy);
					error_detail = "ERR_HUB_IS_BUSY";
					goto CLEANUP;
				}
			}

			if (use_client_license || use_bridge_license)
			{
				if (
					(GetHubAdminOption(hub, "max_sessions") != 0 &&
					(Count(hub->NumSessionsClient) + Count(hub->NumSessionsBridge)) >= GetHubAdminOption(hub, "max_sessions"))
					||
					(hub->Option->MaxSession != 0 &&
					(Count(hub->NumSessionsClient) + Count(hub->NumSessionsBridge)) >= hub->Option->MaxSession))
				{
					Unlock(hub->lock);

					HLog(hub, "LH_MAX_SESSION", c->Name, GetHubAdminOption(hub, "max_sessions"));

					ReleaseHub(hub);
					c->Err = ERR_HUB_IS_BUSY;
					Free(policy);
					goto CLEANUP;
				}
			}

			if (use_client_license)
			{
				if (GetHubAdminOption(hub, "max_sessions_client_bridge_apply") != 0 &&
					Count(hub->NumSessionsClient) >= GetHubAdminOption(hub, "max_sessions_client") && hub->Cedar->Server != NULL)
				{
					Unlock(hub->lock);

					HLog(hub, "LH_MAX_SESSION_CLIENT", c->Name, GetHubAdminOption(hub, "max_sessions_client"));

					ReleaseHub(hub);
					c->Err = ERR_HUB_IS_BUSY;
					Free(policy);
					goto CLEANUP;
				}
			}

			if (use_bridge_license)
			{
				if (GetHubAdminOption(hub, "max_sessions_client_bridge_apply") != 0 &&
					Count(hub->NumSessionsBridge) >= GetHubAdminOption(hub, "max_sessions_bridge") && hub->Cedar->Server != NULL)
				{
					Unlock(hub->lock);

					HLog(hub, "LH_MAX_SESSION_BRIDGE", c->Name, GetHubAdminOption(hub, "max_sessions_bridge"));

					ReleaseHub(hub);
					c->Err = ERR_HUB_IS_BUSY;
					Free(policy);
					goto CLEANUP;
				}
			}

			if (Count(hub->Cedar->CurrentSessions) >= GetServerCapsInt(hub->Cedar->Server, "i_max_sessions"))
			{
				Unlock(hub->lock);

				HLog(hub, "LH_MAX_SESSION_2", c->Name, GetServerCapsInt(hub->Cedar->Server, "i_max_sessions"));

				ReleaseHub(hub);
				c->Err = ERR_HUB_IS_BUSY;
				Free(policy);
				goto CLEANUP;
			}

			Inc(hub->NumSessions);
			if (use_bridge_license)
			{
				Inc(hub->NumSessionsBridge);
			}

			if (use_client_license)
			{
				Inc(hub->NumSessionsClient);
			}
			Inc(hub->Cedar->CurrentSessions);

			timeout = policy->TimeOut * 1000;
			if (timeout == 0)
			{
				timeout = TIMEOUT_DEFAULT;
			}
			timeout = MIN(timeout, TIMEOUT_MAX);
			timeout = MAX(timeout, TIMEOUT_MIN);

			max_connection = MIN(max_connection, policy->MaxConnection);
			max_connection = MIN(max_connection, MAX_TCP_CONNECTION);
			max_connection = MAX(max_connection, 1);

			if (half_connection)
			{
				// Half connection needs at least 2 connections.
				max_connection = MAX(max_connection, 2);
			}

			if (qos)
			{
				// VoIP / QoS needs at least 2 connections.
				max_connection = MAX(max_connection, 2);
				if (half_connection)
				{
					max_connection = MAX(max_connection, 4);
				}
			}

			c->Status = CONNECTION_STATUS_ESTABLISHED;

			DelConnection(c->Cedar, c);

			StrLower(username);
			s = NewServerSession(c->Cedar, c, hub, username, policy);

			s->LocalHostSession = local_host_session;
			s->NormalClient = true;

			IPToStr(s->ClientIP, sizeof(s->ClientIP), &c->ClientIp);

			StrCpy(s->UnderlayProtocol, sizeof(s->UnderlayProtocol), c->FirstSock->UnderlayProtocol);

			AddProtocolDetailsStr(s->ProtocolDetails, sizeof(s->ProtocolDetails), c->FirstSock->ProtocolDetails);

			if (server != NULL)
			{
				s->NoSendSignature = server->NoSendSignature;
			}

			if (use_udp_acceleration_client)
			{
				s->UseUdpAcceleration = true;

				s->UdpAccelFastDisconnectDetect = support_udp_accel_fast_disconnect_detect;

				udp_acceleration_version = 1;
				if (client_udp_acceleration_max_version >= 2)
				{
					udp_acceleration_version = 2;
				}
			}

			if (hub->Option != NULL && hub->Option->DisableUdpAcceleration)
			{
				s->UseUdpAcceleration = false;
			}

			if (s->UseUdpAcceleration)
			{
				s->UseHMacOnUdpAcceleration = use_hmac_on_udp_acceleration;
			}


			if (s->UseUdpAcceleration)
			{
				s->UdpAccel = NewUdpAccel(c->Cedar, &c->FirstSock->LocalIP, false, false);
				if (s->UdpAccel == NULL)
				{
					s->UseUdpAcceleration = false;
				}
				else
				{
					s->UdpAccel->Version = udp_acceleration_version;

					if (UdpAccelInitServer(s->UdpAccel,
						s->UdpAccel->Version == 2 ? udp_acceleration_client_key_v2 : udp_acceleration_client_key,
						&c->FirstSock->RemoteIP, &udp_acceleration_client_ip, udp_acceleration_client_port) == false)
					{
						s->UseUdpAcceleration = false;
					}

					s->UdpAccel->FastDetect = s->UdpAccelFastDisconnectDetect;

					if (use_encrypt == false)
					{
						s->UdpAccel->PlainTextMode = true;
					}

					s->UdpAccel->UseHMac = s->UseHMacOnUdpAcceleration;

					AddProtocolDetailsKeyValueInt(s->ProtocolDetails, sizeof(s->ProtocolDetails), "UDPAccel_Ver", s->UdpAccel->Version);

					AddProtocolDetailsStr(s->ProtocolDetails, sizeof(s->ProtocolDetails), s->UdpAccel->Version > 1 ? "ChaCha20-Poly1305" : "RC4");

					AddProtocolDetailsKeyValueInt(s->ProtocolDetails, sizeof(s->ProtocolDetails), "UDPAccel_MSS", UdpAccelCalcMss(s->UdpAccel));
				}
			}

			s->UseClientLicense = use_client_license;
			s->UseBridgeLicense = use_bridge_license;

			s->AdjustMss = adjust_mss;
			if (s->AdjustMss != 0)
			{
				AddProtocolDetailsKeyValueInt(s->ProtocolDetails, sizeof(s->ProtocolDetails), "AdjustMSS", s->AdjustMss);
			}

			s->IsBridgeMode = (policy->NoBridge == false) || (policy->NoRouting == false);
			s->IsMonitorMode = policy->MonitorPort;

			s->IPv6Session = false;

			if (node.ClientIpAddress == 0)
			{
				s->IPv6Session = true;
			}

			if (use_bridge_license)
			{
				Inc(s->Cedar->AssignedBridgeLicense);
			}

			if (use_client_license)
			{
				Inc(s->Cedar->AssignedClientLicense);
			}

			if (server != NULL)
			{
				server->CurrentAssignedClientLicense = Count(s->Cedar->AssignedClientLicense);
				server->CurrentAssignedBridgeLicense = Count(s->Cedar->AssignedBridgeLicense);
			}

			if (StrLen(sessionname) != 0)
			{
				Free(s->Name);
				s->Name = CopyStr(sessionname);
			}

			{
				char ip[128];
				IPToStr(ip, sizeof(ip), &c->FirstSock->RemoteIP);
				HLog(hub, "LH_NEW_SESSION", c->Name, s->Name, ip, c->FirstSock->RemotePort, c->FirstSock->UnderlayProtocol, c->FirstSock->ProtocolDetails);
			}

			c->Session = s;
			s->AdministratorMode = admin_mode;
			StrCpy(s->UserNameReal, sizeof(s->UserNameReal), username_real);
			StrCpy(s->GroupName, sizeof(s->GroupName), groupname);

			Copy(session_key, s->SessionKey, SHA1_SIZE);

			s->MaxConnection = max_connection;
			s->UseEncrypt = use_encrypt;
			s->UseCompress = use_compress;
			s->HalfConnection = half_connection;
			s->Timeout = timeout;
			s->QoS = qos;
			s->NoReconnectToSession = no_reconnect_to_session;
			s->VLanId = policy->VLanId;

			s->Username = CopyStr(username);

			HLog(hub, "LH_SET_SESSION", s->Name, s->MaxConnection,
				s->UseEncrypt ? _UU("L_YES") : _UU("L_NO"),
				s->UseCompress ? _UU("L_YES") : _UU("L_NO"),
				s->HalfConnection ? _UU("L_YES") : _UU("L_NO"),
				s->Timeout / 1000);

			msg = GetHubMsg(hub);

			if (hub->Option != NULL)
			{
				suppress_client_update_notification = hub->Option->SuppressClientUpdateNotification;
			}
		}
		Unlock(hub->lock);

		if (s->UseUdpAcceleration && s->UdpAccel != NULL)
		{
			// Learn the public endpoint of the UDP acceleration socket by STUN (only if configured and the peer is not local).
			// This is done after releasing the hub lock because the query may block for a while.
			UdpAccelQueryStun(s->UdpAccel, &c->FirstSock->RemoteIP);
		}

		p = PackWelcome(s);

		PackAddBool(p, "suppress_client_update_notification", suppress_client_update_notification);

		if (true)
		{
			char *utf;
			wchar_t winver_msg_client[3800];
			wchar_t winver_msg_server[3800];
			UINT tmpsize;
			wchar_t *tmp;
			RPC_WINVER server_winver;

			GetWinVer(&server_winver);

			Zero(winver_msg_client, sizeof(winver_msg_client));
			Zero(winver_msg_server, sizeof(winver_msg_server));

			if (IsSupportedWinVer(&winver) == false)
			{
				SYSTEMTIME st;

				LocalTime(&st);

				UniFormat(winver_msg_client, sizeof(winver_msg_client), _UU("WINVER_ERROR_FORMAT"),
					_UU("WINVER_ERROR_PC_LOCAL"),
					winver.Title,
					_UU("WINVER_ERROR_VPNSERVER"),
					SUPPORTED_WINDOWS_LIST,
					_UU("WINVER_ERROR_PC_LOCAL"),
					_UU("WINVER_ERROR_VPNSERVER"),
					_UU("WINVER_ERROR_VPNSERVER"),
					_UU("WINVER_ERROR_VPNSERVER"),
					st.wYear, st.wMonth);
			}

			if (IsSupportedWinVer(&server_winver) == false)
			{
				SYSTEMTIME st;

				LocalTime(&st);

				UniFormat(winver_msg_server, sizeof(winver_msg_server), _UU("WINVER_ERROR_FORMAT"),
					_UU("WINVER_ERROR_PC_REMOTE"),
					server_winver.Title,
					_UU("WINVER_ERROR_VPNSERVER"),
					SUPPORTED_WINDOWS_LIST,
					_UU("WINVER_ERROR_PC_REMOTE"),
					_UU("WINVER_ERROR_VPNSERVER"),
					_UU("WINVER_ERROR_VPNSERVER"),
					_UU("WINVER_ERROR_VPNSERVER"),
					st.wYear, st.wMonth);
			}

			tmpsize = UniStrSize(winver_msg_client) + UniStrSize(winver_msg_server) + UniStrSize(msg) + (16000 + 3000) * sizeof(wchar_t);

			tmp = ZeroMalloc(tmpsize);

			if (IsURLMsg(msg, NULL, 0) == false)
			{

				{
					if (GetGlobalServerFlag(GSF_SHOW_OSS_MSG) != 0)
					{
						UniStrCat(tmp, tmpsize, _UU("OSS_MSG"));
					}
				}

				{
					UniStrCat(tmp, tmpsize, winver_msg_client);
					UniStrCat(tmp, tmpsize, winver_msg_server);
				}
			}
			UniStrCat(tmp, tmpsize, msg);
			
			utf = CopyUniToUtf(tmp);

			PackAddData(p, "Msg", utf, StrLen(utf));

			Free(tmp);
			Free(utf);
		}

		Free(msg);

		{
			char *branded_cfroms = _SS("BRANDED_C_FROM_S");
			if(StrLen(branded_cfroms) > 0)
			{
				PackAddStr(p, "branded_cfroms", branded_cfroms);
			}
		}

		HttpServerSend(c->FirstSock, p);
		FreePack(p);

		Copy(&c->Session->NodeInfo, &node, sizeof(NODE_INFO));


		{
			wchar_t tmp[MAX_SIZE * 2];
			NodeInfoToStr(tmp, sizeof(tmp), &s->NodeInfo);

			HLog(hub, "LH_NODE_INFO", s->Name, tmp);

			if (s->VLanId != 0)
			{
				HLog(hub, "LH_VLAN_ID", s->Name, s->VLanId);
			}
		}

		StartTunnelingMode(c);

		if (s->HalfConnection)
		{
			// The first socket's direction is client to server.
			TCPSOCK *ts = (TCPSOCK *)LIST_DATA(c->Tcp->TcpSockList, 0);
			ts->Direction = TCP_CLIENT_TO_SERVER;
		}

		if (s->LocalHostSession)
		{
			RefreshLocalMacAddressList();
		}

		DeleteAllUserListCache(hub->UserList);


		s->NumLoginIncrementUserObject = loggedin_user_object;
		s->NumLoginIncrementHubObject = s->Hub;
		s->NumLoginIncrementTick = Tick64() + (UINT64)NUM_LOGIN_INCREMENT_INTERVAL;
		SessionMain(s);


		DeleteAllUserListCache(hub->UserList);

		Lock(s->Hub->lock);
		{
			if (use_bridge_license)
			{
				Dec(hub->NumSessionsBridge);
			}

			if (use_client_license)
			{
				Dec(hub->NumSessionsClient);
			}

			Dec(s->Hub->NumSessions);
			Dec(s->Hub->Cedar->CurrentSessions);

			if (use_bridge_license)
			{
				Dec(s->Cedar->AssignedBridgeLicense);
			}

			if (use_client_license)
			{
				Dec(s->Cedar->AssignedClientLicense);
			}

			if (server != NULL)
			{
				server->CurrentAssignedClientLicense = Count(s->Cedar->AssignedClientLicense);
				server->CurrentAssignedBridgeLicense = Count(s->Cedar->AssignedBridgeLicense);
			}
		}
		Unlock(s->Hub->lock);

		PrintSessionTotalDataSize(s);

		HLog(s->Hub, "LH_END_SESSION", s->Name, s->TotalSendSizeReal, s->TotalRecvSizeReal);

		if (s->UdpAccel != NULL)
		{
			FreeUdpAccel(s->UdpAccel);
			s->UdpAccel = NULL;
		}

		ReleaseSession(s);

		ret = true;
		c->Err = ERR_SESSION_REMOVED;

		ReleaseHub(hub);

		goto CLEANUP;
	}
	else if (StrCmpi(method, "additional_connect") == 0)
	{
		SOCK *sock;
		TCPSOCK *ts;
		UINT dummy;

		c->Type = CONNECTION_TYPE_ADDITIONAL;

		if (GetSessionKeyFromPack(p, session_key, &dummy) == false)
		{
			FreePack(p);
			c->Err = ERR_PROTOCOL_ERROR;
			goto CLEANUP;
		}

		FreePack(p);

		s = GetSessionFromKey(c->Cedar, session_key);
		if (s == NULL || s->Halt || s->NoReconnectToSession)
		{
			c->Err = ERR_SESSION_TIMEOUT;
			goto CLEANUP;
		}

		c->Err = 0;
		Lock(s->lock);
		{
			if (s->Connection->Protocol != CONNECTION_TCP)
			{
				c->Err = ERR_INVALID_PROTOCOL;
			}
		}
		Unlock(s->lock);
		Lock(s->Connection->lock);
		if (c->Err == 0)
		{
			if (Count(s->Connection->CurrentNumConnection) > s->MaxConnection)
			{
				c->Err = ERR_TOO_MANY_CONNECTION;
			}
		}
		if (c->Err != 0)
		{
			Unlock(s->Connection->lock);
			if (c->Err == ERR_TOO_MANY_CONNECTION)
			{
			}
			else
			{
			}
			ReleaseSession(s);
			goto CLEANUP;
		}

		sock = c->FirstSock;

		ts = NewTcpSock(sock);
		SetTimeout(sock, CONNECTING_TIMEOUT);
		direction = TCP_BOTH;
		LockList(s->Connection->Tcp->TcpSockList);
		{
			if (s->HalfConnection)
			{
				// In half-connection mode, set this socket's direction from the directions of the existing TCP connections.
				UINT i, c2s, s2c;
				c2s = s2c = 0;
				for (i = 0;i < LIST_NUM(s->Connection->Tcp->TcpSockList);i++)
				{
					TCPSOCK *ts = (TCPSOCK *)LIST_DATA(s->Connection->Tcp->TcpSockList, i);
					if (ts->Direction == TCP_SERVER_TO_CLIENT)
					{
						s2c++;
					}
					else
					{
						c2s++;
					}
				}
				if (s2c > c2s)
				{
					direction = TCP_CLIENT_TO_SERVER;
				}
				else
				{
					direction = TCP_SERVER_TO_CLIENT;
				}
				ts->Direction = direction;
			}
		}
		UnlockList(s->Connection->Tcp->TcpSockList);

		p = PackError(ERR_NO_ERROR);
		PackAddInt(p, "direction", direction);

		HttpServerSend(c->FirstSock, p);
		FreePack(p);

		SetTimeout(sock, INFINITE);

		LockList(s->Connection->Tcp->TcpSockList);
		{
			Add(s->Connection->Tcp->TcpSockList, ts);
		}
		UnlockList(s->Connection->Tcp->TcpSockList);

		Inc(s->Connection->CurrentNumConnection);

		Cancel(s->Cancel1);

		Unlock(s->Connection->lock);

		c->flag1 = true;

		ReleaseSession(s);

		return true;
	}
	else if (StrCmpi(method, "enum_hub") == 0)
	{
		UINT i, num;
		LIST *o;
		o = NewListFast(NULL);

		c->Type = CONNECTION_TYPE_ENUM_HUB;

		FreePack(p);
		p = NewPack();
		LockList(c->Cedar->HubList);
		{
			num = LIST_NUM(c->Cedar->HubList);
			for (i = 0;i < num;i++)
			{
				HUB *h = LIST_DATA(c->Cedar->HubList, i);
				if (h->Option != NULL && h->Option->NoEnum == false)
				{
					Insert(o, CopyStr(h->Name));
				}
			}
		}
		UnlockList(c->Cedar->HubList);

		num = LIST_NUM(o);
		for (i = 0;i < num;i++)
		{
			char *name = LIST_DATA(o, i);
			PackAddStrEx(p, "HubName", name, i, num);
			Free(name);
		}
		ReleaseList(o);
		PackAddInt(p, "NumHub", num);

		HttpServerSend(c->FirstSock, p);
		FreePack(p);
		FreePack(HttpServerRecv(c->FirstSock));
		c->Err = 0;

		SLog(c->Cedar, "LS_ENUM_HUB", c->Name, num);

		error_detail = "enum_hub";

		goto CLEANUP;
	}
	else if (StrCmpi(method, "admin") == 0 && c->Cedar->Server != NULL)
	{
		UINT err;
		c->Type = CONNECTION_TYPE_ADMIN_RPC;
		err = AdminAccept(c, p);
		FreePack(p);
		if (err != ERR_NO_ERROR)
		{
			PACK *p = PackError(err);
			HttpServerSend(c->FirstSock, p);
			FreePack(p);
		}

		error_detail = "admin_rpc";

		goto CLEANUP;
	}
	else if (StrCmpi(method, "password") == 0)
	{
		UINT err;
		c->Type = CONNECTION_TYPE_PASSWORD;
		err = ChangePasswordAccept(c, p);
		FreePack(p);

		p = PackError(err);
		HttpServerSend(c->FirstSock, p);
		FreePack(p);

		error_detail = "change_password";

		goto CLEANUP;
	}
	else
	{
		FreePack(p);
		c->Err = ERR_PROTOCOL_ERROR;

		error_detail = "unknown_method";

		goto CLEANUP;
	}

CLEANUP:
	if (loggedin_user_object != NULL)
	{
		ReleaseUser(loggedin_user_object);
	}


	if (supress_return_pack_error == false)
	{
		p = PackError(c->Err);
		PackAddBool(p, "no_save_password", no_save_password);
		HttpServerSend(c->FirstSock, p);
		FreePack(p);
	}

	FreePack(HttpServerRecv(c->FirstSock));

	SleepThread(25);

	SLog(c->Cedar, "LS_CONNECTION_ERROR", c->Name, GetUniErrorStr(c->Err), c->Err);

	return ret;
}

PACK *PackWelcome(SESSION *s)
{
	PACK *p;
	if (s == NULL)
	{
		return NULL;
	}

	p = NewPack();

	PackAddStr(p, "session_name", s->Name);

	PackAddStr(p, "connection_name", s->Connection->Name);

	PackAddInt(p, "max_connection", s->MaxConnection);
	PackAddInt(p, "use_encrypt", s->UseEncrypt == false ? 0 : 1);
	PackAddInt(p, "use_compress", s->UseCompress == false ? 0 : 1);
	PackAddInt(p, "half_connection", s->HalfConnection == false ? 0 : 1);
	PackAddInt(p, "timeout", s->Timeout);
	PackAddInt(p, "qos", s->QoS ? 1 : 0);

	PackAddData(p, "session_key", s->SessionKey, SHA1_SIZE);
	PackAddInt(p, "session_key_32", s->SessionKey32);

	PackAddPolicy(p, s->Policy);

	PackAddInt(p, "vlan_id", s->VLanId);

	if (s->Connection->Protocol == CONNECTION_UDP)
	{
		Rand(s->UdpSendKey, sizeof(s->UdpSendKey));
		Rand(s->UdpRecvKey, sizeof(s->UdpRecvKey));

		PackAddData(p, "udp_send_key", s->UdpRecvKey, sizeof(s->UdpRecvKey));
		PackAddData(p, "udp_recv_key", s->UdpSendKey, sizeof(s->UdpSendKey));
	}

	if (s->NoSendSignature)
	{
		PackAddBool(p, "no_send_signature", true);
	}

	if (s->UdpAccel != NULL)
	{
		PackAddBool(p, "use_udp_acceleration", true);
		PackAddInt(p, "udp_acceleration_version", s->UdpAccel->Version);
		if (s->UdpAccel->UseStun)
		{
			PackAddIp(p, "udp_acceleration_server_ip", &s->UdpAccel->StunIp);
			PackAddInt(p, "udp_acceleration_server_port", s->UdpAccel->StunPort);
		}
		else
		{
			PackAddIp(p, "udp_acceleration_server_ip", &s->UdpAccel->MyIp);
			PackAddInt(p, "udp_acceleration_server_port", s->UdpAccel->MyPort);
		}
		PackAddData(p, "udp_acceleration_server_key", s->UdpAccel->MyKey, sizeof(s->UdpAccel->MyKey));
		PackAddData(p, "udp_acceleration_server_key_v2", s->UdpAccel->MyKey_V2, sizeof(s->UdpAccel->MyKey_V2));
		PackAddInt(p, "udp_acceleration_server_cookie", s->UdpAccel->MyCookie);
		PackAddInt(p, "udp_acceleration_client_cookie", s->UdpAccel->YourCookie);
		PackAddBool(p, "udp_acceleration_use_encryption", !s->UdpAccel->PlainTextMode);
		PackAddBool(p, "use_hmac_on_udp_acceleration", s->UdpAccel->UseHMac);
		PackAddBool(p, "udp_accel_fast_disconnect_detect", s->UdpAccelFastDisconnectDetect);
	}

	return p;
}

#define	PACK_ADD_POLICY_BOOL(name, value)	\
	PackAddBool(p, "policy:" name, y->value == false ? 0 : 1)

#define	PACK_ADD_POLICY_UINT(name, value)	\
	PackAddInt(p, "policy:" name, y->value)

void PackAddPolicy(PACK *p, POLICY *y)
{
	if (p == NULL || y == NULL)
	{
		return;
	}

	// Ver 2
	PACK_ADD_POLICY_BOOL("Access", Access);
	PACK_ADD_POLICY_BOOL("DHCPFilter", DHCPFilter);
	PACK_ADD_POLICY_BOOL("DHCPNoServer", DHCPNoServer);
	PACK_ADD_POLICY_BOOL("DHCPForce", DHCPForce);
	PACK_ADD_POLICY_BOOL("NoBridge", NoBridge);
	PACK_ADD_POLICY_BOOL("NoRouting", NoRouting);
	PACK_ADD_POLICY_BOOL("PrivacyFilter", PrivacyFilter);
	PACK_ADD_POLICY_BOOL("NoServer", NoServer);
	PACK_ADD_POLICY_BOOL("CheckMac", CheckMac);
	PACK_ADD_POLICY_BOOL("CheckIP", CheckIP);
	PACK_ADD_POLICY_BOOL("ArpDhcpOnly", ArpDhcpOnly);
	PACK_ADD_POLICY_BOOL("MonitorPort", MonitorPort);
	PACK_ADD_POLICY_BOOL("NoBroadcastLimiter", NoBroadcastLimiter);
	PACK_ADD_POLICY_BOOL("FixPassword", FixPassword);
	PACK_ADD_POLICY_BOOL("NoQoS", NoQoS);
	// Ver 3
	PACK_ADD_POLICY_BOOL("RSandRAFilter", RSandRAFilter);
	PACK_ADD_POLICY_BOOL("RAFilter", RAFilter);
	PACK_ADD_POLICY_BOOL("DHCPv6Filter", DHCPv6Filter);
	PACK_ADD_POLICY_BOOL("DHCPv6NoServer", DHCPv6NoServer);
	PACK_ADD_POLICY_BOOL("NoRoutingV6", NoRoutingV6);
	PACK_ADD_POLICY_BOOL("CheckIPv6", CheckIPv6);
	PACK_ADD_POLICY_BOOL("NoServerV6", NoServerV6);
	PACK_ADD_POLICY_BOOL("NoSavePassword", NoSavePassword);
	PACK_ADD_POLICY_BOOL("FilterIPv4", FilterIPv4);
	PACK_ADD_POLICY_BOOL("FilterIPv6", FilterIPv6);
	PACK_ADD_POLICY_BOOL("FilterNonIP", FilterNonIP);
	PACK_ADD_POLICY_BOOL("NoIPv6DefaultRouterInRA", NoIPv6DefaultRouterInRA);
	PACK_ADD_POLICY_BOOL("NoIPv6DefaultRouterInRAWhenIPv6", NoIPv6DefaultRouterInRAWhenIPv6);

	// Ver 2
	PACK_ADD_POLICY_UINT("MaxConnection", MaxConnection);
	PACK_ADD_POLICY_UINT("TimeOut", TimeOut);
	PACK_ADD_POLICY_UINT("MaxMac", MaxMac);
	PACK_ADD_POLICY_UINT("MaxIP", MaxIP);
	PACK_ADD_POLICY_UINT("MaxUpload", MaxUpload);
	PACK_ADD_POLICY_UINT("MaxDownload", MaxDownload);
	PACK_ADD_POLICY_UINT("MultiLogins", MultiLogins);
	// Ver 3
	PACK_ADD_POLICY_UINT("MaxIPv6", MaxIPv6);
	PACK_ADD_POLICY_UINT("AutoDisconnect", AutoDisconnect);
	PACK_ADD_POLICY_UINT("VLanId", VLanId);

	// Ver 3 flag
	PackAddBool(p, "policy:Ver3", true);
}

bool ServerUploadHello(CONNECTION *c)
{
	PACK *p;
	if (c == NULL)
	{
		return false;
	}

	Rand(c->Random, SHA1_SIZE);

	p = PackHello(c->Random, c->ServerVer, c->ServerBuild, c->ServerStr);
	if (HttpServerSend(c->FirstSock, p) == false)
	{
		FreePack(p);
		c->Err = ERR_DISCONNECTED;
		return false;
	}

	FreePack(p);

	return true;
}

bool ServerDownloadSignature(CONNECTION *c, char **error_detail_str)
{
	HTTP_HEADER *h;
	UCHAR *data;
	UINT data_size;
	SOCK *s;
	UINT num = 0, max = 19;
	SERVER *server;
	char *vpn_http_target = HTTP_VPN_TARGET2;
	if (c == NULL)
	{
		return false;
	}

	server = c->Cedar->Server;

	s = c->FirstSock;

	while (true)
	{
		bool not_found_error = false;

		num++;
		if (num > max)
		{
			Disconnect(s);
			c->Err = ERR_CLIENT_IS_NOT_VPN;

			*error_detail_str = "HTTP_TOO_MANY_REQUEST";
			return false;
		}
		h = RecvHttpHeader(s);
		if (h == NULL)
		{
			c->Err = ERR_CLIENT_IS_NOT_VPN;
			return false;
		}

		if (StrCmpi(h->Method, "POST") == 0)
		{
			data_size = GetContentLength(h);

			if ((data_size > MAX_WATERMARK_SIZE || data_size < WaterMarkSize) && (data_size != StrLen(HTTP_VPN_TARGET_POSTDATA)))
			{
				HttpSendForbidden(s, h->Target, NULL);
				FreeHttpHeader(h);
				c->Err = ERR_CLIENT_IS_NOT_VPN;
				*error_detail_str = "POST_Recv_TooLong";
				return false;
			}
			data = Malloc(data_size);
			if (RecvAll(s, data, data_size, s->SecureMode) == false)
			{
				Free(data);
				FreeHttpHeader(h);
				c->Err = ERR_DISCONNECTED;
				*error_detail_str = "POST_Recv_Failed";
				return false;
			}
			if ((StrCmpi(h->Target, vpn_http_target) != 0) || not_found_error)
			{
				HttpSendNotFound(s, h->Target);
				Free(data);
				*error_detail_str = "POST_Target_Wrong";
			}
			else
			{
				if ((data_size == StrLen(HTTP_VPN_TARGET_POSTDATA) && (Cmp(data, HTTP_VPN_TARGET_POSTDATA, data_size) == 0))
					|| ((data_size >= WaterMarkSize) && Cmp(data, WaterMark, WaterMarkSize) == 0))
				{
					Free(data);
					FreeHttpHeader(h);
					return true;
				}
				else
				{
					HttpSendForbidden(s, h->Target, NULL);
					*error_detail_str = "POST_WaterMark_Error";
				}
			}
			FreeHttpHeader(h);
		}
		else
		{
			// Not a VPN client, but still answer plain HTTP.
			if (StrCmpi(h->Method, "GET") != 0 && StrCmpi(h->Method, "HEAD") != 0
				 && StrCmpi(h->Method, "POST") != 0)
			{
				HttpSendNotImplemented(s, h->Method, h->Target, h->Version);
				*error_detail_str = "HTTP_BAD_METHOD";
			}
			else
			{
				if (StrCmpi(h->Target, "/") == 0)
				{
					*error_detail_str = "HTTP_ROOT";

					HttpSendForbidden(c->FirstSock, h->Target, "");
				}
				else
				{
					HttpSendNotFound(s, h->Target);

					*error_detail_str = "HTTP_NOT_FOUND";
				}
			}
			FreeHttpHeader(h);
		}
	}
}

PACK *PackHello(void *random, UINT ver, UINT build, char *server_str)
{
	PACK *p;
	if (random == NULL || server_str == NULL)
	{
		return NULL;
	}

	p = NewPack();
	PackAddStr(p, "hello", server_str);
	PackAddInt(p, "version", ver);
	PackAddInt(p, "build", build);
	PackAddData(p, "random", random, SHA1_SIZE);

	return p;
}

UINT GetAuthTypeFromPack(PACK *p)
{
	if (p == NULL)
	{
		return 0;
	}

	return PackGetInt(p, "authtype");
}

bool GetHubnameAndUsernameFromPack(PACK *p, char *username, UINT username_size,
								   char *hubname, UINT hubname_size)
{
	if (p == NULL || username == NULL || hubname == NULL)
	{
		return false;
	}

	if (PackGetStr(p, "username", username, username_size) == false)
	{
		return false;
	}
	if (PackGetStr(p, "hubname", hubname, hubname_size) == false)
	{
		return false;
	}
	return true;
}

UINT GetProtocolFromPack(PACK *p)
{
	if (p == NULL)
	{
		return 0;
	}

	// Only TCP is supported.
	return CONNECTION_TCP;
}

bool GetMethodFromPack(PACK *p, char *method, UINT size)
{
	if (p == NULL || method == NULL || size == 0)
	{
		return false;
	}

	return PackGetStr(p, "method", method, size);
}
