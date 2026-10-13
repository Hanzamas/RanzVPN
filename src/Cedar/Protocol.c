// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module
// © 2020 Nokia

// Protocol.c
// SoftEther protocol related routines

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

// Download and save intermediate certificates if necessary
bool DownloadAndSaveIntermediateCertificatesIfNecessary(X *x) {
	LIST *o;
	bool ret = false;
	// Validate arguments
	if (x == NULL)
		return false;

	if (x->root_cert)
		return true;

	o = NewCertList(true);

	ret = TryGetRootCertChain(o, x, true, NULL);

	FreeCertList(o);

	return ret;
}

// Attempt to fetch the full chain of the specified cert
bool TryGetRootCertChain(LIST *o, X *x, bool auto_save, X **found_root_x) {
	bool ret = false;
	LIST *chain = NULL;
	LIST *current_chain_dir = NULL;
	// Validate arguments
	if (o == NULL || x == NULL)
		return false;

	chain = NewCertList(false);

	ret = TryGetParentCertFromCertList(o, x, chain);

	if (ret) {
		UINT i;
		DIRLIST *dir;
		wchar_t dirname[MAX_SIZE];
		wchar_t exedir[MAX_SIZE];

		GetDbDirW(exedir, sizeof(exedir));
		CombinePathW(dirname, sizeof(dirname), exedir, L"chain_certs");
		MakeDirExW(dirname);

		if (auto_save) {
			// delete the current auto_save files
			dir = EnumDirW(dirname);
			if (dir != NULL) {
				for (i = 0; i < dir->NumFiles; i++) {
					DIRENT *e = dir->File[i];

					if (e->Folder == false) {
						if (UniStartWith(e->FileNameW, AUTO_DOWNLOAD_CERTS_PREFIX)) {
							wchar_t tmp[MAX_SIZE];

							CombinePathW(tmp, sizeof(tmp), dirname, e->FileNameW);

							FileDeleteW(tmp);
						}
					}
				}

				FreeDir(dir);
			}
		}

		current_chain_dir = NewCertList(false);
		AddAllChainCertsToCertList(current_chain_dir);

		for (i = 0; i < LIST_NUM(chain); i++) {
			wchar_t tmp[MAX_SIZE];
			X *xx = LIST_DATA(chain, i);

			GetAllNameFromName(tmp, sizeof(tmp), xx->subject_name);

			Debug("depth = %u, subject = %S\n", i, tmp);

			if (auto_save && CompareX(x, xx) == false && IsXInCertList(current_chain_dir, xx) == false) {
				wchar_t fn[MAX_PATH];
				char hex_a[128];
				wchar_t hex[128];
				UCHAR hash[SHA1_SIZE];
				wchar_t tmp[MAX_SIZE];
				BUF *b;

				GetXDigest(xx, hash, true);
				BinToStr(hex_a, sizeof(hex_a), hash, SHA1_SIZE);
				StrToUni(hex, sizeof(hex), hex_a);

				UniStrCpy(fn, sizeof(fn), AUTO_DOWNLOAD_CERTS_PREFIX);
				UniStrCat(fn, sizeof(fn), hex);
				UniStrCat(fn, sizeof(fn), L".cer");

				CombinePathW(tmp, sizeof(tmp), dirname, fn);

				b = XToBuf(xx, true);

				DumpBufW(b, tmp);

				FreeBuf(b);
			}

			if (xx->root_cert) {
				if (found_root_x != NULL)
					*found_root_x = CloneX(xx);
			}
		}
	}

	FreeCertList(chain);

	FreeCertList(current_chain_dir);

	return ret;
}

// Try get the parent cert
bool TryGetParentCertFromCertList(LIST *o, X *x, LIST *found_chain) {
	bool ret = false;
	X *r;
	bool do_free = false;
	// Validate arguments
	if (o == NULL || x == NULL || found_chain == NULL)
		return false;

	if (LIST_NUM(found_chain) >= FIND_CERT_CHAIN_MAX_DEPTH)
		return false;

	Add(found_chain, CloneX(x));

	if (x->root_cert)
		return true;

	r = FindCertIssuerFromCertList(o, x);

	if (r == NULL) {
		if (IsEmptyStr(x->issuer_url) == false) {
			r = DownloadCert(x->issuer_url);

			if (CheckXEx(x, r, true, true) && CompareX(x, r) == false) {
				// found
				do_free = true;
			} else {
				// invalid
				FreeX(r);
				r = NULL;
			}
		}
	}

	if (r != NULL)
		ret = TryGetParentCertFromCertList(o, r, found_chain);

	if (do_free)
		FreeX(r);

	return ret;
}

// Find the issuer of the cert from the cert list
X *FindCertIssuerFromCertList(LIST *o, X *x) {
	UINT i;
	// Validate arguments
	if (o == NULL || x == NULL)
		return NULL;

	if (x->root_cert)
		return NULL;

	for (i = 0; i < LIST_NUM(o); i++) {
		X *xx = LIST_DATA(o, i);

		if (CheckXEx(x, xx, true, true)) {
			if (CompareX(x, xx) == false)
				return xx;
		}
	}

	return NULL;
}

// Download a cert by using HTTP
X *DownloadCert(char *url) {
	BUF *b;
	URL_DATA url_data;
	X *ret = NULL;
	// Validate arguments
	if (IsEmptyStr(url))
		return NULL;

	Debug("Trying to download a cert from %s ...\n", url);

	if (ParseUrl(&url_data, url, false, NULL) == false) {
		Debug("Download failed.\n");
		return NULL;
	}

	b = HttpRequestEx(&url_data, NULL, CERT_HTTP_DOWNLOAD_TIMEOUT, CERT_HTTP_DOWNLOAD_TIMEOUT,
	                  NULL, false, NULL, NULL, NULL, NULL, NULL, CERT_HTTP_DOWNLOAD_MAXSIZE);

	if (b == NULL) {
		Debug("Download failed.\n");
		return NULL;
	}

	ret = BufToX(b, IsBase64(b));

	FreeBuf(b);

	Debug("Download ok.\n");
	return ret;
}

// New cert list
LIST *NewCertList(bool load_root_and_chain) {
	LIST *o;

	o = NewList(NULL);

	if (load_root_and_chain) {
		AddAllRootCertsToCertList(o);
		AddAllChainCertsToCertList(o);
	}

	return o;
}

// Free cert list
void FreeCertList(LIST *o) {
	UINT i;
	// Validate arguments
	if (o == NULL)
		return;

	for (i = 0; i < LIST_NUM(o); i++) {
		X *x = LIST_DATA(o, i);

		FreeX(x);
	}

	ReleaseList(o);
}

// Check whether the cert is in the cert list
bool IsXInCertList(LIST *o, X *x) {
	UINT i;
	// Validate arguments
	if (o == NULL || x == NULL)
		return false;

	for (i = 0; i < LIST_NUM(o); i++) {
		X *xx = LIST_DATA(o, i);

		if (CompareX(x, xx))
			return true;
	}

	return false;
}

// Add a cert to the cert list
void AddXToCertList(LIST *o, X *x) {
	// Validate arguments
	if (o == NULL || x == NULL)
		return;

	if (IsXInCertList(o, x))
		return;

	if (CheckXDateNow(x) == false)
		return;

	Add(o, CloneX(x));
}

// Add all chain certs to the cert list
void AddAllChainCertsToCertList(LIST *o) {
	wchar_t dirname[MAX_SIZE];
	wchar_t exedir[MAX_SIZE];
	DIRLIST *dir;
	// Validate arguments
	if (o == NULL)
		return;

	GetDbDirW(exedir, sizeof(exedir));

	CombinePathW(dirname, sizeof(dirname), exedir, L"chain_certs");

	MakeDirExW(dirname);

	dir = EnumDirW(dirname);

	if (dir != NULL) {
		UINT i;

		for (i = 0; i < dir->NumFiles; i++) {
			DIRENT *e = dir->File[i];

			if (e->Folder == false) {
				wchar_t tmp[MAX_SIZE];
				X *x;

				CombinePathW(tmp, sizeof(tmp), dirname, e->FileNameW);

				x = FileToXW(tmp);

				if (x != NULL) {
					AddXToCertList(o, x);

					FreeX(x);
				}
			}
		}

		FreeDir(dir);
	}
}

// Add all root certs to the cert list
void AddAllRootCertsToCertList(LIST *o) {
	BUF *buf;
	PACK *p;
	UINT num_ok = 0, num_error = 0;
	// Validate arguments
	if (o == NULL)
		return;

	buf = ReadDump(ROOT_CERTS_FILENAME);
	if (buf == NULL)
		return;

	p = BufToPack(buf);

	if (p != NULL) {
		UINT num = PackGetIndexCount(p, "cert");
		UINT i;

		for (i = 0; i < num; i++) {
			bool ok = false;
			BUF *b = PackGetBufEx(p, "cert", i);

			if (b != NULL) {
				X *x = BufToX(b, false);

				if (x != NULL) {
					AddXToCertList(o, x);

					ok = true;

					FreeX(x);
				}

				FreeBuf(b);
			}

			if (ok)
				num_ok++;
			else
				num_error++;
		}

		FreePack(p);
	}

	FreeBuf(buf);

	Debug("AddAllRootCertsToCertList: ok=%u error=%u total_list_len=%u\n", num_ok, num_error, LIST_NUM(o));
}

// Generate unique IDs for each machine
void GenerateMachineUniqueHash(void *data) {
	BUF *b;
	char name[64];
	OS_INFO *osinfo;
	UINT64 iphash = 0;
	// Validate arguments
	if (data == NULL)
		return;

	iphash = GetHostIPAddressListHash();

	b = NewBuf();
	GetMachineName(name, sizeof(name));

	osinfo = GetOsInfo();

	WriteBuf(b, name, StrLen(name));

	WriteBufInt64(b, iphash);

	WriteBuf(b, &osinfo->OsType, sizeof(osinfo->OsType));
	WriteBuf(b, osinfo->KernelName, StrLen(osinfo->KernelName));
	WriteBuf(b, osinfo->KernelVersion, StrLen(osinfo->KernelVersion));
	WriteBuf(b, osinfo->OsProductName, StrLen(osinfo->OsProductName));
	WriteBuf(b, &osinfo->OsServicePack, sizeof(osinfo->OsServicePack));
	WriteBuf(b, osinfo->OsSystemName, StrLen(osinfo->OsSystemName));
	WriteBuf(b, osinfo->OsVendorName, StrLen(osinfo->OsVendorName));
	WriteBuf(b, osinfo->OsVersion, StrLen(osinfo->OsVersion));

	Sha0(data, b->Buf, b->Size);

	FreeBuf(b);
}

// Convert a node information to a string
void NodeInfoToStr(wchar_t *str, UINT size, NODE_INFO *info) {
	char client_ip[128], server_ip[128], proxy_ip[128], unique_id[128];
	// Validate arguments
	if (str == NULL || info == NULL)
		return;

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

// Accept the password change
UINT ChangePasswordAccept(CONNECTION *c, PACK *p) {
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
	// Validate arguments
	if (c == NULL || p == NULL)
		return ERR_INTERNAL_ERROR;

	Copy(random, c->Random, SHA1_SIZE);
	if (PackGetStr(p, "hubname", hubname, sizeof(hubname)) == false ||
	    PackGetStr(p, "username", username, sizeof(username)) == false ||
	    PackGetData2(p, "secure_old_password", secure_old_password, sizeof(secure_old_password)) == false ||
	    PackGetData2(p, "new_password", new_password, sizeof(new_password)) == false)
		return ERR_PROTOCOL_ERROR;

	if (PackGetData2(p, "new_password_ntlm", new_password_ntlm, MD5_SIZE) == false)
		Zero(new_password_ntlm, sizeof(new_password_ntlm));

	cedar = c->Cedar;

	LockHubList(cedar);
	{
		hub = GetHub(cedar, hubname);
	}
	UnlockHubList(cedar);

	if (hub == NULL) {
		ret = ERR_HUB_NOT_FOUND;
	} else {
		char tmp[MAX_SIZE];

		if (GetHubAdminOption(hub, "deny_change_user_password") != 0) {
			ReleaseHub(hub);
			return ERR_NOT_ENOUGH_RIGHT;
		}

		IPToStr(tmp, sizeof(tmp), &c->FirstSock->RemoteIP);
		HLog(hub, "LH_CHANGE_PASSWORD_1", c->Name, tmp);

		AcLock(hub);
		{
			USER *u = AcGetUser(hub, username);
			if (u == NULL) {
				HLog(hub, "LH_CHANGE_PASSWORD_2", c->Name, username);
				ret = ERR_OLD_PASSWORD_WRONG;
			} else {
				Lock(u->lock);
				{
					if (u->AuthType != AUTHTYPE_PASSWORD) {
						// Not a password authentication
						HLog(hub, "LH_CHANGE_PASSWORD_3", c->Name, username);
						ret = ERR_USER_AUTHTYPE_NOT_PASSWORD;
					} else {
						bool fix_password = false;
						if (u->Policy != NULL) {
							fix_password = u->Policy->FixPassword;
						} else if (u->Group != NULL) {
							if (u->Group->Policy != NULL)
								fix_password = u->Group->Policy->FixPassword;
						}
						if (fix_password == false) {
							// Confirmation of the old password
							AUTHPASSWORD *pw = (AUTHPASSWORD *)u->AuthData;

							SecurePassword(check_secure_old_password, pw->HashedKey, random);
							if (Cmp(check_secure_old_password, secure_old_password, SHA1_SIZE) != 0) {
								// Old password is incorrect
								ret = ERR_OLD_PASSWORD_WRONG;
								HLog(hub, "LH_CHANGE_PASSWORD_4", c->Name, username);
							} else {
								// Write a new password
								if (Cmp(pw->HashedKey, new_password, SHA1_SIZE) != 0 || IsZero(pw->NtLmSecureHash, MD5_SIZE)) {
									Copy(pw->HashedKey, new_password, SHA1_SIZE);
									Copy(pw->NtLmSecureHash, new_password_ntlm, MD5_SIZE);
									IncrementServerConfigRevision(cedar->Server);
								}
								HLog(hub, "LH_CHANGE_PASSWORD_5", c->Name, username);
							}
						} else {
							// Password change is prohibited
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

// Enumerate HUBs
TOKEN_LIST *EnumHub(SESSION *s) {
	SOCK *sock;
	TOKEN_LIST *ret;
	PACK *p;
	UINT num;
	UINT i;
	// Validate arguments
	if (s == NULL || s->Connection == NULL)
		return NULL;

	sock = s->Connection->FirstSock;
	if (sock == NULL)
		return NULL;

	// Set the Timeout
	SetTimeout(sock, 10000);

	p = NewPack();
	PackAddStr(p, "method", "enum_hub");

	PackAddClientVersion(p, s->Connection);

	if (HttpClientSend(sock, p) == false) {
		FreePack(p);
		return NULL;
	}
	FreePack(p);

	p = HttpClientRecv(sock);
	if (p == NULL)
		return NULL;

	num = PackGetInt(p, "NumHub");
	ret = ZeroMalloc(sizeof(TOKEN_LIST));
	ret->NumTokens = num;
	ret->Token = ZeroMalloc(sizeof(char *) * num);
	for (i = 0; i < num; i++) {
		char tmp[MAX_SIZE];
		if (PackGetStrEx(p, "HubName", tmp, sizeof(tmp), i))
			ret->Token[i] = CopyStr(tmp);
	}
	FreePack(p);

	return ret;
}

// Server accepts a connection from client
bool ServerAccept(CONNECTION *c) {
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

	// Validate arguments
	if (c == NULL)
		return false;

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
		BinToStr(ctoken_hash_str, sizeof(ctoken_hash_str), c->CToken_Hash, SHA1_SIZE);

	cedar = c->Cedar;

	// Get the license status

	no_more_users_in_server = SiTooManyUserObjectsInServer(cedar->Server, true);

	c->Status = CONNECTION_STATUS_NEGOTIATION;

	if (c->Cedar->Server != NULL)
		server = c->Cedar->Server;

	// Receive the signature
	Debug("Downloading Signature...\n");
	error_detail_2 = NULL;
	if (ServerDownloadSignature(c, &error_detail_2) == false) {
		if (c->Type == CONNECTION_TYPE_ADMIN_RPC)
			c->Err = ERR_NO_ERROR;

		if (error_detail_2 == NULL)
			error_detail = "ServerDownloadSignature";
		else
			error_detail = error_detail_2;

		supress_return_pack_error = true;

		goto CLEANUP;
	}

	// Send a Hello packet
	Debug("Uploading Hello...\n");
	if (ServerUploadHello(c) == false) {
		error_detail = "ServerUploadHello";
		goto CLEANUP;
	}

	// Receive the authentication data
	Debug("Auth...\n");

	p = HttpServerRecv(c->FirstSock);
	if (p == NULL) {
		// The connection disconnected
		c->Err = ERR_DISCONNECTED;
		error_detail = "RecvAuth1";
		goto CLEANUP;
	}

	if (err = GetErrorFromPack(p)) {
		// An error has occured
		FreePack(p);
		c->Err = err;
		error_detail = "RecvAuth2";
		goto CLEANUP;
	}

	// Get the method
	if (GetMethodFromPack(p, method, sizeof(method)) == false) {
		// Protocol error
		FreePack(p);
		c->Err = ERR_PROTOCOL_ERROR;
		error_detail = "GetMethodFromPack";
		goto CLEANUP;
	}

	// Brand string for the connection limit
	{
		char tmp[20];
		char *branded_ctos = _SS("BRANDED_C_TO_S");
		PackGetStr(p, "branded_ctos", tmp, sizeof(tmp));

		if (StrCmpi(method, "login") == 0 && StrLen(branded_ctos) > 0 && StrCmpi(branded_ctos, tmp) != 0) {
			FreePack(p);
			c->Err = ERR_BRANDED_C_TO_S;
			goto CLEANUP;
		}
	}

	// Get the client version
	PackGetStr(p, "client_str", c->ClientStr, sizeof(c->ClientStr));
	c->ClientVer = PackGetInt(p, "client_ver");
	c->ClientBuild = PackGetInt(p, "client_build");

	if (SearchStrEx(c->ClientStr, "server", 0, false) != INFINITE ||
	    SearchStrEx(c->ClientStr, "bridge", 0, false) != INFINITE)
		is_server_or_bridge = true;

	// Get the client Windows version
	InRpcWinVer(&winver, p);

	DecrementNoSsl(c->Cedar, &c->FirstSock->RemoteIP, 2);

	if (StrCmpi(method, "login") == 0) {
		bool auth_ret = false;

		Debug("Login...\n");
		c->Status = CONNECTION_STATUS_USERAUTH;

		c->Type = CONNECTION_TYPE_LOGIN;

		if (no_more_users_in_server) {
			// There are many users than are allowed in the VPN Server
			FreePack(p);
			c->Err = ERR_TOO_MANY_USER;
			error_detail = "ERR_TOO_MANY_USER";
			goto CLEANUP;
		}

		// Such as the client name
		if (PackGetStr(p, "hello", c->ClientStr, sizeof(c->ClientStr)) == false)
			StrCpy(c->ClientStr, sizeof(c->ClientStr), "Unknown");
		c->ServerVer = GetCedarVersionNumber();
		c->ServerBuild = CEDAR_WIRE_BUILD;

		// Get the NODE_INFO
		Zero(&node, sizeof(node));
		InRpcNodeInfo(&node, p);

		// Protocol
		c->Protocol = GetProtocolFromPack(p);
		if (c->Protocol == CONNECTION_UDP) {
			// Release the structure of the TCP connection
			if (c->Tcp) {
				ReleaseList(c->Tcp->TcpSockList);
				Free(c->Tcp);
			}
		}

		if (GetServerCapsBool(c->Cedar->Server, "b_vpn_client_connect") == false) {
			// VPN client is unable to connect
			FreePack(p);
			c->Err = ERR_NOT_SUPPORTED;
			goto CLEANUP;
		}

		// Get authentication method and initiate login process
		authtype = GetAuthTypeFromPack(p);
		if (GetHubnameAndUsernameFromPack(p, username, sizeof(username), hubname, sizeof(hubname)) == false) {
			FreePack(p);
			c->Err = ERR_PROTOCOL_ERROR;
			error_detail = "GetHubnameAndUsernameFromPack";
			goto CLEANUP;
		}

		Debug("Username = %s, HubName = %s\n", username, hubname);
		LockHubList(c->Cedar);
		{
			hub = GetHub(c->Cedar, hubname);
		}
		UnlockHubList(c->Cedar);
		if (hub == NULL) {
			// The HUB does not exist
			FreePack(p);
			c->Err = ERR_HUB_NOT_FOUND;
			SLog(c->Cedar, "LS_HUB_NOT_FOUND", c->Name, hubname);
			error_detail = "ERR_HUB_NOT_FOUND";
			goto CLEANUP;
		}

		if (hub->ForceDisableComm) {
			// Communication function is disabled
			FreePack(p);
			c->Err = ERR_SERVER_CANT_ACCEPT;
			error_detail = "ERR_COMM_DISABLED";
			ReleaseHub(hub);
			goto CLEANUP;
		}

		if (GetGlobalServerFlag(GSF_DISABLE_AC) == 0) {
			if (hub->HubDb != NULL && c->FirstSock != NULL) {
				IP ip;

				Copy(&ip, &c->FirstSock->RemoteIP, sizeof(IP));

				if (IsIpDeniedByAcList(&ip, hub->HubDb->AcList)) {
					char ip_str[64];
					// Access denied
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

			if (hub->Halt || hub->Offline) {
				// HUB is off-line
				FreePack(p);
				Unlock(hub->lock);
				ReleaseHub(hub);
				c->Err = ERR_HUB_STOPPING;
				goto CLEANUP;
			}

			// Get the various flags
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
				client_udp_acceleration_max_version = 1;
			support_hmac_on_udp_acceleration_client = PackGetBool(p, "support_hmac_on_udp_acceleration");
			support_udp_accel_fast_disconnect_detect = PackGetBool(p, "support_udp_accel_fast_disconnect_detect");

			if (c->CipherName != NULL)
				Free(c->CipherName);
			c->CipherName = NULL;

			if (c->SslVersion != NULL)
				Free(c->SslVersion);
			c->SslVersion = NULL;

			if (c->FirstSock != NULL && IsEmptyStr(c->FirstSock->CipherName) == false)
				c->CipherName = CopyStr(c->FirstSock->CipherName);

			if (c->FirstSock != NULL && IsEmptyStr(c->FirstSock->SslVersion) == false)
				c->SslVersion = CopyStr(c->FirstSock->SslVersion);

			if (use_udp_acceleration_client) {
				PackGetData2(p, "udp_acceleration_client_key", udp_acceleration_client_key, UDP_ACCELERATION_COMMON_KEY_SIZE_V1);
				PackGetData2(p, "udp_acceleration_client_key_v2", udp_acceleration_client_key_v2, UDP_ACCELERATION_COMMON_KEY_SIZE_V2);

				// Get the parameters for the UDP acceleration function
				if (PackGetIp(p, "udp_acceleration_client_ip", &udp_acceleration_client_ip) == false) {
					use_udp_acceleration_client = false;
				} else {
					if (IsZeroIp(&udp_acceleration_client_ip))
						Copy(&udp_acceleration_client_ip, &c->FirstSock->RemoteIP, sizeof(IP));
					udp_acceleration_client_port = PackGetInt(p, "udp_acceleration_client_port");
					if (udp_acceleration_client_port == 0)
						use_udp_acceleration_client = false;
				}

				use_hmac_on_udp_acceleration = support_hmac_on_udp_acceleration_client;
			}

			Debug("use_udp_acceleration_client = %u\n", use_udp_acceleration_client);
			Debug("use_hmac_on_udp_acceleration = %u\n", use_hmac_on_udp_acceleration);

			// Request mode
			require_bridge_routing_mode = PackGetBool(p, "require_bridge_routing_mode");
			require_monitor_mode = PackGetBool(p, "require_monitor_mode");
			if (require_monitor_mode)
				qos = false;

			if (is_server_or_bridge)
				require_bridge_routing_mode = true;

			// Client unique ID
			Zero(unique, sizeof(unique));
			if (PackGetDataSize(p, "unique_id") == SHA1_SIZE)
				PackGetData(p, "unique_id", unique);

			if (1) {
				// Log
				char ip1[64], ip2[64], verstr[64];
				wchar_t *authtype_str = _UU("LH_AUTH_UNKNOWN");
				switch (authtype) {
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

			// Attempt an anonymous authentication first
			auth_ret = SamAuthUserByAnonymous(hub, username);
			if (auth_ret)
				is_empty_password = true;

			if (auth_ret == false) {
				// Attempt other authentication methods if anonymous authentication fails
				switch (authtype) {
				case CLIENT_AUTHTYPE_ANONYMOUS:
					// Anonymous authentication (this have been already attempted)
					break;

				case AUTHTYPE_EXTERNAL:
					// External authentication already completed
					auth_ret = true;
					break;

				case CLIENT_AUTHTYPE_PASSWORD:
					// Password authentication
					if (PackGetDataSize(p, "secure_password") == SHA1_SIZE) {
						POLICY *pol = NULL;
						UCHAR secure_password[SHA1_SIZE];
						Zero(secure_password, sizeof(secure_password));
						if (PackGetDataSize(p, "secure_password") == SHA1_SIZE)
							PackGetData(p, "secure_password", secure_password);
						auth_ret = SamAuthUserByPassword(hub, username, c->Random, secure_password, NULL, NULL, NULL);

						pol = SamGetUserPolicy(hub, username);
						if (pol != NULL) {
							no_save_password = pol->NoSavePassword;
							Free(pol);
						}

						if (auth_ret) {
							// Check whether the password was empty
							UCHAR hashed_empty_password[SHA1_SIZE];
							UCHAR secure_empty_password[SHA1_SIZE];
							HashPassword(hashed_empty_password, username, "");
							SecurePassword(secure_empty_password, hashed_empty_password, c->Random);
							if (Cmp(secure_password, secure_empty_password, SHA1_SIZE) == 0)
								is_empty_password = true;
						}
					}
					break;

				case CLIENT_AUTHTYPE_PLAIN_PASSWORD: {
					POLICY *pol = NULL;

					// Plaintext password authentication
					Zero(plain_password, sizeof(plain_password));
					PackGetStr(p, "plain_password", plain_password, sizeof(plain_password));
					if (StartWith(plain_password, IPC_PASSWORD_MSCHAPV2_TAG)) {
						// Do not allow the MS-CHAPv2 authentication (it was only available to IPC sessions)
						Zero(plain_password, sizeof(plain_password));
					}

					if (auth_ret == false) {
						// Attempt a password authentication of normal user
						UCHAR secure_password[SHA1_SIZE];
						UCHAR hash_password[SHA1_SIZE];
						bool is_mschap = StartWith(plain_password, IPC_PASSWORD_MSCHAPV2_TAG);

						HashPassword(hash_password, username, plain_password);
						SecurePassword(secure_password, hash_password, c->Random);

						if (is_mschap == false)
							auth_ret = SamAuthUserByPassword(hub, username, c->Random, secure_password, NULL, NULL, NULL);
						else
							auth_ret = SamAuthUserByPassword(hub, username, c->Random, secure_password,
							                                 plain_password, mschap_v2_server_response_20, &ms_chap_error);

						if (auth_ret && pol == NULL)
							pol = SamGetUserPolicy(hub, username);
					}

					if (auth_ret == false) {
						// Attempt external authentication
						bool fail_ext_user_auth = false;
						if (GetGlobalServerFlag(GSF_DISABLE_RADIUS_AUTH) != 0)
							fail_ext_user_auth = true;

						if (fail_ext_user_auth == false)
							auth_ret = SamAuthUserByPlainPassword(c, hub, username, plain_password, true);

						if (auth_ret && pol == NULL)
							pol = SamGetUserPolicy(hub, username);
					}

					if (pol != NULL) {
						no_save_password = pol->NoSavePassword;
						Free(pol);
					}

					if (auth_ret) {
						// Check whether the password was empty
						if (IsEmptyStr(plain_password))
							is_empty_password = true;
					}
				} break;

				case CLIENT_AUTHTYPE_CERT:
					if (GetGlobalServerFlag(GSF_DISABLE_CERT_AUTH) == 0) {
						// Certificate authentication
						cert_size = PackGetDataSize(p, "cert");
						if (cert_size >= 1 && cert_size <= 100000) {
							cert_buf = ZeroMalloc(cert_size);
							if (PackGetData(p, "cert", cert_buf)) {
								UCHAR sign[4096 / 8];
								UINT sign_size = PackGetDataSize(p, "sign");
								if (sign_size <= sizeof(sign) && sign_size >= 1) {
									if (PackGetData(p, "sign", sign)) {
										BUF *b = NewBuf();
										X *x;
										WriteBuf(b, cert_buf, cert_size);
										x = BufToX(b, false);
										if (x != NULL && x->is_compatible_bit &&
										    sign_size == (x->bits / 8)) {
											K *k = GetKFromX(x);
											// Verify the signature received from the client
											if (RsaVerifyEx(c->Random, SHA1_SIZE, sign, k, x->bits)) {
												// Confirmed that the client has had this certificate
												// certainly because the signature matched.
												// Check whether the certificate is valid.
												auth_ret = SamAuthUserByCert(hub, username, x);
												if (auth_ret) {
													// Copy the certificate
													c->ClientX = CloneX(x);
												}
											} else {
												// Authentication failure
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
					} else {
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
					// Unknown authentication method
					Unlock(hub->lock);
					ReleaseHub(hub);
					FreePack(p);
					c->Err = ERR_AUTHTYPE_NOT_SUPPORTED;
					error_detail = "ERR_AUTHTYPE_NOT_SUPPORTED";
					goto CLEANUP;
				}
			}

			if (auth_ret == false) {
				char ip[64];
				IPToStr(ip, sizeof(ip), &c->FirstSock->RemoteIP);
				HLog(hub, "LH_AUTH_NG", c->Name, username, ip);

				Unlock(hub->lock);
				ReleaseHub(hub);
				FreePack(p);
				c->Err = ERR_AUTH_FAILED;
				if (ms_chap_error != 0)
					c->Err = ms_chap_error;
				error_detail = "ERR_AUTH_FAILED";
				goto CLEANUP;
			} else {
				if (is_empty_password) {
					const SOCK *s = c->FirstSock;
					if (s != NULL && IsLocalHostIP(&s->RemoteIP) == false) {
						if (StrCmpi(username, ADMINISTRATOR_USERNAME) == 0 || GetHubAdminOption(hub, "deny_empty_password") != 0) {
							// When the password is empty, remote connection is not acceptable
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

			// Authentication success
			FreePack(p);

			if (StrCmpi(username, ADMINISTRATOR_USERNAME) != 0) {
				// Get the policy
				user = AcGetUser(hub, username);
				if (user == NULL) {
					user = AcGetUser(hub, "*");
					if (user == NULL) {
						// User acquisition failure
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
					// Get the expiration date
					user_expires = user->ExpireTime;

					StrCpy(username_real, sizeof(username_real), user->Name);
					group = user->Group;
					if (group != NULL) {
						AddRef(group->ref);

						Lock(group->lock);
						{
							// Get the group name
							StrCpy(groupname, sizeof(groupname), group->Name);
						}
						Unlock(group->lock);
					}

					if (user->Policy != NULL) {
						policy = ClonePolicy(user->Policy);
					} else if (group) {
						Lock(group->lock);
						{
							if (group->Policy != NULL)
								policy = ClonePolicy(group->Policy);
						}
						Unlock(group->lock);
					}

					if (group != NULL)
						ReleaseGroup(group);
				}
				Unlock(user->lock);
				loggedin_user_object = user;
			} else {
				// Administrator mode
				admin_mode = true;
				StrCpy(username_real, sizeof(username_real), ADMINISTRATOR_USERNAME);

				policy = ClonePolicy(GetDefaultPolicy());
				policy->NoBroadcastLimiter = true;
				policy->MonitorPort = true;
			}

			if (policy == NULL) {
				// Use the default policy
				policy = ClonePolicy(GetDefaultPolicy());
			}

			if (policy->MaxConnection == 0)
				policy->MaxConnection = MAX_TCP_CONNECTION;

			if (policy->TimeOut == 0)
				policy->TimeOut = 20;

			if (qos) {
				// VoIP / QoS
				if (policy->NoQoS) {
					// Policy does not allow QoS
					qos = false;
				}
				if (GetServerCapsBool(c->Cedar->Server, "b_support_qos") == false) {
					// Server does not support QoS
					qos = false;
					policy->NoQoS = true;
				}
				if (GetHubAdminOption(hub, "deny_qos") != 0) {
					// It is prohibited in the management options
					qos = false;
					policy->NoQoS = true;
				}
			}

			if (GetHubAdminOption(hub, "max_bitrates_download") != 0) {
				if (policy->MaxDownload == 0) {
					policy->MaxDownload = GetHubAdminOption(hub, "max_bitrates_download");
				} else {
					UINT r = GetHubAdminOption(hub, "max_bitrates_download");
					policy->MaxDownload = MIN(policy->MaxDownload, r);
				}
			}

			if (GetHubAdminOption(hub, "max_bitrates_upload") != 0) {
				if (policy->MaxUpload == 0) {
					policy->MaxUpload = GetHubAdminOption(hub, "max_bitrates_upload");
				} else {
					UINT r = GetHubAdminOption(hub, "max_bitrates_upload");
					policy->MaxUpload = MIN(policy->MaxUpload, r);
				}
			}

			if (GetHubAdminOption(hub, "deny_bridge") != 0)
				policy->NoBridge = true;

			if (GetHubAdminOption(hub, "deny_routing") != 0)
				policy->NoRouting = true;

			if (hub->Option->ClientMinimumRequiredBuild > c->ClientBuild &&
			    InStrEx(c->ClientStr, "client", false)) {
				// Build number of the client is too small
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
			    InStrEx(c->ClientStr, "client", false)) {
				// Build number of the client is too small
				HLog(hub, "LH_CLIENT_ID_REQUIRED", c->Name, client_id, hub->Option->RequiredClientId);

				Unlock(hub->lock);
				ReleaseHub(hub);
				c->Err = ERR_CLIENT_ID_REQUIRED;
				error_detail = "ERR_CLIENT_ID_REQUIRED";
				Free(policy);
				goto CLEANUP;
			}

			if (user_expires != 0 && user_expires <= SystemTime64()) {
				// User expired
				HLog(hub, "LH_USER_EXPIRES", c->Name, username);

				Unlock(hub->lock);
				ReleaseHub(hub);
				c->Err = ERR_ACCESS_DENIED;
				error_detail = "LH_USER_EXPIRES";
				Free(policy);
				goto CLEANUP;
			}

			if (policy->Access == false) {
				// Access is denied
				HLog(hub, "LH_POLICY_ACCESS_NG", c->Name, username);

				Unlock(hub->lock);
				ReleaseHub(hub);
				error_detail = "LH_POLICY_ACCESS_NG";
				c->Err = ERR_ACCESS_DENIED;
				Free(policy);
				goto CLEANUP;
			}

			// Determine the contents of the policy by comparing to
			// option presented by client or deny the connection.
			// Confirm the connectivity in the monitor-mode first
			if (require_monitor_mode && policy->MonitorPort == false) {
				// Can not connect in the monitor port mode
				HLog(hub, "LH_POLICY_MONITOR_MODE", c->Name);

				Unlock(hub->lock);
				ReleaseHub(hub);
				c->Err = ERR_MONITOR_MODE_DENIED;
				Free(policy);
				error_detail = "ERR_MONITOR_MODE_DENIED";
				goto CLEANUP;
			}

			if (policy->MonitorPort) {
				if (require_monitor_mode == false)
					policy->MonitorPort = false;
			}

			if (policy->MonitorPort)
				qos = false;

			// Determine whether it can be connected by a bridge / routing mode next
			if (require_bridge_routing_mode &&
			    (policy->NoBridge && policy->NoRouting)) {
				// Can not be connected by a bridge / routing mode
				HLog(hub, "LH_POLICY_BRIDGE_MODE", c->Name);

				Unlock(hub->lock);
				ReleaseHub(hub);
				c->Err = ERR_BRIDGE_MODE_DENIED;
				error_detail = "ERR_BRIDGE_MODE_DENIED";
				Free(policy);
				goto CLEANUP;
			}

			if (require_bridge_routing_mode == false) {
				policy->NoBridge = true;
				policy->NoRouting = true;
			}

			if (Cmp(unique, unique2, SHA1_SIZE) == 0) {
				// It's a localhost session
				local_host_session = true;
			}

			if (local_host_session == false) {
				// Make further judgment whether localhost session
				SOCK *s = c->FirstSock;

				if (s != NULL) {
					if (IsIPMyHost(&s->RemoteIP)) {
						// It's a localhost session
						local_host_session = true;
					}
				}
			}

			if (local_host_session) {
				// Permit routing or bridging in the case of localhost session
				policy->NoBridge = false;
				policy->NoRouting = false;
			}

			if (local_host_session == false) {

				if (policy->NoBridge == false || policy->NoRouting == false)
					use_bridge_license = true;
				else
					use_client_license = true;
			}


			if (server != NULL && policy != NULL) {
				if (GetServerCapsBool(hub->Cedar->Server, "b_support_limit_multilogin")) {
					// Check if the number of concurrent multiple logins limit is specified in the policy
					RPC_ENUM_SESSION t;
					UINT i, num;
					UINT max_logins = policy->MultiLogins;
					UINT ao = GetHubAdminOption(hub, "max_multilogins_per_user");

					if (ao != 0) {
						if (max_logins != 0)
							max_logins = MIN(max_logins, ao);
						else
							max_logins = ao;
					}

					if (max_logins != 0) {
						Zero(&t, sizeof(t));
						StrCpy(t.HubName, sizeof(t.HubName), hub->Name);

						Unlock(hub->lock);

						SiEnumSessionMain(server, &t);

						Lock(hub->lock);

						num = 0;

						for (i = 0; i < t.NumSession; i++) {
							RPC_ENUM_SESSION_ITEM *e = &t.Sessions[i];

							if (e->BridgeMode == false && e->LinkMode == false && e->CurrentNumTcp != 0) {
								if (StrCmpi(e->Username, username) == 0 &&
								    (IsZero(e->UniqueId, 16) || Cmp(e->UniqueId, node.UniqueId, 16) != 0))
									num++;
							}
						}

						FreeRpcEnumSession(&t);

						if (num >= max_logins) {
							// Can not connect any more
							Unlock(hub->lock);

							// Dump a detailed error log
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

			if (loggedin_user_object != NULL) {
				// Update the user information
				Lock(loggedin_user_object->lock);
				{
					loggedin_user_object->LastLoginTime = SystemTime64();
				}
				Unlock(loggedin_user_object->lock);
			}

			// Update the number of log-ins
			hub->LastCommTime = hub->LastLoginTime = SystemTime64();

			if (admin_mode == false) {
				// Check the maximum number of connections of the HUB
				if (hub->Option->MaxSession != 0 &&
				    hub->Option->MaxSession <= Count(hub->NumSessions)) {
					// Can not connect any more
					Unlock(hub->lock);

					HLog(hub, "LH_MAX_SESSION", c->Name, hub->Option->MaxSession);

					ReleaseHub(hub);
					c->Err = ERR_HUB_IS_BUSY;
					Free(policy);
					error_detail = "ERR_HUB_IS_BUSY";
					goto CLEANUP;
				}
			}

			if (use_client_license || use_bridge_license) {
				// Examine whether not to conflict with the limit of simultaneous connections
				// number of sessions defined by the Virtual HUB management options
				if (
				    (GetHubAdminOption(hub, "max_sessions") != 0 &&
				     (Count(hub->NumSessionsClient) + Count(hub->NumSessionsBridge)) >= GetHubAdminOption(hub, "max_sessions")) ||
				    (hub->Option->MaxSession != 0 &&
				     (Count(hub->NumSessionsClient) + Count(hub->NumSessionsBridge)) >= hub->Option->MaxSession)) {
					// Can not connect any more
					Unlock(hub->lock);

					HLog(hub, "LH_MAX_SESSION", c->Name, GetHubAdminOption(hub, "max_sessions"));

					ReleaseHub(hub);
					c->Err = ERR_HUB_IS_BUSY;
					Free(policy);
					goto CLEANUP;
				}
			}

			if (use_client_license) {
				// Examine whether not to conflict with the limit of simultaneous connections
				// number of sessions(client) defined by the Virtual HUB management options
				if (GetHubAdminOption(hub, "max_sessions_client_bridge_apply") != 0 &&
				    Count(hub->NumSessionsClient) >= GetHubAdminOption(hub, "max_sessions_client") && hub->Cedar->Server != NULL) {
					// Can not connect any more
					Unlock(hub->lock);

					HLog(hub, "LH_MAX_SESSION_CLIENT", c->Name, GetHubAdminOption(hub, "max_sessions_client"));

					ReleaseHub(hub);
					c->Err = ERR_HUB_IS_BUSY;
					Free(policy);
					goto CLEANUP;
				}
			}

			if (use_bridge_license) {
				// Examine whether not to conflict with the limit of simultaneous connections
				// number of sessions(bridge) defined by the Virtual HUB management options
				if (GetHubAdminOption(hub, "max_sessions_client_bridge_apply") != 0 &&
				    Count(hub->NumSessionsBridge) >= GetHubAdminOption(hub, "max_sessions_bridge") && hub->Cedar->Server != NULL) {
					// Can not connect any more
					Unlock(hub->lock);

					HLog(hub, "LH_MAX_SESSION_BRIDGE", c->Name, GetHubAdminOption(hub, "max_sessions_bridge"));

					ReleaseHub(hub);
					c->Err = ERR_HUB_IS_BUSY;
					Free(policy);
					goto CLEANUP;
				}
			}

			if (Count(hub->Cedar->CurrentSessions) >= GetServerCapsInt(hub->Cedar->Server, "i_max_sessions")) {
				// Can not connect any more
				Unlock(hub->lock);

				HLog(hub, "LH_MAX_SESSION_2", c->Name, GetServerCapsInt(hub->Cedar->Server, "i_max_sessions"));

				ReleaseHub(hub);
				c->Err = ERR_HUB_IS_BUSY;
				Free(policy);
				goto CLEANUP;
			}

			// Increment the current number of connections
			Inc(hub->NumSessions);
			if (use_bridge_license)
				Inc(hub->NumSessionsBridge);

			if (use_client_license)
				Inc(hub->NumSessionsClient);
			Inc(hub->Cedar->CurrentSessions);

			// Calculate the time-out period
			timeout = policy->TimeOut * 1000; // Convert milliseconds to seconds
			if (timeout == 0)
				timeout = TIMEOUT_DEFAULT;
			timeout = MIN(timeout, TIMEOUT_MAX);
			timeout = MAX(timeout, TIMEOUT_MIN);

			// Update the max_connection according to the policy
			max_connection = MIN(max_connection, policy->MaxConnection);
			max_connection = MIN(max_connection, MAX_TCP_CONNECTION);
			max_connection = MAX(max_connection, 1);

			if (half_connection) {
				// Number of connections should be more than 2 in the case of Half Connection
				max_connection = MAX(max_connection, 2);
			}

			if (qos) {
				// Number of connections is set to 2 or more when using the VoIP / QoS
				max_connection = MAX(max_connection, 2);
				if (half_connection)
					max_connection = MAX(max_connection, 4);
			}

			c->Status = CONNECTION_STATUS_ESTABLISHED;

			// Remove the connection from Cedar
			DelConnection(c->Cedar, c);

			// Create a Session
			StrLower(username);
			s = NewServerSession(c->Cedar, c, hub, username, policy);

			s->LocalHostSession = local_host_session;
			s->NormalClient = true;

			IPToStr(s->ClientIP, sizeof(s->ClientIP), &c->ClientIp);

			StrCpy(s->UnderlayProtocol, sizeof(s->UnderlayProtocol), c->FirstSock->UnderlayProtocol);

			AddProtocolDetailsStr(s->ProtocolDetails, sizeof(s->ProtocolDetails), c->FirstSock->ProtocolDetails);

			if (server != NULL)
				s->NoSendSignature = server->NoSendSignature;

			// Determine whether the use of UDP acceleration mode
			if (use_udp_acceleration_client) {
				s->UseUdpAcceleration = true;

				s->UdpAccelFastDisconnectDetect = support_udp_accel_fast_disconnect_detect;

				udp_acceleration_version = 1;
				if (client_udp_acceleration_max_version >= 2)
					udp_acceleration_version = 2;
			}

			if (hub->Option != NULL && hub->Option->DisableUdpAcceleration)
				s->UseUdpAcceleration = false;

			if (s->UseUdpAcceleration)
				s->UseHMacOnUdpAcceleration = use_hmac_on_udp_acceleration;

			Debug("UseUdpAcceleration = %u\n", s->UseUdpAcceleration);
			Debug("UseHMacOnUdpAcceleration = %u\n", s->UseHMacOnUdpAcceleration);
			Debug("UdpAccelerationVersion = %u\n", s->UdpAccelerationVersion);

			if (s->UseUdpAcceleration) {
				// Initialize the UDP acceleration function
				s->UdpAccel = NewUdpAccel(c->Cedar, &c->FirstSock->LocalIP, false, false);
				if (s->UdpAccel == NULL) {
					s->UseUdpAcceleration = false;
					Debug("NewUdpAccel Failed.\n");
				} else {
					s->UdpAccel->Version = udp_acceleration_version;

					if (UdpAccelInitServer(s->UdpAccel,
					                       s->UdpAccel->Version == 2 ? udp_acceleration_client_key_v2 : udp_acceleration_client_key,
					                       &c->FirstSock->RemoteIP, &udp_acceleration_client_ip, udp_acceleration_client_port) == false) {
						Debug("UdpAccelInitServer Failed.\n");
						s->UseUdpAcceleration = false;
					}

					s->UdpAccel->FastDetect = s->UdpAccelFastDisconnectDetect;

					if (use_encrypt == false)
						s->UdpAccel->PlainTextMode = true;

					s->UdpAccel->UseHMac = s->UseHMacOnUdpAcceleration;

					AddProtocolDetailsKeyValueInt(s->ProtocolDetails, sizeof(s->ProtocolDetails), "UDPAccel_Ver", s->UdpAccel->Version);

					AddProtocolDetailsStr(s->ProtocolDetails, sizeof(s->ProtocolDetails), s->UdpAccel->Version > 1 ? "ChaCha20-Poly1305" : "RC4");

					AddProtocolDetailsKeyValueInt(s->ProtocolDetails, sizeof(s->ProtocolDetails), "UDPAccel_MSS", UdpAccelCalcMss(s->UdpAccel));
				}
			}

			s->UseClientLicense = use_client_license;
			s->UseBridgeLicense = use_bridge_license;

			s->AdjustMss = adjust_mss;
			if (s->AdjustMss != 0) {
				Debug("AdjustMSS: %u\n", s->AdjustMss);
				AddProtocolDetailsKeyValueInt(s->ProtocolDetails, sizeof(s->ProtocolDetails), "AdjustMSS", s->AdjustMss);
			}

			s->IsBridgeMode = (policy->NoBridge == false) || (policy->NoRouting == false);
			s->IsMonitorMode = policy->MonitorPort;

			// Decide whether IPv6 session
			s->IPv6Session = false;

			if (node.ClientIpAddress == 0)
				s->IPv6Session = true;

			if (use_bridge_license)
				Inc(s->Cedar->AssignedBridgeLicense);

			if (use_client_license)
				Inc(s->Cedar->AssignedClientLicense);

			if (server != NULL) {
				// Update the total allocation of the number of licenses for Server structure
				server->CurrentAssignedClientLicense = Count(s->Cedar->AssignedClientLicense);
				server->CurrentAssignedBridgeLicense = Count(s->Cedar->AssignedBridgeLicense);
			}

			if (StrLen(sessionname) != 0) {
				// Specify the session name
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

			// Get the session key
			Copy(session_key, s->SessionKey, SHA1_SIZE);

			// Set the parameters
			s->MaxConnection = max_connection;
			s->UseEncrypt = use_encrypt;
			s->UseCompress = use_compress;
			s->HalfConnection = half_connection;
			s->Timeout = timeout;
			s->QoS = qos;
			s->NoReconnectToSession = no_reconnect_to_session;
			s->VLanId = policy->VLanId;

			// User name
			s->Username = CopyStr(username);

			HLog(hub, "LH_SET_SESSION", s->Name, s->MaxConnection,
			     s->UseEncrypt ? _UU("L_YES") : _UU("L_NO"),
			     s->UseCompress ? _UU("L_YES") : _UU("L_NO"),
			     s->HalfConnection ? _UU("L_YES") : _UU("L_NO"),
			     s->Timeout / 1000);

			msg = GetHubMsg(hub);

			// Suppress client update notification flag
			if (hub->Option != NULL)
				suppress_client_update_notification = hub->Option->SuppressClientUpdateNotification;
		}
		Unlock(hub->lock);

		if (s->UseUdpAcceleration && s->UdpAccel != NULL) {
			// Learn the public endpoint of the UDP acceleration socket by STUN (only if configured and the peer is not local).
			// This is done after releasing the hub lock because the query may block for a while.
			UdpAccelQueryStun(s->UdpAccel, &c->FirstSock->RemoteIP);
		}

		// Send a Welcome packet to the client
		p = PackWelcome(s);

		PackAddBool(p, "suppress_client_update_notification", suppress_client_update_notification);

		if (true) {
			// A message to be displayed in the VPN Client (Will not be displayed if the VPN Gate Virtual HUB)
			char *utf;
			wchar_t winver_msg_client[3800];
			wchar_t winver_msg_server[3800];
			UINT tmpsize;
			wchar_t *tmp;
			RPC_WINVER server_winver;

			GetWinVer(&server_winver);

			Zero(winver_msg_client, sizeof(winver_msg_client));
			Zero(winver_msg_server, sizeof(winver_msg_server));

			if (IsSupportedWinVer(&winver) == false) {
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

			if (IsSupportedWinVer(&server_winver) == false) {
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

			if (IsURLMsg(msg, NULL, 0) == false) {

				{
					if (GetGlobalServerFlag(GSF_SHOW_OSS_MSG) != 0)
						UniStrCat(tmp, tmpsize, _UU("OSS_MSG"));
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

		// Brand string for the connection limit
		{
			char *branded_cfroms = _SS("BRANDED_C_FROM_S");
			if (StrLen(branded_cfroms) > 0)
				PackAddStr(p, "branded_cfroms", branded_cfroms);
		}

		HttpServerSend(c->FirstSock, p);
		FreePack(p);

		// Receive a signature
		Copy(&c->Session->NodeInfo, &node, sizeof(NODE_INFO));


		{
			wchar_t tmp[MAX_SIZE * 2];
			NodeInfoToStr(tmp, sizeof(tmp), &s->NodeInfo);

			HLog(hub, "LH_NODE_INFO", s->Name, tmp);

			if (s->VLanId != 0)
				HLog(hub, "LH_VLAN_ID", s->Name, s->VLanId);
		}

		// Shift the connection to the tunneling mode
		StartTunnelingMode(c);

		// Processing of half-connection mode
		if (s->HalfConnection) {
			// The direction of the first socket is client to server
			TCPSOCK *ts = (TCPSOCK *)LIST_DATA(c->Tcp->TcpSockList, 0);
			ts->Direction = TCP_CLIENT_TO_SERVER;
		}

		if (s->LocalHostSession) {
			// Update the local MAC address list
			RefreshLocalMacAddressList();
		}

		// Discard the user list cache
		DeleteAllUserListCache(hub->UserList);


		// Main routine of the session
		Debug("SessionMain()\n");
		s->NumLoginIncrementUserObject = loggedin_user_object;
		s->NumLoginIncrementHubObject = s->Hub;
		s->NumLoginIncrementTick = Tick64() + (UINT64)NUM_LOGIN_INCREMENT_INTERVAL;
		SessionMain(s);


		// Discard the user list cache
		DeleteAllUserListCache(hub->UserList);

		// Decrement the current number of connections
		Lock(s->Hub->lock);
		{
			if (use_bridge_license)
				Dec(hub->NumSessionsBridge);

			if (use_client_license)
				Dec(hub->NumSessionsClient);

			Dec(s->Hub->NumSessions);
			Dec(s->Hub->Cedar->CurrentSessions);

			// Decrement the number of licenses
			if (use_bridge_license)
				Dec(s->Cedar->AssignedBridgeLicense);

			if (use_client_license)
				Dec(s->Cedar->AssignedClientLicense);

			if (server != NULL) {
				// Update the total allocation of the number of licenses for Server structure
				server->CurrentAssignedClientLicense = Count(s->Cedar->AssignedClientLicense);
				server->CurrentAssignedBridgeLicense = Count(s->Cedar->AssignedBridgeLicense);
			}
		}
		Unlock(s->Hub->lock);

		PrintSessionTotalDataSize(s);

		HLog(s->Hub, "LH_END_SESSION", s->Name, s->TotalSendSizeReal, s->TotalRecvSizeReal);

		if (s->UdpAccel != NULL) {
			// Release the UDP acceleration
			FreeUdpAccel(s->UdpAccel);
			s->UdpAccel = NULL;
		}

		ReleaseSession(s);

		ret = true;
		c->Err = ERR_SESSION_REMOVED;

		ReleaseHub(hub);

		goto CLEANUP;
	} else if (StrCmpi(method, "additional_connect") == 0) {
		SOCK *sock;
		TCPSOCK *ts;
		UINT dummy;

		c->Type = CONNECTION_TYPE_ADDITIONAL;

		// Additional connection
		// Read the session key
		if (GetSessionKeyFromPack(p, session_key, &dummy) == false) {
			FreePack(p);
			c->Err = ERR_PROTOCOL_ERROR;
			goto CLEANUP;
		}

		FreePack(p);

		// Get the session from the session key
		s = GetSessionFromKey(c->Cedar, session_key);
		if (s == NULL || s->Halt || s->NoReconnectToSession) {
			// Session can not be found, or re-connection is prohibited
			Debug("Session Not Found.\n");
			c->Err = ERR_SESSION_TIMEOUT;
			goto CLEANUP;
		}

		// Session is found
		Debug("Session Found: %s\n", s->Name);
		// Check the protocol of session
		c->Err = 0;
		Lock(s->lock);
		{
			if (s->Connection->Protocol != CONNECTION_TCP)
				c->Err = ERR_INVALID_PROTOCOL;
		}
		Unlock(s->lock);
		// Check the current number of connections of the session
		Lock(s->Connection->lock);
		if (c->Err == 0) {
			if (Count(s->Connection->CurrentNumConnection) > s->MaxConnection)
				c->Err = ERR_TOO_MANY_CONNECTION;
		}
		if (c->Err != 0) {
			Unlock(s->Connection->lock);
			if (c->Err == ERR_TOO_MANY_CONNECTION)
				Debug("Session TOO MANY CONNECTIONS !!: %u\n",
				      Count(s->Connection->CurrentNumConnection));
			else
				Debug("Session Invalid Protocol.\n");
			ReleaseSession(s);
			goto CLEANUP;
		}

		// Add the socket of this connection to the connection list of the session (TCP)
		sock = c->FirstSock;

		ts = NewTcpSock(sock);
		SetTimeout(sock, CONNECTING_TIMEOUT);
		direction = TCP_BOTH;
		LockList(s->Connection->Tcp->TcpSockList);
		{
			if (s->HalfConnection) {
				// In half-connection, directions of the TCP connections are automatically
				// adjusted by examining all current direction of the TCP connections
				UINT i, c2s, s2c;
				c2s = s2c = 0;
				for (i = 0; i < LIST_NUM(s->Connection->Tcp->TcpSockList); i++) {
					TCPSOCK *ts = (TCPSOCK *)LIST_DATA(s->Connection->Tcp->TcpSockList, i);
					if (ts->Direction == TCP_SERVER_TO_CLIENT)
						s2c++;
					else
						c2s++;
				}
				if (s2c > c2s)
					direction = TCP_CLIENT_TO_SERVER;
				else
					direction = TCP_SERVER_TO_CLIENT;
				Debug("%u/%u\n", s2c, c2s);
				ts->Direction = direction;
			}
		}
		UnlockList(s->Connection->Tcp->TcpSockList);

		// Return a success result
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

		// Increment the number of connections
		Inc(s->Connection->CurrentNumConnection);
		Debug("TCP Connection Incremented: %u\n", Count(s->Connection->CurrentNumConnection));

		// Issue the Cancel of session
		Cancel(s->Cancel1);

		Unlock(s->Connection->lock);

		c->flag1 = true;

		ReleaseSession(s);

		return true;
	} else if (StrCmpi(method, "enum_hub") == 0) {
		// Enumerate the Virtual HUB
		UINT i, num;
		LIST *o;
		o = NewListFast(NULL);

		c->Type = CONNECTION_TYPE_ENUM_HUB;

		FreePack(p);
		p = NewPack();
		LockList(c->Cedar->HubList);
		{
			num = LIST_NUM(c->Cedar->HubList);
			for (i = 0; i < num; i++) {
				HUB *h = LIST_DATA(c->Cedar->HubList, i);
				if (h->Option != NULL && h->Option->NoEnum == false)
					Insert(o, CopyStr(h->Name));
			}
		}
		UnlockList(c->Cedar->HubList);

		num = LIST_NUM(o);
		for (i = 0; i < num; i++) {
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
	} else if (StrCmpi(method, "admin") == 0 && c->Cedar->Server != NULL) {
		UINT err;
		// Administrative RPC connection request
		c->Type = CONNECTION_TYPE_ADMIN_RPC;
		err = AdminAccept(c, p);
		FreePack(p);
		if (err != ERR_NO_ERROR) {
			PACK *p = PackError(err);
			HttpServerSend(c->FirstSock, p);
			FreePack(p);
		}

		error_detail = "admin_rpc";

		goto CLEANUP;
	} else if (StrCmpi(method, "password") == 0) {
		UINT err;
		// Password change request
		c->Type = CONNECTION_TYPE_PASSWORD;
		err = ChangePasswordAccept(c, p);
		FreePack(p);

		p = PackError(err);
		HttpServerSend(c->FirstSock, p);
		FreePack(p);

		error_detail = "change_password";

		goto CLEANUP;
	} else {
		// Unknown method
		FreePack(p);
		c->Err = ERR_PROTOCOL_ERROR;

		error_detail = "unknown_method";

		goto CLEANUP;
	}

CLEANUP:
	// Release the user object
	if (loggedin_user_object != NULL)
		ReleaseUser(loggedin_user_object);


	// Error packet transmission
	if (supress_return_pack_error == false) {
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


// Create a Node information
void CreateNodeInfo(NODE_INFO *info, CONNECTION *c) {
	SESSION *s;
	OS_INFO *os;
	char *product_id;
	IP ip;
	// Validate arguments
	if (c == NULL)
		return;

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
	if (true) {
		wchar_t namew[256];
		char namea[256];

		Zero(namew, sizeof(namew));
		MsGetComputerNameFullEx(namew, sizeof(namew), true);

		Zero(namea, sizeof(namea));
		UniToStr(namea, sizeof(namea), namew);

		if (IsEmptyStr(namea))
			GetMachineName(namea, sizeof(namea));

		StrCpy(info->ClientHostname, sizeof(info->ClientHostname), namea);
	}
	// Client IP address
	if (IsIP6(&c->FirstSock->LocalIP) == false)
		info->ClientIpAddress = IPToUINT(&c->FirstSock->LocalIP);
	else
		Copy(info->ClientIpAddress6, c->FirstSock->LocalIP.address, sizeof(info->ClientIpAddress6));
	// Client port number
	info->ClientPort = Endian32(c->FirstSock->LocalPort);

	// Server host name
	StrCpy(info->ServerHostname, sizeof(info->ServerHostname), c->ServerName);
	// Server IP address
	if (s->ClientOption->ProxyType == PROXY_DIRECT) {
		if (IsIP6(&c->FirstSock->RemoteIP) == false)
			info->ServerIpAddress = IPToUINT(&c->FirstSock->RemoteIP);
		else
			Copy(info->ServerIpAddress6, c->FirstSock->RemoteIP.address, sizeof(info->ServerIpAddress6));
	} else if (GetIP(&ip, info->ServerHostname)) {
		if (IsIP6(&ip) == false)
			info->ServerIpAddress = IPToUINT(&ip);
		else
			Copy(info->ServerIpAddress6, ip.address, sizeof(info->ServerIpAddress6));
	}
	// Server port number
	info->ServerPort = Endian32(c->ServerPort);

	if (s->ClientOption->ProxyType == PROXY_SOCKS || s->ClientOption->ProxyType == PROXY_HTTP) {
		// Proxy host name
		StrCpy(info->ProxyHostname, sizeof(info->ProxyHostname), s->ClientOption->ProxyName);

		// Proxy Server IP Address
		if (IsIP6(&c->FirstSock->RemoteIP) == false)
			info->ProxyIpAddress = IPToUINT(&c->FirstSock->RemoteIP);
		else
			Copy(&info->ProxyIpAddress6, c->FirstSock->RemoteIP.address, sizeof(info->ProxyIpAddress6));

		info->ProxyPort = Endian32(c->FirstSock->RemotePort);
	}

	// HUB name
	StrCpy(info->HubName, sizeof(info->HubName), s->ClientOption->HubName);

	// Unique ID
	Copy(info->UniqueId, c->Cedar->UniqueId, sizeof(info->UniqueId));
}

// Connect a socket additionally
SOCK *ClientAdditionalConnectToServer(CONNECTION *c) {
	SOCK *s;
	// Validate arguments
	if (c == NULL)
		return NULL;

	// Socket connection
	s = ClientConnectGetSocket(c, true);
	if (s == NULL) {
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

	if (c->Session->Halt) {
		// Stop
		Disconnect(s);
		LockList(c->ConnectingSocks);
		{
			if (Delete(c->ConnectingSocks, s))
				ReleaseSock(s);
		}
		UnlockList(c->ConnectingSocks);
		ReleaseSock(s);
		return NULL;
	}

	// Time-out
	SetTimeout(s, CONNECTING_TIMEOUT);

	// Start the SSL communication
	if (StartSSLEx(s, NULL, NULL, 0, c->ServerName) == false) {
		// SSL communication failure
		Disconnect(s);
		LockList(c->ConnectingSocks);
		{
			if (Delete(c->ConnectingSocks, s))
				ReleaseSock(s);
		}
		UnlockList(c->ConnectingSocks);
		ReleaseSock(s);
		return NULL;
	}

	// Check the certificate
	if (CompareX(s->RemoteX, c->ServerX) == false) {
		// The certificate is invalid
		Disconnect(s);
		c->Session->SessionTimeOuted = true;
	}

	return s;
}

// Client connects to the server additionally
bool ClientAdditionalConnect(CONNECTION *c, THREAD *t) {
	SOCK *s;
	PACK *p;
	TCPSOCK *ts;
	UINT err;
	UINT direction;

	// Validate arguments
	if (c == NULL)
		return false;

	// Socket connection to the server
	s = ClientAdditionalConnectToServer(c);
	if (s == NULL) {
		// Failed to connect socket
		return false;
	}

	if (c->Halt)
		goto CLEANUP;

	// Send a signature
	Debug("Uploading Signature...\n");
	if (ClientUploadSignature(s) == false)
		goto CLEANUP;

	if (c->Halt) {
		// Stop
		goto CLEANUP;
	}

	// Receive a Hello packet
	Debug("Downloading Hello...\n");
	if (ClientDownloadHello(c, s) == false)
		goto CLEANUP;

	if (c->Halt) {
		// Stop
		goto CLEANUP;
	}

	// Send a authentication data for the additional connection
	if (ClientUploadAuth2(c, s) == false) {
		// Disconnected
		goto CLEANUP;
	}

	// Receive a response
	p = HttpClientRecv(s);
	if (p == NULL) {
		// Disconnected
		goto CLEANUP;
	}

	err = GetErrorFromPack(p);
	direction = PackGetInt(p, "direction");

	FreePack(p);
	p = NULL;

	if (err != 0) {
		// Error has occurred
		Debug("Additional Connect Error: %u\n", err);
		if (err == ERR_SESSION_TIMEOUT || err == ERR_INVALID_PROTOCOL) {
			// We shall re-connection because it is a fatal error
			c->Session->SessionTimeOuted = true;
		}
		goto CLEANUP;
	}

	Debug("Additional Connect Succeed!\n");

	// Success the additional connection
	// Add to the TcpSockList of the connection
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
	Debug("TCP Connection Incremented: %u\n", Count(c->CurrentNumConnection));

	if (c->Session->HalfConnection)
		Debug("New Half Connection: %s\n",
		      direction == TCP_SERVER_TO_CLIENT ? "TCP_SERVER_TO_CLIENT" : "TCP_CLIENT_TO_SERVER");

	// Issue the Cancel to the session
	Cancel(c->Session->Cancel1);

	// Remove the socket from the socket list of connected
	LockList(c->ConnectingSocks);
	{
		if (Delete(c->ConnectingSocks, s))
			ReleaseSock(s);
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
			ReleaseSock(s);
	}
	UnlockList(c->ConnectingSocks);
	ReleaseSock(s);
	return false;
}

// Server certificate confirmation thread
void ClientCheckServerCertThread(THREAD *thread, void *param) {
	CHECK_CERT_THREAD_PROC *p = (CHECK_CERT_THREAD_PROC *)param;
	// Validate arguments
	if (thread == NULL || param == NULL)
		return;

	// Notify the completion of initialization
	NoticeThreadInit(thread);

	// Query for the selection to the user
	p->Ok = p->CheckCertProc(p->Connection->Session, p->Connection, p->ServerX, &p->Expired);
	p->UserSelected = true;
}

// Client verify the certificate of the server
bool ClientCheckServerCert(CONNECTION *c, bool *expired) {
	CLIENT_AUTH *auth;
	X *x;
	CHECK_CERT_THREAD_PROC *p;
	THREAD *thread;
	bool ret;
	UINT64 start;
	// Validate arguments
	if (c == NULL)
		return false;

	if (expired != NULL)
		*expired = false;

	auth = c->Session->ClientAuth;

	if (auth->CheckCertProc == NULL)
		return false;

	x = CloneX(c->FirstSock->RemoteX);
	if (x == NULL) {
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
	while (true) {
		if ((Tick64() - start) > CONNECTING_POOLING_SPAN) {
			// Send a NOOP periodically for disconnection prevention
			start = Tick64();
			// Do not send because we now ask for user permission before sending signature
			//ClientUploadNoop(c);
		}
		if (p->UserSelected) {
			// User-selected
			break;
		}
		WaitThread(thread, 500);
	}

	if (expired != NULL)
		*expired = p->Expired;

	ret = p->Ok;
	FreeX(p->ServerX);
	Free(p);
	ReleaseThread(thread);

	return ret;
}

// Client connects to the server
bool ClientConnect(CONNECTION *c) {
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
		return false;

	sess = c->Session;

	PrintStatus(sess, L"init");
	PrintStatus(sess, _UU("STATUS_1"));

	// [Connecting]
	c->Status = CONNECTION_STATUS_CONNECTING;
	c->Session->ClientStatus = CLIENT_STATUS_CONNECTING;

	s = ClientConnectToServer(c);
	if (s == NULL) {
		// Do not retry if untrusted or hostname mismatched
		if (c->Session->LinkModeClient == false && (c->Err == ERR_CERT_NOT_TRUSTED || c->Err == ERR_HOSTNAME_MISMATCH) && (c->Session->Account == NULL || !c->Session->Account->RetryOnServerCert))
			c->Session->ForceStopFlag = true;
		PrintStatus(sess, L"free");
		return false;
	}

	PrintStatus(sess, _UU("STATUS_5"));

	// Prompt user whether to continue on verification errors
	if ((c->Err == ERR_CERT_NOT_TRUSTED || c->Err == ERR_HOSTNAME_MISMATCH || c->Err == ERR_SERVER_CERT_EXPIRES) && ClientCheckServerCert(c, &expired) == false) {
		if (expired)
			c->Err = ERR_SERVER_CERT_EXPIRES;

		// Do not retry if untrusted or hostname mismatched
		if (c->Session->LinkModeClient == false && (c->Err == ERR_CERT_NOT_TRUSTED || c->Err == ERR_HOSTNAME_MISMATCH) && (c->Session->Account == NULL || !c->Session->Account->RetryOnServerCert))
			c->Session->ForceStopFlag = true;

		goto CLEANUP;
	}

	Copy(&server_ip, &s->RemoteIP, sizeof(IP));

	if (c->Halt) {
		// Stop
		c->Err = ERR_USER_CANCEL;
		goto CLEANUP;
	}

	// [Negotiating]
	c->Session->ClientStatus = CLIENT_STATUS_NEGOTIATION;

	// Initialize the UDP acceleration function
	if (sess->ClientOption != NULL && sess->ClientOption->NoUdpAcceleration == false) {
		if (sess->ClientOption->ProxyType == PROXY_DIRECT) {
			if (s->Type == SOCK_TCP) {
				if (sess->UdpAccel == NULL) {
					sess->UdpAccel = NewUdpAccel(c->Cedar, &s->LocalIP, true, true);

					// Learn the public endpoint of the UDP acceleration socket by STUN (only if configured and the peer is not local)
					UdpAccelQueryStun(sess->UdpAccel, &s->RemoteIP);
				}
			}
		}
	}

	// Send a signature
	Debug("Uploading Signature...\n");
	if (ClientUploadSignature(s) == false) {
		c->Err = ERR_DISCONNECTED;
		goto CLEANUP;
	}

	if (c->Halt) {
		// Stop
		c->Err = ERR_USER_CANCEL;
		goto CLEANUP;
	}

	// Receive a Hello packet
	Debug("Downloading Hello...\n");
	if (ClientDownloadHello(c, s) == false)
		goto CLEANUP;

	if (c->Session->ClientOption != NULL && c->Session->ClientOption->FromAdminPack) {
		if (IsAdminPackSupportedServerProduct(c->ServerStr) == false) {
			c->Err = ERR_NOT_ADMINPACK_SERVER;
			goto CLEANUP;
		}
	}

	if (c->Halt) {
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
		goto CLEANUP;

	if (c->Halt) {
		// Stop
		c->Err = ERR_USER_CANCEL;
		goto CLEANUP;
	}

	// Receive a Welcome packet
	p = HttpClientRecv(s);
	if (p == NULL) {
		c->Err = ERR_DISCONNECTED;
		goto CLEANUP;
	}

	// Error checking
	err = GetErrorFromPack(p);
	if (err != 0) {
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

		if (StrLen(branded_cfroms) > 0 && StrCmpi(branded_cfroms, tmp) != 0) {
			c->Err = ERR_BRANDED_C_FROM_S;
			goto CLEANUP;
		}
	}

	if (true) {
		// Message retrieval
		UINT utf_size;
		char *utf;
		wchar_t *msg;

		utf_size = PackGetDataSize(p, "Msg");
		utf = ZeroMalloc(utf_size + 8);
		PackGetData(p, "Msg", utf);

		msg = CopyUtfToUni(utf);

		if (IsEmptyUniStr(msg) == false) {
			if (c->Session->Client_Message != NULL)
				Free(c->Session->Client_Message);

			c->Session->Client_Message = msg;
		} else {
			Free(msg);
		}

		Free(utf);
	}

	PrintStatus(sess, _UU("STATUS_7"));

	// Parse the Welcome packet
	if (ParseWelcomeFromPack(p, session_name, sizeof(session_name),
	                         connection_name, sizeof(connection_name), &policy) == false) {
		// Parsing failure
		c->Err = ERR_PROTOCOL_ERROR;
		goto CLEANUP;
	}

	// Get the session key
	if (GetSessionKeyFromPack(p, session_key, &session_key_32) == false) {
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
			c->Session->MaxConnection = MAX(c->Session->MaxConnection, (UINT)(c->Session->HalfConnection ? 4 : 2));
		c->Session->VLanId = PackGetInt(p, "vlan_id");

		// Physical communication protocol
		StrCpy(c->Session->UnderlayProtocol, sizeof(c->Session->UnderlayProtocol), s->UnderlayProtocol);

		AddProtocolDetailsStr(c->Session->ProtocolDetails, sizeof(c->Session->ProtocolDetails), s->ProtocolDetails);

		if (c->Protocol == CONNECTION_UDP) {
			// In the case of UDP protocol, receive the key from the server
			if (PackGetDataSize(p, "udp_send_key") == sizeof(c->Session->UdpSendKey))
				PackGetData(p, "udp_send_key", c->Session->UdpSendKey);

			if (PackGetDataSize(p, "udp_recv_key") == sizeof(c->Session->UdpRecvKey))
				PackGetData(p, "udp_recv_key", c->Session->UdpRecvKey);
		}

		sess->UseUdpAcceleration = false;
		sess->IsUsingUdpAcceleration = false;
		sess->UseHMacOnUdpAcceleration = false;

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

					if (IsZeroIp(&udp_acceleration_server_ip))
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
							                       server_cookie, client_cookie) == false) {
								Debug("UdpAccelInitClient failed.\n");
							} else {
								sess->UseUdpAcceleration = true;

								sess->UdpAccel->FastDetect = sess->UdpAccelFastDisconnectDetect;

								sess->UdpAccel->PlainTextMode = !encryption;

								sess->UseHMacOnUdpAcceleration = PackGetBool(p, "use_hmac_on_udp_acceleration");

								if (sess->UseHMacOnUdpAcceleration)
									sess->UdpAccel->UseHMac = true;

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

		// Save the name of a cryptographic algorithm
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

	// Discard the Welcome packet
	FreePack(p);
	p = NULL;


	// Connection establishment
	c->Session->ClientStatus = CLIENT_STATUS_ESTABLISHED;

	// Save the server certificate
	if (c->ServerX == NULL)
		c->ServerX = CloneX(c->FirstSock->RemoteX);

	PrintStatus(sess, _UU("STATUS_9"));
	// Shift the connection to the tunneling mode
	StartTunnelingMode(c);
	s = NULL;

	if (c->Session->HalfConnection) {
		// Processing in the case of half-connection
		TCPSOCK *ts = (TCPSOCK *)LIST_DATA(c->Tcp->TcpSockList, 0);
		ts->Direction = TCP_CLIENT_TO_SERVER;
	}

	PrintStatus(sess, L"free");

	if (c->Session->LinkModeClient && c->Session->Link != NULL)
		HLog(c->Session->Link->Hub, "LH_CONNECT_2", c->Session->ClientOption->AccountName, session_name);

	// Main routine of the session
	SessionMain(c->Session);

	ok = true;

	if (c->Err == ERR_USER_CANCEL)
		ret = true;

CLEANUP:
	c->FirstSock = NULL;

	if (sess->UdpAccel != NULL) {
		FreeUdpAccel(sess->UdpAccel);
		sess->UdpAccel = NULL;
	}

	if (p != NULL)
		FreePack(p);

	Disconnect(s);
	ReleaseSock(s);

	Debug("Error: %u\n", c->Err);

	if (ok == false)
		PrintStatus(sess, L"free");

	return ret;
}

// Parse the Welcome packet
bool ParseWelcomeFromPack(PACK *p, char *session_name, UINT session_name_size,
                          char *connection_name, UINT connection_name_size,
                          POLICY **policy) {
	// Validate arguments
	if (p == NULL || session_name == NULL || connection_name == NULL || policy == NULL)
		return false;

	// Session name
	if (PackGetStr(p, "session_name", session_name, session_name_size) == false)
		return false;

	// Connection name
	if (PackGetStr(p, "connection_name", connection_name, connection_name_size) == false)
		return false;

	// Policy
	*policy = PackGetPolicy(p);
	if (*policy == NULL)
		return false;

	return true;
}

// Generate the Welcome packet
PACK *PackWelcome(SESSION *s) {
	PACK *p;
	// Validate arguments
	if (s == NULL)
		return NULL;

	p = NewPack();

	// Session name
	PackAddStr(p, "session_name", s->Name);

	// Connection name
	PackAddStr(p, "connection_name", s->Connection->Name);

	// Parameters
	PackAddInt(p, "max_connection", s->MaxConnection);
	PackAddInt(p, "use_encrypt", s->UseEncrypt == false ? 0 : 1);
	PackAddInt(p, "use_compress", s->UseCompress == false ? 0 : 1);
	PackAddInt(p, "half_connection", s->HalfConnection == false ? 0 : 1);
	PackAddInt(p, "timeout", s->Timeout);
	PackAddInt(p, "qos", s->QoS ? 1 : 0);

	// Session key
	PackAddData(p, "session_key", s->SessionKey, SHA1_SIZE);
	PackAddInt(p, "session_key_32", s->SessionKey32);

	// Policy
	PackAddPolicy(p, s->Policy);

	// VLAN ID
	PackAddInt(p, "vlan_id", s->VLanId);

	if (s->Connection->Protocol == CONNECTION_UDP) {
		// In the case of UDP protocol, generate 2 pairs of key
		Rand(s->UdpSendKey, sizeof(s->UdpSendKey));
		Rand(s->UdpRecvKey, sizeof(s->UdpRecvKey));

		// Send to client by exchanging 2 keys
		PackAddData(p, "udp_send_key", s->UdpRecvKey, sizeof(s->UdpRecvKey));
		PackAddData(p, "udp_recv_key", s->UdpSendKey, sizeof(s->UdpSendKey));
	}

	// no_send_signature
	if (s->NoSendSignature)
		PackAddBool(p, "no_send_signature", true);

	if (s->UdpAccel != NULL) {
		// UDP acceleration function
		PackAddBool(p, "use_udp_acceleration", true);
		PackAddInt(p, "udp_acceleration_version", s->UdpAccel->Version);
		if (s->UdpAccel->UseStun) {
			// Public endpoint learned by STUN
			PackAddIp(p, "udp_acceleration_server_ip", &s->UdpAccel->StunIp);
			PackAddInt(p, "udp_acceleration_server_port", s->UdpAccel->StunPort);
		} else {
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

#define PACK_ADD_POLICY_BOOL(name, value) \
	PackAddBool(p, "policy:" name, y->value == false ? 0 : 1)
#define PACK_ADD_POLICY_UINT(name, value) \
	PackAddInt(p, "policy:" name, y->value)
#define PACK_GET_POLICY_BOOL(name, value) \
	y->value = (PackGetBool(p, "policy:" name))
#define PACK_GET_POLICY_UINT(name, value) \
	y->value = PackGetInt(p, "policy:" name)

// Get a PACK from the session key
bool GetSessionKeyFromPack(PACK *p, UCHAR *session_key, UINT *session_key_32) {
	// Validate arguments
	if (p == NULL || session_key == NULL || session_key_32 == NULL)
		return false;

	if (PackGetDataSize(p, "session_key") != SHA1_SIZE)
		return false;
	if (PackGetData(p, "session_key", session_key) == false)
		return false;
	*session_key_32 = PackGetInt(p, "session_key_32");

	return true;
}

// Get the policy from the PACK
POLICY *PackGetPolicy(PACK *p) {
	POLICY *y;
	// Validate arguments
	if (p == NULL)
		return NULL;

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

// Insert the policy into the PACK
void PackAddPolicy(PACK *p, POLICY *y) {
	// Validate arguments
	if (p == NULL || y == NULL)
		return;

	// Bool value
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

	// UINT value
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

// Upload the authentication data for the additional connection
bool ClientUploadAuth2(CONNECTION *c, SOCK *s) {
	PACK *p = NULL;
	// Validate arguments
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

// Add client version information to the PACK
void PackAddClientVersion(PACK *p, CONNECTION *c) {
	// Validate arguments
	if (p == NULL || c == NULL)
		return;

	PackAddStr(p, "client_str", c->ClientStr);
	PackAddInt(p, "client_ver", c->ClientVer);
	PackAddInt(p, "client_build", c->ClientBuild);
}

// Upload the certificate data for the new connection
bool ClientUploadAuth(CONNECTION *c) {
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
		return false;

	Zero(sign, sizeof(sign));

	a = c->Session->ClientAuth;
	o = c->Session->ClientOption;

	switch (a->AuthType) {
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
		    a->ClientX->bits != 0 && (a->ClientX->bits / 8) <= sizeof(sign)) {
			if (RsaSignEx(sign, c->Random, SHA1_SIZE, a->ClientK, a->ClientX->bits)) {
				p = PackLoginWithCert(o->HubName, a->Username, a->ClientX, sign, a->ClientX->bits / 8);
				c->ClientX = CloneX(a->ClientX);
			}
		}
		break;

	case CLIENT_AUTHTYPE_OPENSSLENGINE:
		// Certificate authentication
		if (a->ClientX != NULL && a->ClientX->is_compatible_bit &&
		    a->ClientX->bits != 0 && (a->ClientX->bits / 8) <= sizeof(sign)) {
			if (RsaSignEx(sign, c->Random, SHA1_SIZE, a->ClientK, a->ClientX->bits)) {
				p = PackLoginWithCert(o->HubName, a->Username, a->ClientX, sign, a->ClientX->bits / 8);
				c->ClientX = CloneX(a->ClientX);
			}
		}
		break;
	}

	if (p == NULL) {
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
	if (o->NoUdpAcceleration == false && c->Session->UdpAccel != NULL) {
		PackAddBool(p, "use_udp_acceleration", true);

		PackAddInt(p, "udp_acceleration_version", c->Session->UdpAccel->Version);

		IP my_ip;
		UINT my_port = c->Session->UdpAccel->MyPort;
		if (c->Session->UdpAccel->UseStun) {
			// Public endpoint learned by STUN
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

	// Brand string for the connection limit
	{
		char *branded_ctos = _SS("BRANDED_C_TO_S");
		if (StrLen(branded_ctos) > 0)
			PackAddStr(p, "branded_ctos", branded_ctos);
	}

	// Node information
	CreateNodeInfo(&info, c);
	OutRpcNodeInfo(p, &info);

	// OS information
	GetWinVer(&v);
	OutRpcWinVer(p, &v);

	ret = HttpClientSend(c->FirstSock, p);
	if (ret == false)
		c->Err = ERR_DISCONNECTED;

	FreePack(p);

	return ret;
}

// Upload the Hello packet
bool ServerUploadHello(CONNECTION *c) {
	PACK *p;
	// Validate arguments
	if (c == NULL)
		return false;

	// Random number generation
	Rand(c->Random, SHA1_SIZE);

	p = PackHello(c->Random, c->ServerVer, c->ServerBuild, c->ServerStr);
	if (HttpServerSend(c->FirstSock, p) == false) {
		FreePack(p);
		c->Err = ERR_DISCONNECTED;
		return false;
	}

	FreePack(p);

	return true;
}

// Download the Hello packet
bool ClientDownloadHello(CONNECTION *c, SOCK *s) {
	PACK *p;
	UINT err;
	UCHAR random[SHA1_SIZE];
	// Validate arguments
	if (c == NULL)
		return false;

	// Data reception
	p = HttpClientRecv(s);
	if (p == NULL) {
		c->Err = ERR_SERVER_IS_NOT_VPN;
		return false;
	}

	if (err = GetErrorFromPack(p)) {
		// An error has occured
		c->Err = err;
		FreePack(p);
		return false;
	}

	// Packet interpretation
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

// Download the signature
bool ServerDownloadSignature(CONNECTION *c, char **error_detail_str) {
	HTTP_HEADER *h;
	UCHAR *data;
	UINT data_size;
	SOCK *s;
	UINT num = 0, max = 19;
	SERVER *server;
	char *vpn_http_target = HTTP_VPN_TARGET2;
	// Validate arguments
	if (c == NULL)
		return false;

	server = c->Cedar->Server;

	s = c->FirstSock;

	while (true) {
		bool not_found_error = false;

		num++;
		if (num > max) {
			// Disconnect
			Disconnect(s);
			c->Err = ERR_CLIENT_IS_NOT_VPN;

			*error_detail_str = "HTTP_TOO_MANY_REQUEST";
			return false;
		}
		// Receive a header
		h = RecvHttpHeader(s);
		if (h == NULL) {
			c->Err = ERR_CLIENT_IS_NOT_VPN;
			return false;
		}

		// Interpret
		if (StrCmpi(h->Method, "POST") == 0) {
			// Receive the data since it's POST
			data_size = GetContentLength(h);

			if ((data_size > MAX_WATERMARK_SIZE || data_size < WaterMarkSize) && (data_size != StrLen(HTTP_VPN_TARGET_POSTDATA))) {
				// Data is too large
				HttpSendForbidden(s, h->Target, NULL);
				FreeHttpHeader(h);
				c->Err = ERR_CLIENT_IS_NOT_VPN;
				*error_detail_str = "POST_Recv_TooLong";
				return false;
			}
			data = Malloc(data_size);
			if (RecvAll(s, data, data_size, s->SecureMode) == false) {
				// Data reception failure
				Free(data);
				FreeHttpHeader(h);
				c->Err = ERR_DISCONNECTED;
				*error_detail_str = "POST_Recv_Failed";
				return false;
			}
			// Check the Target
			if ((StrCmpi(h->Target, vpn_http_target) != 0) || not_found_error) {
				// Target is invalid
				HttpSendNotFound(s, h->Target);
				Free(data);
				*error_detail_str = "POST_Target_Wrong";
			} else {
				// Compare posted data with the WaterMark
				if ((data_size == StrLen(HTTP_VPN_TARGET_POSTDATA) && (Cmp(data, HTTP_VPN_TARGET_POSTDATA, data_size) == 0)) || ((data_size >= WaterMarkSize) && Cmp(data, WaterMark, WaterMarkSize) == 0)) {
					// Check the WaterMark
					Free(data);
					FreeHttpHeader(h);
					return true;
				} else {
					// WaterMark is incorrect
					HttpSendForbidden(s, h->Target, NULL);
					*error_detail_str = "POST_WaterMark_Error";
				}
			}
			FreeHttpHeader(h);
		} else {
			// This should not be a VPN client, but interpret a bit more
			if (StrCmpi(h->Method, "GET") != 0 && StrCmpi(h->Method, "HEAD") != 0 && StrCmpi(h->Method, "POST") != 0) {
				// Unsupported method calls
				HttpSendNotImplemented(s, h->Method, h->Target, h->Version);
				*error_detail_str = "HTTP_BAD_METHOD";
			} else if (StrCmpi(h->Target, "/") == 0) {
				// Root directory
				*error_detail_str = "HTTP_ROOT";

				HttpSendForbidden(c->FirstSock, h->Target, "");
			} else {
				// Not Found
				HttpSendNotFound(s, h->Target);

				*error_detail_str = "HTTP_NOT_FOUND";
			}
			FreeHttpHeader(h);
		}
	}
}

// Upload a signature
bool ClientUploadSignature(SOCK *s) {
	HTTP_HEADER *h;
	UINT water_size, rand_size;
	UCHAR *water;
	char ip_str[128];
	// Validate arguments
	if (s == NULL)
		return false;

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
	if (PostHttp(s, h, water, water_size) == false) {
		Free(water);
		FreeHttpHeader(h);
		return false;
	}

	Free(water);
	FreeHttpHeader(h);

	return true;
}

// Establish a connection to the server
SOCK *ClientConnectToServer(CONNECTION *c) {
	SOCK *s = NULL;
	X *x = NULL;
	K *k = NULL;
	// Validate arguments
	if (c == NULL)
		return NULL;

	if (c->Halt) {
		c->Err = ERR_USER_CANCEL;
		return NULL;
	}

	// Get the socket by connecting
	s = ClientConnectGetSocket(c, false);
	if (s == NULL) {
		// Connection failure
		return NULL;
	}

	c->FirstSock = s;

	if (c->Halt) {
		c->Err = ERR_USER_CANCEL;
		ReleaseSock(s);
		c->FirstSock = NULL;
		return NULL;
	}

	// Time-out
	SetTimeout(s, CONNECTING_TIMEOUT);

	// Start the SSL communication
	UINT err = 0;
	if (StartSSLEx3(s, x, k, NULL, 0, c->ServerName, c->Session->SslOption, &err) == false) {
		// SSL communication start failure
		Disconnect(s);
		ReleaseSock(s);
		c->FirstSock = NULL;
		if (err != 0)
			c->Err = err;
		else
			c->Err = ERR_SERVER_IS_NOT_VPN;
		return NULL;
	}

	if (err != 0)
		c->Err = err;

	if (s->RemoteX == NULL) {
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
SOCK *ClientConnectGetSocket(CONNECTION *c, bool additional_connect) {
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
		return NULL;

	cancel_flag = &c->Halt;
	sess = c->Session;
	o = c->Session->ClientOption;

	Zero(&resolved_ip, sizeof(resolved_ip));

	if (additional_connect == false && c->RestoreServerNameAndPort) {
		// Update server name and port number.
		// At the time of writing this comment RestoreServerNameAndPort is never true.
		c->RestoreServerNameAndPort = false;

		if (StrCmpi(c->ServerName, o->Hostname) != 0)
			StrCpy(c->ServerName, sizeof(c->ServerName), o->Hostname);

		c->ServerPort = o->Port;
	}

	if (additional_connect && IsZeroIP(&sess->ServerIP_CacheForNextConnect) == false) {
		IPToStr(hostname, sizeof(hostname), &sess->ServerIP_CacheForNextConnect);
		Debug("ClientConnectGetSocket(): Using cached IP address %s\n", hostname);
	} else {
		IP tmp;

		StrCpy(hostname, sizeof(hostname), o->ProxyType == PROXY_DIRECT ? c->ServerName : o->ProxyName);

		if (StrToIP(&tmp, hostname) == false) {
			// The hostname is not an IP address
			save_resolved_ip = true;
		}
	}

	if (o->ProxyType == PROXY_DIRECT) {
		wchar_t tmp[MAX_SIZE];
		UniFormat(tmp, sizeof(tmp), _UU("STATUS_4"), hostname);
		PrintStatus(sess, tmp);

		{
			IP *localIP;
			UINT localport;

			// Top of Bind outgoing connection
			// Decide the binding operation which is explicitly executed on the client-side

			// In the case of first TCP/IP connection
			if (additional_connect == false) {
				if (sess->ClientOption->NoRoutingTracking == false) {
					localIP = BIND_LOCALIP_NULL; // Specify not to bind
				} else {
					// Nonzero address is for source IP address to bind. Zero address is for dummy not to bind.
					if (IsZeroIP(&sess->ClientOption->BindLocalIP) == true)
						localIP = BIND_LOCALIP_NULL;
					else
						localIP = &sess->ClientOption->BindLocalIP;
					Debug("ClientConnectGetSocket(): Source IP address %r and source port number %d for binding\n", &sess->ClientOption->BindLocalIP, sess->ClientOption->BindLocalPort);
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
			} else {
				localport = sess->ClientOption->BindLocalPort + Count(sess->Connection->CurrentNumConnection) - 1;
				Debug("ClientConnectGetSocket(): Additional source port number %u\n", localport);
			}
			// Bottom of Bind outgoing connection

			sock = BindTcpIpConnectEx(localIP, localport, hostname, c->ServerPort,
			                          (bool *)cancel_flag, c->hWndForUI, &resolved_ip);
		}

		if (sock == NULL) {
			// Connection failure
			c->Err = ERR_CONNECT_FAILED;

			return NULL;
		}
	} else {
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
			if (sess->ClientOption->NoRoutingTracking == false)
				in.BindLocalIP = BIND_LOCALIP_NULL; // Specify not to bind
			else if (IsZeroIP(&sess->ClientOption->BindLocalIP) == true)
				in.BindLocalIP = BIND_LOCALIP_NULL;
			else
				in.BindLocalIP = &sess->ClientOption->BindLocalIP;
		}
		// In the case of second and subsequent TCP/IP connections
		else {
			in.BindLocalIP = &sess->LocalIP_CacheForNextConnect;
		}
		if (sess->ClientOption->BindLocalPort == 0)
			in.BindLocalPort = BIND_LOCALPORT_NULL;
		else
			in.BindLocalPort = sess->ClientOption->BindLocalPort + Count(sess->Connection->CurrentNumConnection) - 1;
		// Bottom of Bind outgoing connection

#ifdef OS_WIN32
		in.Hwnd = c->hWndForUI;
#endif

		UniFormat(tmp, sizeof(tmp), _UU("STATUS_2"), in.TargetHostname, in.Hostname);
		PrintStatus(sess, tmp);

		switch (o->ProxyType) {
		case PROXY_HTTP:
			//			ret = ProxyHttpConnect(&out, &in, cancel_flag);
			ret = BindProxyHttpConnect(&out, &in, cancel_flag); // Bind outgoing connection
			break;
		case PROXY_SOCKS:
			//			ret = ProxySocks4Connect(&out, &in, cancel_flag);
			ret = BindProxySocks4Connect(&out, &in, cancel_flag); // Bind outgoing connection
			break;
		case PROXY_SOCKS5:
			//			ret = ProxySocks5Connect(&out, &in, cancel_flag);
			ret = BindProxySocks5Connect(&out, &in, cancel_flag); // Bind outgoing connection
			break;
		default:
			c->Err = ERR_INTERNAL_ERROR;
			Debug("ClientConnectGetSocket(): Unknown proxy type: %u!\n", o->ProxyType);
			return NULL;
		}

		c->Err = ProxyCodeToCedar(ret);

		if (c->Err != ERR_NO_ERROR) {
			Debug("ClientConnectGetSocket(): Connection via proxy server failed with error %u\n", ret);
			return NULL;
		}

		sock = out.Sock;

		CopyIP(&resolved_ip, &out.ResolvedIp);
	}

	if (additional_connect == false || IsZeroIP(&sock->RemoteIP)) {
		if (IsZeroIP(&sock->RemoteIP) == false || (sock->IPv6 && GetIP6(&c->Session->ServerIP, hostname) == false) || (sock->IPv6 == false && GetIP4(&c->Session->ServerIP, hostname) == false))
			Copy(&c->Session->ServerIP, &sock->RemoteIP, sizeof(c->Session->ServerIP));
	}

	if (save_resolved_ip && IsZeroIP(&resolved_ip) == false) {
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
		if (memcmp(sock->LocalIP.address, c->Session->LocalIP_CacheForNextConnect.address, sizeof(sock->LocalIP.address)) == 0)
			Debug("ClientConnectGetSocket(): Binded local IP address %s OK\n", localaddr);
		else
			Debug("ClientConnectGetSocket(): Binded local IP address %s NG\n", localaddr);
	}
	// Bottom of Bind outgoing connection

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

// TCP connection function
SOCK *TcpConnectEx3(char *hostname, UINT port, UINT timeout, bool *cancel_flag, void *hWnd, IP *ret_ip) {
	return BindTcpConnectEx3(BIND_LOCALIP_NULL, BIND_LOCALPORT_NULL, hostname, port, timeout, cancel_flag, hWnd, ret_ip);
}

// TCP connection function
//SOCK* TcpConnectEx3(char* hostname, UINT port, UINT timeout, bool* cancel_flag, void* hWnd, IP* ret_ip)
SOCK *BindTcpConnectEx3(IP *localIP, UINT localport, char *hostname, UINT port, UINT timeout, bool *cancel_flag, void *hWnd, IP *ret_ip) {
	//	return ConnectEx4(hostname, port, timeout, cancel_flag, true, ret_ip);
	return BindConnectEx4(localIP, localport, hostname, port, timeout, cancel_flag, true, ret_ip);
}

// Connect with TCP/IP
//SOCK *TcpIpConnectEx(char *hostname, UINT port, bool *cancel_flag, void *hWnd, IP *ret_ip)
SOCK *BindTcpIpConnectEx(IP *localIP, UINT localport, char *hostname, UINT port, bool *cancel_flag, void *hWnd, IP *ret_ip) {
	SOCK *s = NULL;
	// Validate arguments
	if (hostname == NULL || port == 0)
		return NULL;

	//	s = TcpConnectEx3(hostname, port, 0, cancel_flag, hWnd, ret_ip);
	s = BindTcpConnectEx3(localIP, localport, hostname, port, 0, cancel_flag, hWnd, ret_ip);
	if (s == NULL)
		return NULL;

	return s;
}

// Protocol routine initialization
void InitProtocol() {
}

// Release the protocol routine
void FreeProtocol() {
}

// Create a Hello packet
PACK *PackHello(void *random, UINT ver, UINT build, char *server_str) {
	PACK *p;
	// Validate arguments
	if (random == NULL || server_str == NULL)
		return NULL;

	p = NewPack();
	PackAddStr(p, "hello", server_str);
	PackAddInt(p, "version", ver);
	PackAddInt(p, "build", build);
	PackAddData(p, "random", random, SHA1_SIZE);

	return p;
}

// Interpret the Hello packet
bool GetHello(PACK *p, void *random, UINT *ver, UINT *build, char *server_str, UINT server_str_size) {
	// Validate arguments
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

// Get the authentication method from PACK
UINT GetAuthTypeFromPack(PACK *p) {
	// Validate arguments
	if (p == NULL)
		return 0;

	return PackGetInt(p, "authtype");
}

// Get the HUB name and the user name from the PACK
bool GetHubnameAndUsernameFromPack(PACK *p, char *username, UINT username_size,
                                   char *hubname, UINT hubname_size) {
	// Validate arguments
	if (p == NULL || username == NULL || hubname == NULL)
		return false;

	if (PackGetStr(p, "username", username, username_size) == false)
		return false;
	if (PackGetStr(p, "hubname", hubname, hubname_size) == false)
		return false;
	return true;
}

// Get the protocol from PACK
UINT GetProtocolFromPack(PACK *p) {
	// Validate arguments
	if (p == NULL)
		return 0;

#if 0
	return PackGetInt(p, "protocol");
#else
	// Limit to the TCP protocol in the current version
	return CONNECTION_TCP;
#endif
}

// Get the method from the PACK
bool GetMethodFromPack(PACK *p, char *method, UINT size) {
	// Validate arguments
	if (p == NULL || method == NULL || size == 0)
		return false;

	return PackGetStr(p, "method", method, size);
}

// Generate a packet of certificate authentication login
PACK *PackLoginWithCert(char *hubname, char *username, X *x, void *sign, UINT sign_size) {
	PACK *p;
	BUF *b;
	// Validate arguments
	if (hubname == NULL || username == NULL)
		return NULL;

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
PACK *PackLoginWithPlainPassword(char *hubname, char *username, void *plain_password) {
	PACK *p;
	// Validate arguments
	if (hubname == NULL || username == NULL)
		return NULL;

	p = NewPack();
	PackAddStr(p, "method", "login");
	PackAddStr(p, "hubname", hubname);
	PackAddStr(p, "username", username);
	PackAddInt(p, "authtype", CLIENT_AUTHTYPE_PLAIN_PASSWORD);
	PackAddStr(p, "plain_password", plain_password);

	return p;
}

// Create a packet of password authentication login
PACK *PackLoginWithPassword(char *hubname, char *username, void *secure_password) {
	PACK *p;
	// Validate arguments
	if (hubname == NULL || username == NULL)
		return NULL;

	p = NewPack();
	PackAddStr(p, "method", "login");
	PackAddStr(p, "hubname", hubname);
	PackAddStr(p, "username", username);
	PackAddInt(p, "authtype", CLIENT_AUTHTYPE_PASSWORD);
	PackAddData(p, "secure_password", secure_password, SHA1_SIZE);

	return p;
}

// Create a packet for anonymous login
PACK *PackLoginWithAnonymous(char *hubname, char *username) {
	PACK *p;
	// Validate arguments
	if (hubname == NULL || username == NULL)
		return NULL;

	p = NewPack();
	PackAddStr(p, "method", "login");
	PackAddStr(p, "hubname", hubname);
	PackAddStr(p, "username", username);
	PackAddInt(p, "authtype", CLIENT_AUTHTYPE_ANONYMOUS);

	return p;
}

// Create a packet for the additional connection
PACK *PackAdditionalConnect(UCHAR *session_key) {
	PACK *p;
	// Validate arguments
	if (session_key == NULL)
		return NULL;

	p = NewPack();
	PackAddStr(p, "method", "additional_connect");
	PackAddData(p, "session_key", session_key, SHA1_SIZE);

	return p;
}
