#include "Proxy.h"

#include "DNS.h"
#include "Memory.h"
#include "Str.h"

// SOCKS5: RFC 1928; username/password authentication: RFC 1929
#define SOCKS5_VERSION                 5
#define SOCKS5_METHOD_NONE             0x00
#define SOCKS5_METHOD_USERPASS         0x02
#define SOCKS5_METHOD_NO_ACCEPTABLE    0xFF
#define SOCKS5_USERPASS_VERSION        1
#define SOCKS5_CMD_CONNECT             1
#define SOCKS5_ATYP_IPV4               1
#define SOCKS5_ATYP_DOMAINNAME         3
#define SOCKS5_ATYP_IPV6               4
#define SOCKS5_REP_SUCCEEDED           0
#define SOCKS5_REP_NETWORK_UNREACHABLE 3
#define SOCKS5_REP_HOST_UNREACHABLE    4
#define SOCKS5_REP_CONNECTION_REFUSED  5

// SOCKS4
#define SOCKS4_VERSION              4
#define SOCKS4_CMD_CONNECT          1
#define SOCKS4_REPLY_VERSION        0
#define SOCKS4_REPLY_GRANTED        90
#define SOCKS4_REPLY_REJECTED_IDENT 93

// HTTP CONNECT on the connected socket s. PROXY_ERROR_SUCCESS when the proxy answered 2xx.
static UINT ProxyHttpHandshake(SOCK *s, PROXY_PARAM_IN *in, volatile bool *cancel_flag) {
	bool use_auth = false;
	char target_hostname[MAX_HOST_NAME_LEN + 1];
	char target_hostname_port[MAX_SIZE];

	if ((IsEmptyStr(in->Username) || IsEmptyStr(in->Password)) == false) {
		use_auth = true;
	}

	Zero(target_hostname, sizeof(target_hostname));
	StrCpy(target_hostname, sizeof(target_hostname), in->TargetHostname);

	for (UINT i = 0; i < StrLen(target_hostname); ++i) {
		if (target_hostname[i] == '/') {
			target_hostname[i] = 0;
		}
	}

	if (IsStrIPv6Address(target_hostname)) {
		IP ip;
		char iptmp[MAX_PATH];

		StrToIP(&ip, target_hostname);
		IPToStr(iptmp, sizeof(iptmp), &ip);

		Format(target_hostname_port, sizeof(target_hostname_port), "[%s]:%hu", iptmp, in->TargetPort);
	} else {
		Format(target_hostname_port, sizeof(target_hostname_port), "%s:%hu", target_hostname, in->TargetPort);
	}

	HTTP_HEADER *h = NewHttpHeader("CONNECT", target_hostname_port, "HTTP/1.0");

	if (IsEmptyStr(in->HttpCustomHeader) == false) {
		TOKEN_LIST *tokens = ParseToken(in->HttpCustomHeader, "\r\n");
		if (tokens != NULL) {
			for (UINT i = 0; i < tokens->NumTokens; i++) {
				AddHttpValueStr(h, tokens->Token[i]);
			}

			FreeToken(tokens);
		}
	}

	if (GetHttpValue(h, "User-Agent") == NULL) {
		AddHttpValue(h, NewHttpValue("User-Agent", IsEmptyStr(in->HttpUserAgent) ? DEFAULT_USER_AGENT : in->HttpUserAgent));
	}

	if (GetHttpValue(h, "Host") == NULL) {
		AddHttpValue(h, NewHttpValue("Host", target_hostname));
	}

	if (GetHttpValue(h, "Content-Length") == NULL) {
		AddHttpValue(h, NewHttpValue("Content-Length", "0"));
	}

	if (GetHttpValue(h, "Proxy-Connection") == NULL) {
		AddHttpValue(h, NewHttpValue("Proxy-Connection", "Keep-Alive"));
	}

	if (GetHttpValue(h, "Pragma") == NULL) {
		AddHttpValue(h, NewHttpValue("Pragma", "no-cache"));
	}

	if (use_auth && GetHttpValue(h, "Proxy-Authorization") == NULL) {
		char auth_str[MAX_SIZE * 2];
		Format(auth_str, sizeof(auth_str), "%s:%s", in->Username, in->Password);

		char *base64 = Base64FromBin(NULL, auth_str, StrLen(auth_str));
		Format(auth_str, sizeof(auth_str), "Basic %s", base64);
		Free(base64);

		AddHttpValue(h, NewHttpValue("Proxy-Authorization", auth_str));
	}

	bool ok = SendHttpHeader(s, h);

	FreeHttpHeader(h);

	if (ok == false) {
		return PROXY_ERROR_DISCONNECTED;
	}

	if (*cancel_flag) {
		return PROXY_ERROR_CANCELED;
	}

	h = RecvHttpHeader(s);
	if (h == NULL) {
		return PROXY_ERROR_GENERIC;
	}

	UINT code = 0;
	if (StrLen(h->Method) == 8) {
		if (Cmp(h->Method, "HTTP/1.", 7) == 0) {
			code = ToInt(h->Target);
		}
	}
	FreeHttpHeader(h);

	switch (code) {
	case 401:
	case 403:
	case 407:
		return PROXY_ERROR_AUTHENTICATION;

	default:
		if ((code / 100) == 2) {
			return PROXY_ERROR_SUCCESS;
		}

		return PROXY_ERROR_GENERIC;
	}
}

// SOCKS5 CONNECT on the connected socket s, using the BUF b for the requests.
// PROXY_ERROR_SUCCESS when the proxy reported the connection made.
static UINT ProxySocks5HandshakeBuf(SOCK *s, const PROXY_PARAM_IN *in, BUF *b) {
	UCHAR recv_buf[2], reply[4], tmp;
	// The rest of the reply: a domain name of up to 255 bytes and the port
	UCHAR bnd[255 + 2];
	UINT bnd_size;
	bool atyp_known = true;
	IP target_ip;

	// +----+----------+----------+
	// |VER | NMETHODS | METHODS  |
	// +----+----------+----------+
	// | 1  |    1     | 1 to 255 |
	// +----+----------+----------+
	//
	// X'00'			NO AUTHENTICATION REQUIRED
	// X'01'			GSSAPI
	// X'02'			USERNAME/PASSWORD
	// X'03' to X'7F'	IANA ASSIGNED
	// X'80' to X'FE'	RESERVED FOR PRIVATE METHODS
	// X'FF'			NO ACCEPTABLE METHOD

	WriteBufChar(b, SOCKS5_VERSION);
	WriteBufChar(b, 2);
	WriteBufChar(b, SOCKS5_METHOD_NONE);
	WriteBufChar(b, SOCKS5_METHOD_USERPASS);

	if (SendAll(s, b->Buf, b->Size, false) == false) {
		return PROXY_ERROR_DISCONNECTED;
	}

	// +----+--------+
	// |VER | METHOD |
	// +----+--------+
	// | 1  |   1    |
	// +----+--------+

	if (RecvAll(s, recv_buf, sizeof(recv_buf), false) == false) {
		return PROXY_ERROR_DISCONNECTED;
	}

	if (recv_buf[0] != SOCKS5_VERSION) {
		return PROXY_ERROR_VERSION;
	}

	ClearBuf(b);

	if (recv_buf[1] == SOCKS5_METHOD_USERPASS) {
		// +----+------+----------+------+----------+
		// |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
		// +----+------+----------+------+----------+
		// | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
		// +----+------+----------+------+----------+

		if (IsEmptyStr(in->Username)) {
			// No user name to send: ULEN cannot be 0
			return PROXY_ERROR_AUTHENTICATION;
		}

		WriteBufChar(b, SOCKS5_USERPASS_VERSION);
		tmp = StrLen(in->Username);
		WriteBufChar(b, tmp);
		WriteBuf(b, in->Username, tmp);
		tmp = StrLen(in->Password);
		WriteBufChar(b, tmp);
		WriteBuf(b, in->Password, tmp);

		bool ok = SendAll(s, b->Buf, b->Size, false);

		// The request holds the plain user name and password
		Zero(b->Buf, b->Size);
		ClearBuf(b);

		if (ok == false) {
			return PROXY_ERROR_DISCONNECTED;
		}

		// +----+--------+
		// |VER | STATUS |
		// +----+--------+
		// | 1  |   1    |
		// +----+--------+

		if (RecvAll(s, recv_buf, sizeof(recv_buf), false) == false) {
			return PROXY_ERROR_DISCONNECTED;
		}

		if (recv_buf[0] != SOCKS5_USERPASS_VERSION) {
			return PROXY_ERROR_VERSION;
		}

		if (recv_buf[1] != 0) {
			return PROXY_ERROR_AUTHENTICATION;
		}
	} else if (recv_buf[1] == SOCKS5_METHOD_NO_ACCEPTABLE) {
		// The proxy accepts neither no authentication nor a user name and password
		return PROXY_ERROR_AUTHENTICATION;
	} else if (recv_buf[1] != SOCKS5_METHOD_NONE) {
		// A method that was not offered
		return PROXY_ERROR_GENERIC;
	}

	// +----+-----+-------+------+----------+----------+
	// |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
	// +----+-----+-------+------+----------+----------+
	// | 1  |  1  | X'00' |  1   | Variable |    2     |
	// +----+-----+-------+------+----------+----------+
	//
	// VER				protocol version: X'05'
	// CMD
	// CONNECT			X'01'
	// BIND				X'02'
	// UDP ASSOCIATE	X'03'
	// RSV				RESERVED
	// ATYP				address type of following address
	// IP V4 address	X'01'
	// DOMAINNAME		X'03'
	// IP V6 address	X'04'
	// DST.ADDR			desired destination address
	// DST.PORT			desired destination port in network octet order

	WriteBufChar(b, SOCKS5_VERSION);
	WriteBufChar(b, SOCKS5_CMD_CONNECT);
	WriteBufChar(b, 0);

	StrToIP(&target_ip, in->TargetHostname);

	if (IsZeroIP(&target_ip)) {
		UCHAR dest_length = StrLen(in->TargetHostname);
		WriteBufChar(b, SOCKS5_ATYP_DOMAINNAME);
		WriteBufChar(b, dest_length);
		WriteBuf(b, in->TargetHostname, dest_length);
	} else {
		if (IsIP6(&target_ip)) {
			WriteBufChar(b, SOCKS5_ATYP_IPV6);
			WriteBuf(b, target_ip.address, sizeof(target_ip.address));
		} else {
			WriteBufChar(b, SOCKS5_ATYP_IPV4);
			WriteBuf(b, IPV4(target_ip.address), IPV4_SIZE);
		}
	}

	USHORT target_port = Endian16(in->TargetPort);
	WriteBuf(b, &target_port, sizeof(target_port));

	if (SendAll(s, b->Buf, b->Size, false) == false) {
		return PROXY_ERROR_DISCONNECTED;
	}

	// +----+-----+-------+------+----------+----------+
	// |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
	// +----+-----+-------+------+----------+----------+
	// | 1  |  1  | X’00’ |  1   | Variable |   2      |
	// +----+-----+-------+------+----------+----------+
	//
	// VER protocol version: X’05’
	// REP Reply field:
	// X’00’	succeeded
	// X’01’	general SOCKS server failure
	// X’02’	connection not allowed by ruleset
	// X’03’	Network unreachable
	// X’04’	Host unreachable
	// X’05’	Connection refused
	// X’06’	TTL expired
	// X’07’	Command not supported
	// X’08’	Address type not supported
	// X’09’	to X’FF’ unassigned

	// The packet sent by the server should always have the same size as the one we sent to it.
	// However, there are some implementations which send fixed values (aside from the first 2 bytes).
	// In order to support such implementations, we read the first 4 bytes in order to know the address type before trying to read the rest of the packet.
	if (RecvAll(s, reply, sizeof(reply), false) == false) {
		return PROXY_ERROR_DISCONNECTED;
	}

	// We receive the rest of the packet by knowing the size according to the address type
	switch (reply[3]) {
	case SOCKS5_ATYP_IPV4:
		bnd_size = IPV4_SIZE + 2;
		break;
	case SOCKS5_ATYP_IPV6:
		bnd_size = 16 + 2;
		break;
	case SOCKS5_ATYP_DOMAINNAME:
		if (RecvAll(s, &tmp, 1, false) == false) {
			return PROXY_ERROR_DISCONNECTED;
		}
		bnd_size = (UINT)tmp + 2; // Hostname length + 2 bytes (port)
		break;
	default:
		// The length of the rest is not known
		bnd_size = 0;
		atyp_known = false;
		break;
	}

	if (bnd_size != 0 && RecvAll(s, bnd, bnd_size, false) == false) {
		return PROXY_ERROR_DISCONNECTED;
	}

	if (reply[0] != SOCKS5_VERSION) {
		return PROXY_ERROR_VERSION;
	}

	switch (reply[1]) {
	case SOCKS5_REP_SUCCEEDED:
		// A success with an unknown address type leaves unread bytes in the stream
		return atyp_known ? PROXY_ERROR_SUCCESS : PROXY_ERROR_GENERIC;
	case SOCKS5_REP_NETWORK_UNREACHABLE:
	case SOCKS5_REP_HOST_UNREACHABLE:
	case SOCKS5_REP_CONNECTION_REFUSED:
		return PROXY_ERROR_TARGET;
	default:
		return PROXY_ERROR_GENERIC;
	}
}

static UINT ProxySocks5Handshake(SOCK *s, const PROXY_PARAM_IN *in) {
	BUF *b = NewBuf();
	UINT ret = ProxySocks5HandshakeBuf(s, in, b);

	FreeBuf(b);

	return ret;
}

// SOCKS4 CONNECT to the IPv4 address target_ip on the connected socket s
static UINT ProxySocks4Handshake(SOCK *s, const PROXY_PARAM_IN *in, IP *target_ip) {
	UCHAR recv_buf[8];

	BUF *b = NewBuf();
	WriteBufChar(b, SOCKS4_VERSION);
	WriteBufChar(b, SOCKS4_CMD_CONNECT);
	USHORT target_port = Endian16(in->TargetPort);
	WriteBuf(b, &target_port, sizeof(target_port));
	WriteBuf(b, IPV4(target_ip->address), IPV4_SIZE);
	WriteBuf(b, in->Username, StrLen(in->Username) + 1);

	bool ok = SendAll(s, b->Buf, b->Size, false);

	FreeBuf(b);

	if (ok == false) {
		return PROXY_ERROR_DISCONNECTED;
	}

	if (RecvAll(s, recv_buf, sizeof(recv_buf), false) == false) {
		return PROXY_ERROR_DISCONNECTED;
	}

	if (recv_buf[0] != SOCKS4_REPLY_VERSION) {
		return PROXY_ERROR_GENERIC;
	}

	switch (recv_buf[1]) {
	case SOCKS4_REPLY_GRANTED:
		return PROXY_ERROR_SUCCESS;
	case SOCKS4_REPLY_REJECTED_IDENT:
		return PROXY_ERROR_AUTHENTICATION;
	default:
		return PROXY_ERROR_TARGET;
	}
}

UINT ProxyConnect(UINT proxy_type, PROXY_PARAM_OUT *out, PROXY_PARAM_IN *in, volatile bool *cancel_flag) {
	bool dummy_cancel_flag = false;
	IP target_ip;
	UINT ret;
	if (out == NULL || in == NULL || in->Port == 0 || in->TargetPort == 0 || IsEmptyStr(in->Hostname) || IsEmptyStr(in->TargetHostname) ||
	    (proxy_type != PROXY_HTTP && proxy_type != PROXY_SOCKS && proxy_type != PROXY_SOCKS5)) {
		return PROXY_ERROR_PARAMETER;
	}

	if (cancel_flag == NULL) {
		cancel_flag = &dummy_cancel_flag;
	} else if (*cancel_flag) {
		return PROXY_ERROR_CANCELED;
	}

	Zero(out, sizeof(PROXY_PARAM_OUT));
	Zero(&target_ip, sizeof(target_ip));

	// Get the IPv4 address of the destination server (SOCKS4 does not support IPv6).
	if (proxy_type == PROXY_SOCKS && GetIP4(&target_ip, in->TargetHostname) == false) {
		return PROXY_ERROR_CONNECTION;
	}

	SOCK *s = BindConnectEx4(in->BindLocalIP, in->BindLocalPort, in->Hostname, in->Port, in->Timeout, (bool *)cancel_flag, &out->ResolvedIp);
	if (s == NULL) {
		return PROXY_ERROR_CONNECTION;
	}

	SetTimeout(s, MIN(PROXY_CONNECTION_TIMEOUT, (in->Timeout == 0 ? INFINITE : in->Timeout)));

	switch (proxy_type) {
	case PROXY_HTTP:
		ret = ProxyHttpHandshake(s, in, cancel_flag);
		break;
	case PROXY_SOCKS:
		ret = ProxySocks4Handshake(s, in, &target_ip);
		break;
	default:
		ret = ProxySocks5Handshake(s, in);
		break;
	}

	if (ret != PROXY_ERROR_SUCCESS) {
		Disconnect(s);
		ReleaseSock(s);
		return ret;
	}

	SetTimeout(s, INFINITE);
	out->Sock = s;

	return PROXY_ERROR_SUCCESS;
}
