// Wpc.h
// Header of Wpc.c

#ifndef	WPC_H
#define	WPC_H

#include "Cedar.h"

#include "Mayaqua/Encrypt.h"
#include "Mayaqua/HTTP.h"

#define WPC_HTTP_POST_NAME			"POST"
#define WPC_HTTP_GET_NAME			"GET"
#define WPC_USER_AGENT				DEFAULT_USER_AGENT
#define WPC_TIMEOUT					(15 * 1000)
#define WPC_RECV_BUF_SIZE			64000

struct INTERNET_SETTING
{
	UINT ProxyType;
	char ProxyHostName[MAX_HOST_NAME_LEN + 1];
	UINT ProxyPort;
	char ProxyUsername[MAX_USERNAME_LEN + 1];
	char ProxyPassword[MAX_USERNAME_LEN + 1];
	char CustomHttpHeader[HTTP_CUSTOM_HEADER_MAX_SIZE];
};

struct URL_DATA
{
	bool Secure;
	char HostName[MAX_HOST_NAME_LEN + 1];
	UINT Port;
	char HeaderHostName[MAX_HOST_NAME_LEN + 16];
	char Method[32];
	char Target[MAX_SIZE * 3];
	char Referer[MAX_SIZE * 3];
	char AdditionalHeaderName[128];
	char AdditionalHeaderValue[MAX_SIZE];
	char SniString[MAX_SIZE];
};

typedef bool (WPC_RECV_CALLBACK)(void *param, UINT total_size, UINT current_size, BUF *recv_buf);

bool ParseUrl(URL_DATA *data, char *str, bool is_post, char *referrer);
BUF *HttpRequestEx(URL_DATA *data, INTERNET_SETTING *setting,
				   UINT timeout_connect, UINT timeout_comm,
				   UINT *error_code, bool check_ssl_trust, char *post_data,
				   WPC_RECV_CALLBACK *recv_callback, void *recv_callback_param, void *sha1_cert_hash,
				   bool *cancel, UINT max_recv_size);
BUF *HttpRequestEx2(URL_DATA *data, INTERNET_SETTING *setting,
				   UINT timeout_connect, UINT timeout_comm,
				   UINT *error_code, bool check_ssl_trust, char *post_data,
				   WPC_RECV_CALLBACK *recv_callback, void *recv_callback_param, void *sha1_cert_hash,
				   bool *cancel, UINT max_recv_size, char *header_name, char *header_value);
BUF *HttpRequestEx3(URL_DATA *data, INTERNET_SETTING *setting,
					UINT timeout_connect, UINT timeout_comm,
					UINT *error_code, bool check_ssl_trust, char *post_data,
					WPC_RECV_CALLBACK *recv_callback, void *recv_callback_param, void *sha1_cert_hash, UINT num_hashes,
					bool *cancel, UINT max_recv_size, char *header_name, char *header_value);

#endif	// WPC_H


