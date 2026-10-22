// HttpListener.h
// Header of HttpListener.c

#ifndef HTTPLISTENER_H
#define HTTPLISTENER_H

#include "CedarType.h"

#include "Mayaqua/MayaType.h"

// The setting of a server without an HttpListener folder in its configuration: off, on this port
#define HTTP_LISTENER_DEFAULT_PORT 80

// A redirect names no port when an enabled VPN listener has this one
#define HTTP_LISTENER_HTTPS_PORT 443

// Limits of one connection: the request must be complete within the timeout (ms) and within the size; a listener keeps
// at most the given number of connections open and closes the ones over it at once
#define HTTP_LISTENER_TIMEOUT         (10 * 1000)
#define HTTP_LISTENER_MAX_REQUEST     (16 * 1024)
#define HTTP_LISTENER_MAX_CONNECTIONS 256

// ACME HTTP-01 (RFC 8555 section 8.3): the path prefix of a challenge request, the folder of the challenge files (one
// file per token, in the webroot acme_webroot of the data directory), the largest file served and the longest token
#define HTTP_LISTENER_CHALLENGE_PREFIX   "/.well-known/acme-challenge/"
#define HTTP_LISTENER_CHALLENGE_DIR      "$acme_webroot/.well-known/acme-challenge"
#define HTTP_LISTENER_CHALLENGE_MAX_SIZE 1024
#define HTTP_LISTENER_TOKEN_MAX_LEN      255

// The longest Host header value
#define HTTP_LISTENER_HOST_MAX_LEN 255

// Results of HttpListenerParse: the request is complete (or malformed), more bytes may complete it, or it went over the
// limits of the reader and the connection closes without an answer
#define HTTP_LISTENER_PARSE_DONE 0
#define HTTP_LISTENER_PARSE_MORE 1
#define HTTP_LISTENER_PARSE_OVER 2

// The answer of the HTTP listener to one request (HttpListenerRespond)
struct HTTP_LISTENER_RESPONSE {
	UINT Status;    // 200, 301, 400, 404 or 405
	char *Location; // 301: the HTTPS URL of the redirect, else NULL
	BUF *Body;      // 200: the bytes of the challenge file, else NULL
	bool NoBody;    // HEAD: the headers of the body without the body
	bool Challenge; // The request was under the challenge prefix
	char *Token;    // 200: the token of the challenge served, else NULL
};

// The challenge of an ACME token for HttpListenerRespond: its bytes, or NULL when there is none
typedef BUF *(HTTP_CHALLENGE_LOOKUP)(void *param, char *token);

UINT HttpListenerParse(BUF *b, HTTP_HEADER **request);
HTTP_LISTENER_RESPONSE *HttpListenerRespond(HTTP_HEADER *request, HTTP_CHALLENGE_LOOKUP *lookup, void *param, const UINT *ports, UINT num_ports);
BUF *HttpListenerResponseToBuf(const HTTP_LISTENER_RESPONSE *r);
void FreeHttpListenerResponse(HTTP_LISTENER_RESPONSE *r);
void HttpListenerServe(CEDAR *cedar, SOCK *s, UINT port);

#endif
