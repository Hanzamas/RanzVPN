// controltls.h
// The TLS client of the control stream that two tests of vpntest share: sdntrace.c defines it, firsttest.c uses it

#ifndef	CONTROLTLS_H
#define	CONTROLTLS_H

#include "Core/Transport.h"

// Fills t with the TLS transport of the control stream (SdnTraceTlsInit of sdntrace.c): a TLS 1.3 client on OpenSSL that
// offers the ALPN protocol of the control stream and gives the TLS exporter of the control stream as the Channel binding of
// its streams. The controller's certificate is not checked: the Noise handshake authenticates the controller by its static
// key. It dials only, and it never listens.
void SdnTraceTlsInit(TRANSPORT *t);

#endif	// CONTROLTLS_H
