// Encrypt.c
// Encryption and digital certification routine

#include "Mayaqua/Encrypt.h"

#include "Mayaqua/Crypto/Cng.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Kernel.h"
#include "Mayaqua/Mayaqua.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Trace.h"

#include <string.h>

#include <bcrypt.h>

#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/pkcs7.h>
#include <openssl/pkcs12.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/dh.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>
#include <openssl/provider.h>

	#include <intrin.h> // For __cpuid()
