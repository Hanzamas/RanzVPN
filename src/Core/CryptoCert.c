// CryptoCert.c
// Certificates through CryptoAPI: the self-signed ECDSA P-256 certificate on a CNG key, PFX
// import into the CNG key storage provider, and the system certificate stores, where the
// Schannel server certificate is found by its thumbprint (LocalMachine\My)

#include "Core/CryptoInternal.h"

// Certificate encoding of every function here
#define CRYPTO_CERT_ENCODING (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING)

// 100-ns intervals of FILETIME per day
#define CRYPTO_FILETIME_DAY (24ULL * 60 * 60 * 10000000)

// Characters of a key name made by CryptoCertKeyName(): "Ranz-", 32 hex digits and the terminator
#define CRYPTO_KEY_NAME_SIZE 38

// A random key name for a certificate key that the caller does not name
static bool CryptoCertKeyName(wchar_t *name) {
	static const wchar_t hex[] = L"0123456789ABCDEF";
	UCHAR r[16];

	if (CryptoRandom(r, sizeof(r)) == false)
		return false;

	CopyMemory(name, L"Ranz-", 5 * sizeof(wchar_t));
	for (UINT i = 0; i < sizeof(r); i++) {
		name[5 + 2 * i] = hex[r[i] >> 4];
		name[5 + 2 * i + 1] = hex[r[i] & 0x0F];
	}
	name[5 + 2 * sizeof(r)] = 0;

	return true;
}

// One extension of the certificate, encoded by CryptEncodeObjectEx; LocalFree its value
static bool CryptoCertEncodeExtension(CERT_EXTENSION *ext, LPCSTR oid, BOOL critical, LPCSTR struct_type, const void *value) {
	BYTE *data = NULL;
	DWORD size = 0;

	ext->pszObjId = (LPSTR)oid;
	ext->fCritical = critical;
	ext->Value.cbData = 0;
	ext->Value.pbData = NULL;

	if (CryptEncodeObjectEx(X509_ASN_ENCODING, struct_type, value, CRYPT_ENCODE_ALLOC_FLAG, NULL, &data, &size) == false)
		return false;

	ext->Value.cbData = size;
	ext->Value.pbData = data;
	return true;
}

// The SYSTEMTIME of now plus a number of days, which may be negative
static void CryptoCertTime(SYSTEMTIME *st, INT64 days) {
	FILETIME ft;
	ULARGE_INTEGER t;

	GetSystemTimeAsFileTime(&ft);
	t.LowPart = ft.dwLowDateTime;
	t.HighPart = ft.dwHighDateTime;
	t.QuadPart += (ULONGLONG)(days * (INT64)CRYPTO_FILETIME_DAY);
	ft.dwLowDateTime = t.LowPart;
	ft.dwHighDateTime = t.HighPart;
	FileTimeToSystemTime(&ft, st);
}

// The self-signed certificate of a finalized ECDSA P-256 key of the software KSP
static PCCERT_CONTEXT CryptoCertSelfSign(NCRYPT_KEY_HANDLE key, const wchar_t *key_name, const wchar_t *subject, const wchar_t *dns_name, UINT days, UINT flags) {
	CERT_NAME_BLOB subject_blob;
	CERT_EXTENSION ext[3];
	DWORD num_ext = 0;
	CRYPT_BIT_BLOB usage;
	BYTE usage_bits = CERT_DIGITAL_SIGNATURE_KEY_USAGE;
	LPSTR eku_oids[2] = {szOID_PKIX_KP_SERVER_AUTH, szOID_PKIX_KP_CLIENT_AUTH};
	CERT_ENHKEY_USAGE eku;
	CERT_ALT_NAME_ENTRY alt_entry;
	CERT_ALT_NAME_INFO alt;
	CRYPT_KEY_PROV_INFO prov_info;
	CRYPT_ALGORITHM_IDENTIFIER sig_alg;
	CERT_EXTENSIONS exts;
	SYSTEMTIME start, end;
	PCCERT_CONTEXT cert = NULL;

	// The subject, which is also the issuer
	subject_blob.cbData = 0;
	if (CertStrToNameW(X509_ASN_ENCODING, subject, CERT_X500_NAME_STR, NULL, NULL, &subject_blob.cbData, NULL) == false || subject_blob.cbData == 0)
		return NULL;
	subject_blob.pbData = (BYTE *)HeapAlloc(GetProcessHeap(), 0, subject_blob.cbData);
	if (subject_blob.pbData == NULL)
		return NULL;
	bool ok = CertStrToNameW(X509_ASN_ENCODING, subject, CERT_X500_NAME_STR, NULL, subject_blob.pbData, &subject_blob.cbData, NULL) != FALSE;

	// Extensions: digitalSignature (critical), server and client authentication, the DNS name
	usage.cbData = 1;
	usage.pbData = &usage_bits;
	usage.cUnusedBits = 7;
	eku.cUsageIdentifier = 2;
	eku.rgpszUsageIdentifier = eku_oids;
	if (ok)
		ok = CryptoCertEncodeExtension(&ext[num_ext++], szOID_KEY_USAGE, TRUE, X509_KEY_USAGE, &usage);
	if (ok)
		ok = CryptoCertEncodeExtension(&ext[num_ext++], szOID_ENHANCED_KEY_USAGE, FALSE, X509_ENHANCED_KEY_USAGE, &eku);
	if (ok && dns_name != NULL && dns_name[0] != 0) {
		alt_entry.dwAltNameChoice = CERT_ALT_NAME_DNS_NAME;
		alt_entry.pwszDNSName = (LPWSTR)dns_name;
		alt.cAltEntry = 1;
		alt.rgAltEntry = &alt_entry;
		ok = CryptoCertEncodeExtension(&ext[num_ext++], szOID_SUBJECT_ALT_NAME2, FALSE, X509_ALTERNATE_NAME, &alt);
	}

	if (ok) {
		// The certificate names its key by provider and container, so CryptAcquireCertificatePrivateKey
		// and Schannel open it again; dwProvType 0 marks a CNG provider
		ZeroMemory(&prov_info, sizeof(prov_info));
		prov_info.pwszContainerName = (LPWSTR)key_name;
		prov_info.pwszProvName = (LPWSTR)MS_KEY_STORAGE_PROVIDER;
		prov_info.dwProvType = 0;
		prov_info.dwFlags = (flags & CRYPTO_MACHINE) ? NCRYPT_MACHINE_KEY_FLAG : 0;

		ZeroMemory(&sig_alg, sizeof(sig_alg));
		sig_alg.pszObjId = szOID_ECDSA_SHA256;

		exts.cExtension = num_ext;
		exts.rgExtension = ext;

		// Valid from a day ago, so that a peer whose clock is a little behind accepts it
		CryptoCertTime(&start, -1);
		CryptoCertTime(&end, days);

		cert = CertCreateSelfSignCertificate(key, &subject_blob, 0, &prov_info, &sig_alg, &start, &end, &exts);
	}

	for (DWORD i = 0; i < num_ext; i++)
		LocalFree(ext[i].Value.pbData);
	HeapFree(GetProcessHeap(), 0, subject_blob.pbData);

	return cert;
}

PCCERT_CONTEXT CryptoCertCreateSelfSigned(const wchar_t *subject, const wchar_t *dns_name, const wchar_t *key_name, UINT days, UINT flags) {
	wchar_t random_name[CRYPTO_KEY_NAME_SIZE];
	NCRYPT_PROV_HANDLE prov = 0;
	NCRYPT_KEY_HANDLE key = 0;
	PCCERT_CONTEXT cert = NULL;

	if (subject == NULL || subject[0] == 0 || days == 0)
		return NULL;

	if (key_name == NULL) {
		if (CryptoCertKeyName(random_name) == false)
			return NULL;
		key_name = random_name;
	}

	if (NCryptOpenStorageProvider(&prov, MS_KEY_STORAGE_PROVIDER, 0) != ERROR_SUCCESS)
		return NULL;

	// A new persisted ECDSA P-256 key, not exportable (the default export policy); an existing
	// key of that name is an error, it may belong to another certificate
	if (NCryptCreatePersistedKey(prov, &key, NCRYPT_ECDSA_P256_ALGORITHM, key_name, 0, (flags & CRYPTO_MACHINE) ? NCRYPT_MACHINE_KEY_FLAG : 0) == ERROR_SUCCESS) {
		if (NCryptFinalizeKey(key, NCRYPT_SILENT_FLAG) == ERROR_SUCCESS) {
			cert = CryptoCertSelfSign(key, key_name, subject, dns_name, days, flags);

			// Without a certificate the stored key goes; NCryptDeleteKey frees the handle when it succeeds
			if (cert == NULL && NCryptDeleteKey(key, NCRYPT_SILENT_FLAG) == ERROR_SUCCESS)
				key = 0;
		}

		if (key != 0)
			NCryptFreeObject(key);
	}

	NCryptFreeObject(prov);

	return cert;
}

PCCERT_CONTEXT CryptoCertImportPfx(const void *pfx, UINT size, const wchar_t *password, UINT flags) {
	CRYPT_DATA_BLOB blob;
	PCCERT_CONTEXT found = NULL;

	if (pfx == NULL || size == 0)
		return NULL;

	blob.cbData = size;
	blob.pbData = (BYTE *)pfx;
	if (PFXIsPFXBlob(&blob) == false)
		return NULL;

	// The private keys go into the software KSP, persisted, not exportable. OpenSSL 3 writes
	// PBES2 (PBKDF2 with HMAC-SHA256, AES-256-CBC) and a SHA-256 MAC by default, which Windows
	// 10 1709 and later import.
	DWORD import_flags = PKCS12_ALWAYS_CNG_KSP | ((flags & CRYPTO_MACHINE) ? CRYPT_MACHINE_KEYSET : CRYPT_USER_KEYSET);
	HCERTSTORE store = PFXImportCertStore(&blob, password != NULL ? password : L"", import_flags);
	if (store == NULL)
		return NULL;

	PCCERT_CONTEXT c = NULL;
	while ((c = CertEnumCertificatesInStore(store, c)) != NULL) {
		DWORD prop_size = 0;
		if (CertGetCertificateContextProperty(c, CERT_KEY_PROV_INFO_PROP_ID, NULL, &prop_size)) {
			found = CertDuplicateCertificateContext(c);
			CertFreeCertificateContext(c);
			break;
		}
	}

	CertCloseStore(store, 0);

	return found;
}

bool CryptoCertVerifySelfSigned(PCCERT_CONTEXT cert) {
	if (cert == NULL)
		return false;

	if (CertCompareCertificateName(CRYPTO_CERT_ENCODING, &cert->pCertInfo->Issuer, &cert->pCertInfo->Subject) == false)
		return false;

	return CryptVerifyCertificateSignatureEx(0, X509_ASN_ENCODING, CRYPT_VERIFY_CERT_SIGN_SUBJECT_CERT, (void *)cert,
	                                         CRYPT_VERIFY_CERT_SIGN_ISSUER_CERT, (void *)cert, 0, NULL) != FALSE;
}

bool CryptoCertHasKspKey(PCCERT_CONTEXT cert) {
	HCRYPTPROV_OR_NCRYPT_KEY_HANDLE key = 0;
	DWORD key_spec = 0;
	BOOL must_free = FALSE;

	if (cert == NULL)
		return false;

	// ONLY_NCRYPT refuses a key of a legacy CryptoAPI provider (CSP)
	if (CryptAcquireCertificatePrivateKey(cert, CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG | CRYPT_ACQUIRE_SILENT_FLAG, NULL, &key, &key_spec, &must_free) == false)
		return false;

	if (must_free)
		NCryptFreeObject(key);

	return key_spec == CERT_NCRYPT_KEY_SPEC;
}

bool CryptoCertThumbprint(PCCERT_CONTEXT cert, UCHAR *thumbprint) {
	DWORD size = CRYPTO_THUMBPRINT_SIZE;

	if (thumbprint == NULL)
		return false;

	if (cert != NULL && CertGetCertificateContextProperty(cert, CERT_SHA1_HASH_PROP_ID, thumbprint, &size) && size == CRYPTO_THUMBPRINT_SIZE)
		return true;

	ZeroMemory(thumbprint, CRYPTO_THUMBPRINT_SIZE);
	return false;
}

bool CryptoCertThumbprintStr(PCCERT_CONTEXT cert, char *str, UINT size) {
	static const char hex[] = "0123456789ABCDEF";
	UCHAR t[CRYPTO_THUMBPRINT_SIZE];

	if (str == NULL || size < 2 * CRYPTO_THUMBPRINT_SIZE + 1) {
		if (str != NULL && size != 0)
			str[0] = 0;
		return false;
	}

	if (CryptoCertThumbprint(cert, t) == false) {
		str[0] = 0;
		return false;
	}

	for (UINT i = 0; i < CRYPTO_THUMBPRINT_SIZE; i++) {
		str[2 * i] = hex[t[i] >> 4];
		str[2 * i + 1] = hex[t[i] & 0x0F];
	}
	str[2 * CRYPTO_THUMBPRINT_SIZE] = 0;

	return true;
}

// A thumbprint string as certlm.msc and PowerShell show it: 40 hex digits, any case, with spaces
// or colons between them
static bool CryptoCertParseThumbprint(UCHAR *thumbprint, const char *str) {
	UINT n = 0;

	if (str == NULL)
		return false;

	for (const char *p = str; *p != 0; p++) {
		char c = *p;
		UINT v;

		if (c == ' ' || c == ':')
			continue;
		if (c >= '0' && c <= '9')
			v = (UINT)(c - '0');
		else if (c >= 'a' && c <= 'f')
			v = (UINT)(c - 'a' + 10);
		else if (c >= 'A' && c <= 'F')
			v = (UINT)(c - 'A' + 10);
		else
			return false;

		if (n >= 2 * CRYPTO_THUMBPRINT_SIZE)
			return false;
		if (n % 2 == 0)
			thumbprint[n / 2] = (UCHAR)(v << 4);
		else
			thumbprint[n / 2] |= (UCHAR)v;
		n++;
	}

	return n == 2 * CRYPTO_THUMBPRINT_SIZE;
}

// A system store: LocalMachine or CurrentUser, L"My" when store_name is NULL. An existing store
// only, so that a mistyped name does not create one
static HCERTSTORE CryptoCertOpenStore(const wchar_t *store_name, UINT flags, bool read_only) {
	DWORD open_flags = CERT_STORE_OPEN_EXISTING_FLAG;

	open_flags |= (flags & CRYPTO_MACHINE) ? CERT_SYSTEM_STORE_LOCAL_MACHINE : CERT_SYSTEM_STORE_CURRENT_USER;
	if (read_only)
		open_flags |= CERT_STORE_READONLY_FLAG;

	return CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0, open_flags, store_name != NULL ? store_name : L"My");
}

bool CryptoCertAddToStore(PCCERT_CONTEXT cert, const wchar_t *store_name, UINT flags) {
	bool ok = false;

	if (cert == NULL)
		return false;

	HCERTSTORE store = CryptoCertOpenStore(store_name, flags, false);
	if (store == NULL)
		return false;

	// The store keeps the properties too, CERT_KEY_PROV_INFO_PROP_ID among them, so the copy in
	// the store still finds its key
	if (CertAddCertificateContextToStore(store, cert, CERT_STORE_ADD_REPLACE_EXISTING, NULL))
		ok = true;

	CertCloseStore(store, 0);

	return ok;
}

PCCERT_CONTEXT CryptoCertFindByThumbprint(const char *thumbprint, const wchar_t *store_name, UINT flags) {
	UCHAR hash[CRYPTO_THUMBPRINT_SIZE];
	CRYPT_HASH_BLOB blob;

	if (CryptoCertParseThumbprint(hash, thumbprint) == false)
		return NULL;

	HCERTSTORE store = CryptoCertOpenStore(store_name, flags, true);
	if (store == NULL)
		return NULL;

	blob.cbData = sizeof(hash);
	blob.pbData = hash;

	// The context holds a reference to its store, which stays open until the context is freed
	PCCERT_CONTEXT found = CertFindCertificateInStore(store, CRYPTO_CERT_ENCODING, 0, CERT_FIND_SHA1_HASH, &blob, NULL);

	CertCloseStore(store, 0);

	return found;
}

bool CryptoCertRemoveFromStore(const char *thumbprint, const wchar_t *store_name, UINT flags) {
	UCHAR hash[CRYPTO_THUMBPRINT_SIZE];
	CRYPT_HASH_BLOB blob;
	bool ok = false;

	if (CryptoCertParseThumbprint(hash, thumbprint) == false)
		return false;

	HCERTSTORE store = CryptoCertOpenStore(store_name, flags, false);
	if (store == NULL)
		return false;

	blob.cbData = sizeof(hash);
	blob.pbData = hash;

	// CertDeleteCertificateFromStore frees the context it is given, also on failure
	PCCERT_CONTEXT found = CertFindCertificateInStore(store, CRYPTO_CERT_ENCODING, 0, CERT_FIND_SHA1_HASH, &blob, NULL);
	if (found != NULL && CertDeleteCertificateFromStore(found))
		ok = true;

	CertCloseStore(store, 0);

	return ok;
}

bool CryptoCertDeleteKey(PCCERT_CONTEXT cert) {
	HCRYPTPROV_OR_NCRYPT_KEY_HANDLE key = 0;
	DWORD key_spec = 0;
	BOOL must_free = FALSE;

	if (cert == NULL)
		return false;

	if (CryptAcquireCertificatePrivateKey(cert, CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG | CRYPT_ACQUIRE_SILENT_FLAG, NULL, &key, &key_spec, &must_free) == false)
		return false;

	// A handle the certificate context caches (must_free FALSE) is not ours to delete
	if (key_spec != CERT_NCRYPT_KEY_SPEC || must_free == FALSE) {
		if (must_free)
			NCryptFreeObject(key);
		return false;
	}

	// NCryptDeleteKey frees the handle when it succeeds
	if (NCryptDeleteKey(key, NCRYPT_SILENT_FLAG) == ERROR_SUCCESS)
		return true;

	NCryptFreeObject(key);
	return false;
}

void CryptoCertFree(PCCERT_CONTEXT cert) {
	if (cert != NULL)
		CertFreeCertificateContext(cert);
}
