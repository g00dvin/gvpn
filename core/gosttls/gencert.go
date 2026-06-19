package gosttls

/*
#cgo pkg-config: libssl libcrypto
#cgo CFLAGS: -Wno-deprecated-declarations
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/objects.h>
#include <openssl/engine.h>
#include <stdio.h>
#include <string.h>

// gvpn_gen_gost_selfsigned generates a GOST 2012-256 keypair (via engine e),
// builds a self-signed X509 v3 certificate (CN=cn, SAN DNS:cn, validity days),
// signs it with md_gost12_256, and writes PEM cert and key to the given paths.
// Returns 1 on success, 0 on failure.
static int gvpn_gen_gost_selfsigned(const char *cn, const char *certPath,
                                    const char *keyPath, int days, ENGINE *e) {
    int ok = 0;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    X509 *x = NULL;
    X509_NAME *name = NULL;
    X509_EXTENSION *ext = NULL;
    FILE *fc = NULL, *fk = NULL;
    char san[512];

    int nid = OBJ_txt2nid("gost2012_256");
    if (nid == NID_undef) goto done;
    pctx = EVP_PKEY_CTX_new_id(nid, e);
    if (!pctx) goto done;
    if (EVP_PKEY_keygen_init(pctx) <= 0) goto done;
    if (EVP_PKEY_CTX_ctrl_str(pctx, "paramset", "A") <= 0) goto done;
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) goto done;

    x = X509_new();
    if (!x) goto done;
    X509_set_version(x, 2); // v3
    ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
    X509_gmtime_adj(X509_getm_notBefore(x), 0);
    X509_gmtime_adj(X509_getm_notAfter(x), (long)days * 24L * 3600L);
    if (X509_set_pubkey(x, pkey) != 1) goto done;

    name = X509_get_subject_name(x);
    if (X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
            (const unsigned char *)cn, -1, -1, 0) != 1) goto done;
    if (X509_set_issuer_name(x, name) != 1) goto done; // self-signed

    snprintf(san, sizeof(san), "DNS:%s", cn);
    ext = X509V3_EXT_conf_nid(NULL, NULL, NID_subject_alt_name, san);
    if (!ext) goto done; // a cert without a SAN fails client hostname verification
    if (X509_add_ext(x, ext, -1) != 1) goto done;
    X509_EXTENSION_free(ext);
    ext = NULL;

    {
        const EVP_MD *md = EVP_get_digestbyname("md_gost12_256");
        if (!md) goto done;
        if (X509_sign(x, pkey, md) == 0) goto done;
    }

    fc = fopen(certPath, "wb");
    if (!fc) goto done;
    if (PEM_write_X509(fc, x) != 1) goto done;
    fk = fopen(keyPath, "wb");
    if (!fk) goto done;
    if (PEM_write_PrivateKey(fk, pkey, NULL, NULL, 0, NULL, NULL) != 1) goto done;

    ok = 1;
done:
    if (fc) fclose(fc);
    if (fk) fclose(fk);
    if (ext) X509_EXTENSION_free(ext);
    if (x) X509_free(x);
    if (pkey) EVP_PKEY_free(pkey);
    if (pctx) EVP_PKEY_CTX_free(pctx);
    return ok;
}
*/
import "C"

import (
	"fmt"
	"os"
	"unsafe"
)

// GenerateSelfSignedGOSTCert generates a GOST 2012-256 keypair and a self-signed
// X509 certificate for cn (valid for days), writing PEM cert to certPath and the
// private key to keyPath. The GOST server certificate is pinned by clients (CA
// PEM or fingerprint); it is not part of any public PKI. Requires the gost engine.
func GenerateSelfSignedGOSTCert(cn, certPath, keyPath string, days int) error {
	if err := Init(); err != nil {
		return err
	}
	cCN := C.CString(cn)
	defer C.free(unsafe.Pointer(cCN))
	cCert := C.CString(certPath)
	defer C.free(unsafe.Pointer(cCert))
	cKey := C.CString(keyPath)
	defer C.free(unsafe.Pointer(cKey))

	if C.gvpn_gen_gost_selfsigned(cCN, cCert, cKey, C.int(days), gostEngine) != 1 {
		return fmt.Errorf("gosttls: generate GOST cert: %s", lastError())
	}
	if err := os.Chmod(keyPath, 0o600); err != nil {
		return fmt.Errorf("gosttls: chmod key: %w", err)
	}
	return nil
}
