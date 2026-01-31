// canonical/crypto.c
#define _GNU_SOURCE
#include "mod.h"
#include "schema.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h> /* for access(), R_OK */

/* Public API:
 * int canonical_hash_bytes(const uint8_t *data, size_t len, char out_hex[65]);
 * int canonical_sign_bytes_pem(const uint8_t *data, size_t len,
 *                              const char *privkey_pem_path,
 *                              uint8_t **sig, size_t *siglen,
 *                              canonical_result_t *res);
 * int canonical_verify_bytes_pem(const uint8_t *data, size_t len,
 *                                const uint8_t *sig, size_t siglen,
 *                                const char *pubkey_pem_path);
 */

/* helper: compute SHA-256 hex */
int canonical_hash_bytes(const uint8_t *data, size_t len, char out_hex[65]) {
    if (!out_hex) return -1;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) return -1;
    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) { EVP_MD_CTX_free(mdctx); return -1; }
    if (len > 0 && data) {
        if (EVP_DigestUpdate(mdctx, data, len) != 1) { EVP_MD_CTX_free(mdctx); return -1; }
    }
    if (EVP_DigestFinal_ex(mdctx, digest, &digest_len) != 1) { EVP_MD_CTX_free(mdctx); return -1; }
    EVP_MD_CTX_free(mdctx);
    const char hex[] = "0123456789abcdef";
    for (unsigned int i = 0; i < digest_len; ++i) {
        out_hex[2*i]   = hex[(digest[i] >> 4) & 0xF];
        out_hex[2*i+1] = hex[(digest[i] & 0xF)];
    }
    out_hex[2*digest_len] = '\0';
    return 0;
}

/* helper: load EVP_PKEY from PEM private key file */
static EVP_PKEY *load_private_key_pem(const char *path, canonical_result_t *res) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        if (res) { res->code = CANONICAL_ERR_INTERNAL; snprintf(res->message, sizeof(res->message), "open privkey '%s': %s", path, strerror(errno)); }
        return NULL;
    }
    EVP_PKEY *pkey = PEM_read_PrivateKey(f, NULL, NULL, NULL);
    fclose(f);
    if (!pkey) {
        if (res) { res->code = CANONICAL_ERR_INTERNAL; snprintf(res->message, sizeof(res->message), "PEM_read_PrivateKey failed for %s", path); }
        return NULL;
    }
    return pkey;
}

/* helper: load EVP_PKEY from PEM public key file */
static EVP_PKEY *load_public_key_pem(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    EVP_PKEY *pkey = PEM_read_PUBKEY(f, NULL, NULL, NULL);
    fclose(f);
    return pkey;
}

/* Sign bytes using given private key PEM. Uses EVP_DigestSign with SHA-256.
 * On success returns CANONICAL_OK, sets *sig (malloc'd) and *siglen.
 * canonical_result_t (res) is populated with messages on error/success.
 */
int canonical_sign_bytes_pem(const uint8_t *data, size_t len,
                             const char *privkey_pem_path,
                             uint8_t **sig, size_t *siglen,
                             canonical_result_t *res)
{
    if (!privkey_pem_path || !sig || !siglen || !res) return CANONICAL_ERR_INTERNAL;
    memset(res, 0, sizeof(*res));
    *sig = NULL; *siglen = 0;

    EVP_PKEY *pkey = load_private_key_pem(privkey_pem_path, res);
    if (!pkey) {
        if (res->code == 0) res->code = CANONICAL_ERR_INTERNAL;
        return res->code;
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) { EVP_PKEY_free(pkey); res->code = CANONICAL_ERR_INTERNAL; snprintf(res->message,sizeof(res->message),"EVP_MD_CTX_new failed"); return res->code; }

    if (EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey) != 1) {
        EVP_MD_CTX_free(mdctx); EVP_PKEY_free(pkey);
        res->code = CANONICAL_ERR_INTERNAL; snprintf(res->message,sizeof(res->message),"DigestSignInit failed"); return res->code;
    }

    if (len > 0 && data) {
        if (EVP_DigestSignUpdate(mdctx, data, len) != 1) {
            EVP_MD_CTX_free(mdctx); EVP_PKEY_free(pkey);
            res->code = CANONICAL_ERR_INTERNAL; snprintf(res->message,sizeof(res->message),"DigestSignUpdate failed"); return res->code;
        }
    }

    size_t req = 0;
    if (EVP_DigestSignFinal(mdctx, NULL, &req) != 1) {
        EVP_MD_CTX_free(mdctx); EVP_PKEY_free(pkey);
        res->code = CANONICAL_ERR_INTERNAL; snprintf(res->message,sizeof(res->message),"DigestSignFinal(size) failed"); return res->code;
    }

    uint8_t *buffer = malloc(req);
    if (!buffer) {
        EVP_MD_CTX_free(mdctx); EVP_PKEY_free(pkey);
        res->code = CANONICAL_ERR_INTERNAL; snprintf(res->message,sizeof(res->message),"oom"); return res->code;
    }

    if (EVP_DigestSignFinal(mdctx, buffer, &req) != 1) {
        free(buffer); EVP_MD_CTX_free(mdctx); EVP_PKEY_free(pkey);
        res->code = CANONICAL_ERR_INTERNAL; snprintf(res->message,sizeof(res->message),"DigestSignFinal failed"); return res->code;
    }

    *sig = buffer;
    *siglen = req;
    res->code = CANONICAL_OK;
    snprintf(res->message, sizeof(res->message), "signed using %s", privkey_pem_path);

    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    return CANONICAL_OK;
}

/* Verify signature bytes using given public key PEM. Returns 1 for valid, 0 invalid, negative for error. */
int canonical_verify_bytes_pem(const uint8_t *data, size_t len,
                               const uint8_t *sig, size_t siglen,
                               const char *pubkey_pem_path)
{
    if (!pubkey_pem_path || !sig || siglen == 0) return -1;
    EVP_PKEY *pkey = load_public_key_pem(pubkey_pem_path);
    if (!pkey) return -1;

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) { EVP_PKEY_free(pkey); return -2; }

    if (EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pkey) != 1) {
        EVP_MD_CTX_free(mdctx); EVP_PKEY_free(pkey); return -3;
    }

    if (len > 0 && data) {
        if (EVP_DigestVerifyUpdate(mdctx, data, len) != 1) { EVP_MD_CTX_free(mdctx); EVP_PKEY_free(pkey); return -4; }
    }

    int rc = EVP_DigestVerifyFinal(mdctx, sig, siglen);
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    if (rc == 1) return 1; // valid
    if (rc == 0) return 0; // invalid
    return -5; // error
}

/* ---------------- constructor: auto-check on load ----------------
 * This constructor prints detailed messages and a concise final summary:
 * CRYPTO_SUMMARY: blob=<present|missing> hash=<ok|fail> sign=<ok|skip|fail> verify=<ok|skip|fail>
 */
__attribute__((constructor))
static void canonical_crypto_constructor(void) {
    const char *blob_path = "canonical_blob.bin";
    struct stat st;
    int blob_present = 0;
    int hash_ok = 0;
    int signed_ok = 0;
    int sign_attempted = 0;
    int verify_ok = 0;
    int verify_attempted = 0;

    if (stat(blob_path, &st) != 0) {
        fprintf(stdout, "[crypto] no canonical_blob.bin found; skipping crypto checks\n");
        fprintf(stdout, "CRYPTO_SUMMARY: blob=missing hash=skip sign=skip verify=skip\n");
        return;
    }
    if (st.st_size <= 0) {
        fprintf(stderr, "[crypto] canonical_blob.bin empty; skipping\n");
        fprintf(stdout, "CRYPTO_SUMMARY: blob=empty hash=skip sign=skip verify=skip\n");
        return;
    }

    blob_present = 1;
    FILE *f = fopen(blob_path, "rb");
    if (!f) {
        fprintf(stderr, "[crypto] could not open %s: %s\n", blob_path, strerror(errno));
        fprintf(stdout, "CRYPTO_SUMMARY: blob=present hash=fail sign=skip verify=skip\n");
        return;
    }
    size_t len = (size_t)st.st_size;
    uint8_t *buf = malloc(len);
    if (!buf) { fclose(f); fprintf(stderr, "[crypto] oom reading blob\n"); fprintf(stdout, "CRYPTO_SUMMARY: blob=present hash=fail sign=skip verify=skip\n"); return; }
    size_t r = fread(buf, 1, len, f);
    fclose(f);
    if (r != len) { free(buf); fprintf(stderr, "[crypto] short read of %s\n", blob_path); fprintf(stdout, "CRYPTO_SUMMARY: blob=present hash=fail sign=skip verify=skip\n"); return; }

    char hex[65] = {0};
    if (canonical_hash_bytes(buf, len, hex) != 0) {
        free(buf); fprintf(stderr, "[crypto] hash computation failed\n"); fprintf(stdout, "CRYPTO_SUMMARY: blob=present hash=fail sign=skip verify=skip\n"); return;
    }
    hash_ok = 1;
    fprintf(stdout, "CRYPTO: canonical_blob hash=%s\n", hex);

    /* attempt to sign if signing_key.pem exists */
    const char *sign_path = "signing_key.pem";
    if (access(sign_path, R_OK) == 0) {
        sign_attempted = 1;
        uint8_t *sig = NULL; size_t siglen = 0;
        canonical_result_t res;
        int rc = canonical_sign_bytes_pem(buf, len, sign_path, &sig, &siglen, &res);
        if (rc == CANONICAL_OK) {
            signed_ok = 1;
            /* write signature file (raw bytes) */
            FILE *of = fopen("canonical_blob.sig", "wb");
            if (of) {
                fwrite(sig, 1, siglen, of);
                fclose(of);
                /* also write hex for human reading (best-effort) */
                size_t hlen = siglen * 2;
                if (hlen < 8192) { /* avoid huge stack usage */
                    char *shex = malloc(hlen + 1);
                    if (shex) {
                        const char hexmap[] = "0123456789abcdef";
                        for (size_t i=0;i<siglen;i++) { shex[2*i] = hexmap[(sig[i]>>4)&0xF]; shex[2*i+1] = hexmap[sig[i]&0xF]; }
                        shex[2*siglen] = '\0';
                        FILE *hh = fopen("canonical_blob.sig.hex","w");
                        if (hh) { fprintf(hh, "%s\n", shex); fclose(hh); }
                        free(shex);
                    }
                }
                fprintf(stdout, "CRYPTO: signed with %s sig_len=%zu\n", sign_path, siglen);
            } else {
                fprintf(stderr, "CRYPTO: signing succeeded but could not write canonical_blob.sig\n");
            }
            free(sig);
        } else {
            fprintf(stderr, "CRYPTO: signing failed code=%d msg='%s'\n", res.code, res.message);
        }
    } else {
        fprintf(stdout, "[crypto] no signing_key.pem found; skipping auto-sign\n");
    }

    /* attempt to verify if verifier key + sig are present */
    const char *ver_path = "verifier_key.pem";
    const char *sig_path = "canonical_blob.sig";
    if (access(ver_path, R_OK) == 0 && access(sig_path, R_OK) == 0) {
        verify_attempted = 1;
        struct stat stsig;
        if (stat(sig_path, &stsig) == 0 && stsig.st_size > 0) {
            size_t slen = (size_t)stsig.st_size;
            uint8_t *sbuf = malloc(slen);
            if (sbuf) {
                FILE *sf2 = fopen(sig_path, "rb");
                if (sf2) {
                    size_t rr = fread(sbuf,1,slen, sf2);
                    fclose(sf2);
                    if (rr == slen) {
                        int ok = canonical_verify_bytes_pem(buf, len, sbuf, slen, ver_path);
                        if (ok == 1) {
                            verify_ok = 1;
                            fprintf(stdout, "CRYPTO: verification OK with %s\n", ver_path);
                        } else if (ok == 0) {
                            fprintf(stderr, "CRYPTO: verification FAILED with %s\n", ver_path);
                        } else {
                            fprintf(stderr, "CRYPTO: verification error (%d) with %s\n", ok, ver_path);
                        }
                    } else {
                        fprintf(stderr, "CRYPTO: short read of signature file\n");
                    }
                } else {
                    fprintf(stderr, "CRYPTO: could not open signature file for reading\n");
                }
                free(sbuf);
            } else {
                fprintf(stderr, "CRYPTO: oom allocating sig buffer\n");
            }
        } else {
            fprintf(stdout, "[crypto] signature file missing or empty; skipping verify\n");
        }
    } else {
        if (access(ver_path, R_OK) != 0) fprintf(stdout, "[crypto] no verifier_key.pem found; skipping auto-verify\n");
        if (access(sig_path, R_OK) != 0) fprintf(stdout, "[crypto] no canonical_blob.sig found; skipping auto-verify\n");
    }

    /* Final concise summary */
    fprintf(stdout, "CRYPTO_SUMMARY: blob=%s hash=%s sign=%s verify=%s\n",
            blob_present ? "present" : "missing",
            hash_ok ? "ok" : "fail",
            sign_attempted ? (signed_ok ? "ok" : "fail") : "skip",
            verify_attempted ? (verify_ok ? "ok" : "fail") : "skip"
    );

    free(buf);
}
