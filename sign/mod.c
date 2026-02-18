                                                            /* main_cores/seed_cores/sign/mod.c */
                                                            #include "mod.h"

                                                            #include <stdio.h>
                                                            #include <stdlib.h>
                                                            #include <string.h>
                                                            #include <ctype.h>
                                                            #include <sys/stat.h>
                                                            #include <errno.h>

                                                            #include <openssl/evp.h>
                                                            #include <openssl/pem.h>
                                                            #include <openssl/err.h>
                                                            #include <openssl/crypto.h> /* for OPENSSL_malloc / OPENSSL_free */


                                                            __attribute__((constructor))
                                                            static void sign_mod_constructor(void) {
                                                                fprintf(stderr, "[sign/mod] module loaded (constructor OK)\n");
                                                            }

                                                            static unsigned char *read_file(const char *path, size_t *out_len) {
                                                                if (!path || !out_len) return NULL;
                                                                *out_len = 0;
                                                                FILE *f = fopen(path, "rb");
                                                                if (!f) return NULL;
                                                                struct stat st;
                                                                if (fstat(fileno(f), &st) == -1) {
                                                                    /* fallback to seeking */
                                                                    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
                                                                    long sz = ftell(f);
                                                                    if (sz < 0) { fclose(f); return NULL; }
                                                                    rewind(f);
                                                                    unsigned char *buf = (unsigned char *)malloc((size_t)sz + 1);
                                                                    if (!buf) { fclose(f); return NULL; }
                                                                    size_t r = fread(buf, 1, (size_t)sz, f);
                                                                    fclose(f);
                                                                    if (r != (size_t)sz) { free(buf); return NULL; }
                                                                    buf[r] = 0;
                                                                    *out_len = r;
                                                                    return buf;
                                                                } else {
                                                                    size_t sz = (size_t)st.st_size;
                                                                    unsigned char *buf = (unsigned char *)malloc(sz + 1);
                                                                    if (!buf) { fclose(f); return NULL; }
                                                                    size_t r = fread(buf, 1, sz, f);
                                                                    fclose(f);
                                                                    if (r != sz) { free(buf); return NULL; }
                                                                    buf[r] = 0;
                                                                    *out_len = r;
                                                                    return buf;
                                                                }
                                                            }

                                                            /* Canonicalize: collapse runs of whitespace into single ASCII space, trim ends.
                                                            Deterministic and simple. */
                                                            static unsigned char *canonicalize(const unsigned char *in, size_t in_len, size_t *out_len) {
                                                                if (!in || !out_len) return NULL;
                                                                /* allocate same size + 1 to be safe */
                                                                unsigned char *out = (unsigned char *)malloc(in_len + 1);
                                                                if (!out) return NULL;
                                                                size_t wi = 0;
                                                                int in_space = 0;
                                                                size_t i = 0;
                                                                /* skip leading whitespace */
                                                                while (i < in_len && isspace((unsigned char)in[i])) ++i;
                                                                for (; i < in_len; ++i) {
                                                                    unsigned char c = in[i];
                                                                    if (isspace(c)) {
                                                                        in_space = 1;
                                                                        continue;
                                                                    } else {
                                                                        if (in_space && wi > 0) {
                                                                            out[wi++] = ' ';
                                                                        }
                                                                        in_space = 0;
                                                                        out[wi++] = c;
                                                                    }
                                                                }
                                                                /* remove trailing space */
                                                                if (wi > 0 && out[wi - 1] == ' ') wi--;
                                                                out[wi] = 0;
                                                                *out_len = wi;
                                                                return out;
                                                            }

                                                            int compute_hash(const unsigned char *data, size_t data_len, unsigned char out_hash[32]) {
                                                                if (!data || !out_hash) return 1;
                                                                int rc = 1;
                                                                EVP_MD_CTX *mdctx = NULL;
                                                                unsigned int outlen = 0;

                                                                mdctx = EVP_MD_CTX_new();
                                                                if (!mdctx) return 2;
                                                                if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) goto done;
                                                                if (EVP_DigestUpdate(mdctx, data, data_len) != 1) goto done;
                                                                if (EVP_DigestFinal_ex(mdctx, out_hash, &outlen) != 1) goto done;
                                                                if (outlen != 32) { rc = 6; goto done; }
                                                                rc = 0;
                                                            done:
                                                                if (mdctx) EVP_MD_CTX_free(mdctx);
                                                                return rc;
                                                            }

                                                            int canonicalize_and_sign(const char *input_path,
                                                                                    const char *privkey_path,
                                                                                    unsigned char **out_sig,
                                                                                    size_t *out_sig_len,
                                                                                    unsigned char out_hash[32]) {
                                                                if (!input_path || !privkey_path || !out_sig || !out_sig_len || !out_hash) return 1;

                                                                int rc = 1;
                                                                unsigned char *raw = NULL;
                                                                size_t raw_len = 0;
                                                                unsigned char *canon = NULL;
                                                                size_t canon_len = 0;
                                                                FILE *kf = NULL;
                                                                EVP_PKEY *pkey = NULL;
                                                                EVP_MD_CTX *mdctx = NULL;

                                                            #if OPENSSL_VERSION_NUMBER < 0x10100000L
                                                                OpenSSL_add_all_algorithms();
                                                                ERR_load_crypto_strings();
                                                            #endif

                                                                raw = read_file(input_path, &raw_len);
                                                                if (!raw) {
                                                                    fprintf(stderr, "sign/mod: failed to read input file '%s' (%s)\n", input_path, strerror(errno));
                                                                    rc = 2; goto cleanup;
                                                                }

                                                                canon = canonicalize(raw, raw_len, &canon_len);
                                                                if (!canon) {
                                                                    fprintf(stderr, "sign/mod: canonicalization failed\n");
                                                                    rc = 3; goto cleanup;
                                                                }

                                                                if ((rc = compute_hash(canon, canon_len, out_hash)) != 0) {
                                                                    fprintf(stderr, "sign/mod: compute_hash failed (%d)\n", rc);
                                                                    goto cleanup;
                                                                }

                                                                kf = fopen(privkey_path, "r");
                                                                if (!kf) {
                                                                    fprintf(stderr, "sign/mod: failed to open private key '%s' (%s)\n", privkey_path, strerror(errno));
                                                                    rc = 4; goto cleanup;
                                                                }

                                                                pkey = PEM_read_PrivateKey(kf, NULL, NULL, NULL);
                                                                fclose(kf);
                                                                kf = NULL;
                                                                if (!pkey) {
                                                                    unsigned long e = ERR_get_error();
                                                                    fprintf(stderr, "sign/mod: PEM_read_PrivateKey failed: %s\n", ERR_error_string(e, NULL));
                                                                    rc = 5; goto cleanup;
                                                                }

                                                                mdctx = EVP_MD_CTX_new();
                                                                if (!mdctx) {
                                                                    fprintf(stderr, "sign/mod: EVP_MD_CTX_new failed\n");
                                                                    rc = 6; goto cleanup;
                                                                }

                                                                if (EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey) != 1) {
                                                                    unsigned long e = ERR_get_error();
                                                                    fprintf(stderr, "sign/mod: DigestSignInit failed: %s\n", ERR_error_string(e, NULL));
                                                                    rc = 7; goto cleanup;
                                                                }

                                                                if (EVP_DigestSignUpdate(mdctx, canon, canon_len) != 1) {
                                                                    fprintf(stderr, "sign/mod: DigestSignUpdate failed\n");
                                                                    rc = 8; goto cleanup;
                                                                }

                                                                size_t siglen = 0;
                                                                if (EVP_DigestSignFinal(mdctx, NULL, &siglen) != 1) {
                                                                    fprintf(stderr, "sign/mod: DigestSignFinal (get len) failed\n");
                                                                    rc = 9; goto cleanup;
                                                                }

                                                                unsigned char *sig = (unsigned char *)OPENSSL_malloc(siglen);
                                                                if (!sig) {
                                                                    fprintf(stderr, "sign/mod: OPENSSL_malloc failed\n");
                                                                    rc = 10; goto cleanup;
                                                                }

                                                                if (EVP_DigestSignFinal(mdctx, sig, &siglen) != 1) {
                                                                    unsigned long e = ERR_get_error();
                                                                    fprintf(stderr, "sign/mod: DigestSignFinal (sign) failed: %s\n", ERR_error_string(e, NULL));
                                                                    OPENSSL_free(sig);
                                                                    rc = 11; goto cleanup;
                                                                }

                                                                *out_sig = sig;
                                                                *out_sig_len = siglen;
                                                                rc = 0;

                                                            cleanup:
                                                                if (mdctx) EVP_MD_CTX_free(mdctx);
                                                                if (pkey) EVP_PKEY_free(pkey);
                                                                if (kf) fclose(kf);
                                                                if (raw) { free(raw); raw = NULL; }
                                                                if (canon) { free(canon); canon = NULL; }

                                                                return rc;
                                                            }

                                                            int verify_signature(const char *input_path,
                                                                                const char *pubkey_path,
                                                                                const unsigned char *sig,
                                                                                size_t sig_len) {
                                                                if (!input_path || !pubkey_path || !sig) return 1;

                                                                int rc = 1;
                                                                unsigned char *raw = NULL;
                                                                size_t raw_len = 0;
                                                                unsigned char *canon = NULL;
                                                                size_t canon_len = 0;
                                                                FILE *kf = NULL;
                                                                EVP_PKEY *pubkey = NULL;
                                                                EVP_MD_CTX *mdctx = NULL;

                                                            #if OPENSSL_VERSION_NUMBER < 0x10100000L
                                                                OpenSSL_add_all_algorithms();
                                                                ERR_load_crypto_strings();
                                                            #endif

                                                                raw = read_file(input_path, &raw_len);
                                                                if (!raw) {
                                                                    fprintf(stderr, "sign/mod: failed to read input file '%s' (%s)\n", input_path, strerror(errno));
                                                                    rc = 2; goto cleanup;
                                                                }

                                                                canon = canonicalize(raw, raw_len, &canon_len);
                                                                if (!canon) {
                                                                    fprintf(stderr, "sign/mod: canonicalization failed\n");
                                                                    rc = 3; goto cleanup;
                                                                }

                                                                kf = fopen(pubkey_path, "r");
                                                                if (!kf) {
                                                                    fprintf(stderr, "sign/mod: failed to open public key '%s' (%s)\n", pubkey_path, strerror(errno));
                                                                    rc = 4; goto cleanup;
                                                                }

                                                                pubkey = PEM_read_PUBKEY(kf, NULL, NULL, NULL);
                                                                fclose(kf);
                                                                kf = NULL;
                                                                if (!pubkey) {
                                                                    unsigned long e = ERR_get_error();
                                                                    fprintf(stderr, "sign/mod: PEM_read_PUBKEY failed: %s\n", ERR_error_string(e, NULL));
                                                                    rc = 5; goto cleanup;
                                                                }

                                                                mdctx = EVP_MD_CTX_new();
                                                                if (!mdctx) {
                                                                    fprintf(stderr, "sign/mod: EVP_MD_CTX_new failed\n");
                                                                    rc = 6; goto cleanup;
                                                                }

                                                                if (EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pubkey) != 1) {
                                                                    unsigned long e = ERR_get_error();
                                                                    fprintf(stderr, "sign/mod: DigestVerifyInit failed: %s\n", ERR_error_string(e, NULL));
                                                                    rc = 7; goto cleanup;
                                                                }

                                                                if (EVP_DigestVerifyUpdate(mdctx, canon, canon_len) != 1) {
                                                                    fprintf(stderr, "sign/mod: DigestVerifyUpdate failed\n");
                                                                    rc = 8; goto cleanup;
                                                                }

                                                                int ok = EVP_DigestVerifyFinal(mdctx, sig, sig_len);
                                                                if (ok == 1) {
                                                                    rc = 0; /* valid */
                                                                } else if (ok == 0) {
                                                                    rc = 9; /* invalid signature */
                                                                } else {
                                                                    unsigned long e = ERR_get_error();
                                                                    fprintf(stderr, "sign/mod: DigestVerifyFinal error: %s\n", ERR_error_string(e, NULL));
                                                                    rc = 10;
                                                                }

                                                            cleanup:
                                                                if (mdctx) EVP_MD_CTX_free(mdctx);
                                                                if (pubkey) EVP_PKEY_free(pubkey);
                                                                if (kf) fclose(kf);
                                                                if (raw) { free(raw); raw = NULL; }
                                                                if (canon) { free(canon); canon = NULL; }
                                                                return rc;
                                                            }
