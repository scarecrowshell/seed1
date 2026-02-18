/* sign/hasher.c
*
* Deterministic hashing helpers (SHA-256 + canonical bytes input rules)
* Option B: runtime logging on success/failure
*/

#include "hasher.h"

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>

#include <openssl/evp.h>
#include <openssl/err.h>

/* Startup proof-of-life constructor for hasher */
__attribute__((constructor))
static void hasher_self_test(void) {
    fprintf(stderr, "[HASHER] module loaded (constructor OK)\n");
}

/* print bytes as hex to provided FILE* */
static void hex_print(const unsigned char *buf, size_t len, FILE *out) {
    for (size_t i = 0; i < len; ++i) fprintf(out, "%02x", buf[i]);
}

/* Canonicalize bytes implementation with logging */
int canonicalize_bytes(const unsigned char *in, size_t in_len, unsigned char **out, size_t *out_len) {
    if (!in || !out || !out_len) {
        fprintf(stderr, "[HASHER] canonicalize_bytes: invalid arguments\n");
        return 1;
    }

    unsigned char *buf = (unsigned char *)malloc(in_len + 1);
    if (!buf) {
        fprintf(stderr, "[HASHER] canonicalize_bytes: malloc failed\n");
        return 2;
    }

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
                buf[wi++] = ' ';
            }
            in_space = 0;
            buf[wi++] = c;
        }
    }

    /* trim trailing space if present */
    if (wi > 0 && buf[wi - 1] == ' ') wi--;

    buf[wi] = 0;
    *out = buf;
    *out_len = wi;

    fprintf(stderr, "[HASHER] canonicalize_bytes: input=%zu -> canonical=%zu bytes\n", in_len, wi);
    return 0;
}

/* Compute SHA-256 with logging */
int sha256_hash(const unsigned char *data, size_t data_len, unsigned char out_hash[32]) {
    if (!data || !out_hash) {
        fprintf(stderr, "[HASHER] sha256_hash: invalid arguments\n");
        return 1;
    }

    int rc = 1;
    EVP_MD_CTX *mdctx = NULL;
    unsigned int outlen = 0;

    mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        fprintf(stderr, "[HASHER] sha256_hash: EVP_MD_CTX_new failed\n");
        return 2;
    }

    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) {
        unsigned long e = ERR_get_error();
        fprintf(stderr, "[HASHER] sha256_hash: DigestInit failed: %s\n", ERR_error_string(e, NULL));
        goto done;
    }
    if (EVP_DigestUpdate(mdctx, data, data_len) != 1) {
        unsigned long e = ERR_get_error();
        fprintf(stderr, "[HASHER] sha256_hash: DigestUpdate failed: %s\n", ERR_error_string(e, NULL));
        goto done;
    }
    if (EVP_DigestFinal_ex(mdctx, out_hash, &outlen) != 1) {
        unsigned long e = ERR_get_error();
        fprintf(stderr, "[HASHER] sha256_hash: DigestFinal failed: %s\n", ERR_error_string(e, NULL));
        goto done;
    }
    if (outlen != 32) {
        fprintf(stderr, "[HASHER] sha256_hash: unexpected outlen=%u\n", outlen);
        rc = 6;
        goto done;
    }

    rc = 0;
    fprintf(stderr, "[HASHER] sha256_hash: input=%zu bytes -> hash=", data_len);
    hex_print(out_hash, 32, stderr);
    fprintf(stderr, "\n");

done:
    if (mdctx) EVP_MD_CTX_free(mdctx);
    return rc;
}

/* Deterministic hash: canonicalize then sha256 with detailed logging */
int deterministic_hash(const unsigned char *in, size_t in_len, unsigned char out_hash[32]) {
    if (!in || !out_hash) {
        fprintf(stderr, "[HASHER] deterministic_hash: invalid arguments\n");
        return 1;
    }

    unsigned char *canon = NULL;
    size_t canon_len = 0;
    int rc = 1;

    if (canonicalize_bytes(in, in_len, &canon, &canon_len) != 0) {
        fprintf(stderr, "[HASHER] deterministic_hash: canonicalization FAILED\n");
        rc = 2;
        goto cleanup;
    }

    if (sha256_hash(canon, canon_len, out_hash) != 0) {
        fprintf(stderr, "[HASHER] deterministic_hash: sha256 FAILED\n");
        rc = 3;
        goto cleanup;
    }

    fprintf(stderr, "[HASHER] deterministic_hash: SUCCESS (input=%zu canonical=%zu)\n", in_len, canon_len);
    rc = 0;

cleanup:
    if (canon) free(canon);
    return rc;
}
