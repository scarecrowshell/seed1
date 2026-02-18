#include "signer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <openssl/evp.h>
#include <openssl/err.h>

/* --------------------------------------------------------- */
/* constructor: module load proof-of-life                    */
/* --------------------------------------------------------- */
__attribute__((constructor))
static void signer_self_test(void) {
    fprintf(stderr, "[SIGNER] module loaded (constructor OK)\n");
}

/* --------------------------------------------------------- */
/* keypair generation (OpenSSL Ed25519)                      */
/* --------------------------------------------------------- */
int ed25519_generate_keypair(ed25519_keypair_t *kp) {
    if (!kp) return 1;

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    if (!pctx) return 2;

    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen_init(pctx) <= 0) goto err;
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) goto err;

    size_t pub_len = 32, priv_len = 64;
    if (EVP_PKEY_get_raw_public_key(pkey, kp->pub, &pub_len) <= 0) goto err;
    if (EVP_PKEY_get_raw_private_key(pkey, kp->priv, &priv_len) <= 0) goto err;

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);

    fprintf(stderr, "[SIGNER] Ed25519 keypair generated\n");
    return 0;

err:
    if (pkey) EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
    fprintf(stderr, "[SIGNER] keypair generation FAILED\n");
    return 3;
}

/* --------------------------------------------------------- */
/* signing                                                   */
/* --------------------------------------------------------- */
int ed25519_sign(
    const ed25519_keypair_t *kp,
    const uint8_t *msg, size_t msg_len,
    uint8_t signature[64]
) {
    if (!kp || !msg || !signature) return 1;

    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, kp->priv, 64);
    if (!pkey) return 2;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) { EVP_PKEY_free(pkey); return 3; }

    if (EVP_DigestSignInit(ctx, NULL, NULL, NULL, pkey) <= 0) goto err;
    size_t sig_len = 64;
    if (EVP_DigestSign(ctx, signature, &sig_len, msg, msg_len) <= 0) goto err;

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    fprintf(stderr, "[SIGNER] message signed (len=%zu)\n", msg_len);
    return 0;

err:
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    fprintf(stderr, "[SIGNER] signing FAILED\n");
    return 4;
}

/* --------------------------------------------------------- */
/* verification                                              */
/* --------------------------------------------------------- */
int ed25519_verify(
    const uint8_t *pub, const uint8_t *msg, size_t msg_len,
    const uint8_t signature[64]
) {
    if (!pub || !msg || !signature) return 1;

    EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, pub, 32);
    if (!pkey) return 2;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) { EVP_PKEY_free(pkey); return 3; }

    if (EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pkey) <= 0) goto err;
    int r = EVP_DigestVerify(ctx, signature, 64, msg, msg_len);

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    if (r == 1) {
        fprintf(stderr, "[SIGNER] verification PASSED\n");
        return 0;
    } else {
        fprintf(stderr, "[SIGNER] verification FAILED\n");
        return 4;
    }

err:
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    fprintf(stderr, "[SIGNER] verification ERROR\n");
    return 5;
}

/* --------------------------------------------------------- */
/* signature block formatting                                 */
/* --------------------------------------------------------- */
int format_signature_block(
    const uint8_t signature[64],
    const char *signer_id,
    uint64_t timestamp,
    uint8_t **out_block,
    size_t *out_len
) {
    if (!signature || !signer_id || !out_block || !out_len) return 1;

    size_t id_len = strlen(signer_id);
    *out_len = 8 /*timestamp*/ + id_len + 64 /*signature*/;
    *out_block = malloc(*out_len);
    if (!*out_block) return 2;

    uint8_t *p = *out_block;
    for (int i = 7; i >= 0; i--) p[i] = (timestamp >> (8*(7-i))) & 0xFF;
    p += 8;
    memcpy(p, signer_id, id_len);
    p += id_len;
    memcpy(p, signature, 64);

    fprintf(stderr,
        "[SIGNER] signature block formatted: sig=64 bytes id_len=%zu timestamp=%" PRIu64 "\n",
        id_len, timestamp
    );
    return 0;
}
