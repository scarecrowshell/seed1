#ifndef SIGN_SIGNER_H
#define SIGN_SIGNER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Keypair structure using OpenSSL EVP */
typedef struct {
    uint8_t pub[32];
    uint8_t priv[64];
} ed25519_keypair_t;

/* Generate Ed25519 keypair */
int ed25519_generate_keypair(ed25519_keypair_t *kp);

/* Sign message using Ed25519 */
int ed25519_sign(
    const ed25519_keypair_t *kp,
    const uint8_t *msg, size_t msg_len,
    uint8_t signature[64]
);

/* Verify Ed25519 signature */
int ed25519_verify(
    const uint8_t *pub, const uint8_t *msg, size_t msg_len,
    const uint8_t signature[64]
);

/* Format signature block (signature + signer_id + timestamp) */
int format_signature_block(
    const uint8_t signature[64],
    const char *signer_id,
    uint64_t timestamp,
    uint8_t **out_block,
    size_t *out_len
);

#ifdef __cplusplus
}
#endif

#endif /* SIGN_SIGNER_H */
