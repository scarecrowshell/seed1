#include "verifier.h"
#include "signer.h"  // to call ed25519_verify
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>

/* --------------------------------------------------------- */
/* constructor: proof-of-life                                */
/* --------------------------------------------------------- */
__attribute__((constructor))
static void verifier_self_test(void) {
    fprintf(stderr, "[VERIFIER] module loaded (constructor OK)\n");
}

/* --------------------------------------------------------- */
/* stub key lookup                                           */
/* --------------------------------------------------------- */
int lookup_signer_pubkey(const char *signer_id, uint8_t pubkey_out[32]) {
    if (!signer_id || !pubkey_out) return 1;

    /* Example: fill dummy public key based on signer_id length */
    for (int i = 0; i < 32; i++) {
        pubkey_out[i] = (uint8_t)((i + strlen(signer_id)) & 0xFF);
    }

    fprintf(stderr, "[VERIFIER] public key for signer '%s' retrieved\n", signer_id);
    return 0;
}

/* --------------------------------------------------------- */
/* signature block verification                               */
/* --------------------------------------------------------- */
int verify_signature_block(
    const uint8_t *signature_block,
    size_t block_len,
    const uint8_t *message,
    size_t msg_len
) {
    if (!signature_block || !message || block_len < (8 + 1 + 64)) {
        fprintf(stderr, "[VERIFIER] invalid signature block\n");
        return 1;
    }

    /* parse timestamp */
    uint64_t timestamp = 0;
    for (int i = 0; i < 8; i++) {
        timestamp <<= 8;
        timestamp |= signature_block[i];
    }

    /* parse signer id */
    size_t sig_offset = 8;
    size_t signer_id_len = block_len - 8 - 64;
    char *signer_id = malloc(signer_id_len + 1);
    if (!signer_id) return 2;
    memcpy(signer_id, signature_block + sig_offset, signer_id_len);
    signer_id[signer_id_len] = '\0';
    sig_offset += signer_id_len;

    /* parse signature */
    const uint8_t *signature = signature_block + sig_offset;

    /* lookup signer public key */
    uint8_t pubkey[32];
    if (lookup_signer_pubkey(signer_id, pubkey) != 0) {
        fprintf(stderr, "[VERIFIER] failed to retrieve pubkey for '%s'\n", signer_id);
        free(signer_id);
        return 3;
    }

    /* verify signature */
    int r = ed25519_verify(pubkey, message, msg_len, signature);
    if (r == 0) {
        fprintf(stderr, "[VERIFIER] signature verified successfully for signer '%s', timestamp=%" PRIu64 "\n",
                signer_id, timestamp);
    } else {
        fprintf(stderr, "[VERIFIER] signature verification FAILED for signer '%s', timestamp=%" PRIu64 "\n",
                signer_id, timestamp);
    }

    free(signer_id);
    return r;
}
