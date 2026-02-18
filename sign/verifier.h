#ifndef SIGN_VERIFIER_H
#define SIGN_VERIFIER_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Verify a signature block
*
* - signature_block: raw block (timestamp + signer_id + signature)
* - block_len: length of block
* - message: original message
* - msg_len: length of original message
*
* Returns 0 on success, nonzero on failure.
*/
int verify_signature_block(
    const uint8_t *signature_block,
    size_t block_len,
    const uint8_t *message,
    size_t msg_len
);

/* Lookup signer public key (stub, replace with real keymgmt integration) */
int lookup_signer_pubkey(
    const char *signer_id,
    uint8_t pubkey_out[32]
);

#ifdef __cplusplus
}
#endif

#endif /* SIGN_VERIFIER_H */
