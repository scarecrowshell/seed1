/* main_cores/seed_cores/sign/mod.h */
#ifndef SIGN_MOD_H
#define SIGN_MOD_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Compute SHA-256 of data. out_hash must be at least 32 bytes. Returns 0 on success. */
int compute_hash(const unsigned char *data, size_t data_len, unsigned char out_hash[32]);

/* 
* Read input_path, canonicalize contents, compute hash (out_hash), sign with privkey_path.
* On success:
*   *out_sig is allocated with OPENSSL_malloc (free with OPENSSL_free)
*   *out_sig_len contains signature length
* Returns 0 on success, non-zero on failure.
*/
int canonicalize_and_sign(const char *input_path,
  const char *privkey_path,
  unsigned char **out_sig,
  size_t *out_sig_len,
  unsigned char out_hash[32]);

/*
* Verify signature: reads input_path, canonicalizes it, verifies sig using pubkey_path.
* Returns 0 on successful verification, non-zero otherwise.
*/
int verify_signature(const char *input_path,
const char *pubkey_path,
const unsigned char *sig,
size_t sig_len);

#ifdef __cplusplus
}
#endif

#endif /* SIGN_MOD_H */
