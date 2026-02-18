/* sign/hasher.h */
#ifndef SIGN_HASHER_H
#define SIGN_HASHER_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Canonicalize input bytes:
* - Collapses runs of ASCII whitespace (isspace) into a single ASCII space (0x20)
* - Trims leading and trailing whitespace
* - Preserves other bytes verbatim
*
* On success:
*   *out points to malloc'd buffer (caller must free)
*   *out_len is set
* Returns 0 on success, non-zero on failure.
*/
int canonicalize_bytes(const unsigned char *in, size_t in_len, unsigned char **out, size_t *out_len);

/* Compute SHA-256 of data. out_hash must be at least 32 bytes.
* Returns 0 on success, non-zero on failure.
*/
int sha256_hash(const unsigned char *data, size_t data_len, unsigned char out_hash[32]);

/* Deterministic hash: canonicalize then SHA-256. Returns 0 on success. */
int deterministic_hash(const unsigned char *in, size_t in_len, unsigned char out_hash[32]);

#ifdef __cplusplus
}
#endif

#endif /* SIGN_HASHER_H */
