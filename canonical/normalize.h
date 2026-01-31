#ifndef CANONICAL_NORMALIZE_H
#define CANONICAL_NORMALIZE_H

#include <stddef.h>
#include <stdint.h>
#include "schema.h"
#include "mod.h" /* uses canonical_result_t */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Parse, normalize, and deterministically serialize a seed.manifest v1 JSON input.
 *
 * - input: pointer/length to UTF-8 JSON bytes.
 * - out: allocated buffer with canonical bytes (caller must free()).
 * - outlen: length of buffer.
 * - result: fills status & message.
 *
 * Returns 0 on success, non-zero canonical error codes on failure.
 *
 * NOTE: This implementation targets the seed.manifest v1 schema and entry.v1 child objects.
 */
int normalize_seed_manifest_and_serialize(const char *input,
                                          size_t input_len,
                                          uint8_t **out,
                                          size_t *outlen,
                                          canonical_result_t *result);

#ifdef __cplusplus
}
#endif

#endif // CANONICAL_NORMALIZE_H
