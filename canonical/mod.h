// canonical/mod.h
#ifndef CANONICAL_MOD_H
#define CANONICAL_MOD_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint8_t *data;
    size_t len;
    int schema_version;
} canonical_bytes_t;

typedef struct {
    int code;
    int schema_version;
    size_t input_bytes;
    size_t output_bytes;
    char message[128];
} canonical_result_t;

int canonical_mod_canonicalize(const char *schema_name,
                               int schema_version,
                               const void *input,
                               size_t input_len,
                               canonical_bytes_t *out,
                               canonical_result_t *result,
                               int verbose);

void canonical_mod_free(canonical_bytes_t *cb);

void mod_run(const char *root_rel);

#ifdef __cplusplus
}
#endif

#endif // CANONICAL_MOD_H
