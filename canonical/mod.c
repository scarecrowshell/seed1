#include "mod.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---------------------------------------------------------
 * Constructor: runs automatically when seed starts
 * --------------------------------------------------------- */
__attribute__((constructor))
static void canonical_mod_ctor(void) {
    printf("[canonical] module loaded (constructor OK)\n");
}

/* ---------------------------------------------------------
 * Entry point expected by seed.c
 * --------------------------------------------------------- */
void mod_run(const char *root_rel) {
    printf("[canonical] mod_run invoked\n");

    if (root_rel) {
        printf("[canonical] root_rel = %s\n", root_rel);
    } else {
        printf("[canonical] root_rel = (null)\n");
    }

    printf("[canonical] bootstrap complete\n");
}

/* ---------------------------------------------------------
 * Stub canonicalization API (safe no-op for now)
 * --------------------------------------------------------- */
int canonical_mod_canonicalize(const char *schema_name,
                               int schema_version,
                               const void *input,
                               size_t input_len,
                               canonical_bytes_t *out,
                               canonical_result_t *result,
                               int verbose)
{
    if (!out || !result) return -1;

    out->data = NULL;
    out->len = 0;
    out->schema_version = schema_version;

    result->code = 0;
    result->schema_version = schema_version;
    result->input_bytes = input_len;
    result->output_bytes = 0;

    snprintf(result->message,
             sizeof(result->message),
             "canonicalize stub OK (schema=%s v%d)",
             schema_name ? schema_name : "null",
             schema_version);

    if (verbose) {
        printf("[canonical] %s\n", result->message);
    }

    (void)input; /* unused for now */
    return 0;
}

/* ---------------------------------------------------------
 * Free canonical bytes
 * --------------------------------------------------------- */
void canonical_mod_free(canonical_bytes_t *cb) {
    if (!cb) return;
    free(cb->data);
    cb->data = NULL;
    cb->len = 0;
}
