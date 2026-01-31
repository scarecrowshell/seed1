// canonical/serialize.c
// Deterministic wrapper serializer: adds a stable self-describing header
// to a payload and produces canonical bytes suitable for hashing/signing.
//
// API:
//   int canonical_serialize_wrap(const char *schema_name, uint16_t schema_version,
//                                const uint8_t *payload, size_t payload_len,
//                                uint8_t **out, size_t *outlen,
//                                canonical_result_t *res);
//
// Also auto-runs at load time to attempt to serialize manifest.bin and print status.

#define _GNU_SOURCE
#include "mod.h"
#include "schema.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <errno.h>

#define MAGIC "CAN0"   // 4 bytes magic

// Helper: write 16-bit BE
static void write_u16be(uint8_t *b, uint16_t v) {
    b[0] = (v >> 8) & 0xFF;
    b[1] = v & 0xFF;
}
// Helper: write 64-bit BE
static void write_u64be(uint8_t *b, uint64_t v) {
    b[0] = (v >> 56) & 0xFF;
    b[1] = (v >> 48) & 0xFF;
    b[2] = (v >> 40) & 0xFF;
    b[3] = (v >> 32) & 0xFF;
    b[4] = (v >> 24) & 0xFF;
    b[5] = (v >> 16) & 0xFF;
    b[6] = (v >> 8) & 0xFF;
    b[7] = v & 0xFF;
}

// compute sha256 hex
static int compute_sha256_hex_buf(const uint8_t *data, size_t len, char out_hex[65]) {
    if (!out_hex) return -1;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) return -1;
    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) { EVP_MD_CTX_free(mdctx); return -1; }
    if (len > 0) {
        if (EVP_DigestUpdate(mdctx, data, len) != 1) { EVP_MD_CTX_free(mdctx); return -1; }
    }
    if (EVP_DigestFinal_ex(mdctx, digest, &digest_len) != 1) { EVP_MD_CTX_free(mdctx); return -1; }
    EVP_MD_CTX_free(mdctx);
    const char hex[] = "0123456789abcdef";
    for (unsigned int i = 0; i < digest_len; ++i) {
        out_hex[2*i]   = hex[(digest[i] >> 4) & 0xF];
        out_hex[2*i+1] = hex[digest[i] & 0xF];
    }
    out_hex[2*digest_len] = '\0';
    return 0;
}

/*
 * canonical_serialize_wrap:
 *  - schema_name: pointer to C string (must be non-NULL)
 *  - schema_version: numeric version (u16)
 *  - payload: raw bytes (can be NULL with payload_len == 0)
 *  - out: receives malloc'd buffer (caller frees)
 *  - outlen: receives length
 *  - result: fills status and message (optional but recommended)
 *
 * Format:
 *   4 bytes MAGIC ("CAN0")
 *   2 bytes schema_name_len (u16 BE)
 *   N bytes schema_name (UTF-8)
 *   2 bytes schema_version (u16 BE)
 *   8 bytes payload_len (u64 BE)
 *   payload_len bytes payload
 *
 * This is intentionally simple, self-describing, and deterministic.
 */
int canonical_serialize_wrap(const char *schema_name, uint16_t schema_version,
                             const uint8_t *payload, size_t payload_len,
                             uint8_t **out, size_t *outlen,
                             canonical_result_t *result)
{
    if (!schema_name || !out || !outlen || !result) return CANONICAL_ERR_INTERNAL;
    memset(result, 0, sizeof(*result));
    size_t name_len = strlen(schema_name);
    // compute total size
    // MAGIC (4) + name_len_field(2) + name_len + ver(2) + payload_len_field(8) + payload_len
    uint64_t total = 4 + 2 + name_len + 2 + 8 + (uint64_t)payload_len;
    if (total > SIZE_MAX) { result->code = CANONICAL_ERR_INTERNAL; snprintf(result->message,sizeof(result->message),"payload too large"); return result->code; }

    uint8_t *buf = malloc((size_t)total);
    if (!buf) { result->code = CANONICAL_ERR_INTERNAL; snprintf(result->message,sizeof(result->message),"oom"); return result->code; }

    size_t off = 0;
    // MAGIC
    memcpy(buf + off, MAGIC, 4); off += 4;
    // name len
    write_u16be(buf + off, (uint16_t)name_len); off += 2;
    // name bytes
    if (name_len > 0) { memcpy(buf + off, schema_name, name_len); off += name_len; }
    // version
    write_u16be(buf + off, schema_version); off += 2;
    // payload len (u64 BE)
    write_u64be(buf + off, (uint64_t)payload_len); off += 8;
    // payload
    if (payload_len > 0 && payload) { memcpy(buf + off, payload, payload_len); off += payload_len; }

    if (off != total) {
        free(buf);
        result->code = CANONICAL_ERR_INTERNAL;
        snprintf(result->message, sizeof(result->message), "length mismatch");
        return result->code;
    }

    *out = buf;
    *outlen = (size_t)total;
    result->output_bytes = (size_t)total;
    result->schema_version = (int)schema_version;
    result->code = CANONICAL_OK;
    snprintf(result->message, sizeof(result->message), "serialize_wrap OK");

    return CANONICAL_OK;
}

/* ---------- Constructor: auto-run at load time to check serialization ---------- */
/*
 * Behavior:
 * - Try to read "manifest.bin" (produced by normalization). If missing, try "canonical_input.json" as fallback.
 * - Call canonical_serialize_wrap("seed.manifest", 1, payload...).
 * - Compute SHA-256 of resulting bytes and print concise status line.
 * - Write "canonical_blob.bin" and "canonical_blob.hash" on success (non-fatal).
 */

__attribute__((constructor))
static void canonical_serialize_constructor(void) {
    const char *payload_path_candidates[] = { "manifest.bin", "canonical_input.json", NULL };
    uint8_t *payload = NULL;
    size_t payload_len = 0;
    for (const char **p = payload_path_candidates; *p != NULL; ++p) {
        const char *path = *p;
        FILE *f = fopen(path, "rb");
        if (!f) continue;
        struct stat st;
        if (fstat(fileno(f), &st) != 0) { fclose(f); continue; }
        if (st.st_size <= 0) { fclose(f); continue; }
        payload_len = (size_t)st.st_size;
        payload = malloc(payload_len);
        if (!payload) { fclose(f); payload = NULL; payload_len = 0; break; }
        size_t r = fread(payload, 1, payload_len, f);
        fclose(f);
        if (r != payload_len) { free(payload); payload = NULL; payload_len = 0; continue; }
        // found payload
        break;
    }

    if (!payload) {
        fprintf(stderr, "[serialize] constructor: no manifest.bin/canonical_input.json found; skipping serialize check\n");
        return;
    }

    uint8_t *outbuf = NULL;
    size_t outlen = 0;
    canonical_result_t res;
    int rc = canonical_serialize_wrap("seed.manifest", 1, payload, payload_len, &outbuf, &outlen, &res);
    if (rc != CANONICAL_OK) {
        fprintf(stderr, "[serialize] constructor: serialize FAILED code=%d msg='%s'\n", res.code, res.message);
        free(payload);
        return;
    }

    // compute hash
    char hex[65] = {0};
    if (compute_sha256_hex_buf(outbuf, outlen, hex) != 0) {
        fprintf(stderr, "[serialize] constructor: hash computation FAILED\n");
        free(outbuf);
        free(payload);
        return;
    }

    fprintf(stdout, "SERIALIZE: ok schema_v=%d out_bytes=%zu hash=%s\n", res.schema_version, outlen, hex);

    // try writing output (best-effort; non-fatal)
    FILE *ob = fopen("canonical_blob.bin", "wb");
    if (ob) {
        if (outlen > 0) fwrite(outbuf, 1, outlen, ob);
        fclose(ob);
    }
    FILE *oh = fopen("canonical_blob.hash", "w");
    if (oh) {
        fprintf(oh, "%s\n", hex);
        fclose(oh);
    }

    free(outbuf);
    free(payload);
}
