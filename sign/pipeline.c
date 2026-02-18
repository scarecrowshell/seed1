/* sign/pipeline.c
*
* Flow: canonicalize -> compute hash -> sign -> package signature block
* Visible terminal output on success/failure via constructor that runs at startup
*/

#include "mod.h" /* compute_hash, canonicalize_and_sign, verify_signature */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <dirent.h>
#include <sys/stat.h>
#include <errno.h>
#include <unistd.h>

#include <openssl/crypto.h> /* OPENSSL_free */

/* --- helpers ----------------------------------------------------------- */

static void hex_encode(const unsigned char *in, size_t in_len, char *out /* must be 2*in_len+1 */) {
    static const char *hex = "0123456789abcdef";
    for (size_t i = 0; i < in_len; ++i) {
        out[i * 2 + 0] = hex[(in[i] >> 4) & 0xF];
        out[i * 2 + 1] = hex[(in[i] >> 0) & 0xF];
    }
    out[in_len * 2] = '\0';
}

/* Find a file in `dirpath` recursively whose name ends with `suffix`.
* Returns malloc'd path (caller must free) or NULL if not found.
*/
static char *find_file_recursive(const char *dirpath, const char *suffix) {
    struct dirent *d;
    DIR *dir = opendir(dirpath);
    if (!dir) return NULL;

    while ((d = readdir(dir)) != NULL) {
        if (strcmp(d->d_name, ".") == 0 || strcmp(d->d_name, "..") == 0) continue;
        size_t pathlen = strlen(dirpath) + 1 + strlen(d->d_name) + 1;
        char *full = (char *)malloc(pathlen);
        if (!full) { closedir(dir); return NULL; }
        snprintf(full, pathlen, "%s/%s", dirpath, d->d_name);

        struct stat st;
        if (stat(full, &st) == -1) { free(full); continue; }

        if (S_ISDIR(st.st_mode)) {
            char *r = find_file_recursive(full, suffix);
            free(full);
            if (r) { closedir(dir); return r; }
            continue;
        } else if (S_ISREG(st.st_mode)) {
            size_t n = strlen(d->d_name), s = strlen(suffix);
            if (n >= s && strcmp(d->d_name + n - s, suffix) == 0) {
                closedir(dir);
                return full; /* caller frees */
            }
        }
        free(full);
    }
    closedir(dir);
    return NULL;
}

/* Find a first file matching ext in current directory (non-recursive).
* ext should include the dot, e.g., ".json" or ".bin"
* Returns malloc'd name or NULL.
*/
static char *find_first_in_cwd_with_ext(const char *ext) {
    DIR *dir = opendir(".");
    if (!dir) return NULL;
    struct dirent *d;
    while ((d = readdir(dir)) != NULL) {
        if (d->d_type == DT_REG) {
            const char *name = d->d_name;
            size_t n = strlen(name), s = strlen(ext);
            if (n >= s && strcmp(name + n - s, ext) == 0) {
                char *r = strdup(name);
                closedir(dir);
                return r;
            }
        }
    }
    closedir(dir);
    return NULL;
}

/* Pretty ISO8601 UTC timestamp for time_t t. Caller-provided buffer must be >= 25 bytes. */
static void iso8601_utc(time_t t, char *buf, size_t buflen) {
    struct tm g;
#if defined(_WIN32) || defined(_WIN64)
    gmtime_s(&g, &t);
#else
    gmtime_r(&t, &g);
#endif
    strftime(buf, buflen, "%Y-%m-%dT%H:%M:%SZ", &g);
}

/* --- pipeline runner -------------------------------------------------- */

/* Attempt to auto-detect an input canonical blob to sign.
* Preference order:
*  1) ./canonical_blob.bin
*  2) ./canonical_input.json
*  3) any .json file in cwd
*  4) first .bin file in cwd
* Returns malloc'd path or NULL.
*/
static char *detect_canonical_input(void) {
    const char *candidates[] = {
        "canonical_blob.bin",
        "canonical_input.json",
        NULL
    };
    for (size_t i = 0; candidates[i]; ++i) {
        struct stat st;
        if (stat(candidates[i], &st) == 0 && S_ISREG(st.st_mode)) {
            return strdup(candidates[i]);
        }
    }
    char *j = find_first_in_cwd_with_ext(".json");
    if (j) return j;
    char *b = find_first_in_cwd_with_ext(".bin");
    if (b) return b;
    return NULL;
}

/* Attempt to find a private key to use for signing.
* We look under keymgmt/signers recursively for any .pem file.
* Returns malloc'd path or NULL.
*/
static char *detect_private_key(void) {
    /* common expected locations */
    const char *paths[] = {
        "keymgmt/signers",
        "keymgmt",
        "sign",
        NULL
    };
    for (size_t i = 0; paths[i]; ++i) {
        char *p = find_file_recursive(paths[i], ".pem");
        if (p) return p;
    }
    /* fallback: look for any .pem in cwd */
    DIR *dir = opendir(".");
    if (dir) {
        struct dirent *d;
        while ((d = readdir(dir)) != NULL) {
            if (d->d_type == DT_REG) {
                const char *name = d->d_name;
                size_t n = strlen(name);
                if (n > 4 && strcmp(name + n - 4, ".pem") == 0) {
                    closedir(dir);
                    return strdup(name);
                }
            }
        }
        closedir(dir);
    }
    return NULL;
}

/* Build a small JSON signature block. Caller must free returned ptr. */
static char *build_signature_block(const char *signer_id,
                                const char *timestamp,
                                const unsigned char hash[32],
                                const unsigned char *sig,
                                size_t sig_len) {
    /* hex encode hash and signature */
    char hash_hex[65];
    hex_encode(hash, 32, hash_hex);

    char *sig_hex = (char *)malloc((sig_len * 2) + 1);
    if (!sig_hex) return NULL;
    hex_encode(sig, sig_len, sig_hex);

    /* estimate size and build JSON */
    size_t needed = 256 + strlen(signer_id) + strlen(timestamp) + strlen(hash_hex) + strlen(sig_hex);
    char *out = (char *)malloc(needed);
    if (!out) { free(sig_hex); return NULL; }

    snprintf(out, needed,
            "{\n"
            "  \"signer_id\": \"%s\",\n"
            "  \"signed_at\": \"%s\",\n"
            "  \"hash\": \"%s\",\n"
            "  \"signature\": \"%s\",\n"
            "  \"signature_len\": %zu\n"
            "}\n",
            signer_id, timestamp, hash_hex, sig_hex, sig_len);

    free(sig_hex);
    return out;
}

/* Run pipeline for a given input file and private key.
* Returns 0 on success, non-zero on failure.
*/
static int run_pipeline_for(const char *input_path, const char *privkey_path) {
    if (!input_path || !privkey_path) return 1;

    fprintf(stderr, "[sign/pipeline] starting pipeline for input='%s' privkey='%s'\n", input_path, privkey_path);

    unsigned char *signature = NULL;
    size_t sig_len = 0;
    unsigned char hash[32];

    int sret = canonicalize_and_sign(input_path, privkey_path, &signature, &sig_len, hash);
    if (sret != 0) {
        fprintf(stderr, "[sign/pipeline] canonicalize_and_sign FAILED (code %d)\n", sret);
        return 2;
    }
    fprintf(stderr, "[sign/pipeline] sign succeeded (sig_len=%zu bytes)\n", sig_len);

    /* signer id: attempt to derive from privkey filename */
    const char *basename = strrchr(privkey_path, '/');
    basename = basename ? (basename + 1) : privkey_path;

    /* timestamp */
    char ts[32];
    time_t now = time(NULL);
    iso8601_utc(now, ts, sizeof(ts));

    /* build signature block */
    char *block = build_signature_block(basename, ts, hash, signature, sig_len);
    if (!block) {
        fprintf(stderr, "[sign/pipeline] failed to allocate signature block\n");
        OPENSSL_free(signature);
        return 3;
    }

    /* write out a .sigblock file next to input: input.sig.json */
    size_t outpath_len = strlen(input_path) + 8;
    char *outpath = (char *)malloc(outpath_len);
    if (!outpath) { free(block); OPENSSL_free(signature); return 4; }
    snprintf(outpath, outpath_len, "%s.sig", input_path);

    FILE *f = fopen(outpath, "wb");
    if (!f) {
        fprintf(stderr, "[sign/pipeline] failed to open '%s' for writing: %s\n", outpath, strerror(errno));
        free(outpath);
        free(block);
        OPENSSL_free(signature);
        return 5;
    }
    size_t w = fwrite(block, 1, strlen(block), f);
    fclose(f);
    if (w != strlen(block)) {
        fprintf(stderr, "[sign/pipeline] failed to write full signature block to '%s'\n", outpath);
        free(outpath);
        free(block);
        OPENSSL_free(signature);
        return 6;
    }

    fprintf(stderr, "[sign/pipeline] signature block written: %s (bytes=%zu)\n", outpath, w);
    fprintf(stderr, "[sign/pipeline] HASH: ");
    for (int i = 0; i < 32; ++i) fprintf(stderr, "%02x", hash[i]);
    fprintf(stderr, "\n");

    /* cleanup */
    free(outpath);
    free(block);
    OPENSSL_free(signature);

    return 0;
}

/* --- constructor: attempt to run pipeline at startup for visibility ----- */

__attribute__((constructor))
static void sign_pipeline_constructor(void) {
    /* attempt to detect input and private key */
    char *input = detect_canonical_input();
    if (!input) {
        fprintf(stderr, "[sign/pipeline] no canonical input found; skipping signature pipeline\n");
        return;
    }

    char *priv = detect_private_key();
    if (!priv) {
        fprintf(stderr, "[sign/pipeline] no private key (.pem) found under keymgmt/signers or sign/; skipping\n");
        free(input);
        return;
    }

    int rc = run_pipeline_for(input, priv);
    if (rc == 0) {
        fprintf(stderr, "[sign/pipeline] pipeline completed SUCCESS for '%s'\n", input);
    } else {
        fprintf(stderr, "[sign/pipeline] pipeline FAILED (code %d) for '%s'\n", rc, input);
    }

    free(input);
    free(priv);
}
