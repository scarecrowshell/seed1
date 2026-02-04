// keymgmt/storage.c
// Minimal secure key storage abstraction (sealed-file style + in-memory test backend)
// - Loads public-key blobs from keymgmt/signers/<id> files (filename = id, contents = pubkey bytes).
// - Exposes storage_init/shutdown, listing and public-key retrieval.
// - Does NOT return private key bytes. storage_sign() returns "unsupported" unless a backend supports it.
// - Prints visible terminal lines on success/failure for each major action.

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <dirent.h>
#include <sys/stat.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>
#include <stdarg.h>    // <--- required for va_start / va_end

#define STORAGE_DIR "keymgmt/signers" /* relative to CWD; change via storage_init(cfg) if desired */

/* Return codes */
enum {
    ST_OK = 0,
    ST_NOT_FOUND = -1,
    ST_BACKEND_ERROR = -2,
    ST_UNSUPPORTED = -3,
    ST_INTERNAL = -10,
};

/* Internal signer representation */
typedef struct {
    char *id;           // heap: signer id (filename)
    uint8_t *pub;       // heap: public key bytes (opaque)
    size_t pub_len;
} storage_signer_t;

/* In-memory registry */
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static storage_signer_t *g_signers = NULL;
static size_t g_signer_count = 0;
static int g_initialized = 0;

/* Simple logging visible in terminal */
static void storage_log(const char *fmt, ...)
{
    va_list ap;
    printf("[STORAGE] ");
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    printf("\n");
    fflush(stdout);
}

/* Helper to free signer array */
static void internal_free_signers(void)
{
    if (!g_signers) return;
    for (size_t i = 0; i < g_signer_count; ++i) {
        free(g_signers[i].id);
        if (g_signers[i].pub) {
            /* public key bytes are not secret, but clear to avoid stale memory */
            memset(g_signers[i].pub, 0, g_signers[i].pub_len);
            free(g_signers[i].pub);
        }
    }
    free(g_signers);
    g_signers = NULL;
    g_signer_count = 0;
}

/* Attempt to load all files in STORAGE_DIR as signers.
   Each regular file's filename (basename) -> signer id, content -> public key blob.
   Returns ST_OK on success (including count == 0), or ST_BACKEND_ERROR on error.
*/
int storage_init(const char *path_override)
{
    const char *path = (path_override && path_override[0]) ? path_override : STORAGE_DIR;
    DIR *d = NULL;
    struct dirent *entry;
    struct stat stbuf;
    char fullpath[4096];

    pthread_mutex_lock(&g_lock);

    if (g_initialized) {
        storage_log("already initialized");
        pthread_mutex_unlock(&g_lock);
        return ST_OK;
    }

    /* clear any previous state just in case */
    internal_free_signers();

    d = opendir(path);
    if (!d) {
        if (errno == ENOENT) {
            storage_log("READY: no signers directory '%s' (no signers configured)", path);
            g_initialized = 1;
            pthread_mutex_unlock(&g_lock);
            return ST_OK;
        } else {
            storage_log("INITIALIZATION FAILURE: cannot open signers dir '%s' (%s)", path, strerror(errno));
            pthread_mutex_unlock(&g_lock);
            return ST_BACKEND_ERROR;
        }
    }

    /* First pass: count regular files */
    size_t count = 0;
    while ((entry = readdir(d)) != NULL) {
        if (entry->d_name[0] == '.') continue; /* skip . and hidden */
        snprintf(fullpath, sizeof(fullpath), "%s/%s", path, entry->d_name);
        if (stat(fullpath, &stbuf) != 0) continue;
        if (!S_ISREG(stbuf.st_mode)) continue;
        count++;
    }

    if (count == 0) {
        closedir(d);
        storage_log("READY: signers directory '%s' is present but empty (no signers configured)", path);
        g_initialized = 1;
        pthread_mutex_unlock(&g_lock);
        return ST_OK;
    }

    /* Allocate array */
    g_signers = calloc(count, sizeof(storage_signer_t));
    if (!g_signers) {
        closedir(d);
        storage_log("INITIALIZATION FAILURE: out of memory");
        pthread_mutex_unlock(&g_lock);
        return ST_INTERNAL;
    }

    /* Second pass: load files */
    rewinddir(d);
    size_t idx = 0;
    while ((entry = readdir(d)) != NULL) {
        if (entry->d_name[0] == '.') continue;
        snprintf(fullpath, sizeof(fullpath), "%s/%s", path, entry->d_name);
        if (stat(fullpath, &stbuf) != 0) continue;
        if (!S_ISREG(stbuf.st_mode)) continue;

        /* open and read file */
        FILE *f = fopen(fullpath, "rb");
        if (!f) {
            storage_log("warning: cannot open signer file '%s' (%s) -- skipping", fullpath, strerror(errno));
            continue;
        }

        /* read file into buffer */
        if (fseek(f, 0, SEEK_END) == 0) {
            long flen = ftell(f);
            if (flen < 0) flen = 0;
            rewind(f);

            uint8_t *buf = NULL;
            if (flen > 0) {
                buf = malloc((size_t)flen);
                if (!buf) {
                    storage_log("warning: cannot malloc for '%s' (%ld bytes) -- skipping", fullpath, flen);
                    fclose(f);
                    continue;
                }
                size_t got = fread(buf, 1, (size_t)flen, f);
                if (got != (size_t)flen) {
                    storage_log("warning: short read for '%s' -- skipping", fullpath);
                    free(buf); fclose(f); continue;
                }
            } else {
                /* empty file -> 0-length public key (treat as invalid but store id) */
                buf = NULL;
            }

            /* record signer id (filename) and pubkey bytes */
            g_signers[idx].id = strdup(entry->d_name);
            g_signers[idx].pub = buf;
            g_signers[idx].pub_len = (size_t)flen;
            idx++;
        } else {
            storage_log("warning: fseek failed on '%s' -- skipping", fullpath);
            fclose(f);
            continue;
        }
        fclose(f);
    }

    closedir(d);

    if (idx == 0) {
        free(g_signers);
        g_signers = NULL;
        g_signer_count = 0;
        storage_log("INITIALIZATION WARNING: no valid signer files found in '%s'", path);
        g_initialized = 1;
        pthread_mutex_unlock(&g_lock);
        return ST_OK;
    }

    g_signer_count = idx;
    g_initialized = 1;
    storage_log("INITIALIZATION SUCCESS: loaded %zu signer(s) from '%s'", g_signer_count, path);
    pthread_mutex_unlock(&g_lock);
    return ST_OK;
}

/* Shutdown and zero sensitive state */
void storage_shutdown(void)
{
    pthread_mutex_lock(&g_lock);
    internal_free_signers();
    g_initialized = 0;
    pthread_mutex_unlock(&g_lock);
    storage_log("shutdown complete");
}

/* Return a heap-allocated list of signer IDs (caller must free via storage_free_list) */
int storage_list_signers(char ***out_ids, size_t *out_count)
{
    if (!out_ids || !out_count) return ST_INTERNAL;
    *out_ids = NULL;
    *out_count = 0;

    pthread_mutex_lock(&g_lock);
    if (!g_initialized) {
        pthread_mutex_unlock(&g_lock);
        return ST_INTERNAL;
    }

    if (g_signer_count == 0) {
        pthread_mutex_unlock(&g_lock);
        return ST_OK;
    }

    char **arr = calloc(g_signer_count, sizeof(char*));
    if (!arr) { pthread_mutex_unlock(&g_lock); return ST_INTERNAL; }

    for (size_t i = 0; i < g_signer_count; ++i) {
        arr[i] = strdup(g_signers[i].id);
    }

    *out_ids = arr;
    *out_count = g_signer_count;
    pthread_mutex_unlock(&g_lock);
    return ST_OK;
}

/* Free list produced by storage_list_signers */
void storage_free_list(char **ids, size_t count)
{
    if (!ids) return;
    for (size_t i = 0; i < count; ++i) free(ids[i]);
    free(ids);
}

/* Retrieve public key bytes for signer id. Caller receives heap buffer and must free it. */
int storage_get_public(const char *signer_id, uint8_t **out_pub, size_t *out_len)
{
    if (!signer_id || !out_pub || !out_len) return ST_INTERNAL;
    *out_pub = NULL;
    *out_len = 0;

    pthread_mutex_lock(&g_lock);
    if (!g_initialized) { pthread_mutex_unlock(&g_lock); return ST_INTERNAL; }

    for (size_t i = 0; i < g_signer_count; ++i) {
        if (strcmp(g_signers[i].id, signer_id) == 0) {
            if (g_signers[i].pub_len == 0) {
                pthread_mutex_unlock(&g_lock);
                return ST_NOT_FOUND;
            }
            uint8_t *buf = malloc(g_signers[i].pub_len);
            if (!buf) { pthread_mutex_unlock(&g_lock); return ST_INTERNAL; }
            memcpy(buf, g_signers[i].pub, g_signers[i].pub_len);
            *out_pub = buf;
            *out_len = g_signers[i].pub_len;
            pthread_mutex_unlock(&g_lock);
            storage_log("public key retrieved for signer '%s' (len=%zu)", signer_id, *out_len);
            return ST_OK;
        }
    }

    pthread_mutex_unlock(&g_lock);
    return ST_NOT_FOUND;
}

/* Sign using the signer's private key.
   This minimal backend does NOT hold private keys; therefore this returns ST_UNSUPPORTED.
   When you later plug an HSM/KMS backend, implement the signing operation here and
   return ST_OK with allocated signature bytes in *sig_out and *sig_len_out.
*/
int storage_sign(const char *signer_id,
                 const uint8_t *message, size_t message_len,
                 uint8_t **sig_out, size_t *sig_len_out,
                 char **err_out)
{
    (void)signer_id; (void)message; (void)message_len;
    (void)sig_out; (void)sig_len_out;
    if (err_out) {
        *err_out = strdup("sign operation unsupported: no private-key backend configured");
    }
    storage_log("sign request for '%s' -> unsupported (no private-key backend)", signer_id ? signer_id : "<null>");
    return ST_UNSUPPORTED;
}

/* Convenience auto-init at load time (so you see storage status without editing seed) */
__attribute__((constructor))
static void storage_autoinit(void)
{
    /* attempt init but ignore error code (already logged) */
    storage_init(NULL);
}
