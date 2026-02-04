// keymgmt/revocation.c
// Minimal revocation engine: load active CRL, check revocations, publish manifests, apply killswitches.
// - visible terminal output on init / publish / killswitch / checks
// - requires integrator-provided verifier callback for manifest validation
// - active CRL format (simple CSV-like): "<id>,<revoked_at>,<reason>\n"

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <pthread.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <stdbool.h>
#include <stdarg.h>

#define REV_ROOT_DIR "keymgmt/revocation"
#define REV_PENDING_DIR REV_ROOT_DIR "/pending"
#define REV_ARCHIVE_DIR REV_ROOT_DIR "/archive"
#define REV_ACTIVE_FILE REV_ROOT_DIR "/active.crl"
#define REV_TMP_FILE REV_ROOT_DIR "/active.crl.tmp"

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

/* In-memory revocation entry */
typedef struct {
    char *id;           // heap
    time_t revoked_at;
    char *reason;       // may be NULL
} rev_entry_t;

static rev_entry_t *g_entries = NULL;
static size_t g_entry_count = 0;
static int g_initialized = 0;
static char g_last_status[256] = {0};

/* Verifier callback: integrator must register a function that validates
   a manifest file (returns 0 on valid, non-zero on invalid).
   Signature: int (*verifier)(const char *manifest_path, char **err_out)
*/
typedef int (*rev_manifest_verifier_t)(const char *manifest_path, char **err_out);
static rev_manifest_verifier_t g_manifest_verifier = NULL;

/* Logging helper */
static void rev_log(const char *fmt, ...)
{
    va_list ap;
    printf("[REVOCATION] ");
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    printf("\n");
    fflush(stdout);
}

/* Helper to set last status (short string) */
static void rev_set_statusf(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(g_last_status, sizeof(g_last_status), fmt, ap);
    va_end(ap);
}

/* Ensure directory exists (create if missing) */
static int rev_ensure_dirs(void)
{
    const char *dirs[] = { "keymgmt", REV_ROOT_DIR, REV_PENDING_DIR, REV_ARCHIVE_DIR, NULL };
    for (const char **p = dirs; *p; ++p) {
        struct stat st;
        if (stat(*p, &st) != 0) {
            if (errno == ENOENT) {
                if (mkdir(*p, 0755) != 0) {
                    rev_log("FAILED to create dir '%s' (%s)", *p, strerror(errno));
                    rev_set_statusf("failed-create-dir:%s", *p);
                    return -1;
                }
                rev_log("created directory '%s'", *p);
            } else {
                rev_log("ERROR stat '%s' (%s)", *p, strerror(errno));
                rev_set_statusf("stat-failed:%s", *p);
                return -1;
            }
        } else if (!S_ISDIR(st.st_mode)) {
            rev_log("ERROR: path '%s' exists but is not a directory", *p);
            rev_set_statusf("not-dir:%s", *p);
            return -1;
        }
    }
    return 0;
}

/* Free in-memory entries */
static void rev_free_entries(void)
{
    if (!g_entries) return;
    for (size_t i = 0; i < g_entry_count; ++i) {
        free(g_entries[i].id);
        free(g_entries[i].reason);
    }
    free(g_entries);
    g_entries = NULL;
    g_entry_count = 0;
}

/* Parse a line from active.crl: "id,revoked_at,reason"
   reason may contain commas; we treat first comma as separator to revoked_at, remainder as reason.
   Returns 0 on success, non-zero on parse error.
*/
static int rev_parse_crl_line(const char *line, char **id_out, time_t *revoked_at_out, char **reason_out)
{
    if (!line || !id_out || !revoked_at_out || !reason_out) return -1;
    *id_out = NULL; *reason_out = NULL; *revoked_at_out = 0;

    // skip leading whitespace
    const char *p = line;
    while (*p == ' ' || *p == '\t') p++;
    if (*p == '\0' || *p == '\n') return -1;

    // find first comma
    const char *c1 = strchr(p, ',');
    if (!c1) return -1;
    size_t idlen = (size_t)(c1 - p);
    char *id = malloc(idlen + 1);
    if (!id) return -1;
    memcpy(id, p, idlen);
    id[idlen] = '\0';

    // find second comma (revoked_at may be numeric without comma; look for next comma)
    const char *c2 = strchr(c1 + 1, ',');
    if (!c2) {
        // no reason field; parse revoked_at as remainder up to newline
        char *num = NULL;
        size_t numlen = strcspn(c1 + 1, "\r\n");
        num = malloc(numlen + 1);
        if (!num) { free(id); return -1; }
        memcpy(num, c1 + 1, numlen); num[numlen] = '\0';
        long long v = atoll(num);
        free(num);
        *id_out = id;
        *revoked_at_out = (time_t)v;
        *reason_out = NULL;
        return 0;
    } else {
        // parse revoked_at between c1+1 and c2-1
        size_t numlen = (size_t)(c2 - (c1 + 1));
        char *num = malloc(numlen + 1);
        if (!num) { free(id); return -1; }
        memcpy(num, c1 + 1, numlen); num[numlen] = '\0';
        long long v = atoll(num);
        free(num);
        // reason is remainder (skip whitespace)
        const char *rstart = c2 + 1;
        while (*rstart == ' ' || *rstart == '\t') rstart++;
        size_t rlen = strcspn(rstart, "\r\n");
        char *reason = NULL;
        if (rlen > 0) {
            reason = malloc(rlen + 1);
            if (!reason) { free(id); return -1; }
            memcpy(reason, rstart, rlen);
            reason[rlen] = '\0';
        }
        *id_out = id;
        *revoked_at_out = (time_t)v;
        *reason_out = reason;
        return 0;
    }
}

/* Load active.crl into memory (replaces in-memory entries).
   Returns 0 on success, non-zero on error.
*/
static int rev_load_active_crl(void)
{
    rev_free_entries();

    FILE *f = fopen(REV_ACTIVE_FILE, "r");
    if (!f) {
        if (errno == ENOENT) {
            rev_log("READY: no active CRL found (no revocations configured)");
            rev_set_statusf("no-active-crl");
            return 0;
        } else {
            rev_log("INITIALIZATION FAILURE: cannot open active CRL '%s' (%s)", REV_ACTIVE_FILE, strerror(errno));
            rev_set_statusf("crl-open-failure");
            return -1;
        }
    }

    // read lines, parse, store entries
    char *line = NULL;
    size_t len = 0;
    ssize_t read;
    size_t cap = 16;
    rev_entry_t *arr = calloc(cap, sizeof(rev_entry_t));
    size_t n = 0;

    while ((read = getline(&line, &len, f)) != -1) {
        if (read <= 1) continue;
        // parse
        char *id = NULL, *reason = NULL;
        time_t revoked_at = 0;
        if (rev_parse_crl_line(line, &id, &revoked_at, &reason) == 0) {
            if (n >= cap) {
                size_t nc = cap * 2;
                rev_entry_t *tmp = realloc(arr, nc * sizeof(rev_entry_t));
                if (!tmp) { free(id); free(reason); break; }
                arr = tmp; cap = nc;
            }
            arr[n].id = id;
            arr[n].revoked_at = revoked_at;
            arr[n].reason = reason;
            n++;
        } else {
            // skip invalid lines but log
            rev_log("warning: skipping invalid CRL line: %s", line);
        }
    }
    free(line);
    fclose(f);

    g_entries = arr;
    g_entry_count = n;

    rev_log("INITIALIZATION SUCCESS: loaded %zu revoked entry(ies) from active CRL", n);
    rev_set_statusf("loaded:%zu", n);
    return 0;
}

/* Public API: register a manifest verifier callback */
void revocation_register_manifest_verifier(rev_manifest_verifier_t cb)
{
    pthread_mutex_lock(&g_lock);
    g_manifest_verifier = cb;
    pthread_mutex_unlock(&g_lock);
    rev_log("manifest verifier registered");
}

/* Initialize revocation subsystem */
int revocation_init(const char *base_dir)
{
    (void)base_dir; // for now we use default REV_ROOT_DIR
    pthread_mutex_lock(&g_lock);
    if (g_initialized) {
        pthread_mutex_unlock(&g_lock);
        rev_log("revocation: already initialized");
        return 0;
    }

    if (rev_ensure_dirs() != 0) {
        pthread_mutex_unlock(&g_lock);
        return -1;
    }

    if (rev_load_active_crl() != 0) {
        pthread_mutex_unlock(&g_lock);
        return -1;
    }

    g_initialized = 1;
    pthread_mutex_unlock(&g_lock);
    return 0;
}

/* Shutdown */
void revocation_shutdown(void)
{
    pthread_mutex_lock(&g_lock);
    rev_free_entries();
    g_initialized = 0;
    pthread_mutex_unlock(&g_lock);
    rev_log("shutdown complete");
}

/* Check if id is revoked at time 'at' (if at==0 use now). If revoked, set *reason_out (caller frees) and return 1.
   Returns 0 if not revoked, negative on error.
*/
int revocation_is_revoked(const char *id, time_t at, char **reason_out)
{
    if (!id) return -1;
    if (reason_out) *reason_out = NULL;
    pthread_mutex_lock(&g_lock);
    if (!g_initialized) {
        pthread_mutex_unlock(&g_lock);
        rev_log("check: revocation subsystem not initialized");
        return -1;
    }
    time_t now = at ? at : time(NULL);

    for (size_t i = 0; i < g_entry_count; ++i) {
        if (strcmp(g_entries[i].id, id) == 0) {
            if (g_entries[i].revoked_at <= now) {
                if (reason_out && g_entries[i].reason) *reason_out = strdup(g_entries[i].reason);
                rev_log("check id=%s -> REVOKED (at=%lld reason='%s')", id, (long long)g_entries[i].revoked_at, g_entries[i].reason ? g_entries[i].reason : "");
                pthread_mutex_unlock(&g_lock);
                return 1;
            }
            // revoked in future? treat as not revoked yet
            break;
        }
    }

    pthread_mutex_unlock(&g_lock);
    return 0;
}

/* Helper: append entry into in-memory list (caller must hold lock) */
static int rev_add_entry_locked(const char *id, time_t revoked_at, const char *reason)
{
    if (!id) return -1;
    rev_entry_t *tmp = realloc(g_entries, (g_entry_count + 1) * sizeof(rev_entry_t));
    if (!tmp) return -1;
    g_entries = tmp;
    g_entries[g_entry_count].id = strdup(id);
    g_entries[g_entry_count].revoked_at = revoked_at;
    g_entries[g_entry_count].reason = reason ? strdup(reason) : NULL;
    g_entry_count++;
    return 0;
}

/* Merge a new revocation entry into active.crl atomically and update in-memory index.
   new_id, revoked_at, reason come from validated manifest. Caller must hold lock or function will lock.
*/
static int rev_merge_into_crl(const char *new_id, time_t revoked_at, const char *reason)
{
    if (!new_id) return -1;
    // Read existing active.crl (if exists) and write to tmp file then append new record, then rename.
    FILE *fin = fopen(REV_ACTIVE_FILE, "r");
    FILE *fout = fopen(REV_TMP_FILE, "w");
    if (!fout) {
        if (fin) fclose(fin);
        rev_log("merge: failed to open tmp CRL file '%s' (%s)", REV_TMP_FILE, strerror(errno));
        return -1;
    }

    // copy existing content if any
    if (fin) {
        char buf[4096];
        size_t r;
        while ((r = fread(buf, 1, sizeof(buf), fin)) > 0) {
            if (fwrite(buf, 1, r, fout) != r) {
                fclose(fin); fclose(fout);
                unlink(REV_TMP_FILE);
                rev_log("merge: write failure");
                return -1;
            }
        }
        fclose(fin);
    }

    // append new CSV line
    if (fprintf(fout, "%s,%lld,%s\n", new_id, (long long)revoked_at, reason ? reason : "") < 0) {
        fclose(fout);
        unlink(REV_TMP_FILE);
        rev_log("merge: failed to append new record");
        return -1;
    }
    fflush(fout);
    fsync(fileno(fout));
    fclose(fout);

    // atomic rename
    if (rename(REV_TMP_FILE, REV_ACTIVE_FILE) != 0) {
        unlink(REV_TMP_FILE);
        rev_log("merge: failed to rename tmp -> active (%s)", strerror(errno));
        return -1;
    }

    // update in-memory index
    if (rev_add_entry_locked(new_id, revoked_at, reason) != 0) {
        rev_log("merge: warning - failed to add in-memory entry (but file updated)");
        // not fatal
    }

    rev_log("MERGED new revocation: id=%s at=%lld reason='%s'", new_id, (long long)revoked_at, reason ? reason : "");
    return 0;
}

/* Parse minimal fields from a manifest file.
   We accept JSON-like files and use strstr to find "revoked_id" and "revoked_at" and optional "reason".
   Returns 0 on success (strings heap-allocated into out_id/out_reason), non-zero on parse error.
*/
static int rev_parse_manifest_minimal(const char *path, char **out_id, time_t *out_revoked_at, char **out_reason)
{
    if (!path || !out_id || !out_revoked_at || !out_reason) return -1;
    *out_id = NULL; *out_reason = NULL; *out_revoked_at = 0;

    FILE *f = fopen(path, "r");
    if (!f) return -1;

    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        char *p;
        if ((p = strstr(line, "\"revoked_id\"")) != NULL) {
            char *q = strchr(p, ':');
            if (!q) continue;
            q++;
            while (*q == ' ' || *q == '\t') q++;
            if (*q == '\"') {
                q++;
                char *r = strchr(q, '\"');
                if (r) {
                    size_t len = (size_t)(r - q);
                    *out_id = malloc(len + 1);
                    memcpy(*out_id, q, len);
                    (*out_id)[len] = '\0';
                }
            }
        } else if ((p = strstr(line, "\"revoked_at\"")) != NULL) {
            char *q = strchr(p, ':');
            if (!q) continue;
            long long v = atoll(q+1);
            *out_revoked_at = (time_t)v;
        } else if ((p = strstr(line, "\"reason\"")) != NULL) {
            char *q = strchr(p, ':');
            if (!q) continue;
            q++;
            while (*q == ' ' || *q == '\t') q++;
            if (*q == '\"') {
                q++;
                char *r = strchr(q, '\"');
                if (r) {
                    size_t len = (size_t)(r - q);
                    *out_reason = malloc(len + 1);
                    memcpy(*out_reason, q, len);
                    (*out_reason)[len] = '\0';
                }
            } else {
                // handle non-quoted to newline
                size_t len = strcspn(q, "\r\n");
                if (len > 0) {
                    *out_reason = malloc(len + 1);
                    memcpy(*out_reason, q, len);
                    (*out_reason)[len] = '\0';
                }
            }
        }
    }

    fclose(f);

    if (!*out_id) return -1;
    if (*out_revoked_at == 0) *out_revoked_at = time(NULL); // default to now if not present
    return 0;
}

/* Add a manifest into pending (simple copy). Caller supplies path to manifest file.
   Returns 0 on success, non-zero on error.
*/
int revocation_add_pending(const char *manifest_path, char **err_out)
{
    if (!manifest_path) {
        if (err_out) *err_out = strdup("no manifest_path provided");
        return -1;
    }

    pthread_mutex_lock(&g_lock);
    if (!g_initialized) {
        if (err_out) *err_out = strdup("revocation subsystem not initialized");
        pthread_mutex_unlock(&g_lock);
        return -1;
    }

    // compute basename
    const char *slash = strrchr(manifest_path, '/');
    const char *basename = slash ? (slash + 1) : manifest_path;
    char dest[1024];
    snprintf(dest, sizeof(dest), "%s/%s", REV_PENDING_DIR, basename);

    FILE *fin = fopen(manifest_path, "rb");
    if (!fin) {
        if (err_out) *err_out = strdup("cannot open manifest source");
        pthread_mutex_unlock(&g_lock);
        return -1;
    }
    FILE *fout = fopen(dest, "wb");
    if (!fout) {
        fclose(fin);
        if (err_out) *err_out = strdup("cannot open pending destination");
        pthread_mutex_unlock(&g_lock);
        return -1;
    }
    char buf[4096];
    size_t r;
    while ((r = fread(buf, 1, sizeof(buf), fin)) > 0) fwrite(buf, 1, r, fout);
    fclose(fin); fclose(fout);

    rev_log("PENDING manifest added: %s", dest);
    rev_set_statusf("pending-added:%s", basename);
    pthread_mutex_unlock(&g_lock);
    return 0;
}

/* Publish a pending manifest: verify via registered verifier, then merge into active CRL and archive.
   Returns 0 on success, non-zero on error.
*/
int revocation_publish_manifest(const char *pending_path, char **err_out)
{
    if (!pending_path) {
        if (err_out) *err_out = strdup("no pending_path provided");
        return -1;
    }

    pthread_mutex_lock(&g_lock);
    if (!g_initialized) {
        if (err_out) *err_out = strdup("revocation subsystem not initialized");
        pthread_mutex_unlock(&g_lock);
        return -1;
    }

    // verify manifest exists
    struct stat st;
    if (stat(pending_path, &st) != 0) {
        if (err_out) *err_out = strdup("pending manifest not found");
        pthread_mutex_unlock(&g_lock);
        return -1;
    }

    // require verifier
    if (!g_manifest_verifier) {
        if (err_out) *err_out = strdup("manifest verifier not registered");
        rev_log("PUBLISH FAILED: no manifest verifier registered");
        rev_set_statusf("publish-failed:no-verifier");
        pthread_mutex_unlock(&g_lock);
        return -1;
    }

    // call verifier
    char *verr = NULL;
    int vrc = g_manifest_verifier(pending_path, &verr);
    if (vrc != 0) {
        rev_log("PUBLISH FAILED: manifest verification failed: %s", verr ? verr : "unknown");
        if (err_out) *err_out = verr ? verr : strdup("verification failed");
        else free(verr);
        rev_set_statusf("publish-failed:verification");
        pthread_mutex_unlock(&g_lock);
        return -1;
    }
    if (verr) { free(verr); verr = NULL; }

    // parse minimal fields from manifest
    char *rid = NULL; char *reason = NULL; time_t revoked_at = 0;
    if (rev_parse_manifest_minimal(pending_path, &rid, &revoked_at, &reason) != 0) {
        if (err_out) *err_out = strdup("manifest parse failed");
        rev_log("PUBLISH FAILED: manifest parse failed");
        rev_set_statusf("publish-failed:parse");
        pthread_mutex_unlock(&g_lock);
        return -1;
    }

    // merge into CRL
    if (rev_merge_into_crl(rid, revoked_at, reason) != 0) {
        if (err_out) *err_out = strdup("merge into CRL failed");
        rev_log("PUBLISH FAILED: merge into CRL failed for id='%s'", rid);
        rev_set_statusf("publish-failed:merge");
        free(rid); free(reason);
        pthread_mutex_unlock(&g_lock);
        return -1;
    }

    // archive the pending file (move into archive)
    const char *basename = strrchr(pending_path, '/');
    basename = basename ? (basename + 1) : pending_path;
    char archive_path[1024];
    snprintf(archive_path, sizeof(archive_path), "%s/%s", REV_ARCHIVE_DIR, basename);
    if (rename(pending_path, archive_path) != 0) {
        rev_log("PUBLISH WARNING: could not archive pending manifest (%s)", strerror(errno));
    } else {
        rev_log("PUBLISHED manifest: archived -> %s", archive_path);
    }

    rev_log("PUBLISHED revocation for id='%s' (at=%lld reason='%s')", rid, (long long)revoked_at, reason ? reason : "");
    rev_set_statusf("published:%s", rid);

    free(rid);
    free(reason);
    pthread_mutex_unlock(&g_lock);
    return 0;
}

/* Apply a killswitch manifest: validate via verifier and then treat as high-priority revocation
   (we implement it as just merging the specified id) */
int revocation_apply_killswitch(const char *manifest_path, char **err_out)
{
    if (!manifest_path) {
        if (err_out) *err_out = strdup("no manifest_path provided");
        return -1;
    }

    pthread_mutex_lock(&g_lock);
    if (!g_initialized) {
        if (err_out) *err_out = strdup("revocation subsystem not initialized");
        pthread_mutex_unlock(&g_lock);
        return -1;
    }

    if (!g_manifest_verifier) {
        if (err_out) *err_out = strdup("no manifest verifier registered");
        rev_log("KILLSWITCH FAILED: no manifest verifier");
        pthread_mutex_unlock(&g_lock);
        return -1;
    }

    char *verr = NULL;
    int vrc = g_manifest_verifier(manifest_path, &verr);
    if (vrc != 0) {
        rev_log("KILLSWITCH FAILED: manifest verification failed: %s", verr ? verr : "unknown");
        if (err_out) *err_out = verr ? verr : strdup("verification failed");
        else free(verr);
        pthread_mutex_unlock(&g_lock);
        return -1;
    }
    if (verr) { free(verr); verr = NULL; }

    // parse manifest
    char *rid = NULL; char *reason = NULL; time_t revoked_at = 0;
    if (rev_parse_manifest_minimal(manifest_path, &rid, &revoked_at, &reason) != 0) {
        if (err_out) *err_out = strdup("manifest parse failed");
        rev_log("KILLSWITCH FAILED: manifest parse failed");
        pthread_mutex_unlock(&g_lock);
        return -1;
    }

    // merge immediately
    if (rev_merge_into_crl(rid, revoked_at, reason) != 0) {
        if (err_out) *err_out = strdup("failed to merge killswitch");
        rev_log("KILLSWITCH FAILED: merge error for id=%s", rid);
        free(rid); free(reason);
        pthread_mutex_unlock(&g_lock);
        return -1;
    }

    rev_log("KILLSWITCH APPLIED: id=%s reason='%s'", rid, reason ? reason : "");
    rev_set_statusf("killswitch:%s", rid);

    free(rid); free(reason);
    pthread_mutex_unlock(&g_lock);
    return 0;
}

/* List active revoked ids (caller frees array via revocation_free_list) */
int revocation_list_active(char ***out_ids, size_t *out_count)
{
    if (!out_ids || !out_count) return -1;
    *out_ids = NULL; *out_count = 0;

    pthread_mutex_lock(&g_lock);
    if (!g_initialized) { pthread_mutex_unlock(&g_lock); return -1; }

    if (g_entry_count == 0) { pthread_mutex_unlock(&g_lock); return 0; }

    char **arr = calloc(g_entry_count, sizeof(char*));
    if (!arr) { pthread_mutex_unlock(&g_lock); return -1; }
    for (size_t i = 0; i < g_entry_count; ++i) arr[i] = strdup(g_entries[i].id);

    *out_ids = arr; *out_count = g_entry_count;
    pthread_mutex_unlock(&g_lock);
    return 0;
}

/* Free list returned by revocation_list_active */
void revocation_free_list(char **list, size_t count)
{
    if (!list) return;
    for (size_t i = 0; i < count; ++i) free(list[i]);
    free(list);
}

/* Return short status string (not heap) */
const char *revocation_last_status(void)
{
    return g_last_status;
}

/* Auto-init at load time so you see revocation status on startup */
__attribute__((constructor))
static void revocation_autoinit(void)
{
    revocation_init(NULL);
}
