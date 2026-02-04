// keymgmt/rotation.c
// Key rotation / rollover manager (C)
// - manages rotation manifests (JSON text files) and active-key pointer
// - no private-key generation, no signature verification (other modules handle that)
// - prints visible terminal lines on success / failure for operations

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
#include <stdarg.h> /* required for va_list / va_start / va_end */

#define ROT_DIR_PENDING "keymgmt/rotation_pending"
#define ROT_DIR_MANIFESTS "keymgmt/rotation_manifests"
#define ROT_DIR_ARCHIVE "keymgmt/rotation_archive"
#define ROT_ACTIVE_KEY_FILE "keymgmt/active_key"
#define ROT_LINEAGE_FILE "keymgmt/key_lineage.csv"

/* Return codes */
enum {
    ROT_OK = 0,
    ROT_ERR = -1,
    ROT_NOT_FOUND = -2,
    ROT_INVALID = -3
};

static pthread_mutex_t g_rot_lock = PTHREAD_MUTEX_INITIALIZER;
static int g_rot_initialized = 0;

/* Simple visible logging */
static void rot_log(const char *fmt, ...)
{
    va_list ap;
    printf("[ROTATION] ");
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    printf("\n");
    fflush(stdout);
}

/* Ensure required directories exist (create them if missing). */
static int rot_ensure_dirs(void)
{
    const char *dirs[] = { "keymgmt", ROT_DIR_PENDING, ROT_DIR_MANIFESTS, ROT_DIR_ARCHIVE, NULL };
    for (const char **p = dirs; *p; ++p) {
        struct stat st;
        if (stat(*p, &st) != 0) {
            if (errno == ENOENT) {
                if (mkdir(*p, 0755) != 0) {
                    rot_log("FAILED to create dir '%s' (%s)", *p, strerror(errno));
                    return ROT_ERR;
                }
                rot_log("created directory '%s'", *p);
            } else {
                rot_log("ERROR stat '%s' (%s)", *p, strerror(errno));
                return ROT_ERR;
            }
        } else if (!S_ISDIR(st.st_mode)) {
            rot_log("ERROR: path '%s' exists but is not a directory", *p);
            return ROT_ERR;
        }
    }
    return ROT_OK;
}

/* Generate a filename-safe timestamp string */
static void rot_now_ts(char *out, size_t out_sz, time_t t)
{
    struct tm tm;
    localtime_r(&t, &tm);
    strftime(out, out_sz, "%Y%m%dT%H%M%SZ", &tm);
}

/* Create a canonical manifest JSON content and write to a file under pending dir.
   Parameters:
     old_id: existing key id (may be empty for initial provisioning)
     new_id: new key id
     effective_at: epoch seconds when new key becomes authoritative
     acceptance_window_seconds: seconds after effective_at where old signatures are still accepted
     reason: freeform text (can be NULL)
   Returns file path on success (heap string) or NULL on failure.
*/
char *rotation_schedule_rotation(const char *old_id, const char *new_id,
                                 time_t effective_at, unsigned acceptance_window_seconds,
                                 const char *reason)
{
    if (!new_id) return NULL;

    pthread_mutex_lock(&g_rot_lock);
    if (!g_rot_initialized) {
        rot_log("schedule_rotation: rotation subsystem not initialized");
        pthread_mutex_unlock(&g_rot_lock);
        return NULL;
    }

    time_t now = time(NULL);
    char ts[32];
    rot_now_ts(ts, sizeof(ts), now);

    /* compose filename: pending/<ts>.<old>_to_<new>.manifest.json or pending/<ts>.init_to_<new>.manifest.json */
    char filename[1024];
    if (old_id && old_id[0]) {
        snprintf(filename, sizeof(filename), "%s/%s.%s_to_%s.manifest.json", ROT_DIR_PENDING, ts, old_id, new_id);
    } else {
        snprintf(filename, sizeof(filename), "%s/%s.init_to_%s.manifest.json", ROT_DIR_PENDING, ts, new_id);
    }

    FILE *f = fopen(filename, "w");
    if (!f) {
        rot_log("schedule_rotation: failed to open '%s' for write (%s)", filename, strerror(errno));
        pthread_mutex_unlock(&g_rot_lock);
        return NULL;
    }

    /* Write canonical JSON (minimal fields) */
    fprintf(f, "{\n");
    fprintf(f, "  \"version\": 1,\n");
    if (old_id && old_id[0]) fprintf(f, "  \"old_key_id\": \"%s\",\n", old_id);
    fprintf(f, "  \"new_key_id\": \"%s\",\n", new_id);
    fprintf(f, "  \"effective_at\": %lld,\n", (long long)effective_at);
    fprintf(f, "  \"acceptance_window_seconds\": %u,\n", acceptance_window_seconds);
    fprintf(f, "  \"created_at\": %lld,\n", (long long)now);
    if (reason && reason[0]) fprintf(f, "  \"reason\": \"%s\",\n", reason);
    fprintf(f, "  \"manifest_filename\": \"%s\"\n", (strrchr(filename, '/') ? strrchr(filename, '/') + 1 : filename));
    fprintf(f, "}\n");
    fclose(f);

    rot_log("SCHEDULED rotation manifest written: %s", filename);

    /* Return heap-allocated filepath so caller can publish if desired */
    char *ret = strdup(filename);
    pthread_mutex_unlock(&g_rot_lock);
    return ret;
}

/* Publish a pending manifest to manifests directory (atomic via rename).
   pending_path must be a path returned by schedule_rotation or similar.
   Returns ROT_OK on success, ROT_NOT_FOUND if file missing, ROT_ERR otherwise.
*/
int rotation_publish_manifest(const char *pending_path)
{
    if (!pending_path) return ROT_INVALID;

    pthread_mutex_lock(&g_rot_lock);
    if (!g_rot_initialized) {
        rot_log("publish_manifest: rotation subsystem not initialized");
        pthread_mutex_unlock(&g_rot_lock);
        return ROT_ERR;
    }

    struct stat st;
    if (stat(pending_path, &st) != 0) {
        rot_log("publish_manifest: pending manifest '%s' not found", pending_path);
        pthread_mutex_unlock(&g_rot_lock);
        return ROT_NOT_FOUND;
    }

    /* dest path */
    const char *basename = strrchr(pending_path, '/');
    basename = basename ? (basename + 1) : pending_path;
    char dest[1024];
    snprintf(dest, sizeof(dest), "%s/%s", ROT_DIR_MANIFESTS, basename);

    /* atomic rename */
    if (rename(pending_path, dest) != 0) {
        rot_log("publish_manifest: failed to rename '%s' -> '%s' (%s)", pending_path, dest, strerror(errno));
        pthread_mutex_unlock(&g_rot_lock);
        return ROT_ERR;
    }

    rot_log("PUBLISHED manifest: %s", dest);
    pthread_mutex_unlock(&g_rot_lock);
    return ROT_OK;
}

/* Helper: parse minimal fields from manifest file: new_key_id and effective_at.
   Returns 0 on success, non-zero on parse error.
*/
static int rot_parse_manifest_minimal(const char *path, char *new_id_out, size_t new_id_sz, time_t *effective_at_out)
{
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char line[512];
    new_id_out[0] = '\0';
    *effective_at_out = 0;

    while (fgets(line, sizeof(line), f)) {
        char *p;
        if ((p = strstr(line, "\"new_key_id\"")) != NULL) {
            char *q = strchr(p, ':');
            if (!q) continue;
            q++;
            while (*q == ' ' || *q == '\t') q++;
            if (*q == '\"') {
                q++;
                char *r = strchr(q, '\"');
                if (r) {
                    size_t len = r - q;
                    if (len >= new_id_sz) len = new_id_sz - 1;
                    memcpy(new_id_out, q, len);
                    new_id_out[len] = '\0';
                }
            }
        } else if ((p = strstr(line, "\"effective_at\"")) != NULL) {
            char *q = strchr(p, ':');
            if (!q) continue;
            q++;
            long long v = atoll(q);
            *effective_at_out = (time_t)v;
        }
    }
    fclose(f);
    if (new_id_out[0] == '\0') return -1;
    return 0;
}

/* Apply a published manifest (move into active), must exist in ROT_DIR_MANIFESTS.
   If force_apply is true, apply regardless of effective_at.
   Returns ROT_OK on success, ROT_NOT_FOUND if manifest missing, ROT_INVALID on parse/logic errors.
*/
int rotation_apply_manifest(const char *manifest_basename, bool force_apply)
{
    if (!manifest_basename) return ROT_INVALID;

    pthread_mutex_lock(&g_rot_lock);
    if (!g_rot_initialized) {
        rot_log("apply_manifest: rotation subsystem not initialized");
        pthread_mutex_unlock(&g_rot_lock);
        return ROT_ERR;
    }

    char manifest_path[1024];
    snprintf(manifest_path, sizeof(manifest_path), "%s/%s", ROT_DIR_MANIFESTS, manifest_basename);

    struct stat st;
    if (stat(manifest_path, &st) != 0) {
        rot_log("apply_manifest: manifest '%s' not found in manifests dir", manifest_basename);
        pthread_mutex_unlock(&g_rot_lock);
        return ROT_NOT_FOUND;
    }

    char new_key[256];
    time_t effective_at = 0;
    if (rot_parse_manifest_minimal(manifest_path, new_key, sizeof(new_key), &effective_at) != 0) {
        rot_log("apply_manifest: failed to parse manifest '%s'", manifest_basename);
        pthread_mutex_unlock(&g_rot_lock);
        return ROT_INVALID;
    }

    time_t now = time(NULL);
    if (!force_apply && effective_at > now) {
        rot_log("apply_manifest: manifest '%s' effective at %lld (now %lld) - not yet allowed",
                manifest_basename, (long long)effective_at, (long long)now);
        pthread_mutex_unlock(&g_rot_lock);
        return ROT_INVALID;
    }

    /* Write active key pointer atomically to a temp file then rename */
    char tmpfile[1024];
    snprintf(tmpfile, sizeof(tmpfile), "%s.tmp", ROT_ACTIVE_KEY_FILE);
    FILE *f = fopen(tmpfile, "w");
    if (!f) {
        rot_log("apply_manifest: failed to write tmp active key file '%s' (%s)", tmpfile, strerror(errno));
        pthread_mutex_unlock(&g_rot_lock);
        return ROT_ERR;
    }
    fprintf(f, "%s\n", new_key);
    fprintf(f, "applied_at: %lld\n", (long long)now);
    fclose(f);

    if (rename(tmpfile, ROT_ACTIVE_KEY_FILE) != 0) {
        rot_log("apply_manifest: failed to rename tmp active key file '%s' -> '%s' (%s)", tmpfile, ROT_ACTIVE_KEY_FILE, strerror(errno));
        unlink(tmpfile);
        pthread_mutex_unlock(&g_rot_lock);
        return ROT_ERR;
    }

    /* Append lineage record (manifest_basename, new_key, applied_at) */
    FILE *lf = fopen(ROT_LINEAGE_FILE, "a");
    if (lf) {
        fprintf(lf, "%s,%s,%lld\n", manifest_basename, new_key, (long long)now);
        fclose(lf);
    } else {
        rot_log("apply_manifest: warning - could not append lineage record (%s)", strerror(errno));
    }

    /* Optionally archive the manifest (move to archive dir) */
    char archive_path[1024];
    snprintf(archive_path, sizeof(archive_path), "%s/%s", ROT_DIR_ARCHIVE, manifest_basename);
    if (rename(manifest_path, archive_path) != 0) {
        rot_log("apply_manifest: warning - could not archive manifest '%s' (%s); leaving in manifests dir", manifest_basename, strerror(errno));
    } else {
        rot_log("apply_manifest: archived manifest -> %s", archive_path);
    }

    rot_log("APPLIED manifest '%s' -> new active key '%s'", manifest_basename, new_key);
    pthread_mutex_unlock(&g_rot_lock);
    return ROT_OK;
}

/* Emergency rollover: create a manifest and apply it immediately (force).
   This does not perform signature checks — operator must ensure external checks.
   Returns ROT_OK on success, ROT_ERR otherwise.
*/
int rotation_emergency_rollover(const char *old_id, const char *new_id, const char *reason)
{
    if (!new_id) return ROT_INVALID;

    pthread_mutex_lock(&g_rot_lock);
    if (!g_rot_initialized) {
        rot_log("emergency_rollover: rotation subsystem not initialized");
        pthread_mutex_unlock(&g_rot_lock);
        return ROT_ERR;
    }

    time_t now = time(NULL);
    /* acceptance window 0 for emergency (old accepted=0 unless operator chooses otherwise) */
    char *pending = rotation_schedule_rotation(old_id, new_id, now, 0, reason ? reason : "emergency rollover");
    if (!pending) {
        rot_log("emergency_rollover: failed to schedule manifest");
        pthread_mutex_unlock(&g_rot_lock);
        return ROT_ERR;
    }

    /* Create a safe copy of the basename before freeing pending */
    char basename_buf[512] = {0};
    const char *slash = strrchr(pending, '/');
    const char *basename_src = slash ? (slash + 1) : pending;
    strncpy(basename_buf, basename_src, sizeof(basename_buf) - 1);

    int pub = rotation_publish_manifest(pending);
    free(pending);
    if (pub != ROT_OK) {
        rot_log("emergency_rollover: failed to publish manifest");
        pthread_mutex_unlock(&g_rot_lock);
        return ROT_ERR;
    }

    int applied = rotation_apply_manifest(basename_buf, true);
    if (applied != ROT_OK) {
        rot_log("emergency_rollover: failed to apply manifest '%s'", basename_buf);
        pthread_mutex_unlock(&g_rot_lock);
        return ROT_ERR;
    }

    rot_log("EMERGENCY_ROLLOVER: completed '%s' -> '%s'", old_id ? old_id : "<none>", new_id);
    pthread_mutex_unlock(&g_rot_lock);
    return ROT_OK;
}

/* List pending manifests filenames (heap-allocated array returned via out_list; caller frees each and array) */
int rotation_list_pending(char ***out_list, size_t *out_count)
{
    if (!out_list || !out_count) return ROT_INVALID;
    *out_list = NULL; *out_count = 0;

    pthread_mutex_lock(&g_rot_lock);
    if (!g_rot_initialized) {
        pthread_mutex_unlock(&g_rot_lock);
        return ROT_ERR;
    }

    DIR *d = opendir(ROT_DIR_PENDING);
    if (!d) {
        pthread_mutex_unlock(&g_rot_lock);
        return ROT_OK; /* no pending dir -> empty list */
    }

    struct dirent *e;
    size_t cap = 16;
    char **list = calloc(cap, sizeof(char*));
    size_t n = 0;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.') continue;
        if (n >= cap) {
            cap *= 2;
            char **tmp = realloc(list, cap * sizeof(char*));
            if (!tmp) break;
            list = tmp;
        }
        list[n++] = strdup(e->d_name);
    }
    closedir(d);

    *out_list = list;
    *out_count = n;
    pthread_mutex_unlock(&g_rot_lock);
    return ROT_OK;
}

/* List published manifests */
int rotation_list_manifests(char ***out_list, size_t *out_count)
{
    if (!out_list || !out_count) return ROT_INVALID;
    *out_list = NULL; *out_count = 0;

    pthread_mutex_lock(&g_rot_lock);
    if (!g_rot_initialized) {
        pthread_mutex_unlock(&g_rot_lock);
        return ROT_ERR;
    }

    DIR *d = opendir(ROT_DIR_MANIFESTS);
    if (!d) {
        pthread_mutex_unlock(&g_rot_lock);
        return ROT_OK;
    }

    struct dirent *e;
    size_t cap = 16;
    char **list = calloc(cap, sizeof(char*));
    size_t n = 0;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.') continue;
        if (n >= cap) {
            cap *= 2;
            char **tmp = realloc(list, cap * sizeof(char*));
            if (!tmp) break;
            list = tmp;
        }
        list[n++] = strdup(e->d_name);
    }
    closedir(d);

    *out_list = list;
    *out_count = n;
    pthread_mutex_unlock(&g_rot_lock);
    return ROT_OK;
}

/* Free list */
void rotation_free_list(char **list, size_t n)
{
    if (!list) return;
    for (size_t i = 0; i < n; ++i) free(list[i]);
    free(list);
}

/* Initialize rotation subsystem (explicit call). */
int rotation_init(void)
{
    pthread_mutex_lock(&g_rot_lock);
    if (g_rot_initialized) {
        pthread_mutex_unlock(&g_rot_lock);
        rot_log("already initialized");
        return ROT_OK;
    }

    if (rot_ensure_dirs() != ROT_OK) {
        pthread_mutex_unlock(&g_rot_lock);
        rot_log("INITIALIZATION FAILURE: could not ensure directories");
        return ROT_ERR;
    }

    g_rot_initialized = 1;
    pthread_mutex_unlock(&g_rot_lock);
    rot_log("INITIALIZATION SUCCESS: rotation subsystem ready");
    return ROT_OK;
}

/* Shutdown */
void rotation_shutdown(void)
{
    pthread_mutex_lock(&g_rot_lock);
    g_rot_initialized = 0;
    pthread_mutex_unlock(&g_rot_lock);
    rot_log("shutdown complete");
}

/* Auto-init so you'll see rotation status on startup without editing seed (optional) */
__attribute__((constructor))
static void rotation_autoinit(void)
{
    /* ignore result; messages printed by rotation_init */
    rotation_init();
}
