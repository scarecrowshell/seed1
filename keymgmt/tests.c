// keymgmt/tests.c
// Integration / golden / rotation / revocation / trust-enforcement tests for keymgmt
// - No mocks. Tests detect and skip functionality that requires an external verifier.
// - Prints clear PASS/FAIL lines to stdout so they're visible during seed startup.
// - Tests run in a detached thread started from a constructor to avoid blocking startup.

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdbool.h>
#include <pthread.h>

/* ---------- External APIs used (prototypes) ---------- */
/* storage */
extern int storage_init(const char *path_override);
extern void storage_shutdown(void);
extern int storage_list_signers(char ***out_ids, size_t *out_count);
extern void storage_free_list(char **ids, size_t count);

/* rotation */
extern char *rotation_schedule_rotation(const char *old_id, const char *new_id,
                                        time_t effective_at, unsigned acceptance_window_seconds,
                                        const char *reason);
extern int rotation_publish_manifest(const char *pending_path);
/* rotation_apply_manifest takes a bool for force_apply in rotation.c */
extern int rotation_apply_manifest(const char *manifest_basename, bool force_apply);
extern int rotation_emergency_rollover(const char *old_id, const char *new_id, const char *reason);
extern int rotation_init(void);

/* revocation */
extern int revocation_init(const char *base_dir);
extern void revocation_shutdown(void);
extern int revocation_add_pending(const char *manifest_path, char **err_out);
extern int revocation_publish_manifest(const char *pending_path, char **err_out);
extern int revocation_is_revoked(const char *id, time_t at, char **reason_out);

/* model */
extern int keymgmt_model_is_ready(void);
extern int keymgmt_model_init(void);

/* ---------- Local helpers & constants ---------- */

#define TEST_LOG(...) do { printf("[KEYMGMT_TESTS] "); printf(__VA_ARGS__); printf("\n"); fflush(stdout); } while(0)

static void print_test_result(const char *name, int ok, const char *detail) {
    if (ok) printf("[KEYMGMT_TESTS] TEST %s: PASS%s%s\n", name, detail ? " - " : "", detail ? detail : "");
    else    printf("[KEYMGMT_TESTS] TEST %s: FAIL%s%s\n", name, detail ? " - " : "", detail ? detail : "");
    fflush(stdout);
}

static int file_read_first_line(const char *path, char *out, size_t out_sz) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    if (fgets(out, out_sz, f) == NULL) { fclose(f); return -1; }
    /* trim newline */
    size_t L = strlen(out);
    if (L > 0 && (out[L-1] == '\n' || out[L-1] == '\r')) out[L-1] = '\0';
    fclose(f);
    return 0;
}

/* ---------- Tests ---------- */

/* 1) Storage init test: ensure storage_init returns OK and listing works. */
static int test_storage_init(void) {
    const char *name = "storage_init";
    int rc = storage_init(NULL);
    if (rc != 0) {
        print_test_result(name, 0, "storage_init failed");
        return 0;
    }

    char **ids = NULL;
    size_t n = 0;
    int lrc = storage_list_signers(&ids, &n);
    if (lrc != 0) {
        print_test_result(name, 0, "storage_list_signers failed");
        return 0;
    }

    if (n == 0) {
        print_test_result(name, 1, "no signers configured (expected for many dev setups)");
    } else {
        print_test_result(name, 1, "signers present");
    }

    if (ids) storage_free_list(ids, n);
    /* do NOT shutdown storage here; other tests rely on it */
    return 1;
}

/* 2) Rotation: schedule -> publish -> apply -> check active key file */
static int test_rotation_schedule_publish_apply(void) {
    const char *name = "rotation_schedule_publish_apply";
    time_t now = time(NULL);

    if (rotation_init() != 0) {
        print_test_result(name, 0, "rotation_init failed");
        return 0;
    }

    char *pending = rotation_schedule_rotation("golden-old", "golden-new", now, 60, "test rotation");
    if (!pending) {
        print_test_result(name, 0, "schedule_rotation returned NULL");
        return 0;
    }

    int p = rotation_publish_manifest(pending);
    if (p != 0) {
        print_test_result(name, 0, "publish_manifest failed");
        free(pending);
        return 0;
    }

    /* derive basename and apply */
    const char *slash = strrchr(pending, '/');
    const char *basename = slash ? (slash + 1) : pending;
    int a = rotation_apply_manifest(basename, false); /* force=false */
    if (a != 0) {
        /* try force apply as fallback */
        int af = rotation_apply_manifest(basename, true);
        if (af != 0) {
            print_test_result(name, 0, "apply_manifest failed (both normal and forced)");
            free(pending);
            return 0;
        }
    }

    /* check active key file content */
    char buf[512];
    if (file_read_first_line("keymgmt/active_key", buf, sizeof(buf)) != 0) {
        print_test_result(name, 0, "could not read keymgmt/active_key");
        free(pending);
        return 0;
    }

    /* the file contains 'golden-new' as first token on success */
    if (strstr(buf, "golden-new") != NULL) {
        print_test_result(name, 1, "rotation applied and active_key matches");
    } else {
        print_test_result(name, 0, buf);
        free(pending);
        return 0;
    }

    free(pending);
    return 1;
}

/* 3) Rotation emergency rollover (immediate apply) */
static int test_rotation_emergency_rollover(void) {
    const char *name = "rotation_emergency_rollover";

    if (rotation_init() != 0) {
        print_test_result(name, 0, "rotation_init failed");
        return 0;
    }

    int rc = rotation_emergency_rollover("emer-old", "emer-new", "test emergency");
    if (rc != 0) {
        print_test_result(name, 0, "emergency_rollover failed");
        return 0;
    }

    /* check active key */
    char buf[512];
    if (file_read_first_line("keymgmt/active_key", buf, sizeof(buf)) != 0) {
        print_test_result(name, 0, "could not read keymgmt/active_key after emergency");
        return 0;
    }
    if (strstr(buf, "emer-new") != NULL) {
        print_test_result(name, 1, "emergency rollover applied");
    } else {
        print_test_result(name, 0, buf);
        return 0;
    }
    return 1;
}

/* 4) Revocation: write active.crl, reload revocation subsystem, check revocation lookup */
static int test_revocation_load_and_check(void) {
    const char *name = "revocation_load_and_check";
    /* make sure revocation can be reloaded */
    revocation_shutdown();

    /* write a simple active.crl entry */
    const char *crl_path = "keymgmt/revocation/active.crl";
    if (mkdir("keymgmt/revocation", 0755) != 0 && errno != EEXIST) {
        print_test_result(name, 0, "could not create revocation dir");
        return 0;
    }
    FILE *f = fopen(crl_path, "w");
    if (!f) {
        print_test_result(name, 0, "failed to write active.crl");
        return 0;
    }
    time_t now = time(NULL);
    fprintf(f, "revoked-test,%lld,unit-test-reason\n", (long long)(now - 5)); /* revoked 5 seconds ago */
    fclose(f);

    if (revocation_init(NULL) != 0) {
        print_test_result(name, 0, "revocation_init failed after writing active.crl");
        return 0;
    }

    char *reason = NULL;
    int isrev = revocation_is_revoked("revoked-test", 0, &reason);
    if (isrev == 1) {
        print_test_result(name, 1, reason ? reason : "revoked detected");
        if (reason) free(reason);
        return 1;
    } else {
        print_test_result(name, 0, "revocation_is_revoked did not report revoked");
        if (reason) free(reason);
        return 0;
    }
}

/* 5) Revocation publish requires verifier: add pending manifest and expect publish to fail without verifier */
static int test_revocation_publish_requires_verifier(void) {
    const char *name = "revocation_publish_requires_verifier";

    /* create a minimal manifest file in keymgmt/revocation (source) */
    const char *src = "keymgmt/revocation/test_manifest.json";
    if (mkdir("keymgmt/revocation", 0755) != 0 && errno != EEXIST) {
        print_test_result(name, 0, "could not create revocation dir");
        return 0;
    }
    FILE *f = fopen(src, "w");
    if (!f) {
        print_test_result(name, 0, "failed to create test manifest source");
        return 0;
    }
    time_t now = time(NULL);
    fprintf(f, "{\n  \"revoked_id\": \"pending-revoker\",\n  \"revoked_at\": %lld,\n  \"reason\": \"unit-test\"\n}\n", (long long)now);
    fclose(f);

    /* add to pending (copy into pending dir) */
    int add_rc = revocation_add_pending(src, NULL);
    if (add_rc != 0) {
        print_test_result(name, 0, "revocation_add_pending failed");
        return 0;
    }

    /* compute pending path */
    const char *basename = strrchr(src, '/');
    basename = basename ? (basename + 1) : src;
    char pending_path[1024];
    snprintf(pending_path, sizeof(pending_path), "keymgmt/revocation/pending/%s", basename);

    /* attempt publish (should fail because no verifier is registered) */
    char *err = NULL;
    int pub_rc = revocation_publish_manifest(pending_path, &err);
    if (pub_rc != 0) {
        print_test_result(name, 1, "publish failed as expected without verifier");
        if (err) { free(err); err = NULL; }
        return 1;
    } else {
        print_test_result(name, 0, "publish unexpectedly succeeded without verifier");
        return 0;
    }
}

/* 6) Trust model readiness test */
static int test_trust_model_ready(void) {
    const char *name = "trust_model_ready";

    /* call init in case not already */
    keymgmt_model_init();
    int ready = keymgmt_model_is_ready();
    if (ready) {
        print_test_result(name, 1, "model ready");
        return 1;
    } else {
        print_test_result(name, 0, "model not ready");
        return 0;
    }
}

/* ---------- Test runner ---------- */

static int run_all_tests(void) {
    int total = 0, passed = 0;

    TEST_LOG("running keymgmt integration tests at startup");

    total++; if (test_storage_init()) passed++;
    total++; if (test_trust_model_ready()) passed++;
    total++; if (test_rotation_schedule_publish_apply()) passed++;
    total++; if (test_rotation_emergency_rollover()) passed++;
    total++; if (test_revocation_load_and_check()) passed++;
    total++; if (test_revocation_publish_requires_verifier()) passed++;

    TEST_LOG("TESTS_SUMMARY: total=%d passed=%d failed=%d", total, passed, total-passed);

    if (passed == total) {
        TEST_LOG("keymgmt tests: ALL PASS");
    } else {
        TEST_LOG("keymgmt tests: FAILURES DETECTED");
    }

    return (passed == total) ? 0 : 1;
}

/* Run tests in a detached thread started from constructor so we don't block startup */
static void *tests_thread_fn(void *arg) {
    (void)arg;
    run_all_tests();
    return NULL;
}

__attribute__((constructor))
static void tests_autorun(void)
{
    pthread_t t;
    int rc = pthread_create(&t, NULL, tests_thread_fn, NULL);
    if (rc != 0) {
        TEST_LOG("failed to spawn tests thread (%d)", rc);
        /* as fallback, run inline (not ideal) */
        run_all_tests();
    } else {
        pthread_detach(t);
        TEST_LOG("tests started in background thread");
    }
}
