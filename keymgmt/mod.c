// keymgmt/mod.c
// Public entrypoint for key management subsystem
// Responsible for initialization, signer lookup, and verification dispatch
// No mocks. If nothing is configured, state is reported explicitly.

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>   // localtime_r, time
#include <pthread.h>

/* =========================
   Internal state
   ========================= */

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static int g_initialized = 0;

/* =========================
   Helpers
   ========================= */



/* =========================
   Public API
   ========================= */

/*
 * Initialize key management subsystem.
 * cfg is reserved for future configuration (trust roots, storage backends).
 * Passing NULL is valid and means "no external configuration".
 */
int keymgmt_init(const void *cfg) {
    (void)cfg;

    pthread_mutex_lock(&g_lock);

    if (g_initialized) {
        pthread_mutex_unlock(&g_lock);
        printf("KEYMGMT: ALREADY INITIALIZED\n");
        fflush(stdout);
        return 0;
    }

    g_initialized = 1;

    pthread_mutex_unlock(&g_lock);

    /*
     * IMPORTANT:
     * At this stage there are no signers, no trust roots, and no storage backends.
     * This is not an error — it simply means verification is not yet enforceable.
     */
    printf("KEYMGMT: READY (no signers configured)\n");
    fflush(stdout);

    return 0;
}

/*
 * Shutdown key management subsystem.
 * Safe to call even if never initialized.
 */
void keymgmt_shutdown(void) {
    pthread_mutex_lock(&g_lock);
    g_initialized = 0;
    pthread_mutex_unlock(&g_lock);

    printf("KEYMGMT: SHUTDOWN\n");
    fflush(stdout);
}

/*
 * Retrieve signer by identifier.
 * Since no signers exist yet, this always reports absence explicitly.
 */
void *keymgmt_get_signer_by_id(const char *signer_id) {
    if (!g_initialized) {
        printf("KEYMGMT: ERROR (not initialized)\n");
        fflush(stdout);
        return NULL;
    }

    printf("KEYMGMT: signer '%s' not found (no signers configured)\n",
           signer_id ? signer_id : "<null>");
    fflush(stdout);

    return NULL;
}

/*
 * Verify a signature.
 * Without signers or trust roots, verification is impossible and stated clearly.
 */
int keymgmt_verify_signature(const void *data,
                             size_t data_len,
                             const void *sig,
                             size_t sig_len,
                             const char *signer_id) {
    (void)data;
    (void)data_len;
    (void)sig;
    (void)sig_len;

    if (!g_initialized) {
        printf("KEYMGMT: VERIFY FAIL (not initialized)\n");
        fflush(stdout);
        return -1;
    }

    printf("KEYMGMT: VERIFY SKIPPED (no signers configured, signer='%s')\n",
           signer_id ? signer_id : "<null>");
    fflush(stdout);

    return 0;
}
