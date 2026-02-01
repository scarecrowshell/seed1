// keymgmt/model.c
// Trust model for key management
// Defines authorized signers, quorum rules, and signer metadata
// No mocks. Explicit status reporting.

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

/* =========================
   Types
   ========================= */

typedef struct {
    char id[64];
    char role[32];
    int  active;   // 1 == active, 0 == inactive/revoked
} signer_t;

typedef struct {
    unsigned required;
    unsigned total;
} quorum_t;

/* =========================
   Internal state
   ========================= */

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

static signer_t *g_signers = NULL;
static size_t    g_signer_count = 0;
static quorum_t  g_quorum = {0, 0};

static int g_model_initialized = 0;

/* =========================
   Internal helpers
   ========================= */

static void model_print_signers(void) {
    if (g_signer_count == 0) {
        printf("KEYMGMT_MODEL: no authorized signers configured\n");
        return;
    }

    for (size_t i = 0; i < g_signer_count; i++) {
        printf("KEYMGMT_MODEL: signer[%zu] id='%s' role='%s' active=%d\n",
               i,
               g_signers[i].id,
               g_signers[i].role,
               g_signers[i].active);
    }
}

static int model_validate_quorum(void) {
    if (g_quorum.total == 0) {
        printf("KEYMGMT_MODEL: quorum undefined (no signers)\n");
        return 0; /* not an error for empty model */
    }

    if (g_quorum.required == 0) {
        printf("KEYMGMT_MODEL: INVALID quorum (required=0)\n");
        return -1;
    }

    if (g_quorum.required > g_quorum.total) {
        printf("KEYMGMT_MODEL: INVALID quorum (%u required > %u total)\n",
               g_quorum.required, g_quorum.total);
        return -1;
    }

    printf("KEYMGMT_MODEL: quorum OK (%u-of-%u)\n",
           g_quorum.required, g_quorum.total);
    return 0;
}

/* =========================
   Public API
   ========================= */

/* Initialize trust model. Returns 0 on success, -1 on invalid policy. */
int keymgmt_model_init(void) {
    pthread_mutex_lock(&g_lock);

    if (g_model_initialized) {
        pthread_mutex_unlock(&g_lock);
        printf("KEYMGMT_MODEL: already initialized\n");
        fflush(stdout);
        return 0;
    }

    /* No external config yet: empty model is allowed but reported. */
    g_signers = NULL;
    g_signer_count = 0;
    g_quorum.total = 0;
    g_quorum.required = 0;

    printf("KEYMGMT_MODEL: initializing trust model\n");

    model_print_signers();

    if (model_validate_quorum() == 0) {
        printf("KEYMGMT_MODEL: READY (no trust policy enforced)\n");
    } else {
        printf("KEYMGMT_MODEL: ERROR (invalid trust policy)\n");
        pthread_mutex_unlock(&g_lock);
        return -1;
    }

    g_model_initialized = 1;
    pthread_mutex_unlock(&g_lock);
    fflush(stdout);
    return 0;
}

/* Query readiness */
int keymgmt_model_is_ready(void) {
    return g_model_initialized;
}

/* (Optional) destructor if you want to free model state later */
void keymgmt_model_shutdown(void) {
    pthread_mutex_lock(&g_lock);
    if (g_signers) {
        free(g_signers);
        g_signers = NULL;
    }
    g_signer_count = 0;
    g_quorum.total = g_quorum.required = 0;
    g_model_initialized = 0;
    pthread_mutex_unlock(&g_lock);
    printf("KEYMGMT_MODEL: shutdown\n");
    fflush(stdout);
}
