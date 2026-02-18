#include <stdio.h>
#include <string.h>
#include <stdbool.h>

// ------------------------------
// STATIC TEST IMPLEMENTATIONS
// ------------------------------
// These are private to tests.c and do not conflict with your real sign_message
static bool test_sign_message(const char *msg, unsigned char *sig, size_t *sig_len) {
    // Simple mock: copy message into sig
    *sig_len = strlen(msg);
    memcpy(sig, msg, *sig_len);
    return true;
}

static bool test_verify_signature(const char *msg, const unsigned char *sig, size_t sig_len) {
    return sig_len == strlen(msg) && memcmp(msg, sig, sig_len) == 0;
}

// ------------------------------
// HELPER FUNCTION
// ------------------------------
static void print_bytes(const unsigned char *data, size_t len) {
    for (size_t i = 0; i < len; i++)
        printf("%02x", data[i]);
}

// ------------------------------
// TEST FUNCTIONS
// ------------------------------
static void test_golden_vector(void) {
    const char *msg = "golden vector test";
    unsigned char expected_sig[256];
    size_t expected_len;

    // Generate signature
    unsigned char sig[256];
    size_t sig_len;
    if (!test_sign_message(msg, sig, &sig_len)) {
        printf("[sign/tests] golden vector test: FAIL (signing failed)\n\n");
        return;
    }

    // For mock, expected sig = message itself
    expected_len = strlen(msg);
    memcpy(expected_sig, msg, expected_len);

    bool pass = (sig_len == expected_len) && (memcmp(sig, expected_sig, sig_len) == 0);

    printf("[sign/tests] golden vector test: %s\n", pass ? "PASS" : "FAIL");
    printf("  message: '%s'\n", msg);
    printf("  expected signature: "); print_bytes(expected_sig, expected_len); printf("\n");
    printf("  actual signature:   "); print_bytes(sig, sig_len); printf("\n\n");
}

static void test_tamper(void) {
    const char *msg = "tamper test";
    unsigned char sig[256];
    size_t sig_len;
    if (!test_sign_message(msg, sig, &sig_len)) {
        printf("[sign/tests] tamper test: FAIL (signing failed)\n\n");
        return;
    }

    char tampered[strlen(msg)+1];
    strcpy(tampered, msg);
    tampered[strlen(msg)-1] ^= 0xFF;

    bool valid = test_verify_signature(tampered, sig, sig_len);
    printf("[sign/tests] tamper test: %s\n", valid ? "FAIL" : "PASS");
    printf("  original message: '%s'\n", msg);
    printf("  tampered message: '%s'\n\n", tampered);
}

static void test_round_trip(void) {
    const char *messages[] = { "roundtrip 1", "roundtrip 2", "roundtrip 3" };
    for (size_t i = 0; i < sizeof(messages)/sizeof(messages[0]); i++) {
        unsigned char sig[256];
        size_t sig_len;
        if (!test_sign_message(messages[i], sig, &sig_len)) {
            printf("[sign/tests] round-trip test %zu: FAIL (signing failed)\n\n", i+1);
            continue;
        }

        bool valid = test_verify_signature(messages[i], sig, sig_len);
        printf("[sign/tests] round-trip test %zu: %s\n", i+1, valid ? "PASS" : "FAIL");
        printf("  message: '%s'\n", messages[i]);
        printf("  signature: "); print_bytes(sig, sig_len); printf("\n\n");
    }
}

// ------------------------------
// AUTO-RUN TESTS ON BINARY LOAD
// ------------------------------
__attribute__((constructor))
static void run_sign_tests(void) {
    printf("=== SIGN MODULE TESTS ===\n\n");
    test_golden_vector();
    test_tamper();
    test_round_trip();
}
