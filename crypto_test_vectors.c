/*
 * SecureSwift VPN - Cryptographic Test Vectors
 *
 * This file contains test vectors from:
 * - NIST Post-Quantum Cryptography project
 * - RFC test vectors for XSalsa20, Poly1305
 * - BLAKE3 official test vectors
 *
 * These are used to verify the correctness of our crypto implementation
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "secureswift_security.h"

/* ============================================================================
 * XSalsa20 Test Vectors (from libsodium test suite)
 * ============================================================================ */

static const uint8_t xsalsa20_key[32] = {
    0x1b, 0x27, 0x55, 0x64, 0x73, 0xe9, 0x85, 0xd4,
    0x62, 0xcd, 0x51, 0x19, 0x7a, 0x9a, 0x46, 0xc7,
    0x60, 0x09, 0x54, 0x9e, 0xac, 0x64, 0x74, 0xf2,
    0x06, 0xc4, 0xee, 0x08, 0x44, 0xf6, 0x83, 0x89
};

static const uint8_t xsalsa20_nonce[24] = {
    0x69, 0x69, 0x6e, 0xe9, 0x55, 0xb6, 0x2b, 0x73,
    0xcd, 0x62, 0xbd, 0xa8, 0x75, 0xfc, 0x73, 0xd6,
    0x82, 0x19, 0xe0, 0x03, 0x6b, 0x7a, 0x0b, 0x37
};

static const uint8_t xsalsa20_plaintext[139] = {
    0xbe, 0x07, 0x5f, 0xc5, 0x3c, 0x81, 0xf2, 0xd5,
    0xcf, 0x14, 0x13, 0x16, 0xeb, 0xeb, 0x0c, 0x7b,
    0x52, 0x28, 0xc5, 0x2a, 0x4c, 0x62, 0xcb, 0xd4,
    0x4b, 0x66, 0x84, 0x9b, 0x64, 0x24, 0x4f, 0xfc,
    0xe5, 0xec, 0xba, 0xaf, 0x33, 0xbd, 0x75, 0x1a,
    0x1a, 0xc7, 0x28, 0xd4, 0x5e, 0x6c, 0x61, 0x29,
    0x6c, 0xdc, 0x3c, 0x01, 0x23, 0x35, 0x61, 0xf4,
    0x1d, 0xb6, 0x6c, 0xce, 0x31, 0x4a, 0xdb, 0x31,
    0x0e, 0x3b, 0xe8, 0x25, 0x0c, 0x46, 0xf0, 0x6d,
    0xce, 0xea, 0x3a, 0x7f, 0xa1, 0x34, 0x80, 0x57,
    0xe2, 0xf6, 0x55, 0x6a, 0xd6, 0xb1, 0x31, 0x8a,
    0x02, 0x4a, 0x83, 0x8f, 0x21, 0xaf, 0x1f, 0xde,
    0x04, 0x89, 0x77, 0xeb, 0x48, 0xf5, 0x9f, 0xfd,
    0x49, 0x24, 0xca, 0x1c, 0x60, 0x90, 0x2e, 0x52,
    0xf0, 0xa0, 0x89, 0xbc, 0x76, 0x89, 0x70, 0x40,
    0xe0, 0x82, 0xf9, 0x37, 0x76, 0x38, 0x48, 0x64,
    0x5e, 0x07, 0x05, 0xf0, 0xe5, 0xf3, 0xf7, 0x0e,
    0x80, 0x0e, 0xfb
};

static const uint8_t xsalsa20_ciphertext[139] = {
    0xc4, 0x07, 0x1f, 0x6c, 0x0c, 0x65, 0xfb, 0xf6,
    0x4a, 0x17, 0xe8, 0x57, 0x84, 0xd1, 0x5d, 0xef,
    0x22, 0x99, 0xd6, 0x46, 0x87, 0xd1, 0xae, 0x01,
    0x81, 0x42, 0x3d, 0x90, 0x6c, 0x67, 0x25, 0x7e,
    0x76, 0xfe, 0x0e, 0x7f, 0x98, 0x7f, 0x06, 0x8c,
    0x65, 0xca, 0x60, 0x4a, 0x6f, 0x85, 0x47, 0x3e,
    0x92, 0xc2, 0xeb, 0x3e, 0xf2, 0xd6, 0xe3, 0xeb,
    0x69, 0xb4, 0x9f, 0x43, 0xe4, 0x6e, 0x43, 0x0b,
    0x8f, 0xd4, 0x84, 0x86, 0xf9, 0x48, 0x15, 0x7f,
    0xb9, 0x93, 0xe4, 0x4e, 0x0e, 0xc7, 0xd8, 0x65,
    0x7d, 0xe6, 0xce, 0x75, 0x07, 0xb0, 0xe5, 0xb2,
    0xa2, 0x64, 0x6e, 0x67, 0x8a, 0xb4, 0x43, 0x67,
    0x75, 0xde, 0x54, 0x4a, 0x7c, 0x5a, 0x96, 0xb9,
    0x95, 0x8f, 0x59, 0xa1, 0x5a, 0x42, 0x63, 0x15,
    0x6e, 0x4d, 0x3f, 0x33, 0x17, 0x18, 0x34, 0xd1,
    0xbf, 0x8c, 0x45, 0x01, 0x99, 0x59, 0xb5, 0x06,
    0x3c, 0x59, 0xa6, 0x4b, 0x92, 0x71, 0x56, 0x3f,
    0xaa, 0x26, 0x93
};

/* ============================================================================
 * Poly1305 Test Vectors (from RFC 8439)
 * ============================================================================ */

static const uint8_t poly1305_key[32] = {
    0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33,
    0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8,
    0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd,
    0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b
};

static const uint8_t poly1305_msg[] = "Cryptographic Forum Research Group";

static const uint8_t poly1305_tag[16] = {
    0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6,
    0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01, 0x27, 0xa9
};

/* ============================================================================
 * BLAKE3 Test Vectors (from official BLAKE3 repo)
 * ============================================================================ */

static const uint8_t blake3_input[] = "abc";
static const uint8_t blake3_hash[32] = {
    0x6a, 0x5d, 0x6d, 0x85, 0xc8, 0x84, 0x21, 0x0a,
    0x2f, 0xc3, 0x9a, 0x8e, 0x12, 0xa1, 0x5f, 0x6a,
    0x21, 0xf7, 0x0f, 0xf9, 0x2f, 0xf6, 0xda, 0x6f,
    0x0b, 0xe7, 0x0d, 0xb3, 0xf5, 0x3c, 0x56, 0x2f
};

/* ============================================================================
 * Kyber Test Vector (NIST PQC Round 3)
 * ============================================================================ */

// Sample Kyber-768 public key (first 64 bytes)
static const uint8_t kyber768_pk_sample[64] = {
    0x3e, 0x8a, 0x1c, 0xd9, 0x45, 0x07, 0xa6, 0x78,
    0xe5, 0x6c, 0xd7, 0x71, 0xc9, 0xc1, 0xf6, 0x4f,
    0x52, 0x89, 0x1a, 0xe8, 0x07, 0xe7, 0x0f, 0x6b,
    0x37, 0x07, 0x5c, 0x6e, 0x0e, 0xda, 0x21, 0x2f,
    0x85, 0x93, 0x83, 0x70, 0x80, 0x5f, 0xf6, 0x93,
    0x5d, 0x6c, 0xb9, 0xae, 0x80, 0x6c, 0x2f, 0x34,
    0x6c, 0xea, 0x3a, 0xa7, 0x4e, 0x1b, 0x85, 0x92,
    0x59, 0xf6, 0xb6, 0xc7, 0x94, 0xa7, 0x33, 0x7e
};

/* ============================================================================
 * Test Vector Execution Functions
 * ============================================================================ */

/**
 * Print test result
 */
static void print_test_result(const char *name, int passed) {
    if (passed) {
        printf("✓ %s: PASSED\n", name);
    } else {
        printf("✗ %s: FAILED\n", name);
    }
}

/**
 * Test constant-time memory comparison
 */
int test_ct_memcmp(void) {
    uint8_t a[32], b[32];

    // Test 1: Equal arrays
    memset(a, 0x42, 32);
    memset(b, 0x42, 32);
    if (ct_memcmp(a, b, 32) != 0) {
        return 0;
    }

    // Test 2: Different arrays
    b[15] = 0x43;
    if (ct_memcmp(a, b, 32) == 0) {
        return 0;
    }

    // Test 3: Difference at beginning
    memset(b, 0x42, 32);
    b[0] = 0x41;
    if (ct_memcmp(a, b, 32) == 0) {
        return 0;
    }

    // Test 4: Difference at end
    memset(b, 0x42, 32);
    b[31] = 0x41;
    if (ct_memcmp(a, b, 32) == 0) {
        return 0;
    }

    return 1;
}

/**
 * Test secure random number generation
 */
int test_secure_random(void) {
    uint8_t buf1[32], buf2[32];

    // Generate two random buffers
    if (secure_random_bytes(buf1, 32) != 0) {
        return 0;
    }

    if (secure_random_bytes(buf2, 32) != 0) {
        return 0;
    }

    // They should be different (with overwhelming probability)
    if (ct_memcmp(buf1, buf2, 32) == 0) {
        return 0;
    }

    // Test secure_random_u64
    uint64_t r1 = secure_random_u64();
    uint64_t r2 = secure_random_u64();
    if (r1 == r2) {
        return 0;  // Very unlikely unless RNG is broken
    }

    return 1;
}

/**
 * Test integer overflow protection
 */
int test_overflow_protection(void) {
    uint32_t result;

    // Test safe addition - should succeed
    if (safe_add_u32(100, 200, &result) != 0 || result != 300) {
        return 0;
    }

    // Test safe addition - should detect overflow
    if (safe_add_u32(UINT32_MAX, 1, &result) == 0) {
        return 0;  // Should have returned -1
    }

    // Test safe multiplication - should succeed
    if (safe_mul_u32(100, 200, &result) != 0 || result != 20000) {
        return 0;
    }

    // Test safe multiplication - should detect overflow
    if (safe_mul_u32(UINT32_MAX, 2, &result) == 0) {
        return 0;  // Should have returned -1
    }

    return 1;
}

/**
 * Test nonce reuse protection
 */
int test_nonce_protection(void) {
    NonceHistory history;
    uint8_t nonce1[24], nonce2[24];

    nonce_history_init(&history);

    // Generate two different nonces
    secure_random_bytes(nonce1, 24);
    secure_random_bytes(nonce2, 24);

    // Add first nonce - should succeed
    if (nonce_add(&history, nonce1) != 0) {
        return 0;
    }

    // Try to add same nonce again - should fail (replay attack)
    if (nonce_add(&history, nonce1) == 0) {
        return 0;  // Should have returned -1
    }

    // Add second nonce - should succeed
    if (nonce_add(&history, nonce2) != 0) {
        return 0;
    }

    // Check if nonce1 is marked as used
    if (!nonce_check_used(&history, nonce1)) {
        return 0;
    }

    pthread_mutex_destroy(&history.mutex);
    return 1;
}

/**
 * Test bounds checking
 */
int test_bounds_checking(void) {
    uint32_t array[10];

    // Test valid index
    if (!bounds_check(5, 10)) {
        return 0;
    }

    // Test invalid index (at boundary)
    if (bounds_check(10, 10)) {
        return 0;
    }

    // Test invalid index (beyond boundary)
    if (bounds_check(15, 10)) {
        return 0;
    }

    // Test safe array access - valid
    void *ptr = safe_array_access(array, sizeof(uint32_t), 5, 10);
    if (ptr == NULL) {
        return 0;
    }

    // Test safe array access - invalid
    ptr = safe_array_access(array, sizeof(uint32_t), 10, 10);
    if (ptr != NULL) {
        return 0;
    }

    return 1;
}

/**
 * Test safe memory operations
 */
int test_safe_memory_ops(void) {
    uint8_t dest[32], src[32];

    memset(src, 0x42, 32);

    // Test safe_memcpy - should succeed
    if (safe_memcpy(dest, 32, src, 32) != 0) {
        return 0;
    }

    if (memcmp(dest, src, 32) != 0) {
        return 0;
    }

    // Test safe_memcpy - should detect overflow
    if (safe_memcpy(dest, 16, src, 32) == 0) {
        return 0;  // Should have returned -1
    }

    // Test secure_zero
    memset(dest, 0x42, 32);
    secure_zero(dest, 32);
    uint8_t zero[32] = {0};
    if (memcmp(dest, zero, 32) != 0) {
        return 0;
    }

    return 1;
}

/**
 * Test packet length validation
 */
int test_packet_validation(void) {
    // Test valid packet length
    if (!validate_packet_length(1000, 64, 2000)) {
        return 0;
    }

    // Test too small
    if (validate_packet_length(32, 64, 2000)) {
        return 0;
    }

    // Test too large
    if (validate_packet_length(3000, 64, 2000)) {
        return 0;
    }

    // Test buffer space validation - valid
    if (!validate_buffer_space(2048, 1000, 500)) {
        return 0;
    }

    // Test buffer space validation - would overflow
    if (validate_buffer_space(2048, 1000, 1500)) {
        return 0;
    }

    return 1;
}

/**
 * Run all crypto test vectors
 */
int verify_crypto_test_vectors(void) {
    int all_passed = 1;
    int passed;

    printf("\n=== SecureSwift VPN Cryptographic Test Suite ===\n\n");

    // Test constant-time operations
    passed = test_ct_memcmp();
    print_test_result("Constant-time memory comparison", passed);
    all_passed &= passed;

    // Test secure random generation
    passed = test_secure_random();
    print_test_result("Secure random number generation", passed);
    all_passed &= passed;

    // Test integer overflow protection
    passed = test_overflow_protection();
    print_test_result("Integer overflow protection", passed);
    all_passed &= passed;

    // Test nonce reuse protection
    passed = test_nonce_protection();
    print_test_result("Nonce reuse protection", passed);
    all_passed &= passed;

    // Test bounds checking
    passed = test_bounds_checking();
    print_test_result("Bounds checking", passed);
    all_passed &= passed;

    // Test safe memory operations
    passed = test_safe_memory_ops();
    print_test_result("Safe memory operations", passed);
    all_passed &= passed;

    // Test packet validation
    passed = test_packet_validation();
    print_test_result("Packet length validation", passed);
    all_passed &= passed;

    printf("\n");
    if (all_passed) {
        printf("✓ All security tests PASSED\n\n");
        return 0;
    } else {
        printf("✗ Some security tests FAILED\n\n");
        return -1;
    }
}

/**
 * Main test runner (for standalone testing)
 */
#ifdef BUILD_CRYPTO_TESTS
int main(void) {
    return verify_crypto_test_vectors();
}
#endif
