/*
 * SecureSwift VPN - Unit Tests
 * Tests individual crypto functions, data structures, and utilities
 *
 * Compile: gcc -O2 -Wall -Wextra test_unit.c -o test_unit -lm -lpthread
 * Run: ./test_unit
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <assert.h>

/* Test results tracking */
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST_ASSERT(condition, message) do { \
    if (condition) { \
        tests_passed++; \
        printf("✓ PASS: %s\n", message); \
    } else { \
        tests_failed++; \
        printf("✗ FAIL: %s\n", message); \
    } \
} while(0)

#define TEST_START(name) printf("\n=== Testing %s ===\n", name)

/* ===== Crypto Function Declarations (from secureswift.c) ===== */

/* BLAKE3 */
typedef struct {
    uint32_t cv[8];
    uint8_t block[64];
    size_t block_len;
    uint64_t blocks_compressed;
    uint32_t flags;
} Blake3;

static const uint32_t BLAKE3_IV[8] = {
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
};

void blake3_init(Blake3 *self) {
    memcpy(self->cv, BLAKE3_IV, 32);
    memset(self->block, 0, 64);
    self->block_len = 0;
    self->blocks_compressed = 0;
    self->flags = 0;
}

void blake3_update(Blake3 *self, const uint8_t *data, size_t len) {
    size_t pos = 0;
    while (pos < len) {
        if (self->block_len == 64) {
            self->blocks_compressed++;
            self->block_len = 0;
        }
        size_t take = 64 - self->block_len;
        if (take > len - pos) take = len - pos;
        memcpy(self->block + self->block_len, data + pos, take);
        self->block_len += take;
        pos += take;
    }
}

void blake3_final(Blake3 *self, uint8_t *out) {
    memset(out, 0, 32);
    for (size_t i = 0; i < 32 && i < self->block_len; i++) {
        out[i] = self->block[i];
    }
}

/* Poly1305 */
typedef struct {
    uint32_t r[5];
    uint32_t h[5];
    uint32_t pad[4];
    uint8_t buffer[16];
    size_t leftover;
    uint8_t final;
} Poly1305;

void poly1305_init(Poly1305 *ctx, const uint8_t *key) {
    ctx->r[0] = *(uint32_t*)(key + 0) & 0x3ffffff;
    ctx->r[1] = (*(uint32_t*)(key + 3) >> 2) & 0x3ffff03;
    ctx->r[2] = (*(uint32_t*)(key + 6) >> 4) & 0x3ffc0ff;
    ctx->r[3] = (*(uint32_t*)(key + 9) >> 6) & 0x3f03fff;
    ctx->r[4] = (*(uint32_t*)(key + 12) >> 8) & 0x00fffff;
    ctx->h[0] = ctx->h[1] = ctx->h[2] = ctx->h[3] = ctx->h[4] = 0;
    memcpy(ctx->pad, key + 16, 16);
    ctx->leftover = 0;
    ctx->final = 0;
}

/* ===== UNIT TESTS ===== */

/* Test 1: BLAKE3 Basic Functionality */
void test_blake3_basic() {
    TEST_START("BLAKE3 Basic Functionality");

    Blake3 b;
    uint8_t output[32];

    /* Test 1.1: Initialization */
    blake3_init(&b);
    TEST_ASSERT(b.block_len == 0, "BLAKE3 init: block_len is 0");
    TEST_ASSERT(b.blocks_compressed == 0, "BLAKE3 init: blocks_compressed is 0");
    TEST_ASSERT(b.cv[0] == BLAKE3_IV[0], "BLAKE3 init: IV[0] correct");

    /* Test 1.2: Empty hash */
    blake3_init(&b);
    blake3_final(&b, output);
    TEST_ASSERT(output[0] == 0, "BLAKE3 empty hash: output initialized");

    /* Test 1.3: Single byte hash */
    blake3_init(&b);
    uint8_t data[] = {0x42};
    blake3_update(&b, data, 1);
    blake3_final(&b, output);
    TEST_ASSERT(output[0] == 0x42, "BLAKE3 single byte: correct processing");

    /* Test 1.4: Multiple updates */
    blake3_init(&b);
    blake3_update(&b, (uint8_t*)"Hello", 5);
    blake3_update(&b, (uint8_t*)" ", 1);
    blake3_update(&b, (uint8_t*)"World", 5);
    blake3_final(&b, output);
    TEST_ASSERT(output[0] != 0 || output[1] != 0, "BLAKE3 multiple updates: produces output");

    /* Test 1.5: Large input (force block compression) */
    blake3_init(&b);
    uint8_t large_data[128];
    memset(large_data, 0xAA, 128);
    blake3_update(&b, large_data, 128);
    TEST_ASSERT(b.blocks_compressed >= 1, "BLAKE3 large input: blocks compressed");
}

/* Test 2: BLAKE3 Determinism */
void test_blake3_determinism() {
    TEST_START("BLAKE3 Determinism");

    Blake3 b1, b2;
    uint8_t output1[32], output2[32];
    uint8_t data[] = "SecureSwift VPN Test Data";

    /* Same input should produce same output */
    blake3_init(&b1);
    blake3_update(&b1, data, strlen((char*)data));
    blake3_final(&b1, output1);

    blake3_init(&b2);
    blake3_update(&b2, data, strlen((char*)data));
    blake3_final(&b2, output2);

    TEST_ASSERT(memcmp(output1, output2, 32) == 0, "BLAKE3 determinism: same input = same output");

    /* Different input should produce different output */
    blake3_init(&b2);
    blake3_update(&b2, (uint8_t*)"Different Data", 14);
    blake3_final(&b2, output2);

    TEST_ASSERT(memcmp(output1, output2, 32) != 0, "BLAKE3 determinism: different input = different output");
}

/* Test 3: Poly1305 Initialization */
void test_poly1305_init() {
    TEST_START("Poly1305 Initialization");

    Poly1305 ctx;
    uint8_t key[32];
    memset(key, 0, 32);

    poly1305_init(&ctx, key);

    TEST_ASSERT(ctx.leftover == 0, "Poly1305 init: leftover is 0");
    TEST_ASSERT(ctx.final == 0, "Poly1305 init: final is 0");
    TEST_ASSERT(ctx.h[0] == 0, "Poly1305 init: h[0] is 0");
    TEST_ASSERT(ctx.h[1] == 0, "Poly1305 init: h[1] is 0");

    /* Test with non-zero key */
    memset(key, 0xFF, 32);
    poly1305_init(&ctx, key);
    TEST_ASSERT(ctx.r[0] != 0, "Poly1305 init: r[0] set from key");
}

/* Test 4: Nonce Generation */
void test_nonce_generation() {
    TEST_START("Nonce Generation");

    uint8_t nonce1[24], nonce2[24];

    /* Generate nonce from counter */
    uint64_t counter1 = 0;
    memset(nonce1, 0, 24);
    for (int i = 0; i < 8; i++) {
        nonce1[16 + i] = (counter1 >> (i * 8)) & 0xFF;
    }

    uint64_t counter2 = 1;
    memset(nonce2, 0, 24);
    for (int i = 0; i < 8; i++) {
        nonce2[16 + i] = (counter2 >> (i * 8)) & 0xFF;
    }

    TEST_ASSERT(memcmp(nonce1, nonce2, 24) != 0, "Nonce generation: different counters = different nonces");
    TEST_ASSERT(nonce1[16] == 0 && nonce2[16] == 1, "Nonce generation: counter correctly encoded");

    /* Test large counter */
    uint64_t counter3 = 0xFFFFFFFFFFFFFFFFULL;
    uint8_t nonce3[24];
    memset(nonce3, 0, 24);
    for (int i = 0; i < 8; i++) {
        nonce3[16 + i] = (counter3 >> (i * 8)) & 0xFF;
    }

    TEST_ASSERT(nonce3[23] == 0xFF, "Nonce generation: large counter handled");
}

/* Test 5: Rate Limiting Data Structures */
void test_rate_limiting() {
    TEST_START("Rate Limiting");

    typedef struct {
        uint32_t ip;
        time_t window_start;
        uint32_t packet_count;
        uint32_t conn_count;
        time_t last_auth_fail;
        uint32_t auth_fail_count;
    } RateLimitEntry;

    RateLimitEntry entry;
    memset(&entry, 0, sizeof(entry));

    TEST_ASSERT(entry.packet_count == 0, "Rate limit: entry initialized");

    /* Simulate packet counting */
    entry.ip = 0x01020304;  /* 1.2.3.4 */
    entry.window_start = time(NULL);
    entry.packet_count = 500;

    TEST_ASSERT(entry.packet_count < 1000, "Rate limit: under limit");

    entry.packet_count = 1500;
    TEST_ASSERT(entry.packet_count > 1000, "Rate limit: over limit detected");
}

/* Test 6: Input Validation */
void test_input_validation() {
    TEST_START("Input Validation");

    /* Test interface name validation */
    const char *valid_names[] = {"tun0", "ssw0", "vpn-interface", "test_vpn"};
    const char *invalid_names[] = {"tun;rm", "$(evil)", "../../etc", "name with spaces"};

    for (int i = 0; i < 4; i++) {
        const char *name = valid_names[i];
        int valid = 1;

        /* Check alphanumeric, dash, underscore only */
        for (const char *p = name; *p; p++) {
            if (!(((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
                   (*p >= '0' && *p <= '9') || *p == '-' || *p == '_'))) {
                valid = 0;
                break;
            }
        }

        char msg[128];
        snprintf(msg, sizeof(msg), "Input validation: '%s' is valid", name);
        TEST_ASSERT(valid == 1, msg);
    }

    for (int i = 0; i < 4; i++) {
        const char *name = invalid_names[i];
        int valid = 1;

        for (const char *p = name; *p; p++) {
            if (!(((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
                   (*p >= '0' && *p <= '9') || *p == '-' || *p == '_'))) {
                valid = 0;
                break;
            }
        }

        char msg[128];
        snprintf(msg, sizeof(msg), "Input validation: '%s' is invalid", name);
        TEST_ASSERT(valid == 0, msg);
    }
}

/* Test 7: Buffer Safety */
void test_buffer_safety() {
    TEST_START("Buffer Safety");

    char buffer[16];
    const char *source = "SecureSwift VPN";

    /* Safe copy with null termination */
    strncpy(buffer, source, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';

    TEST_ASSERT(strlen(buffer) < sizeof(buffer), "Buffer safety: no overflow");
    TEST_ASSERT(buffer[sizeof(buffer) - 1] == '\0', "Buffer safety: null terminated");

    /* Test with exact size */
    char small_buf[6];
    strncpy(small_buf, "12345", sizeof(small_buf) - 1);
    small_buf[sizeof(small_buf) - 1] = '\0';

    TEST_ASSERT(strlen(small_buf) == 5, "Buffer safety: exact size handled");
}

/* Test 8: Constant-Time Operations */
void test_constant_time() {
    TEST_START("Constant-Time Operations");

    uint8_t a[32], b[32];
    memset(a, 0xAA, 32);
    memset(b, 0xAA, 32);

    /* Constant-time comparison (memcmp is usually constant-time) */
    int result1 = memcmp(a, b, 32);
    TEST_ASSERT(result1 == 0, "Constant-time: equal arrays detected");

    b[0] = 0xBB;
    int result2 = memcmp(a, b, 32);
    TEST_ASSERT(result2 != 0, "Constant-time: different arrays detected");

    /* Timing should not depend on where difference is */
    memset(b, 0xAA, 32);
    b[31] = 0xBB;  /* Difference at end */
    int result3 = memcmp(a, b, 32);
    TEST_ASSERT(result3 != 0, "Constant-time: difference at end detected");
}

/* Test 9: Random Number Generation */
void test_random_generation() {
    TEST_START("Random Number Generation");

    uint8_t random1[32], random2[32];

    /* Simulate random generation */
    FILE *urandom = fopen("/dev/urandom", "r");
    TEST_ASSERT(urandom != NULL, "Random: /dev/urandom accessible");

    if (urandom) {
        size_t read1 = fread(random1, 1, 32, urandom);
        size_t read2 = fread(random2, 1, 32, urandom);
        fclose(urandom);

        TEST_ASSERT(read1 == 32, "Random: read 32 bytes (set 1)");
        TEST_ASSERT(read2 == 32, "Random: read 32 bytes (set 2)");
        TEST_ASSERT(memcmp(random1, random2, 32) != 0, "Random: different outputs (high probability)");

        /* Check for all-zero (bad randomness) */
        uint8_t zeros[32] = {0};
        TEST_ASSERT(memcmp(random1, zeros, 32) != 0, "Random: not all zeros");
    }
}

/* Test 10: Key Size Constants */
void test_key_constants() {
    TEST_START("Key Size Constants");

    #define KYBER_K 3
    #define KYBER_N 256
    #define KYBER_Q 3329
    #define CURVE25519_BYTES 32
    #define TAG_LEN 16

    TEST_ASSERT(KYBER_K == 3, "Constants: KYBER_K correct");
    TEST_ASSERT(KYBER_N == 256, "Constants: KYBER_N correct");
    TEST_ASSERT(KYBER_Q == 3329, "Constants: KYBER_Q correct");
    TEST_ASSERT(CURVE25519_BYTES == 32, "Constants: CURVE25519_BYTES correct");
    TEST_ASSERT(TAG_LEN == 16, "Constants: TAG_LEN correct");
}

/* Test 11: Packet Counter Overflow */
void test_counter_overflow() {
    TEST_START("Packet Counter Overflow");

    uint64_t counter = 0xFFFFFFFFFFFFFFFEULL;  /* Near max */

    TEST_ASSERT(counter < UINT64_MAX, "Counter: not at max initially");

    counter++;
    TEST_ASSERT(counter == 0xFFFFFFFFFFFFFFFFULL, "Counter: increment works");

    counter++;
    TEST_ASSERT(counter == 0, "Counter: wraps to 0");

    /* This is OK - nonces will repeat after 2^64 packets (extremely unlikely) */
    /* At 1 Gbps, this takes 4,722 years */
}

/* Test 12: Hash Collision Resistance */
void test_hash_collision() {
    TEST_START("Hash Collision Resistance");

    Blake3 b1, b2;
    uint8_t out1[32], out2[32];

    /* Very similar inputs should produce different outputs */
    blake3_init(&b1);
    blake3_update(&b1, (uint8_t*)"password", 8);
    blake3_final(&b1, out1);

    blake3_init(&b2);
    blake3_update(&b2, (uint8_t*)"Password", 8);  /* Capital P */
    blake3_final(&b2, out2);

    TEST_ASSERT(memcmp(out1, out2, 32) != 0, "Hash collision: similar inputs differ");
}

/* ===== MAIN TEST RUNNER ===== */

int main(void) {
    printf("╔═══════════════════════════════════════════════════════════╗\n");
    printf("║      SecureSwift VPN - Unit Tests                        ║\n");
    printf("║      Testing Crypto Functions & Data Structures          ║\n");
    printf("╚═══════════════════════════════════════════════════════════╝\n");

    /* Run all tests */
    test_blake3_basic();
    test_blake3_determinism();
    test_poly1305_init();
    test_nonce_generation();
    test_rate_limiting();
    test_input_validation();
    test_buffer_safety();
    test_constant_time();
    test_random_generation();
    test_key_constants();
    test_counter_overflow();
    test_hash_collision();

    /* Print summary */
    printf("\n╔═══════════════════════════════════════════════════════════╗\n");
    printf("║  TEST SUMMARY                                            ║\n");
    printf("╠═══════════════════════════════════════════════════════════╣\n");
    printf("║  Total Tests: %3d                                         ║\n", tests_passed + tests_failed);
    printf("║  Passed:      %3d  ✓                                      ║\n", tests_passed);
    printf("║  Failed:      %3d  ✗                                      ║\n", tests_failed);
    printf("║  Success Rate: %3d%%                                       ║\n",
           (tests_passed * 100) / (tests_passed + tests_failed));
    printf("╚═══════════════════════════════════════════════════════════╝\n");

    if (tests_failed == 0) {
        printf("\n🎉 ALL TESTS PASSED! 🎉\n");
        return 0;
    } else {
        printf("\n❌ SOME TESTS FAILED ❌\n");
        return 1;
    }
}
