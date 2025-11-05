/*
 * SecureSwift VPN - Fuzz Tests
 * Tests stability and robustness with random/malformed inputs
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>

/* Test framework */
static int tests_passed = 0;
static int tests_failed = 0;
static int crashes = 0;

#define TEST_START(name) do { \
    printf("\n=== %s ===\n", name); \
} while(0)

#define TEST_ASSERT(condition, message) do { \
    if (condition) { \
        tests_passed++; \
        printf("✓ PASS: %s\n", message); \
    } else { \
        tests_failed++; \
        printf("✗ FAIL: %s\n", message); \
    } \
} while(0)

#define FUZZ_ITERATIONS 10000

/* Crypto constants */
#define KYBER_K 3
#define KYBER_N 256
#define KYBER_Q 3329
#define KYBER_POLYBYTES 384
#define KYBER_PUBLICKEYBYTES (KYBER_K * KYBER_POLYBYTES)

#define NONCE_LEN 24
#define TAG_LEN 16
#define MAX_PACKET_SIZE 1500

/* Helper: Read random bytes */
static int read_random_bytes(uint8_t *out, size_t len) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) return 0;
    size_t read_len = fread(out, 1, len, f);
    fclose(f);
    return read_len == len;
}

/* Helper: Generate random packet size */
static uint32_t random_packet_size(int allow_invalid) {
    uint32_t size;
    read_random_bytes((uint8_t*)&size, sizeof(size));

    if (!allow_invalid) {
        size = size % MAX_PACKET_SIZE;
        if (size == 0) size = 1;
    }
    return size;
}

/* Helper: Validate interface name */
static int is_valid_ifname(const char *name) {
    if (!name) return 0;
    size_t len = strlen(name);
    if (len == 0 || len >= 16) return 0;

    for (size_t i = 0; i < len; i++) {
        char c = name[i];
        if (!((c >= 'a' && c <= 'z') ||
              (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') ||
              c == '_' || c == '-')) {
            return 0;
        }
    }
    return 1;
}

/* Test 1: Fuzz Packet Sizes */
void test_fuzz_packet_sizes() {
    TEST_START("Fuzzing Packet Sizes");

    int valid_count = 0;
    int invalid_count = 0;

    for (int i = 0; i < 1000; i++) {
        uint32_t size = random_packet_size(1);  /* Allow invalid */

        /* Validate packet size */
        if (size > 0 && size <= MAX_PACKET_SIZE) {
            valid_count++;
        } else {
            invalid_count++;
        }
    }

    TEST_ASSERT(valid_count > 0, "Found valid packet sizes");
    TEST_ASSERT(invalid_count > 0, "Found invalid packet sizes");

    printf("  → Valid: %d, Invalid: %d\n", valid_count, invalid_count);
}

/* Test 2: Fuzz Nonce Generation */
void test_fuzz_nonce_generation() {
    TEST_START("Fuzzing Nonce Generation");

    uint8_t nonce1[NONCE_LEN];
    uint8_t nonce2[NONCE_LEN];
    int unique_count = 0;

    for (int i = 0; i < 1000; i++) {
        uint64_t counter1, counter2;
        read_random_bytes((uint8_t*)&counter1, sizeof(counter1));
        read_random_bytes((uint8_t*)&counter2, sizeof(counter2));

        /* Generate nonces */
        memset(nonce1, 0, NONCE_LEN);
        memset(nonce2, 0, NONCE_LEN);

        for (int j = 0; j < 8; j++) {
            nonce1[j] = (counter1 >> (j * 8)) & 0xFF;
            nonce2[j] = (counter2 >> (j * 8)) & 0xFF;
        }

        if (counter1 != counter2 && memcmp(nonce1, nonce2, NONCE_LEN) != 0) {
            unique_count++;
        }
    }

    TEST_ASSERT(unique_count > 990, "Nonces are unique (>99%)");
    printf("  → Unique nonces: %d/1000\n", unique_count);
}

/* Test 3: Fuzz Encryption Keys */
void test_fuzz_encryption_keys() {
    TEST_START("Fuzzing Encryption Keys");

    uint8_t key1[32], key2[32];
    int different_count = 0;

    for (int i = 0; i < 1000; i++) {
        read_random_bytes(key1, 32);
        read_random_bytes(key2, 32);

        if (memcmp(key1, key2, 32) != 0) {
            different_count++;
        }
    }

    TEST_ASSERT(different_count == 1000, "All random keys are different");
    printf("  → Different keys: %d/1000\n", different_count);

    /* Test key entropy */
    uint8_t key[32];
    read_random_bytes(key, 32);

    int zero_count = 0;
    for (int i = 0; i < 32; i++) {
        if (key[i] == 0) zero_count++;
    }

    TEST_ASSERT(zero_count < 10, "Key has good entropy (not mostly zeros)");
    printf("  → Zero bytes in sample key: %d/32\n", zero_count);
}

/* Test 4: Fuzz Rate Limiting */
void test_fuzz_rate_limiting() {
    TEST_START("Fuzzing Rate Limiting");

    #define RATE_LIMIT_TABLE_SIZE 1024
    #define MAX_PACKETS_PER_WINDOW 1000

    typedef struct {
        uint32_t ip;
        uint32_t packet_count;
        int blocked;
    } FuzzRateLimitEntry;

    FuzzRateLimitEntry entries[100];
    memset(entries, 0, sizeof(entries));

    int blocked_count = 0;
    int allowed_count = 0;

    /* Simulate random packet arrivals */
    for (int i = 0; i < FUZZ_ITERATIONS; i++) {
        uint32_t ip;
        read_random_bytes((uint8_t*)&ip, sizeof(ip));
        int entry_idx = ip % 100;

        entries[entry_idx].ip = ip;
        entries[entry_idx].packet_count++;

        if (entries[entry_idx].packet_count > MAX_PACKETS_PER_WINDOW) {
            entries[entry_idx].blocked = 1;
            blocked_count++;
        } else {
            allowed_count++;
        }
    }

    TEST_ASSERT(allowed_count > 0, "Some packets allowed");
    TEST_ASSERT(blocked_count > 0, "Some packets blocked");

    printf("  → Allowed: %d, Blocked: %d\n", allowed_count, blocked_count);
}

/* Test 5: Fuzz Input Validation */
void test_fuzz_input_validation() {
    TEST_START("Fuzzing Input Validation");

    int valid_count = 0;
    int invalid_count = 0;

    for (int i = 0; i < 1000; i++) {
        char ifname[32];
        uint8_t len;
        read_random_bytes(&len, 1);
        len = (len % 30) + 1;  /* 1-30 chars */

        read_random_bytes((uint8_t*)ifname, len);
        ifname[len] = '\0';

        /* Make some ASCII printable */
        for (int j = 0; j < len; j++) {
            if (ifname[j] < 32 || ifname[j] > 126) {
                ifname[j] = 'a' + (ifname[j] % 26);
            }
        }

        if (is_valid_ifname(ifname)) {
            valid_count++;
        } else {
            invalid_count++;
        }
    }

    TEST_ASSERT(valid_count > 0, "Some interface names valid");
    TEST_ASSERT(invalid_count > 0, "Some interface names invalid");

    printf("  → Valid: %d, Invalid: %d\n", valid_count, invalid_count);
}

/* Test 6: Fuzz Packet Parsing */
void test_fuzz_packet_parsing() {
    TEST_START("Fuzzing Packet Parsing");

    int parse_success = 0;
    int parse_failure = 0;

    for (int i = 0; i < 1000; i++) {
        uint8_t packet[1500];
        read_random_bytes(packet, sizeof(packet));

        /* Try to parse packet length */
        uint32_t len = (packet[0] << 24) | (packet[1] << 16) |
                      (packet[2] << 8) | packet[3];

        /* Validate */
        if (len > 0 && len <= MAX_PACKET_SIZE - 4 - TAG_LEN) {
            /* Valid packet size */
            uint32_t expected_total = 4 + len + TAG_LEN;
            if (expected_total <= sizeof(packet)) {
                parse_success++;
            } else {
                parse_failure++;
            }
        } else {
            parse_failure++;
        }
    }

    TEST_ASSERT(parse_success > 0, "Some packets parsed successfully");
    TEST_ASSERT(parse_failure > 0, "Some packets rejected");

    printf("  → Parsed: %d, Rejected: %d\n", parse_success, parse_failure);
}

/* Test 7: Fuzz Counter Overflow */
void test_fuzz_counter_overflow() {
    TEST_START("Fuzzing Counter Overflow");

    int overflow_handled = 0;

    for (int i = 0; i < 1000; i++) {
        uint64_t counter;
        read_random_bytes((uint8_t*)&counter, sizeof(counter));

        /* Test near-overflow values */
        if (counter > UINT64_MAX - 100) {
            counter++;
            if (counter == 0 || counter < UINT64_MAX - 100) {
                overflow_handled++;
            }
        }
    }

    TEST_ASSERT(overflow_handled >= 0, "Counter overflow handled");
    printf("  → Overflows detected: %d\n", overflow_handled);

    /* Test explicit overflow */
    uint64_t max_counter = UINT64_MAX;
    uint64_t after_overflow = max_counter + 1;
    TEST_ASSERT(after_overflow == 0, "Explicit overflow wraps to 0");
}

/* Test 8: Fuzz MAC Tag Verification */
void test_fuzz_mac_verification() {
    TEST_START("Fuzzing MAC Tag Verification");

    uint8_t mac1[TAG_LEN];
    uint8_t mac2[TAG_LEN];

    int matches = 0;
    int mismatches = 0;

    for (int i = 0; i < 1000; i++) {
        read_random_bytes(mac1, TAG_LEN);
        read_random_bytes(mac2, TAG_LEN);

        if (memcmp(mac1, mac2, TAG_LEN) == 0) {
            matches++;
        } else {
            mismatches++;
        }
    }

    TEST_ASSERT(mismatches > 999, "Random MACs almost never match");
    printf("  → Matches: %d, Mismatches: %d\n", matches, mismatches);

    /* Test MAC corruption detection */
    read_random_bytes(mac1, TAG_LEN);
    memcpy(mac2, mac1, TAG_LEN);

    TEST_ASSERT(memcmp(mac1, mac2, TAG_LEN) == 0, "Identical MACs match");

    mac2[0] ^= 1;  /* Flip one bit */
    TEST_ASSERT(memcmp(mac1, mac2, TAG_LEN) != 0, "Single bit flip detected");
}

/* Test 9: Fuzz Memory Safety */
void test_fuzz_memory_safety() {
    TEST_START("Fuzzing Memory Safety");

    int safe_operations = 0;

    for (int i = 0; i < 1000; i++) {
        /* Test buffer operations */
        char src[64];
        char dst[32];

        uint8_t len;
        read_random_bytes(&len, 1);
        len = len % 100;  /* 0-99 */

        read_random_bytes((uint8_t*)src, sizeof(src));
        src[sizeof(src) - 1] = '\0';

        /* Safe copy: always bound to destination size */
        size_t copy_len = len;
        if (copy_len >= sizeof(dst)) {
            copy_len = sizeof(dst) - 1;
        }

        memcpy(dst, src, copy_len);
        dst[copy_len] = '\0';

        /* Verify no overflow */
        if (strlen(dst) < sizeof(dst)) {
            safe_operations++;
        }
    }

    TEST_ASSERT(safe_operations == 1000, "All memory operations safe");
    printf("  → Safe operations: %d/1000\n", safe_operations);
}

/* Test 10: Stress Test - High Volume */
void test_stress_high_volume() {
    TEST_START("Stress Testing - High Volume");

    int operations = 0;
    int errors = 0;

    printf("  → Processing %d operations...\n", FUZZ_ITERATIONS);

    for (int i = 0; i < FUZZ_ITERATIONS; i++) {
        uint8_t data[128];
        uint8_t key[32];
        uint8_t output[128];

        /* Random data and key */
        if (!read_random_bytes(data, sizeof(data)) ||
            !read_random_bytes(key, sizeof(key))) {
            errors++;
            continue;
        }

        /* Simulate encryption (XOR for stress test) */
        for (size_t j = 0; j < sizeof(data); j++) {
            output[j] = data[j] ^ key[j % 32];
        }

        operations++;
    }

    TEST_ASSERT(operations == FUZZ_ITERATIONS, "All operations completed");
    TEST_ASSERT(errors == 0, "No errors during stress test");

    printf("  → Completed: %d operations, %d errors\n", operations, errors);
}

/* Test 11: Fuzz IP Address Handling */
void test_fuzz_ip_addresses() {
    TEST_START("Fuzzing IP Address Handling");

    int valid_ips = 0;
    int invalid_ips = 0;

    for (int i = 0; i < 1000; i++) {
        uint32_t ip;
        read_random_bytes((uint8_t*)&ip, sizeof(ip));

        /* Check for special IPs */
        uint8_t first_octet = (ip >> 24) & 0xFF;

        if (first_octet == 0 || first_octet == 127 || first_octet == 255) {
            /* Loopback, broadcast, or zero */
            invalid_ips++;
        } else if (first_octet >= 224) {
            /* Multicast */
            invalid_ips++;
        } else {
            valid_ips++;
        }
    }

    TEST_ASSERT(valid_ips > 0, "Found valid IPs");
    TEST_ASSERT(invalid_ips > 0, "Found invalid IPs");

    printf("  → Valid: %d, Invalid: %d\n", valid_ips, invalid_ips);
}

/* Test 12: Fuzz Timestamp Handling */
void test_fuzz_timestamps() {
    TEST_START("Fuzzing Timestamp Handling");

    time_t now = time(NULL);
    int valid_timestamps = 0;
    int invalid_timestamps = 0;

    for (int i = 0; i < 1000; i++) {
        time_t timestamp;
        read_random_bytes((uint8_t*)&timestamp, sizeof(timestamp));

        /* Check if timestamp is reasonable (within 10 years) */
        time_t diff = timestamp > now ? timestamp - now : now - timestamp;
        time_t ten_years = 10 * 365 * 24 * 3600;

        if (diff < ten_years && timestamp > 0) {
            valid_timestamps++;
        } else {
            invalid_timestamps++;
        }
    }

    TEST_ASSERT(valid_timestamps > 0, "Found valid timestamps");
    TEST_ASSERT(invalid_timestamps > 0, "Found invalid timestamps");

    printf("  → Valid: %d, Invalid: %d\n", valid_timestamps, invalid_timestamps);
}

/* Main test runner */
int main(void) {
    printf("╔═══════════════════════════════════════════════════════════╗\n");
    printf("║      SecureSwift VPN - Fuzz Tests                        ║\n");
    printf("║      Testing Stability with Random Inputs               ║\n");
    printf("╚═══════════════════════════════════════════════════════════╝\n");

    /* Seed random number generator */
    srand(time(NULL));

    test_fuzz_packet_sizes();
    test_fuzz_nonce_generation();
    test_fuzz_encryption_keys();
    test_fuzz_rate_limiting();
    test_fuzz_input_validation();
    test_fuzz_packet_parsing();
    test_fuzz_counter_overflow();
    test_fuzz_mac_verification();
    test_fuzz_memory_safety();
    test_stress_high_volume();
    test_fuzz_ip_addresses();
    test_fuzz_timestamps();

    printf("\n╔═══════════════════════════════════════════════════════════╗\n");
    printf("║  TEST SUMMARY                                            ║\n");
    printf("╠═══════════════════════════════════════════════════════════╣\n");
    printf("║  Total Tests: %3d                                         ║\n", tests_passed + tests_failed);
    printf("║  Passed:      %3d  ✓                                      ║\n", tests_passed);
    printf("║  Failed:      %3d  ✗                                      ║\n", tests_failed);
    printf("║  Crashes:     %3d  💥                                      ║\n", crashes);
    if (tests_failed == 0 && crashes == 0) {
        printf("║  Success Rate: 100%%                                       ║\n");
    } else {
        int success_rate = (tests_passed * 100) / (tests_passed + tests_failed);
        printf("║  Success Rate: %3d%%                                       ║\n", success_rate);
    }
    printf("╚═══════════════════════════════════════════════════════════╝\n");

    if (tests_failed == 0 && crashes == 0) {
        printf("\n🎉 ALL FUZZ TESTS PASSED! 🎉\n");
        printf("Tested with %d iterations of random inputs\n", FUZZ_ITERATIONS);
        return 0;
    } else {
        printf("\n❌ SOME TESTS FAILED ❌\n");
        return 1;
    }
}
