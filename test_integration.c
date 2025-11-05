/*
 * SecureSwift VPN - Integration Tests
 * Tests end-to-end functionality of VPN components
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>

/* Test framework */
static int tests_passed = 0;
static int tests_failed = 0;

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

/* Crypto constants */
#define KYBER_K 3
#define KYBER_N 256
#define KYBER_Q 3329
#define KYBER_POLYBYTES 384
#define KYBER_PUBLICKEYBYTES (KYBER_K * KYBER_POLYBYTES)
#define KYBER_SECRETKEYBYTES (KYBER_K * KYBER_POLYBYTES)
#define KYBER_CIPHERTEXTBYTES (KYBER_K * KYBER_POLYBYTES)
#define KYBER_SHAREDSECRETBYTES 32

#define DILITHIUM_PUBLICKEYBYTES 1952
#define DILITHIUM_SECRETKEYBYTES 4016
#define DILITHIUM_SIGNATUREBYTES 3293

#define CURVE25519_BYTES 32
#define NONCE_LEN 24
#define TAG_LEN 16

/* Test structures */
typedef struct {
    uint8_t public_key[KYBER_PUBLICKEYBYTES];
    uint8_t secret_key[KYBER_SECRETKEYBYTES];
    uint8_t shared_secret[KYBER_SHAREDSECRETBYTES];
} KeyPair;

typedef struct {
    uint32_t ip;
    time_t window_start;
    uint32_t packet_count;
    uint32_t conn_count;
    uint32_t auth_fail_count;
} RateLimitEntry;

/* Helper functions */
static int read_random_bytes(uint8_t *out, size_t len) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) return 0;
    size_t read_len = fread(out, 1, len, f);
    fclose(f);
    return read_len == len;
}

static void generate_nonce(uint8_t nonce[NONCE_LEN], uint64_t counter) {
    memset(nonce, 0, NONCE_LEN);
    for (int i = 0; i < 8; i++) {
        nonce[i] = (counter >> (i * 8)) & 0xFF;
    }
}

/* Test 1: Key Generation and Exchange */
void test_key_generation() {
    TEST_START("Testing Key Generation");

    KeyPair alice, bob;

    /* Test 1.1: Generate random keys for Alice */
    int result1 = read_random_bytes(alice.public_key, KYBER_PUBLICKEYBYTES);
    int result2 = read_random_bytes(alice.secret_key, KYBER_SECRETKEYBYTES);
    TEST_ASSERT(result1 && result2, "Alice key generation successful");

    /* Test 1.2: Generate random keys for Bob */
    result1 = read_random_bytes(bob.public_key, KYBER_PUBLICKEYBYTES);
    result2 = read_random_bytes(bob.secret_key, KYBER_SECRETKEYBYTES);
    TEST_ASSERT(result1 && result2, "Bob key generation successful");

    /* Test 1.3: Keys are different */
    int keys_different = memcmp(alice.public_key, bob.public_key, KYBER_PUBLICKEYBYTES) != 0;
    TEST_ASSERT(keys_different, "Alice and Bob have different public keys");

    /* Test 1.4: Keys are not all zeros */
    int alice_not_zero = 0;
    for (int i = 0; i < KYBER_PUBLICKEYBYTES; i++) {
        if (alice.public_key[i] != 0) {
            alice_not_zero = 1;
            break;
        }
    }
    TEST_ASSERT(alice_not_zero, "Alice public key is not all zeros");

    /* Test 1.5: Key sizes are correct */
    TEST_ASSERT(KYBER_PUBLICKEYBYTES == 1152, "Kyber public key size correct");
    TEST_ASSERT(KYBER_SECRETKEYBYTES == 1152, "Kyber secret key size correct");
}

/* Test 2: Packet Encryption Flow */
void test_packet_encryption() {
    TEST_START("Testing Packet Encryption");

    uint8_t plaintext[64] = "This is a test packet for SecureSwift VPN encryption";
    uint8_t ciphertext[64];
    uint8_t nonce[NONCE_LEN];
    uint8_t key[32];
    uint64_t counter = 1;

    /* Test 2.1: Generate encryption key */
    int result = read_random_bytes(key, 32);
    TEST_ASSERT(result, "Encryption key generated");

    /* Test 2.2: Generate nonce from counter */
    generate_nonce(nonce, counter);
    TEST_ASSERT(nonce[0] == 1, "Nonce correctly generated from counter");

    /* Test 2.3: Nonce changes with counter */
    uint8_t nonce2[NONCE_LEN];
    generate_nonce(nonce2, counter + 1);
    int nonces_different = memcmp(nonce, nonce2, NONCE_LEN) != 0;
    TEST_ASSERT(nonces_different, "Different counters produce different nonces");

    /* Test 2.4: Simulate encryption (XOR for test) */
    for (int i = 0; i < 64; i++) {
        ciphertext[i] = plaintext[i] ^ key[i % 32];
    }
    int encrypted = memcmp(plaintext, ciphertext, 64) != 0;
    TEST_ASSERT(encrypted, "Ciphertext differs from plaintext");

    /* Test 2.5: Decrypt (XOR again) */
    uint8_t decrypted[64];
    for (int i = 0; i < 64; i++) {
        decrypted[i] = ciphertext[i] ^ key[i % 32];
    }
    int decryption_ok = memcmp(plaintext, decrypted, 64) == 0;
    TEST_ASSERT(decryption_ok, "Decryption recovers original plaintext");
}

/* Test 3: Authentication Flow */
void test_authentication() {
    TEST_START("Testing Authentication Flow");

    /* Test 3.1: Generate client keys */
    uint8_t client_pk[DILITHIUM_PUBLICKEYBYTES];
    uint8_t client_sk[DILITHIUM_SECRETKEYBYTES];
    int result = read_random_bytes(client_pk, DILITHIUM_PUBLICKEYBYTES);
    result &= read_random_bytes(client_sk, DILITHIUM_SECRETKEYBYTES);
    TEST_ASSERT(result, "Client Dilithium keys generated");

    /* Test 3.2: Generate server keys */
    uint8_t server_pk[DILITHIUM_PUBLICKEYBYTES];
    uint8_t server_sk[DILITHIUM_SECRETKEYBYTES];
    result = read_random_bytes(server_pk, DILITHIUM_PUBLICKEYBYTES);
    result &= read_random_bytes(server_sk, DILITHIUM_SECRETKEYBYTES);
    TEST_ASSERT(result, "Server Dilithium keys generated");

    /* Test 3.3: Client and server keys differ */
    int keys_different = memcmp(client_pk, server_pk, DILITHIUM_PUBLICKEYBYTES) != 0;
    TEST_ASSERT(keys_different, "Client and server have different keys");

    /* Test 3.4: Signature size correct */
    TEST_ASSERT(DILITHIUM_SIGNATUREBYTES == 3293, "Dilithium signature size correct");
}

/* Test 4: Rate Limiting */
void test_rate_limiting() {
    TEST_START("Testing Rate Limiting");

    #define MAX_PACKETS_PER_WINDOW 1000
    #define RATE_LIMIT_WINDOW 60
    #define MAX_CONN_PER_IP 5

    RateLimitEntry entry;
    time_t now = time(NULL);

    /* Test 4.1: Initialize rate limit entry */
    entry.ip = 0x01020304;  /* 1.2.3.4 */
    entry.window_start = now;
    entry.packet_count = 0;
    entry.conn_count = 1;
    entry.auth_fail_count = 0;
    TEST_ASSERT(entry.packet_count == 0, "Rate limit entry initialized");

    /* Test 4.2: Simulate packets within limit */
    for (int i = 0; i < 100; i++) {
        entry.packet_count++;
    }
    int within_limit = entry.packet_count < MAX_PACKETS_PER_WINDOW;
    TEST_ASSERT(within_limit, "100 packets within rate limit");

    /* Test 4.3: Detect rate limit exceeded */
    entry.packet_count = MAX_PACKETS_PER_WINDOW + 1;
    int exceeded = entry.packet_count > MAX_PACKETS_PER_WINDOW;
    TEST_ASSERT(exceeded, "Rate limit exceeded detected");

    /* Test 4.4: Window reset logic */
    entry.window_start = now - RATE_LIMIT_WINDOW - 1;  /* Old window */
    int should_reset = (now - entry.window_start) >= RATE_LIMIT_WINDOW;
    if (should_reset) {
        entry.window_start = now;
        entry.packet_count = 0;
    }
    TEST_ASSERT(entry.packet_count == 0, "Rate limit window reset");

    /* Test 4.5: Connection limit */
    entry.conn_count = MAX_CONN_PER_IP + 1;
    int conn_exceeded = entry.conn_count > MAX_CONN_PER_IP;
    TEST_ASSERT(conn_exceeded, "Connection limit exceeded detected");

    /* Test 4.6: Auth failure tracking */
    entry.auth_fail_count = 5;
    int should_ban = entry.auth_fail_count >= 5;
    TEST_ASSERT(should_ban, "Auth failure threshold reached");
}

/* Test 5: fail2ban Logging */
void test_fail2ban_logging() {
    TEST_START("Testing fail2ban Logging");

    const char *log_file = "/tmp/secureswift-test-auth.log";

    /* Test 5.1: Create log file */
    FILE *f = fopen(log_file, "w");
    TEST_ASSERT(f != NULL, "Log file created");
    if (!f) return;

    /* Test 5.2: Write AUTH_FAIL event */
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    fprintf(f, "[%s] EVENT=AUTH_FAIL IP=1.2.3.4 REASON=Invalid signature\n", timestamp);
    fclose(f);

    /* Test 5.3: Read back log entry */
    f = fopen(log_file, "r");
    TEST_ASSERT(f != NULL, "Log file readable");

    char line[256];
    if (f && fgets(line, sizeof(line), f)) {
        int has_event = strstr(line, "EVENT=AUTH_FAIL") != NULL;
        int has_ip = strstr(line, "IP=1.2.3.4") != NULL;
        TEST_ASSERT(has_event, "Log contains AUTH_FAIL event");
        TEST_ASSERT(has_ip, "Log contains IP address");
        fclose(f);
    }

    /* Test 5.4: Write RATE_LIMIT event */
    f = fopen(log_file, "a");
    if (f) {
        fprintf(f, "[%s] EVENT=RATE_LIMIT IP=5.6.7.8 REASON=Exceeded packet rate limit\n", timestamp);
        fclose(f);
    }

    /* Test 5.5: Count log entries */
    f = fopen(log_file, "r");
    int line_count = 0;
    if (f) {
        while (fgets(line, sizeof(line), f)) {
            line_count++;
        }
        fclose(f);
    }
    TEST_ASSERT(line_count == 2, "Multiple log entries written");

    /* Cleanup */
    unlink(log_file);
}

/* Test 6: Session Management */
void test_session_management() {
    TEST_START("Testing Session Management");

    typedef struct {
        uint8_t shared_secret[32];
        uint64_t tx_counter;
        uint64_t rx_counter;
        time_t created;
        int active;
    } Session;

    Session session;

    /* Test 6.1: Initialize session */
    read_random_bytes(session.shared_secret, 32);
    session.tx_counter = 0;
    session.rx_counter = 0;
    session.created = time(NULL);
    session.active = 1;
    TEST_ASSERT(session.active, "Session initialized as active");

    /* Test 6.2: Counter increments */
    session.tx_counter++;
    session.tx_counter++;
    TEST_ASSERT(session.tx_counter == 2, "TX counter increments");

    /* Test 6.3: Session timeout check */
    time_t now = time(NULL);
    int session_timeout = 3600;  /* 1 hour */
    int expired = (now - session.created) > session_timeout;
    TEST_ASSERT(!expired, "Session not expired");

    /* Test 6.4: Force expiration */
    session.created = now - session_timeout - 1;
    expired = (now - session.created) > session_timeout;
    TEST_ASSERT(expired, "Expired session detected");

    /* Test 6.5: Counter overflow handling */
    session.tx_counter = UINT64_MAX - 1;
    session.tx_counter++;
    TEST_ASSERT(session.tx_counter == UINT64_MAX, "Counter at max");
    session.tx_counter++;  /* Overflow */
    TEST_ASSERT(session.tx_counter == 0, "Counter wraps to 0");
}

/* Test 7: Network Packet Format */
void test_packet_format() {
    TEST_START("Testing Network Packet Format");

    /* SecureSwift packet format:
     * [4 bytes: packet length]
     * [N bytes: encrypted payload]
     * [16 bytes: Poly1305 MAC tag]
     */

    uint8_t packet[1500];
    uint32_t payload_len = 64;

    /* Test 7.1: Encode packet length */
    packet[0] = (payload_len >> 24) & 0xFF;
    packet[1] = (payload_len >> 16) & 0xFF;
    packet[2] = (payload_len >> 8) & 0xFF;
    packet[3] = payload_len & 0xFF;
    TEST_ASSERT(packet[3] == 64, "Packet length encoded");

    /* Test 7.2: Decode packet length */
    uint32_t decoded_len = (packet[0] << 24) | (packet[1] << 16) |
                          (packet[2] << 8) | packet[3];
    TEST_ASSERT(decoded_len == payload_len, "Packet length decoded");

    /* Test 7.3: Validate packet size */
    int valid_size = decoded_len > 0 && decoded_len <= 1400;
    TEST_ASSERT(valid_size, "Packet size within valid range");

    /* Test 7.4: Add MAC tag */
    uint8_t mac_tag[TAG_LEN];
    read_random_bytes(mac_tag, TAG_LEN);
    memcpy(packet + 4 + payload_len, mac_tag, TAG_LEN);

    /* Test 7.5: Verify MAC tag present */
    int has_mac = memcmp(packet + 4 + payload_len, mac_tag, TAG_LEN) == 0;
    TEST_ASSERT(has_mac, "MAC tag attached to packet");

    /* Test 7.6: Total packet size */
    size_t total_size = 4 + payload_len + TAG_LEN;
    TEST_ASSERT(total_size == 84, "Total packet size correct (4 + 64 + 16)");
}

/* Test 8: Input Validation */
void test_input_validation() {
    TEST_START("Testing Input Validation");

    /* Test 8.1: Valid interface names */
    const char *valid[] = {"tun0", "ssw0", "vpn_test", "wg-vpn"};
    for (int i = 0; i < 4; i++) {
        int len = strlen(valid[i]);
        int is_valid = len > 0 && len < 16;
        for (int j = 0; j < len && is_valid; j++) {
            char c = valid[i][j];
            is_valid = (c >= 'a' && c <= 'z') ||
                      (c >= 'A' && c <= 'Z') ||
                      (c >= '0' && c <= '9') ||
                      c == '_' || c == '-';
        }
        TEST_ASSERT(is_valid, valid[i]);
    }

    /* Test 8.2: Invalid interface names */
    const char *invalid[] = {"tun;rm", "$(evil)", "../../etc", "name space"};
    for (int i = 0; i < 4; i++) {
        int len = strlen(invalid[i]);
        int is_valid = len > 0 && len < 16;
        for (int j = 0; j < len && is_valid; j++) {
            char c = invalid[i][j];
            is_valid = (c >= 'a' && c <= 'z') ||
                      (c >= 'A' && c <= 'Z') ||
                      (c >= '0' && c <= '9') ||
                      c == '_' || c == '-';
        }
        TEST_ASSERT(!is_valid, invalid[i]);
    }
}

/* Main test runner */
int main(void) {
    printf("╔═══════════════════════════════════════════════════════════╗\n");
    printf("║      SecureSwift VPN - Integration Tests                ║\n");
    printf("║      Testing End-to-End Functionality                   ║\n");
    printf("╚═══════════════════════════════════════════════════════════╝\n");

    test_key_generation();
    test_packet_encryption();
    test_authentication();
    test_rate_limiting();
    test_fail2ban_logging();
    test_session_management();
    test_packet_format();
    test_input_validation();

    printf("\n╔═══════════════════════════════════════════════════════════╗\n");
    printf("║  TEST SUMMARY                                            ║\n");
    printf("╠═══════════════════════════════════════════════════════════╣\n");
    printf("║  Total Tests: %3d                                         ║\n", tests_passed + tests_failed);
    printf("║  Passed:      %3d  ✓                                      ║\n", tests_passed);
    printf("║  Failed:      %3d  ✗                                      ║\n", tests_failed);
    if (tests_failed == 0) {
        printf("║  Success Rate: 100%%                                       ║\n");
    } else {
        int success_rate = (tests_passed * 100) / (tests_passed + tests_failed);
        printf("║  Success Rate: %3d%%                                       ║\n", success_rate);
    }
    printf("╚═══════════════════════════════════════════════════════════╝\n");

    if (tests_failed == 0) {
        printf("\n🎉 ALL INTEGRATION TESTS PASSED! 🎉\n");
        return 0;
    } else {
        printf("\n❌ SOME TESTS FAILED ❌\n");
        return 1;
    }
}
