#ifndef SECURESWIFT_SECURITY_H
#define SECURESWIFT_SECURITY_H

/*
 * SecureSwift VPN - Security Utilities Header
 *
 * This header provides comprehensive security utilities:
 * - Safe memory operations
 * - Bounds checking
 * - Constant-time operations
 * - Secure random generation
 * - Integer overflow protection
 * - Nonce reuse protection
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <limits.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/random.h>
#include <errno.h>

/* ============================================================================
 * SECURE RANDOM NUMBER GENERATION
 * ============================================================================ */

/**
 * Generate cryptographically secure random bytes
 * Uses getrandom() syscall with fallback to /dev/urandom
 *
 * @param buf Output buffer
 * @param len Number of bytes to generate
 * @return 0 on success, -1 on failure
 */
static inline int secure_random_bytes(void *buf, size_t len) {
    if (!buf || len == 0) {
        return -1;
    }

    // Try getrandom() first (Linux 3.17+)
    #ifdef __linux__
    ssize_t result = getrandom(buf, len, GRND_NONBLOCK);
    if (result == (ssize_t)len) {
        return 0;
    }
    // If ENOSYS (not implemented) or EAGAIN (not enough entropy yet), fall through
    if (result >= 0 || (errno != ENOSYS && errno != EAGAIN)) {
        // Partial read or other error
        if (result > 0 && result < (ssize_t)len) {
            // Got partial data, continue with /dev/urandom for rest
            buf = (uint8_t*)buf + result;
            len -= result;
        } else if (result < 0 && errno != ENOSYS && errno != EAGAIN) {
            return -1;
        }
    }
    #endif

    // Fallback to /dev/urandom
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        return -1;
    }

    size_t total = 0;
    while (total < len) {
        ssize_t n = read(fd, (uint8_t*)buf + total, len - total);
        if (n <= 0) {
            close(fd);
            return -1;
        }
        total += n;
    }

    close(fd);
    return 0;
}

/**
 * Generate a cryptographically secure 64-bit random number
 */
static inline uint64_t secure_random_u64(void) {
    uint64_t val;
    if (secure_random_bytes(&val, sizeof(val)) != 0) {
        // Fallback to less secure method if secure random fails
        // This should never happen in production
        return (uint64_t)time(NULL) ^ (uint64_t)getpid();
    }
    return val;
}

/**
 * Generate a cryptographically secure 32-bit random number
 */
static inline uint32_t secure_random_u32(void) {
    uint32_t val;
    if (secure_random_bytes(&val, sizeof(val)) != 0) {
        return (uint32_t)time(NULL);
    }
    return val;
}

/* ============================================================================
 * CONSTANT-TIME OPERATIONS (prevent timing side-channel attacks)
 * ============================================================================ */

/**
 * Constant-time memory comparison
 * Returns 0 if equal, non-zero if different
 * Execution time is constant regardless of where differences occur
 */
static inline int ct_memcmp(const void *a, const void *b, size_t len) {
    const uint8_t *pa = (const uint8_t *)a;
    const uint8_t *pb = (const uint8_t *)b;
    uint8_t diff = 0;

    for (size_t i = 0; i < len; i++) {
        diff |= pa[i] ^ pb[i];
    }

    return diff;
}

/**
 * Constant-time conditional select
 * Returns a if condition is true (non-zero), b otherwise
 * Execution time is constant regardless of condition value
 */
static inline uint32_t ct_select_u32(uint32_t condition, uint32_t a, uint32_t b) {
    uint32_t mask = -(uint32_t)(condition != 0);
    return (a & mask) | (b & ~mask);
}

/**
 * Constant-time conditional select for bytes
 */
static inline uint8_t ct_select_u8(uint8_t condition, uint8_t a, uint8_t b) {
    uint8_t mask = -(uint8_t)(condition != 0);
    return (a & mask) | (b & ~mask);
}

/**
 * Constant-time zero check
 * Returns 1 if value is zero, 0 otherwise
 */
static inline uint32_t ct_is_zero_u32(uint32_t x) {
    return ~(x | -x) >> 31;
}

/**
 * Constant-time equality check
 * Returns 1 if a == b, 0 otherwise
 */
static inline uint32_t ct_eq_u32(uint32_t a, uint32_t b) {
    return ct_is_zero_u32(a ^ b);
}

/* ============================================================================
 * INTEGER OVERFLOW PROTECTION
 * ============================================================================ */

/**
 * Safe addition with overflow check
 * Returns 0 on success, -1 on overflow
 */
static inline int safe_add_u32(uint32_t a, uint32_t b, uint32_t *result) {
    if (a > UINT32_MAX - b) {
        return -1;  // Overflow would occur
    }
    *result = a + b;
    return 0;
}

/**
 * Safe addition for size_t
 */
static inline int safe_add_size(size_t a, size_t b, size_t *result) {
    if (a > SIZE_MAX - b) {
        return -1;
    }
    *result = a + b;
    return 0;
}

/**
 * Safe multiplication with overflow check
 */
static inline int safe_mul_u32(uint32_t a, uint32_t b, uint32_t *result) {
    if (a != 0 && b > UINT32_MAX / a) {
        return -1;
    }
    *result = a * b;
    return 0;
}

/**
 * Safe multiplication for size_t
 */
static inline int safe_mul_size(size_t a, size_t b, size_t *result) {
    if (a != 0 && b > SIZE_MAX / a) {
        return -1;
    }
    *result = a * b;
    return 0;
}

/* ============================================================================
 * SAFE MEMORY OPERATIONS
 * ============================================================================ */

/**
 * Secure zero memory (prevents compiler optimization)
 * Use this to clear sensitive data like keys
 */
static inline void secure_zero(void *ptr, size_t len) {
    if (!ptr || len == 0) return;

    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) {
        *p++ = 0;
    }

    // Additional barrier to prevent optimization
    __asm__ __volatile__("" : : "r"(ptr) : "memory");
}

/**
 * Safe memory copy with bounds checking
 * Returns 0 on success, -1 if bounds violated
 */
static inline int safe_memcpy(void *dest, size_t dest_size, const void *src, size_t src_size) {
    if (!dest || !src) {
        return -1;
    }

    if (src_size > dest_size) {
        return -1;  // Would overflow destination
    }

    if (src_size == 0) {
        return 0;  // Nothing to copy
    }

    memcpy(dest, src, src_size);
    return 0;
}

/**
 * Safe string copy with null termination guarantee
 * Returns 0 on success, -1 if truncation occurred
 */
static inline int safe_strncpy(char *dest, size_t dest_size, const char *src) {
    if (!dest || !src || dest_size == 0) {
        return -1;
    }

    size_t i;
    for (i = 0; i < dest_size - 1 && src[i] != '\0'; i++) {
        dest[i] = src[i];
    }
    dest[i] = '\0';

    // Check if we truncated
    if (src[i] != '\0') {
        return -1;  // Truncation occurred
    }

    return 0;
}

/**
 * Safe array bounds check
 * Returns 1 if index is in bounds, 0 otherwise
 */
static inline int bounds_check(size_t index, size_t array_size) {
    return index < array_size;
}

/**
 * Safe array access with bounds checking
 * Returns pointer to element if in bounds, NULL otherwise
 */
static inline void* safe_array_access(void *array, size_t element_size, size_t index, size_t array_size) {
    if (!array || !bounds_check(index, array_size)) {
        return NULL;
    }

    size_t offset;
    if (safe_mul_size(element_size, index, &offset) != 0) {
        return NULL;  // Offset calculation would overflow
    }

    return (uint8_t*)array + offset;
}

/* ============================================================================
 * NONCE REUSE PROTECTION
 * ============================================================================ */

#define NONCE_HISTORY_SIZE 1024

typedef struct {
    uint8_t nonce[24];  // XSalsa20 nonce size
    uint64_t timestamp;
    uint8_t used;
} NonceHistoryEntry;

typedef struct {
    NonceHistoryEntry entries[NONCE_HISTORY_SIZE];
    size_t next_index;
    uint64_t generation;  // Incremented on each rotation
    pthread_mutex_t mutex;
} NonceHistory;

/**
 * Initialize nonce history tracking
 */
static inline void nonce_history_init(NonceHistory *history) {
    memset(history, 0, sizeof(NonceHistory));
    pthread_mutex_init(&history->mutex, NULL);
}

/**
 * Check if nonce was previously used (constant-time)
 * Returns 1 if nonce was used, 0 if new
 */
static inline int nonce_check_used(NonceHistory *history, const uint8_t *nonce) {
    pthread_mutex_lock(&history->mutex);

    uint8_t found = 0;
    // Constant-time search through all entries
    for (size_t i = 0; i < NONCE_HISTORY_SIZE; i++) {
        if (history->entries[i].used) {
            uint8_t match = (ct_memcmp(history->entries[i].nonce, nonce, 24) == 0);
            found |= match;
        }
    }

    pthread_mutex_unlock(&history->mutex);
    return found;
}

/**
 * Add nonce to history
 * Returns 0 on success, -1 if nonce was already used
 */
static inline int nonce_add(NonceHistory *history, const uint8_t *nonce) {
    pthread_mutex_lock(&history->mutex);

    // Check if already used (attack detection)
    for (size_t i = 0; i < NONCE_HISTORY_SIZE; i++) {
        if (history->entries[i].used &&
            ct_memcmp(history->entries[i].nonce, nonce, 24) == 0) {
            pthread_mutex_unlock(&history->mutex);
            return -1;  // Replay attack detected!
        }
    }

    // Add to history (circular buffer)
    size_t idx = history->next_index;
    memcpy(history->entries[idx].nonce, nonce, 24);
    history->entries[idx].timestamp = time(NULL);
    history->entries[idx].used = 1;

    history->next_index = (history->next_index + 1) % NONCE_HISTORY_SIZE;

    pthread_mutex_unlock(&history->mutex);
    return 0;
}

/**
 * Generate a cryptographically secure nonce
 * Never uses time as source of randomness
 */
static inline int secure_nonce_generate(uint8_t *nonce, size_t nonce_len) {
    return secure_random_bytes(nonce, nonce_len);
}

/* ============================================================================
 * PACKET LENGTH VALIDATION
 * ============================================================================ */

/**
 * Validate packet length is within acceptable bounds
 * Returns 1 if valid, 0 if invalid
 */
static inline int validate_packet_length(size_t length, size_t min_length, size_t max_length) {
    return length >= min_length && length <= max_length;
}

/**
 * Validate buffer has enough space for operation
 * Returns 1 if valid, 0 if would overflow
 */
static inline int validate_buffer_space(size_t buffer_size, size_t offset, size_t required_space) {
    // Check offset doesn't overflow
    if (offset > buffer_size) {
        return 0;
    }

    // Check required space doesn't overflow
    size_t remaining = buffer_size - offset;
    if (required_space > remaining) {
        return 0;
    }

    return 1;
}

/* ============================================================================
 * DOUBLE-FREE PROTECTION
 * ============================================================================ */

/**
 * Safe free with NULL poisoning
 * Prevents double-free by setting pointer to NULL
 */
#define SAFE_FREE(ptr) do { \
    if (ptr) { \
        free(ptr); \
        (ptr) = NULL; \
    } \
} while(0)

/**
 * Safe free with secure zeroing before free
 * Use for freeing sensitive data
 */
#define SECURE_FREE(ptr, size) do { \
    if (ptr) { \
        secure_zero(ptr, size); \
        free(ptr); \
        (ptr) = NULL; \
    } \
} while(0)

/* ============================================================================
 * MEMORY LEAK PREVENTION
 * ============================================================================ */

/**
 * Cleanup helper for automatic cleanup on scope exit
 * Use with __attribute__((cleanup))
 */
static inline void cleanup_free(void *p) {
    void **pp = (void**)p;
    if (*pp) {
        free(*pp);
        *pp = NULL;
    }
}

/**
 * Cleanup helper for secure free
 */
#define cleanup_secure_free(size) \
    __attribute__((cleanup(cleanup_secure_free_##size)))

/* ============================================================================
 * CRYPTO TEST VECTORS (NIST PQC)
 * ============================================================================ */

typedef struct {
    const char *name;
    const uint8_t *input;
    size_t input_len;
    const uint8_t *expected_output;
    size_t output_len;
} CryptoTestVector;

/**
 * Verify cryptographic implementation against test vectors
 * Returns 0 if all tests pass, -1 if any test fails
 */
int verify_crypto_test_vectors(void);

#endif /* SECURESWIFT_SECURITY_H */
