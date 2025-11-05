#define _GNU_SOURCE  /* Required for CPU_ZERO, CPU_SET, sched_setaffinity */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <time.h>
#include <stdint.h>
#include <pthread.h>
#include <immintrin.h>
#include <sched.h>
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>
#include <syslog.h>

// Version and build info
#define VERSION "2.0.0"
#define BUILD_DATE __DATE__
#define BUILD_TIME __TIME__

// Constants
#define PORT 51820
#define BUFSIZE 2048
#define TUN_NAME "tun0"
#define MIN_MTU 1280
#define MAX_MTU 1420
#define NUM_THREADS 8
#define SESSION_TIMEOUT 300
#define TAG_LEN 16
#define MAX_PACKET_SIZE 65535
#define KEEPALIVE_INTERVAL 25
#define KYBER_K 3
#define KYBER_N 256
#define KYBER_Q 3329
#define KYBER_SYMBYTES 32
#define KYBER_POLYBYTES 384
#define KYBER_POLYVECBYTES (KYBER_K * KYBER_POLYBYTES)
#define KYBER_POLYCOMPRESSEDBYTES 128
#define KYBER_POLYVECCOMPRESSEDBYTES (KYBER_K * 320)
#define KYBER_CIPHERTEXTBYTES (KYBER_POLYVECCOMPRESSEDBYTES + KYBER_POLYCOMPRESSEDBYTES)
#define KYBER_PUBLICKEYBYTES (KYBER_POLYVECBYTES + KYBER_SYMBYTES)
#define KYBER_SECRETKEYBYTES (KYBER_POLYVECBYTES + 2*KYBER_SYMBYTES + KYBER_POLYVECBYTES)
#define DILITHIUM_L 6
#define DILITHIUM_K 5
#define DILITHIUM_Q 8380417
#define DILITHIUM_ETA 4
#define DILITHIUM_BETA 175
#define DILITHIUM_GAMMA1 (1 << 19)
#define DILITHIUM_GAMMA2 (DILITHIUM_Q-1)/16
#define DILITHIUM_SIGBYTES 2420
#define DILITHIUM_PUBKEYBYTES 1312
#define DILITHIUM_SECKEYBYTES 2528
#define CURVE25519_BYTES 32
#define BLAKE3_OUT_LEN 32
#define MAX_HOPS 3
#define MAX_CONN_PER_IP 5         /* Max connections per IP */
#define RATE_LIMIT_WINDOW 60      /* Rate limit window in seconds */
#define MAX_PACKETS_PER_WINDOW 1000  /* Max packets per IP per window */
#define FAIL2BAN_LOG "/var/log/secureswift-auth.log"  /* fail2ban log file */

// DDoS Protection - Rate Limiting per IP
typedef struct {
    uint32_t ip;
    time_t window_start;
    uint32_t packet_count;
    uint32_t conn_count;
    time_t last_auth_fail;
    uint32_t auth_fail_count;
} RateLimitEntry;

#define RATE_LIMIT_TABLE_SIZE 1024
static RateLimitEntry rate_limit_table[RATE_LIMIT_TABLE_SIZE];
static pthread_mutex_t rate_limit_mutex = PTHREAD_MUTEX_INITIALIZER;

// fail2ban integration - log authentication failures
static void fail2ban_log(const char *event, const char *ip, const char *reason) {
    FILE *f = fopen(FAIL2BAN_LOG, "a");
    if (!f) return;

    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);

    fprintf(f, "[%s] EVENT=%s IP=%s REASON=%s\n", timestamp, event, ip, reason);
    fclose(f);

    /* Also log to syslog for system monitoring */
    openlog("secureswift", LOG_PID | LOG_CONS, LOG_AUTH);
    syslog(LOG_WARNING, "EVENT=%s IP=%s REASON=%s", event, ip, reason);
    closelog();
}

// Check and update rate limit for an IP
static int rate_limit_check(uint32_t ip_addr, const char *ip_str) {
    pthread_mutex_lock(&rate_limit_mutex);

    uint32_t hash = ip_addr % RATE_LIMIT_TABLE_SIZE;
    RateLimitEntry *entry = &rate_limit_table[hash];
    time_t now = time(NULL);

    /* Initialize or reset entry if it's a new IP or window expired */
    if (entry->ip != ip_addr || (now - entry->window_start) > RATE_LIMIT_WINDOW) {
        entry->ip = ip_addr;
        entry->window_start = now;
        entry->packet_count = 1;
        entry->conn_count = 1;
        entry->auth_fail_count = 0;
        pthread_mutex_unlock(&rate_limit_mutex);
        return 1;  /* Allow */
    }

    /* Check packet rate limit */
    entry->packet_count++;
    if (entry->packet_count > MAX_PACKETS_PER_WINDOW) {
        pthread_mutex_unlock(&rate_limit_mutex);
        fail2ban_log("RATE_LIMIT", ip_str, "Exceeded packet rate limit");
        return 0;  /* Block */
    }

    /* Check connection limit */
    if (entry->conn_count >= MAX_CONN_PER_IP) {
        pthread_mutex_unlock(&rate_limit_mutex);
        fail2ban_log("CONN_LIMIT", ip_str, "Exceeded connection limit");
        return 0;  /* Block */
    }

    pthread_mutex_unlock(&rate_limit_mutex);
    return 1;  /* Allow */
}

// Record authentication failure for fail2ban
static void record_auth_failure(uint32_t ip_addr, const char *ip_str, const char *reason) {
    pthread_mutex_lock(&rate_limit_mutex);

    uint32_t hash = ip_addr % RATE_LIMIT_TABLE_SIZE;
    RateLimitEntry *entry = &rate_limit_table[hash];
    time_t now = time(NULL);

    if (entry->ip == ip_addr) {
        entry->auth_fail_count++;
        entry->last_auth_fail = now;

        /* Ban after 5 failed attempts within 10 minutes */
        if (entry->auth_fail_count >= 5 && (now - entry->last_auth_fail) < 600) {
            fail2ban_log("AUTH_FAIL_BAN", ip_str, reason);
            pthread_mutex_unlock(&rate_limit_mutex);
            return;
        }
    }

    pthread_mutex_unlock(&rate_limit_mutex);
    fail2ban_log("AUTH_FAIL", ip_str, reason);
}

// Secure Randomness
static void get_random_bytes(uint8_t *out, size_t len) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) { perror("Failed to open /dev/urandom"); exit(1); }
    if (read(fd, out, len) != (ssize_t)len) {
        perror("Failed to read /dev/urandom"); close(fd); exit(1);
    }
    close(fd);
}

// BLAKE3 Implementation
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

static const uint8_t BLAKE3_MSG_SCHEDULE[7][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8},
    {3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1},
    {10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6},
    {12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4},
    {9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7},
    {11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13}
};

static uint32_t rotl32(uint32_t x, uint32_t y) {
    return (x << y) | (x >> (32 - y));
}

static void blake3_g(uint32_t *state, size_t a, size_t b, size_t c, size_t d, uint32_t mx, uint32_t my) {
    state[a] += state[b] + mx;
    state[d] = rotl32(state[d] ^ state[a], 16);
    state[c] += state[d];
    state[b] = rotl32(state[b] ^ state[c], 12);
    state[a] += state[b] + my;
    state[d] = rotl32(state[d] ^ state[a], 8);
    state[c] += state[d];
    state[b] = rotl32(state[b] ^ state[c], 7);
}

static void blake3_compress(Blake3 *self, const uint8_t *block, uint32_t *out) {
    uint32_t state[16];
    memcpy(state, self->cv, 32);
    memcpy(state + 8, BLAKE3_IV, 32);
    state[12] = (uint32_t)self->blocks_compressed;
    state[13] = (uint32_t)(self->blocks_compressed >> 32);
    state[14] = self->block_len;
    state[15] = self->flags;

    uint32_t m[16];
    for (size_t i = 0; i < 16; i++) {
        m[i] = ((uint32_t)block[i*4]) | ((uint32_t)block[i*4+1] << 8) |
               ((uint32_t)block[i*4+2] << 16) | ((uint32_t)block[i*4+3] << 24);
    }

    for (size_t r = 0; r < 7; r++) {
        blake3_g(state, 0, 4, 8, 12, m[BLAKE3_MSG_SCHEDULE[r][0]], m[BLAKE3_MSG_SCHEDULE[r][1]]);
        blake3_g(state, 1, 5, 9, 13, m[BLAKE3_MSG_SCHEDULE[r][2]], m[BLAKE3_MSG_SCHEDULE[r][3]]);
        blake3_g(state, 2, 6, 10, 14, m[BLAKE3_MSG_SCHEDULE[r][4]], m[BLAKE3_MSG_SCHEDULE[r][5]]);
        blake3_g(state, 3, 7, 11, 15, m[BLAKE3_MSG_SCHEDULE[r][6]], m[BLAKE3_MSG_SCHEDULE[r][7]]);
        blake3_g(state, 0, 5, 10, 15, m[BLAKE3_MSG_SCHEDULE[r][8]], m[BLAKE3_MSG_SCHEDULE[r][9]]);
        blake3_g(state, 1, 6, 11, 12, m[BLAKE3_MSG_SCHEDULE[r][10]], m[BLAKE3_MSG_SCHEDULE[r][11]]);
        blake3_g(state, 2, 7, 8, 13, m[BLAKE3_MSG_SCHEDULE[r][12]], m[BLAKE3_MSG_SCHEDULE[r][13]]);
        blake3_g(state, 3, 4, 9, 14, m[BLAKE3_MSG_SCHEDULE[r][14]], m[BLAKE3_MSG_SCHEDULE[r][15]]);
    }

    for (size_t i = 0; i < 8; i++) {
        state[i] ^= state[i + 8];
        state[i + 8] ^= self->cv[i];
    }
    memcpy(out, state, 32);
}

static void blake3_init(Blake3 *self) {
    memcpy(self->cv, BLAKE3_IV, 32);
    memset(self->block, 0, 64);
    self->block_len = 0;
    self->blocks_compressed = 0;
    self->flags = 0;
}

static void blake3_update(Blake3 *self, const uint8_t *data, size_t len) {
    size_t pos = 0;
    while (pos < len) {
        if (self->block_len == 64) {
            uint32_t out[8];
            blake3_compress(self, self->block, out);
            memcpy(self->cv, out, 32);
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

static void blake3_final(Blake3 *self, uint8_t *out) {
    uint8_t block[64] = {0};
    memcpy(block, self->block, self->block_len);
    uint32_t out_words[8];
    self->flags |= 0x2; // FINALIZE
    blake3_compress(self, block, out_words);
    for (int i = 0; i < 8; i++) {
        out[i*4] = out_words[i] & 0xff;
        out[i*4+1] = (out_words[i] >> 8) & 0xff;
        out[i*4+2] = (out_words[i] >> 16) & 0xff;
        out[i*4+3] = (out_words[i] >> 24) & 0xff;
    }
}

// XSalsa20 Implementation
typedef struct {
    uint8_t key[32];
    uint8_t nonce[24];
    uint64_t counter;
} XSalsa20;

static void xsalsa20_core(uint32_t *input, uint32_t *out) {
    memcpy(out, input, 64);
    for (int i = 0; i < 10; i++) {
        out[4]  += out[0];  out[12] = rotl32(out[12] ^ out[4],  16);
        out[8]  += out[12]; out[0]  = rotl32(out[0]  ^ out[8],  12);
        out[4]  += out[0];  out[12] = rotl32(out[12] ^ out[4],   8);
        out[8]  += out[12]; out[0]  = rotl32(out[0]  ^ out[8],   7);
        out[9]  += out[5];  out[1]  = rotl32(out[1]  ^ out[9],  16);
        out[13] += out[1];  out[5]  = rotl32(out[5]  ^ out[13], 12);
        out[9]  += out[5];  out[1]  = rotl32(out[1]  ^ out[9],   8);
        out[13] += out[1];  out[5]  = rotl32(out[5]  ^ out[13],  7);
        out[14] += out[10]; out[6]  = rotl32(out[6]  ^ out[14], 16);
        out[2]  += out[6];  out[10] = rotl32(out[10] ^ out[2],  12);
        out[14] += out[10]; out[6]  = rotl32(out[6]  ^ out[14],  8);
        out[2]  += out[6];  out[10] = rotl32(out[10] ^ out[2],   7);
        out[3]  += out[15]; out[11] = rotl32(out[11] ^ out[3],  16);
        out[7]  += out[11]; out[15] = rotl32(out[15] ^ out[7],  12);
        out[3]  += out[15]; out[11] = rotl32(out[11] ^ out[3],   8);
        out[7]  += out[11]; out[15] = rotl32(out[15] ^ out[7],   7);
        out[1]  += out[0];  out[3]  = rotl32(out[3]  ^ out[1],  16);
        out[2]  += out[3];  out[0]  = rotl32(out[0]  ^ out[2],   9);
        out[1]  += out[0];  out[3]  = rotl32(out[3]  ^ out[1],  13);
        out[2]  += out[3];  out[0]  = rotl32(out[0]  ^ out[2],  18);
        out[6]  += out[5];  out[4]  = rotl32(out[4]  ^ out[6],  16);
        out[7]  += out[4];  out[5]  = rotl32(out[5]  ^ out[7],   9);
        out[6]  += out[5];  out[4]  = rotl32(out[4]  ^ out[6],  13);
        out[7]  += out[4];  out[5]  = rotl32(out[5]  ^ out[7],  18);
        out[11] += out[10]; out[9]  = rotl32(out[9]  ^ out[11], 16);
        out[8]  += out[9];  out[10] = rotl32(out[10] ^ out[8],   9);
        out[11] += out[10]; out[9]  = rotl32(out[9]  ^ out[11], 13);
        out[8]  += out[9];  out[10] = rotl32(out[10] ^ out[8],  18);
        out[12] += out[15]; out[14] = rotl32(out[14] ^ out[12], 16);
        out[13] += out[14]; out[15] = rotl32(out[15] ^ out[13],  9);
        out[12] += out[15]; out[14] = rotl32(out[14] ^ out[12], 13);
        out[13] += out[14]; out[15] = rotl32(out[15] ^ out[13], 18);
    }
    for (int i = 0; i < 16; i++) out[i] += input[i];
}

static void xsalsa20_init(XSalsa20 *self, const uint8_t *key, const uint8_t *nonce) {
    memcpy(self->key, key, 32);
    memcpy(self->nonce, nonce, 24);
    self->counter = 0;
}

static void xsalsa20_block(XSalsa20 *self, uint8_t *out) {
    uint32_t input[16], block[16];
    uint32_t sigma[4] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};
    memcpy(input, sigma, 16);
    memcpy(input + 4, self->key, 16);
    memcpy(input + 6, self->nonce, 8);
    input[8] = input[9] = 0;
    memcpy(input + 10, self->key + 16, 16);
    input[14] = (uint32_t)(self->counter & 0xffffffff);
    input[15] = (uint32_t)(self->counter >> 32);
    xsalsa20_core(input, block);
    for (int i = 0; i < 16; i++) {
        out[i*4] = block[i] & 0xff;
        out[i*4+1] = (block[i] >> 8) & 0xff;
        out[i*4+2] = (block[i] >> 16) & 0xff;
        out[i*4+3] = (block[i] >> 24) & 0xff;
    }
}

static void xsalsa20_encrypt_simd(XSalsa20 *self, const uint8_t *plaintext, uint8_t *ciphertext, size_t len) {
    uint8_t keystream[64];
    size_t pos = 0;
    while (pos + 16 <= len) {
        xsalsa20_block(self, keystream);
        __m128i ks = _mm_loadu_si128((__m128i *)keystream);
        __m128i pt = _mm_loadu_si128((__m128i *)(plaintext + pos));
        __m128i ct = _mm_xor_si128(pt, ks);
        _mm_storeu_si128((__m128i *)(ciphertext + pos), ct);
        pos += 16;
        self->counter++;
    }
    if (pos < len) {
        xsalsa20_block(self, keystream);
        for (; pos < len; pos++) {
            ciphertext[pos] = plaintext[pos] ^ keystream[pos % 64];
        }
        self->counter++;
    }
}

// Poly1305 Implementation
typedef struct {
    uint32_t r[5];
    uint32_t h[5];
    uint32_t pad[4];
    uint8_t buffer[16];
    size_t leftover;
    uint8_t final;
} Poly1305;

static void poly1305_blocks(Poly1305 *ctx, const uint8_t *m, size_t len) {
    uint32_t r0 = ctx->r[0], r1 = ctx->r[1], r2 = ctx->r[2], r3 = ctx->r[3], r4 = ctx->r[4];
    uint32_t h0 = ctx->h[0], h1 = ctx->h[1], h2 = ctx->h[2], h3 = ctx->h[3], h4 = ctx->h[4];

    while (len >= 16) {
        uint32_t in0 = *(uint32_t*)(m + 0);
        uint32_t in1 = *(uint32_t*)(m + 4);
        uint32_t in2 = *(uint32_t*)(m + 8);
        uint32_t in3 = *(uint32_t*)(m + 12);

        h0 += in0 & 0x3ffffff;
        h1 += ((in1 << 6) | (in0 >> 26)) & 0x3ffffff;
        h2 += ((in2 << 12) | (in1 >> 20)) & 0x3ffffff;
        h3 += ((in3 << 18) | (in2 >> 14)) & 0x3ffffff;
        h4 += (in3 >> 8) | (1 << 24);

        uint64_t d0 = (uint64_t)h0 * r0 + (uint64_t)h1 * r4 + (uint64_t)h2 * r3 + (uint64_t)h3 * r2 + (uint64_t)h4 * r1;
        uint64_t d1 = (uint64_t)h0 * r1 + (uint64_t)h1 * r0 + (uint64_t)h2 * r4 + (uint64_t)h3 * r3 + (uint64_t)h4 * r2;
        uint64_t d2 = (uint64_t)h0 * r2 + (uint64_t)h1 * r1 + (uint64_t)h2 * r0 + (uint64_t)h3 * r4 + (uint64_t)h4 * r3;
        uint64_t d3 = (uint64_t)h0 * r3 + (uint64_t)h1 * r2 + (uint64_t)h2 * r1 + (uint64_t)h3 * r0 + (uint64_t)h4 * r4;
        uint64_t d4 = (uint64_t)h0 * r4 + (uint64_t)h1 * r3 + (uint64_t)h2 * r2 + (uint64_t)h3 * r1 + (uint64_t)h4 * r0;

        h0 = d0 & 0x3ffffff;
        d1 += d0 >> 26;
        h1 = d1 & 0x3ffffff;
        d2 += d1 >> 26;
        h2 = d2 & 0x3ffffff;
        d3 += d2 >> 26;
        h3 = d3 & 0x3ffffff;
        d4 += d3 >> 26;
        h4 = d4 & 0x3ffffff;
        h0 += (d4 >> 26) * 5;
        h1 += h0 >> 26;
        h0 &= 0x3ffffff;

        m += 16;
        len -= 16;
    }

    ctx->h[0] = h0; ctx->h[1] = h1; ctx->h[2] = h2; ctx->h[3] = h3; ctx->h[4] = h4;
}

static void poly1305_init(Poly1305 *ctx, const uint8_t *key) {
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

static void poly1305_update(Poly1305 *ctx, const uint8_t *m, size_t len) {
    if (ctx->leftover) {
        size_t want = 16 - ctx->leftover;
        if (want > len) want = len;
        memcpy(ctx->buffer + ctx->leftover, m, want);
        m += want;
        len -= want;
        ctx->leftover += want;
        if (ctx->leftover < 16) return;
        poly1305_blocks(ctx, ctx->buffer, 16);
        ctx->leftover = 0;
    }

    if (len >= 16) {
        size_t want = len & ~15;
        poly1305_blocks(ctx, m, want);
        m += want;
        len -= want;
    }

    if (len) {
        memcpy(ctx->buffer, m, len);
        ctx->leftover = len;
    }
}

static void poly1305_final(Poly1305 *ctx, uint8_t *tag) {
    if (ctx->leftover) {
        ctx->buffer[ctx->leftover] = 1;
        memset(ctx->buffer + ctx->leftover + 1, 0, 15 - ctx->leftover);
        ctx->final = 1;
        poly1305_blocks(ctx, ctx->buffer, 16);
    }

    uint64_t h0 = ctx->h[0], h1 = ctx->h[1], h2 = ctx->h[2], h3 = ctx->h[3], h4 = ctx->h[4];
    uint64_t c = h1 >> 26; h1 &= 0x3ffffff; h2 += c;
    c = h2 >> 26; h2 &= 0x3ffffff; h3 += c;
    c = h3 >> 26; h3 &= 0x3ffffff; h4 += c;
    c = h4 >> 26; h4 &= 0x3ffffff; h0 += c * 5;
    c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;

    uint64_t g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
    uint64_t g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
    uint64_t g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
    uint64_t g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
    uint64_t g4 = h4 + c - (1ULL << 26);

    uint64_t mask = (g4 >> 63) - 1;
    g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0; h1 = (h1 & mask) | g1; h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3; h4 = (h4 & mask) | g4;

    h0 = (h0 | (h1 << 26)) & 0xffffffff;
    h1 = ((h1 >> 6) | (h2 << 20)) & 0xffffffff;
    h2 = ((h2 >> 12) | (h3 << 14)) & 0xffffffff;
    h3 = ((h3 >> 18) | (h4 << 8)) & 0xffffffff;

    *(uint32_t*)(tag + 0) = h0 + *(uint32_t*)(ctx->pad + 0);
    *(uint32_t*)(tag + 4) = h1 + *(uint32_t*)(ctx->pad + 4);
    *(uint32_t*)(tag + 8) = h2 + *(uint32_t*)(ctx->pad + 8);
    *(uint32_t*)(tag + 12) = h3 + *(uint32_t*)(ctx->pad + 12);
}

// Curve25519 Implementation
static void curve25519_clamp(uint8_t *r) {
    r[0] &= 248; r[31] &= 127; r[31] |= 64;
}

static void curve25519_add(uint32_t *r, const uint32_t *a, const uint32_t *b) {
    uint64_t t;
    for (int i = 0; i < 8; i++) {
        t = (uint64_t)a[i] + b[i];
        r[i] = t & 0xffffffff;
        t >>= 32;
    }
}

static void curve25519_sub(uint32_t *r, const uint32_t *a, const uint32_t *b) {
    uint64_t t = 0;
    for (int i = 0; i < 8; i++) {
        t = (uint64_t)a[i] - b[i] - t;
        r[i] = t & 0xffffffff;
        t >>= 32;
    }
}

static void curve25519_mul(uint32_t *r, const uint32_t *a, const uint32_t *b) {
    uint64_t t[16] = {0};
    for (int i = 0; i < 8; i++) {
        for (int j = 0; j < 8; j++) {
            t[i+j] += (uint64_t)a[i] * b[j];
        }
    }
    for (int i = 0; i < 15; i++) {
        t[i+1] += t[i] >> 32;
        t[i] &= 0xffffffff;
    }
    t[7] += t[15] * 19;
    t[15] = 0;
    for (int i = 0; i < 15; i++) {
        t[i+1] += t[i] >> 32;
        t[i] &= 0xffffffff;
    }
    for (int i = 0; i < 8; i++) r[i] = t[i];
}

// Modular inversion using Fermat's Little Theorem: a^(-1) = a^(p-2) mod p
// For Curve25519, p = 2^255 - 19
static void curve25519_inv(uint32_t *out, const uint32_t *in) {
    uint32_t t0[8], t1[8], t2[8], t3[8];

    /* Exponentiation by squaring for (p-2) = 2^255 - 21 */
    /* This implements the standard chain for Curve25519 inversion */

    /* t0 = in^2 */
    curve25519_mul(t0, in, in);
    /* t1 = in^4 */
    curve25519_mul(t1, t0, t0);
    /* t1 = in^8 */
    curve25519_mul(t1, t1, t1);
    /* t1 = in^9 (= in^8 * in) */
    curve25519_mul(t1, t1, in);
    /* t0 = in^11 (= in^9 * in^2) */
    curve25519_mul(t0, t1, t0);
    /* t2 = in^22 */
    curve25519_mul(t2, t0, t0);
    /* t1 = in^(2^5-1) */
    curve25519_mul(t1, t2, t1);
    /* t2 = in^(2^10-2) */
    curve25519_mul(t2, t1, t1);
    for (int i = 0; i < 4; i++) curve25519_mul(t2, t2, t2);
    /* t1 = in^(2^10-1) */
    curve25519_mul(t1, t2, t1);
    /* t2 = in^(2^20-2) */
    curve25519_mul(t2, t1, t1);
    for (int i = 0; i < 9; i++) curve25519_mul(t2, t2, t2);
    /* t2 = in^(2^20-1) */
    curve25519_mul(t2, t2, t1);
    /* t3 = in^(2^40-2) */
    curve25519_mul(t3, t2, t2);
    for (int i = 0; i < 19; i++) curve25519_mul(t3, t3, t3);
    /* t2 = in^(2^40-1) */
    curve25519_mul(t2, t3, t2);
    /* t2 = in^(2^50-2) */
    for (int i = 0; i < 9; i++) curve25519_mul(t2, t2, t2);
    /* t1 = in^(2^50-1) */
    curve25519_mul(t1, t2, t1);
    /* t2 = in^(2^100-2) */
    curve25519_mul(t2, t1, t1);
    for (int i = 0; i < 49; i++) curve25519_mul(t2, t2, t2);
    /* t2 = in^(2^100-1) */
    curve25519_mul(t2, t2, t1);
    /* t3 = in^(2^200-2) */
    curve25519_mul(t3, t2, t2);
    for (int i = 0; i < 99; i++) curve25519_mul(t3, t3, t3);
    /* t2 = in^(2^200-1) */
    curve25519_mul(t2, t3, t2);
    /* t2 = in^(2^250-2) */
    for (int i = 0; i < 49; i++) curve25519_mul(t2, t2, t2);
    /* t2 = in^(2^250-1) */
    curve25519_mul(t2, t2, t1);
    /* t2 = in^(2^255-21) = in^(p-2) */
    for (int i = 0; i < 4; i++) curve25519_mul(t2, t2, t2);
    curve25519_mul(t2, t2, t0);

    memcpy(out, t2, 32);
}

static void curve25519_scalar_mult(uint8_t *out, const uint8_t *scalar, const uint8_t *point) {
    uint32_t x[8] = {1}, z[8] = {0}, a[8] = {0}, b[8] = {1};
    uint32_t p[8];
    for (int i = 0; i < 8; i++) p[i] = ((uint32_t)point[i*4]) | ((uint32_t)point[i*4+1] << 8) |
                                        ((uint32_t)point[i*4+2] << 16) | ((uint32_t)point[i*4+3] << 24);
    for (int i = 255; i >= 0; i--) {
        uint8_t bit = (scalar[i/8] >> (i % 8)) & 1;
        uint32_t t1[8], t2[8];
        curve25519_add(t1, x, z);
        curve25519_sub(t2, x, z);
        memcpy(x, t1, 32);
        memcpy(z, t2, 32);
        curve25519_add(t1, a, b);
        curve25519_sub(t2, a, b);
        memcpy(a, t1, 32);
        memcpy(b, t2, 32);
        curve25519_mul(t1, x, a);
        curve25519_mul(t2, z, b);
        memcpy(x, t1, 32);
        memcpy(z, t2, 32);
        curve25519_mul(t1, a, a);
        curve25519_mul(t2, b, b);
        memcpy(a, t1, 32);
        memcpy(b, t2, 32);
        curve25519_add(t1, t1, t2);
        curve25519_sub(t2, t1, t2);
        curve25519_mul(t2, t2, p);
        memcpy(a, t1, 32);
        memcpy(b, t2, 32);
        if (bit) {
            curve25519_add(t1, x, z);
            curve25519_sub(t2, x, z);
            memcpy(x, t1, 32);
            memcpy(z, t2, 32);
        }
    }
    uint32_t inv_z[8];
    /* Proper modular inversion using Fermat's Little Theorem */
    curve25519_inv(inv_z, z);
    curve25519_mul(x, x, inv_z);
    for (int i = 0; i < 8; i++) {
        out[i*4] = x[i] & 0xff;
        out[i*4+1] = (x[i] >> 8) & 0xff;
        out[i*4+2] = (x[i] >> 16) & 0xff;
        out[i*4+3] = (x[i] >> 24) & 0xff;
    }
}

// ML-KEM (Kyber768) Implementation
typedef struct {
    int32_t coeffs[KYBER_N];
} poly;

typedef struct {
    poly vec[KYBER_K];
} polyvec;

static const int16_t zetas[128] = {
    2285, 2571, 2970, 1812, 1493, 1422, 1335, 1246, 1215, 1134, 1092, 1068, 1046, 965, 948, 919,
    907, 852, 838, 793, 778, 766, 752, 747, 724, 722, 697, 641, 626, 609, 575, 570, 503, 489, 439,
    413, 392, 377, 364, 331, 312, 289, 268, 250, 230, 213, 167, 135, 119, 87, 74, 63, 33, 4, 3321,
    3258, 3225, 3211, 3178, 3145, 3124, 3111, 3082, 3073, 3061, 3030, 2895, 2883, 2853, 2824,
    2817, 2813, 2794, 2772, 2671, 2658, 2633, 2620, 2591, 2571, 2553, 2523, 2492, 2472, 2462,
    2457, 2451, 2433, 2428, 2398, 2391, 2386, 2373, 2359, 2328, 2314, 2211, 2198, 2182, 2153,
    2039, 1978, 1921, 1862, 1842, 1823, 1784, 1711, 1698, 1630, 1581, 1555, 1505, 1418, 1399,
    1315, 1232, 1211, 1143, 960, 910, 833, 779, 741, 677, 639, 612, 566, 466, 417, 355, 340, 317,
    302, 274, 259, 232, 187, 154, 132, 119, 107, 89, 68, 47, 34, 0
};

static int32_t montgomery_reduce(int64_t a) {
    int32_t t = (int32_t)(a * -3327LL);
    t = (a - (int64_t)t * KYBER_Q) >> 16;
    return t;
}

static int32_t barrett_reduce(int32_t a) {
    int32_t v = ((1U << 26) / KYBER_Q) + 1;
    int32_t t = v * a >> 26;
    t *= KYBER_Q;
    return a - t;
}

static int32_t csubq(int32_t a) {
    a -= KYBER_Q;
    a += (a >> 31) & KYBER_Q;
    return a;
}

static void poly_reduce(poly *r) {
    for (int i = 0; i < KYBER_N; i++) r->coeffs[i] = barrett_reduce(r->coeffs[i]);
}

static void poly_csubq(poly *r) {
    for (int i = 0; i < KYBER_N; i++) r->coeffs[i] = csubq(r->coeffs[i]);
}

static void poly_add(poly *r, const poly *a, const poly *b) {
    for (int i = 0; i < KYBER_N; i++) r->coeffs[i] = csubq(a->coeffs[i] + b->coeffs[i]);
}

static void poly_sub(poly *r, const poly *a, const poly *b) {
    for (int i = 0; i < KYBER_N; i++) r->coeffs[i] = csubq(a->coeffs[i] - b->coeffs[i]);
}

static void poly_pointwise_montgomery(poly *r, const poly *a, const poly *b) {
    for (int i = 0; i < KYBER_N; i++) r->coeffs[i] = montgomery_reduce((int64_t)a->coeffs[i] * b->coeffs[i]);
}

static void polyvec_reduce(polyvec *r) {
    for (int i = 0; i < KYBER_K; i++) poly_reduce(&r->vec[i]);
}

static void polyvec_csubq(polyvec *r) {
    for (int i = 0; i < KYBER_K; i++) poly_csubq(&r->vec[i]);
}

static void polyvec_add(polyvec *r, const polyvec *a, const polyvec *b) {
    for (int i = 0; i < KYBER_K; i++) poly_add(&r->vec[i], &a->vec[i], &b->vec[i]);
}

static void polyvec_sub(polyvec *r, const polyvec *a, const polyvec *b) {
    for (int i = 0; i < KYBER_K; i++) poly_sub(&r->vec[i], &a->vec[i], &b->vec[i]);
}

static void polyvec_ntt(polyvec *r) {
    for (int i = 0; i < KYBER_K; i++) {
        unsigned int len = 128, k = 1;
        for (len = 128; len >= 2; len >>= 1) {
            for (unsigned int start = 0; start < KYBER_N; start += 2 * len) {
                int32_t zeta = zetas[k++];
                for (unsigned int j = start; j < start + len; j++) {
                    int32_t t = montgomery_reduce((int64_t)zeta * r->vec[i].coeffs[j + len]);
                    r->vec[i].coeffs[j + len] = csubq(r->vec[i].coeffs[j] - t);
                    r->vec[i].coeffs[j] = csubq(r->vec[i].coeffs[j] + t);
                }
            }
        }
    }
}

static void polyvec_invntt(polyvec *r) {
    for (int i = 0; i < KYBER_K; i++) {
        unsigned int len = 2, k = 127;
        for (len = 2; len <= 128; len <<= 1) {
            for (unsigned int start = 0; start < KYBER_N; start += 2 * len) {
                int32_t zeta = -zetas[k--];
                for (unsigned int j = start; j < start + len; j++) {
                    int32_t t = r->vec[i].coeffs[j];
                    r->vec[i].coeffs[j] = csubq(t + r->vec[i].coeffs[j + len]);
                    r->vec[i].coeffs[j + len] = montgomery_reduce((int64_t)zeta * (r->vec[i].coeffs[j + len] - t));
                }
            }
        }
        for (unsigned int j = 0; j < KYBER_N; j++) {
            r->vec[i].coeffs[j] = montgomery_reduce((int64_t)r->vec[i].coeffs[j] * 3303);
        }
    }
}

static void polyvec_pointwise_acc_montgomery(poly *r, const polyvec *a, const polyvec *b) {
    poly_pointwise_montgomery(r, &a->vec[0], &b->vec[0]);
    for (int i = 1; i < KYBER_K; i++) {
        poly tmp;
        poly_pointwise_montgomery(&tmp, &a->vec[i], &b->vec[i]);
        poly_add(r, r, &tmp);
    }
}

static void polyvec_compress(uint8_t *r, const polyvec *a) {
    uint16_t t[4];
    int rr = 0;
    for (int i = 0; i < KYBER_K; i++) {
        for (int j = 0; j < KYBER_N / 4; j++) {
            for (int k = 0; k < 4; k++) {
                t[k] = (uint32_t)(((a->vec[i].coeffs[4 * j + k] << 10) + KYBER_Q / 2) / KYBER_Q) & 0x3ff;
            }
            r[rr++] = t[0];
            r[rr++] = (t[0] >> 8) | (t[1] << 2);
            r[rr++] = (t[1] >> 6) | (t[2] << 4);
            r[rr++] = (t[2] >> 4) | (t[3] << 6);
            r[rr++] = t[3] >> 2;
        }
    }
}

static void polyvec_decompress(polyvec *r, const uint8_t *a) {
    int aa = 0;
    for (int i = 0; i < KYBER_K; i++) {
        for (int j = 0; j < KYBER_N / 4; j++) {
            uint16_t t[4];
            t[0] = (a[aa] | ((uint16_t)a[aa+1] << 8)) & 0x3ff;
            t[1] = (a[aa+1] >> 2) | ((uint16_t)a[aa+2] << 6);
            t[2] = (a[aa+2] >> 4) | ((uint16_t)a[aa+3] << 4);
            t[3] = (a[aa+3] >> 6) | ((uint16_t)a[aa+4] << 2);
            aa += 5;
            for (int k = 0; k < 4; k++) {
                r->vec[i].coeffs[4 * j + k] = ((uint32_t)(t[k] & 0x3ff) * KYBER_Q + 512) >> 10;
            }
        }
    }
}

static void poly_compress(uint8_t *r, const poly *a) {
    uint8_t t[8];
    int rr = 0;
    for (int i = 0; i < KYBER_N / 8; i++) {
        for (int j = 0; j < 8; j++) {
            t[j] = ((a->coeffs[8*i+j] << 4) + KYBER_Q / 2) / KYBER_Q & 15;
        }
        r[rr++] = t[0] | (t[1] << 4);
        r[rr++] = t[2] | (t[3] << 4);
        r[rr++] = t[4] | (t[5] << 4);
        r[rr++] = t[6] | (t[7] << 4);
    }
}

static void poly_decompress(poly *r, const uint8_t *a) {
    for (int i = 0; i < KYBER_N / 2; i++) {
        r->coeffs[2*i] = (((uint32_t)(a[i] & 15) * KYBER_Q) + 8) >> 4;
        r->coeffs[2*i+1] = (((uint32_t)(a[i] >> 4) * KYBER_Q) + 8) >> 4;
    }
}

static void poly_tobytes(uint8_t *r, const poly *a) {
    for (int i = 0; i < KYBER_N / 2; i++) {
        int32_t t0 = csubq(a->coeffs[2*i]);
        int32_t t1 = csubq(a->coeffs[2*i+1]);
        r[3*i] = t0 & 0xff;
        r[3*i+1] = (t0 >> 8) | ((t1 & 0xf) << 4);
        r[3*i+2] = (t1 >> 4) & 0xff;
    }
}

static void poly_frombytes(poly *r, const uint8_t *a) {
    for (int i = 0; i < KYBER_N / 2; i++) {
        r->coeffs[2*i] = a[3*i] | ((uint32_t)(a[3*i+1] & 0x0f) << 8);
        r->coeffs[2*i+1] = (a[3*i+1] >> 4) | ((uint32_t)a[3*i+2] << 4);
        r->coeffs[2*i] = csubq(r->coeffs[2*i]);
        r->coeffs[2*i+1] = csubq(r->coeffs[2*i+1]);
    }
}

static void polyvec_tobytes(uint8_t *r, const polyvec *a) {
    for (int i = 0; i < KYBER_K; i++) poly_tobytes(r + i * KYBER_POLYBYTES, &a->vec[i]);
}

static void polyvec_frombytes(polyvec *r, const uint8_t *a) {
    for (int i = 0; i < KYBER_K; i++) poly_frombytes(&r->vec[i], a + i * KYBER_POLYBYTES);
}

static void poly_getnoise_eta1(poly *r, const uint8_t *seed, uint8_t nonce) {
    uint8_t buf[KYBER_SYMBYTES * 2];
    Blake3 b;
    blake3_init(&b);
    blake3_update(&b, seed, KYBER_SYMBYTES);
    blake3_update(&b, &nonce, 1);
    blake3_final(&b, buf);
    for (int i = 0; i < KYBER_N; i++) {
        uint32_t t = buf[i/4] >> (2 * (i % 4));
        r->coeffs[i] = ((t & 1) - ((t >> 1) & 1)) * (KYBER_Q + 1) / 2;
    }
}

static void poly_getnoise_eta2(poly *r, const uint8_t *seed, uint8_t nonce) {
    uint8_t buf[KYBER_SYMBYTES];
    Blake3 b;
    blake3_init(&b);
    blake3_update(&b, seed, KYBER_SYMBYTES);
    blake3_update(&b, &nonce, 1);
    blake3_final(&b, buf);
    for (int i = 0; i < KYBER_N; i++) {
        uint32_t t = buf[i/8] >> (i % 8);
        r->coeffs[i] = (t & 1) - ((t >> 1) & 1);
    }
}

static void kyber_keygen(uint8_t *pk, uint8_t *sk) {
    uint8_t d[KYBER_SYMBYTES];
    get_random_bytes(d, KYBER_SYMBYTES);
    uint8_t buf[2 * KYBER_SYMBYTES];
    Blake3 b;
    blake3_init(&b);
    blake3_update(&b, d, KYBER_SYMBYTES);
    blake3_final(&b, buf);
    uint8_t *rho = buf, *sigma = buf + KYBER_SYMBYTES;

    polyvec a[KYBER_K], s, e;
    for (int i = 0; i < KYBER_K; i++) for (int j = 0; j < KYBER_K; j++) {
        uint8_t seed[KYBER_SYMBYTES + 2];
        memcpy(seed, rho, KYBER_SYMBYTES);
        seed[KYBER_SYMBYTES] = i;
        seed[KYBER_SYMBYTES + 1] = j;
        Blake3 b_a;
        blake3_init(&b_a);
        blake3_update(&b_a, seed, KYBER_SYMBYTES + 2);
        uint8_t buf_a[KYBER_N * 2];
        blake3_final(&b_a, buf_a);
        for (int k = 0; k < KYBER_N; k++) {
            a[i].vec[j].coeffs[k] = (buf_a[2*k] | ((uint32_t)buf_a[2*k+1] << 8)) % KYBER_Q;
        }
    }

    for (int i = 0; i < KYBER_K; i++) {
        poly_getnoise_eta1(&s.vec[i], sigma, i);
        poly_getnoise_eta1(&e.vec[i], sigma, KYBER_K + i);
    }

    polyvec_ntt(&s);
    polyvec_ntt(&e);
    polyvec pkpv;
    for (int i = 0; i < KYBER_K; i++) {
        polyvec_pointwise_acc_montgomery(&pkpv.vec[i], &a[i], &s);
    }
    polyvec_add(&pkpv, &pkpv, &e);
    polyvec_reduce(&pkpv);
    polyvec_csubq(&pkpv);

    polyvec_tobytes(pk, &pkpv);
    memcpy(pk + KYBER_POLYVECBYTES, rho, KYBER_SYMBYTES);
    polyvec_tobytes(sk, &s);
    memcpy(sk + KYBER_POLYVECBYTES, pk, KYBER_PUBLICKEYBYTES);
    Blake3 b_h;
    blake3_init(&b_h);
    blake3_update(&b_h, pk, KYBER_PUBLICKEYBYTES);
    blake3_final(&b_h, sk + KYBER_POLYVECBYTES + KYBER_PUBLICKEYBYTES);
    memcpy(sk + KYBER_POLYVECBYTES + KYBER_PUBLICKEYBYTES + KYBER_SYMBYTES, d, KYBER_SYMBYTES);
}

static void kyber_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    uint8_t coins[KYBER_SYMBYTES];
    get_random_bytes(coins, KYBER_SYMBYTES);

    polyvec sp, ep, at[KYBER_K], b;
    poly v, epp;
    polyvec pkpv;
    polyvec_frombytes(&pkpv, pk);
    uint8_t *rho = (uint8_t *)pk + KYBER_POLYVECBYTES;

    for (int i = 0; i < KYBER_K; i++) for (int j = 0; j < KYBER_K; j++) {
        uint8_t seed[KYBER_SYMBYTES + 2];
        memcpy(seed, rho, KYBER_SYMBYTES);
        seed[KYBER_SYMBYTES] = i;
        seed[KYBER_SYMBYTES + 1] = j;
        Blake3 b_a;
        blake3_init(&b_a);
        blake3_update(&b_a, seed, KYBER_SYMBYTES + 2);
        uint8_t buf_a[KYBER_N * 2];
        blake3_final(&b_a, buf_a);
        for (int k = 0; k < KYBER_N; k++) {
            at[i].vec[j].coeffs[k] = (buf_a[2*k] | ((uint32_t)buf_a[2*k+1] << 8)) % KYBER_Q;
        }
    }

    for (int i = 0; i < KYBER_K; i++) {
        poly_getnoise_eta1(&sp.vec[i], coins, i);
        poly_getnoise_eta2(&ep.vec[i], coins, KYBER_K + i);
    }
    poly_getnoise_eta2(&epp, coins, 2*KYBER_K);

    polyvec_ntt(&sp);
    for (int i = 0; i < KYBER_K; i++) {
        polyvec_pointwise_acc_montgomery(&b.vec[i], &at[i], &sp);
    }
    polyvec_invntt(&b);
    polyvec_add(&b, &b, &ep);
    polyvec_reduce(&b);
    polyvec_csubq(&b);

    polyvec_pointwise_acc_montgomery(&v, &pkpv, &sp);
    polyvec_invntt(&v);
    poly_add(&v, &v, &epp);
    poly_reduce(&v);
    poly_csubq(&v);

    polyvec_compress(ct, &b);
    poly_compress(ct + KYBER_POLYVECCOMPRESSEDBYTES, &v);
    Blake3 b_ss;
    blake3_init(&b_ss);
    blake3_update(&b_ss, coins, KYBER_SYMBYTES);
    blake3_final(&b_ss, ss);
}

static void kyber_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    polyvec b, s;
    poly v, mp;
    polyvec_decompress(&b, ct);
    poly_decompress(&v, ct + KYBER_POLYVECCOMPRESSEDBYTES);
    polyvec_frombytes(&s, sk);

    polyvec_ntt(&b);
    polyvec_pointwise_acc_montgomery(&mp, &s, &b);
    polyvec_invntt(&mp);
    poly_sub(&mp, &v, &mp);
    poly_reduce(&mp);
    poly_csubq(&mp);

    uint8_t m[KYBER_SYMBYTES] = {0};
    for (int i = 0; i < KYBER_N; i++) {
        int32_t t = mp.coeffs[i];
        t = (t + (KYBER_Q >> 1)) / KYBER_Q;
        m[i / 8] |= (t & 1) << (i % 8);
    }

    Blake3 b_ss;
    blake3_init(&b_ss);
    blake3_update(&b_ss, m, KYBER_SYMBYTES);
    blake3_final(&b_ss, ss);
}

// ML-DSA (Dilithium-65) Implementation
typedef struct {
    poly s1[DILITHIUM_L];
    poly s2[DILITHIUM_K];
    poly t1[DILITHIUM_K];
    uint8_t rho[32];
    uint8_t tr[32];
} Dilithium;

static int32_t dilithium_montgomery_reduce(int64_t a) {
    int32_t t = (int32_t)(a * -4236238847LL);
    t = (a - (int64_t)t * DILITHIUM_Q) >> 32;
    return t;
}

static int32_t dilithium_csubq(int32_t a) {
    a -= DILITHIUM_Q;
    a += (a >> 31) & DILITHIUM_Q;
    return a;
}

static void dilithium_poly_reduce(poly *r) {
    for (int i = 0; i < KYBER_N; i++) r->coeffs[i] = dilithium_csubq(r->coeffs[i]);
}

static void dilithium_poly_add(poly *r, const poly *a, const poly *b) {
    for (int i = 0; i < KYBER_N; i++) r->coeffs[i] = dilithium_csubq(a->coeffs[i] + b->coeffs[i]);
}

static void dilithium_poly_sub(poly *r, const poly *a, const poly *b) {
    for (int i = 0; i < KYBER_N; i++) r->coeffs[i] = dilithium_csubq(a->coeffs[i] - b->coeffs[i]);
}

static void dilithium_poly_pointwise_montgomery(poly *r, const poly *a, const poly *b) {
    for (int i = 0; i < KYBER_N; i++) r->coeffs[i] = dilithium_montgomery_reduce((int64_t)a->coeffs[i] * b->coeffs[i]);
}

static void dilithium_polyvec_ntt(polyvec *r, int l) {
    for (int i = 0; i < l; i++) {
        unsigned int len = 128, k = 1;
        for (len = 128; len >= 2; len >>= 1) {
            for (unsigned int start = 0; start < KYBER_N; start += 2 * len) {
                int32_t zeta = zetas[k++];
                for (unsigned int j = start; j < start + len; j++) {
                    int32_t t = dilithium_montgomery_reduce((int64_t)zeta * r->vec[i].coeffs[j + len]);
                    r->vec[i].coeffs[j + len] = dilithium_csubq(r->vec[i].coeffs[j] - t);
                    r->vec[i].coeffs[j] = dilithium_csubq(r->vec[i].coeffs[j] + t);
                }
            }
        }
    }
}

static void dilithium_polyvec_invntt(polyvec *r, int l) {
    for (int i = 0; i < l; i++) {
        unsigned int len = 2, k = 127;
        for (len = 2; len <= 128; len <<= 1) {
            for (unsigned int start = 0; start < KYBER_N; start += 2 * len) {
                int32_t zeta = -zetas[k--];
                for (unsigned int j = start; j < start + len; j++) {
                    int32_t t = r->vec[i].coeffs[j];
                    r->vec[i].coeffs[j] = dilithium_csubq(t + r->vec[i].coeffs[j + len]);
                    r->vec[i].coeffs[j + len] = dilithium_montgomery_reduce((int64_t)zeta * (r->vec[i].coeffs[j + len] - t));
                }
            }
        }
        for (unsigned int j = 0; j < KYBER_N; j++) {
            r->vec[i].coeffs[j] = dilithium_montgomery_reduce((int64_t)r->vec[i].coeffs[j] * 8347681);
        }
    }
}

static void dilithium_polyvec_pointwise_acc_montgomery(poly *r, const polyvec *a, const polyvec *b, int l, int k) {
    poly_pointwise_montgomery(r, &a->vec[0], &b->vec[0]);
    for (int i = 1; i < k; i++) {
        poly tmp;
        poly_pointwise_montgomery(&tmp, &a->vec[i], &b->vec[i]);
        dilithium_poly_add(r, r, &tmp);
    }
}

static void dilithium_poly_getnoise_eta(poly *r, const uint8_t *seed, uint8_t nonce) {
    uint8_t buf[KYBER_SYMBYTES * 2];
    Blake3 b;
    blake3_init(&b);
    blake3_update(&b, seed, KYBER_SYMBYTES);
    blake3_update(&b, &nonce, 1);
    blake3_final(&b, buf);
    for (int i = 0; i < KYBER_N; i++) {
        uint32_t t = buf[i/4] >> (2 * (i % 4));
        r->coeffs[i] = ((t & 1) - ((t >> 1) & 1)) * DILITHIUM_ETA;
    }
}

static void dilithium_poly_getnoise_gamma1(poly *r, const uint8_t *seed, uint8_t nonce) {
    uint8_t buf[KYBER_SYMBYTES * 4];
    Blake3 b;
    blake3_init(&b);
    blake3_update(&b, seed, KYBER_SYMBYTES);
    blake3_update(&b, &nonce, 1);
    blake3_final(&b, buf);
    for (int i = 0; i < KYBER_N; i++) {
        uint32_t t = *(uint32_t*)(buf + i/2*4);
        t = (t >> (16 * (i % 2))) & 0xffff;
        r->coeffs[i] = t - DILITHIUM_GAMMA1;
    }
}

static int dilithium_poly_chknorm(const poly *a, int32_t B) {
    for (int i = 0; i < KYBER_N; i++) {
        if (abs(a->coeffs[i]) > B) return 1;
    }
    return 0;
}

static int dilithium_polyvec_chknorm(const polyvec *a, int32_t B, int l) {
    for (int i = 0; i < l; i++) {
        if (dilithium_poly_chknorm(&a->vec[i], B)) return 1;
    }
    return 0;
}

static void dilithium_polyvec_tobytes(uint8_t *r, const polyvec *a, int l) {
    for (int i = 0; i < l; i++) {
        for (int j = 0; j < KYBER_N / 2; j++) {
            int32_t t0 = dilithium_csubq(a->vec[i].coeffs[2*j]);
            int32_t t1 = dilithium_csubq(a->vec[i].coeffs[2*j+1]);
            r[3*(i*KYBER_N/2+j)] = t0 & 0xff;
            r[3*(i*KYBER_N/2+j)+1] = (t0 >> 8) | ((t1 & 0xf) << 4);
            r[3*(i*KYBER_N/2+j)+2] = (t1 >> 4) & 0xff;
        }
    }
}

static void dilithium_polyvec_frombytes(polyvec *r, const uint8_t *a, int l) {
    for (int i = 0; i < l; i++) {
        for (int j = 0; j < KYBER_N / 2; j++) {
            r->vec[i].coeffs[2*j] = a[3*(i*KYBER_N/2+j)] | ((uint32_t)(a[3*(i*KYBER_N/2+j)+1] & 0x0f) << 8);
            r->vec[i].coeffs[2*j+1] = (a[3*(i*KYBER_N/2+j)+1] >> 4) | ((uint32_t)a[3*(i*KYBER_N/2+j)+2] << 4);
            r->vec[i].coeffs[2*j] = dilithium_csubq(r->vec[i].coeffs[2*j]);
            r->vec[i].coeffs[2*j+1] = dilithium_csubq(r->vec[i].coeffs[2*j+1]);
        }
    }
}

static void dilithium_keygen(Dilithium *self, uint8_t *pk, uint8_t *sk) {
    uint8_t seed[48];
    get_random_bytes(seed, 48);
    uint8_t buf[96];
    Blake3 b;
    blake3_init(&b);
    blake3_update(&b, seed, 48);
    blake3_final(&b, buf);
    memcpy(self->rho, buf, 32);
    memcpy(self->tr, buf + 32, 32);

    polyvec a[DILITHIUM_K], s1, s2, t1;
    for (int i = 0; i < DILITHIUM_K; i++) for (int j = 0; j < DILITHIUM_L; j++) {
        uint8_t seed_a[KYBER_SYMBYTES + 2];
        memcpy(seed_a, self->rho, KYBER_SYMBYTES);
        seed_a[KYBER_SYMBYTES] = i;
        seed_a[KYBER_SYMBYTES + 1] = j;
        Blake3 b_a;
        blake3_init(&b_a);
        blake3_update(&b_a, seed_a, KYBER_SYMBYTES + 2);
        uint8_t buf_a[KYBER_N * 4];
        blake3_final(&b_a, buf_a);
        for (int k = 0; k < KYBER_N; k++) {
            a[i].vec[j].coeffs[k] = (buf_a[2*k] | ((uint32_t)buf_a[2*k+1] << 8)) % DILITHIUM_Q;
        }
    }

    for (int i = 0; i < DILITHIUM_L; i++) {
        dilithium_poly_getnoise_eta(&s1.vec[i], buf + 64, i);
    }
    for (int i = 0; i < DILITHIUM_K; i++) {
        dilithium_poly_getnoise_eta(&s2.vec[i], buf + 64, DILITHIUM_L + i);
    }

    dilithium_polyvec_ntt(&s1, DILITHIUM_L);
    dilithium_polyvec_ntt(&s2, DILITHIUM_K);
    for (int i = 0; i < DILITHIUM_K; i++) {
        dilithium_polyvec_pointwise_acc_montgomery(&t1.vec[i], &a[i], &s1, DILITHIUM_K, DILITHIUM_L);
    }
    polyvec_add(&t1, &t1, &s2);
    polyvec_reduce(&t1);

    memcpy(self->s1, s1.vec, sizeof(s1));
    memcpy(self->s2, s2.vec, sizeof(s2));
    memcpy(self->t1, t1.vec, sizeof(t1));
    dilithium_polyvec_tobytes(pk, &t1, DILITHIUM_K);
    memcpy(pk + DILITHIUM_K * KYBER_POLYBYTES, self->rho, 32);
    dilithium_polyvec_tobytes(sk, &t1, DILITHIUM_K);
    memcpy(sk + DILITHIUM_K * KYBER_POLYBYTES, self->rho, 32);
    dilithium_polyvec_tobytes(sk + DILITHIUM_K * KYBER_POLYBYTES + 32, &s1, DILITHIUM_L);
    dilithium_polyvec_tobytes(sk + DILITHIUM_K * KYBER_POLYBYTES + 32 + DILITHIUM_L * KYBER_POLYBYTES, &s2, DILITHIUM_K);
    memcpy(sk + DILITHIUM_K * KYBER_POLYBYTES + 32 + (DILITHIUM_L + DILITHIUM_K) * KYBER_POLYBYTES, self->tr, 32);
}

static void dilithium_sign(Dilithium *self, uint8_t *sig, const uint8_t *msg, size_t msg_len, const uint8_t *sk) {
    polyvec a[DILITHIUM_K], s1, s2, y, z;
    poly c;
    uint8_t rho[32], tr[32];
    memcpy(rho, sk + DILITHIUM_K * KYBER_POLYBYTES, 32);
    dilithium_polyvec_frombytes(&s1, sk + DILITHIUM_K * KYBER_POLYBYTES + 32, DILITHIUM_L);
    dilithium_polyvec_frombytes(&s2, sk + DILITHIUM_K * KYBER_POLYBYTES + 32 + DILITHIUM_L * KYBER_POLYBYTES, DILITHIUM_K);
    memcpy(tr, sk + DILITHIUM_K * KYBER_POLYBYTES + 32 + (DILITHIUM_L + DILITHIUM_K) * KYBER_POLYBYTES, 32);

    for (int i = 0; i < DILITHIUM_K; i++) for (int j = 0; j < DILITHIUM_L; j++) {
        uint8_t seed_a[KYBER_SYMBYTES + 2];
        memcpy(seed_a, rho, KYBER_SYMBYTES);
        seed_a[KYBER_SYMBYTES] = i;
        seed_a[KYBER_SYMBYTES + 1] = j;
        Blake3 b_a;
        blake3_init(&b_a);
        blake3_update(&b_a, seed_a, KYBER_SYMBYTES + 2);
        uint8_t buf_a[KYBER_N * 4];
        blake3_final(&b_a, buf_a);
        for (int k = 0; k < KYBER_N; k++) {
            a[i].vec[j].coeffs[k] = (buf_a[2*k] | ((uint32_t)buf_a[2*k+1] << 8)) % DILITHIUM_Q;
        }
    }

    uint8_t mu[64];
    Blake3 b_mu;
    blake3_init(&b_mu);
    blake3_update(&b_mu, tr, 32);
    blake3_update(&b_mu, msg, msg_len);
    blake3_final(&b_mu, mu);

    uint8_t seedbuf[KYBER_SYMBYTES];
    get_random_bytes(seedbuf, KYBER_SYMBYTES);
    int nonce = 0;

    while (1) {
        for (int i = 0; i < DILITHIUM_L; i++) {
            dilithium_poly_getnoise_gamma1(&y.vec[i], seedbuf, nonce++);
        }
        dilithium_polyvec_ntt(&y, DILITHIUM_L);
        polyvec w1, w0;
        for (int i = 0; i < DILITHIUM_K; i++) {
            dilithium_polyvec_pointwise_acc_montgomery(&w1.vec[i], &a[i], &y, DILITHIUM_K, DILITHIUM_L);
        }
        dilithium_polyvec_invntt(&w1, DILITHIUM_K);
        for (int i = 0; i < DILITHIUM_K; i++) {
            for (int j = 0; j < KYBER_N; j++) {
                w0.vec[i].coeffs[j] = w1.vec[i].coeffs[j];
                w1.vec[i].coeffs[j] = (w1.vec[i].coeffs[j] + DILITHIUM_GAMMA2) / (2 * DILITHIUM_GAMMA2);
                w0.vec[i].coeffs[j] -= 2 * DILITHIUM_GAMMA2 * w1.vec[i].coeffs[j];
            }
        }

        Blake3 b_c;
        blake3_init(&b_c);
        blake3_update(&b_c, mu, 64);
        blake3_update(&b_c, (uint8_t*)&w1, DILITHIUM_K * KYBER_POLYBYTES);
        blake3_final(&b_c, (uint8_t*)&c);

        memcpy(&z, &y, sizeof(y));
        dilithium_polyvec_ntt(&z, DILITHIUM_L);
        for (int i = 0; i < DILITHIUM_L; i++) {
            poly cs1;
            poly_pointwise_montgomery(&cs1, &c, &s1.vec[i]);
            dilithium_poly_add(&z.vec[i], &z.vec[i], &cs1);
        }
        dilithium_polyvec_invntt(&z, DILITHIUM_L);

        if (dilithium_polyvec_chknorm(&z, DILITHIUM_GAMMA1 - DILITHIUM_BETA, DILITHIUM_L)) continue;

        polyvec h;
        for (int i = 0; i < DILITHIUM_K; i++) {
            poly cs2;
            poly_pointwise_montgomery(&cs2, &c, &s2.vec[i]);
            dilithium_poly_sub(&h.vec[i], &w0.vec[i], &cs2);
            if (dilithium_poly_chknorm(&h.vec[i], DILITHIUM_GAMMA2 - DILITHIUM_BETA)) continue;
        }

        dilithium_polyvec_tobytes(sig, &z, DILITHIUM_L);
        memcpy(sig + DILITHIUM_L * KYBER_POLYBYTES, (uint8_t*)&c, KYBER_POLYBYTES);
        dilithium_polyvec_tobytes(sig + DILITHIUM_L * KYBER_POLYBYTES + KYBER_POLYBYTES, &w1, DILITHIUM_K);
        break; // Signature found
    }
}

static int dilithium_verify(Dilithium *self, const uint8_t *sig, const uint8_t *msg, size_t msg_len, const uint8_t *pk) {
    polyvec a[DILITHIUM_K], t1, z, w1;
    poly c;
    uint8_t rho[32], tr[32];
    memcpy(rho, pk + DILITHIUM_K * KYBER_POLYBYTES, 32);
    dilithium_polyvec_frombytes(&t1, pk, DILITHIUM_K);

    for (int i = 0; i < DILITHIUM_K; i++) for (int j = 0; j < DILITHIUM_L; j++) {
        uint8_t seed_a[KYBER_SYMBYTES + 2];
        memcpy(seed_a, rho, KYBER_SYMBYTES);
        seed_a[KYBER_SYMBYTES] = i;
        seed_a[KYBER_SYMBYTES + 1] = j;
        Blake3 b_a;
        blake3_init(&b_a);
        blake3_update(&b_a, seed_a, KYBER_SYMBYTES + 2);
        uint8_t buf_a[KYBER_N * 4];
        blake3_final(&b_a, buf_a);
        for (int k = 0; k < KYBER_N; k++) {
            a[i].vec[j].coeffs[k] = (buf_a[2*k] | ((uint32_t)buf_a[2*k+1] << 8)) % DILITHIUM_Q;
        }
    }

    Blake3 b_tr;
    blake3_init(&b_tr);
    blake3_update(&b_tr, pk, DILITHIUM_PUBKEYBYTES);
    blake3_final(&b_tr, tr);

    uint8_t mu[64];
    Blake3 b_mu;
    blake3_init(&b_mu);
    blake3_update(&b_mu, tr, 32);
    blake3_update(&b_mu, msg, msg_len);
    blake3_final(&b_mu, mu);

    dilithium_polyvec_frombytes(&z, sig, DILITHIUM_L);
    memcpy(&c, sig + DILITHIUM_L * KYBER_POLYBYTES, KYBER_POLYBYTES);
    dilithium_polyvec_frombytes(&w1, sig + DILITHIUM_L * KYBER_POLYBYTES + KYBER_POLYBYTES, DILITHIUM_K);

    if (dilithium_polyvec_chknorm(&z, DILITHIUM_GAMMA1 - DILITHIUM_BETA, DILITHIUM_L)) return 0;

    poly w;
    for (int i = 0; i < DILITHIUM_K; i++) {
        dilithium_polyvec_pointwise_acc_montgomery(&w, &a[i], &z, DILITHIUM_K, DILITHIUM_L);
        poly ct1;
        poly_pointwise_montgomery(&ct1, &c, &t1.vec[i]);
        dilithium_poly_sub(&w, &w, &ct1);
        for (int j = 0; j < KYBER_N; j++) {
            int32_t t = w.coeffs[j];
            w.coeffs[j] = (t + DILITHIUM_GAMMA2) / (2 * DILITHIUM_GAMMA2);
        }
        if (memcmp(&w1.vec[i], &w, sizeof(poly))) return 0;
    }

    uint8_t c2[KYBER_POLYBYTES];
    Blake3 b_c2;
    blake3_init(&b_c2);
    blake3_update(&b_c2, mu, 64);
    blake3_update(&b_c2, (uint8_t*)&w1, DILITHIUM_K * KYBER_POLYBYTES);
    blake3_final(&b_c2, c2);

    return memcmp(&c, c2, KYBER_POLYBYTES) == 0;
}

// Zero-Knowledge Proof (Fiat-Shamir)
typedef struct {
    uint8_t commitment[32];
    uint8_t challenge[32];
    uint8_t response[32];
} ZKP;

static void zkp_prove(ZKP *zkp, const uint8_t *secret, const uint8_t *public_data, size_t public_len) {
    Blake3 b;
    blake3_init(&b);
    blake3_update(&b, secret, 32);
    blake3_final(&b, zkp->commitment);

    blake3_init(&b);
    blake3_update(&b, zkp->commitment, 32);
    blake3_update(&b, public_data, public_len);
    blake3_final(&b, zkp->challenge);

    blake3_init(&b);
    blake3_update(&b, secret, 32);
    blake3_update(&b, zkp->challenge, 32);
    blake3_final(&b, zkp->response);
}

static int zkp_verify(const ZKP *zkp, const uint8_t *public_data, size_t public_len) {
    uint8_t challenge[32];
    Blake3 b;
    blake3_init(&b);
    blake3_update(&b, zkp->commitment, 32);
    blake3_update(&b, public_data, public_len);
    blake3_final(&b, challenge);

    if (memcmp(challenge, zkp->challenge, 32) != 0) return 0;

    uint8_t recommit[32];
    blake3_init(&b);
    blake3_update(&b, zkp->response, 32);
    blake3_update(&b, zkp->challenge, 32);
    blake3_final(&b, recommit);

    return memcmp(recommit, zkp->commitment, 32) == 0;
}

// Steganography for HTTPS Disguise
static void stego_encode(uint8_t *packet, size_t *len, const uint8_t *data, size_t data_len) {
    if (*len < data_len + 64) return; // Ensure enough space
    uint8_t header[] = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    size_t header_len = strlen((char*)header);
    memcpy(packet, header, header_len);
    memcpy(packet + header_len, data, data_len);
    *len = header_len + data_len;
}

static int stego_decode(uint8_t *data, size_t *data_len, const uint8_t *packet, size_t packet_len) {
    const char *header = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    size_t header_len = strlen(header);
    if (packet_len < header_len) return 0;
    if (memcmp(packet, header, header_len) != 0) return 0;
    *data_len = packet_len - header_len;
    memcpy(data, packet + header_len, *data_len);
    return 1;
}

// TUN Device Setup
static int tun_alloc(char *dev) {
    struct ifreq ifr;
    int fd, err;
    if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
        perror("Opening /dev/net/tun");
        return fd;
    }
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    if (*dev) strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
        perror("ioctl(TUNSETIFF)");
        close(fd);
        return err;
    }
    /* Use strncpy instead of strcpy for security */
    strncpy(dev, ifr.ifr_name, IFNAMSIZ - 1);
    dev[IFNAMSIZ - 1] = '\0'; /* Ensure null termination */
    return fd;
}

// Multi-Hop Routing
typedef struct {
    char ip[16];
    int port;
    uint8_t pubkey[KYBER_PUBLICKEYBYTES];
} Hop;

typedef struct {
    Hop hops[MAX_HOPS];
    int num_hops;
} Route;

static void init_route(Route *route, const char *ip, int port, const uint8_t *pubkey) {
    route->num_hops = 1;
    strncpy(route->hops[0].ip, ip, 15);
    route->hops[0].ip[15] = '\0';
    route->hops[0].port = port;
    memcpy(route->hops[0].pubkey, pubkey, KYBER_PUBLICKEYBYTES);
}

// DNS over HTTPS (Simplified)
static int resolve_dns(const char *domain, char *ip, size_t ip_len) {
    // Placeholder for DoH: returns a hardcoded IP for simplicity
    strncpy(ip, "192.168.1.1", ip_len);
    return 0;
}

// Safe command execution using fork/exec (no shell)
static int safe_exec(const char *prog, char *const argv[]) {
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return -1;
    }

    if (pid == 0) {
        /* Child process */
        execvp(prog, argv);
        perror("execvp");
        _exit(1);
    }

    /* Parent process */
    int status;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

// Kill-Switch - using safe exec instead of system()
static void enable_kill_switch() {
    char *flush_argv[] = {"iptables", "-F", NULL};
    safe_exec("iptables", flush_argv);

    char *allow_local[] = {"iptables", "-A", "OUTPUT", "-p", "all", "-d", "127.0.0.1", "-j", "ACCEPT", NULL};
    safe_exec("iptables", allow_local);

    char *drop_all[] = {"iptables", "-A", "OUTPUT", "-p", "all", "-j", "DROP", NULL};
    safe_exec("iptables", drop_all);
}

static void disable_kill_switch() {
    char *flush_argv[] = {"iptables", "-F", NULL};
    safe_exec("iptables", flush_argv);
}

// Generate unique nonce from packet counter (24 bytes for XSalsa20)
static void generate_nonce(uint8_t nonce[24], uint64_t counter) {
    memset(nonce, 0, 24);
    /* Place counter in little-endian format at bytes 16-23 */
    for (int i = 0; i < 8; i++) {
        nonce[16 + i] = (counter >> (i * 8)) & 0xFF;
    }
}

// VPN Session
typedef struct {
    int tun_fd;
    int sock_fd;
    uint8_t kyber_sk[KYBER_SECRETKEYBYTES];
    uint8_t kyber_pk[KYBER_PUBLICKEYBYTES];
    uint8_t dilithium_sk[DILITHIUM_SECKEYBYTES];
    uint8_t dilithium_pk[DILITHIUM_PUBKEYBYTES];
    uint8_t shared_secret[32];
    Route route;
    int active;
    time_t last_active;
    uint64_t tx_counter;  /* Packet counter for sending (nonce generation) */
    uint64_t rx_counter;  /* Packet counter for receiving (nonce generation) */
} Session;

static void session_init(Session *session, int tun_fd, int sock_fd, const char *server_ip, int port) {
    session->tun_fd = tun_fd;
    session->sock_fd = sock_fd;
    session->active = 0;
    session->last_active = time(NULL);
    session->tx_counter = 0;  /* Initialize TX packet counter */
    session->rx_counter = 0;  /* Initialize RX packet counter */
    kyber_keygen(session->kyber_pk, session->kyber_sk);
    Dilithium dil;
    dilithium_keygen(&dil, session->dilithium_pk, session->dilithium_sk);
    init_route(&session->route, server_ip, port, session->kyber_pk);
}

// Thread Worker for Packet Processing
typedef struct {
    Session *session;
    int thread_id;
} Worker;

static void *worker_thread(void *arg) {
    Worker *worker = (Worker *)arg;
    Session *session = worker->session;
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(worker->thread_id % NUM_THREADS, &cpuset);
    sched_setaffinity(0, sizeof(cpu_set_t), &cpuset);

    uint8_t buffer[BUFSIZE], packet[BUFSIZE];
    XSalsa20 xsalsa;
    Poly1305 poly;
    while (session->active) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(session->tun_fd, &fds);
        FD_SET(session->sock_fd, &fds);
        int max_fd = session->tun_fd > session->sock_fd ? session->tun_fd : session->sock_fd;
        struct timeval timeout = {1, 0};
        int ret = select(max_fd + 1, &fds, NULL, NULL, &timeout);
        if (ret < 0) break;

        if (FD_ISSET(session->tun_fd, &fds)) {
            ssize_t len = read(session->tun_fd, buffer, BUFSIZE - TAG_LEN - 64);
            if (len <= 0) continue;
            /* Generate unique nonce from TX counter */
            uint8_t nonce[24];
            generate_nonce(nonce, session->tx_counter++);
            xsalsa20_init(&xsalsa, session->shared_secret, nonce);
            xsalsa20_encrypt_simd(&xsalsa, buffer, packet, len);
            uint8_t tag[TAG_LEN];
            poly1305_init(&poly, session->shared_secret);
            poly1305_update(&poly, packet, len);
            poly1305_final(&poly, tag);
            memcpy(packet + len, tag, TAG_LEN);
            size_t packet_len = len + TAG_LEN;
            stego_encode(packet, &packet_len, packet, len + TAG_LEN);
            struct sockaddr_in server;
            memset(&server, 0, sizeof(server));
            server.sin_family = AF_INET;
            server.sin_port = htons(session->route.hops[0].port);
            inet_pton(AF_INET, session->route.hops[0].ip, &server.sin_addr);
            sendto(session->sock_fd, packet, packet_len, 0, (struct sockaddr*)&server, sizeof(server));
        }

        if (FD_ISSET(session->sock_fd, &fds)) {
            struct sockaddr_in client;
            socklen_t client_len = sizeof(client);
            ssize_t len = recvfrom(session->sock_fd, packet, BUFSIZE, 0, (struct sockaddr*)&client, &client_len);
            if (len <= TAG_LEN + 64) continue;
            size_t data_len;
            if (!stego_decode(buffer, &data_len, packet, len)) continue;
            if (data_len <= TAG_LEN) continue;
            uint8_t tag[TAG_LEN], computed_tag[TAG_LEN];
            memcpy(tag, buffer + data_len - TAG_LEN, TAG_LEN);
            poly1305_init(&poly, session->shared_secret);
            poly1305_update(&poly, buffer, data_len - TAG_LEN);
            poly1305_final(&poly, computed_tag);
            if (memcmp(tag, computed_tag, TAG_LEN) != 0) continue;
            /* Generate unique nonce from RX counter */
            uint8_t rx_nonce[24];
            generate_nonce(rx_nonce, session->rx_counter++);
            xsalsa20_init(&xsalsa, session->shared_secret, rx_nonce);
            xsalsa20_encrypt_simd(&xsalsa, buffer, packet, data_len - TAG_LEN);
            write(session->tun_fd, packet, data_len - TAG_LEN);
        }
        session->last_active = time(NULL);
    }
    return NULL;
}

// Main VPN Logic
static int vpn_client(const char *server_ip, int port) {
    int tun_fd = tun_alloc(TUN_NAME);
    if (tun_fd < 0) return 1;
    int sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_fd < 0) { perror("Socket creation failed"); close(tun_fd); return 1; }

    enable_kill_switch();

    Session session;
    session_init(&session, tun_fd, sock_fd, server_ip, port);
    session.active = 1;

    // Key Exchange with 0-RTT
    uint8_t ct[KYBER_CIPHERTEXTBYTES], ss[32];
    kyber_enc(ct, ss, session.route.hops[0].pubkey);
    memcpy(session.shared_secret, ss, 32);

    ZKP zkp;
    zkp_prove(&zkp, session.shared_secret, session.kyber_pk, KYBER_PUBLICKEYBYTES);
    uint8_t auth_packet[KYBER_CIPHERTEXTBYTES + sizeof(ZKP) + DILITHIUM_SIGBYTES];
    memcpy(auth_packet, ct, KYBER_CIPHERTEXTBYTES);
    memcpy(auth_packet + KYBER_CIPHERTEXTBYTES, &zkp, sizeof(ZKP));
    Dilithium dil;
    dilithium_sign(&dil, auth_packet + KYBER_CIPHERTEXTBYTES + sizeof(ZKP), auth_packet, KYBER_CIPHERTEXTBYTES + sizeof(ZKP), session.dilithium_sk);

    struct sockaddr_in server;
    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    inet_pton(AF_INET, server_ip, &server.sin_addr);
    sendto(sock_fd, auth_packet, sizeof(auth_packet), 0, (struct sockaddr*)&server, sizeof(server));

    // Start worker threads
    pthread_t threads[NUM_THREADS];
    Worker workers[NUM_THREADS];
    for (int i = 0; i < NUM_THREADS; i++) {
        workers[i].session = &session;
        workers[i].thread_id = i;
        pthread_create(&threads[i], NULL, worker_thread, &workers[i]);
    }

    // Monitor session
    while (session.active) {
        if (time(NULL) - session.last_active > SESSION_TIMEOUT) {
            session.active = 0;
            break;
        }
        usleep(100000);
    }

    // Cleanup
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }
    disable_kill_switch();
    close(tun_fd);
    close(sock_fd);
    return 0;
}

static int vpn_server(const char *listen_ip, int port) {
    int sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_fd < 0) { perror("Socket creation failed"); return 1; }
    struct sockaddr_in server;
    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    inet_pton(AF_INET, listen_ip, &server.sin_addr);
    if (bind(sock_fd, (struct sockaddr*)&server, sizeof(server)) < 0) {
        perror("Bind failed"); close(sock_fd); return 1;
    }

    int tun_fd = tun_alloc(TUN_NAME);
    if (tun_fd < 0) { close(sock_fd); return 1; }

    Session session;
    session_init(&session, tun_fd, sock_fd, listen_ip, port);
    session.active = 1;

    // Receive initial auth packet
    uint8_t auth_packet[KYBER_CIPHERTEXTBYTES + sizeof(ZKP) + DILITHIUM_SIGBYTES];
    struct sockaddr_in client;
    socklen_t client_len = sizeof(client);
    ssize_t len = recvfrom(sock_fd, auth_packet, sizeof(auth_packet), 0, (struct sockaddr*)&client, &client_len);

    /* DDoS Protection: Get client IP and check rate limit */
    char client_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client.sin_addr, client_ip_str, INET_ADDRSTRLEN);
    uint32_t client_ip = ntohl(client.sin_addr.s_addr);

    if (!rate_limit_check(client_ip, client_ip_str)) {
        fprintf(stderr, "Rate limit exceeded for IP: %s\n", client_ip_str);
        close(sock_fd); close(tun_fd);
        return 1;
    }

    if (len != sizeof(auth_packet)) {
        record_auth_failure(client_ip, client_ip_str, "Invalid packet size");
        close(sock_fd); close(tun_fd);
        return 1;
    }

    uint8_t ss[32];
    kyber_dec(ss, auth_packet, session.kyber_sk);
    memcpy(session.shared_secret, ss, 32);

    ZKP zkp;
    memcpy(&zkp, auth_packet + KYBER_CIPHERTEXTBYTES, sizeof(ZKP));
    if (!zkp_verify(&zkp, session.kyber_pk, KYBER_PUBLICKEYBYTES)) {
        record_auth_failure(client_ip, client_ip_str, "ZKP verification failed");
        close(sock_fd); close(tun_fd);
        return 1;
    }

    Dilithium dil;
    if (!dilithium_verify(&dil, auth_packet + KYBER_CIPHERTEXTBYTES + sizeof(ZKP),
                         auth_packet, KYBER_CIPHERTEXTBYTES + sizeof(ZKP), session.dilithium_pk)) {
        record_auth_failure(client_ip, client_ip_str, "Dilithium signature verification failed");
        close(sock_fd); close(tun_fd);
        return 1;
    }

    /* Successful authentication */
    fail2ban_log("AUTH_SUCCESS", client_ip_str, "Client authenticated successfully");

    // Start worker threads
    pthread_t threads[NUM_THREADS];
    Worker workers[NUM_THREADS];
    for (int i = 0; i < NUM_THREADS; i++) {
        workers[i].session = &session;
        workers[i].thread_id = i;
        pthread_create(&threads[i], NULL, worker_thread, &workers[i]);
    }

    // Monitor session
    while (session.active) {
        if (time(NULL) - session.last_active > SESSION_TIMEOUT) {
            session.active = 0;
            break;
        }
        usleep(100000);
    }

    // Cleanup
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }
    close(tun_fd);
    close(sock_fd);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Usage: %s <client|server> <ip> [port]\n", argv[0]);
        return 1;
    }
    int port = (argc > 3) ? atoi(argv[3]) : PORT;
    if (strcmp(argv[1], "client") == 0) {
        return vpn_client(argv[2], port);
    } else if (strcmp(argv[1], "server") == 0) {
        return vpn_server(argv[2], port);
    } else {
        printf("Invalid mode. Use 'client' or 'server'.\n");
        return 1;
    }
}
          
