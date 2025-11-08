/*
 * SecureSwift VPN - Advanced Cryptography Module
 * Next-Generation Crypto Features:
 * - Perfect Forward Secrecy (PFS)
 * - HKDF Key Derivation
 * - Automatic Key Rotation
 * - Multi-Key Support
 * - Hardware Acceleration
 * - Quantum-Resistant Hybrid Encryption
 */

#ifndef ADVANCED_CRYPTO_H
#define ADVANCED_CRYPTO_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include "secureswift_security.h"

/* ============================================================================
 * HKDF (HMAC-based Key Derivation Function) - RFC 5869
 * ============================================================================ */

#define HKDF_HASH_SIZE 32  // SHA-256
#define HKDF_MAX_OUTPUT 8160  // 255 * HASH_SIZE

/**
 * HKDF Extract: Extract a pseudorandom key from input key material
 *
 * @param prk Pseudorandom key output (HKDF_HASH_SIZE bytes)
 * @param salt Optional salt value (can be NULL)
 * @param salt_len Length of salt
 * @param ikm Input key material
 * @param ikm_len Length of input key material
 * @return 0 on success, -1 on error
 */
int hkdf_extract(uint8_t *prk, const uint8_t *salt, size_t salt_len,
                 const uint8_t *ikm, size_t ikm_len);

/**
 * HKDF Expand: Expand a pseudorandom key to desired length
 *
 * @param okm Output key material
 * @param okm_len Desired length of output key material
 * @param prk Pseudorandom key from extract phase
 * @param info Optional context and application specific info
 * @param info_len Length of info
 * @return 0 on success, -1 on error
 */
int hkdf_expand(uint8_t *okm, size_t okm_len, const uint8_t *prk,
                const uint8_t *info, size_t info_len);

/**
 * HKDF: Complete key derivation (extract + expand)
 *
 * @param okm Output key material
 * @param okm_len Desired length of output
 * @param salt Optional salt
 * @param salt_len Length of salt
 * @param ikm Input key material
 * @param ikm_len Length of input
 * @param info Optional info
 * @param info_len Length of info
 * @return 0 on success, -1 on error
 */
int hkdf(uint8_t *okm, size_t okm_len,
         const uint8_t *salt, size_t salt_len,
         const uint8_t *ikm, size_t ikm_len,
         const uint8_t *info, size_t info_len);

/* ============================================================================
 * PERFECT FORWARD SECRECY (PFS)
 * ============================================================================ */

#define PFS_ECDH_KEYSIZE 32  // X25519
#define PFS_SESSION_KEY_SIZE 64  // Derived session key

/**
 * PFS Key Pair for Ephemeral Diffie-Hellman
 */
typedef struct {
    uint8_t private_key[PFS_ECDH_KEYSIZE];
    uint8_t public_key[PFS_ECDH_KEYSIZE];
    uint64_t generation_time;
    uint64_t expiry_time;
    uint8_t valid;
} PFS_KeyPair;

/**
 * PFS Session with rotating ephemeral keys
 */
typedef struct {
    PFS_KeyPair current_keypair;
    PFS_KeyPair next_keypair;  // Pre-generated for seamless rotation
    uint8_t shared_secret[PFS_SESSION_KEY_SIZE];
    uint64_t last_rotation;
    uint32_t rotation_interval;  // Seconds between rotations
    pthread_mutex_t mutex;
} PFS_Session;

/**
 * Initialize PFS session with automatic key rotation
 *
 * @param session PFS session structure
 * @param rotation_interval Seconds between key rotations (e.g., 3600 for 1 hour)
 * @return 0 on success, -1 on error
 */
int pfs_init(PFS_Session *session, uint32_t rotation_interval);

/**
 * Generate ephemeral X25519 key pair for PFS
 *
 * @param keypair Output key pair
 * @return 0 on success, -1 on error
 */
int pfs_generate_keypair(PFS_KeyPair *keypair);

/**
 * Compute shared secret using X25519 ECDH
 *
 * @param shared_secret Output shared secret
 * @param our_private Our private key
 * @param their_public Their public key
 * @return 0 on success, -1 on error
 */
int pfs_compute_shared_secret(uint8_t *shared_secret,
                               const uint8_t *our_private,
                               const uint8_t *their_public);

/**
 * Check if keys need rotation and rotate if necessary
 *
 * @param session PFS session
 * @return 1 if rotated, 0 if not needed, -1 on error
 */
int pfs_check_and_rotate(PFS_Session *session);

/**
 * Destroy PFS session and securely wipe all keys
 *
 * @param session PFS session to destroy
 */
void pfs_destroy(PFS_Session *session);

/* ============================================================================
 * KEY ROTATION MANAGER
 * ============================================================================ */

#define MAX_KEY_SLOTS 16
#define KEY_MATERIAL_SIZE 64

/**
 * Key Slot with metadata
 */
typedef struct {
    uint8_t key_material[KEY_MATERIAL_SIZE];
    uint64_t created_at;
    uint64_t expires_at;
    uint64_t last_used;
    uint32_t use_count;
    uint8_t slot_id;
    uint8_t active;
    uint8_t deprecated;  // Still valid but being phased out
} KeySlot;

/**
 * Key Rotation Manager
 */
typedef struct {
    KeySlot slots[MAX_KEY_SLOTS];
    uint8_t current_slot;
    uint32_t rotation_interval;  // Seconds
    uint32_t max_key_age;  // Maximum age before forced rotation
    uint64_t last_rotation;
    pthread_mutex_t mutex;

    // Statistics
    uint64_t total_rotations;
    uint64_t forced_rotations;
    uint64_t automatic_rotations;
} KeyRotationManager;

/**
 * Initialize key rotation manager
 *
 * @param manager Key rotation manager
 * @param rotation_interval Seconds between rotations
 * @param max_key_age Maximum key age in seconds
 * @return 0 on success, -1 on error
 */
int key_rotation_init(KeyRotationManager *manager,
                      uint32_t rotation_interval,
                      uint32_t max_key_age);

/**
 * Generate and activate new key
 *
 * @param manager Key rotation manager
 * @param force Force rotation even if not scheduled
 * @return Slot ID of new key, or -1 on error
 */
int key_rotation_rotate(KeyRotationManager *manager, int force);

/**
 * Get current active key
 *
 * @param manager Key rotation manager
 * @param key_out Output buffer for key material
 * @param key_len Size of output buffer
 * @return 0 on success, -1 on error
 */
int key_rotation_get_current(KeyRotationManager *manager,
                              uint8_t *key_out, size_t key_len);

/**
 * Get key by slot ID (for decrypting old messages)
 *
 * @param manager Key rotation manager
 * @param slot_id Slot ID to retrieve
 * @param key_out Output buffer for key material
 * @param key_len Size of output buffer
 * @return 0 on success, -1 on error
 */
int key_rotation_get_by_slot(KeyRotationManager *manager, uint8_t slot_id,
                              uint8_t *key_out, size_t key_len);

/**
 * Check if automatic rotation is needed and perform if necessary
 *
 * @param manager Key rotation manager
 * @return 1 if rotated, 0 if not needed, -1 on error
 */
int key_rotation_check(KeyRotationManager *manager);

/**
 * Clean up expired keys
 *
 * @param manager Key rotation manager
 * @return Number of keys cleaned up, or -1 on error
 */
int key_rotation_cleanup(KeyRotationManager *manager);

/**
 * Destroy key rotation manager and securely wipe all keys
 *
 * @param manager Key rotation manager to destroy
 */
void key_rotation_destroy(KeyRotationManager *manager);

/* ============================================================================
 * MULTI-KEY DERIVATION CHAIN
 * ============================================================================ */

#define CHAIN_KEY_SIZE 32
#define MESSAGE_KEY_SIZE 32

/**
 * Key Chain for Double Ratchet Algorithm (Signal Protocol style)
 */
typedef struct {
    uint8_t chain_key[CHAIN_KEY_SIZE];
    uint8_t message_keys[256][MESSAGE_KEY_SIZE];  // Cached message keys
    uint32_t chain_index;
    uint32_t message_index;
    pthread_mutex_t mutex;
} KeyChain;

/**
 * Initialize key chain
 *
 * @param chain Key chain structure
 * @param initial_key Initial chain key
 * @return 0 on success, -1 on error
 */
int keychain_init(KeyChain *chain, const uint8_t *initial_key);

/**
 * Derive next message key and advance chain
 *
 * @param chain Key chain structure
 * @param message_key Output message key
 * @return 0 on success, -1 on error
 */
int keychain_next_message_key(KeyChain *chain, uint8_t *message_key);

/**
 * Get message key for specific index (for out-of-order messages)
 *
 * @param chain Key chain structure
 * @param index Message index
 * @param message_key Output message key
 * @return 0 on success, -1 on error
 */
int keychain_get_message_key(KeyChain *chain, uint32_t index,
                              uint8_t *message_key);

/**
 * Destroy key chain and wipe all keys
 *
 * @param chain Key chain to destroy
 */
void keychain_destroy(KeyChain *chain);

/* ============================================================================
 * HARDWARE CRYPTO ACCELERATION
 * ============================================================================ */

/**
 * Hardware acceleration capabilities
 */
typedef struct {
    uint8_t aes_ni;      // Intel AES-NI
    uint8_t avx2;        // AVX2 SIMD
    uint8_t avx512;      // AVX-512
    uint8_t sha_ext;     // SHA extensions
    uint8_t arm_crypto;  // ARM crypto extensions
    uint8_t gpu_accel;   // GPU acceleration available
} HardwareCapabilities;

/**
 * Detect available hardware acceleration
 *
 * @param caps Output capabilities structure
 * @return 0 on success, -1 on error
 */
int hw_detect_capabilities(HardwareCapabilities *caps);

/**
 * AES-GCM encryption with hardware acceleration
 *
 * @param ciphertext Output ciphertext
 * @param tag Output authentication tag (16 bytes)
 * @param plaintext Input plaintext
 * @param len Length of plaintext
 * @param key Encryption key (32 bytes for AES-256)
 * @param iv Initialization vector (12 bytes)
 * @param aad Additional authenticated data
 * @param aad_len Length of AAD
 * @return 0 on success, -1 on error
 */
int hw_aes_gcm_encrypt(uint8_t *ciphertext, uint8_t *tag,
                       const uint8_t *plaintext, size_t len,
                       const uint8_t *key, const uint8_t *iv,
                       const uint8_t *aad, size_t aad_len);

/**
 * AES-GCM decryption with hardware acceleration
 *
 * @param plaintext Output plaintext
 * @param ciphertext Input ciphertext
 * @param len Length of ciphertext
 * @param tag Authentication tag to verify (16 bytes)
 * @param key Decryption key (32 bytes for AES-256)
 * @param iv Initialization vector (12 bytes)
 * @param aad Additional authenticated data
 * @param aad_len Length of AAD
 * @return 0 on success, -1 on authentication failure
 */
int hw_aes_gcm_decrypt(uint8_t *plaintext,
                       const uint8_t *ciphertext, size_t len,
                       const uint8_t *tag, const uint8_t *key,
                       const uint8_t *iv, const uint8_t *aad,
                       size_t aad_len);

/* ============================================================================
 * QUANTUM-RESISTANT HYBRID ENCRYPTION
 * ============================================================================ */

#define HYBRID_CLASSIC_KEY_SIZE 32   // X25519
#define HYBRID_PQC_KEY_SIZE 1184     // Kyber-768 ciphertext
#define HYBRID_SHARED_SIZE 64        // Combined shared secret

/**
 * Hybrid encryption context (classic + post-quantum)
 */
typedef struct {
    // Classic crypto (X25519)
    uint8_t x25519_private[HYBRID_CLASSIC_KEY_SIZE];
    uint8_t x25519_public[HYBRID_CLASSIC_KEY_SIZE];

    // Post-quantum crypto (Kyber-768)
    uint8_t kyber_pk[KYBER_PUBLICKEYBYTES];
    uint8_t kyber_sk[KYBER_SECRETKEYBYTES];

    // Combined shared secret
    uint8_t hybrid_secret[HYBRID_SHARED_SIZE];

    uint8_t initialized;
} HybridCryptoContext;

/**
 * Initialize hybrid crypto context
 *
 * @param ctx Hybrid crypto context
 * @return 0 on success, -1 on error
 */
int hybrid_crypto_init(HybridCryptoContext *ctx);

/**
 * Perform hybrid key exchange (combines X25519 and Kyber)
 *
 * @param ctx Hybrid crypto context
 * @param peer_x25519_public Peer's X25519 public key
 * @param peer_kyber_public Peer's Kyber public key
 * @param shared_secret Output combined shared secret
 * @return 0 on success, -1 on error
 */
int hybrid_key_exchange(HybridCryptoContext *ctx,
                        const uint8_t *peer_x25519_public,
                        const uint8_t *peer_kyber_public,
                        uint8_t *shared_secret);

/**
 * Destroy hybrid crypto context and wipe keys
 *
 * @param ctx Context to destroy
 */
void hybrid_crypto_destroy(HybridCryptoContext *ctx);

/* ============================================================================
 * ADVANCED KEY MATERIAL MANAGEMENT
 * ============================================================================ */

/**
 * Secure key storage with encryption at rest
 */
typedef struct {
    uint8_t encrypted_key[KEY_MATERIAL_SIZE + 16];  // Key + GCM tag
    uint8_t nonce[12];
    uint8_t salt[32];
    uint64_t created_at;
    uint32_t iterations;  // PBKDF2 iterations
    uint8_t valid;
} SecureKeyStorage;

/**
 * Store key material encrypted at rest
 *
 * @param storage Output storage structure
 * @param key_material Key to store
 * @param key_len Length of key
 * @param password Password for encryption
 * @param password_len Length of password
 * @return 0 on success, -1 on error
 */
int secure_key_store(SecureKeyStorage *storage,
                     const uint8_t *key_material, size_t key_len,
                     const char *password, size_t password_len);

/**
 * Retrieve and decrypt stored key material
 *
 * @param key_material Output buffer for key
 * @param key_len Size of output buffer
 * @param storage Storage structure
 * @param password Password for decryption
 * @param password_len Length of password
 * @return 0 on success, -1 on error or auth failure
 */
int secure_key_retrieve(uint8_t *key_material, size_t key_len,
                        const SecureKeyStorage *storage,
                        const char *password, size_t password_len);

/* ============================================================================
 * CRYPTO PERFORMANCE MONITORING
 * ============================================================================ */

typedef struct {
    uint64_t encryptions;
    uint64_t decryptions;
    uint64_t key_rotations;
    uint64_t key_derivations;
    uint64_t hw_accelerated;
    uint64_t sw_fallback;

    // Performance metrics
    uint64_t total_encrypt_ns;
    uint64_t total_decrypt_ns;
    uint64_t avg_encrypt_ns;
    uint64_t avg_decrypt_ns;

    pthread_mutex_t mutex;
} CryptoMetrics;

/**
 * Initialize crypto metrics
 */
void crypto_metrics_init(CryptoMetrics *metrics);

/**
 * Record encryption operation
 */
void crypto_metrics_record_encrypt(CryptoMetrics *metrics, uint64_t duration_ns,
                                   int hw_accelerated);

/**
 * Record decryption operation
 */
void crypto_metrics_record_decrypt(CryptoMetrics *metrics, uint64_t duration_ns,
                                   int hw_accelerated);

/**
 * Get metrics snapshot
 */
void crypto_metrics_get(CryptoMetrics *metrics, CryptoMetrics *snapshot);

#endif /* ADVANCED_CRYPTO_H */
