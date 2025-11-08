/*
 * SecureSwift VPN - Advanced Networking Module
 * Next-Generation Network Features:
 * - Multi-Path TCP (MPTCP)
 * - Load Balancing & Failover
 * - Zero-Copy Networking
 * - Adaptive MTU Discovery
 * - Connection Bonding
 * - Split Tunneling
 * - Quality of Service (QoS)
 * - Network Telemetry
 */

#ifndef ADVANCED_NETWORKING_H
#define ADVANCED_NETWORKING_H

#include <stdint.h>
#include <stddef.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sys/epoll.h>

/* ============================================================================
 * MULTI-PATH CONFIGURATION
 * ============================================================================ */

#define MAX_PATHS 8
#define MAX_SERVERS 16
#define PATH_NAME_LEN 64

/**
 * Network path quality metrics
 */
typedef struct {
    uint32_t latency_ms;
    uint32_t jitter_ms;
    uint32_t packet_loss_ppm;  // Parts per million
    uint64_t throughput_bps;
    uint32_t mtu_bytes;
    uint8_t quality_score;  // 0-100
} PathMetrics;

/**
 * Individual network path
 */
typedef struct {
    char name[PATH_NAME_LEN];
    char interface[16];  // eth0, wlan0, etc.
    struct sockaddr_in local_addr;
    struct sockaddr_in remote_addr;

    int socket_fd;
    uint8_t path_id;
    uint8_t active;
    uint8_t primary;  // Primary path for new connections

    PathMetrics metrics;
    PathMetrics ewma_metrics;  // Exponentially weighted moving average

    uint64_t packets_sent;
    uint64_t packets_received;
    uint64_t bytes_sent;
    uint64_t bytes_received;
    uint64_t errors;

    uint64_t last_probe_time;
    uint64_t last_active_time;

    pthread_mutex_t mutex;
} NetworkPath;

/**
 * Multi-path manager
 */
typedef struct {
    NetworkPath paths[MAX_PATHS];
    uint8_t num_paths;
    uint8_t active_paths;

    // Load balancing strategy
    enum {
        LB_ROUND_ROBIN,
        LB_LEAST_LATENCY,
        LB_WEIGHTED,
        LB_BANDWIDTH,
        LB_REDUNDANT  // Send on all paths
    } load_balance_strategy;

    uint8_t current_path_index;  // For round-robin

    pthread_mutex_t mutex;
} MultiPathManager;

/**
 * Initialize multi-path manager
 */
int multipath_init(MultiPathManager *manager);

/**
 * Add network path
 */
int multipath_add_path(MultiPathManager *manager, const char *interface,
                       const char *local_ip, uint16_t local_port,
                       const char *remote_ip, uint16_t remote_port);

/**
 * Remove network path
 */
int multipath_remove_path(MultiPathManager *manager, uint8_t path_id);

/**
 * Select best path based on strategy and metrics
 */
NetworkPath* multipath_select_path(MultiPathManager *manager);

/**
 * Send packet on selected path(s)
 */
int multipath_send(MultiPathManager *manager, const uint8_t *data, size_t len);

/**
 * Probe all paths to update metrics
 */
int multipath_probe_paths(MultiPathManager *manager);

/**
 * Get aggregated statistics
 */
void multipath_get_stats(MultiPathManager *manager, PathMetrics *aggregate);

/* ============================================================================
 * LOAD BALANCER & FAILOVER
 * ============================================================================ */

#define HEALTH_CHECK_INTERVAL 5  // Seconds

/**
 * Server backend
 */
typedef struct {
    char address[256];
    uint16_t port;
    uint8_t server_id;

    // Health status
    uint8_t healthy;
    uint8_t active;
    uint32_t consecutive_failures;
    uint64_t last_health_check;

    // Load balancing weight
    uint32_t weight;
    uint32_t current_connections;
    uint32_t total_connections;

    // Performance metrics
    uint32_t avg_response_time_ms;
    uint64_t total_requests;
    uint64_t failed_requests;

    pthread_mutex_t mutex;
} ServerBackend;

/**
 * Load balancer
 */
typedef struct {
    ServerBackend servers[MAX_SERVERS];
    uint8_t num_servers;
    uint8_t healthy_servers;

    // Strategy
    enum {
        LB_STRATEGY_ROUND_ROBIN,
        LB_STRATEGY_LEAST_CONN,
        LB_STRATEGY_WEIGHTED_RR,
        LB_STRATEGY_IP_HASH,
        LB_STRATEGY_RANDOM
    } strategy;

    uint8_t current_index;  // For round-robin

    // Health checking
    pthread_t health_check_thread;
    uint8_t health_check_running;

    // Failover configuration
    uint8_t auto_failover;
    uint32_t failure_threshold;  // Consecutive failures before marking unhealthy

    pthread_mutex_t mutex;
} LoadBalancer;

/**
 * Initialize load balancer
 */
int lb_init(LoadBalancer *lb, int strategy);

/**
 * Add server to load balancer
 */
int lb_add_server(LoadBalancer *lb, const char *address, uint16_t port,
                  uint32_t weight);

/**
 * Remove server from load balancer
 */
int lb_remove_server(LoadBalancer *lb, uint8_t server_id);

/**
 * Select server based on strategy
 */
ServerBackend* lb_select_server(LoadBalancer *lb, uint32_t client_ip);

/**
 * Mark server as failed (for health checking)
 */
int lb_mark_failure(LoadBalancer *lb, uint8_t server_id);

/**
 * Mark server as healthy
 */
int lb_mark_healthy(LoadBalancer *lb, uint8_t server_id);

/**
 * Start health checking thread
 */
int lb_start_health_check(LoadBalancer *lb);

/**
 * Stop health checking
 */
void lb_stop_health_check(LoadBalancer *lb);

/* ============================================================================
 * ZERO-COPY NETWORKING
 * ============================================================================ */

/**
 * Zero-copy buffer pool
 */
typedef struct {
    uint8_t *buffers;
    size_t buffer_size;
    size_t num_buffers;
    uint32_t *free_list;
    uint32_t free_count;
    pthread_mutex_t mutex;
} ZeroCopyPool;

/**
 * Initialize zero-copy buffer pool
 */
int zerocopy_pool_init(ZeroCopyPool *pool, size_t buffer_size, size_t num_buffers);

/**
 * Allocate buffer from pool
 */
uint8_t* zerocopy_alloc(ZeroCopyPool *pool);

/**
 * Release buffer back to pool
 */
void zerocopy_free(ZeroCopyPool *pool, uint8_t *buffer);

/**
 * Send using sendfile/splice for zero-copy
 */
ssize_t zerocopy_send(int sockfd, const uint8_t *data, size_t len);

/**
 * Receive using splice for zero-copy
 */
ssize_t zerocopy_recv(int sockfd, uint8_t *buffer, size_t len);

/* ============================================================================
 * ADAPTIVE MTU DISCOVERY
 * ============================================================================ */

#define MTU_MIN 576
#define MTU_MAX 9000  // Jumbo frames

/**
 * MTU discovery state
 */
typedef struct {
    uint32_t current_mtu;
    uint32_t min_mtu;
    uint32_t max_mtu;
    uint32_t optimal_mtu;

    // Discovery state
    uint8_t discovery_active;
    uint32_t probe_size;
    uint32_t consecutive_successes;
    uint32_t consecutive_failures;

    uint64_t last_update;

    pthread_mutex_t mutex;
} MTUDiscovery;

/**
 * Initialize MTU discovery
 */
int mtu_discovery_init(MTUDiscovery *mtu);

/**
 * Probe MTU with specific size
 */
int mtu_probe(MTUDiscovery *mtu, int sockfd, uint32_t size);

/**
 * Update MTU based on probe results
 */
int mtu_update(MTUDiscovery *mtu, int success);

/**
 * Get current optimal MTU
 */
uint32_t mtu_get_current(MTUDiscovery *mtu);

/* ============================================================================
 * SPLIT TUNNELING
 * ============================================================================ */

#define MAX_SPLIT_RULES 256

/**
 * Split tunnel rule
 */
typedef struct {
    enum {
        RULE_TYPE_IP_RANGE,
        RULE_TYPE_DOMAIN,
        RULE_TYPE_PORT,
        RULE_TYPE_PROTOCOL
    } type;

    union {
        struct {
            uint32_t start_ip;
            uint32_t end_ip;
        } ip_range;

        struct {
            char domain[256];
        } domain;

        struct {
            uint16_t port;
            uint8_t protocol;  // TCP/UDP
        } port;

        uint8_t protocol;
    } match;

    enum {
        ACTION_VPN,      // Route through VPN
        ACTION_DIRECT,   // Route directly (bypass VPN)
        ACTION_BLOCK     // Block traffic
    } action;

    uint8_t active;
} SplitTunnelRule;

/**
 * Split tunneling manager
 */
typedef struct {
    SplitTunnelRule rules[MAX_SPLIT_RULES];
    uint32_t num_rules;

    uint8_t default_action;  // Default: route through VPN

    // Statistics
    uint64_t vpn_packets;
    uint64_t direct_packets;
    uint64_t blocked_packets;

    pthread_mutex_t mutex;
} SplitTunnelManager;

/**
 * Initialize split tunneling
 */
int split_tunnel_init(SplitTunnelManager *manager);

/**
 * Add split tunnel rule
 */
int split_tunnel_add_rule(SplitTunnelManager *manager, SplitTunnelRule *rule);

/**
 * Check if packet should go through VPN
 */
int split_tunnel_check(SplitTunnelManager *manager,
                       uint32_t dest_ip, uint16_t dest_port, uint8_t protocol);

/**
 * Remove rule
 */
int split_tunnel_remove_rule(SplitTunnelManager *manager, uint32_t rule_id);

/* ============================================================================
 * QUALITY OF SERVICE (QoS)
 * ============================================================================ */

/**
 * Traffic class
 */
typedef enum {
    QOS_CLASS_REALTIME,     // VoIP, gaming (highest priority)
    QOS_CLASS_INTERACTIVE,  // SSH, RDP (high priority)
    QOS_CLASS_BULK,         // File transfers (normal priority)
    QOS_CLASS_BACKGROUND    // Updates, backups (low priority)
} QoSClass;

/**
 * QoS queue
 */
typedef struct {
    uint8_t *packets[1024];
    size_t packet_sizes[1024];
    uint32_t head;
    uint32_t tail;
    uint32_t count;
    QoSClass class;

    uint64_t enqueued;
    uint64_t dequeued;
    uint64_t dropped;

    pthread_mutex_t mutex;
} QoSQueue;

/**
 * QoS manager
 */
typedef struct {
    QoSQueue queues[4];  // One per class
    uint8_t enabled;

    // Bandwidth limits per class (bytes/sec)
    uint64_t class_limits[4];

    pthread_mutex_t mutex;
} QoSManager;

/**
 * Initialize QoS manager
 */
int qos_init(QoSManager *qos);

/**
 * Classify packet
 */
QoSClass qos_classify_packet(const uint8_t *packet, size_t len);

/**
 * Enqueue packet
 */
int qos_enqueue(QoSManager *qos, QoSClass class, const uint8_t *packet, size_t len);

/**
 * Dequeue packet (prioritized)
 */
int qos_dequeue(QoSManager *qos, uint8_t **packet, size_t *len, QoSClass *class);

/**
 * Set class bandwidth limit
 */
int qos_set_limit(QoSManager *qos, QoSClass class, uint64_t bytes_per_sec);

/* ============================================================================
 * CONNECTION BONDING
 * ============================================================================ */

/**
 * Bonded connection (aggregates multiple paths)
 */
typedef struct {
    NetworkPath *paths[MAX_PATHS];
    uint8_t num_paths;

    // Bonding mode
    enum {
        BOND_MODE_ACTIVE_BACKUP,   // Only one path active
        BOND_MODE_LOAD_BALANCE,    // Distribute across all paths
        BOND_MODE_BROADCAST,       // Send on all paths (redundancy)
        BOND_MODE_ADAPTIVE         // Dynamic based on conditions
    } mode;

    uint64_t total_throughput;
    uint8_t primary_path;

    pthread_mutex_t mutex;
} BondedConnection;

/**
 * Initialize bonded connection
 */
int bond_init(BondedConnection *bond, int mode);

/**
 * Add path to bond
 */
int bond_add_path(BondedConnection *bond, NetworkPath *path);

/**
 * Remove path from bond
 */
int bond_remove_path(BondedConnection *bond, uint8_t path_id);

/**
 * Send data across bonded connection
 */
int bond_send(BondedConnection *bond, const uint8_t *data, size_t len);

/**
 * Check bond health and adjust
 */
int bond_health_check(BondedConnection *bond);

/* ============================================================================
 * NETWORK TELEMETRY
 * ============================================================================ */

/**
 * Detailed network statistics
 */
typedef struct {
    // Packet counters
    uint64_t packets_sent;
    uint64_t packets_received;
    uint64_t packets_dropped;
    uint64_t packets_retransmitted;

    // Byte counters
    uint64_t bytes_sent;
    uint64_t bytes_received;

    // Error counters
    uint64_t checksum_errors;
    uint64_t sequence_errors;
    uint64_t timeout_errors;

    // Performance metrics
    uint32_t current_rtt_ms;
    uint32_t min_rtt_ms;
    uint32_t max_rtt_ms;
    uint32_t avg_rtt_ms;

    uint64_t current_bandwidth_bps;
    uint64_t peak_bandwidth_bps;

    // Congestion
    uint32_t congestion_window;
    uint32_t slow_start_threshold;
    uint8_t congestion_detected;

    pthread_mutex_t mutex;
} NetworkTelemetry;

/**
 * Initialize telemetry
 */
void telemetry_init(NetworkTelemetry *telemetry);

/**
 * Record packet sent
 */
void telemetry_record_sent(NetworkTelemetry *telemetry, size_t bytes);

/**
 * Record packet received
 */
void telemetry_record_received(NetworkTelemetry *telemetry, size_t bytes,
                               uint32_t rtt_ms);

/**
 * Record error
 */
void telemetry_record_error(NetworkTelemetry *telemetry, int error_type);

/**
 * Get telemetry snapshot
 */
void telemetry_get_snapshot(NetworkTelemetry *telemetry, NetworkTelemetry *snapshot);

/**
 * Export telemetry to Prometheus format
 */
int telemetry_export_prometheus(NetworkTelemetry *telemetry, char *output,
                                size_t output_size);

/* ============================================================================
 * HIGH-PERFORMANCE EVENT LOOP (epoll-based)
 * ============================================================================ */

#define MAX_EVENTS 1024

/**
 * Event loop context
 */
typedef struct {
    int epoll_fd;
    struct epoll_event events[MAX_EVENTS];
    uint8_t running;

    // Event handlers
    void (*on_readable)(int fd, void *ctx);
    void (*on_writable)(int fd, void *ctx);
    void (*on_error)(int fd, void *ctx);

    void *user_context;

    pthread_t thread;
    pthread_mutex_t mutex;
} EventLoop;

/**
 * Initialize event loop
 */
int event_loop_init(EventLoop *loop);

/**
 * Add file descriptor to event loop
 */
int event_loop_add_fd(EventLoop *loop, int fd, uint32_t events);

/**
 * Remove file descriptor from event loop
 */
int event_loop_remove_fd(EventLoop *loop, int fd);

/**
 * Run event loop (blocking)
 */
int event_loop_run(EventLoop *loop);

/**
 * Stop event loop
 */
void event_loop_stop(EventLoop *loop);

#endif /* ADVANCED_NETWORKING_H */
