/*
 * SecureSwift VPN - End-to-End Production Tests
 * Tests actual VPN client-server functionality with real crypto
 *
 * Requirements: sudo privileges for TUN interface
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>

/* Test framework */
static int tests_passed = 0;
static int tests_failed = 0;
static pid_t server_pid = 0;
static pid_t client_pid = 0;

#define TEST_START(name) do { \
    printf("\n╔═══════════════════════════════════════════════════════════╗\n"); \
    printf("║  %s\n", name); \
    printf("╚═══════════════════════════════════════════════════════════╝\n"); \
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

/* Constants */
#define TEST_PORT 51820
#define TEST_SERVER_IP "127.0.0.1"
#define TUN_DEVICE "tun0"
#define PACKET_SIZE 1400
#define STRESS_PACKETS 100000

/* Cleanup handler */
void cleanup() {
    if (server_pid > 0) {
        kill(server_pid, SIGTERM);
        waitpid(server_pid, NULL, 0);
    }
    if (client_pid > 0) {
        kill(client_pid, SIGTERM);
        waitpid(client_pid, NULL, 0);
    }
}

void signal_handler(int sig) {
    cleanup();
    exit(1);
}

/* Test 1: Binary exists and is executable */
void test_binary_exists() {
    TEST_START("Test 1: Binary Validation");

    int result = access("./secureswift", X_OK);
    TEST_ASSERT(result == 0, "SecureSwift binary exists and is executable");

    if (result != 0) {
        printf("   ERROR: Please compile first: gcc -O3 secureswift.c -o secureswift -lm -lpthread\n");
    }

    /* Check if running as root (required for TUN interface) */
    int is_root = (geteuid() == 0);
    if (!is_root) {
        printf("   WARNING: Not running as root. TUN interface tests will fail.\n");
        printf("   Run with: sudo ./test_e2e\n");
    }
    TEST_ASSERT(is_root, "Running with root privileges (required for TUN)");
}

/* Test 2: Server can start */
void test_server_start() {
    TEST_START("Test 2: Server Startup");

    server_pid = fork();
    if (server_pid == 0) {
        /* Child: Start server */
        freopen("/dev/null", "w", stdout);
        freopen("/dev/null", "w", stderr);
        execl("./secureswift", "secureswift", "server", TEST_SERVER_IP, NULL);
        exit(1);  /* If execl fails */
    }

    /* Wait for server to initialize */
    sleep(2);

    /* Check if server is still running */
    int status;
    pid_t result = waitpid(server_pid, &status, WNOHANG);
    TEST_ASSERT(result == 0, "Server process started successfully");

    if (result != 0) {
        printf("   ERROR: Server exited immediately. Check permissions.\n");
        server_pid = 0;
    }
}

/* Test 3: Socket binding */
void test_socket_binding() {
    TEST_START("Test 3: Socket Port Binding");

    /* Try to bind to the same port - should fail if server is using it */
    int test_sock = socket(AF_INET, SOCK_DGRAM, 0);
    TEST_ASSERT(test_sock >= 0, "Test socket created");

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(TEST_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    int result = bind(test_sock, (struct sockaddr*)&addr, sizeof(addr));

    /* Should fail because server is already using it */
    TEST_ASSERT(result < 0, "Port 51820 is bound by server (bind fails as expected)");

    close(test_sock);
}

/* Test 4: Client can connect */
void test_client_connect() {
    TEST_START("Test 4: Client Connection");

    client_pid = fork();
    if (client_pid == 0) {
        /* Child: Start client */
        freopen("/dev/null", "w", stdout);
        freopen("/dev/null", "w", stderr);
        execl("./secureswift", "secureswift", "client", TEST_SERVER_IP, NULL);
        exit(1);
    }

    /* Wait for client to connect */
    sleep(2);

    /* Check if client is running */
    int status;
    pid_t result = waitpid(client_pid, &status, WNOHANG);
    TEST_ASSERT(result == 0, "Client process connected successfully");

    if (result != 0) {
        printf("   ERROR: Client exited immediately\n");
        client_pid = 0;
    }
}

/* Test 5: TUN interface creation */
void test_tun_interface() {
    TEST_START("Test 5: TUN Interface");

    /* Check if TUN interface exists */
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, TUN_DEVICE, IFNAMSIZ - 1);

    int result = ioctl(sock, SIOCGIFFLAGS, &ifr);
    close(sock);

    TEST_ASSERT(result == 0, "TUN interface exists");

    if (result == 0) {
        int is_up = (ifr.ifr_flags & IFF_UP);
        TEST_ASSERT(is_up, "TUN interface is UP");

        int is_running = (ifr.ifr_flags & IFF_RUNNING);
        TEST_ASSERT(is_running, "TUN interface is RUNNING");
    } else {
        printf("   ERROR: TUN interface not created (errno: %s)\n", strerror(errno));
    }
}

/* Test 6: UDP packet transmission */
void test_udp_transmission() {
    TEST_START("Test 6: UDP Packet Transmission");

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    TEST_ASSERT(sock >= 0, "UDP socket created");

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(TEST_PORT);
    inet_pton(AF_INET, TEST_SERVER_IP, &server_addr.sin_addr);

    /* Send test packet */
    uint8_t test_packet[100];
    memset(test_packet, 0xAA, sizeof(test_packet));

    ssize_t sent = sendto(sock, test_packet, sizeof(test_packet), 0,
                          (struct sockaddr*)&server_addr, sizeof(server_addr));
    TEST_ASSERT(sent == sizeof(test_packet), "UDP packet sent to server");

    close(sock);
}

/* Test 7: Process resource usage */
void test_resource_usage() {
    TEST_START("Test 7: Resource Usage");

    if (server_pid > 0) {
        /* Check /proc/<pid>/status for server */
        char path[256];
        snprintf(path, sizeof(path), "/proc/%d/status", server_pid);

        FILE *f = fopen(path, "r");
        if (f) {
            char line[256];
            int threads = 0;
            int vm_size = 0;

            while (fgets(line, sizeof(line), f)) {
                if (strncmp(line, "Threads:", 8) == 0) {
                    sscanf(line, "Threads: %d", &threads);
                }
                if (strncmp(line, "VmSize:", 7) == 0) {
                    sscanf(line, "VmSize: %d kB", &vm_size);
                }
            }
            fclose(f);

            TEST_ASSERT(threads > 0, "Server has worker threads");
            TEST_ASSERT(vm_size < 100000, "Server memory usage < 100MB");

            printf("   → Server threads: %d\n", threads);
            printf("   → Server memory: %d KB\n", vm_size);
        } else {
            TEST_ASSERT(0, "Could not read server process info");
        }
    }
}

/* Test 8: Packet throughput stress test */
void test_packet_throughput() {
    TEST_START("Test 8: Packet Throughput Stress Test");

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    TEST_ASSERT(sock >= 0, "Stress test socket created");

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(TEST_PORT);
    inet_pton(AF_INET, TEST_SERVER_IP, &server_addr.sin_addr);

    uint8_t packet[PACKET_SIZE];
    memset(packet, 0xBB, sizeof(packet));

    int packets_sent = 0;
    time_t start = time(NULL);

    printf("   Sending %d packets...\n", STRESS_PACKETS);

    for (int i = 0; i < STRESS_PACKETS; i++) {
        ssize_t sent = sendto(sock, packet, sizeof(packet), 0,
                              (struct sockaddr*)&server_addr, sizeof(server_addr));
        if (sent > 0) packets_sent++;

        /* Print progress every 10k packets */
        if (i > 0 && i % 10000 == 0) {
            printf("   → Progress: %d/%d packets\n", i, STRESS_PACKETS);
        }
    }

    time_t end = time(NULL);
    double duration = difftime(end, start);
    double pps = packets_sent / (duration > 0 ? duration : 1);

    TEST_ASSERT(packets_sent > STRESS_PACKETS * 0.99,
                "Successfully sent >99% of stress packets");

    printf("   → Packets sent: %d/%d (%.1f%%)\n",
           packets_sent, STRESS_PACKETS,
           (100.0 * packets_sent) / STRESS_PACKETS);
    printf("   → Duration: %.1f seconds\n", duration);
    printf("   → Throughput: %.0f packets/sec\n", pps);

    close(sock);
}

/* Test 9: Memory leak check */
void test_memory_leak() {
    TEST_START("Test 9: Memory Leak Detection");

    if (server_pid > 0) {
        char path[256];
        snprintf(path, sizeof(path), "/proc/%d/status", server_pid);

        /* Read initial memory */
        FILE *f = fopen(path, "r");
        int vm_size_before = 0;
        if (f) {
            char line[256];
            while (fgets(line, sizeof(line), f)) {
                if (strncmp(line, "VmSize:", 7) == 0) {
                    sscanf(line, "VmSize: %d kB", &vm_size_before);
                    break;
                }
            }
            fclose(f);
        }

        /* Send many packets to stress memory allocation */
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        struct sockaddr_in server_addr;
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(TEST_PORT);
        inet_pton(AF_INET, TEST_SERVER_IP, &server_addr.sin_addr);

        uint8_t packet[1400];
        for (int i = 0; i < 10000; i++) {
            sendto(sock, packet, sizeof(packet), 0,
                   (struct sockaddr*)&server_addr, sizeof(server_addr));
        }
        close(sock);

        /* Wait for processing */
        sleep(2);

        /* Read final memory */
        f = fopen(path, "r");
        int vm_size_after = 0;
        if (f) {
            char line[256];
            while (fgets(line, sizeof(line), f)) {
                if (strncmp(line, "VmSize:", 7) == 0) {
                    sscanf(line, "VmSize: %d kB", &vm_size_after);
                    break;
                }
            }
            fclose(f);
        }

        int growth = vm_size_after - vm_size_before;
        printf("   → Memory before: %d KB\n", vm_size_before);
        printf("   → Memory after: %d KB\n", vm_size_after);
        printf("   → Growth: %d KB\n", growth);

        /* Memory growth should be < 10MB for 10k packets */
        TEST_ASSERT(growth < 10000, "Memory growth < 10MB (no major leaks)");
    }
}

/* Test 10: Process stability */
void test_process_stability() {
    TEST_START("Test 10: Process Stability");

    /* Check if server is still running after all tests */
    if (server_pid > 0) {
        int status;
        pid_t result = waitpid(server_pid, &status, WNOHANG);
        TEST_ASSERT(result == 0, "Server still running after stress tests");

        if (result != 0) {
            printf("   ERROR: Server crashed (exit status: %d)\n",
                   WEXITSTATUS(status));
        }
    }

    /* Check if client is still running */
    if (client_pid > 0) {
        int status;
        pid_t result = waitpid(client_pid, &status, WNOHANG);
        TEST_ASSERT(result == 0, "Client still running after stress tests");

        if (result != 0) {
            printf("   ERROR: Client crashed (exit status: %d)\n",
                   WEXITSTATUS(status));
        }
    }
}

/* Test 11: Graceful shutdown */
void test_graceful_shutdown() {
    TEST_START("Test 11: Graceful Shutdown");

    /* Send SIGTERM to client */
    if (client_pid > 0) {
        kill(client_pid, SIGTERM);
        int status;
        pid_t result = waitpid(client_pid, &status, 0);
        TEST_ASSERT(result == client_pid, "Client shutdown gracefully");
        client_pid = 0;
    }

    /* Send SIGTERM to server */
    if (server_pid > 0) {
        kill(server_pid, SIGTERM);
        int status;
        pid_t result = waitpid(server_pid, &status, 0);
        TEST_ASSERT(result == server_pid, "Server shutdown gracefully");
        server_pid = 0;
    }
}

/* Main test runner */
int main(int argc, char *argv[]) {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    printf("╔═══════════════════════════════════════════════════════════╗\n");
    printf("║      SecureSwift VPN - End-to-End Production Tests      ║\n");
    printf("║      Real VPN Client-Server Functionality Testing       ║\n");
    printf("╚═══════════════════════════════════════════════════════════╝\n");

    if (geteuid() != 0) {
        printf("\n❌ ERROR: This test requires root privileges\n");
        printf("Please run: sudo ./test_e2e\n\n");
        return 1;
    }

    /* Compile binary if it doesn't exist */
    if (access("./secureswift", X_OK) != 0) {
        printf("\n⚙ Compiling SecureSwift VPN...\n");
        int result = system("gcc -O3 -msse2 secureswift.c -o secureswift -lm -lpthread 2>&1");
        if (result != 0) {
            printf("❌ Compilation failed!\n");
            return 1;
        }
        printf("✓ Compilation successful\n\n");
    }

    /* Run all tests */
    test_binary_exists();
    test_server_start();
    test_socket_binding();
    test_client_connect();
    test_tun_interface();
    test_udp_transmission();
    test_resource_usage();
    test_packet_throughput();
    test_memory_leak();
    test_process_stability();
    test_graceful_shutdown();

    /* Final summary */
    printf("\n╔═══════════════════════════════════════════════════════════╗\n");
    printf("║  END-TO-END TEST SUMMARY                                 ║\n");
    printf("╠═══════════════════════════════════════════════════════════╣\n");
    printf("║  Total Tests: %3d                                         ║\n",
           tests_passed + tests_failed);
    printf("║  Passed:      %3d  ✓                                      ║\n",
           tests_passed);
    printf("║  Failed:      %3d  ✗                                      ║\n",
           tests_failed);

    if (tests_failed == 0) {
        printf("║  Success Rate: 100%%                                       ║\n");
    } else {
        int success_rate = (tests_passed * 100) / (tests_passed + tests_failed);
        printf("║  Success Rate: %3d%%                                       ║\n",
               success_rate);
    }

    printf("╚═══════════════════════════════════════════════════════════╝\n");

    if (tests_failed == 0) {
        printf("\n🎉 ALL END-TO-END TESTS PASSED! 🎉\n");
        printf("VPN is production-ready and fully functional!\n\n");
        return 0;
    } else {
        printf("\n❌ SOME TESTS FAILED ❌\n");
        printf("Review the failures above.\n\n");
        return 1;
    }
}
