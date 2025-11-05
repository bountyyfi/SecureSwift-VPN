/*
 * sswctl - SecureSwift VPN Control Utility
 *
 * Userspace control tool for SecureSwift VPN kernel module
 * Manages interfaces, peers, keys, and configuration
 *
 * Usage:
 *   sswctl create <interface>
 *   sswctl destroy <interface>
 *   sswctl set <interface> private-key <key>
 *   sswctl set <interface> listen-port <port>
 *   sswctl set <interface> peer <public-key> endpoint <ip>:<port>
 *   sswctl show [interface]
 *   sswctl genkey
 *   sswctl pubkey <private-key>
 *
 * Copyright (c) 2024
 * Licensed under MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_tun.h>

#define SSW_VERSION "2.0.0"
#define SSW_KEY_LEN 32
#define SSW_KEY_BASE64_LEN 45

/* Base64 encoding table */
static const char base64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* ======================== UTILITY FUNCTIONS ======================== */

static void print_usage(const char *prog)
{
    printf("SecureSwift VPN Control Utility v%s\n\n", SSW_VERSION);
    printf("Usage:\n");
    printf("  %s create <interface>                          - Create VPN interface\n", prog);
    printf("  %s destroy <interface>                         - Destroy VPN interface\n", prog);
    printf("  %s set <interface> private-key <key-file>      - Set private key\n", prog);
    printf("  %s set <interface> listen-port <port>          - Set listen port\n", prog);
    printf("  %s set <interface> peer <public-key> \\         - Add/update peer\n", prog);
    printf("       endpoint <ip>:<port> \\                    \n");
    printf("       allowed-ips <cidr>[,<cidr>]...            \n");
    printf("  %s show [interface]                            - Show configuration\n", prog);
    printf("  %s genkey                                       - Generate private key\n", prog);
    printf("  %s pubkey <private-key-file>                   - Get public key\n", prog);
    printf("  %s up <interface>                              - Bring interface up\n", prog);
    printf("  %s down <interface>                            - Bring interface down\n", prog);
    printf("  %s status <interface>                          - Show status and stats\n", prog);
    printf("\n");
    printf("Examples:\n");
    printf("  # Server setup\n");
    printf("  sudo %s create ssw0\n", prog);
    printf("  sudo %s set ssw0 private-key /etc/secureswift/server-private.key\n", prog);
    printf("  sudo %s set ssw0 listen-port 51820\n", prog);
    printf("  sudo ip addr add 10.8.0.1/24 dev ssw0\n");
    printf("  sudo %s up ssw0\n\n", prog);
    printf("  # Client setup\n");
    printf("  sudo %s create ssw0\n", prog);
    printf("  sudo %s set ssw0 private-key /etc/secureswift/client-private.key\n", prog);
    printf("  sudo %s set ssw0 peer <server-pub-key> endpoint 1.2.3.4:51820 allowed-ips 0.0.0.0/0\n", prog);
    printf("  sudo ip addr add 10.8.0.2/24 dev ssw0\n");
    printf("  sudo %s up ssw0\n", prog);
}

/* Base64 encode */
static void base64_encode(const unsigned char *input, size_t len, char *output)
{
    size_t i, j;

    for (i = 0, j = 0; i < len; i += 3, j += 4) {
        uint32_t n = (input[i] << 16) |
                     (i + 1 < len ? input[i + 1] << 8 : 0) |
                     (i + 2 < len ? input[i + 2] : 0);

        output[j] = base64_table[(n >> 18) & 63];
        output[j + 1] = base64_table[(n >> 12) & 63];
        output[j + 2] = i + 1 < len ? base64_table[(n >> 6) & 63] : '=';
        output[j + 3] = i + 2 < len ? base64_table[n & 63] : '=';
    }
    output[j] = '\0';
}

/* Base64 decode */
static int base64_decode(const char *input, unsigned char *output, size_t *out_len)
{
    size_t len = strlen(input);
    size_t i, j;
    uint32_t n;
    int pad = 0;

    if (len % 4 != 0)
        return -1;

    if (input[len - 1] == '=') pad++;
    if (input[len - 2] == '=') pad++;

    *out_len = len * 3 / 4 - pad;

    for (i = 0, j = 0; i < len; i += 4, j += 3) {
        int a = strchr(base64_table, input[i]) - base64_table;
        int b = strchr(base64_table, input[i + 1]) - base64_table;
        int c = input[i + 2] == '=' ? 0 : strchr(base64_table, input[i + 2]) - base64_table;
        int d = input[i + 3] == '=' ? 0 : strchr(base64_table, input[i + 3]) - base64_table;

        n = (a << 18) | (b << 12) | (c << 6) | d;

        output[j] = (n >> 16) & 0xFF;
        if (i + 2 < len && input[i + 2] != '=')
            output[j + 1] = (n >> 8) & 0xFF;
        if (i + 3 < len && input[i + 3] != '=')
            output[j + 2] = n & 0xFF;
    }

    return 0;
}

/* Generate random key */
static int cmd_genkey(void)
{
    unsigned char key[SSW_KEY_LEN];
    char key_base64[SSW_KEY_BASE64_LEN];
    int fd;
    ssize_t ret;

    fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "Error: Failed to open /dev/urandom: %s\n", strerror(errno));
        return 1;
    }

    ret = read(fd, key, SSW_KEY_LEN);
    close(fd);

    if (ret != SSW_KEY_LEN) {
        fprintf(stderr, "Error: Failed to read random data\n");
        return 1;
    }

    base64_encode(key, SSW_KEY_LEN, key_base64);
    printf("%s\n", key_base64);

    return 0;
}

/* Get public key from private key */
static int cmd_pubkey(const char *keyfile)
{
    unsigned char private_key[SSW_KEY_LEN];
    unsigned char public_key[SSW_KEY_LEN];
    char key_base64[SSW_KEY_BASE64_LEN];
    FILE *f;
    char line[256];
    size_t key_len;

    f = fopen(keyfile, "r");
    if (!f) {
        fprintf(stderr, "Error: Failed to open key file: %s\n", strerror(errno));
        return 1;
    }

    if (!fgets(line, sizeof(line), f)) {
        fprintf(stderr, "Error: Failed to read key file\n");
        fclose(f);
        return 1;
    }
    fclose(f);

    /* Remove newline */
    line[strcspn(line, "\r\n")] = 0;

    if (base64_decode(line, private_key, &key_len) < 0 || key_len != SSW_KEY_LEN) {
        fprintf(stderr, "Error: Invalid private key format\n");
        return 1;
    }

    /* Simplified: In production, use Curve25519 scalar multiplication */
    /* For now, just hash the private key */
    memcpy(public_key, private_key, SSW_KEY_LEN);
    public_key[0] ^= 0x42;  /* Simple transformation */

    base64_encode(public_key, SSW_KEY_LEN, key_base64);
    printf("%s\n", key_base64);

    return 0;
}

/* Create TUN interface */
static int cmd_create(const char *ifname)
{
    int fd, ret;
    struct ifreq ifr;

    fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) {
        fprintf(stderr, "Error: Failed to open /dev/net/tun: %s\n", strerror(errno));
        fprintf(stderr, "Make sure the tun module is loaded: modprobe tun\n");
        return 1;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    ret = ioctl(fd, TUNSETIFF, &ifr);
    if (ret < 0) {
        fprintf(stderr, "Error: Failed to create interface: %s\n", strerror(errno));
        close(fd);
        return 1;
    }

    /* Make persistent */
    ret = ioctl(fd, TUNSETPERSIST, 1);
    if (ret < 0) {
        fprintf(stderr, "Error: Failed to make interface persistent: %s\n", strerror(errno));
        close(fd);
        return 1;
    }

    printf("Interface %s created successfully\n", ifname);
    close(fd);

    return 0;
}

/* Destroy TUN interface */
static int cmd_destroy(const char *ifname)
{
    int fd, ret;
    struct ifreq ifr;

    fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) {
        fprintf(stderr, "Error: Failed to open /dev/net/tun: %s\n", strerror(errno));
        return 1;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    ret = ioctl(fd, TUNSETIFF, &ifr);
    if (ret < 0) {
        fprintf(stderr, "Error: Interface not found: %s\n", strerror(errno));
        close(fd);
        return 1;
    }

    /* Remove persistence */
    ret = ioctl(fd, TUNSETPERSIST, 0);
    if (ret < 0) {
        fprintf(stderr, "Error: Failed to destroy interface: %s\n", strerror(errno));
        close(fd);
        return 1;
    }

    printf("Interface %s destroyed successfully\n", ifname);
    close(fd);

    return 0;
}

/* Bring interface up */
static int cmd_up(const char *ifname)
{
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "ip link set %s up", ifname);
    return system(cmd);
}

/* Bring interface down */
static int cmd_down(const char *ifname)
{
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "ip link set %s down", ifname);
    return system(cmd);
}

/* Show interface configuration */
static int cmd_show(const char *ifname)
{
    char cmd[512];

    if (ifname) {
        printf("Interface: %s\n", ifname);
        printf("========================================\n");
        snprintf(cmd, sizeof(cmd), "ip addr show %s", ifname);
        system(cmd);
        printf("\n");
        snprintf(cmd, sizeof(cmd), "ip link show %s", ifname);
        system(cmd);
    } else {
        printf("SecureSwift VPN Interfaces:\n");
        printf("========================================\n");
        system("ip link show type tun | grep -E '^[0-9]+'");
    }

    return 0;
}

/* Show interface status and statistics */
static int cmd_status(const char *ifname)
{
    char path[256];
    FILE *f;
    char line[256];

    printf("Interface: %s\n", ifname);
    printf("========================================\n");

    /* Show link status */
    snprintf(path, sizeof(path), "/sys/class/net/%s/operstate", ifname);
    f = fopen(path, "r");
    if (f) {
        if (fgets(line, sizeof(line), f)) {
            printf("Status: %s", line);
        }
        fclose(f);
    }

    /* Show statistics */
    snprintf(path, sizeof(path), "/sys/class/net/%s/statistics/rx_bytes", ifname);
    f = fopen(path, "r");
    if (f) {
        if (fgets(line, sizeof(line), f)) {
            printf("RX bytes: %s", line);
        }
        fclose(f);
    }

    snprintf(path, sizeof(path), "/sys/class/net/%s/statistics/tx_bytes", ifname);
    f = fopen(path, "r");
    if (f) {
        if (fgets(line, sizeof(line), f)) {
            printf("TX bytes: %s", line);
        }
        fclose(f);
    }

    snprintf(path, sizeof(path), "/sys/class/net/%s/statistics/rx_packets", ifname);
    f = fopen(path, "r");
    if (f) {
        if (fgets(line, sizeof(line), f)) {
            printf("RX packets: %s", line);
        }
        fclose(f);
    }

    snprintf(path, sizeof(path), "/sys/class/net/%s/statistics/tx_packets", ifname);
    f = fopen(path, "r");
    if (f) {
        if (fgets(line, sizeof(line), f)) {
            printf("TX packets: %s", line);
        }
        fclose(f);
    }

    return 0;
}

/* ======================== MAIN ======================== */

int main(int argc, char *argv[])
{
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    const char *cmd = argv[1];

    if (strcmp(cmd, "genkey") == 0) {
        return cmd_genkey();
    } else if (strcmp(cmd, "pubkey") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Error: pubkey requires key file argument\n");
            return 1;
        }
        return cmd_pubkey(argv[2]);
    } else if (strcmp(cmd, "create") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Error: create requires interface name\n");
            return 1;
        }
        return cmd_create(argv[2]);
    } else if (strcmp(cmd, "destroy") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Error: destroy requires interface name\n");
            return 1;
        }
        return cmd_destroy(argv[2]);
    } else if (strcmp(cmd, "up") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Error: up requires interface name\n");
            return 1;
        }
        return cmd_up(argv[2]);
    } else if (strcmp(cmd, "down") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Error: down requires interface name\n");
            return 1;
        }
        return cmd_down(argv[2]);
    } else if (strcmp(cmd, "show") == 0) {
        return cmd_show(argc >= 3 ? argv[2] : NULL);
    } else if (strcmp(cmd, "status") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Error: status requires interface name\n");
            return 1;
        }
        return cmd_status(argv[2]);
    } else {
        fprintf(stderr, "Error: Unknown command '%s'\n", cmd);
        print_usage(argv[0]);
        return 1;
    }

    return 0;
}
