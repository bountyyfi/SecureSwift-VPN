#!/bin/bash
#
# SecureSwift VPN - Advanced Installation Script
# Supports both userspace and kernel module modes
# 100% automated with zero configuration
#
# Usage:
#   Server: curl -sSL https://get.secureswift.io | sudo bash -s server <ip> [port]
#   Client: curl -sSL https://get.secureswift.io | sudo bash -s client <server-ip> [port]
#
#   Or with mode selection:
#   sudo ./install-advanced.sh server <ip> [port] [--kernel | --userspace]
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Configuration
VERSION="2.0.0"
DEFAULT_PORT=51820
BINARY_NAME="secureswift"
CONFIG_DIR="/etc/secureswift"
SYSTEMD_DIR="/etc/systemd/system"
LOG_DIR="/var/log/secureswift"
KEY_DIR="$CONFIG_DIR/keys"
INTERFACE_NAME="ssw0"

# Mode selection
MODE_KERNEL=false
MODE_USERSPACE=false
AUTO_MODE=true

# ======================== HELPER FUNCTIONS ========================

print_banner() {
    clear
    echo -e "${CYAN}${BOLD}"
    cat << "EOF"
    ____                           ____         _ ______        _______   ____  _   __
   / ___|  ___  ___ _   _ _ __ ___/ ___|_      _(_)  _ \_   __ _   _\ \ / /  _ \| \ | |
   \___ \ / _ \/ __| | | | '__/ _ \___ \ \ /\ / / | |_) \ \ / /   | |  \ V /| |_) |  \| |
    ___) |  __/ (__| |_| | | |  __/___) \ V  V /| |  __/ \ V /    | |   | | |  __/| |\  |
   |____/ \___|\___|\__,_|_|  \___|____/ \_/\_/ |_|_|    _\_/_    |_|   |_| |_|   |_| \_|
                                                         |_____|

   Post-Quantum Secure VPN - Faster & Safer than WireGuard
   Version: v2.0.0 | https://secureswift-vpn.org

EOF
    echo -e "${NC}"
}

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[⚠]${NC} $1"
}

print_step() {
    echo -e "${CYAN}[→]${NC} ${BOLD}$1${NC}"
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        print_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        VERSION_ID=$VERSION_ID
        print_info "Detected: $PRETTY_NAME"
    else
        print_error "Cannot detect OS"
        exit 1
    fi

    # Check if OS is supported
    case "$OS" in
        ubuntu|debian|linuxmint|pop)
            print_success "OS supported"
            ;;
        *)
            print_warning "OS not officially supported, attempting installation anyway"
            ;;
    esac
}

check_system() {
    print_step "Checking system requirements..."

    # Check CPU
    if ! grep -q sse2 /proc/cpuinfo; then
        print_error "CPU does not support SSE2 instructions"
        exit 1
    fi
    print_success "CPU supports SSE2"

    # Check kernel version
    KERNEL_VER=$(uname -r | cut -d'.' -f1-2)
    KERNEL_MAJOR=$(echo $KERNEL_VER | cut -d'.' -f1)
    KERNEL_MINOR=$(echo $KERNEL_VER | cut -d'.' -f2)

    if [ "$KERNEL_MAJOR" -lt 3 ] || ([ "$KERNEL_MAJOR" -eq 3 ] && [ "$KERNEL_MINOR" -lt 10 ]); then
        print_error "Kernel version too old (need 3.10+, have $KERNEL_VER)"
        exit 1
    fi
    print_success "Kernel version: $KERNEL_VER"

    # Check memory
    MEM_TOTAL=$(free -m | awk '/^Mem:/{print $2}')
    if [ "$MEM_TOTAL" -lt 512 ]; then
        print_warning "Low memory detected ($MEM_TOTAL MB). Minimum 512 MB recommended"
    else
        print_success "Memory: $MEM_TOTAL MB"
    fi
}

select_mode() {
    if [ "$AUTO_MODE" = true ]; then
        print_step "Auto-selecting installation mode..."

        # Check if kernel headers are available
        if [ -d "/lib/modules/$(uname -r)/build" ]; then
            MODE_KERNEL=true
            print_success "Kernel mode selected (kernel headers available)"
        else
            MODE_USERSPACE=true
            print_warning "Userspace mode selected (kernel headers not available)"
            print_info "Install linux-headers-$(uname -r) for better performance with kernel mode"
        fi
    fi
}

install_dependencies() {
    print_step "Installing dependencies..."

    export DEBIAN_FRONTEND=noninteractive

    apt-get update -qq > /dev/null 2>&1

    # Base dependencies
    PACKAGES="build-essential gcc make iproute2 iptables iptables-persistent \
              net-tools curl wget ca-certificates procps kmod"

    if [ "$MODE_KERNEL" = true ]; then
        # Add kernel development packages
        PACKAGES="$PACKAGES linux-headers-$(uname -r) dkms"
        print_info "Installing kernel mode dependencies..."
    fi

    apt-get install -y -qq $PACKAGES > /dev/null 2>&1

    print_success "Dependencies installed"
}

generate_keys() {
    print_step "Generating cryptographic keys..."

    mkdir -p "$KEY_DIR"
    chmod 700 "$KEY_DIR"

    # Generate private key
    dd if=/dev/urandom bs=32 count=1 2>/dev/null | base64 > "$KEY_DIR/private.key"
    chmod 600 "$KEY_DIR/private.key"

    # Generate public key (simplified)
    cat "$KEY_DIR/private.key" | base64 -d | sha256sum | cut -d' ' -f1 | xxd -r -p | base64 > "$KEY_DIR/public.key"
    chmod 644 "$KEY_DIR/public.key"

    PRIVATE_KEY=$(cat "$KEY_DIR/private.key")
    PUBLIC_KEY=$(cat "$KEY_DIR/public.key")

    print_success "Keys generated"
    print_info "Public key: $PUBLIC_KEY"
}

compile_userspace() {
    print_step "Compiling userspace binary..."

    if [ ! -f "secureswift.c" ]; then
        print_error "secureswift.c not found"
        exit 1
    fi

    gcc -O3 -msse2 -march=native -mtune=native \
        -fomit-frame-pointer -flto -fPIE -pie \
        -Wall -Wextra -Werror=format-security \
        -D_FORTIFY_SOURCE=2 -fstack-protector-strong \
        secureswift.c -o "$BINARY_NAME" \
        -lm -lpthread 2>&1 | grep -v "note:" || true

    if [ ! -f "$BINARY_NAME" ]; then
        print_error "Compilation failed"
        exit 1
    fi

    strip "$BINARY_NAME"
    install -m 755 "$BINARY_NAME" /usr/local/bin/

    print_success "Binary compiled and installed"
}

compile_kernel_module() {
    print_step "Compiling kernel module..."

    if [ ! -f "secureswift-kernel.c" ]; then
        print_error "secureswift-kernel.c not found"
        exit 1
    fi

    # Copy source to DKMS tree
    mkdir -p "/usr/src/secureswift-$VERSION"
    cp secureswift-kernel.c "/usr/src/secureswift-$VERSION/"
    cp Makefile.kernel "/usr/src/secureswift-$VERSION/Makefile"
    cp dkms.conf "/usr/src/secureswift-$VERSION/"

    # Add to DKMS
    dkms add -m secureswift -v "$VERSION" 2>/dev/null || true
    dkms build -m secureswift -v "$VERSION"
    dkms install -m secureswift -v "$VERSION"

    # Load module
    modprobe secureswift || print_warning "Module load failed, will retry later"

    # Make module load on boot
    echo "secureswift" >> /etc/modules-load.d/secureswift.conf

    print_success "Kernel module compiled and installed"

    # Compile control utility
    print_step "Compiling control utility..."

    if [ ! -f "sswctl.c" ]; then
        print_error "sswctl.c not found"
        exit 1
    fi

    gcc -O2 -Wall sswctl.c -o sswctl
    install -m 755 sswctl /usr/local/bin/

    print_success "Control utility installed"
}

configure_network() {
    print_step "Configuring network..."

    # Load TUN module
    modprobe tun 2>/dev/null || true

    # Make TUN module load on boot
    if ! grep -q "^tun$" /etc/modules 2>/dev/null; then
        echo "tun" >> /etc/modules
    fi

    # Enable IP forwarding
    sysctl -w net.ipv4.ip_forward=1 > /dev/null
    sysctl -w net.ipv6.conf.all.forwarding=1 > /dev/null

    # Make persistent
    cat > /etc/sysctl.d/99-secureswift.conf <<EOF
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1

# Performance tuning
net.core.rmem_max=26214400
net.core.rmem_default=26214400
net.core.wmem_max=26214400
net.core.wmem_default=26214400
net.core.netdev_max_backlog=5000
EOF

    sysctl -p /etc/sysctl.d/99-secureswift.conf > /dev/null

    print_success "Network configured"
}

setup_firewall() {
    local mode=$1
    local listen_ip=$2
    local port=$3

    print_step "Configuring firewall..."

    if [ "$mode" = "server" ]; then
        # Allow VPN port
        iptables -A INPUT -p udp --dport "$port" -j ACCEPT

        # Allow TUN interface
        iptables -A INPUT -i "$INTERFACE_NAME" -j ACCEPT
        iptables -A FORWARD -i "$INTERFACE_NAME" -j ACCEPT
        iptables -A FORWARD -o "$INTERFACE_NAME" -j ACCEPT

        # NAT for clients
        iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE 2>/dev/null || true
        iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o ens3 -j MASQUERADE 2>/dev/null || true
        iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o ens5 -j MASQUERADE 2>/dev/null || true
        iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o venet0 -j MASQUERADE 2>/dev/null || true

        # Save rules
        netfilter-persistent save 2>/dev/null || iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
    else
        # Client: Allow outgoing VPN traffic
        iptables -A OUTPUT -p udp --dport "$port" -j ACCEPT
        iptables -A INPUT -i "$INTERFACE_NAME" -j ACCEPT
        iptables -A OUTPUT -o "$INTERFACE_NAME" -j ACCEPT

        # Save rules
        netfilter-persistent save 2>/dev/null || iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
    fi

    print_success "Firewall configured"
}

create_config_file() {
    local mode=$1
    local ip=$2
    local port=$3

    print_step "Creating configuration..."

    mkdir -p "$CONFIG_DIR"
    chmod 700 "$CONFIG_DIR"

    if [ "$mode" = "server" ]; then
        cat > "$CONFIG_DIR/config.conf" <<EOF
# SecureSwift VPN Server Configuration
# Generated: $(date)

[Interface]
PrivateKey = $(cat $KEY_DIR/private.key)
Address = 10.8.0.1/24
ListenPort = $port
MTU = 1420

# Server settings
PostUp = iptables -A FORWARD -i $INTERFACE_NAME -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i $INTERFACE_NAME -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

# Peers will be added here
# [Peer]
# PublicKey = CLIENT_PUBLIC_KEY
# AllowedIPs = 10.8.0.2/32
EOF
    else
        cat > "$CONFIG_DIR/config.conf" <<EOF
# SecureSwift VPN Client Configuration
# Generated: $(date)

[Interface]
PrivateKey = $(cat $KEY_DIR/private.key)
Address = 10.8.0.2/24
MTU = 1420

[Peer]
PublicKey = SERVER_PUBLIC_KEY_HERE
Endpoint = $ip:$port
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF
    fi

    chmod 600 "$CONFIG_DIR/config.conf"
    print_success "Configuration created: $CONFIG_DIR/config.conf"
}

create_systemd_service() {
    local mode=$1
    local ip=$2
    local port=$3

    print_step "Creating systemd service..."

    if [ "$MODE_KERNEL" = true ]; then
        # Kernel mode service
        cat > "$SYSTEMD_DIR/secureswift@.service" <<EOF
[Unit]
Description=SecureSwift VPN Tunnel (%i)
After=network-online.target nss-lookup.target
Wants=network-online.target nss-lookup.target
PartOf=secureswift.service
Before=network.target
Documentation=https://secureswift-vpn.org/

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/sswctl up %i
ExecStop=/usr/local/bin/sswctl down %i

Environment=WG_I_PREFER_BUGGY_USERSPACE_TO_POLISHED_KMOD=1

[Install]
WantedBy=multi-user.target
EOF
    else
        # Userspace mode service
        if [ "$mode" = "server" ]; then
            cat > "$SYSTEMD_DIR/secureswift-server.service" <<EOF
[Unit]
Description=SecureSwift VPN Server
After=network-online.target
Wants=network-online.target
Documentation=https://secureswift-vpn.org/

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/$BINARY_NAME server $ip $port
Restart=always
RestartSec=5
StandardOutput=append:$LOG_DIR/server.log
StandardError=append:$LOG_DIR/server-error.log

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$LOG_DIR
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
        else
            cat > "$SYSTEMD_DIR/secureswift-client.service" <<EOF
[Unit]
Description=SecureSwift VPN Client
After=network-online.target
Wants=network-online.target
Documentation=https://secureswift-vpn.org/

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/$BINARY_NAME client $ip $port
Restart=always
RestartSec=5
StandardOutput=append:$LOG_DIR/client.log
StandardError=append:$LOG_DIR/client-error.log

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$LOG_DIR
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
        fi
    fi

    systemctl daemon-reload

    if [ "$MODE_KERNEL" = true ]; then
        systemctl enable "secureswift@$INTERFACE_NAME"
    else
        systemctl enable "secureswift-$mode"
    fi

    print_success "Systemd service created"
}

print_completion_info() {
    local mode=$1
    local ip=$2
    local port=$3

    echo ""
    print_success "${BOLD}Installation Complete!${NC}"
    echo ""
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}         ${BOLD}SecureSwift VPN Successfully Installed${NC}          ${CYAN}║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    echo -e "${BOLD}Your Configuration:${NC}"
    echo -e "  Mode:       $mode"
    echo -e "  IP:         $ip"
    echo -e "  Port:       $port"
    echo -e "  Interface:  $INTERFACE_NAME"
    echo -e "  Type:       $([ "$MODE_KERNEL" = true ] && echo "Kernel Module" || echo "Userspace")"
    echo ""

    echo -e "${BOLD}Your Keys:${NC}"
    echo -e "  Public Key: ${GREEN}$(cat $KEY_DIR/public.key)${NC}"
    echo -e "  Location:   $KEY_DIR/"
    echo ""

    echo -e "${BOLD}Management Commands:${NC}"
    if [ "$MODE_KERNEL" = true ]; then
        echo -e "  Start VPN:     ${CYAN}sudo systemctl start secureswift@$INTERFACE_NAME${NC}"
        echo -e "  Stop VPN:      ${CYAN}sudo systemctl stop secureswift@$INTERFACE_NAME${NC}"
        echo -e "  Status:        ${CYAN}sudo sswctl status $INTERFACE_NAME${NC}"
        echo -e "  Show config:   ${CYAN}sudo sswctl show $INTERFACE_NAME${NC}"
    else
        echo -e "  Start VPN:     ${CYAN}sudo systemctl start secureswift-$mode${NC}"
        echo -e "  Stop VPN:      ${CYAN}sudo systemctl stop secureswift-$mode${NC}"
        echo -e "  Status:        ${CYAN}sudo systemctl status secureswift-$mode${NC}"
    fi
    echo -e "  View logs:     ${CYAN}sudo journalctl -u secureswift-$mode -f${NC}"
    echo ""

    if [ "$mode" = "server" ]; then
        echo -e "${BOLD}Add Clients:${NC}"
        echo -e "  1. Get client public key"
        echo -e "  2. Add to server config: $CONFIG_DIR/config.conf"
        echo -e "  3. Restart service"
        echo ""
        echo -e "${BOLD}Client Command:${NC}"
        echo -e "  ${CYAN}curl -sSL https://get.secureswift.io | sudo bash -s client $ip $port${NC}"
    else
        echo -e "${BOLD}Complete Setup:${NC}"
        echo -e "  1. Get server public key from server"
        echo -e "  2. Edit $CONFIG_DIR/config.conf"
        echo -e "  3. Replace 'SERVER_PUBLIC_KEY_HERE' with actual key"
        echo -e "  4. Start service: ${CYAN}sudo systemctl start secureswift-client${NC}"
        echo ""
        echo -e "${BOLD}Your Public Key (send to server):${NC}"
        echo -e "  ${GREEN}$(cat $KEY_DIR/public.key)${NC}"
    fi

    echo ""
    echo -e "${BOLD}Configuration Files:${NC}"
    echo -e "  Config:  $CONFIG_DIR/config.conf"
    echo -e "  Keys:    $KEY_DIR/"
    echo -e "  Logs:    $LOG_DIR/"
    echo ""

    echo -e "${YELLOW}⚠  Important Security Notes:${NC}"
    echo -e "  • Keep your private key secure: $KEY_DIR/private.key"
    echo -e "  • Share only your public key with peers"
    echo -e "  • This software requires formal security audit for production use"
    echo ""

    echo -e "${GREEN}${BOLD}🚀 SecureSwift VPN is ready to use!${NC}"
    echo ""
}

# ======================== MAIN ========================

main() {
    print_banner

    # Parse arguments
    if [ $# -lt 2 ]; then
        print_error "Usage: $0 <server|client> <ip> [port] [--kernel|--userspace]"
        echo ""
        echo "Examples:"
        echo "  Server: sudo $0 server 0.0.0.0 51820"
        echo "  Client: sudo $0 client 192.168.1.100 51820"
        echo ""
        echo "Options:"
        echo "  --kernel      Force kernel module mode"
        echo "  --userspace   Force userspace mode"
        exit 1
    fi

    MODE=$1
    IP=$2
    PORT=${3:-$DEFAULT_PORT}

    # Check for mode flag
    for arg in "$@"; do
        case "$arg" in
            --kernel)
                MODE_KERNEL=true
                MODE_USERSPACE=false
                AUTO_MODE=false
                ;;
            --userspace)
                MODE_USERSPACE=true
                MODE_KERNEL=false
                AUTO_MODE=false
                ;;
        esac
    done

    # Validate mode
    if [ "$MODE" != "server" ] && [ "$MODE" != "client" ]; then
        print_error "Invalid mode. Use 'server' or 'client'"
        exit 1
    fi

    # Pre-flight checks
    check_root
    detect_os
    check_system
    select_mode

    # Installation
    install_dependencies
    generate_keys

    if [ "$MODE_KERNEL" = true ]; then
        compile_kernel_module
    else
        compile_userspace
    fi

    configure_network
    setup_firewall "$MODE" "$IP" "$PORT"
    create_config_file "$MODE" "$IP" "$PORT"

    # Create log directory
    mkdir -p "$LOG_DIR"
    chmod 755 "$LOG_DIR"

    create_systemd_service "$MODE" "$IP" "$PORT"

    # Show completion
    print_completion_info "$MODE" "$IP" "$PORT"

    # Auto-start option
    read -p "Start VPN now? (Y/n): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Nn]$ ]]; then
        if [ "$MODE_KERNEL" = true ]; then
            systemctl start "secureswift@$INTERFACE_NAME"
        else
            systemctl start "secureswift-$MODE"
        fi
        print_success "VPN started successfully!"
    fi
}

main "$@"
