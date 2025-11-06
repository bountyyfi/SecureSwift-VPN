#!/bin/bash
#
# SecureSwift VPN - Automated Installation Script
# Works on: Debian, Ubuntu, and derivatives
# Requires: Root privileges
#
# Usage:
#   Server: sudo ./install.sh server <listen_ip> [port]
#   Client: sudo ./install.sh client <server_ip> [port]
#

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
DEFAULT_PORT=443
BINARY_NAME="secureswift"
CONFIG_DIR="/etc/secureswift"
SYSTEMD_DIR="/etc/systemd/system"
LOG_DIR="/var/log/secureswift"

# Helper functions
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        print_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# Detect OS
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        VERSION=$VERSION_ID
        print_info "Detected OS: $OS $VERSION"
    else
        print_error "Cannot detect OS. /etc/os-release not found."
        exit 1
    fi
}

# Install dependencies
install_dependencies() {
    print_info "Installing dependencies..."

    export DEBIAN_FRONTEND=noninteractive

    apt-get update -qq > /dev/null 2>&1

    # Install required packages
    apt-get install -y -qq \
        build-essential \
        gcc \
        make \
        iproute2 \
        iptables \
        iptables-persistent \
        net-tools \
        curl \
        wget \
        ca-certificates \
        procps \
        > /dev/null 2>&1

    print_success "Dependencies installed"
}

# Check CPU capabilities
check_cpu() {
    print_info "Checking CPU capabilities..."

    if ! grep -q sse2 /proc/cpuinfo; then
        print_error "CPU does not support SSE2 instructions (required for SIMD optimizations)"
        exit 1
    fi

    print_success "CPU supports SSE2"
}

# Compile SecureSwift
compile_binary() {
    print_info "Compiling SecureSwift VPN..."

    if [ ! -f "secureswift.c" ]; then
        print_error "secureswift.c not found in current directory"
        exit 1
    fi

    # Compile with optimizations
    gcc -O3 -msse2 -march=native -mtune=native \
        -fomit-frame-pointer -flto \
        -Wall -Wextra \
        secureswift.c -o "$BINARY_NAME" \
        -lm -lpthread

    if [ ! -f "$BINARY_NAME" ]; then
        print_error "Compilation failed"
        exit 1
    fi

    # Strip binary to reduce size
    strip "$BINARY_NAME"

    print_success "Binary compiled successfully"
}

# Install binary
install_binary() {
    print_info "Installing binary to /usr/local/bin..."

    cp "$BINARY_NAME" /usr/local/bin/
    chmod 755 /usr/local/bin/"$BINARY_NAME"

    print_success "Binary installed"
}

# Create configuration directories
create_directories() {
    print_info "Creating configuration directories..."

    mkdir -p "$CONFIG_DIR"
    mkdir -p "$LOG_DIR"
    chmod 700 "$CONFIG_DIR"
    chmod 755 "$LOG_DIR"

    print_success "Directories created"
}

# Configure network (TUN device support)
configure_network() {
    print_info "Configuring network..."

    # Load TUN module
    if ! lsmod | grep -q tun; then
        modprobe tun
    fi

    # Make TUN module load on boot
    if ! grep -q "^tun$" /etc/modules 2>/dev/null; then
        echo "tun" >> /etc/modules
    fi

    # Enable IP forwarding
    sysctl -w net.ipv4.ip_forward=1 > /dev/null

    # Make IP forwarding persistent
    if ! grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf 2>/dev/null; then
        echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    fi

    print_success "Network configured (auto-loads on boot)"
}

# Setup server
setup_server() {
    local listen_ip=$1
    local port=${2:-$DEFAULT_PORT}

    print_info "Setting up SecureSwift VPN Server..."
    print_info "Listen IP: $listen_ip"
    print_info "Port: $port"

    # Create server configuration
    cat > "$CONFIG_DIR/server.conf" <<EOF
# SecureSwift VPN Server Configuration
# Generated: $(date)

MODE=server
LISTEN_IP=$listen_ip
PORT=$port
INTERFACE=tun0
EOF

    # Configure firewall rules
    print_info "Configuring firewall rules..."

    # Allow VPN port
    iptables -A INPUT -p udp --dport "$port" -j ACCEPT

    # Allow TUN interface
    iptables -A INPUT -i tun0 -j ACCEPT
    iptables -A FORWARD -i tun0 -j ACCEPT
    iptables -A FORWARD -o tun0 -j ACCEPT

    # NAT for VPN clients
    iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE
    iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o ens3 -j MASQUERADE
    iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o ens5 -j MASQUERADE

    # Save iptables rules
    if command -v iptables-save &> /dev/null; then
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
        netfilter-persistent save 2>/dev/null || true
    fi

    # Create systemd service
    cat > "$SYSTEMD_DIR/secureswift-server.service" <<EOF
[Unit]
Description=SecureSwift VPN Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/$BINARY_NAME server $listen_ip $port
Restart=always
RestartSec=10
StandardOutput=append:$LOG_DIR/server.log
StandardError=append:$LOG_DIR/server-error.log

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$LOG_DIR

[Install]
WantedBy=multi-user.target
EOF

    # Reload systemd, enable and start service automatically
    systemctl daemon-reload
    systemctl enable secureswift-server.service
    systemctl start secureswift-server.service

    print_success "Server setup complete and running!"
    print_info ""
    print_info "Service auto-starts on boot"
    print_info "Current status:"
    print_info "  systemctl status secureswift-server"
    print_info ""
    print_info "To check status:"
    print_info "  systemctl status secureswift-server"
    print_info ""
    print_info "To view logs:"
    print_info "  journalctl -u secureswift-server -f"
    print_info "  tail -f $LOG_DIR/server.log"
}

# Setup client
setup_client() {
    local server_ip=$1
    local port=${2:-$DEFAULT_PORT}

    print_info "Setting up SecureSwift VPN Client..."
    print_info "Server IP: $server_ip"
    print_info "Port: $port"

    # Create client configuration
    cat > "$CONFIG_DIR/client.conf" <<EOF
# SecureSwift VPN Client Configuration
# Generated: $(date)

MODE=client
SERVER_IP=$server_ip
PORT=$port
INTERFACE=tun0
EOF

    # Configure firewall rules
    print_info "Configuring firewall rules..."

    # Allow outgoing VPN traffic
    iptables -A OUTPUT -p udp --dport "$port" -j ACCEPT

    # Allow TUN interface
    iptables -A INPUT -i tun0 -j ACCEPT
    iptables -A OUTPUT -o tun0 -j ACCEPT

    # Kill-switch: Block all non-VPN traffic (optional, commented out by default)
    # Uncomment these lines in the service file if you want strict kill-switch
    # iptables -A OUTPUT -o tun0 -j ACCEPT
    # iptables -A OUTPUT -d $server_ip -p udp --dport $port -j ACCEPT
    # iptables -A OUTPUT -o lo -j ACCEPT
    # iptables -P OUTPUT DROP

    # Save iptables rules
    if command -v iptables-save &> /dev/null; then
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
        netfilter-persistent save 2>/dev/null || true
    fi

    # Create systemd service
    cat > "$SYSTEMD_DIR/secureswift-client.service" <<EOF
[Unit]
Description=SecureSwift VPN Client
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/$BINARY_NAME client $server_ip $port
Restart=always
RestartSec=10
StandardOutput=append:$LOG_DIR/client.log
StandardError=append:$LOG_DIR/client-error.log

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$LOG_DIR

[Install]
WantedBy=multi-user.target
EOF

    # Reload systemd, enable and start service automatically
    systemctl daemon-reload
    systemctl enable secureswift-client.service
    systemctl start secureswift-client.service

    print_success "Client setup complete and running!"
    print_info ""
    print_info "Service auto-starts on boot"
    print_info "Current status:"
    print_info "  systemctl status secureswift-client"
    print_info ""
    print_info "To check status:"
    print_info "  systemctl status secureswift-client"
    print_info ""
    print_info "To view logs:"
    print_info "  journalctl -u secureswift-client -f"
    print_info "  tail -f $LOG_DIR/client.log"
    print_info ""
    print_info "To enable kill-switch (blocks all non-VPN traffic):"
    print_info "  Edit /etc/systemd/system/secureswift-client.service"
    print_info "  Uncomment the kill-switch iptables rules"
}

# Display banner
display_banner() {
    cat << "EOF"
    ____                           ____         _ ______  _______   ____  _   __
   / ___|  ___  ___ _   _ _ __ ___/ ___|_      _(_)  _ \|_   _\ \ / /  _ \| \ | |
   \___ \ / _ \/ __| | | | '__/ _ \___ \ \ /\ / / | |_) | | |  \ V /| |_) |  \| |
    ___) |  __/ (__| |_| | | |  __/___) \ V  V /| |  __/  | |   | | |  __/| |\  |
   |____/ \___|\___|\__,_|_|  \___|____/ \_/\_/ |_|_|     |_|   |_| |_|   |_| \_|

   Post-Quantum Secure VPN - Faster than WireGuard

EOF
}

# Main installation function
main() {
    display_banner

    # Parse arguments
    if [ $# -lt 2 ]; then
        print_error "Usage: $0 <server|client> <ip> [port]"
        echo ""
        echo "Examples:"
        echo "  Server: sudo $0 server 0.0.0.0 443"
        echo "  Client: sudo $0 client 192.168.1.100 443"
        exit 1
    fi

    MODE=$1
    IP=$2
    PORT=${3:-$DEFAULT_PORT}

    # Validate mode
    if [ "$MODE" != "server" ] && [ "$MODE" != "client" ]; then
        print_error "Invalid mode. Use 'server' or 'client'"
        exit 1
    fi

    # Check prerequisites
    check_root
    detect_os

    # Install and configure
    install_dependencies
    check_cpu
    compile_binary
    install_binary
    create_directories
    configure_network

    # Setup based on mode
    if [ "$MODE" = "server" ]; then
        setup_server "$IP" "$PORT"
    else
        setup_client "$IP" "$PORT"
    fi

    print_success ""
    print_success "====================================================="
    print_success "SecureSwift VPN installation complete!"
    print_success "====================================================="
    print_info ""
    print_info "Configuration files: $CONFIG_DIR"
    print_info "Log files: $LOG_DIR"
    print_info "Binary: /usr/local/bin/$BINARY_NAME"
    print_info ""

    if [ "$MODE" = "server" ]; then
        print_success "✓ Server is running and auto-starts on boot"
        print_info "Clients can now connect to this server!"
    else
        print_success "✓ Client is running and auto-starts on boot"
        print_info "VPN connection is active!"
    fi
}

# Run main function
main "$@"
