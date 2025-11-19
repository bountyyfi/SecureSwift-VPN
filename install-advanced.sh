#!/bin/bash
#
# SecureSwift VPN - Advanced Installation Script with Kernel Module Support
# Works on: Debian, Ubuntu, and derivatives
# Requires: Root privileges
#
# Usage:
#   Server (userspace): sudo ./install-advanced.sh server <listen_ip> [port]
#   Client (userspace): sudo ./install-advanced.sh client <server_ip> [port]
#   Server (kernel):    sudo ./install-advanced.sh server <listen_ip> [port] --kernel
#   Client (kernel):    sudo ./install-advanced.sh client <server_ip> [port] --kernel
#

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Configuration
DEFAULT_PORT=51820
BINARY_NAME="secureswift"
KERNEL_BINARY="sswctl"
KERNEL_MODULE="secureswift-kernel"
CONFIG_DIR="/etc/secureswift"
SYSTEMD_DIR="/etc/systemd/system"
LOG_DIR="/var/log/secureswift"
KERNEL_MODE=0

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

print_banner() {
    echo -e "${PURPLE}"
    echo "=================================================="
    echo "  SecureSwift VPN - Advanced Installer"
    echo "  Post-Quantum Secure VPN with Kernel Acceleration"
    echo "=================================================="
    echo -e "${NC}"
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

    # Base packages
    local PACKAGES="build-essential gcc make iproute2 iptables iptables-persistent net-tools curl wget ca-certificates procps"

    # Add kernel development packages if kernel mode requested
    if [ "$KERNEL_MODE" -eq 1 ]; then
        print_info "Kernel mode enabled - installing kernel headers..."
        KERNEL_VERSION=$(uname -r)
        PACKAGES="$PACKAGES linux-headers-${KERNEL_VERSION} dkms"
    fi

    apt-get install -y -qq $PACKAGES > /dev/null 2>&1

    print_success "Dependencies installed"
}

# Check kernel compatibility
check_kernel() {
    if [ "$KERNEL_MODE" -eq 0 ]; then
        return
    fi

    print_info "Checking kernel compatibility..."

    KERNEL_VERSION=$(uname -r)
    MAJOR=$(echo $KERNEL_VERSION | cut -d. -f1)
    MINOR=$(echo $KERNEL_VERSION | cut -d. -f2)

    if [ "$MAJOR" -lt 4 ] || ([ "$MAJOR" -eq 4 ] && [ "$MINOR" -lt 4 ]); then
        print_error "Kernel version $KERNEL_VERSION is too old. Minimum required: 4.4"
        exit 1
    fi

    print_success "Kernel version $KERNEL_VERSION is compatible"
}

# Build userspace binary
build_userspace() {
    print_info "Building userspace VPN binary..."

    if [ ! -f "secureswift.c" ]; then
        print_error "Source file secureswift.c not found"
        exit 1
    fi

    gcc -O3 -march=native -mtune=native \
        -Wall -Wextra \
        -fstack-protector-strong \
        -fPIE -pie \
        -D_FORTIFY_SOURCE=2 \
        -Wl,-z,relro,-z,now \
        -o "$BINARY_NAME" secureswift.c \
        -lm -lpthread

    if [ ! -f "$BINARY_NAME" ]; then
        print_error "Build failed"
        exit 1
    fi

    print_success "Userspace binary built successfully"
}

# Build kernel module
build_kernel_module() {
    if [ "$KERNEL_MODE" -eq 0 ]; then
        return
    fi

    print_info "Building kernel module..."

    if [ ! -f "secureswift-kernel.c" ]; then
        print_error "Kernel module source not found"
        exit 1
    fi

    if [ ! -f "Makefile.kernel" ]; then
        print_error "Kernel Makefile not found"
        exit 1
    fi

    make -f Makefile.kernel clean > /dev/null 2>&1 || true
    make -f Makefile.kernel

    if [ ! -f "${KERNEL_MODULE}.ko" ]; then
        print_error "Kernel module build failed"
        exit 1
    fi

    print_success "Kernel module built successfully"

    # Build control utility
    print_info "Building kernel control utility..."

    if [ ! -f "sswctl.c" ]; then
        print_error "Control utility source not found"
        exit 1
    fi

    gcc -O2 -Wall -o "$KERNEL_BINARY" sswctl.c

    if [ ! -f "$KERNEL_BINARY" ]; then
        print_error "Control utility build failed"
        exit 1
    fi

    print_success "Control utility built successfully"
}

# Install binaries
install_binaries() {
    print_info "Installing binaries..."

    # Install userspace binary
    install -m 0755 "$BINARY_NAME" /usr/local/bin/
    print_success "Installed /usr/local/bin/$BINARY_NAME"

    # Install kernel module if built
    if [ "$KERNEL_MODE" -eq 1 ]; then
        # Install kernel module
        KERNEL_VERSION=$(uname -r)
        MODULE_DIR="/lib/modules/${KERNEL_VERSION}/extra"
        mkdir -p "$MODULE_DIR"
        install -m 0644 "${KERNEL_MODULE}.ko" "$MODULE_DIR/"
        depmod -a
        print_success "Installed kernel module to $MODULE_DIR"

        # Install control utility
        install -m 0755 "$KERNEL_BINARY" /usr/local/bin/
        print_success "Installed /usr/local/bin/$KERNEL_BINARY"

        # Setup DKMS for automatic rebuilds
        if command -v dkms > /dev/null 2>&1; then
            print_info "Setting up DKMS..."
            DKMS_DIR="/usr/src/${KERNEL_MODULE}-1.0"
            mkdir -p "$DKMS_DIR"
            cp secureswift-kernel.c "$DKMS_DIR/"
            cp Makefile.kernel "$DKMS_DIR/Makefile"

            cat > "$DKMS_DIR/dkms.conf" << EOF
PACKAGE_NAME="${KERNEL_MODULE}"
PACKAGE_VERSION="1.0"
BUILT_MODULE_NAME[0]="${KERNEL_MODULE}"
DEST_MODULE_LOCATION[0]="/extra"
AUTOINSTALL="yes"
EOF

            dkms add -m "${KERNEL_MODULE}" -v 1.0 || true
            dkms build -m "${KERNEL_MODULE}" -v 1.0 || true
            dkms install -m "${KERNEL_MODULE}" -v 1.0 || true
            print_success "DKMS configured"
        fi
    fi
}

# Create configuration directory
create_config() {
    print_info "Creating configuration..."

    mkdir -p "$CONFIG_DIR"
    mkdir -p "$LOG_DIR"

    # Create config file
    cat > "$CONFIG_DIR/config" << EOF
# SecureSwift VPN Configuration
MODE=$MODE
IP=$IP
PORT=$PORT
KERNEL_MODE=$KERNEL_MODE
CREATED=$(date)
EOF

    chmod 600 "$CONFIG_DIR/config"
    print_success "Configuration created"
}

# Create systemd service
create_systemd_service() {
    print_info "Creating systemd service..."

    local SERVICE_FILE="$SYSTEMD_DIR/secureswift.service"

    if [ "$KERNEL_MODE" -eq 1 ]; then
        # Kernel mode service
        cat > "$SERVICE_FILE" << EOF
[Unit]
Description=SecureSwift VPN (Kernel Mode)
After=network.target
Wants=network.target

[Service]
Type=forking
ExecStartPre=/sbin/modprobe ${KERNEL_MODULE}
ExecStart=/usr/local/bin/${KERNEL_BINARY} start --mode=$MODE --ip=$IP --port=$PORT
ExecStop=/usr/local/bin/${KERNEL_BINARY} stop
ExecStopPost=/sbin/modprobe -r ${KERNEL_MODULE}
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$LOG_DIR

[Install]
WantedBy=multi-user.target
EOF
    else
        # Userspace mode service
        cat > "$SERVICE_FILE" << EOF
[Unit]
Description=SecureSwift VPN (Userspace Mode)
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/${BINARY_NAME} $MODE $IP $PORT
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$LOG_DIR

[Install]
WantedBy=multi-user.target
EOF
    fi

    chmod 644 "$SERVICE_FILE"
    systemctl daemon-reload
    print_success "Systemd service created"
}

# Configure firewall
configure_firewall() {
    print_info "Configuring firewall..."

    # Allow VPN port
    iptables -A INPUT -p udp --dport "$PORT" -j ACCEPT || true

    # Save iptables rules
    if command -v netfilter-persistent > /dev/null 2>&1; then
        netfilter-persistent save > /dev/null 2>&1 || true
    elif command -v iptables-save > /dev/null 2>&1; then
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
    fi

    print_success "Firewall configured"
}

# Enable and start service
enable_service() {
    print_info "Enabling and starting service..."

    systemctl enable secureswift.service
    systemctl start secureswift.service

    print_success "Service enabled and started"
}

# Print completion message
print_completion() {
    echo ""
    print_success "Installation complete!"
    echo ""
    echo "Configuration:"
    echo "  Mode:        $MODE"
    echo "  IP:          $IP"
    echo "  Port:        $PORT"
    echo "  Kernel Mode: $([ "$KERNEL_MODE" -eq 1 ] && echo 'ENABLED' || echo 'DISABLED')"
    echo ""
    echo "Service management:"
    echo "  Status:  systemctl status secureswift"
    echo "  Start:   systemctl start secureswift"
    echo "  Stop:    systemctl stop secureswift"
    echo "  Restart: systemctl restart secureswift"
    echo "  Logs:    journalctl -u secureswift -f"
    echo ""
    if [ "$KERNEL_MODE" -eq 1 ]; then
        echo "Kernel module:"
        echo "  Load:    modprobe ${KERNEL_MODULE}"
        echo "  Unload:  modprobe -r ${KERNEL_MODULE}"
        echo "  Status:  lsmod | grep ${KERNEL_MODULE}"
        echo "  Control: ${KERNEL_BINARY} status"
        echo ""
    fi
}

# Parse arguments
parse_args() {
    if [ $# -lt 2 ]; then
        echo "Usage: $0 <server|client> <ip> [port] [--kernel]"
        echo ""
        echo "Examples:"
        echo "  Server (userspace): sudo $0 server 0.0.0.0 51820"
        echo "  Client (userspace): sudo $0 client 192.168.1.100 51820"
        echo "  Server (kernel):    sudo $0 server 0.0.0.0 51820 --kernel"
        echo "  Client (kernel):    sudo $0 client 192.168.1.100 51820 --kernel"
        exit 1
    fi

    MODE=$1
    IP=$2
    PORT=${3:-$DEFAULT_PORT}

    # Check for --kernel flag
    for arg in "$@"; do
        if [ "$arg" = "--kernel" ]; then
            KERNEL_MODE=1
            break
        fi
    done

    if [ "$MODE" != "server" ] && [ "$MODE" != "client" ]; then
        print_error "Invalid mode. Use 'server' or 'client'"
        exit 1
    fi
}

# Main installation flow
main() {
    print_banner
    parse_args "$@"
    check_root
    detect_os
    install_dependencies
    check_kernel
    build_userspace
    build_kernel_module
    install_binaries
    create_config
    create_systemd_service
    configure_firewall
    enable_service
    print_completion
}

# Run main
main "$@"
