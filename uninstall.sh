#!/bin/bash
#
# SecureSwift VPN - Uninstallation Script
# Removes all SecureSwift VPN components
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

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
if [ "$EUID" -ne 0 ]; then
    print_error "This script must be run as root (use sudo)"
    exit 1
fi

print_warning "This will completely remove SecureSwift VPN from your system."
read -p "Are you sure you want to continue? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    print_info "Uninstallation cancelled"
    exit 0
fi

print_info "Uninstalling SecureSwift VPN..."

# Stop and disable services
print_info "Stopping services..."
systemctl stop secureswift-server.service 2>/dev/null || true
systemctl stop secureswift-client.service 2>/dev/null || true
systemctl disable secureswift-server.service 2>/dev/null || true
systemctl disable secureswift-client.service 2>/dev/null || true

# Remove systemd service files
print_info "Removing systemd services..."
rm -f /etc/systemd/system/secureswift-server.service
rm -f /etc/systemd/system/secureswift-client.service
systemctl daemon-reload

# Remove binary
print_info "Removing binary..."
rm -f /usr/local/bin/secureswift

# Remove configuration and logs
print_info "Removing configuration and logs..."
rm -rf /etc/secureswift
rm -rf /var/log/secureswift

# Remove TUN interface if exists
print_info "Removing TUN interface..."
ip link delete tun0 2>/dev/null || true

# Optionally remove iptables rules (commented out for safety)
print_warning "Note: iptables rules were NOT removed automatically."
print_info "If you want to remove them, review and modify /etc/iptables/rules.v4"

print_success ""
print_success "SecureSwift VPN has been uninstalled successfully!"
print_info "Note: Dependencies (gcc, iptables, etc.) were NOT removed."
