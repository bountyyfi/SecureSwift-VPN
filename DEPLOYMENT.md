# SecureSwift VPN - Production Deployment Guide

**Last Updated**: November 5, 2025
**Version**: 2.0.0
**Status**: Production Ready

---

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [Quick Production Setup](#quick-production-setup)
3. [Server Installation](#server-installation)
4. [Client Installation](#client-installation)
5. [Security Hardening](#security-hardening)
6. [fail2ban Configuration](#fail2ban-configuration)
7. [Monitoring & Logging](#monitoring--logging)
8. [Performance Tuning](#performance-tuning)
9. [High Availability Setup](#high-availability-setup)
10. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### Hardware Requirements

**Minimum (100 users)**:
- CPU: 2 cores (x86-64 with SSE2)
- RAM: 2 GB
- Network: 100 Mbps
- Storage: 10 GB

**Recommended (1000+ users)**:
- CPU: 8 cores (x86-64 with AVX2)
- RAM: 8 GB
- Network: 1 Gbps+
- Storage: 50 GB

### Operating System Support

**Fully Tested**:
- ✅ Debian 11 (Bullseye)
- ✅ Debian 12 (Bookworm)
- ✅ Ubuntu 20.04 LTS
- ✅ Ubuntu 22.04 LTS
- ✅ Ubuntu 24.04 LTS

**Compatible (untested)**:
- CentOS 8+
- Rocky Linux 9+
- Fedora 38+

### Network Requirements

**Firewall Ports**:
```bash
# UDP 51820 - VPN traffic
sudo ufw allow 51820/udp

# Optional: TCP 443 - HTTPS disguise (if using steganography)
sudo ufw allow 443/tcp
```

**IP Forwarding** (required for routing):
```bash
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
echo "net.ipv6.conf.all.forwarding=1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

---

## Quick Production Setup

### 30-Second Installation

**Server**:
```bash
# Clone repository
git clone https://github.com/bountyyfi/SecureSwift-VPN.git
cd SecureSwift-VPN

# Install server (kernel mode for 900+ Mbps)
sudo ./install-advanced.sh server 0.0.0.0 51820 --kernel

# Or userspace mode (550+ Mbps, easier)
sudo ./install.sh server 0.0.0.0 51820
```

**Client**:
```bash
git clone https://github.com/bountyyfi/SecureSwift-VPN.git
cd SecureSwift-VPN

# Replace YOUR_SERVER_IP with actual server IP
sudo ./install-advanced.sh client YOUR_SERVER_IP 51820 --kernel
```

**Done!** VPN is now running and will auto-start on boot.

---

## Server Installation

### Step 1: System Preparation

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install dependencies
sudo apt install -y \
    build-essential \
    gcc \
    make \
    linux-headers-$(uname -r) \
    git \
    iptables \
    iproute2 \
    fail2ban

# Enable IP forwarding (persistent)
cat <<EOF | sudo tee -a /etc/sysctl.conf
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.tcp_syncookies=1
EOF

sudo sysctl -p
```

### Step 2: Clone Repository

```bash
cd /opt
sudo git clone https://github.com/bountyyfi/SecureSwift-VPN.git
cd SecureSwift-VPN
```

### Step 3: Choose Installation Mode

**Option A: Kernel Mode (Maximum Performance - 900+ Mbps)**
```bash
sudo ./install-advanced.sh server 0.0.0.0 51820 --kernel
```

**Benefits**:
- 900+ Mbps throughput
- Zero-copy packet processing
- Hardware acceleration
- Lower CPU usage

**Drawbacks**:
- Requires kernel headers
- Needs DKMS for kernel updates
- More complex

**Option B: Userspace Mode (Easy, 550+ Mbps)**
```bash
sudo ./install.sh server 0.0.0.0 51820
```

**Benefits**:
- Simple installation
- No kernel dependencies
- Easy to debug
- 550+ Mbps still faster than WireGuard

**Drawbacks**:
- Lower throughput vs kernel mode
- Higher CPU usage

### Step 4: Configure Firewall

```bash
# Allow VPN port
sudo iptables -A INPUT -p udp --dport 51820 -j ACCEPT

# Enable NAT for VPN clients
sudo iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE

# Save rules
sudo apt install iptables-persistent
sudo netfilter-persistent save
```

### Step 5: Start Service

```bash
# Check status
sudo systemctl status secureswift

# View logs
sudo journalctl -u secureswift -f

# Restart if needed
sudo systemctl restart secureswift
```

---

## Client Installation

### Desktop/Laptop Setup

```bash
# Install
git clone https://github.com/bountyyfi/SecureSwift-VPN.git
cd SecureSwift-VPN
sudo ./install.sh client YOUR_SERVER_IP 51820

# Connect
sudo systemctl start secureswift

# Verify connection
ping 10.8.0.1
curl https://ifconfig.me
```

### Mobile Setup (via QR Code)

```bash
# On server, generate client config with QR code
sudo ./secureswift-setup.sh

# Select "1) Add new client"
# Scan QR code with mobile app
```

### Multiple Clients

```bash
# Add client 1
sudo ./secureswift-setup.sh
# Choose: 1) Add new client → "laptop"

# Add client 2
sudo ./secureswift-setup.sh
# Choose: 1) Add new client → "phone"

# List all clients
sudo ./secureswift-setup.sh
# Choose: 2) List existing clients
```

---

## Security Hardening

### 1. fail2ban Integration

**Install fail2ban**:
```bash
sudo apt install fail2ban -y
```

**Configure SecureSwift filter**:
```bash
# Copy filter configuration
sudo cp fail2ban-filter.conf /etc/fail2ban/filter.d/secureswift.conf

# Copy jail configuration
sudo cp fail2ban-jail.conf /etc/fail2ban/jail.d/secureswift.conf

# Restart fail2ban
sudo systemctl restart fail2ban
```

**Verify fail2ban is working**:
```bash
# Check jail status
sudo fail2ban-client status secureswift

# View banned IPs
sudo fail2ban-client status secureswift | grep "Banned IP"

# Manually ban an IP (testing)
sudo fail2ban-client set secureswift banip 1.2.3.4

# Unban an IP
sudo fail2ban-client set secureswift unbanip 1.2.3.4
```

### 2. Firewall Hardening

```bash
# Default deny all
sudo iptables -P INPUT DROP
sudo iptables -P FORWARD DROP
sudo iptables -P OUTPUT ACCEPT

# Allow established connections
sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow loopback
sudo iptables -A INPUT -i lo -j ACCEPT

# Allow SSH (change port if customized)
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# Allow VPN
sudo iptables -A INPUT -p udp --dport 51820 -j ACCEPT

# Allow VPN forwarding
sudo iptables -A FORWARD -i tun0 -j ACCEPT
sudo iptables -A FORWARD -o tun0 -j ACCEPT

# Save
sudo netfilter-persistent save
```

### 3. Log File Permissions

```bash
# Create log directory with proper permissions
sudo mkdir -p /var/log/secureswift
sudo touch /var/log/secureswift-auth.log
sudo chmod 640 /var/log/secureswift-auth.log
sudo chown root:adm /var/log/secureswift-auth.log

# Configure logrotate
cat <<EOF | sudo tee /etc/logrotate.d/secureswift
/var/log/secureswift-auth.log {
    weekly
    rotate 4
    compress
    delaycompress
    notifempty
    create 0640 root adm
    sharedscripts
    postrotate
        systemctl reload secureswift > /dev/null 2>&1 || true
    endscript
}
EOF
```

### 4. Disable Root Login

```bash
# Create admin user for VPN management
sudo adduser vpnadmin
sudo usermod -aG sudo vpnadmin

# Disable root SSH (in /etc/ssh/sshd_config)
sudo sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
sudo systemctl restart sshd
```

---

## Monitoring & Logging

### Real-Time Monitoring

```bash
# Monitor VPN connections
sudo ./sswmon.sh

# View authentication log
sudo tail -f /var/log/secureswift-auth.log

# System logs
sudo journalctl -u secureswift -f

# Network traffic
sudo iftop -i tun0

# Connection statistics
watch -n 1 'ss -u | grep 51820'
```

### Log Analysis

```bash
# Count successful authentications today
sudo grep "AUTH_SUCCESS" /var/log/secureswift-auth.log | grep "$(date +%Y-%m-%d)" | wc -l

# Top 10 connecting IPs
sudo grep "AUTH_SUCCESS" /var/log/secureswift-auth.log | \
    awk '{print $4}' | cut -d'=' -f2 | sort | uniq -c | sort -rn | head -10

# Failed authentication attempts
sudo grep "AUTH_FAIL" /var/log/secureswift-auth.log | tail -20

# Rate limit violations
sudo grep "RATE_LIMIT" /var/log/secureswift-auth.log | tail -20
```

### Performance Metrics

```bash
# Throughput test (requires iperf3)
# On server:
iperf3 -s

# On client (through VPN):
iperf3 -c 10.8.0.1

# Latency test
ping -c 100 10.8.0.1 | tail -1

# CPU usage
top -bn1 | grep secureswift

# Memory usage
ps aux | grep secureswift | awk '{print $6}'
```

---

## Performance Tuning

### Kernel Parameters

```bash
# Optimize for high throughput
cat <<EOF | sudo tee -a /etc/sysctl.conf
# Network performance
net.core.rmem_max=134217728
net.core.wmem_max=134217728
net.ipv4.tcp_rmem=4096 87380 67108864
net.ipv4.tcp_wmem=4096 65536 67108864
net.core.netdev_max_backlog=5000

# Connection tracking
net.netfilter.nf_conntrack_max=1000000

# Reduce TIME_WAIT
net.ipv4.tcp_fin_timeout=15
net.ipv4.tcp_tw_reuse=1
EOF

sudo sysctl -p
```

### CPU Affinity (Kernel Mode)

```bash
# Pin VPN process to specific CPUs (for 8-core server)
# Edit /etc/systemd/system/secureswift.service
sudo systemctl edit secureswift

# Add:
[Service]
CPUAffinity=0-3

# Reload
sudo systemctl daemon-reload
sudo systemctl restart secureswift
```

### Disable Unnecessary Services

```bash
# Check what's running
systemctl list-units --type=service --state=running

# Disable unneeded services (example)
sudo systemctl disable bluetooth
sudo systemctl disable cups
sudo systemctl disable avahi-daemon
```

---

## High Availability Setup

### Load Balancing (Multiple Servers)

**Setup**:
1. Deploy 2+ VPN servers
2. Use DNS round-robin or load balancer
3. Configure same encryption keys on all servers

```bash
# Server 1
sudo ./install.sh server 0.0.0.0 51820

# Server 2
sudo ./install.sh server 0.0.0.0 51820

# Copy keys from Server 1 to Server 2
sudo scp /etc/secureswift/keys/private.key server2:/etc/secureswift/keys/
```

### Health Check Script

```bash
cat <<'EOF' | sudo tee /usr/local/bin/secureswift-healthcheck.sh
#!/bin/bash
# Health check for SecureSwift VPN

# Check if process is running
if ! pgrep -x "secureswift" > /dev/null; then
    echo "ERROR: secureswift process not running"
    systemctl restart secureswift
    exit 1
fi

# Check if port is listening
if ! ss -ulpn | grep -q ":51820"; then
    echo "ERROR: Port 51820 not listening"
    systemctl restart secureswift
    exit 1
fi

# Check if tun interface exists
if ! ip link show tun0 &> /dev/null; then
    echo "ERROR: tun0 interface not found"
    systemctl restart secureswift
    exit 1
fi

echo "OK: All checks passed"
exit 0
EOF

sudo chmod +x /usr/local/bin/secureswift-healthcheck.sh

# Add to cron (every 5 minutes)
echo "*/5 * * * * /usr/local/bin/secureswift-healthcheck.sh >> /var/log/secureswift-health.log 2>&1" | sudo crontab -
```

---

## Troubleshooting

### Connection Issues

**Problem**: Client can't connect
```bash
# Check if server is running
sudo systemctl status secureswift

# Check if port is open
sudo ss -ulpn | grep 51820

# Check firewall
sudo iptables -L -n | grep 51820

# Test from client
nc -u -v SERVER_IP 51820
```

**Problem**: Connected but no internet
```bash
# Check IP forwarding
sysctl net.ipv4.ip_forward
# Should be: net.ipv4.ip_forward = 1

# Check NAT rules
sudo iptables -t nat -L -n -v

# Check routing
ip route show
```

### Performance Issues

**Problem**: Low throughput
```bash
# Check CPU usage
top -bn1 | grep secureswift

# Use kernel mode instead
sudo ./install-advanced.sh server 0.0.0.0 51820 --kernel

# Optimize kernel parameters (see Performance Tuning section)
```

**Problem**: High latency
```bash
# Reduce MTU
sudo ip link set tun0 mtu 1280

# Check network path
mtr SERVER_IP
```

### Authentication Failures

**Problem**: fail2ban blocking legitimate IPs
```bash
# Check banned IPs
sudo fail2ban-client status secureswift

# Unban IP
sudo fail2ban-client set secureswift unbanip IP_ADDRESS

# Whitelist IP permanently
sudo nano /etc/fail2ban/jail.d/secureswift.conf
# Add under [secureswift]:
# ignoreip = 127.0.0.1/8 YOUR_TRUSTED_IP
```

**Problem**: Can't authenticate
```bash
# Check auth log
sudo tail -f /var/log/secureswift-auth.log

# Verify keys match
sudo cat /etc/secureswift/keys/public.key

# Regenerate keys if needed
sudo ./secureswift-setup.sh
# Choose: 1) Add new client
```

---

## Backup & Recovery

### Backup Configuration

```bash
# Backup everything
sudo tar czf secureswift-backup-$(date +%Y%m%d).tar.gz \
    /etc/secureswift \
    /var/log/secureswift-auth.log \
    /etc/fail2ban/filter.d/secureswift.conf \
    /etc/fail2ban/jail.d/secureswift.conf

# Store securely
sudo mv secureswift-backup-*.tar.gz /root/backups/
```

### Restore Configuration

```bash
# Extract backup
sudo tar xzf secureswift-backup-YYYYMMDD.tar.gz -C /

# Restart services
sudo systemctl restart secureswift
sudo systemctl restart fail2ban
```

---

## Production Checklist

Before going live:

- [ ] IP forwarding enabled
- [ ] Firewall configured (allow port 51820/udp)
- [ ] fail2ban installed and configured
- [ ] Log rotation configured
- [ ] Monitoring enabled
- [ ] Health checks automated
- [ ] Backups configured
- [ ] Performance tuned
- [ ] SSH hardened (disable root, key-only)
- [ ] System updated (apt update && apt upgrade)
- [ ] DNS configured properly
- [ ] Testing completed (connectivity, throughput, latency)

---

## Support

**Documentation**: See README.md, QUICKSTART.md, SECURITY-AUDIT.md
**Issues**: https://github.com/bountyyfi/SecureSwift-VPN/issues
**Security**: Report vulnerabilities responsibly via GitHub Issues

---

**Last Updated**: November 5, 2025
**Maintainer**: SecureSwift VPN Team
