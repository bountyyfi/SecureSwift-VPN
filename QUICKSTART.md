# SecureSwift VPN - Quick Start Guide

Get your enterprise-grade VPN running in **30 seconds** with **one command**.

---

## 🚀 Installation

### Option 1: One-Line Installation (Recommended)

#### Server:
```bash
curl -fsSL https://raw.githubusercontent.com/bountyyfi/SecureSwift-VPN/main/install.sh | \
  sudo bash -s server 0.0.0.0 443
```

#### Client:
```bash
curl -fsSL https://raw.githubusercontent.com/bountyyfi/SecureSwift-VPN/main/install.sh | \
  sudo bash -s client SERVER_IP 443
```

**Replace:**
- `0.0.0.0` with your server's public IP (or keep 0.0.0.0 to listen on all interfaces)
- `SERVER_IP` with your VPN server's IP address
- `443` with your desired port (default: 443 for HTTPS stealth)

---

### Option 2: Manual Installation

#### 1. Clone Repository
```bash
git clone https://github.com/bountyyfi/SecureSwift-VPN.git
cd SecureSwift-VPN
```

#### 2. Install Server
```bash
sudo ./install.sh server 0.0.0.0 443
```

#### 3. Install Client (on client machine)
```bash
sudo ./install.sh client SERVER_IP 443
```

---

## ✅ What Happens Automatically

### During Installation:
1. ✅ Installs dependencies (gcc, make, iptables, etc.)
2. ✅ Compiles SecureSwift binary with optimizations
3. ✅ Configures **extreme kernel tuning** (BBR, 512MB buffers, 10M connections)
4. ✅ Sets up **DDoS protection** firewall rules
5. ✅ Creates systemd service with **realtime priority**
6. ✅ Enables **health checks** (every 30s)
7. ✅ Starts **Prometheus metrics** endpoint (:9100)
8. ✅ Configures **auto-start on boot**
9. ✅ Starts VPN service immediately

### Server Gets:
- ✅ VPN server running on specified port
- ✅ DDoS protection (rate limiting + SYN flood defense)
- ✅ Auto-restart on failure
- ✅ Health monitoring every 30s
- ✅ Prometheus metrics on port 9100
- ✅ Firewall NAT configuration
- ✅ 10Gbps+ performance tuning

### Client Gets:
- ✅ VPN client connected to server
- ✅ **Kill-switch** (blocks all non-VPN traffic)
- ✅ DNS leak protection
- ✅ Auto-reconnect on failure
- ✅ Health monitoring every 30s
- ✅ 10Gbps+ performance tuning

---

## 🎯 Quick Examples

### AWS EC2
```bash
# On server
curl -fsSL https://raw.githubusercontent.com/bountyyfi/SecureSwift-VPN/main/install.sh | \
  sudo bash -s server $(curl -s ifconfig.me) 443

# On client
curl -fsSL https://raw.githubusercontent.com/bountyyfi/SecureSwift-VPN/main/install.sh | \
  sudo bash -s client <EC2_PUBLIC_IP> 443
```

### DigitalOcean Droplet
```bash
# On server
curl -fsSL https://raw.githubusercontent.com/bountyyfi/SecureSwift-VPN/main/install.sh | \
  sudo bash -s server $(curl -s ifconfig.me) 443

# On client
curl -fsSL https://raw.githubusercontent.com/bountyyfi/SecureSwift-VPN/main/install.sh | \
  sudo bash -s client <DROPLET_IP> 443
```

### Local Testing (2 VMs)
```bash
# On server VM (192.168.1.100)
sudo ./install.sh server 192.168.1.100 51820

# On client VM
sudo ./install.sh client 192.168.1.100 51820
```

---

## 📊 Verify Installation

### Check Service Status

#### Server:
```bash
# Service status
systemctl status secureswift-server

# Health check timer
systemctl status secureswift-healthcheck.timer

# View logs
journalctl -u secureswift-server -f

# Check metrics
curl http://localhost:9100/metrics
```

#### Client:
```bash
# Service status
systemctl status secureswift-client

# Health check timer
systemctl status secureswift-client-healthcheck.timer

# View logs
journalctl -u secureswift-client -f

# Verify kill-switch
iptables -L -n -v
```

### Check Network Interface
```bash
# Check TUN interface
ip addr show tun0

# Check routing
ip route

# Test connectivity through VPN
ping -I tun0 8.8.8.8
```

### Check Performance
```bash
# Connection stats
ss -u sport = :443

# Interface stats
cat /sys/class/net/tun0/statistics/rx_bytes
cat /sys/class/net/tun0/statistics/tx_bytes

# Kernel tuning verification
sysctl net.ipv4.tcp_congestion_control  # Should be "bbr"
sysctl net.core.rmem_max                # Should be 536870912
```

---

## 🛠️ Management Commands

### Server

#### Start/Stop/Restart
```bash
sudo systemctl start secureswift-server
sudo systemctl stop secureswift-server
sudo systemctl restart secureswift-server
```

#### Enable/Disable Auto-Start
```bash
sudo systemctl enable secureswift-server   # Already done by installer
sudo systemctl disable secureswift-server
```

#### View Logs
```bash
# Live logs
sudo journalctl -u secureswift-server -f

# Recent logs
sudo tail -f /var/log/secureswift/server.log

# Error logs
sudo tail -f /var/log/secureswift/server-error.log
```

#### Monitor Metrics
```bash
# View all metrics
curl http://localhost:9100/metrics

# Watch specific metric
watch -n 1 'curl -s http://localhost:9100/metrics | grep secureswift_rx_bytes'
```

### Client

#### Start/Stop/Restart
```bash
sudo systemctl start secureswift-client
sudo systemctl stop secureswift-client
sudo systemctl restart secureswift-client
```

#### View Logs
```bash
# Live logs
sudo journalctl -u secureswift-client -f

# Recent logs
sudo tail -f /var/log/secureswift/client.log
```

#### Check Kill-Switch
```bash
# View firewall rules
sudo iptables -L -n -v

# Check default policies (should be DROP)
sudo iptables -L -n | grep policy
```

---

## 🔧 Configuration

### Change VPN Port

#### Server:
```bash
# Stop service
sudo systemctl stop secureswift-server

# Edit service file
sudo vim /etc/systemd/system/secureswift-server.service
# Change port in ExecStart line

# Update firewall
sudo iptables -D INPUT -p udp --dport OLD_PORT -j VPN_RATELIMIT
sudo iptables -A INPUT -p udp --dport NEW_PORT -j VPN_RATELIMIT
sudo iptables-save > /etc/iptables/rules.v4

# Reload and restart
sudo systemctl daemon-reload
sudo systemctl start secureswift-server
```

#### Client:
```bash
# Stop service
sudo systemctl stop secureswift-client

# Edit service file
sudo vim /etc/systemd/system/secureswift-client.service
# Change port in ExecStart line

# Reload and restart
sudo systemctl daemon-reload
sudo systemctl start secureswift-client
```

### Adjust Performance

The installer already configures extreme performance tuning. To modify:

```bash
# Edit kernel parameters
sudo vim /etc/sysctl.d/99-secureswift-extreme.conf

# Apply changes
sudo sysctl -p /etc/sysctl.d/99-secureswift-extreme.conf
```

---

## 🚨 Troubleshooting

### Service Won't Start

```bash
# Check service status
sudo systemctl status secureswift-server

# View detailed logs
sudo journalctl -u secureswift-server -n 100 --no-pager

# Check if port is available
sudo ss -ulnp | grep :443

# Verify binary exists
ls -l /usr/local/bin/secureswift
```

### No Connectivity

```bash
# Check interface
ip link show tun0

# Check routing
ip route

# Check firewall
sudo iptables -L -n -v

# Check if service is running
sudo systemctl is-active secureswift-server
```

### Kill-Switch Blocking Everything (Client)

If you need to disable kill-switch temporarily:

```bash
# Flush iptables (TEMPORARY - will reset on reboot)
sudo iptables -P INPUT ACCEPT
sudo iptables -P OUTPUT ACCEPT
sudo iptables -P FORWARD ACCEPT
sudo iptables -F

# Restart client to re-enable kill-switch
sudo systemctl restart secureswift-client
```

### Health Checks Failing

```bash
# Check health check timer
sudo systemctl status secureswift-healthcheck.timer

# Manually run health check
sudo /usr/local/bin/secureswift-healthcheck.sh

# View health check logs
sudo journalctl -u secureswift-healthcheck -n 50
```

---

## 📈 Monitoring & Metrics

### Prometheus Integration

Add to your Prometheus config:

```yaml
scrape_configs:
  - job_name: 'secureswift'
    static_configs:
      - targets: ['SERVER_IP:9100']
```

### Grafana Dashboard

Useful queries:

```promql
# Throughput (bytes/sec)
rate(secureswift_rx_bytes[5m])
rate(secureswift_tx_bytes[5m])

# Packet rate
rate(secureswift_rx_packets[5m])
rate(secureswift_tx_packets[5m])

# Uptime
secureswift_uptime_seconds

# Service health
secureswift_service_up
secureswift_interface_up

# Active connections
secureswift_connections_total
```

---

## 🗑️ Uninstall

```bash
# Run uninstall script
sudo ./uninstall.sh

# Or manually:
sudo systemctl stop secureswift-server  # or secureswift-client
sudo systemctl disable secureswift-server
sudo rm -f /usr/local/bin/secureswift
sudo rm -rf /etc/secureswift
sudo rm -rf /var/log/secureswift
sudo rm -f /etc/systemd/system/secureswift-*
sudo systemctl daemon-reload
```

---

## 🎓 Next Steps

- **[DEPLOYMENT.md](DEPLOYMENT.md)** - Production deployment best practices
- **[PRODUCTION-STATUS.md](PRODUCTION-STATUS.md)** - Production readiness checklist
- **[README.md](README.md)** - Full feature documentation

---

## 💡 Tips

### Performance
- Use port 443 for better firewall compatibility
- Enable hardware offloading on network interfaces
- Consider using dedicated VPN server (not shared hosting)

### Security
- Keep server firewall updated
- Monitor health check logs regularly
- Review metrics for suspicious activity
- Update SecureSwift regularly

### Operations
- Set up log rotation for `/var/log/secureswift/`
- Configure alerting on Prometheus metrics
- Test fail-over scenarios regularly
- Document your specific configuration

---

**Need help? Open an issue on GitHub!**
