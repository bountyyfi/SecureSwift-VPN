# SecureSwift VPN Performance Benchmark

Comprehensive performance testing suite for SecureSwift VPN.

## What It Tests

1. **Latency** - ICMP ping tests (min/avg/max)
2. **TCP Throughput (Single Stream)** - Maximum single connection speed
3. **TCP Throughput (Parallel)** - 10 concurrent connections
4. **UDP Throughput** - Maximum UDP speed with jitter and packet loss
5. **Reverse Throughput** - Server to client performance
6. **System Resources** - CPU, memory, and network interface stats

## Requirements

Install required tools:
```bash
sudo apt-get install iperf3 bc
```

## Usage

### On VPN Server

Start the benchmark server:
```bash
./benchmark.sh server
```

This starts an iperf3 server on port 5201.

### On VPN Client

Run benchmarks against the server:
```bash
./benchmark.sh client <SERVER_IP>
```

Example:
```bash
./benchmark.sh client 192.168.1.100
```

## What You'll See

### Latency Test
- Minimum latency
- Average latency
- Maximum latency
- Packet loss percentage

**Expected Results:**
- **Excellent**: <1ms average latency
- **Good**: <5ms average latency
- **Fair**: <20ms average latency
- **Poor**: >20ms average latency

### TCP Throughput (Single Stream)
- Maximum throughput for a single TCP connection

**Expected Results:**
- **Excellent**: >5 Gbps
- **Good**: >1 Gbps
- **Fair**: >500 Mbps
- **Poor**: <500 Mbps

### TCP Throughput (Parallel)
- Maximum throughput with 10 concurrent TCP connections
- Tests ability to handle multiple streams

### UDP Throughput
- Maximum UDP speed
- Jitter (variation in latency)
- Packet loss percentage

### Reverse Throughput
- Server to client download speed
- Verifies bidirectional performance

### System Resources
- Current CPU usage
- Memory usage
- tun0 interface RX/TX statistics

## Output

Results are displayed on screen AND saved to:
```
/tmp/secureswift-benchmark-YYYYMMDD-HHMMSS.txt
```

Example output:
```
═══════════════════════════════════════════════════════════
  Test 1: Latency (ICMP Ping)
═══════════════════════════════════════════════════════════

Latency Results:
  Min latency:     0.321 ms
  Avg latency:     0.845 ms
  Max latency:     2.103 ms
  Packet loss:     0%

═══════════════════════════════════════════════════════════
  Test 2: TCP Throughput (Single Stream)
═══════════════════════════════════════════════════════════

TCP Throughput (Single Stream):
  Throughput:      8.95 Gbps (8950 Mbps)

═══════════════════════════════════════════════════════════
  Benchmark Summary
═══════════════════════════════════════════════════════════

Performance Ratings:
  Latency:         EXCELLENT (<1ms)
  Throughput:      EXCELLENT (>5 Gbps)
```

## Comparing with WireGuard/OpenVPN

To compare SecureSwift with other VPN solutions:

### 1. Baseline Test (No VPN)
```bash
# On server
iperf3 -s

# On client
./benchmark.sh client <SERVER_IP>
```

### 2. Test with SecureSwift VPN
```bash
# Connect to SecureSwift VPN first
sudo systemctl start secureswift-client

# Run benchmark through VPN
./benchmark.sh client <VPN_SERVER_IP>
```

### 3. Test with WireGuard (for comparison)
```bash
# Connect to WireGuard
sudo wg-quick up wg0

# Run benchmark
./benchmark.sh client <WG_SERVER_IP>
```

### 4. Test with OpenVPN (for comparison)
```bash
# Connect to OpenVPN
sudo openvpn --config client.ovpn

# Run benchmark
./benchmark.sh client <OVPN_SERVER_IP>
```

## Expected Performance Targets

Based on our enterprise tuning (BBR, 512MB buffers, 10M connections):

| Metric | SecureSwift Target | WireGuard | OpenVPN |
|--------|-------------------|-----------|---------|
| **Latency** | <1ms | ~2ms | ~20ms |
| **TCP Throughput** | 10+ Gbps | ~5 Gbps | ~500 Mbps |
| **UDP Throughput** | 10+ Gbps | ~5 Gbps | ~400 Mbps |
| **Parallel Streams** | 10+ Gbps | ~5 Gbps | ~500 Mbps |
| **CPU Usage** | Low (SIMD) | Medium | High (userspace) |

## Troubleshooting

### iperf3 server won't start
```bash
# Check if port 5201 is already in use
sudo ss -tlnp | grep 5201

# Kill existing iperf3 processes
sudo killall iperf3
```

### Cannot reach server
```bash
# Check VPN is running
systemctl status secureswift-client

# Check tun0 interface
ip addr show tun0

# Verify routing
ip route
```

### Low throughput
```bash
# Check kernel tuning is applied
sysctl net.ipv4.tcp_congestion_control  # Should be "bbr"
sysctl net.core.rmem_max                # Should be 536870912

# Check CPU affinity
ps -eo pid,comm,psr | grep secureswift

# Check for packet loss
ping -I tun0 <SERVER_IP>
```

### High latency
```bash
# Check CPU scheduling priority
ps -eo pid,comm,rtprio | grep secureswift  # Should show 99

# Check for CPU throttling
cat /proc/cpuinfo | grep MHz

# Monitor system load
top
```

## Advanced Testing

### Long Duration Test
```bash
# Modify BENCHMARK_DURATION in benchmark.sh
vim benchmark.sh
# Change: BENCHMARK_DURATION=300  # 5 minutes
```

### Custom iperf3 Tests
```bash
# Test with specific window size
iperf3 -c <SERVER_IP> -w 512M -t 60

# Test with multiple parallel streams
iperf3 -c <SERVER_IP> -P 20 -t 60

# Test UDP with specific bandwidth
iperf3 -c <SERVER_IP> -u -b 10G -t 60
```

## Interpreting Results

### What "Good" Looks Like

For a **10Gbps network** with SecureSwift:
- Latency: <1ms average
- TCP single stream: 8-9.5 Gbps
- TCP parallel: 9-10 Gbps
- UDP: 9-10 Gbps
- Packet loss: <0.01%

For a **1Gbps network**:
- Latency: <2ms average
- TCP single stream: 900-980 Mbps
- TCP parallel: 950-980 Mbps
- UDP: 900-980 Mbps
- Packet loss: <0.1%

### What "Bad" Looks Like

Signs of problems:
- Latency >10ms on local network
- Throughput <50% of network capacity
- Packet loss >1%
- High CPU usage (>80%)
- Memory usage growing over time

## Automated Testing

Create a cron job to run benchmarks regularly:

```bash
# Add to crontab
0 2 * * * /path/to/benchmark.sh client <SERVER_IP> > /var/log/secureswift-benchmark-$(date +\%Y\%m\%d).log 2>&1
```

## Performance Monitoring Integration

### Grafana Dashboard

Import benchmark results into Grafana:

1. Parse the benchmark report file
2. Send metrics to Prometheus
3. Create Grafana dashboard with:
   - Latency trends over time
   - Throughput trends
   - Packet loss trends
   - System resource trends

### Alerting

Set up alerts for:
- Latency >5ms
- Throughput <1 Gbps
- Packet loss >0.1%
- CPU usage >90%

## Contributing

If you find ways to improve benchmark coverage, please submit a PR!

---

**Need help? Open an issue on GitHub!**
