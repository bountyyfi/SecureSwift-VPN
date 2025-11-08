#!/bin/bash
# SecureSwift VPN Performance Benchmark Script
# Tests throughput, latency, packet loss, and connection scalability
#
# Usage:
#   Server: ./benchmark.sh server
#   Client: ./benchmark.sh client <SERVER_IP>

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

MODE="$1"
SERVER_IP="${2:-127.0.0.1}"
BENCHMARK_DURATION=30  # seconds for throughput tests
LATENCY_COUNT=100      # number of ping packets
REPORT_FILE="/tmp/secureswift-benchmark-$(date +%Y%m%d-%H%M%S).txt"

print_header() {
    echo -e "\n${CYAN}${BOLD}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}${BOLD}  $1${NC}"
    echo -e "${CYAN}${BOLD}═══════════════════════════════════════════════════════════${NC}\n"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

# Check dependencies
check_dependencies() {
    print_header "Checking Dependencies"

    local missing=0

    if ! command -v iperf3 &> /dev/null; then
        print_error "iperf3 not found. Install: apt-get install iperf3"
        missing=1
    else
        print_success "iperf3 found"
    fi

    if ! command -v ping &> /dev/null; then
        print_error "ping not found"
        missing=1
    else
        print_success "ping found"
    fi

    if ! command -v bc &> /dev/null; then
        print_error "bc not found. Install: apt-get install bc"
        missing=1
    else
        print_success "bc found"
    fi

    if [ $missing -eq 1 ]; then
        print_error "Missing dependencies. Please install them first."
        exit 1
    fi
}

# Start benchmark server
start_server() {
    print_header "SecureSwift VPN Benchmark Server"

    print_info "Starting iperf3 server on port 5201..."
    iperf3 -s -p 5201 -D

    print_success "Benchmark server started"
    print_info "Clients can now connect with: ./benchmark.sh client <SERVER_IP>"
    print_info ""
    print_warning "To stop server: killall iperf3"
}

# Run client benchmarks
run_benchmarks() {
    print_header "SecureSwift VPN Performance Benchmark"

    echo -e "${BOLD}Date:${NC} $(date)" | tee "$REPORT_FILE"
    echo -e "${BOLD}Server IP:${NC} $SERVER_IP" | tee -a "$REPORT_FILE"
    echo "" | tee -a "$REPORT_FILE"

    # Test 1: Latency (ping)
    print_header "Test 1: Latency (ICMP Ping)"
    print_info "Running $LATENCY_COUNT ping tests..."

    PING_OUTPUT=$(ping -c $LATENCY_COUNT "$SERVER_IP" 2>&1)

    if [ $? -eq 0 ]; then
        AVG_LATENCY=$(echo "$PING_OUTPUT" | grep "rtt min/avg/max" | cut -d'/' -f5)
        MIN_LATENCY=$(echo "$PING_OUTPUT" | grep "rtt min/avg/max" | cut -d'/' -f4)
        MAX_LATENCY=$(echo "$PING_OUTPUT" | grep "rtt min/avg/max" | cut -d'/' -f6)
        PACKET_LOSS=$(echo "$PING_OUTPUT" | grep "packet loss" | awk '{print $6}')

        echo -e "${BOLD}Latency Results:${NC}" | tee -a "$REPORT_FILE"
        echo -e "  Min latency:     ${GREEN}${MIN_LATENCY} ms${NC}" | tee -a "$REPORT_FILE"
        echo -e "  Avg latency:     ${GREEN}${AVG_LATENCY} ms${NC}" | tee -a "$REPORT_FILE"
        echo -e "  Max latency:     ${GREEN}${MAX_LATENCY} ms${NC}" | tee -a "$REPORT_FILE"
        echo -e "  Packet loss:     ${GREEN}${PACKET_LOSS}${NC}" | tee -a "$REPORT_FILE"
        print_success "Latency test completed"
    else
        print_error "Latency test failed - cannot reach server"
        echo -e "${RED}Latency test FAILED${NC}" | tee -a "$REPORT_FILE"
    fi

    echo "" | tee -a "$REPORT_FILE"

    # Test 2: TCP Throughput (Single Stream)
    print_header "Test 2: TCP Throughput (Single Stream)"
    print_info "Running $BENCHMARK_DURATION second TCP test..."

    IPERF_TCP=$(iperf3 -c "$SERVER_IP" -p 5201 -t $BENCHMARK_DURATION -J 2>&1)

    if [ $? -eq 0 ]; then
        # Parse JSON output
        TCP_THROUGHPUT=$(echo "$IPERF_TCP" | grep -o '"bits_per_second":[0-9.]*' | head -1 | cut -d':' -f2)
        TCP_GBPS=$(echo "scale=2; $TCP_THROUGHPUT / 1000000000" | bc)
        TCP_MBPS=$(echo "scale=2; $TCP_THROUGHPUT / 1000000" | bc)

        echo -e "${BOLD}TCP Throughput (Single Stream):${NC}" | tee -a "$REPORT_FILE"
        echo -e "  Throughput:      ${GREEN}${TCP_GBPS} Gbps${NC} (${TCP_MBPS} Mbps)" | tee -a "$REPORT_FILE"
        print_success "TCP throughput test completed"
    else
        print_error "TCP throughput test failed"
        echo -e "${RED}TCP throughput test FAILED${NC}" | tee -a "$REPORT_FILE"
    fi

    echo "" | tee -a "$REPORT_FILE"

    # Test 3: TCP Throughput (Parallel Streams)
    print_header "Test 3: TCP Throughput (10 Parallel Streams)"
    print_info "Running $BENCHMARK_DURATION second TCP test with 10 parallel streams..."

    IPERF_PARALLEL=$(iperf3 -c "$SERVER_IP" -p 5201 -t $BENCHMARK_DURATION -P 10 -J 2>&1)

    if [ $? -eq 0 ]; then
        PARALLEL_THROUGHPUT=$(echo "$IPERF_PARALLEL" | grep -o '"bits_per_second":[0-9.]*' | head -1 | cut -d':' -f2)
        PARALLEL_GBPS=$(echo "scale=2; $PARALLEL_THROUGHPUT / 1000000000" | bc)
        PARALLEL_MBPS=$(echo "scale=2; $PARALLEL_THROUGHPUT / 1000000" | bc)

        echo -e "${BOLD}TCP Throughput (10 Parallel Streams):${NC}" | tee -a "$REPORT_FILE"
        echo -e "  Throughput:      ${GREEN}${PARALLEL_GBPS} Gbps${NC} (${PARALLEL_MBPS} Mbps)" | tee -a "$REPORT_FILE"
        print_success "Parallel TCP throughput test completed"
    else
        print_error "Parallel TCP throughput test failed"
        echo -e "${RED}Parallel TCP throughput test FAILED${NC}" | tee -a "$REPORT_FILE"
    fi

    echo "" | tee -a "$REPORT_FILE"

    # Test 4: UDP Throughput
    print_header "Test 4: UDP Throughput (1 Gbps target)"
    print_info "Running $BENCHMARK_DURATION second UDP test..."

    IPERF_UDP=$(iperf3 -c "$SERVER_IP" -p 5201 -u -b 1G -t $BENCHMARK_DURATION -J 2>&1)

    if [ $? -eq 0 ]; then
        UDP_THROUGHPUT=$(echo "$IPERF_UDP" | grep -o '"bits_per_second":[0-9.]*' | head -1 | cut -d':' -f2)
        UDP_GBPS=$(echo "scale=2; $UDP_THROUGHPUT / 1000000000" | bc)
        UDP_MBPS=$(echo "scale=2; $UDP_THROUGHPUT / 1000000" | bc)
        UDP_JITTER=$(echo "$IPERF_UDP" | grep -o '"jitter_ms":[0-9.]*' | head -1 | cut -d':' -f2)
        UDP_LOSS=$(echo "$IPERF_UDP" | grep -o '"lost_percent":[0-9.]*' | head -1 | cut -d':' -f2)

        echo -e "${BOLD}UDP Throughput:${NC}" | tee -a "$REPORT_FILE"
        echo -e "  Throughput:      ${GREEN}${UDP_GBPS} Gbps${NC} (${UDP_MBPS} Mbps)" | tee -a "$REPORT_FILE"
        echo -e "  Jitter:          ${GREEN}${UDP_JITTER} ms${NC}" | tee -a "$REPORT_FILE"
        echo -e "  Packet loss:     ${GREEN}${UDP_LOSS}%${NC}" | tee -a "$REPORT_FILE"
        print_success "UDP throughput test completed"
    else
        print_error "UDP throughput test failed"
        echo -e "${RED}UDP throughput test FAILED${NC}" | tee -a "$REPORT_FILE"
    fi

    echo "" | tee -a "$REPORT_FILE"

    # Test 5: Reverse Throughput
    print_header "Test 5: Reverse TCP Throughput (Server → Client)"
    print_info "Running $BENCHMARK_DURATION second reverse TCP test..."

    IPERF_REVERSE=$(iperf3 -c "$SERVER_IP" -p 5201 -R -t $BENCHMARK_DURATION -J 2>&1)

    if [ $? -eq 0 ]; then
        REVERSE_THROUGHPUT=$(echo "$IPERF_REVERSE" | grep -o '"bits_per_second":[0-9.]*' | head -1 | cut -d':' -f2)
        REVERSE_GBPS=$(echo "scale=2; $REVERSE_THROUGHPUT / 1000000000" | bc)
        REVERSE_MBPS=$(echo "scale=2; $REVERSE_THROUGHPUT / 1000000" | bc)

        echo -e "${BOLD}Reverse TCP Throughput:${NC}" | tee -a "$REPORT_FILE"
        echo -e "  Throughput:      ${GREEN}${REVERSE_GBPS} Gbps${NC} (${REVERSE_MBPS} Mbps)" | tee -a "$REPORT_FILE"
        print_success "Reverse TCP throughput test completed"
    else
        print_error "Reverse TCP throughput test failed"
        echo -e "${RED}Reverse TCP throughput test FAILED${NC}" | tee -a "$REPORT_FILE"
    fi

    echo "" | tee -a "$REPORT_FILE"

    # Test 6: System Resource Usage
    print_header "Test 6: System Resource Usage"

    # CPU usage
    CPU_USAGE=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)

    # Memory usage
    MEM_TOTAL=$(free -m | grep "Mem:" | awk '{print $2}')
    MEM_USED=$(free -m | grep "Mem:" | awk '{print $3}')
    MEM_PERCENT=$(echo "scale=2; $MEM_USED * 100 / $MEM_TOTAL" | bc)

    # Network interface stats (tun0)
    if [ -f /sys/class/net/tun0/statistics/rx_bytes ]; then
        RX_BYTES=$(cat /sys/class/net/tun0/statistics/rx_bytes)
        TX_BYTES=$(cat /sys/class/net/tun0/statistics/tx_bytes)
        RX_GB=$(echo "scale=2; $RX_BYTES / 1073741824" | bc)
        TX_GB=$(echo "scale=2; $TX_BYTES / 1073741824" | bc)

        echo -e "${BOLD}System Resources:${NC}" | tee -a "$REPORT_FILE"
        echo -e "  CPU usage:       ${GREEN}${CPU_USAGE}%${NC}" | tee -a "$REPORT_FILE"
        echo -e "  Memory usage:    ${GREEN}${MEM_USED}/${MEM_TOTAL} MB (${MEM_PERCENT}%)${NC}" | tee -a "$REPORT_FILE"
        echo -e "  tun0 RX:         ${GREEN}${RX_GB} GB${NC}" | tee -a "$REPORT_FILE"
        echo -e "  tun0 TX:         ${GREEN}${TX_GB} GB${NC}" | tee -a "$REPORT_FILE"
    else
        echo -e "${BOLD}System Resources:${NC}" | tee -a "$REPORT_FILE"
        echo -e "  CPU usage:       ${GREEN}${CPU_USAGE}%${NC}" | tee -a "$REPORT_FILE"
        echo -e "  Memory usage:    ${GREEN}${MEM_USED}/${MEM_TOTAL} MB (${MEM_PERCENT}%)${NC}" | tee -a "$REPORT_FILE"
        print_warning "tun0 interface not found (VPN not running?)"
    fi

    echo "" | tee -a "$REPORT_FILE"

    # Final Summary
    print_header "Benchmark Summary"

    echo -e "${BOLD}Performance Ratings:${NC}" | tee -a "$REPORT_FILE"

    # Rate latency
    if [ -n "$AVG_LATENCY" ]; then
        if (( $(echo "$AVG_LATENCY < 1" | bc -l) )); then
            echo -e "  Latency:         ${GREEN}EXCELLENT (<1ms)${NC}" | tee -a "$REPORT_FILE"
        elif (( $(echo "$AVG_LATENCY < 5" | bc -l) )); then
            echo -e "  Latency:         ${GREEN}GOOD (<5ms)${NC}" | tee -a "$REPORT_FILE"
        elif (( $(echo "$AVG_LATENCY < 20" | bc -l) )); then
            echo -e "  Latency:         ${YELLOW}FAIR (<20ms)${NC}" | tee -a "$REPORT_FILE"
        else
            echo -e "  Latency:         ${RED}POOR (>20ms)${NC}" | tee -a "$REPORT_FILE"
        fi
    fi

    # Rate throughput
    if [ -n "$TCP_GBPS" ]; then
        if (( $(echo "$TCP_GBPS > 5" | bc -l) )); then
            echo -e "  Throughput:      ${GREEN}EXCELLENT (>5 Gbps)${NC}" | tee -a "$REPORT_FILE"
        elif (( $(echo "$TCP_GBPS > 1" | bc -l) )); then
            echo -e "  Throughput:      ${GREEN}GOOD (>1 Gbps)${NC}" | tee -a "$REPORT_FILE"
        elif (( $(echo "$TCP_GBPS > 0.5" | bc -l) )); then
            echo -e "  Throughput:      ${YELLOW}FAIR (>500 Mbps)${NC}" | tee -a "$REPORT_FILE"
        else
            echo -e "  Throughput:      ${RED}POOR (<500 Mbps)${NC}" | tee -a "$REPORT_FILE"
        fi
    fi

    echo "" | tee -a "$REPORT_FILE"
    print_success "Benchmark completed successfully!"
    print_info "Full report saved to: $REPORT_FILE"
    echo ""
}

# Main
main() {
    if [ -z "$MODE" ]; then
        echo "Usage: $0 {server|client} [SERVER_IP]"
        echo ""
        echo "Examples:"
        echo "  Server:  $0 server"
        echo "  Client:  $0 client 192.168.1.100"
        exit 1
    fi

    check_dependencies

    case "$MODE" in
        server)
            start_server
            ;;
        client)
            if [ -z "$SERVER_IP" ] || [ "$SERVER_IP" = "127.0.0.1" ]; then
                print_error "Please specify server IP address"
                echo "Usage: $0 client <SERVER_IP>"
                exit 1
            fi
            run_benchmarks
            ;;
        *)
            print_error "Invalid mode: $MODE"
            echo "Usage: $0 {server|client} [SERVER_IP]"
            exit 1
            ;;
    esac
}

main
