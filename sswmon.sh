#!/bin/bash
#
# SecureSwift VPN Monitor
# Real-time monitoring and statistics dashboard
#

INTERFACE="${1:-ssw0}"
REFRESH_RATE="${2:-1}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m'

get_stats() {
    if [ ! -d "/sys/class/net/$INTERFACE" ]; then
        echo "Error: Interface $INTERFACE not found"
        exit 1
    fi

    RX_BYTES=$(cat /sys/class/net/$INTERFACE/statistics/rx_bytes 2>/dev/null || echo 0)
    TX_BYTES=$(cat /sys/class/net/$INTERFACE/statistics/tx_bytes 2>/dev/null || echo 0)
    RX_PACKETS=$(cat /sys/class/net/$INTERFACE/statistics/rx_packets 2>/dev/null || echo 0)
    TX_PACKETS=$(cat /sys/class/net/$INTERFACE/statistics/tx_packets 2>/dev/null || echo 0)
    RX_ERRORS=$(cat /sys/class/net/$INTERFACE/statistics/rx_errors 2>/dev/null || echo 0)
    TX_ERRORS=$(cat /sys/class/net/$INTERFACE/statistics/tx_errors 2>/dev/null || echo 0)
    RX_DROPPED=$(cat /sys/class/net/$INTERFACE/statistics/rx_dropped 2>/dev/null || echo 0)
    TX_DROPPED=$(cat /sys/class/net/$INTERFACE/statistics/tx_dropped 2>/dev/null || echo 0)

    STATUS=$(cat /sys/class/net/$INTERFACE/operstate 2>/dev/null || echo "unknown")
    MTU=$(cat /sys/class/net/$INTERFACE/mtu 2>/dev/null || echo "unknown")

    # Get IP address
    IP_ADDR=$(ip addr show "$INTERFACE" 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}/\d+' || echo "none")
}

format_bytes() {
    local bytes=$1
    if [ $bytes -lt 1024 ]; then
        echo "${bytes}B"
    elif [ $bytes -lt 1048576 ]; then
        echo "$((bytes / 1024))KB"
    elif [ $bytes -lt 1073741824 ]; then
        echo "$((bytes / 1048576))MB"
    else
        echo "$((bytes / 1073741824))GB"
    fi
}

calculate_rate() {
    local current=$1
    local previous=$2
    local time_diff=$3

    if [ $time_diff -eq 0 ]; then
        echo "0"
    else
        echo $(( (current - previous) / time_diff ))
    fi
}

draw_bar() {
    local value=$1
    local max=$2
    local width=40

    if [ $max -eq 0 ]; then
        max=1
    fi

    local filled=$((value * width / max))
    if [ $filled -gt $width ]; then
        filled=$width
    fi

    printf "["
    for ((i=0; i<$filled; i++)); do
        printf "="
    done
    for ((i=$filled; i<$width; i++)); do
        printf " "
    done
    printf "]"
}

display_dashboard() {
    clear

    echo -e "${CYAN}${BOLD}"
    echo "╔════════════════════════════════════════════════════════════════╗"
    echo "║          SecureSwift VPN - Real-Time Monitor                   ║"
    echo "╚════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"

    # Interface info
    echo -e "${BOLD}Interface:${NC} $INTERFACE"
    if [ "$STATUS" = "up" ]; then
        echo -e "${BOLD}Status:${NC}    ${GREEN}● UP${NC}"
    else
        echo -e "${BOLD}Status:${NC}    ${RED}● DOWN${NC}"
    fi
    echo -e "${BOLD}Address:${NC}   $IP_ADDR"
    echo -e "${BOLD}MTU:${NC}       $MTU"
    echo ""

    # Statistics
    echo -e "${CYAN}${BOLD}═══ TRAFFIC STATISTICS ═══${NC}"
    echo ""

    # RX
    echo -e "${BOLD}RECEIVE (RX)${NC}"
    echo -e "  Bytes:      ${GREEN}$(format_bytes $RX_BYTES)${NC}"
    echo -e "  Packets:    ${GREEN}$RX_PACKETS${NC}"
    if [ ${RX_RATE:-0} -gt 0 ]; then
        echo -e "  Rate:       ${GREEN}$(format_bytes $RX_RATE)/s${NC}"
        draw_bar $RX_RATE $MAX_RATE
    fi
    echo -e "  Errors:     ${RED}$RX_ERRORS${NC}"
    echo -e "  Dropped:    ${YELLOW}$RX_DROPPED${NC}"
    echo ""

    # TX
    echo -e "${BOLD}TRANSMIT (TX)${NC}"
    echo -e "  Bytes:      ${BLUE}$(format_bytes $TX_BYTES)${NC}"
    echo -e "  Packets:    ${BLUE}$TX_PACKETS${NC}"
    if [ ${TX_RATE:-0} -gt 0 ]; then
        echo -e "  Rate:       ${BLUE}$(format_bytes $TX_RATE)/s${NC}"
        draw_bar $TX_RATE $MAX_RATE
    fi
    echo -e "  Errors:     ${RED}$TX_ERRORS${NC}"
    echo -e "  Dropped:    ${YELLOW}$TX_DROPPED${NC}"
    echo ""

    # Totals
    TOTAL_BYTES=$((RX_BYTES + TX_BYTES))
    TOTAL_PACKETS=$((RX_PACKETS + TX_PACKETS))
    TOTAL_ERRORS=$((RX_ERRORS + TX_ERRORS))

    echo -e "${CYAN}${BOLD}═══ TOTALS ═══${NC}"
    echo -e "  Total Bytes:   ${MAGENTA}$(format_bytes $TOTAL_BYTES)${NC}"
    echo -e "  Total Packets: ${MAGENTA}$TOTAL_PACKETS${NC}"
    echo -e "  Total Errors:  ${MAGENTA}$TOTAL_ERRORS${NC}"
    echo ""

    # System info
    echo -e "${CYAN}${BOLD}═══ SYSTEM ═══${NC}"
    UPTIME=$(uptime -p)
    LOAD=$(cat /proc/loadavg | cut -d' ' -f1-3)
    echo -e "  Uptime:  $UPTIME"
    echo -e "  Load:    $LOAD"
    echo ""

    echo -e "${BOLD}Press Ctrl+C to exit${NC} | Refresh: ${REFRESH_RATE}s"
}

# Main loop
echo "SecureSwift VPN Monitor - Starting..."
echo "Monitoring interface: $INTERFACE"
echo "Press Ctrl+C to exit"
sleep 2

PREV_RX_BYTES=0
PREV_TX_BYTES=0
MAX_RATE=1048576  # 1 MB/s default

while true; do
    get_stats

    # Calculate rates
    RX_RATE=$(calculate_rate $RX_BYTES $PREV_RX_BYTES $REFRESH_RATE)
    TX_RATE=$(calculate_rate $TX_BYTES $PREV_TX_BYTES $REFRESH_RATE)

    # Update max rate for bar graph
    if [ $RX_RATE -gt $MAX_RATE ]; then
        MAX_RATE=$RX_RATE
    fi
    if [ $TX_RATE -gt $MAX_RATE ]; then
        MAX_RATE=$TX_RATE
    fi

    display_dashboard

    PREV_RX_BYTES=$RX_BYTES
    PREV_TX_BYTES=$TX_BYTES

    sleep $REFRESH_RATE
done
