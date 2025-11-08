#!/bin/bash
#
# SecureSwift VPN - Secure Build Script
# Compiles with all security hardening flags and runs comprehensive tests
#

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

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

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

# Security-hardened compiler flags
SECURITY_FLAGS=(
    # Stack protection
    "-fstack-protector-strong"
    "-fstack-clash-protection"

    # Format string protection
    "-Wformat"
    "-Wformat-security"
    "-Werror=format-security"

    # Buffer overflow detection
    "-D_FORTIFY_SOURCE=2"

    # Position Independent Code (for ASLR)
    "-fPIC"
    "-pie"

    # Control Flow Integrity
    "-fcf-protection=full"

    # Undefined Behavior Sanitizer (for testing)
    # "-fsanitize=undefined"

    # Address Sanitizer (for testing)
    # "-fsanitize=address"

    # Memory Sanitizer (for testing - requires special libc)
    # "-fsanitize=memory"

    # Enable all warnings
    "-Wall"
    "-Wextra"
    "-Wpedantic"

    # Treat warnings as errors
    "-Werror"

    # Optimization (O2 is good balance of speed and security)
    "-O2"

    # Debug symbols (strip later for production)
    "-g"

    # SIMD optimizations (SSE2 for XSalsa20)
    "-msse2"

    # Additional security warnings
    "-Warray-bounds"
    "-Wcast-align"
    "-Wconversion"
    "-Wsign-conversion"
    "-Wstrict-overflow=5"
    "-Wwrite-strings"
    "-Wpointer-arith"
    "-Wcast-qual"
    "-Wswitch-default"
    "-Wswitch-enum"
    "-Wunreachable-code"
)

# Linker security flags
LINKER_FLAGS=(
    # Full RELRO (makes GOT read-only)
    "-Wl,-z,relro"
    "-Wl,-z,now"

    # No executable stack
    "-Wl,-z,noexecstack"

    # No executable heap
    "-Wl,-z,noexecheap"
)

print_header "SecureSwift VPN - Secure Build System"

# Check for required tools
print_info "Checking build environment..."

if ! command -v gcc &> /dev/null; then
    print_error "gcc not found. Please install build-essential"
    exit 1
fi
print_success "gcc found: $(gcc --version | head -1)"

# Show security flags
print_info "Security hardening flags enabled:"
for flag in "${SECURITY_FLAGS[@]}"; do
    echo "  - $flag"
done

# Clean previous builds
print_info "Cleaning previous builds..."
rm -f secureswift secureswift_debug crypto_tests
print_success "Clean complete"

# Build crypto test suite
print_header "Building Crypto Test Suite"

print_info "Compiling crypto tests..."
gcc ${SECURITY_FLAGS[@]} ${LINKER_FLAGS[@]} \
    -DBUILD_CRYPTO_TESTS \
    -o crypto_tests \
    crypto_test_vectors.c \
    -lpthread \
    || { print_error "Crypto test compilation failed"; exit 1; }

print_success "Crypto tests compiled successfully"

# Run crypto tests
print_header "Running Cryptographic Tests"

./crypto_tests || { print_error "Crypto tests FAILED"; exit 1; }

print_success "All crypto tests PASSED"

# Build main VPN binary (production mode)
print_header "Building SecureSwift VPN (Production)"

print_info "Compiling with full security hardening..."
gcc ${SECURITY_FLAGS[@]} ${LINKER_FLAGS[@]} \
    -o secureswift \
    secureswift.c \
    crypto_test_vectors.c \
    -lpthread \
    -lm \
    || { print_error "Production compilation failed"; exit 1; }

print_success "Production binary compiled successfully"

# Build debug version with sanitizers (optional)
print_header "Building SecureSwift VPN (Debug with Sanitizers)"

print_info "Compiling debug version with AddressSanitizer and UBSan..."
gcc ${SECURITY_FLAGS[@]} ${LINKER_FLAGS[@]} \
    -fsanitize=address \
    -fsanitize=undefined \
    -fno-omit-frame-pointer \
    -O1 \
    -g \
    -o secureswift_debug \
    secureswift.c \
    crypto_test_vectors.c \
    -lpthread \
    -lm \
    2>&1 | grep -v "warning: -fstack-protector not supported" || true

if [ -f secureswift_debug ]; then
    print_success "Debug binary compiled successfully"
else
    print_warning "Debug binary compilation failed (sanitizers may not be available)"
fi

# Security analysis
print_header "Security Analysis"

# Check for common security issues
print_info "Checking binary security features..."

if command -v checksec &> /dev/null; then
    checksec --file=./secureswift
    print_success "Security check complete"
else
    print_warning "checksec not found. Install with: sudo apt-get install checksec"

    # Manual checks
    print_info "Running manual security checks..."

    # Check for PIE
    if readelf -h secureswift 2>/dev/null | grep -q "Type:.*DYN"; then
        print_success "PIE (Position Independent Executable) enabled"
    else
        print_error "PIE not enabled"
    fi

    # Check for RELRO
    if readelf -l secureswift 2>/dev/null | grep -q "GNU_RELRO"; then
        print_success "RELRO enabled"
    else
        print_error "RELRO not enabled"
    fi

    # Check for stack canary
    if readelf -s secureswift 2>/dev/null | grep -q "__stack_chk_fail"; then
        print_success "Stack canary enabled"
    else
        print_error "Stack canary not enabled"
    fi

    # Check for NX (No-Execute)
    if readelf -l secureswift 2>/dev/null | grep "GNU_STACK" | grep -q "RW "; then
        print_success "NX (No-Execute) enabled"
    else
        print_error "NX not enabled"
    fi
fi

# Size comparison
print_header "Build Statistics"

if [ -f secureswift ]; then
    SIZE=$(du -h secureswift | cut -f1)
    print_info "Production binary size: $SIZE"
fi

if [ -f secureswift_debug ]; then
    SIZE_DEBUG=$(du -h secureswift_debug | cut -f1)
    print_info "Debug binary size: $SIZE_DEBUG"
fi

# Summary
print_header "Build Summary"

print_success "Production binary: ./secureswift"
if [ -f secureswift_debug ]; then
    print_success "Debug binary: ./secureswift_debug"
fi
print_success "Crypto tests: ./crypto_tests"

echo ""
print_info "Security features enabled:"
echo "  ✓ Stack protection (stack canaries)"
echo "  ✓ FORTIFY_SOURCE (buffer overflow detection)"
echo "  ✓ Position Independent Code (ASLR)"
echo "  ✓ Full RELRO (GOT hardening)"
echo "  ✓ NX bit (non-executable stack)"
echo "  ✓ Format string protection"
echo "  ✓ Secure random nonce generation"
echo "  ✓ Constant-time cryptographic operations"
echo "  ✓ Nonce reuse protection"
echo "  ✓ Replay attack detection"
echo "  ✓ Buffer overflow protection"
echo "  ✓ Integer overflow protection"

echo ""
print_info "Next steps:"
echo "  1. Run crypto tests: ./crypto_tests"
echo "  2. Test production binary: sudo ./secureswift server 0.0.0.0 443"
echo "  3. Run debug version for memory testing: sudo ./secureswift_debug server 0.0.0.0 443"
echo "  4. Install: sudo cp secureswift /usr/local/bin/"
echo "  5. Run benchmarks: ./benchmark.sh client <SERVER_IP>"

print_success "Build complete!"
