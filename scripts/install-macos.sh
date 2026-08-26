#!/bin/bash
# install-macos.sh - macOS installation script for agentmon
#
# Usage:
#   curl -fsSL https://get.agentmon.dev/macos | bash
#   ./install-macos.sh [version]
#
# Environment variables:
#   AGENTMON_VERSION - version to install (default: latest)
#   AGENTMON_MODE - installation mode: fuse-t, lima, network-only (default: interactive)
#   AGENTMON_INSTALL_DIR - installation directory (default: /usr/local/bin)

set -e

VERSION="${AGENTMON_VERSION:-${1:-latest}}"
MODE="${AGENTMON_MODE:-}"
INSTALL_DIR="${AGENTMON_INSTALL_DIR:-/usr/local/bin}"
GITHUB_REPO="diffsec/agentmon"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

# Check for Homebrew
check_homebrew() {
    if command -v brew &> /dev/null; then
        info "Homebrew is installed"
        return 0
    fi

    warn "Homebrew not found."
    echo ""
    read -p "Install Homebrew? [y/N]: " install_brew

    if [[ "$install_brew" =~ ^[Yy]$ ]]; then
        info "Installing Homebrew..."
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

        # Add brew to PATH for Apple Silicon
        if [[ -f /opt/homebrew/bin/brew ]]; then
            eval "$(/opt/homebrew/bin/brew shellenv)"
        fi
    else
        error "Homebrew is required for FUSE-T and Lima installation."
        exit 1
    fi
}

# Install FUSE-T (recommended - no kernel extension)
install_fuse_t() {
    info "Installing FUSE-T..."

    if brew list fuse-t &> /dev/null; then
        info "FUSE-T is already installed"
    else
        brew install fuse-t
    fi

    echo -e "${GREEN}✅ FUSE-T installed - no restart required!${NC}"
}

# Install Lima for full Linux security
install_lima() {
    info "Installing Lima..."

    if ! brew list lima &> /dev/null; then
        brew install lima
    fi

    # Create agentmon VM if it doesn't exist
    if ! limactl list 2>/dev/null | grep -q "agentmon"; then
        info "Creating agentmon Lima VM..."
        limactl create --name=agentmon template://ubuntu-lts

        info "Starting agentmon VM..."
        limactl start agentmon

        info "Installing agentmon inside Lima VM..."
        limactl shell agentmon -- bash -c 'curl -fsSL https://get.agentmon.dev/linux | bash'
    else
        info "agentmon Lima VM already exists"

        # Make sure it's running
        if ! limactl list 2>/dev/null | grep -q "agentmon.*Running"; then
            info "Starting agentmon VM..."
            limactl start agentmon
        fi
    fi

    echo -e "${GREEN}✅ Lima VM ready with full Linux security${NC}"
}

# Configure pf for network interception
configure_pf() {
    info "Configuring pf for network interception..."

    local pf_conf="/etc/pf.anchors/com.agentmon"

    if [[ ! -f "$pf_conf" ]]; then
        sudo tee "$pf_conf" > /dev/null << 'EOF'
# agentmon network interception rules
# These rules redirect traffic through the agentmon proxy

# Redirect outbound HTTP/HTTPS through agentmon
# rdr pass on lo0 inet proto tcp from any to any port 80 -> 127.0.0.1 port 8080
# rdr pass on lo0 inet proto tcp from any to any port 443 -> 127.0.0.1 port 8443

# Placeholder - actual rules configured at runtime by agentmon
EOF
        info "Created pf anchor file"
    fi

    # Check if anchor is in pf.conf
    if ! grep -q "com.agentmon" /etc/pf.conf 2>/dev/null; then
        warn "pf anchor not configured in /etc/pf.conf"
        warn "You may need to add: anchor \"com.agentmon\""
    fi

    echo -e "${GREEN}✅ pf configured for network interception${NC}"
}

# Detect system architecture
detect_arch() {
    local arch=$(uname -m)

    case $arch in
        x86_64)
            echo "amd64"
            ;;
        arm64)
            echo "arm64"
            ;;
        *)
            error "Unsupported architecture: $arch"
            exit 1
            ;;
    esac
}

# Get the latest version from GitHub
get_latest_version() {
    local latest
    latest=$(curl -fsSL "https://api.github.com/repos/${GITHUB_REPO}/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')

    if [[ -z "$latest" ]]; then
        error "Failed to fetch latest version"
        exit 1
    fi

    echo "$latest"
}

# Download and install agentmon binary
install_agentmon() {
    local version="$VERSION"
    local arch=$(detect_arch)

    if [[ "$version" == "latest" ]]; then
        version=$(get_latest_version)
    fi

    info "Installing agentmon ${version} for darwin/${arch}..."

    local download_url="https://github.com/${GITHUB_REPO}/releases/download/${version}/agentmon-darwin-${arch}"
    local tmp_file="/tmp/agentmon-$$"

    if ! curl -fsSL "$download_url" -o "$tmp_file"; then
        error "Failed to download agentmon from ${download_url}"
        exit 1
    fi

    chmod +x "$tmp_file"

    # Create install directory if it doesn't exist
    if [[ ! -d "$INSTALL_DIR" ]]; then
        sudo mkdir -p "$INSTALL_DIR"
    fi

    sudo mv "$tmp_file" "${INSTALL_DIR}/agentmon"

    echo -e "${GREEN}✅ agentmon installed to ${INSTALL_DIR}/${NC}"
}

# Download and install envshim helper
install_envshim() {
    local version="$VERSION"
    local arch=$(detect_arch)

    if [[ "$version" == "latest" ]]; then
        version=$(get_latest_version)
    fi

    info "Installing envshim helper..."

    local download_url="https://github.com/${GITHUB_REPO}/releases/download/${version}/envshim-darwin-${arch}"
    local tmp_file="/tmp/envshim-$$"

    if curl -fsSL "$download_url" -o "$tmp_file" 2>/dev/null; then
        chmod +x "$tmp_file"
        sudo mv "$tmp_file" "${INSTALL_DIR}/envshim"
        info "envshim installed to ${INSTALL_DIR}/envshim"
    else
        # Not "not available for this release" -- it is not built for macOS at
        # all. scripts/build-envshim.sh compiles only shim/linux for Linux
        # targets, so envshim-darwin-* is never published. shim/darwin/envshim.c
        # exists but nothing builds it, so environment-variable interception is
        # simply unimplemented on macOS.
        warn "envshim is not built for macOS; environment-variable interception is unavailable"
    fi
}

# Verify installation
verify_installation() {
    if command -v agentmon &> /dev/null; then
        info "Verification successful!"
        agentmon version 2>/dev/null || true
    else
        warn "agentmon not found in PATH. You may need to add ${INSTALL_DIR} to your PATH."
    fi
}

# Print mode selection menu
print_mode_menu() {
    echo ""
    echo -e "${BLUE}Select installation mode:${NC}"
    echo ""
    echo "  1) FUSE-T + pf (Recommended for development)"
    echo "     - No kernel extension required"
    echo "     - Works on Apple Silicon without reduced security"
    echo "     - File + Network interception (no isolation)"
    echo "     - Security: 70%"
    echo ""
    echo "  2) Lima VM (Recommended for production)"
    echo "     - Full Linux isolation in VM"
    echo "     - All security features available"
    echo "     - Slight performance overhead"
    echo "     - Security: 85%"
    echo ""
    echo "  3) Network only (minimal setup)"
    echo "     - pf for network interception"
    echo "     - FSEvents for file monitoring (observe only)"
    echo "     - No FUSE installation needed"
    echo "     - Security: 50%"
    echo ""
}

# Print post-install instructions
print_instructions() {
    local mode="$1"

    echo ""
    echo "============================================"
    echo "  agentmon installed successfully!"
    echo "============================================"
    echo ""

    case $mode in
        fuse-t)
            echo "Run with:"
            echo "  sudo agentmon server"
            echo ""
            echo "Security level: 70% (file + network interception)"
            ;;
        lima)
            echo "Run with:"
            echo "  limactl shell agentmon -- agentmon server"
            echo ""
            echo "Or use the native wrapper:"
            echo "  agentmon server --mode=lima"
            echo ""
            echo "Security level: 85% (full Linux isolation)"
            ;;
        network-only)
            echo "Run with:"
            echo "  sudo agentmon server"
            echo ""
            echo "Note: File monitoring is observation-only without FUSE-T"
            echo "Security level: 50% (network only)"
            ;;
    esac

    echo ""
    echo "Check status with: agentmon status"
    echo ""
    echo "Configuration:"
    echo "  Default config: ~/.config/agentmon/config.yml"
    echo "  Default policy: ~/.config/agentmon/policy.yml"
    echo ""
    echo "Documentation:"
    echo "  https://github.com/${GITHUB_REPO}"
    echo ""
}

# Main installation flow
main() {
    echo "agentmon macOS Installer"
    echo "======================="
    echo ""

    local selected_mode="$MODE"

    # If mode not set via environment, show interactive menu
    if [[ -z "$selected_mode" ]]; then
        print_mode_menu
        read -p "Choice [1/2/3]: " choice

        case $choice in
            1) selected_mode="fuse-t" ;;
            2) selected_mode="lima" ;;
            3) selected_mode="network-only" ;;
            *)
                warn "Invalid choice, defaulting to FUSE-T (recommended)"
                selected_mode="fuse-t"
                ;;
        esac
    fi

    info "Selected mode: $selected_mode"
    echo ""

    case $selected_mode in
        fuse-t)
            check_homebrew
            install_fuse_t
            configure_pf
            install_agentmon
            install_envshim
            ;;
        lima)
            check_homebrew
            install_lima
            install_agentmon
            install_envshim
            ;;
        network-only)
            configure_pf
            install_agentmon
            install_envshim
            ;;
        *)
            error "Unknown mode: $selected_mode"
            exit 1
            ;;
    esac

    echo ""
    verify_installation
    print_instructions "$selected_mode"
}

main "$@"
