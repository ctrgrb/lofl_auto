#!/bin/bash

# Disable output buffering to ensure prompts are shown immediately
stty -icanon -echo 2>/dev/null || true
stty icanon echo 2>/dev/null || true

# Configuration file path
CONFIG_FILE="lofl_config.conf"

# Function to detect the operating system
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_ID="$ID"
        OS_VERSION="$VERSION_ID"
        OS_NAME="$NAME"
    elif [ -f /etc/arch-release ]; then
        OS_ID="arch"
        OS_NAME="Arch Linux"
    elif [ -f /etc/debian_version ]; then
        OS_ID="debian"
        OS_NAME="Debian"
    else
        OS_ID="unknown"
        OS_NAME="Unknown"
    fi
    
    echo "Detected OS: $OS_NAME ($OS_ID)"
}

# Function to get architecture for tun2socks
get_architecture() {
    local arch
    if command -v dpkg >/dev/null 2>&1; then
        arch=$(dpkg --print-architecture)
    else
        arch=$(uname -m)
        case $arch in
            x86_64) arch="amd64" ;;
            aarch64) arch="arm64" ;;
            armv7l) arch="armhf" ;;
        esac
    fi
    echo "$arch"
}

# Function to install packages based on OS
install_packages() {
    local packages_debian="dnsmasq python3-dnslib tcpdump openssh-client iproute2 iptables net-tools tmux wget curl git build-essential procps netcat-openbsd unzip sshpass expect socat"
    local packages_arch="dnsmasq python-dnslib tcpdump openssh iproute2 iptables net-tools tmux wget curl git base-devel procps-ng openbsd-netcat unzip sshpass expect socat bind"
    
    case "$OS_ID" in
        ubuntu|debian)
            echo "Installing packages using apt..."
            run_cmd apt update
            run_cmd apt install -y $packages_debian
            ;;
        arch|manjaro)
            echo "Installing packages using pacman..."
            run_cmd pacman -Sy --noconfirm
            run_cmd pacman -S --noconfirm $packages_arch
            ;;
        *)
            echo "Unsupported OS: $OS_NAME"
            echo "This script only supports Ubuntu, Debian, and Arch Linux"
            echo "Please install the following packages manually:"
            echo "dnsmasq, python3-dnslib, tcpdump, openssh-client, iproute2, iptables,"
            echo "net-tools, tmux, wget, curl, git, build-essential, procps, netcat, unzip, sshpass, expect, socat"
            echo -n "Continue anyway? (Y/n): " >&2
            read -r continue_unsupported
            if [[ ! -z "$continue_unsupported" && ! "$continue_unsupported" =~ ^[Yy]$ ]]; then
                echo "Exiting. Please install packages manually and run again."
                exit 1
            fi
            ;;
    esac
}

# Function to restart network service based on OS
restart_network_service() {
    case "$OS_ID" in
        ubuntu)
            echo "Restarting networking service..."
            # Check if using netplan (Ubuntu 18.04+)
            if [ -d "/etc/netplan" ] && [ "$(ls -A /etc/netplan 2>/dev/null)" ]; then
                echo "Detected Netplan configuration, applying netplan..."
                run_cmd netplan apply
            else
                # Fallback to traditional networking service
                run_cmd systemctl restart networking
            fi
            ;;
        debian)
            echo "Restarting networking service..."
            run_cmd systemctl restart networking
            ;;
        arch|manjaro)
            echo "Restarting NetworkManager service..."
            if systemctl is-active NetworkManager >/dev/null 2>&1; then
                run_cmd systemctl restart NetworkManager
            else
                echo "NetworkManager not active, skipping network restart"
                echo "You may need to restart network manually: sudo systemctl restart NetworkManager"
            fi
            ;;
        *)
            echo "Unknown OS, attempting to restart networking..."
            run_cmd systemctl restart networking 2>/dev/null || echo "Failed to restart networking - please restart manually"
            ;;
    esac
}

# Function to restart dnsmasq service
restart_dnsmasq_service() {
    echo "Restarting dnsmasq service..."
    run_cmd systemctl restart dnsmasq
}

# Function to configure network interfaces based on OS
configure_network_interfaces() {
    case "$OS_ID" in
        ubuntu)
            # Check if Ubuntu uses Netplan (18.04+)
            if [ -d "/etc/netplan" ] && [ "$(ls -A /etc/netplan 2>/dev/null)" ]; then
                echo "Configuring network interfaces using Netplan..."
                # Backup existing netplan config
                run_cmd cp -r /etc/netplan /etc/netplan.backup.$(date +%Y%m%d_%H%M%S) 2>/dev/null || true
                
                # Create netplan configuration
                cat > /etc/netplan/01-lofl-config.yaml << EOF
network:
  version: 2
  renderer: networkd
  ethernets:
    $INTERNET_INTERFACE:
      dhcp4: true
    $LAN_INTERFACE:
      dhcp4: false
      addresses:
        - $LAN_IP/24
EOF
                echo "Netplan configuration created"
            else
                echo "Configuring network interfaces using /etc/network/interfaces..."
                cp /etc/network/interfaces /etc/network/interfaces.backup.$(date +%Y%m%d_%H%M%S)
                
                cat > /etc/network/interfaces << EOF
# This file describes the network interfaces available on your system
# and how to activate them. For more information, see interfaces(5).            
source /etc/network/interfaces.d/*

# The loopback network interface
auto lo
iface lo inet loopback

auto $INTERNET_INTERFACE
iface $INTERNET_INTERFACE inet dhcp

auto $LAN_INTERFACE
iface $LAN_INTERFACE inet static
        address $LAN_IP
        netmask $LAN_NETMASK
EOF
            fi
            ;;
        debian)
            echo "Configuring network interfaces using /etc/network/interfaces..."
            cp /etc/network/interfaces /etc/network/interfaces.backup.$(date +%Y%m%d_%H%M%S)
            
            cat > /etc/network/interfaces << EOF
# This file describes the network interfaces available on your system
# and how to activate them. For more information, see interfaces(5).            
source /etc/network/interfaces.d/*

# The loopback network interface
auto lo
iface lo inet loopback

auto $INTERNET_INTERFACE
iface $INTERNET_INTERFACE inet dhcp

auto $LAN_INTERFACE
iface $LAN_INTERFACE inet static
        address $LAN_IP
        netmask $LAN_NETMASK
EOF
            ;;
        arch|manjaro)
            echo "Configuring network interfaces using NetworkManager..."
            # For Arch, we'll use NetworkManager nmcli commands
            # First, check if NetworkManager is available
            if ! command -v nmcli >/dev/null 2>&1; then
                echo "NetworkManager not found. Installing..."
                run_cmd pacman -S --noconfirm networkmanager
                run_cmd systemctl enable NetworkManager
                run_cmd systemctl start NetworkManager
                sleep 3  # Give NetworkManager time to start
            fi
            
            # Configure LAN interface with static IP
            echo "Setting up static IP on $LAN_INTERFACE..."
            echo "nmcli connection delete \"$LAN_INTERFACE\" 2>/dev/null || true"
            nmcli connection delete "$LAN_INTERFACE" 2>/dev/null || true
            run_cmd nmcli connection add type ethernet con-name "$LAN_INTERFACE" ifname "$LAN_INTERFACE" ip4 "$LAN_IP/24"
            run_cmd nmcli connection up "$LAN_INTERFACE"
            
            # Make sure Internet interface is managed by NetworkManager
            run_cmd nmcli device set "$INTERNET_INTERFACE" managed yes
            ;;
        *)
            echo "Unknown OS - trying Debian-style interface configuration..."
            cp /etc/network/interfaces /etc/network/interfaces.backup.$(date +%Y%m%d_%H%M%S) 2>/dev/null || true
            
            cat > /etc/network/interfaces << EOF
# This file describes the network interfaces available on your system
# and how to activate them. For more information, see interfaces(5).            
source /etc/network/interfaces.d/*

# The loopback network interface
auto lo
iface lo inet loopback

auto $INTERNET_INTERFACE
iface $INTERNET_INTERFACE inet dhcp

auto $LAN_INTERFACE
iface $LAN_INTERFACE inet static
        address $LAN_IP
        netmask $LAN_NETMASK
EOF
            echo "Note: Network configuration may need manual adjustment for your OS"
            ;;
    esac
}

# Function to get iptables path
get_iptables_cmd() {
    if command -v iptables >/dev/null 2>&1; then
        echo "iptables"
    elif [ -x "/usr/sbin/iptables" ]; then
        echo "/usr/sbin/iptables"
    elif [ -x "/sbin/iptables" ]; then
        echo "/sbin/iptables"
    else
        echo "iptables"  # fallback, might fail
    fi
}

# Function to get sysctl path
get_sysctl_cmd() {
    if command -v sysctl >/dev/null 2>&1; then
        echo "sysctl"
    elif [ -x "/usr/sbin/sysctl" ]; then
        echo "/usr/sbin/sysctl"
    elif [ -x "/sbin/sysctl" ]; then
        echo "/sbin/sysctl"
    else
        echo "sysctl"  # fallback, might fail
    fi
}

echo "========================================================"
echo "    LOFL Linux SOCKS Routing Automation Script v1.1"
echo "    Supports: Debian, Arch Linux"
echo "========================================================"
echo

# Function to save configuration
save_config() {
    cat > "$CONFIG_FILE" << EOF
# LOFL Configuration File
# Generated on $(date)

# Network Interfaces
INTERNET_INTERFACE="$INTERNET_INTERFACE"
LAN_INTERFACE="$LAN_INTERFACE"

# IP Configuration
LAN_IP="$LAN_IP"
LAN_NETMASK="$LAN_NETMASK"
DHCP_START="$DHCP_START"
DHCP_END="$DHCP_END"

# DNS Configuration
DOMAIN="$DOMAIN"
DC_IPS=(${DC_IPS[@]})
DEFAULT_DNS="$DEFAULT_DNS"

# SSH Configuration
SSH_USER="$SSH_USER"
SSH_SERVER="$SSH_SERVER"
NEEDS_PASSWORD="$NEEDS_PASSWORD"

# Tunnel Settings (fixed)
TUN_INTERFACE="tun1"
TUN_IP="198.18.0.1"
TUN_CIDR="15"
EOF
    echo "Configuration saved to $CONFIG_FILE"
}

# Function to load configuration
load_config() {
    if [ -f "$CONFIG_FILE" ]; then
        source "$CONFIG_FILE"
        return 0
    else
        return 1
    fi
}

# Function to display loaded configuration
display_config() {
    echo "=== Loaded Configuration ==="
    echo "Internet Interface: $INTERNET_INTERFACE"
    echo "LAN Interface: $LAN_INTERFACE"
    echo "LAN IP: $LAN_IP/$LAN_NETMASK"
    echo "DHCP Range: $DHCP_START - $DHCP_END"
    echo "Domain: $DOMAIN"
    echo "DC IPs: ${DC_IPS[*]}"
    echo "Default DNS: $DEFAULT_DNS"
    echo "SSH: $SSH_USER@$SSH_SERVER"
    echo "SSH needs password: $NEEDS_PASSWORD"
    echo
}

# Function to echo and run commands
run_cmd() {
    echo "$*"
    "$@"
    local exit_code=$?
    if [ $exit_code -ne 0 ]; then
        echo "ERROR: Command failed with exit code $exit_code: $*"
    echo -n "Do you want to continue anyway? (Y/n): "
    read -r continue_choice
    if [[ -z "$continue_choice" || "$continue_choice" =~ ^[Yy]$ ]]; then
        echo "Continuing despite error..."
    else
        echo "Script execution stopped by user."
        exit $exit_code
    fi
        echo "Continuing despite error..."
    fi
    return $exit_code
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "This script must be run as root or with sudo."
    echo "Please run: sudo $0"
    exit 1
fi

# Check for existing configuration
USE_EXISTING_CONFIG=false
if [ -f "$CONFIG_FILE" ]; then
    echo "Found existing configuration file: $CONFIG_FILE"
    echo
    echo -n "Do you want to use the existing configuration? (Y/n): "
    read -r use_config
    echo
    
    if [[ -z "$use_config" || "$use_config" =~ ^[Yy]$ ]]; then
        if load_config; then
            USE_EXISTING_CONFIG=true
            display_config
            echo -n "Proceed with this configuration? (Y/n): "
            read -r proceed_existing
            echo
            
            if [[ ! -z "$proceed_existing" && ! "$proceed_existing" =~ ^[Yy]$ ]]; then
                echo "Will prompt for new configuration..."
                USE_EXISTING_CONFIG=false
            fi
        else
            echo "Error loading configuration file. Will prompt for new configuration."
            USE_EXISTING_CONFIG=false
        fi
    else
        echo "Will prompt for new configuration..."
        USE_EXISTING_CONFIG=false
    fi
fi

# Always detect operating system (needed for network configuration)
detect_os

# Skip tool installation if using existing configuration
if [ "$USE_EXISTING_CONFIG" = false ]; then
    echo "=== Installing Required Tools ==="
    
    # Install packages based on OS
    install_packages

    echo "Checking for tun2socks..."
    if ! command -v tun2socks &> /dev/null; then
        echo "Installing tun2socks..."
        # Download and install tun2socks
        ARCH=$(get_architecture)
        case $ARCH in
            amd64)
                TUN2SOCKS_ARCH="linux-amd64"
                ;;
            arm64)
                TUN2SOCKS_ARCH="linux-arm64"
                ;;
            armhf)
                TUN2SOCKS_ARCH="linux-armv7"
                ;;
            *)
                echo "Unsupported architecture: $ARCH"
                echo "Please install tun2socks manually from https://github.com/xjasonlyu/tun2socks"
                ;;
        esac
        
        if [ -n "$TUN2SOCKS_ARCH" ]; then
            TUN2SOCKS_VERSION="v2.6.0"
            echo "Downloading tun2socks for $TUN2SOCKS_ARCH..."
            run_cmd wget -O /tmp/tun2socks.zip "https://github.com/xjasonlyu/tun2socks/releases/download/${TUN2SOCKS_VERSION}/tun2socks-${TUN2SOCKS_ARCH}.zip"
            
            echo "Extracting tun2socks..."
            run_cmd cd /tmp
            run_cmd unzip -o tun2socks.zip
            
            # The extracted file is named tun2socks-linux-amd64 (or similar for other architectures)
            TUN2SOCKS_BINARY="/tmp/tun2socks-${TUN2SOCKS_ARCH}"
            
            # Also try generic patterns in case the naming changes
            if [ ! -f "$TUN2SOCKS_BINARY" ]; then
                TUN2SOCKS_BINARY=$(find /tmp -name "tun2socks*" -type f 2>/dev/null | head -1)
            fi
            
            if [ -f "$TUN2SOCKS_BINARY" ]; then
                echo "Found tun2socks binary: $TUN2SOCKS_BINARY"
                run_cmd chmod +x "$TUN2SOCKS_BINARY"
                run_cmd mv "$TUN2SOCKS_BINARY" /usr/local/bin/tun2socks
                echo "tun2socks installed successfully"
                
                # Clean up
                run_cmd rm -f /tmp/tun2socks.zip
                run_cmd rm -rf /tmp/tun2socks-* 2>/dev/null || true
            else
                echo "Error: Could not find tun2socks binary in extracted files"
                echo "Please install tun2socks manually"
            fi
            
            run_cmd cd - > /dev/null
        fi
    else
        echo "tun2socks is already installed"
    fi

    echo "Verifying required files exist in current directory..."
    REQUIRED_FILES=("dns_over_tcp.py" "add_routes.sh" "iptables_nat.sh" "cldaproxy.sh")
    MISSING_FILES=()

    for file in "${REQUIRED_FILES[@]}"; do
        if [ ! -f "$file" ]; then
            MISSING_FILES+=("$file")
        fi
    done

    if [ ${#MISSING_FILES[@]} -gt 0 ]; then
        echo "WARNING: The following required files are missing:"
        for file in "${MISSING_FILES[@]}"; do
            echo "  - $file"
        done
        echo "Please ensure all LOFL repository files are present before continuing."
        echo -n "Continue anyway? (Y/n): " >&2
        read -r continue_anyway
        if [[ -z "$continue_anyway" || "$continue_anyway" =~ ^[Yy]$ ]]; then
            echo
        else
            echo "Exiting. Please download missing files and run again."
            exit 1
        fi
    fi

    echo "Tool installation completed!"
    echo
else
    echo "=== Skipping Tool Installation ==="
    echo "Using existing configuration - assuming tools are already installed."
    echo
fi

# Function to validate IP address format
validate_ip() {
    local ip=$1
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        IFS='.' read -ra ADDR <<< "$ip"
        for i in "${ADDR[@]}"; do
            if [[ $i -gt 255 ]]; then
                return 1
            fi
        done
        return 0
    else
        return 1
    fi
}

# Function to validate network interface exists
validate_interface() {
    local interface=$1
    if ip link show "$interface" &> /dev/null; then
        return 0
    else
        return 1
    fi
}

# Function to prompt for input with validation
prompt_with_validation() {
    local prompt="$1"
    local validation_func="$2"
    local example="$3"
    local default_value="$4"
    local value
    
    while true; do
        if [ -n "$default_value" ]; then
            echo -n "$prompt (default: $default_value): " >&2
        elif [ -n "$example" ]; then
            echo -n "$prompt (e.g., $example): " >&2
        else
            echo -n "$prompt: " >&2
        fi
        
        read -r value
        
        # Use default value if empty and default is provided
        if [ -z "$value" ] && [ -n "$default_value" ]; then
            value="$default_value"
        fi
        
        if [ -z "$value" ]; then
            echo "Value cannot be empty. Please try again." >&2
            echo >&2
            continue
        fi
        
        if [ -n "$validation_func" ] && ! $validation_func "$value"; then
            echo "Invalid value. Please try again." >&2
            echo >&2
            continue
        fi
        
        echo "$value"
        break
    done
}

# Configuration input section
if [ "$USE_EXISTING_CONFIG" = false ]; then
    echo "=== Network Interface Configuration ==="
    echo "Available network interfaces:"
    ip link show | grep -E '^[0-9]+:' | cut -d: -f2 | sed 's/^ */- /'
    echo

    INTERNET_INTERFACE=$(prompt_with_validation "Enter Internet interface name" "validate_interface" "" "ens33")
    LAN_INTERFACE=$(prompt_with_validation "Enter LAN segment interface name" "validate_interface" "" "ens36")

    # Fixed tunnel interface settings
    TUN_INTERFACE="tun1"
    TUN_IP="198.18.0.1"
    TUN_CIDR="15"

    echo
    echo "=== IP Configuration ==="
    LAN_IP=$(prompt_with_validation "Enter static IP for LAN interface" "validate_ip" "" "10.120.0.1")
    LAN_NETMASK=$(prompt_with_validation "Enter netmask for LAN interface" "validate_ip" "" "255.255.255.0")

    # Calculate network for DHCP range
    IFS='.' read -ra IP_PARTS <<< "$LAN_IP"
    NETWORK="${IP_PARTS[0]}.${IP_PARTS[1]}.${IP_PARTS[2]}"
    DHCP_START=$(prompt_with_validation "Enter DHCP range start IP" "validate_ip" "" "${NETWORK}.100")
    DHCP_END=$(prompt_with_validation "Enter DHCP range end IP" "validate_ip" "" "${NETWORK}.200")

    echo
    echo "=== DNS Configuration ==="
    DOMAIN=$(prompt_with_validation "Enter target domain" "" "" "OFFICE.AD.CORPORATE")

    echo "Enter Domain Controller IPs (press Enter on empty line to finish):"
    DC_IPS=()
    while true; do
        echo -n "DC IP: " >&2
        read -r dc_ip
        if [ -z "$dc_ip" ]; then
            break
        fi
        if validate_ip "$dc_ip"; then
            DC_IPS+=("$dc_ip")
        else
            echo "Invalid IP address. Please try again." >&2
            echo >&2
        fi
    done

    # Keep asking until at least one DC IP is provided
    while [ ${#DC_IPS[@]} -eq 0 ]; do
        echo "WARNING: At least one Domain Controller IP is required for proper DNS resolution."
        echo "Please provide at least one DC IP address:"
        echo
        while true; do
            echo -n "DC IP: " >&2
            read -r dc_ip
            if [ -z "$dc_ip" ]; then
                break
            fi
            if validate_ip "$dc_ip"; then
                DC_IPS+=("$dc_ip")
                echo "Added DC IP: $dc_ip"
            else
                echo "Invalid IP address. Please try again." >&2
                echo >&2
            fi
        done
        
        if [ ${#DC_IPS[@]} -eq 0 ]; then
            echo "No valid DC IPs provided. You must provide at least one DC IP to continue."
            echo
        fi
    done

    echo "DC IPs configured: ${DC_IPS[*]}"

    DEFAULT_DNS=$(prompt_with_validation "Enter default DNS server" "validate_ip" "" "1.0.0.1")

    echo
    echo "=== SSH Configuration ==="
    SSH_USER=$(prompt_with_validation "Enter SSH username for SOCKS connection" "" "" "user")
    SSH_SERVER=$(prompt_with_validation "Enter SSH server hostname/IP" "" "" "172.172.172.155")

    # Ask about SSH authentication method
    echo
    echo "=== SSH Authentication ==="
    echo -n "Will you need to enter a password for SSH authentication? (Y/n): " >&2
    read -r needs_password

    NEEDS_PASSWORD="$needs_password"
    SSH_PASSWORD=""
    if [[ -z "$needs_password" || "$needs_password" =~ ^[Yy]$ ]]; then
        echo -n "Enter SSH password (will be hidden): " >&2
        read -s SSH_PASSWORD
        echo
        
        if [ -z "$SSH_PASSWORD" ]; then
            echo "Password cannot be empty. SSH connection may fail."
            echo -n "Continue anyway? (Y/n): " >&2
            read -r continue_empty_pass
            if [[ ! -z "$continue_empty_pass" && ! "$continue_empty_pass" =~ ^[Yy]$ ]]; then
                echo "Exiting. Please run again with proper password."
                exit 1
            fi
        fi
    else
        echo "Will use key-based authentication"
    fi

    echo
    echo "=== Routes Configuration ==="
    echo -n "Do you have a routes.txt file with target subnets? (Y/n): " >&2
    read -r has_routes
    echo

    if [[ ! -z "$has_routes" && ! "$has_routes" =~ ^[Yy]$ ]]; then
        echo "Enter target network routes (CIDR format, press Enter on empty line to finish):"
        echo "Examples: 10.0.0.0/8, 172.16.0.0/12, 192.168.1.0/24"
        echo
        
        ROUTES=()
        while true; do
            echo -n "Route (CIDR): " >&2
            read -r route
            if [ -z "$route" ]; then
                break
            fi
            
            # Basic CIDR validation
            if [[ $route =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$ ]]; then
                ROUTES+=("$route")
                echo "Added: $route"
            else
                echo "Invalid CIDR format. Please use format like 192.168.1.0/24" >&2
            fi
        done
        
        if [ ${#ROUTES[@]} -eq 0 ]; then
            echo "No routes provided. Creating routes.txt with common private networks..."
            cat > routes.txt << EOF
# Common private network routes
10.0.0.0/8       # Private network A (10.x.x.x)
172.16.0.0/12    # Private network B (172.16-31.x.x)
192.168.0.0/16   # Private network C (192.168.x.x)
EOF
        else
            echo "Creating routes.txt with your specified routes..."
            cat > routes.txt << EOF
# Target network routes
EOF
            for route in "${ROUTES[@]}"; do
                echo "$route" >> routes.txt
            done
        fi
        
        echo "Created routes.txt file."
    fi
else
    # When using existing config, still ask for SSH password if needed
    if [[ -z "$NEEDS_PASSWORD" || "$NEEDS_PASSWORD" =~ ^[Yy]$ ]]; then
        echo "SSH authentication requires a password."
        echo -n "Enter SSH password (will be hidden): " >&2
        read -s SSH_PASSWORD
        echo
    fi
    
    # Set fixed tunnel interface settings for existing config
    TUN_INTERFACE="tun1"
    TUN_IP="198.18.0.1"
    TUN_CIDR="15"
fi

echo
echo "=== Configuration Summary ==="
echo "Internet Interface: $INTERNET_INTERFACE"
echo "LAN Interface: $LAN_INTERFACE"
echo "LAN IP: $LAN_IP/$LAN_NETMASK"
echo "DHCP Range: $DHCP_START - $DHCP_END"
echo "Domain: $DOMAIN"
echo "DC IPs: ${DC_IPS[*]}"
echo "Default DNS: $DEFAULT_DNS"
echo "SSH: $SSH_USER@$SSH_SERVER"
echo

echo "Proceed with configuration? (Y/n)"
read -n 1 proceed
echo
if [[ ! -z "$proceed" && ! "$proceed" =~ ^[Yy]$ ]]; then
    echo "Setup cancelled."
    exit 0
fi

# Save configuration for future use
save_config

echo
echo "=== Starting Setup ==="

# Step 1: Configure network interfaces
echo "Configuring network interfaces..."
configure_network_interfaces

# Step 2: Restart networking
echo "Restarting networking..."
restart_network_service
run_cmd sleep 2

# Step 3: Configure dnsmasq
echo "Configuring dnsmasq..."
run_cmd cp /etc/dnsmasq.conf /etc/dnsmasq.conf.backup.$(date +%Y%m%d_%H%M%S)

cat > /etc/dnsmasq.conf << EOF
# Set port (because of dns_over_tcp)
port=5353

# DHCP server
dhcp-range=$DHCP_START,$DHCP_END,12h
dhcp-option=option:dns-server,$LAN_IP
dhcp-authoritative

# Target environment DNS information
EOF

for dc_ip in "${DC_IPS[@]}"; do
    echo "server=/$DOMAIN/$dc_ip" >> /etc/dnsmasq.conf
done

cat >> /etc/dnsmasq.conf << EOF

# Default DNS server
server=$DEFAULT_DNS

# Log DNS queries to the syslog
log-queries
log-facility=/var/log/dnsmasq.log
EOF

# Step 4: Restart dnsmasq
echo "Restarting dnsmasq..."
restart_dnsmasq_service

# Step 5: Set nameserver and lock resolv.conf
echo "Configuring local DNS resolution..."
run_cmd cp /etc/resolv.conf /etc/resolv.conf.backup.$(date +%Y%m%d_%H%M%S)
run_cmd chattr -i /etc/resolv.conf 2>/dev/null || true
echo "Running: echo 'nameserver 127.0.0.1' > /etc/resolv.conf"
echo "nameserver 127.0.0.1" > /etc/resolv.conf
run_cmd chattr +i /etc/resolv.conf

# Step 6: Configure IP forwarding
echo "Enabling IP forwarding..."
run_cmd echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
echo "Applying IP forwarding setting immediately..."
SYSCTL_CMD=$(get_sysctl_cmd)
run_cmd $SYSCTL_CMD -w net.ipv4.ip_forward=1

# Step 7: Prepare for DNS over TCP proxy (will start in tmux)
echo "Preparing DNS over TCP proxy..."
if [ -f "./dns_over_tcp.py" ]; then
    echo "DNS over TCP script found - will start in tmux pane"
else
    echo "Warning: dns_over_tcp.py not found in current directory"
fi

# Step 8: Set up tunnel interface
echo "Setting up tunnel interface..."
run_cmd ip tuntap add mode tun dev $TUN_INTERFACE 2>/dev/null || true
run_cmd ip addr add $TUN_IP/$TUN_CIDR dev $TUN_INTERFACE
run_cmd ip link set dev $TUN_INTERFACE up

# Step 9: Set up routes
echo "Setting up routes..."
if [ -f "./add_routes.sh" ] && [ -f "routes.txt" ]; then
    run_cmd chmod +x ./add_routes.sh
    echo "Running: ./add_routes.sh routes.txt $TUN_INTERFACE $TUN_IP"
    ./add_routes.sh routes.txt $TUN_INTERFACE $TUN_IP
else
    echo "Warning: add_routes.sh or routes.txt not found"
fi

# Step 10: Set up iptables for NAT
echo "Setting up iptables NAT rules..."

# Get iptables command path
IPTABLES_CMD=$(get_iptables_cmd)

# Internet NAT
run_cmd $IPTABLES_CMD -t nat -A POSTROUTING -o $INTERNET_INTERFACE -j MASQUERADE
run_cmd $IPTABLES_CMD -A FORWARD -i $INTERNET_INTERFACE -o $LAN_INTERFACE -m state --state RELATED,ESTABLISHED -j ACCEPT
run_cmd $IPTABLES_CMD -A FORWARD -i $LAN_INTERFACE -o $INTERNET_INTERFACE -j ACCEPT

# Target network NAT
run_cmd $IPTABLES_CMD -t nat -A POSTROUTING -o $TUN_INTERFACE -j MASQUERADE
run_cmd $IPTABLES_CMD -A FORWARD -i $TUN_INTERFACE -o $LAN_INTERFACE -m state --state RELATED,ESTABLISHED -j ACCEPT
run_cmd $IPTABLES_CMD -A FORWARD -i $LAN_INTERFACE -o $TUN_INTERFACE -j ACCEPT

echo
echo "=== Setup Complete ==="
echo
echo "=== Starting Services in tmux Session ==="
echo
echo "Creating tmux session 'lofl' with multiple panes for monitoring..."

# Kill existing tmux session if it exists
tmux kill-session -t lofl 2>/dev/null || true

# Create new tmux session
run_cmd tmux new-session -d -s lofl -x 120 -y 30

# Rename the first window
run_cmd tmux rename-window -t lofl:0 'LOFL-Services'

# Split the window into 4 panes
run_cmd tmux split-window -h -t lofl:0
run_cmd tmux split-window -v -t lofl:0.0
run_cmd tmux split-window -v -t lofl:0.1

# Pane 0 (top-left): DNS over TCP
if [ -f "./dns_over_tcp.py" ]; then
    tmux send-keys -t lofl:0.0 "python3 ./dns_over_tcp.py" Enter
else
    tmux send-keys -t lofl:0.0 "echo 'ERROR: dns_over_tcp.py not found'" Enter
fi

# Pane 1 (bottom-left): Traffic logging
tmux send-keys -t lofl:0.1 "tcpdump -s0 -n -i $TUN_INTERFACE -w \$(date +%Y%m%d%H%M%S).pcap" Enter

# Pane 2 (top-right): SSH SOCKS tunnel
# Use sshpass for password authentication or key-based auth
if [ -n "$SSH_PASSWORD" ]; then
    # Use sshpass for password authentication with host key acceptance
    tmux send-keys -t lofl:0.2 "sshpass -p '$SSH_PASSWORD' ssh -o StrictHostKeyChecking=accept-new $SSH_USER@$SSH_SERVER -N -L 1080:127.0.0.1:1080" Enter
else
    # Use key-based authentication with host key acceptance
    tmux send-keys -t lofl:0.2 "ssh -o StrictHostKeyChecking=accept-new $SSH_USER@$SSH_SERVER -N -L 1080:127.0.0.1:1080" Enter
fi

# Pane 3 (bottom-right): tun2socks (wait for SSH tunnel)
if command -v tun2socks >/dev/null 2>&1; then
    # Create a script that waits for SSH tunnel then starts tun2socks
    tmux send-keys -t lofl:0.3 "while ! nc -z 127.0.0.1 1080; do sleep 2; done && tun2socks -device $TUN_INTERFACE -proxy socks5://127.0.0.1:1080" Enter
else
    tmux send-keys -t lofl:0.3 "echo 'ERROR: tun2socks not found in PATH'" Enter
fi

# Add 5th pane for CLDAP (split bottom-right pane vertically)
run_cmd tmux split-window -v -t lofl:0.3
sleep 2

# Pane 4 (bottom-center): CLDAP proxy
if [ -f "./cldaproxy.sh" ]; then
    tmux send-keys -t lofl:0.4 "./cldaproxy.sh $DOMAIN" Enter
else
    tmux send-keys -t lofl:0.4 "echo 'ERROR: cldaproxy.sh not found'" Enter
fi

# Create labels for each pane
tmux send-keys -t lofl:0.0 C-l
tmux send-keys -t lofl:0.1 C-l
tmux send-keys -t lofl:0.2 C-l
tmux send-keys -t lofl:0.3 C-l
tmux send-keys -t lofl:0.4 C-l

echo
echo "=== Configuration Summary ==="
echo "Internet Interface: $INTERNET_INTERFACE"
echo "LAN Interface: $LAN_INTERFACE"
echo "Tunnel Interface: $TUN_INTERFACE ($TUN_IP/$TUN_CIDR)"
echo "LAN IP: $LAN_IP/$LAN_NETMASK"
echo "DHCP Range: $DHCP_START - $DHCP_END"
echo "Domain: $DOMAIN"
echo "DC IPs: ${DC_IPS[*]}"
echo "Default DNS: $DEFAULT_DNS"
echo "SSH: $SSH_USER@$SSH_SERVER"
echo
echo "tmux session 'lofl' created with 5 panes:"
echo "  - Top-left: DNS over TCP proxy"
echo "  - Bottom-left: Traffic capture"
echo "  - Top-right: SSH SOCKS tunnel"
echo "  - Bottom-right: tun2socks"
echo "  - Bottom-center: CLDAP proxy"
echo
echo "To attach to the session: tmux attach-session -t lofl"
echo "To kill session: tmux kill-session -t lofl"

