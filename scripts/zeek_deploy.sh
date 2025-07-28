#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/functions.sh"

PACKAGES_DIR="$SCRIPT_DIR/packages"
ELK_ENV_FILE="$SCRIPT_DIR/.elk_env"

trap 'echo -e "\n${YELLOW}⚠️   Zeek installation interrupted by user. Returning to main menu...${NC}"; pause_and_return_to_menu' SIGINT
trap - SIGINT

echo -e "${GREEN}📡 Starting Zeek installation process...${NC}"

# 🔍 Check for existing Zeek service and prompt to uninstall
uninstall_and_cleanup_zeek

# 🔹 Prompt for install method
echo -e "${CYAN}How would you like to install Zeek?${NC}"
echo -e "  ${YELLOW}apt${NC}    → Install via APT (faster, easier)"
echo -e "  ${YELLOW}source${NC} → Build from source (slower, supports airgapped)"
read -rp "$(echo -e "${GREEN}Enter your choice [apt/source]: ${NC}")" INSTALL_METHOD

if [[ "$INSTALL_METHOD" == "apt" ]]; then
    echo -e "${GREEN}📦 Installing Zeek via APT...${NC}"
    
    echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /' | sudo tee /etc/apt/sources.list.d/security:zeek.list
    curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_22.04/Release.key | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null
    
    sudo apt update
    sudo apt install -y zeek

    echo -e "${GREEN}🧩 Adding Zeek to PATH (/opt/zeek)...${NC}"
    if ! grep -q '/opt/zeek/bin' ~/.bashrc; then
        echo 'export PATH=/opt/zeek/bin:$PATH' >> ~/.bashrc
    fi
    export PATH="/opt/zeek/bin:$PATH"

    echo -e "${GREEN}🔍 Verifying Zeek installation...${NC}"
    if command -v zeek >/dev/null; then
        zeek --version
    else
        echo -e "${RED}❌ Zeek not found in PATH. Aborting.${NC}"
        exit 1
    fi

    ZEEK_VERSION=$(zeek --version | awk '{print $3}')
    add_to_summary_table "Zeek Version" "$ZEEK_VERSION"
    add_to_summary_table "Install Method" "APT (/opt/zeek)"
    
    goto_configure_interface=true

elif [[ "$INSTALL_METHOD" == "source" ]]; then
    echo -e "${YELLOW}⚠️ Building Zeek from source. This is CPU-intensive and may take 5–10 minutes.${NC}"
    sleep 2

    ZEEK_TAR_PATH=$(find "$PACKAGES_DIR" -maxdepth 1 -type f -name "zeek-*.tar.gz" | head -n 1)
    if [[ -z "$ZEEK_TAR_PATH" ]]; then
        echo -e "${RED}❌ No Zeek tarball found in '${PACKAGES_DIR}'.${NC}"
        echo -e "${YELLOW}Please download and place a file like 'zeek-${DEFAULT_ZEEK_VERSION}.tar.gz' into '${PACKAGES_DIR}'${NC}"
        echo -e "  - ${BLUE}https://download.zeek.org/${NC}"
        exit 1
    fi

    FOUND_ZEEK_VERSION=$(basename "$ZEEK_TAR_PATH" | sed -n 's/zeek-\(.*\)\.tar\.gz/\1/p')
    if [[ -z "$FOUND_ZEEK_VERSION" ]]; then
        echo -e "${RED}❌ Unable to determine Zeek version from tarball filename.${NC}"
        exit 1
    fi

    ZEEK_VERSION="$FOUND_ZEEK_VERSION"
    ZEEK_SRC_DIR="zeek-${ZEEK_VERSION}"
    add_to_summary_table "Zeek Version" "$ZEEK_VERSION"
    add_to_summary_table "Install Method" "Local Tarball (Airgapped)"

    echo -e "${GREEN}📋 Checking for required packages...${NC}"
    REQUIRED_PACKAGES=(cmake make gcc g++ flex bison libpcap-dev libssl-dev python3-dev swig zlib1g-dev)
    MISSING_PACKAGES=()

    for pkg in "${REQUIRED_PACKAGES[@]}"; do
        if ! dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "install ok installed"; then
            MISSING_PACKAGES+=("$pkg")
        fi
    done

    if [[ ${#MISSING_PACKAGES[@]} -gt 0 ]]; then
        echo -e "${YELLOW}⚠️  The following packages are missing and will be installed:${NC}"
        for pkg in "${MISSING_PACKAGES[@]}"; do
            echo -e "   - ${YELLOW}$pkg${NC}"
        done
        sudo apt-get update -y
        sudo apt-get install -y "${MISSING_PACKAGES[@]}"
    fi

    echo -e "${GREEN}📁 Extracting Zeek package...${NC}"
    cd "$PACKAGES_DIR" || exit 1
    rm -rf "$ZEEK_SRC_DIR" 2>/dev/null
    tar -xzf "$ZEEK_TAR_PATH"
    cd "$ZEEK_SRC_DIR" || exit 1

    echo -e "${GREEN}⚙️  Configuring Zeek build...${NC}"
    ./configure || { echo -e "${RED}❌ Configuration failed. Aborting.${NC}"; exit 1; }

    echo -e "${GREEN}🔨 Compiling Zeek...${NC}"
    make -j"$(nproc)" || { echo -e "${RED}❌ Compilation failed. Aborting.${NC}"; exit 1; }

    echo -e "${GREEN}📥 Installing Zeek to /usr/local/zeek...${NC}"
    sudo make install || { echo -e "${RED}❌ Installation failed. Aborting.${NC}"; exit 1; }

    echo -e "${GREEN}🧩 Adding Zeek to PATH...${NC}"
    if ! grep -q '/usr/local/zeek/bin' ~/.bashrc; then
        echo 'export PATH=/usr/local/zeek/bin:$PATH' >> ~/.bashrc
    fi
    export PATH="/usr/local/zeek/bin:$PATH"

    echo -e "${GREEN}🔍 Verifying Zeek installation...${NC}"
    which zeek && zeek --version || { echo -e "${RED}❌ Zeek not found in PATH. Aborting.${NC}"; exit 1; }

    goto_configure_interface=true
else
    echo -e "${RED}❌ Invalid install option. Exiting.${NC}"
    exit 1
fi

# Interface setup
if [[ "$goto_configure_interface" == true ]]; then
    echo -e "${GREEN}🌐 Scanning available network interfaces...${NC}"

    # Get all non-loopback interfaces
    INTERFACES=($(ip -o link show | awk -F': ' '{print $2}' | grep -v '^lo$'))

    VALID_INTERFACES=()
    PROM_FOUND=false

    echo -e "${GREEN}📋 Interface List:${NC}"
    for i in "${!INTERFACES[@]}"; do
        iface="${INTERFACES[$i]}"
        ip_addr=$(ip -o -4 addr show dev "$iface" | awk '{print $4}')
        [[ -z "$ip_addr" ]] && ip_addr="N/A"

        prom_status=$(ip link show "$iface" | grep -q PROMISC && echo "yes" || echo "no")
        [[ "$prom_status" == "yes" ]] && PROM_FOUND=true

        if [[ "$ip_addr" == "N/A" ]]; then
            echo -e " $((i+1)). Interface: ${YELLOW}$iface${NC} | IP: ${CYAN}$ip_addr${NC} ${MAGENTA}(🛑 No IP — good for monitoring)${NC}"
        else
            echo -e " $((i+1)). Interface: ${YELLOW}$iface${NC} | IP: ${CYAN}$ip_addr${NC}"
        fi

        VALID_INTERFACES+=("$iface")
    done

    if [[ "${#VALID_INTERFACES[@]}" -eq 0 ]]; then
        echo -e "\n${RED}❌ No usable interfaces found. Please connect a network interface and try again.${NC}"
        echo -e "${YELLOW}Returning to main menu or press Ctrl+C to abort...${NC}"
        read -rp "Press Enter to continue..."
        return 1
    fi

    if [[ "$PROM_FOUND" == true ]]; then
        echo -e "${GREEN}✔ At least one interface is already in promiscuous mode.${NC}"
    fi

    while true; do
        read -rp "$(echo -e "${YELLOW}Enter the number of the interface to use for Zeek monitoring: ${NC}")" IFACE_INDEX
        if [[ "$IFACE_INDEX" =~ ^[0-9]+$ ]] && (( IFACE_INDEX >= 1 && IFACE_INDEX <= ${#VALID_INTERFACES[@]} )); then
            ZEEK_IFACE="${VALID_INTERFACES[$((IFACE_INDEX-1))]}"
            echo -e "${GREEN}✔ Selected interface: ${YELLOW}${ZEEK_IFACE}${NC}"
            break
        else
            echo -e "${RED}❌ Invalid selection. Please enter a valid number between 1 and ${#VALID_INTERFACES[@]}.${NC}"
        fi
    done

    echo -e "${GREEN}🔧 Bringing up interface ${YELLOW}${ZEEK_IFACE}${GREEN} in promiscuous mode...${NC}"
    sudo ip link set "$ZEEK_IFACE" up
    sudo ip link set "$ZEEK_IFACE" promisc on

    add_to_summary_table "Zeek Interface" "$ZEEK_IFACE"

    # Configure Zeek
    if [[ -f "/usr/local/zeek/etc/node.cfg" ]]; then
        ZEEK_ETC_PATH="/usr/local/zeek/etc"
    elif [[ -f "/opt/zeek/etc/node.cfg" ]]; then
        ZEEK_ETC_PATH="/opt/zeek/etc"
    else
        echo -e "${RED}❌ Could not locate Zeek node.cfg in standard locations.${NC}"
        exit 1
    fi

    echo -e "${GREEN}📄 Found Zeek config in: ${YELLOW}${ZEEK_ETC_PATH}${NC}"
    cd "$ZEEK_ETC_PATH" || { echo -e "${RED}❌ Failed to change to $ZEEK_ETC_PATH${NC}"; exit 1; }

    cp node.cfg node.cfg.bak
    sed -i "s/^interface=.*/interface=$ZEEK_IFACE/" node.cfg

    echo -e "${GREEN}📄 Updating local.zeek with file extract + JSON logging...${NC}"
    LOCAL_ZEEK_PATH=""
    if [[ -f "/usr/local/zeek/share/zeek/site/local.zeek" ]]; then
        LOCAL_ZEEK_PATH="/usr/local/zeek/share/zeek/site/local.zeek"
    elif [[ -f "/opt/zeek/share/zeek/site/local.zeek" ]]; then
        LOCAL_ZEEK_PATH="/opt/zeek/share/zeek/site/local.zeek"
    fi

    if [[ -n "$LOCAL_ZEEK_PATH" ]] && ! grep -q '@load frameworks/files/extract-all-files' "$LOCAL_ZEEK_PATH"; then
        cat <<EOF >> "$LOCAL_ZEEK_PATH"

@load frameworks/files/extract-all-files
redef ignore_checksums=T;
redef LogAscii::use_json=T;
EOF
        echo -e "${GREEN}✅ local.zeek updated at ${YELLOW}${LOCAL_ZEEK_PATH}${NC}"
    fi

    echo -e "${GREEN}✅ Checking Zeek configuration...${NC}"
    zeekctl check || { echo -e "${RED}❌ Zeek check failed. Please review node.cfg.${NC}"; exit 1; }

    echo -e "${GREEN}🚀 Deploying Zeek...${NC}"
    zeekctl deploy

    echo -e "${GREEN}📊 Zeek status:${NC}"
    zeekctl status

    echo -e "${GREEN}📁 Zeek logs available in:${NC} ${YELLOW}/usr/local/zeek/logs/current${NC}"
    echo -e "${GREEN}📖 To follow logs in real-time, run:${NC} ${YELLOW}tail -f /usr/local/zeek/logs/current/conn.log${NC}"

    # Detect zeekctl path and create systemd service
    ZEEKCTL_BIN="$(command -v zeekctl)"
    if [[ -z "$ZEEKCTL_BIN" ]]; then
        echo -e "${RED}❌ zeekctl not found in PATH. Cannot create systemd service.${NC}"
        exit 1
    fi

    if [[ ! -f /etc/systemd/system/zeek.service ]]; then
        echo -e "${CYAN}🔧 Creating systemd service for Zeek...${NC}"
        sudo tee /etc/systemd/system/zeek.service > /dev/null <<EOF
[Unit]
Description=Zeek Network Security Monitor
After=network.target

[Service]
ExecStart=${ZEEKCTL_BIN} start
ExecStop=${ZEEKCTL_BIN} stop
ExecReload=${ZEEKCTL_BIN} deploy
Type=forking
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
        sudo systemctl daemon-reexec
        sudo systemctl daemon-reload
    fi

    echo -e "${GREEN}🔒 Enabling Zeek to start on boot...${NC}"
    sudo systemctl enable zeek

    echo -e "${GREEN}🚀 Starting Zeek service via systemd...${NC}"
    sudo systemctl start zeek
    sleep 2
    sudo systemctl status zeek --no-pager

    echo "ZEEK_VERSION=\"$ZEEK_VERSION\"" >> "$ELK_ENV_FILE"
    echo "ZEEK_INTERFACE=\"$ZEEK_IFACE\"" >> "$ELK_ENV_FILE"
fi

# Final summary
echo -e "\n${GREEN}📄 Zeek installation summary:${NC}"
print_summary_table

# Final summary
echo -e "\n${GREEN}📄 Zeek installation summary:${NC}"
print_summary_table
