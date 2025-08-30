#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/functions.sh"

PACKAGES_DIR="$SCRIPT_DIR/packages"
ELK_ENV_FILE="$SCRIPT_DIR/.elk_env"

trap 'echo -e "\n${YELLOW}⚠️  Suricata installation interrupted by user. Returning to menu...${NC}"; return' SIGINT

# Function to print and log summary
declare -A SUMMARY
add_to_summary_table() {
  SUMMARY["$1"]="$2"
}
print_summary_table() {
  for key in "${!SUMMARY[@]}"; do
    printf "${GREEN}%-20s${NC}: %s\n" "$key" "${SUMMARY[$key]}"
  done
}

# Begin install
clear
echo -e "${GREEN}📡 Starting Suricata installation...${NC}"
uninstall_and_cleanup_suricata

# 🔹 Prompt for install method
echo -e "${CYAN}How would you like to install Suricata?${NC}"
echo -e "  ${YELLOW}apt${NC}    → Install via APT (recommended)"
echo -e "  ${YELLOW}source${NC} → (Not yet supported)"
read -rp "$(echo -e "${GREEN}Enter your choice [apt/source]: ${NC}")" INSTALL_METHOD

# 🔹 Prompt for install method (loop until valid)
while true; do
  echo -e "${CYAN}How would you like to install Suricata?${NC}"
  echo -e "  ${YELLOW}apt${NC}    → Install via APT (recommended)"
  echo -e "  ${YELLOW}source${NC} → (Not yet supported)"
  read -rp "$(echo -e "${GREEN}Enter your choice [apt/source]: ${NC}")" INSTALL_METHOD

  if [[ "$INSTALL_METHOD" =~ ^[Aa][Pp][Tt]$ ]]; then
    INSTALL_METHOD="apt"
    break
  elif [[ "$INSTALL_METHOD" =~ ^[Ss][Oo][Uu][Rr][Cc][Ee]$ ]]; then
    echo -e "${YELLOW}⚠️  Source-based Suricata installation is not yet supported.${NC}"
    echo -e "${CYAN}Please choose the ${YELLOW}apt${CYAN} method instead.${NC}"
  else
    echo -e "${RED}❌ Invalid selection. Please enter 'apt'.${NC}"
  fi
done

# Install Suricata via APT
echo -e "${GREEN}📦 Installing Suricata via APT...${NC}"
sudo apt-get update
sudo apt-get install -y suricata

# Verify installation
if ! command -v suricata &>/dev/null; then
  echo -e "${RED}❌ Suricata installation failed.${NC}"
  exit 1
fi

SURICATA_VERSION=$(suricata -V | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')
echo -e "${GREEN}✅ Installed Suricata version: ${YELLOW}${SURICATA_VERSION}${NC}"
add_to_summary_table "Suricata Version" "$SURICATA_VERSION"

# Scan available interfaces
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

# Abort or pause if no interfaces are found
if [[ "${#VALID_INTERFACES[@]}" -eq 0 ]]; then
  echo -e "\n${RED}❌ No usable interfaces found for monitoring.${NC}"
  echo -e "${YELLOW}Please connect a network interface and re-run the script.${NC}"
  read -rp "Press Enter to return or Ctrl+C to exit..."
  return 1
fi

# Notify if any interfaces already in promiscuous mode
if [[ "$PROM_FOUND" == true ]]; then
  echo -e "${GREEN}✔ At least one interface is already in promiscuous mode.${NC}"
fi

# Prompt for interface selection
while true; do
  read -rp "$(echo -e "${YELLOW}Enter the number of the interface to use for Suricata monitoring: ${NC}")" IFACE_INDEX
  if [[ "$IFACE_INDEX" =~ ^[0-9]+$ ]] && (( IFACE_INDEX >= 1 && IFACE_INDEX <= ${#VALID_INTERFACES[@]} )); then
    SURICATA_IFACE="${VALID_INTERFACES[$((IFACE_INDEX-1))]}"
    echo -e "${GREEN}✔ Selected interface: ${YELLOW}${SURICATA_IFACE}${NC}"
    break
  else
    echo -e "${RED}❌ Invalid selection. Please enter a valid number between 1 and ${#VALID_INTERFACES[@]}.${NC}"
  fi
done

# Bring interface up and set to promiscuous mode
sudo ip link set "$SURICATA_IFACE" up
sudo ip link set "$SURICATA_IFACE" promisc on

# Prompt for HOME_NET
# Validate CIDR (e.g., 192.168.1.0/24)
while true; do
  read -rp "$(echo -e "${YELLOW}Enter HOME_NET value (e.g., 192.168.1.0/24): ${NC}")" HOME_NET
  if [[ "$HOME_NET" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[12][0-9]|3[0-2])$ ]]; then
    IFS='/' read -r ip mask <<< "$HOME_NET"
    if [[ "$ip" =~ ^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$ ]]; then
      break
    fi
  fi
  echo -e "${RED}❌ Invalid subnet format. Please enter in CIDR format (e.g., 10.1.1.0/24).${NC}"
done

# Ask user if they want to enable PCAP logging
read -rp "$(echo -e "${YELLOW}Would you like to enable full PCAP logging in Suricata? (yes/no): ${NC}")" ENABLE_PCAP
if [[ "$ENABLE_PCAP" =~ ^[Yy][Ee]?[Ss]?$ ]]; then

  SURICATA_YAML="/etc/suricata/suricata.yaml"

  if [[ -f "$SURICATA_YAML" ]]; then
    echo -e "${GREEN}🛠 Applying full PCAP capture config to ${YELLOW}$SURICATA_YAML${NC}"

    # Backup the original file
    sudo cp "$SURICATA_YAML" "$SURICATA_YAML.bak"

	# Rebuild suricata.yaml with proper pcap-log block (complete replacement)
	sudo awk '
	  BEGIN { inside_pcap = 0 }
	  /^[[:space:]]*- pcap-log:/ {
		print "  - pcap-log:"
		print "      enabled: yes"
		print "      filename: pcap.%n.%t"
		print "      limit: 1000mb"
		print "      max-files: 2000"
		print "      compression: none"
		print "      mode: multi"
		print "      dir: /var/log/suricata/pcap"
		print "        #enabled: no"
		print "        #filename: log.pcap"
		print ""
		print "      # File size limit.  Can be specified in kb, mb, gb.  Just a number"
		print "      # is parsed as bytes."
		print "      #limit: 1000mb"
		print ""
		print "      # If set to a value, ring buffer mode is enabled. Will keep maximum of"
		print "      # \"max-files\" of size \"limit\""
		print "      #max-files: 2000"
		print ""
		print "      # Compression algorithm for pcap files. Possible values: none, lz4."
		print "      # Enabling compression is incompatible with the sguil mode. Note also"
		print "      # that on Windows, enabling compression will *increase* disk I/O."
		print "      #compression: none"
		print ""
		print "      # Further options for lz4 compression. The compression level can be set"
		print "      # to a value between 0 and 16, where higher values result in higher"
		print "      # compression."
		print "      #lz4-checksum: no"
		print "      #lz4-level: 0"
		print ""
		print "        #mode: normal # normal, multi or sguil."
		print ""
		print "      # Directory to place pcap files. If not provided the default log"
		print "      # directory will be used. Required for \"sguil\" mode."
		print "      #dir: /nsm_data/"
		print ""
		print "      #ts-format: usec # sec or usec second format (default) is filename.sec usec is filename.sec.usec"
		print "      use-stream-depth: no #If set to \"yes\" packets seen after reaching stream inspection depth are ignored. \"no\" logs all packets"
		print "      honor-pass-rules: no # If set to \"yes\", flows in which a pass rule matched will stop being logged."
		print "      # Use \"all\" to log all packets or use \"alerts\" to log only alerted packets and flows or \"tag\""
		print "      # to log only flow tagged via the \"tag\" keyword"
		print "      #conditional: all"
		inside_pcap = 1
		next
	  }
	  inside_pcap {
		if (/^[[:space:]]{2,}[^[:space:]]/) {
		  # Still inside pcap-log block, skip lines
		  next
		} else if (/^[[:space:]]{0,1}[^[:space:]]/) {
		  # New top-level key, stop skipping
		  inside_pcap = 0
		} else {
		  # Inside pcap-log, skip line
		  next
		}
	  }
	  { print }
	' "$SURICATA_YAML.bak" | sudo tee "$SURICATA_YAML" > /dev/null

    # Ensure log directory exists
    sudo mkdir -p /var/log/suricata/pcap
    sudo chown suricata:suricata /var/log/suricata/pcap

    echo -e "${GREEN}✅ PCAP logging block updated successfully in suricata.yaml${NC}"
  else
    echo -e "${RED}❌ suricata.yaml not found. Skipping PCAP logging setup.${NC}"
  fi
else
  echo -e "${CYAN}ℹ️ Skipping PCAP logging setup as requested.${NC}"
fi

# Update suricata.yml
CONFIG_FILE="/etc/suricata/suricata.yaml"
echo -e "${CYAN}🛠 Configuring Suricata in ${CONFIG_FILE}...${NC}"
if [[ -f "$CONFIG_FILE" ]]; then
  sudo sed -i "s|HOME_NET:.*|HOME_NET: \"[$HOME_NET]\"|" "$CONFIG_FILE"
  sudo sed -i "/af-packet:/,/ - interface:/ s|interface:.*|interface: $SURICATA_IFACE|" "$CONFIG_FILE"
else
  echo -e "${RED}❌ Could not find Suricata config file at $CONFIG_FILE${NC}"
  exit 1
fi

# Update rules
echo -e "${GREEN}📥 Updating Suricata rules...${NC}"
sudo suricata-update

# Start and enable Suricata
echo -e "${GREEN}🚀 Starting Suricata service...${NC}"
sudo systemctl start suricata
sleep 2

echo -e "${GREEN}🔒 Enabling Suricata to start on boot...${NC}"
sudo systemctl enable suricata

# Display status
sudo systemctl status suricata --no-pager

# Save to env file
echo "SURICATA_VERSION=\"$SURICATA_VERSION\"" >> "$ELK_ENV_FILE"
echo "SURICATA_INTERFACE=\"$SURICATA_IFACE\"" >> "$ELK_ENV_FILE"
echo "SURICATA_HOME_NET=\"$HOME_NET\"" >> "$ELK_ENV_FILE"

# Summary
echo -e "\n${GREEN}📄 Suricata installation summary:${NC}"
print_summary_table