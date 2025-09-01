#!/bin/bash
clear
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/functions.sh"
init_colors

# Trap Ctrl+C and return to menu
trap 'echo -e "\n${YELLOW}⚠️   Setup interrupted by user. Returning to main menu...${NC}"; pause_and_return_to_menu' SIGINT

# Disable trap after read completes
trap - SIGINT

echo -e "${GREEN}"
cat << 'EOF'
▓█████  ██▓     ██ ▄█▀    ▄▄▄▄    ▄▄▄        ██████  ██░ ██ 
▓█   ▀ ▓██▒     ██▄█▒    ▓█████▄ ▒████▄    ▒██    ▒ ▓██░ ██▒
▒███   ▒██░    ▓███▄░    ▒██▒ ▄██▒██  ▀█▄  ░ ▓██▄   ▒██▀▀██░
▒▓█  ▄ ▒██░    ▓██ █▄    ▒██░█▀  ░██▄▄▄▄██   ▒   ██▒░▓█ ░██ 
░▒████▒░██████▒▒██▒ █▄   ░▓█  ▀█▓ ▓█   ▓██▒▒██████▒▒░▓█▒░██▓
░░ ▒░ ░░ ▒░▓  ░▒ ▒▒ ▓▒   ░▒▓███▀▒ ▒▒   ▓▒█░▒ ▒▓▒ ▒ ░ ▒ ░░▒░▒
 ░ ░  ░░ ░ ▒  ░░ ░▒ ▒░   ▒░▒   ░   ▒   ▒▒ ░░ ░▒  ░ ░ ▒ ░▒░ ░
   ░     ░ ░   ░ ░░ ░     ░    ░   ░   ▒   ░  ░  ░   ░  ░░ ░
   ░  ░    ░  ░░  ░       ░            ░  ░      ░   ░  ░  ░                         
EOF
echo -e "${NC}"

# Check for sudo usage
if [[ "$EUID" -eq 0 && -z "$SUDO_USER" ]]; then
    echo -e "${RED}❌ Please run this script using sudo, not as the root user directly (e.g., use: sudo ./script.sh).${NC}"
    exit 1
fi

echo -e "${GREEN}✔ Running with sudo as expected.${NC}"

# --- Confirm local ELK (Elasticsearch, Logstash, Kibana) deployment with TLS ---
printf '%b\n' "${CYAN}This will deploy ${YELLOW}Elasticsearch${NC}, ${YELLOW}Logstash${NC}, and ${YELLOW}Kibana${NC} on this node with ${YELLOW}TLS${NC} configured."

# Loop until the user types a valid "yes" or "no"
while true; do
  read -rp "$(printf '%b' "${GREEN}Proceed with deployment? Type ${YELLOW}yes${GREEN} or ${RED}no${GREEN}: ${NC}")" CONFIRM_DEPLOY
  case "${CONFIRM_DEPLOY,,}" in
    y|yes)
      printf '%b\n' "${GREEN}✔ Proceeding with ELK+TLS deployment on this node...${NC}"
      DEPLOY_ELK_TLS="yes"
      break
      ;;
    n|no)
      printf '%b\n' "${YELLOW}ℹ Deployment canceled by user. No changes made.${NC}"
      DEPLOY_ELK_TLS="no"
      # If this script is sourced, return; otherwise exit cleanly.
      return 0 2>/dev/null || exit 0
      ;;
    *)
      printf '%b\n' "${RED}❌ Invalid input. Please type exactly 'yes' or 'no'.${NC}"
      ;;
  esac
done

# --- Prompt for ELK install history ---
echo -e "\n${GREEN}Has Elasticsearch, Logstash, or Kibana ever been installed on this machine before?${NC}"
prompt_input "$(echo -e "${GREEN}Type \"${YELLOW}yes${GREEN}\" if there is a previous installation on this machine, or \"${YELLOW}no${GREEN}\" to continue with a fresh install:${NC} ")" INSTALL_RESPONSE

# --- Function to clean up any existing ELK stack and Elastic Agent ---
perform_elk_cleanup() {
    echo -e "\n${YELLOW}Starting cleanup of any existing ELK stack components...${NC}"
    echo "           This may take a few minutes — Go grab a coffee!"
    echo -e "${NC}\n"

	# Spinner function
	spinner() {
		local pid=$1
		local delay=0.1
		local spinstr='|/-\\'  # <- Fixed: Escaped the backslash
		while ps -p "$pid" > /dev/null 2>&1; do
			local temp=${spinstr#?}
			printf " [%c]  " "$spinstr"
			spinstr=$temp${spinstr%"$temp"}
			sleep $delay
			printf "\b\b\b\b\b\b"
		done
		printf "    \b\b\b\b"
	}

    # Stop and disable services
    for svc in elasticsearch logstash kibana; do
        if systemctl list-units --type=service | grep -q "$svc"; then
            echo -e "${CYAN}Stopping and disabling $svc...${NC}"
            sudo systemctl stop "$svc" 2>/dev/null || echo -e "${YELLOW}Could not stop $svc or it was not running.${NC}"
            sudo systemctl disable "$svc" 2>/dev/null || echo -e "${YELLOW}Could not disable $svc or it was not enabled.${NC}"
        else
            echo -e "${YELLOW}$svc service not found. Skipping systemd stop...${NC}"
        fi

        # Kill lingering processes
        echo -e "${CYAN}Killing any remaining $svc processes...${NC}"
        sudo pkill -f "$svc" 2>/dev/null || echo -e "${YELLOW}No lingering $svc processes found.${NC}"
    done

    # Elastic Agent cleanup
    echo -e "${CYAN}Checking for Elastic Agent cleanup...${NC}"
    if pgrep -f elastic-agent > /dev/null; then
        echo -e "${YELLOW}Elastic Agent process detected. Terminating...${NC}"
        sudo pkill -f elastic-agent
        echo -e "${GREEN}✔ Elastic Agent process terminated.${NC}"
    else
        echo -e "${GREEN}No running Elastic Agent process found.${NC}"
    fi

    if [ -d "/opt/Elastic" ]; then
        echo -e "${YELLOW}Removing existing Elastic Agent installation at /opt/Elastic...${NC}"
        sudo rm -rf /opt/Elastic
        echo -e "${GREEN}✔ Elastic Agent directory removed successfully.${NC}"
    else
        echo -e "${GREEN}No Elastic Agent directory found at /opt/Elastic. Skipping...${NC}"
    fi

    if [ -f "/etc/systemd/system/elastic-agent.service" ]; then
        echo -e "${YELLOW}Found systemd unit file for Elastic Agent. Cleaning up...${NC}"
        sudo systemctl disable elastic-agent 2>/dev/null || true
        sudo rm -f /etc/systemd/system/elastic-agent.service
        sudo systemctl daemon-reexec
        sudo systemctl daemon-reload
        echo -e "${GREEN}✔ Removed stale elastic-agent systemd service.${NC}"
    else
        echo -e "${GREEN}No elastic-agent systemd service file found. Skipping...${NC}"
    fi

		# --- Docker Cleanup for Elastic Package Registry ---
	echo -e "${CYAN}Cleaning up Elastic Package Registry Docker resources...${NC}"

	# Containers derived from EPR image (any tag)
	mapfile -t EPR_CONTAINERS < <(docker ps -aq --filter "ancestor=docker.elastic.co/package-registry/distribution" || true)

	if ((${#EPR_CONTAINERS[@]})); then
	  echo -e "${YELLOW}Stopping and removing container(s):${NC}\n${EPR_CONTAINERS[*]}"
	  docker stop "${EPR_CONTAINERS[@]}" >/dev/null 2>&1 || true
	  docker rm   "${EPR_CONTAINERS[@]}" >/dev/null 2>&1 || true
	  echo -e "${GREEN}✔ Containers stopped and removed.${NC}"
	else
	  echo -e "${GREEN}No EPR containers found.${NC}"
	fi

	# Image IDs for EPR
	mapfile -t EPR_IMAGE_IDS < <(
	  docker images --format "{{.Repository}}:{{.Tag}} {{.ID}}" 2>/dev/null \
	  | awk '$1 ~ /^docker\.elastic\.co\/package-registry\/distribution:/ {print $2}' \
	  | sort -u
	) || true

	if ((${#EPR_IMAGE_IDS[@]})); then
	  echo -e "${YELLOW}Removing image(s):${NC}\n${EPR_IMAGE_IDS[*]}"
	  docker rmi -f "${EPR_IMAGE_IDS[@]}" >/dev/null 2>&1 \
		&& echo -e "${GREEN}✔ Image(s) removed.${NC}" \
		|| echo -e "${RED}⚠ Failed to remove some images.${NC}"
	else
	  echo -e "${GREEN}No EPR images found. Skipping image removal...${NC}"
	fi

    # Clean home directory artifacts
    echo -e "${GREEN}Scanning for stale Elastic Agent packages in home directory...${NC}"
    AGENT_TAR_PATTERN="$HOME/elastic-agent-*-linux-x86_64.tar.gz"
    AGENT_DIR_PATTERN="$HOME/elastic-agent-*-linux-x86_64"
    shopt -s nullglob

    AGENT_TARS=($AGENT_TAR_PATTERN)
    if [ ${#AGENT_TARS[@]} -gt 0 ]; then
        for file in "${AGENT_TARS[@]}"; do
            echo -e "${YELLOW}Removing Elastic Agent archive: $(basename "$file")${NC}"
            rm -f "$file"
        done
    else
        echo -e "${GREEN}No Elastic Agent tar.gz files found. Skipping archive cleanup...${NC}"
    fi

    AGENT_DIRS=($AGENT_DIR_PATTERN)
    if [ ${#AGENT_DIRS[@]} -gt 0 ]; then
        for dir in "${AGENT_DIRS[@]}"; do
            if [ -d "$dir" ]; then
                echo -e "${YELLOW}Removing Elastic Agent directory: $(basename "$dir")${NC}"
                rm -rf "$dir"
            fi
        done
    else
        echo -e "${GREEN}No Elastic Agent directories found. Skipping directory cleanup...${NC}"
    fi

    shopt -u nullglob

    # Uninstall packages and remove residual directories
    echo -e "${CYAN}Attempting to uninstall Elasticsearch, Logstash, and Kibana...${NC}"
    sudo apt-get purge -y elasticsearch logstash kibana > /dev/null 2>&1 || true
    sudo apt-get autoremove -y > /dev/null 2>&1 || true

    paths_to_clean=(
        /etc/elasticsearch /etc/logstash /etc/kibana
        /var/lib/elasticsearch /var/lib/logstash
        /var/log/elasticsearch /var/log/logstash /var/log/kibana
        /usr/share/elasticsearch /usr/share/logstash /usr/share/kibana
        /etc/apt/sources.list.d/elastic-8.x.list
        /etc/apt/sources.list.d/elastic-9.x.list
    )

    for path in "${paths_to_clean[@]}"; do
        if [ -e "$path" ]; then
            echo -e "${CYAN}Removing $path...${NC}"
            sudo rm -rf "$path"
        else
            echo -e "${YELLOW}Path not found: $path — skipping.${NC}"
        fi
    done

    echo -e "${GREEN}✔ Cleanup complete. Proceeding with a fresh installation.${NC}"
}

# --- User Input Processing ---
if [[ "$INSTALL_RESPONSE" =~ ^[Yy][Ee]?[Ss]?$ ]]; then
    PREVIOUS_INSTALL=true
    FRESH_INSTALL=false
    perform_elk_cleanup

elif [[ "$INSTALL_RESPONSE" =~ ^[Nn][Oo]$ ]]; then
    echo -e "${YELLOW}User reported this is a clean install. Verifying if indeed this machine is clean...${NC}"

    SERVICES_FOUND=false
    for svc in elasticsearch logstash kibana; do
        if systemctl list-units --type=service | grep -q "$svc"; then
            echo -e "${RED}Detected $svc service on system.${NC}"
            SERVICES_FOUND=true
        fi
    done

    if $SERVICES_FOUND; then
        echo -e "${YELLOW}⚠️  Found Elasticsearch, Logstash, or Kibana services still present.${NC}"
        read -p "$(echo -e "${CYAN}Do you want to clean up old ELK services before continuing? (yes/no): ${NC}")" CONFIRM_CLEANUP

        if [[ "$CONFIRM_CLEANUP" =~ ^[Yy][Ee]?[Ss]?$ ]]; then
            echo -e "${YELLOW}Proceeding with cleanup of old services...${NC}"
            PREVIOUS_INSTALL=true
            FRESH_INSTALL=false
            perform_elk_cleanup
        else
            echo -e "${RED}Cleanup skipped. Cannot proceed while old services exist. Exiting.${NC}"
            exit 1
        fi
    else
        echo -e "${GREEN}System appears clean. Proceeding with fresh install...${NC}"
        PREVIOUS_INSTALL=false
        FRESH_INSTALL=true
    fi

else
    echo -e "${RED}Invalid response. Please enter \"yes\" or \"no\".${NC}"
    exit 1
fi

# Lowercase & trim just in case
INSTALL_RESPONSE="$(echo "$INSTALL_RESPONSE" | tr '[:upper:]' '[:lower:]' | xargs)"

# Add appropriate row to final output table
if [[ "$INSTALL_RESPONSE" == "yes" ]]; then
  add_to_summary_table "Services Cleaned/Reinstalled" "Yes"
elif [[ "$INSTALL_RESPONSE" == "no" ]]; then
  add_to_summary_table "First Time Install" "Yes"
else
  echo -e "${RED}Invalid response. Please type 'yes' or 'no'.${NC}"
  exit 1
fi

# === Deployment Type Selection ===
while true; do
    echo -e "${GREEN}Select the deployment type:${NC}"
    echo -e "${CYAN}  [1] Single-node ELK stack${NC}"
    echo -e "${CYAN}  [2] Multi-node ELK cluster${NC}"
    read -p "$(echo -e "${GREEN}Enter your choice (1 or 2): ${NC}")" DEPLOYMENT_OPTION

    case "$DEPLOYMENT_OPTION" in
        1)
            DEPLOYMENT_TYPE="Single Node"
            echo -e "${GREEN}✔ You selected: single deployment.${NC}"
            add_to_summary_table "Deployment Type" "$DEPLOYMENT_TYPE"
            break
            ;;
        2)
            DEPLOYMENT_TYPE="Cluster"
            echo -e "${GREEN}✔ You selected: cluster deployment.${NC}"
            add_to_summary_table "Deployment Type" "$DEPLOYMENT_TYPE"
            break
            ;;
        *)
            echo -e "${RED}❌ Invalid input. Please enter 1 or 2.${NC}"
            ;;
    esac
done

# === Common IP Prompt and Assignment ===
echo -e "\n${GREEN}Elasticsearch, Logstash, and Kibana will be hosted using the IP you enter below.${NC}"

echo -e "${GREEN}--- Network Interfaces ---${NC}"
ip -br a | awk '{print $1, $2, $3}' | while read iface state addr; do
    echo -e "${CYAN}$iface${NC} - $state - IP: ${YELLOW}$addr${NC}"
done

# Identify default management interface and IP
MGMT_IFACE=$(ip -br a | awk '$1 != "lo" && $3 ~ /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/ {print $1; exit}')
MGMT_IP=$(ip -4 -o addr show dev "$MGMT_IFACE" | awk '{print $4}' | cut -d/ -f1)

echo -e "${GREEN}Use the following IP for accessing this node (management interface):${NC}"
echo -e "${CYAN}$MGMT_IFACE${NC} - ${YELLOW}$MGMT_IP${NC}"

# Prompt for IP and validate until correct
while true; do
    read -p "$(echo -e "${YELLOW}Enter the IP address to use for Elasticsearch, Logstash, and Kibana: ${NC}")" COMMON_IP
    if validate_ip "$COMMON_IP"; then
        echo -e "${GREEN}✔ Accepted IP: $COMMON_IP${NC}"
        break
    else
        echo -e "${RED}❌ Invalid IP format. Please enter a valid IPv4 address.${NC}"
    fi
done

# Assign to services
ELASTIC_HOST=$COMMON_IP
KIBANA_HOST=$COMMON_IP
LOGSTASH_HOST=$COMMON_IP

# Add to summary table
add_to_summary_table "Management IP" "$COMMON_IP"

# Ask if this is an airgapped environment
echo -e "\n${GREEN}Is this machine in an airgapped (offline) environment?${NC}"
prompt_input "$(echo -e "${GREEN}Type ${YELLOW}\"yes\"${GREEN} to skip internet check, or ${YELLOW}\"no\"${GREEN} to verify connectivity: ${NC}")" IS_airgapped

if [[ "$IS_airgapped" =~ ^[Yy][Ee]?[Ss]?$ ]]; then
	echo -e "${YELLOW}airgapped mode confirmed. Skipping internet connectivity check.${NC}"
else
	# --- Check internet connectivity ---
	echo -e "\n${GREEN}Checking internet connectivity...${NC}"
	PING_TARGET="google.com"
	PING_COUNT=2

	if ping -c "$PING_COUNT" "$PING_TARGET" > /dev/null 2>&1; then
		echo -e "${GREEN}Internet connectivity confirmed via ping to ${YELLOW}$PING_TARGET.${NC}"
	else
		echo -e "${RED}Unable to reach $PING_TARGET. Please verify that this host has internet access.${NC}"
		read -p "$(echo -e "${YELLOW}Do you want to retry the connectivity check? (yes/no): ${NC}")" RETRY_NET

		if [[ "$RETRY_NET" =~ ^[Yy][Ee]?[Ss]?$ ]]; then
			echo -e "${YELLOW}Retrying ping...${NC}"
			if ping -c "$PING_COUNT" "$PING_TARGET" > /dev/null 2>&1; then
				echo -e "${GREEN}Internet connectivity confirmed on retry.${NC}"
			else
				echo -e "${RED}Still no internet. Exiting setup.${NC}"
				exit 1
			fi
		else
			echo -e "${RED}User opted not to retry. Exiting setup.${NC}"
			exit 1
		fi
	fi
fi

# Normalize the input
IS_airgapped="$(echo "$IS_airgapped" | tr '[:upper:]' '[:lower:]' | xargs)"

# Validate and add to summary table
if [[ "$IS_airgapped" == "yes" ]]; then
  echo -e "${GREEN}✔ Airgap check skipped.${NC}"
  add_to_summary_table "airgapped Environment" "Yes"
elif [[ "$IS_airgapped" == "no" ]]; then
  echo -e "${GREEN}✔ Internet connectivity will be verified.${NC}"
  add_to_summary_table "airgapped Environment" "No"
else
  echo -e "${RED}❌ Invalid input. Please type 'yes' or 'no'.${NC}"
  exit 1
fi

if [[ "$DEPLOYMENT_TYPE" == "Cluster" ]]; then
    while true; do
        read -p "$(echo -e "${GREEN}How many additional Elasticsearch nodes will be added to this node for clustering? ${YELLOW}(enter a number)${GREEN}: ${NC}")" NODE_INPUT
        if [[ "$NODE_INPUT" =~ ^[1-9][0-9]*$ ]]; then
            NODE_COUNT=$NODE_INPUT
            echo -e "${GREEN}✔ Cluster will include ${YELLOW}$NODE_COUNT${GREEN} additional node(s).${NC}"
            add_to_summary_table "Additional Nodes" "$NODE_COUNT"
            break
        else
            echo -e "${RED}❌ Invalid input. Please enter a positive integer greater than 0.${NC}"
        fi
    done
fi

# Assign to final variable
NODE_COUNT=$NODE_INPUT

echo -e "${GREEN}Cluster will include $NODE_COUNT additional node(s).${NC}"

# Add 1 to include the current node
NODE_COUNT=$((NODE_INPUT + 1))

# Optional: Display the collected IPs
echo -e "${GREEN}Elasticsearch host: ${YELLOW}$ELASTIC_HOST${NC}"
echo -e "${GREEN}Kibana host: ${YELLOW}$KIBANA_HOST${NC}"
echo -e "${GREEN}Logstash host: ${YELLOW}$LOGSTASH_HOST${NC}"

# Prompt in a loop until valid node name is entered
while true; do
	read -p "$(echo -e "${GREEN}Enter the name you would like to assign your node (e.g., ${YELLOW}node-1${GREEN}): ${NC}")" NODE_NAME
	if validate_nodename "$NODE_NAME"; then
		echo -e "${GREEN}✔ Node name '${YELLOW}${NODE_NAME}${GREEN}' is valid and has been accepted.${NC}"
		break
	fi
done

# Prompt for superuser username with validation and confirmation
while true; do
  prompt_input "Enter the superuser username for Kibana webUI access and Elasticsearch interactions: " USERNAME

  # ✅ Only allow alphanumeric and underscores, no @ signs or emails
  if [[ "$USERNAME" =~ ^[a-zA-Z0-9_]+$ ]]; then
    echo -e "${GREEN}✔ Accepted username: $USERNAME${NC}"
    add_to_summary_table "Admin Username" "$USERNAME"
    break
  else
    echo -e "${RED}❌ Invalid username. Only letters, numbers, and underscores are allowed (no @ signs).${NC}"
  fi
done

# Prompt for password with validation and confirmation
while true; do
    read -s -p "$(echo -e "${GREEN}Enter a password for the superuser: ${NC}")" PASSWORD
    echo ""
    if validate_password "$PASSWORD"; then
        read -s -p "$(echo -e "${GREEN}Confirm the password: ${NC}")" PASSWORD_CONFIRM
        echo ""
        if [[ "$PASSWORD" == "$PASSWORD_CONFIRM" ]]; then
            break
        else
            echo -e "${RED}Passwords do not match. Please try again.${NC}"
        fi
    else
        echo -e "${RED}Please enter a valid password.${NC}"
    fi
done

# Final confirmation message
echo -e "\n${GREEN}Created Superuser variables for use later on during install.${NC}"

# Check if the system is Ubuntu
if grep -q '^NAME="Ubuntu"' /etc/os-release; then
    echo -e "\n${BLUE}Ubuntu system detected. Proceeding with LVM check...${NC}"

    # Check for VG free space
    VG_NAME=$(vgdisplay | awk '/VG Name/ {print $3}')
    FREE_EXTENTS=$(vgdisplay "$VG_NAME" | awk '/Free  PE/ {print $5}')

    if [[ "$FREE_EXTENTS" -gt 0 ]]; then
        echo -e "\n${BLUE}Free space detected in volume group [$VG_NAME].${NC}"

        read -p "$(echo -e ${GREEN}'Would you like to extend the root Logical Volume using the available free space? (yes/no): '${NC})" EXTEND_CONFIRM
        if [[ "$EXTEND_CONFIRM" == "yes" ]]; then
            echo -e "${YELLOW}Attempting to extend root Logical Volume to use remaining free space...${NC}"

            echo -e "\n${BLUE}Before lvextend:${NC}"
            sudo lvdisplay

            # Get LV path
            LV_PATH=$(lvdisplay | awk '/LV Path/ {print $3}' | grep -E '/ubuntu-vg/ubuntu-lv|/mapper/ubuntu--vg--ubuntu--lv')

            if [[ -n "$LV_PATH" ]]; then
                sudo lvextend -l +100%FREE "$LV_PATH"

                echo -e "\n${BLUE}After lvextend:${NC}"
                sudo lvdisplay

                echo -e "\n${BLUE}Filesystem usage before resize:${NC}"
                df -h /

                echo -e "${YELLOW}Resizing the filesystem...${NC}"
                sudo resize2fs "$LV_PATH"

                echo -e "\n${BLUE}Filesystem usage after resize:${NC}"
                df -h /
            else
                echo -e "${RED}Logical Volume path not found. Skipping resize.${NC}"
            fi
        else
            echo -e "${YELLOW}Skipping LVM extension as requested by user.${NC}"
        fi
    else
        echo -e "\n${BLUE}No free space detected in Volume Group [$VG_NAME]. Skipping extension steps.${NC}"
    fi

    # Always show final disk usage
    echo -e "\n${GREEN}Final root volume size and usage:${NC}"
    df -h /

else
    echo -e "\n${YELLOW}Non-Ubuntu system detected. If you are using LVM, you may need to manually extend your logical volume after installation.${NC}"
fi

# Set var for disk usage
ROOT_FS_USAGE=$(df -h / | awk '/\/$/ {printf "Size: %s Used: %s Avail: %s Use%%: %s",$2,$3,$4,$5}')
# Add to summary table
add_to_summary_table "Root Disk Usage" "$ROOT_FS_USAGE"
