#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/functions.sh"

cat << 'EOF'

 ░▒▓████████▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░      ░▒▓███████▓▒░ ░▒▓██████▓▒░ ░▒▓███████▓▒░▒▓█▓▒░░▒▓█▓▒░
 ░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░
 ░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░
 ░▒▓██████▓▒░ ░▒▓█▓▒░      ░▒▓███████▓▒░       ░▒▓███████▓▒░░▒▓████████▓▒░░▒▓██████▓▒░░▒▓████████▓▒░
 ░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░
 ░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░
 ░▒▓████████▓▒░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░      ░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░

EOF

# Define color codes (ANSI escape codes)
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[1;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Check for sudo usage
if [[ "$EUID" -eq 0 && -z "$SUDO_USER" ]]; then
    echo -e "${RED}❌ Please run this script using sudo, not as the root user directly (e.g., use: sudo ./script.sh).${NC}"
    exit 1
fi

echo -e "${GREEN}✔ Running with sudo as expected.${NC}"


# --- Prompt for ELK install history ---
echo -e "\n${GREEN}Has Elasticsearch, Logstash, or Kibana ever been installed on this machine before?${NC}"
read -p "$(echo -e ${YELLOW}Type \"yes\" if there is a previous installation on this machine, or \"no\" to continue with a fresh install: ${NC})" INSTALL_RESPONSE

if [[ "$INSTALL_RESPONSE" =~ ^[Yy][Ee]?[Ss]?$ ]]; then
    PREVIOUS_INSTALL=true
    FRESH_INSTALL=false
    echo -e "\n${YELLOW}Starting cleanup of any existing ELK stack components...${NC}"

    # Stop and disable services, then forcefully kill remaining processes if needed
    for svc in elasticsearch logstash kibana; do
        if systemctl list-units --type=service | grep -q "$svc"; then
            echo -e "${CYAN}Stopping and disabling $svc...${NC}"
            sudo systemctl stop "$svc" 2>/dev/null || echo -e "${YELLOW}Could not stop $svc or it was not running.${NC}"
            sudo systemctl disable "$svc" 2>/dev/null || echo -e "${YELLOW}Could not disable $svc or it was not enabled.${NC}"
        else
            echo -e "${YELLOW}$svc service not found. Skipping systemd stop...${NC}"
        fi

        # Force kill any lingering processes
        echo -e "${CYAN}Killing any remaining $svc processes...${NC}"
        sudo pkill -f "$svc" 2>/dev/null || echo -e "${YELLOW}No lingering $svc processes found.${NC}"
    done

		# --- Clean up Elastic Agent ---
	echo -e "${CYAN}Checking for Elastic Agent cleanup...${NC}"

	# Kill any running elastic-agent processes
	if pgrep -f elastic-agent > /dev/null; then
		echo -e "${YELLOW}Elastic Agent process detected. Terminating...${NC}"
		sudo pkill -f elastic-agent
		echo -e "${GREEN}✔ Elastic Agent process terminated.${NC}"
	else
		echo -e "${GREEN}No running Elastic Agent process found.${NC}"
	fi

	# Remove Elastic Agent install directory
	if [ -d "/opt/Elastic" ]; then
		echo -e "${YELLOW}Removing existing Elastic Agent installation at /opt/Elastic...${NC}"
		sudo rm -rf /opt/Elastic
		echo -e "${GREEN}✔ Elastic Agent directory removed successfully.${NC}"
	else
		echo -e "${GREEN}No Elastic Agent directory found at /opt/Elastic. Skipping...${NC}"
	fi

	# Remove lingering systemd service unit
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
	
	# Cleanup: Remove lingering Elastic Agent files from user's home directory
	echo -e "${GREEN}Scanning for stale Elastic Agent packages in home directory...${NC}"

	# Define patterns
	AGENT_TAR_PATTERN="$HOME/elastic-agent-*-linux-x86_64.tar.gz"
	AGENT_DIR_PATTERN="$HOME/elastic-agent-*-linux-x86_64"

	shopt -s nullglob

	# Find tarballs
	AGENT_TARS=($AGENT_TAR_PATTERN)
	if [ ${#AGENT_TARS[@]} -gt 0 ]; then
		for file in "${AGENT_TARS[@]}"; do
			echo -e "${YELLOW}Removing Elastic Agent archive: $(basename "$file")${NC}"
			rm -f "$file"
		done
	else
		echo -e "${GREEN}No Elastic Agent tar.gz files found. Skipping archive cleanup...${NC}"
	fi

	# Find directories
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

	echo -e "${GREEN}✔ Finished cleaning up Elastic Agent artifacts in home directory.${NC}"


    # Uninstall packages
    echo -e "${CYAN}Attempting to uninstall Elasticsearch, Logstash, and Kibana...${NC}"
    sudo apt-get purge -y elasticsearch logstash kibana > /dev/null 2>&1 || true
    sudo apt-get autoremove -y > /dev/null 2>&1 || true

    # Remove directories and files (only if they exist)
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

elif [[ "$INSTALL_RESPONSE" =~ ^[Nn][Oo]$ ]]; then
    PREVIOUS_INSTALL=false
    FRESH_INSTALL=true
    echo -e "${GREEN}Confirmed: Fresh install. Continuing setup...${NC}"
else
    echo -e "${RED}Invalid response. Please enter \"yes\" or \"no\".${NC}"
    exit 1
fi

# === Deployment Type Selection ===
while true; do
    read -p "$(echo -e "${GREEN}Is this a single ELK stack deployment or a cluster deployment? (single/cluster): ${NC}")" DEPLOYMENT_TYPE
    DEPLOYMENT_TYPE=$(echo "$DEPLOYMENT_TYPE" | tr '[:upper:]' '[:lower:]')

    if [[ "$DEPLOYMENT_TYPE" == "single" || "$DEPLOYMENT_TYPE" == "cluster" ]]; then
        echo -e "${GREEN}✔ You selected: $DEPLOYMENT_TYPE deployment.${NC}"
        break
    else
        echo -e "${RED}❌ Invalid input. Please enter either 'single' or 'cluster'.${NC}"
    fi
done

# === Deployment Specific Handling ===
if [ "$DEPLOYMENT_TYPE" == "cluster" ]; then
    read -p "$(echo -e ${GREEN}'Will this node host Elasticsearch, Logstash, and Kibana? (y/n): '${NC})" HOST_ALL_SERVICES
    if [[ ! "$HOST_ALL_SERVICES" =~ ^[Yy]$ ]]; then
        echo -e "${GREEN}This script only supports adding additional Elasticsearch nodes. Clustering separate Logstash nodes will be developed later.${NC}"
        read -p "$(echo -e ${GREEN}'Would you like to continue anyway? (y/n): '${NC})" CONTINUE_ANYWAY
        if [[ ! "$CONTINUE_ANYWAY" =~ ^[Yy]$ ]]; then
            echo -e "${GREEN}Exiting script at user request.${NC}"
            exit 1
        fi
    fi
fi

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

# Prompt for IP and validate until correct format is entered
while true; do
    read -p "$(echo -e "${YELLOW}Enter the IP address to use for Elasticsearch, Logstash, and Kibana for this machine. : ${NC}")" COMMON_IP
    if validate_ip "$COMMON_IP"; then
        echo -e "${GREEN}✔ Accepted IP: $COMMON_IP${NC}"
        break
    fi
done

# Assign and validate IP
ELASTIC_HOST=$COMMON_IP
KIBANA_HOST=$COMMON_IP
LOGSTASH_HOST=$COMMON_IP

# Ask if this is an airgapped environment
echo -e "\n${YELLOW}Is this machine in an airgapped (offline) environment?${NC}"
read -p "$(echo -e ${GREEN}Type \"yes\" to skip internet check, or \"no\" to verify connectivity: ${NC})" IS_AIRGAPPED

if [[ "$IS_AIRGAPPED" =~ ^[Yy][Ee]?[Ss]?$ ]]; then
	echo -e "${YELLOW}Airgapped mode confirmed. Skipping internet connectivity check.${NC}"
else
	# --- Check internet connectivity ---
	echo -e "\n${GREEN}Checking internet connectivity...${NC}"
	PING_TARGET="google.com"
	PING_COUNT=2

	if ping -c "$PING_COUNT" "$PING_TARGET" > /dev/null 2>&1; then
		echo -e "${GREEN}Internet connectivity confirmed via ping to $PING_TARGET.${NC}"
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

if [[ "$DEPLOYMENT_TYPE" == "cluster" ]]; then
    while true; do
        read -p "$(echo -e "${GREEN}How many additional Elasticsearch nodes will be added to this node for clustering?: ${NC}")" NODE_INPUT
        if [[ "$NODE_INPUT" =~ ^[1-9][0-9]*$ ]]; then
            NODE_COUNT=$NODE_INPUT
            echo -e "${GREEN}✔ Cluster will include $NODE_COUNT additional node(s).${NC}"
            break
        else
            echo -e "${RED}Invalid input. Please enter a positive integer greater than 0.${NC}"
        fi
    done
fi

# Assign to final variable
NODE_COUNT=$NODE_INPUT

echo -e "${GREEN}Cluster will include $NODE_COUNT additional node(s).${NC}"

# Add 1 to include the current node
NODE_COUNT=$((NODE_INPUT + 1))

# Optional: Display the collected IPs
echo -e "${GREEN}Elasticsearch host: $ELASTIC_HOST${NC}"
echo -e "${GREEN}Kibana host: $KIBANA_HOST${NC}"
echo -e "${GREEN}Logstash host: $LOGSTASH_HOST${NC}"


# Prompt in a loop until valid node name is entered
while true; do
	read -p "$(echo -e "${GREEN}Enter the name you would like to assign your node (e.g., node-1): ${NC}")" NODE_NAME
	if validate_nodename "$NODE_NAME"; then
		echo -e "${GREEN}✔ Node name '${NODE_NAME}' is valid and has been accepted.${NC}"
		break
	fi
done


# Prompt for superuser username with validation
while true; do
    read -p "$(echo -e "${GREEN}Enter a username for the superuser: ${NC}")" USERNAME
    if validate_username "$USERNAME"; then
        break
    else
        echo -e "${RED}Please enter a valid username.${NC}"
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

    # ✅ Always show final disk usage
    echo -e "\n${GREEN}Final root volume size and usage:${NC}"
    df -h /

else
    echo -e "\n${YELLOW}Non-Ubuntu system detected. If you are using LVM, you may need to manually extend your logical volume after installation.${NC}"
fi


# Prompt in a loop until valid version is entered
while true; do
	read -p "$(echo -e "${GREEN}Enter the Elastic Stack version to install (e.g., 8.18.2 or 9.0.2): ${NC}")" ELASTIC_VERSION
	if validate_version "$ELASTIC_VERSION"; then
		echo -e "${GREEN}✔ Version '${ELASTIC_VERSION}' is valid and has been accepted.${NC}"
		break
	fi
done

# Spinner function
