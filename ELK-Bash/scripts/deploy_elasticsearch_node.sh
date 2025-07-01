#!/bin/bash

# Define colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${GREEN}"
cat << 'EOF'
  ______ _           _   _                              _       _   _           _      
 |  ____| |         | | (_)                            | |     | \ | |         | |     
 | |__  | | __ _ ___| |_ _  ___ ___  ___  __ _ _ __ ___| |__   |  \| | ___   __| | ___ 
 |  __| | |/ _` / __| __| |/ __/ __|/ _ \/ _` | '__/ __| '_ \  | . ` |/ _ \ / _` |/ _ \
 | |____| | (_| \__ \ |_| | (__\__ \  __/ (_| | | | (__| | | | | |\  | (_) | (_| |  __/
 |______|_|\__,_|___/\__|_|\___|___/\___|\__,_|_|  \___|_| |_| |_| \_|\___/ \__,_|\___|

EOF
echo -e "${NC}"

# Inform user that this portion of the script is for Elasticsearch node install only
echo -e "${GREEN}This portion of the script is intended to deploy an Elasticsearch node which will be joined to your cluster.${NC}"
read -p "$(echo -e ${GREEN}'Do you want to continue? (y/n): '${NC})" CONFIRM

if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
    echo -e "${GREEN}Exiting script. No changes made.${NC}"
    exit 0
fi

# --- Prompt for ELK install history ---
echo -e "\n${GREEN}Has Elasticsearch, Logstash, or Kibana ever been installed on this machine before?${NC}"
# Prompt the user
prompt_input "Type \"${YELLOW}yes${GREEN}\" if there is a previous installation on this machine, or \"${YELLOW}no${GREEN}\" to continue with a fresh install: " INSTALL_RESPONSE

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

# === Common IP Prompt and Assignment ===
echo -e "\n${GREEN}Elasticsearch will be hosted using the IP you enter below.${NC}"

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
    read -p "$(echo -e "${YELLOW}Enter the IP address to use for Elasticsearch: ${NC}")" COMMON_IP
    if validate_ip "$COMMON_IP"; then
        echo -e "${GREEN}✔ Accepted IP: $COMMON_IP${NC}"
        break
    else
        echo -e "${RED}❌ Invalid IP format. Please enter a valid IPv4 address.${NC}"
    fi
done

echo -e "${GREEN}✔ This Elasticsearch node will be set up at IP: $ELASTIC_HOST${NC}"

# Add to summary table
add_to_summary_table "Management IP" "$COMMON_IP"

# Ask if this is an airgapped environment
echo -e "\n${YELLOW}Is this machine in an airgapped (offline) environment?${NC}"
prompt_input "Type \"yes\" to skip internet check, or \"no\" to verify connectivity: " IS_AIRGAPPED

if [[ "$IS_AIRGAPPED" =~ ^[Yy][Ee]?[Ss]?$ ]]; then
	echo -e "${YELLOW}Airgapped mode confirmed. Skipping internet connectivity check.${NC}"
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
IS_AIRGAPPED="$(echo "$IS_AIRGAPPED" | tr '[:upper:]' '[:lower:]' | xargs)"

# Validate and add to summary table
if [[ "$IS_AIRGAPPED" == "yes" ]]; then
  echo -e "${GREEN}✔ Airgap check skipped.${NC}"
  add_to_summary_table "Airgapped Environment" "Yes"
elif [[ "$IS_AIRGAPPED" == "no" ]]; then
  echo -e "${GREEN}✔ Internet connectivity will be verified.${NC}"
  add_to_summary_table "Airgapped Environment" "No"
else
  echo -e "${RED}❌ Invalid input. Please type 'yes' or 'no'.${NC}"
  exit 1
fi

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

# Prompt in a loop until valid node name is entered
while true; do
	read -p "$(echo -e "${GREEN}Enter the name you would like to assign your node (e.g., ${YELLOW}node-1${GREEN}): ${NC}")" NODE_NAME
	if validate_nodename "$NODE_NAME"; then
		echo -e "${GREEN}✔ Node name '${YELLOW}${NODE_NAME}${GREEN}' is valid and has been accepted.${NC}"
		break
	fi
done

# Prompt in a loop until valid version is entered
while true; do
    read -p "$(echo -e "${GREEN}Enter the Elastic Stack version to install ${YELLOW}(e.g., 8.18.2 or 9.0.2)${GREEN}: ${NC}")" ELASTIC_VERSION
    if validate_version "$ELASTIC_VERSION"; then
        echo -e "${GREEN}✔ Version '${ELASTIC_VERSION}' is valid and has been accepted.${NC}"
        add_to_summary_table "Elastic Stack Version" "$ELASTIC_VERSION"
        break
    else
        echo -e "${RED}❌ Invalid version format. Please enter something like 8.18.2.${NC}"
    fi
done

# Update
echo -e "${GREEN}Updating package lists and installing prerequisites.${NC}"
sudo apt-get update > /dev/null 2>&1
sleep 5 & spinner

# Add Elastic APT repository
echo -e "${BLUE}Adding Elastic APT repository...${NC}"
{
    curl -s https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add - > /dev/null 2>&1
    echo "deb https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list > /dev/null 2>&1
	echo "deb https://artifacts.elastic.co/packages/9.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-9.x.list > /dev/null 2>&1
} &
sleep 5 & spinner "Adding repository..."

echo -e "${GREEN}✔ Repository added successfully.${NC}"

# Install Elasticsearch
sudo apt-get update > /dev/null 2>&1
sleep 2 & spinner "Updating package lists"
sudo apt-get install -y "elasticsearch=$ELASTIC_VERSION" > /dev/null 2>&1
sleep 2 & spinner "Installing Elasticsearch version $ELASTIC_VERSION"
echo -e "${GREEN}✔ Elasticsearch installation completed successfully.${NC}"

sleep 5 & spinner "Configuring Elasticsearch..."
echo -e "${GREEN}✔ Time to join nodes together and create a cluster.${NC}"

# Prompt for the first Node IP with validation
while true; do
    read -p "$(echo -e ${GREEN}Enter the first node IP: ${NC})" NODE_IP
    if validate_ip "$NODE_IP"; then
        echo -e "${GREEN}✔ Node IP accepted: ${YELLOW}$NODE_IP${NC}"
        break
    else
        echo -e "${RED}❌ Invalid IP address. Please try again.${NC}"
    fi
done

# Prompt for superuser username used to stand up the first elasticsearch service with validation
while true; do
    read -p "$(echo -e ${GREEN}Enter your superuser username: ${NC})" USERNAME
    if validate_username "$USERNAME"; then
        echo -e "${GREEN}✔ Username accepted: ${YELLOW}$USERNAME${NC}"
        break
    else
        echo -e "${RED}❌ Invalid username. Please try again.${NC}"
    fi
done

# Prompt for superuser password (silent) with basic non-empty check
while true; do
    read -s -p "$(echo -e ${GREEN}Enter your superuser password: ${NC})" PASSWORD
    echo ""
    if validate_password "$PASSWORD"; then
        echo -e "${GREEN}✔ Password accepted.${NC}"
        break
    else
        echo -e "${RED}❌ Invalid password. Please try again.${NC}"
    fi
done

# Extract cluster health status using validated inputs
CLUSTER_RESPONSE=$(curl -s -k -u "$USERNAME:$PASSWORD" https://$NODE_IP:9200/_cluster/health)
CLUSTER_STATUS=$(echo "$CLUSTER_RESPONSE" | grep -o '"status":"[^"]*"' | cut -d':' -f2 | tr -d '"')

# Extract cluster_name from the response
CLUSTER_NAME=$(echo "$RESPONSE" | grep '"cluster_name"' | awk -F'"' '{print $4}')

# Output the extracted cluster name
echo -e "${GREEN}Detected Elasticsearch cluster name: ${YELLOW}${CLUSTER_NAME}${NC}"

# Prompt for the cluster API token for joining cluster
while true; do
    read -p "$(echo -e ${GREEN}Enter the API key generated from your first node using the following cmd /usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s node:${NC} ) " CLUSTER_TOKEN

    CLUSTER_TOKEN="$(echo "$CLUSTER_TOKEN" | xargs)"

    if [[ -z "$CLUSTER_TOKEN" ]]; then
        echo -e "${RED}❌ API key cannot be empty. Please enter a valid key.${NC}"
    elif [[ ! "$CLUSTER_TOKEN" =~ ^[a-zA-Z0-9+/=]+$ ]]; then
        echo -e "${RED}❌ API key appears invalid. Check for typos and try again.${NC}"
    else
        echo -e "${GREEN}✔ API key accepted.${NC}"
        break
    fi
done

sudo /usr/share/elasticsearch/bin/elasticsearch-reconfigure-node --enrollment-token $CLUSTER_TOKEN

# Configure Elasticsearch - only update cluster.name and node.name
echo -e "${GREEN}Updating node.name and cluster.name...${NC}"

# Update node.name
sudo sed -i "s/^node\.name:.*/node.name: \"${NODE_NAME}\"/" /etc/elasticsearch/elasticsearch.yml

# Update cluster.name
sudo sed -i "s/^cluster\.name:.*/cluster.name: \"${CLUSTER_NAME}\"/" /etc/elasticsearch/elasticsearch.yml

echo -e "${GREEN}Reloading Daemon.${NC}"
sudo systemctl daemon-reload

echo -e "${GREEN}Enabling Elasticsearch for persistent start upon reboot.${NC}"
sudo systemctl enable elasticsearch

# Start Elasticsearch service and report status
echo -e "${GREEN}Starting Elasticsearch...${NC}"
sudo systemctl start elasticsearch
sleep 5 & spinner
echo -e "${GREEN}Checking Elasticsearch status...${NC}"
check_service elasticsearch

echo -e "${GREEN}This node has been successfully added to the Elasticsearch cluster.${NC}"
echo -e "${GREEN}You can now repeat the process on the next node using the corresponding token generated from the initial node.${NC}"

# Extract cluster health status using grep and awk for table summary output
echo -e "${GREEN}Checking Elasticsearch cluster health status...${NC}"

while true; do
    CLUSTER_RESPONSE=$(curl -s -k -u $USERNAME:$PASSWORD https://$NODE_IP:9200/_cluster/health)
    CLUSTER_STATUS=$(echo "$CLUSTER_RESPONSE" | grep -o '"status":"[^"]*"' | cut -d':' -f2 | tr -d '"')

    echo -e "${GREEN}Current cluster status: ${YELLOW}${CLUSTER_STATUS}${NC}"

    if [[ "$CLUSTER_STATUS" == "green" ]]; then
        echo -e "${GREEN}✅ Cluster status is GREEN. Continuing...${NC}"
        break
    else
        echo -e "${YELLOW}⏳ Waiting for cluster to reach GREEN status... checking again in 5 seconds.${NC}"
        sleep 5
    fi
done

add_to_summary_table "Cluster Status" "$CLUSTER_STATUS"

echo -e "${GREEN}"
cat << 'EOF'
          o
/|   o         o
\|=--            o
   ##
                   \\
                /   \O
               O_/   T
               T    /|
               |\  | |
_______________|_|________
EOF
echo -e "${NC}"


# Final table
echo -e "\n${GREEN}Summary of your configuration:${NC}"
print_summary_table


echo -e "${GREEN}"
cat << 'EOF'
  ______ _           _   _                              _       _   _           _      
 |  ____| |         | | (_)                            | |     | \ | |         | |     
 | |__  | | __ _ ___| |_ _  ___ ___  ___  __ _ _ __ ___| |__   |  \| | ___   __| | ___ 
 |  __| | |/ _` / __| __| |/ __/ __|/ _ \/ _` | '__/ __| '_ \  | . ` |/ _ \ / _` |/ _ \
 | |____| | (_| \__ \ |_| | (__\__ \  __/ (_| | | | (__| | | | | |\  | (_) | (_| |  __/
 |______|_|\__,_|___/\__|_|\___|___/\___|\__,_|_|  \___|_| |_| |_| \_|\___/ \__,_|\___|

EOF
echo -e "${NC}"