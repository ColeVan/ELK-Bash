#!/bin/bash

cat << 'EOF'

 ░▒▓████████▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░      ░▒▓███████▓▒░ ░▒▓██████▓▒░ ░▒▓███████▓▒░▒▓█▓▒░░▒▓█▓▒░ 
 ░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ 
 ░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ 
 ░▒▓██████▓▒░ ░▒▓█▓▒░      ░▒▓███████▓▒░       ░▒▓███████▓▒░░▒▓████████▓▒░░▒▓██████▓▒░░▒▓████████▓▒░ 
 ░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
 ░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
 ░▒▓████████▓▒░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░      ░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░ 
 
EOF
# Define colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Function to show a progress bar with color
show_loading_bar() {
    local duration=$1
    local interval=1  # Use 1 second for each step
    local count=$((duration / interval))
    local i=0
    local bar=""
    echo -n "["
    while [ $i -le $count ]; do
        bar="#"
        echo -n "$bar"
        sleep $interval
        ((i++))
    done
    echo "]"
}

## --- Define the IP validation function before use ---
validate_ip() {
    local ip=$1
    if [[ $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        for segment in ${ip//./ }; do
            if ((segment < 0 || segment > 255)); then
                echo -e "${RED}Invalid IP: $ip. Segment out of range.${NC}"
                return 1
            fi
        done
        return 0
    else
        echo -e "${RED}Invalid IP: $ip. Format is incorrect.${NC}"
        return 1
    fi
}

# --- Display interfaces and suggest MGMT IP ---
echo -e "\n${GREEN}--- Network Interfaces ---${NC}"
ip -br a | awk '{print $1, $2, $3}' | while read iface state addr; do
    echo -e "${CYAN}$iface${NC} - $state - IP: ${YELLOW}$addr${NC}"
done

MGMT_IFACE=$(ip -br a | awk '$1 != "lo" && $3 ~ /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/ {print $1; exit}')
MGMT_IP=$(ip -4 -o addr show dev "$MGMT_IFACE" | awk '{print $4}' | cut -d/ -f1)

echo -e "\n${GREEN}Suggested management IP for this node:${NC}"
echo -e "${CYAN}$MGMT_IFACE${NC} - ${YELLOW}$MGMT_IP${NC}"

read -p "$(echo -e ${GREEN}'Enter the IP address for this Elasticsearch node: '${NC})" ELASTIC_HOST

# Validate input
if ! validate_ip "$ELASTIC_HOST"; then
    echo -e "${RED}Invalid IP address entered: $ELASTIC_HOST${NC}"
    exit 1
fi

echo -e "${GREEN}✔ Elasticsearch node will be set up at IP: $ELASTIC_HOST${NC}"

read -p "$(echo -e ${GREEN}'Enter the common IP address for all nodes in the cluster (typically the MGMT IP shown above): '${NC})" COMMON_IP

if ! validate_ip "$COMMON_IP"; then
    echo -e "${RED}Invalid cluster common IP entered: $COMMON_IP${NC}"
    exit 1
fi

echo -e "${GREEN}✔ Cluster-wide IP will be: $COMMON_IP${NC}"

# --- Airgapped Environment Check ---
echo -e "\n${YELLOW}Is this machine in an airgapped (offline) environment?${NC}"
read -p "$(echo -e ${GREEN}Type \"yes\" to skip internet check, or \"no\" to verify connectivity: ${NC})" IS_AIRGAPPED

if [[ "$IS_AIRGAPPED" =~ ^[Yy][Ee]?[Ss]?$ ]]; then
    echo -e "${YELLOW}Airgapped mode confirmed. Skipping internet connectivity check.${NC}"
else
    echo -e "\n${GREEN}Checking internet connectivity...${NC}"
    if ping -c 2 google.com > /dev/null 2>&1; then
        echo -e "${GREEN}Internet connectivity confirmed.${NC}"
    else
        echo -e "${RED}Ping failed. No internet detected.${NC}"
        read -p "$(echo -e "${YELLOW}Do you want to retry the connectivity check? (yes/no): ${NC}")" RETRY_NET
        if [[ "$RETRY_NET" =~ ^[Yy][Ee]?[Ss]?$ ]]; then
            if ping -c 2 google.com > /dev/null 2>&1; then
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

# --- Ubuntu Check and LVM Extension ---
if grep -q '^NAME="Ubuntu"' /etc/os-release; then
    echo -e "\n${BLUE}Ubuntu system detected. Proceeding with LVM check...${NC}"
    VG_NAME=$(vgdisplay | awk '/VG Name/ {print $3}')
    FREE_EXTENTS=$(vgdisplay "$VG_NAME" | awk '/Free  PE/ {print $5}')

    if [[ "$FREE_EXTENTS" -gt 0 ]]; then
        echo -e "\n${BLUE}Free space available in Volume Group [$VG_NAME].${NC}"
        read -p "$(echo -e ${GREEN}'Would you like to extend the root Logical Volume? (yes/no): '${NC})" EXTEND_CONFIRM
        if [[ "$EXTEND_CONFIRM" =~ ^[Yy][Ee]?[Ss]?$ ]]; then
            LV_PATH=$(lvdisplay | awk '/LV Path/ {print $3}' | grep -E '/ubuntu-vg/ubuntu-lv|/mapper/ubuntu--vg--ubuntu--lv')
            if [[ -n "$LV_PATH" ]]; then
                echo -e "\n${YELLOW}Extending volume...${NC}"
                sudo lvextend -l +100%FREE "$LV_PATH"
                sudo resize2fs "$LV_PATH"
                echo -e "${GREEN}✔ Volume extended successfully.${NC}"
            else
                echo -e "${RED}Could not determine LV path. Skipping extension.${NC}"
            fi
        else
            echo -e "${YELLOW}Skipping volume extension as requested.${NC}"
        fi
    else
        echo -e "${BLUE}No free space available in VG [$VG_NAME]. Skipping...${NC}"
    fi
else
    echo -e "\n${YELLOW}Non-Ubuntu system detected. Manual LVM steps may be required.${NC}"
fi

# --- ELK Install History ---
echo -e "\n${GREEN}Has Elasticsearch, Logstash, or Kibana ever been installed on this machine?${NC}"
read -p "$(echo -e ${YELLOW}Type \"yes\" if previously installed, or \"no\" for fresh install: ${NC})" INSTALL_RESPONSE

if [[ "$INSTALL_RESPONSE" =~ ^[Yy][Ee]?[Ss]?$ ]]; then
    echo -e "\n${YELLOW}Removing existing ELK components...${NC}"
    show_loading_bar 3

    for svc in elasticsearch logstash kibana; do
        echo -e "${CYAN}Stopping $svc...${NC}"
        sudo systemctl stop "$svc" 2>/dev/null || true
        sudo systemctl disable "$svc" 2>/dev/null || true
        sudo pkill -f "$svc" 2>/dev/null || true
    done

    echo -e "${CYAN}Checking Elastic Agent cleanup...${NC}"
    sudo pkill -f elastic-agent 2>/dev/null || true
    sudo rm -rf /opt/Elastic /etc/systemd/system/elastic-agent.service
    sudo systemctl daemon-reexec
    sudo systemctl daemon-reload

    echo -e "${CYAN}Uninstalling ELK packages...${NC}"
    sudo apt-get purge -y elasticsearch logstash kibana > /dev/null
    sudo apt-get autoremove -y > /dev/null

    echo -e "${CYAN}Removing ELK directories...${NC}"
    for path in /etc/elasticsearch /etc/logstash /etc/kibana \
                /var/lib/elasticsearch /var/lib/logstash \
                /var/log/elasticsearch /var/log/logstash /var/log/kibana \
                /usr/share/elasticsearch /usr/share/logstash /usr/share/kibana \
                /etc/apt/sources.list.d/elastic-8.x.list; do
        [ -e "$path" ] && sudo rm -rf "$path"
    done

    echo -e "${GREEN}✔ ELK cleanup complete.${NC}"
else
    echo -e "${GREEN}Confirmed: Fresh install. Continuing...${NC}"
fi


# Function to validate IP address
validate_ip() {
    local ip=$1
    local valid_check=$(echo "$ip" | awk -F'.' '$1<=255 && $2<=255 && $3<=255 && $4<=255')
    if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && [ ! -z "$valid_check" ]; then
        return 0
    else
        return 1
    fi
}

# Inform user this script is for Elasticsearch node only
echo -e "${GREEN}This script is intended to deploy an Elasticsearch node which will be joined to your cluster.${NC}"
read -p "$(echo -e ${GREEN}'Do you want to continue? (y/n): '${NC})" CONFIRM

if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
    echo -e "${GREEN}Exiting script. No changes made.${NC}"
    exit 0
fi

# Prompt for the node name
read -p "Enter the name you would like to assign your node name (e.g., node-1): " NODE_NAME

# Prompt user for the Elastic Stack version
read -p "Enter the Elastic Stack version to install (e.g., 8.14.3): " ELASTIC_VERSION

# Function to track the time taken for installation
start_time=$(date +%s)

# Update and install prerequisites with a progress bar
echo -e "\nUpdating package lists and installing prerequisites...\n"
sudo apt-get update > /dev/null 2>&1
show_loading_bar 5
sudo apt-get install -y curl apt-transport-https unzip > /dev/null 2>&1
show_loading_bar 10

# Calculate the time taken for the installation
end_time=$(date +%s)
elapsed_time=$((end_time - start_time))

# Display success message with color
echo -e "${GREEN}Installation of needed components completed successfully in $elapsed_time seconds.${NC}"

# Ensure `pv` is installed
if ! command -v pv &> /dev/null; then
    echo -e "${GREEN}Installing pv for progress visualization...${NC}"
    sudo apt-get install -y pv
fi

# Function to display a progress bar using `pv`
progress_bar() {
    local duration=$1
    local message=$2
    
    echo -ne "${GREEN}$message${NC}"
    sleep 0.5  # Small delay for better visualization
    echo -n "0%" 
    echo -n "#######################" | pv -qL 10
    echo -e " 100%\n"
}

start_time=$(date +%s)

# Add Elastic APT repository
echo -e "${GREEN}Adding Elastic APT repository...${NC}"
curl -s https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add - > /dev/null 2>&1
echo "deb https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list > /dev/null 2>&1
progress_bar 3 "Adding repository..."
end_time=$(date +%s)
elapsed_time=$((end_time - start_time))
echo -e "${GREEN}✔ Repository added successfully in $elapsed_time seconds.${NC}"

# Install specific version of Elasticsearch
progress_bar 5 "Updating package lists..."
sudo apt-get update > /dev/null 2>&1

progress_bar 10 "Installing Elasticsearch version $ELASTIC_VERSION..."
sudo apt-get install -y "elasticsearch=$ELASTIC_VERSION" 2>&1 | pv -lep -s 100

echo -e "${GREEN}✔ Elasticsearch installation completed successfully.${NC}"

progress_bar 3 "Configuring Elasticsearch..."
echo -e "${GREEN}✔ Time to create a cluster.${NC}"

# Prompt for Node IP, Username, and Password (hide password input)
read -p "Enter the first node IP: " NODE_IP
read -p "Enter your  superuser username: " USERNAME
read -s -p "Enter your superuser password: " PASSWORD
echo ""

# Fetch cluster health info using curl
RESPONSE=$(curl -ksu "$USERNAME:$PASSWORD" "https://${NODE_IP}:9200/_cluster/health?pretty")

# Extract cluster_name from the response
CLUSTER_NAME=$(echo "$RESPONSE" | grep '"cluster_name"' | awk -F'"' '{print $4}')

# Output the extracted cluster name
echo -e "${GREEN}Detected Elasticsearch cluster name: \033[1;32m${CLUSTER_NAME}${NC}"

# Prompt for the cluster api token for joining cluster
read -p "Enter the API key generated from your first node using the following cmd /usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s node: " CLUSTER_TOKEN

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

echo -e "${GREEN}Starting Elasticsearch.${NC}"
sudo systemctl start elasticsearch

echo -e "${GREEN}Checking Elasticsearch status for potential errors...${NC}"
sudo systemctl status elasticsearch --no-pager

echo -e "${GREEN}This node has been successfully added to the Elasticsearch cluster.${NC}"
echo -e "${GREEN}You can now repeat the process on the next node using the corresponding token.${NC}"
