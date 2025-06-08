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

# Function to display a loading bar
show_loading_bar() {
    local DURATION=$1
    local PROGRESS=0
    while [ $PROGRESS -lt $DURATION ]; do
        echo -n "."
        sleep 1
        PROGRESS=$((PROGRESS + 1))
    done
    echo ""
}

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

# Function to validate if the IP address is valid
validate_ip() {
    local ip=$1
    if [[ $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        for segment in ${ip//./ }; do
            if ((segment < 0 || segment > 255)); then
                echo "Invalid IP: $ip. Out of range."
                return 1
            fi
        done
        return 0
    else
        echo "Invalid IP: $ip. Format is incorrect."
        return 1
    fi
}

#!/bin/bash

# Define colors
GREEN='[0;32m'
NC='[0m' # No Color

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

# Prompt for Elasticsearch host IP
read -p "$(echo -e ${GREEN}'Enter the IP address for this Elasticsearch node: '${NC})" ELASTIC_HOST

# Validate Elasticsearch IP
if ! validate_ip "$ELASTIC_HOST"; then
    echo -e "${GREEN}Invalid IP address entered: $ELASTIC_HOST${NC}"
    exit 1
fi

echo -e "${GREEN}Elasticsearch node will be set up at IP: $ELASTIC_HOST${NC}"

# Further deployment steps go here...


# Optional: Display the collected IPs
echo "Elasticsearch host: $ELASTIC_HOST"


# Prompt for the node name
read -p "Enter the name you would like to assign your node name (e.g., node-1): " NODE_NAME

# Prompt user for the Elastic Stack version
read -p "Enter the Elastic Stack version to install (e.g., 8.14.3): " ELASTIC_VERSION

# Function to track the time taken for installation
start_time=$(date +%s)

# Update and install prerequisites with a progress bar
echo -e "
Updating package lists and installing prerequisites...
"
sudo apt-get update > /dev/null 2>&1
show_loading_bar 5
sudo apt-get install -y curl apt-transport-https unzip > /dev/null 2>&1
show_loading_bar 10

# Calculate the time taken for the installation
end_time=$(date +%s)
elapsed_time=$((end_time - start_time))

# Display success message with color
echo -e "
[32mInstallation of needed components completed successfully in $elapsed_time seconds.[0m
"

# Ensure `pv` is installed
if ! command -v pv &> /dev/null; then
    echo -e "[1;34mInstalling pv for progress visualization...[0m"
    sudo apt-get install -y pv
fi

# Function to display a progress bar using `pv`
progress_bar() {
    local duration=$1
    local message=$2

    echo -ne "[1;34m$message[0m
"
    sleep 0.5  # Small delay for better visualization
    echo -n "0%"
    echo -n "#######################" | pv -qL 10
    echo -e " 100%
"
}

start_time=$(date +%s)

# Add Elastic APT repository
echo -e "
[1;34mAdding Elastic APT repository...[0m"
curl -s https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add - > /dev/null 2>&1
echo "deb https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list > /dev/null 2>&1
progress_bar 3 "Adding repository..."
end_time=$(date +%s)
elapsed_time=$((end_time - start_time))
echo -e "
[32m✔ Repository added successfully in $elapsed_time seconds.[0m
"

# Install specific version of Elasticsearch
progress_bar 5 "Updating package lists..."
sudo apt-get update > /dev/null 2>&1

progress_bar 10 "Installing Elasticsearch version $ELASTIC_VERSION..."
sudo apt-get install -y "elasticsearch=$ELASTIC_VERSION" 2>&1 | pv -lep -s 100

echo -e "
[32m✔ Elasticsearch installation completed successfully.[0m
"

progress_bar 3 "Configuring Elasticsearch..."
echo -e "
[32m✔ Time to create a cluster.[0m
"

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
echo -e "
Detected Elasticsearch cluster name: [1;32m${CLUSTER_NAME}[0m"

# Prompt for the cluster api token for joining cluster
read -p "Enter the API key generated from your first node using the following cmd /usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s node: " CLUSTER_TOKEN

sudo /usr/share/elasticsearch/bin/elasticsearch-reconfigure-node --enrollment-token $CLUSTER_TOKEN

# Configure Elasticsearch - only update cluster.name and node.name
echo -e "
[1;34mUpdating node.name and cluster.name...[0m"

# Update node.name
sudo sed -i "s/^node\.name:.*/node.name: "${NODE_NAME}"/" /etc/elasticsearch/elasticsearch.yml

# Update cluster.name
sudo sed -i "s/^cluster\.name:.*/cluster.name: "${CLUSTER_NAME}"/" /etc/elasticsearch/elasticsearch.yml

echo -e "
[32mReloading Daemon.[0m
"
sudo systemctl daemon-reload

echo -e "
[32mEnabling Elasticsearch for persistent start upon reboot.[0m
"
sudo systemctl enable elasticsearch

echo -e "
[32mStarting Elasticsearch.[0m
"
sudo systemctl start elasticsearch

echo -e "
[32mChecking Elasticsearch status for potential errors...[0m
"
sudo systemctl status elasticsearch --no-pager

echo -e "
[32mThis node has been successfully added to the Elasticsearch cluster.[0m"
echo -e "[32mYou can now repeat the process on the next node using the corresponding token.[0m
"
