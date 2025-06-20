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

# Define color codes (ANSI escape codes)
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[1;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Function to display a loading/progress bar with color
show_loading_bar() {
    local duration=$1
    local interval=1
    local count=$((duration / interval))
    local i=0

    echo -ne "${GREEN}["
    while [ $i -lt $count ]; do
        echo -ne "#"
        sleep $interval
        ((i++))
    done
    echo -e "]${NC}"
}

# Function to validate if the IP address is valid
validate_ip() {
    local ip=$1
    if [[ $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        for segment in ${ip//./ }; do
            if ((segment < 0 || segment > 255)); then
                echo -e "${RED}Invalid IP: $ip. Out of range.${NC}"
                return 1
            fi
        done
        return 0
    else
        echo -e "${RED}Invalid IP: $ip. Format is incorrect.${NC}"
        return 1
    fi
}

# --- Prompt for ELK install history ---
echo -e "\n${GREEN}Has Elasticsearch, Logstash, or Kibana ever been installed on this machine before?${NC}"
read -p "$(echo -e ${YELLOW}Type \"yes\" if there is a previous installation on this machine, or \"no\" to continue with a fresh install: ${NC})" INSTALL_RESPONSE

if [[ "$INSTALL_RESPONSE" =~ ^[Yy][Ee]?[Ss]?$ ]]; then
    PREVIOUS_INSTALL=true
    FRESH_INSTALL=false
    echo -e "\n${YELLOW}Starting cleanup of any existing ELK stack components...${NC}"
    show_loading_bar 3

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
    )

    for path in "${paths_to_clean[@]}"; do
        if [ -e "$path" ]; then
            echo -e "${CYAN}Removing $path...${NC}"
            sudo rm -rf "$path"
            show_loading_bar 1
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


# Ask if it's a single ELK stack or a cluster deployment
read -p "Is this a single ELK stack deployment or a cluster deployment? (single/cluster): " DEPLOYMENT_TYPE

if [ "$DEPLOYMENT_TYPE" == "single" ]; then
    # Single ELK stack deployment, prompt for one IP for all components
    read -p "Enter the IP address you will use for this single node STACK. Elasticsearch, Logstash, and Kibana will be hosted here: " COMMON_IP

    # Assign the same IP for all components
    ELASTIC_HOST=$COMMON_IP
    KIBANA_HOST=$COMMON_IP
    LOGSTASH_HOST=$COMMON_IP

    # Validate each IP
    for ip in "$ELASTIC_HOST" "$KIBANA_HOST" "$LOGSTASH_HOST"; do
        if ! validate_ip $ip; then
            echo -e "${GREEN}Exiting script due to invalid IP: $ip${NC}"
            exit 1
        fi
    done

elif [ "$DEPLOYMENT_TYPE" == "cluster" ]; then
    # Cluster deployment, confirm all services are on this node
    read -p "$(echo -e ${GREEN}'Will this node host Elasticsearch, Logstash, and Kibana? (y/n): '${NC})" HOST_ALL_SERVICES
    if [[ ! "$HOST_ALL_SERVICES" =~ ^[Yy]$ ]]; then
        echo -e "${GREEN}Separating these services from this node is not supported at this time.${NC}"
        read -p "$(echo -e ${GREEN}'Would you like to continue anyway? (y/n): '${NC})" CONTINUE_ANYWAY
        if [[ ! "$CONTINUE_ANYWAY" =~ ^[Yy]$ ]]; then
            echo -e "${GREEN}Exiting script at user request.${NC}"
            exit 1
        fi
    fi

    # Prompt for a common IP for all components
    echo -e "${GREEN}Elasticsearch, Logstash, and Kibana will be hosted here using the following IP you enter.${NC}"
	echo -e "
${GREEN}--- Network Interfaces ---${NC}"
    ip -br a | awk '{print $1, $2, $3}' | while read iface state addr; do
        echo -e "${CYAN}$iface${NC} - $state - IP: ${YELLOW}$addr${NC}"
    done

    # Identify first non-loopback interface with an IP as "MGMT"
    MGMT_IFACE=$(ip -br a | awk '$1 != "lo" && $3 ~ /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/ {print $1; exit}')
    MGMT_IP=$(ip -4 -o addr show dev "$MGMT_IFACE" | awk '{print $4}' | cut -d/ -f1)

    echo -e "
${GREEN}Use the following IP for accessing this node (management interface):${NC}"
    echo -e "${CYAN}$MGMT_IFACE${NC} - ${YELLOW}$MGMT_IP${NC}"
    read -p "Enter the common IP address for all nodes in the cluster which should be the management interface shown above: " COMMON_IP

    # Assign the same IP for all components
    ELASTIC_HOST=$COMMON_IP
    KIBANA_HOST=$COMMON_IP
    LOGSTASH_HOST=$COMMON_IP

    # Validate each IP
    for ip in "$ELASTIC_HOST" "$KIBANA_HOST" "$LOGSTASH_HOST"; do
        if ! validate_ip $ip; then
            echo -e "${GREEN}Exiting script due to invalid IP: $ip${NC}"
            exit 1
        fi
    done
	
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

    # Prompt for number of nodes in the cluster
    read -p "How many additional Elasticsearch nodes will be added to this node for clustering?: " NODE_INPUT

    # Add 1 to include the current node
    NODE_COUNT=$((NODE_INPUT + 1))

    # Optional: Display the collected IPs
    echo -e "${GREEN}Elasticsearch host: $ELASTIC_HOST${NC}"
    echo -e "${GREEN}Kibana host: $KIBANA_HOST${NC}"
    echo -e "${GREEN}Logstash host: $LOGSTASH_HOST${NC}"

    # Prompt for the node name
    read -p "Enter the name you would like to assign your node name (e.g., node-1): " NODE_NAME

    # Function to validate username
    validate_username() {
        if [[ -z "$1" || "$1" =~ [^a-zA-Z0-9_\-] ]]; then
            echo -e "${GREEN}Invalid username. Only alphanumeric characters, underscores (_), and dashes (-) are allowed.${NC}"
            return 1
        fi
        return 0
    }

    # Function to validate password
    validate_password() {
        if [[ -z "$1" || ${#1} -lt 8 ]]; then
            echo -e "${GREEN}Invalid password. It must be at least 8 characters long.${NC}"
            return 1
        fi
        return 0
    }

    # Capture start time for deployment
    start_time=$(date +%s)

    # Prompt for username and validate
    while true; do
        read -p "Enter a username for the superuser: " USERNAME
        if validate_username "$USERNAME"; then
            break
        else
            echo -e "${GREEN}Please enter a valid username.${NC}"
        fi
    done

    # Prompt for password and validate
    while true; do
        read -s -p "Enter a password for the superuser: " PASSWORD
        echo "" # Print a new line after password prompt
        if validate_password "$PASSWORD"; then
            read -s -p "Confirm the password: " PASSWORD_CONFIRM
            echo "" # Print a new line after confirmation prompt
            if [[ "$PASSWORD" == "$PASSWORD_CONFIRM" ]]; then
                break
            else
                echo -e "${GREEN}Passwords do not match. Please try again.${NC}"
            fi
        else
            echo -e "${GREEN}Please enter a valid password.${NC}"
        fi
    done
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
else
    echo -e "\n${YELLOW}Non-Ubuntu system detected. If you are using LVM, you may need to manually extend your logical volume after installation.${NC}"
fi

echo -e "
${GREEN}Created Superuser variables for use later on during install.${NC}
"

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
${GREEN}Installation of needed components completed successfully in $elapsed_time seconds.${NC}
"

# Spinner function
spinner() {
    local pid=$!
    local delay=0.1
    local spinstr='|/-\'
    local msg="$1"
    echo -ne "${BLUE}${msg}...${NC} "
    while [ "$(ps a | awk '{print $1}' | grep "$pid")" ]; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    echo " [✔]"
}

start_time=$(date +%s)

# Add Elastic APT repository
echo -e "${BLUE}Adding Elastic APT repository...${NC}"
{
    curl -s https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add - > /dev/null 2>&1
    echo "deb https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list > /dev/null 2>&1
} &
spinner "Adding repository"

end_time=$(date +%s)
elapsed_time=$((end_time - start_time))
echo -e "${GREEN}✔ Repository added successfully in $elapsed_time seconds.${NC}"

# Install Elasticsearch
{
    sudo apt-get update > /dev/null 2>&1
} &
spinner "Updating package lists"

{
    sudo apt-get install -y "elasticsearch=$ELASTIC_VERSION" > /dev/null 2>&1
} &
spinner "Installing Elasticsearch version $ELASTIC_VERSION"

echo -e "${GREEN}✔ Elasticsearch installation completed successfully.${NC}"

# Configure Elasticsearch
echo -e "${BLUE}Configuring Elasticsearch...${NC}"
sudo tee /etc/elasticsearch/elasticsearch.yml > /dev/null <<EOL
network.host: ${ELASTIC_HOST}
http.port: 9200
node.name: ${NODE_NAME}
path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch
xpack.security.enrollment.enabled: true
xpack.security.http.ssl.enabled: true
xpack.security.http.ssl.keystore.path: certs/http.p12
xpack.security.transport.ssl.enabled: true
xpack.security.transport.ssl.verification_mode: certificate
xpack.security.transport.ssl.keystore.path: certs/transport.p12
xpack.security.transport.ssl.truststore.path: certs/transport.p12
cluster.initial_master_nodes: ["${NODE_NAME}"]
transport.host: ${ELASTIC_HOST}
EOL

sleep 2 & spinner "Configuring Elasticsearch"
echo -e "${GREEN}✔ Elasticsearch configuration completed successfully.${NC}"

# Install Kibana
{
    sudo apt-get update > /dev/null 2>&1
} &
spinner "Updating package lists"

{
    sudo apt-get install -y "kibana=$ELASTIC_VERSION" > /dev/null 2>&1
} &
spinner "Installing Kibana version $ELASTIC_VERSION"

echo -e "${GREEN}✔ Kibana installation completed successfully.${NC}"

# Configure Kibana
echo -e "${BLUE}Configuring Kibana...${NC}"
sudo tee /etc/kibana/kibana.yml > /dev/null <<EOL
server.port: 5601
server.host: ${KIBANA_HOST}
elasticsearch.hosts: ["https://${ELASTIC_HOST}:9200"]
elasticsearch.ssl.certificateAuthorities: ["/etc/kibana/certs/http_ca.crt"]
server.ssl.enabled: true
server.ssl.certificate: "/etc/kibana/certs/kibana.crt"
server.ssl.key: "/etc/kibana/certs/kibana.key"
pid.file: /run/kibana/kibana.pid
elasticsearch.username: "kibana"
elasticsearch.password: "<kibana_password>"
xpack.security.encryptionKey: "something_at_least_32_characters"
xpack.encryptedSavedObjects.encryptionKey: "something_at_least_32_characters"
EOL

sleep 2 & spinner "Configuring Kibana"
echo -e "${GREEN}✔ Kibana configuration completed successfully.${NC}"

# Install Logstash
{
    sudo apt-get update > /dev/null 2>&1
} &
spinner "Updating package lists"

{
    sudo apt-get install -y logstash > /dev/null 2>&1
} &
spinner "Installing Logstash"

echo -e "${GREEN}🚀 All components installed and configured successfully! 🎉${NC}"


start_time=$(date +%s)
# Configure logstash
echo -e "${BLUE}Configuring Logstash...${NC}"
sudo tee /etc/logstash/logstash.yml > /dev/null <<EOL
queue.type: persisted
path.queue: /var/lib/logstash/data
dead_letter_queue.enable: false
# Elastic Output
node.name: ${NODE_NAME}
#path.config: /etc/logstash/conf.d/*.conf
xpack.monitoring.enabled: true
xpack.monitoring.elasticsearch.username: "logstash_system"
xpack.monitoring.elasticsearch.password: "<logstash_password>"
xpack.monitoring.elasticsearch.hosts: ["https://${ELASTIC_HOST}:9200"]
xpack.monitoring.elasticsearch.ssl.certificate_authority: "/etc/logstash/certs/http_ca.crt"
xpack.management.elasticsearch.ssl.verification_mode: certificate
# log.level: info
path.logs: /var/log/logstash
EOL

# Open the pipelines.yml file and add the pipeline configuration for Elastic Agent
sudo tee -a /etc/logstash/pipelines.yml > /dev/null <<EOL
- pipeline.id: main
  queue.type: persisted
  path.config: "/etc/logstash/conf.d/logstash.conf"
EOL

# Define the file path
JVM_OPTIONS_FILE="/etc/logstash/jvm.options"

# Use sed to replace the lines
sudo sed -i.bak -e 's/^-Xms[0-9]*[gG]/-Xms8g/' \
           -e 's/^-Xmx[0-9]*[gG]/-Xmx8g/' \
           -e '/-Xmx[0-9]*[gG]/a\-Djava.io.tmpdir=/opt/logstash_tmp' \
           "$JVM_OPTIONS_FILE"
echo -e "
${GREEN}JVM options updated successfully.${NC}
"		   
end_time=$(date +%s)
elapsed_time=$((end_time - start_time))
echo -e "
${GREEN}Initial Configuration of Logstash completed successfully in $elapsed_time seconds.${NC}
"

start_time=$(date +%s)
# Set up SSL certificates for Elasticsearch and Kibana
echo -e "
${GREEN}Setting up SSL certificates for Kibana, Elasticsearch, and Logstash...${NC}
"
sudo mkdir -p /usr/share/elasticsearch/ssl
sudo tee /usr/share/elasticsearch/instances.yml > /dev/null <<EOL
instances:
  - name: "elasticsearch"
    ip:
      - "${ELASTIC_HOST}"
  - name: "kibana"
    ip:
      - "${KIBANA_HOST}"
  - name: "logstash"
    ip:
      - "${LOGSTASH_HOST}"
EOL

# Generate SSL certificates
sudo /usr/share/elasticsearch/bin/elasticsearch-certgen --in /usr/share/elasticsearch/instances.yml --out /usr/share/elasticsearch/certs.zip > /dev/null 2>&1

# Unzip the generated certificates
sudo unzip /usr/share/elasticsearch/certs.zip -d /usr/share/elasticsearch/ssl/ > /dev/null 2>&1
show_loading_bar 5

# Set up Kibana SSL certificates
echo -e "${GREEN}Setting up Kibana SSL certificates...${NC}"
sudo mkdir -p /etc/kibana/certs
sudo cp /usr/share/elasticsearch/ssl/kibana/kibana.crt /etc/kibana/certs/ > /dev/null 2>&1
sudo cp /usr/share/elasticsearch/ssl/kibana/kibana.key /etc/kibana/certs/ > /dev/null 2>&1
sudo cp /etc/elasticsearch/certs/http_ca.crt /etc/kibana/certs/ > /dev/null 2>&1
sudo cp /usr/share/elasticsearch/ssl/ca/ca.crt /etc/kibana/certs/ > /dev/null 2>&1
sudo cp /usr/share/elasticsearch/ssl/elasticsearch/elasticsearch.crt /etc/kibana/certs/ > /dev/null 2>&1
sudo cp /usr/share/elasticsearch/ssl/elasticsearch/elasticsearch.key /etc/kibana/certs/ > /dev/null 2>&1
sudo chown -R kibana: /etc/kibana/certs > /dev/null 2>&1
sudo chmod -R 770 /etc/kibana/certs > /dev/null 2>&1
show_loading_bar 3
cd
# Set up Logstash SSL certificates
echo -e "${GREEN}Setting up Logstash SSL certificates...${NC}"
sudo mkdir -p /etc/logstash/certs
sudo cp /usr/share/elasticsearch/ssl/logstash/logstash.crt /etc/logstash/certs/ > /dev/null 2>&1
sudo cp /usr/share/elasticsearch/ssl/logstash/logstash.key /etc/logstash/certs/ > /dev/null 2>&1
sudo cp /etc/elasticsearch/certs/http_ca.crt /etc/logstash/certs/ > /dev/null 2>&1
sudo cp /usr/share/elasticsearch/ssl/ca/ca.crt /etc/logstash/certs/ > /dev/null 2>&1
sudo chown -R logstash: /etc/logstash/certs > /dev/null 2>&1
sudo chmod -R 770 /etc/logstash/certs > /dev/null 2>&1
sudo chown -R elasticsearch: /etc/elasticsearch > /dev/null 2>&1
sudo chown -R logstash: /var/lib/logstash/  > /dev/null 2>&1
show_loading_bar 3

# Convert Logstash key to PKCS#8 format
echo -e "${GREEN}Converting Logstash key to PKCS#8 format...${NC}"
sudo openssl pkcs8 -inform PEM -in /etc/logstash/certs/logstash.key -topk8 -nocrypt -outform PEM -out /etc/logstash/certs/logstash.pkcs8.key
sudo chown -R logstash: /etc/logstash/certs > /dev/null 2>&1
echo -e "${GREEN}Logstash key converted and saved as logstash.pkcs8.key.${NC}"
show_loading_bar 3
end_time=$(date +%s)
elapsed_time=$((end_time - start_time))
echo -e "
${GREEN}Finished setting up SSL certificates for Kibana, Elasticsearch, and Logstash....${NC}
"
start_time=$(date +%s)
echo -e "
${GREEN}Tweaking a few Logstash settings....${NC}
"
# Fixing logstash pipeline.yml
file_path="/etc/logstash/pipelines.yml"

# Replace the contents of the file with the desired configuration
sudo bash -c "cat <<EOF > $file_path
- pipeline.id: main
  queue.type: persisted
  path.config: "/etc/logstash/conf.d/logstash.conf"
EOF"

# Set ownership of the file to the logstash user and group
sudo chown logstash:logstash "$file_path"

# Confirm the changes
echo -e "${GREEN}File updated and ownership set to logstash for $file_path.${NC}"
show_loading_bar 3
end_time=$(date +%s)
elapsed_time=$((end_time - start_time))
echo -e "
${GREEN}Logstash settings tweaked....${NC}
"

# Start Elasticsearch service and report status
echo -e "${GREEN}Starting Elasticsearch...${NC}"
sudo systemctl start elasticsearch
show_loading_bar 5
echo -e "${GREEN}Checking Elasticsearch status...${NC}"
sudo systemctl status elasticsearch --no-pager

# Reset Logstash password and store it in a variable
echo -e "${GREEN}Resetting Logstash password...${NC}"
show_loading_bar 5
logstash_password=$(sudo /usr/share/elasticsearch/bin/elasticsearch-reset-password -u logstash_system -s -b)

# Update logstash configuration with the new password
sudo sed -i "s/<logstash_password>/$logstash_password/" /etc/logstash/logstash.yml

# Create the superuser
echo -e "${GREEN}Creating a superuser...${NC}"
if sudo /usr/share/elasticsearch/bin/elasticsearch-users useradd "$USERNAME" -p "$PASSWORD" -r superuser > /dev/null 2>&1; then
  echo -e "${GREEN}Superuser $USERNAME created successfully.{NC}"
else
  echo -e "${RED}Failed to create superuser $USERNAME. Check logs for details.${NC}"
  exit 1
fi

start_time=$(date +%s)
# Reset Kibana password and store it in a variable
echo -e "${GREEN}Resetting Kibana password and saving to variable{NC}"
show_loading_bar 5
kibana_password=$(sudo /usr/share/elasticsearch/bin/elasticsearch-reset-password -u kibana -s -b)
end_time=$(date +%s)
elapsed_time=$((end_time - start_time))
echo -e "
${GREEN}Kibana password successfully reset in $elapsed_time seconds.${NC}
"


# Configure Kibana
echo -e "${GREEN}Configuring Kibana yaml ...{NC}"
sudo tee /etc/kibana/kibana.yml > /dev/null <<EOL
# Kibana configuration
# =================== System: Logging ===================
server.port: 5601
server.host: ${KIBANA_HOST}
elasticsearch.hosts: ["https://${ELASTIC_HOST}:9200"]
elasticsearch.ssl.certificateAuthorities: ["/etc/kibana/certs/http_ca.crt"]
server.ssl.enabled: true
server.ssl.certificate: "/etc/kibana/certs/kibana.crt"
server.ssl.key: "/etc/kibana/certs/kibana.key"
# Specifies the path where Kibana creates the process ID file.
pid.file: /run/kibana/kibana.pid
# X-Pack Security
elasticsearch.username: "kibana"
elasticsearch.password: "${kibana_password}"
xpack.security.encryptionKey: "something_at_least_32_characters"
xpack.encryptedSavedObjects.encryptionKey: "something_at_least_32_characters"
EOL
show_loading_bar 3

elapsed_time=$((end_time - start_time))
echo -e "
${GREEN}Kibana yml file successfully configured.${NC}
"

# Start Kibana service and report status
echo -e "${GREEN}Starting Kibana...${NC}"
sudo systemctl start kibana
show_loading_bar 15
echo -e "${GREEN}Checking Kibana status...${NC}"
sudo systemctl status kibana --no-pager

echo -e "
${GREEN}Creating Logstash directories for critical functions.${NC}
"
sudo mkdir -p /opt/logstash_tmp
sudo chown -R logstash:logstash /opt/logstash_tmp
sudo chown -R logstash:logstash /usr/share/logstash
sudo mkdir -p /var/lib/logstash/data
sudo chown -R logstash:logstash /var/lib/logstash/data
sudo chown -R logstash:logstash /etc/logstash

# Ensure DLQ directory is in place
sudo mkdir -p /var/lib/logstash/data/dead_letter_queue
sudo chown -R logstash:logstash /var/lib/logstash/data

start_time=$(date +%s)
# Start the Elastic Stack trial license
echo -e "
${GREEN}Starting the Elastic Stack trial license...${NC}
"
response=$(curl --request POST \
  --url "https://${ELASTIC_HOST}:9200/_license/start_trial?acknowledge=true" \
  --header 'Accept: */*' \
  -u "${USERNAME}:${PASSWORD}" \
  --header 'Cache-Control: no-cache' \
  --header 'Connection: keep-alive' \
  --header 'Content-Type: application/json' \
  --header 'kbn-xsrf: xxx' \
  --insecure)

# Display the response
echo -e "${GREEN}Response from the server:${NC}"
echo -e "${GREEN}${response}${NC}"

# Check if the trial was successfully started
if echo "$response" | grep -q '"trial_was_started":true'; then
    echo "Trial license has been successfully started."
else
    echo "${RED}Failed to start the trial license.${NC}"
fi
end_time=$(date +%s)
elapsed_time=$((end_time - start_time))
echo -e "
${GREEN}Started Elastic Stack trial license in $elapsed_time seconds.${NC}
"

start_time=$(date +%s)
# Obtain the OAuth2 access token
echo -e "
${GREEN}Obtaining OAuth2 access token...${NC}
"
ACCESS_TOKEN=$(curl --request POST \
  --url "https://${ELASTIC_HOST}:9200/_security/oauth2/token" \
  -u "${USERNAME}:${PASSWORD}" \
  --header 'Content-Type: application/json' \
  --insecure \
  --data '{
    "grant_type": "password",
    "username": "'"${USERNAME}"'",
    "password": "'"${PASSWORD}"'"
  }')

# Display the access token
echo -e "${GREEN}Access Token: $ACCESS_TOKEN${NC}"
api_access_token=$(echo "$ACCESS_TOKEN" | grep -o '"access_token":"[^"]*"' | sed 's/"access_token":"\([^"]*\)".*/\1/')

# Display the stored access token
echo -e "${GREEN}Stored Access Token: $api_access_token{NC}"

# Display the access token
if [ -n "$api_access_token" ]; then
	echo -e "
${GREEN}Access token obtained successfully: $api_access_token${NC}
"
else
	echo -e "
${RED}Failed to obtain access token.${NC}
"
fi
end_time=$(date +%s)
elapsed_time=$((end_time - start_time))
echo -e "
${GREEN}Creating Access Token for follow on system critical functions took $elapsed_time seconds.${NC}
"
# Wait for 15 seconds for packages to settle
echo -e "
${GREEN}Sending API request to Elasticsearch Waiting for 15 seconds while adding correct API key to logstash pipline...${NC}
"
show_loading_bar 15
logstash_api_key=$(curl --user "${USERNAME}:${PASSWORD}" --request POST \
  --url "https://${ELASTIC_HOST}:9200/_security/api_key" \
  --header 'Accept: */*' \
  --header 'Cache-Control: no-cache' \
  --header 'Connection: keep-alive' \
  --header 'Content-Type: application/json' \
  --header 'kbn-xsrf: xxx' \
  --data '{
  "name": "fleet_logstash-api-key",
  "role_descriptors": { 
    "logstash-output": { 
      "cluster": ["monitor"],
      "indices": [
        {
          "names": [
          "logs-*-*",
          "metrics-*-*",
          "traces-*-*",
          "synthetics-*-*",
          ".logs-endpoint.diagnostic.collection-*",
          ".logs-endpoint.action.responses-*",
          "profiling-*",
          ".profiling-*"
        ],
          "privileges": ["auto_configure", "create_doc"],
        "allow_restricted_indices": false
      }
    ],
    "applications": [],
    "run_as": [],
    "metadata": {},
    "transient_metadata": {
      "enabled": true
    }
  }
},
  "metadata": {
    "managed_by": "fleet",
	"managed": true,
	"type": "logstash"
  }
}' --insecure)
echo $logstash_api_key
logstash_pipeline_api_key=$(echo "$logstash_api_key" | grep -o '"encoded":"[^"]*"' | sed 's/"encoded":"\([^"]*\)".*/\1/')
echo $logstash_pipeline_api_key
decoded_value=$(echo -n $logstash_pipeline_api_key| base64 -d)
echo "$decoded_value"

# Configure logstash
echo -e "
${GREEN}Configuring Logstash Conf with decoded API key for Elastic Agent communication over port 5044 using SSL certs...${NC}
"
# Modify or create the Logstash input and output configuration
sudo tee /etc/logstash/conf.d/logstash.conf > /dev/null <<EOL
input {
  elastic_agent {
    port => 5044
    ssl_enabled => true
    ssl_certificate_authorities => ["/etc/logstash/certs/ca.crt"]
    ssl_certificate => "/etc/logstash/certs/logstash.crt"
    ssl_key => "/etc/logstash/certs/logstash.pkcs8.key"
    ssl_client_authentication => "required"
  }
}
output {
  elasticsearch {
    hosts => ["https://${ELASTIC_HOST}:9200"]
    api_key => "$decoded_value"
    data_stream => true
    ssl_enabled => true
    ssl_certificate_authorities => '/etc/logstash/certs/http_ca.crt'
  }
}
EOL
echo -e "
${GREEN}Configuring Logstash Conf configured with input and output settings...${NC}
"
show_loading_bar 5

echo -e "
${GREEN}Setting variable paths and creating service token ...${NC}
"
# Variables for ES token
ES_BIN_PATH="/usr/share/elasticsearch/bin"
SERVICE_NAME="my-token-$(date +%s)" # Generate a unique token name

# Create Service Token
echo -e "
${GREEN}Creating service token with name: $SERVICE_NAME ...${NC}
"
SERVICE_TOKEN_OUTPUT=$(sudo $ES_BIN_PATH/elasticsearch-service-tokens create elastic/fleet-server "$SERVICE_NAME" 2>&1)

# Debug: Output the command response
echo "Debug: $SERVICE_TOKEN_OUTPUT"

# Extract the token from the output
SERVICE_NAME_TOKEN=$(echo "$SERVICE_TOKEN_OUTPUT" | awk -F'=' '{print $2}' | tr -d ' ')

# Check if the token was successfully extracted
if [ -n "$SERVICE_NAME_TOKEN" ]; then
  echo "Service token created successfully: $SERVICE_NAME_TOKEN"
  # Adjust ownership of Elasticsearch configuration
  sudo chown -R elasticsearch: /etc/elasticsearch > /dev/null 2>&1
else
  echo "${RED}Failed to create service token. Check debug output for details.${NC}"
  exit 1
fi
echo -e "
${GREEN}Service token prep work completed...${NC}
"
show_loading_bar 5

#Restart Elasticsearch services to take new token creation
echo -e "
${GREEN}Restarting Elasticsearch service to take new token creation...${NC}
"
sudo systemctl restart elasticsearch
echo "Checking Elasticsearch status..."
sudo systemctl status elasticsearch --no-pager
show_loading_bar 10

#Starting Kibana and checking status
echo -e "
${GREEN}Checking Kibana status...${NC}
"
sudo systemctl status kibana --no-pager
show_loading_bar 3
echo -e "
${YELLOW}The installation hasn't failed yet... Things look good so far, continuing forward....${NC}
"
show_loading_bar 3

# --- Download Linux Elastic Agent for Fleet Server Setup ---
echo -e "\n${GREEN}Downloading Elastic Agent for Fleet Server setup... please wait.${NC}"
show_loading_bar 3

ELASTIC_AGENT_URL="https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-${ELASTIC_VERSION}-linux-x86_64.tar.gz"
ELASTIC_AGENT_FILE="elastic-agent-${ELASTIC_VERSION}-linux-x86_64.tar.gz"
USER_HOME=$(eval echo ~"$SUDO_USER")
DEST_DIR="$USER_HOME"
DEST_PATH="$DEST_DIR/$ELASTIC_AGENT_FILE"

# Spinner for background tasks
spinner() {
  local pid=$!
  local delay=0.1
  local spinstr='|/-\'
  echo -n "$1"
  while kill -0 "$pid" 2>/dev/null; do
    local temp=${spinstr#?}
    printf " [%c]  " "$spinstr"
    spinstr=$temp${spinstr%"$temp"}
    sleep $delay
    printf "\b\b\b\b\b\b"
  done
  echo -e " [✔]"
}

# Download Elastic Agent with curl and built-in progress bar
echo -e "${CYAN}Downloading: ${ELASTIC_AGENT_FILE}${NC}"
curl -L --progress-bar -o "$DEST_PATH" "$ELASTIC_AGENT_URL"

if [ $? -eq 0 ]; then
  echo -e "${GREEN}✔ Download completed successfully.${NC}"
else
  echo -e "${RED}✘ Download failed. Please check your internet connection and try again.${NC}"
  exit 1
fi

# Extract archive with spinner
echo -e "${CYAN}Extracting Elastic Agent archive...${NC}"
(
  tar -xzf "$DEST_PATH" -C "$DEST_DIR"
) & spinner "Extracting"

echo -e "${GREEN}✔ Elastic Agent ready at: ${DEST_DIR}/elastic-agent-${ELASTIC_VERSION}-linux-x86_64${NC}"

# Create Fleet Policy
leet_policy_id=$(curl --request POST \
  --url "https://${ELASTIC_HOST}:5601/api/fleet/agent_policies?sys_monitoring=true" \
  --header 'Accept: */*' \
  --header "Authorization: Bearer $api_access_token" \
  --header 'Cache-Control: no-cache' \
  --header 'Connection: keep-alive' \
  --header 'Content-Type: application/json' \
  --header 'kbn-xsrf: xxx' \
  --data '{
  "name": "fleet-server-policy",
  "description": "",
  "namespace": "default",
  "monitoring_enabled": [
    "logs",
    "metrics"
  ],
  "has_fleet_server": "true"
}' --insecure)

echo $fleet_policy_id

# Output the fleet policy ID
echo -e "${YELLOW}Fleet Policy ID: $fleet_policy_id...${NC}"
show_loading_bar 5

# Create Fleet Server Host on https://elastic_ip:8220
echo -e "
${RED}Creating Fleet Server Host via Elastic API..${NC}
"
fleet_server_host=$(curl --request POST \
  --url "https://${ELASTIC_HOST}:5601/api/fleet/fleet_server_hosts" \
  --header 'Accept: */*' \
  --header "Authorization: Bearer $api_access_token" \
  --header 'Cache-Control: no-cache' \
  --header 'Connection: keep-alive' \
  --header 'Content-Type: application/json' \
  --header 'kbn-xsrf: xxx' \
  --data "{\"name\":\"Default\",\"host_urls\":[\"https://${ELASTIC_HOST}:8220\"],\"is_default\":true}" \
  --insecure)
  
# Output the Fleet Server Host response
echo -e "${YELLOW}Fleet Server Host Response: $fleet_server_host.${NC}"
show_loading_bar 10

# Variables
USER_HOME="/home/$(logname)"
ELASTIC_AGENT_DIR="elastic-agent-$ELASTIC_VERSION-linux-x86_64"

# Change directory to the user's home directory where the Elastic Agent was untarred
cd "$USER_HOME/$ELASTIC_AGENT_DIR"

# Install the Elastic Agent with the specified options
echo -e "${GREEN}$SERVICE_NAME_TOKEN${NC}"
sudo yes | sudo ./elastic-agent install \
  --url=https://${ELASTIC_HOST}:8220 \
  --fleet-server-es=https://${ELASTIC_HOST}:9200 \
  --fleet-server-service-token=$SERVICE_NAME_TOKEN \
  --fleet-server-policy=fleet-server-policy \
  --fleet-server-es-ca=/usr/share/elasticsearch/ssl/ca/ca.crt \
  --certificate-authorities=/usr/share/elasticsearch/ssl/ca/ca.crt \
  --fleet-server-cert=/usr/share/elasticsearch/ssl/elasticsearch/elasticsearch.crt \
  --fleet-server-cert-key=/usr/share/elasticsearch/ssl/elasticsearch/elasticsearch.key \
  --fleet-server-port=8220 \
  --elastic-agent-cert=/usr/share/elasticsearch/ssl/elasticsearch/elasticsearch.crt \
  --elastic-agent-cert-key=/usr/share/elasticsearch/ssl/elasticsearch/elasticsearch.key \
  --fleet-server-es-cert=/usr/share/elasticsearch/ssl/elasticsearch/elasticsearch.crt \
  --fleet-server-es-cert-key=/usr/share/elasticsearch/ssl/elasticsearch/elasticsearch.key \
  --fleet-server-es-insecure
  
# Confirm installation success
if [ $? -eq 0 ]; then
  echo -e "
${GREEN}Elastic Agent installed successfully.${NC}"

else
  echo -e "
${RED}Elastic Agent installation failed.${NC}"
  exit 1
fi

# Wait for 10 seconds while creating windows policy
echo -e "
${GREEN}Sending API request to Kibana Waiting for 10 seconds before creating windows policy...${NC}"
show_loading_bar 10
# Send the API request to create the policy and store the response
windows_policy_info=$(curl --user "${USERNAME}:${PASSWORD}" --request POST \
  --url "https://${ELASTIC_HOST}:5601/api/fleet/agent_policies?sys_monitoring=true" \
  --header 'Accept: */*' \
  --header 'Cache-Control: no-cache' \
  --header 'Connection: keep-alive' \
  --header 'Content-Type: application/json' \
  --header 'kbn-xsrf: xxx' \
  --data '{
  "name": "Windows_EDR_and_Host_logs",
  "description": "",
  "namespace": "default",
  "monitoring_enabled": [
    "logs",
    "metrics"
  ],
  "has_fleet_server": "false"
}' --insecure)

# Extract the "id" value from the response and store it in a variable
policy_id=$(echo "$windows_policy_info" | grep -o '"id":"[^"]*"' | sed 's/"id":"\([^"]*\)".*/\1/')

# Wait for 10 seconds for Elastic Defend to merge to windows policy
echo -e "
${GREEN}Sending API request to Kibana Waiting for 15 seconds before adding Elastic Defend to windows policy...${NC}"
show_loading_bar 15
# Send the next API request using the extracted "id" as the policy_id
windows_policy_EDR_info=$(curl --user "${USERNAME}:${PASSWORD}" --request POST \
  --url "https://${ELASTIC_HOST}:5601/api/fleet/package_policies" \
  --header 'Accept: */*' \
  --header 'Cache-Control: no-cache' \
  --header 'Connection: keep-alive' \
  --header 'Content-Type: application/json' \
  --header 'kbn-xsrf: xxx' \
  --data '{
  "name": "Protect",
  "description": "",
  "namespace": "default",
  "policy_id": "'"$policy_id"'",
  "enabled": true,
  "inputs": [
    {
      "enabled": true,
      "streams": [],
      "type": "ENDPOINT_INTEGRATION_CONFIG",
      "config": {
        "_config": {
          "value": {
            "type": "endpoint",
            "endpointConfig": {
              "preset": "EDRComplete"
            }
          }
        }
      }
    }
  ],
  "package": {
    "name": "endpoint",
    "title": "Elastic Defend",
    "version": "$ELASTIC_VERSION"
  }
}' --insecure)

# Output the response from the second request
echo -e "
${GREEN}$windows_policy_EDR_info..${NC}"

# Check if the "id" was successfully extracted
if [ -z "$policy_id" ]; then
  echo -e "
${RED}Failed to retrieve policy ID. Adding EDR package to Windows policy failed...${NC}"
  exit 1
fi

# Start Logstash services
echo -e "
${GREEN}Starting logstash services....${NC}"
sudo systemctl start logstash
echo -e "
${GREEN}Checking logstash status..${NC}"
sudo systemctl status logstash --no-pager

start_time=$(date +%s)
echo -e "
${GREEN}Pulling certs and keys into a variable for API request payload...${NC}
"
# Read the CA, certificate, and key contents, properly formatting them for JSON/YAML
CA_CONTENT=$(awk '{print "    "$0}' /usr/share/elasticsearch/ssl/ca/ca.crt | sed ':a;N;$!ba;s/\n/\\n/g')
CERT_CONTENT=$(awk '{print "    "$0}' /usr/share/elasticsearch/ssl/elasticsearch/elasticsearch.crt | sed ':a;N;$!ba;s/\n/\\n/g')
KEY_CONTENT=$(awk '{print "    "$0}' /usr/share/elasticsearch/ssl/elasticsearch/elasticsearch.key | sed ':a;N;$!ba;s/\n/\\n/g')

# Define the JSON payload with properly formatted YAML
echo -e "
${GREEN}Setting Logstash output as default output...${NC}
"
JSON_PAYLOAD=$(cat <<EOF
{
  "name": "Logstash Output",
  "type": "logstash",
  "is_default": true,
  "is_default_monitoring": true,
  "hosts": ["${LOGSTASH_HOST}:5044"],
  "config_yaml": "ssl:\\n  certificate: |\\n$CERT_CONTENT\\n  certificate_authorities: |\\n$CA_CONTENT\\n  key: |\\n$KEY_CONTENT"
}
EOF
)

# Obtain the OAuth2 access token for creating logstash ssl output in Fleet settings
echo -e "
${GREEN}Obtaining OAuth2 access token to setup Logstash SSL output for Fleet server...${NC}
"
ACCESS_TOKEN_LOGSTASH=$(curl --request POST \
  --url "https://${ELASTIC_HOST}:9200/_security/oauth2/token" \
  -u "${USERNAME}:${PASSWORD}" \
  --header 'Content-Type: application/json' \
  --insecure \
  --data '{
    "grant_type": "password",
    "username": "'"${USERNAME}"'",
    "password": "'"${PASSWORD}"'"
  }')

# Display the access token and store it into a new variable
echo "Access Token: $ACCESS_TOKEN_LOGSTASH"
api_access_token_logstash=$(echo "$ACCESS_TOKEN_LOGSTASH" | grep -o '"access_token":"[^"]*"' | sed 's/"access_token":"\([^"]*\)".*/\1/')

# Display the access token
if [ -n "$api_access_token_logstash" ]; then
	echo -e "
${GREEN}Access token obtained successfully: $api_access_token_logstash${NC}
"
else
	echo -e "
${RED}Failed to obtain access token.${NC}
"
fi

# Send API request
curl -X 'POST' \
  --url "https://${ELASTIC_HOST}:5601/api/fleet/outputs" \
  -H "Authorization: Bearer $api_access_token_logstash" \
  -H "kbn-xsrf: true" \
  -H "accept: application/json" \
  -H "Content-Type: application/json" \
  --data-binary "$JSON_PAYLOAD" \
  --insecure
  
end_time=$(date +%s)
elapsed_time=$((end_time - start_time))
echo -e "
${GREEN}Finished creating Fleet server Logstash output.${NC}
"

# Enable Kibana logging for debugging
echo -e "
${GREEN}Enabling Kibana logging to /var/log/kibana.log...${NC}
"

sudo tee -a /etc/kibana/kibana.yml > /dev/null <<EOL

# Logging Configuration
logging:
  appenders:
    file:
      type: file
      fileName: /var/log/kibana.log
      layout:
        type: json
  root:
    appenders: [default, file]
EOL

echo -e "
${GREEN}Logging enabled. Check logs at /var/log/kibana.log${NC}
"

# Ensure /var/log/kibana.log is writable
sudo touch /var/log/kibana.log
sudo chown kibana:kibana /var/log/kibana.log
sudo chmod 644 /var/log/kibana.log

# Restart Kibana to apply changes
echo -e "
${YELLOW}Restarting Kibana to apply changes...${NC}
"
sudo systemctl restart kibana
show_loading_bar 10

echo -e "
${GREEN}Enabling Elasticsearch, Logstash, and Kibana for persistent start upon reboot.${NC}
"
sudo systemctl enable elasticsearch
echo -e "
${GREEN}Elasticsearch Enabled.${NC}"
sudo systemctl enable logstash
echo -e "
${GREEN}Logstash Enabled.${NC}"
sudo systemctl enable kibana
echo -e "
${GREEN}Kibana Enabled.${NC}"

echo -e "
${GREEN}Everything should be good to go. Run top and watch Logstash CPU to ensure it's running low.${NC}
"
echo -e "
${GREEN}If the machine CPU settles down in 30 seconds, Logstash is running correctly.${NC}
"
echo -e "
${GREEN}If cpu tops out CPU over 300%, stop Logstash with:
 sudo systemctl stop logstash${NC}
"

# Extract cluster health status using grep and awk (fallback method)
CLUSTER_STATUS=$(echo "$CLUSTER_RESPONSE" | grep -o '"status":"[^"]*"' | cut -d':' -f2 | tr -d '"')

echo -e "${GREEN}Elasticsearch cluster health status: ${CLUSTER_STATUS}${NC}"

# Output completion message
echo -e "${GREEN}Access Kibana at:${NC} ${BLUE}https://${KIBANA_HOST}:5601${NC}
"

# === Setting file output var for Token Gen Configuration ===
TOKEN_FILE="./enrollment_tokens.txt"

# Token Generation for Adding Additional Elasticsearch Nodes
echo -e "
${GREEN}Setup complete for the initial Elasticsearch node.${NC}"
echo -e "${GREEN}You are about to generate enrollment tokens for follow-on nodes in the cluster.${NC}"

read -p "$(echo -e ${GREEN}'Would you like to continue generating tokens for the other nodes? (y/n): '${NC})" CONFIRM_TOKEN
if [[ "$CONFIRM_TOKEN" =~ ^[Yy]$ ]]; then
    echo -e "${GREEN}Generating enrollment tokens for additional nodes...${NC}"
    > "$TOKEN_FILE"  # Clear file if it exists

    for ((i = 2; i <= NODE_COUNT; i++)); do
        echo -e "${GREEN}Generating token for node ${i}...${NC}"

        sudo bash -c "echo 'Node ${i}:' >> '$TOKEN_FILE'; /usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s node >> '$TOKEN_FILE' 2>&1; echo '' >> '$TOKEN_FILE'"

        # Optional: Check if token was appended
        if ! tail -n 5 "$TOKEN_FILE" | grep -q '^ey'; then
            echo -e "${RED}Warning: Token for node ${i} may not have been generated correctly.${NC}"
        fi
    done

    if grep -q '^ey' "$TOKEN_FILE"; then
        echo -e "${GREEN}All generated tokens have been saved to: ${TOKEN_FILE}${NC}"
    else
        echo -e "${RED}No valid tokens were successfully generated.${NC}"
        echo -e "${YELLOW}You can manually attempt to generate a token using:${NC}"
        echo -e "${CYAN}sudo /usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s node${NC}"
    fi

    echo -e "
${GREEN}--- Contents of ${TOKEN_FILE} ---${NC}"
    cat "$TOKEN_FILE"
else
    echo -e "${GREEN}Token generation skipped by user.${NC}"
fi

cat << 'EOF'

 ░▒▓████████▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░      ░▒▓███████▓▒░ ░▒▓██████▓▒░ ░▒▓███████▓▒░▒▓█▓▒░░▒▓█▓▒░
 ░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░
 ░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░
 ░▒▓██████▓▒░ ░▒▓█▓▒░      ░▒▓███████▓▒░       ░▒▓███████▓▒░░▒▓████████▓▒░░▒▓██████▓▒░░▒▓████████▓▒░
 ░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░
 ░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░
 ░▒▓████████▓▒░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░      ░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░

EOF
