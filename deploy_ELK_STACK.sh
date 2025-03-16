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

# Ask if it's a single ELK stack or a cluster deployment
read -p "Is this a single ELK stack deployment or a cluster deployment? (single/cluster): " DEPLOYMENT_TYPE

if [ "$DEPLOYMENT_TYPE" == "single" ]; then
    # Single ELK stack deployment, prompt for one IP for all components
    read -p "Enter the IP address for the Elasticsearch, Kibana, and Logstash hosts: " COMMON_IP

    # Assign the same IP for all components
    ELASTIC_HOST=$COMMON_IP
    KIBANA_HOST=$COMMON_IP
    LOGSTASH_HOST=$COMMON_IP

    # Validate each IP
    for ip in "$ELASTIC_HOST" "$KIBANA_HOST" "$LOGSTASH_HOST"; do
        if ! validate_ip $ip; then
            echo "Exiting script due to invalid IP: $ip"
            exit 1
        fi
    done
elif [ "$DEPLOYMENT_TYPE" == "cluster" ]; then
    # Cluster deployment, prompt for separate IPs for each component
    read -p "Enter the IP address for the Elasticsearch host: " ELASTIC_HOST
    read -p "Enter the IP address for the Kibana host: " KIBANA_HOST
    read -p "Enter the IP address for the Logstash host: " LOGSTASH_HOST

    # Validate each IP
    for ip in "$ELASTIC_HOST" "$KIBANA_HOST" "$LOGSTASH_HOST"; do
        if ! validate_ip $ip; then
            echo "Exiting script due to invalid IP: $ip"
            exit 1
        fi
    done
else
    echo "Invalid input. Please enter 'single' or 'cluster'."
    exit 1
fi

# Optional: Display the collected IPs
echo "Elasticsearch host: $ELASTIC_HOST"
echo "Kibana host: $KIBANA_HOST"
echo "Logstash host: $LOGSTASH_HOST"

# Function to validate username
validate_username() {
  if [[ -z "$1" || "$1" =~ [^a-zA-Z0-9_\-] ]]; then
    echo "Invalid username. Only alphanumeric characters, underscores (_), and dashes (-) are allowed."
    return 1
  fi
  return 0
}

# Function to validate password
validate_password() {
  if [[ -z "$1" || ${#1} -lt 8 ]]; then
    echo "Invalid password. It must be at least 8 characters long."
    return 1
  fi
  return 0
}

start_time=$(date +%s)
# Prompt for username and validate
while true; do
  read -p "Enter a username for the superuser: " USERNAME
  if validate_username "$USERNAME"; then
    break
  else
    echo "Please enter a valid username."
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
      echo "Passwords do not match. Please try again."
    fi
  else
    echo "Please enter a valid password."
  fi
done

# Simulate a loading bar (optional)
show_loading_bar 3
end_time=$(date +%s)
elapsed_time=$((end_time - start_time))
echo -e "\n\033[32mSuccess!! Created Superuser variables for use later on during install which took $elapsed_time seconds.\033[0m\n"

# Define Elastic version
ELASTIC_VERSION="8.x"

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
echo -e "\n\033[32mInstallation completed successfully in $elapsed_time seconds.\033[0m\n"

start_time=$(date +%s)
# Add the Elastic APT repository
echo "Adding Elastic APT repository..."
curl -s https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add - > /dev/null 2>&1
echo "deb https://artifacts.elastic.co/packages/${ELASTIC_VERSION}/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-${ELASTIC_VERSION}.list > /dev/null 2>&1
show_loading_bar 3
end_time=$(date +%s)
elapsed_time=$((end_time - start_time))
echo -e "\n\033[32mInstallation completed successfully in $elapsed_time seconds.\033[0m\n"

start_time=$(date +%s)
# Update the package list and install Elasticsearch
echo "Installing Elasticsearch..."
sudo apt-get update > /dev/null 2>&1
sudo apt-get install -y elasticsearch > /dev/null 2>&1
show_loading_bar 5
end_time=$(date +%s)
elapsed_time=$((end_time - start_time))
echo -e "\n\033[32mInstallation completed successfully in $elapsed_time seconds.\033[0m\n"

start_time=$(date +%s)
# Configure Elasticsearch
echo "Configuring Elasticsearch..."
sudo tee /etc/elasticsearch/elasticsearch.yml > /dev/null <<EOL
# Elasticsearch configuration
network.host: ${ELASTIC_HOST}
http.port: 9200
node.name: elk-edr
path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch
xpack.security.enrollment.enabled: true

# Enable encryption for HTTP API client connections, such as Kibana, Logstash, and Agents
xpack.security.http.ssl.enabled: true
xpack.security.http.ssl.keystore.path: certs/http.p12

# Enable encryption and mutual authentication between cluster nodes
xpack.security.transport.ssl.enabled: true
xpack.security.transport.ssl.verification_mode: certificate
xpack.security.transport.ssl.keystore.path: certs/transport.p12
xpack.security.transport.ssl.truststore.path: certs/transport.p12

# nodes
cluster.initial_master_nodes: ["elk-edr"]

# Allow HTTP API connections from localhost and local networks
http.host: [_local_, _site_]
EOL
show_loading_bar 3
end_time=$(date +%s)
elapsed_time=$((end_time - start_time))
echo -e "\n\033[32mInitial Configuration of Elasticsearch completed successfully in $elapsed_time seconds.\033[0m\n"

start_time=$(date +%s)
# Install Kibana
echo "Installing Kibana..."
sudo apt-get install -y kibana > /dev/null 2>&1
show_loading_bar 5
end_time=$(date +%s)
elapsed_time=$((end_time - start_time))
echo -e "\n\033[32mInstallation completed successfully in $elapsed_time seconds.\033[0m\n"

start_time=$(date +%s)
# Configure Kibana
echo "Configuring Kibana..."
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
elasticsearch.password: "<kibana_password>"
xpack.security.encryptionKey: "something_at_least_32_characters"
xpack.encryptedSavedObjects.encryptionKey: "something_at_least_32_characters"
EOL
show_loading_bar 3
end_time=$(date +%s)
elapsed_time=$((end_time - start_time))
echo -e "\n\033[32mInitial Configuration of Kibana completed successfully in $elapsed_time seconds.\033[0m\n"

start_time=$(date +%s)
# Install Logstash
echo "Installing Logstash..."
sudo apt-get install -y logstash > /dev/null 2>&1
show_loading_bar 5
end_time=$(date +%s)
elapsed_time=$((end_time - start_time))
echo -e "\n\033[32mInstallation completed successfully in $elapsed_time seconds.\033[0m\n"

start_time=$(date +%s)
# Configure logstash
echo "Configuring Logstash..."
sudo tee /etc/logstash/logstash.yml > /dev/null <<EOL
queue.type: persisted
path.queue: /var/lib/logstash/data
dead_letter_queue.enable: false
# Elastic Output
node.name: elk-edr
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

echo "JVM options updated successfully."
end_time=$(date +%s)
elapsed_time=$((end_time - start_time))
echo -e "\n\033[32mInitial Configuration of Logstash completed successfully in $elapsed_time seconds.\033[0m\n"

start_time=$(date +%s)
# Set up SSL certificates for Elasticsearch and Kibana
echo "Setting up SSL certificates for Kibana, Elasticsearch, and Logstash..."
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
echo "Setting up Kibana SSL certificates..."
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
echo "Setting up Logstash SSL certificates..."
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
echo "Converting Logstash key to PKCS#8 format..."
sudo openssl pkcs8 -inform PEM -in /etc/logstash/certs/logstash.key -topk8 -nocrypt -outform PEM -out /etc/logstash/certs/logstash.pkcs8.key
sudo chown -R logstash: /etc/logstash/certs > /dev/null 2>&1
echo "Logstash key converted and saved as logstash.pkcs8.key."
show_loading_bar 3
end_time=$(date +%s)
elapsed_time=$((end_time - start_time))
echo -e "\n\033[32mFinished setting up SSL certificates for Kibana, Elasticsearch, and Logstash....\033[0m\n"


start_time=$(date +%s)
echo -e "\n\033[32mTweaking a few Logstash settings....\033[0m\n"
# Fixing logstash pipeline.yml
file_path="/etc/logstash/pipelines.yml"

# Replace the contents of the file with the desired configuration
sudo bash -c "cat <<EOF > $file_path
- pipeline.id: main
  queue.type: persisted
  path.config: \"/etc/logstash/conf.d/logstash.conf\"
EOF"

# Set ownership of the file to the logstash user and group
sudo chown logstash:logstash "$file_path"

# Confirm the changes
echo "File updated and ownership set to logstash for $file_path."
show_loading_bar 3
end_time=$(date +%s)
elapsed_time=$((end_time - start_time))
echo -e "\n\033[32mLogstash settings tweaked....\033[0m\n"

# Start Elasticsearch service and report status
echo "Starting Elasticsearch..."
sudo systemctl start elasticsearch
show_loading_bar 5
echo "Checking Elasticsearch status..."
sudo systemctl status elasticsearch --no-pager

# Reset Logstash password and store it in a variable
echo "Resetting Logstash password..."
show_loading_bar 5
logstash_password=$(sudo /usr/share/elasticsearch/bin/elasticsearch-reset-password -u logstash_system -s -b)

# Update logstash configuration with the new password
sudo sed -i "s/<logstash_password>/$logstash_password/" /etc/logstash/logstash.yml

# Create the superuser
echo "Creating a superuser..."
if sudo /usr/share/elasticsearch/bin/elasticsearch-users useradd "$USERNAME" -p "$PASSWORD" -r superuser > /dev/null 2>&1; then
  echo "Superuser $USERNAME created successfully."
else
  echo "Failed to create superuser $USERNAME. Check logs for details."
  exit 1
fi

start_time=$(date +%s)
# Reset Kibana password and store it in a variable
echo "Resetting Kibana password and saving to variable"
show_loading_bar 5
kibana_password=$(sudo /usr/share/elasticsearch/bin/elasticsearch-reset-password -u kibana -s -b)
end_time=$(date +%s)
elapsed_time=$((end_time - start_time))
echo -e "\n\033[32mKibana password successfully reset in $elapsed_time seconds.\033[0m\n"

start_time=$(date +%s)
# Configure Kibana
echo "Configuring Kibana yaml ..."
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
end_time=$(date +%s)
elapsed_time=$((end_time - start_time))
echo -e "\n\033[32mKibana yml file successfully configured in $elapsed_time seconds.\033[0m\n"

# Start Kibana service and report status
echo "Starting Kibana..."
sudo systemctl start kibana
show_loading_bar 15
echo "Checking Kibana status..."
sudo systemctl status kibana --no-pager

echo -e "\n\033[32mCreating Logstash directories for critical functions.\033[0m\n"
sudo mkdir /opt/logstash_tmp
sudo chown -R logstash:logstash /opt/logstash_tmp
sudo chown -R logstash:logstash /usr/share/logstash
sudo chown -R logstash:logstash /var/lib/logstash/data
sudo chown -R logstash:logstash /etc/logstash

start_time=$(date +%s)
# Start the Elastic Stack trial license
echo -e "\n\033[32mStarting the Elastic Stack trial license...\033[0m\n"
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
echo "Response from the server:"
echo "$response"

# Check if the trial was successfully started
if echo "$response" | grep -q '"trial_was_started":true'; then
    echo "Trial license has been successfully started."
else
    echo "Failed to start the trial license."
fi
end_time=$(date +%s)
elapsed_time=$((end_time - start_time))
echo -e "\n\033[32mStarted Elastic Stack trial license in $elapsed_time seconds.\033[0m\n"

start_time=$(date +%s)
# Obtain the OAuth2 access token
echo -e "\n\033[32mObtaining OAuth2 access token...\033[0m\n"
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
echo "Access Token: $ACCESS_TOKEN"
api_access_token=$(echo "$ACCESS_TOKEN" | grep -o '"access_token":"[^"]*"' | sed 's/"access_token":"\([^"]*\)".*/\1/')

# Display the stored access token
echo "Stored Access Token: $api_access_token"

# Display the access token
if [ -n "$api_access_token" ]; then
	echo -e "\n\033[32mAccess token obtained successfully: $api_access_token\033[0m\n"
else
	echo -e "\n\033[32mFailed to obtain access token.\033[0m\n"
fi
end_time=$(date +%s)
elapsed_time=$((end_time - start_time))
echo -e "\n\033[32mCreating Access Token for follow on system critical functions took $elapsed_time seconds.\033[0m\n"

# Wait for 15 seconds for packages to settle
echo -e "\n\033[32mSending API request to Elasticsearch Waiting for 15 seconds while adding correct API key to logstash pipline...\033[0m\n"
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
echo -e "\n\033[32mConfiguring Logstash Conf with decoded API key for Elastic Agent communication over port 5044 using SSL certs...\033[0m\n"
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
echo -e "\n\033[32mConfiguring Logstash Conf configured with input and output settings...\033[0m\n"
show_loading_bar 5

echo -e "\n\033[32mSetting variable paths and creating service token ...\033[0m\n"
# Variables for ES token
ES_BIN_PATH="/usr/share/elasticsearch/bin"
SERVICE_NAME="my-token-$(date +%s)" # Generate a unique token name

# Create Service Token
echo "Creating service token with name: $SERVICE_NAME"
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
  echo "Failed to create service token. Check debug output for details."
  exit 1
fi
echo -e "\n\033[32mService token prep work completed...\033[0m\n"
show_loading_bar 5

#Restart Elasticsearch services to take new token creation
echo -e "\n\033[32mRestarting Elasticsearch service to take new token creation...\033[0m\n"
sudo systemctl restart elasticsearch
echo "Checking Elasticsearch status..."
sudo systemctl status elasticsearch --no-pager
show_loading_bar 10

#Starting Kibana and checking status
echo -e "\n\033[32mRChecking Kibana status...\033[0m\n"
sudo systemctl status kibana --no-pager
show_loading_bar 3
echo -e "\n\033[33mThe installation hasn't failed yet... Things look good so far, continuing forward....\033[0m\n"
show_loading_bar 3

#Start the linux elastic agent download for fleet server....
echo -e "\n\033[34mDownloading Linux Elastic Agent to host for Fleet server setup..... standby....... ;)\033[0m\n"
show_loading_bar 3

#This is for Elastic Agent version 8.17.2. In the future this will need to be updated our replaced with a variable for easy update.
URL="https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-8.17.3-linux-x86_64.tar.gz"
FILE="elastic-agent-8.17.3-linux-x86_64.tar.gz"
USER_HOME=$(eval echo ~"$SUDO_USER")  # Get the original user's home directory
DEST_DIR="$USER_HOME"
DEST_PATH="$DEST_DIR/$FILE"

# Function to display a progress bar
progress_bar() {
  local pid=$!
  local delay=0.1
  local spinstr='|/-\'
  local temp

  echo -n "Extracting $FILE "

  while kill -0 "$pid" 2>/dev/null; do
    temp=${spinstr#?}
    printf " [%c]  " "$spinstr"
    spinstr=$temp${spinstr%"$temp"}
    sleep "$delay"
    printf "\b\b\b\b\b\b"
  done
  echo ""
}

# Download the file with progress bar
echo "Downloading $FILE..."
curl -L -o "$DEST_PATH" "$URL" --progress-bar

if [ $? -eq 0 ]; then
  echo -e "\n\033[33mDownload completed successfully....\033[0m\n"
else
  echo -e "\n\033[31mDownload failed...Does your box have stable internet connection???\033[0m\n"
  exit 1
fi

# Extract the file with progress bar
tar xzvf "$DEST_PATH" -C "$DEST_DIR" & progress_bar

if [ $? -eq 0 ]; then
  echo -e "\n\033[32mExtraction completed successfully....\033[0m\n"
else
  echo "Extraction failed."
  echo -e "\n\033[31mExtraction failed....\033[0m\n"
  exit 1
fi

# Create Fleet Policy
echo -e "\033[1;33mCreating fleet policy...\033[0m"
fleet_policy_id=$(curl --request POST \
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
echo -e "\033[1;33mFleet Policy ID: $fleet_policy_id...\033[0m"
show_loading_bar 5

# Create Fleet Server Host on https://elastic_ip:8220
echo -e "\n\033[31mCreating Fleet Server Host via Elastic API..\033[0m\n"
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
echo -e "\033[1;33mFleet Server Host Response: $fleet_server_host.\033[0m"
show_loading_bar 10

# Variables
USER_HOME="/home/$(logname)"
ELASTIC_AGENT_DIR="elastic-agent-8.17.3-linux-x86_64"

# Change directory to the user's home directory where the Elastic Agent was untarred
cd "$USER_HOME/$ELASTIC_AGENT_DIR"

# Install the Elastic Agent with the specified options
echo -e "\033[1;33m$SERVICE_NAME_TOKEN\033[0m"
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
  echo -e "\n\033[32mElastic Agent installed successfully.\033[0m"
  
else
  echo -e "\n\033[31mElastic Agent installation failed.\033[0m"
  exit 1
fi

# Wait for 10 seconds while creating windows policy
echo -e "\n\033[32mSending API request to Kibana Waiting for 10 seconds before creating windows policy...\033[0m"
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
echo -e "\n\033[32mSending API request to Kibana Waiting for 15 seconds before adding Elastic Defend to windows policy...\033[0m"
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
  "name": "EDR",
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
    "version": "8.17.2"
  }
}' --insecure)

# Output the response from the second request
echo -e "\n\033[32m$windows_policy_EDR_info..\033[0m"

# Check if the "id" was successfully extracted
if [ -z "$policy_id" ]; then
  echo -e "\n\033[31mFailed to retrieve policy ID. Adding EDR package to Windows policy failed...\033[0m"
  exit 1
fi

# Start Logstash services
echo -e "\n\033[32mStarting logstash services....\033[0m"
sudo systemctl start logstash
echo -e "\n\033[32mChecking logstash status..\033[0m"
sudo systemctl status logstash --no-pager


echo -e "\n\033[32mEnabling Elasticsearch, Logstash, and Kibana for persistent start upon reboot.\033[0m\n"
sudo systemctl enable elasticsearch
echo -e "\n\033[32mElasticsearch Enabled.\033[0m"
sudo systemctl enable logstash
echo -e "\n\033[32mLogstash Enabled.\033[0m"
sudo systemctl enable kibana
echo -e "\n\033[32mKibana Enabled.\033[0m"

# Append Logstash output configuration to kibana.yml
echo -e "\n\033[1;33mConfiguring Kibana Fleet Output to Logstash...\033[0m\n"

sudo tee -a /etc/kibana/kibana.yml > /dev/null <<EOL

# Fleet Output Configuration
xpack.fleet.outputs:
  - id: secure-logstash-output
    name: secure-logstash-output
    type: logstash
    hosts: ["${LOGSTASH_HOST}:5044"]
    ssl:
      certificate: "/usr/share/elasticsearch/ssl/elasticsearch/elasticsearch.crt"
      certificate_authorities: ["/usr/share/elasticsearch/ssl/ca/ca.crt"]
    secrets:
      ssl:
        key: "/usr/share/elasticsearch/ssl/elasticsearch/elasticsearch.key"
    is_default: true
    is_default_monitoring: true
EOL

echo -e "\n\033[32mFleet Output Configuration added to kibana.yml\033[0m\n"

# Enable Kibana logging for debugging
echo -e "\n\033[1;33mEnabling Kibana logging to /var/log/kibana.log...\033[0m\n"

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

echo -e "\n\033[32mLogging enabled. Check logs at /var/log/kibana.log\033[0m\n"

# Ensure /var/log/kibana.log is writable
sudo touch /var/log/kibana.log
sudo chown kibana:kibana /var/log/kibana.log
sudo chmod 644 /var/log/kibana.log

# Restart Kibana to apply changes
echo -e "\n\033[1;33mRestarting Kibana to apply changes...\033[0m\n"
sudo systemctl restart kibana

echo -e "\n\033[32mEverything should be good to go. Run top and watch Logstash CPU to ensure it's running low.\033[0m\n"
echo -e "\n\033[32mIf the CPU settles down in 30 seconds, Logstash is running correctly.\033[0m\n"
echo -e "\n\033[32mIf it tops out CPU over 300%, stop Logstash with:\n sudo systemctl stop logstash\033[0m\n"

# Output completion message
echo -e "\033[1;32mAccess Kibana at:\033[0m \033[1;34mhttps://${KIBANA_HOST}:5601\033[0m\n"
echo -e "\n\033[1;33mInstallation Complete! 🎉\033[0m\n"

cat << 'EOF'

 ░▒▓████████▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░      ░▒▓███████▓▒░ ░▒▓██████▓▒░ ░▒▓███████▓▒░▒▓█▓▒░░▒▓█▓▒░ 
 ░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ 
 ░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ 
 ░▒▓██████▓▒░ ░▒▓█▓▒░      ░▒▓███████▓▒░       ░▒▓███████▓▒░░▒▓████████▓▒░░▒▓██████▓▒░░▒▓████████▓▒░ 
 ░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
 ░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
 ░▒▓████████▓▒░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░      ░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░ 
 
EOF

