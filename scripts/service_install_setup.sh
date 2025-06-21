#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/functions.sh"

# Update and install prerequisites with a progress bar
echo -e "${YELLOW}Updating package lists and installing prerequisites...${NC}"

sudo apt-get update > /dev/null 2>&1
sleep 2 & spinner "Running apt-get update."

sudo apt-get install -y curl apt-transport-https unzip > /dev/null 2>&1
sleep 2 & spinner "Running apt-get install for curl and unzip packages."

# Display success message with color
echo -e "${GREEN}Installation of needed components completed successfully in $elapsed_time seconds.${NC}"

# Add Elastic APT repository
echo -e "${BLUE}Adding Elastic APT repository...${NC}"
{
    curl -s https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add - > /dev/null 2>&1
    echo "deb https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list > /dev/null 2>&1
	echo "deb https://artifacts.elastic.co/packages/9.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-9.x.list > /dev/null 2>&1
} &
sleep 2 & spinner "Adding repository"

echo -e "${GREEN}✔ Repository added successfully.${NC}"

# Install Elasticsearch
sudo apt-get update > /dev/null 2>&1
sleep 2 & spinner "Updating package lists"
sudo apt-get install -y "elasticsearch=$ELASTIC_VERSION" > /dev/null 2>&1
sleep 2 & spinner "Installing Elasticsearch version $ELASTIC_VERSION"
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

sleep 2 & spinner
echo -e "${GREEN}✔ Elasticsearch configuration completed successfully.${NC}"

# Install Kibana
sudo apt-get update > /dev/null 2>&1
sleep 2 & spinner "Updating package lists"
sudo apt-get install -y "kibana=$ELASTIC_VERSION" > /dev/null 2>&1
sleep 2 & spinner "Installing Kibana version $ELASTIC_VERSION"
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

sleep 2 & spinner
echo -e "${GREEN}✔ Kibana configuration completed successfully.${NC}"

# Install Logstash
sudo apt-get update > /dev/null 2>&1
sleep 2 & spinner "Updating package lists"
sudo apt-get install -y logstash > /dev/null 2>&1
sleep 2 & spinner "Installing Logstash"

echo -e "${GREEN}🚀 All components installed and configured successfully! 🎉${NC}"

# Configure logstash
echo -e "${BLUE}Configuring Logstash yml file.${NC}"
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
sleep 2
echo -e "${GREEN}Updating logstash pipeline.yml.${NC}"
# Open the pipelines.yml file and add the pipeline configuration for Elastic Agent
sudo tee -a /etc/logstash/pipelines.yml > /dev/null <<EOL
- pipeline.id: main
  queue.type: persisted
  path.config: "/etc/logstash/conf.d/logstash.conf"
EOL
sleep 1
# Define the file path
JVM_OPTIONS_FILE="/etc/logstash/jvm.options"
sleep 1
# Use sed to replace the lines
sudo sed -i.bak -e 's/^-Xms[0-9]*[gG]/-Xms8g/' \
           -e 's/^-Xmx[0-9]*[gG]/-Xmx8g/' \
           -e '/-Xmx[0-9]*[gG]/a\-Djava.io.tmpdir=/opt/logstash_tmp' \
           "$JVM_OPTIONS_FILE"
		   
echo -e "${GREEN}JVM options updated successfully.${NC}"		   

echo -e "${GREEN}Initial Configuration of Logstash completed successfully.${NC}"

# Set up SSL certificates for Elasticsearch and Kibana
echo -e "${GREEN}Setting up SSL certificates for Kibana, Elasticsearch, and Logstash in instances.yml...${NC}"
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

echo -e "${GREEN}Generating SSL certificates from instances.yml...${NC}"
# Generate SSL certificates
sudo /usr/share/elasticsearch/bin/elasticsearch-certgen --in /usr/share/elasticsearch/instances.yml --out /usr/share/elasticsearch/certs.zip > /dev/null 2>&1

echo -e "${GREEN}Unzipping SSL certificates...${NC}"
# Unzip the generated certificates
sudo unzip /usr/share/elasticsearch/certs.zip -d /usr/share/elasticsearch/ssl/ > /dev/null 2>&1
sleep 2 & spinner "Unzipping certs.zip"

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
sleep 3 & spinner 

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
sleep 3 & spinner 

# Convert Logstash key to PKCS#8 format
echo -e "${GREEN}Converting Logstash key to PKCS#8 format...${NC}"
sudo openssl pkcs8 -inform PEM -in /etc/logstash/certs/logstash.key -topk8 -nocrypt -outform PEM -out /etc/logstash/certs/logstash.pkcs8.key
sudo chown -R logstash: /etc/logstash/certs > /dev/null 2>&1
echo -e "${GREEN}Logstash key converted and saved as logstash.pkcs8.key.${NC}"
sleep 3 & spinner 

echo -e "${GREEN}Finished setting up SSL certificates for Kibana, Elasticsearch, and Logstash....${NC}"

echo -e "${GREEN}Tweaking a few Logstash settings....${NC}"

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
sleep 3 & spinner 
echo -e "${GREEN}Logstash settings tweaked....${NC}"

# Start Elasticsearch service and report status
echo -e "${GREEN}Starting Elasticsearch...${NC}"
sudo systemctl start elasticsearch
sleep 5 & spinner
echo -e "${GREEN}Checking Elasticsearch status...${NC}"
sudo systemctl status elasticsearch --no-pager

# Reset Logstash password and store it in a variable
echo -e "${GREEN}Resetting Logstash password...${NC}"
sleep 5 & spinner 
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

# Reset Kibana password and store it in a variable
echo -e "${GREEN}Resetting Kibana password and saving to variable{NC}"
sleep 5 & spinner
kibana_password=$(sudo /usr/share/elasticsearch/bin/elasticsearch-reset-password -u kibana -s -b)

echo -e "${GREEN}Kibana password successfully reset in $elapsed_time seconds.${NC}"

# Configure Kibana
echo -e "${GREEN}Configuring Kibana yaml...{NC}"
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
sleep 5 & spinner

echo -e "${GREEN}Kibana yml file successfully configured.${NC}"
# Start Kibana service and report status
echo -e "${GREEN}Starting Kibana...${NC}"
sudo systemctl start kibana
sleep 15 & spinner
echo -e "${GREEN}Checking Kibana status...${NC}"
sudo systemctl status kibana --no-pager

echo -e "${GREEN}Creating Logstash directories for critical functions.${NC}"
sudo mkdir -p /opt/logstash_tmp
sudo chown -R logstash:logstash /opt/logstash_tmp
sudo chown -R logstash:logstash /usr/share/logstash
sudo mkdir -p /var/lib/logstash/data
sudo chown -R logstash:logstash /var/lib/logstash/data
sudo chown -R logstash:logstash /etc/logstash

# Ensure DLQ directory is in place
sudo mkdir -p /var/lib/logstash/data/dead_letter_queue
sudo chown -R logstash:logstash /var/lib/logstash/data

# Start the Elastic Stack trial license
echo -e "${GREEN}Starting the Elastic Stack trial license...${NC}"
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

echo -e "${GREEN}Started Elastic Stack trial license.${NC}"

# Obtain the OAuth2 access token
echo -e "${GREEN}Obtaining OAuth2 access token...${NC}"
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

echo -e "${GREEN}Creating Access Token for follow on system critical functions.${NC}"
# Wait for 15 seconds for packages to settle
echo -e "
${GREEN}Sending API request to Elasticsearch Waiting for 15 seconds while adding correct API key to logstash pipline...${NC}
"
sleep 15 & spinner
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
echo -e "${GREEN}Configuring Logstash Conf with decoded API key for Elastic Agent communication over port 5044 using SSL certs...${NC}"
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
echo -e "${GREEN}Configuring Logstash Conf configured with input and output settings...${NC}"
sleep 15 & spinner

echo -e "${GREEN}Setting variable paths and creating service token ...${NC}"
# Variables for ES token
ES_BIN_PATH="/usr/share/elasticsearch/bin"
SERVICE_NAME="my-token-$(date +%s)" # Generate a unique token name

# Create Service Token
echo -e "${GREEN}Creating service token with name: $SERVICE_NAME ...${NC}"
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
sleep 10 & spinner

#Restart Elasticsearch services to take new token creation
echo -e "${GREEN}Restarting Elasticsearch service to take new token creation...${NC}"
sudo systemctl restart elasticsearch
echo "Checking Elasticsearch status..."
sudo systemctl status elasticsearch --no-pager
sleep 10 & spinner

#Starting Kibana and checking status
echo -e "${GREEN}Checking Kibana status...${NC}"
sudo systemctl status kibana --no-pager
sleep 5 & spinner
echo -e "${YELLOW}The installation hasn't failed yet... Things look good so far, continuing forward....${NC}"
sleep 5 & spinner

