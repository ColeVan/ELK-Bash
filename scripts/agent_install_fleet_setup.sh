#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/functions.sh"

PACKAGES_DIR="$SCRIPT_DIR/packages"
mkdir -p "$PACKAGES_DIR"

# --- Main Logic ---

if [[ "$AIRGAP_INSTALL" == "true" ]]; then
    echo -e "${YELLOW}📦 Airgapped mode enabled. Searching for Elastic Agent tarball in: ${PACKAGES_DIR}${NC}"

    FOUND_TAR=$(find "$PACKAGES_DIR" -maxdepth 1 -name "elastic-agent-*-linux-x86_64.tar.gz" | head -n 1)

    if [[ ! -f "$FOUND_TAR" ]]; then
        echo -e "${RED}❌ Elastic Agent tarball not found.${NC}"
        read -rp "$(echo -e "${YELLOW}Download tarball via curl now? [y/N]: ${NC}")" download_choice

        if [[ "$download_choice" =~ ^[Yy]$ ]]; then
            read -rp "$(echo -e "${YELLOW}Enter Elastic Agent version (e.g., 9.1.0): ${NC}")" AGENT_VERSION
            download_agent "$AGENT_VERSION"
        else
            echo -e "${RED}❌ Cannot continue without tarball. Exiting.${NC}"
            exit 1
        fi
    else
        AGENT_FILENAME=$(basename "$FOUND_TAR")
        AGENT_VERSION=$(extract_version_from_filename "$AGENT_FILENAME")
        echo -e "${GREEN}✔ Found existing tarball: $AGENT_FILENAME${NC}"
    fi
else
    echo -e "${GREEN}🌐 Online installation: Downloading Elastic Agent...${NC}"
    read -rp "$(echo -e "${YELLOW}Enter Elastic Agent version (e.g., 9.1.0): ${NC}")" AGENT_VERSION
    download_agent "$AGENT_VERSION"
fi

# --- 1. Extraction ---
extract_agent  # This extracts to $PACKAGES_DIR/elastic-agent-${AGENT_VERSION}-linux-x86_64

# --- 2. Create Fleet Policy ---
echo -e "${BLUE}Creating Fleet Policy...${NC}"
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
  "monitoring_enabled": ["logs", "metrics"],
  "has_fleet_server": true
}' --insecure)

echo -e "${YELLOW}Fleet Policy Created. Response:${NC} $fleet_policy_id"
sleep 5 & spinner

# --- 3. Create Fleet Server Host ---
echo -e "${BLUE}Creating Fleet Server Host...${NC}"
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

echo -e "${YELLOW}Fleet Server Host Response:${NC} $fleet_server_host"
sleep 10 & spinner

# --- 4. Install Elastic Agent ---
# Use the extracted directory from PACKAGES_DIR
AGENT_EXTRACTED_DIR="$PACKAGES_DIR/elastic-agent-${AGENT_VERSION}-linux-x86_64"

if [[ -d "$AGENT_EXTRACTED_DIR" ]]; then
    cd "$AGENT_EXTRACTED_DIR" || {
        echo -e "${RED}❌ Could not enter directory: $AGENT_EXTRACTED_DIR${NC}"
        exit 1
    }
    echo -e "${GREEN}✔ Using extracted Elastic Agent directory: $AGENT_EXTRACTED_DIR${NC}"
else
    echo -e "${RED}❌ Extracted Elastic Agent directory not found. Exiting.${NC}"
    exit 1
fi

# Install agent with Fleet server options
echo -e "${GREEN}🔑 Using Service Token:${NC} $SERVICE_NAME_TOKEN"
sudo yes | sudo ./elastic-agent install \
  --url=https://${ELASTIC_HOST}:8220 \
  --fleet-server-es=https://${ELASTIC_HOST}:9200 \
  --fleet-server-service-token="$SERVICE_NAME_TOKEN" \
  --fleet-server-policy="fleet-server-policy" \
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

# --- 5. Confirm Installation ---
if [[ $? -eq 0 ]]; then
    echo -e "${GREEN}✔ Elastic Agent installed successfully.${NC}"
else
    echo -e "${RED}❌ Elastic Agent installation failed.${NC}"
    exit 1
fi

# Wait for 10 seconds while creating windows policy
echo -e "
${GREEN}Sending API request to Kibana Waiting for 10 seconds before creating windows policy...${NC}"
sleep 10 & spinner

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
echo -e "${GREEN}Sending API request to Kibana Waiting for 15 seconds before adding Elastic Defend to windows policy...${NC}"
sleep 15 & spinner
# Send the next API request using the extracted "id" as the policy_id
windows_policy_EDR_info=$(curl --user "${USERNAME}:${PASSWORD}" --request POST \
  --url "https://${ELASTIC_HOST}:5601/api/fleet/package_policies" \
  --header 'Accept: */*' \
  --header 'Cache-Control: no-cache' \
  --header 'Connection: keep-alive' \
  --header 'Content-Type: application/json' \
  --header "kbn-version: ${ELASTIC_VERSION}" \
  --header 'kbn-xsrf: xxx' \
  --data '{
    "name": "Protect",
    "description": "",
    "namespace": "default",
    "policy_id": "'"${policy_id}"'",
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
      "version": "'"${ELASTIC_VERSION}"'"
    }
  }' --insecure)

# Output the response from the second request
if [[ -n "$windows_policy_EDR_info" ]]; then
  echo -e "${GREEN}Windows EDR policy has been deployed. Elastic Defend ${ELASTIC_VERSION}${NC}"
else
  echo -e "${RED}Failed to deploy Windows EDR policy.${NC}"
fi

# Check if the "id" was successfully extracted
if [ -z "$policy_id" ]; then
  echo -e "${RED}Failed to retrieve policy ID. Adding EDR package to Windows policy failed...${NC}"
  exit 1
fi

# Reset Logstash password and store it in a variable
echo -e "${GREEN}Resetting Logstash password...${NC}"
sleep 5 & spinner 
logstash_password=$(sudo /usr/share/elasticsearch/bin/elasticsearch-reset-password -u logstash_system -s -b)

# Update logstash configuration with the new password
sudo sed -i "s/<logstash_password>/$logstash_password/" /etc/logstash/logstash.yml
sleep 5 & spinner

# Start Logstash services
echo -e "${GREEN}Starting logstash services....${NC}"
sudo systemctl start logstash
echo -e "${GREEN}Checking logstash status..${NC}"
check_service logstash

echo -e "${GREEN}Pulling certs and keys into a variable for API request payload...${NC}"
# Read the CA, certificate, and key contents, properly formatting them for JSON/YAML
CA_CONTENT=$(awk '{print "    "$0}' /usr/share/elasticsearch/ssl/ca/ca.crt | sed ':a;N;$!ba;s/\n/\\n/g')
CERT_CONTENT=$(awk '{print "    "$0}' /usr/share/elasticsearch/ssl/elasticsearch/elasticsearch.crt | sed ':a;N;$!ba;s/\n/\\n/g')
KEY_CONTENT=$(awk '{print "    "$0}' /usr/share/elasticsearch/ssl/elasticsearch/elasticsearch.key | sed ':a;N;$!ba;s/\n/\\n/g')

# Define the JSON payload with properly formatted YAML
echo -e "${GREEN}Setting Logstash output as default output...${NC}"
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
echo -e "${GREEN}Obtaining OAuth2 access token to setup Logstash SSL output for Fleet server...${NC}"
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

response=$(curl -s -X 'POST' \
  --url "https://${ELASTIC_HOST}:5601/api/fleet/outputs" \
  -H "Authorization: Bearer $api_access_token_logstash" \
  -H "kbn-xsrf: true" \
  -H "accept: application/json" \
  -H "Content-Type: application/json" \
  --data-binary "$JSON_PAYLOAD" \
  --insecure)

# Optional: check success, e.g. look for "id" or a known field
if [[ -n "$response" ]]; then
  echo -e "${GREEN}Finished creating Fleet server Logstash output.${NC}"
else
  echo -e "${RED}Failed to create Fleet server Logstash output.${NC}"
fi

# Enable Kibana logging for debugging
echo -e "${GREEN}Enabling Kibana logging to /var/log/kibana.log...${NC}"

sudo tee -a /etc/kibana/kibana.yml > /dev/null <<EOL

# Logging Configuration
logging:
  appenders:
    file:
      type: file
      fileName: /var/log/kibana/kibana.log
      layout:
        type: json
  root:
    appenders: [default, file]
EOL

echo -e "${GREEN}Logging enabled. Check logs at /var/log/kibana.log${NC}"

# Ensure /var/log/kibana.log is writable
sudo touch /var/log/kibana/kibana.log
sudo chown kibana:kibana /var/log/kibana/kibana.log
sudo chmod 644 /var/log/kibana/kibana.log

# Restart Kibana to apply changes
echo -e "${YELLOW}Restarting Kibana to apply changes for logging.${NC}"
sudo systemctl restart kibana
check_service kibana
sleep 10 & spinner

echo -e "${GREEN}Enabling Elasticsearch, Logstash, and Kibana for persistent start upon reboot.${NC}"
sudo systemctl enable elasticsearch
echo -e "${GREEN}Elasticsearch Enabled.${NC}"
sudo systemctl enable logstash
echo -e "${GREEN}Logstash Enabled.${NC}"
sudo systemctl enable kibana
echo -e "${GREEN}Kibana Enabled.${NC}"

echo -e "${GREEN}Everything should be good to go. Run top and watch Logstash CPU to ensure it's running low.${NC}"
echo -e "${GREEN}If the machine CPU settles down in 30 seconds, Logstash is running correctly.${NC}"
echo -e "${GREEN}If cpu tops out over 300%, stop Logstash with: sudo systemctl stop logstash${NC}"

# Extract cluster health status using grep and awk (fallback method)
CLUSTER_RESPONSE=$(curl -s -k -u $USERNAME:$PASSWORD https://$ELASTIC_HOST:9200/_cluster/health)
CLUSTER_STATUS=$(echo "$CLUSTER_RESPONSE" | grep -o '"status":"[^"]*"' | cut -d':' -f2 | tr -d '"')
echo -e "${GREEN}Elasticsearch cluster health status: ${YELLOW}${CLUSTER_STATUS}!!!${NC}"
add_to_summary_table "Cluster Status" "$CLUSTER_STATUS"

# Output completion message
echo -e "${GREEN}Access Kibana at:${NC} ${BLUE}https://${KIBANA_HOST}:5601${NC}"
add_to_summary_table "Kibana WebUI IP" "https://${KIBANA_HOST}:5601"

# === Setting file output var for Token Gen Configuration ===
TOKEN_FILE="./enrollment_tokens.txt"

if [[ "$DEPLOYMENT_TYPE" == "cluster" ]]; then
    # Token Generation for Adding Additional Elasticsearch Nodes
    echo -e "${GREEN}Setup complete for the initial Elasticsearch node.${NC}"
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
            echo -e "${GREEN}All generated tokens have been saved to:${NC} ${CYAN}${TOKEN_FILE}${NC}"
            echo -e "${YELLOW}‼️  These tokens are valid for only 20 minutes! ‼️${NC}"
        else
            echo -e "${RED}No valid tokens were successfully generated.${NC}"
            echo -e "${YELLOW}You can manually attempt to generate a token using:${NC}"
            echo -e "${CYAN}sudo /usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s node${NC}"
        fi

        echo -e "${GREEN}--- Contents of ${TOKEN_FILE} ---${NC}"
        cat "$TOKEN_FILE"
    else
        echo -e "${GREEN}Token generation skipped by user.${NC}"
    fi
fi

