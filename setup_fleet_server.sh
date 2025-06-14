#!/bin/bash

# Source common functions
if [ -f ./common_functions.sh ]; then
  source ./common_functions.sh
else
  echo -e "${RED}ERROR: common_functions.sh not found. Please ensure it's in the same directory.${NC}"
  exit 1
fi

# Source ELK variables
ELK_VARS_FILE="elk_vars.conf"
if [ -f ./${ELK_VARS_FILE} ]; then
  echo -e "${YELLOW}Loading variables from ${ELK_VARS_FILE}...${NC}"
  source ./${ELK_VARS_FILE}
else
  echo -e "${RED}ERROR: ${ELK_VARS_FILE} not found. Please run previous installation scripts first. Exiting.${NC}"
  exit 1
fi

# Verify essential variables are loaded
essential_vars=(
  "SUPERUSER_USERNAME" "SUPERUSER_PASSWORD" "ELASTICSEARCH_HOST" "KIBANA_HOST"
  "ELASTIC_VERSION" "ES_NODE_NAME" "CA_CERT_PATH" "ES_CERT_PATH" "ES_KEY_PATH"
)
if [ -n "${LOGSTASH_HOST}" ]; then # Only require Logstash vars if LOGSTASH_HOST is set
    essential_vars+=("LOGSTASH_CERT_PATH" "LOGSTASH_PKCS8_KEY_PATH")
fi

for var_name in "${essential_vars[@]}"; do
  if [ -z "${!var_name}" ]; then
    echo -e "${RED}ERROR: Essential variable ${var_name} not found in ${ELK_VARS_FILE}. Exiting.${NC}"
    exit 1
  fi
done
echo -e "${GREEN}Essential variables loaded successfully.${NC}"

ES_BIN_PATH=${ES_BIN_PATH:-/usr/share/elasticsearch/bin} # Default if not set

# --- 1. Start Trial License (Optional, idempotent) ---
echo -e "${YELLOW}Attempting to start trial license (if not already active)...${NC}"
# The output of this command can be verbose, so we capture it.
trial_response=$(curl --cacert "${CA_CERT_PATH}" -s -w "%{http_code}" -u "${SUPERUSER_USERNAME}:${SUPERUSER_PASSWORD}" -X POST "https://${ELASTICSEARCH_HOST}:9200/_license/start_trial?acknowledge=true" -o /dev/null)
if [[ "$trial_response" == "200" ]]; then
    echo -e "${GREEN}Trial license command sent successfully (or already active).${NC}"
else
    echo -e "${YELLOW}Trial license command returned HTTP ${trial_response}. Might be already active or an issue occurred. Continuing...${NC}"
fi
echo # Newline for cleaner output

# --- 2. Obtain OAuth2 Access Token for Kibana API ---
echo -e "${YELLOW}Obtaining OAuth2 Access Token for Kibana API...${NC}"
ACCESS_TOKEN_JSON=$(curl --cacert "${CA_CERT_PATH}" -s -X POST "https://${ELASTICSEARCH_HOST}:9200/_security/oauth2/token" \
  -u "${SUPERUSER_USERNAME}:${SUPERUSER_PASSWORD}" \
  -H 'Content-Type: application/json' \
  -d'{"grant_type":"password","username":"'"${SUPERUSER_USERNAME}"'","password":"'"${SUPERUSER_PASSWORD}"'"}')

OAUTH_ACCESS_TOKEN_VALUE=$(echo "${ACCESS_TOKEN_JSON}" | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4)

if [ -z "${OAUTH_ACCESS_TOKEN_VALUE}" ]; then
  echo -e "${RED}Failed to obtain OAuth2 Access Token. Response: ${ACCESS_TOKEN_JSON}${NC}"
  exit 1
fi
grep -qxF "OAUTH_ACCESS_TOKEN_VALUE=${OAUTH_ACCESS_TOKEN_VALUE}" "${ELK_VARS_FILE}" || echo "OAUTH_ACCESS_TOKEN_VALUE=${OAUTH_ACCESS_TOKEN_VALUE}" >> "${ELK_VARS_FILE}"
echo -e "${GREEN}OAuth2 Access Token obtained and saved.${NC}"

# --- 3. Download and Extract Elastic Agent ---
echo -e "${YELLOW}Downloading and extracting Elastic Agent ${ELASTIC_VERSION}...${NC}"
AGENT_BASE_DIR="/opt"
AGENT_DIR_NAME="elastic-agent-${ELASTIC_VERSION}-linux-x86_64"
AGENT_DIR="${AGENT_BASE_DIR}/${AGENT_DIR_NAME}"
AGENT_TARBALL="elastic-agent-${ELASTIC_VERSION}-linux-x86_64.tar.gz"
AGENT_URL="https://artifacts.elastic.co/downloads/beats/elastic-agent/${AGENT_TARBALL}"

if [ ! -d "${AGENT_DIR}" ]; then
  progress_bar 10 "Downloading Elastic Agent..."
  # sudo curl -L -o "${AGENT_BASE_DIR}/${AGENT_TARBALL}" "${AGENT_URL}" # Using sudo if /opt needs it
  curl -L -o "/tmp/${AGENT_TARBALL}" "${AGENT_URL}" --progress-bar
  if [ $? -ne 0 ]; then echo -e "${RED}Download failed! Exiting.${NC}"; exit 1; fi

  progress_bar 5 "Extracting Elastic Agent..."
  sudo tar xzvf "/tmp/${AGENT_TARBALL}" -C "${AGENT_BASE_DIR}"
  if [ $? -ne 0 ]; then echo -e "${RED}Extraction failed! Exiting.${NC}"; exit 1; fi
  sudo rm -f "/tmp/${AGENT_TARBALL}"
  grep -qxF "AGENT_DIR=${AGENT_DIR}" "${ELK_VARS_FILE}" || echo "AGENT_DIR=${AGENT_DIR}" >> "${ELK_VARS_FILE}"
  echo -e "${GREEN}Elastic Agent downloaded and extracted to ${AGENT_DIR}.${NC}"
else
  echo -e "${GREEN}Elastic Agent directory ${AGENT_DIR} already exists. Skipping download and extraction.${NC}"
  grep -qxF "AGENT_DIR=${AGENT_DIR}" "${ELK_VARS_FILE}" || echo "AGENT_DIR=${AGENT_DIR}" >> "${ELK_VARS_FILE}" # Ensure it's in elk_vars
fi


# --- 4. Create Fleet Server Policy ---
echo -e "${YELLOW}Creating Fleet Server Policy...${NC}"
FLEET_POLICY_RESPONSE=$(curl --cacert "${CA_CERT_PATH}" -s -X POST "https://${KIBANA_HOST}:5601/api/fleet/agent_policies?sys_monitoring=true" \
  -H "Authorization: Bearer ${OAUTH_ACCESS_TOKEN_VALUE}" \
  -H "kbn-xsrf: true" \
  -H "Content-Type: application/json" \
  -d '{"name":"fleet-server-policy-'${ES_NODE_NAME}'","description":"Policy for Fleet Server on '${ES_NODE_NAME}'","namespace":"default","monitoring_enabled":["logs","metrics"],"has_fleet_server":true}')

FLEET_SERVER_POLICY_ID=$(echo "${FLEET_POLICY_RESPONSE}" | grep -o '"id":"[^"]*"' | cut -d'"' -f4)

if [ -z "${FLEET_SERVER_POLICY_ID}" ]; then
  # Check if policy already exists
  EXISTING_POLICY_ID=$(curl --cacert "${CA_CERT_PATH}" -s -X GET "https://${KIBANA_HOST}:5601/api/fleet/agent_policies?perPage=100&kuery=name:fleet-server-policy-${ES_NODE_NAME}" \
    -H "Authorization: Bearer ${OAUTH_ACCESS_TOKEN_VALUE}" \
    -H "kbn-xsrf: true" | grep -o '"id":"[^"]*"' | grep -m1 -o '"[^"]*"$' | cut -d'"' -f2) # complex grep to find specific policy by name

  if [ -n "${EXISTING_POLICY_ID}" ]; then
    FLEET_SERVER_POLICY_ID="${EXISTING_POLICY_ID}"
    echo -e "${YELLOW}Fleet Server Policy 'fleet-server-policy-${ES_NODE_NAME}' already exists with ID: ${FLEET_SERVER_POLICY_ID}. Using existing.${NC}"
  else
    echo -e "${RED}Failed to create Fleet Server Policy. Response: ${FLEET_POLICY_RESPONSE}${NC}"
    exit 1
  fi
fi
grep -qxF "FLEET_SERVER_POLICY_ID=${FLEET_SERVER_POLICY_ID}" "${ELK_VARS_FILE}" || echo "FLEET_SERVER_POLICY_ID=${FLEET_SERVER_POLICY_ID}" >> "${ELK_VARS_FILE}"
echo -e "${GREEN}Fleet Server Policy configured with ID: ${FLEET_SERVER_POLICY_ID}${NC}"


# --- 5. Create Fleet Server Host Settings ---
echo -e "${YELLOW}Creating/Updating Fleet Server Host Settings...${NC}"
# Check if default host settings exist, then decide to POST or PUT
DEFAULT_HOST_ID=$(curl --cacert "${CA_CERT_PATH}" -s -X GET "https://${KIBANA_HOST}:5601/api/fleet/fleet_server_hosts" \
    -H "Authorization: Bearer ${OAUTH_ACCESS_TOKEN_VALUE}" \
    -H "kbn-xsrf: true" | jq -r '.items[] | select(.is_default == true) | .id' | head -n 1)

FLEET_HOST_PAYLOAD="{\"name\":\"Default-${ES_NODE_NAME}\",\"host_urls\":[\"https://${ELASTICSEARCH_HOST}:8220\"],\"is_default\":true}"

if [ -n "$DEFAULT_HOST_ID" ]; then
    echo -e "${YELLOW}Default Fleet Host setting found (ID: $DEFAULT_HOST_ID). Updating it...${NC}"
    FLEET_HOST_RESPONSE=$(curl --cacert "${CA_CERT_PATH}" -s -X PUT "https://${KIBANA_HOST}:5601/api/fleet/fleet_server_hosts/${DEFAULT_HOST_ID}" \
      -H "Authorization: Bearer ${OAUTH_ACCESS_TOKEN_VALUE}" \
      -H "kbn-xsrf: true" \
      -H "Content-Type: application/json" \
      -d "${FLEET_HOST_PAYLOAD}")
else
    echo -e "${YELLOW}No default Fleet Host setting found. Creating new one...${NC}"
    FLEET_HOST_RESPONSE=$(curl --cacert "${CA_CERT_PATH}" -s -X POST "https://${KIBANA_HOST}:5601/api/fleet/fleet_server_hosts" \
      -H "Authorization: Bearer ${OAUTH_ACCESS_TOKEN_VALUE}" \
      -H "kbn-xsrf: true" \
      -H "Content-Type: application/json" \
      -d "${FLEET_HOST_PAYLOAD}")
fi
echo -e "${GREEN}Fleet Server Host settings configured. Response: ${FLEET_HOST_RESPONSE}${NC}"


# --- 6. Generate Fleet Server Service Token ---
echo -e "${YELLOW}Generating Fleet Server Service Token...${NC}"
# This command generates a token for the 'elastic/fleet-server' user.
# It might require the context of a user with privileges to create service tokens.
# The elasticsearch-service-tokens command should be run on an Elasticsearch node.
SERVICE_TOKEN_NAME="fleet-server-token-${ES_NODE_NAME}"
SERVICE_TOKEN_OUTPUT=$(sudo "${ES_BIN_PATH}/elasticsearch-service-tokens" create elastic/fleet-server "${SERVICE_TOKEN_NAME}")
FLEET_SERVICE_TOKEN_VALUE=$(echo "${SERVICE_TOKEN_OUTPUT}" | grep "The service token value is:" | cut -d ':' -f2- | sed 's/^[[:space:]]*//')

if [ -z "${FLEET_SERVICE_TOKEN_VALUE}" ]; then
  echo -e "${RED}Failed to generate Fleet Server Service Token. Output: ${SERVICE_TOKEN_OUTPUT}${NC}"
  echo -e "${RED}Please ensure Elasticsearch is running and ${ES_BIN_PATH}/elasticsearch-service-tokens is executable.${NC}"
  exit 1
fi
grep -qxF "FLEET_SERVICE_TOKEN_VALUE=${FLEET_SERVICE_TOKEN_VALUE}" "${ELK_VARS_FILE}" || echo "FLEET_SERVICE_TOKEN_VALUE=${FLEET_SERVICE_TOKEN_VALUE}" >> "${ELK_VARS_FILE}"
echo -e "${GREEN}Fleet Server Service Token generated and saved.${NC}"


# --- 7. Install and Enroll Local Elastic Agent as Fleet Server ---
echo -e "${YELLOW}Installing and enrolling local Elastic Agent as Fleet Server...${NC}"
# The -f flag is for non-interactive.
# Ensure CA_CERT_PATH, ES_CERT_PATH, ES_KEY_PATH are accessible by the user running this (or use sudo cp to a temp location if needed)
# For Fleet Server, --fleet-server-es-ca is for ES connection, --certificate-authorities is for agent's own outbound comms (e.g. to itself via LB)
# --fleet-server-cert and --fleet-server-cert-key are for the Fleet Server HTTPS endpoint (port 8220)
sudo "${AGENT_DIR}/elastic-agent" install -f \
  --url="https://${ELASTICSEARCH_HOST}:8220" \
  --fleet-server-es="https://${ELASTICSEARCH_HOST}:9200" \
  --fleet-server-service-token="${FLEET_SERVICE_TOKEN_VALUE}" \
  --fleet-server-policy="${FLEET_SERVER_POLICY_ID}" \
  --fleet-server-es-ca="${CA_CERT_PATH}" \
  --fleet-server-cert="${ES_CERT_PATH}" \
  --fleet-server-cert-key="${ES_KEY_PATH}" \
  --certificate-authorities="${CA_CERT_PATH}" # General CA for agent to trust

INSTALL_STATUS=$?
if [ ${INSTALL_STATUS} -ne 0 ]; then
  echo -e "${RED}Elastic Agent installation/enrollment as Fleet Server failed with status ${INSTALL_STATUS}.${NC}"
  echo -e "${RED}Check logs: /var/log/elastic-agent/elastic-agent-YYYYMMDD.ndjson or journalctl -u elastic-agent ${NC}"
  # Attempt to uninstall if failed part-way
  sudo "${AGENT_DIR}/elastic-agent" uninstall -f || true
  exit 1
fi
echo -e "${GREEN}Elastic Agent for Fleet Server installed and enrolled successfully.${NC}"

sudo systemctl enable elastic-agent.service > /dev/null 2>&1
sudo systemctl start elastic-agent.service
echo -e "${YELLOW}Waiting for Elastic Agent (Fleet Server) to start...${NC}"
progress_bar 5 "Waiting for agent..."
sleep 10 # Increased wait time
sudo systemctl status elastic-agent.service --no-pager || true


# --- 8. Create Example Windows EDR Policy (Optional) ---
echo -e "${YELLOW}Creating example Windows EDR Policy...${NC}"
WINDOWS_POLICY_JSON='{"name":"Windows_EDR_Host_Logs-'${ES_NODE_NAME}'","description":"Default EDR and Host Logs for Windows","namespace":"default","monitoring_enabled":["logs","metrics"],"has_fleet_server":false}'
WINDOWS_POLICY_RESPONSE=$(curl --cacert "${CA_CERT_PATH}" -s -X POST "https://${KIBANA_HOST}:5601/api/fleet/agent_policies?sys_monitoring=true" \
  -H "Authorization: Bearer ${OAUTH_ACCESS_TOKEN_VALUE}" \
  -H "kbn-xsrf: true" \
  -H "Content-Type: application/json" \
  -d "${WINDOWS_POLICY_JSON}")

WINDOWS_POLICY_ID=$(echo "${WINDOWS_POLICY_RESPONSE}" | grep -o '"id":"[^"]*"' | cut -d'"' -f4)

if [ -n "${WINDOWS_POLICY_ID}" ]; then
  grep -qxF "WINDOWS_POLICY_ID=${WINDOWS_POLICY_ID}" "${ELK_VARS_FILE}" || echo "WINDOWS_POLICY_ID=${WINDOWS_POLICY_ID}" >> "${ELK_VARS_FILE}"
  echo -e "${GREEN}Windows EDR Policy created with ID: ${WINDOWS_POLICY_ID}${NC}"

  # Add Elastic Defend integration to this policy
  # Ensure ELASTIC_VERSION is in a format like "1.2.3", not "v1.2.3" for package version.
  # The agent version might be different from integration version, usually related.
  # Let's find the latest endpoint package version.
  ENDPOINT_PKG_VERSION=$(curl --cacert "${CA_CERT_PATH}" -s -X GET "https://${KIBANA_HOST}:5601/api/fleet/epm/packages/endpoint" \
    -H "Authorization: Bearer ${OAUTH_ACCESS_TOKEN_VALUE}" \
    -H "kbn-xsrf: true" | jq -r '.item.version')

  if [ -z "$ENDPOINT_PKG_VERSION" ]; then
    echo -e "${YELLOW}Could not determine latest Elastic Defend package version. Using agent version ${ELASTIC_VERSION} as a fallback.${NC}"
    ENDPOINT_PKG_VERSION=${ELASTIC_VERSION}
  fi
  echo -e "${INFO}Using Elastic Defend package version: ${ENDPOINT_PKG_VERSION}${NC}"

  DEFEND_INTEGRATION_JSON='{"name":"endpoint","policy_id":"'"${WINDOWS_POLICY_ID}"'","enabled":true,"inputs":[],"package":{"name":"endpoint","title":"Elastic Defend","version":"'"${ENDPOINT_PKG_VERSION}"'"},"config":{"package_policy_action":"add","config_id_to_edit":"","vars":{},"yaml":"type: endpoint\nendpointConfig:\n  preset: EDRComplete\n"}}'
  # Note: The structure for package_policies can be complex. The above is simplified based on common patterns.
  # A more robust way might be to fetch current policy, add integration, then PUT.
  # For now, direct POST to create package policy.
  DEFEND_RESPONSE=$(curl --cacert "${CA_CERT_PATH}" -s -X POST "https://${KIBANA_HOST}:5601/api/fleet/package_policies" \
    -H "Authorization: Bearer ${OAUTH_ACCESS_TOKEN_VALUE}" \
    -H "kbn-xsrf: true" \
    -H "Content-Type: application/json" \
    -d "${DEFEND_INTEGRATION_JSON}")
  echo -e "${GREEN}Elastic Defend integration configuration sent for Windows policy. Response: ${DEFEND_RESPONSE}${NC}"
else
  echo -e "${YELLOW}Failed to create Windows EDR Policy or it might already exist. Response: ${WINDOWS_POLICY_RESPONSE}${NC}"
fi

# --- 9. Set Logstash as Default Output in Fleet (if LOGSTASH_HOST is defined) ---
if [ -n "${LOGSTASH_HOST}" ] && [ -n "${LOGSTASH_CERT_PATH}" ] && [ -n "${LOGSTASH_PKCS8_KEY_PATH}" ]; then
  echo -e "${YELLOW}Setting Logstash as a Fleet Output...${NC}"

  # Prepare certificate content for JSON embedding (newlines as \n)
  LS_CERT_CONTENT=$(awk '{printf "%s\\n", $0}' "${LOGSTASH_CERT_PATH}")
  LS_KEY_CONTENT=$(awk '{printf "%s\\n", $0}' "${LOGSTASH_PKCS8_KEY_PATH}") # Using PKCS8 key
  CA_PEM_CONTENT=$(awk '{printf "%s\\n", $0}' "${CA_CERT_PATH}")

  # Construct JSON payload carefully
  # Note: config_yaml is a string containing YAML. Newlines must be escaped.
  FLEET_OUTPUT_JSON_PAYLOAD=$(cat <<EOF
{
  "name": "Logstash Output - ${ES_NODE_NAME}",
  "type": "logstash",
  "is_default": true,
  "is_default_monitoring": true,
  "hosts": ["${LOGSTASH_HOST}:5044"],
  "config_yaml": "ssl:\\n  enabled: true\\n  certificate: |\\n${LS_CERT_CONTENT}  key: |\\n${LS_KEY_CONTENT}  certificate_authorities: |\\n${CA_PEM_CONTENT}"
}
EOF
)
  # Verify JSON - this is tricky. The above may still need tweaking.
  # A safer way for complex YAML in JSON:
  CONFIG_YAML_CONTENT="ssl:\n  enabled: true\n  certificate: |\n$(while IFS= read -r line; do printf '    %s\n' "$line"; done < "${LOGSTASH_CERT_PATH}")\n  key: |\n$(while IFS= read -r line; do printf '    %s\n' "$line"; done < "${LOGSTASH_PKCS8_KEY_PATH}")\n  certificate_authorities: |\n$(while IFS= read -r line; do printf '    %s\n' "$line"; done < "${CA_CERT_PATH}")"

  FLEET_OUTPUT_JSON_PAYLOAD=$(jq -n \
    --arg name "Logstash Output - ${ES_NODE_NAME}" \
    --arg type "logstash" \
    --argjson is_default true \
    --argjson is_default_monitoring true \
    --argjson hosts "[\"${LOGSTASH_HOST}:5044\"]" \
    --arg config_yaml "$CONFIG_YAML_CONTENT" \
    '{name: $name, type: $type, is_default: $is_default, is_default_monitoring: $is_default_monitoring, hosts: $hosts, config_yaml: $config_yaml}')


  FLEET_OUTPUT_RESPONSE=$(curl --cacert "${CA_CERT_PATH}" -s -X POST "https://${KIBANA_HOST}:5601/api/fleet/outputs" \
    -H "Authorization: Bearer ${OAUTH_ACCESS_TOKEN_VALUE}" \
    -H "kbn-xsrf: true" \
    -H "Content-Type: application/json" \
    -d "${FLEET_OUTPUT_JSON_PAYLOAD}")

  OUTPUT_ID=$(echo "$FLEET_OUTPUT_RESPONSE" | jq -r '.item.id // ""')
  if [ -n "$OUTPUT_ID" ]; then
    echo -e "${GREEN}Fleet Logstash Output configured successfully. ID: $OUTPUT_ID. Response: ${FLEET_OUTPUT_RESPONSE}${NC}"
  else
    echo -e "${YELLOW}Fleet Logstash Output configuration attempt response: ${FLEET_OUTPUT_RESPONSE}${NC}"
    echo -e "${YELLOW}Payload used: ${FLEET_OUTPUT_JSON_PAYLOAD}${NC}"
    echo -e "${YELLOW}If this failed, it might be due to existing default or invalid YAML in JSON. Manual check in Kibana UI might be needed.${NC}"
  fi
else
  echo -e "${INFO}Logstash host or certificate paths not defined in ${ELK_VARS_FILE}. Skipping Logstash Fleet Output setup.${NC}"
fi

# --- Final Output ---
echo -e "\n${CYAN}====================================================="
echo -e " Fleet Server Setup Script Finished!"
echo -e "=====================================================${NC}"
echo -e "${GREEN}Fleet Server should be running and connected to Elasticsearch & Kibana.${NC}"
echo -e "${GREEN}Local Elastic Agent has been enrolled as this Fleet Server.${NC}"
echo -e "${YELLOW}Check the Kibana Fleet UI (Management > Fleet) for status and to add more agents or integrations.${NC}"
echo -e "${YELLOW}Elastic Agent logs: /opt/Elastic/Agent/data/elastic-agent-*/logs/elastic-agent-YYYYMMDD.ndjson or journalctl -u elastic-agent${NC}"
echo -e "${CYAN}If you created the example Windows EDR policy, you can find it in Fleet UI and assign it to agents.${NC}"
echo -e "${CYAN}If Logstash output was configured, agents using this output will send data through Logstash.${NC}"

exit 0
