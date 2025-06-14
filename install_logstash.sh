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
  # Verify essential variables are loaded
  essential_vars=(
    "ELASTIC_VERSION" "LOGSTASH_HOST" "ELASTICSEARCH_HOST" "LOGSTASH_SYSTEM_PASSWORD"
    "CA_CERT_PATH" "LOGSTASH_CERT_STAGING_PATH" "LOGSTASH_KEY_STAGING_PATH"
    "ES_NODE_NAME" "LOGSTASH_OUTPUT_API_KEY_ENCODED" # This last one is critical
  )
  for var_name in "${essential_vars[@]}"; do
    if [ -z "${!var_name}" ]; then
      echo -e "${RED}ERROR: Essential variable ${var_name} not found in ${ELK_VARS_FILE}. Exiting.${NC}"
      echo -e "${RED}Ensure Elasticsearch script ran successfully and generated LOGSTASH_OUTPUT_API_KEY_ENCODED.${NC}"
      exit 1
    fi
  done
  echo -e "${GREEN}Variables loaded successfully.${NC}"
else
  echo -e "${RED}ERROR: ${ELK_VARS_FILE} not found. Please run the Elasticsearch installation script first. Exiting.${NC}"
  exit 1
fi

# --- Initialization and Setup ---
echo -e "${CYAN}=== Logstash Installation Script ===${NC}"

LOGSTASH_CONFIG_DIR="/etc/logstash"
LOGSTASH_CERTS_DIR="${LOGSTASH_CONFIG_DIR}/certs"
LOGSTASH_PIPELINE_DIR="${LOGSTASH_CONFIG_DIR}/conf.d"
LOGSTASH_DATA_DIR="/var/lib/logstash" # Default Logstash data path
LOGSTASH_TEMP_DIR="/opt/logstash_tmp" # Custom temp dir

echo -e "${YELLOW}Creating Logstash directories...${NC}"
sudo mkdir -p "${LOGSTASH_CERTS_DIR}"
sudo mkdir -p "${LOGSTASH_PIPELINE_DIR}"
sudo mkdir -p "${LOGSTASH_DATA_DIR}/queue" # For persisted queue
sudo mkdir -p "${LOGSTASH_DATA_DIR}/dead_letter_queue" # For DLQ
sudo mkdir -p "${LOGSTASH_TEMP_DIR}"
echo -e "${GREEN}Logstash directories created.${NC}"

echo -e "${YELLOW}Setting ownership for Logstash data and temp directories...${NC}"
sudo chown -R logstash:logstash "${LOGSTASH_DATA_DIR}" "${LOGSTASH_TEMP_DIR}"
echo -e "${GREEN}Ownership set.${NC}"

# Append Logstash specific paths to elk_vars.conf (idempotent)
grep -qxF "LOGSTASH_CONFIG_DIR=${LOGSTASH_CONFIG_DIR}" "${ELK_VARS_FILE}" || echo "LOGSTASH_CONFIG_DIR=${LOGSTASH_CONFIG_DIR}" >> "${ELK_VARS_FILE}"
grep -qxF "LOGSTASH_CERTS_DIR=${LOGSTASH_CERTS_DIR}" "${ELK_VARS_FILE}" || echo "LOGSTASH_CERTS_DIR=${LOGSTASH_CERTS_DIR}" >> "${ELK_VARS_FILE}"
grep -qxF "LOGSTASH_PIPELINE_DIR=${LOGSTASH_PIPELINE_DIR}" "${ELK_VARS_FILE}" || echo "LOGSTASH_PIPELINE_DIR=${LOGSTASH_PIPELINE_DIR}" >> "${ELK_VARS_FILE}"
grep -qxF "LOGSTASH_DATA_DIR=${LOGSTASH_DATA_DIR}" "${ELK_VARS_FILE}" || echo "LOGSTASH_DATA_DIR=${LOGSTASH_DATA_DIR}" >> "${ELK_VARS_FILE}"


# --- Prerequisites ---
install_prerequisites


# --- Logstash Installation ---
echo -e "${YELLOW}Installing Logstash version ${ELASTIC_VERSION}...${NC}"
progress_bar 5 "Preparing for Logstash installation..."
sudo apt-get update > /dev/null 2>&1
if sudo apt-get install -y "logstash=${ELASTIC_VERSION}"; then
  echo -e "${GREEN}Logstash ${ELASTIC_VERSION} installed successfully.${NC}"
else
  echo -e "${YELLOW}Failed to install Logstash ${ELASTIC_VERSION}. Attempting to install latest available Logstash...${NC}"
  echo -e "${YELLOW}This might lead to version compatibility issues with Elasticsearch.${NC}"
  if sudo apt-get install -y logstash; then
    echo -e "${GREEN}Latest Logstash installed successfully. Please verify compatibility with Elasticsearch ${ELASTIC_VERSION}.${NC}"
  else
    echo -e "${RED}Failed to install Logstash. Please check APT repository configuration and network access.${NC}"
    exit 1
  fi
fi


# --- SSL Certificate Setup ---
echo -e "${YELLOW}Configuring Logstash SSL certificates...${NC}"
sudo cp "${CA_CERT_PATH}" "${LOGSTASH_CERTS_DIR}/ca.crt"
sudo cp "${LOGSTASH_CERT_STAGING_PATH}" "${LOGSTASH_CERTS_DIR}/logstash.crt"
sudo cp "${LOGSTASH_KEY_STAGING_PATH}" "${LOGSTASH_CERTS_DIR}/logstash.key" # This is the original PEM key

echo -e "${YELLOW}Converting Logstash private key to PKCS#8 format...${NC}"
sudo openssl pkcs8 -inform PEM -in "${LOGSTASH_CERTS_DIR}/logstash.key" -topk8 -nocrypt -outform PEM -out "${LOGSTASH_CERTS_DIR}/logstash.pkcs8.key"
if [ $? -ne 0 ]; then
    echo -e "${RED}Failed to convert Logstash key to PKCS#8. Check OpenSSL and key file.${NC}"
    exit 1
fi
echo -e "${GREEN}SSL certificates copied and key converted to PKCS#8.${NC}"

# Add Logstash cert paths to elk_vars.conf (idempotent)
grep -qxF "LOGSTASH_CA_PATH=${LOGSTASH_CERTS_DIR}/ca.crt" "${ELK_VARS_FILE}" || echo "LOGSTASH_CA_PATH=${LOGSTASH_CERTS_DIR}/ca.crt" >> "${ELK_VARS_FILE}"
grep -qxF "LOGSTASH_CERT_PATH=${LOGSTASH_CERTS_DIR}/logstash.crt" "${ELK_VARS_FILE}" || echo "LOGSTASH_CERT_PATH=${LOGSTASH_CERTS_DIR}/logstash.crt" >> "${ELK_VARS_FILE}"
grep -qxF "LOGSTASH_KEY_PATH=${LOGSTASH_CERTS_DIR}/logstash.key" "${ELK_VARS_FILE}" || echo "LOGSTASH_KEY_PATH=${LOGSTASH_CERTS_DIR}/logstash.key" >> "${ELK_VARS_FILE}" # Original key
grep -qxF "LOGSTASH_PKCS8_KEY_PATH=${LOGSTASH_CERTS_DIR}/logstash.pkcs8.key" "${ELK_VARS_FILE}" || echo "LOGSTASH_PKCS8_KEY_PATH=${LOGSTASH_CERTS_DIR}/logstash.pkcs8.key" >> "${ELK_VARS_FILE}"

echo -e "${YELLOW}Setting ownership and permissions for Logstash certificates...${NC}"
sudo chown -R logstash:logstash "${LOGSTASH_CERTS_DIR}"
sudo chmod 750 "${LOGSTASH_CERTS_DIR}" # Owner rwx, Group rx, Others ---
# Set specific permissions for files inside
sudo chmod 640 "${LOGSTASH_CERTS_DIR}/ca.crt"
sudo chmod 640 "${LOGSTASH_CERTS_DIR}/logstash.crt"
sudo chmod 600 "${LOGSTASH_CERTS_DIR}/logstash.key" # Original key, more restrictive
sudo chmod 600 "${LOGSTASH_CERTS_DIR}/logstash.pkcs8.key" # PKCS8 key, more restrictive
echo -e "${GREEN}Ownership and permissions for certificates set.${NC}"


# --- Logstash Configuration ---
LOGSTASH_NODE_NAME="${ES_NODE_NAME}-logstash" # Using ES_NODE_NAME as a prefix for uniqueness
echo "LOGSTASH_NODE_NAME=${LOGSTASH_NODE_NAME}" >> "${ELK_VARS_FILE}"

# Check for LOGSTASH_SYSTEM_PASSWORD or LOGSTASH_SYSTEM_PASSWORD_VALUE
if [ -z "${LOGSTASH_SYSTEM_PASSWORD}" ] && [ -n "${LOGSTASH_SYSTEM_PASSWORD_VALUE}" ]; then
    LOGSTASH_SYSTEM_PASSWORD="${LOGSTASH_SYSTEM_PASSWORD_VALUE}"
elif [ -z "${LOGSTASH_SYSTEM_PASSWORD}" ] && [ -z "${LOGSTASH_SYSTEM_PASSWORD_VALUE}" ]; then
    echo -e "${RED}ERROR: LOGSTASH_SYSTEM_PASSWORD or LOGSTASH_SYSTEM_PASSWORD_VALUE not found in environment. Exiting.${NC}"
    exit 1
fi

# logstash.yml
echo -e "${YELLOW}Configuring Logstash (logstash.yml)...${NC}"
LOGSTASH_YML_PATH="${LOGSTASH_CONFIG_DIR}/logstash.yml"
sudo bash -c "cat <<EOF > ${LOGSTASH_YML_PATH}
http.host: \"${LOGSTASH_HOST}\"
path.data: ${LOGSTASH_DATA_DIR}
node.name: ${LOGSTASH_NODE_NAME}

# Queue settings
queue.type: persisted
path.queue: ${LOGSTASH_DATA_DIR}/queue

# Dead Letter Queue settings
dead_letter_queue.enable: true
path.dead_letter_queue: ${LOGSTASH_DATA_DIR}/dead_letter_queue

# X-Pack Monitoring settings
xpack.monitoring.enabled: true
xpack.monitoring.elasticsearch.username: \"logstash_system\"
xpack.monitoring.elasticsearch.password: \"${LOGSTASH_SYSTEM_PASSWORD}\"
xpack.monitoring.elasticsearch.hosts: [\"https://${ELASTICSEARCH_HOST}:9200\"]
xpack.monitoring.elasticsearch.ssl.ca: \"${LOGSTASH_CERTS_DIR}/ca.crt\"
xpack.monitoring.elasticsearch.ssl.verification_mode: certificate # full, certificate, or none
EOF"
sudo chown logstash:logstash "${LOGSTASH_YML_PATH}"
sudo chmod 640 "${LOGSTASH_YML_PATH}"
echo -e "${GREEN}logstash.yml configured.${NC}"

# pipelines.yml
echo -e "${YELLOW}Configuring Logstash (pipelines.yml)...${NC}"
PIPELINES_YML_PATH="${LOGSTASH_CONFIG_DIR}/pipelines.yml"
sudo bash -c "cat <<EOF > ${PIPELINES_YML_PATH}
- pipeline.id: main
  path.config: \"${LOGSTASH_PIPELINE_DIR}/*.conf\"
  queue.type: persisted
EOF"
sudo chown logstash:logstash "${PIPELINES_YML_PATH}"
sudo chmod 640 "${PIPELINES_YML_PATH}"
echo -e "${GREEN}pipelines.yml configured.${NC}"

# jvm.options
echo -e "${YELLOW}Configuring Logstash JVM options (jvm.options)...${NC}"
JVM_OPTIONS_PATH="${LOGSTASH_CONFIG_DIR}/jvm.options"
sudo cp "${JVM_OPTIONS_PATH}" "${JVM_OPTIONS_PATH}.bak" # Backup original
sudo sed -i -e 's/^-Xms[0-9]\+[gGmM]$/-Xms1g/' -e 's/^-Xmx[0-9]\+[gGmM]$/-Xmx1g/' "${JVM_OPTIONS_PATH}"
# Add tmpdir if not already present
grep -q -- "-Djava.io.tmpdir=${LOGSTASH_TEMP_DIR}" "${JVM_OPTIONS_PATH}" || \
  echo "-Djava.io.tmpdir=${LOGSTASH_TEMP_DIR}" | sudo tee -a "${JVM_OPTIONS_PATH}" > /dev/null
sudo chown logstash:logstash "${JVM_OPTIONS_PATH}"
sudo chmod 640 "${JVM_OPTIONS_PATH}"
echo -e "${GREEN}JVM options configured (Heap: 1g, Temp Dir: ${LOGSTASH_TEMP_DIR}).${NC}"

# Pipeline Configuration: 01-beats-input.conf
echo -e "${YELLOW}Configuring Logstash pipeline: 01-beats-input.conf...${NC}"
BEATS_INPUT_CONF="${LOGSTASH_PIPELINE_DIR}/01-beats-input.conf"
sudo bash -c "cat <<EOF > ${BEATS_INPUT_CONF}
input {
  beats {
    port => 5044
    ssl => true
    ssl_certificate => \"${LOGSTASH_CERTS_DIR}/logstash.crt\"
    ssl_key => \"${LOGSTASH_CERTS_DIR}/logstash.pkcs8.key\" # Use PKCS#8 key
    # ssl_client_authentication => \"none\" # Default is none, explicitly 'none' or 'optional' or 'required'
    # ssl_verify_mode => \"none\" # For client certs, not typically for server side of Beats
  }
}
EOF"
echo -e "${GREEN}01-beats-input.conf configured.${NC}"

# Pipeline Configuration: 99-elastic-output.conf
echo -e "${YELLOW}Configuring Logstash pipeline: 99-elastic-output.conf...${NC}"
ELASTIC_OUTPUT_CONF="${LOGSTASH_PIPELINE_DIR}/99-elastic-output.conf"
sudo bash -c "cat <<EOF > ${ELASTIC_OUTPUT_CONF}
output {
  elasticsearch {
    hosts => [\"https://${ELASTICSEARCH_HOST}:9200\"]
    auth_type => {
        type => 'api_key'
        id => \"\$(echo '${LOGSTASH_OUTPUT_API_KEY_ENCODED}' | base64 --decode | cut -d: -f1)\"
        api_key => \"\$(echo '${LOGSTASH_OUTPUT_API_KEY_ENCODED}' | base64 --decode | cut -d: -f2 )\"
    }
    ssl => {
        enabled => true # SSL is enabled for https hosts
        ca_path => \"${LOGSTASH_CERTS_DIR}/ca.crt\"
        # verification_mode => 'full' # 'full', 'certificate', or 'none'. Default 'full'
    }
    # data_stream => false # Set to true if using data streams, false for regular indices
    index => \"logstash-%{+YYYY.MM.dd}\" # Default index pattern
    action => \"create\"
    # manage_template => true # Let Logstash manage its template
    # template_name => \"logstash\"
    # template_path => \"/etc/logstash/elasticsearch-template.json\" # If custom template
  }
}
EOF"
echo -e "${GREEN}99-elastic-output.conf configured.${NC}"

echo -e "${YELLOW}Setting ownership and permissions for pipeline configurations...${NC}"
sudo chown -R logstash:logstash "${LOGSTASH_PIPELINE_DIR}"
sudo chmod -R 640 "${LOGSTASH_PIPELINE_DIR}"/*
echo -e "${GREEN}Pipeline configuration permissions set.${NC}"


# --- Service Management ---
echo -e "${YELLOW}Reloading systemd daemon, enabling and starting Logstash service...${NC}"
sudo systemctl daemon-reload
sudo systemctl enable logstash.service
sudo systemctl start logstash.service
echo -e "${GREEN}Logstash service enabled and start command issued.${NC}"

progress_bar 5 "Waiting for Logstash to initialize (approx. 15-45 seconds)..."
sleep 15 # Give Logstash some time to start

echo -e "${YELLOW}Checking Logstash service status...${NC}"
sudo systemctl status logstash.service --no-pager || true # Display status

# --- Final Output ---
echo -e "\n${CYAN}====================================================="
echo -e " Logstash Installation and Configuration Complete!"
echo -e "=====================================================${NC}"
echo -e "${GREEN}Logstash should now be listening on port 5044 (Beats input) and sending data to Elasticsearch.${NC}"
echo -e "${YELLOW}Check Logstash logs for any errors or status updates:${NC}"
echo -e "${YELLOW}  sudo journalctl -u logstash.service${NC}"
echo -e "${YELLOW}  sudo cat /var/log/logstash/logstash-plain.log (or as configured in log4j2.properties if customized)${NC}"
echo -e "${CYAN}Ensure your firewall allows traffic on port 5044 (if Beats are external).${NC}"
echo -e "${RED}CRITICAL: Ensure the variable LOGSTASH_OUTPUT_API_KEY_ENCODED was correctly populated in ${ELK_VARS_FILE} by the Elasticsearch setup script. Logstash will not be able to send data to Elasticsearch otherwise.${NC}"

exit 0
