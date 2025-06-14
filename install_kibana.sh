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
  essential_vars=("ELASTIC_VERSION" "KIBANA_HOST" "ELASTICSEARCH_HOST" "KIBANA_SYSTEM_PASSWORD" "CA_CERT_PATH" "KIBANA_CERT_STAGING_PATH" "KIBANA_KEY_STAGING_PATH")
  for var_name in "${essential_vars[@]}"; do
    if [ -z "${!var_name}" ]; then
      echo -e "${RED}ERROR: Essential variable ${var_name} not found in ${ELK_VARS_FILE}. Exiting.${NC}"
      exit 1
    fi
  done
  echo -e "${GREEN}Variables loaded successfully.${NC}"
else
  echo -e "${RED}ERROR: ${ELK_VARS_FILE} not found. Please run the Elasticsearch installation script first. Exiting.${NC}"
  exit 1
fi


# --- Initialization and Setup ---
echo -e "${CYAN}=== Kibana Installation Script ===${NC}"

KIBANA_CONFIG_DIR="/etc/kibana"
KIBANA_CERTS_DIR="${KIBANA_CONFIG_DIR}/certs"

echo -e "${YELLOW}Creating Kibana directories...${NC}"
sudo mkdir -p "${KIBANA_CERTS_DIR}"
echo -e "${GREEN}Kibana directories created.${NC}"

# Append Kibana specific paths to elk_vars.conf (idempotent)
grep -qxF "KIBANA_CONFIG_DIR=${KIBANA_CONFIG_DIR}" "${ELK_VARS_FILE}" || echo "KIBANA_CONFIG_DIR=${KIBANA_CONFIG_DIR}" >> "${ELK_VARS_FILE}"
grep -qxF "KIBANA_CERTS_DIR=${KIBANA_CERTS_DIR}" "${ELK_VARS_FILE}" || echo "KIBANA_CERTS_DIR=${KIBANA_CERTS_DIR}" >> "${ELK_VARS_FILE}"


# --- Prerequisites ---
install_prerequisites


# --- Kibana Installation ---
echo -e "${YELLOW}Installing Kibana version ${ELASTIC_VERSION}...${NC}"
progress_bar 5 "Preparing for Kibana installation..."
sudo apt-get update > /dev/null 2>&1
if sudo apt-get install -y "kibana=${ELASTIC_VERSION}"; then
  echo -e "${GREEN}Kibana ${ELASTIC_VERSION} installed successfully.${NC}"
else
  echo -e "${RED}Failed to install Kibana ${ELASTIC_VERSION}. Please check the version and APT repository configuration.${NC}"
  exit 1
fi


# --- SSL Certificate Setup ---
echo -e "${YELLOW}Configuring Kibana SSL certificates...${NC}"
sudo cp "${CA_CERT_PATH}" "${KIBANA_CERTS_DIR}/ca.crt"
sudo cp "${KIBANA_CERT_STAGING_PATH}" "${KIBANA_CERTS_DIR}/kibana.crt"
sudo cp "${KIBANA_KEY_STAGING_PATH}" "${KIBANA_CERTS_DIR}/kibana.key"
echo -e "${GREEN}SSL certificates copied to ${KIBANA_CERTS_DIR}.${NC}"

# Add Kibana cert paths to elk_vars.conf (idempotent)
grep -qxF "KIBANA_CA_PATH=${KIBANA_CERTS_DIR}/ca.crt" "${ELK_VARS_FILE}" || echo "KIBANA_CA_PATH=${KIBANA_CERTS_DIR}/ca.crt" >> "${ELK_VARS_FILE}"
grep -qxF "KIBANA_CERT_PATH=${KIBANA_CERTS_DIR}/kibana.crt" "${ELK_VARS_FILE}" || echo "KIBANA_CERT_PATH=${KIBANA_CERTS_DIR}/kibana.crt" >> "${ELK_VARS_FILE}"
grep -qxF "KIBANA_KEY_PATH=${KIBANA_CERTS_DIR}/kibana.key" "${ELK_VARS_FILE}" || echo "KIBANA_KEY_PATH=${KIBANA_CERTS_DIR}/kibana.key" >> "${ELK_VARS_FILE}"

echo -e "${YELLOW}Setting ownership and permissions for Kibana certificates...${NC}"
sudo chown -R kibana:kibana "${KIBANA_CERTS_DIR}"
sudo chmod -R 750 "${KIBANA_CERTS_DIR}" # Owner rwx, Group rx, Others --- (Note: original said 750, but keys should be more restrictive)
sudo chmod 640 "${KIBANA_CERTS_DIR}/kibana.key" # Owner rw, Group r, Others --- (More secure for private key)
sudo chmod 644 "${KIBANA_CERTS_DIR}/kibana.crt" # Readable by all, but chown restricts to kibana user/group
sudo chmod 644 "${KIBANA_CERTS_DIR}/ca.crt"
echo -e "${GREEN}Ownership and permissions for certificates set.${NC}"


# --- Kibana Configuration (kibana.yml) ---
echo -e "${YELLOW}Configuring Kibana (kibana.yml)...${NC}"
KIBANA_YML_PATH="${KIBANA_CONFIG_DIR}/kibana.yml"

# Generate random keys for encryption
ENC_KEY_1=$(openssl rand -hex 16) # 32 chars
ENC_KEY_2=$(openssl rand -hex 16) # 32 chars

# Create Kibana log directory and file
sudo mkdir -p /var/log/kibana
sudo touch /var/log/kibana/kibana.log
sudo chown -R kibana:kibana /var/log/kibana
sudo chmod -R 750 /var/log/kibana # Owner rwx, Group rx

# Check if KIBANA_SYSTEM_PASSWORD (new name) or KIBANA_SYSTEM_PASSWORD_VALUE (old name from earlier thought process) exists
if [ -z "${KIBANA_SYSTEM_PASSWORD}" ] && [ -n "${KIBANA_SYSTEM_PASSWORD_VALUE}" ]; then
    KIBANA_SYSTEM_PASSWORD="${KIBANA_SYSTEM_PASSWORD_VALUE}"
elif [ -z "${KIBANA_SYSTEM_PASSWORD}" ] && [ -z "${KIBANA_SYSTEM_PASSWORD_VALUE}" ]; then
    echo -e "${RED}ERROR: KIBANA_SYSTEM_PASSWORD or KIBANA_SYSTEM_PASSWORD_VALUE not found in environment. Exiting.${NC}"
    exit 1
fi


sudo bash -c "cat <<EOF > ${KIBANA_YML_PATH}
server.port: 5601
server.host: \"${KIBANA_HOST}\"
server.name: \"kibana-on-${KIBANA_HOST}\"

elasticsearch.hosts: [\"https://${ELASTICSEARCH_HOST}:9200\"]
elasticsearch.username: \"kibana_system\" # Corrected username as per ES 8.x default setup
elasticsearch.password: \"${KIBANA_SYSTEM_PASSWORD}\"
elasticsearch.ssl.certificateAuthorities: [\"${KIBANA_CERTS_DIR}/ca.crt\"]
elasticsearch.ssl.verificationMode: certificate # full, certificate, or none

server.ssl.enabled: true
server.ssl.certificate: \"${KIBANA_CERTS_DIR}/kibana.crt\"
server.ssl.key: \"${KIBANA_CERTS_DIR}/kibana.key\"

pid.file: /run/kibana/kibana.pid

# Security and Encryption Settings
xpack.security.encryptionKey: \"${ENC_KEY_1}\"
xpack.encryptedSavedObjects.encryptionKey: \"${ENC_KEY_2}\"

# Logging Configuration
logging.appenders.file:
  type: file
  fileName: /var/log/kibana/kibana.log
  layout:
    type: json
logging.root:
  appenders: [default, file]
  level: info

# Optional: Add if Kibana URL needs to be explicitly known by Kibana itself for some features
# server.publicBaseUrl: "https://${KIBANA_HOST}:5601"
EOF"

progress_bar 2 "Writing kibana.yml configuration..."
echo -e "${GREEN}kibana.yml configured.${NC}"

echo -e "${YELLOW}Setting ownership and permissions for kibana.yml...${NC}"
sudo chown kibana:kibana "${KIBANA_YML_PATH}"
sudo chmod 640 "${KIBANA_YML_PATH}" # Owner rw, Group r, Others ---
echo -e "${GREEN}Ownership and permissions for kibana.yml set.${NC}"


# --- Service Management ---
echo -e "${YELLOW}Reloading systemd daemon, enabling and starting Kibana service...${NC}"
sudo systemctl daemon-reload
sudo systemctl enable kibana.service
sudo systemctl start kibana.service
echo -e "${GREEN}Kibana service enabled and start command issued.${NC}"

progress_bar 5 "Waiting for Kibana to initialize (approx. 15-30 seconds)..."
sleep 15 # Give Kibana some time to start

echo -e "${YELLOW}Checking Kibana service status...${NC}"
sudo systemctl status kibana.service --no-pager || true # Display status, continue even if it briefly shows an error during startup

# A more robust check could involve curling Kibana's status endpoint if available and unauthenticated
# For now, rely on systemctl status and user checking the logs/URL


# --- Final Output ---
echo -e "\n${CYAN}====================================================="
echo -e " Kibana Installation and Configuration Complete!"
echo -e "=====================================================${NC}"
echo -e "${GREEN}Access Kibana at: https://${KIBANA_HOST}:5601${NC}"
echo -e "${YELLOW}It might take a few minutes for Kibana to fully initialize and become available.${NC}"
echo -e "${YELLOW}If you encounter issues, check the Kibana logs:${NC}"
echo -e "${YELLOW}  sudo journalctl -u kibana.service${NC}"
echo -e "${YELLOW}  sudo cat /var/log/kibana/kibana.log${NC}"
echo -e "${CYAN}Make sure your firewall allows traffic on port 5601.${NC}"

exit 0
