#!/bin/bash

# Source common functions
if [ -f ./common_functions.sh ]; then
  source ./common_functions.sh
else
  echo "ERROR: common_functions.sh not found. Please ensure it's in the same directory."
  exit 1
fi

# --- Initialization and Setup ---
echo -e "${CYAN}=== Elasticsearch First Node Installation Script ===${NC}"

ELK_VARS_FILE="elk_vars.conf"
# Attempt to source elk_vars.conf if it exists (might be populated by orchestrator)
if [ -f "${ELK_VARS_FILE}" ]; then
  echo -e "${YELLOW}Sourcing existing ${ELK_VARS_FILE}...${NC}"
  source "./${ELK_VARS_FILE}"
fi

# --- User Input Collection (Conditional) ---
# Install prerequisites first
if [ -z "${PREREQUISITES_INSTALLED}" ]; then # Assuming install_prerequisites sets this or similar
    install_prerequisites
    echo "PREREQUISITES_INSTALLED=true" >> "${ELK_VARS_FILE}"
else
    echo -e "${GREEN}Prerequisites appear to be already installed (check ${ELK_VARS_FILE}).${NC}"
fi


# Deployment Type
if [ -z "${DEPLOYMENT_TYPE}" ]; then
  read -p "Enter Deployment Type (single/cluster): " DEPLOYMENT_TYPE_INPUT
  DEPLOYMENT_TYPE="${DEPLOYMENT_TYPE_INPUT}"
  echo "DEPLOYMENT_TYPE=${DEPLOYMENT_TYPE}" >> "${ELK_VARS_FILE}"
else
  echo -e "${INFO}Using DEPLOYMENT_TYPE from ${ELK_VARS_FILE}: ${DEPLOYMENT_TYPE}${NC}"
fi

# Elastic Version
if [ -z "${ELASTIC_VERSION}" ]; then
  read -p "Enter Elasticsearch Version (e.g., 8.10.4): " ELASTIC_VERSION_INPUT
  ELASTIC_VERSION="${ELASTIC_VERSION_INPUT}"
  if [ -z "${ELASTIC_VERSION}" ]; then echo -e "${RED}Elasticsearch Version cannot be empty. Exiting.${NC}"; exit 1; fi
  echo "ELASTIC_VERSION=${ELASTIC_VERSION}" >> "${ELK_VARS_FILE}"
else
  echo -e "${INFO}Using ELASTIC_VERSION from ${ELK_VARS_FILE}: ${ELASTIC_VERSION}${NC}"
fi

# Primary Node IP (Elasticsearch Host IP for this node)
if [ -z "${PRIMARY_NODE_IP}" ]; then # PRIMARY_NODE_IP is the IP of the current machine for ES
  while true; do
    read -p "Enter Primary Elasticsearch Node IP (this machine's IP for Elasticsearch): " PRIMARY_NODE_IP_INPUT
    if validate_ip "${PRIMARY_NODE_IP_INPUT}"; then
      PRIMARY_NODE_IP="${PRIMARY_NODE_IP_INPUT}"
      echo "PRIMARY_NODE_IP=${PRIMARY_NODE_IP}" >> "${ELK_VARS_FILE}"
      # ELASTICSEARCH_HOST should be this node's IP for the first node.
      echo "ELASTICSEARCH_HOST=${PRIMARY_NODE_IP}" >> "${ELK_VARS_FILE}"
      break
    else
      echo -e "${RED}Invalid IP address format. Please try again.${NC}"
    fi
  done
else
  echo -e "${INFO}Using PRIMARY_NODE_IP from ${ELK_VARS_FILE}: ${PRIMARY_NODE_IP}${NC}"
  # Ensure ELASTICSEARCH_HOST is also set, defaults to PRIMARY_NODE_IP if not already set by orchestrator
  if [ -z "${ELASTICSEARCH_HOST}" ]; then
    echo "ELASTICSEARCH_HOST=${PRIMARY_NODE_IP}" >> "${ELK_VARS_FILE}"
  fi
fi
# Ensure ELASTICSEARCH_HOST is set to PRIMARY_NODE_IP if it wasn't set from elk_vars separately
ELASTICSEARCH_HOST=${ELASTICSEARCH_HOST:-$PRIMARY_NODE_IP}


# Kibana Host IP
if [ -z "${KIBANA_HOST}" ]; then
  if [[ "${DEPLOYMENT_TYPE,,}" == "single" ]]; then
    KIBANA_HOST="${PRIMARY_NODE_IP}"
    echo "KIBANA_HOST=${KIBANA_HOST}" >> "${ELK_VARS_FILE}"
  else # cluster
    while true; do
      read -p "Enter Kibana Host IP (can be same as ES primary node IP [${PRIMARY_NODE_IP}]): " KIBANA_HOST_INPUT
      KIBANA_HOST_INPUT=${KIBANA_HOST_INPUT:-$PRIMARY_NODE_IP}
      if validate_ip "${KIBANA_HOST_INPUT}"; then
        KIBANA_HOST="${KIBANA_HOST_INPUT}"
        echo "KIBANA_HOST=${KIBANA_HOST}" >> "${ELK_VARS_FILE}"
        break
      else
        echo -e "${RED}Invalid IP address format for Kibana Host. Please try again.${NC}"
      fi
    done
  fi
else
  echo -e "${INFO}Using KIBANA_HOST from ${ELK_VARS_FILE}: ${KIBANA_HOST}${NC}"
fi

# Logstash Host IP
if [ -z "${LOGSTASH_HOST}" ]; then
  if [[ "${DEPLOYMENT_TYPE,,}" == "single" ]]; then
    LOGSTASH_HOST="${PRIMARY_NODE_IP}"
    echo "LOGSTASH_HOST=${LOGSTASH_HOST}" >> "${ELK_VARS_FILE}"
  else # cluster
    while true; do
      read -p "Enter Logstash Host IP (can be same as ES primary node IP [${PRIMARY_NODE_IP}]): " LOGSTASH_HOST_INPUT
      LOGSTASH_HOST_INPUT=${LOGSTASH_HOST_INPUT:-$PRIMARY_NODE_IP}
      if validate_ip "${LOGSTASH_HOST_INPUT}"; then
        LOGSTASH_HOST="${LOGSTASH_HOST_INPUT}"
        echo "LOGSTASH_HOST=${LOGSTASH_HOST}" >> "${ELK_VARS_FILE}"
        break
      else
        echo -e "${RED}Invalid IP address format for Logstash Host. Please try again.${NC}"
      fi
    done
  fi
else
  echo -e "${INFO}Using LOGSTASH_HOST from ${ELK_VARS_FILE}: ${LOGSTASH_HOST}${NC}"
fi

# ES Node Count (for cluster)
if [[ "${DEPLOYMENT_TYPE,,}" == "cluster" ]]; then
  if [ -z "${ES_NODE_COUNT}" ]; then
    read -p "Enter total number of Elasticsearch nodes in the cluster: " ES_NODE_COUNT_INPUT
    ES_NODE_COUNT="${ES_NODE_COUNT_INPUT}"
    if ! [[ "${ES_NODE_COUNT}" =~ ^[0-9]+$ ]] || [ "${ES_NODE_COUNT}" -lt 1 ]; then echo "${RED}Invalid node count. Exiting.${NC}"; exit 1; fi
    echo "ES_NODE_COUNT=${ES_NODE_COUNT}" >> "${ELK_VARS_FILE}"
  else
    echo -e "${INFO}Using ES_NODE_COUNT from ${ELK_VARS_FILE}: ${ES_NODE_COUNT}${NC}"
  fi
else # single node
  if [ -z "${ES_NODE_COUNT}" ]; then # If not set by orchestrator for single, default to 1
    ES_NODE_COUNT=1
    echo "ES_NODE_COUNT=${ES_NODE_COUNT}" >> "${ELK_VARS_FILE}"
  fi
fi


# ES Node Name
if [ -z "${ES_NODE_NAME}" ]; then
  read -p "Enter Elasticsearch Node Name for this first node (e.g., es-node-1): " ES_NODE_NAME_INPUT
  ES_NODE_NAME="${ES_NODE_NAME_INPUT}"
  if [ -z "${ES_NODE_NAME}" ]; then echo -e "${RED}ES_NODE_NAME cannot be empty. Exiting.${NC}"; exit 1; fi
  echo "ES_NODE_NAME=${ES_NODE_NAME}" >> "${ELK_VARS_FILE}"
else
  echo -e "${INFO}Using ES_NODE_NAME from ${ELK_VARS_FILE}: ${ES_NODE_NAME}${NC}"
fi

# Superuser Username
if [ -z "${SUPERUSER_USERNAME}" ]; then
  read -p "Enter Superuser Username for Elasticsearch: " SUPERUSER_USERNAME_INPUT
  SUPERUSER_USERNAME="${SUPERUSER_USERNAME_INPUT}"
  if [ -z "${SUPERUSER_USERNAME}" ]; then echo -e "${RED}SUPERUSER_USERNAME cannot be empty. Exiting.${NC}"; exit 1; fi
  echo "SUPERUSER_USERNAME=${SUPERUSER_USERNAME}" >> "${ELK_VARS_FILE}"
else
  echo -e "${INFO}Using SUPERUSER_USERNAME from ${ELK_VARS_FILE}: ${SUPERUSER_USERNAME}${NC}"
fi

# Superuser Password
if [ -z "${SUPERUSER_PASSWORD}" ]; then
  while true; do
    read -s -p "Enter Superuser Password for Elasticsearch: " SUPERUSER_PASSWORD_INPUT
    echo
    read -s -p "Confirm Superuser Password: " SUPERUSER_PASSWORD_CONFIRM_INPUT
    echo
    if [[ "${SUPERUSER_PASSWORD_INPUT}" == "${SUPERUSER_PASSWORD_CONFIRM_INPUT}" ]]; then
      SUPERUSER_PASSWORD="${SUPERUSER_PASSWORD_INPUT}"
      if [ -z "${SUPERUSER_PASSWORD}" ]; then echo -e "${RED}SUPERUSER_PASSWORD cannot be empty. Exiting.${NC}"; exit 1; fi
      echo "SUPERUSER_PASSWORD=${SUPERUSER_PASSWORD}" >> "${ELK_VARS_FILE}"
      break
    else
      echo -e "${RED}Passwords do not match. Please try again.${NC}"
    fi
  done
else
  echo -e "${INFO}SUPERUSER_PASSWORD is set from ${ELK_VARS_FILE}.${NC}"
fi

# --- Directory Definitions ---
# Define paths - if already in elk_vars.conf, these will just be re-set to same value locally
# Or if orchestrator defines them, these specific values will be used.
# If script is standalone & these are not in elk_vars, these become the defaults.
_SSL_CERTS_BASE_DIR=${SSL_CERTS_BASE_DIR:-"/usr/share/elasticsearch/elk_certs_generated"}
_ES_CONFIG_DIR=${ES_CONFIG_DIR:-"/etc/elasticsearch"}
_ES_CERTS_DIR=${ES_CERTS_DIR:-"${_ES_CONFIG_DIR}/certs"}

# Ensure these are written to elk_vars.conf if not already present from orchestrator
grep -qxF "SSL_CERTS_BASE_DIR=${_SSL_CERTS_BASE_DIR}" "${ELK_VARS_FILE}" || echo "SSL_CERTS_BASE_DIR=${_SSL_CERTS_BASE_DIR}" >> "${ELK_VARS_FILE}"
grep -qxF "ES_CONFIG_DIR=${_ES_CONFIG_DIR}" "${ELK_VARS_FILE}" || echo "ES_CONFIG_DIR=${_ES_CONFIG_DIR}" >> "${ELK_VARS_FILE}"
grep -qxF "ES_CERTS_DIR=${_ES_CERTS_DIR}" "${ELK_VARS_FILE}" || echo "ES_CERTS_DIR=${_ES_CERTS_DIR}" >> "${ELK_VARS_FILE}"

# Update local script variables to use the determined paths
SSL_CERTS_BASE_DIR="${_SSL_CERTS_BASE_DIR}"
ES_CONFIG_DIR="${_ES_CONFIG_DIR}"
ES_CERTS_DIR="${_ES_CERTS_DIR}"

echo -e "${YELLOW}Creating necessary directories (if they don't exist)...${NC}"
sudo mkdir -p "${ES_CERTS_DIR}"
sudo mkdir -p "${SSL_CERTS_BASE_DIR}"
sudo mkdir -p "${SSL_CERTS_BASE_DIR}/extracted_certs/kibana" # For Kibana certs
sudo mkdir -p "${SSL_CERTS_BASE_DIR}/extracted_certs/logstash" # For Logstash certs
echo -e "${GREEN}Directories ensured.${NC}"


# --- Elasticsearch Installation ---
echo -e "${YELLOW}Adding Elastic APT repository...${NC}"
progress_bar 2 "Adding Elastic GPG Key..."
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/${ELASTIC_VERSION%.*}.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-${ELASTIC_VERSION%.*}.x.list
echo -e "${GREEN}Elastic APT repository added.${NC}"

echo -e "${YELLOW}Updating package lists and installing Elasticsearch ${ELASTIC_VERSION}...${NC}"
sudo apt-get update > /dev/null 2>&1
progress_bar 5 "Installing Elasticsearch (version ${ELASTIC_VERSION})... This may take a few minutes."
if sudo apt-get install -y "elasticsearch=${ELASTIC_VERSION}"; then
  echo -e "${GREEN}Elasticsearch ${ELASTIC_VERSION} installed successfully.${NC}"
else
  echo -e "${RED}Failed to install Elasticsearch ${ELASTIC_VERSION}. Please check the version and try again.${NC}"
  exit 1
fi

# --- Elasticsearch Configuration (elasticsearch.yml) ---
echo -e "${YELLOW}Configuring Elasticsearch (elasticsearch.yml)...${NC}"
ES_YML_PATH="${ES_CONFIG_DIR}/elasticsearch.yml"
sudo bash -c "> ${ES_YML_PATH}" # Clear existing config or create new

sudo bash -c "cat <<EOF > ${ES_YML_PATH}
cluster.name: elk-cluster
node.name: ${ES_NODE_NAME}
path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch
network.host: ${ELASTICSEARCH_HOST}
http.port: 9200
#http.host: [_local_, _site_] # Optional: uncomment if needed for specific binding
#transport.host: ${ELASTICSEARCH_HOST} # Usually not needed if network.host is specific

xpack.security.enabled: true
xpack.security.enrollment.enabled: true
xpack.security.http.ssl.enabled: true
xpack.security.http.ssl.keystore.path: certs/http.p12
xpack.security.transport.ssl.enabled: true
xpack.security.transport.ssl.verification_mode: certificate
xpack.security.transport.ssl.keystore.path: certs/transport.p12
xpack.security.transport.ssl.truststore.path: certs/transport.p12
cluster.initial_master_nodes: [\"${ES_NODE_NAME}\"]
EOF"
progress_bar 2 "Writing elasticsearch.yml configuration..."
echo -e "${GREEN}elasticsearch.yml configured.${NC}"


# --- SSL Certificate Generation ---
echo -e "${YELLOW}Generating SSL certificates...${NC}"

# 1. Create CA
progress_bar 3 "Generating Certificate Authority (CA)..."
sudo /usr/share/elasticsearch/bin/elasticsearch-certutil ca --pem --out "${SSL_CERTS_BASE_DIR}/ca.zip" --pass ""
sudo unzip -o "${SSL_CERTS_BASE_DIR}/ca.zip" -d "${SSL_CERTS_BASE_DIR}"
CA_CERT_PATH_VALUE="${SSL_CERTS_BASE_DIR}/ca/ca.crt"
CA_KEY_PATH_VALUE="${SSL_CERTS_BASE_DIR}/ca/ca.key" # Store temporarily, ensure it's secured
sudo cp "${CA_CERT_PATH_VALUE}" "${ES_CERTS_DIR}/ca.crt"
echo "CA_CERT_PATH=${ES_CERTS_DIR}/ca.crt" >> "${ELK_VARS_FILE}"
echo -e "${GREEN}CA generated and copied to ${ES_CERTS_DIR}/ca.crt.${NC}"

# 2. Create Elasticsearch Node Certificate using CA
progress_bar 3 "Generating Elasticsearch node certificate..."
sudo /usr/share/elasticsearch/bin/elasticsearch-certutil cert --pem --ca-cert "${CA_CERT_PATH_VALUE}" --ca-key "${CA_KEY_PATH_VALUE}" --name "${ES_NODE_NAME}" --dns "${ES_NODE_NAME},localhost,${ELASTICSEARCH_HOST}" --ip "${ELASTICSEARCH_HOST},127.0.0.1" --out "${SSL_CERTS_BASE_DIR}/${ES_NODE_NAME}.zip" --pass ""
sudo unzip -o "${SSL_CERTS_BASE_DIR}/${ES_NODE_NAME}.zip" -d "${SSL_CERTS_BASE_DIR}/${ES_NODE_NAME}_certs"
sudo cp "${SSL_CERTS_BASE_DIR}/${ES_NODE_NAME}_certs/${ES_NODE_NAME}.crt" "${ES_CERTS_DIR}/elasticsearch.crt"
sudo cp "${SSL_CERTS_BASE_DIR}/${ES_NODE_NAME}_certs/${ES_NODE_NAME}.key" "${ES_CERTS_DIR}/elasticsearch.key"
echo "ES_CERT_PATH=${ES_CERTS_DIR}/elasticsearch.crt" >> "${ELK_VARS_FILE}"
echo "ES_KEY_PATH=${ES_CERTS_DIR}/elasticsearch.key" >> "${ELK_VARS_FILE}"
echo -e "${GREEN}Elasticsearch node certificate and key generated and copied.${NC}"

# 3. Create P12 Keystores for Elasticsearch
progress_bar 2 "Creating P12 keystore for Elasticsearch HTTP..."
sudo openssl pkcs12 -export -out "${ES_CERTS_DIR}/http.p12" \
  -inkey "${ES_CERTS_DIR}/elasticsearch.key" \
  -in "${ES_CERTS_DIR}/elasticsearch.crt" \
  -certfile "${CA_CERT_PATH_VALUE}" \
  -name "${ES_NODE_NAME}" -passout pass:
echo "ES_HTTP_P12_PATH=${ES_CERTS_DIR}/http.p12" >> "${ELK_VARS_FILE}"

progress_bar 2 "Creating P12 keystore for Elasticsearch Transport..."
# For simplicity, using the same cert for transport. In production, you might have dedicated transport certs.
# Ensure ES_TRANSPORT_P12_PATH is appended
_ES_TRANSPORT_P12_PATH_VALUE="${ES_CERTS_DIR}/transport.p12"
sudo cp "${ES_CERTS_DIR}/http.p12" "${_ES_TRANSPORT_P12_PATH_VALUE}"
grep -qxF "ES_TRANSPORT_P12_PATH=${_ES_TRANSPORT_P12_PATH_VALUE}" "${ELK_VARS_FILE}" || echo "ES_TRANSPORT_P12_PATH=${_ES_TRANSPORT_P12_PATH_VALUE}" >> "${ELK_VARS_FILE}"
echo -e "${GREEN}P12 keystores for Elasticsearch created.${NC}"

# 4. Generate Kibana Certificate and Key (PEM format, to be used by Kibana setup script)
progress_bar 3 "Generating Kibana certificate and key..."
# CA_CERT_PATH should already be defined and in elk_vars.conf
_KIBANA_CERT_STAGING_PATH="${SSL_CERTS_BASE_DIR}/extracted_certs/kibana/kibana.crt"
_KIBANA_KEY_STAGING_PATH="${SSL_CERTS_BASE_DIR}/extracted_certs/kibana/kibana.key"

sudo /usr/share/elasticsearch/bin/elasticsearch-certutil cert --pem --ca-cert "${CA_CERT_PATH}" --ca-key "${SSL_CERTS_BASE_DIR}/ca/ca.key" --name "kibana" --dns "kibana,${KIBANA_HOST}" --ip "${KIBANA_HOST}" --out "${SSL_CERTS_BASE_DIR}/kibana.zip" --pass ""
sudo unzip -o "${SSL_CERTS_BASE_DIR}/kibana.zip" -d "${SSL_CERTS_BASE_DIR}/extracted_certs/kibana"

grep -qxF "KIBANA_CERT_STAGING_PATH=${_KIBANA_CERT_STAGING_PATH}" "${ELK_VARS_FILE}" || echo "KIBANA_CERT_STAGING_PATH=${_KIBANA_CERT_STAGING_PATH}" >> "${ELK_VARS_FILE}"
grep -qxF "KIBANA_KEY_STAGING_PATH=${_KIBANA_KEY_STAGING_PATH}" "${ELK_VARS_FILE}" || echo "KIBANA_KEY_STAGING_PATH=${_KIBANA_KEY_STAGING_PATH}" >> "${ELK_VARS_FILE}"
echo -e "${GREEN}Kibana certificate and key generated and staged.${NC}"

# 5. Generate Logstash Certificate and Key (PEM format, to be used by Logstash setup script)
progress_bar 3 "Generating Logstash certificate and key..."
_LOGSTASH_CERT_STAGING_PATH="${SSL_CERTS_BASE_DIR}/extracted_certs/logstash/logstash.crt"
_LOGSTASH_KEY_STAGING_PATH="${SSL_CERTS_BASE_DIR}/extracted_certs/logstash/logstash.key"

sudo /usr/share/elasticsearch/bin/elasticsearch-certutil cert --pem --ca-cert "${CA_CERT_PATH}" --ca-key "${SSL_CERTS_BASE_DIR}/ca/ca.key" --name "logstash" --dns "logstash,${LOGSTASH_HOST}" --ip "${LOGSTASH_HOST}" --out "${SSL_CERTS_BASE_DIR}/logstash.zip" --pass ""
sudo unzip -o "${SSL_CERTS_BASE_DIR}/logstash.zip" -d "${SSL_CERTS_BASE_DIR}/extracted_certs/logstash"

grep -qxF "LOGSTASH_CERT_STAGING_PATH=${_LOGSTASH_CERT_STAGING_PATH}" "${ELK_VARS_FILE}" || echo "LOGSTASH_CERT_STAGING_PATH=${_LOGSTASH_CERT_STAGING_PATH}" >> "${ELK_VARS_FILE}"
grep -qxF "LOGSTASH_KEY_STAGING_PATH=${_LOGSTASH_KEY_STAGING_PATH}" "${ELK_VARS_FILE}" || echo "LOGSTASH_KEY_STAGING_PATH=${_LOGSTASH_KEY_STAGING_PATH}" >> "${ELK_VARS_FILE}"
echo -e "${GREEN}Logstash certificate and key generated and staged.${NC}"

# Secure CA private key (remove or restrict access after use)
# CA_KEY_PATH_VALUE was a temporary script variable holding path to ${SSL_CERTS_BASE_DIR}/ca/ca.key
# This path is still valid if we need to refer to it directly for deletion.
if [ -f "${SSL_CERTS_BASE_DIR}/ca/ca.key" ]; then
    sudo rm -f "${SSL_CERTS_BASE_DIR}/ca/ca.key"
    echo -e "${YELLOW}CA private key removed from staging directory (${SSL_CERTS_BASE_DIR}/ca/ca.key) for security.${NC}"
else
    echo -e "${YELLOW}CA private key already removed or not found at ${SSL_CERTS_BASE_DIR}/ca/ca.key.${NC}"
fi


# 6. Set ownership and permissions
echo -e "${YELLOW}Setting ownership and permissions for Elasticsearch directories...${NC}"
sudo chown -R elasticsearch:elasticsearch "${ES_CONFIG_DIR}"
sudo chmod -R 750 "${ES_CONFIG_DIR}"
# Also ensure elasticsearch user can read from SSL_CERTS_BASE_DIR if certs are directly linked from there in future
# For now, all ES specific certs are copied to ES_CONFIG_DIR/certs
sudo chown -R elasticsearch:elasticsearch "${SSL_CERTS_BASE_DIR}" # For staging other certs
sudo chmod -R 750 "${SSL_CERTS_BASE_DIR}"
echo -e "${GREEN}Ownership and permissions set.${NC}"


# --- Service Management & Post-Start ---
echo -e "${YELLOW}Reloading systemd daemon and enabling Elasticsearch service...${NC}"
sudo systemctl daemon-reload
sudo systemctl enable elasticsearch.service
echo -e "${GREEN}Elasticsearch service enabled.${NC}"

echo -e "${YELLOW}Starting Elasticsearch service...${NC}"
sudo systemctl start elasticsearch.service
progress_bar 10 "Waiting for Elasticsearch to start (approx. 30-60 seconds)..."

# Wait for Elasticsearch to start
MAX_RETRIES=30
RETRY_COUNT=0
ES_UP=false
echo -e "${YELLOW}Attempting to connect to Elasticsearch at https://${ELASTICSEARCH_HOST}:9200 ${NC}"
while [ ${RETRY_COUNT} -lt ${MAX_RETRIES} ]; do
  # Use --cacert for proper validation once CA is in place and curl can access it
  # For now, -k is used for simplicity as ES might take time to fully initialize SSL context
  # Using SUPERUSER for this check is not ideal, but ES might not respond to unauth root endpoint if security is strict from start
  curl_output=$(curl -s -k --user "${SUPERUSER_USERNAME}:${SUPERUSER_PASSWORD}" "https://${ELASTICSEARCH_HOST}:9200/_cluster/health?pretty" --connect-timeout 5)
  if [[ $? -eq 0 ]] && [[ "${curl_output}" == *"cluster_name"* ]]; then
    echo -e "\n${GREEN}Elasticsearch is up and running!${NC}"
    echo "${curl_output}" # Print cluster health
    ES_UP=true
    break
  fi
  RETRY_COUNT=$((RETRY_COUNT + 1))
  echo -ne "${YELLOW}Attempt ${RETRY_COUNT}/${MAX_RETRIES}: Elasticsearch not ready yet, retrying in 5 seconds... \r${NC}"
  sleep 5
done

if [ "$ES_UP" = false ]; then
  echo -e "\n${RED}Elasticsearch did not start within the expected time. Please check logs: journalctl -u elasticsearch.service and /var/log/elasticsearch/${ES_NODE_NAME}.log ${NC}"
  exit 1
fi

echo -e "${YELLOW}Setting up Elasticsearch superuser...${NC}"
# The user is already created via bootstrap password, this step might not be needed if bootstrap password is the SU password
# However, elasticsearch-users can also set roles. Let's ensure the role.
# Note: In ES 8.x, initial superuser is often setup via bootstrap password or enrollment.
# This command might fail if user already exists from bootstrap.
# A better approach is to use the bootstrap password directly.
# For now, we assume the user provided SUPERUSER_USERNAME and SUPERUSER_PASSWORD are to be the primary ones.
# If security auto-configuration created a random password for 'elastic', this will create a new one or update.
echo "${SUPERUSER_PASSWORD}" | sudo /usr/share/elasticsearch/bin/elasticsearch-users useradd "${SUPERUSER_USERNAME}" -p - -r superuser
if [ $? -eq 0 ]; then
  echo -e "${GREEN}Superuser '${SUPERUSER_USERNAME}' configured.${NC}"
else
  echo -e "${YELLOW}Superuser '${SUPERUSER_USERNAME}' might already exist or an error occurred. Check output. (Error code: $?)${NC}"
  echo -e "${YELLOW}Attempting to set password for existing user '${SUPERUSER_USERNAME}'...${NC}"
  echo "${SUPERUSER_PASSWORD}" | sudo /usr/share/elasticsearch/bin/elasticsearch-users passwd "${SUPERUSER_USERNAME}" -p -
   if [ $? -eq 0 ]; then
      echo -e "${GREEN}Password for superuser '${SUPERUSER_USERNAME}' set/updated.${NC}"
   else
      echo -e "${RED}Failed to set password for '${SUPERUSER_USERNAME}'. Manual intervention may be required.${NC}"
   fi
fi


echo -e "${YELLOW}Resetting password for kibana_system user...${NC}"
KIBANA_SYSTEM_PASSWORD_VALUE=$(sudo /usr/share/elasticsearch/bin/elasticsearch-reset-password -u kibana_system -s -b)
if [ $? -eq 0 ] && [ -n "${KIBANA_SYSTEM_PASSWORD_VALUE}" ]; then
  grep -qxF "KIBANA_SYSTEM_PASSWORD=${KIBANA_SYSTEM_PASSWORD_VALUE}" "${ELK_VARS_FILE}" || echo "KIBANA_SYSTEM_PASSWORD=${KIBANA_SYSTEM_PASSWORD_VALUE}" >> "${ELK_VARS_FILE}"
  echo -e "${GREEN}kibana_system user password reset and saved to ${ELK_VARS_FILE}.${NC}"
else
  echo -e "${YELLOW}Failed to reset kibana_system user password (it might not exist yet). Attempting to create.${NC}"
  _KIBANA_SYSTEM_PASSWORD_NEW=$(openssl rand -hex 16) # Generate a random password
  echo "${_KIBANA_SYSTEM_PASSWORD_NEW}" | sudo /usr/share/elasticsearch/bin/elasticsearch-users useradd kibana_system -p - -r kibana_system &> /dev/null
  if [ $? -eq 0 ]; then
      KIBANA_SYSTEM_PASSWORD_VALUE=${_KIBANA_SYSTEM_PASSWORD_NEW}
      grep -qxF "KIBANA_SYSTEM_PASSWORD=${KIBANA_SYSTEM_PASSWORD_VALUE}" "${ELK_VARS_FILE}" || echo "KIBANA_SYSTEM_PASSWORD=${KIBANA_SYSTEM_PASSWORD_VALUE}" >> "${ELK_VARS_FILE}"
      echo -e "${GREEN}kibana_system user created with a new password and saved to ${ELK_VARS_FILE}.${NC}"
  else
      # If useradd failed, maybe it exists but reset failed. Try setting password for existing user.
      echo "${_KIBANA_SYSTEM_PASSWORD_NEW}" | sudo /usr/share/elasticsearch/bin/elasticsearch-users passwd kibana_system -p - &> /dev/null
      if [ $? -eq 0 ]; then
        KIBANA_SYSTEM_PASSWORD_VALUE=${_KIBANA_SYSTEM_PASSWORD_NEW}
        grep -qxF "KIBANA_SYSTEM_PASSWORD=${KIBANA_SYSTEM_PASSWORD_VALUE}" "${ELK_VARS_FILE}" || echo "KIBANA_SYSTEM_PASSWORD=${KIBANA_SYSTEM_PASSWORD_VALUE}" >> "${ELK_VARS_FILE}"
        echo -e "${GREEN}Password for existing kibana_system user set and saved to ${ELK_VARS_FILE}.${NC}"
      else
        echo -e "${RED}Failed to create or set password for kibana_system user. Manual intervention required.${NC}"
      fi
  fi
fi


echo -e "${YELLOW}Resetting password for logstash_system user...${NC}"
LOGSTASH_SYSTEM_PASSWORD_VALUE=$(sudo /usr/share/elasticsearch/bin/elasticsearch-reset-password -u logstash_system -s -b)
if [ $? -eq 0 ] && [ -n "${LOGSTASH_SYSTEM_PASSWORD_VALUE}" ]; then
  grep -qxF "LOGSTASH_SYSTEM_PASSWORD=${LOGSTASH_SYSTEM_PASSWORD_VALUE}" "${ELK_VARS_FILE}" || echo "LOGSTASH_SYSTEM_PASSWORD=${LOGSTASH_SYSTEM_PASSWORD_VALUE}" >> "${ELK_VARS_FILE}"
  echo -e "${GREEN}logstash_system user password reset and saved to ${ELK_VARS_FILE}.${NC}"
else
  echo -e "${YELLOW}Failed to reset logstash_system user password (it might not exist yet). Attempting to create.${NC}"
  _LOGSTASH_SYSTEM_PASSWORD_NEW=$(openssl rand -hex 16) # Generate a random password
  echo "${_LOGSTASH_SYSTEM_PASSWORD_NEW}" | sudo /usr/share/elasticsearch/bin/elasticsearch-users useradd logstash_system -p - -r logstash_system &> /dev/null
  if [ $? -eq 0 ]; then
      LOGSTASH_SYSTEM_PASSWORD_VALUE=${_LOGSTASH_SYSTEM_PASSWORD_NEW}
      grep -qxF "LOGSTASH_SYSTEM_PASSWORD=${LOGSTASH_SYSTEM_PASSWORD_VALUE}" "${ELK_VARS_FILE}" || echo "LOGSTASH_SYSTEM_PASSWORD=${LOGSTASH_SYSTEM_PASSWORD_VALUE}" >> "${ELK_VARS_FILE}"
      echo -e "${GREEN}logstash_system user created with a new password and saved to ${ELK_VARS_FILE}.${NC}"
  else
      # If useradd failed, maybe it exists but reset failed. Try setting password for existing user.
      echo "${_LOGSTASH_SYSTEM_PASSWORD_NEW}" | sudo /usr/share/elasticsearch/bin/elasticsearch-users passwd logstash_system -p - &> /dev/null
      if [ $? -eq 0 ]; then
        LOGSTASH_SYSTEM_PASSWORD_VALUE=${_LOGSTASH_SYSTEM_PASSWORD_NEW}
        grep -qxF "LOGSTASH_SYSTEM_PASSWORD=${LOGSTASH_SYSTEM_PASSWORD_VALUE}" "${ELK_VARS_FILE}" || echo "LOGSTASH_SYSTEM_PASSWORD=${LOGSTASH_SYSTEM_PASSWORD_VALUE}" >> "${ELK_VARS_FILE}"
        echo -e "${GREEN}Password for existing logstash_system user set and saved to ${ELK_VARS_FILE}.${NC}"
      else
        echo -e "${RED}Failed to create or set password for logstash_system user. Manual intervention required.${NC}"
      fi
  fi
fi


# --- Cluster Enrollment Tokens (if DEPLOYMENT_TYPE == "cluster") ---
if [[ "${DEPLOYMENT_TYPE,,}" == "cluster" ]] && [[ -n "${ES_NODE_COUNT}" ]] && [[ "${ES_NODE_COUNT}" -gt 1 ]]; then
  echo -e "${YELLOW}Generating enrollment tokens for other Elasticsearch nodes...${NC}"
  ENROLLMENT_TOKENS_FILE="enrollment_tokens.txt"
  > "${ENROLLMENT_TOKENS_FILE}"
  # Start from node 2 up to ES_NODE_COUNT. Node 1 is this current node.
  for i in $(seq 2 "${ES_NODE_COUNT}"); do
    echo -e "${YELLOW}Generating token for Node ${i}...${NC}"
    TOKEN=$(sudo /usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s node)
    if [ $? -eq 0 ] && [ -n "${TOKEN}" ]; then
      echo "Token for Node ${i}: ${TOKEN}" | sudo tee -a "${ENROLLMENT_TOKENS_FILE}" # Use sudo if user doesn't own current dir
      grep -qxF "ENROLLMENT_TOKEN_NODE_${i}=${TOKEN}" "${ELK_VARS_FILE}" || echo "ENROLLMENT_TOKEN_NODE_${i}=${TOKEN}" >> "${ELK_VARS_FILE}"
      echo -e "${GREEN}Token for Node ${i} generated and saved.${NC}"
    else
      echo -e "${RED}Failed to generate enrollment token for Node ${i}.${NC}"
    fi
  done
  echo -e "${CYAN}Enrollment tokens for other nodes saved in ${ENROLLMENT_TOKENS_FILE} and ${ELK_VARS_FILE}.${NC}"
fi

# --- Generate Logstash Output API Key ---
echo -e "${YELLOW}Creating API key for Logstash output...${NC}"
# Using SUPERUSER_USERNAME and SUPERUSER_PASSWORD from elk_vars.conf (already sourced and checked)
# CA_CERT_PATH should also be available from earlier SSL generation steps
LOGSTASH_API_KEY_ROLE_DESCRIPTOR='{ "logstash_writer_role": { "cluster": ["manage_index_templates", "monitor", "manage_ilm"], "indices": [{ "names": ["logstash-*", "logs-*", "metrics-*", "traces-*", "synthetics-*"], "privileges": ["write", "create_index", "manage", "manage_ilm", "auto_configure"] }] } }'

# Create API key using curl
API_KEY_RESPONSE=$(curl --cacert "${CA_CERT_PATH}" -s -u "${SUPERUSER_USERNAME}:${SUPERUSER_PASSWORD}" -XPOST "https://${ELASTICSEARCH_HOST}:9200/_security/api_key" -H "Content-Type: application/json" -d"{\"name\":\"logstash_pipeline_writer_${ES_NODE_NAME}\",\"role_descriptors\": ${LOGSTASH_API_KEY_ROLE_DESCRIPTOR}}")

API_KEY_ID=$(echo "${API_KEY_RESPONSE}" | grep -o '"id":"[^"]*"' | cut -d'"' -f4)
API_KEY_SECRET=$(echo "${API_KEY_RESPONSE}" | grep -o '"api_key":"[^"]*"' | cut -d'"' -f4)

if [ -n "${API_KEY_ID}" ] && [ -n "${API_KEY_SECRET}" ]; then
  LOGSTASH_OUTPUT_API_KEY_ENCODED_VALUE=$(echo -n "${API_KEY_ID}:${API_KEY_SECRET}" | base64)
  grep -qxF "LOGSTASH_OUTPUT_API_KEY_ENCODED=${LOGSTASH_OUTPUT_API_KEY_ENCODED_VALUE}" "${ELK_VARS_FILE}" || echo "LOGSTASH_OUTPUT_API_KEY_ENCODED=${LOGSTASH_OUTPUT_API_KEY_ENCODED_VALUE}" >> "${ELK_VARS_FILE}"
  echo -e "${GREEN}Logstash output API key created and saved to ${ELK_VARS_FILE}.${NC}"
else
  echo -e "${RED}Failed to create Logstash output API key. Response: ${API_KEY_RESPONSE}${NC}"
  echo -e "${YELLOW}Logstash may not be able to send data to Elasticsearch without this key. Manual creation might be needed.${NC}"
  # Decide if this is a fatal error. For now, continue but warn.
    fi
  done
  echo -e "${CYAN}Enrollment tokens for other nodes saved in ${ENROLLMENT_TOKENS_FILE} and ${ELK_VARS_FILE}.${NC}"
fi

# --- Final Output ---
echo -e "\n${CYAN}====================================================="
echo -e " Elasticsearch First Node Installation Complete!"
echo -e "=====================================================${NC}"
echo -e "${GREEN}Elasticsearch URL: https://${ELASTICSEARCH_HOST}:9200${NC}"
echo -e "${GREEN}Superuser Username: ${SUPERUSER_USERNAME}${NC}"
echo -e "${GREEN}Superuser Password: (saved in ${ELK_VARS_FILE} - keep this secure)${NC}"
echo -e "${GREEN}CA Certificate Path: ${ES_CERTS_DIR}/ca.crt${NC}"
echo -e "${YELLOW}Configuration details and credentials saved in: ${ELK_VARS_FILE}${NC}"
if [[ "${DEPLOYMENT_TYPE,,}" == "cluster" ]] && [[ -n "${ES_NODE_COUNT}" ]] && [[ "${ES_NODE_COUNT}" -gt 1 ]]; then
  echo -e "${YELLOW}Enrollment tokens for other nodes saved in: enrollment_tokens.txt and ${ELK_VARS_FILE}${NC}"
fi
  echo -e "${CYAN}Please ensure to secure ${ELK_VARS_FILE}. The CA private key used for cert generation was temporarily stored in ${SSL_CERTS_BASE_DIR}/ca/ca.key and should have been removed.${NC}"
  echo -e "${CYAN}You may need to distribute the CA certificate (${CA_CERT_PATH}) to clients that need to connect to Elasticsearch.${NC}"

exit 0
