#!/bin/bash
set -e # Exit immediately if a command exits with a non-zero status.

# Ensure common_functions.sh is available and executable
if [ -f ./common_functions.sh ]; then
  source ./common_functions.sh
  chmod +x ./common_functions.sh # Ensure it's executable
else
  echo "ERROR: common_functions.sh not found. Please ensure it's in the same directory."
  exit 1
fi

echo -e "${CYAN}===============================================${NC}"
echo -e "${CYAN} ELK Stack Orchestrated Deployment Script ${NC}"
echo -e "${CYAN}===============================================${NC}"

# Initialize or clear elk_vars.conf
ELK_VARS_FILE="elk_vars.conf"
echo -e "${YELLOW}Initializing configuration file: ${ELK_VARS_FILE}...${NC}"
truncate -s 0 "${ELK_VARS_FILE}"
echo -e "${GREEN}${ELK_VARS_FILE} created/cleared.${NC}"

# --- 1. Gather Common Configuration & Prerequisites ---
echo -e "\n${CYAN}--- Gathering Common Configuration ---${NC}"
# Call install_prerequisites early
echo -e "${YELLOW}Ensuring prerequisite packages are installed...${NC}"
install_prerequisites # from common_functions.sh

# Deployment Type
read -p "Is this a 'single' ELK node deployment or the 'first' node of a 'cluster'? (single/cluster): " DEPLOYMENT_TYPE_INPUT
DEPLOYMENT_TYPE=$(echo "${DEPLOYMENT_TYPE_INPUT}" | tr '[:upper:]' '[:lower:]') # Convert to lowercase
if [[ "${DEPLOYMENT_TYPE}" != "single" && "${DEPLOYMENT_TYPE}" != "cluster" ]]; then
  echo -e "${RED}Invalid deployment type. Please enter 'single' or 'cluster'. Exiting.${NC}"
  exit 1
fi
echo "DEPLOYMENT_TYPE=${DEPLOYMENT_TYPE}" >> "${ELK_VARS_FILE}"

# Elastic Version
read -p "Enter the Elastic Stack version to install (e.g., 8.11.4): " ELASTIC_VERSION
if [ -z "${ELASTIC_VERSION}" ]; then
  echo -e "${RED}Elastic version cannot be empty. Exiting.${NC}"
  exit 1
fi
echo "ELASTIC_VERSION=${ELASTIC_VERSION}" >> "${ELK_VARS_FILE}"

# IP Addresses
while true; do
  read -p "Enter the Primary IP address for this ELK node (this machine's main IP): " PRIMARY_NODE_IP
  if validate_ip "${PRIMARY_NODE_IP}"; then
    echo "PRIMARY_NODE_IP=${PRIMARY_NODE_IP}" >> "${ELK_VARS_FILE}"
    echo "ELASTICSEARCH_HOST=${PRIMARY_NODE_IP}" >> "${ELK_VARS_FILE}" # Elasticsearch will run on this primary IP
    break
  else
    echo -e "${RED}Invalid IP address format. Please try again.${NC}"
  fi
done

if [ "${DEPLOYMENT_TYPE}" == "single" ]; then
  echo "KIBANA_HOST=${PRIMARY_NODE_IP}" >> "${ELK_VARS_FILE}"
  echo "LOGSTASH_HOST=${PRIMARY_NODE_IP}" >> "${ELK_VARS_FILE}"
  echo -e "${INFO}Kibana and Logstash will use IP: ${PRIMARY_NODE_IP}${NC}"
else # cluster deployment
  read -p "Will Kibana be on the same IP as Elasticsearch (${PRIMARY_NODE_IP})? (y/n): " KIBANA_SAME_IP
  if [[ "${KIBANA_SAME_IP,,}" == "y" ]]; then
    echo "KIBANA_HOST=${PRIMARY_NODE_IP}" >> "${ELK_VARS_FILE}"
    echo -e "${INFO}Kibana will use IP: ${PRIMARY_NODE_IP}${NC}"
  else
    while true; do
      read -p "Enter the IP address for Kibana: " KIBANA_HOST_IP
      if validate_ip "${KIBANA_HOST_IP}"; then
        echo "KIBANA_HOST=${KIBANA_HOST_IP}" >> "${ELK_VARS_FILE}"
        echo -e "${INFO}Kibana will use IP: ${KIBANA_HOST_IP}${NC}"
        break
      else
        echo -e "${RED}Invalid Kibana IP address format. Please try again.${NC}"
      fi
    done
  fi

  read -p "Will Logstash be on the same IP as Elasticsearch (${PRIMARY_NODE_IP})? (y/n): " LOGSTASH_SAME_IP
  if [[ "${LOGSTASH_SAME_IP,,}" == "y" ]]; then
    echo "LOGSTASH_HOST=${PRIMARY_NODE_IP}" >> "${ELK_VARS_FILE}"
    echo -e "${INFO}Logstash will use IP: ${PRIMARY_NODE_IP}${NC}"
  else
    while true; do
      read -p "Enter the IP address for Logstash: " LOGSTASH_HOST_IP
      if validate_ip "${LOGSTASH_HOST_IP}"; then
        echo "LOGSTASH_HOST=${LOGSTASH_HOST_IP}" >> "${ELK_VARS_FILE}"
        echo -e "${INFO}Logstash will use IP: ${LOGSTASH_HOST_IP}${NC}"
        break
      else
        echo -e "${RED}Invalid Logstash IP address format. Please try again.${NC}"
      fi
    done
  fi
fi

# Node Name for first Elasticsearch node
read -p "Enter the name for the first Elasticsearch node (e.g., elk-node-1): " ES_NODE_NAME
if [ -z "${ES_NODE_NAME}" ]; then
  echo -e "${RED}Elasticsearch node name cannot be empty. Exiting.${NC}"
  exit 1
fi
echo "ES_NODE_NAME=${ES_NODE_NAME}" >> "${ELK_VARS_FILE}"

# Superuser Credentials
read -p "Enter a username for the Elasticsearch superuser (e.g., elasticadmin): " SUPERUSER_USERNAME
if [ -z "${SUPERUSER_USERNAME}" ]; then
  echo -e "${RED}Superuser username cannot be empty. Exiting.${NC}"
  exit 1
fi
echo "SUPERUSER_USERNAME=${SUPERUSER_USERNAME}" >> "${ELK_VARS_FILE}"

while true; do
  read -s -p "Enter a password for the superuser (min 6 characters for some tools): " SUPERUSER_PASSWORD
  echo
  read -s -p "Confirm superuser password: " SUPERUSER_PASSWORD_CONFIRM
  echo
  if [[ "${SUPERUSER_PASSWORD}" == "${SUPERUSER_PASSWORD_CONFIRM}" ]]; then
    if [ ${#SUPERUSER_PASSWORD} -lt 6 ]; then
        echo -e "${YELLOW}Warning: Password is less than 6 characters. Some tools might require a longer password.${NC}"
    fi
    echo "SUPERUSER_PASSWORD=${SUPERUSER_PASSWORD}" >> "${ELK_VARS_FILE}" # Note: Storing plain password.
    break
  else
    echo -e "${RED}Passwords do not match. Please try again.${NC}"
  fi
done


# Cluster Settings (if applicable)
if [ "${DEPLOYMENT_TYPE}" == "cluster" ]; then
  while true; do
    read -p "How many TOTAL Elasticsearch nodes will be in this cluster (including this first one, min 1)?: " ES_NODE_COUNT
    if [[ "${ES_NODE_COUNT}" =~ ^[0-9]+$ ]] && [ "${ES_NODE_COUNT}" -ge 1 ]; then
      echo "ES_NODE_COUNT=${ES_NODE_COUNT}" >> "${ELK_VARS_FILE}"
      break
    else
      echo -e "${RED}Please enter a valid number (1 or more).${NC}"
    fi
  done
else
  echo "ES_NODE_COUNT=1" >> "${ELK_VARS_FILE}" # Single node deployment
fi

# Default Paths (Component scripts can define these too; this provides defaults)
# These are appended so component scripts can check if they exist and use them.
# If component scripts are run standalone, they'd prompt or use their own defaults.
echo "SSL_CERTS_BASE_DIR=/opt/elk_stack/generated_certs" >> "${ELK_VARS_FILE}"
echo "ES_CONFIG_DIR=/etc/elasticsearch" >> "${ELK_VARS_FILE}"
echo "ES_CERTS_DIR=/etc/elasticsearch/certs" >> "${ELK_VARS_FILE}"
echo "KIBANA_CONFIG_DIR=/etc/kibana" >> "${ELK_VARS_FILE}"
echo "KIBANA_CERTS_DIR=/etc/kibana/certs" >> "${ELK_VARS_FILE}"
echo "LOGSTASH_CONFIG_DIR=/etc/logstash" >> "${ELK_VARS_FILE}"
echo "LOGSTASH_CERTS_DIR=/etc/logstash/certs" >> "${ELK_VARS_FILE}"
echo "LOGSTASH_PIPELINE_DIR=/etc/logstash/conf.d" >> "${ELK_VARS_FILE}"
echo "ES_BIN_PATH=/usr/share/elasticsearch/bin" >> "${ELK_VARS_FILE}" # Default ES binary path

echo -e "${GREEN}Initial configuration saved to ${ELK_VARS_FILE}.${NC}"

# --- 2. Ensure Component Scripts are Executable ---
echo -e "\n${YELLOW}Ensuring component scripts are executable...${NC}"
scripts_to_make_executable=(
    "install_elasticsearch.sh"
    "install_kibana.sh"
    "install_logstash.sh"
    "setup_fleet_server.sh"
    "deploy_elasticsearch_node.sh"
)
for script_name in "${scripts_to_make_executable[@]}"; do
    if [ -f "./${script_name}" ]; then
        chmod +x "./${script_name}"
        echo -e "${GREEN}Made ./${script_name} executable.${NC}"
    else
        echo -e "${YELLOW}Warning: Script ./${script_name} not found. Skipping chmod.${NC}"
    fi
done

# --- 3. Execute Component Scripts ---
# Note: Each component script should source elk_vars.conf and use existing values if set.
# They should also append any new generated values to elk_vars.conf.

echo -e "\n${CYAN}--- Starting Elasticsearch Installation (First Node) ---${NC}"
if bash ./install_elasticsearch.sh; then
  echo -e "${GREEN}Elasticsearch installation script completed successfully.${NC}"
else
  echo -e "${RED}Elasticsearch installation script failed. Aborting deployment.${NC}"
  exit 1
fi
# Re-source elk_vars.conf as ES script might have added to it (passwords, API keys, cert paths etc.)
source ./"${ELK_VARS_FILE}"

echo -e "\n${CYAN}--- Starting Kibana Installation ---${NC}"
if bash ./install_kibana.sh; then
  echo -e "${GREEN}Kibana installation script completed successfully.${NC}"
else
  echo -e "${RED}Kibana installation script failed. Aborting deployment.${NC}"
  exit 1 # Decide if to exit or continue if Kibana fails. For now, exit.
fi
source ./"${ELK_VARS_FILE}" # Kibana script might add to it (e.g. specific cert paths)

echo -e "\n${CYAN}--- Starting Logstash Installation ---${NC}"
if bash ./install_logstash.sh; then
  echo -e "${GREEN}Logstash installation script completed successfully.${NC}"
else
  echo -e "${RED}Logstash installation script failed. Aborting deployment.${NC}"
  exit 1
fi
source ./"${ELK_VARS_FILE}" # Logstash script might add to it

# Fleet Server setup is often optional or might be on a different node.
read -p "Do you want to set up Fleet Server on this node? (y/n): " SETUP_FLEET_SERVER
if [[ "${SETUP_FLEET_SERVER,,}" == "y" ]]; then
  echo -e "\n${CYAN}--- Starting Fleet Server Setup ---${NC}"
  if bash ./setup_fleet_server.sh; then
    echo -e "${GREEN}Fleet Server setup script completed successfully.${NC}"
  else
    echo -e "${YELLOW}Fleet Server setup script failed. Continuing deployment as Fleet is often optional.${NC}"
    # Don't necessarily exit here as Fleet is often additional.
  fi
else
  echo -e "${INFO}Skipping Fleet Server setup on this node.${NC}"
fi

# --- 4. Final Output ---
echo -e "\n${CYAN}=====================================================${NC}"
echo -e "${CYAN} ELK Stack Orchestrated Deployment Finished! ${NC}"
echo -e "${CYAN}=====================================================${NC}"
echo -e "${GREEN}Review the output from each script for specific details and access URLs.${NC}"
echo -e "Kibana should be accessible at: https://${KIBANA_HOST}:5601 (username: ${SUPERUSER_USERNAME})"
if [ "${DEPLOYMENT_TYPE}" == "cluster" ] && [ "${ES_NODE_COUNT}" -gt 1 ]; then
  echo -e "${YELLOW}This is the first node of a ${ES_NODE_COUNT}-node Elasticsearch cluster.${NC}"
  echo -e "Enrollment tokens for additional Elasticsearch nodes should be in 'enrollment_tokens.txt' (created by install_elasticsearch.sh)."
  echo -e "Use './deploy_elasticsearch_node.sh' on other machines to add them to the cluster."
fi
echo -e "${YELLOW}Remember to check system logs of each component if you encounter any issues.${NC}"
echo -e "Important variables, generated keys, and passwords are in '${ELK_VARS_FILE}'."
echo -e "${RED}IMPORTANT: Secure the '${ELK_VARS_FILE}' file as it contains sensitive information.${NC}"

exit 0
