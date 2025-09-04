#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/functions.sh"
init_colors

echo -e "${GREEN}"
cat << 'EOF'
  ______ _           _   _                              _       _   _           _      
 |  ____| |         | | (_)                            | |     | \ | |         | |     
 | |__  | | __ _ ___| |_ _  ___ ___  ___  __ _ _ __ ___| |__   |  \| | ___   __| | ___ 
 |  __| | |/ _` / __| __| |/ __/ __|/ _ \/ _` | '__/ __| '_ \  | . ` |/ _ \ / _` |/ _ \
 | |____| | (_| \__ \ |_| | (__\__ \  __/ (_| | | | (__| | | | | |\  | (_) | (_| |  __/
 |______|_|\__,_|___/\__|_|\___|___/\___|\__,_|_|  \___|_| |_| |_| \_|\___/ \__,_|\___|

EOF
echo -e "${NC}"

echo -e "${GREEN}This portion of the script is intended to deploy an Elasticsearch node which will be joined to your cluster.${NC}"
read -r -p "$(echo -e "${GREEN}Do you want to continue? (yes/no): ${NC}")" CONFIRM

# Exit unless the user explicitly answers y/yes (case-insensitive)
if [[ "${CONFIRM,,}" != "y" && "${CONFIRM,,}" != "yes" ]]; then
  echo -e "${GREEN}Exiting script. No changes made.${NC}"
  exit 0
fi

unit_loaded() { [[ "$(systemctl show -p LoadState --value "${1}.service" 2>/dev/null)" == "loaded" ]]; }
kill_unit_procs() {
  local svc="$1"
  sudo systemctl kill -s TERM "$svc" 2>/dev/null || true
  sleep 1
  sudo systemctl kill -s KILL "$svc" 2>/dev/null || true
}

# --- Prompt for ELK install history ---
echo -e "\n${GREEN}Has Elasticsearch, Logstash, or Kibana ever been installed on this machine before?${NC}"
prompt_input "$(echo -e "${GREEN}Type \"${YELLOW}yes${GREEN}\" if there is a previous installation on this machine, or \"${YELLOW}no${GREEN}\" to continue with a fresh install:${NC} ")" INSTALL_RESPONSE

# --- User Input Processing ---
if [[ "$INSTALL_RESPONSE" =~ ^[Yy][Ee]?[Ss]?$ ]]; then
    PREVIOUS_INSTALL=true
    FRESH_INSTALL=false
    perform_elk_cleanup

elif [[ "$INSTALL_RESPONSE" =~ ^[Nn][Oo]$ ]]; then
  echo -e "${YELLOW}User reported this is a clean install. Verifying for any remnants...${NC}"

  # robust detection (handles inactive/disabled/leftovers)
  unit_exists() { systemctl cat "${1}.service" >/dev/null 2>&1; }  # unit file present
  pkg_installed() {
    local s; s="$(dpkg-query -W -f='${Status}' "$1" 2>/dev/null || true)"
    [[ "$s" == *"install ok installed"* ]]
  }
  artifacts_present() {
    local n="$1"
    [[ -e "/etc/$n" || -e "/var/lib/$n" || -e "/var/log/$n" || -e "/usr/share/$n" ]]
  }

  SERVICES_FOUND=false
  FOUND_SERVICES=()
  for svc in elasticsearch logstash kibana; do
    if systemctl is-active --quiet "$svc" \
       || unit_exists "$svc" \
       || systemctl list-unit-files --type=service --no-legend 2>/dev/null | grep -q "^${svc}\.service" \
       || pkg_installed "$svc" \
       || artifacts_present "$svc"
    then
      echo -e "${RED}Detected ${svc} remnants (running/unit/package/files).${NC}"
      FOUND_SERVICES+=("$svc")
      SERVICES_FOUND=true
    fi
  done

  if $SERVICES_FOUND; then
    echo -e "${YELLOW}⚠️  Found ELK components present: ${CYAN}${FOUND_SERVICES[*]}${NC}"
    echo -e "${YELLOW}Proceeding with cleanup of old services and files...${NC}"
    PREVIOUS_INSTALL=true
    FRESH_INSTALL=false
    perform_elk_cleanup           # <- SSH-safe cleanup function below
  else
    echo -e "${GREEN}System appears clean. Proceeding with fresh install...${NC}"
    PREVIOUS_INSTALL=false
    FRESH_INSTALL=true
  fi

else
  echo -e "${RED}Invalid response. Please enter \"yes\" or \"no\".${NC}"
  exit 1
fi

# === Common IP Prompt and Assignment ===
echo -e "\n${GREEN}Elasticsearch will be hosted using the IP you enter below.${NC}"

echo -e "${GREEN}--- Network Interfaces ---${NC}"
ip -br a | awk '{print $1, $2, $3}' | while read iface state addr; do
    echo -e "${CYAN}$iface${NC} - $state - IP: ${YELLOW}$addr${NC}"
done

# Identify default management interface and IP
MGMT_IFACE=$(ip -br a | awk '$1 != "lo" && $3 ~ /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/ {print $1; exit}')
MGMT_IP=$(ip -4 -o addr show dev "$MGMT_IFACE" | awk '{print $4}' | cut -d/ -f1)

echo -e "${GREEN}Use the following IP for accessing this node (management interface):${NC}"
echo -e "${CYAN}$MGMT_IFACE${NC} - ${YELLOW}$MGMT_IP${NC}"

# Prompt for IP and validate until correct
while true; do
    read -p "$(echo -e "${YELLOW}Enter the IP address to use for Elasticsearch: ${NC}")" COMMON_IP
    if validate_ip "$COMMON_IP"; then
        echo -e "${GREEN}✔ Accepted IP: $COMMON_IP${NC}"
        break
    else
        echo -e "${RED}❌ Invalid IP format. Please enter a valid IPv4 address.${NC}"
    fi
done

echo -e "${GREEN}✔ This Elasticsearch node will be set up at IP: $ELASTIC_HOST${NC}"

# Add to summary table
add_to_summary_table "Management IP" "$COMMON_IP"

# Ask if this is an airgapped environment
echo -e "\n${YELLOW}Is this machine in an airgapped (offline) environment?${NC}"
prompt_input "Type \"yes\" to skip internet check, or \"no\" to verify connectivity: " IS_AIRGAPPED

if [[ "$IS_AIRGAPPED" =~ ^[Yy][Ee]?[Ss]?$ ]]; then
	echo -e "${YELLOW}Airgapped mode confirmed. Skipping internet connectivity check.${NC}"
else
	# --- Check internet connectivity ---
	echo -e "\n${GREEN}Checking internet connectivity...${NC}"
	PING_TARGET="google.com"
	PING_COUNT=2

	if ping -c "$PING_COUNT" "$PING_TARGET" > /dev/null 2>&1; then
		echo -e "${GREEN}Internet connectivity confirmed via ping to ${YELLOW}$PING_TARGET.${NC}"
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

# Normalize the input
IS_AIRGAPPED="$(echo "$IS_AIRGAPPED" | tr '[:upper:]' '[:lower:]' | xargs)"

# Validate and add to summary table
if [[ "$IS_AIRGAPPED" == "yes" ]]; then
  echo -e "${GREEN}✔ Airgap check skipped.${NC}"
  add_to_summary_table "Airgapped Environment" "Yes"
elif [[ "$IS_AIRGAPPED" == "no" ]]; then
  echo -e "${GREEN}✔ Internet connectivity will be verified.${NC}"
  add_to_summary_table "Airgapped Environment" "No"
else
  echo -e "${RED}❌ Invalid input. Please type 'yes' or 'no'.${NC}"
  exit 1
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

    # Always show final disk usage
    echo -e "\n${GREEN}Final root volume size and usage:${NC}"
    df -h /

else
    echo -e "\n${YELLOW}Non-Ubuntu system detected. If you are using LVM, you may need to manually extend your logical volume after installation.${NC}"
fi

# Set var for disk usage
ROOT_FS_USAGE=$(df -h / | awk '/\/$/ {printf "Size: %s Used: %s Avail: %s Use%%: %s",$2,$3,$4,$5}')
# Add to summary table
add_to_summary_table "Root Disk Usage" "$ROOT_FS_USAGE"

# Prompt in a loop until valid node name is entered
while true; do
	read -p "$(echo -e "${GREEN}Enter the name you would like to assign your node (e.g., ${YELLOW}node-1${GREEN}): ${NC}")" NODE_NAME
	if validate_nodename "$NODE_NAME"; then
		echo -e "${GREEN}✔ Node name '${YELLOW}${NODE_NAME}${GREEN}' is valid and has been accepted.${NC}"
		break
	fi
done

# Prompt in a loop until valid version is entered
while true; do
    read -p "$(echo -e "${GREEN}Enter the Elastic Stack version to install ${YELLOW}(e.g., 8.18.2 or 9.0.2)${GREEN}: ${NC}")" ELASTIC_VERSION
    if validate_version "$ELASTIC_VERSION"; then
        echo -e "${GREEN}✔ Version '${ELASTIC_VERSION}' is valid and has been accepted.${NC}"
        add_to_summary_table "Elastic Stack Version" "$ELASTIC_VERSION"
        break
    else
        echo -e "${RED}❌ Invalid version format. Please enter something like 8.18.2.${NC}"
    fi
done

# -----------------------------
# Elasticsearch installation (deb vs internet)
# -----------------------------
install_elasticsearch_selected_method() {
  : "${INSTALL_FROM_DEB:=}"                 # "1" for local .deb, "0" for internet
  : "${ES_DEB_LOCAL:=}"                     # path to local .deb when INSTALL_FROM_DEB=1
  : "${ES_DEB_VERSION:=}"                   # may be passed from runner
  : "${ES_VERSION:=}"                       # may be passed from runner
  : "${ELASTIC_VERSION:=}"                  # you already prompted this earlier

  # Prefer the most specific version hint we have
  local TARGET_VERSION="${ES_DEB_VERSION:-${ELASTIC_VERSION:-${ES_VERSION:-}}}"
  if [[ -z "$TARGET_VERSION" ]]; then
    echo -e "${RED}No target version provided (ES_DEB_VERSION / ELASTIC_VERSION / ES_VERSION).${NC}"
    exit 1
  fi

  # Helper for optional spinner
  _spin() { if type -t spinner >/dev/null 2>&1; then sleep "${2:-2}" & spinner "${1:-}"; fi; }

  if [[ "$INSTALL_FROM_DEB" == "1" ]]; then
    # ----------------------------
    # Local .deb path (air-gapped)
    # ----------------------------
    echo -e "${GREEN}Installing Elasticsearch from local deb: ${CYAN}${ES_DEB_LOCAL}${NC}"
    if [[ -z "$ES_DEB_LOCAL" || ! -f "$ES_DEB_LOCAL" ]]; then
      echo -e "${RED}ES_DEB_LOCAL is not a file: ${ES_DEB_LOCAL:-<empty>}${NC}"
      exit 1
    fi

    # Install prerequisites for dpkg fixups
    sudo apt-get update -y >/dev/null 2>&1 || true
    sudo apt-get install -y apt-transport-https ca-certificates gnupg curl >/dev/null 2>&1 || true

    # Install the .deb and fix deps if needed
    if ! sudo dpkg -i "$ES_DEB_LOCAL" >/dev/null 2>&1; then
      echo -e "${YELLOW}Resolving dependencies via apt-get -f install...${NC}"
      sudo apt-get -f install -y >/dev/null 2>&1 || {
        echo -e "${RED}Failed to resolve dependencies for ${ES_DEB_LOCAL}.${NC}"
        exit 1
      }
    fi

    # Verify version
    local INSTALLED_VER
    INSTALLED_VER="$(dpkg-query -W -f='${Version}\n' elasticsearch 2>/dev/null || true)"
    if [[ -z "$INSTALLED_VER" ]]; then
      echo -e "${RED}Elasticsearch not installed after dpkg run.${NC}"
      exit 1
    fi
    echo -e "${GREEN}✔ Installed Elasticsearch version: ${YELLOW}${INSTALLED_VER}${NC}"
    if [[ "$INSTALLED_VER" != "$TARGET_VERSION" ]]; then
      echo -e "${YELLOW}⚠ Version mismatch (wanted ${TARGET_VERSION}). Continuing, but verify compatibility.${NC}"
    fi

  else
    # ----------------------------
    # Internet (APT repository)
    # ----------------------------
    echo -e "${GREEN}Installing Elasticsearch ${YELLOW}${TARGET_VERSION}${GREEN} from Elastic APT repo...${NC}"

    # Install pre-reqs
    echo -e "${GREEN}Updating package lists and prerequisites.${NC}"
    sudo apt-get update -y >/dev/null 2>&1 || true
    sudo apt-get install -y apt-transport-https ca-certificates gnupg curl >/dev/null 2>&1 || true
    _spin "Preparing install" 1

    # Add correct repo for major version
    local MAJOR="${TARGET_VERSION%%.*}"
    if [[ "$MAJOR" != "8" && "$MAJOR" != "9" ]]; then
      echo -e "${RED}Unsupported major version: ${TARGET_VERSION}. Expected 8.x or 9.x.${NC}"
      exit 1
    fi

    echo -e "${BLUE}Configuring Elastic ${MAJOR}.x APT repository (signed-by keyring)...${NC}"
    sudo install -m 0755 -d /usr/share/keyrings
    curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch \
      | sudo gpg --dearmor -o /usr/share/keyrings/elastic-archive-keyring.gpg >/dev/null 2>&1
    sudo rm -f /etc/apt/sources.list.d/elastic-8.x.list /etc/apt/sources.list.d/elastic-9.x.list 2>/dev/null || true
    echo "deb [signed-by=/usr/share/keyrings/elastic-archive-keyring.gpg] https://artifacts.elastic.co/packages/${MAJOR}.x/apt stable main" \
      | sudo tee "/etc/apt/sources.list.d/elastic-${MAJOR}.x.list" >/dev/null

    echo -e "${GREEN}✔ Repository added.${NC}"
    echo -e "${GREEN}Updating package lists...${NC}"
    if ! sudo apt-get update -y >/dev/null 2>&1; then
      echo -e "${RED}apt-get update failed. Check network / repo config and retry.${NC}"
      exit 1
    fi

    # Confirm requested version exists in repo
    local AVAILABLE
    AVAILABLE="$(apt-cache madison elasticsearch | awk '{print $3}' | paste -sd ', ' -)"
    if ! apt-cache madison elasticsearch | awk '{print $3}' | grep -qx "${TARGET_VERSION}"; then
      echo -e "${RED}Requested version ${TARGET_VERSION} not found in ${MAJOR}.x repo.${NC}"
      echo -e "${YELLOW}Available versions:${NC} ${CYAN}${AVAILABLE:-<none>}${NC}"
      exit 1
    fi

    echo -e "${GREEN}Installing elasticsearch=${TARGET_VERSION} ...${NC}"
    if ! sudo apt-get install -y "elasticsearch=${TARGET_VERSION}" >/dev/null 2>&1; then
      echo -e "${RED}Failed to install elasticsearch=${TARGET_VERSION}.${NC}"
      echo -e "${YELLOW}Available versions:${NC} ${CYAN}${AVAILABLE:-<none>}${NC}"
      exit 1
    fi
    echo -e "${GREEN}✔ Elasticsearch ${TARGET_VERSION} installed from repo.${NC}"
  fi

  # Common post-checks (both paths)
  if ! dpkg -s elasticsearch >/dev/null 2>&1; then
    echo -e "${RED}Elasticsearch package not installed. Aborting.${NC}"
    exit 1
  fi
  local ES_BIN_DIR="/usr/share/elasticsearch/bin"
  if [[ ! -x "${ES_BIN_DIR}/elasticsearch-reconfigure-node" ]]; then
    echo -e "${RED}Missing ${ES_BIN_DIR}/elasticsearch-reconfigure-node after install.${NC}"
    echo -e "${YELLOW}Package contents:${NC}"
    dpkg -L elasticsearch | sed -n 's@.*usr/share/elasticsearch/bin/@@p' | sed 's/^/  - /'
    exit 1
  fi
  echo -e "${GREEN}✔ Elasticsearch installation verified.${NC}"
}

# >>> Call the function (replaces your previous install block) <<<
install_elasticsearch_selected_method

sleep 5 & spinner "Configuring Elasticsearch..."
echo -e "${GREEN}✔ Time to join nodes together and create a cluster.${NC}"

# --- SAFE PROMPTS (replace your read -p "$(echo -e ...") with these) ---

# Node IP
while true; do
  read -rp "$(printf '%b' "${GREEN}Enter the first node IP: ${NC}") " NODE_IP
  if validate_ip "$NODE_IP"; then
    printf '%b\n' "${GREEN}✔ Node IP accepted: ${YELLOW}${NODE_IP}${NC}"
    break
  else
    printf '%b\n' "${RED}❌ Invalid IP address. Please try again.${NC}"
  fi
done

# Superuser username
while true; do
  read -rp "$(printf '%b' "${GREEN}Enter your superuser username: ${NC}") " USERNAME
  if validate_username "$USERNAME"; then
    printf '%b\n' "${GREEN}✔ Username accepted: ${YELLOW}${USERNAME}${NC}"
    break
  else
    printf '%b\n' "${RED}❌ Invalid username. Please try again.${NC}"
  fi
done

# Superuser password (silent)
while true; do
  read -rsp "$(printf '%b' "${GREEN}Enter your superuser password: ${NC}") " PASSWORD; echo
  if validate_password "$PASSWORD"; then
    printf '%b\n' "${GREEN}✔ Password accepted.${NC}"
    break
  else
    printf '%b\n' "${RED}❌ Invalid password. Please try again.${NC}"
  fi
done

# --- CLUSTER HEALTH + CLUSTER NAME (fixes $RESPONSE bug) ---
CLUSTER_RESPONSE="$(curl -s -k -u "$USERNAME:$PASSWORD" "https://${NODE_IP}:9200/_cluster/health")"
CLUSTER_STATUS="$(echo "$CLUSTER_RESPONSE" | grep -o '"status":"[^"]*"' | cut -d':' -f2 | tr -d '"')"
CLUSTER_NAME="$(echo "$CLUSTER_RESPONSE" | grep -o '"cluster_name":"[^"]*"' | awk -F'"' '{print $4}')"
printf '%b\n' "${GREEN}Detected Elasticsearch cluster name: ${YELLOW}${CLUSTER_NAME:-<unknown>}${NC}"

# --- ENROLLMENT TOKEN (env/arg aware; safe prompt fallback) ---
: "${GREEN:=$'\e[32m'}"; : "${YELLOW:=$'\e[33m'}"; : "${RED:=$'\e[31m'}"; : "${NC:=$'\e[0m'}"
is_valid_enrollment_token() { [[ "${1:-}" =~ ^[A-Za-z0-9+/=._-]{20,}$ ]]; }

CANDIDATE_TOKEN="${1:-${CLUSTER_TOKEN:-${ENROLLMENT_TOKEN:-}}}"
CANDIDATE_TOKEN="$(printf '%s' "$CANDIDATE_TOKEN" | tr -d '\r' | xargs)"

if [[ -n "$CANDIDATE_TOKEN" ]] && is_valid_enrollment_token "$CANDIDATE_TOKEN"; then
  CLUSTER_TOKEN="$CANDIDATE_TOKEN"
  printf '%b\n' "${GREEN}✔ Enrollment token received from environment/arguments.${NC}"
else
  printf -v _prompt '%b' \
    "${GREEN}Enter the enrollment token from your first node (${YELLOW}/usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s node${GREEN}): ${NC}"
  while true; do
    read -rsp "$_prompt " CLUSTER_TOKEN; echo
    CLUSTER_TOKEN="$(printf '%s' "$CLUSTER_TOKEN" | tr -d '\r' | xargs)"
    if [[ -z "$CLUSTER_TOKEN" ]]; then
      printf '%b\n' "${RED}❌ Token cannot be empty.${NC}"; continue
    fi
    if is_valid_enrollment_token "$CLUSTER_TOKEN"; then
      printf '%b\n' "${GREEN}✔ Token accepted.${NC}"; break
    else
      printf '%b\n' "${RED}❌ Token appears invalid. Check for copy/paste issues and try again.${NC}"
    fi
  done
fi
export CLUSTER_TOKEN

# --- ENROLL THIS NODE BEFORE STARTING ES ---
ES_RECONF="/usr/share/elasticsearch/bin/elasticsearch-reconfigure-node"
printf '%b\n' "${GREEN}🔐 Enrolling node with cluster using provided token...${NC}"

if [[ ! -x "$ES_RECONF" ]]; then
  echo -e "${RED}Cannot enroll: ${ES_RECONF} is missing.${NC}"
  echo -e "${YELLOW}Verify Elasticsearch ${ELASTIC_VERSION} actually installed from the ${MAJOR}.x repo and rerun.${NC}"
  exit 1
fi

set +e
sudo "$ES_RECONF" --enrollment-token "$CLUSTER_TOKEN"
enroll_rc=$?
set -e
if (( enroll_rc != 0 )); then
  printf '%b\n' "${RED}❌ Node enrollment failed (rc=${enroll_rc}).${NC}"
  printf '%b\n' "${YELLOW}Tip:${NC} Ensure the first node is up on 9200, credentials are correct, and the token is fresh."
  exit $enroll_rc
fi
printf '%b\n' "${GREEN}✔ Node enrollment completed.${NC}"

# --- DO NOT OVERRIDE TRANSPORT-TLS; SCRUB ANY MANUAL SETTINGS ---
ES_YML="/etc/elasticsearch/elasticsearch.yml"
if grep -qE '^\s*xpack\.security\.transport\.ssl\.' "$ES_YML"; then
  printf '%b\n' "${YELLOW}⚠ Found transport SSL overrides in ${ES_YML}. Commenting them out to use enrolled settings...${NC}"
  sudo sed -Ei 's/^(\s*xpack\.security\.transport\.ssl\..*)/# \1/' "$ES_YML"
fi

# --- UPDATE ONLY node.name / cluster.name ---
printf '%b\n' "${GREEN}Updating node.name and cluster.name...${NC}"
sudo sed -i "s/^node\.name:.*/node.name: \"${NODE_NAME}\"/" "$ES_YML" || echo "node.name: \"${NODE_NAME}\"" | sudo tee -a "$ES_YML" >/dev/null
sudo sed -i "s/^cluster\.name:.*/cluster.name: \"${CLUSTER_NAME}\"/" "$ES_YML" || echo "cluster.name: \"${CLUSTER_NAME}\"" | sudo tee -a "$ES_YML" >/dev/null

# --- START ES ---
printf '%b\n' "${GREEN}Reloading Daemon.${NC}"
sudo systemctl daemon-reload
printf '%b\n' "${GREEN}Enabling Elasticsearch for persistent start upon reboot.${NC}"
sudo systemctl enable elasticsearch
printf '%b\n' "${GREEN}Starting Elasticsearch...${NC}"
sudo systemctl start elasticsearch
sleep 5 & spinner "Waiting for Elasticsearch to start"
printf '%b\n' "${GREEN}Checking Elasticsearch status...${NC}"
check_service elasticsearch

# --- FIXED MESSAGE (COMMON_IP vs ELASTIC_HOST) ---
echo -e "${GREEN}✔ This Elasticsearch node will be set up at IP: ${COMMON_IP}${NC}"

echo -e "${GREEN}This node has been successfully added to the Elasticsearch cluster.${NC}"
echo -e "${GREEN}You can now repeat the process on the next node using the corresponding token generated from the initial node.${NC}"

# Extract cluster health status using grep and awk for table summary output
echo -e "${GREEN}Checking Elasticsearch cluster health status...${NC}"

while true; do
    CLUSTER_RESPONSE=$(curl -s -k -u $USERNAME:$PASSWORD https://$NODE_IP:9200/_cluster/health)
    CLUSTER_STATUS=$(echo "$CLUSTER_RESPONSE" | grep -o '"status":"[^"]*"' | cut -d':' -f2 | tr -d '"')

    echo -e "${GREEN}Current cluster status: ${YELLOW}${CLUSTER_STATUS}${NC}"

    if [[ "$CLUSTER_STATUS" == "green" ]]; then
        echo -e "${GREEN}✅ Cluster status is GREEN. Continuing...${NC}"
        break
    else
        echo -e "${YELLOW}⏳ Waiting for cluster to reach GREEN status... checking again in 5 seconds.${NC}"
        sleep 5
    fi
done

add_to_summary_table "Cluster Status" "$CLUSTER_STATUS"

echo -e "${GREEN}"
cat << 'EOF'
          o
/|   o         o
\|=--            o
   ##
                   \\
                /   \O
               O_/   T
               T    /|
               |\  | |
_______________|_|________
EOF
echo -e "${NC}"


# Final table
echo -e "\n${GREEN}Summary of your configuration:${NC}"
print_summary_table


echo -e "${GREEN}"
cat << 'EOF'
  ______ _           _   _                              _       _   _           _      
 |  ____| |         | | (_)                            | |     | \ | |         | |     
 | |__  | | __ _ ___| |_ _  ___ ___  ___  __ _ _ __ ___| |__   |  \| | ___   __| | ___ 
 |  __| | |/ _` / __| __| |/ __/ __|/ _ \/ _` | '__/ __| '_ \  | . ` |/ _ \ / _` |/ _ \
 | |____| | (_| \__ \ |_| | (__\__ \  __/ (_| | | | (__| | | | | |\  | (_) | (_| |  __/
 |______|_|\__,_|___/\__|_|\___|___/\___|\__,_|_|  \___|_| |_| |_| \_|\___/ \__,_|\___|

EOF
echo -e "${NC}"