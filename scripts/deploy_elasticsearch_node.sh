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

# --- Prompt for ELK install history (SAFE) ---
printf '\n%b\n' "${GREEN}Has Elasticsearch, Logstash, or Kibana ever been installed on this machine before?${NC}"
while true; do
  read -rp "$(printf 'Type "%byes%b" if there is a previous installation on this machine, or "%bno%b" to continue with a fresh install: ' "$YELLOW" "$NC" "$YELLOW" "$NC")" INSTALL_RESPONSE
  case "${INSTALL_RESPONSE,,}" in
    y|yes) INSTALL_RESPONSE="yes"; PREVIOUS_INSTALL=true; FRESH_INSTALL=false; break;;
    n|no)  INSTALL_RESPONSE="no";  PREVIOUS_INSTALL=false; FRESH_INSTALL=true;  break;;
    *)     printf '%b\n' "${RED}Invalid response. Please enter \"yes\" or \"no\".${NC}";;
  esac
done

if [[ "$INSTALL_RESPONSE" == "yes" ]]; then
  echo -e "\n${YELLOW}Starting cleanup of any existing ELK stack components...${NC}"

  # Helpers: unit existence + safe kill within service cgroup
  unit_loaded() { [[ "$(systemctl show -p LoadState --value "${1}.service" 2>/dev/null)" == "loaded" ]]; }
  kill_unit_procs() {
    local svc="$1"
    sudo systemctl kill -s TERM "$svc" 2>/dev/null || true
    sleep 1
    sudo systemctl kill -s KILL "$svc" 2>/dev/null || true
  }

  # Stop/disable and ensure no lingering procs (NO pkill -f)
  for svc in elasticsearch logstash kibana; do
    if unit_loaded "$svc"; then
      echo -e "${CYAN}Stopping and disabling $svc...${NC}"
      sudo systemctl stop "$svc" 2>/dev/null || true
      sudo systemctl disable "$svc" 2>/dev/null || true
      echo -e "${CYAN}Ensuring no lingering $svc processes...${NC}"
      kill_unit_procs "$svc"
    else
      echo -e "${YELLOW}$svc service not found. Skipping systemd stop...${NC}"
    fi
  done

  # --- Elastic Agent cleanup (service-aware; no broad pkill) ---
  if unit_loaded "elastic-agent"; then
    echo -e "${CYAN}Stopping and disabling elastic-agent...${NC}"
    sudo systemctl stop elastic-agent 2>/dev/null || true
    sudo systemctl disable elastic-agent 2>/dev/null || true
    kill_unit_procs "elastic-agent"
  else
    # Fallback: kill exact process name if present
    if pgrep -x elastic-agent >/dev/null 2>&1; then
      echo -e "${YELLOW}Elastic Agent process detected. Terminating...${NC}"
      pkill -x elastic-agent 2>/dev/null || true
      echo -e "${GREEN}✔ Elastic Agent process terminated.${NC}"
    else
      echo -e "${GREEN}No running Elastic Agent process found.${NC}"
    fi
  fi

  # Remove Elastic Agent install dir
  if [[ -d "/opt/Elastic" ]]; then
    echo -e "${YELLOW}Removing existing Elastic Agent installation at /opt/Elastic...${NC}"
    sudo rm -rf /opt/Elastic
    echo -e "${GREEN}✔ Elastic Agent directory removed successfully.${NC}"
  else
    echo -e "${GREEN}No Elastic Agent directory found at /opt/Elastic. Skipping...${NC}"
  fi

  # Remove lingering systemd unit (agent)
  if [[ -f "/etc/systemd/system/elastic-agent.service" ]]; then
    echo -e "${YELLOW}Found systemd unit file for Elastic Agent. Cleaning up...${NC}"
    sudo systemctl disable elastic-agent 2>/dev/null || true
    sudo rm -f /etc/systemd/system/elastic-agent.service
    sudo systemctl daemon-reexec || true
    sudo systemctl daemon-reload || true
    echo -e "${GREEN}✔ Removed stale elastic-agent systemd service.${NC}"
  else
    echo -e "${GREEN}No elastic-agent systemd service file found. Skipping...${NC}"
  fi

  # Cleanup: stale agent artifacts in $HOME
  echo -e "${GREEN}Scanning for stale Elastic Agent packages in home directory...${NC}"
  shopt -s nullglob
  AGENT_TARS=( "$HOME"/elastic-agent-*-linux-x86_64.tar.gz )
  AGENT_DIRS=( "$HOME"/elastic-agent-*-linux-x86_64 )
  for file in "${AGENT_TARS[@]}"; do
    echo -e "${YELLOW}Removing Elastic Agent archive: $(basename "$file")${NC}"
    rm -f -- "$file"
  done
  for dir in "${AGENT_DIRS[@]}"; do
    if [[ -d "$dir" ]]; then
      echo -e "${YELLOW}Removing Elastic Agent directory: $(basename "$dir")${NC}"
      rm -rf -- "$dir"
    fi
  done
  shopt -u nullglob
  echo -e "${GREEN}✔ Finished cleaning up Elastic Agent artifacts in home directory.${NC}"

  # Uninstall packages (don’t let set -e nuke the script)
  echo -e "${CYAN}Attempting to uninstall Elasticsearch, Logstash, and Kibana...${NC}"
  set +e
  sudo apt-get purge -y elasticsearch logstash kibana >/dev/null 2>&1
  sudo apt-get autoremove -y >/dev/null 2>&1
  set -e

  # Remove directories and files (only if they exist)
  paths_to_clean=(
    /etc/elasticsearch /etc/logstash /etc/kibana
    /var/lib/elasticsearch /var/lib/logstash
    /var/log/elasticsearch /var/log/logstash /var/log/kibana
    /usr/share/elasticsearch /usr/share/logstash /usr/share/kibana
    /etc/apt/sources.list.d/elastic-8.x.list
    /etc/apt/sources.list.d/elastic-9.x.list
  )
  for path in "${paths_to_clean[@]}"; do
    if [[ -e "$path" ]]; then
      echo -e "${CYAN}Removing $path...${NC}"
      sudo rm -rf -- "$path"
    else
      echo -e "${YELLOW}Path not found: $path — skipping.${NC}"
    fi
  done

  echo -e "${GREEN}✔ Cleanup complete. Proceeding with a fresh installation.${NC}"
else
  echo -e "${GREEN}Confirmed: Fresh install. Continuing setup...${NC}"
fi

# Lowercase & trim just in case
INSTALL_RESPONSE="$(echo "$INSTALL_RESPONSE" | tr '[:upper:]' '[:lower:]' | xargs)"

# Add appropriate row to final output table
if [[ "$INSTALL_RESPONSE" == "yes" ]]; then
  add_to_summary_table "Services Cleaned/Reinstalled" "Yes"
elif [[ "$INSTALL_RESPONSE" == "no" ]]; then
  add_to_summary_table "First Time Install" "Yes"
else
  echo -e "${RED}Invalid response. Please type 'yes' or 'no'.${NC}"
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

# Update
echo -e "${GREEN}Updating package lists and installing prerequisites.${NC}"
sudo apt-get update > /dev/null 2>&1
sleep 5 & spinner

# Add Elastic APT repository
echo -e "${BLUE}Adding Elastic APT repository...${NC}"
{
    curl -s https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add - > /dev/null 2>&1
    echo "deb https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list > /dev/null 2>&1
	echo "deb https://artifacts.elastic.co/packages/9.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-9.x.list > /dev/null 2>&1
} &
sleep 5 & spinner "Adding repository..."

echo -e "${GREEN}✔ Repository added successfully.${NC}"

# Install Elasticsearch
sudo apt-get update > /dev/null 2>&1
sleep 2 & spinner "Updating package lists"
sudo apt-get install -y "elasticsearch=$ELASTIC_VERSION" > /dev/null 2>&1
sleep 2 & spinner "Installing Elasticsearch version $ELASTIC_VERSION"
echo -e "${GREEN}✔ Elasticsearch installation completed successfully.${NC}"

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

# --- ENROLL THIS NODE *BEFORE* STARTING ES; QUOTE THE TOKEN ---
printf '%b\n' "${GREEN}🔐 Enrolling node with cluster using provided token...${NC}"
set +e
sudo /usr/share/elasticsearch/bin/elasticsearch-reconfigure-node --enrollment-token "$CLUSTER_TOKEN"
enroll_rc=$?
set -e
if (( enroll_rc != 0 )); then
  printf '%b\n' "${RED}❌ Node enrollment failed (rc=${enroll_rc}).${NC}"
  printf '%b\n' "${YELLOW}Tip:${NC} Ensure the first node is running and reachable on 9200, and the token hasn’t expired."
  return 1 2>/dev/null || exit 1
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
printf '%b\n' "${GREEN}✔ This Elasticsearch node will be set up at IP: ${YELLOW}${COMMON_IP}${NC}"


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