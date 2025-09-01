#!/bin/bash
# Common utility functions for deployment scripts

# Initialize color/style variables safely.
# Usage: init_colors            # normal (no override if already inited)
#        init_colors force      # re-evaluate (e.g., after changing NO_COLOR/FORCE_COLOR)
init_colors() {
  local force="${1:-}"
  if [[ -n "${COLORS_INITIALIZED:-}" && -z "$force" ]]; then
    return 0
  fi

  # If NO_COLOR is set (to anything), disable colors unconditionally.
  if [[ -n "${NO_COLOR-}" ]]; then
    BOLD=""; UNDERLINE=""; NC=""
    RED=""; GREEN=""; YELLOW=""; BLUE=""; MAGENTA=""; CYAN=""
  elif [[ -t 1 || -n "${FORCE_COLOR-}" ]]; then
    # Color output enabled: TTY or FORCE_COLOR present
    if command -v tput >/dev/null 2>&1; then
      BOLD="${BOLD:-$(tput bold 2>/dev/null || echo $'\e[1m')}"
      UNDERLINE="${UNDERLINE:-$(tput smul 2>/dev/null || echo $'\e[4m')}"
      NC="${NC:-$(tput sgr0 2>/dev/null || echo $'\e[0m')}"
    else
      BOLD="${BOLD:-$'\e[1m'}"
      UNDERLINE="${UNDERLINE:-$'\e[4m'}"
      NC="${NC:-$'\e[0m'}"
    fi
    RED="${RED:-$'\e[31m'}"
    GREEN="${GREEN:-$'\e[32m'}"
    YELLOW="${YELLOW:-$'\e[33m'}"
    BLUE="${BLUE:-$'\e[34m'}"
    MAGENTA="${MAGENTA:-$'\e[35m'}"
    CYAN="${CYAN:-$'\e[36m'}"
  else
    # Not a TTY and not forced → disable colors (empty strings avoid set -u issues)
    BOLD=""; UNDERLINE=""; NC=""
    RED=""; GREEN=""; YELLOW=""; BLUE=""; MAGENTA=""; CYAN=""
  fi

  COLORS_INITIALIZED=1
  # Export so subshells (sudo -E env ...) get the same styling if you preserve env
  export BOLD UNDERLINE NC RED GREEN YELLOW BLUE MAGENTA CYAN COLORS_INITIALIZED
}

# logs steps for elk env file for history
log_step() {
  KEY="$1"
  VALUE="$2"
  grep -v "^$KEY=" "$ELK_ENV_FILE" > "$ELK_ENV_FILE.tmp" && mv "$ELK_ENV_FILE.tmp" "$ELK_ENV_FILE"
  echo "$KEY=$VALUE" >> "$ELK_ENV_FILE"
}

# Validate an IPv4 address
validate_ip() {
    local ip=$1
    if [[ $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        for segment in ${ip//./ }; do
            if ((segment < 0 || segment > 255)); then
                echo -e "${RED}Invalid IP: $ip. Out of range.${NC}"
                return 1
            fi
        done
        return 0
    else
        echo -e "${RED}Invalid IP: $ip. Format is incorrect.${NC}"
        return 1
    fi
}

# Validate node name
validate_nodename() {
    if [[ ! "$1" =~ ^[a-zA-Z0-9_-]+$ ]]; then
        echo -e "${RED}Invalid node name. Only letters, numbers, underscores (_), and dashes (-) are allowed.${NC}"
        return 1
    fi
    return 0
}

# Validate username or email
validate_username() {
    if [[ ! "$1" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ && ! "$1" =~ ^[a-zA-Z0-9_-]+$ ]]; then
        echo -e "${RED}Invalid username. Use a simple name (letters, numbers, _, -) OR a valid email like user@example.com.${NC}"
        return 1
    fi
    return 0
}

# Validate password (minimum 8 characters)
validate_password() {
    if [[ -z "$1" || ${#1} -lt 8 ]]; then
        echo -e "${RED}Invalid password. It must be at least 8 characters long.${NC}"
        return 1
    fi
    return 0
}

# Validate Elastic Stack version format
validate_version() {
    if [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        return 0
    else
        echo -e "${RED}Invalid version format. Please use the format: X.Y.Z (e.g., 8.18.2 or 9.0.2)${NC}"
        return 1
    fi
}

#yaml template function
apply_template() {
    local template_file="$1"
    local destination_file="$2"

    if [[ ! -f "$template_file" ]]; then
        echo -e "${RED}❌ Template not found: $template_file${NC}"
        return 1
    fi

    echo -e "${BLUE}→ Applying template: $template_file → $destination_file${NC}"

    # List all variables used in the template
    local content
    content=$(<"$template_file")

    # Replace ${VAR} with their values
    while read -r line; do
        var_name=$(echo "$line" | sed -n 's/.*${\([^}]\+\)}.*/\1/p')
        if [[ -n "$var_name" && -n "${!var_name}" ]]; then
            content=$(echo "$content" | sed "s|\${$var_name}|${!var_name}|g")
        fi
    done < <(grep -o '\${[^}]\+}' "$template_file" | sort -u)

    echo "$content" | sudo tee "$destination_file" > /dev/null
}

sanitize_line_endings() {
    local target_file="$1"
    if [[ -f "$target_file" ]]; then
        sed -i 's/\r$//' "$target_file"
        echo -e "${GREEN}✔ Sanitized line endings in: ${YELLOW}$target_file${NC}"
    else
        echo -e "${RED}❌ File not found: $target_file${NC}"
    fi
}

spinner() {
  local pid=$!
  local delay=0.1
  local spinstr='|/-\'
  local msg="${1:-Working...}"   # <— default to avoid unbound var with set -u

  printf "%s " "$msg"
  while kill -0 "$pid" 2>/dev/null; do
    for ((i=0; i<${#spinstr}; i++)); do
      printf '\r%s %s' "$msg" "${spinstr:i:1}"
      sleep "$delay"
    done
  done
  printf '\r%s [✔]\n' "$msg"
}


# Spinner specifically for elastic-agent download/extraction
spinner_agent_download() {
    local pid=$!
    local delay=0.1
    local spinstr='|/-\\'
    echo -n "$1"
    while kill -0 "$pid" 2>/dev/null; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    echo -e " [✔]"
}

check_service() {
    local svc="$1"
    echo -e "${GREEN}Checking ${svc^} status...${NC}"
    local status
    status=$(sudo systemctl status "$svc" --no-pager \
        | awk -F': ' '/Active:/ {print $2}' \
        | awk '{print $1}')
    echo -e "${YELLOW}${svc^} status: ${status}${NC}"

    if [[ "$status" == "active" ]]; then
        echo -e "${GREEN}✔ ${svc^} is running.${NC}"
    elif [[ "$status" == "failed" ]]; then
        echo -e "${RED}❌ ${svc^} failed to start. Exiting.${NC}"
        exit 1
    else
        echo -e "${RED}❌ Unexpected ${svc^} state: ${status}. Exiting.${NC}"
        exit 1
    fi
}

# An array to hold table rows
declare -a SUMMARY_TABLE

# Prompt user and return input
prompt_input() {
  local prompt="$1"
  local varname="$2"
  read -p "$(echo -e "${GREEN}${prompt}${NC}")" "$varname"
}

# Add a row to the summary table
add_to_summary_table() {
  local key="$1"
  local value="$2"
  SUMMARY_TABLE+=("$key|$value")
}

# Global table store (set -u safe)
declare -ga SUMMARY_TABLE=() 2>/dev/null || true

reset_summary_table() { SUMMARY_TABLE=(); }
add_to_summary_table() { SUMMARY_TABLE+=("${1:-}|${2:-}"); }

# truthy -> Yes/No
bool_yesno() { bool_true "${1:-}"; [[ $? -eq 0 ]] && echo "Yes" || echo "No"; }

# Build rows from .elk_env + live state so table shows even when steps are skipped
populate_summary_rows() {
  load_env
  reset_summary_table

  local dep="${DEPLOYMENT_TYPE:-single}"
  local ver="${ELASTIC_VERSION:-unknown}"

  # service_install_ok handles non-zero internally via 'if ...; then' so it's -e safe here
  local svc_state; if service_install_ok; then svc_state="Installed"; else svc_state="Not Installed"; fi

  local air="$(bool_yesno "${AIRGAPPED_MODE:-false}")"
  local epr="$(bool_yesno "${EPR_CONFIGURED:-false}")"
  local agent="$(bool_yesno "${AGENT_FLEET_SETUP:-false}")"
  local remote="$(bool_yesno "${REMOTE_DEPLOY_TRIGGERED:-false}")"

  local remote_ready="No"
  if [[ "${DEPLOYMENT_TYPE,,}" == "cluster" ]] \
     && bool_true "${SERVICE_INSTALL:-false}" \
     && bool_true "${AGENT_FLEET_SETUP:-false}" \
     && ! bool_true "${REMOTE_DEPLOY_TRIGGERED:-false}"
  then
    remote_ready="Yes"
  fi

  [[ -n "${DEPLOY_STARTED:-}" ]] && add_to_summary_table "Deploy Started" "${DEPLOY_STARTED}"

  add_to_summary_table "Deployment Type" "$dep"
  add_to_summary_table "Elastic Version" "$ver"
  add_to_summary_table "Core Services Installed" "$svc_state"
  add_to_summary_table "Airgapped Mode" "$air"
  add_to_summary_table "EPR Configured" "$epr"
  add_to_summary_table "Agent/Fleet Setup" "$agent"
  add_to_summary_table "Remote Deploy Triggered" "$remote"
  add_to_summary_table "Remote Deploy Ready" "$remote_ready"
}

# Robust ASCII table printer (no crash if empty/unset; ANSI-safe widths optional)
print_summary_table() {
  local rows=()
  if declare -p SUMMARY_TABLE >/dev/null 2>&1; then
    rows=("${SUMMARY_TABLE[@]}")
  fi

  # Optional: strip ANSI for width calc (keeps colors in printed cells)
  strip_ansi() { sed -r 's/\x1B\[[0-9;]*[A-Za-z]//g'; }

  local max_key=5 max_val=5 row key val sk sv
  for row in "${rows[@]}"; do
    IFS='|' read -r key val <<<"$row"
    sk="$(printf '%s' "${key:-}" | strip_ansi)"; sv="$(printf '%s' "${val:-}" | strip_ansi)"
    (( ${#sk} > max_key )) && max_key=${#sk}
    (( ${#sv} > max_val )) && max_val=${#sv}
  done

  local sep="+-$(printf '%*s' "$max_key" '' | tr ' ' '-')-+-$(printf '%*s' "$max_val" '' | tr ' ' '-')-+"
  echo "$sep"
  printf "| %-*s | %-*s |\n" "$max_key" "Input" "$max_val" "Value"
  echo "$sep"

  if ((${#rows[@]} == 0)); then
    printf "| %-*s | %-*s |\n" "$max_key" "(no items)" "$max_val" ""
  else
    for row in "${rows[@]}"; do
      IFS='|' read -r key val <<<"$row"
      printf "| %-*s | %-*s |\n" "$max_key" "${key:-}" "$max_val" "${val:-}"
    done
  fi
  echo "$sep"
}

secure_node_with_iptables() {

  # --- Audit Log Location ---
  AUDIT_LOG="/var/log/elk-firewall.log"
  sudo touch "$AUDIT_LOG"
  sudo chmod 644 "$AUDIT_LOG"
  echo "### iptables audit log - $(date)" | sudo tee "$AUDIT_LOG" > /dev/null

  # --- CIDR Validator ---
  validate_cidr() {
    local cidr=$1
    if [[ "$cidr" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[12][0-9]|3[0-2])$ ]]; then
      return 0
    else
      return 1
    fi
  }

  echo -e "${CYAN}============================"
  echo -e "🛡️  Hardening airgapped node with iptables"
  echo -e "============================${NC}"

  echo -e "\n${CYAN}Current iptables rules:${NC}"
  sudo iptables -L -n -v --line-numbers

  echo -e "\n${YELLOW}Is this node running Elasticsearch only, or Elasticsearch + Logstash + Kibana?${NC}"
  echo -e "${GREEN}Type 'single' for Elasticsearch only, or 'stack' for the full stack.${NC}"
  read -p "$(echo -e "${CYAN}Enter your choice [single/stack]: ${NC}")" NODE_TYPE

  if [[ "$NODE_TYPE" =~ ^[Ss][Ii][Nn][Gg][Ll][Ee]$ ]]; then
    echo -e "\n${GREEN}🔒 This is an Elasticsearch-only node.${NC}"
    PORTS=(9200)
    declare -A SERVICE_PORTS=( ["Elasticsearch"]=9200 )
  elif [[ "$NODE_TYPE" =~ ^[Ss][Tt][Aa][Cc][Kk]$ ]]; then
    echo -e "\n${GREEN}🔒 This is a full stack node (Elasticsearch, Logstash, Kibana, Fleet Server).${NC}"
    PORTS=(5044 9200 9300 5601 8220)
    declare -A SERVICE_PORTS=(
      ["Logstash"]=5044
      ["FleetServer"]=8220
      ["Elasticsearch"]=9200
      ["Kibana"]=5601
    )
  else
    echo -e "${RED}❌ Invalid input. Please run the function again.${NC}"
    return 1
  fi

  echo -e "\n${YELLOW}Blocking all inbound TCP, UDP ports and ICMP...${NC}"
  for PORT in "${PORTS[@]}"; do
    echo -e "${CYAN}Blocking TCP port $PORT...${NC}"
    sudo iptables -A INPUT -p tcp --dport "$PORT" -j DROP
    echo "$(date) - Blocked TCP port $PORT" | sudo tee -a "$AUDIT_LOG" > /dev/null

    echo -e "${CYAN}Blocking UDP port $PORT...${NC}"
    sudo iptables -A INPUT -p udp --dport "$PORT" -j DROP
    echo "$(date) - Blocked UDP port $PORT" | sudo tee -a "$AUDIT_LOG" > /dev/null
  done

  echo -e "${CYAN}Blocking ICMP echo requests (ping)...${NC}"
  sudo iptables -A INPUT -p icmp --icmp-type 8 -j DROP
  echo "$(date) - Blocked ICMP type 8 (echo-request)" | sudo tee -a "$AUDIT_LOG" > /dev/null

  echo -e "\n${YELLOW}Now you may ALLOW specific subnets to access services (TCP only)...${NC}"

  for SERVICE in "${!SERVICE_PORTS[@]}"; do
    PORT=${SERVICE_PORTS[$SERVICE]}
    echo -e "\n${YELLOW}Do you want to allow a subnet to access ${CYAN}$SERVICE${YELLOW} on port ${CYAN}$PORT${YELLOW}?${NC}"
    read -p "$(echo -e "${CYAN}Enter yes or no: ${NC}")" ALLOW

    if [[ "$ALLOW" =~ ^[Yy][Ee]?[Ss]?$ ]]; then
      while true; do
        read -p "$(echo -e "${CYAN}Enter subnet in CIDR (e.g. 10.0.0.0/24): ${NC}")" SUBNET
        if validate_cidr "$SUBNET"; then
          sudo iptables -I INPUT -p tcp -s "$SUBNET" --dport "$PORT" -j ACCEPT
          echo -e "${GREEN}✔ Allowed $SUBNET to access $SERVICE (TCP $PORT)${NC}"
          echo "$(date) - Allowed $SUBNET to access $SERVICE on TCP port $PORT" | sudo tee -a "$AUDIT_LOG" > /dev/null
          break
        else
          echo -e "${RED}❌ Invalid CIDR. Try again.${NC}"
        fi
      done
    else
      echo -e "${YELLOW}Skipping allow rule for $SERVICE.${NC}"
    fi
  done

  echo -e "\n${YELLOW}Do you want to REMOVE any existing allowed rules?${NC}"
  read -p "$(echo -e "${CYAN}Enter yes or no: ${NC}")" REMOVE

  if [[ "$REMOVE" =~ ^[Yy][Ee]?[Ss]?$ ]]; then
    echo -e "${CYAN}Showing current iptables rules:${NC}"
    sudo iptables -L INPUT -n --line-numbers

    for SERVICE in "${!SERVICE_PORTS[@]}"; do
      PORT=${SERVICE_PORTS[$SERVICE]}
      echo -e "\n${YELLOW}Remove rules for ${CYAN}$SERVICE${YELLOW} on port ${CYAN}$PORT${YELLOW}?${NC}"
      read -p "$(echo -e "${CYAN}Enter yes or no: ${NC}")" REMOVE_PORT

      if [[ "$REMOVE_PORT" =~ ^[Yy][Ee]?[Ss]?$ ]]; then
        sudo iptables -L INPUT -n --line-numbers | grep "$PORT"
        echo -e "${YELLOW}Enter the LINE NUMBER to delete:${NC}"
        read -p "$(echo -e "${CYAN}Line number: ${NC}")" LINE

        RULE=$(sudo iptables -L INPUT -n --line-numbers | grep "^$LINE ")
        sudo iptables -D INPUT "$LINE"
        echo -e "${GREEN}✔ Deleted rule $LINE for $SERVICE.${NC}"
        echo "$(date) - Deleted rule: $RULE" | sudo tee -a "$AUDIT_LOG" > /dev/null
      fi
    done
  fi

  echo -e "\n${CYAN}Final iptables rules:${NC}"
  sudo iptables -L -n -v --line-numbers

  echo -e "\n${CYAN}💾 Saving rules to disk using iptables-save...${NC}"
  sudo iptables-save | sudo tee /etc/iptables/rules.v4 > /dev/null
  echo -e "${GREEN}✅ Rules saved to /etc/iptables/rules.v4.${NC}"
  echo -e "${YELLOW}📌 To restore these rules later, run: ${CYAN}sudo iptables-restore < /etc/iptables/rules.v4${NC}"

  echo -e "\n${GREEN}🛡️ Node hardened for airgapped deployment.${NC}"
  echo -e "${YELLOW}📄 Log of all actions: ${CYAN}$AUDIT_LOG${NC}"
    # --- Persist iptables rules using iptables-restore at boot ---
  echo -e "\n${CYAN}Creating systemd service to restore iptables rules at boot...${NC}"

  sudo tee /etc/systemd/system/iptables-restore.service > /dev/null <<EOF
[Unit]
Description=Restore iptables firewall rules
Before=network-pre.target
Wants=network-pre.target
DefaultDependencies=no

[Service]
Type=oneshot
ExecStart=/sbin/iptables-restore < /etc/iptables/rules.v4
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

  sudo systemctl daemon-reexec
  sudo systemctl daemon-reload
  sudo systemctl enable iptables-restore.service

  echo -e "${GREEN}✅ iptables-restore.service created and enabled to run at boot.${NC}"
  echo -e "${YELLOW}🧠 On reboot, rules will be restored from ${CYAN}/etc/iptables/rules.v4${NC}"
}


tmux_help() {
  echo -e ""
  echo -e "${GREEN}==============================="
  echo -e " 🧩  TMUX QUICK COMMANDS "
  echo -e "===============================${NC}"
  echo -e "${YELLOW} Split panes:${NC}"
  echo -e "   H: Ctrl+b + % (vert)"
  echo -e "   V: Ctrl+b + \" (horiz)"
  echo -e ""
  echo -e "${YELLOW} Move panes:${NC}"
  echo -e "   Ctrl+b + o  (next)"
  echo -e "   Ctrl+b + arrows"
  echo -e ""
  echo -e "${YELLOW} Windows:${NC}"
  echo -e "   New:  Ctrl+b + c"
  echo -e "   Next: Ctrl+b + n"
  echo -e "   Prev: Ctrl+b + p"
  echo -e "   List: Ctrl+b + w"
  echo -e ""
  echo -e "${YELLOW} Misc:${NC}"
  echo -e "   Detach: Ctrl+b + d"
  echo -e "   Help:   Ctrl+b + ?"
  echo -e "${GREEN}===============================${NC}"
  echo -e ""
}

# Function to pause and return to menu
pause_and_return_to_menu() {
  echo -e "\n${YELLOW}Press Enter to return to the main menu...${NC}"
  read
}

# Function to uninstall zeek cleanly
uninstall_and_cleanup_zeek() {
    echo -e "${GREEN}🔍 Checking for existing Zeek installation...${NC}"
    local found=false

    # Check for systemd-managed Zeek service
    if systemctl list-units --type=service | grep -q 'zeek.service'; then
        echo -e "${YELLOW}⚠️  Zeek systemd service is active.${NC}"
        found=true
    fi

    # Check for zeekctl binary
    if command -v zeekctl &>/dev/null; then
        if zeekctl status 2>/dev/null | grep -qi 'running'; then
            echo -e "${YELLOW}⚠️  Zeek appears to be running via zeekctl.${NC}"
            found=true
        fi
    fi

    # Check if /opt/zeek exists (APT install)
    if [[ -d "/opt/zeek" ]]; then
        echo -e "${YELLOW}⚠️  Zeek installation detected in /opt/zeek (APT).${NC}"
        found=true
    fi

    # Check if /usr/local/zeek exists (source install)
    if [[ -d "/usr/local/zeek" ]]; then
        echo -e "${YELLOW}⚠️  Zeek installation detected in /usr/local/zeek (source).${NC}"
        found=true
    fi

    if [[ "$found" == false ]]; then
        echo -e "${GREEN}✅ No active Zeek installation found.${NC}"
        return 0
    fi

    echo -e "${RED}⚠️  A previous Zeek installation has been detected.${NC}"
    read -rp "$(echo -e "${YELLOW}Would you like to uninstall and remove all related files? (yes/no): ${NC}")" CLEANUP_CONFIRM
    if [[ ! "$CLEANUP_CONFIRM" =~ ^([yY][eE][sS]|[yY])$ ]]; then
        echo -e "${YELLOW}⏭ Skipping Zeek cleanup.${NC}"
        return 0
    fi

    # Stop Zeek via zeekctl if available
    if command -v zeekctl &>/dev/null; then
        echo -e "${CYAN}⛔ Stopping Zeek via zeekctl...${NC}"
        zeekctl stop || echo -e "${YELLOW}⚠️  Could not stop Zeek with zeekctl.${NC}"
    fi

    # Stop and disable Zeek systemd service if present
    if systemctl list-units --type=service | grep -q 'zeek.service'; then
        echo -e "${CYAN}🛑 Disabling Zeek systemd service...${NC}"
        sudo systemctl stop zeek.service
        sudo systemctl disable zeek.service
        sudo rm -f /etc/systemd/system/zeek.service
        sudo systemctl daemon-reload
    fi

    echo -e "${RED}🧹 Removing Zeek binaries, configs, and logs...${NC}"

    # Remove source install files
    sudo rm -rf /usr/local/zeek /usr/local/bin/zeek* 2>/dev/null

    # Remove APT install files
    sudo apt purge -y zeek zeek-core zeekctl 2>/dev/null
    sudo rm -rf /opt/zeek /usr/bin/zeek /usr/share/zeek 2>/dev/null

    # Remove logs if still present
    sudo rm -rf /usr/local/zeek/logs /opt/zeek/logs /usr/local/zeek/spool /opt/zeek/spool 2>/dev/null

    # Clean up PATH export from bashrc
    sed -i '/\/opt\/zeek\/bin/d' ~/.bashrc
    sed -i '/\/usr\/local\/zeek\/bin/d' ~/.bashrc

    echo -e "${GREEN}✅ Zeek uninstalled and cleaned up.${NC}"
}


# Function to uninstall Suricata cleanly
uninstall_and_cleanup_suricata() {
  echo -e "${CYAN}🔍 Checking for existing Suricata installation...${NC}"

  if command -v suricata &>/dev/null || systemctl list-units --type=service | grep -q 'suricata'; then
    echo -e "${YELLOW}⚠️  Suricata is already installed.${NC}"
    read -rp "$(echo -e "${YELLOW}Do you want to remove the old installation and clean logs/configs? (yes/no): ${NC}")" CLEAN_CONFIRM

    if [[ "$CLEAN_CONFIRM" =~ ^[Yy]([Ee][Ss])?$ ]]; then
      echo -e "${CYAN}🛑 Stopping Suricata service...${NC}"
      sudo systemctl stop suricata 2>/dev/null
      sudo systemctl disable suricata 2>/dev/null

      echo -e "${CYAN}🧹 Removing Suricata binaries and configs...${NC}"
      sudo apt-get remove --purge -y suricata
      sudo rm -rf /etc/suricata /var/lib/suricata

      echo -e "${CYAN}🧹 Cleaning Suricata logs from /var/log/suricata...${NC}"
      if [[ -d /var/log/suricata ]]; then
        sudo find /var/log/suricata -type f -name "*.log" -delete
        sudo find /var/log/suricata -type f -name "*.pcap" -delete
        sudo rm -rf /var/log/suricata/*  # extra safety wipe
      fi

      sudo systemctl daemon-reexec
      sudo systemctl daemon-reload

      echo -e "${GREEN}✅ Old Suricata installation and logs removed.${NC}"
    else
      echo -e "${YELLOW}⏭ Skipping Suricata cleanup.${NC}"
    fi
  else
    echo -e "${GREEN}✅ No existing Suricata installation found.${NC}"
  fi
}

# Helper: extract version from tar filename
extract_version_from_filename() {
    local filename="$1"
    echo "$filename" | sed -n 's/elastic-agent-\(.*\)-linux-x86_64\.tar\.gz/\1/p'
}

download_agent() {
    local version="$1"
    AGENT_FILENAME="elastic-agent-${version}-linux-x86_64.tar.gz"
    AGENT_SHA_FILENAME="${AGENT_FILENAME}.sha512"
    AGENT_PATH="$PACKAGES_DIR/$AGENT_FILENAME"
    AGENT_SHA_PATH="$PACKAGES_DIR/$AGENT_SHA_FILENAME"
    AGENT_URL="https://artifacts.elastic.co/downloads/beats/elastic-agent/${AGENT_FILENAME}"
    AGENT_SHA_URL="${AGENT_URL}.sha512"

    # Skip download if already exists
    if [[ -f "$AGENT_PATH" ]]; then
        echo -e "${GREEN}✔ Found existing agent tarball: $AGENT_FILENAME. Skipping download.${NC}"
    else
        echo -e "${BLUE}⬇ Downloading Elastic Agent $version...${NC}"
        curl -L --progress-bar -o "$AGENT_PATH" "$AGENT_URL"
        curl -s -o "$AGENT_SHA_PATH" "$AGENT_SHA_URL"
    fi

    # Checksum validation
    if [[ ! -s "$AGENT_SHA_PATH" ]]; then
        echo -e "${YELLOW}⚠️ No checksum file found. Generating SHA512 manually...${NC}"
        GENERATED_SHA=$(sha512sum "$AGENT_PATH")
        echo "$GENERATED_SHA" | tee -a "$PACKAGES_DIR/checksums.txt"
    else
        echo -e "${CYAN}Validating SHA512 checksum...${NC}"
        if (cd "$PACKAGES_DIR" && sha512sum -c "$AGENT_SHA_FILENAME" 2>/dev/null); then
            echo -e "${GREEN}✔ Checksum passed.${NC}"
        else
            echo -e "${RED}❌ Checksum validation failed for $AGENT_FILENAME. Continuing without strict validation.${NC}"
        fi
    fi
}

extract_agent() {
    echo -e "${CYAN}Extracting Elastic Agent...${NC}"
    AGENT_DIR="$PACKAGES_DIR/elastic-agent-${AGENT_VERSION}-linux-x86_64"

    (
        tar -xzf "$PACKAGES_DIR/$AGENT_FILENAME" -C "$PACKAGES_DIR"
    ) & spinner_agent_download "Extracting"

    if [[ -d "$AGENT_DIR" ]]; then
        cd "$AGENT_DIR" || {
            echo -e "${RED}❌ Could not enter agent directory: $AGENT_DIR${NC}"
            exit 1
        }
        echo -e "${GREEN}✔ Ready to install agent from: $AGENT_DIR${NC}"
    else
        echo -e "${RED}❌ Extracted agent directory not found: $AGENT_DIR${NC}"
        exit 1
    fi
}

# --- Function to clean up any existing ELK stack and Elastic Agent ---
perform_elk_cleanup() {
    echo -e "\n${YELLOW}Starting cleanup of any existing ELK stack components...${NC}"
    echo "           This may take a few minutes — Go grab a coffee!"
    echo -e "${NC}\n"

    # Detect SSH vs local TTY
    local SSH_MODE=false
    if [[ -n "${SSH_CONNECTION:-}" || -n "${SSH_CLIENT:-}" || -n "${SSH_TTY:-}" ]]; then
      SSH_MODE=true
    fi

    # Spinner (you can run long ops in background & pass their PID to this)
    spinner() {
        local pid=$1 delay=0.1 spinstr='|/-\\'
        while ps -p "$pid" > /dev/null 2>&1; do
            local temp=${spinstr#?}
            printf " [%c]  " "$spinstr"
            spinstr=$temp${spinstr%"$temp"}
            sleep $delay
            printf "\b\b\b\b\b\b"
        done
        printf "    \b\b\b\b"
    }

    # Safer unit detection + kills
    unit_present() { systemctl cat "${1}.service" >/dev/null 2>&1; }
    kill_unit_procs() {
        local svc="$1"
        sudo systemctl kill -s TERM "$svc" 2>/dev/null || true
        sleep 1
        sudo systemctl kill -s KILL "$svc" 2>/dev/null || true
    }
    # Narrow process kill patterns to avoid touching sshd
    kill_match() {
        local rx="$1" pids
        pids="$(pgrep -f "$rx" 2>/dev/null || true)"
        if [[ -n "$pids" ]]; then
            echo -e "${CYAN}Killing stray processes matching: ${rx}${NC}"
            # shellcheck disable=SC2086
            sudo kill -TERM $pids 2>/dev/null || true
            sleep 1
            # shellcheck disable=SC2086
            sudo kill -KILL $pids 2>/dev/null || true
        fi
    }

    # Stop and disable services (even if not running)
    for svc in elasticsearch logstash kibana; do
        if unit_present "$svc"; then
            echo -e "${CYAN}Stopping and disabling $svc...${NC}"
            sudo systemctl stop "$svc" 2>/dev/null || echo -e "${YELLOW}Could not stop $svc or it was not running.${NC}"
            sudo systemctl disable "$svc" 2>/dev/null || echo -e "${YELLOW}Could not disable $svc or it was not enabled.${NC}"
        else
            echo -e "${YELLOW}$svc unit not present. Skipping systemd stop...${NC}"
        fi

        # Kill lingering processes (SSH-safe sequence)
        echo -e "${CYAN}Killing any remaining $svc processes...${NC}"
        kill_unit_procs "$svc"  # scoped to the unit's cgroup

        # Tight process signatures by component
        case "$svc" in
          elasticsearch) kill_match 'org\.elasticsearch\.bootstrap\.Elasticsearch|/usr/share/elasticsearch' ;;
          logstash)      kill_match 'org\.logstash\.Logstash|/usr/share/logstash' ;;
          kibana)        kill_match '/usr/share/kibana|node .*kibana' ;;
        esac

        # As a last resort, only when NOT in SSH, fall back to the broad match you had
        if ! $SSH_MODE; then
          sudo pkill -f "$svc" 2>/dev/null || echo -e "${YELLOW}No lingering $svc processes found.${NC}"
        fi
    done

    # Elastic Agent cleanup
    echo -e "${CYAN}Checking for Elastic Agent cleanup...${NC}"
    if unit_present "elastic-agent"; then
        echo -e "${CYAN}Stopping and disabling elastic-agent...${NC}"
        sudo systemctl stop elastic-agent 2>/dev/null || true
        sudo systemctl disable elastic-agent 2>/dev/null || true
        kill_unit_procs "elastic-agent"
    fi
    if pgrep -x elastic-agent >/dev/null 2>&1; then
        echo -e "${YELLOW}Elastic Agent process detected. Terminating...${NC}"
        sudo pkill -x elastic-agent 2>/dev/null || true
        echo -e "${GREEN}✔ Elastic Agent process terminated.${NC}"
    else
        echo -e "${GREEN}No running Elastic Agent process found.${NC}"
    fi

    if [[ -d "/opt/Elastic" ]]; then
        echo -e "${YELLOW}Removing existing Elastic Agent installation at /opt/Elastic...${NC}"
        sudo rm -rf /opt/Elastic
        echo -e "${GREEN}✔ Elastic Agent directory removed successfully.${NC}"
    else
        echo -e "${GREEN}No Elastic Agent directory found at /opt/Elastic. Skipping...${NC}"
    fi

    if [[ -f "/etc/systemd/system/elastic-agent.service" ]]; then
        echo -e "${YELLOW}Found systemd unit file for Elastic Agent. Cleaning up...${NC}"
        sudo systemctl disable elastic-agent 2>/dev/null || true
        sudo rm -f /etc/systemd/system/elastic-agent.service || true
        # Reload unit files; avoid daemon-reexec over SSH
        if $SSH_MODE; then
          sudo systemctl daemon-reload || true
        else
          if [[ "${ALLOW_SYSTEMD_REEXEC:-false}" == "true" ]]; then
            sudo systemctl daemon-reexec || sudo systemctl daemon-reload || true
          else
            sudo systemctl daemon-reload || true
          fi
        fi
        echo -e "${GREEN}✔ Removed stale elastic-agent systemd service.${NC}"
    else
        echo -e "${GREEN}No elastic-agent systemd service file found. Skipping...${NC}"
    fi

    # --- Docker Cleanup for Elastic Package Registry (only if docker present) ---
    if command -v docker >/dev/null 2>&1; then
      echo -e "${CYAN}Cleaning up Elastic Package Registry Docker resources...${NC}"
      mapfile -t EPR_CONTAINERS < <(docker ps -aq --filter "ancestor=docker.elastic.co/package-registry/distribution" 2>/dev/null || true)
      if ((${#EPR_CONTAINERS[@]})); then
        echo -e "${YELLOW}Stopping and removing container(s):${NC}\n${EPR_CONTAINERS[*]}"
        docker stop "${EPR_CONTAINERS[@]}" >/dev/null 2>&1 || true
        docker rm   "${EPR_CONTAINERS[@]}" >/dev/null 2>&1 || true
        echo -e "${GREEN}✔ Containers stopped and removed.${NC}"
      else
        echo -e "${GREEN}No EPR containers found.${NC}"
      fi

      mapfile -t EPR_IMAGE_IDS < <(
        docker images --format "{{.Repository}}:{{.Tag}} {{.ID}}" 2>/dev/null \
        | awk '$1 ~ /^docker\.elastic\.co\/package-registry\/distribution:/ {print $2}' \
        | sort -u
      ) || true
      if ((${#EPR_IMAGE_IDS[@]})); then
        echo -e "${YELLOW}Removing image(s):${NC}\n${EPR_IMAGE_IDS[*]}"
        docker rmi -f "${EPR_IMAGE_IDS[@]}" >/dev/null 2>&1 \
          && echo -e "${GREEN}✔ Image(s) removed.${NC}" \
          || echo -e "${RED}⚠ Failed to remove some images.${NC}"
      else
        echo -e "${GREEN}No EPR images found. Skipping image removal...${NC}"
      fi
    else
      echo -e "${YELLOW}Docker not found. Skipping EPR Docker cleanup...${NC}"
    fi

    # Clean home directory artifacts
    echo -e "${GREEN}Scanning for stale Elastic Agent packages in home directory...${NC}"
    shopt -s nullglob
    local AGENT_TARS=( "$HOME"/elastic-agent-*-linux-*.tar.gz )
    local AGENT_DIRS=( "$HOME"/elastic-agent-*-linux-* )
    for file in "${AGENT_TARS[@]}"; do
        echo -e "${YELLOW}Removing Elastic Agent archive: $(basename "$file")${NC}"
        rm -f -- "$file" 2>/dev/null || true
    done
    for dir in "${AGENT_DIRS[@]}"; do
        if [[ -d "$dir" ]]; then
            echo -e "${YELLOW}Removing Elastic Agent directory: $(basename "$dir")${NC}"
            rm -rf -- "$dir" 2>/dev/null || true
        fi
    done
    shopt -u nullglob

    # Uninstall packages and remove residual directories (best-effort)
    echo -e "${CYAN}Attempting to uninstall Elasticsearch, Logstash, and Kibana...${NC}"
    DEBIAN_FRONTEND=noninteractive sudo apt-get purge -y elasticsearch logstash kibana >/dev/null 2>&1 || true
    DEBIAN_FRONTEND=noninteractive sudo apt-get autoremove -y >/dev/null 2>&1 || true

    local paths_to_clean=(
        /etc/elasticsearch /etc/logstash /etc/kibana
        /var/lib/elasticsearch /var/lib/logstash
        /var/log/elasticsearch /var/log/logstash /var/log/kibana
        /usr/share/elasticsearch /usr/share/logstash /usr/share/kibana
        /etc/default/elasticsearch /etc/default/logstash /etc/default/kibana
        /etc/apt/sources.list.d/elastic-8.x.list
        /etc/apt/sources.list.d/elastic-9.x.list
        /etc/systemd/system/elasticsearch.service
        /etc/systemd/system/logstash.service
        /etc/systemd/system/kibana.service
        /lib/systemd/system/elasticsearch.service
        /lib/systemd/system/logstash.service
        /lib/systemd/system/kibana.service
    )
    for path in "${paths_to_clean[@]}"; do
        if [[ -e "$path" ]]; then
            echo -e "${CYAN}Removing $path...${NC}"
            sudo rm -rf -- "$path" 2>/dev/null || true
        else
            echo -e "${YELLOW}Path not found: $path — skipping.${NC}"
        fi
    done

    # Final systemd reload (never reexec on SSH)
    if $SSH_MODE; then
      sudo systemctl daemon-reload || true
    else
      if [[ "${ALLOW_SYSTEMD_REEXEC:-false}" == "true" ]]; then
        sudo systemctl daemon-reexec || sudo systemctl daemon-reload || true
      else
        sudo systemctl daemon-reload || true
      fi
    fi

    echo -e "${GREEN}✔ Cleanup complete. Proceeding with a fresh installation.${NC}"
}



