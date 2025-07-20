#!/bin/bash
# Common utility functions for deployment scripts

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[1;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

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
  local msg="$1"

  printf "%s " "$msg"

  while ps -p $pid > /dev/null 2>&1; do
    for i in $(echo $spinstr | fold -w1); do
      printf "\r%s %s" "$msg" "$i"
      sleep $delay
    done
  done

  printf "\r%s [✔]\n" "$msg"
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

# Render the table nicely (ASCII-safe)
print_summary_table() {
  local border="-"
  local corner="+"

  # Find max widths
  local max_key=0
  local max_val=0
  for row in "${SUMMARY_TABLE[@]}"; do
    IFS='|' read -r key val <<< "$row"
    [[ ${#key} -gt $max_key ]] && max_key=${#key}
    [[ ${#val} -gt $max_val ]] && max_val=${#val}
  done

  local total=$((max_key + max_val + 7))

  # Top border
  printf '%s' "$corner"
  printf '%*s' $total '' | tr ' ' "$border"
  printf '%s\n' "$corner"

  # Header
  printf "| %-*s | %-*s |\n" $max_key "Input" $max_val "Value"

  # Header bottom border
  printf '%s' "$corner"
  printf '%*s' $total '' | tr ' ' "$border"
  printf '%s\n' "$corner"

  # Rows
  for row in "${SUMMARY_TABLE[@]}"; do
    IFS='|' read -r key val <<< "$row"
    printf "| %-*s | %-*s |\n" $max_key "$key" $max_val "$val"
  done

  # Bottom border
  printf '%s' "$corner"
  printf '%*s' $total '' | tr ' ' "$border"
  printf '%s\n' "$corner"
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

