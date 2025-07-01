#!/bin/bash
# Common utility functions for deployment scripts

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[1;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

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

# Spinner for background tasks
spinner() {
    local pid=$!
    local delay=0.1
    local spinstr='|/-\\'
    local msg="$1"
    echo -ne "${BLUE}${msg}...${NC} "
    while [ "$(ps a | awk '{print $1}' | grep "$pid")" ]; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    echo " [✔]"
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


