#!/bin/bash
# Common utility functions for deployment scripts

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[1;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# Display a loading/progress bar
show_loading_bar() {
    local duration=$1
    local interval=1
    local count=$((duration / interval))
    local i=0

    echo -ne "${GREEN}["
    while [ $i -lt $count ]; do
        echo -ne "#"
        sleep $interval
        ((i++))
    done
    echo -e "]${NC}"
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

# Validate username
validate_username() {
    if [[ ! "$1" =~ ^[a-zA-Z0-9_-]+$ ]]; then
        echo -e "${RED}Invalid username. Only letters, numbers, underscores (_), and dashes (-) are allowed.${NC}"
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

