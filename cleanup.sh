#!/bin/bash

# --- Path to extracted agent directory ---
AGENT_DIR="$HOME/elastic-agent-9.0.2-linux-x86_64"

# --- Header ---
echo -e "${CYAN}"
echo "========================================="
echo "   🧹 Cleaning up Extracted Agent Folder"
echo "                    AND"
echo "       Elasticsearch, Logstash, Kibana"
echo "========================================="
echo -e "${NC}"

# --- Remove extracted directory ---
if [[ -d "$AGENT_DIR" ]]; then
    echo -e "${YELLOW}Removing directory: ${CYAN}$AGENT_DIR${NC}"
    rm -rf "$AGENT_DIR"
    echo -e "${GREEN}✔ Removed extracted agent directory.${NC}"
else
    echo -e "${YELLOW}Directory not found: $AGENT_DIR — skipping.${NC}"
fi

# --- Prompt for ELK install history ---
echo -e "\n${GREEN}Has Elasticsearch, Logstash, or Kibana ever been installed on this machine before?${NC}"
read -p "$(echo -e "${GREEN}Type \"${YELLOW}yes${GREEN}\" if there is a previous installation, or \"${YELLOW}no${GREEN}\" to continue: ${NC}")" INSTALL_RESPONSE

# --- Function to clean up ELK stack and Elastic Agent ---
perform_elk_cleanup() {
	echo -e "${YELLOW}"
	echo "     (  )   (   ) "
	echo "      ) (   )  ("
	echo "      ( )  (    )"
	echo "     _____________"
	echo "   <|   ☕ Coffee |>"
	echo "   <|             |>"
	echo "     -------------"
	echo "           \\   ^__^"
	echo "            \\  (oo)\\_______"
	echo "               (__)\\       )\\/\\"
	echo "                   ||----w |"
	echo "                   ||     ||"
	echo -e "${GREEN}   This may take a few minutes — Go grab a coffee!${NC}"
	
    # Spinner function
    spinner() {
        local pid=$1
        local delay=0.1
        local spinstr='|/-\'
        while ps -p "$pid" > /dev/null 2>&1; do
            local temp=${spinstr#?}
            printf " [%c]  " "$spinstr"
            spinstr=$temp${spinstr%"$temp"}
            sleep $delay
            printf "\b\b\b\b\b\b"
        done
        printf "    \b\b\b\b"
    }

    # Stop and disable services
    for svc in elasticsearch logstash kibana; do
        if systemctl list-units --type=service | grep -q "$svc"; then
            echo -e "${CYAN}Stopping and disabling $svc...${NC}"
            sudo systemctl stop "$svc" 2>/dev/null || echo -e "${YELLOW}Could not stop $svc or it was not running.${NC}"
            sudo systemctl disable "$svc" 2>/dev/null || echo -e "${YELLOW}Could not disable $svc or it was not enabled.${NC}"
        else
            echo -e "${YELLOW}$svc service not found. Skipping systemd stop...${NC}"
        fi

        # Kill lingering processes
        echo -e "${CYAN}Killing any remaining $svc processes...${NC}"
        sudo pkill -f "$svc" 2>/dev/null || echo -e "${YELLOW}No lingering $svc processes found.${NC}"
    done

    # Elastic Agent cleanup
    echo -e "${CYAN}Checking for Elastic Agent cleanup...${NC}"
    if pgrep -f elastic-agent > /dev/null; then
        echo -e "${YELLOW}Elastic Agent process detected. Terminating...${NC}"
        sudo pkill -f elastic-agent
        echo -e "${GREEN}✔ Elastic Agent process terminated.${NC}"
    else
        echo -e "${GREEN}No running Elastic Agent process found.${NC}"
    fi

    if [ -d "/opt/Elastic" ]; then
        echo -e "${YELLOW}Removing existing Elastic Agent installation at /opt/Elastic...${NC}"
        sudo rm -rf /opt/Elastic
        echo -e "${GREEN}✔ Elastic Agent directory removed successfully.${NC}"
    else
        echo -e "${GREEN}No Elastic Agent directory found at /opt/Elastic. Skipping...${NC}"
    fi

    if [ -f "/etc/systemd/system/elastic-agent.service" ]; then
        echo -e "${YELLOW}Found systemd unit file for Elastic Agent. Cleaning up...${NC}"
        sudo systemctl disable elastic-agent 2>/dev/null || true
        sudo rm -f /etc/systemd/system/elastic-agent.service
        sudo systemctl daemon-reexec
        sudo systemctl daemon-reload
        echo -e "${GREEN}✔ Removed stale elastic-agent systemd service.${NC}"
    else
        echo -e "${GREEN}No elastic-agent systemd service file found. Skipping...${NC}"
    fi

    # Clean home directory artifacts
    echo -e "${GREEN}Scanning for stale Elastic Agent packages in home directory...${NC}"
    AGENT_TAR_PATTERN="$HOME/elastic-agent-*-linux-x86_64.tar.gz"
    AGENT_DIR_PATTERN="$HOME/elastic-agent-*-linux-x86_64"
    shopt -s nullglob

    AGENT_TARS=($AGENT_TAR_PATTERN)
    if [ ${#AGENT_TARS[@]} -gt 0 ]; then
        for file in "${AGENT_TARS[@]}"; do
            echo -e "${YELLOW}Removing Elastic Agent archive: $(basename "$file")${NC}"
            rm -f "$file"
        done
    else
        echo -e "${GREEN}No Elastic Agent tar.gz files found. Skipping archive cleanup...${NC}"
    fi

    AGENT_DIRS=($AGENT_DIR_PATTERN)
    if [ ${#AGENT_DIRS[@]} -gt 0 ]; then
        for dir in "${AGENT_DIRS[@]}"; do
            if [ -d "$dir" ]; then
                echo -e "${YELLOW}Removing Elastic Agent directory: $(basename "$dir")${NC}"
                rm -rf "$dir"
            fi
        done
    else
        echo -e "${GREEN}No Elastic Agent directories found. Skipping directory cleanup...${NC}"
    fi

    shopt -u nullglob

    # Uninstall packages and remove residual directories
    echo -e "${CYAN}Attempting to uninstall Elasticsearch, Logstash, and Kibana...${NC}"
    sudo apt-get purge -y elasticsearch logstash kibana > /dev/null 2>&1 || true
    sudo apt-get autoremove -y > /dev/null 2>&1 || true

    paths_to_clean=(
        /etc/elasticsearch /etc/logstash /etc/kibana
        /var/lib/elasticsearch /var/lib/logstash
        /var/log/elasticsearch /var/log/logstash /var/log/kibana
        /usr/share/elasticsearch /usr/share/logstash /usr/share/kibana
        /etc/apt/sources.list.d/elastic-8.x.list
        /etc/apt/sources.list.d/elastic-9.x.list
    )

    for path in "${paths_to_clean[@]}"; do
        if [ -e "$path" ]; then
            echo -e "${CYAN}Removing $path...${NC}"
            sudo rm -rf "$path"
        else
            echo -e "${YELLOW}Path not found: $path — skipping.${NC}"
        fi
    done

    echo -e "${GREEN}✔ Cleanup complete. Proceeding with a fresh installation.${NC}"
}

if [[ "$INSTALL_RESPONSE" =~ ^[Yy][Ee]?[Ss]?$ ]]; then
    perform_elk_cleanup
elif [[ "$INSTALL_RESPONSE" =~ ^[Nn][Oo]$ ]]; then
    echo -e "${YELLOW}Verifying if system is truly clean...${NC}"
    SERVICES_FOUND=false
    for svc in elasticsearch logstash kibana; do
        if systemctl list-units --type=service | grep -q "$svc"; then
            echo -e "${RED}Detected $svc service.${NC}"
            SERVICES_FOUND=true
        fi
    done

    if $SERVICES_FOUND; then
        read -p "$(echo -e "${CYAN}Clean up old ELK services before continuing? (yes/no): ${NC}")" CONFIRM_CLEANUP
        if [[ "$CONFIRM_CLEANUP" =~ ^[Yy][Ee]?[Ss]?$ ]]; then
            perform_elk_cleanup
        else
            echo -e "${RED}Cleanup skipped. Exiting.${NC}"
            exit 1
        fi
    else
        echo -e "${GREEN}System appears clean. Proceeding...${NC}"
    fi
else
    echo -e "${RED}Invalid response. Please enter \"yes\" or \"no\".${NC}"
    exit 1
fi
