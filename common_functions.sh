#!/bin/bash

# Color definitions
GREEN='\033[0;32m'
NC='\033[0m' # No Color
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'

# Function to show a simple loading bar
show_loading_bar() {
  local duration=$1
  local sleep_interval=0.1
  local progress=0
  local bar_length=50

  echo -ne "Progress: ["
  for ((i = 0; i < bar_length; i++)); do echo -ne " "; done # Initialize empty bar
  echo -ne "] 0%"

  while [ $progress -le 100 ]; do
    # Calculate how many '#' to print
    local num_chars=$((progress * bar_length / 100))
    echo -ne "\rProgress: ["
    for ((j = 0; j < num_chars; j++)); do echo -ne "#"; done
    for ((j = num_chars; j < bar_length; j++)); do echo -ne " "; done
    echo -ne "] $progress%"
    sleep $sleep_interval
    progress=$((progress + 100 / (duration / sleep_interval))) # Approximate progress
  done
  echo -ne "\rProgress: ["
  for ((i = 0; i < bar_length; i++)); do echo -ne "#"; done
  echo -ne "] 100%\n"
}

# Function to validate an IP address
validate_ip() {
  local ip=$1
  local stat=1

  if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
    OIFS=$IFS
    IFS='.'
    ip=($ip)
    IFS=$OIFS
    [[ ${ip[0]} -le 255 && ${ip[1]} -le 255 && \
       ${ip[2]} -le 255 && ${ip[3]} -le 255 ]]
    stat=$?
  fi
  return $stat
}

# Function to display a progress bar using pv
progress_bar() {
  local duration=$1
  local title=$2

  echo -e "${CYAN}${title}${NC}"
  seq 1 100 | pv -cN "Progress" -W -B 100 -s 100 -t -p -l -F '%p%% %b %t %r' --force | \
  awk '{print $0}' ORS='\r'
  sleep $duration
  echo -ne "\n"
}

# Function to install prerequisite packages
install_prerequisites() {
  echo -e "${YELLOW}Updating package lists...${NC}"
  sudo apt-get update > /dev/null 2>&1
  echo -e "${GREEN}Package lists updated.${NC}"

  echo -e "${YELLOW}Installing curl, apt-transport-https, unzip...${NC}"
  sudo apt-get install -y curl apt-transport-https unzip > /dev/null 2>&1
  echo -e "${GREEN}curl, apt-transport-https, unzip installed.${NC}"

  # Check if pv is installed, install if not
  if ! command -v pv &> /dev/null; then
    echo -e "${YELLOW}pv (Progress Viewer) not found. Installing...${NC}"
    sudo apt-get install -y pv > /dev/null 2>&1
    if command -v pv &> /dev/null; then
      echo -e "${GREEN}pv installed successfully.${NC}"
    else
      echo -e "${RED}Failed to install pv. Please install it manually.${NC}"
      # It's a good idea to exit here if pv is critical,
      # but for this function, we'll just inform the user.
    fi
  else
    echo -e "${GREEN}pv is already installed.${NC}"
  fi
}

# Example usage (optional - can be removed or commented out)
# if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
#   echo "Running example usage:"
#   show_loading_bar 5
#   validate_ip "192.168.1.1" && echo "Valid IP" || echo "Invalid IP"
#   validate_ip "300.168.1.1" && echo "Valid IP" || echo "Invalid IP"
#   progress_bar 3 "Simulating a task..."
#   install_prerequisites
#   echo "Common functions script finished."
# fi
