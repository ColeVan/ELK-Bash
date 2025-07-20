#!/bin/bash

# Ensure the shared functions and color variables are sourced
source "$SCRIPT_DIR/functions.sh"

# --- Header ---
echo -e "${CYAN}"
echo "============================================"
echo "   🛠️  Air-Gapped Elastic Registry Setup"
echo "============================================"
echo -e "${NC}"

# --- Check for Docker ---
if ! command -v docker &> /dev/null; then
    echo -e "${YELLOW}Docker is not installed. Installing Docker via snap...${NC}"
    sudo snap install docker

    echo -e "${YELLOW}Starting Docker daemon...${NC}"
    sudo snap start docker
else
    echo -e "${GREEN}Docker is already installed.${NC}"

    # Make sure the service is running
    if ! sudo snap services docker | grep -q "active"; then
        echo -e "${YELLOW}Docker daemon is not running. Starting it now...${NC}"
        sudo snap start docker
    fi
fi

# --- Verify Docker is active before continuing ---
if ! sudo snap services docker | grep -q "active"; then
    echo -e "${RED}❌ Docker daemon is not active. Cannot proceed with registry setup.${NC}"
    exit 1
fi

# --- Pull Elastic Package Registry Image ---
ELASTIC_VERSION="$ELASTIC_VERSION"
echo -e "${GREEN}Pulling Elastic package-registry image (version ${ELASTIC_VERSION})...${NC}"
sudo docker pull "docker.elastic.co/package-registry/distribution:${ELASTIC_VERSION}"

# --- Run Registry Container ---
echo -e "${GREEN}Launching Elastic package-registry container on port 8080...${NC}"
sudo docker run -it -d -p 8080:8080 "docker.elastic.co/package-registry/distribution:${ELASTIC_VERSION}"

# --- Modify kibana.yml ---
KIBANA_YML="/etc/kibana/kibana.yml"

if [[ -f "$KIBANA_YML" ]]; then
    echo -e "${GREEN}Modifying ${CYAN}$KIBANA_YML${GREEN} with airgapped Fleet settings...${NC}"

    # Remove any existing definitions to prevent duplicates
    sudo sed -i '/^xpack\.fleet\.isAirGapped:/d' "$KIBANA_YML"
    sudo sed -i '/^xpack\.fleet\.registryUrl:/d' "$KIBANA_YML"

    # Append new settings to the end of the file
    {
        echo ""
        echo "# =================== X-Pack Fleet (Air-Gapped) ==================="
        echo "xpack.fleet.isAirGapped: true"
        echo "xpack.fleet.registryUrl: \"http://127.0.0.1:8080\""
    } | sudo tee -a "$KIBANA_YML" > /dev/null

    echo -e "${GREEN}✔ kibana.yml successfully updated.${NC}"

    # Restart and verify Kibana using existing check_service + spinner logic
    echo -e "${YELLOW}Restarting Kibana service to apply new configuration...${NC}"
    sudo systemctl restart kibana

    echo -e "${GREEN}Checking Kibana status...${NC}"
    check_service kibana
    sleep 5 & spinner

    echo -e "${YELLOW}The installation hasn't failed yet... Things look good so far, continuing forward....${NC}"
    sleep 5 & spinner
else
    echo -e "${RED}kibana.yml not found at ${KIBANA_YML}. Please check your installation path.${NC}"
    exit 1
fi

# --- Completion ---
echo -e "\n${GREEN}✅ Setup complete. Elastic package registry is running, and Kibana is configured for air-gapped Fleet.${NC}"
