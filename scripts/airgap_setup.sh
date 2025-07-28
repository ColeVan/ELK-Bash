#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/functions.sh"

PACKAGES_DIR="$SCRIPT_DIR/packages"

# Trap Ctrl+C and return to menu
trap 'echo -e "\n${YELLOW}⚠️   Setup interrupted by user. Returning to main menu...${NC}"; pause_and_return_to_menu' SIGINT
trap - SIGINT

echo -e "${GREEN}📦 Are you installing from local Elastic .deb packages (airgapped install)?${NC}"
read -rp "$(echo -e "${YELLOW}Enter 'yes' to search for packages or anything else to manually enter version: ${NC}")" INSTALL_FROM_PACKAGE

if [[ "$INSTALL_FROM_PACKAGE" =~ ^([yY][eE][sS]|[yY])$ ]]; then
    export AIRGAP_INSTALL="true"

    # Check for existence of packages directory
    if [[ ! -d "$PACKAGES_DIR" ]]; then
        echo -e "${RED}❌ 'packages/' directory not found in current working directory.${NC}"
        echo -e "${YELLOW}Please create a 'packages' directory and place the following .deb files inside it:${NC}"
        echo -e "  - elasticsearch-<version>-amd64.deb"
        echo -e "  - kibana-<version>-amd64.deb"
        echo -e "  - logstash-<version>-amd64.deb"
        exit 1
    fi

    ES_DEB=$(find "$PACKAGES_DIR" -maxdepth 1 -type f -name "elasticsearch-*-amd64.deb" | head -n 1)
    KB_DEB=$(find "$PACKAGES_DIR" -maxdepth 1 -type f -name "kibana-*-amd64.deb" | head -n 1)
    LS_DEB=$(find "$PACKAGES_DIR" -maxdepth 1 -type f -name "logstash-*-amd64.deb" | head -n 1)

    if [[ -f "$ES_DEB" && -f "$KB_DEB" && -f "$LS_DEB" ]]; then
        ES_VERSION=$(basename "$ES_DEB" | sed -n 's/elasticsearch-\(.*\)-amd64\.deb/\1/p')
        KB_VERSION=$(basename "$KB_DEB" | sed -n 's/kibana-\(.*\)-amd64\.deb/\1/p')
        LS_VERSION=$(basename "$LS_DEB" | sed -n 's/logstash-\(.*\)-amd64\.deb/\1/p')

        if [[ "$ES_VERSION" == "$KB_VERSION" && "$ES_VERSION" == "$LS_VERSION" ]]; then
            ELASTIC_VERSION="$ES_VERSION"
            echo -e "${GREEN}✔ Detected version $ELASTIC_VERSION from .deb packages in ./packages.${NC}"
            add_to_summary_table "Elastic Stack Version" "$ELASTIC_VERSION"
            add_to_summary_table "Airgap Install" "Yes"
        else
            echo -e "${RED}❌ Version mismatch between packages. Please verify that all package versions match.${NC}"
            exit 1
        fi
    else
        echo -e "${RED}❌ One or more required packages were not found in the 'packages/' directory.${NC}"
        echo -e "${YELLOW}Please download the following packages and place them in '${PACKAGES_DIR}':${NC}"
        echo -e "  - Elasticsearch: ${BLUE}https://www.elastic.co/downloads/elasticsearch${NC}"
        echo -e "  - Kibana:        ${BLUE}https://www.elastic.co/downloads/kibana${NC}"
        echo -e "  - Logstash:      ${BLUE}https://www.elastic.co/downloads/logstash${NC}"
        exit 1
    fi
else
    export AIRGAP_INSTALL="false"
    # Prompt in a loop until valid version is entered
    while true; do
        read -p "$(echo -e "${GREEN}Enter the Elastic Stack version to install ${YELLOW}(e.g., 8.18.2 or 9.0.2)${GREEN}: ${NC}")" ELASTIC_VERSION
        if validate_version "$ELASTIC_VERSION"; then
            echo -e "${GREEN}✔ Version '${ELASTIC_VERSION}' is valid and has been accepted.${NC}"
            add_to_summary_table "Elastic Stack Version" "$ELASTIC_VERSION"
            add_to_summary_table "Airgap Install" "No"
            break
        else
            echo -e "${RED}❌ Invalid version format. Please enter something like 8.18.2.${NC}"
        fi
    done
fi

# Optional: Persist to .elk_env for later use
ELK_ENV_FILE="$SCRIPT_DIR/.elk_env"
echo "AIRGAP_INSTALL=\"$AIRGAP_INSTALL\"" >> "$ELK_ENV_FILE"
echo "ELASTIC_VERSION=\"$ELASTIC_VERSION\"" >> "$ELK_ENV_FILE"

# Final table
echo -e "\n${GREEN}Summary of your configuration:${NC}"
print_summary_table
