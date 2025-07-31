#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/functions.sh"

PACKAGES_DIR="$SCRIPT_DIR/packages"
mkdir -p "$PACKAGES_DIR"

trap 'echo -e "\n${YELLOW}⚠️ Setup interrupted by user. Returning to main menu...${NC}"; pause_and_return_to_menu' SIGINT
trap - SIGINT

# Find existing packages
ES_DEB=$(find "$PACKAGES_DIR" -maxdepth 1 -type f -name "elasticsearch-*-amd64.deb" | head -n 1)
KB_DEB=$(find "$PACKAGES_DIR" -maxdepth 1 -type f -name "kibana-*-amd64.deb" | head -n 1)
LS_DEB=$(find "$PACKAGES_DIR" -maxdepth 1 -type f -name "logstash-*-amd64.deb" | head -n 1)

# Detect missing packages
MISSING_PKGS=()
[[ ! -f "$ES_DEB" ]] && MISSING_PKGS+=("elasticsearch")
[[ ! -f "$KB_DEB" ]] && MISSING_PKGS+=("kibana")
[[ ! -f "$LS_DEB" ]] && MISSING_PKGS+=("logstash")

# Handle missing packages
if (( ${#MISSING_PKGS[@]} > 0 )); then
    echo -e "${YELLOW}⚠️ Missing packages: ${MISSING_PKGS[*]}${NC}"
    read -rp "$(echo -e "${YELLOW}Download missing packages now via curl? [y/N]: ${NC}")" DOWNLOAD_CHOICE

    if [[ "$DOWNLOAD_CHOICE" =~ ^[Yy]$ ]]; then
        read -rp "$(echo -e "${YELLOW}Enter Elastic version to download (e.g., 9.1.0): ${NC}")" version
        for pkg in "${MISSING_PKGS[@]}"; do
            echo -e "${BLUE}⬇ Downloading $pkg version $version...${NC}"
            url="https://artifacts.elastic.co/downloads/${pkg}/${pkg}-${version}-amd64.deb"
            curl -L -o "${PACKAGES_DIR}/${pkg}-${version}-amd64.deb" "$url"
            echo -e "${GREEN}✔ Downloaded $pkg${NC}"
        done
        ELASTIC_VERSION="$version"
    else
        echo -e "${RED}❌ Cannot continue without required .deb packages. Exiting.${NC}"
        exit 1
    fi
else
    ES_VERSION=$(basename "$ES_DEB" | sed -n 's/elasticsearch-\(.*\)-amd64\.deb/\1/p')
    KB_VERSION=$(basename "$KB_DEB" | sed -n 's/kibana-\(.*\)-amd64\.deb/\1/p')
    LS_VERSION=$(basename "$LS_DEB" | sed -n 's/logstash-\(.*\)-amd64\.deb/\1/p')

    if [[ "$ES_VERSION" == "$KB_VERSION" && "$ES_VERSION" == "$LS_VERSION" ]]; then
        ELASTIC_VERSION="$ES_VERSION"
        echo -e "${GREEN}✔ Detected version $ELASTIC_VERSION from existing packages.${NC}"
    else
        echo -e "${RED}❌ Version mismatch between existing packages. Please verify all match.${NC}"
        exit 1
    fi
fi

# ✅ Install packages (no service enabling here)
echo -e "${CYAN}📦 Installing Elasticsearch, Kibana, and Logstash from local .deb packages...${NC}"
sudo dpkg -i "$PACKAGES_DIR/elasticsearch-${ELASTIC_VERSION}-amd64.deb"
sudo dpkg -i "$PACKAGES_DIR/kibana-${ELASTIC_VERSION}-amd64.deb"
sudo dpkg -i "$PACKAGES_DIR/logstash-${ELASTIC_VERSION}-amd64.deb"

# ✅ Validate installation
for dir in /etc/elasticsearch /etc/kibana /etc/logstash; do
    if [[ ! -d "$dir" ]]; then
        echo -e "${RED}❌ Installation failed: Missing directory $dir${NC}"
        exit 1
    fi
done

# Mark as airgap install
AIRGAP_INSTALL="true"

# Persist environment variables
ELK_ENV_FILE="$SCRIPT_DIR/.elk_env"
{
    echo "AIRGAP_INSTALL=\"$AIRGAP_INSTALL\""
    echo "ELASTIC_VERSION=\"$ELASTIC_VERSION\""
} > "$ELK_ENV_FILE"

# Final summary
add_to_summary_table "Elastic Stack Version" "$ELASTIC_VERSION"
add_to_summary_table "Airgap Install" "Yes"

echo -e "\n${GREEN}Summary of your configuration:${NC}"
print_summary_table

echo -e "${GREEN}✅ Package installation completed successfully!${NC}"
