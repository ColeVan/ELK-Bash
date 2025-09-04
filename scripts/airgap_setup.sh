#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
: "${PACKAGES_DIR:=$SCRIPT_DIR/packages}"
mkdir -p "$PACKAGES_DIR"

# Load helpers/colors if present
if [[ -f "$SCRIPT_DIR/functions.sh" ]]; then
  # shellcheck source=/dev/null
  source "$SCRIPT_DIR/functions.sh"
fi
: "${GREEN:=$'\e[32m'}"; : "${YELLOW:=$'\e[33m'}"; : "${RED:=$'\e[31m'}"
: "${CYAN:=$'\e[36m'}";  : "${NC:=$'\e[0m'}"; : "${DIM:=$'\e[2m'}"

ELK_ENV_FILE="$SCRIPT_DIR/.elk_env"
ARCH="amd64"
PRODUCTS=("elasticsearch" "kibana" "logstash")

# ------------- Traps -------------
trap 'echo -e "\n${YELLOW}⚠️ Setup interrupted by user. Returning to main menu...${NC}"; type pause_and_return_to_menu &>/dev/null && pause_and_return_to_menu || true' SIGINT
trap - SIGINT

# ------------- Helpers -------------
has_file() { [[ -f "$1" && -s "$1" ]]; }

pkg_path() { # pkg_path <product> <version>
  local p="$1" v="$2"
  echo "${PACKAGES_DIR}/${p}-${v}-${ARCH}.deb"
}

find_local_versions_for() { # find_local_versions_for <product>
  local p="$1"
  find "$PACKAGES_DIR" -maxdepth 1 -type f -name "${p}-*- ${ARCH}.deb" -print 2>/dev/null | sed 's/  */ /g' >/dev/null || true
}

list_versions_for() { # list_versions_for <product>
  local p="$1"
  # Extract version portion elasticsearch-<ver>-amd64.deb
  find "$PACKAGES_DIR" -maxdepth 1 -type f -name "${p}-*-$(printf %q "$ARCH").deb" \
    -printf "%f\n" 2>/dev/null \
    | sed -n "s/${p}-\(.*\)-${ARCH}\.deb/\1/p" \
    | sort -Vu
}

all_local_versions_union() {
  # union of versions available for any of the three products
  { list_versions_for "elasticsearch"
    list_versions_for "kibana"
    list_versions_for "logstash"; } \
  | sort -Vu
}

have_full_set_locally() { # have_full_set_locally <version>
  local v="$1"
  for p in "${PRODUCTS[@]}"; do
    has_file "$(pkg_path "$p" "$v")" || return 1
  done
  return 0
}

download_pkg() { # download_pkg <product> <version>
  local p="$1" v="$2"
  local url="https://artifacts.elastic.co/downloads/${p}/${p}-${v}-${ARCH}.deb"
  local out; out="$(pkg_path "$p" "$v")"
  echo -e "${CYAN}⬇ Downloading ${p} ${v} ...${NC}"
  if ! curl -fL --progress-bar -o "$out" "$url"; then
    echo -e "${RED}❌ Failed to download ${p} ${v} from:${NC} ${DIM}$url${NC}"
    return 1
  fi
  if ! has_file "$out"; then
    echo -e "${RED}❌ Downloaded file missing or empty: ${out}${NC}"
    return 1
  fi
  echo -e "${GREEN}✔ Downloaded ${p} ${v}${NC}"
}

download_full_set() { # download_full_set <version>
  local v="$1" p
  for p in "${PRODUCTS[@]}"; do
    download_pkg "$p" "$v"
  done
}

detect_existing_versions_triplet() {
  local es kb ls
  es="$(list_versions_for elasticsearch | tail -n1 || true)"
  kb="$(list_versions_for kibana | tail -n1 || true)"
  ls="$(list_versions_for logstash | tail -n1 || true)"
  echo "$es|$kb|$ls"
}

prompt_version() { # sets ELASTIC_VERSION
  local prompt="${YELLOW}Enter Elastic version (e.g., 9.1.3): ${NC}"
  if type prompt_input &>/dev/null; then
    prompt_input "$(echo -e "$prompt")" ELASTIC_VERSION
  else
    read -rp "$(echo -e "$prompt")" ELASTIC_VERSION
  fi
  [[ -n "${ELASTIC_VERSION:-}" ]] || { echo -e "${RED}Version cannot be empty.${NC}"; prompt_version; }
}

confirm() { # confirm "<question>"
  local q="$1" ans=""
  read -rp "$(echo -e "${YELLOW}${q} [y/N]: ${NC}")" ans || true
  [[ "$ans" =~ ^[Yy]$ ]]
}

install_local_set() { # install_local_set <version>
  local v="$1"
  echo -e "${CYAN}📦 Installing Elasticsearch, Kibana, and Logstash ${v} from local .deb packages...${NC}"
  sudo dpkg -i "$(pkg_path elasticsearch "$v")"
  sudo dpkg -i "$(pkg_path kibana "$v")"
  sudo dpkg -i "$(pkg_path logstash "$v")"

  # Validate installs created expected dirs
  local ok=1
  for dir in /etc/elasticsearch /etc/kibana /etc/logstash; do
    if [[ ! -d "$dir" ]]; then
      echo -e "${RED}❌ Installation failed: Missing directory $dir${NC}"
      ok=0
    fi
  done
  (( ok == 1 )) || exit 1
}

persist_env() {
  local v="$1"
  local AIRGAP_INSTALL="true"
  {
    echo "AIRGAP_INSTALL=\"$AIRGAP_INSTALL\""
    echo "ELASTIC_VERSION=\"$v\""
  } > "$ELK_ENV_FILE"
}

summarize() {
  local v="$1"
  type add_to_summary_table &>/dev/null && add_to_summary_table "Elastic Stack Version" "$v" || true
  type add_to_summary_table &>/dev/null && add_to_summary_table "Airgap Install" "Yes" || true
  echo -e "\n${GREEN}Summary of your configuration:${NC}"
  type print_summary_table &>/dev/null && print_summary_table || echo -e "  Version: $v\n  Airgap: Yes"
  echo -e "${GREEN}✅ Package installation completed successfully!${NC}"
}

# ------------- Flow -------------

echo -e "${CYAN}Elastic Offline Installer (airgapped)${NC}"
echo -e "${DIM}Packages dir:${NC} $PACKAGES_DIR"
echo

# 1) Ask for the desired version
prompt_version

# 2) If we already have all three locally, use them
if have_full_set_locally "$ELASTIC_VERSION"; then
  echo -e "${GREEN}✔ Found local packages for ${ELASTIC_VERSION}.${NC}"
else
  echo -e "${YELLOW}⚠ Not all packages for ${ELASTIC_VERSION} are present locally.${NC}"

  # 2a) Show what we *do* have (all versions we can see)
  echo -e "${CYAN}Local package versions discovered:${NC}"
  union="$(all_local_versions_union || true)"
  if [[ -n "$union" ]]; then
    echo "$union" | nl -w2 -s'. '
  else
    echo -e "${DIM}(none found)${NC}"
  fi
  echo

  # 2b) If the desired version exists partially, offer to switch to a local full version
  #     Ask user: "Use any of the above versions instead?"
  if [[ -n "$union" ]]; then
    if confirm "Use one of the above local versions instead of downloading ${ELASTIC_VERSION}?"; then
      # Prompt to choose a version from the list
      local_choice=""
      while [[ -z "${local_choice:-}" ]]; do
        read -rp "$(echo -e "${YELLOW}Enter a version from the list (or press Enter to cancel): ${NC}")" local_choice || true
        [[ -z "$local_choice" ]] && break
        if echo "$union" | grep -Fxq "$local_choice"; then
          if have_full_set_locally "$local_choice"; then
            ELASTIC_VERSION="$local_choice"
            echo -e "${GREEN}✔ Using local version ${ELASTIC_VERSION}.${NC}"
          else
            echo -e "${RED}Local files for ${local_choice} are incomplete (not all three).${NC}"
            local_choice=""
            continue
          fi
        else
          echo -e "${RED}Version not in the list. Try again.${NC}"
          local_choice=""
        fi
      done
    fi
  fi

  # 2c) If we still don’t have a full local set, offer to download the requested version
  if ! have_full_set_locally "$ELASTIC_VERSION"; then
    echo -e "${YELLOW}Proceed to download ${ELASTIC_VERSION} for all components?${NC}"
    if confirm "Download now"; then
      download_full_set "$ELASTIC_VERSION" || {
        echo -e "${RED}❌ Download failed. Aborting.${NC}"
        exit 1
      }
    else
      echo -e "${RED}❌ Cannot continue without a complete local set. Exiting.${NC}"
      exit 1
    fi
  fi
fi

# 3) Install from local set
install_local_set "$ELASTIC_VERSION"

# 4) Persist + summarize
persist_env "$ELASTIC_VERSION"
summarize "$ELASTIC_VERSION"
