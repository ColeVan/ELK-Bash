#!/usr/bin/env bash
# nsm_policy_create_and_remote_enroll_scp.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
PACKAGES_DIR="${PACKAGES_DIR:-$SCRIPT_DIR/packages}"
ELK_ENV_FILE="${ELK_ENV_FILE:-$SCRIPT_DIR/.elk_env}"

# ------------------------------------------------------
# Colors
# ------------------------------------------------------
: "${GREEN:=$'\e[32m'}"; : "${YELLOW:=$'\e[33m'}"; : "${RED:=$'\e[31m'}"
: "${BLUE:=$'\e[34m'}";  : "${CYAN:=$'\e[36m'}";   : "${NC:=$'\e[0m'}"

# ------------------------------------------------------
# Minimal .elk_env loader (KEY=VAL with basic quoting)
# ------------------------------------------------------
if [[ -f "$ELK_ENV_FILE" ]]; then
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%$'\r'}"
    [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
    if [[ "$line" =~ ^([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*=(.*)$ ]]; then
      key="${BASH_REMATCH[1]}"; raw="${BASH_REMATCH[2]}"
      raw="${raw#"${raw%%[![:space:]]*}"}"
      if   [[ "$raw" =~ ^\"(.*)\"$ ]]; then val="${BASH_REMATCH[1]}"
      elif [[ "$raw" =~ ^\'(.*)\'$ ]]; then val="${BASH_REMATCH[1]}"
      else val="$raw"; fi
      printf -v val_escaped '%q' "$val"
      eval "export ${key}=${val_escaped}"
    fi
  done < "$ELK_ENV_FILE"
fi

persist_kv_safe() {
  local f="$1" key="$2" val="$3"
  mkdir -p "$(dirname "$f")"
  if [[ -f "$f" ]]; then
    sed -i -E "s|^[[:space:]]*${key}=.*$||" "$f"
    sed -i -E '/^[[:space:]]*$/N;/^\n$/D' "$f" 2>/dev/null || true
  fi
  printf '%s="%s"\n' "$key" "$val" >> "$f"
}

# ------------------------------------------------------
# Prompts (with fallbacks to any existing env)
# ------------------------------------------------------
read -rp "Enter Elastic host (hostname or IP, no scheme) [${ELASTIC_HOST:-}]: " ELASTIC_HOST_IN
ELASTIC_HOST="${ELASTIC_HOST_IN:-${ELASTIC_HOST:-}}"
[[ -n "$ELASTIC_HOST" ]] || { echo -e "${RED}Elastic host is required.${NC}"; exit 1; }

read -rp "Enter username [${USERNAME:-}]: " USERNAME_IN
USERNAME="${USERNAME_IN:-${USERNAME:-}}"
[[ -n "$USERNAME" ]] || { echo -e "${RED}Username is required.${NC}"; exit 1; }

read -srp "Enter password: " PASSWORD
echo ""

read -rp "Fleet Server host (ENTER to use ${ELASTIC_HOST}) [${FLEET_SERVER_HOST:-}]: " FLEET_HOST_IN
FLEET_HOST="${FLEET_HOST_IN:-${FLEET_SERVER_HOST:-$ELASTIC_HOST}}"

read -rp "Policy name [${POLICY_NAME:-network monitoring}]: " POLICY_NAME_IN
POLICY_NAME="${POLICY_NAME_IN:-${POLICY_NAME:-network monitoring}}"

read -rp "Policy description [${POLICY_DESCRIPTION:-Networking Monitoring Policy}]: " POLICY_DESC_IN
POLICY_DESCRIPTION="${POLICY_DESC_IN:-${POLICY_DESCRIPTION:-Networking Monitoring Policy}}"

read -rp "Policy namespace [${POLICY_NAMESPACE:-default}]: " POLICY_NS_IN
POLICY_NAMESPACE="${POLICY_NS_IN:-${POLICY_NAMESPACE:-default}}"

read -rp "Should this policy host Fleet Server? (y/N) [${HAS_FLEET_SERVER:-}]: " HAS_FS_IN
case "${HAS_FS_IN,,}" in y|yes) HAS_FLEET_SERVER=true ;; "") HAS_FLEET_SERVER="${HAS_FLEET_SERVER:-false}" ;; *) HAS_FLEET_SERVER=false ;; esac

read -rp "Integrations to add (comma-separated; empty for none) [${PACKAGES_TO_ADD:-system}]: " PKGS_IN
if [[ -z "${PKGS_IN// }" ]]; then
  PACKAGES_TO_ADD="${PACKAGES_TO_ADD:-system}"
else
  PACKAGES_TO_ADD="$PKGS_IN"
fi

read -rp "NSM host(s) to enroll (comma-separated hostnames/IPs) [${NSM_TARGETS:-}]: " HOSTS_CSV_IN
HOSTS_CSV="${HOSTS_CSV_IN:-${NSM_TARGETS:-}}"
[[ -n "$HOSTS_CSV" ]] || { echo -e "${RED}At least one NSM host is required.${NC}"; exit 1; }

read -rp "SSH user [${SSH_USER:-root}]: " SSH_USER_IN
SSH_USER="${SSH_USER_IN:-${SSH_USER:-root}}"

read -rp "SSH port [${SSH_PORT:-22}]: " SSH_PORT_IN
SSH_PORT="${SSH_PORT_IN:-${SSH_PORT:-22}}"

read -rp "SSH private key path [${SSH_KEY:-$HOME/.ssh/id_ed25519}]: " SSH_KEY_IN
SSH_KEY="${SSH_KEY_IN:-${SSH_KEY:-$HOME/.ssh/id_ed25519}}"

read -rp "Elastic Agent version to install (e.g., 9.1.3) [${ELASTIC_AGENT_VERSION:-}]: " VERSION_IN
VERSION="${VERSION_IN:-${ELASTIC_AGENT_VERSION:-}}"

# ------------------------------------------------------
# Ports & constants
# ------------------------------------------------------
ES_PORT=9200
KB_PORT=443
FLEET_HOST="${FLEET_HOST#http://}"; FLEET_HOST="${FLEET_HOST#https://}"
FLEET_HOST="${FLEET_HOST%%/*}"; FLEET_HOST="${FLEET_HOST%%:*}"
FLEET_URL="https://${FLEET_HOST}:8220"

# ------------------------------------------------------
# Pre-flight checks
# ------------------------------------------------------
for b in curl jq ssh scp sed awk; do
  command -v "$b" >/dev/null 2>&1 || { echo -e "${RED}Missing required binary: $b${NC}"; exit 1; }
done
[[ -r "$SSH_KEY" ]] || { echo -e "${RED}SSH key not readable: ${SSH_KEY}${NC}"; exit 1; }
mkdir -p "$PACKAGES_DIR"

# ------------------------------------------------------
# Helper: Kibana API
# ------------------------------------------------------
kb() {
  local method="$1"; shift
  local path="$1"; shift
  curl --silent --show-error --fail --insecure \
    --request "$method" \
    --url "https://${ELASTIC_HOST}:${KB_PORT}${path}" \
    --header 'Accept: */*' \
    --header 'Content-Type: application/json' \
    --header 'kbn-xsrf: xxx' \
    --header "Authorization: Bearer ${api_access_token}" \
    "$@"
}

# ------------------------------------------------------
# 1) Obtain OAuth2 access token
# ------------------------------------------------------
echo -e "${GREEN}Obtaining OAuth2 access token...${NC}"
ACCESS_TOKEN_JSON=$(curl --silent --show-error --fail --insecure \
  --request POST \
  --url "https://${ELASTIC_HOST}:${ES_PORT}/_security/oauth2/token" \
  -u "${USERNAME}:${PASSWORD}" \
  --header 'Content-Type: application/json' \
  --data '{
    "grant_type": "password",
    "username": "'"${USERNAME}"'",
    "password": "'"${PASSWORD}"'"
  }')
api_access_token=$(echo "$ACCESS_TOKEN_JSON" | jq -r '.access_token // empty')
[[ -n "$api_access_token" ]] || { echo -e "${RED}Failed to obtain access token.${NC}"; echo "$ACCESS_TOKEN_JSON"; exit 1; }
echo -e "${GREEN}Access token obtained successfully.${NC}"

# ------------------------------------------------------
# 2) Ensure Fleet policy exists (create if missing)
# ------------------------------------------------------
echo -e "${BLUE}Ensuring Fleet policy '${POLICY_NAME}' exists...${NC}"
existing=$(kb GET "/api/fleet/agent_policies" | jq -c --arg n "$POLICY_NAME" '.items[]? | select(.name == $n)' || true)
if [[ -n "$existing" ]]; then
  fleet_policy_id=$(echo "$existing" | jq -r '.id')
  echo -e "${YELLOW}Policy already exists.${NC} ID: ${fleet_policy_id}"
else
  create_policy_payload=$(jq -nc --arg name "$POLICY_NAME" \
                               --arg desc "$POLICY_DESCRIPTION" \
                               --arg ns "$POLICY_NAMESPACE" \
                               --argjson has_fs "$HAS_FLEET_SERVER" '
    { name:$name, description:$desc, namespace:$ns,
      monitoring_enabled:["logs","metrics"], has_fleet_server:$has_fs }')
  create_policy_resp=$(kb POST "/api/fleet/agent_policies?sys_monitoring=true" --data "$create_policy_payload")
  fleet_policy_id=$(echo "$create_policy_resp" | jq -r '.item.id // empty')
  [[ -n "$fleet_policy_id" ]] || { echo -e "${RED}Failed to create policy.${NC}"; echo "$create_policy_resp"; exit 1; }
  echo -e "${YELLOW}Policy created.${NC} ID: ${fleet_policy_id}"
fi

# ------------------------------------------------------
# 3) (Optional) Install packages & attach to policy
# ------------------------------------------------------
IFS=',' read -r -a PKGS_ARR <<< "$PACKAGES_TO_ADD"
trim() { echo -n "$1" | awk '{$1=$1;print}'; }

install_and_attach_package() {
  local pkg="$(trim "$1")"
  [[ -n "$pkg" ]] || return 0
  echo -e "${BLUE}Adding integration '${pkg}'…${NC}"
  pkg_info=$(kb GET "/api/fleet/epm/packages/${pkg}" || true)
  pkg_version=$(echo "$pkg_info" | jq -r '.item.version // empty')
  pkg_title=$(echo "$pkg_info" | jq -r '.item.title   // empty')
  if [[ -z "$pkg_version" ]]; then
    echo -e "${YELLOW}Package '${pkg}' not found. Skipping.${NC}"
    return 0
  fi
  kb POST "/api/fleet/epm/packages/${pkg}/${pkg_version}" >/dev/null || true
  pkg_policy_name="${pkg}-on-${POLICY_NAME// /-}"
  pkg_policy_payload=$(jq -nc --arg policy_id "$fleet_policy_id" \
                               --arg name "$pkg_policy_name" \
                               --arg ns "$POLICY_NAMESPACE" \
                               --arg pkg "$pkg" \
                               --arg ver "$pkg_version" \
                               --arg title "$pkg_title" '
    { name:$name, description:"", namespace:$ns, policy_id:$policy_id,
      package:{name:$pkg, title:$title, version:$ver} }')
  add_resp=$(kb POST "/api/fleet/package_policies" --data "$pkg_policy_payload" || true)
  if [[ -n "$(echo "$add_resp" | jq -r '.item.id // empty')" ]]; then
    echo -e "${GREEN}Attached '${pkg}'.${NC}"
  else
    echo -e "${YELLOW}Could not attach '${pkg}' (maybe already attached).${NC}"
  fi
}

if (( ${#PKGS_ARR[@]} > 0 )); then
  for pkg in "${PKGS_ARR[@]}"; do install_and_attach_package "$pkg"; done
fi

# ------------------------------------------------------
# 4) Create enrollment token for the policy
# ------------------------------------------------------
echo -e "${BLUE}Creating enrollment API key…${NC}"
enroll_payload=$(jq -nc --arg pid "$fleet_policy_id" '{policy_id: $pid}')
enroll_resp=$(kb POST "/api/fleet/enrollment_api_keys" --data "$enroll_payload")
enrollment_key=$(echo "$enroll_resp" | jq -r '.item.api_key // empty')
enrollment_id=$(echo  "$enroll_resp" | jq -r '.item.id     // empty')
[[ -n "$enrollment_key" ]] || { echo -e "${RED}Failed to create enrollment API key.${NC}"; echo "$enroll_resp"; exit 1; }

echo -e "${GREEN}Enrollment token created.${NC}"
echo -e "${YELLOW}Token ID:${NC} $enrollment_id"
echo -e "${YELLOW}Enrollment Token:${NC} $enrollment_key"
echo -e "${BLUE}Fleet URL:${NC} $FLEET_URL"

# Persist for continuity
persist_kv_safe "$ELK_ENV_FILE" "ELASTIC_HOST" "$ELASTIC_HOST"
persist_kv_safe "$ELK_ENV_FILE" "FLEET_SERVER_HOST" "$FLEET_HOST"
persist_kv_safe "$ELK_ENV_FILE" "NSM_FLEET_SERVER_HOST" "$FLEET_HOST"
persist_kv_safe "$ELK_ENV_FILE" "NSM_ENROLLMENT_TOKEN" "$enrollment_key"
persist_kv_safe "$ELK_ENV_FILE" "POLICY_NAME" "$POLICY_NAME"
persist_kv_safe "$ELK_ENV_FILE" "POLICY_NAMESPACE" "$POLICY_NAMESPACE"

# ------------------------------------------------------
# 5) Local tarball selection / download (once), then SCP per host
# ------------------------------------------------------
# Detect local arch tarball needs per remote host (we’ll choose per-remote arch)
echo -e "${BLUE}Preparing Elastic Agent tarballs in ${PACKAGES_DIR}…${NC}"

download_agent_tarball() {
  local version="$1" arch_label="$2" alt_label="$3"
  local base="elastic-agent-${version}-linux-${arch_label}.tar.gz"
  local target="$PACKAGES_DIR/$base"
  local url_primary="https://artifacts.elastic.co/downloads/beats/elastic-agent/$base"
  if [[ -f "$target" ]]; then echo "$target"; return 0; fi
  echo -e "${GREEN}Downloading ${base}…${NC}"
  if curl -fSLk "$url_primary" -o "$target"; then
    echo "$target"; return 0
  fi
  if [[ -n "$alt_label" ]]; then
    local alt="elastic-agent-${version}-linux-${alt_label}.tar.gz"
    local target_alt="$PACKAGES_DIR/$alt"
    local url_alt="https://artifacts.elastic.co/downloads/beats/elastic-agent/$alt"
    echo -e "${YELLOW}Primary failed, trying alt ${alt_label}…${NC}"
    if curl -fSLk "$url_alt" -o "$target_alt"; then
      echo "$target_alt"; return 0
    fi
  fi
  return 1
}

[[ -n "$VERSION" ]] || { read -rp "Elastic Agent version to download (e.g., 9.1.3): " VERSION; [[ -n "$VERSION" ]] || { echo -e "${RED}Version required.${NC}"; exit 1; }; }

IFS=',' read -r -a HOSTS <<< "$HOSTS_CSV"

# ------------------------------------------------------
# 6) For each host: detect arch, pick tarball, SCP, remote install using token
# ------------------------------------------------------
remote_installer='
#!/usr/bin/env bash
set -euo pipefail
RDIR="${1:-/tmp}"
FLEET_URL="${2:?fleet_url}"
TOKEN="${3:?token}"
# Extract
tar xzf "$RDIR/agent.tgz" -C "$RDIR"
cd "$(ls -1d "$RDIR"/elastic-agent-* | head -n1)"
# Install
if [ "$(id -u)" -eq 0 ]; then
  ./elastic-agent install --non-interactive --url="$FLEET_URL" --enrollment-token="$TOKEN" --insecure
elif sudo -n true 2>/dev/null; then
  sudo -n ./elastic-agent install --non-interactive --url="$FLEET_URL" --enrollment-token="$TOKEN" --insecure
else
  tries=0
  while : ; do
    tries=$((tries+1))
    read -srp "Sudo password for $USER: " sudopw </dev/tty; echo
    if printf "%s\n" "$sudopw" | sudo -S -p "" true 2>/dev/null; then
      if printf "%s\n" "$sudopw" | sudo -S -p "" ./elastic-agent install --non-interactive --url="$FLEET_URL" --enrollment-token="$TOKEN" --insecure; then
        unset sudopw; break
      else
        unset sudopw; echo "sudo command failed." >&2; exit 1
      fi
    else
      unset sudopw; echo "Sorry, try again." >&2
      [ "$tries" -ge 3 ] && { echo "sudo authentication failed"; exit 1; }
    fi
  done
fi
'

NSM_ENROLLED_HOSTS="${NSM_ENROLLED_HOSTS:-}"

echo -e "${BLUE}Starting remote installs…${NC}"
for H in "${HOSTS[@]}"; do
  host="$(echo "$H" | awk '{$1=$1;print}')"   # trim
  [[ -z "$host" ]] && continue
  echo -e "${CYAN}→ ${host}${NC}"

  # 1) Detect remote arch
  uname_m="$(ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p "$SSH_PORT" \
             "${SSH_USER}@${host}" "uname -m" 2>/dev/null || true)"
  case "$uname_m" in
    aarch64|arm64) arch_label_primary="arm64"; arch_label_alt="aarch64" ;;
    x86_64|amd64|"") arch_label_primary="x86_64"; arch_label_alt="" ;;
    *) arch_label_primary="x86_64"; arch_label_alt=""; echo -e "${YELLOW}${host}: unknown arch '${uname_m}', defaulting to x86_64${NC}";;
  esac

  # 2) Ensure local tarball exists (download if missing)
  tarball=""
  # Try exact
  if [[ -n "$VERSION" ]]; then
    for lbl in "$arch_label_primary" "$arch_label_alt"; do
      [[ -z "$lbl" ]] && continue
      candidate="$PACKAGES_DIR/elastic-agent-${VERSION}-linux-${lbl}.tar.gz"
      [[ -f "$candidate" ]] && { tarball="$candidate"; break; }
    done
  fi
  # Try latest downloaded for arch
  if [[ -z "$tarball" ]]; then
    for lbl in "$arch_label_primary" "$arch_label_alt"; do
      [[ -z "$lbl" ]] && continue
      found="$(find "$PACKAGES_DIR" -maxdepth 1 -type f -name "elastic-agent-*-linux-${lbl}.tar.gz" -printf "%T@ %p\n" 2>/dev/null | sort -nr | awk '{print $2}' | head -n1 || true)"
      [[ -n "$found" ]] && { tarball="$found"; break; }
    done
  fi
  # Download if still missing
  if [[ -z "$tarball" ]]; then
    if pth="$(download_agent_tarball "$VERSION" "$arch_label_primary" "$arch_label_alt")"; then
      tarball="$pth"
    else
      echo -e "${RED}${host}: failed to obtain agent tarball for ${arch_label_primary}/${arch_label_alt}.${NC}"
      exit 1
    fi
  fi

  echo -e "${GREEN}${host}: using tarball ${tarball##*/}${NC}"

  # 3) Copy tarball + remote installer, then execute
  rdir="/tmp/ea_nsm.$$.$RANDOM"
  ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p "$SSH_PORT" \
      "${SSH_USER}@${host}" "mkdir -p '$rdir'"

  scp -i "$SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -P "$SSH_PORT" \
      "$tarball" "${SSH_USER}@${host}:$rdir/agent.tgz"

  printf '%s\n' "$remote_installer" > "$SCRIPT_DIR/.install_remote.tmp"
  scp -i "$SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -P "$SSH_PORT" \
      "$SCRIPT_DIR/.install_remote.tmp" "${SSH_USER}@${host}:$rdir/install_remote.sh"
  rm -f "$SCRIPT_DIR/.install_remote.tmp"

  echo -e "${CYAN}${host}:${NC} installing agent…"
  ssh -tt -i "$SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p "$SSH_PORT" \
      "${SSH_USER}@${host}" "bash -lc 'bash \"$rdir/install_remote.sh\" \"$rdir\" \"$FLEET_URL\" \"$enrollment_key\"'"

  echo -e "${GREEN}✔ Installed on ${host}${NC}"

  # 4) Track enrolled hosts in .elk_env
  case ",${NSM_ENROLLED_HOSTS}," in
    *,"$host",*) ;; # already present
    *) NSM_ENROLLED_HOSTS="${NSM_ENROLLED_HOSTS:+${NSM_ENROLLED_HOSTS},}$host" ;;
  esac
  persist_kv_safe "$ELK_ENV_FILE" "NSM_ENROLLED_HOSTS" "$NSM_ENROLLED_HOSTS"
done

# Also persist convenience keys
persist_kv_safe "$ELK_ENV_FILE" "NSM_FLEET_SERVER_HOST" "$FLEET_HOST"
persist_kv_safe "$ELK_ENV_FILE" "NSM_ENROLLMENT_TOKEN" "$enrollment_key"
persist_kv_safe "$ELK_ENV_FILE" "ELASTIC_AGENT_VERSION" "$VERSION"
persist_kv_safe "$ELK_ENV_FILE" "NSM_TARGETS" "$HOSTS_CSV"

echo -e "${GREEN}All requested NSM sensor hosts processed.${NC}"
echo -e "${BLUE}Manual enroll (fallback) example:${NC}"
echo "sudo elastic-agent enroll --url=${FLEET_URL} --enrollment-token ${enrollment_key} --insecure"
