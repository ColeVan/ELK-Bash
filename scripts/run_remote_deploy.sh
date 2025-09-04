#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"

# Optional colors/logging
if [[ -f "$SCRIPT_DIR/functions.sh" ]]; then
  # shellcheck source=/dev/null
  source "$SCRIPT_DIR/functions.sh"
  type init_colors >/dev/null 2>&1 && init_colors || true
fi
: "${GREEN:=$'\e[32m'}"; : "${YELLOW:=$'\e[33m'}"; : "${RED:=$'\e[31m'}"
: "${CYAN:=$'\e[36m'}";  : "${NC:=$'\e[0m'}"

SCRIPT_NAME="deploy_elasticsearch_node.sh"
LOCAL_SCRIPT="$SCRIPT_DIR/$SCRIPT_NAME"
LOCAL_FUNCS="$SCRIPT_DIR/functions.sh"
TOKEN_FILE="${TOKEN_FILE:-$SCRIPT_DIR/enrollment_tokens.txt}"
CLEAN_RECENT_MINS="${CLEAN_RECENT_MINS:-180}"   # how recent to prune fallback files in $HOME

PACKAGES_DIR="${PACKAGES_DIR:-$SCRIPT_DIR/packages}"
ELK_ENV_FILE="${ELK_ENV_FILE:-$SCRIPT_DIR/.elk_env}"

# --- sanity checks ---
if [[ ! -f "$LOCAL_SCRIPT" ]]; then
  echo "deploy script not found at: $LOCAL_SCRIPT" >&2
  exit 1
fi

# --- helper: load .elk_env safely (only simple KEY="VAL" lines) ---
load_env_file() {
  local f="$1"
  [[ -f "$f" ]] || return 0
  # shellcheck disable=SC1090
  source <(grep -E '^[A-Za-z_][A-Za-z0-9_]*="[^"]*"$' "$f" || true)
}

# Try to pick up previously selected version
load_env_file "$ELK_ENV_FILE"

# The user already picked a version earlier; honor it in this order:
ES_DEB_VERSION="${ES_DEB_VERSION:-${ELASTIC_VERSION:-${ES_VERSION:-}}}"

# --- helpers for package discovery ---
list_available_debs() {
  find "$PACKAGES_DIR" -maxdepth 1 -type f -name "elasticsearch-*-amd64.deb" -printf "%f\n" 2>/dev/null | sort -V
}
find_deb_for_version() {
  local ver="$1"
  local candidate="$PACKAGES_DIR/elasticsearch-${ver}-amd64.deb"
  if [[ -f "$candidate" ]]; then
    echo "$candidate"
    return 0
  fi
  return 1
}

# --- helper: validate token ---
is_valid_enrollment_token() {
  [[ "${1:-}" =~ ^[A-Za-z0-9+/=._-]{20,}$ ]]
}

# --- enrollment token ---
if [[ -z "${CLUSTER_TOKEN:-}" ]]; then
  echo -e "${CYAN}Creating Elasticsearch enrollment token on this node...${NC}"
  set +e
  TOKEN_OUTPUT="$(sudo /usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s node 2>&1)"
  gen_rc=$?
  set -e
  if (( gen_rc != 0 )); then
    echo -e "${RED}Failed to generate enrollment token (rc=${gen_rc}).${NC}" >&2
    echo "$TOKEN_OUTPUT" >&2
    exit 1
  fi
  token="$(echo "$TOKEN_OUTPUT" | tail -n1 | xargs)"
  if ! is_valid_enrollment_token "$token"; then
    echo -e "${RED}Token output didn't look valid.${NC}" >&2
    echo "$TOKEN_OUTPUT" >&2
    exit 1
  fi
  CLUSTER_TOKEN="$token"
else
  token="$CLUSTER_TOKEN"
  is_valid_enrollment_token "$token" || { echo -e "${RED}Provided CLUSTER_TOKEN invalid.${NC}" >&2; exit 1; }
fi

# --- prompt for install method (SCP vs Internet) ---
echo -e "${GREEN}Choose install method for the remote node:${NC}"
echo -e "  ${YELLOW}[1]${NC} Secure-copy local ${CYAN}.deb${NC} (exact version from ${PACKAGES_DIR})"
echo -e "  ${YELLOW}[2]${NC} Install via ${CYAN}internet${NC} (Elastic APT repo)"
read -rp "$(echo -e "Selection ${YELLOW}[1/2]${NC} (default 1): ")" INSTALL_METHOD_CHOICE
INSTALL_METHOD_CHOICE="${INSTALL_METHOD_CHOICE:-1}"

INSTALL_FROM_DEB=""
case "$INSTALL_METHOD_CHOICE" in
  1)
    INSTALL_FROM_DEB="1"
    # Require a version and a matching deb
    if [[ -z "${ES_DEB_VERSION:-}" ]]; then
      echo -e "${RED}No ES version found in .elk_env (ES_DEB_VERSION / ELASTIC_VERSION / ES_VERSION).${NC}" >&2
      echo -e "${YELLOW}Available debs in ${PACKAGES_DIR}:${NC}"
      list_available_debs | sed 's/^/  - /' || true
      echo -e "${RED}Aborting. Ensure elasticsearch-<version>-amd64.deb exists and version is saved in .elk_env.${NC}" >&2
      exit 1
    fi
    if ! ES_DEB_LOCAL_PATH="$(find_deb_for_version "$ES_DEB_VERSION")"; then
      echo -e "${RED}Could not find ${CYAN}elasticsearch-${ES_DEB_VERSION}-amd64.deb${RED} in ${PACKAGES_DIR}.${NC}" >&2
      echo -e "${YELLOW}Available debs in ${PACKAGES_DIR}:${NC}"
      list_available_debs | sed 's/^/  - /' || true
      echo -e "${RED}Aborting to avoid version mismatch.${NC}" >&2
      exit 1
    fi
    echo -e "${GREEN}✔ Using Elasticsearch deb: ${ES_DEB_LOCAL_PATH}${NC}"
    ;;
  2)
    INSTALL_FROM_DEB="0"
    if [[ -z "${ES_DEB_VERSION:-}" ]]; then
      echo -e "${YELLOW}No ES version found in .elk_env; remote will use its repo default/latest in the tracked series.${NC}"
    else
      echo -e "${GREEN}Will install via internet using version hint: ${CYAN}${ES_DEB_VERSION}${NC}"
    fi
    ;;
  *)
    echo -e "${RED}Invalid selection. Please run again and choose 1 or 2.${NC}"
    exit 1
    ;;
esac

# --- prompt for remote target ---
read -rp "Remote host/IP: " REMOTE_HOST
read -rp "Remote SSH user: " REMOTE_USER
read -rp "SSH port [22]: " REMOTE_PORT
REMOTE_PORT="${REMOTE_PORT:-22}"

# --- ensure SSH key and copy to remote ---
[[ -f "$HOME/.ssh/id_ed25519" ]] || ssh-keygen -t ed25519 -N "" -f "$HOME/.ssh/id_ed25519"
ssh-copy-id -p "$REMOTE_PORT" -o StrictHostKeyChecking=accept-new "${REMOTE_USER}@${REMOTE_HOST}"

# --- create a temp dir on remote (capture path locally) ---
REMOTE_DIR="$(ssh -p "$REMOTE_PORT" "${REMOTE_USER}@${REMOTE_HOST}" "mktemp -d -p /tmp es_deploy.XXXXXX")"

# --- copy deploy script (+ functions if present) ---
scp -P "$REMOTE_PORT" "$LOCAL_SCRIPT" "${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_DIR}/"
if [[ -f "$LOCAL_FUNCS" ]]; then
  scp -P "$REMOTE_PORT" "$LOCAL_FUNCS" "${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_DIR}/"
fi

# --- if chosen, copy the exact deb and prepare remote path ---
REMOTE_DEB_PATH=""
if [[ "$INSTALL_FROM_DEB" == "1" ]]; then
  REMOTE_DEB_PATH="${REMOTE_DIR}/$(basename "$ES_DEB_LOCAL_PATH")"
  echo -e "${CYAN}Copying Elasticsearch deb to remote temp dir...${NC}"
  scp -P "$REMOTE_PORT" "$ES_DEB_LOCAL_PATH" "${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_DEB_PATH}"
fi

# --- run remote deploy from INSIDE the temp dir, with cleanup trap ---
# Pass env so the remote script knows what to do.
# - INSTALL_FROM_DEB=1 with ES_DEB_LOCAL=<path> for local dpkg install
# - INSTALL_FROM_DEB=0 with ES_VERSION hint for repo-based install
ssh -tt -p "$REMOTE_PORT" "${REMOTE_USER}@${REMOTE_HOST}" bash -lc "'
  set -euo pipefail
  cd \"$REMOTE_DIR\"
  trap \"rm -rf \\\"$REMOTE_DIR\\\"\" EXIT

  chmod +x \"./$SCRIPT_NAME\" || true

  export INSTALL_FROM_DEB=\"$INSTALL_FROM_DEB\"
  ${ES_DEB_VERSION:+export ES_DEB_VERSION=\"$ES_DEB_VERSION\"}
  ${ES_DEB_VERSION:+export ES_VERSION=\"$ES_DEB_VERSION\"}

  if [[ \"$INSTALL_FROM_DEB\" == \"1\" ]]; then
    if [[ -f \"${REMOTE_DEB_PATH}\" ]]; then
      export ES_DEB_LOCAL=\"${REMOTE_DEB_PATH}\"
    else
      echo \"Local deb expected but not found: ${REMOTE_DEB_PATH}\" >&2
      exit 2
    fi
  fi

  sudo -E env FUNC_PATH=\"\$PWD\" CLUSTER_TOKEN=\"$CLUSTER_TOKEN\" bash \"./$SCRIPT_NAME\"
'"
RC=$?

# --- conservative post-clean: prune stray backups in the remote user's HOME created recently ---
ssh -p "$REMOTE_PORT" "${REMOTE_USER}@${REMOTE_HOST}" bash -lc "'
  set -euo pipefail
  find \"\$HOME\" -maxdepth 1 -type f -name \"$SCRIPT_NAME.*\" -mmin -$CLEAN_RECENT_MINS -delete 2>/dev/null || true
'"

# --- (optional) log token for audit/ops (expires ~20 min) ---
{
  echo "[$(date '+%F %T')] Remote ${REMOTE_HOST} | Enrollment token:"
  echo "$token"
  echo
} >> "$TOKEN_FILE" 2>/dev/null || true

# --- final status ---
if (( RC == 0 )); then
  echo -e "${GREEN}✅ Remote Elasticsearch deploy finished successfully on ${REMOTE_HOST}.${NC}"
else
  echo -e "${RED}❌ Remote deploy failed with code ${RC} on ${REMOTE_HOST}.${NC}"
fi

exit $RC
