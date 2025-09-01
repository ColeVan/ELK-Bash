#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"

# Optional colors/logging
if [[ -f "$SCRIPT_DIR/functions.sh" ]]; then
  # shellcheck source=/dev/null
  source "$SCRIPT_DIR/functions.sh"
  type init_colors >/dev/null 2>&1 && init_colors || true
fi

SCRIPT_NAME="deploy_elasticsearch_node.sh"
LOCAL_SCRIPT="$SCRIPT_DIR/$SCRIPT_NAME"
LOCAL_FUNCS="$SCRIPT_DIR/functions.sh"
TOKEN_FILE="${TOKEN_FILE:-$SCRIPT_DIR/enrollment_tokens.txt}"
CLEAN_RECENT_MINS="${CLEAN_RECENT_MINS:-180}"   # how recent to prune fallback files in $HOME

# --- sanity checks ---
if [[ ! -f "$LOCAL_SCRIPT" ]]; then
  echo "deploy script not found at: $LOCAL_SCRIPT" >&2
  exit 1
fi

# --- helper: validate token ---
is_valid_enrollment_token() {
  [[ "${1:-}" =~ ^[A-Za-z0-9+/=._-]{20,}$ ]]
}

# Get token (or validate provided)
if [[ -z "${CLUSTER_TOKEN:-}" ]]; then
  echo -e "${CYAN:-}Creating Elasticsearch enrollment token on this node...${NC:-}"
  set +e
  TOKEN_OUTPUT="$(sudo /usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s node 2>&1)"
  gen_rc=$?
  set -e
  if (( gen_rc != 0 )); then
    echo -e "${RED:-}Failed to generate enrollment token (rc=${gen_rc}).${NC:-}" >&2
    echo "$TOKEN_OUTPUT" >&2
    exit 1
  fi
  token="$(echo "$TOKEN_OUTPUT" | tail -n1 | xargs)"
  if ! is_valid_enrollment_token "$token"; then
    echo -e "${RED:-}Token output didn't look valid.${NC:-}" >&2
    echo "$TOKEN_OUTPUT" >&2
    exit 1
  fi
  CLUSTER_TOKEN="$token"
else
  token="$CLUSTER_TOKEN"
  is_valid_enrollment_token "$token" || { echo -e "${RED:-}Provided CLUSTER_TOKEN invalid.${NC:-}" >&2; exit 1; }
fi

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

# --- run remote deploy from INSIDE the temp dir, with cleanup trap ---
ssh -tt -p "$REMOTE_PORT" "${REMOTE_USER}@${REMOTE_HOST}" bash -lc "'
  set -euo pipefail
  cd \"$REMOTE_DIR\"
  trap \"rm -rf \\\"$REMOTE_DIR\\\"\" EXIT

  # ensure script is executable
  chmod +x \"./$SCRIPT_NAME\" || true

  # run with cwd inside REMOTE_DIR so any self-backups land here
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
  echo -e "${GREEN:-}✅ Remote Elasticsearch deploy finished successfully on ${REMOTE_HOST}.${NC:-}"
else
  echo -e "${RED:-}❌ Remote deploy failed with code ${RC} on ${REMOTE_HOST}.${NC:-}"
fi

exit $RC