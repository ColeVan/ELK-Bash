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

# --- sanity checks ---
if [[ ! -f "$LOCAL_SCRIPT" ]]; then
  echo "deploy script not found at: $LOCAL_SCRIPT" >&2
  exit 1
fi

# --- helper: validate token ---
is_valid_enrollment_token() {
  # Accept standard base64 (A–Z a–z 0–9 + / =) and base64url (._-)
  # Require a reasonable length so short junk doesn't pass.
  local s="${1:-}"
  [[ "$s" =~ ^[A-Za-z0-9+/=._-]{20,}$ ]]
}

# If caller already provided CLUSTER_TOKEN, reuse it; otherwise generate a fresh one.
if [[ -z "${CLUSTER_TOKEN:-}" ]]; then
  echo -e "${CYAN:-}Creating Elasticsearch enrollment token on this node...${NC:-}"
  # Capture output + exit code safely under set -e
  set +e
  TOKEN_OUTPUT="$(sudo /usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s node 2>&1)"
  gen_rc=$?
  set -e
  if (( gen_rc != 0 )); then
    echo -e "${RED:-}Failed to generate enrollment token (rc=${gen_rc}).${NC:-}" >&2
    echo "$TOKEN_OUTPUT" >&2
    exit 1
  fi
  # The token is typically the last line of output
  token="$(echo "$TOKEN_OUTPUT" | tail -n1 | xargs)"
  if ! is_valid_enrollment_token "$token"; then
    echo -e "${RED:-}Token output didn't look valid. Received:${NC:-}" >&2
    echo "$TOKEN_OUTPUT" >&2
    exit 1
  fi
  CLUSTER_TOKEN="$token"
else
  token="$CLUSTER_TOKEN"
  if ! is_valid_enrollment_token "$token"; then
    echo -e "${RED:-}Provided CLUSTER_TOKEN doesn't look valid.${NC:-}" >&2
    exit 1
  fi
fi

# --- prompt for remote target ---
read -rp "Remote host/IP: " REMOTE_HOST
read -rp "Remote SSH user: " REMOTE_USER
read -rp "SSH port [22]: " REMOTE_PORT
REMOTE_PORT="${REMOTE_PORT:-22}"

# --- ensure SSH key and copy to remote ---
[[ -f "$HOME/.ssh/id_ed25519" ]] || ssh-keygen -t ed25519 -N "" -f "$HOME/.ssh/id_ed25519"
ssh-copy-id -p "$REMOTE_PORT" -o StrictHostKeyChecking=accept-new "${REMOTE_USER}@${REMOTE_HOST}"

# --- create a temp dir on remote ---
REMOTE_DIR="/tmp/es_deploy.$RANDOM.$$"
ssh -p "$REMOTE_PORT" "${REMOTE_USER}@${REMOTE_HOST}" "mkdir -p '$REMOTE_DIR'"

# --- copy deploy script (+ functions if present) ---
scp -P "$REMOTE_PORT" "$LOCAL_SCRIPT" "${REMOTE_USER}@${REMOTE_HOST}:$REMOTE_DIR/"
if [[ -f "$LOCAL_FUNCS" ]]; then
  scp -P "$REMOTE_PORT" "$LOCAL_FUNCS" "${REMOTE_USER}@${REMOTE_HOST}:$REMOTE_DIR/"
fi

# --- run remote deploy with token passed via env and functions path preserved ---
ssh -tt -p "$REMOTE_PORT" "${REMOTE_USER}@${REMOTE_HOST}" "
  chmod +x '$REMOTE_DIR/$SCRIPT_NAME' &&
  sudo -E env FUNC_PATH='$REMOTE_DIR' CLUSTER_TOKEN='$CLUSTER_TOKEN' bash '$REMOTE_DIR/$SCRIPT_NAME'
"
RC=$?

# --- cleanup remote temp dir regardless ---
ssh -p "$REMOTE_PORT" "${REMOTE_USER}@${REMOTE_HOST}" "rm -rf '$REMOTE_DIR'" || true

# --- (optional) log token to a file for audit/ops (expires ~20 min) ---
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
