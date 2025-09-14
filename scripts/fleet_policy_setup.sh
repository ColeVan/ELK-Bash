#!/usr/bin/env bash
# fleet_policy_setup.sh — create/find a Fleet policy and mint an enrollment token
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"

# ---- Colors (safe fallbacks) -------------------------------------------------
if [[ -f "$SCRIPT_DIR/functions.sh" ]]; then
  # shellcheck source=/dev/null
  source "$SCRIPT_DIR/functions.sh"
  type init_colors >/dev/null 2>&1 && init_colors || true
fi
: "${GREEN:=$'\e[32m'}"; : "${YELLOW:=$'\e[33m'}"; : "${RED:=$'\e[31m'}"
: "${CYAN:=$'\e[36m'}";  : "${NC:=$'\e[0m'}"; : "${BOLD:=$'\e[1m'}"; : "${DIM:=$'\e[2m'}"

ELK_ENV_FILE="${ELK_ENV_FILE:-$SCRIPT_DIR/.elk_env}"

# ---- Safe .elk_env loader/writer ---------------------------------------------
load_env_file() {
  local f="$1"
  [[ -f "$f" ]] || return 0
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%$'\r'}"
    [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
    if [[ "$line" =~ ^[[:space:]]*([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*=(.*)$ ]]; then
      local key="${BASH_REMATCH[1]}"
      local raw="${BASH_REMATCH[2]}" val
      raw="${raw#"${raw%%[![:space:]]*}"}"
      if   [[ "$raw" =~ ^\"(.*)\"$ ]]; then val="${BASH_REMATCH[1]}"
      elif [[ "$raw" =~ ^\'(.*)\'$ ]]; then val="${BASH_REMATCH[1]}"
      else val="$raw"
      fi
      printf -v val_escaped '%q' "$val"
      eval "export ${key}=${val_escaped}"
    fi
  done < "$f"
}
persist_kv_safe() {
  local f="$1" key="$2" val="$3"
  mkdir -p "$(dirname "$f")"
  if [[ -f "$f" ]]; then
    sed -i -E "s|^[[:space:]]*${key}=.*$||" "$f"
    sed -i -E '/^[[:space:]]*$/N;/^\n$/D' "$f" 2>/dev/null || true
  fi
  printf '%s="%s"\n' "$key" "$val" >> "$f"
}

load_env_file "$ELK_ENV_FILE"

# ---- Inputs / flags -----------------------------------------------------------
SSH_USER="${SSH_USER:-${REMOTE_SSH_USER:-root}}"
ELASTIC_HOST="${ELASTIC_HOST:-${FLEET_SERVER_HOST:-${ELASTIC_HOST:-}}}"  # host only, no scheme/port
KIBANA_URL="${KIBANA_URL:-${FLEET_URL:-${KIBANA_URL:-}}}"                 # full https://host:5601
API_TOKEN="${API_TOKEN:-${KIBANA_API_TOKEN:-}}"
KIBANA_SPACE="${KIBANA_SPACE:-}" # e.g. "default"

ASSUME_YES=0
POLICY_NAME_DEFAULT="elastic cluster"
POLICY_NAME="${POLICY_NAME:-}"

print_help() {
  cat <<EOF
${BOLD}fleet_policy_setup.sh${NC}
Ensures Fleet is ready, prompts for a policy name, creates/uses it, and mints an enrollment token.

Options:
  -e HOST      Fleet Server host (HOST/IP ONLY; agents use https://HOST:8220)
  -b URL       Kibana URL (e.g., https://kibana:5601 or https://10.0.0.1)
  -T TOKEN     Kibana OAuth token (if omitted, prompts for elastic creds to fetch one)
  -n NAME      Fleet policy name to create/use (default: "${POLICY_NAME_DEFAULT}")
  -s SPACE     Kibana space id (omit for default space)
  -y           Assume defaults for prompts
  -?           Help
EOF
}
while getopts ":e:b:T:n:s:y?" opt; do
  case "$opt" in
    e) ELASTIC_HOST="$OPTARG" ;;
    b) KIBANA_URL="$OPTARG" ;;
    T) API_TOKEN="$OPTARG" ;;
    n) POLICY_NAME="$OPTARG" ;;
    s) KIBANA_SPACE="$OPTARG" ;;
    y) ASSUME_YES=1 ;;
    \?|*) print_help; exit 0 ;;
  esac
done

# ---- Prompt helpers -----------------------------------------------------------
prompt_if_empty() {
  local var="$1" prompt="$2" def="${3:-}" val=""
  if [[ -z "${!var:-}" ]]; then
    if (( ASSUME_YES )); then eval "$var=\"${def}\""
    else read -r -p "$(echo -e "${GREEN}${prompt}${NC}${def:+ [${def}]}: ")" val; eval "$var=\"\${val:-$def}\""
    fi
  fi
}
prompt_secret() { local var="$1" prompt="$2" val=""; read -r -s -p "$(echo -e "${GREEN}${prompt}${NC}: ")" val; echo; eval "$var=\"\$val\""; }

normalize_endpoints() {
  ELASTIC_HOST="${ELASTIC_HOST#http://}"; ELASTIC_HOST="${ELASTIC_HOST#https://}"
  ELASTIC_HOST="${ELASTIC_HOST%%/*}"; ELASTIC_HOST="${ELASTIC_HOST%%:*}"
  if [[ -n "${KIBANA_URL:-}" && ! "$KIBANA_URL" =~ ^https?:// ]]; then KIBANA_URL="https://${KIBANA_URL}"; fi
}
api_prefix(){ [[ -n "$KIBANA_SPACE" ]] && printf '/s/%s' "$KIBANA_SPACE" || true; }

# ---- Kibana API (STRICT SYNTAX) ----------------------------------------------
kbn_api() {
  local m="$1" path="$2" data="${3:-}"
  if [[ -n "$data" ]]; then
    curl -sS -k -X "$m" "${KIBANA_URL}$(api_prefix)${path}" \
      -H "Authorization: Bearer ${API_TOKEN}" \
      -H 'kbn-xsrf: xxx' \
      -H 'Content-Type: application/json' \
      --data "$data"
  else
    curl -sS -k -X "$m" "${KIBANA_URL}$(api_prefix)${path}" \
      -H "Authorization: Bearer ${API_TOKEN}" \
      -H 'kbn-xsrf: xxx'
  fi
}
kbn_api_with_status() {
  local m="$1" path="$2" data="${3:-}" tmpf status
  tmpf="$(mktemp)"
  if [[ -n "$data" ]]; then
    status="$(curl -sS -k -w '%{http_code}' -o "$tmpf" -X "$m" "${KIBANA_URL}$(api_prefix)${path}" \
      -H "Authorization: Bearer ${API_TOKEN}" -H 'kbn-xsrf: xxx' -H 'Content-Type: application/json' --data "$data")"
  else
    status="$(curl -sS -k -w '%{http_code}' -o "$tmpf" -X "$m" "${KIBANA_URL}$(api_prefix)${path}" \
      -H "Authorization: Bearer ${API_TOKEN}" -H 'kbn-xsrf: xxx')"
  fi
  printf '%s\t' "$status"; cat "$tmpf"; rm -f "$tmpf"
}

# ---- Fleet helpers ------------------------------------------------------------
ensure_fleet_setup() {
  local resp init
  resp="$(kbn_api GET '/api/fleet/setup')" || true
  init="$(echo "$resp" | jq -r '.is_initialized // .isInitialized // empty' 2>/dev/null || true)"
  [[ "$init" == "true" ]] && { echo -e "${GREEN}✔ Fleet already initialized${NC}"; return 0; }
  echo -e "${CYAN}Initializing Fleet…${NC}"
  resp="$(kbn_api POST '/api/fleet/setup')" || true
  init="$(echo "$resp" | jq -r '.is_initialized // .isInitialized // empty' 2>/dev/null || true)"
  [[ "$init" == "true" ]] && { echo -e "${GREEN}✔ Fleet initialized${NC}"; return 0; }
  resp="$(kbn_api POST '/api/fleet/agents/setup')" || true
  init="$(echo "$resp" | jq -r '.isInitialized // .is_initialized // empty' 2>/dev/null || true)"
  [[ "$init" == "true" ]] && { echo -e "${GREEN}✔ Fleet initialized (agents/setup)${NC}"; return 0; }
  echo -e "${RED}❌ Could not initialize Fleet.${NC}"; return 1
}
ensure_default_fleet_server_host() {
  local existing resp urls
  existing="$(kbn_api GET '/api/fleet/fleet_server_hosts' | jq -r '.items[]? | select(.is_default==true) | .host_urls[0] // empty' 2>/dev/null || true)"
  if [[ -n "$existing" ]]; then echo -e "${GREEN}✔ Default Fleet Server Host present: ${existing}${NC}"; return 0; fi
  echo -e "${CYAN}Creating default Fleet Server Host…${NC}"
  resp="$(kbn_api POST '/api/fleet/fleet_server_hosts' "{\"name\":\"Default\",\"is_default\":true,\"host_urls\":[\"https://${ELASTIC_HOST}:8220\"]}")"
  urls="$(echo "$resp" | jq -r '.item.host_urls[0] // empty' 2>/dev/null || true)"
  [[ -n "$urls" ]] && echo -e "${GREEN}✔ Fleet Server Host set to: ${urls}${NC}" || echo -e "${YELLOW}⚠ Could not confirm host creation.${NC}"
}
ensure_policy() {
  local name="$1" resp id
  resp="$(kbn_api GET '/api/fleet/agent_policies?perPage=1000')" || true
  id="$(echo "$resp" | jq -r --arg name "$name" '.items[]? | select(.name==$name) | .id // empty' 2>/dev/null || true)"
  if [[ -n "$id" ]]; then >&2 echo -e "${GREEN}✔ Fleet policy exists: ${CYAN}${name}${NC} (id=${id})"; echo "$id"; return 0; fi
  >&2 echo -e "${CYAN}Creating Fleet policy: ${name}…${NC}"
  resp="$(kbn_api POST '/api/fleet/agent_policies?sys_monitoring=true' \
    "{\"name\":\"${name}\",\"description\":\"Policy for Elasticsearch service nodes\",\"namespace\":\"default\",\"monitoring_enabled\":[\"logs\",\"metrics\"]}")" || true
  id="$(echo "$resp" | jq -r '.item.id // empty' 2>/dev/null || true)"
  [[ -z "$id" ]] && { resp="$(kbn_api GET '/api/fleet/agent_policies?perPage=1000')" || true; id="$(echo "$resp" | jq -r --arg name "$name" '.items[]? | select(.name==$name) | .id // empty')"; }
  [[ -n "$id" ]] && { >&2 echo -e "${GREEN}✔ Policy ready: ${CYAN}${name}${NC} (id=${id})"; echo "$id"; return 0; }
  >&2 echo -e "${RED}❌ Failed to create/find policy '${name}'.${NC}"; return 1
}
mint_enrollment_token() {
  local pid="$1" name="elastic-cluster-$(date +%s)" status body tok path='/api/fleet/enrollment-api-keys'
  [[ -z "$pid" ]] && { >&2 echo -e "${RED}❌ mint_enrollment_token: missing policy id${NC}"; return 1; }
  >&2 echo -e "${CYAN}Minting enrollment token for policy id=${pid}…${NC}"
  IFS=$'\t' read -r status body < <(kbn_api_with_status POST "${path}" "{\"policy_id\":\"${pid}\",\"name\":\"${name}\"}")
  if command -v jq >/dev/null 2>&1; then tok="$(printf '%s' "$body" | jq -r '.item.api_key // .api_key // .item.value // .item.secret // empty' 2>/dev/null || true)"
  else tok="$(printf '%s' "$body" | sed -nE 's/.*"api_key":"([^"]*)".*/\1/p; s/.*"value":"([^"]*)".*/\1/p; s/.*"secret":"([^"]*)".*/\1/p' | head -n1)"; fi
  [[ -n "$tok" && "$status" =~ ^2[0-9][0-9]$ ]] && { >&2 echo -e "${GREEN}✔ Enrollment token minted.${NC}"; printf '%s\n' "$tok"; return 0; }
  # retry underscore variant if 404
  if [[ "$status" == "404" ]]; then
    path='/api/fleet/enrollment_api_keys'
    IFS=$'\t' read -r status body < <(kbn_api_with_status POST "${path}" "{\"policy_id\":\"${pid}\",\"name\":\"${name}\"}")
    if command -v jq >/dev/null 2>&1; then tok="$(printf '%s' "$body" | jq -r '.item.api_key // .api_key // .item.value // .item.secret // empty' 2>/dev/null || true)"
    else tok="$(printf '%s' "$body" | sed -nE 's/.*"api_key":"([^"]*)".*/\1/p; s/.*"value":"([^"]*)".*/\1/p; s/.*"secret":"([^"]*)".*/\1/p' | head -n1)"; fi
    [[ -n "$tok" && "$status" =~ ^2[0-9][0-9]$ ]] && { >&2 echo -e "${GREEN}✔ Enrollment token minted.${NC}"; printf '%s\n' "$tok"; return 0; }
  fi
  >&2 echo -e "${RED}❌ Failed to mint enrollment token.${NC}"; return 1
}

# ---- Flow --------------------------------------------------------------------
prompt_if_empty ELASTIC_HOST "Fleet Server host (HOST/IP ONLY; agents will use https://<host>:8220)"
prompt_if_empty KIBANA_URL   "Kibana URL (e.g., https://kibana:5601 or https://10.0.0.1)"
normalize_endpoints
prompt_if_empty POLICY_NAME  "Name for the Fleet policy used to enroll remote Elasticsearch nodes" "${POLICY_NAME_DEFAULT}"

# Get API token if not provided
if [[ -z "${API_TOKEN:-}" ]]; then
  USERNAME="${USERNAME:-}"; PASSWORD="${PASSWORD:-}"
  prompt_if_empty USERNAME "Elasticsearch username"
  prompt_secret  PASSWORD "Elasticsearch password"
  echo -e "\n${GREEN}Obtaining OAuth2 access token...${NC}"
  ACCESS_TOKEN_JSON="$(curl -sS --request POST --url "https://${ELASTIC_HOST}:9200/_security/oauth2/token" \
    -u "${USERNAME}:${PASSWORD}" -H 'Content-Type: application/json' --insecure \
    --data "{\"grant_type\":\"password\",\"username\":\"${USERNAME}\",\"password\":\"${PASSWORD}\"}" || true)"
  if command -v jq >/dev/null 2>&1; then API_TOKEN="$(echo "$ACCESS_TOKEN_JSON" | jq -r '.access_token // empty')"
  else API_TOKEN="$(echo "$ACCESS_TOKEN_JSON" | sed -nE 's/.*"access_token":"([^"]+)".*/\1/p')"; fi
  [[ -z "${API_TOKEN:-}" ]] && { echo -e "${RED}Failed to obtain access token from Elasticsearch.${NC}"; exit 1; }
fi

echo -e "${CYAN}Preparing Fleet…${NC}"
ensure_fleet_setup || exit 1
ensure_default_fleet_server_host

POLICY_ID="$(ensure_policy "$POLICY_NAME")" || exit 1
TOKEN="$(mint_enrollment_token "$POLICY_ID")" || exit 1

# Persist for downstream scripts
persist_kv_safe "$ELK_ENV_FILE" "FLEET_SERVER_HOST" "$ELASTIC_HOST"
persist_kv_safe "$ELK_ENV_FILE" "KIBANA_URL" "$KIBANA_URL"
persist_kv_safe "$ELK_ENV_FILE" "KIBANA_SPACE" "${KIBANA_SPACE:-}"
persist_kv_safe "$ELK_ENV_FILE" "POLICY_NAME" "$POLICY_NAME"
persist_kv_safe "$ELK_ENV_FILE" "POLICY_ID" "$POLICY_ID"
persist_kv_safe "$ELK_ENV_FILE" "ENROLLMENT_TOKEN" "$TOKEN"

# Print a friendly summary (and echo token last for callers to capture)
echo -e "${GREEN}✔ Policy:${NC} ${POLICY_NAME}  ${DIM}(id=${POLICY_ID})${NC}"
echo -e "${GREEN}🔑 Enrollment token:${NC} ${TOKEN:0:6}…${TOKEN: -4}"
# stdout return (for caller capture)
printf '%s\n' "$TOKEN"
