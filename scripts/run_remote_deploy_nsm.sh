#!/usr/bin/env bash
# run_remote_deploy_nsm.sh — remotely deploy Zeek and Suricata
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"

# Color helpers (fallbacks if functions.sh not found)
if [[ -f "$SCRIPT_DIR/functions.sh" ]]; then
  # shellcheck source=/dev/null
  source "$SCRIPT_DIR/functions.sh"
  type init_colors >/dev/null 2>&1 && init_colors || true
fi
: "${GREEN:=$'\e[32m'}"; : "${YELLOW:=$'\e[33m'}"; : "${RED:=$'\e[31m'}"
: "${CYAN:=$'\e[36m'}";  : "${NC:=$'\e[0m'}"

# Local scripts
SURICATA_SCRIPT="$SCRIPT_DIR/suricata_deploy.sh"
ZEEK_SCRIPT="$SCRIPT_DIR/zeek_deploy.sh"
LOCAL_FUNCS="$SCRIPT_DIR/functions.sh"
PACKAGES_DIR="${PACKAGES_DIR:-$SCRIPT_DIR/packages}"

[[ -f "$SURICATA_SCRIPT" ]] || { echo -e "${RED}Missing $SURICATA_SCRIPT${NC}"; exit 1; }
[[ -f "$ZEEK_SCRIPT"     ]] || { echo -e "${RED}Missing $ZEEK_SCRIPT${NC}"; exit 1; }

echo -e "${GREEN}🛡️ Remote NSM Deployment Orchestrator${NC}"

# --- Select component(s) ---
echo -e "${CYAN}Select components to deploy:${NC}"
echo -e "  ${YELLOW}[1]${NC} Suricata only"
echo -e "  ${YELLOW}[2]${NC} Zeek only"
echo -e "  ${YELLOW}[3]${NC} Both Suricata and Zeek"
read -rp "$(echo -e "Selection ${YELLOW}[1/2/3]${NC} (default 3): ")" WHICH
WHICH="${WHICH:-3}"
case "$WHICH" in
  1) DO_SURICATA=1; DO_ZEEK=0 ;;
  2) DO_SURICATA=0; DO_ZEEK=1 ;;
  3) DO_SURICATA=1; DO_ZEEK=1 ;;
  *) echo -e "${RED}Invalid choice${NC}"; exit 1 ;;
esac

# --- Remote host details ---
read -rp "$(echo -e "${GREEN}Remote host/IP:${NC} ")" REMOTE_HOST
read -rp "$(echo -e "${GREEN}Remote SSH user:${NC} ")" REMOTE_USER
read -rp "$(echo -e "${GREEN}SSH port [22]:${NC} ")" REMOTE_PORT
REMOTE_PORT="${REMOTE_PORT:-22}"

# --- Package sync option ---
SYNC_PACKAGES=0
if [[ -d "$PACKAGES_DIR" ]]; then
  echo -e "${CYAN}Local packages detected in $PACKAGES_DIR${NC}"
  read -rp "$(echo -e "${YELLOW}Sync packages to remote? (yes/no) [no]: ${NC}")" ANS
  [[ "$ANS" =~ ^[Yy] ]] && SYNC_PACKAGES=1
fi

# --- SSH key setup ---
[[ -f "$HOME/.ssh/id_ed25519" ]] || ssh-keygen -t ed25519 -N "" -f "$HOME/.ssh/id_ed25519"
ssh-copy-id -p "$REMOTE_PORT" -o StrictHostKeyChecking=accept-new "${REMOTE_USER}@${REMOTE_HOST}" || true

# --- Remote temp dir (persistent for whole run) ---
REMOTE_DIR="$(ssh -p "$REMOTE_PORT" "${REMOTE_USER}@${REMOTE_HOST}" "mktemp -d -p /tmp nsm_deploy.XXXXXX")"
echo -e "${GREEN}📂 Remote workspace:${NC} ${YELLOW}$REMOTE_DIR${NC}"

# Ensure final cleanup regardless of outcome
cleanup_remote() {
  ssh -p "$REMOTE_PORT" "${REMOTE_USER}@${REMOTE_HOST}" "rm -rf '$REMOTE_DIR'" >/dev/null 2>&1 || true
}
trap cleanup_remote EXIT

# --- Copy scripts ---
scp -P "$REMOTE_PORT" "$SURICATA_SCRIPT" "$ZEEK_SCRIPT" "${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_DIR}/"
[[ -f "$LOCAL_FUNCS" ]] && scp -P "$REMOTE_PORT" "$LOCAL_FUNCS" "${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_DIR}/"

if (( SYNC_PACKAGES )); then
  echo -e "${CYAN}📦 Syncing packages...${NC}"
  if command -v rsync >/dev/null; then
    rsync -az -e "ssh -p $REMOTE_PORT" "$PACKAGES_DIR/" "${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_DIR}/packages/"
  else
    scp -r -P "$REMOTE_PORT" "$PACKAGES_DIR" "${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_DIR}/"
  fi
fi

# --- Helper to run remote script (no per-call cleanup) ---
run_remote() {
  local script="$1"
  local label="$2"
  echo -e "${GREEN}🚀 Deploying $label on $REMOTE_HOST...${NC}"
  ssh -tt -p "$REMOTE_PORT" "${REMOTE_USER}@${REMOTE_HOST}" bash -lc "'
    set -euo pipefail
    cd \"$REMOTE_DIR\"
    chmod +x ./*.sh || true
    [[ -d packages ]] && export PACKAGES_DIR=\"$REMOTE_DIR/packages\"
    sudo -E bash \"./$script\"
  '"
}

RC=0
if (( DO_SURICATA )); then
  if ! run_remote "suricata_deploy.sh" "Suricata"; then RC=1; fi
fi
if (( DO_ZEEK )); then
  if ! run_remote "zeek_deploy.sh" "Zeek"; then RC=1; fi
fi

if (( RC == 0 )); then
  echo -e "${GREEN}✅ Deployment complete on $REMOTE_HOST${NC}"
else
  echo -e "${RED}❌ Deployment encountered errors on $REMOTE_HOST${NC}"
fi

exit $RC
