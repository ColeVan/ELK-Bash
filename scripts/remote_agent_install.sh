#!/usr/bin/env bash
# remote_agent_simple.sh — Simple SSH installer for Elastic Agent with token handoff
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
PACKAGES_DIR="${PACKAGES_DIR:-$SCRIPT_DIR/packages}"
ELK_ENV_FILE="${ELK_ENV_FILE:-$SCRIPT_DIR/.elk_env}"

# Colors (no helpers)
: "${GREEN:=$'\e[32m'}"; : "${YELLOW:=$'\e[33m'}"; : "${RED:=$'\e[31m'}"
: "${CYAN:=$'\e[36m'}";  : "${NC:=$'\e[0m'}"

# Read .elk_env (minimal, safe)
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

# ---- Args
SSH_USER="${SSH_USER:-${REMOTE_SSH_USER:-root}}"
SSH_PORT="${SSH_PORT:-${REMOTE_SSH_PORT:-22}}"
SSH_KEY="${SSH_KEY:-${SSH_KEY_PATH:-$HOME/.ssh/id_ed25519}}"
FLEET_HOST="${FLEET_SERVER_HOST:-${ELASTIC_HOST:-}}"
ENROLLMENT_TOKEN="${ENROLLMENT_TOKEN:-}"
VERSION="${ELASTIC_AGENT_VERSION:-}"     # optional upfront
HOSTS_CSV=""

print_help() {
  cat <<EOF
${CYAN}remote_agent_simple.sh${NC}
Copy an elastic-agent tarball to remote host(s) and run:
  tar xzf; cd dir; sudo ./elastic-agent install --url=https://<fleet>:8220 --enrollment-token=<token> --insecure

Options:
  -h "host1,host2"  Comma-separated hosts (prompt if omitted)
  -e HOST           Fleet Server host/IP (default from .elk_env FLEET_SERVER_HOST)
  -t TOKEN          Enrollment token (default from .elk_env ENROLLMENT_TOKEN)
  -v VERSION        Agent version (e.g., 9.1.3). If tarball missing, you'll be prompted.
  -u USER           SSH user (default: ${SSH_USER})
  -p PORT           SSH port (default: ${SSH_PORT})
  -k KEY            SSH key (default: ${SSH_KEY})
  -?                Help
EOF
}

while getopts ":h:e:t:v:u:p:k:?" opt; do
  case "$opt" in
    h) HOSTS_CSV="$OPTARG" ;;
    e) FLEET_HOST="$OPTARG" ;;
    t) ENROLLMENT_TOKEN="$OPTARG" ;;
    v) VERSION="$OPTARG" ;;
    u) SSH_USER="$OPTARG" ;;
    p) SSH_PORT="$OPTARG" ;;
    k) SSH_KEY="$OPTARG" ;;
    \?|*) print_help; exit 0 ;;
  esac
done

# ---- Prompts
[[ -n "$HOSTS_CSV" ]] || { echo -en "${GREEN}Enter comma-separated host/IP list to enroll${NC}: "; read -r HOSTS_CSV; }
[[ -n "$FLEET_HOST" ]] || { echo -en "${GREEN}Enter Fleet Server host (HOST/IP ONLY)${NC}: "; read -r FLEET_HOST; }
[[ -n "$ENROLLMENT_TOKEN" ]] || { echo -en "${GREEN}Enter enrollment token${NC}: "; read -r ENROLLMENT_TOKEN; }

# normalize fleet host (strip scheme/port)
FLEET_HOST="${FLEET_HOST#http://}"; FLEET_HOST="${FLEET_HOST#https://}"
FLEET_HOST="${FLEET_HOST%%/*}"; FLEET_HOST="${FLEET_HOST%%:*}"
FLEET_URL="https://${FLEET_HOST}:8220"

[[ -r "$SSH_KEY" ]] || { echo -e "${RED}SSH key not readable: ${SSH_KEY}${NC}"; exit 1; }
mkdir -p "$PACKAGES_DIR"

# split hosts
IFS=',' read -r -a HOSTS <<< "$HOSTS_CSV"

for H in "${HOSTS[@]}"; do
  host="${H//[[:space:]]/}"
  [[ -z "$host" ]] && continue
  echo -e "${CYAN}→ ${host}${NC}"

  # 1) Detect remote arch (for filename selection only)
  uname_m="$(ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p "$SSH_PORT" \
             "${SSH_USER}@${host}" "uname -m" 2>/dev/null || true)"
  case "$uname_m" in
    aarch64|arm64) arch_label_primary="arm64"; arch_label_alt="aarch64" ;;
    x86_64|amd64|"") arch_label_primary="x86_64"; arch_label_alt="" ;;
    *) arch_label_primary="x86_64"; arch_label_alt=""; echo -e "${YELLOW}${host}: unknown arch '${uname_m}', defaulting to x86_64${NC}";;
  esac

  # 2) Ensure local tarball exists, else prompt + download
  tarball=""
  if [[ -n "$VERSION" ]]; then
    # Try exact version/arch naming (favor user's example 'arm64', fallback to 'aarch64')
    for lbl in "$arch_label_primary" "$arch_label_alt"; do
      [[ -z "$lbl" ]] && continue
      candidate="$PACKAGES_DIR/elastic-agent-${VERSION}-linux-${lbl}.tar.gz"
      if [[ -f "$candidate" ]]; then tarball="$candidate"; break; fi
    done
  fi

  if [[ -z "$tarball" ]]; then
    # Try any existing tarball for this arch (newest)
    if [[ -n "$arch_label_primary" ]]; then
      tarball="$(find "$PACKAGES_DIR" -maxdepth 1 -type f -name "elastic-agent-*-linux-${arch_label_primary}.tar.gz" -printf "%T@ %p\n" | sort -nr | awk '{print $2}' | head -n1 || true)"
    fi
  fi

  if [[ -z "$tarball" && -n "$arch_label_alt" ]]; then
    tarball="$(find "$PACKAGES_DIR" -maxdepth 1 -type f -name "elastic-agent-*-linux-${arch_label_alt}.tar.gz" -printf "%T@ %p\n" | sort -nr | awk '{print $2}' | head -n1 || true)"
  fi

  if [[ -z "$tarball" ]]; then
    # Prompt to download
    if [[ -z "$VERSION" ]]; then
      echo -en "${GREEN}No local tarball found. Enter Elastic Agent version to download (e.g., 9.1.3)${NC}: "
      read -r VERSION
    fi
    echo -en "${GREEN}Download elastic-agent ${VERSION} for ${CYAN}${arch_label_primary:-x86_64}${NC}? [y/N]: "
    read -r yn
    if [[ "${yn,,}" != "y" && "${yn,,}" != "yes" ]]; then
      echo -e "${RED}Aborted: tarball required.${NC}"
      exit 1
    fi

    # Try primary label first (arm64 or x86_64), then alternate (aarch64)
    url_primary="https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-${VERSION}-linux-${arch_label_primary}.tar.gz"
    target_primary="$PACKAGES_DIR/elastic-agent-${VERSION}-linux-${arch_label_primary}.tar.gz"
    if ! curl -fSLk "$url_primary" -o "$target_primary"; then
      if [[ -n "$arch_label_alt" ]]; then
        url_alt="https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-${VERSION}-linux-${arch_label_alt}.tar.gz"
        target_alt="$PACKAGES_DIR/elastic-agent-${VERSION}-linux-${arch_label_alt}.tar.gz"
        echo -e "${YELLOW}Primary URL failed, trying alternate naming (${arch_label_alt})…${NC}"
        if ! curl -fSLk "$url_alt" -o "$target_alt"; then
          echo -e "${RED}Failed to download agent for both '${arch_label_primary}' and '${arch_label_alt}'.${NC}"
          exit 1
        fi
        tarball="$target_alt"
      else
        echo -e "${RED}Failed to download agent (${url_primary}).${NC}"
        exit 1
      fi
    else
      tarball="$target_primary"
    fi
  fi

  echo -e "${GREEN}Using tarball:${NC} ${tarball##*/}"

  # 3) SCP tarball, functions.sh (if present), and a small install script
  rdir="/tmp/ea_es.$$.$RANDOM"
  ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p "$SSH_PORT" \
      "${SSH_USER}@${host}" "mkdir -p '$rdir'"

  scp -i "$SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -P "$SSH_PORT" \
      "$tarball" "${SSH_USER}@${host}:$rdir/agent.tgz"

  if [[ -f "$SCRIPT_DIR/functions.sh" ]]; then
    scp -i "$SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -P "$SSH_PORT" \
        "$SCRIPT_DIR/functions.sh" "${SSH_USER}@${host}:$rdir/functions.sh" || true
  fi

  # Build remote installer (exact commands you requested; dir name auto-detected from tarball)
  install_remote="$(cat <<'EOS'
#!/usr/bin/env bash
set -euo pipefail
RDIR="${1:-/tmp}"
FLEET_URL="${2:?fleet_url}"
TOKEN="${3:?token}"
# Extract
tar xzf "$RDIR/agent.tgz" -C "$RDIR"
cd "$(ls -1d "$RDIR"/elastic-agent-* | head -n1)"
# Install (root, passwordless sudo, or prompt for sudo password)
if [ "$(id -u)" -eq 0 ]; then
  ./elastic-agent install --url="$FLEET_URL" --enrollment-token="$TOKEN" --insecure
elif sudo -n true 2>/dev/null; then
  sudo -n ./elastic-agent install --non-interactive --url="$FLEET_URL" --enrollment-token="$TOKEN" --insecure
else
  # Prompt for sudo password on a real TTY and feed via -S
  tries=0
  while : ; do
    tries=$((tries+1))
    read -srp "Sudo password for $USER: " sudopw </dev/tty; echo
    # Validate password first (quietly), then run the install
    if printf '%s\n' "$sudopw" | sudo -S -p '' true 2>/dev/null; then
      if printf '%s\n' "$sudopw" | sudo -S -p '' ./elastic-agent install --non-interactive --url="$FLEET_URL" --enrollment-token="$TOKEN" --insecure; then
        unset sudopw
        break
      else
        unset sudopw
        echo "sudo command failed." >&2
        exit 1
      fi
    else
      unset sudopw
      echo "Sorry, try again." >&2
      [ "$tries" -ge 3 ] && { echo "sudo authentication failed"; exit 1; }
    fi
  done
fi
EOS
)"
  printf '%s\n' "$install_remote" > "$SCRIPT_DIR/.install_remote.tmp"
  scp -i "$SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -P "$SSH_PORT" \
      "$SCRIPT_DIR/.install_remote.tmp" "${SSH_USER}@${host}:$rdir/install_remote.sh"
  rm -f "$SCRIPT_DIR/.install_remote.tmp"

  # 4) Execute remote installer
  echo -e "${CYAN}${host}:${NC} installing agent via remote script…"
  ssh -tt -i "$SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p "$SSH_PORT" \
      "${SSH_USER}@${host}" "bash -lc 'bash \"$rdir/install_remote.sh\" \"$rdir\" \"$FLEET_URL\" \"$ENROLLMENT_TOKEN\"'"

  echo -e "${GREEN}✔ Installed on ${host}${NC}"
done
