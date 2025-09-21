#!/usr/bin/env bash
# suricata-log-maint.sh (v1.3)
# - Rotate/compress Suricata text logs via logrotate
# - Prune oldest PCAPs to keep filesystem usage below a threshold

set -euo pipefail

SURICATA_USER="suricata"
SURICATA_GROUP="suricata"

LOG_DIR="/var/log/suricata"
PCAP_DIR="$LOG_DIR/pcap"

TARGET_USAGE=89       # normal prune target %
AGGR_TARGET_USAGE=85  # --aggressive target %

LR_CONF="/etc/logrotate.d/suricata"
CRON_FILE="/etc/cron.d/suricata-pcap-prune"
SELF_PATH="$(readlink -f "$0")"

DO_INSTALL=0
DO_PRUNE=0
DO_ROTATE=0
DRY_RUN=0
AGGRESSIVE=0

log() { printf '[suricata-maint] %s\n' "$*" >&2; }
run() {
  if [[ $DRY_RUN -eq 1 ]]; then
    log "DRY-RUN: $*"
  else
    log "+ $*"
    eval "$@"
  fi
}
need() { command -v "$1" >/dev/null 2>&1 || { log "Missing: $1"; exit 1; }; }

# -------- arg parsing --------
if (( $# == 0 )); then
  DO_PRUNE=1
  DO_ROTATE=1
else
  for a in "$@"; do
    case "$a" in
      --install)    DO_INSTALL=1 ;;
      --prune)      DO_PRUNE=1 ;;
      --rotate)     DO_ROTATE=1 ;;
      --dry-run)    DRY_RUN=1 ;;
      --aggressive) AGGRESSIVE=1 ;;
      *) log "Unknown option: $a"; exit 2 ;;
    esac
  done
fi

# -------- helpers --------
fs_usage_pct() { df -P "$LOG_DIR" | awk 'NR==2{gsub("%","",$5); print $5}'; }

is_open() {
  if command -v lsof >/dev/null 2>&1; then
    lsof -t -- "$1" >/dev/null 2>&1
  elif command -v fuser >/dev/null 2>&1; then
    fuser "$1" >/dev/null 2>&1
  else
    log "ERROR: need lsof or fuser to detect open files"; exit 1
  fi
}

delete_file() {
  local f="$1"
  if [[ $DRY_RUN -eq 1 ]]; then
    log "DRY-RUN: would delete $f"
  else
    if rm -f -- "$f"; then log "Deleted $f"; else log "WARN: failed to delete $f"; fi
  fi
}

# -------- pruning logic --------
prune_pcaps() {
  local target="${TARGET_USAGE}"
  [[ $AGGRESSIVE -eq 1 ]] && target="${AGGR_TARGET_USAGE}"

  if [[ ! -d "$PCAP_DIR" ]]; then
    log "PCAP dir not found: $PCAP_DIR (skipping prune)"
    return 0
  fi

  # zero-byte quick wins
  mapfile -t ZEROES < <(find "$PCAP_DIR" -maxdepth 1 -type f -size 0c -name 'pcap.*' -print 2>/dev/null | sort)
  if (( ${#ZEROES[@]} > 0 )); then
    log "Found ${#ZEROES[@]} zero-byte pcaps; removing…"
    for f in "${ZEROES[@]}"; do
      is_open "$f" && { log "Skip open (0B): $f"; continue; }
      delete_file "$f"
    done
  fi

  local use; use="$(fs_usage_pct)"
  log "Filesystem usage: ${use}% (target < ${target}%)"
  if (( use < target )); then
    log "Nothing to prune."
    return 0
  fi

  # oldest -> newest candidates
  mapfile -t CANDS < <(
    find "$PCAP_DIR" -maxdepth 1 -type f -name 'pcap.*' -printf '%T@ %p\n' 2>/dev/null \
      | sort -n | awk '{ $1=""; sub(/^ /,""); print }'
  )
  if (( ${#CANDS[@]} == 0 )); then
    log "No candidate pcaps to delete, but usage is ${use}%."
    return 0
  fi

  for f in "${CANDS[@]}"; do
    use="$(fs_usage_pct)"; (( use < target )) && { log "Stopped at ${use}% (< ${target}%)."; break; }
    is_open "$f" && { log "Skip open: $f"; continue; }
    case "$f" in
      "$PCAP_DIR"/*) delete_file "$f" ;;
      *) log "WARN: refusing to delete outside $PCAP_DIR: $f" ;;
    esac
  done
  use="$(fs_usage_pct)"; log "Prune complete. Usage now ${use}%"
}

# -------- logrotate install/execute --------
install_logrotate() {
  need logrotate
  local NOLOGIN_SHELL; NOLOGIN_SHELL="$(command -v nologin || echo /bin/false)"

  # ensure user/group
  getent passwd "$SURICATA_USER" >/dev/null || run "useradd --system --no-create-home --shell '$NOLOGIN_SHELL' '$SURICATA_USER'"
  getent group  "$SURICATA_GROUP" >/dev/null || run "groupadd '$SURICATA_GROUP'"
  run "usermod -g '$SURICATA_GROUP' '$SURICATA_USER' || true"

  # dirs & perms
  run "install -d -m 0755 '$LOG_DIR'"
  run "install -d -m 0755 '$PCAP_DIR'"
  run "chown -R '$SURICATA_USER':'$SURICATA_GROUP' '$LOG_DIR'"
  run "find '$LOG_DIR' -type d -exec chmod 750 {} +"
  run "find '$LOG_DIR' -type f -exec chmod 640 {} +"

  # text logs only — DO NOT include pcaps here
  read -r -d '' LR <<'EOF'
# Suricata text logs (PCAPs are pruned separately)
/var/log/suricata/*.log {
    rotate 2
    weekly
    missingok
    compress
    delaycompress
    notifempty
    su suricata suricata
    create 0640 suricata suricata
    sharedscripts
    postrotate
        /usr/bin/systemctl reload suricata > /dev/null 2>&1 || true
    endscript
}

/var/log/suricata/eve.json {
    rotate 2
    weekly
    missingok
    compress
    notifempty
    su suricata suricata
    create 0640 suricata suricata
    sharedscripts
    postrotate
        /usr/bin/systemctl reload suricata > /dev/null 2>&1 || true
    endscript
}
EOF

  if [[ $DRY_RUN -eq 1 ]]; then
    log "DRY-RUN: would write $LR_CONF with:"
    echo "$LR"
  else
    printf '%s\n' "$LR" > "$LR_CONF"
    chmod 0644 "$LR_CONF"
    log "Installed logrotate config: $LR_CONF"
  fi
}

rotate_now() {
  need logrotate
  local use; use="$(fs_usage_pct)"
  if (( use >= 95 )); then
    log "Usage ${use}% is very high; emergency prune first…"
    prune_pcaps
  fi
  if [[ $DRY_RUN -eq 1 ]]; then
    log "DRY-RUN: would run: logrotate -v '$LR_CONF'"
  else
    log "Running logrotate…"
    logrotate -v "$LR_CONF"
  fi
}

install_cron() {
  read -r -d '' CR <<EOF
# Keep Suricata PCAP usage under ${TARGET_USAGE}% (runs every 5 minutes)
*/5 * * * * root $SELF_PATH --prune >> /var/log/suricata-pcap-prune.log 2>&1
# Rotate text logs nightly at 00:07
7 0 * * * root $SELF_PATH --rotate >> /var/log/suricata-rotate.log 2>&1
EOF
  if [[ $DRY_RUN -eq 1 ]]; then
    log "DRY-RUN: would write $CRON_FILE with:"; echo "$CR"
  else
    printf '%s\n' "$CR" > "$CRON_FILE"
    chmod 0644 "$CRON_FILE"
    log "Installed cron: $CRON_FILE"
  fi
}

# -------- main --------
need df; need awk
if ! command -v lsof >/dev/null 2>&1 && ! command -v fuser >/dev/null 2>&1; then
  log "Installing lsof is recommended for open-file checks."
fi
command -v systemctl >/dev/null 2>&1 || true

if (( DO_INSTALL == 1 )); then
  install_logrotate
  install_cron
  log "Post-install: initial prune then rotate…"
  prune_pcaps
  rotate_now
fi

if (( DO_INSTALL == 0 && DO_PRUNE == 1 )); then prune_pcaps; fi
if (( DO_INSTALL == 0 && DO_ROTATE == 1 )); then rotate_now; fi

log "Done."
exit 0

