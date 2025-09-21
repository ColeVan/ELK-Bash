#!/usr/bin/env bash
# orchestrate.sh — ELK + Remote Deploy Orchestrator with NSM tracking & auto-probe
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ELK_ENV_FILE="${ELK_ENV_FILE:-$SCRIPT_DIR/.elk_env}"

# ----------------------------
# Colors / helpers
# ----------------------------
if [[ -f "$SCRIPT_DIR/functions.sh" ]]; then
  # shellcheck source=/dev/null
  source "$SCRIPT_DIR/functions.sh"
  type init_colors >/dev/null 2>&1 && init_colors || true
fi
: "${GREEN:=$'\e[32m'}"; : "${YELLOW:=$'\e[33m'}"; : "${RED:=$'\e[31m'}"
: "${CYAN:=$'\e[36m'}";  : "${NC:=$'\e[0m'}"
: "${BOLD:=$'\e[1m'}";   : "${DIM:=$'\e[2m'}"

FORCE_EXIT_ON_INT="${FORCE_EXIT_ON_INT:-false}"
trap 'echo -e "\n${YELLOW}⚠️  Operation interrupted by user.${NC}"; if bool_true "$FORCE_EXIT_ON_INT"; then exit 130; else echo -e "${YELLOW}Returning to main menu...${NC}"; sleep 1; fi' SIGINT

# ----------------------------
# Minimal fallbacks for common helpers (only if missing)
# ----------------------------
type load_env >/dev/null 2>&1 || load_env() {
  [[ -f "$ELK_ENV_FILE" ]] || { echo '# ELK Deployment State' > "$ELK_ENV_FILE"; }
  # shellcheck disable=SC1090
  source <(grep -E '^[A-Za-z_][A-Za-z0-9_]*="[^"]*"$' "$ELK_ENV_FILE" || true)
}
type bool_true >/dev/null 2>&1 || bool_true() { [[ "${1,,}" =~ ^(y|yes|true|1)$ ]]; }
type persist_bool >/dev/null 2>&1 || persist_bool() { local k="$1" v="$2"; [[ "$v" == "true" || "$v" == "false" ]] || v="false"; persist_kv "$k" "$v"; }
type pause_and_return_to_menu >/dev/null 2>&1 || pause_and_return_to_menu() { read -rp "$(echo -e "${YELLOW}Press Enter to return to the menu...${NC}")"; }
type run_script >/dev/null 2>&1 || run_script() { bash "$1"; }

# ----------------------------
# Ensure .elk_env exists
# ----------------------------
if [[ ! -f "$ELK_ENV_FILE" ]]; then
  {
    echo "# ELK Deployment State"
    echo "DEPLOY_STARTED=\"$(date '+%Y-%m-%d %H:%M:%S')\""
  } > "$ELK_ENV_FILE"
fi
load_env

# ----------------------------
# State persistence helpers
# ----------------------------
persist_kv() {
  local k="$1" v="$2"
  [[ -n "$k" ]] || return 0
  [[ -f "$ELK_ENV_FILE" ]] || touch "$ELK_ENV_FILE"
  if grep -qE "^${k}=" "$ELK_ENV_FILE"; then
    v="$(printf '%s' "$v" | sed 's/[\/&]/\\&/g')"
    sed -i "s|^${k}=\".*\"$|${k}=\"${v}\"|" "$ELK_ENV_FILE"
  else
    printf '%s="%s"\n' "$k" "$v" >> "$ELK_ENV_FILE"
  fi
}

persist_list_add() {
  local var="$1" item="$2"
  [[ -n "$var" && -n "$item" ]] || return 0
  load_env 2>/dev/null || true
  local cur; cur="$(eval "printf '%s' \"\${$var:-}\"")"
  for x in $cur; do [[ "$x" == "$item" ]] && { persist_kv "$var" "$cur"; return 0; }; done
  [[ -n "$cur" ]] && cur="$cur $item" || cur="$item"
  persist_kv "$var" "$cur"
}

host_token() { printf '%s\n' "${1//./_}"; }

record_host_status() {
  local ns="$1" host="$2" status="$3" ts
  ts="$(date '+%Y-%m-%d %H:%M:%S')"
  local tok; tok="$(host_token "$host")"
  persist_kv "${ns}_NODE_${tok}_STATUS" "$status"
  persist_kv "${ns}_NODE_${tok}_UPDATED_AT" "$ts"
}

status_chip() {
  case "$1" in
    success|ok|running)  printf "%b✔%b" "$GREEN" "$NC" ;;
    partial|degraded)    printf "%b!%b" "$YELLOW" "$NC" ;;
    failed|error)        printf "%b✖%b" "$RED" "$NC" ;;
    pending|unknown|*)   printf "%b•%b" "$YELLOW" "$NC" ;;
  esac
}

# ----------------------------
# Progress & UI helpers
# ----------------------------
progress_bar() {
  local steps=5 done=0
  [[ "${FOUNDATION_SETUP:-}" == "true" ]] && ((done++))
  [[ "${SERVICE_INSTALL:-}" == "true" ]] && ((done++))
  [[ "${AGENT_FLEET_SETUP:-}" == "true" ]] && ((done++))
  [[ "${EPR_CONFIGURED:-}" == "true" ]] && ((done++))
  [[ "${FIREWALL_HARDENED:-}" == "true" ]] && ((done++))

  local width=30; (( width < 1 )) && width=30
  local filled=$(( done * width / steps )); (( filled < 0 )) && filled=0; (( filled > width )) && filled="$width"
  local empty=$(( width - filled ))

  printf "%b" "${CYAN}[${NC}"
  (( filled > 0 )) && { printf "%b" "${GREEN}"; printf "%${filled}s" "" | tr ' ' '#'; printf "%b" "${NC}"; }
  (( empty > 0 )) && { printf "%b" "${DIM}";   printf "%${empty}s" ""  | tr ' ' '-'; printf "%b" "${NC}"; }
  printf "%b\n" "${CYAN}] ${GREEN}${done}${NC}/${CYAN}${steps}${NC}"
}

legend_line() { echo -e "${DIM}Keys:${NC} ${GREEN}l${NC}=view log  ${DIM}|${NC}  ${GREEN}q${NC}=quit"; }
done_chip() { [[ "${1:-}" == "true" ]] && echo -e " ${GREEN}(done)${NC}" || echo ""; }

# ----------------------------
# Service status helpers (env-independent)
# ----------------------------
unit_exists() { systemctl cat "${1}.service" >/dev/null 2>&1; }
unit_active() { systemctl is-active --quiet "${1}.service"; }
pkg_installed() { local s; s="$(dpkg-query -W -f='${Status}' "$1" 2>/dev/null || true)"; [[ "$s" == *"install ok installed"* ]]; }

get_service_state() {
  local svc="$1" unit="$1" pkg="$1"
  case "$svc" in
    elasticsearch) unit="elasticsearch"; pkg="elasticsearch" ;;
    logstash)      unit="logstash";      pkg="logstash" ;;
    kibana)        unit="kibana";        pkg="kibana" ;;
    elastic-agent) unit="elastic-agent"; pkg="elastic-agent" ;;
    *)             unit="$svc";          pkg="$svc" ;;
  esac

  if unit_active "$unit"; then echo "RUNNING"; return; fi
  if unit_exists "$unit" || pkg_installed "$pkg"; then echo "INSTALLED_STOPPED"; return; fi
  echo "NOT_INSTALLED"
}

status_box() {
  local state="$1"
  case "$state" in
    RUNNING)           printf "[%bx%b]" "$GREEN" "$NC" ;;
    INSTALLED_STOPPED) printf "[%b!%b]" "$YELLOW" "$NC" ;;
    NOT_INSTALLED|*)   printf "[ ]" ;;
  esac
}

render_service_status_row() {
  local es ls kb ag
  es="$(get_service_state elasticsearch)"
  ls="$(get_service_state logstash)"
  kb="$(get_service_state kibana)"
  ag="$(get_service_state elastic-agent)"

  printf "%b" "${CYAN}----------------------------------------------------------------${NC}\n"
  printf " %bServices%b:  ES %s  |  LS %s  |  KB %s  |  Agent %s\n" \
    "$BOLD" "$NC" "$(status_box "$es")" "$(status_box "$ls")" "$(status_box "$kb")" "$(status_box "$ag")"
  printf "           %bLegend%b: %s running   %s installed, stopped   %s not installed\n" \
    "$DIM" "$NC" "$(printf '[%bx%b]' "$GREEN" "$NC")" "$(printf '[%b!%b]' "$YELLOW" "$NC")" "[ ]"
}

# ----------------------------
# Remote status renderers
# ----------------------------
render_remote_counters() {
  load_env 2>/dev/null || true
  local es_count=0 nsm_count=0
  for _ in ${REMOTE_ES_NODES:-};  do ((es_count++));  done
  for _ in ${NSM_REMOTE_NODES:-}; do ((nsm_count++)); done
  printf " %bRemote%b:  ES nodes %s  •  NSM nodes %s\n" "$BOLD" "$NC" "$es_count" "$nsm_count"
}

render_remote_details() {
  load_env 2>/dev/null || true
  local it tok st ts zst sst
  if [[ -n "${REMOTE_ES_NODES:-}" ]]; then
    echo -e "${DIM}Elasticsearch remote nodes:${NC}"
    for it in $REMOTE_ES_NODES; do
      tok="$(host_token "$it")"
      st="$(eval "printf '%s' \"\${ES_NODE_${tok}_STATUS:-unknown}\"")"
      ts="$(eval "printf '%s' \"\${ES_NODE_${tok}_UPDATED_AT:-n/a}\"")"
      printf "   %s  %s  %s\n" "$(status_chip "$st")" "$it" "${DIM}${ts}${NC}"
    done
  fi
  if [[ -n "${NSM_REMOTE_NODES:-}" ]]; then
    echo -e "${DIM}NSM (Zeek/Suricata) remote nodes:${NC}"
    for it in $NSM_REMOTE_NODES; do
      tok="$(host_token "$it")"
      st="$(eval "printf '%s' \"\${NSM_NODE_${tok}_STATUS:-unknown}\"")"
      ts="$(eval "printf '%s' \"\${NSM_NODE_${tok}_UPDATED_AT:-n/a}\"")"
      zst="$(eval "printf '%s' \"\${NSM_NODE_${tok}_ZEEK:-unknown}\"")"
      sst="$(eval "printf '%s' \"\${NSM_NODE_${tok}_SURI:-unknown}\"")"
      printf "   %s  %s  %s  %s%s%s\n" \
        "$(status_chip "$st")" "$it" \
        "${DIM}${ts}${NC}" \
        "${DIM}[zeek:${NC}${zst}${DIM}, suri:${NC}${sst}${DIM}]${NC}"
    done
  fi
}

# ----------------------------
# Remote probing (SSH)
# ----------------------------
remote_ssh() {
  local host="$1" port="$2" user="$3" cmd="$4"
  ssh -o BatchMode=yes -o ConnectTimeout=6 -o StrictHostKeyChecking=no -p "$port" "${user}@${host}" "$cmd"
}

probe_es_host() {
  local host="$1" port="$2" user="$3"
  # Try systemd elasticsearch or docker container name with 'elasticsearch'
  if remote_ssh "$host" "$port" "$user" "systemctl is-active --quiet elasticsearch"; then
    echo "running"; return 0
  fi
  if remote_ssh "$host" "$port" "$user" "command -v docker >/dev/null 2>&1 && docker ps --format '{{.Names}}' | grep -qi elasticsearch"; then
    echo "running"; return 0
  fi
  echo "failed"; return 1
}

probe_nsm_host() {
  local host="$1" port="$2" user="$3"
  local z="failed" s="failed"
  if remote_ssh "$host" "$port" "$user" "systemctl is-active --quiet zeek"; then z="running"; fi
  if remote_ssh "$host" "$port" "$user" "systemctl is-active --quiet suricata"; then s="running"; fi

  # Overall status: both running -> running; only one -> partial; none -> failed
  local overall="failed"
  if [[ "$z" == "running" && "$s" == "running" ]]; then overall="running"
  elif [[ "$z" == "running" || "$s" == "running" ]]; then overall="partial"
  fi

  echo "$overall|$z|$s"
}

refresh_remote_status() {
  clear
  echo -e "${CYAN}----------------------------------------------------------------${NC}"
  echo -e " ${BOLD}${GREEN}Refresh Remote Status (ES / Zeek / Suricata)${NC}"
  echo -e "${CYAN}----------------------------------------------------------------${NC}"

  load_env

  local SSH_USER SSH_PORT
  read -r -p "$(echo -e "${GREEN}SSH user [${USER}]: ${NC}")" SSH_USER
  SSH_USER="${SSH_USER:-$USER}"
  read -r -p "$(echo -e "${GREEN}SSH port [22]: ${NC}")" SSH_PORT
  SSH_PORT="${SSH_PORT:-22}"

  # ES nodes
  if [[ -n "${REMOTE_ES_NODES:-}" ]]; then
    echo -e "${CYAN}🔍 Probing Elasticsearch nodes...${NC}"
    for h in $REMOTE_ES_NODES; do
      printf "  %s ... " "$h"
      local es_state; es_state="$(probe_es_host "$h" "$SSH_PORT" "$SSH_USER")" || true
      if [[ "$es_state" == "running" ]]; then
        echo -e "${GREEN}running${NC}"
        record_host_status "ES" "$h" "running"
      else
        echo -e "${RED}failed${NC}"
        record_host_status "ES" "$h" "failed"
      fi
    done
  fi

  # NSM nodes
  if [[ -n "${NSM_REMOTE_NODES:-}" ]]; then
    echo -e "${CYAN}🔍 Probing NSM nodes (Zeek/Suricata)...${NC}"
    for h in $NSM_REMOTE_NODES; do
      printf "  %s ... " "$h"
      local out; out="$(probe_nsm_host "$h" "$SSH_PORT" "$SSH_USER")"
      local overall="${out%%|*}"; local rest="${out#*|}"
      local z="${rest%%|*}"; local s="${rest##*|}"

      case "$overall" in
        running) echo -e "${GREEN}running${NC}" ;;
        partial) echo -e "${YELLOW}partial${NC}" ;;
        *)       echo -e "${RED}failed${NC}" ;;
      esac
      # Persist per-service & overall
      local tok; tok="$(host_token "$h")"
      persist_kv "NSM_NODE_${tok}_ZEEK" "$z"
      persist_kv "NSM_NODE_${tok}_SURI" "$s"
      record_host_status "NSM" "$h" "$overall"
    done
  fi

  echo -e "${GREEN}✔ Remote status refreshed. Returning to menu...${NC}"
  sleep 1
  pause_and_return_to_menu
}

# ----------------------------
# Full send
# ----------------------------
run_full_setup() {
  clear
  echo -e "${CYAN}Starting full setup...${NC}"

  # Expand variables at signal time; works fine with single-quoted trap string.
  trap 'echo -e "\n${YELLOW}⚠️  Setup interrupted. Returning to main menu...${NC}"; return 130' SIGINT

  load_env

  # Resume/fresh prompt if we see prior state
  if [[ -f "$ELK_ENV_FILE" ]] && grep -Eq '^(FOUNDATION_SETUP|SERVICE_INSTALL|AGENT_FLEET_SETUP|AIRGAPPED_MODE|EPR_CONFIGURED|REMOTE_DEPLOY_TRIGGERED|DEPLOYMENT_TYPE|REMOTE_ES_NODES|NSM_REMOTE_NODES)=' "$ELK_ENV_FILE"; then
    ELK_ENV_MTIME="$(date -r "$ELK_ENV_FILE" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo 'unknown')"
    echo -e "${YELLOW}Detected previous deployment state at:${NC} ${CYAN}${ELK_ENV_FILE}${NC}"
    echo -e "${YELLOW}Last updated:${NC} ${CYAN}${ELK_ENV_MTIME}${NC}"
    echo -e "${CYAN}Options:${NC}"
    echo -e "  ${GREEN}yes${NC}  → Remove saved state and perform a ${YELLOW}fresh install${NC}"
    echo -e "  ${GREEN}no${NC}   → Keep saved state and ${YELLOW}resume from where you left off${NC}"
    echo
    echo -e "${YELLOW}Default:${NC} ${GREEN}yes (fresh install)${NC}"
    echo

    if type prompt_input >/dev/null 2>&1; then
      prompt_input "$(echo -e "${GREEN}Delete saved state and start fresh? (${YELLOW}yes${GREEN}=fresh, ${YELLOW}no${GREEN}=resume) [default: ${YELLOW}yes${GREEN}]: ${NC}")" RESET_ENV
    else
      read -r -p "$(echo -e "${GREEN}Delete saved state and start fresh? (${YELLOW}yes${GREEN}=fresh, ${YELLOW}no${GREEN}=resume) [default: ${YELLOW}yes${GREEN}]: ${NC}")" RESET_ENV
    fi

    # Default to "yes" if user pressed Enter
    RESET_ENV="${RESET_ENV:-yes}"

    if bool_true "$RESET_ENV"; then
      local TS; TS="$(date '+%Y%m%d-%H%M%S')"
      cp -a -- "$ELK_ENV_FILE" "${ELK_ENV_FILE}.${TS}.bak" 2>/dev/null || true
      rm -f -- "$ELK_ENV_FILE" 2>/dev/null || true
      { echo "# ELK Deployment State"; echo "DEPLOY_STARTED=\"$(date '+%Y-%m-%d %H:%M:%S')\""; } > "$ELK_ENV_FILE"
      for _k in FOUNDATION_SETUP SERVICE_INSTALL AIRGAPPED_MODE EPR_CONFIGURED AGENT_FLEET_SETUP \
                DEPLOYMENT_TYPE REMOTE_DEPLOY_TRIGGERED FOUNDATION_CANCELLED DEPLOY_COMPLETE \
                OFFLINE_MODE SHOW_TMUX REMOTE_ES_NODES NSM_REMOTE_NODES; do
        unset "${_k}" 2>/dev/null || true
      done
      echo -e "${GREEN}✔ Previous state removed. Starting fresh deployment.${NC}"
      load_env
    else
      echo -e "${GREEN}✔ Resuming from saved state — previously completed steps will be skipped.${NC}"
    fi
  fi

  # Preflight
  echo -e "${YELLOW}Preflight (.elk_env):${NC}"
  echo -e "  SERVICE_INSTALL=${CYAN}${SERVICE_INSTALL:-}<${NC}"
  echo -e "  AIRGAPPED_MODE=${CYAN}${AIRGAPPED_MODE:-}<${NC}"
  echo -e "  AGENT_FLEET_SETUP=${CYAN}${AGENT_FLEET_SETUP:-}<${NC}"
  echo -e "  DEPLOYMENT_TYPE=${CYAN}${DEPLOYMENT_TYPE:-}<${NC}"
  echo -e "  REMOTE_DEPLOY_TRIGGERED=${CYAN}${REMOTE_DEPLOY_TRIGGERED:-}<${NC}"
  echo

  {
    # STEP 1: Foundation
    if ! bool_true "${FOUNDATION_SETUP:-false}"; then
      # shellcheck source=/dev/null
      source "$SCRIPT_DIR/foundation.sh" || true
      load_env
      if bool_true "${FOUNDATION_CANCELLED:-false}"; then
        echo -e "${YELLOW}Foundation cancelled. Returning to menu.${NC}"
        trap - SIGINT; pause_and_return_to_menu; return 0
      fi
      type log_step >/dev/null 2>&1 && log_step "FOUNDATION_SETUP" "true" || true
      persist_bool "FOUNDATION_SETUP" "true"
    else
      echo -e "${GREEN}✔ Foundation already done.${NC}"
    fi

    # STEP 2: Services
    if ! bool_true "${SERVICE_INSTALL:-false}"; then
      # shellcheck source=/dev/null
      source "$SCRIPT_DIR/service_install_setup.sh"
      type log_step >/dev/null 2>&1 && log_step "SERVICE_INSTALL" "true" || true
      persist_bool "SERVICE_INSTALL" "true"
    else
      echo -e "${GREEN}✔ Services already installed.${NC}"
    fi

    # STEP 3-4: Airgapped / EPR
    if [[ -z "${AIRGAPPED_MODE:-}" ]]; then
      echo -e "\n${YELLOW}Will this be moved to an airgapped environment after setup?${NC}"
      echo -e "  ${GREEN}[1] Yes${NC} — set up local Elastic Package Registry (EPR)"
      echo -e "  ${GREEN}[2] No ${NC} — continue without EPR (default)"
      OFFLINE_MODE=""
      local retries=0 max_retries=3
      while true; do
        ((retries++))
        read -rp "$(echo -e "${YELLOW}Select option [1-2, default 2]: ${NC}")" choice
        [[ -z "$choice" ]] && choice="2"   # default = No
        case "$choice" in
          1) OFFLINE_MODE="yes"; break ;;
          2) OFFLINE_MODE="no";  break ;;
          *) 
            echo -e "${YELLOW}Invalid choice. Please enter 1 or 2.${NC}"
            [[ $retries -ge $max_retries ]] && { echo -e "${RED}Too many invalid attempts. Defaulting to 'no'.${NC}"; OFFLINE_MODE="no"; break; }
            ;;
        esac
      done

      if [[ "$OFFLINE_MODE" == "yes" ]]; then
        echo -e "${GREEN}Airgapped mode selected.${NC}"
        type log_step >/dev/null 2>&1 && log_step "AIRGAPPED_MODE" "true" || true
        persist_bool "AIRGAPPED_MODE" "true"
        echo -e "${CYAN}📦 Setting up Elastic Package Registry...${NC}"
        # shellcheck source=/dev/null
        source "$SCRIPT_DIR/Elastic_EPR_install.sh"
        type log_step >/dev/null 2>&1 && log_step "EPR_CONFIGURED" "true" || true
        persist_bool "EPR_CONFIGURED" "true"
      else
        type log_step >/dev/null 2>&1 && log_step "AIRGAPPED_MODE" "false" || true
        persist_bool "AIRGAPPED_MODE" "false"
        echo -e "${GREEN}Continuing without local EPR...${NC}"
      fi

    else
      if bool_true "${AIRGAPPED_MODE}"; then
        echo -e "${CYAN}📦 Airgapped mode previously selected. Ensuring EPR is configured...${NC}"
        # shellcheck source=/dev/null
        source "$SCRIPT_DIR/Elastic_EPR_install.sh"
        type log_step >/dev/null 2>&1 && log_step "EPR_CONFIGURED" "true" || true
        persist_bool "EPR_CONFIGURED" "true"
      else
        echo -e "${GREEN}Airgapped mode disabled previously. Skipping EPR setup...${NC}"
      fi
    fi

    # STEP 5: Agent/Fleet
    if ! bool_true "${AGENT_FLEET_SETUP:-false}"; then
      echo -e "\n${CYAN}🔧 Installing Elastic Agent and configuring Fleet...${NC}"
      # shellcheck source=/dev/null
      source "$SCRIPT_DIR/agent_install_fleet_setup.sh"
      type log_step >/dev/null 2>&1 && log_step "AGENT_FLEET_SETUP" "true" || true
      persist_bool "AGENT_FLEET_SETUP" "true"
    else
      echo -e "${GREEN}✔ Agent/Fleet already configured.${NC}"
    fi

    # STEP 6: Summary
    echo -e "\n${GREEN}Summary of your configuration:${NC}"
    type populate_summary_rows >/dev/null 2>&1 && populate_summary_rows || true
    set +e; type print_summary_table >/dev/null 2>&1 && print_summary_table || true; set -e

    # STEP 6.5: Optional remote ES deploy for cluster
    case "${DEPLOYMENT_TYPE:-}" in
      [Cc]luster)
        if ! bool_true "${REMOTE_DEPLOY_TRIGGERED:-false}"; then
          if ! bool_true "${SERVICE_INSTALL:-false}"; then
            echo -e "${YELLOW}Skipping remote ES deploy: services not installed locally.${NC}"
          elif ! bool_true "${AGENT_FLEET_SETUP:-false}"; then
            echo -e "${YELLOW}Skipping remote ES deploy: Fleet not configured locally.${NC}"
          else
            echo -e "\n${CYAN}🌐 Cluster deployment detected.${NC}"
            local RUN_REMOTE=""
            if type prompt_input >/dev/null 2>&1; then
              prompt_input "$(echo -e "${GREEN}Run remote Elasticsearch node deployment now? ${YELLOW}(yes/no)${NC}: ")" RUN_REMOTE
            else
              read -r -p "$(echo -e "${GREEN}Run remote Elasticsearch node deployment now? ${YELLOW}(yes/no)${NC}: ")" RUN_REMOTE
            fi
            if bool_true "${RUN_REMOTE:-}"; then
              local REMOTE_ES_HOST=""
              read -r -p "$(echo -e "${GREEN}Enter remote ES host/IP to record (optional): ${NC}")" REMOTE_ES_HOST
              local REMOTE_SCRIPT="$SCRIPT_DIR/run_remote_deploy.sh"
              if ORCH_REMOTE_HOST="$REMOTE_ES_HOST" run_script "$REMOTE_SCRIPT"; then
                type log_step >/dev/null 2>&1 && log_step "REMOTE_DEPLOY_TRIGGERED" "true" || true
                persist_bool "REMOTE_DEPLOY_TRIGGERED" "true"
                [[ -n "$REMOTE_ES_HOST" ]] && { persist_list_add "REMOTE_ES_NODES" "$REMOTE_ES_HOST"; record_host_status "ES" "$REMOTE_ES_HOST" "success"; }
                echo -e "${GREEN}✅ Remote ES deployment executed.${NC}"
              else
                echo -e "${RED}❌ Remote ES deployment failed.${NC}"
                [[ -n "$REMOTE_ES_HOST" ]] && { persist_list_add "REMOTE_ES_NODES" "$REMOTE_ES_HOST"; record_host_status "ES" "$REMOTE_ES_HOST" "failed"; }
                persist_bool "REMOTE_DEPLOY_TRIGGERED" "false"
              fi
            else
              echo -e "${GREEN}✅ Skipping remote ES deployment at user request.${NC}"
            fi
          fi
        else
          echo -e "${GREEN}✔ Remote ES deployment previously completed. Skipping...${NC}"
        fi
        ;;
    esac

    # STEP 7: (Optional) tmux helper
    echo -e "\n${YELLOW}Would you like to see the TMUX cheat sheet now?${NC}"
    read -r -p "$(echo -e "${CYAN}Type yes or no: ${NC}")" SHOW_TMUX
    if bool_true "${SHOW_TMUX:-}"; then
      type tmux_help >/dev/null 2>&1 && tmux_help || echo -e "${YELLOW}(tmux_help not available)${NC}"
      type log_step >/dev/null 2>&1 && log_step "TMUX_HELP_SHOWN" "true" || true
      echo -e "${GREEN}✅ TMUX help displayed.${NC}"
    else
      echo -e "${GREEN}✅ Skipping TMUX help.${NC}"
    fi

    type log_step >/dev/null 2>&1 && log_step "DEPLOY_COMPLETE" "true" || true
  }

  trap - SIGINT
  pause_and_return_to_menu
}

# Safe helpers (no-exit on failures)
safe_hostname() { hostname 2>/dev/null || echo host; }
safe_primary_ip() {
  # Return first IPv4 or '-' without exiting the shell if hostname -I/awk fails
  local ip
  ip="$({ hostname -I 2>/dev/null | awk '{print $1}'; } 2>/dev/null || true)"
  echo "${ip:-"-"}"
}
safe_pretty_os() {
  # Prefer /etc/os-release; never fail under -e
  local name
  name="$({ . /etc/os-release 2>/dev/null && echo "${PRETTY_NAME:-Linux}"; } 2>/dev/null || true)"
  echo "${name:-Linux}"
}

# ----------------------------
# Menu icons
# ----------------------------
ICO_DEPLOY="${CYAN}🚀${NC}"
ICO_SETUP="${CYAN}🛠️ ${NC}"
ICO_SERVICES="${CYAN}📡${NC}"
ICO_AGENT="${CYAN}🔧${NC}"
ICO_EPR="${CYAN}📦${NC}"
ICO_CLEAN="${RED}🗑️ ${NC}"
ICO_WALL="${YELLOW}🧱${NC}"
ICO_LOGS="${CYAN}📜${NC}"
ICO_REMOTE="${CYAN}🌐${NC}"
ICO_ZEEK="${CYAN}🔎${NC}"
ICO_SURI="${CYAN}🕵️ ${NC}"
ICO_NSM="${CYAN}🌐🔎${NC}"
ICO_RAGENT="${CYAN}🌐🔧${NC}"
ICO_REFRESH="${CYAN}♻️ ${NC}"
ICO_EXIT="${RED}❌${NC}"
num() { printf " ${DIM}%s${NC}" "$1"; }

# =========================
# main menu
# =========================

# restore on exit
_menu_restore_cursor() { tput cnorm 2>/dev/null || true; }
trap _menu_restore_cursor EXIT

# Read a single key (arrow/enter/space/q)
_read_key() {
  local k
  IFS= read -rsn1 k || return 1          # first byte
  if [[ "$k" == $'\x1b' ]]; then         # possible escape seq
    local k2 k3
    IFS= read -rsn1 -t 0.005 k2 || { REPLY="$k"; return 0; }
    IFS= read -rsn1 -t 0.005 k3 || true
    REPLY="$k$k2$k3"
  else
    REPLY="$k"
  fi
  return 0
}

# boolean state from env vars
_bool_chip() { # $1=VAR
  local v="${!1:-}"
  if [[ "$v" == "true" ]]; then echo -e "[${GREEN}x${NC}]"; else echo -e "[ ]"; fi
}

# Execute by numeric id (1..16)
_execute_action_by_id() {
  local id="$1"
  case "$id" in
    1) run_full_setup ;;
    2) clear; source "$SCRIPT_DIR/foundation.sh"; type log_step >/dev/null 2>&1 && log_step "FOUNDATION_SETUP" "true" || true; pause_and_return_to_menu ;;
    3) clear; source "$SCRIPT_DIR/service_install_setup.sh"; type log_step >/dev/null 2>&1 && log_step "SERVICE_INSTALL" "true" || true; persist_bool "SERVICE_INSTALL" "true"; pause_and_return_to_menu ;;
    4) if require_service_installed; then clear; source "$SCRIPT_DIR/agent_install_fleet_setup.sh"; type log_step >/dev/null 2>&1 && log_step "AGENT_FLEET_SETUP" "true" || true; persist_bool "AGENT_FLEET_SETUP" "true"; fi; pause_and_return_to_menu ;;
    5) if require_service_installed; then clear; source "$SCRIPT_DIR/Elastic_EPR_install.sh"; type log_step >/dev/null 2>&1 && log_step "EPR_CONFIGURED" "true" || true; persist_bool "EPR_CONFIGURED" "true"; fi; pause_and_return_to_menu ;;
    6) type run_elk_cleanup >/dev/null 2>&1 && run_elk_cleanup || echo -e "${YELLOW}cleanup function not found${NC}"; pause_and_return_to_menu ;;
    7) type run_firewall_hardening >/dev/null 2>&1 && run_firewall_hardening || echo -e "${YELLOW}firewall function not found${NC}"; pause_and_return_to_menu ;;
    8) type view_env_file >/dev/null 2>&1 && view_env_file || { echo -e "${CYAN}--- .elk_env ---${NC}"; cat "$ELK_ENV_FILE"; echo; pause_and_return_to_menu; };;
    9) clear; local REMOTE_ES_HOST=""; read -r -p "$(echo -e "${GREEN}Enter remote Elasticsearch host/IP to record (optional): ${NC}")" REMOTE_ES_HOST; local REMOTE_SCRIPT="$SCRIPT_DIR/run_remote_deploy.sh"; if ORCH_REMOTE_HOST="$REMOTE_ES_HOST" run_script "$REMOTE_SCRIPT"; then [[ -n "$REMOTE_ES_HOST" ]] && { persist_list_add "REMOTE_ES_NODES" "$REMOTE_ES_HOST"; record_host_status "ES" "$REMOTE_ES_HOST" "success"; }; else [[ -n "$REMOTE_ES_HOST" ]] && { persist_list_add "REMOTE_ES_NODES" "$REMOTE_ES_HOST"; record_host_status "ES" "$REMOTE_ES_HOST" "failed"; }; fi; pause_and_return_to_menu ;;
    10) deploy_es_agents; pause_and_return_to_menu ;;
    11) type run_zeek_deploy     >/dev/null 2>&1 && run_zeek_deploy     || echo -e "${YELLOW}zeek_deploy function not found${NC}"; pause_and_return_to_menu ;;
    12) type run_suricata_deploy >/dev/null 2>&1 && run_suricata_deploy || echo -e "${YELLOW}suricata_deploy function not found${NC}"; pause_and_return_to_menu ;;
    13) run_remote_nsm_deployment; pause_and_return_to_menu ;;
    14) run_nsm_enroll_remote; pause_and_return_to_menu ;;
    15) refresh_remote_status ;;
    16) echo -e "${GREEN}Exiting setup. Goodbye!${NC}"; exit 0 ;;
    *) : ;;
  esac
}

# Render the status header/top bars
_render_header() {
  clear
  load_env 2>/dev/null || true

  local HOSTNAME IP OS_NAME
  HOSTNAME="$(safe_hostname)"
  IP="$(safe_primary_ip)"
  OS_NAME="$(safe_pretty_os)"

  echo -e "${CYAN}----------------------------------------------------------------${NC}"
  echo -e " 🛠️  ${BOLD}${GREEN}ELK Stack Deployment Menu${NC}"
  echo -e "${CYAN}----------------------------------------------------------------${NC}"
  echo -e "[${GREEN}Host${NC}: ${HOSTNAME}] [${GREEN}IP${NC}: ${IP}] [${GREEN}OS${NC}: ${OS_NAME}]"

  render_service_status_row
  render_remote_counters

  local svc_box="$(_bool_chip SERVICE_INSTALL)"
  local fleet_box="$(_bool_chip AGENT_FLEET_SETUP)"
  local epr_box="$(_bool_chip EPR_CONFIGURED)"
  echo -e "[${GREEN}Services${NC}: ${svc_box}] [${GREEN}Fleet${NC}: ${fleet_box}] [${GREEN}EPR${NC}: ${epr_box}]"

  local USAGE_PERCENT WIDTH FILLED EMPTY
  USAGE_PERCENT="$( { df -h / 2>/dev/null | awk 'NR==2 {gsub("%","",$5); print $5}'; } || true )"
  [[ -z "$USAGE_PERCENT" || ! "$USAGE_PERCENT" =~ ^[0-9]+$ ]] && USAGE_PERCENT=0
  WIDTH=30
  FILLED=$(( USAGE_PERCENT * WIDTH / 100 ))
  (( FILLED < 0 )) && FILLED=0
  (( FILLED > WIDTH )) && FILLED=$WIDTH
  EMPTY=$(( WIDTH - FILLED ))

  printf "[${GREEN}Storage${NC}: %3s%% " "$USAGE_PERCENT"
  printf "%b" "${CYAN}[${NC}"
  (( FILLED > 0 )) && { printf "%b" "${GREEN}"; printf "%${FILLED}s" "" | tr ' ' '#'; printf "%b" "${NC}"; }
  (( EMPTY > 0 )) && { printf "%b" "${DIM}";   printf "%${EMPTY}s" ""  | tr ' ' '-'; printf "%b" "${NC}"; }
  printf "%b\n\n" "${CYAN}]${NC}"
}

# Build the item arrays (labels, notes, lock, state var)
_build_menu_model() {
  local services_ready
  if service_install_ok; then services_ready=1; else services_ready=0; fi
  load_env  # Ensure env vars are loaded for dynamic notes

  local foundation_note=""
  if bool_true "${FOUNDATION_SETUP:-false}"; then
    foundation_note="${GREEN}(completed via full setup)${NC}"
  fi

  # Items: id|icon|label|note|statevar|locked
  MENU_ITEMS=(
    "1|$ICO_DEPLOY|Deploy Elasticsearch, Logstash, and Kibana \"ELK\" on this node||0"
    "2|$ICO_SETUP|Run foundational setup|$foundation_note|FOUNDATION_SETUP|0"
    "3|$ICO_SERVICES|Only deploy \"ELK\" services||SERVICE_INSTALL|0"
    "4|$ICO_AGENT|Deploy Elastic Agent in Fleet mode on this node|$( ((services_ready)) || echo "${YELLOW}(requires services to be installed)${NC}")|AGENT_FLEET_SETUP|$(( services_ready ? 0 : 1 ))"
    "5|$ICO_EPR|Install Elastic Package Registry with Docker|$( ((services_ready)) || echo "${YELLOW}(requires services to be installed)${NC}")|EPR_CONFIGURED|$(( services_ready ? 0 : 1 ))"
    "6|$ICO_CLEAN|Cleanup all services and start fresh|||0"
    "7|$ICO_WALL|Firewall Hardening (iptables)|||0"
    "8|$ICO_LOGS|View deployment log (.elk_env)|||0"
    "9|$ICO_REMOTE|Deploy Remote Elasticsearch Node|||0"
    "10|$ICO_RAGENT|Deploy Elastic Agent to remote nodes||REMOTE_AGENT_DEPLOYED|0"
    "11|$ICO_ZEEK|Deploy Zeek (local)|||0"
    "12|$ICO_SURI|Deploy Suricata (local)|||0"
    "13|$ICO_NSM|Deploy NSM on a remote node (Zeek & Suricata)|||0"
    "14|$ICO_RAGENT|Enroll remote NSM sensor nodes||NSM_REMOTE_DEPLOYED|0"
    "15|$ICO_REFRESH|Refresh remote status (SSH probe ES/Zeek/Suricata)|||0"
    "16|$ICO_EXIT|Exit|||0"
  )
}

# Draw the interactive list with a highlight on $1 (row index, 0-based)
_draw_menu_list() {
  local idx="$1" total="${#MENU_ITEMS[@]}"
  local i line id icon label note statevar locked
  for (( i=0; i<total; i++ )); do
    IFS='|' read -r id icon label note statevar locked <<<"${MENU_ITEMS[$i]}"
    local box="[ ]"
    [[ -n "$statevar" && "${!statevar:-}" == "true" ]] && box="[${GREEN}x${NC}]"

    local lock_prefix="" lock_note=""
    if [[ "$locked" == "1" ]]; then lock_prefix="🔒 "; fi
    if [[ -n "$note" ]]; then lock_note=" ${note}"; fi

    if (( i == idx )); then
      # highlight line
      echo -e " ${CYAN}>${NC} ${lock_prefix}${icon}${BOLD}${label}${NC} ${lock_note}  $box"
    else
      echo -e "   ${lock_prefix}${icon}${label} ${lock_note}  $box"
    fi

    # After item 1, add subline hint (like your original)
    if [[ "$id" == "1" ]]; then
      echo -e "     ${YELLOW}↳ Option during setup for remote Elasticsearch node to be setup${NC}"
    fi
  done

  echo
  legend_line
  echo
  echo -e " ${YELLOW}💡 Tip:${NC} If setup is interrupted or breaks, you can rerun the menu with:"
  echo -e "    ${CYAN}bash ./orchestrate.sh${NC}"
  echo
  echo -e " ${DIM}Use ↑/↓ to select • Enter to run • q to quit • l to view .elk_env${NC}"
}

# Main interactive loop
main_menu() {
  set +e  # rendering shouldn’t kill the shell
  tput civis 2>/dev/null || true

  local cursor=0 key total id icon label note statevar locked
  while :; do
    _render_header
    _build_menu_model
    total="${#MENU_ITEMS[@]}"
    (( cursor < 0 )) && cursor=0
    (( cursor >= total )) && cursor=$((total-1))
    _draw_menu_list "$cursor"

    _read_key || continue
    key="$REPLY"
    case "$key" in
      $'\x1b[A')  cursor=$((cursor-1)); (( cursor < 0 )) && cursor=0 ;;           # Up
      $'\x1b[B')  cursor=$((cursor+1)); (( cursor >= total )) && cursor=$((total-1)) ;; # Down
      "")         # Enter
                  IFS='|' read -r id icon label note statevar locked <<<"${MENU_ITEMS[$cursor]}"
                  if [[ "$locked" == "1" ]]; then
                    echo -e "${YELLOW}⚠️  '${label}' is locked until services are installed.${NC}"
                    sleep 1
                  else
                    _menu_restore_cursor
                    _execute_action_by_id "$id"
                    tput civis 2>/dev/null || true
                  fi
                  ;;
      l|L)        _menu_restore_cursor; type view_env_file >/dev/null 2>&1 && view_env_file || { echo -e "${CYAN}--- .elk_env ---${NC}"; cat "$ELK_ENV_FILE"; echo; read -rp "Press Enter to return..." _; }; tput civis 2>/dev/null || true ;;
      q|Q)        _menu_restore_cursor; echo -e "${GREEN}Exiting setup. Goodbye!${NC}"; exit 0 ;;
      *)          : ;;
    esac
  done
  set -e  # Restore strict mode after menu
}

# keep main menu running
while true; do
  main_menu
  load_env  # Reload to check flags
  if bool_true "${DEPLOY_COMPLETE:-false}"; then
    echo -e "${GREEN}Deployment complete! Exiting.${NC}"
    exit 0
  fi
done