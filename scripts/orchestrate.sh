#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ELK_ENV_FILE="${ELK_ENV_FILE:-$SCRIPT_DIR/.elk_env}"

# functions.sh (colors, helpers)
if [[ -f "$SCRIPT_DIR/functions.sh" ]]; then
  # shellcheck source=/dev/null
  source "$SCRIPT_DIR/functions.sh"
  type init_colors &>/dev/null && init_colors || true
fi
: "${GREEN:=$'\e[32m'}"; : "${YELLOW:=$'\e[33m'}"; : "${RED:=$'\e[31m'}"
: "${CYAN:=$'\e[36m'}";  : "${NC:=$'\e[0m'}"

trap 'echo -e "\n${YELLOW}⚠️  Operation interrupted by user. Returning to main menu...${NC}"; sleep 1' SIGINT

# =========================
# ELK ENV HELPERS
# =========================
if [[ ! -f "$ELK_ENV_FILE" ]]; then
  {
    echo "# ELK Deployment State"
    echo "DEPLOY_STARTED=\"$(date '+%Y-%m-%d %H:%M:%S')\""
  } > "$ELK_ENV_FILE"
fi

load_env

# =========================
# Run the full ELK setup (RESUMABLE options)
# =========================
run_full_setup() {
  clear
  echo -e "${CYAN}Starting full setup...${NC}"
  trap 'echo -e "\n${YELLOW}⚠️  Setup interrupted. Returning to main menu...${NC}"; return 130' SIGINT

  # Always read the latest state first
  load_env

  #Resume or Start Fresh prompt if an existing .elk_env has state ---
  if [[ -f "$ELK_ENV_FILE" ]] && grep -Eq '^(FOUNDATION_SETUP|SERVICE_INSTALL|AGENT_FLEET_SETUP|AIRGAPPED_MODE|EPR_CONFIGURED|REMOTE_DEPLOY_TRIGGERED|DEPLOYMENT_TYPE)=' "$ELK_ENV_FILE"; then
    # Try to show when it was last modified (best-effort)
    ELK_ENV_MTIME="$(date -r "$ELK_ENV_FILE" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo 'unknown')"
    echo -e "${YELLOW}Detected previous deployment state at:${NC} ${CYAN}${ELK_ENV_FILE}${NC}"
    echo -e "${YELLOW}Last updated:${NC} ${CYAN}${ELK_ENV_MTIME}${NC}"
    echo

    # Ask user: delete to start fresh (YES) or resume (NO)
    local RESET_ENV=""
    if type prompt_input &>/dev/null; then
      prompt_input "$(echo -e "${GREEN}Do you want to ${RED}delete${GREEN} the saved state and start fresh? Type ${YELLOW}yes${GREEN} to delete or ${YELLOW}no${GREEN} to resume from the saved state: ${NC}")" RESET_ENV
    else
      read -r -p "$(echo -e "${GREEN}Do you want to ${RED}delete${GREEN} the saved state and start fresh? Type ${YELLOW}yes${GREEN} to delete or ${YELLOW}no${GREEN} to resume: ${NC}")" RESET_ENV
    fi

    if bool_true "${RESET_ENV:-}"; then
      # Backup, wipe, re-init, and clear in-shell variables so we truly start over
      local TS; TS="$(date '+%Y%m%d-%H%M%S')"
      cp -a -- "$ELK_ENV_FILE" "${ELK_ENV_FILE}.${TS}.bak" 2>/dev/null || true
      rm -f -- "$ELK_ENV_FILE" 2>/dev/null || true
      {
        echo "# ELK Deployment State"
        echo "DEPLOY_STARTED=\"$(date '+%Y-%m-%d %H:%M:%S')\""
      } > "$ELK_ENV_FILE"

      # Unset known flags in the current shell so subsequent checks see a clean slate
      local _k
      for _k in FOUNDATION_SETUP SERVICE_INSTALL AIRGAPPED_MODE EPR_CONFIGURED \
                AGENT_FLEET_SETUP DEPLOYMENT_TYPE REMOTE_DEPLOY_TRIGGERED \
                FOUNDATION_CANCELLED DEPLOY_COMPLETE OFFLINE_MODE SHOW_TMUX; do
        unset "${_k}" 2>/dev/null || true
      done

      echo -e "${GREEN}✔ Previous state removed. Starting a fresh deployment.${NC}"
      # Reload the clean env
      load_env
    else
      echo -e "${GREEN}✔ Resuming from saved state in ${CYAN}${ELK_ENV_FILE}${NC}.${NC}"
    fi
  fi

  # --- Preflight: show what we think the current state is (no prompts here) ---
  echo -e "${YELLOW}Preflight (.elk_env):${NC}"
  echo -e "  SERVICE_INSTALL=${CYAN}${SERVICE_INSTALL:-}<${NC}"
  echo -e "  AIRGAPPED_MODE=${CYAN}${AIRGAPPED_MODE:-}<${NC}"
  echo -e "  AGENT_FLEET_SETUP=${CYAN}${AGENT_FLEET_SETUP:-}<${NC}"
  echo -e "  DEPLOYMENT_TYPE=${CYAN}${DEPLOYMENT_TYPE:-}<${NC}"
  echo -e "  REMOTE_DEPLOY_TRIGGERED=${CYAN}${REMOTE_DEPLOY_TRIGGERED:-}<${NC}"
  echo

  {
    # STEP 1: Foundation (safe to re-run, but skip if already done)
    if ! bool_true "${FOUNDATION_SETUP:-false}"; then
      # shellcheck source=/dev/null
      source "$SCRIPT_DIR/foundation.sh" || true
      load_env
      if bool_true "${FOUNDATION_CANCELLED:-false}"; then
        echo -e "${YELLOW}Foundation step was cancelled. Aborting full setup and returning to menu.${NC}"
        trap - SIGINT
        pause_and_return_to_menu
        return 0
      fi
      type log_step &>/dev/null && log_step "FOUNDATION_SETUP" "true" || true
      persist_bool "FOUNDATION_SETUP" "true"
    else
      echo -e "${GREEN}✔ Foundation previously completed (FOUNDATION_SETUP=true). Skipping...${NC}"
    fi

    # STEP 2: Core services
    if ! bool_true "${SERVICE_INSTALL:-false}"; then
      # shellcheck source=/dev/null
      source "$SCRIPT_DIR/service_install_setup.sh"
      type log_step &>/dev/null && log_step "SERVICE_INSTALL" "true" || true
      persist_bool "SERVICE_INSTALL" "true"
    else
      echo -e "${GREEN}✔ Core services already installed (SERVICE_INSTALL=true). Skipping...${NC}"
    fi

    # STEP 3/4: Airgapped EPR
    if [[ -z "${AIRGAPPED_MODE:-}" ]]; then
      echo -e "\n${YELLOW}Will this Elastic Stack build be moved to an offline (airgapped) environment after setup?${NC}"
      local OFFLINE_MODE=""
      if type prompt_input &>/dev/null; then
        prompt_input "$(echo -e "${GREEN}Type ${GREEN}'yes'${YELLOW} for airgapped registry setup or ${RED}'no'${YELLOW} to continue: ${NC}")" OFFLINE_MODE
      else
        read -r -p "$(echo -e "${GREEN}Type ${GREEN}'yes'${YELLOW} for airgapped registry setup or ${RED}'no'${YELLOW} to continue: ${NC}")" OFFLINE_MODE
      fi
      if bool_true "${OFFLINE_MODE:-}"; then
        echo -e "${GREEN}Airgapped deployment selected.${NC}"
        type log_step &>/dev/null && log_step "AIRGAPPED_MODE" "true" || true
        persist_bool "AIRGAPPED_MODE" "true"
        echo -e "${CYAN}📦 Setting up Elastic Package Registry for offline integrations...${NC}"
        # shellcheck source=/dev/null
        source "$SCRIPT_DIR/Elastic_EPR_install.sh"
        type log_step &>/dev/null && log_step "EPR_CONFIGURED" "true" || true
        persist_bool "EPR_CONFIGURED" "true"
      else
        echo -e "${GREEN}Continuing without airgapped registry setup...${NC}"
        type log_step &>/dev/null && log_step "AIRGAPPED_MODE" "false" || true
        persist_bool "AIRGAPPED_MODE" "false"
      fi
    else
      if bool_true "${AIRGAPPED_MODE}"; then
        echo -e "${CYAN}📦 Airgapped mode previously selected. Ensuring EPR is configured...${NC}"
        # shellcheck source=/dev/null
        source "$SCRIPT_DIR/Elastic_EPR_install.sh"
        type log_step &>/dev/null && log_step "EPR_CONFIGURED" "true" || true
        persist_bool "EPR_CONFIGURED" "true"
      else
        echo -e "${GREEN}Airgapped mode previously disabled. Skipping EPR setup...${NC}"
      fi
    fi

    # STEP 5: Agent + Fleet
    if ! bool_true "${AGENT_FLEET_SETUP:-false}"; then
      echo -e "\n${CYAN}🔧 Installing Elastic Agent and configuring Fleet server...${NC}"
      # shellcheck source=/dev/null
      source "$SCRIPT_DIR/agent_install_fleet_setup.sh"
      type log_step &>/dev/null && log_step "AGENT_FLEET_SETUP" "true" || true
      persist_bool "AGENT_FLEET_SETUP" "true"
    else
      echo -e "${GREEN}✔ Agent/Fleet already configured (AGENT_FLEET_SETUP=true). Skipping...${NC}"
    fi

    # STEP 6: Summary (always render even if steps were skipped)
    echo -e "\n${GREEN}Summary of your configuration:${NC}"
    populate_summary_rows
    set +e
    print_summary_table
    set -e

    # STEP 6.5: Cluster remote deploy (resumable, with prerequisites & user confirm)
    case "${DEPLOYMENT_TYPE:-}" in
      [Cc]luster)
        if ! bool_true "${REMOTE_DEPLOY_TRIGGERED:-false}"; then
          if ! bool_true "${SERVICE_INSTALL:-false}"; then
            echo -e "${YELLOW}Skipping remote deploy: SERVICE_INSTALL is not true.${NC}"
          elif ! bool_true "${AGENT_FLEET_SETUP:-false}"; then
            echo -e "${YELLOW}Skipping remote deploy: AGENT_FLEET_SETUP is not true.${NC}"
          else
            echo -e "\n${CYAN}🌐 Cluster deployment detected.${NC}"
            local RUN_REMOTE=""
            if type prompt_input &>/dev/null; then
              prompt_input "$(echo -e "${GREEN}Run the remote Elasticsearch node deployment now? Type ${YELLOW}yes${GREEN} to continue or ${RED}no${GREEN} to skip: ${NC}")" RUN_REMOTE
            else
              read -r -p "$(echo -e "${GREEN}Run the remote Elasticsearch node deployment now? Type ${YELLOW}yes${GREEN} to continue or ${RED}no${GREEN} to skip: ${NC}")" RUN_REMOTE
            fi
            if bool_true "${RUN_REMOTE:-}"; then
              type log_step &>/dev/null && log_step "DEPLOYMENT_TYPE" "cluster" || true
              local REMOTE_SCRIPT="$SCRIPT_DIR/run_remote_deploy.sh"
              if run_script "$REMOTE_SCRIPT"; then
                type log_step &>/dev/null && log_step "REMOTE_DEPLOY_TRIGGERED" "true" || true
                persist_bool "REMOTE_DEPLOY_TRIGGERED" "true"
                echo -e "${GREEN}✅ Remote deployment script executed.${NC}"
              else
                echo -e "${RED}❌ Remote deployment failed.${NC}"
                persist_bool "REMOTE_DEPLOY_TRIGGERED" "false"
              fi
            else
              echo -e "${GREEN}✅ Skipping remote deployment at user request.${NC}"
            fi
          fi
        else
          echo -e "${GREEN}✔ Remote deploy previously completed (REMOTE_DEPLOY_TRIGGERED=true). Skipping...${NC}"
        fi
        ;;
    esac

    # STEP 7: TMUX help (optional)
    echo -e "\n${YELLOW}Would you like to see the TMUX cheat sheet now?${NC}"
    read -r -p "$(echo -e "${CYAN}Type yes or no: ${NC}")" SHOW_TMUX
    if bool_true "${SHOW_TMUX:-}"; then
      type tmux_help &>/dev/null && tmux_help || echo -e "${YELLOW}(tmux_help not available)${NC}"
      type log_step &>/dev/null && log_step "TMUX_HELP_SHOWN" "true" || true
      echo -e "${GREEN}✅ TMUX help displayed. Use the keys above to switch panes!${NC}"
    else
      echo -e "${GREEN}✅ Skipping TMUX help. Use Ctrl+b ? if you forget!${NC}"
    fi

    type log_step &>/dev/null && log_step "DEPLOY_COMPLETE" "true" || true
  }

  trap - SIGINT
  pause_and_return_to_menu
}

# --- color fallbacks (add near your other color vars) ---
: "${BOLD:=$'\e[1m'}"
: "${DIM:=$'\e[2m'}"

# --- hardened progress bar (tmux-safe, works when values are unset/false) ---
progress_bar() {
  local steps=5 done=0
  [[ "${FOUNDATION_SETUP:-}" == "true" ]] && ((done++))
  [[ "${SERVICE_INSTALL:-}" == "true" ]] && ((done++))
  [[ "${AGENT_FLEET_SETUP:-}" == "true" ]] && ((done++))
  [[ "${EPR_CONFIGURED:-}" == "true" ]] && ((done++))
  [[ "${FIREWALL_HARDENED:-}" == "true" ]] && ((done++))

  local width=30
  (( width < 1 )) && width=30
  local filled=$(( done * width / steps ))
  (( filled < 0 )) && filled=0
  (( filled > width )) && filled="$width"
  local empty=$(( width - filled ))

  # [#####-----] 3/5
  printf "%b" "${CYAN}[${NC}"
  if (( filled > 0 )); then
    printf "%b" "${GREEN}"; printf "%${filled}s" "" | tr ' ' '#'; printf "%b" "${NC}"
  fi
  if (( empty > 0 )); then
    printf "%b" "${DIM}"; printf "%${empty}s" "" | tr ' ' '-'; printf "%b" "${NC}"
  fi
  printf "%b\n" "${CYAN}] ${GREEN}${done}${NC}/${CYAN}${steps}${NC}"
}

legend_line() {
  echo -e "${DIM}Keys:${NC} ${GREEN}1-12${NC}  ${DIM}|${NC}  ${GREEN}l${NC}=view log  ${DIM}|${NC}  ${GREEN}q${NC}=quit"
}

done_chip() {  # usage: done_chip "$VAR"
  [[ "${1:-}" == "true" ]] && echo -e " ${GREEN}(done)${NC}" || echo ""
}

# =========================
# Service status helpers (env-independent)
# =========================
unit_exists() { systemctl cat "${1}.service" >/dev/null 2>&1; }
unit_active() { systemctl is-active --quiet "${1}.service"; }     # returns 0 if active
pkg_installed() {
  local s; s="$(dpkg-query -W -f='${Status}' "$1" 2>/dev/null || true)"
  [[ "$s" == *"install ok installed"* ]]
}

# Get state for a service (by canonical unit/pkg names)
# Prints one of: RUNNING | INSTALLED_STOPPED | NOT_INSTALLED
get_service_state() {
  local svc="$1" unit="$1" pkg="$1"

  # Map well-known aliases (keep simple; adjust if your unit names differ)
  case "$svc" in
    elasticsearch) unit="elasticsearch"; pkg="elasticsearch";;
    logstash)      unit="logstash";      pkg="logstash";;
    kibana)        unit="kibana";        pkg="kibana";;
    elastic-agent) unit="elastic-agent"; pkg="elastic-agent";;
    *) unit="$svc"; pkg="$svc";;
  esac

  if unit_active "$unit"; then
    echo "RUNNING"; return
  fi

  # If unit exists or package is installed but not running:
  if unit_exists "$unit" || pkg_installed "$pkg"; then
    echo "INSTALLED_STOPPED"; return
  fi

  echo "NOT_INSTALLED"
}

# Render a colored checkbox for a service state
status_box() {
  local state="$1"
  case "$state" in
    RUNNING)           printf "[%bx%b]" "$GREEN" "$NC" ;;   # running → green x
    INSTALLED_STOPPED) printf "[%b!%b]" "$YELLOW" "$NC" ;; # installed but not running
    NOT_INSTALLED)     printf "[ ]" ;;
    *)                 printf "[ ]" ;;
  esac
}

# Build one-line status row for ES/LS/KB/Agent
render_service_status_row() {
  local es ls kb ag
  es="$(get_service_state elasticsearch)"
  ls="$(get_service_state logstash)"
  kb="$(get_service_state kibana)"
  ag="$(get_service_state elastic-agent)"

  printf "%b" "${CYAN}----------------------------------------------------------------${NC}\n"
  printf " %bServices%b:  ES %s  |  LS %s  |  KB %s  |  Agent %s\n" \
    "$BOLD" "$NC" \
    "$(status_box "$es")" \
    "$(status_box "$ls")" \
    "$(status_box "$kb")" \
    "$(status_box "$ag")"

  printf "           %bLegend%b: %s running   %s installed, stopped   %s not installed\n" \
    "$DIM" "$NC" \
    "$(printf '[%bx%b]' "$GREEN" "$NC")" \
    "$(printf '[%b!%b]' "$YELLOW" "$NC")" \
    "[ ]"
}

# =========================
# MENU
# =========================
#
type service_install_ok &>/dev/null || service_install_ok() { [[ "${SERVICE_INSTALL:-}" == "true" ]]; }
type require_service_installed &>/dev/null || require_service_installed() { service_install_ok; }
type pause_and_return_to_menu &>/dev/null || pause_and_return_to_menu() { read -rp "$(echo -e "${YELLOW}Press Enter to return to the menu...${NC}")"; }

: "${BOLD:=$'\e[1m'}"; : "${DIM:=$'\e[2m'}"

# Icon accents (minimal color, no rainbow soup)
ICO_DEPLOY="${CYAN}🚀${NC}"
ICO_SETUP="${CYAN}🛠️ ${NC}"
ICO_SERVICES="${CYAN}📡${NC}"
ICO_AGENT="${CYAN}🔧${NC}"
ICO_EPR="${CYAN}📦${NC}"
ICO_CLEAN="${RED}🗑️ ${NC}"       # destructive / caution
ICO_WALL="${YELLOW}🧱${NC}"       # firewall
ICO_LOGS="${CYAN}📜${NC}"
ICO_REMOTE="${CYAN}🌐${NC}"
ICO_ZEEK="${CYAN}🔎${NC}"
ICO_SURI="${CYAN}🕵️ ${NC}"
ICO_EXIT="${RED}❌${NC}"

# Number style (dimmed green digits)
num() { printf " ${DIM}%s${NC}" "$1"; }

main_menu() {
  clear
  load_env 2>/dev/null || true

  #
  if service_install_ok; then
    OPT4_NOTE=""; OPT5_NOTE=""; OPT4_LOCK=""; OPT5_LOCK=""
  else
    OPT4_NOTE=" ${YELLOW}(requires services to be installed)${NC}"
    OPT5_NOTE=" ${YELLOW}(requires services to be installed)${NC}"
    OPT4_LOCK="🔒 "; OPT5_LOCK="🔒 "
  fi

  #
  local HOSTNAME="$(hostname 2>/dev/null || echo host)"
  local IP="$(hostname -I 2>/dev/null | awk '{print $1}' || echo -)"
  local OS_NAME; OS_NAME="$(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-Linux}")"

  echo -e "${CYAN}----------------------------------------------------------------${NC}"
  echo -e " 🛠️  ${BOLD:-}${GREEN:-}ELK Stack Deployment Menu${NC}"
  echo -e "${CYAN}----------------------------------------------------------------${NC}"
  echo -e "[${GREEN}Host${NC}: ${HOSTNAME}] [${GREEN}IP${NC}: ${IP}] [${GREEN}OS${NC}: ${OS_NAME}]"
  # Real-time service status (does not rely on .elk_env)
  render_service_status_row

  # --- Status checkboxes ---
  local svc_box="[ ]";   [[ "${SERVICE_INSTALL:-}" == "true" ]] && svc_box="[${GREEN}x${NC}]"
  local fleet_box="[ ]"; [[ "${AGENT_FLEET_SETUP:-}" == "true" ]] && fleet_box="[${GREEN}x${NC}]"
  local epr_box="[ ]";   [[ "${EPR_CONFIGURED:-}" == "true" ]] && epr_box="[${GREEN}x${NC}]"

  echo -e "[${GREEN}Services${NC}: ${svc_box}] \
  [${GREEN}Fleet${NC}: ${fleet_box}] \
  [${GREEN}EPR${NC}: ${epr_box}]"

  # --- Storage Usage Bar (root filesystem) ---
  local USAGE_PERCENT=$(df -h / | awk 'NR==2 {gsub("%","",$5); print $5}')
  local WIDTH=30
  local FILLED=$(( USAGE_PERCENT * WIDTH / 100 ))
  local EMPTY=$(( WIDTH - FILLED ))

  printf "[${GREEN}Storage${NC}: %3s%% " "$USAGE_PERCENT"
  printf "%b" "${CYAN}[${NC}"
  if (( FILLED > 0 )); then
    printf "%b" "${GREEN}"; printf "%${FILLED}s" "" | tr ' ' '#'; printf "%b" "${NC}"
  fi
  if (( EMPTY > 0 )); then
    printf "%b" "${DIM}"; printf "%${EMPTY}s" "" | tr ' ' '-'; printf "%b" "${NC}"
  fi
  printf "%b\n" "${CYAN}]${NC}"
  echo
  #progress_bar
  echo
  
	# --- Menu body ---
	printf "%s. %b %s %s\n"    "$(num 1)" "$ICO_DEPLOY" "${BOLD}Deploy Elasticsearch, Logstash, and Kibana \"ELK\" on this node${NC}" ""
	echo   "    ${YELLOW}↳ Option during setup for remote Elasticsearch node to be setup${NC}"

	printf "%s. %b %s%s\n"     "$(num 2)" "$ICO_SETUP"   "${BOLD}Run foundational setup${NC}"            "$(done_chip "${FOUNDATION_SETUP:-}")"
	printf "%s. %b %s%s\n"     "$(num 3)" "$ICO_SERVICES" "${BOLD}Only deploy \"ELK\" services${NC}"       "$(done_chip "${SERVICE_INSTALL:-}")"

	# Locks/notes preserved; icon remains tinted, label is bold not colored
	printf "%s. %s%b %s%s%s\n" "$(num 4)" "${OPT4_LOCK}" "$ICO_AGENT" "${BOLD}Deploy Elastic Agent in Fleet mode on this node${NC}" \
								 "${OPT4_NOTE}" "$(done_chip "${AGENT_FLEET_SETUP:-}")"

	printf "%s. %s%b %s%s%s\n" "$(num 5)" "${OPT5_LOCK}" "$ICO_EPR"   "${BOLD}Install Elastic Package Registry with Docker${NC}" \
								 " ${OPT5_NOTE}" "$(done_chip "${EPR_CONFIGURED:-}")"

	printf "%s. %b %s\n"       "$(num 6)" "$ICO_CLEAN"  "${BOLD}Cleanup all services and start fresh${NC}"
	printf "%s. %b %s%s\n"     "$(num 7)" "$ICO_WALL"   "${BOLD}Firewall Hardening (iptables)${NC}"      "$(done_chip "${FIREWALL_HARDENED:-}")"
	printf "%s. %b %s\n"       "$(num 8)" "$ICO_LOGS"   "${BOLD}View deployment log (.elk_env)${NC}"
	printf "%s. %b %s\n"       "$(num 9)" "$ICO_REMOTE" "${BOLD}Deploy Remote Elasticsearch Node${NC}"
	printf "%s. %b %s\n"       "$(num 10)" "$ICO_ZEEK"  "${BOLD}Deploy Zeek (local)${NC}"
	printf "%s. %b %s\n"       "$(num 11)" "$ICO_SURI"  "${BOLD}Deploy Suricata (local)${NC}"
	printf "%s. %b %s\n"       "$(num 12)" "$ICO_EXIT"  "${BOLD}Exit${NC}"
	echo

  legend_line
  echo
  echo -e " ${YELLOW}💡 Tip:${NC} If setup is interrupted or breaks, you can rerun the menu with:"
  echo -e "    ${CYAN}bash ./orchestrate.sh${NC}"

  read -r -p "$(echo -e "${YELLOW}Select an option [1-12]: ${NC}")" CHOICE
  case "${CHOICE:-}" in
    1) run_full_setup ;;
    2) clear; source "$SCRIPT_DIR/foundation.sh"; type log_step &>/dev/null && log_step "FOUNDATION_SETUP" "true" || true; pause_and_return_to_menu ;;
    3) clear; source "$SCRIPT_DIR/service_install_setup.sh"; type log_step &>/dev/null && log_step "SERVICE_INSTALL" "true" || true; persist_bool "SERVICE_INSTALL" "true"; pause_and_return_to_menu ;;
    4) if require_service_installed; then clear; source "$SCRIPT_DIR/agent_install_fleet_setup.sh"; type log_step &>/dev/null && log_step "AGENT_FLEET_SETUP" "true" || true; persist_bool "AGENT_FLEET_SETUP" "true"; fi; pause_and_return_to_menu ;;
    5) if require_service_installed; then clear; source "$SCRIPT_DIR/Elastic_EPR_install.sh"; type log_step &>/dev/null && log_step "EPR_CONFIGURED" "true" || true; persist_bool "EPR_CONFIGURED" "true"; fi; pause_and_return_to_menu ;;
    6) run_elk_cleanup ;;
    7) run_firewall_hardening ;;
    8) view_env_file ;;
    9) run_remote_node_deployment ;;
    10) run_zeek_deploy ;;
    11) run_suricata_deploy ;;
    12) echo -e "${GREEN}Exiting setup. Goodbye!${NC}"; exit 0 ;;
	l|L) clear; view_env_file; pause_and_return_to_menu ;;
    q|Q) echo -e "${GREEN}Exiting setup. Goodbye!${NC}"; exit 0 ;;
    *) echo -e "${RED}Invalid option. Please try again.${NC}"; sleep 2 ;;
  esac
}

while true; do main_menu; done

