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

bool_true() {
  local v="${1:-}"; v="${v//\"/}"; v="${v//\'/}"
  shopt -s nocasematch
  [[ "$v" =~ ^(true|yes|y|1|on)$ ]]
}

load_env() { source "$ELK_ENV_FILE" 2>/dev/null || true; }

persist_kv() {
  local k="$1" v="$2"
  mkdir -p "$(dirname "$ELK_ENV_FILE")"; touch "$ELK_ENV_FILE"
  # exact-key delete; avoid nuking similarly prefixed vars
  sed -i -E "/^${k}=.*/d" "$ELK_ENV_FILE"
  echo "${k}=${v}" >> "$ELK_ENV_FILE"
}

persist_bool() { local k="$1"; bool_true "${2:-false}" && persist_kv "$k" "true" || persist_kv "$k" "false"; }

load_env

# =========================
# RUNTIME HELPERS
# =========================
svc_active() { systemctl is-active --quiet "$1"; }

service_install_ok() {
  load_env
  if bool_true "${SERVICE_INSTALL:-}"; then return 0; fi
  if svc_active elasticsearch && svc_active kibana && svc_active logstash; then
    type log_step &>/dev/null && log_step "SERVICE_INSTALL" "true" || true
    persist_bool "SERVICE_INSTALL" "true"
    load_env
    return 0
  fi
  return 1
}

require_service_installed() {
  if service_install_ok; then return 0; fi
  echo -e "\n${YELLOW}⚠️  This step requires core services to be installed and running.${NC}"
  echo -e "   ${CYAN}- Elasticsearch${NC}\n   ${CYAN}- Kibana${NC}\n   ${CYAN}- Logstash${NC}\n"
  echo -e "${GREEN}Run ${CYAN}service_install_setup.sh${GREEN} first (menu option 3) or use full setup (option 1).${NC}"
  return 1
}

pause_and_return_to_menu() { echo -e "\n${YELLOW}Press Enter to return to the main menu...${NC}"; read -r; }

# Run a child script via bash (never source), report RC, let caller persist flags
run_script() {
  local path="$1"; shift || true
  if [[ ! -f "$path" ]]; then echo -e "${RED}❌ Script not found:${NC} ${YELLOW}$path${NC}"; return 127; fi
  chmod +x "$path" 2>/dev/null || true
  if [[ ! -x "$path" ]]; then bash "$path" "$@"; else "$path" "$@"; fi
}

# =========================
# FULL SETUP (RESUMABLE)
# =========================
run_full_setup() {
  clear
  echo -e "${CYAN}Starting full setup...${NC}"
  trap 'echo -e "\n${YELLOW}⚠️  Setup interrupted. Returning to main menu...${NC}"; return 130' SIGINT

  # Always read the latest state first
  load_env

  # --- NEW: Resume or Start Fresh prompt if an existing .elk_env has state ---
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
  # --- END NEW BLOCK ---

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

# =========================
# UTIL VIEWS / ACTIONS
# =========================
view_env_file() {
  clear
  echo -e "${CYAN}Displaying contents of ${ELK_ENV_FILE}:${NC}\n"
  if [[ -f "$ELK_ENV_FILE" ]]; then ${PAGER:-less} "$ELK_ENV_FILE"; else
    echo -e "${RED}No deployment log found yet.${NC}"; sleep 2
  fi
}

run_firewall_hardening() {
  clear
  echo -e "${GREEN}Running firewall hardening...${NC}"
  trap 'echo -e "\n${YELLOW}Firewall hardening interrupted. Returning to menu...${NC}"; return 130' SIGINT
  type secure_node_with_iptables &>/dev/null && secure_node_with_iptables || echo -e "${YELLOW}(secure_node_with_iptables not available)${NC}"
  type log_step &>/dev/null && log_step "FIREWALL_HARDENING" "true" || true
  echo -e "\n${GREEN}Firewall configuration complete.${NC}"
  trap - SIGINT
  pause_and_return_to_menu
}

run_elk_cleanup() {
  clear
  echo -e "${GREEN}Running ELK cleanup...${NC}"
  trap 'echo -e "\n${YELLOW}Cleanup interrupted. Returning to menu...${NC}"; return 130' SIGINT
  # shellcheck source=/dev/null
  source "$SCRIPT_DIR/cleanup.sh"
  type log_step &>/dev/null && log_step "CLEANUP_COMPLETE" "true" || true
  echo -e "\n${GREEN}Cleanup complete.${NC}"
  trap - SIGINT
  pause_and_return_to_menu
}

run_remote_node_deployment() {
  clear
  trap 'echo -e "\n${YELLOW}⚠️  Remote Node installation interrupted. Returning to menu...${NC}"; return 130' SIGINT
  local REMOTE_SCRIPT="$SCRIPT_DIR/run_remote_deploy.sh"
  if run_script "$REMOTE_SCRIPT"; then
    type log_step &>/dev/null && log_step "REMOTE_DEPLOY_TRIGGERED" "true" || true
    persist_bool "REMOTE_DEPLOY_TRIGGERED" "true"
  fi
  trap - SIGINT
  pause_and_return_to_menu
}

run_zeek_deploy() {
  clear
  trap 'echo -e "\n${YELLOW}⚠️  Zeek installation interrupted. Returning to menu...${NC}"; return 130' SIGINT
  # shellcheck source=/dev/null
  source "$SCRIPT_DIR/zeek_deploy.sh"
  type log_step &>/dev/null && log_step "ZEEK_DEPLOYED" "true" || true
  trap - SIGINT
  pause_and_return_to_menu
}

run_suricata_deploy() {
  clear
  trap 'echo -e "\n${YELLOW}⚠️  Suricata installation interrupted. Returning to menu...${NC}"; return 130' SIGINT
  # shellcheck source=/dev/null
  source "$SCRIPT_DIR/suricata_deploy.sh"
  type log_step &>/dev/null && log_step "SURICATA_DEPLOYED" "true" || true
  trap - SIGINT
  pause_and_return_to_menu
}

# =========================
# MENU
# =========================
main_menu() {
  clear
  if service_install_ok; then
    OPT4_NOTE=""; OPT5_NOTE=""; OPT4_LOCK=""; OPT5_LOCK=""
  else
    OPT4_NOTE=" ${YELLOW}(requires services to be installed)${NC}"
    OPT5_NOTE=" ${YELLOW}(requires services to be installed)${NC}"
    OPT4_LOCK="🔒 "; OPT5_LOCK="🔒 "
  fi

  echo -e "${CYAN}"
  echo "========================================="
  echo "      🛠️  ELK Stack Deployment Menu       "
  echo "========================================="
  echo -e "${NC}"
  echo -e " ${GREEN}1${NC}. Deploy Elasticsearch, Logstash, and Kibana \"ELK\" on this node"
  echo -e "    ${YELLOW}↳ Option during setup for remote Elasticsearch node to be setup${NC}"
  echo -e " ${GREEN}2${NC}. Run foundational setup"
  echo -e " ${GREEN}3${NC}. Only deploy \"ELK\" services"
  echo -e " ${GREEN}4${NC}. ${OPT4_LOCK}Deploy elastic agent in Fleet mode on this node${OPT4_NOTE}"
  echo -e " ${GREEN}5${NC}. ${OPT5_LOCK}Install Elastic Package Registry with Docker ${OPT5_NOTE}"
  echo -e " ${GREEN}6${NC}. Cleanup all services and start fresh"
  echo -e " ${GREEN}7${NC}. Firewall hardening IPTables"
  echo -e " ${GREEN}8${NC}. View deployment log (.elk_env)"
  echo -e " ${GREEN}9${NC}. Deploy Remote Elasticsearch Node"
  echo -e " ${GREEN}10${NC}. Deploy Zeek"
  echo -e " ${GREEN}11${NC}. Deploy Suricata"
  echo -e " ${GREEN}12${NC}. Exit"
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
    *) echo -e "${RED}Invalid option. Please try again.${NC}"; sleep 2 ;;
  esac
}

while true; do main_menu; done
