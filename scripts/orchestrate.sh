#!/bin/bash

# Modular ELK Deployment Orchestrator with Menu
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ELK_ENV_FILE="$SCRIPT_DIR/.elk_env"

# Load common functions (colors, log_step, prompt_input, etc.)
# We also set color fallbacks if functions.sh doesn't define them.
if [[ -f "$SCRIPT_DIR/functions.sh" ]]; then
  # shellcheck source=/dev/null
  source "$SCRIPT_DIR/functions.sh"
  init_colors
fi
: "${GREEN:=$'\e[32m'}"
: "${YELLOW:=$'\e[33m'}"
: "${RED:=$'\e[31m'}"
: "${CYAN:=$'\e[36m'}"
: "${NC:=$'\e[0m'}"

# --- Global Ctrl+C handler: never exit the orchestrator ---
trap 'echo -e "\n${YELLOW}⚠️  Operation interrupted by user. Returning to main menu...${NC}"; sleep 1' SIGINT

# Initialize env file only if it doesn't exist
if [[ ! -f "$ELK_ENV_FILE" ]]; then
  {
    echo "# ELK Deployment State"
    echo "DEPLOY_STARTED=\"$(date '+%Y-%m-%d %H:%M:%S')\""
  } > "$ELK_ENV_FILE"
fi

# Helper: reload environment from .elk_env (non-fatal if empty)
reload_env() {
  # shellcheck source=/dev/null
  source "$ELK_ENV_FILE" 2>/dev/null || true
}

reload_env

# Helper: robust boolean check (true/1/yes)
is_true() {
  local v="${1:-}"
  shopt -s nocasematch
  [[ "$v" == "true" || "$v" == "1" || "$v" == "yes" || "$v" == "y" ]]
}

# Helper: service active check
svc_active() {
  systemctl is-active --quiet "$1"
}

# Helper: determine if core services are installed/running
# If .elk_env says false but services are actually up, we flip it to true and persist.
service_install_ok() {
  reload_env
  if is_true "${SERVICE_INSTALL:-}"; then
    return 0
  fi

  # Fallback to runtime state check
  if svc_active elasticsearch && svc_active kibana && svc_active logstash; then
    # If log_step exists, persist corrected state
    if type log_step &>/dev/null; then
      log_step "SERVICE_INSTALL" "true"
      reload_env
    else
      SERVICE_INSTALL=true
    fi
    return 0
  fi

  return 1
}

# Gating guard (prints helpful message)
require_service_installed() {
  if service_install_ok; then
    return 0
  fi

  echo -e "\n${YELLOW}⚠️  This step requires core services to be installed and running.${NC}"
  echo -e "   ${CYAN}- Elasticsearch${NC}"
  echo -e "   ${CYAN}- Kibana${NC}"
  echo -e "   ${CYAN}- Logstash${NC}\n"
  echo -e "${GREEN}Run ${CYAN}service_install_setup.sh${GREEN} first (menu option 3) or use the full setup (option 1).${NC}"
  return 1
}

# Pause function for returning to menu
pause_and_return_to_menu() {
  echo -e "\n${YELLOW}Press Enter to return to the main menu...${NC}"
  read -r
}

# Full setup
run_full_setup() {
  clear
  echo -e "${CYAN}Starting full setup...${NC}"
  trap 'echo -e "\n${YELLOW}⚠️  Setup interrupted. Returning to main menu...${NC}"; return 130' SIGINT

  {
    # Step 1: Foundation setup
    # shellcheck source=/dev/null
    source "$SCRIPT_DIR/foundation.sh"
    if type log_step &>/dev/null; then log_step "FOUNDATION_SETUP" "true"; fi

    # Step 2: Core services (Elasticsearch, Kibana, Logstash)
    # shellcheck source=/dev/null
    source "$SCRIPT_DIR/service_install_setup.sh"
    if type log_step &>/dev/null; then log_step "SERVICE_INSTALL" "true"; fi

    # Step 3: Ask if environment will be offline (airgapped)
    echo -e "\n${YELLOW}Will this Elastic Stack build be moved to an offline (airgapped) environment after setup?${NC}"
    if type prompt_input &>/dev/null; then
      prompt_input "$(echo -e "${GREEN}Type ${GREEN}'yes'${YELLOW} for airgapped registry setup or ${RED}'no'${YELLOW} to continue: ${NC}")" OFFLINE_MODE
    else
      read -r -p "$(echo -e "${GREEN}Type ${GREEN}'yes'${YELLOW} for airgapped registry setup or ${RED}'no'${YELLOW} to continue: ${NC}")" OFFLINE_MODE
    fi

    if is_true "${OFFLINE_MODE:-}"; then
      echo -e "${GREEN}Airgapped deployment selected.${NC}"
      if type log_step &>/dev/null; then log_step "AIRGAPPED_MODE" "true"; fi

      # Step 4: Setup Elastic Package Registry first (before Fleet server)
      echo -e "${CYAN}📦 Setting up Elastic Package Registry for offline integrations...${NC}"
      # shellcheck source=/dev/null
      source "$SCRIPT_DIR/Elastic_EPR_install.sh"
      if type log_step &>/dev/null; then log_step "EPR_CONFIGURED" "true"; fi
    else
      echo -e "${GREEN}Continuing without airgapped registry setup...${NC}"
      if type log_step &>/dev/null; then log_step "AIRGAPPED_MODE" "false"; fi
    fi

    # Step 5: Install Elastic Agent and Fleet server
    echo -e "\n${CYAN}🔧 Installing Elastic Agent and configuring Fleet server...${NC}"
    # shellcheck source=/dev/null
    source "$SCRIPT_DIR/agent_install_fleet_setup.sh"
    if type log_step &>/dev/null; then log_step "AGENT_FLEET_SETUP" "true"; fi

    # Step 6: Summary of configuration
    echo -e "\n${GREEN}Summary of your configuration:${NC}"
    if type print_summary_table &>/dev/null; then
      print_summary_table
    else
      echo -e "${YELLOW}Summary function not defined. Skipping summary display.${NC}"
    fi

    # Step 7: TMUX help prompt
    echo -e "\n${YELLOW}Would you like to see the TMUX cheat sheet now?${NC}"
    read -r -p "$(echo -e "${CYAN}Type yes or no: ${NC}")" SHOW_TMUX

    if is_true "${SHOW_TMUX:-}"; then
      tmux_help
      if type log_step &>/dev/null; then log_step "TMUX_HELP_SHOWN" "true"; fi
      echo -e "${GREEN}✅ TMUX help displayed. Use the keys above to switch panes!${NC}"
    else
      echo -e "${GREEN}✅ Skipping TMUX help. Use Ctrl+b ? if you forget!${NC}"
    fi

    if type log_step &>/dev/null; then log_step "DEPLOY_COMPLETE" "true"; fi
  }

  trap - SIGINT
  pause_and_return_to_menu
}

# View deployment log
view_env_file() {
  clear
  echo -e "${CYAN}Displaying contents of ${ELK_ENV_FILE}:${NC}\n"
  if [[ -f "$ELK_ENV_FILE" ]]; then
    ${PAGER:-less} "$ELK_ENV_FILE"
  else
    echo -e "${RED}No deployment log found yet.${NC}"
    sleep 2
  fi
}

# Firewall hardening
run_firewall_hardening() {
  clear
  echo -e "${GREEN}Running firewall hardening function...${NC}"
  trap 'echo -e "\n${YELLOW}Firewall hardening interrupted. Returning to menu...${NC}"; return 130' SIGINT
  secure_node_with_iptables
  if type log_step &>/dev/null; then log_step "FIREWALL_HARDENING" "true"; fi
  echo -e "\n${GREEN}Firewall configuration complete.${NC}"
  trap - SIGINT
  pause_and_return_to_menu
}

# Cleanup
run_elk_cleanup() {
  clear
  echo -e "${GREEN}Running ELK cleanup...${NC}"
  trap 'echo -e "\n${YELLOW}Cleanup interrupted. Returning to menu...${NC}"; return 130' SIGINT
  # shellcheck source=/dev/null
  source "$SCRIPT_DIR/cleanup.sh"
  if type log_step &>/dev/null; then log_step "CLEANUP_COMPLETE" "true"; fi
  echo -e "\n${GREEN}Cleanup complete.${NC}"
  trap - SIGINT
  pause_and_return_to_menu
}

# --- Wrappers so Ctrl+C during Remote Node Deployment returns to menu ---
run_remote_node_deployment() {
  clear
  trap 'echo -e "\n${YELLOW}⚠️  Remote Node installation interrupted. Returning to menu...${NC}"; return 130' SIGINT
  # shellcheck source=/dev/null
  source "$SCRIPT_DIR/run_remote_deploy.sh"
  if type log_step &>/dev/null; then log_step "REMOTE_NODE_DEPLOYED" "true"; fi
  trap - SIGINT
  pause_and_return_to_menu
}

# --- Wrappers so Ctrl+C during Zeek/Suricata returns to menu ---
run_zeek_deploy() {
  clear
  trap 'echo -e "\n${YELLOW}⚠️  Zeek installation interrupted. Returning to menu...${NC}"; return 130' SIGINT
  # shellcheck source=/dev/null
  source "$SCRIPT_DIR/zeek_deploy.sh"
  if type log_step &>/dev/null; then log_step "ZEEK_DEPLOYED" "true"; fi
  trap - SIGINT
  pause_and_return_to_menu
}

# --- Wrappers so Ctrl+C during Zeek/Suricata returns to menu ---
run_suricata_deploy() {
  clear
  trap 'echo -e "\n${YELLOW}⚠️  Suricata installation interrupted. Returning to menu...${NC}"; return 130' SIGINT
  # shellcheck source=/dev/null
  source "$SCRIPT_DIR/suricata_deploy.sh"
  if type log_step &>/dev/null; then log_step "SURICATA_DEPLOYED" "true"; fi
  trap - SIGINT
  pause_and_return_to_menu
}

# Main menu
main_menu() {
  clear
  # Re-evaluate availability each time we draw the menu
  if service_install_ok; then
    OPT4_NOTE=""
    OPT5_NOTE=""
    OPT4_LOCK=""
    OPT5_LOCK=""
  else
    OPT4_NOTE=" ${YELLOW}(requires services to be installed)${NC}"
    OPT5_NOTE=" ${YELLOW}(requires services to be installed)${NC}"
    OPT4_LOCK="🔒 "
    OPT5_LOCK="🔒 "
  fi

  echo -e "${CYAN}"
  echo "========================================="
  echo "      🛠️  ELK Stack Deployment Menu       "
  echo "========================================="
  echo -e "${NC}"
  echo -e " ${GREEN}1${NC}. Deploy Elasticsearch, Logstash, and Kibana "ELK" on this node"
  echo -e " ${GREEN}2${NC}. Run foundational setup"
  echo -e " ${GREEN}3${NC}. Only deploy "ELK" services"
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

  read -r -p "$(echo -e "${YELLOW}Select an option [1-12]: ${NC}")" CHOICE

  case "${CHOICE:-}" in
    1) run_full_setup ;;
    2) clear; source "$SCRIPT_DIR/foundation.sh"; if type log_step &>/dev/null; then log_step "FOUNDATION_SETUP" "true"; fi; pause_and_return_to_menu ;;
    3) clear; source "$SCRIPT_DIR/service_install_setup.sh"; if type log_step &>/dev/null; then log_step "SERVICE_INSTALL" "true"; fi; pause_and_return_to_menu ;;
    4)
       if require_service_installed; then
         clear; source "$SCRIPT_DIR/agent_install_fleet_setup.sh"
         if type log_step &>/dev/null; then log_step "AGENT_FLEET_SETUP" "true"; fi
       fi
       pause_and_return_to_menu
       ;;
    5)
       if require_service_installed; then
         clear; source "$SCRIPT_DIR/Elastic_EPR_install.sh"
         if type log_step &>/dev/null; then log_step "EPR_CONFIGURED" "true"; fi
       fi
       pause_and_return_to_menu
       ;;
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

# Main loop
while true; do
  main_menu
done
