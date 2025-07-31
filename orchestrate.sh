#!/bin/bash

# Modular ELK Deployment Orchestrator with Menu
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ELK_ENV_FILE="$SCRIPT_DIR/.elk_env"

# Load common functions
source "$SCRIPT_DIR/functions.sh"

# Initialize env file only if it doesn't exist
if [[ ! -f "$ELK_ENV_FILE" ]]; then
  echo "# ELK Deployment State" > "$ELK_ENV_FILE"
  log_step "DEPLOY_STARTED" "$(date '+%Y-%m-%d %H:%M:%S')"
fi

# Load environment variables
source "$ELK_ENV_FILE"

# Pause function for returning to menu
pause_and_return_to_menu() {
  echo -e "\n${YELLOW}Press Enter to return to the main menu...${NC}"
  read
}

# View deployment log
view_env_file() {
  clear
  echo -e "${CYAN}Displaying contents of ${ELK_ENV_FILE}:${NC}\n"
  if [[ -f "$ELK_ENV_FILE" ]]; then
    less "$ELK_ENV_FILE"
  else
    echo -e "${RED}No deployment log found yet.${NC}"
    sleep 2
  fi
}

# Firewall hardening
run_firewall_hardening() {
  clear
  echo -e "${GREEN}Running firewall hardening function...${NC}"
  trap 'echo -e "\n${YELLOW}Firewall hardening interrupted. Returning to menu...${NC}"; return' SIGINT
  secure_node_with_iptables
  log_step "FIREWALL_HARDENING" "true"
  echo -e "\n${GREEN}Firewall configuration complete.${NC}"
  trap - SIGINT
  pause_and_return_to_menu
}

# Cleanup
run_elk_cleanup() {
  clear
  echo -e "${GREEN}Running ELK cleanup...${NC}"
  trap 'echo -e "\n${YELLOW}Cleanup interrupted. Returning to menu...${NC}"; return' SIGINT
  source "$SCRIPT_DIR/cleanup.sh" && log_step "CLEANUP_COMPLETE" "true"
  echo -e "\n${GREEN}Cleanup complete.${NC}"
  trap - SIGINT
  pause_and_return_to_menu
}

# Full setup
run_full_setup() {
  clear
  echo -e "${CYAN}Starting full setup...${NC}"
  trap 'echo -e "\n${YELLOW}⚠️  Setup interrupted. Returning to main menu...${NC}"; pause_and_return_to_menu' SIGINT

  {
    # Step 1: Foundation setup
    source "$SCRIPT_DIR/foundation.sh" && log_step "FOUNDATION_SETUP" "true"

    # Step 2: Core services (Elasticsearch, Kibana, Logstash)
    source "$SCRIPT_DIR/service_install_setup.sh" && log_step "SERVICE_INSTALL" "true"

    # Step 3: Ask if environment will be offline (airgapped)
    echo -e "\n${YELLOW}Will this Elastic Stack build be moved to an offline (airgapped) environment after setup?${NC}"
    prompt_input "$(echo -e "${GREEN}Type ${GREEN}'yes'${YELLOW} for airgapped registry setup or ${RED}'no'${YELLOW} to continue: ${NC}")" OFFLINE_MODE

    if [[ "$OFFLINE_MODE" =~ ^[Yy][Ee]?[Ss]?$ ]]; then
      echo -e "${GREEN}Airgapped deployment selected.${NC}"
      log_step "AIRGAPPED_MODE" "true"

      # Step 4: Setup Elastic Package Registry first (before Fleet server)
      echo -e "${CYAN}📦 Setting up Elastic Package Registry for offline integrations...${NC}"
      source "$SCRIPT_DIR/Elastic_EPR_install.sh" && log_step "EPR_CONFIGURED" "true"
    else
      echo -e "${GREEN}Continuing without airgapped registry setup...${NC}"
      log_step "AIRGAPPED_MODE" "false"
    fi

    # Step 5: Install Elastic Agent and Fleet server
    echo -e "\n${CYAN}🔧 Installing Elastic Agent and configuring Fleet server...${NC}"
    source "$SCRIPT_DIR/agent_install_fleet_setup.sh" && log_step "AGENT_FLEET_SETUP" "true"

    # Step 6: Summary of configuration
    echo -e "\n${GREEN}Summary of your configuration:${NC}"
    if type print_summary_table &>/dev/null; then
      print_summary_table
    else
      echo -e "${YELLOW}Summary function not defined. Skipping summary display.${NC}"
    fi

    # Step 7: TMUX help prompt
    echo -e "\n${YELLOW}Would you like to see the TMUX cheat sheet now?${NC}"
    read -p "$(echo -e "${CYAN}Type yes or no: ${NC}")" SHOW_TMUX

    if [[ "$SHOW_TMUX" =~ ^[Yy][Ee]?[Ss]?$ ]]; then
      tmux_help
      log_step "TMUX_HELP_SHOWN" "true"
      echo -e "${GREEN}✅ TMUX help displayed. Use the keys above to switch panes!${NC}"
    else
      echo -e "${GREEN}✅ Skipping TMUX help. Use Ctrl+b ? if you forget!${NC}"
    fi

    log_step "DEPLOY_COMPLETE" "true"
  }

  trap - SIGINT
  pause_and_return_to_menu
}

# Main menu
main_menu() {
  clear
  echo -e "${CYAN}"
  echo "========================================="
  echo "      🛠️  ELK Stack Deployment Menu       "
  echo "========================================="
  echo -e "${NC}"
  echo -e " ${GREEN}1${NC}. Run full setup (foundation + services + Fleet + EPR)"
  echo -e " ${GREEN}2${NC}. Run foundation.sh"
  echo -e " ${GREEN}3${NC}. Run service_install_setup.sh"
  echo -e " ${GREEN}4${NC}. Run agent_install_fleet_setup.sh"
  echo -e " ${GREEN}5${NC}. Run Elastic_EPR_install.sh (air-gapped)"
  echo -e " ${GREEN}6${NC}. Run cleanup.sh"
  echo -e " ${GREEN}7${NC}. Firewall hardening"
  echo -e " ${GREEN}8${NC}. View deployment log (.elk_env)"
  echo -e " ${GREEN}9${NC}. Deploy Zeek"
  echo -e " ${GREEN}10${NC}. Deploy Suricata"
  echo -e " ${GREEN}11${NC}. Exit"
  echo

  read -p "$(echo -e ${YELLOW}"Select an option [1-11]: "${NC})" CHOICE

  case "$CHOICE" in
    1) run_full_setup ;;
    2) clear; source "$SCRIPT_DIR/foundation.sh"; log_step "FOUNDATION_SETUP" "true"; pause_and_return_to_menu ;;
    3) clear; source "$SCRIPT_DIR/service_install_setup.sh"; log_step "SERVICE_INSTALL" "true"; pause_and_return_to_menu ;;
    4) clear; source "$SCRIPT_DIR/agent_install_fleet_setup.sh"; log_step "AGENT_FLEET_SETUP" "true"; pause_and_return_to_menu ;;
    5) clear; source "$SCRIPT_DIR/Elastic_EPR_install.sh"; log_step "EPR_CONFIGURED" "true"; pause_and_return_to_menu ;;
    6) run_elk_cleanup ;;
    7) run_firewall_hardening ;;
    8) view_env_file ;;
    9) clear; source "$SCRIPT_DIR/zeek_deploy.sh"; log_step "ZEEK_DEPLOYED" "true"; pause_and_return_to_menu ;;
    10) clear; source "$SCRIPT_DIR/suricata_deploy.sh"; log_step "SURICATA_DEPLOYED" "true"; pause_and_return_to_menu ;;
    11) echo -e "${GREEN}Exiting setup. Goodbye!${NC}"; exit 0 ;;
    *) echo -e "${RED}Invalid option. Please try again.${NC}"; sleep 2 ;;
  esac
}

# Main loop
while true; do
  main_menu
done
