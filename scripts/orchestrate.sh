#!/bin/bash

# Modular ELK Deployment Orchestrator with Menu
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ELK_ENV_FILE="$SCRIPT_DIR/.elk_env"

# Source common functions
source "$SCRIPT_DIR/functions.sh"

# Initialize or load .elk_env
if [ ! -f "$ELK_ENV_FILE" ]; then
  echo "# ELK Deployment State" > "$ELK_ENV_FILE"
  echo "DEPLOY_STARTED=$(date '+%Y-%m-%d %H:%M:%S')" >> "$ELK_ENV_FILE"
else
  source "$ELK_ENV_FILE"
fi

# Function to log and persist key state variables
log_step() {
  KEY="$1"
  VALUE="$2"
  grep -v "^$KEY=" "$ELK_ENV_FILE" > "$ELK_ENV_FILE.tmp" && mv "$ELK_ENV_FILE.tmp" "$ELK_ENV_FILE"
  echo "$KEY=$VALUE" >> "$ELK_ENV_FILE"
}

# Function to view the .elk_env file
view_env_file() {
  clear
  echo -e "${CYAN}Viewing .elk_env contents:${NC}\n"
  cat "$ELK_ENV_FILE"
  pause_and_return_to_menu
}

# Function to run secure_node_with_iptables
run_firewall_hardening() {
  clear
  echo -e "${GREEN}Running firewall hardening function...${NC}"

  # Set trap for Ctrl+C and EXIT
  trap 'echo -e "\n${YELLOW}Firewall hardening was interrupted. Returning to menu...${NC}"; return' SIGINT
  secure_node_with_iptables
  log_step "FIREWALL_HARDENING" "true"
  echo -e "\n${GREEN}Firewall configuration complete.${NC}"
  trap - SIGINT

  pause_and_return_to_menu
}

# Function to run cleanup.sh and return to menu
run_elk_cleanup() {
  clear
  echo -e "${GREEN}Running ELK cleanup...${NC}"

  # Set trap for Ctrl+C
  trap 'echo -e "\n${YELLOW}Cleanup was interrupted. Returning to menu...${NC}"; return' SIGINT

  # Run cleanup.sh and log
  source "$SCRIPT_DIR/cleanup.sh" && log_step "CLEANUP_COMPLETE" "true"
  echo -e "\n${GREEN}Cleanup complete.${NC}"

  # Reset trap and return to menu
  trap - SIGINT
  pause_and_return_to_menu
}

# Function to run full orchestration
run_full_setup() {
  clear
  echo -e "${CYAN}Starting full setup...${NC}"

  # Run setup steps
  source "$SCRIPT_DIR/foundation.sh" && log_step "FOUNDATION_SETUP" "true"
  source "$SCRIPT_DIR/service_install_setup.sh" && log_step "SERVICE_INSTALL" "true"
  source "$SCRIPT_DIR/agent_install_fleet_setup.sh" && log_step "AGENT_FLEET_SETUP" "true"

  echo -e "\n${YELLOW}Will this Elastic Stack build be moved to an offline (airgapped) environment after setup?${NC}"
  prompt_input "${GREEN}Type \"${YELLOW}yes${GREEN}\" to configure an internal Elastic Package Registry, or \"${YELLOW}no${GREEN}\" to continue normally: ${NC}" OFFLINE_MODE

  if [[ "$OFFLINE_MODE" =~ ^[Yy][Ee]?[Ss]?$ ]]; then
    echo -e "${GREEN}Airgapped deployment selected.${NC}"
    log_step "AIRGAPPED_MODE" "true"
    source "$SCRIPT_DIR/Elastic_EPR_install.sh"
    log_step "EPR_CONFIGURED" "true"
  else
    echo -e "${GREEN}Continuing without airgapped registry setup...${NC}"
    log_step "AIRGAPPED_MODE" "false"
  fi

  # Display configuration summary
  echo -e "\n${GREEN}Summary of your configuration:${NC}"
  if type print_summary_table &>/dev/null; then
    print_summary_table
  else
    echo -e "${YELLOW}Summary function not defined. Skipping summary display.${NC}"
  fi

  echo -e "\n${YELLOW}Would you like to see the TMUX cheat sheet now so you can switch panes to the iptables panel?${NC}"
  read -p "$(echo -e "${CYAN}Type yes or no: ${NC}")" SHOW_TMUX

  if [[ "$SHOW_TMUX" =~ ^[Yy][Ee]?[Ss]?$ ]]; then
    tmux_help
    log_step "TMUX_HELP_SHOWN" "true"
    echo -e "${GREEN}✅ TMUX help displayed. Use the keys above to switch panes!${NC}"
  else
    echo -e "${GREEN}✅ Skipping TMUX help. Use Ctrl+b ? if you forget!${NC}"
  fi

  log_step "DEPLOY_COMPLETE" "true"
  pause_and_return_to_menu
}

# Function to display the menu and handle user input
main_menu() {
  clear
  echo -e "${CYAN}"
  echo "========================================="
  echo "   ELK Stack Modular Deployment Menu"
  echo "========================================="
  echo -e "${NC}"
  echo "1. Run full setup (foundation, services, Fleet Server Setup, and EPR if needed.)"
  echo "2. Run foundation.sh"
  echo "3. Run service_install_setup.sh"
  echo "4. Run agent_install_fleet_setup.sh"
  echo "5. Run Elastic_EPR_install.sh (Only if moving to air gap env)"
  echo "6. Run cleanup.sh (cleans previous installs)"
  echo "7. Run firewall hardening (secure_node_with_iptables)"
  echo "8. View deployment log (.elk_env)"
  echo "9. Exit"
  echo

  read -p "Select an option [1-9]: " CHOICE

  case "$CHOICE" in
    1) run_full_setup ;;
    2) clear; source "$SCRIPT_DIR/foundation.sh"; log_step "FOUNDATION_SETUP" "true"; pause_and_return_to_menu ;;
    3) clear; source "$SCRIPT_DIR/service_install_setup.sh"; log_step "SERVICE_INSTALL" "true"; pause_and_return_to_menu ;;
    4) clear; source "$SCRIPT_DIR/agent_install_fleet_setup.sh"; log_step "AGENT_FLEET_SETUP" "true"; pause_and_return_to_menu ;;
    5) clear; source "$SCRIPT_DIR/Elastic_EPR_install.sh"; log_step "EPR_CONFIGURED" "true"; pause_and_return_to_menu ;;
    6) clear; source "$SCRIPT_DIR/cleanup.sh"; log_step "CLEANUP_COMPLETE" "true"; pause_and_return_to_menu ;;
    7) run_firewall_hardening ;;
    8) view_env_file ;;
    9) echo -e "${GREEN}Exiting setup. Goodbye!${NC}"; exit 0 ;;
    *) echo -e "${RED}Invalid option. Please try again.${NC}"; sleep 2 ;;
  esac
}

# --- Main loop ---
while true; do
  main_menu
done
