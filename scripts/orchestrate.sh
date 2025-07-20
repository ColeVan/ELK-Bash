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
