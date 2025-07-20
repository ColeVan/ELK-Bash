#!/bin/bash
set -e

# --- Path to extracted agent directory ---
AGENT_DIR="$HOME/elastic-agent-9.0.2-linux-x86_64"

# --- Header ---
echo -e "${CYAN}"
echo "========================================="
echo "   🧹 Cleaning up Extracted Agent Folder"
echo "========================================="
echo -e "${NC}"

# --- Remove extracted directory ---
if [[ -d "$AGENT_DIR" ]]; then
    echo -e "${YELLOW}Removing directory: ${CYAN}$AGENT_DIR${NC}"
    rm -rf "$AGENT_DIR"
    echo -e "${GREEN}✔ Removed extracted agent directory.${NC}"
else
    echo -e "${YELLOW}Directory not found: ${AGENT_DIR} — skipping.${NC}"
fi

# --- Done ---
echo -e "${GREEN}✅ Cleanup complete. Tarball has been retained for future use.${NC}"
