#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

source "$SCRIPT_DIR/functions.sh"
source "$SCRIPT_DIR/foundation.sh"
source "$SCRIPT_DIR/service_install_setup.sh"
source "$SCRIPT_DIR/agent_install_fleet_setup.sh"
