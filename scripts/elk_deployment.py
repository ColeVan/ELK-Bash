#!/usr/bin/env python3

import subprocess
import os
import shutil
import time

SESSION = "elk_monitor"
ORCHESTRATE = "./orchestrate.sh"
FUNCTIONS = "./functions.sh"

# Ensure needed scripts are executable
os.chmod(ORCHESTRATE, 0o755)
os.chmod(FUNCTIONS, 0o755)

# Determine CPU monitoring command
cpu_monitor_cmd = "htop" if shutil.which("htop") else "top"

# Kill old session if it exists
subprocess.run(["tmux", "kill-session", "-t", SESSION], stderr=subprocess.DEVNULL)

# Start new tmux session with one window
subprocess.run([
    "tmux", "-2", "new-session", "-d", "-s", SESSION, "-n", "Main"
])

# ✅ Prevent race conditions with a short pause
time.sleep(1)

# Now safe to begin splitting panes
subprocess.run([
    "tmux", "split-window", "-h", "-t", f"{SESSION}:0.0"
])

# Split vertically LEFT → pane 0 → 0 + 2
subprocess.run([
    "tmux", "select-pane", "-t", f"{SESSION}:0.0"
])
subprocess.run([
    "tmux", "split-window", "-v", "-t", f"{SESSION}:0.0"
])

# Split vertically RIGHT → pane 1 → 1 + 3
subprocess.run([
    "tmux", "select-pane", "-t", f"{SESSION}:0.1"
])
subprocess.run([
    "tmux", "split-window", "-v", "-t", f"{SESSION}:0.1"
])

# Pane 0: htop or fallback to top
subprocess.run([
    "tmux", "select-pane", "-t", f"{SESSION}:0.0"
])
subprocess.run([
    "tmux", "send-keys", cpu_monitor_cmd, "C-m"
])

# Pane 1: watch ss
subprocess.run([
    "tmux", "select-pane", "-t", f"{SESSION}:0.1"
])
subprocess.run([
    "tmux", "send-keys", "watch \"ss -tnp state established\"", "C-m"
])

# Pane 2: matrix
subprocess.run([
    "tmux", "select-pane", "-t", f"{SESSION}:0.2"
])
subprocess.run([
    "tmux", "send-keys", f"source {FUNCTIONS} && matrix_rain", "C-m"
])

# Pane 3: orchestrate.sh
subprocess.run([
    "tmux", "select-pane", "-t", f"{SESSION}:0.3"
])
subprocess.run([
    "tmux", "send-keys", f"bash {ORCHESTRATE}", "C-m"
])

# Attach to session
subprocess.run([
    "tmux", "-2", "attach-session", "-t", SESSION
])
