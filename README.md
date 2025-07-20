# ELK-Bash

<img width="1024" height="1536" alt="image" src="https://github.com/user-attachments/assets/2b7914f6-583a-4f0e-89ab-2c4273d6e3c7" />


ELK-Bash contains a collection of Bash scripts that automate the installation and hardening of the Elastic Stack (Elasticsearch, Logstash and Kibana) on Ubuntu.  The scripts can deploy a single node or build out additional nodes, install Fleet Server and Elastic Agent, and even prepare an air‑gapped Elastic Package Registry for offline environments.  Firewall hardening options and a TMUX based monitoring helper are included to streamline the entire setup.

<img width="1773" height="925" alt="image" src="https://github.com/user-attachments/assets/ce9d9b8e-9bb8-4174-96e3-1a2826b0e942" />


## Repository layout

```
scripts/
├── orchestrate.sh               # Menu driven entry point to run setup steps
├── foundation.sh                # Gathers input and performs cleanup of old installs
├── service_install_setup.sh     # Installs Elasticsearch, Kibana and Logstash
├── agent_install_fleet_setup.sh # Installs Elastic Agent/Fleet Server
├── Elastic_EPR_install.sh       # Optional local package registry for air‑gapped use
├── deploy_elasticsearch_node.sh # Join additional nodes to an existing cluster
├── elk_deployment.py            # Launches orchestrate.sh inside a tmux session
├── functions.sh                 # Shared helper functions
└── cleanup.sh                   # Removes previous installations
```

Template configuration files used by the scripts reside in `scripts/elk_templates/`.

## Prerequisites

- Ubuntu server with `sudo` privileges.
- Internet access for package downloads (unless you plan to build an offline registry).
- At least 4 vCPUs and 8 GB of memory are recommended.

## Quick start

1. Clone this repository on the target Ubuntu host:
   ```bash
   git clone https://github.com/yourorg/ELK-Bash.git
   cd ELK-Bash
   ```
2. Execute the orchestrator script with sudo to begin the guided install:
   ```bash
   sudo bash scripts/orchestrate.sh
   ```
3. Follow the prompts to select your deployment options.  The menu allows you to run all steps or each script individually.  Enrollment tokens for additional nodes are saved to `enrollment_tokens.txt`.
4. When building extra Elasticsearch nodes, run the following on the new machine and supply the token created by the first node:
   ```bash
   sudo bash scripts/deploy_elasticsearch_node.sh
   ```
5. For a tmux based experience that displays monitoring panes while the setup runs, launch:
   ```bash
   sudo python3 scripts/elk_deployment.py
   ```

The `.elk_env` file records the progress of the deployment and can be viewed from the menu for troubleshooting.

## Troubleshooting tips

- **Check services** – after installation, verify each service using `systemctl status elasticsearch`, `logstash`, `kibana` and `elastic-agent`.
- **Inspect logs** – service logs reside under `/var/log/` for Elasticsearch, Logstash and Kibana.  Fleet Server logs are under `/opt/Elastic/Agent`.
- **Ports blocked** – if agents cannot connect, ensure the required ports (9200, 5044, 5601 and 8220) are reachable or adjust the firewall rules created by `secure_node_with_iptables`.
- **Reuse of nodes** – running `scripts/cleanup.sh` removes prior installations in case you need to redeploy from scratch.
- **Deployment history** – inspect `.elk_env` to review which steps completed successfully.

## License

This project is made available under the terms of the [MIT License](LICENSE).  You may use, modify and distribute the code freely, but the software is provided "as is" without warranty.
