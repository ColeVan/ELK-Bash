# Elastic Logstash Kibana Deployment Script

<!--
**Note on Images:** The images currently linked are GitHub user-specific assets and might not render for everyone.
For wider visibility, these images should be embedded directly into the repository or removed if not essential.
-->
![htb_pic](https://github.com/user-attachments/assets/d786152b-9751-499d-aaef-f9d1c4f0ba21)




https://github.com/user-attachments/assets/33e2cdad-5ec9-4ac0-a22b-4b9ad4001186




## Table of Contents
- [Overview](#-overview)
- [System Requirements](#%EF%B8%8F-system-requirements)
- [Features](#-features)
- [Deployment Steps](#-deployment-steps)
- [Fleet and Elastic Agent Integration](#-fleet-and-elastic-agent-integration)
- [GitHub To-Do List](#-github-to-do-list)
- [Usage](#-usage)
- [Troubleshooting](#-troubleshooting)
- [Contributing](#-contributing)
- [License](#-license)

# 🚀 ELK Stack Deployment Script 

## 🚨 Disclaimer
**This script is intended for testing/training purposes only and is NOT recommended for large-scale production deployments. Yet....**

## 🔥 Overview  
The script **`deploy_ELK_STACK.sh`** automates the deployment and configuration of the **Elastic Stack** (**Elasticsearch, Kibana, and Logstash**) on a Linux host.
It supports deploying a single, all-in-one instance, or setting up the initial node for a multi-node Elasticsearch cluster.
When deploying for a cluster, the script prepares the first node and includes a feature to **generate enrollment tokens** for easily adding subsequent Elasticsearch nodes.
The "cluster" deployment option now genuinely prepares the current host as the first node of a potential multi-node cluster, rather than just allowing different IPs for services on the same host.

## 🖥️ System Requirements
To ensure a smooth deployment, the following minimum VM specifications are **recommended**. The script does not enforce these, but performance may suffer on lesser systems.

**Recommended OS:** 🐧 Ubuntu (Latest LTS version)
- **CPU:** ⚡ 4 vCPUs
- **RAM:** 🔥 8GB - 16GB (Logstash alone is configured by the script for an 8GB heap size)
- **Storage:** 💾 100GB attached storage (This is a recommendation; actual usage will vary based on data volume.)
- **Internet Connection:** 🌍 Required for downloading packages.
- **Installation Time:** ⏳ Typically less than 15 minutes on a stable connection with adequate resources.

---

# ✨ Features  

## 🔹 **Interactive Deployment**  
- Choose between **single-instance** (one IP for all services) or **cluster** (prepares the node for a multi-node Elasticsearch cluster) deployment.
- If "cluster" is chosen:
    - Confirmation if the current node will host all services (Elasticsearch, Logstash, Kibana).
    - Selection/confirmation of the management interface IP for cluster communication.
    - Prompts for the number of *additional* Elasticsearch nodes that will be added to this cluster.
    - Prompts for the name for the current Elasticsearch node (e.g., `node-1`).
- Set **IP addresses** for **Elasticsearch, Kibana, and Logstash** based on the deployment type.
- Prompts for a **superuser username and password** for Elasticsearch.
- Prompts for the desired **Elastic Stack version** (e.g., `8.14.3`) for Elasticsearch, Kibana, and related components like Elastic Agent and Elastic Defend integration.
- **Disk Space Confirmation:** Before proceeding with installation, asks for user confirmation regarding sufficient disk space, especially important for cluster nodes.
- **Enrollment Token Generation:** If a cluster deployment is selected, automatically generates and saves enrollment tokens for adding new Elasticsearch nodes to the cluster.

## 🔹 **Validation Checks**  
- Ensures **correct IPv4 address formatting**.
- Validates **superuser username and password** complexity (minimum length for password, allowed characters for username).

## 🔹 **Automated Installation**  
- Updates system packages (`apt-get update`).
- Installs **prerequisites (curl, apt-transport-https, unzip, pv)**.
- Adds the **Elastic APT repository** (8.x).
- Installs user-specified versions of **Elasticsearch and Kibana**.
- Installs the latest available version of **Logstash** from the repository.

## 🔹 **Security Enhancements**  
- **Resets default passwords** for internal Elasticsearch users like `kibana` (used by Kibana service) and `logstash_system` (used by Logstash for monitoring). These new passwords are then automatically configured in `kibana.yml` and `logstash.yml`. The script does not store these passwords elsewhere for later retrieval.
- Creates an **Elasticsearch superuser account** based on credentials provided by the user during prompts.
- Generates **SSL certificates** using `elasticsearch-certgen` for secure communication:
    - Between Elasticsearch, Kibana, and Logstash.
    - For accessing Kibana via HTTPS (`https://${KIBANA_HOST}:5601`).
    - For Elastic Agent communication with Logstash (port 5044).
- Configures **API keys for Elasticsearch** interactions, used by Fleet Server and Logstash pipelines for secure, token-based authentication.
- Converts the **Logstash SSL private key to PKCS#8 format** for compatibility with the Logstash input plugin.

---

# 📜 Deployment Steps  

## 1️⃣ **User Input & Validation**  
- Prompts for **deployment type**: `single` (all components share one IP) or `cluster` (prepares the node for a multi-node Elasticsearch cluster).
- If "cluster" deployment is selected:
    - Asks if the current node will host Elasticsearch, Logstash, and Kibana.
    - Prompts for the management IP address for the node, suggesting a detected one.
    - Asks for the number of *additional* Elasticsearch nodes that will join the cluster.
    - Asks for a unique name for the current Elasticsearch node (e.g., `node-1`).
- Prompts for and validates **IP addresses** for Elasticsearch, Kibana, and Logstash based on the deployment type.
- Prompts for and validates **superuser credentials** (username and password) for Elasticsearch.
- Prompts for the desired **Elastic Stack version** (e.g., `8.14.3`) to be used for Elasticsearch, Kibana, and associated Elastic Agent/Defend versions.
- **Disk Space Confirmation:** Requires the user to type "yes" to acknowledge disk space considerations before proceeding with installation.

## 2️⃣ **Package Installation**  
- Updates system package lists (`apt-get update`).
- Installs **dependencies**: `curl`, `apt-transport-https`, `unzip`, and `pv` (for progress visualization).
- Adds the **Elastic APT repository** for version 8.x.
- Installs the user-specified versions of **Elasticsearch and Kibana**.
- Installs the **latest available version of Logstash** from the Elastic repository.

## 3️⃣ **Service Configuration**  
- **Elasticsearch (`elasticsearch.yml`):**
    - Sets `network.host: ${ELASTIC_HOST}`.
    - Sets `http.port: 9200`.
    - Sets `node.name: ${NODE_NAME}` (user-defined during cluster setup, e.g., `node-1`).
    - Configures paths for data and logs.
    - Enables X-Pack security features, including SSL for HTTP and transport layers, pointing to generated certificate paths (`certs/http.p12`, `certs/transport.p12`).
    - Sets `cluster.initial_master_nodes: ["${NODE_NAME}"]`.
    - Adds `transport.host: ${ELASTIC_HOST}` for explicit binding of the transport layer.
- **Kibana (`kibana.yml`):**
    - Sets `server.port`, `server.host`.
    - Configures `elasticsearch.hosts` to connect to Elasticsearch via HTTPS, including the path to the CA certificate (`/etc/kibana/certs/http_ca.crt`).
    - Enables SSL for Kibana's server using generated certificates (`/etc/kibana/certs/kibana.crt`, `/etc/kibana/certs/kibana.key`).
    - Sets `elasticsearch.username` to `kibana` and `elasticsearch.password` to the dynamically reset password (`${kibana_password}`).
    - Configures X-Pack security encryption keys.
- **Logstash:**
    - **`logstash.yml`**: Configures queue type, `node.name: ${NODE_NAME}`, monitoring settings (including `logstash_system` username and its dynamically reset password), Elasticsearch connection details with SSL CA (`/etc/logstash/certs/http_ca.crt`), and log paths.
    - **`pipelines.yml`**: Defines the main pipeline pointing to `"/etc/logstash/conf.d/logstash.conf"`.
    - **`jvm.options`**: Modifies heap size (e.g., to 8GB using `-Xms8g` and `-Xmx8g`) and sets a temporary directory for Java (`-Djava.io.tmpdir=/opt/logstash_tmp`).
    - **`conf.d/logstash.conf`**:
        - **Input:** Configures an `elastic_agent` input plugin listening on port 5044, secured with SSL (`ssl_certificate_authorities => ["/etc/logstash/certs/ca.crt"]`, `ssl_certificate => "/etc/logstash/certs/logstash.crt"`, `ssl_key => "/etc/logstash/certs/logstash.pkcs8.key"`) and requiring client authentication (`ssl_client_authentication => "required"`).
        - **Output:** Configures an `elasticsearch` output plugin to send data to the Elasticsearch host, using an **API key** for authentication and SSL with CA verification (`ssl_certificate_authorities => '/etc/logstash/certs/http_ca.crt'`). Enables `data_stream` support.

## 4️⃣ **Security Setup**  
- **SSL Certificate Generation:**
    - Creates an `instances.yml` file defining the Elasticsearch, Kibana, and Logstash instances with their IPs for `elasticsearch-certgen`.
    - Uses `sudo /usr/share/elasticsearch/bin/elasticsearch-certgen --in /usr/share/elasticsearch/instances.yml --out /usr/share/elasticsearch/certs.zip` to generate SSL certificates.
    - Unzips `certs.zip` and copies the generated CA (`ca.crt`), certificates (`.crt`), and keys (`.key`) to the appropriate directories under `/etc/elasticsearch/certs`, `/etc/kibana/certs`, and `/etc/logstash/certs`. This includes `http_ca.crt` copied from Elasticsearch certs to Kibana and Logstash cert directories.
    - Sets correct ownership (e.g., `kibana:kibana`, `logstash:logstash`) and permissions for these certificate directories.
    - Converts the Logstash private key (`logstash.key`) to **PKCS#8 format (`logstash.pkcs8.key`)** using `openssl pkcs8` as required by the Logstash input plugin.
- **Password Resets & Superuser Creation:**
    - Resets the password for the internal `logstash_system` user using `elasticsearch-reset-password -u logstash_system` and updates the password in `logstash.yml`.
    - Resets the password for the internal `kibana` user (for `elasticsearch.username` in `kibana.yml`) using `elasticsearch-reset-password -u kibana` and updates the password in `kibana.yml`.
    - Creates the **Elasticsearch superuser account** (e.g., `elastic`) using the username and password provided by the user during prompts, assigning the `superuser` role.

## 5️⃣ **Fleet & API Configuration**  
- **Trial License:** Activates the Elastic Stack trial license via a `POST` request to `/_license/start_trial` on Elasticsearch.
- **OAuth2 Access Token:** Obtains an OAuth2 access token for the newly created superuser by sending a `POST` request to `/_security/oauth2/token`. This token is used to authorize subsequent API calls.
- **Logstash API Key:** Creates an Elasticsearch API key named `fleet_logstash-api-key` with specific roles for data ingestion from Logstash to Elasticsearch. The decoded version of this key is used in `logstash.conf`. This is done via a `POST` request to `/_security/api_key`.
- **Fleet Service Token:** Creates an Elasticsearch service token for `elastic/fleet-server` using `elasticsearch-service-tokens create`. This token is used to enroll the Fleet Server.

## 6️⃣ **Fleet and Elastic Agent Integration**  
- **Elastic Agent Download:** Downloads and extracts the Elastic Agent. The version downloaded matches the user-specified `$ELASTIC_VERSION` (e.g., `elastic-agent-$ELASTIC_VERSION-linux-x86_64.tar.gz`).
- **Fleet Policy for Fleet Server:** Creates a Fleet agent policy named "fleet-server-policy" via Kibana API (`/api/fleet/agent_policies`), configured for monitoring and to host a Fleet Server.
- **Fleet Server Host Configuration:** Defines the Fleet Server host URL (e.g., `https://${ELASTIC_HOST}:8220`) via Kibana API (`/api/fleet/fleet_server_hosts`).
- **Elastic Agent Installation as Fleet Server:** Installs and enrolls the downloaded Elastic Agent to function as the Fleet Server using `sudo ./elastic-agent install`. This command uses the generated service token, the "fleet-server-policy", and specifies paths to the CA and server certificates for secure communication with Elasticsearch and for its own HTTPS endpoint.
- **Windows EDR Policy Creation:**
    - Creates a new Fleet agent policy named "Windows_EDR_and_Host_logs" via Kibana API.
    - Adds the "Elastic Defend" integration to this policy with the "EDRComplete" preset via Kibana API (`/api/fleet/package_policies`). The version of the "Elastic Defend" package used is dynamically set to the user-provided `$ELASTIC_VERSION`.
- **Default Output for Fleet (Logstash):** Configures "Logstash Output" as the default output in Fleet settings via Kibana API (`/api/fleet/outputs`). This setup specifies the Logstash host and port (e.g., `${LOGSTASH_HOST}:5044`) and includes the SSL CA, certificate, and key (from `/usr/share/elasticsearch/ssl/`) for secure communication from Fleet-managed agents to Logstash.

## 7️⃣ **Service Management & Finalization**  
- Starts/restarts **Elasticsearch, Kibana, and Logstash** services using `systemctl start` and `systemctl restart`, and reports their status using `systemctl status --no-pager`.
- Enables these services for **persistent start upon system reboot** (`systemctl enable`).
- Provides a final message with the Kibana access URL: `https://${KIBANA_HOST}:5601`.
- Includes a note about monitoring Logstash CPU usage post-installation and how to stop Logstash if issues arise.
- Appends logging configuration to `kibana.yml` to ensure Kibana logs to `/var/log/kibana.log` for easier troubleshooting, then restarts Kibana.
- If a "cluster" deployment was chosen, it proceeds to the [Elasticsearch Cluster Setup](#-elasticsearch-cluster-setup) steps for token generation.
---
# 🔗 Elasticsearch Cluster Setup
This section applies if you selected the "cluster" deployment type. The script prepares the current node as the first node of your Elasticsearch cluster and can help you generate enrollment tokens for additional nodes.

After the main installation and configuration of the first node, the script will:
1.  **Prompt for Token Generation:** Ask if you want to generate enrollment tokens for the additional Elasticsearch nodes you specified earlier (via the `NODE_COUNT` variable, which is your input + 1 for the current node).
2.  **Token Generation Loop:** If you confirm:
    *   It will loop from the second node up to `NODE_COUNT`.
    *   For each additional node, it executes:
        ```bash
        sudo /usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s node
        ```
    *   The output (the token) is appended to a file named `enrollment_tokens.txt` in the current directory where the script is run.
3.  **Token File:** The `enrollment_tokens.txt` file will store the tokens. It might look something like this:
    ```
    Node 2:
    eyJ2ZXIiOiI4LjE0LjMiLCJhZHIiOlsiMTkyLjE2OC4xLjEwOjkyMDAiXSwiZmdyIjoiY2IwZjRj...IiwiZWsiOiJNVFkyTXprek5UVTBOekkxTmcwPSJ9Cg==

    Node 3:
    eyJ2ZXIiOiI4LjE0LjMiLCJhZHIiOlsiMTkyLjE2OC4xLjEwOjkyMDAiXSwiZmdyIjoiNzRkYzYx...IiwiZWsiOiJNVFkyTXprek5UVTBOekkxTmcwPSJ9Cg==
    ```
    (Note: The tokens above are examples and will be much longer.)
4.  **Manual Token Generation:** If token generation is skipped or fails, the script reminds you that you can manually generate a token for a new node using:
    ```bash
    sudo /usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s node
    ```
    You would run this on the existing, already-configured Elasticsearch node (the one set up by this script) when you are ready to add a new node to the cluster.

Use these tokens when setting up new Elasticsearch nodes to securely join them to this cluster. Each token is for a single new node.

---
# 🚀 Happy Logging! 🎉  
---

## 📖 Usage
To use the ELK Stack deployment script, follow these steps:

1.  **Download the script:**
    ```bash
    git clone https://github.com/YOUR_USERNAME/YOUR_REPOSITORY.git
    cd YOUR_REPOSITORY
    ```
    (Replace `YOUR_USERNAME` and `YOUR_REPOSITORY` with the actual GitHub username and repository name. If you cloned this repository, you are likely already in the correct directory.)

2.  **Make the script executable:**
    ```bash
    chmod +x deploy_ELK_STACK.sh
    ```

3.  **Run the script:**
    The script requires `sudo` privileges to install packages, configure services, manage system files, and run binaries from `/usr/share/elasticsearch/bin/`.
    ```bash
    sudo ./deploy_ELK_STACK.sh
    ```

4.  **Follow the prompts:**
    Upon execution, the script will guide you through the setup process:
    *   **Deployment Type:** Choose between `single` (all services use one IP) or `cluster` (prepares the current node for a multi-node Elasticsearch cluster).
        *   If `cluster` is chosen, you'll be asked for:
            *   Confirmation if the current node will host all services (Elasticsearch, Logstash, Kibana).
            *   The management IP for the node.
            *   The number of *additional* Elasticsearch nodes for the cluster.
            *   A name for the current Elasticsearch node (e.g., `node-1`).
    *   **IP Addresses:** Enter the IPv4 addresses for Elasticsearch, Kibana, and Logstash as prompted.
    *   **Superuser Credentials:** Set up a username and password for the Elasticsearch superuser.
    *   **Elastic Stack Version:** Enter the desired version for Elasticsearch, Kibana, and related components (e.g., `8.14.3`). This version will also be used for downloading the corresponding Elastic Agent and for setting the Elastic Defend integration version. Logstash will be installed as the latest version available in the repository.
    *   **Disk Space Confirmation:** You'll be asked to confirm you understand disk space requirements.

    The script will then automate the installation and configuration. If "cluster" mode was selected, it will offer to generate enrollment tokens for additional nodes (see [Elasticsearch Cluster Setup](#-elasticsearch-cluster-setup)).

## ❓ Troubleshooting
This section covers common issues you might encounter during or after deployment and how to resolve them.

1.  **Script Execution Errors:**
    *   **Permission Denied:** If you see an error like `bash: ./deploy_ELK_STACK.sh: Permission denied`, ensure you've made the script executable:
        ```bash
        chmod +x deploy_ELK_STACK.sh
        ```
        And that you are running it with `sudo`:
        ```bash
        sudo ./deploy_ELK_STACK.sh
        ```
    *   **Command Not Found (e.g., `curl`, `pv`, `unzip`, `openssl`):** The script attempts to install `curl`, `apt-transport-https`, `unzip`, and `pv`. If `openssl` (used by the script for Logstash key conversion) or another critical command is missing, it might indicate a very minimal OS installation or a `PATH` issue. Try installing them manually:
        ```bash
        sudo apt update
        sudo apt install -y curl apt-transport-https unzip pv openssl
        ```
        Then, re-run the deployment script.

2.  **Elasticsearch / Kibana / Logstash Service Failures:**
    *   **Service Not Starting:** If a service fails to start, check its logs for specific error messages:
        *   Elasticsearch: `sudo journalctl -u elasticsearch` or check files in `/var/log/elasticsearch/` (default log path).
        *   Kibana: `sudo journalctl -u kibana` or check `/var/log/kibana/kibana.log` (the script explicitly configures Kibana to log here by appending to `kibana.yml`).
        *   Logstash: `sudo journalctl -u logstash` or check files in `/var/log/logstash/` (default log path).
    *   **Port Conflicts:** Services might fail if their configured ports are already in use. Key ports used by the script and their default assignments:
        *   Elasticsearch: `9200` (HTTP), `9300` (Transport Layer)
        *   Kibana: `5601` (HTTPS access)
        *   Logstash: `5044` (Elastic Agent/Beats input via SSL), `9600` (internal monitoring API, though X-Pack monitoring configured by script uses Elasticsearch credentials)
        *   Fleet Server (run by Elastic Agent): `8220` (HTTPS)
        Check for listening ports using a command like:
        ```bash
        sudo netstat -tulnp | grep -E '9200|9300|5601|5044|9600|8220'
        ```
        If another service is using a required port, you'll need to stop that service or reconfigure the Elastic Stack component (which would require manual adjustments to the script's configurations and potentially generated certificate SANs).

3.  **IP Address Validation Errors:**
    *   The script expects IPv4 addresses in the standard dot-decimal notation (e.g., `192.168.1.10`). Ensure there are no typos or incorrect characters. If using hostnames, ensure they are resolvable from the machine running the script and from within the ELK components themselves (e.g., add to `/etc/hosts` or ensure DNS is correct). The generated certificates will also use the provided IPs/hostnames.

4.  **SSL Certificate Issues:**
    *   **Certificate Generation:** The script automatically generates self-signed SSL certificates using `elasticsearch-certgen`. The primary CA certificate generated by this process (found at `/usr/share/elasticsearch/ssl/ca/ca.crt` after generation, and copied to places like `/etc/elasticsearch/certs/http_ca.crt`, `/etc/kibana/certs/http_ca.crt`, `/etc/logstash/certs/http_ca.crt`) is used to sign other certificates for Elasticsearch, Kibana, and Logstash. These component-specific certificates and keys are stored in their respective `/etc/{service}/certs/` directories.
    *   **Browser Warnings for Kibana:** When you access Kibana at `https://${KIBANA_HOST}:5601` (replace `${KIBANA_HOST}` with your Kibana IP/hostname), your browser will show a warning about the site's security certificate not being trusted. This is normal because the certificate is self-signed by the CA generated via `elasticsearch-certgen`. You can safely bypass this warning for testing/training purposes. For production environments, you would use certificates signed by a globally trusted Certificate Authority (CA).
    *   **PKCS#8 Key for Logstash:** Logstash's `elastic_agent` input with SSL requires the private key to be in PKCS#8 format. The script handles this conversion using `openssl pkcs8`. If this step fails or is skipped, Logstash might not start with SSL enabled on port 5044.

5.  **Fleet Server / Elastic Agent Issues:**
    *   **Agent Not Enrolling or Sending Data (to Fleet or Logstash):**
        *   **Check Fleet Server Status:** In Kibana, navigate to **Stack Management > Fleet > Agents**. The Elastic Agent installed by the script to act as Fleet Server should appear here, be healthy, and show recent check-ins.
        *   **Network Connectivity:**
            *   Ensure other Elastic Agents (if any) can reach the Fleet Server URL (e.g., `https://<FLEET_SERVER_IP_OR_HOSTNAME>:8220`).
            *   Ensure Fleet Server (via the Elastic Agent it runs on) can reach Logstash on `${LOGSTASH_HOST}:5044` if Logstash is the configured output for Fleet.
            *   Check for any firewalls (e.g., `ufw`, `firewalld` on the host, or network firewalls) that might be blocking these ports.
        *   **CA Certificate Trust:**
            *   **Agents to Fleet Server:** The script installs the Fleet Server agent with flags like `--fleet-server-es-ca=/usr/share/elasticsearch/ssl/ca/ca.crt`. If enrolling other agents manually to this Fleet Server, they will need to trust this CA or the specific Fleet Server certificate.
            *   **Fleet to Logstash:** The script configures Logstash as a Fleet output using the CA from `/usr/share/elasticsearch/ssl/ca/ca.crt`, and the Elasticsearch server certificate/key (as Logstash output in Fleet settings uses these certs intended for ES, which should be signed by the same CA). The Logstash input on port 5044 is also configured with its own cert/key signed by this CA and `ssl_client_authentication => "required"`. This means agents sending data via Fleet to Logstash must present a certificate signed by this CA.
    *   **Logstash Output Problems (Data not appearing in Elasticsearch from Logstash):**
        *   Verify the Logstash pipeline configuration (`/etc/logstash/conf.d/logstash.conf`). Ensure the `input.elastic_agent` and `output.elasticsearch` sections are correct.
        *   Check the Elasticsearch API key (`api_key => "..."`) in the `output.elasticsearch` block of `logstash.conf`. Confirm it's the correct decoded key generated by the script and that it has the necessary permissions (the script creates one with specific roles like `logstash-output`).
        *   Confirm Elasticsearch output settings in `logstash.conf`, especially `ssl_certificate_authorities => '/etc/logstash/certs/http_ca.crt'`, are pointing to the correct CA certificate that Elasticsearch's HTTP layer is using.
    *   **Elastic Agent Version:** The script now uses the user-provided `$ELASTIC_VERSION` to download the matching Elastic Agent (e.g., `elastic-agent-$ELASTIC_VERSION-linux-x86_64.tar.gz`) and to set the Elastic Defend integration version in the Windows policy. Ensure this version is valid and available. If you encounter issues, verify the specified version exists in Elastic's download repositories.

6.  **Resource Limitations:**
    *   **Low Memory, CPU, or Disk Space:** Elasticsearch and Logstash are resource-intensive. The script configures Logstash with an 8GB heap (`-Xms8g`, `-Xmx8g` in `jvm.options`), which is substantial. The script also includes a disk space confirmation prompt.
        *   Refer to the **[System Requirements](#️-system-requirements)** section.
        *   Check current system resource usage (e.g., using `htop`, `free -m`, `df -h`).
        *   Elasticsearch and Logstash logs often indicate resource exhaustion.

7.  **Cluster Enrollment Issues:**
    *   **Token generation failed:**
        *   Check Elasticsearch logs (`sudo journalctl -u elasticsearch` or files in `/var/log/elasticsearch/`) on the primary node immediately after the script attempts token generation.
        *   Ensure the `/usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token` script has execute permissions and that there are no underlying Elasticsearch issues preventing token creation (e.g., cluster health red, insufficient master nodes if it was already part of a degraded cluster).
    *   **Nodes not joining cluster:**
        *   **Network Connectivity:** Verify that new nodes can reach the primary node on the `transport.host` IP (e.g., `${ELASTIC_HOST}`) and port `9300` (default transport port, though not explicitly set in script, it's implied by `transport.host`). Also, ensure new nodes can reach the primary node on the Elasticsearch HTTP port (`9200`) as listed in the enrollment token.
        *   **Firewall:** Check firewalls (`ufw`, `firewalld`, cloud security groups) on all nodes. Ports `9200` and `9300` must be open between cluster members.
        *   **`transport.host` Configuration:** Ensure `transport.host` is correctly set in `elasticsearch.yml` on all nodes to an IP address reachable by other nodes in the cluster. The script sets this for the first node. Subsequent nodes configured manually or by other means also need this.
        *   **Correct Token:** Double-check that the exact enrollment token generated by the primary node is being used on the new node during its setup process. Each token is for one node only.
        *   **Elasticsearch Logs on New Node:** Check the Elasticsearch logs on the node attempting to join for errors related to discovery or joining (e.g., "failed to join cluster," "master not discovered").

If you encounter an issue not listed here, check the service logs first, as they often provide detailed error messages that can help pinpoint the problem.

## 🤝 Contributing
We welcome contributions to improve and expand this ELK Stack deployment script! Whether you're fixing a bug, adding a new feature, or improving documentation, your help is appreciated.

**Ways to Contribute:**

*   **Reporting Bugs:** If you find a bug, please open an issue on GitHub with a clear description and steps to reproduce it.
*   **Suggesting Enhancements:** Have an idea for a new feature or an improvement to an existing one? Open an issue to discuss it.
*   **Improving Documentation:** If you find parts of the documentation unclear or incomplete, feel free to suggest changes or submit a pull request.
*   **Submitting Pull Requests:** For code changes, please follow the process outlined below.

**Contribution Process:**

1.  **Fork the Repository:** Create your own fork of the project on GitHub.
2.  **Create a Branch:** Create a new branch in your fork for your changes. Choose a descriptive branch name (e.g., `fix-kibana-config-bug` or `feature-add-metricbeat-setup`).
    ```bash
    git checkout -b your-branch-name
    ```
3.  **Make Your Changes:** Implement your bug fix or feature. Ensure your code is clear, well-commented, and follows the existing style where possible.
4.  **Test Your Changes:** Thoroughly test your changes to ensure they work as expected and do not introduce new issues. If applicable, consider how your changes might affect different deployment scenarios (e.g., single instance vs. cluster, different Linux distributions if supported in the future).
5.  **Commit Your Changes:**
    ```bash
    git add .
    git commit -m "Brief description of your changes"
    ```
6.  **Push to Your Fork:**
    ```bash
    git push origin your-branch-name
    ```
7.  **Submit a Pull Request:** Open a pull request from your branch to the main repository's `main` branch. Provide a clear title and a detailed description of your changes, including the problem you're solving or the feature you're adding. Reference any relevant issue numbers.

**Licensing of Contributions:**

By contributing to this project, you agree that your contributions will be licensed under the same license as the project (see the [License](#-license) section).

We look forward to your contributions!

## 📜 License
This project is licensed under the **MIT License**.

The MIT License is a permissive free software license originating at the Massachusetts Institute of Technology (MIT). It is a simple license that grants broad permissions, including the right to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the software.

Key aspects of the MIT License:
- **Permissive:** It allows for reuse within proprietary software, provided that all copies of the licensed software include a copy of the MIT License terms and the copyright notice.
- **No Warranty:** The software is provided "as is", without warranty of any kind.

You can find the full text of the license at:
[https://opensource.org/licenses/MIT](https://opensource.org/licenses/MIT)

## ✅ GitHub To-Do List  
- 🔍 **System Performance Checks**
  
## 🔧 Tasks to Implement:
- [ ] **Remote Execution Support**: Add functionality to execute commands on a remote Elasticsearch instance via SSH.
  - Prompt for the remote host IP, username, and SSH key.
  - Ensure the remote system has Elasticsearch installed or provide installation steps.
  - Configure the remote Elasticsearch instance to integrate with Kibana and Logstash.

- [ ] **System Health Check Before Installation**:
  - Check **disk space** availability and recommend minimum requirements.
  - Detect system **architecture** (x86_64, ARM) and suggest optimal settings.

- [ ] **Post-Install Validation**:
  - Verify that all services (Elasticsearch, Logstash, Kibana) are running correctly.
  - Log any errors for debugging.

## 🚀 Future Enhancements:
- [ ] Automate Elasticsearch cluster setup (multi-node deployment).
- [ ] Add an option for **full-stack monitoring** with Metricbeat.
- [ ] Provide an easy rollback mechanism in case of installation failure.



