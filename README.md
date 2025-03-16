# Elastic Logstash Kibana Deployment Script

![htb_pic](https://github.com/user-attachments/assets/d786152b-9751-499d-aaef-f9d1c4f0ba21)



https://github.com/user-attachments/assets/da4704f8-cc7b-4702-9bec-9404fa2190c4

# 🚀 ELK Stack Deployment Script 

## 🚨 Disclaimer
**This script is intended for testing/training purposes only and is NOT recommended for large-scale production deployments. Yet....**

## 🔥 Overview  
The script **`deploy_ELK_STACK.sh`** automates the deployment and configuration of the **Elastic Stack** (**Elasticsearch, Kibana, and Logstash**) on Linux.
It provides options for both single-instance and cluster deployments, handling all necessary installations, configurations, and security settings. However, the cluster deployment is still in the works so only use single instace settings when prompted.

## 🖥️ System Requirements
To ensure a smooth deployment, it's recommended to use the following minimum VM specifications:

## Recommended OS: 🐧 Ubuntu (Latest LTS version)
- CPU: ⚡ 4 vCPUs
- RAM: 🔥 8GB - 16GB
- Storage: 💾 100GB attached storage
- Internet Connection: 🌍 Required for installation
- Installation Time: ⏳ Less than 15 minutes on a stable connection

---

# ✨ Features  

## 🔹 **Interactive Deployment**  
- Choose **single-instance or cluster** deployment.  
- Set **IP addresses** for **Elasticsearch, Kibana, and Logstash**.  

## 🔹 **Validation Checks**  
- Ensures **correct IP address formatting**.  

## 🔹 **Automated Installation**  
- Updates system packages.  
- Installs **prerequisites (curl, apt-transport-https, unzip)**.  
- Sets up **Elasticsearch, Kibana, and Logstash**.  

## 🔹 **Security Enhancements**  
- Resets and securely stores **Logstash and Kibana passwords**.  
- Creates a **superuser account**.  
- Generates **SSL certificates**.  
- Configures **API keys for Elasticsearch**.  

---

# 📜 Deployment Steps  

## 1️⃣ **User Input & Validation**  
- Choose **single-instance or cluster** deployment.  
- Enter and validate **IP addresses**.  

## 2️⃣ **Package Installation**  
- Update system and install **dependencies**.  
- Add the **Elastic APT repository**.  
- Install **Elasticsearch, Kibana, and Logstash**.  

## 3️⃣ **Service Configuration**  
- Configure **elasticsearch.yml** for security.  
- Update **kibana.yml** with SSL settings.  
- Set **logstash.yml and pipelines.yml**.  

## 4️⃣ **Security Setup**  
- Reset passwords for **Logstash and Kibana**.  
- Create a **superuser account**.  
- Generate and install **SSL certificates**.  

## 5️⃣ **Fleet & API Configuration**  
- Start **Elastic Stack trial license**.  
- Obtain **OAuth2 access token**.  
- Configure **Logstash API key authentication**.

## 6️⃣ **Fleet and Elastic Agent Integration**  
- 🚀 **Installs and configures Fleet Server** for centralized management.  
- 🔧 **Applies a default Fleet policy** for Fleet Server.  
- 🛡️ **Creates a Windows security policy** with the **Elastic Defend** package for endpoint protection.  
- 🔄 **Registers the Elastic Agent** with Fleet for automated monitoring.  

## 7️⃣ **Service Management & Finalization**  
- Restart all services and check status.  
- Monitor **Logstash CPU usage**.  
- 🔗 **Access Kibana at:** `https://${KIBANA_HOST}:5601`  
---
# 🚀 Happy Logging! 🎉  
---
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



