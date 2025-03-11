# PS-Managment

![image](https://github.com/ColeVan/PS-Kit-Managment/assets/70167373/37a9846e-5168-4cfa-a2cf-7bad9c7f7c93)


🚀 ELK Stack Deployment Script

Overview

The script deploy_ELK_STACK_ALPHA_version_1.3.sh automates the deployment and configuration of the Elastic Stack (Elasticsearch, Kibana, and Logstash) on a Linux system. It provides options for both single-instance and cluster deployments, handling all necessary installations, configurations, and security settings.

✨ Features

🔹 Interactive Deployment

Prompts the user to choose between a single-instance or cluster deployment.

Asks for IP addresses for Elasticsearch, Kibana, and Logstash.

🔹 Validation Checks

Ensures entered IP addresses are correctly formatted.

🔹 Automated Installation

Updates system packages.

Installs prerequisites (curl, apt-transport-https, unzip).

Sets up Elasticsearch, Kibana, and Logstash.

🔹 Configuration Management

Configures elasticsearch.yml, kibana.yml, and logstash.yml.

Enables SSL encryption and authentication.

Optimizes JVM settings for better performance.

🔹 Security Enhancements

Resets and securely stores passwords for Logstash and Kibana.

Creates a superuser account.

Generates SSL certificates for secure communication.

Configures API keys for Elasticsearch.

🔹 Fleet and Elastic Agent Integration

Downloads and installs the Elastic Agent for Fleet Server.

Configures Fleet Server policies via Kibana API.

Installs and integrates Elastic Defend for endpoint security.

🔹 Service Management

Starts and enables Elasticsearch, Kibana, and Logstash as system services.

Provides status checks to ensure successful deployment.

📜 Deployment Steps

1️⃣ User Input & Validation

Prompts user for deployment type (single/cluster).

Requests and validates IP addresses.

2️⃣ Package Installation

Updates system and installs required dependencies.

Adds the Elastic APT repository.

Installs Elasticsearch, Kibana, and Logstash.

3️⃣ Service Configuration

Configures elasticsearch.yml for secure communication and cluster setup.

Updates kibana.yml with SSL settings and authentication details.

Edits logstash.yml and pipelines.yml for pipeline configuration.

Ensures proper file permissions.

4️⃣ Security Setup

Resets passwords for Logstash and Kibana.

Prompts user for a superuser account and password.

Generates and installs SSL certificates.

5️⃣ Fleet & API Configuration

Starts the Elastic Stack trial license.

Obtains OAuth2 access token.

Configures Logstash API key authentication.

Downloads and installs the Elastic Agent.

Creates Fleet and Windows security policies.

6️⃣ Service Management & Finalization

Restarts all services and checks their statuses.

Provides guidance on monitoring Logstash CPU usage.

Outputs Kibana access details.

🔗 Access Kibana at: https://${KIBANA_HOST}:5601

🚀 Happy Logging! 🎉


✅ GitHub To-Do List

🔍 System Performance Checks

🔒 Automate Logstash Outputs with SSL Certificates



