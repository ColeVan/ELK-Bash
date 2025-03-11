# PS-Managment

![image](https://github.com/ColeVan/PS-Kit-Managment/assets/70167373/37a9846e-5168-4cfa-a2cf-7bad9c7f7c93)

Overview

The script deploy_ELK_STACK_ALPHA_version_1.3.sh automates the deployment and configuration of the Elastic Stack (Elasticsearch, Kibana, and Logstash) on a Linux system. It provides options for both single-instance and cluster deployments, handling all necessary installations, configurations, and security settings.

Features

Interactive Deployment: Prompts the user to choose between a single-instance or cluster deployment and enter the necessary IP addresses.

Validation Checks: Ensures entered IP addresses are in the correct format.

Automated Installation: Updates system packages, installs prerequisites, and sets up Elasticsearch, Kibana, and Logstash.

Configuration Management:

Sets up elasticsearch.yml, kibana.yml, and logstash.yml with appropriate settings.

Enables SSL encryption and authentication.

Adjusts JVM settings for performance optimization.

Security Enhancements:

Resets and stores passwords for Logstash and Kibana.

Creates a superuser account.

Generates SSL certificates for secure communication between services.

Configures API keys for secure interaction with Elasticsearch.

Fleet and Elastic Agent Integration:

Downloads and installs the Elastic Agent for Fleet Server.

Configures Fleet Server policies via Kibana API.

Installs and integrates Elastic Defend for endpoint security.

Service Management:

Starts and enables Elasticsearch, Kibana, and Logstash as system services.

Provides status checks to ensure successful deployment.

Deployment Steps

User Input & Validation:

Prompts user for deployment type and relevant IP addresses.

Validates the provided IPs.

Package Installation:

Updates system and installs required dependencies (curl, apt-transport-https, unzip).

Adds the Elastic APT repository.

Installs Elasticsearch, Kibana, and Logstash.

Service Configuration:

Configures elasticsearch.yml for secure communication and cluster setup.

Updates kibana.yml with SSL settings and authentication details.

Edits logstash.yml and pipelines.yml for pipeline configuration.

Ensures proper permissions for configuration files.

Security Setup:

Resets passwords for Logstash and Kibana.

Prompts user for a superuser account and password.

Generates and installs SSL certificates.

Fleet & API Configuration:

Starts the Elastic Stack trial license.

Obtains OAuth2 access token.

Configures Logstash API key authentication.

Downloads and installs the Elastic Agent.

Creates Fleet and Windows security policies.

Service Management & Finalization:

Restarts all services and checks their statuses.

Provides guidance on monitoring Logstash CPU usage.

Outputs Kibana access details.
