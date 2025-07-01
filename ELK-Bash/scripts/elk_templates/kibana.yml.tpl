# Kibana configuration
# =================== System: Logging ===================
server.port: 5601
server.host: ${KIBANA_HOST}
elasticsearch.hosts: ["https://${ELASTIC_HOST}:9200"]
elasticsearch.ssl.certificateAuthorities: ["/etc/kibana/certs/http_ca.crt"]
server.ssl.enabled: true
server.ssl.certificate: "/etc/kibana/certs/kibana.crt"
server.ssl.key: "/etc/kibana/certs/kibana.key"
# Specifies the path where Kibana creates the process ID file.
pid.file: /run/kibana/kibana.pid
# X-Pack Security
elasticsearch.username: "kibana"
elasticsearch.password: "${kibana_password}"
xpack.security.encryptionKey: "something_at_least_32_characters"
xpack.encryptedSavedObjects.encryptionKey: "something_at_least_32_characters"