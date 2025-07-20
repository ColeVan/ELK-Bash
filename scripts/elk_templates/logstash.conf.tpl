input {
  elastic_agent {
    port => 5044
    ssl_enabled => true
    ssl_certificate_authorities => ["/etc/logstash/certs/ca.crt"]
    ssl_certificate => "/etc/logstash/certs/logstash.crt"
    ssl_key => "/etc/logstash/certs/logstash.pkcs8.key"
    ssl_client_authentication => "required"
  }
}
output {
  elasticsearch {
    hosts => ["https://${ELASTIC_HOST}:9200"]
    api_key => "${decoded_value}"
    data_stream => true
    ssl_enabled => true
    ssl_certificate_authorities => '/etc/logstash/certs/http_ca.crt'
  }
}