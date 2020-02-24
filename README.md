# prometheus-http-discovery

`prometheus-http-discovery` is a Prometheus sidecar for dicovering scrape targets
by calling HTTP endpoints.

HTTP services are expected to return json in the same format as [file_sd_config](https://prometheus.io/docs/prometheus/latest/configuration/configuration/#file_sd_config)

### Example Configuration

```yaml
discover_configs:
  - url: http://my-service:8080/discover
    file: /configs/test.json
    refresh_interval: 5m
```

Will do an HTTP GET to http://my-service:8080/discover every 5 minutes, verify the json is valid, and write it to /configs/test.json

Each discover_configs item may include:

- url: target url - required.
- file: output file - required.
- timeout: request timeout as a [duration](https://prometheus.io/docs/prometheus/latest/configuration/configuration/#duration)
- tls_config: See [tls_config](https://prometheus.io/docs/prometheus/latest/configuration/configuration/#tls_config)
- refresh_internal: a [duration](https://prometheus.io/docs/prometheus/latest/configuration/configuration/#duration)
- bearer_token: Optional bearer token authentication information.
- proxy_url: Optional proxy URL.
- basic_auth:
```
basic_auth:
  [ username: <string> ]
  [ password: <string> ]
  [ password_file: <string> ]
```
