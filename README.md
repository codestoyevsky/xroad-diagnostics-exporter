# xroad-diagnostics-exporter

Prometheus exporter for the checks on the X-Road® Security Server **Diagnostics** and
**Keys and certificates** pages.

The Security Server already checks its global configuration, OCSP responders, timestamping
services and certificates, but you only see the results when you open the admin UI. This
exporter reads the same data from the management REST API, so you can put it on a Grafana
dashboard and get alerts before something breaks, for example:

- global configuration has not been updated, so the server will soon stop serving traffic
- an OCSP responder or timestamping service is failing
- the authentication or signing certificate expires in 30 days
- a certificate has no good OCSP response
- the software token is logged out after a restart

It only reads data. It needs an API key with the read-only `XROAD_SECURITYSERVER_OBSERVER` role.

This is a community project and is not affiliated with or endorsed by NIIS.

## How this compares to the built-in checks

The Security Server has a [health check service](https://github.com/nordic-institute/X-Road/blob/develop/doc/Manuals/LoadBalancing/ig-xlb_x-road_external_load_balancer_installation_guide.md#34-health-check-service-configuration)
(port 5588, disabled by default). It answers HTTP 200 or 500 and is meant for load balancers.
Use it for that. This exporter is for monitoring and alerting:

- it tells you *what* is wrong, for example which OCSP responder or which certificate
- it warns before things break, for example 30 days before a certificate expires
- it also covers timestamping services, which the health check does not
- the output is in Prometheus format, so it works with existing dashboards and alerting

The environmental monitoring service also reports certificate data, but in X-Road's own
format, through an X-Road message or JMX.

## Try the demo

The [`demo`](demo) folder starts a fake Security Server with made-up data, the exporter,
Prometheus and Grafana:

```bash
cd demo
docker compose up -d --build
```

Open http://localhost:3000 for the dashboard and http://localhost:9090/alerts for the alerts.
In the demo data one OCSP responder is failing and one signing certificate expires in 21 days.
Stop it with `docker compose down`.

## Quick start

1. Create an API key on the Security Server (API key management works from localhost by default):

   ```bash
   curl -X POST -u <user>:<password> https://localhost:4000/api/v1/api-keys \
     --data '["XROAD_SECURITYSERVER_OBSERVER"]' --header "Content-Type: application/json" -k
   ```

   Copy the `key` value from the response. It cannot be read again later.

2. Run the exporter:

   ```bash
   export XROAD_SECURITY_SERVER_URL=https://ss.example.org:4000
   export XROAD_API_KEY=<key>
   ./xroad-diagnostics-exporter --tls-ca-file=ss-admin-ui.pem
   ```

   Or with Docker:

   ```bash
   docker build -t xroad-diagnostics-exporter .
   docker run -p 9792:9792 \
     -e XROAD_SECURITY_SERVER_URL=https://ss.example.org:4000 \
     -e XROAD_API_KEY=<key> \
     xroad-diagnostics-exporter --tls-insecure-skip-verify
   ```

3. Add it to Prometheus:

   ```yaml
   scrape_configs:
     - job_name: xroad
       scrape_interval: 60s
       static_configs:
         - targets: ["exporter-host:9792"]
   ```

The admin UI usually has a self-signed TLS certificate. Download it (for example with
`openssl s_client -connect ss.example.org:4000 </dev/null | openssl x509 > ss-admin-ui.pem`) and
pass it with `--tls-ca-file`. `--tls-insecure-skip-verify` works too, but use it only for testing.

## Configuration

| Flag | Environment variable | Default | Description |
|---|---|---|---|
| `--security-server-url` | `XROAD_SECURITY_SERVER_URL` | | Admin UI address, e.g. `https://ss.example.org:4000` |
| `--api-key-file` | `XROAD_API_KEY_FILE` | | File with the API key |
| | `XROAD_API_KEY` | | API key, used when no key file is given |
| `--tls-ca-file` | `XROAD_TLS_CA_FILE` | | PEM file with the certificate or CA to trust |
| `--tls-insecure-skip-verify` | | `false` | Do not verify the TLS certificate |
| `--listen-address` | `LISTEN_ADDRESS` | `:9792` | Address for the metrics endpoint |
| `--metrics-path` | | `/metrics` | Path for the metrics endpoint |
| `--scrape-timeout` | | `10s` | Time limit for querying the Security Server |
| `--log-level` | | `info` | `debug`, `info`, `warn` or `error` |

The API key is not accepted as a flag, so it does not show up in the process list.

## Metrics

Status metrics have one series per status class (`OK`, `WAITING`, `FAIL`) with value 1 for the
current one, so alerts can use `xroad_ocsp_responder_status{status_class="FAIL"} == 1`.

| Metric | Labels | Source |
|---|---|---|
| `xroad_up` | | 1 if at least one API request succeeded |
| `xroad_scrape_endpoint_success` | `endpoint` | 1 if the request to that endpoint succeeded |
| `xroad_scrape_duration_seconds` | | |
| `xroad_globalconf_status` | `status_class` | `/diagnostics/globalconf` |
| `xroad_globalconf_last_update_timestamp_seconds` | | `/diagnostics/globalconf` |
| `xroad_globalconf_next_update_timestamp_seconds` | | `/diagnostics/globalconf` |
| `xroad_globalconf_download_status` | `url`, `status_class` | `/diagnostics/global-conf-status` |
| `xroad_ocsp_responder_status` | `ca`, `url`, `status_class` | `/diagnostics/ocsp-responders` |
| `xroad_ocsp_responder_last_update_timestamp_seconds` | `ca`, `url` | `/diagnostics/ocsp-responders` |
| `xroad_ocsp_responder_next_update_timestamp_seconds` | `ca`, `url` | `/diagnostics/ocsp-responders` |
| `xroad_timestamping_service_status` | `url`, `status_class` | `/diagnostics/timestamping-services` |
| `xroad_timestamping_service_last_update_timestamp_seconds` | `url` | `/diagnostics/timestamping-services` |
| `xroad_auth_cert_registration_status` | `status_class` | `/diagnostics/auth-cert-req-status` |
| `xroad_proxy_memory_used_bytes`, `_total_bytes`, `_max_bytes` | | `/diagnostics/proxy-memory-usage-status` |
| `xroad_proxy_memory_usage_ratio`, `_threshold_ratio` | | `/diagnostics/proxy-memory-usage-status` |
| `xroad_proxy_memory_over_threshold` | | `/diagnostics/proxy-memory-usage-status` |
| `xroad_token_status` | `token_id`, `token_name`, `token_type`, `status` | `/tokens` |
| `xroad_token_logged_in`, `xroad_token_available` | `token_id`, `token_name` | `/tokens` |
| `xroad_certificate_not_after_timestamp_seconds` | see below | `/tokens` |
| `xroad_certificate_active` | see below | `/tokens` |
| `xroad_certificate_ocsp_good` | see below | `/tokens` |
| `xroad_certificate_info` | see below, plus `status`, `ocsp_status` | `/tokens` |

Certificate labels: `token_id`, `key_usage` (`AUTHENTICATION` or `SIGNING`), `owner_id`,
`subject_cn`, `issuer_cn`, `serial`, `hash`.

Older Security Server versions do not have every endpoint. A missing endpoint only sets its
`xroad_scrape_endpoint_success` to 0; the other metrics are still exported.

## Alerts and dashboard

[`examples/alerts.yml`](examples/alerts.yml) has Prometheus alert rules for the cases listed at
the top. Adjust the thresholds to your environment.

[`examples/grafana-dashboard.json`](examples/grafana-dashboard.json) is a Grafana dashboard. Import
it in Grafana under Dashboards > New > Import. It has a Security Server selector, so one dashboard
works for several servers.

## Building

Requires Go 1.26 or newer.

```bash
go build .
go test ./...
```

## License

MIT
