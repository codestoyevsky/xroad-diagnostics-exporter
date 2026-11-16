// Command xroad-diagnostics-exporter exposes X-Road Security Server
// diagnostics (global configuration, OCSP, timestamping, certificates) as
// Prometheus metrics.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/codestoyevsky/xroad-diagnostics-exporter/internal/collector"
	"github.com/codestoyevsky/xroad-diagnostics-exporter/internal/xroad"
)

var version = "dev"

func main() {
	var (
		listenAddr = flag.String("listen-address", envOr("LISTEN_ADDRESS", ":9792"),
			"Address to expose metrics on.")
		metricsPath = flag.String("metrics-path", "/metrics", "Path to expose metrics on.")
		ssURL       = flag.String("security-server-url", os.Getenv("XROAD_SECURITY_SERVER_URL"),
			"Security Server admin UI address, for example https://ss.example.org:4000.")
		apiKeyFile = flag.String("api-key-file", os.Getenv("XROAD_API_KEY_FILE"),
			"File with the API key. If not set, the XROAD_API_KEY environment variable is used.")
		caFile = flag.String("tls-ca-file", os.Getenv("XROAD_TLS_CA_FILE"),
			"PEM file with the CA or certificate to trust for the Security Server admin UI.")
		insecure = flag.Bool("tls-insecure-skip-verify", false,
			"Do not verify the Security Server TLS certificate. Only for testing.")
		timeout = flag.Duration("scrape-timeout", 10*time.Second,
			"Timeout for querying the Security Server on one scrape.")
		logLevel    = flag.String("log-level", "info", "Log level: debug, info, warn or error.")
		showVersion = flag.Bool("version", false, "Print version and exit.")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: parseLevel(*logLevel)}))

	if err := run(log, *listenAddr, *metricsPath, *ssURL, *apiKeyFile, *caFile, *insecure, *timeout); err != nil {
		log.Error("exiting", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger, listenAddr, metricsPath, ssURL, apiKeyFile, caFile string,
	insecure bool, timeout time.Duration) error {
	if ssURL == "" {
		return errors.New("--security-server-url or XROAD_SECURITY_SERVER_URL is required")
	}
	apiKey, err := readAPIKey(apiKeyFile)
	if err != nil {
		return err
	}
	tlsConfig, err := buildTLSConfig(caFile, insecure)
	if err != nil {
		return err
	}
	if insecure {
		log.Warn("TLS certificate verification is disabled")
	}

	httpClient := &http.Client{
		Timeout:   timeout,
		Transport: &http.Transport{TLSClientConfig: tlsConfig, MaxIdleConnsPerHost: 8},
	}
	api := xroad.NewClient(ssURL, apiKey, httpClient)

	reg := prometheus.NewRegistry()
	reg.MustRegister(
		collector.New(api, timeout, log),
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	mux := http.NewServeMux()
	mux.Handle(metricsPath, promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprintf(w, "<html><body><h1>X-Road diagnostics exporter</h1><a href=%q>Metrics</a></body></html>",
			metricsPath)
	})

	log.Info("starting", "version", version, "listen", listenAddr, "security_server", ssURL)
	srv := &http.Server{Addr: listenAddr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	return srv.ListenAndServe()
}

func readAPIKey(file string) (string, error) {
	if file != "" {
		b, err := os.ReadFile(file)
		if err != nil {
			return "", fmt.Errorf("read API key file: %w", err)
		}
		return strings.TrimSpace(string(b)), nil
	}
	if k := os.Getenv("XROAD_API_KEY"); k != "" {
		return k, nil
	}
	return "", errors.New("API key is required: set --api-key-file or XROAD_API_KEY")
}

func buildTLSConfig(caFile string, insecure bool) (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: insecure} //nolint:gosec // opt-in flag
	if caFile == "" {
		return cfg, nil
	}
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read CA file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no certificates found in %s", caFile)
	}
	cfg.RootCAs = pool
	return cfg, nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func parseLevel(s string) slog.Level {
	var l slog.Level
	if err := l.UnmarshalText([]byte(s)); err != nil {
		return slog.LevelInfo
	}
	return l
}
