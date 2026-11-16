// Package collector turns X-Road Security Server diagnostics into Prometheus
// metrics. The Security Server is queried on every scrape.
package collector

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/codestoyevsky/xroad-diagnostics-exporter/internal/xroad"
)

const namespace = "xroad"

// API is the part of the X-Road client the collector needs.
type API interface {
	GlobalConfDiagnostics(ctx context.Context) (xroad.GlobalConfDiagnostics, error)
	GlobalConfDownloadStatus(ctx context.Context) ([]xroad.GlobalConfConnectionStatus, error)
	OcspResponders(ctx context.Context) ([]xroad.CaOcspDiagnostics, error)
	TimestampingServices(ctx context.Context) ([]xroad.TimestampingServiceDiagnostics, error)
	AuthCertRegistrationStatus(ctx context.Context) (xroad.ConnectionStatus, error)
	ProxyMemoryUsage(ctx context.Context) (xroad.ProxyMemoryUsageStatus, error)
	Tokens(ctx context.Context) ([]xroad.Token, error)
}

func desc(name, help string, labels ...string) *prometheus.Desc {
	return prometheus.NewDesc(prometheus.BuildFQName(namespace, "", name), help, labels, nil)
}

var certLabels = []string{"token_id", "key_usage", "owner_id", "subject_cn", "issuer_cn", "serial", "hash"}

var (
	upDesc = desc("up",
		"1 if the Security Server management API answered at least one diagnostics request.")
	scrapeSuccessDesc = desc("scrape_endpoint_success",
		"1 if the request to the endpoint succeeded.", "endpoint")
	scrapeDurationDesc = desc("scrape_duration_seconds",
		"Time spent querying the Security Server.")

	globalConfStatusDesc = desc("globalconf_status",
		"Global configuration status, 1 for the current status class.", "status_class")
	globalConfLastUpdateDesc = desc("globalconf_last_update_timestamp_seconds",
		"Time of the last global configuration update attempt.")
	globalConfNextUpdateDesc = desc("globalconf_next_update_timestamp_seconds",
		"Time of the next scheduled global configuration update.")
	globalConfDownloadDesc = desc("globalconf_download_status",
		"Connection status to a global configuration download URL, 1 for the current status class.",
		"url", "status_class")

	ocspStatusDesc = desc("ocsp_responder_status",
		"OCSP responder status, 1 for the current status class.", "ca", "url", "status_class")
	ocspLastUpdateDesc = desc("ocsp_responder_last_update_timestamp_seconds",
		"Time of the last OCSP responder check.", "ca", "url")
	ocspNextUpdateDesc = desc("ocsp_responder_next_update_timestamp_seconds",
		"Time of the next scheduled OCSP responder check.", "ca", "url")

	tsaStatusDesc = desc("timestamping_service_status",
		"Timestamping service status, 1 for the current status class.", "url", "status_class")
	tsaLastUpdateDesc = desc("timestamping_service_last_update_timestamp_seconds",
		"Time of the last timestamping service check.", "url")

	authCertRegDesc = desc("auth_cert_registration_status",
		"Status of the connection used for authentication certificate registration requests, "+
			"1 for the current status class.", "status_class")

	proxyMemUsedDesc      = desc("proxy_memory_used_bytes", "Heap memory used by the proxy.")
	proxyMemTotalDesc     = desc("proxy_memory_total_bytes", "Heap memory allocated by the proxy.")
	proxyMemMaxDesc       = desc("proxy_memory_max_bytes", "Maximum heap memory of the proxy.")
	proxyMemUsageDesc     = desc("proxy_memory_usage_ratio", "Proxy heap usage, from 0 to 1.")
	proxyMemThresholdDesc = desc("proxy_memory_threshold_ratio",
		"Proxy heap usage alert threshold configured on the Security Server, from 0 to 1.")
	proxyMemOverDesc = desc("proxy_memory_over_threshold",
		"1 if the Security Server reports proxy heap usage over its threshold.")

	tokenStatusDesc = desc("token_status", "Token status, value is always 1.",
		"token_id", "token_name", "token_type", "status")
	tokenLoggedInDesc  = desc("token_logged_in", "1 if the token is logged in.", "token_id", "token_name")
	tokenAvailableDesc = desc("token_available", "1 if the token is available.", "token_id", "token_name")

	certNotAfterDesc = desc("certificate_not_after_timestamp_seconds",
		"Expiry time of an authentication or signing certificate.", certLabels...)
	certActiveDesc   = desc("certificate_active", "1 if the certificate is active.", certLabels...)
	certOcspGoodDesc = desc("certificate_ocsp_good",
		"1 if the last OCSP response for the certificate was good.", certLabels...)
	certInfoDesc = desc("certificate_info",
		"Certificate status and OCSP status, value is always 1.",
		append(append([]string{}, certLabels...), "status", "ocsp_status")...)
)

// Collector implements prometheus.Collector.
type Collector struct {
	api     API
	timeout time.Duration
	log     *slog.Logger
}

// New creates a collector. timeout limits the time spent on one scrape.
func New(api API, timeout time.Duration, log *slog.Logger) *Collector {
	return &Collector{api: api, timeout: timeout, log: log}
}

// Describe implements prometheus.Collector.
func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{
		upDesc, scrapeSuccessDesc, scrapeDurationDesc,
		globalConfStatusDesc, globalConfLastUpdateDesc, globalConfNextUpdateDesc, globalConfDownloadDesc,
		ocspStatusDesc, ocspLastUpdateDesc, ocspNextUpdateDesc,
		tsaStatusDesc, tsaLastUpdateDesc, authCertRegDesc,
		proxyMemUsedDesc, proxyMemTotalDesc, proxyMemMaxDesc, proxyMemUsageDesc, proxyMemThresholdDesc,
		proxyMemOverDesc,
		tokenStatusDesc, tokenLoggedInDesc, tokenAvailableDesc,
		certNotAfterDesc, certActiveDesc, certOcspGoodDesc, certInfoDesc,
	} {
		ch <- d
	}
}

type endpoint struct {
	name    string
	collect func(ctx context.Context, ch chan<- prometheus.Metric) error
}

// Collect implements prometheus.Collector.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	endpoints := []endpoint{
		{"globalconf", c.collectGlobalConf},
		{"global-conf-status", c.collectGlobalConfDownload},
		{"ocsp-responders", c.collectOcsp},
		{"timestamping-services", c.collectTimestamping},
		{"auth-cert-req-status", c.collectAuthCertReg},
		{"proxy-memory-usage-status", c.collectProxyMemory},
		{"tokens", c.collectTokens},
	}

	var (
		wg        sync.WaitGroup
		mu        sync.Mutex
		succeeded int
	)
	for _, e := range endpoints {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := e.collect(ctx, ch)
			ok := 0.0
			switch {
			case err == nil:
				ok = 1
				mu.Lock()
				succeeded++
				mu.Unlock()
			case errors.Is(err, xroad.ErrNotSupported):
				c.log.Debug("endpoint not available", "endpoint", e.name, "err", err)
			default:
				c.log.Warn("scrape failed", "endpoint", e.name, "err", err)
			}
			ch <- prometheus.MustNewConstMetric(scrapeSuccessDesc, prometheus.GaugeValue, ok, e.name)
		}()
	}
	wg.Wait()

	ch <- prometheus.MustNewConstMetric(upDesc, prometheus.GaugeValue, boolValue(succeeded > 0))
	ch <- prometheus.MustNewConstMetric(scrapeDurationDesc, prometheus.GaugeValue, time.Since(start).Seconds())
}

func (c *Collector) collectGlobalConf(ctx context.Context, ch chan<- prometheus.Metric) error {
	gc, err := c.api.GlobalConfDiagnostics(ctx)
	if err != nil {
		return err
	}
	statusSet(ch, globalConfStatusDesc, gc.StatusClass)
	timestamp(ch, globalConfLastUpdateDesc, gc.PrevUpdateAt)
	timestamp(ch, globalConfNextUpdateDesc, gc.NextUpdateAt)
	return nil
}

func (c *Collector) collectGlobalConfDownload(ctx context.Context, ch chan<- prometheus.Metric) error {
	statuses, err := c.api.GlobalConfDownloadStatus(ctx)
	if err != nil {
		return err
	}
	for _, s := range statuses {
		statusSet(ch, globalConfDownloadDesc, s.ConnectionStatus.StatusClass, s.DownloadURL)
	}
	return nil
}

func (c *Collector) collectOcsp(ctx context.Context, ch chan<- prometheus.Metric) error {
	cas, err := c.api.OcspResponders(ctx)
	if err != nil {
		return err
	}
	for _, ca := range cas {
		for _, r := range ca.OcspResponders {
			statusSet(ch, ocspStatusDesc, r.StatusClass, ca.DistinguishedName, r.URL)
			timestamp(ch, ocspLastUpdateDesc, r.PrevUpdateAt, ca.DistinguishedName, r.URL)
			timestamp(ch, ocspNextUpdateDesc, r.NextUpdateAt, ca.DistinguishedName, r.URL)
		}
	}
	return nil
}

func (c *Collector) collectTimestamping(ctx context.Context, ch chan<- prometheus.Metric) error {
	tsas, err := c.api.TimestampingServices(ctx)
	if err != nil {
		return err
	}
	for _, t := range tsas {
		statusSet(ch, tsaStatusDesc, t.StatusClass, t.URL)
		timestamp(ch, tsaLastUpdateDesc, t.PrevUpdateAt, t.URL)
	}
	return nil
}

func (c *Collector) collectAuthCertReg(ctx context.Context, ch chan<- prometheus.Metric) error {
	s, err := c.api.AuthCertRegistrationStatus(ctx)
	if err != nil {
		return err
	}
	statusSet(ch, authCertRegDesc, s.StatusClass)
	return nil
}

func (c *Collector) collectProxyMemory(ctx context.Context, ch chan<- prometheus.Metric) error {
	m, err := c.api.ProxyMemoryUsage(ctx)
	if err != nil {
		return err
	}
	gauge := func(d *prometheus.Desc, v float64) {
		ch <- prometheus.MustNewConstMetric(d, prometheus.GaugeValue, v)
	}
	gauge(proxyMemUsedDesc, m.UsedMemory)
	gauge(proxyMemTotalDesc, m.TotalMemory)
	gauge(proxyMemMaxDesc, m.MaxMemory)
	gauge(proxyMemUsageDesc, m.UsagePercent/100)
	if m.Threshold != nil {
		gauge(proxyMemThresholdDesc, *m.Threshold/100)
	}
	gauge(proxyMemOverDesc, boolValue(m.IsUsedOverThreshold))
	return nil
}

func (c *Collector) collectTokens(ctx context.Context, ch chan<- prometheus.Metric) error {
	tokens, err := c.api.Tokens(ctx)
	if err != nil {
		return err
	}
	for _, t := range tokens {
		// Not every version sends the token status (7.8.3 does not), so only
		// export it when it is there.
		if t.Status != "" {
			ch <- prometheus.MustNewConstMetric(tokenStatusDesc, prometheus.GaugeValue, 1, t.ID, t.Name, t.Type, t.Status)
		}
		ch <- prometheus.MustNewConstMetric(tokenLoggedInDesc, prometheus.GaugeValue, boolValue(t.LoggedIn), t.ID, t.Name)
		ch <- prometheus.MustNewConstMetric(tokenAvailableDesc, prometheus.GaugeValue, boolValue(t.Available), t.ID, t.Name)

		for _, k := range t.Keys {
			for _, cert := range k.Certificates {
				d := cert.CertificateDetails
				labels := []string{t.ID, k.Usage, cert.OwnerID, d.SubjectCommonName, d.IssuerCommonName, d.Serial, d.Hash}
				if !d.NotAfter.IsZero() {
					ch <- prometheus.MustNewConstMetric(certNotAfterDesc, prometheus.GaugeValue,
						float64(d.NotAfter.Unix()), labels...)
				}
				ch <- prometheus.MustNewConstMetric(certActiveDesc, prometheus.GaugeValue,
					boolValue(cert.Active), labels...)
				ch <- prometheus.MustNewConstMetric(certOcspGoodDesc, prometheus.GaugeValue,
					boolValue(cert.OcspStatus == xroad.OcspResponseGood), labels...)
				ch <- prometheus.MustNewConstMetric(certInfoDesc, prometheus.GaugeValue, 1,
					append(labels, cert.Status, cert.OcspStatus)...)
			}
		}
	}
	return nil
}

// statusSet emits one series per status class, 1 for the current one and 0
// for the others, so alerts can use `== 1` without matching on strings.
func statusSet(ch chan<- prometheus.Metric, d *prometheus.Desc, current string, labels ...string) {
	for _, s := range xroad.StatusClasses {
		ch <- prometheus.MustNewConstMetric(d, prometheus.GaugeValue, boolValue(s == current),
			append(append([]string{}, labels...), s)...)
	}
}

func timestamp(ch chan<- prometheus.Metric, d *prometheus.Desc, t *time.Time, labels ...string) {
	if t == nil || t.IsZero() {
		return
	}
	ch <- prometheus.MustNewConstMetric(d, prometheus.GaugeValue, float64(t.UnixMilli())/1000, labels...)
}

func boolValue(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
