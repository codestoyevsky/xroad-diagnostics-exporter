package collector

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/codestoyevsky/xroad-diagnostics-exporter/internal/xroad"
)

const testAPIKey = "test-key"

// fakeSecurityServer serves the files in testdata. A path without a file
// returns 404, like an older Security Server without that endpoint.
func fakeSecurityServer(t *testing.T, files map[string]string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "X-Road-ApiKey token="+testAPIKey {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		name, ok := files[strings.TrimPrefix(r.URL.Path, "/api/v1")]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		body, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			t.Errorf("read fixture: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
}

var allEndpoints = map[string]string{
	"/diagnostics/globalconf":                "globalconf.json",
	"/diagnostics/global-conf-status":        "global-conf-status.json",
	"/diagnostics/ocsp-responders":           "ocsp-responders.json",
	"/diagnostics/timestamping-services":     "timestamping-services.json",
	"/diagnostics/auth-cert-req-status":      "auth-cert-req-status.json",
	"/diagnostics/proxy-memory-usage-status": "proxy-memory-usage-status.json",
	"/tokens":                                "tokens.json",
}

func newCollector(url, apiKey string) *Collector {
	api := xroad.NewClient(url, apiKey, http.DefaultClient)
	return New(api, 5*time.Second, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func TestCollectAllEndpoints(t *testing.T) {
	srv := fakeSecurityServer(t, allEndpoints)
	defer srv.Close()

	c := newCollector(srv.URL, testAPIKey)

	expected := `
# HELP xroad_up 1 if the Security Server management API answered at least one diagnostics request.
# TYPE xroad_up gauge
xroad_up 1
# HELP xroad_globalconf_status Global configuration status, 1 for the current status class.
# TYPE xroad_globalconf_status gauge
xroad_globalconf_status{status_class="FAIL"} 0
xroad_globalconf_status{status_class="OK"} 1
xroad_globalconf_status{status_class="WAITING"} 0
# HELP xroad_globalconf_next_update_timestamp_seconds Time of the next scheduled global configuration update.
# TYPE xroad_globalconf_next_update_timestamp_seconds gauge
xroad_globalconf_next_update_timestamp_seconds 1.763287260e+09
# HELP xroad_ocsp_responder_status OCSP responder status, 1 for the current status class.
# TYPE xroad_ocsp_responder_status gauge
xroad_ocsp_responder_status{ca="CN=Test CA, O=Example",status_class="FAIL",url="http://ocsp.example.org"} 1
xroad_ocsp_responder_status{ca="CN=Test CA, O=Example",status_class="OK",url="http://ocsp.example.org"} 0
xroad_ocsp_responder_status{ca="CN=Test CA, O=Example",status_class="WAITING",url="http://ocsp.example.org"} 0
xroad_ocsp_responder_status{ca="CN=Test CA, O=Example",status_class="FAIL",url="http://ocsp2.example.org"} 0
xroad_ocsp_responder_status{ca="CN=Test CA, O=Example",status_class="OK",url="http://ocsp2.example.org"} 1
xroad_ocsp_responder_status{ca="CN=Test CA, O=Example",status_class="WAITING",url="http://ocsp2.example.org"} 0
# HELP xroad_timestamping_service_status Timestamping service status, 1 for the current status class.
# TYPE xroad_timestamping_service_status gauge
xroad_timestamping_service_status{status_class="FAIL",url="http://tsa.example.org"} 0
xroad_timestamping_service_status{status_class="OK",url="http://tsa.example.org"} 0
xroad_timestamping_service_status{status_class="WAITING",url="http://tsa.example.org"} 1
# HELP xroad_proxy_memory_usage_ratio Proxy heap usage, from 0 to 1.
# TYPE xroad_proxy_memory_usage_ratio gauge
xroad_proxy_memory_usage_ratio 0.42
# HELP xroad_proxy_memory_threshold_ratio Proxy heap usage alert threshold configured on the Security Server, from 0 to 1.
# TYPE xroad_proxy_memory_threshold_ratio gauge
xroad_proxy_memory_threshold_ratio 0.8
# HELP xroad_token_logged_in 1 if the token is logged in.
# TYPE xroad_token_logged_in gauge
xroad_token_logged_in{token_id="0",token_name="softToken-0"} 1
# HELP xroad_certificate_not_after_timestamp_seconds Expiry time of an authentication or signing certificate.
# TYPE xroad_certificate_not_after_timestamp_seconds gauge
xroad_certificate_not_after_timestamp_seconds{hash="AUTHHASH",issuer_cn="Test CA",key_usage="AUTHENTICATION",owner_id="",serial="10",subject_cn="ss1.example.org",token_id="0"} 1.7804448e+09
xroad_certificate_not_after_timestamp_seconds{hash="SIGNHASH",issuer_cn="Test CA",key_usage="SIGNING",owner_id="DEV:COM:1234",serial="11",subject_cn="Example Org",token_id="0"} 1.7678304e+09
# HELP xroad_certificate_ocsp_good 1 if the last OCSP response for the certificate was good.
# TYPE xroad_certificate_ocsp_good gauge
xroad_certificate_ocsp_good{hash="AUTHHASH",issuer_cn="Test CA",key_usage="AUTHENTICATION",owner_id="",serial="10",subject_cn="ss1.example.org",token_id="0"} 1
xroad_certificate_ocsp_good{hash="SIGNHASH",issuer_cn="Test CA",key_usage="SIGNING",owner_id="DEV:COM:1234",serial="11",subject_cn="Example Org",token_id="0"} 0
`
	names := []string{
		"xroad_up", "xroad_globalconf_status", "xroad_globalconf_next_update_timestamp_seconds",
		"xroad_ocsp_responder_status", "xroad_timestamping_service_status",
		"xroad_proxy_memory_usage_ratio", "xroad_proxy_memory_threshold_ratio",
		"xroad_token_logged_in", "xroad_certificate_not_after_timestamp_seconds", "xroad_certificate_ocsp_good",
	}
	if err := testutil.CollectAndCompare(c, strings.NewReader(expected), names...); err != nil {
		t.Fatal(err)
	}

	// Every endpoint succeeded.
	if got := testutil.CollectAndCount(c, "xroad_scrape_endpoint_success"); got != len(allEndpoints) {
		t.Fatalf("scrape_endpoint_success series: got %d, want %d", got, len(allEndpoints))
	}

	// The output must pass the Prometheus linter.
	problems, err := testutil.CollectAndLint(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range problems {
		t.Errorf("lint: %s: %s", p.Metric, p.Text)
	}
}

func TestMissingEndpointDoesNotBreakOthers(t *testing.T) {
	files := map[string]string{
		"/diagnostics/globalconf": "globalconf.json",
		"/tokens":                 "tokens.json",
	}
	srv := fakeSecurityServer(t, files)
	defer srv.Close()

	c := newCollector(srv.URL, testAPIKey)

	expected := `
# HELP xroad_up 1 if the Security Server management API answered at least one diagnostics request.
# TYPE xroad_up gauge
xroad_up 1
# HELP xroad_scrape_endpoint_success 1 if the request to the endpoint succeeded.
# TYPE xroad_scrape_endpoint_success gauge
xroad_scrape_endpoint_success{endpoint="auth-cert-req-status"} 0
xroad_scrape_endpoint_success{endpoint="global-conf-status"} 0
xroad_scrape_endpoint_success{endpoint="globalconf"} 1
xroad_scrape_endpoint_success{endpoint="ocsp-responders"} 0
xroad_scrape_endpoint_success{endpoint="proxy-memory-usage-status"} 0
xroad_scrape_endpoint_success{endpoint="timestamping-services"} 0
xroad_scrape_endpoint_success{endpoint="tokens"} 1
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(expected),
		"xroad_up", "xroad_scrape_endpoint_success"); err != nil {
		t.Fatal(err)
	}
}

func TestWrongAPIKey(t *testing.T) {
	srv := fakeSecurityServer(t, allEndpoints)
	defer srv.Close()

	c := newCollector(srv.URL, "wrong-key")

	expected := `
# HELP xroad_up 1 if the Security Server management API answered at least one diagnostics request.
# TYPE xroad_up gauge
xroad_up 0
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(expected), "xroad_up"); err != nil {
		t.Fatal(err)
	}
}
