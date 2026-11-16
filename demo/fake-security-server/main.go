// Command fake-security-server serves made-up Security Server diagnostics for
// the demo. Dates are relative to the current time, so the demo always shows
// the same situation: one failing OCSP responder and one signing certificate
// that expires in three weeks.
package main

import (
	"encoding/json"
	"log"
	"math"
	"net/http"
	"time"
)

const day = 24 * time.Hour

func main() {
	start := time.Now()
	mux := http.NewServeMux()

	handle := func(path string, body func(now time.Time) any) {
		mux.HandleFunc("GET /api/v1"+path, func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "X-Road-ApiKey token=demo" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(body(time.Now().UTC()))
		})
	}

	handle("/diagnostics/globalconf", func(now time.Time) any {
		return map[string]any{
			"status_class":        "OK",
			"prev_update_at":      now.Truncate(time.Minute),
			"next_update_at":      now.Truncate(time.Minute).Add(time.Minute),
			"last_successful_url": "http://cs.example.org/internalconf",
		}
	})
	handle("/diagnostics/global-conf-status", func(time.Time) any {
		return []any{map[string]any{
			"download_url":      "http://cs.example.org/internalconf",
			"connection_status": map[string]any{"status_class": "OK"},
		}}
	})
	handle("/diagnostics/ocsp-responders", func(now time.Time) any {
		prev := now.Truncate(20 * time.Minute)
		return []any{map[string]any{
			"distinguished_name": "CN=Example CA, O=Example, C=EE",
			"ocsp_responders": []any{
				map[string]any{"url": "http://ocsp1.example.org", "status_class": "OK",
					"prev_update_at": prev, "next_update_at": prev.Add(20 * time.Minute)},
				map[string]any{"url": "http://ocsp2.example.org", "status_class": "FAIL",
					"prev_update_at": prev, "next_update_at": prev.Add(20 * time.Minute),
					"error": map[string]any{"code": "network_error", "metadata": []string{"Connection timed out"}}},
			},
		}}
	})
	handle("/diagnostics/timestamping-services", func(now time.Time) any {
		return []any{map[string]any{
			"url": "http://tsa.example.org", "status_class": "OK", "prev_update_at": now.Truncate(time.Minute),
		}}
	})
	handle("/diagnostics/auth-cert-req-status", func(time.Time) any {
		return map[string]any{"status_class": "OK"}
	})
	handle("/diagnostics/proxy-memory-usage-status", func(now time.Time) any {
		// Slow wave between 35% and 65% so the graph moves.
		percent := 50 + 15*math.Sin(now.Sub(start).Minutes()/3)
		max := 4.0 * 1024 * 1024 * 1024
		return map[string]any{
			"max_memory": max, "total_memory": max * 0.75, "used_memory": max * percent / 100,
			"threshold": 80, "usage_percent": math.Round(percent), "is_used_over_threshold": false,
		}
	})
	handle("/tokens", func(now time.Time) any {
		cert := func(owner, cn, serial string, expiresIn time.Duration) map[string]any {
			var ownerID any
			if owner != "" {
				ownerID = owner
			}
			return map[string]any{
				"ocsp_status": "OCSP_RESPONSE_GOOD", "owner_id": ownerID, "active": true, "status": "REGISTERED",
				"certificate_details": map[string]any{
					"issuer_common_name": "Example CA", "subject_common_name": cn, "serial": serial,
					"hash":       "DEMO" + serial,
					"not_before": now.Add(expiresIn - 365*day).Truncate(day),
					"not_after":  now.Add(expiresIn).Truncate(day),
				},
			}
		}
		return []any{map[string]any{
			"id": "0", "name": "softToken-0", "type": "SOFTWARE", "status": "OK",
			"logged_in": true, "available": true, "read_only": false,
			"keys": []any{
				map[string]any{"id": "auth", "usage": "AUTHENTICATION", "certificates": []any{
					cert("", "ss1.example.org", "1001", 240*day),
				}},
				map[string]any{"id": "sign1", "usage": "SIGNING", "certificates": []any{
					cert("DEMO:GOV:1234", "Ministry of Examples", "1002", 21*day),
				}},
				map[string]any{"id": "sign2", "usage": "SIGNING", "certificates": []any{
					cert("DEMO:COM:5678", "Example Company", "1003", 310*day),
				}},
			},
		}}
	})

	log.Println("fake Security Server listening on :8080")
	srv := &http.Server{Addr: ":8080", Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	log.Fatal(srv.ListenAndServe())
}
