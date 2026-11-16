// Package xroad is a small read-only client for the X-Road Security Server
// management REST API (the endpoints behind the "Diagnostics" and "Keys and
// certificates" pages of the admin UI).
package xroad

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// ErrNotSupported is returned when the Security Server does not have the
// endpoint, which happens with older versions.
var ErrNotSupported = errors.New("endpoint not supported by this Security Server version")

// Client calls the Security Server management REST API.
type Client struct {
	baseURL string
	apiKey  string
	http    *http.Client
}

// NewClient creates a client. baseURL is the admin UI address, for example
// https://ss.example.org:4000. The /api/v1 prefix is added automatically.
func NewClient(baseURL, apiKey string, httpClient *http.Client) *Client {
	return &Client{
		baseURL: strings.TrimSuffix(baseURL, "/") + "/api/v1",
		apiKey:  apiKey,
		http:    httpClient,
	}
}

// APIError is a non-2xx response from the API.
type APIError struct {
	Path       string
	StatusCode int
	Body       string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("GET %s: HTTP %d: %s", e.Path, e.StatusCode, e.Body)
}

func (c *Client) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "X-Road-ApiKey token="+c.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("GET %s: %w", path, ErrNotSupported)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return &APIError{Path: path, StatusCode: resp.StatusCode, Body: strings.TrimSpace(string(body))}
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("GET %s: decode response: %w", path, err)
	}
	return nil
}

// GlobalConfDiagnostics is GET /diagnostics/globalconf.
func (c *Client) GlobalConfDiagnostics(ctx context.Context) (GlobalConfDiagnostics, error) {
	var out GlobalConfDiagnostics
	err := c.get(ctx, "/diagnostics/globalconf", &out)
	return out, err
}

// GlobalConfDownloadStatus is GET /diagnostics/global-conf-status.
func (c *Client) GlobalConfDownloadStatus(ctx context.Context) ([]GlobalConfConnectionStatus, error) {
	var out []GlobalConfConnectionStatus
	err := c.get(ctx, "/diagnostics/global-conf-status", &out)
	return out, err
}

// OcspResponders is GET /diagnostics/ocsp-responders.
func (c *Client) OcspResponders(ctx context.Context) ([]CaOcspDiagnostics, error) {
	var out []CaOcspDiagnostics
	err := c.get(ctx, "/diagnostics/ocsp-responders", &out)
	return out, err
}

// TimestampingServices is GET /diagnostics/timestamping-services.
func (c *Client) TimestampingServices(ctx context.Context) ([]TimestampingServiceDiagnostics, error) {
	var out []TimestampingServiceDiagnostics
	err := c.get(ctx, "/diagnostics/timestamping-services", &out)
	return out, err
}

// AuthCertRegistrationStatus is GET /diagnostics/auth-cert-req-status.
func (c *Client) AuthCertRegistrationStatus(ctx context.Context) (ConnectionStatus, error) {
	var out ConnectionStatus
	err := c.get(ctx, "/diagnostics/auth-cert-req-status", &out)
	return out, err
}

// ProxyMemoryUsage is GET /diagnostics/proxy-memory-usage-status.
func (c *Client) ProxyMemoryUsage(ctx context.Context) (ProxyMemoryUsageStatus, error) {
	var out ProxyMemoryUsageStatus
	err := c.get(ctx, "/diagnostics/proxy-memory-usage-status", &out)
	return out, err
}

// Tokens is GET /tokens. It includes the keys and certificates of each token.
func (c *Client) Tokens(ctx context.Context) ([]Token, error) {
	var out []Token
	err := c.get(ctx, "/tokens", &out)
	return out, err
}
