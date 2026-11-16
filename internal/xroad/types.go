package xroad

import "time"

// Status classes used by all diagnostics endpoints.
const (
	StatusOK      = "OK"
	StatusWaiting = "WAITING"
	StatusFail    = "FAIL"
)

// StatusClasses lists every diagnostics status class.
var StatusClasses = []string{StatusOK, StatusWaiting, StatusFail}

// CodeWithDetails is the error object the API attaches to a failed check.
type CodeWithDetails struct {
	Code     string   `json:"code"`
	Metadata []string `json:"metadata"`
}

type GlobalConfDiagnostics struct {
	StatusClass       string           `json:"status_class"`
	PrevUpdateAt      *time.Time       `json:"prev_update_at"`
	NextUpdateAt      *time.Time       `json:"next_update_at"`
	LastSuccessfulURL string           `json:"last_successful_url"`
	Error             *CodeWithDetails `json:"error"`
}

type ConnectionStatus struct {
	StatusClass string           `json:"status_class"`
	Error       *CodeWithDetails `json:"error"`
}

type GlobalConfConnectionStatus struct {
	DownloadURL      string           `json:"download_url"`
	ConnectionStatus ConnectionStatus `json:"connection_status"`
}

type CaOcspDiagnostics struct {
	DistinguishedName string                     `json:"distinguished_name"`
	OcspResponders    []OcspResponderDiagnostics `json:"ocsp_responders"`
}

type OcspResponderDiagnostics struct {
	URL          string           `json:"url"`
	StatusClass  string           `json:"status_class"`
	PrevUpdateAt *time.Time       `json:"prev_update_at"`
	NextUpdateAt *time.Time       `json:"next_update_at"`
	Error        *CodeWithDetails `json:"error"`
}

type TimestampingServiceDiagnostics struct {
	URL          string           `json:"url"`
	StatusClass  string           `json:"status_class"`
	PrevUpdateAt *time.Time       `json:"prev_update_at"`
	Error        *CodeWithDetails `json:"error"`
}

type ProxyMemoryUsageStatus struct {
	MaxMemory           float64  `json:"max_memory"`
	TotalMemory         float64  `json:"total_memory"`
	UsedMemory          float64  `json:"used_memory"`
	Threshold           *float64 `json:"threshold"`
	UsagePercent        float64  `json:"usage_percent"`
	IsUsedOverThreshold bool     `json:"is_used_over_threshold"`
}

type Token struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Type      string `json:"type"`
	Status    string `json:"status"`
	LoggedIn  bool   `json:"logged_in"`
	Available bool   `json:"available"`
	ReadOnly  bool   `json:"read_only"`
	Keys      []Key  `json:"keys"`
}

// Key usage values.
const (
	KeyUsageAuthentication = "AUTHENTICATION"
	KeyUsageSigning        = "SIGNING"
)

type Key struct {
	ID           string             `json:"id"`
	Name         string             `json:"name"`
	Label        string             `json:"label"`
	Usage        string             `json:"usage"`
	Certificates []TokenCertificate `json:"certificates"`
}

// OCSP status value for a good certificate.
const OcspResponseGood = "OCSP_RESPONSE_GOOD"

type TokenCertificate struct {
	OcspStatus         string             `json:"ocsp_status"`
	OwnerID            string             `json:"owner_id"`
	Active             bool               `json:"active"`
	Status             string             `json:"status"`
	CertificateDetails CertificateDetails `json:"certificate_details"`
}

type CertificateDetails struct {
	IssuerCommonName  string    `json:"issuer_common_name"`
	SubjectCommonName string    `json:"subject_common_name"`
	NotBefore         time.Time `json:"not_before"`
	NotAfter          time.Time `json:"not_after"`
	Serial            string    `json:"serial"`
	Hash              string    `json:"hash"`
}
