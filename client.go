package trafficorchestrator

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"
	"time"
)

const Version = "2.0.0"

// Client is the Traffic Orchestrator API client.
type Client struct {
	BaseURL    string
	ApiKey     string
	HTTPClient *http.Client
	Retries    int
}

type ValidationRequest struct {
	Token  string `json:"token"`
	Domain string `json:"domain"`
}

type ValidationResponse struct {
	Valid     bool     `json:"valid"`
	Message   string   `json:"message,omitempty"`
	Error     string   `json:"error,omitempty"`
	Reason    string   `json:"reason,omitempty"`
	Plan      string   `json:"plan,omitempty"`
	Domains   []string `json:"domains,omitempty"`
	ExpiresAt string   `json:"expiresAt,omitempty"`
}

type License struct {
	LicenseID  string   `json:"license_id"`
	LicenseKey string   `json:"license_key"`
	Status     string   `json:"status"`
	PlanID     string   `json:"plan_id"`
	Domains    []string `json:"domains"`
	CreatedAt  string   `json:"created_at"`
	ExpiresAt  string   `json:"expires_at"`
}

type LicenseListResponse struct {
	Licenses []License `json:"licenses"`
}

type CreateLicenseRequest struct {
	AppName string `json:"appName"`
	Domain  string `json:"domain,omitempty"`
	PlanID  string `json:"planId,omitempty"`
}

type UsageStats struct {
	ValidationsToday int `json:"validationsToday"`
	ValidationsMonth int `json:"validationsMonth"`
	MonthlyLimit     int `json:"monthlyLimit"`
	ActiveLicenses   int `json:"activeLicenses"`
	ActiveDomains    int `json:"activeDomains"`
}

type HealthResponse struct {
	Status  string `json:"status"`
	Version string `json:"version"`
}

// NewClient creates a new Traffic Orchestrator client.
func NewClient(baseURL string) *Client {
	if baseURL == "" {
		baseURL = "https://api.trafficorchestrator.com/api/v1"
	}
	return &Client{
		BaseURL: strings.TrimRight(baseURL, "/"),
		HTTPClient: &http.Client{
			Timeout: time.Second * 10,
		},
		Retries: 2,
	}
}

// NewAuthenticatedClient creates a client with an API key for management endpoints.
func NewAuthenticatedClient(baseURL, apiKey string) *Client {
	c := NewClient(baseURL)
	c.ApiKey = apiKey
	return c
}


// RequireApiKey returns a developer-friendly error directing to the signup page.
func (c *Client) RequireApiKey() error {
	if c.ApiKey == "" {
		return errors.New("TrafficOrchestrator Auth Error: Missing API Key. To generate your free API Key in 60 seconds, visit: https://trafficorchestrator.com/dashboard/keys")
	}
	return nil
}
// ── Core: License Validation ────────────────────────────────────────────────

// ValidateLicense validates a license key against the API server.
func (c *Client) ValidateLicense(token, domain string) (*ValidationResponse, error) {
	body := ValidationRequest{Token: token, Domain: domain}
	var result ValidationResponse
	if err := c.doRequest("POST", "/validate", body, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// VerifyOffline verifies a license offline using Ed25519 public key verification.
func (c *Client) VerifyOffline(token string, publicKeyBase64 string, domain string) (*ValidationResponse, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid token format")
	}

	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("failed to decode payload")
	}

	var claims struct {
		Exp int64    `json:"exp"`
		Dom []string `json:"dom"`
	}
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return nil, errors.New("failed to parse claims")
	}

	if time.Now().Unix() > claims.Exp {
		return &ValidationResponse{Valid: false, Reason: "TOKEN_EXPIRED"}, nil
	}

	if domain != "" {
		match := false
		for _, d := range claims.Dom {
			if strings.Contains(domain, d) {
				match = true
				break
			}
		}
		if !match {
			return &ValidationResponse{Valid: false, Reason: "DOMAIN_MISMATCH"}, nil
		}
	}

	pubKey, err := base64.StdEncoding.DecodeString(publicKeyBase64)
	if err != nil {
		return nil, errors.New("invalid public key format")
	}

	if len(pubKey) != 32 {
		return nil, errors.New("invalid ed25519 public key length")
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, errors.New("invalid signature format")
	}

	msg := []byte(parts[0] + "." + parts[1])
	if !ed25519.Verify(ed25519.PublicKey(pubKey), msg, sig) {
		return &ValidationResponse{Valid: false, Reason: "INVALID_SIGNATURE"}, nil
	}

	return &ValidationResponse{Valid: true}, nil
}

// ── License Management (requires API key) ───────────────────────────────────

// ListLicenses returns all licenses for the authenticated user.
func (c *Client) ListLicenses() ([]License, error) {
	if err := c.RequireApiKey(); err != nil {
		return nil, err
	}
	var result LicenseListResponse
	if err := c.doRequest("GET", "/portal/licenses", nil, &result); err != nil {
		return nil, err
	}
	return result.Licenses, nil
}

// CreateLicense creates a new license.
func (c *Client) CreateLicense(appName, domain, planID string) (*License, error) {
	if err := c.RequireApiKey(); err != nil {
		return nil, err
	}
	body := CreateLicenseRequest{AppName: appName, Domain: domain, PlanID: planID}
	var result License
	if err := c.doRequest("POST", "/portal/licenses", body, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// RotateResponse is returned by RotateLicense.
type RotateResponse struct {
	Success           bool    `json:"success"`
	PreviousLicenseID string  `json:"previousLicenseId"`
	NewLicense        License `json:"newLicense,omitempty"`
}

// DomainResponse is returned by AddDomain.
type DomainResponse struct {
	DomainID string `json:"domainId"`
	Domain   string `json:"domain"`
}

// RotateLicense rotates a license key, revoking the old key and generating a new one.
func (c *Client) RotateLicense(licenseID string) (*RotateResponse, error) {
	var result RotateResponse
	if err := c.doRequest("POST", "/portal/licenses/"+licenseID+"/rotate", nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// AddDomain adds a domain to a license.
func (c *Client) AddDomain(licenseID, domain string) (*DomainResponse, error) {
	body := map[string]string{"domain": domain}
	var result DomainResponse
	if err := c.doRequest("POST", "/portal/licenses/"+licenseID+"/domains", body, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// RemoveDomain removes a domain from a license.
func (c *Client) RemoveDomain(licenseID, domain string) error {
	body := map[string]string{"domain": domain}
	var result map[string]interface{}
	return c.doRequest("DELETE", "/portal/licenses/"+licenseID+"/domains", body, &result)
}

// DeleteLicense deletes (revokes) a license.
func (c *Client) DeleteLicense(licenseID string) error {
	var result map[string]interface{}
	return c.doRequest("DELETE", "/portal/licenses/"+licenseID, nil, &result)
}

// ── Usage & Analytics ───────────────────────────────────────────────────────

// GetUsage returns current usage statistics.
func (c *Client) GetUsage() (*UsageStats, error) {
	var result UsageStats
	if err := c.doRequest("GET", "/portal/stats", nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ── Health ──────────────────────────────────────────────────────────────────

// HealthCheck checks the API health status.
func (c *Client) HealthCheck() (*HealthResponse, error) {
	var result HealthResponse
	if err := c.doRequest("GET", "/health", nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ── Analytics & SLA ────────────────────────────────────────────────────────

// GetAnalytics returns detailed analytics for the specified number of days.
func (c *Client) GetAnalytics(days int) (map[string]interface{}, error) {
	if err := c.RequireApiKey(); err != nil {
		return nil, err
	}
	var result map[string]interface{}
	if err := c.doRequest("GET", fmt.Sprintf("/portal/analytics?days=%d", days), nil, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// GetDashboard returns a full dashboard overview.
func (c *Client) GetDashboard() (map[string]interface{}, error) {
	var result map[string]interface{}
	if err := c.doRequest("GET", "/portal/dashboard", nil, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// GetSLA returns SLA compliance data for the specified number of days.
func (c *Client) GetSLA(days int) (map[string]interface{}, error) {
	var result map[string]interface{}
	if err := c.doRequest("GET", fmt.Sprintf("/portal/sla?days=%d", days), nil, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// ── Audit & Webhooks ───────────────────────────────────────────────────────

// ExportAuditLogs exports audit logs in the specified format (json/csv).
func (c *Client) ExportAuditLogs(format string, since string) (map[string]interface{}, error) {
	path := fmt.Sprintf("/portal/audit-logs/export?format=%s", format)
	if since != "" {
		path += "&since=" + since
	}
	var result map[string]interface{}
	if err := c.doRequest("GET", path, nil, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// GetWebhookDeliveries returns webhook delivery history.
func (c *Client) GetWebhookDeliveries(limit int, status string) (map[string]interface{}, error) {
	path := fmt.Sprintf("/portal/webhooks/deliveries?limit=%d", limit)
	if status != "" {
		path += "&status=" + status
	}
	var result map[string]interface{}
	if err := c.doRequest("GET", path, nil, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// ── Batch Operations ───────────────────────────────────────────────────────

// BatchLicenseRequest is the request body for BatchLicenseOperation.
type BatchLicenseRequest struct {
	Action     string   `json:"action"`
	LicenseIDs []string `json:"licenseIds"`
	Days       int      `json:"days,omitempty"`
}

// BatchLicenseOperation performs a batch operation (suspend/activate/extend) on multiple licenses.
func (c *Client) BatchLicenseOperation(action string, licenseIDs []string, days int) (map[string]interface{}, error) {
	body := BatchLicenseRequest{Action: action, LicenseIDs: licenseIDs}
	if days > 0 {
		body.Days = days
	}
	var result map[string]interface{}
	if err := c.doRequest("POST", "/portal/licenses/batch", body, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// ── IP Allowlist ───────────────────────────────────────────────────────────

// GetIPAllowlist returns the IP allowlist for a license.
func (c *Client) GetIPAllowlist(licenseID string) (map[string]interface{}, error) {
	var result map[string]interface{}
	if err := c.doRequest("GET", "/portal/licenses/"+licenseID+"/ip-allowlist", nil, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// SetIPAllowlist sets the IP allowlist for a license.
func (c *Client) SetIPAllowlist(licenseID string, allowedIPs []string) (map[string]interface{}, error) {
	body := map[string]interface{}{"allowedIps": allowedIPs}
	var result map[string]interface{}
	if err := c.doRequest("PUT", "/portal/licenses/"+licenseID+"/ip-allowlist", body, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// ── Internal ────────────────────────────────────────────────────────────────

func (c *Client) doRequest(method, path string, body interface{}, target interface{}) error {
	url := c.BaseURL + path
	var lastErr error

	for attempt := 0; attempt <= c.Retries; attempt++ {
		var reqBody io.Reader
		if body != nil {
			data, err := json.Marshal(body)
			if err != nil {
				return err
			}
			reqBody = bytes.NewBuffer(data)
		}

		req, err := http.NewRequest(method, url, reqBody)
		if err != nil {
			return err
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "TrafficOrchestrator-Go/"+Version)
		if c.ApiKey != "" {
			req.Header.Set("Authorization", "Bearer "+c.ApiKey)
		}

		resp, err := c.HTTPClient.Do(req)
		if err != nil {
			lastErr = err
			if attempt < c.Retries {
				time.Sleep(time.Duration(math.Min(float64(time.Second)*math.Pow(2, float64(attempt)), float64(5*time.Second))))
			}
			continue
		}

		defer resp.Body.Close()
		respBody, _ := io.ReadAll(resp.Body)

		if resp.StatusCode >= 400 && resp.StatusCode < 500 {
			// Special case: /validate returns 403 with JSON for invalid tokens
			if resp.StatusCode == 403 && strings.Contains(url, "/validate") {
				return json.Unmarshal(respBody, target)
			}
			return fmt.Errorf("API error (HTTP %d): %s", resp.StatusCode, string(respBody))
		}

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return json.Unmarshal(respBody, target)
		}

		lastErr = fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
		if attempt < c.Retries {
			time.Sleep(time.Duration(math.Min(float64(time.Second)*math.Pow(2, float64(attempt)), float64(5*time.Second))))
		}
	}

	if lastErr != nil {
		return lastErr
	}
	return errors.New("request failed after retries")
}
