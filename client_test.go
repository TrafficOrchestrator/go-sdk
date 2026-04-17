package trafficorchestrator

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// ═══════════════════════════════════════════════════════════════════════════════
// NewClient
// ═══════════════════════════════════════════════════════════════════════════════

func TestNewClient_DefaultBaseURL(t *testing.T) {
	c := NewClient("")
	if c.BaseURL != "https://api.trafficorchestrator.com/api/v1" {
		t.Errorf("expected production default, got %s", c.BaseURL)
	}
}

func TestNewClient_CustomBaseURL(t *testing.T) {
	c := NewClient("https://custom.example.com")
	if c.BaseURL != "https://custom.example.com" {
		t.Errorf("expected custom URL, got %s", c.BaseURL)
	}
}

func TestNewClient_TimeoutSet(t *testing.T) {
	c := NewClient("")
	if c.HTTPClient.Timeout != 10*time.Second {
		t.Errorf("expected 10s timeout, got %v", c.HTTPClient.Timeout)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// ValidateLicense
// ═══════════════════════════════════════════════════════════════════════════════

func TestValidateLicense_ValidResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/validate" {
			t.Errorf("expected /validate, got %s", r.URL.Path)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("expected application/json content type")
		}

		var req ValidationRequest
		json.NewDecoder(r.Body).Decode(&req)
		if req.Token == "" {
			t.Error("expected token in request body")
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ValidationResponse{Valid: true})
	}))
	defer server.Close()

	c := NewClient(server.URL)
	resp, err := c.ValidateLicense("test-token", "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Valid {
		t.Error("expected valid=true")
	}
}

func TestValidateLicense_InvalidResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(ValidationResponse{Valid: false, Reason: "INVALID_TOKEN"})
	}))
	defer server.Close()

	c := NewClient(server.URL)
	resp, err := c.ValidateLicense("bad-token", "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Valid {
		t.Error("expected valid=false")
	}
	if resp.Reason != "INVALID_TOKEN" {
		t.Errorf("expected INVALID_TOKEN reason, got %s", resp.Reason)
	}
}

func TestValidateLicense_UnexpectedStatusCode(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	c := NewClient(server.URL)
	_, err := c.ValidateLicense("token", "domain.com")
	if err == nil {
		t.Error("expected error for unexpected status code")
	}
}

func TestValidateLicense_NetworkError(t *testing.T) {
	c := NewClient("http://localhost:1") // Unreachable port
	_, err := c.ValidateLicense("token", "domain.com")
	if err == nil {
		t.Error("expected network error")
	}
}

func TestValidateLicense_SendsCorrectPayload(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req ValidationRequest
		json.NewDecoder(r.Body).Decode(&req)
		if req.Token != "my-token" {
			t.Errorf("expected token 'my-token', got '%s'", req.Token)
		}
		if req.Domain != "my-domain.com" {
			t.Errorf("expected domain 'my-domain.com', got '%s'", req.Domain)
		}
		json.NewEncoder(w).Encode(ValidationResponse{Valid: true})
	}))
	defer server.Close()

	c := NewClient(server.URL)
	c.ValidateLicense("my-token", "my-domain.com")
}

// ═══════════════════════════════════════════════════════════════════════════════
// VerifyOffline
// ═══════════════════════════════════════════════════════════════════════════════

func makeTestToken(t *testing.T, claims map[string]interface{}, privKey ed25519.PrivateKey) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","typ":"JWT"}`))
	payloadJSON, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(payloadJSON)
	msg := header + "." + payload
	sig := ed25519.Sign(privKey, []byte(msg))
	return msg + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func TestVerifyOffline_InvalidTokenFormat(t *testing.T) {
	c := NewClient("")
	_, err := c.VerifyOffline("not.a.valid.token.too.many.parts", "key", "")
	if err == nil || err.Error() != "invalid token format" {
		t.Errorf("expected 'invalid token format', got %v", err)
	}

	_, err = c.VerifyOffline("only-one-part", "key", "")
	if err == nil {
		t.Error("expected error for single-part token")
	}
}

func TestVerifyOffline_ExpiredToken(t *testing.T) {
	pubKey, privKey, _ := ed25519.GenerateKey(nil)
	pubKeyB64 := base64.StdEncoding.EncodeToString(pubKey)

	token := makeTestToken(t, map[string]interface{}{
		"exp": time.Now().Add(-1 * time.Hour).Unix(), // Expired 1 hour ago
		"dom": []string{"example.com"},
	}, privKey)

	c := NewClient("")
	resp, err := c.VerifyOffline(token, pubKeyB64, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Valid {
		t.Error("expected valid=false for expired token")
	}
	if resp.Reason != "TOKEN_EXPIRED" {
		t.Errorf("expected TOKEN_EXPIRED, got %s", resp.Reason)
	}
}

func TestVerifyOffline_DomainMismatch(t *testing.T) {
	pubKey, privKey, _ := ed25519.GenerateKey(nil)
	pubKeyB64 := base64.StdEncoding.EncodeToString(pubKey)

	token := makeTestToken(t, map[string]interface{}{
		"exp": time.Now().Add(1 * time.Hour).Unix(),
		"dom": []string{"allowed.com"},
	}, privKey)

	c := NewClient("")
	resp, err := c.VerifyOffline(token, pubKeyB64, "evil.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Valid {
		t.Error("expected valid=false for domain mismatch")
	}
	if resp.Reason != "DOMAIN_MISMATCH" {
		t.Errorf("expected DOMAIN_MISMATCH, got %s", resp.Reason)
	}
}

func TestVerifyOffline_ValidToken(t *testing.T) {
	pubKey, privKey, _ := ed25519.GenerateKey(nil)
	pubKeyB64 := base64.StdEncoding.EncodeToString(pubKey)

	token := makeTestToken(t, map[string]interface{}{
		"exp": time.Now().Add(1 * time.Hour).Unix(),
		"dom": []string{"example.com"},
	}, privKey)

	c := NewClient("")
	resp, err := c.VerifyOffline(token, pubKeyB64, "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Valid {
		t.Errorf("expected valid=true, got reason: %s", resp.Reason)
	}
}

func TestVerifyOffline_NoDomainCheck(t *testing.T) {
	pubKey, privKey, _ := ed25519.GenerateKey(nil)
	pubKeyB64 := base64.StdEncoding.EncodeToString(pubKey)

	token := makeTestToken(t, map[string]interface{}{
		"exp": time.Now().Add(1 * time.Hour).Unix(),
		"dom": []string{"example.com"},
	}, privKey)

	c := NewClient("")
	resp, err := c.VerifyOffline(token, pubKeyB64, "") // No domain = skip check
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Valid {
		t.Error("expected valid=true when domain is empty")
	}
}

func TestVerifyOffline_InvalidSignature(t *testing.T) {
	_, privKey1, _ := ed25519.GenerateKey(nil)  // Sign with key1
	pubKey2, _, _ := ed25519.GenerateKey(nil)   // Verify with key2
	pubKeyB64 := base64.StdEncoding.EncodeToString(pubKey2)

	token := makeTestToken(t, map[string]interface{}{
		"exp": time.Now().Add(1 * time.Hour).Unix(),
		"dom": []string{"example.com"},
	}, privKey1)

	c := NewClient("")
	resp, err := c.VerifyOffline(token, pubKeyB64, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Valid {
		t.Error("expected valid=false for mismatched keys")
	}
	if resp.Reason != "INVALID_SIGNATURE" {
		t.Errorf("expected INVALID_SIGNATURE, got %s", resp.Reason)
	}
}

func TestVerifyOffline_InvalidPublicKey(t *testing.T) {
	c := NewClient("")
	_, err := c.VerifyOffline("aaa.bbb.ccc", "not-valid-base64!!!", "")
	if err == nil {
		t.Error("expected error for invalid public key")
	}
}

func TestVerifyOffline_WrongKeyLength(t *testing.T) {
	shortKey := base64.StdEncoding.EncodeToString([]byte("tooshort"))
	c := NewClient("")
	// Need valid JWT parts to get past token parsing
	pubKey, privKey, _ := ed25519.GenerateKey(nil)
	_ = pubKey
	token := makeTestToken(t, map[string]interface{}{
		"exp": time.Now().Add(1 * time.Hour).Unix(),
	}, privKey)

	_, err := c.VerifyOffline(token, shortKey, "")
	if err == nil || err.Error() != "invalid ed25519 public key length" {
		t.Errorf("expected 'invalid ed25519 public key length', got %v", err)
	}
}

func TestVerifyOffline_InvalidPayloadBase64(t *testing.T) {
	c := NewClient("")
	_, err := c.VerifyOffline("valid-header.!!!invalid-base64!!!.sig", "key", "")
	if err == nil {
		t.Error("expected error for invalid payload base64")
	}
}
