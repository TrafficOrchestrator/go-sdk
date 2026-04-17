# @traffic-orchestrator/go-sdk

Official Go SDK for [Traffic Orchestrator](https://trafficorchestrator.com) — license validation, management, and analytics.

📖 [API Reference](https://trafficorchestrator.com/docs#api) · [SDK Guides](https://trafficorchestrator.com/docs/sdk/go) · [OpenAPI Spec](https://api.trafficorchestrator.com/api/v1/openapi.json)

## Install

```bash
go get github.com/Traffic-Orchestrator/TO/packages/go-sdk
```

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    to "github.com/Traffic-Orchestrator/TO/packages/go-sdk"
)

func main() {
    client := to.NewClient()

    result, err := client.ValidateLicense(context.Background(), "LK-xxxx-xxxx-xxxx", "example.com")
    if err != nil {
        panic(err)
    }

    if result.Valid {
        fmt.Printf("License active, plan: %s\n", result.PlanID)
    }
}
```

## API Methods

### Core License Operations

| Method | Auth | Description |
| --- | --- | --- |
| `ValidateLicense(ctx, token, domain)` | No | Validate a license key |
| `VerifyOffline(token, publicKey, domain)` | No | Ed25519 offline verification |
| `ListLicenses(ctx)` | Yes | List all licenses |
| `CreateLicense(ctx, opts)` | Yes | Create a new license |
| `RotateLicense(ctx, licenseID)` | Yes | Rotate license key |
| `DeleteLicense(ctx, licenseID)` | Yes | Revoke a license |
| `GetUsage(ctx)` | Yes | Get usage statistics |
| `GetAnalytics(ctx, days)` | Yes | Get detailed analytics |
| `HealthCheck(ctx)` | No | Check API health |

### Portal & Enterprise Methods

| Method | Auth | Description |
| --- | --- | --- |
| `AddDomain(ctx, licenseID, domain)` | Yes | Add domain to license |
| `RemoveDomain(ctx, licenseID, domain)` | Yes | Remove domain from license |
| `GetDomains(ctx, licenseID)` | Yes | Get license domains |
| `UpdateLicenseStatus(ctx, id, status)` | Yes | Suspend/reactivate license |
| `ListAPIKeys(ctx)` | Yes | List API keys |
| `CreateAPIKey(ctx, name, scopes)` | Yes | Create API key |
| `DeleteAPIKey(ctx, keyID)` | Yes | Delete API key |
| `GetDashboard(ctx)` | Yes | Full dashboard overview |

## Context Support

All methods accept `context.Context` for timeouts and cancellation:

```go
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()

result, err := client.ValidateLicense(ctx, token, domain)
```

## Connection Pooling

```go
client := to.NewClient(
    to.WithAPIKey(os.Getenv("TO_API_KEY")),
    to.WithMaxIdleConns(10),
    to.WithTimeout(5 * time.Second),
    to.WithRetries(3),
)
```

## Multi-Environment

```go
// Production (default)
client := to.NewClient(to.WithAPIKey(os.Getenv("TO_API_KEY")))

// Staging
client := to.NewClient(
    to.WithAPIKey(os.Getenv("TO_API_KEY_DEV")),
    to.WithBaseURL("https://api-staging.trafficorchestrator.com/api/v1"),
)
```

## Error Handling

```go
result, err := client.ValidateLicense(ctx, token, domain)
if err != nil {
    var apiErr *to.APIError
    if errors.As(err, &apiErr) {
        fmt.Printf("API error: %s (code: %s, status: %d)\n", apiErr.Message, apiErr.Code, apiErr.Status)
    }
}
```

## Offline Verification (Enterprise)

Enterprise licenses are signed JWTs verified without network access using Ed25519:

```go
pubKeyB64 := os.Getenv("TO_PUBLIC_KEY") // base64-encoded Ed25519 public key

result, err := client.VerifyOffline(licenseToken, pubKeyB64, "example.com")
if err != nil {
    log.Fatal(err)
}

if result.Valid {
    fmt.Printf("Plan: %s, Expires: %s\n", result.PlanID, result.ExpiresAt)
}
```

## Requirements

- Go 1.21+

## License

MIT
