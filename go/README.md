# antiscamai-go

[![Go Reference](https://pkg.go.dev/badge/github.com/nebulamatch/antiscamai-sdk-go.svg)](https://pkg.go.dev/github.com/nebulamatch/antiscamai-sdk-go)
[![Go Report Card](https://goreportcard.com/badge/github.com/nebulamatch/antiscamai-sdk-go)](https://goreportcard.com/report/github.com/nebulamatch/antiscamai-sdk-go)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**AI-powered request inspection middleware for Go.**  
Wraps any `http.Handler` — works with net/http, chi, gin, echo, fiber, and every other Go router.

---

## Install

```bash
go get github.com/nebulamatch/antiscamai-sdk-go@latest
```

## Quick Start

### net/http

```go
package main

import (
    "net/http"
    "os"

    antiscamai "github.com/nebulamatch/antiscamai-sdk-go"
)

func main() {
    mux := http.NewServeMux()
    mux.HandleFunc("/api/contact", contactHandler)
    mux.HandleFunc("/api/payment", paymentHandler)

    // Wrap with AntiScam AI — one line
    protected := antiscamai.NewMiddleware(antiscamai.Config{
        APIKey: os.Getenv("ANTISCAM_API_KEY"),
        Mode:   "block", // "block" | "flag" | "monitor"
    }).Handler(mux)

    http.ListenAndServe(":8080", protected)
}
```

### chi

```go
r := chi.NewRouter()
r.Use(antiscamai.NewMiddleware(cfg).Handler)
r.Post("/api/contact", contactHandler)
```

### gin

```go
// Adapt for gin using a gin-compatible wrapper
engine := gin.Default()
protected := antiscamai.NewMiddleware(cfg).Handler(engine)
http.ListenAndServe(":8080", protected)
```

## What Gets Blocked

| Threat | Example |
|--------|---------|
| Phishing messages | "Your account is suspended — verify now" |
| Investment fraud | "Guaranteed 500% ROI — risk-free" |
| Phishing URLs in body | `http://secur3-paypal.xyz/verify` |
| Social engineering | "I'm from Apple Support, share your OTP" |
| Prompt injection | "Ignore previous instructions…" |

## HTTP 403 on Blocked Request

```json
{
  "error": "Request blocked by AntiScam AI",
  "requestId": "a4f2c1d3...",
  "riskLevel": "HIGH",
  "reason": "High urgency language + suspicious patterns detected"
}
```

## Read the Inspection Result

```go
func contactHandler(w http.ResponseWriter, r *http.Request) {
    result, ok := antiscamai.FromContext(r.Context())
    if ok {
        // result.ThreatScore  → float64 0–100
        // result.RiskLevel    → "MINIMAL" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
        // result.Decision     → "allow" | "flag" | "block"
        // result.Threats      → []ThreatDetail
    }
}
```

## Threat Callback

```go
antiscamai.NewMiddleware(antiscamai.Config{
    APIKey: os.Getenv("ANTISCAM_API_KEY"),
    OnThreat: func(e antiscamai.ThreatEvent) {
        log.Printf("Threat: score=%.1f type=%s ip=%s",
            e.Score, e.Threats[0].Category, e.SourceIP)
        // Push to Slack, PagerDuty, your SIEM...
    },
})
```

## Modes

| Mode | Behaviour |
|------|-----------|
| `block` | Requests scoring ≥65 return HTTP 403 (default) |
| `flag` | Allowed but sets `X-AntiScam-Flag: true` header |
| `monitor` | All requests pass; threats are only logged |

## Config Reference

```go
antiscamai.Config{
    APIKey:         "required",
    Endpoint:       "http://localhost:5000",   // AntiScam AI gateway
    Mode:           "block",                   // block | flag | monitor
    TimeoutMs:      3000,
    OnError:        "allow",                   // allow (fail-open) | block (fail-closed)
    ExcludePaths:   []string{"/health", "/metrics"},
    InspectMethods: []string{"POST", "PUT", "PATCH"},
    OnThreat:       nil,                       // func(ThreatEvent)
}
```

## Self-Hosting

```bash
git clone https://github.com/antiscamai/backend
cd backend/deploy/docker
docker-compose up -d
```

```go
antiscamai.NewMiddleware(antiscamai.Config{
    APIKey:   "YOUR_KEY",
    Endpoint: "http://localhost:5000",
})
```

## Requirements

- Go 1.22+

## License

MIT © AntiScam AI
