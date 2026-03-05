# AntiScam AI — Universal Request Inspection SDK

[![npm](https://img.shields.io/npm/v/@antiscamai/sdk?label=npm&color=crimson)](https://www.npmjs.com/package/@antiscamai/sdk)
[![PyPI](https://img.shields.io/pypi/v/antiscamai?label=pypi&color=blue)](https://pypi.org/project/antiscamai/)
[![NuGet](https://img.shields.io/nuget/v/AntiScamAI.SDK?label=nuget&color=blue)](https://www.nuget.org/packages/AntiScamAI.SDK/)
[![Go](https://img.shields.io/github/v/tag/nebulamatch/antiscamai-sdk-go?label=go&color=00acd7)](https://pkg.go.dev/github.com/nebulamatch/antiscamai-sdk-go)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**One AI brain. Plug-in middleware for every backend.**

AntiScam AI SDK is a language-agnostic security middleware that sits in front of your API, inspects every incoming request in real-time using fine-tuned AI models, and automatically blocks, flags, or logs harmful traffic — **without you writing a single detection rule**.

---

## Why this exists

Modern businesses lose millions every year to threats that **traditional WAFs and rate-limiters miss**:

| Threat | Traditional WAF | AntiScam AI SDK |
|-------|----------------|-----------------|
| SQL injection / XSS | ✅ | ✅ |
| Scam messages via contact forms | ❌ | ✅ AI semantic analysis |
| Phishing URLs submitted to your API | ❌ | ✅ URL Risk AI |
| Social engineering through chat/support APIs | ❌ | ✅ Text AI |
| Account takeover via credential stuffing | ❌ | ✅ Behavioral AI |
| Fake review / comment injection | ❌ | ✅ Text AI |
| Investment fraud via payment APIs | ❌ | ✅ Text + URL AI |
| Chatbot prompt injection attacks | ❌ | ✅ Text AI |
| Image-based scam uploads | ❌ | ✅ Image AI (OCR) |
| Checkout/promo abuse bots | ❌ | ✅ Behavioral AI |

---

## Architecture

```
Your App (any language)
  │
  ▼
┌──────────────────────────────────┐
│  AntiScam AI SDK  (middleware)   │  ← 1 line of code
│  • reads request body + headers  │
│  • extracts text, URLs, files    │
│  • calls AI gateway (async, <3s) │
└────────────────┬─────────────────┘
                 │  POST /sdk/v1/inspect
                 ▼
┌──────────────────────────────────┐
│  AntiScam AI Gateway  (.NET API) │
│  ┌─────────────────────────────┐ │
│  │  Text AI  (DistilBERT)      │ │  ← scam text, social engineering
│  │  URL Risk AI                │ │  ← phishing domains, shorteners
│  │  Image AI (OCR + vision)    │ │  ← scam screenshots, fake docs
│  │  Behavioral AI              │ │  ← account anomaly, bot patterns
│  └─────────────────────────────┘ │
└────────────────┬─────────────────┘
                 │  verdict: allow / flag / block
                 ▼
        Your App continues  ✅
        or request blocked  🚫
```

---

## Supported Languages & Frameworks

| Language | Framework | Install |
|---------|-----------|---------|
| **Node.js** | Express | `npm i @antiscamai/sdk` |
| **Node.js** | Fastify | `npm i @antiscamai/sdk` |
| **Node.js** | Koa | `npm i @antiscamai/sdk` |
| **Python** | FastAPI / Starlette | `pip install antiscamai[fastapi]` |
| **Python** | Django | `pip install antiscamai[django]` |
| **Python** | Flask | `pip install antiscamai[flask]` |
| **Go** | net/http, chi, gin, echo | `go get github.com/nebulamatch/antiscamai-sdk-go` |
| **.NET** | ASP.NET Core 8+ | `dotnet add package AntiScamAI.SDK` |

---

## Quick Start

### Node.js — Express

```typescript
import express from "express";
import { antiScamExpress } from "@antiscamai/sdk/express";

const app = express();
app.use(express.json());

// Add AntiScam AI middleware — one line
app.use(antiScamExpress({
  apiKey: process.env.ANTISCAM_API_KEY!,
  mode: "block",          // block | flag | monitor
  onThreat: (threat) => console.log("Threat detected:", threat),
}));

app.post("/api/messages", (req, res) => {
  // req.antiScam contains the inspection result
  res.json({ ok: true });
});
```

### Node.js — Fastify

```typescript
import Fastify from "fastify";
import antiScamFastify from "@antiscamai/sdk/fastify";

const app = Fastify();
await app.register(antiScamFastify, { apiKey: process.env.ANTISCAM_API_KEY! });
```

### Python — FastAPI

```python
from fastapi import FastAPI
from antiscamai.middleware.fastapi import AntiScamFastAPIMiddleware

app = FastAPI()
app.add_middleware(
    AntiScamFastAPIMiddleware,
    api_key=os.environ["ANTISCAM_API_KEY"],
    mode="block",
)
```

**Alternative — per-route dependency**:

```python
from fastapi import Depends
from antiscamai.middleware.fastapi import antiscam_fastapi

checker = antiscam_fastapi(api_key="YOUR_KEY")

@app.post("/api/contact")
async def contact(body: ContactForm, _=Depends(checker)):
    ...
```

### Python — Django

```python
# settings.py
ANTISCAMAI = {
    "API_KEY": os.environ.get("ANTISCAM_API_KEY"),
    "MODE": "block",
    "EXCLUDE_PATHS": ["/health/", "/static/"],
}

MIDDLEWARE = [
    ...
    "antiscamai.middleware.django.AntiScamDjangoMiddleware",
]
```

### Python — Flask

```python
from flask import Flask
from antiscamai.middleware.flask import antiscam_flask

app = Flask(__name__)
antiscam_flask(app, api_key=os.environ["ANTISCAM_API_KEY"])
```

### Go — net/http

```go
import antiscamai "github.com/nebulamatch/antiscamai-sdk-go"

mux := http.NewServeMux()
mux.HandleFunc("/api/message", myHandler)

protected := antiscamai.NewMiddleware(antiscamai.Config{
    APIKey: os.Getenv("ANTISCAM_API_KEY"),
    Mode:   "block",
    OnThreat: func(e antiscamai.ThreatEvent) {
        log.Printf("Threat: score=%.1f type=%s ip=%s", e.Score, e.Threats[0].Category, e.SourceIP)
    },
}).Handler(mux)

http.ListenAndServe(":8080", protected)
```

### Go — chi

```go
r := chi.NewRouter()
r.Use(antiscamai.NewMiddleware(cfg).Handler)
```

### .NET — ASP.NET Core

```csharp
// Program.cs
builder.Services.AddAntiScamAI(options =>
{
    options.ApiKey   = builder.Configuration["AntiScam:ApiKey"]!;
    options.Mode     = "block";
    options.OnThreat = threat =>
    {
        logger.LogWarning("Threat: {Score} {RiskLevel}", threat.Score, threat.RiskLevel);
        return Task.CompletedTask;
    };
});

var app = builder.Build();
app.UseRouting();
app.UseAntiScamAI();   // ← one line, before UseAuthorization
app.UseAuthorization();
```

**Read result in a controller**:
```csharp
var result = HttpContext.GetAntiScamResult();
if (result?.Decision == "flag")
    // extra verification step
```

---

## Modes

| Mode | Behaviour | Best for |
|------|-----------|---------|
| `block` | Requests scoring ≥65 return HTTP 403 | Production — payment, messaging, auth APIs |
| `flag` | Requests scoring ≥40 are allowed but headers `X-AntiScam-Flag: true` + `X-AntiScam-Score` are set | Staging, content review flows |
| `monitor` | All requests allowed; threats logged only | Onboarding / testing |

---

## Inspection Response Shape

```json
{
  "requestId": "a4f2c1d3...",
  "threatScore": 78.4,
  "riskLevel": "HIGH",
  "decision": "block",
  "shouldBlock": true,
  "threats": [
    {
      "type": "TEXT",
      "category": "PHISHING",
      "score": 78.4,
      "confidence": 91.2,
      "explanation": "Message contains urgency manipulation, financial keywords, and suspicious patterns"
    },
    {
      "type": "URL",
      "category": "PHISHING",
      "score": 65.0,
      "confidence": 85.0,
      "explanation": "Risk Level: HIGH. ⚠️ Domain age < 30 days ⚠️ Suspicious keywords found"
    }
  ],
  "processedAt": "2026-03-04T12:00:00Z",
  "modelVersion": "1.0.0"
}
```

---

## What Gets Inspected

The SDK automatically extracts and inspects:

| Source | What the AI sees |
|--------|----------------|
| Request body (JSON) | All string values, deep-flattened |
| Request body (plain text) | Direct content |
| URLs in the body / query | Risk-scored for phishing patterns |
| Custom headers | User-Agent, Referer, Origin anomalies |
| User identity | Behavioral pattern (if `userId` provided) |
| Uploaded images | OCR-extracted text + visual scam signals |

---

## Configuration Reference

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `apiKey` | string | *required* | Your SDK API key |
| `endpoint` | string | `http://localhost:5000` | AntiScam AI gateway URL |
| `mode` | string | `"block"` | `block`, `flag`, or `monitor` |
| `timeoutMs` | number | `3000` | AI service call timeout |
| `onError` | string | `"allow"` | Fail-open or fail-closed when AI is unreachable |
| `excludePaths` | string[] | `["/health", "/metrics"]` | Paths to skip |
| `inspectMethods` | string[] | `["POST","PUT","PATCH"]` | HTTP methods to inspect |
| `onThreat` | function | `undefined` | Callback on threat detection |

---

## Self-Hosted vs Cloud

The SDK works with **any** AntiScam AI backend instance:

```typescript
// Self-hosted (Docker Compose)
antiScamExpress({ apiKey: "...", endpoint: "http://antiscam-api:5000" })

// Kubernetes
antiScamExpress({ apiKey: "...", endpoint: "http://antiscam-svc.security.svc.cluster.local" })

// Cloud (future SaaS)
antiScamExpress({ apiKey: "...", endpoint: "https://api.antiscamai.io" })
```

---

## Batch Inspection API

For inspecting multiple items at once (e.g. chat thread, bulk upload review):

```
POST /sdk/v1/batch-inspect
X-AntiScam-Key: YOUR_KEY

{
  "items": [
    { "bodyText": "Win $10,000 now!" },
    { "bodyText": "Meeting at 3pm" },
    { "extractedUrls": ["http://192.168.1.1/login"] }
  ]
}
```

---

## Security Best Practices

1. **Never expose your API key** on the client side. The SDK is server-side only.
2. **Use `monitor` mode first** — run for 1 week to understand your traffic baseline.
3. **Set `onThreat`** to feed alerts into your SIEM / Slack / PagerDuty.
4. **Exclude internal health/metrics routes** via `excludePaths`.
5. **Keep `onError: "allow"`** (fail-open) in production to avoid outages if the AI service restarts.

---

## Deployment

The AntiScam AI gateway runs as a Docker container alongside your existing services:

```yaml
# docker-compose.yml (excerpt)
  antiscam-api:
    image: antiscamai/api:latest
    environment:
      - AIServices__TextService=http://text-ai:8001
      - AIServices__UrlService=http://url-risk:8004
      - Sdk__ApiKeys=your-secret-key-1,your-secret-key-2
    ports:
      - "5000:5000"
```

See [deploy/docker/docker-compose.yml](../deploy/docker/docker-compose.yml) for the full configuration.
