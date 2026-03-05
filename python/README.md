# antiscamai

[![PyPI version](https://img.shields.io/pypi/v/antiscamai?color=blue)](https://pypi.org/project/antiscamai/)
[![Python versions](https://img.shields.io/pypi/pyversions/antiscamai)](https://pypi.org/project/antiscamai/)
[![Downloads](https://img.shields.io/pypi/dm/antiscamai)](https://pypi.org/project/antiscamai/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**AI-powered request inspection middleware for Python.**  
Add one line to your FastAPI, Django, or Flask app and every incoming request is automatically screened by a trained AI model for scams, phishing, social engineering, and fraudulent content.

---

## Install

```bash
# FastAPI / Starlette
pip install antiscamai[fastapi]

# Django
pip install antiscamai[django]

# Flask
pip install antiscamai[flask]

# All frameworks
pip install antiscamai[all]
```

## Quick Start

### FastAPI (Middleware)

```python
from fastapi import FastAPI
from antiscamai.middleware.fastapi import AntiScamFastAPIMiddleware
import os

app = FastAPI()
app.add_middleware(
    AntiScamFastAPIMiddleware,
    api_key=os.environ["ANTISCAM_API_KEY"],
    mode="block",   # "block" | "flag" | "monitor"
)

# All your existing routes are now protected — no other changes needed
@app.post("/api/contact")
async def contact(body: ContactForm):
    ...
```

### FastAPI (Per-Route Dependency)

```python
from fastapi import Depends
from antiscamai.middleware.fastapi import antiscam_fastapi

checker = antiscam_fastapi(api_key=os.environ["ANTISCAM_API_KEY"])

@app.post("/api/payment")
async def payment(body: PaymentForm, _=Depends(checker)):
    ...
```

### Django

```python
# settings.py
ANTISCAMAI = {
    "API_KEY": os.environ.get("ANTISCAM_API_KEY"),
    "MODE": "block",                              # block | flag | monitor
    "ENDPOINT": "http://localhost:5000",
    "EXCLUDE_PATHS": ["/health/", "/static/"],
    "INSPECT_METHODS": ["POST", "PUT", "PATCH"],
}

MIDDLEWARE = [
    # ... your existing middleware ...
    "antiscamai.middleware.django.AntiScamDjangoMiddleware",
]
```

### Flask

```python
from flask import Flask
from antiscamai.middleware.flask import antiscam_flask
import os

app = Flask(__name__)
antiscam_flask(app, api_key=os.environ["ANTISCAM_API_KEY"])
```

## What Gets Blocked

| Threat | Example |
|--------|---------|
| Phishing messages | "Your account is suspended — verify now" |
| Investment fraud | "Guaranteed 500% ROI — risk-free" |
| Lottery / prize scams | "You've won $50,000 — claim your prize" |
| Social engineering | "I'm from Apple Support, share your OTP" |
| Phishing URLs in body | `http://secur3-paypal.xyz/verify` |
| Prompt injection (LLM APIs) | "Ignore previous instructions…" |
| Credential phishing | "Enter your password to verify identity" |

## Response on Blocked Request

```json
HTTP 403 Forbidden
{
  "error": "Request blocked by AntiScam AI",
  "requestId": "a4f2c1d3...",
  "riskLevel": "HIGH",
  "reason": "High urgency language + suspicious patterns detected"
}
```

## Read the Inspection Result

```python
# FastAPI — result stored in request.state
@app.post("/api/contact")
async def contact(request: Request, body: ContactForm):
    result = request.state.antiscam
    # result.threat_score  → 0–100
    # result.risk_level    → MINIMAL | LOW | MEDIUM | HIGH | CRITICAL
    # result.decision      → allow | flag | block
    # result.threats       → list of detected threats with explanations

# Django — result stored in request.antiscam
def my_view(request):
    result = getattr(request, "antiscam", None)

# Flask — result stored in g.antiscam
from flask import g
result = g.antiscam
```

## Threat Callback

```python
from antiscamai.middleware.fastapi import AntiScamFastAPIMiddleware

async def on_threat(result):
    print(f"Threat! score={result.threat_score} level={result.risk_level}")
    # Send to Slack, PagerDuty, your SIEM...

app.add_middleware(
    AntiScamFastAPIMiddleware,
    api_key="...",
    on_threat=on_threat,
)
```

## Modes

| Mode | Behaviour |
|------|-----------|
| `block` | Requests scoring ≥65 return HTTP 403 (default) |
| `flag` | Allowed but sets `X-AntiScam-Flag: true` header |
| `monitor` | All requests pass; threats are only logged |

## Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `api_key` | *required* | Your API key |
| `endpoint` | `http://localhost:5000` | AntiScam AI gateway URL |
| `mode` | `"block"` | `block`, `flag`, or `monitor` |
| `timeout_ms` | `3000` | AI call timeout in ms |
| `on_error` | `"allow"` | Fail-open (`allow`) or fail-closed (`block`) |
| `exclude_paths` | `["/health", "/metrics"]` | URL prefixes to skip |
| `inspect_methods` | `["POST","PUT","PATCH"]` | HTTP methods to inspect |
| `on_threat` | `None` | Async/sync callback on threat detection |

## Self-Hosting

```bash
git clone https://github.com/antiscamai/backend
cd backend/deploy/docker
docker-compose up -d
```

```python
AntiScamFastAPIMiddleware(app, api_key="YOUR_KEY", endpoint="http://localhost:5000")
```

## Requirements

- Python 3.10+
- `httpx >= 0.27.0`

## License

MIT © AntiScam AI
