# @antiscamai/sdk

[![npm version](https://img.shields.io/npm/v/@antiscamai/sdk?color=crimson&label=npm)](https://www.npmjs.com/package/@antiscamai/sdk)
[![npm downloads](https://img.shields.io/npm/dm/@antiscamai/sdk)](https://www.npmjs.com/package/@antiscamai/sdk)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**AI-powered request inspection middleware for Node.js.**  
Drop one middleware into your Express, Fastify, or Koa app and every incoming request is silently screened by a trained AI model for scams, phishing, social engineering, and fraudulent content — in under 3 seconds.

---

## Install

```bash
npm install @antiscamai/sdk
# or
yarn add @antiscamai/sdk
# or
pnpm add @antiscamai/sdk
```

## Quick Start

### Express

```typescript
import express from "express";
import { antiScamExpress } from "@antiscamai/sdk/express";

const app = express();
app.use(express.json());

app.use(antiScamExpress({
  apiKey: process.env.ANTISCAM_API_KEY!,
  mode: "block",   // "block" | "flag" | "monitor"
}));

// All your existing routes are now protected — no other changes needed
app.post("/api/contact", handler);
app.post("/api/payment", handler);
```

### Fastify

```typescript
import Fastify from "fastify";
import antiScamFastify from "@antiscamai/sdk/fastify";

const app = Fastify();
await app.register(antiScamFastify, {
  apiKey: process.env.ANTISCAM_API_KEY!,
});
```

### Koa

```typescript
import Koa from "koa";
import bodyParser from "koa-bodyparser";
import { antiScamKoa } from "@antiscamai/sdk/koa";

const app = new Koa();
app.use(bodyParser());
app.use(antiScamKoa({ apiKey: process.env.ANTISCAM_API_KEY! }));
```

## What Gets Blocked

The AI inspects every `POST`, `PUT`, and `PATCH` request body automatically:

| Threat | Example |
|--------|---------|
| Phishing messages | "Your account is suspended — verify now" |
| Investment fraud | "Guaranteed 500% ROI — risk-free" |
| Lottery / prize scams | "You've won $50,000 — claim your prize" |
| Social engineering | "I'm from Apple Support, share your OTP" |
| Phishing URLs in body | `http://secur3-paypal.xyz/verify` |
| Prompt injection (LLM) | "Ignore previous instructions…" |
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

```typescript
app.post("/api/contact", (req, res) => {
  const result = req.antiScam;
  // result.threatScore  → 0–100
  // result.riskLevel    → MINIMAL | LOW | MEDIUM | HIGH | CRITICAL
  // result.decision     → allow | flag | block
  // result.threats      → array of detected threats with explanations
});
```

## Threat Callback

```typescript
antiScamExpress({
  apiKey: "...",
  onThreat: (threat) => {
    console.log(`Score ${threat.score} | ${threat.riskLevel}`);
    // Send to Slack, PagerDuty, Sentry, your SIEM...
  },
});
```

## Modes

| Mode | Behaviour |
|------|-----------|
| `block` | Requests scoring ≥65 return HTTP 403 (default) |
| `flag` | Allowed but sets `X-AntiScam-Flag: true` header |
| `monitor` | All requests pass; threats are only logged |

## Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `apiKey` | string | *required* | Your API key |
| `endpoint` | string | `http://localhost:5000` | AntiScam AI gateway URL |
| `mode` | string | `"block"` | `block`, `flag`, or `monitor` |
| `timeoutMs` | number | `3000` | AI call timeout in ms |
| `onError` | string | `"allow"` | Fail-open (`allow`) or fail-closed (`block`) |
| `excludePaths` | string[] | `["/health","/metrics"]` | Paths to skip |
| `inspectMethods` | string[] | `["POST","PUT","PATCH"]` | Methods to inspect |
| `onThreat` | function | — | Callback on threat detection |

## Self-Hosting

The SDK works with any running AntiScam AI backend:

```bash
# Docker Compose (quickest start)
git clone https://github.com/antiscamai/backend
cd backend/deploy/docker
docker-compose up -d
```

Then point your SDK at it:
```typescript
antiScamExpress({ apiKey: "YOUR_KEY", endpoint: "http://localhost:5000" })
```

## License

MIT © AntiScam AI
