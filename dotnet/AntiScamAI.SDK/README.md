# AntiScamAI.SDK

[![NuGet version](https://img.shields.io/nuget/v/AntiScamAI.SDK?color=blue)](https://www.nuget.org/packages/AntiScamAI.SDK/)
[![NuGet downloads](https://img.shields.io/nuget/dt/AntiScamAI.SDK)](https://www.nuget.org/packages/AntiScamAI.SDK/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**AI-powered request inspection middleware for ASP.NET Core.**  
Register two lines in `Program.cs` and every incoming request is automatically screened by a trained AI model for scams, phishing, social engineering, and fraudulent content.

---

## Install

```bash
dotnet add package AntiScamAI.SDK
```

## Quick Start

```csharp
// Program.cs
builder.Services.AddAntiScamAI(options =>
{
    options.ApiKey   = builder.Configuration["AntiScam:ApiKey"]!;
    options.Mode     = "block";   // "block" | "flag" | "monitor"
    options.OnThreat = threat =>
    {
        logger.LogWarning("Threat detected: score={Score} level={Level}",
            threat.Score, threat.RiskLevel);
        return Task.CompletedTask;
    };
});

var app = builder.Build();
app.UseRouting();
app.UseAntiScamAI();          // ← add before UseAuthorization
app.UseAuthorization();
app.MapControllers();
app.Run();
```

## What Gets Blocked

| Threat | Example |
|--------|---------|
| Phishing messages | "Your account is suspended — verify now" |
| Investment fraud | "Guaranteed 500% ROI — risk-free" |
| Lottery / prize scams | "You've won $50,000 — claim your prize" |
| Social engineering | "I'm from Apple Support, share your OTP" |
| Phishing URLs in body | `http://secur3-paypal.xyz/verify` |
| Prompt injection (LLM) | "Ignore previous instructions…" |
| Credential phishing | "Enter your password to verify identity" |

## HTTP 403 on Blocked Request

```json
{
  "error": "Request blocked by AntiScam AI",
  "requestId": "a4f2c1d3...",
  "riskLevel": "HIGH",
  "reason": "High urgency language + suspicious patterns detected"
}
```

## Read the Inspection Result in a Controller

```csharp
[HttpPost("contact")]
public IActionResult Contact([FromBody] ContactRequest request)
{
    var result = HttpContext.GetAntiScamResult();
    // result.ThreatScore  → double 0–100
    // result.RiskLevel    → "MINIMAL" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    // result.Decision     → "allow" | "flag" | "block"
    // result.Threats      → List<ThreatDetail>
    return Ok();
}
```

## Modes

| Mode | Behaviour |
|------|-----------|
| `block` | Requests scoring ≥65 return HTTP 403 (default) |
| `flag` | Allowed but sets `X-AntiScam-Flag: true` response header |
| `monitor` | All requests pass; threats are only logged |

## Configuration Reference

```csharp
builder.Services.AddAntiScamAI(options =>
{
    options.ApiKey          = "required";
    options.Endpoint        = "http://localhost:5000";   // AntiScam AI gateway
    options.Mode            = "block";                   // block | flag | monitor
    options.TimeoutMs       = 3000;
    options.OnError         = "allow";                   // allow (fail-open) | block
    options.ExcludePaths    = new[] { "/health", "/metrics", "/swagger" };
    options.InspectMethods  = new[] { "POST", "PUT", "PATCH" };
    options.OnThreat        = threat => { /* ... */ return Task.CompletedTask; };
});
```

Or via `appsettings.json`:

```json
{
  "AntiScam": {
    "ApiKey": "YOUR_KEY",
    "Endpoint": "http://localhost:5000",
    "Mode": "block"
  }
}
```

## Self-Hosting

```bash
git clone https://github.com/antiscamai/backend
cd backend/deploy/docker
docker-compose up -d
```

## Requirements

- .NET 8.0+
- ASP.NET Core 8.0+

## License

MIT © AntiScam AI
