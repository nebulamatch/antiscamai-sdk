using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AntiScamAI.SDK;

/// <summary>
/// ASP.NET Core middleware that intercepts every request and sends it to
/// the AntiScam AI gateway for threat inspection.
/// </summary>
public class AntiScamMiddleware
{
    private readonly RequestDelegate _next;
    private readonly AntiScamOptions _options;
    private readonly AntiScamClient _client;
    private readonly ILogger<AntiScamMiddleware> _logger;

    public AntiScamMiddleware(
        RequestDelegate next,
        AntiScamOptions options,
        AntiScamClient client,
        ILogger<AntiScamMiddleware> logger)
    {
        _next = next;
        _options = options;
        _client = client;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var request = context.Request;
        var method = request.Method.ToUpperInvariant();
        var path = request.Path.Value ?? "/";

        // ── Skip checks ──────────────────────────────────────────
        bool shouldSkip =
            _options.ExcludePaths.Any(p => path.StartsWith(p, StringComparison.OrdinalIgnoreCase)) ||
            !_options.InspectMethods.Any(m => m.Equals(method, StringComparison.OrdinalIgnoreCase));

        if (shouldSkip)
        {
            await _next(context);
            return;
        }

        // ── Read body ────────────────────────────────────────────
        string rawBody = string.Empty;
        request.EnableBuffering();

        if (request.ContentLength > 0 || request.Body.CanSeek)
        {
            using var reader = new StreamReader(
                request.Body,
                encoding: Encoding.UTF8,
                detectEncodingFromByteOrderMarks: false,
                bufferSize: 1024 * 4,
                leaveOpen: true);

            rawBody = await reader.ReadToEndAsync();
            request.Body.Position = 0; // restore for downstream
        }

        var (text, urls) = AntiScamClient.ExtractContent(rawBody);
        var safeHeaders = AntiScamClient.FilterHeaders(request.Headers);

        // Resolve user ID from JWT claims if available
        var userId = context.User?.FindFirstValue(ClaimTypes.NameIdentifier) ??
                     context.User?.FindFirstValue("sub");

        var payload = new SdkInspectPayload
        {
            BodyText = text.Length > 4000 ? text[..4000] : text,
            ExtractedUrls = urls.Take(10).ToList(),
            Headers = safeHeaders,
            SourceIp = context.Connection.RemoteIpAddress?.ToString(),
            Endpoint = $"{method} {path}",
            Method = method,
            UserId = userId,
            Mode = _options.Mode,
        };

        var result = await _client.InspectAsync(payload, context.RequestAborted);

        // Attach to HttpContext for controllers to read
        context.Items["AntiScam"] = result;

        // ── Threat callback ──────────────────────────────────────
        if (_options.OnThreat is not null && result.Threats.Count > 0)
        {
            await _options.OnThreat(new ThreatEvent(
                result.RequestId,
                result.ThreatScore,
                result.RiskLevel,
                result.Decision,
                result.Threats.Select(t => new ThreatDetail
                {
                    Type = t.Type,
                    Category = t.Category,
                    Score = t.Score,
                    Confidence = t.Confidence,
                    Explanation = t.Explanation
                }).ToList().AsReadOnly(),
                $"{method} {path}",
                context.Connection.RemoteIpAddress?.ToString(),
                userId
            ));
        }

        // ── Block ────────────────────────────────────────────────
        if (result.ShouldBlock)
        {
            _logger.LogWarning(
                "[AntiScamAI] Blocked request | endpoint={Endpoint} score={Score} riskLevel={RiskLevel}",
                $"{method} {path}", result.ThreatScore, result.RiskLevel);

            var reason = result.Threats.Count > 0
                ? result.Threats[0].Explanation
                : "Suspicious content detected";

            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            context.Response.ContentType = "application/json";

            await context.Response.WriteAsJsonAsync(new
            {
                error = "Request blocked by AntiScam AI",
                requestId = result.RequestId,
                riskLevel = result.RiskLevel,
                reason,
            });
            return;
        }

        // ── Flag ─────────────────────────────────────────────────
        if (result.Decision == "flag")
        {
            context.Response.OnStarting(() =>
            {
                context.Response.Headers["X-AntiScam-Flag"] = "true";
                context.Response.Headers["X-AntiScam-Score"] = result.ThreatScore.ToString("F2");
                return Task.CompletedTask;
            });
        }

        await _next(context);
    }
}
