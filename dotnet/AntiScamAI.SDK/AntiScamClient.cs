using System.Net.Http.Json;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace AntiScamAI.SDK;

// ─── DTOs ─────────────────────────────────────────────────────────────────────

public class SdkInspectPayload
{
    public string? BodyText { get; set; }
    public string? BodyRaw { get; set; }
    public List<string>? ExtractedUrls { get; set; }
    public Dictionary<string, string>? Headers { get; set; }
    public string? SourceIp { get; set; }
    public string? Endpoint { get; set; }
    public string? Method { get; set; }
    public string? UserId { get; set; }
    public string? Mode { get; set; }
    public Dictionary<string, string>? Metadata { get; set; }
}

public class ThreatDetail
{
    public string Type { get; set; } = default!;
    public string Category { get; set; } = default!;
    public double Score { get; set; }
    public double Confidence { get; set; }
    public string Explanation { get; set; } = default!;
}

public class SdkInspectResult
{
    public string RequestId { get; set; } = default!;
    public double ThreatScore { get; set; }
    public string RiskLevel { get; set; } = default!;
    public string Decision { get; set; } = default!;
    public bool ShouldBlock { get; set; }
    public List<ThreatDetail> Threats { get; set; } = new();
    public DateTimeOffset ProcessedAt { get; set; }
    public string ModelVersion { get; set; } = default!;
}

// ─── Client ───────────────────────────────────────────────────────────────────

/// <summary>
/// Thin HTTP client that calls the AntiScam AI gateway.  
/// Registered as a singleton via AddAntiScamAI().
/// </summary>
public class AntiScamClient
{
    private static readonly Regex _urlRegex = new(
        @"https?://[^\s""'\]\)>]+",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static readonly string[] _headerAllowList =
        ["user-agent", "referer", "x-forwarded-for", "origin"];

    private readonly HttpClient _http;
    private readonly AntiScamOptions _options;
    private readonly ILogger<AntiScamClient> _logger;

    public AntiScamClient(
        IHttpClientFactory httpClientFactory,
        AntiScamOptions options,
        ILogger<AntiScamClient> logger)
    {
        _http = httpClientFactory.CreateClient("AntiScamAI");
        _options = options;
        _logger = logger;
    }

    /// <summary>Inspect a request snapshot. Never throws — returns a fallback on error.</summary>
    public async Task<SdkInspectResult> InspectAsync(
        SdkInspectPayload payload,
        CancellationToken ct = default)
    {
        payload.Mode ??= _options.Mode;

        try
        {
            var response = await _http.PostAsJsonAsync(
                $"{_options.Endpoint.TrimEnd('/')}/sdk/v1/inspect",
                payload,
                ct);

            response.EnsureSuccessStatusCode();

            var result = await response.Content.ReadFromJsonAsync<SdkInspectResult>(
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true },
                ct);

            return result ?? Fallback();
        }
        catch (Exception ex) when (ex is TaskCanceledException or HttpRequestException or OperationCanceledException)
        {
            _logger.LogWarning("[AntiScamAI] Inspection failed: {Error}. Falling back to: {Mode}", ex.Message, _options.OnError);
            return Fallback();
        }
    }

    /// <summary>Extract human-readable text + URLs from a raw JSON body string.</summary>
    public static (string text, List<string> urls) ExtractContent(string? rawJson)
    {
        if (string.IsNullOrWhiteSpace(rawJson))
            return (string.Empty, new List<string>());

        var textParts = new List<string>();
        var urlsFound = new List<string>();

        try
        {
            using var doc = JsonDocument.Parse(rawJson);
            FlattenJson(doc.RootElement, textParts, urlsFound);
        }
        catch
        {
            textParts.Add(rawJson);
            urlsFound.AddRange(_urlRegex.Matches(rawJson).Select(m => m.Value));
        }

        var combinedText = string.Join(" ", textParts);
        urlsFound.AddRange(_urlRegex.Matches(combinedText).Select(m => m.Value));

        return (combinedText, urlsFound.Distinct().ToList());
    }

    public static Dictionary<string, string> FilterHeaders(IHeaderDictionary headers)
    {
        var result = new Dictionary<string, string>();
        foreach (var key in _headerAllowList)
        {
            if (headers.TryGetValue(key, out var val))
                result[key] = val.ToString();
        }
        return result;
    }

    private SdkInspectResult Fallback()
    {
        var blocked = _options.OnError == "block";
        return new SdkInspectResult
        {
            RequestId = "error-fallback",
            ThreatScore = 0,
            RiskLevel = "MINIMAL",
            Decision = blocked ? "block" : "allow",
            ShouldBlock = blocked,
        };
    }

    private static void FlattenJson(JsonElement el, List<string> texts, List<string> urls)
    {
        switch (el.ValueKind)
        {
            case JsonValueKind.String:
                var s = el.GetString() ?? "";
                if (s.StartsWith("http", StringComparison.OrdinalIgnoreCase))
                    urls.Add(s);
                else if (s.Length > 2)
                    texts.Add(s);
                break;
            case JsonValueKind.Object:
                foreach (var prop in el.EnumerateObject()) FlattenJson(prop.Value, texts, urls);
                break;
            case JsonValueKind.Array:
                foreach (var item in el.EnumerateArray()) FlattenJson(item, texts, urls);
                break;
        }
    }
}
