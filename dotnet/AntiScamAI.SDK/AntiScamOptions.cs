namespace AntiScamAI.SDK;

/// <summary>
/// Configuration for the AntiScam AI SDK middleware.
/// </summary>
public class AntiScamOptions
{
    /// <summary>Your SDK API key (required).</summary>
    public string ApiKey { get; set; } = string.Empty;

    /// <summary>
    /// Base URL of your AntiScam AI instance.
    /// Default: http://localhost:5000
    /// </summary>
    public string Endpoint { get; set; } = "http://localhost:5000";

    /// <summary>
    /// Operating mode:
    /// <list type="bullet">
    ///   <item><term>block</term><description>Requests scoring ≥65 are automatically blocked (default)</description></item>
    ///   <item><term>flag</term><description>Requests scoring ≥40 are flagged but allowed</description></item>
    ///   <item><term>monitor</term><description>All requests are allowed; threats are only logged</description></item>
    /// </list>
    /// </summary>
    public string Mode { get; set; } = "block";

    /// <summary>Score threshold for blocking (0-100). Default: 65.</summary>
    public double BlockThreshold { get; set; } = 65;

    /// <summary>Score threshold for flagging (0-100). Default: 40.</summary>
    public double FlagThreshold { get; set; } = 40;

    /// <summary>Max milliseconds to wait for the AI service. Default: 3000.</summary>
    public int TimeoutMs { get; set; } = 3000;

    /// <summary>
    /// What to do when the AI service is unreachable:
    /// <list type="bullet">
    ///   <item><term>allow</term><description>Fail-open – keeps your service available (default)</description></item>
    ///   <item><term>block</term><description>Fail-closed – safer but may affect availability</description></item>
    /// </list>
    /// </summary>
    public string OnError { get; set; } = "allow";

    /// <summary>URL prefixes to skip entirely. Default: ["/health", "/metrics"]</summary>
    public IReadOnlyList<string> ExcludePaths { get; set; } =
        new[] { "/health", "/metrics", "/swagger", "/favicon.ico" };

    /// <summary>HTTP methods to inspect. Default: POST, PUT, PATCH</summary>
    public IReadOnlyList<string> InspectMethods { get; set; } =
        new[] { "POST", "PUT", "PATCH" };

    /// <summary>Optional callback invoked on every detected threat.</summary>
    public Func<ThreatEvent, Task>? OnThreat { get; set; }
}

/// <summary>Threat event passed to the OnThreat callback.</summary>
public record ThreatEvent(
    string RequestId,
    double Score,
    string RiskLevel,
    string Decision,
    IReadOnlyList<ThreatDetail> Threats,
    string? Endpoint,
    string? SourceIp,
    string? UserId
);
