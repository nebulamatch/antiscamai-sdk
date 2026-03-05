using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

namespace AntiScamAI.SDK;

/// <summary>
/// Extension methods for registering AntiScam AI SDK in ASP.NET Core apps.
/// </summary>
public static class AntiScamExtensions
{
    /// <summary>
    /// Registers AntiScam AI services.
    ///
    /// <code>
    /// builder.Services.AddAntiScamAI(options =>
    /// {
    ///     options.ApiKey = "YOUR_KEY";
    ///     options.Mode   = "block";  // block | flag | monitor
    /// });
    /// </code>
    /// </summary>
    public static IServiceCollection AddAntiScamAI(
        this IServiceCollection services,
        Action<AntiScamOptions> configure)
    {
        var options = new AntiScamOptions();
        configure(options);

        if (string.IsNullOrWhiteSpace(options.ApiKey))
            throw new InvalidOperationException("[AntiScamAI] ApiKey is required.");

        services.AddSingleton(options);

        services.AddHttpClient("AntiScamAI", client =>
        {
            client.BaseAddress = new Uri(options.Endpoint.TrimEnd('/') + "/");
            client.Timeout = TimeSpan.FromMilliseconds(options.TimeoutMs);
            client.DefaultRequestHeaders.Add("X-AntiScam-Key", options.ApiKey);
        });

        services.AddSingleton<AntiScamClient>();

        return services;
    }

    /// <summary>
    /// Adds the AntiScam AI request inspection middleware to the pipeline.
    /// Must be called after UseRouting() and before UseAuthorization().
    ///
    /// <code>
    /// app.UseAntiScamAI();
    /// </code>
    /// </summary>
    public static IApplicationBuilder UseAntiScamAI(this IApplicationBuilder app)
    {
        return app.UseMiddleware<AntiScamMiddleware>();
    }

    /// <summary>
    /// Retrieves the AntiScam AI inspection result from the current HttpContext.
    /// Available to controllers and endpoints after the middleware runs.
    ///
    /// <code>
    /// var result = HttpContext.GetAntiScamResult();
    /// if (result?.Decision == "flag") { /* handle flagged request */ }
    /// </code>
    /// </summary>
    public static SdkInspectResult? GetAntiScamResult(this Microsoft.AspNetCore.Http.HttpContext context)
    {
        return context.Items.TryGetValue("AntiScam", out var value)
            ? value as SdkInspectResult
            : null;
    }
}
