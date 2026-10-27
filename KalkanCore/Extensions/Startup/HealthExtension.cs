using KalkanCore.Services;
using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace KalkanCore.Extensions.Startup;

public static class HealthExtension
{
    public static void AddHealth(this WebApplicationBuilder builder)
    {
        builder.Services.AddHealthChecks().AddCheck<CryptServiceHealthCheck>("crypt");
    }

    public static void MapHealth(this WebApplication app)
    {
        app.MapHealthChecks("/health");
    }
}

/// <summary>
/// Healthy once the crypt service can be built: the signing key loads and the trust store
/// parses. The service is constructed lazily on first use, so without this a missing .p12
/// or a wrong password surfaces only on the first real request.
/// </summary>
public class CryptServiceHealthCheck(IServiceProvider services) : IHealthCheck
{
    public Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        try
        {
            using var scope = services.CreateScope();
            scope.ServiceProvider.GetRequiredService<ICryptService>();
            return Task.FromResult(HealthCheckResult.Healthy());
        }
        catch (Exception ex)
        {
            return Task.FromResult(HealthCheckResult.Unhealthy("Сервис подписи не инициализирован.", ex));
        }
    }
}
