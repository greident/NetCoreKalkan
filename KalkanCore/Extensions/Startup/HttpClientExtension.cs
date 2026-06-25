
namespace KalkanCore.Extensions.Startup;

public static class HttpClientExtension
{
    public const string AppClient = nameof(AppClient);
    public static void AddHttpClientExtensions(this WebApplicationBuilder builder)
    {
        builder.Services.AddHttpClient(AppClient, client =>
        {
            client.Timeout = TimeSpan.FromMinutes(5); // Оптимальное время ожидания
        });
    }
}