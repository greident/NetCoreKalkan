using KalkanCore.Services;

namespace KalkanCore.Extensions.Startup;

public static class IocExtension
{
    public static void AddIoC(this WebApplicationBuilder builder)
    {
        // Provider selection (CryptOption:Provider): "CryptCore" (pure-managed,
        // ARM-friendly) or "Mock". Defaults to Mock in Development, CryptCore otherwise.
        var provider = builder.Configuration["CryptOption:Provider"]
                       ?? (builder.Environment.IsDevelopment() ? "Mock" : "CryptCore");

        if (provider.Equals("Mock", StringComparison.OrdinalIgnoreCase))
            builder.Services.AddScoped<ICryptService, MockCryptService>();
        else
            builder.Services.AddSingleton<ICryptService, CryptCoreCryptService>();
    }
}