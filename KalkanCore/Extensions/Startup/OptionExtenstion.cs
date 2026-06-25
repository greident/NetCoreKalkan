
using KalkanCore.BaseOptions;

namespace KalkanCore.Extensions.Startup;

public static class OptionExtenstion
{
    public static void AddOption(this WebApplicationBuilder builder)
    {
        builder.Services.AddOptions<KalkanOption>()
            .Bind(builder.Configuration.GetSection("KalkanOption"))
            .ValidateDataAnnotations()
            .ValidateOnStart();

        builder.Services.AddOptions<AppOptions>()
            .Bind(builder.Configuration.GetSection("AppOptions"))
            .ValidateDataAnnotations()
            .ValidateOnStart();
    }
}