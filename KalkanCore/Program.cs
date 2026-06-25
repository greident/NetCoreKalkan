using KalkanCore.Extensions.Startup;
using KalkanCore.MinimalApi;

var builder = WebApplication.CreateBuilder(args);

builder.AddHttpClientExtensions();

builder.Services.AddEndpointsApiExplorer();

builder.AddIoC();

builder.Services.AddOpenApi(options =>
{
    //options.OpenApiVersion = OpenApiSpecVersion.OpenApi2_0;
});

builder.AddOption();

builder.WebHost.ConfigureKestrel(options =>
{
    options.AllowSynchronousIO = true;
});

var app = builder.Build();



app.AddCryptApi();

app.MapOpenApi();
app.MapScalarUi();

app.UseRouting();

app.Run();
