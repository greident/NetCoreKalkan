using KalkanCore.DTO.Kalkan;
using KalkanCore.Services;
using Microsoft.AspNetCore.Mvc;

namespace KalkanCore.MinimalApi;

public static class CryptApi
{
    public static IEndpointRouteBuilder AddCryptApi(this IEndpointRouteBuilder endpoints)
    {
      
        endpoints.MapPost("crypt/SignXml", ([FromBody] SignXmlDto dto, ICryptService cryptService) =>
            {
                var response = cryptService.SignXml(dto.Xml);

                return Results.Text(response);
            })
            .WithName("Калкан подпись SignXml")
            .WithOpenApi();

        endpoints.MapPost("crypt/SignWsse", (SignWsseDto dto, ICryptService cryptService) =>
            {
                var response = cryptService.SignWsse(dto.MessageBody, dto.MessageId);

                return Results.Text(response);
            })
            .WithName("Калкан подпись Soap 1 только тело")
            .WithOpenApi();

        endpoints.MapPost("crypt/SignWsseRaw", (SignWsseRawDto dto, ICryptService cryptService) =>
            {
                var response = cryptService.SignWsseRaw(dto.Envelope, dto.MessageId);

                return Results.Text(response);
            })
            .WithName("Калкан подпись xml с envelope тэгом")
            .WithOpenApi();

        endpoints.MapPost("crypt/verify/xml", (VerifyDto dto, ICryptService cryptService) =>
            {
                var response = cryptService.Verify(dto);
                return Results.Ok(response);
            })
            .WithName("Калкан верификация xml")
            .WithOpenApi();

        endpoints.MapPost("crypt/verify/xml/base64", (VerifyBase64Dto dto, ICryptService cryptService) =>
            {
                var response = cryptService.VerifyBase64(dto);
                return Results.Ok(response);
            })
            .WithName("Калкан верификация xml base64")
            .WithOpenApi();
        
        return endpoints;
    }
}