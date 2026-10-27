using KalkanCore.DTO.Kalkan;
using KalkanCore.Services;
using Microsoft.AspNetCore.Mvc;

namespace KalkanCore.MinimalApi;

public static class CryptApi
{
    public static IEndpointRouteBuilder AddCryptApi(this IEndpointRouteBuilder endpoints)
    {
      
        endpoints.MapPost("crypt/SignXml", ([FromBody] SignXmlDto dto, ICryptService cryptService) =>
                Guard(() => Results.Text(cryptService.SignXml(dto))))
            .WithName("Калкан подпись SignXml")
            .WithOpenApi();

        endpoints.MapPost("crypt/SignWsse", (SignWsseDto dto, ICryptService cryptService) =>
                Guard(() => Results.Text(cryptService.SignWsse(dto))))
            .WithName("Калкан подпись Soap 1 только тело")
            .WithOpenApi();

        endpoints.MapPost("crypt/SignWsseRaw", (SignWsseRawDto dto, ICryptService cryptService) =>
                Guard(() => Results.Text(cryptService.SignWsseRaw(dto))))
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

        endpoints.MapPost("crypt/verify/wsse", (VerifyWsseDto dto, ICryptService cryptService) =>
            {
                var response = cryptService.VerifyWsse(dto);
                return Results.Ok(response);
            })
            .WithName("Калкан верификация Soap WSSE")
            .WithOpenApi();

        endpoints.MapPost("crypt/cms/sign", (SignCmsDto dto, ICryptService cryptService) =>
                Guard(() => Results.Text(Convert.ToBase64String(cryptService.SignCms(dto)))))
            .WithName("Калкан подпись CMS (base64)")
            .WithOpenApi();

        endpoints.MapPost("crypt/cms/sign/add", (AddCmsSignersDto dto, ICryptService cryptService) =>
                Guard(() => Results.Text(Convert.ToBase64String(cryptService.AddCmsSigners(dto)))))
            .WithName("Калкан добавить подписантов в CMS (base64)")
            .WithOpenApi();

        endpoints.MapPost("crypt/pkcs12/aliases", (Pkcs12Dto dto, ICryptService cryptService) =>
                Guard(() => Results.Ok(cryptService.Pkcs12Aliases(dto))))
            .WithName("Калкан алиасы ключей в .p12")
            .WithOpenApi();

        endpoints.MapPost("crypt/pkcs12/info", (Pkcs12Dto dto, ICryptService cryptService) =>
                Guard(() => Results.Ok(cryptService.Pkcs12Info(dto))))
            .WithName("Калкан ключи .p12 с проверкой сертификатов")
            .WithOpenApi();

        endpoints.MapPost("crypt/cms/verify", (VerifyCmsDto dto, ICryptService cryptService) =>
            {
                var response = cryptService.VerifyCms(dto);
                return Results.Ok(response);
            })
            .WithName("Калкан верификация CMS")
            .WithOpenApi();

        endpoints.MapPost("crypt/cms/extract", (VerifyCmsDto dto, ICryptService cryptService) =>
            {
                var response = cryptService.ExtractCms(dto);
                return Results.Ok(response);
            })
            .WithName("Калкан данные из CMS с проверкой подписи")
            .WithOpenApi();

        endpoints.MapPost("crypt/x509/info", (VerifyCertificateDto dto, ICryptService cryptService) =>
            {
                var response = cryptService.VerifyCertificate(dto);
                return Results.Ok(response);
            })
            .WithName("Калкан информация и проверка сертификата")
            .WithOpenApi();

        return endpoints;
    }

    /// <summary>
    /// Bad input — a wrong .p12 password, an unknown alias, a detached CMS without its data —
    /// is the caller's to fix: 400 with the reason. An unreachable TSA is an upstream failure: 502.
    /// </summary>
    private static IResult Guard(Func<IResult> action)
    {
        try
        {
            return action();
        }
        catch (HttpRequestException ex)
        {
            return Results.Problem(ex.Message, statusCode: StatusCodes.Status502BadGateway);
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or NotSupportedException
                                       or IOException or Org.BouncyCastle.Crypto.CryptoException)
        {
            return Results.Problem(ex.Message, statusCode: StatusCodes.Status400BadRequest);
        }
    }
}