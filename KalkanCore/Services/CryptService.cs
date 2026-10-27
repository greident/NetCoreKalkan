using System.Text;
using System.Text.Json;
using KalkanCore.BaseOptions;
using KalkanCore.DTO.Kalkan;
using Microsoft.Extensions.Options;

namespace KalkanCore.Services;

public interface ICryptService
{
    string SignWsse(SignWsseDto dto);
    string SignWsse(string messageBody, string messageId);
    string SignWsseRaw(SignWsseRawDto dto);
    string SignWsseRaw(string envelope, string messageId);
    string SignXml(string messageBody);
    VerifyResultDto Verify(VerifyDto dto);
    VerifyResultDto VerifyBase64(VerifyBase64Dto dto);
    VerifyResultDto VerifyWsse(VerifyWsseDto dto);
    byte[] SignCms(SignCmsDto dto);
    VerifyResultDto VerifyCms(VerifyCmsDto dto);
}

public class MockCryptService : ICryptService
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly KalkanOption _options;

    public MockCryptService(IHttpClientFactory httpClientFactory, IOptions<KalkanOption> options)
    {
        _httpClientFactory = httpClientFactory;
        _options = options.Value;
    }

    public string SignWsse(SignWsseDto dto) => SignWsse(dto.MessageBody, dto.MessageId);

    public string SignWsse(string messageBody, string messageId)
    {
        var client = _httpClientFactory.CreateClient(nameof(MockCryptService));

        var dto = new SignWsseDto(messageBody, messageId);

        var request = new HttpRequestMessage
        {
            Method = HttpMethod.Post,
            Content = new StringContent(JsonSerializer.Serialize(dto), Encoding.UTF8, "application/json"),
            RequestUri = new Uri($"{_options.Url}/crypt/SignWsse"),
        };
        using var response = client.Send(request);
        response.EnsureSuccessStatusCode();
        return response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
    }

    public string SignWsseRaw(SignWsseRawDto dto) => SignWsseRaw(dto.Envelope, dto.MessageId);

    public string SignWsseRaw(string envelope, string messageId)
    {
        var client = _httpClientFactory.CreateClient(nameof(MockCryptService));

        var dto = new SignWsseRawDto(envelope, messageId);

        var request = new HttpRequestMessage
        {
            Method = HttpMethod.Post,
            Content = new StringContent(JsonSerializer.Serialize(dto), Encoding.UTF8, "application/json"),
            RequestUri = new Uri($"{_options.Url}/crypt/SignWsseRaw"),
        };
        using var response = client.Send(request);

        response.EnsureSuccessStatusCode();
        return response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
    }

    public string SignXml(string messageBody)
    {
        var client = _httpClientFactory.CreateClient(nameof(MockCryptService));

        var request = new HttpRequestMessage
        {
            Method = HttpMethod.Post,
            RequestUri = new Uri($"{_options.Url}/crypt/SignXml"),
            Content = new StringContent(JsonSerializer.Serialize(new SignXmlDto(messageBody)), Encoding.UTF8, "application/json"),
        };
        using var response = client.Send(request);
        response.EnsureSuccessStatusCode();
        return response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
    }

    VerifyResultDto ICryptService.Verify(VerifyDto dto)
    {
        throw new NotImplementedException();
    }

    public VerifyResultDto VerifyBase64(VerifyBase64Dto dto)
    {
        throw new NotImplementedException();
    }

    public VerifyResultDto VerifyWsse(VerifyWsseDto dto)
    {
        throw new NotImplementedException();
    }

    public byte[] SignCms(SignCmsDto dto)
    {
        throw new NotImplementedException();
    }

    public VerifyResultDto VerifyCms(VerifyCmsDto dto)
    {
        throw new NotImplementedException();
    }

    public string Verify(VerifyDto dto)
    {
        var client = _httpClientFactory.CreateClient(nameof(MockCryptService));

        var request = new HttpRequestMessage
        {
            Method = HttpMethod.Post,
            RequestUri = new Uri($"{_options.Url}/crypt/verify/xml"),
            Content = new StringContent(JsonSerializer.Serialize(dto), Encoding.UTF8, "application/json"),
        };

        using var response = client.Send(request);
        response.EnsureSuccessStatusCode();
        return response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
    }

    public string VerifyCert()
    {
        throw new NotImplementedException();
    }
}
