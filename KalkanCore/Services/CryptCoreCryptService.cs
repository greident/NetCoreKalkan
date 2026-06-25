using System.Text;
using System.Web;
using CryptCore;
using CryptCore.Models;
using CryptCore.Pki;
using KalkanCore.BaseOptions;
using KalkanCore.DTO.Kalkan;
using Microsoft.Extensions.Options;

namespace KalkanCore.Services;

/// <summary>
/// <see cref="ICryptService"/> backed by the pure-managed <c>CryptCore</c>
/// library instead of the native Kalkan provider. Works on ARM (and anywhere)
/// because it carries no native dependency. Drop-in replacement for
/// <see cref="CryptService"/>; select it via configuration (CryptOption:Provider).
/// </summary>
public class CryptCoreCryptService : ICryptService
{
    private readonly ILogger<CryptCoreCryptService> _logger;
    private readonly KzCryptoService _crypto;

    // Shared client for OCSP requests; bounded timeout so verification never blocks long.
    private static readonly HttpClient OcspHttp = new() { Timeout = TimeSpan.FromSeconds(10) };

    public CryptCoreCryptService(IOptions<KalkanOption> options, ILogger<CryptCoreCryptService> logger)
    {
        _logger = logger;
        var opt = options.Value;

        ChainValidator? trust = null;
        if (!string.IsNullOrWhiteSpace(opt.CaCertsPath) && Directory.Exists(opt.CaCertsPath))
        {
            // OCSP responder is only consulted when the caller passes ValidateOcsp=true
            // (see Verify); building the checker here is cheap and stateless.
            var ocsp = new OcspRevocationChecker(OcspHttp, opt.OcspResponderUrl);
            trust = ChainValidator.FromPemDirectory(opt.CaCertsPath, ocsp);
            _logger.LogInformation(
                "Загружен trust-store НУЦ РК из {Path}; проверка цепочки включена, OCSP-ответчик: {Url}.",
                opt.CaCertsPath, opt.OcspResponderUrl ?? "из AIA сертификата");
        }
        else
        {
            _logger.LogWarning(
                "CaCertsPath не задан или не найден — проверка цепочки сертификатов ОТКЛЮЧЕНА. " +
                "Подпись будет приниматься от любого (в т.ч. самоподписанного) сертификата.");
        }

        _crypto = KzCryptoService.FromPkcs12(opt.Path, opt.Key, trust);
    }

    public string SignXml(string messageBody)
        => _crypto.SignXml(HttpUtility.HtmlDecode(messageBody));

    public string SignWsse(SignWsseDto dto) => SignWsse(dto.MessageBody, dto.MessageId);

    public string SignWsse(string messageBody, string messageId)
        => _crypto.SignWsse(messageBody, messageId);

    public string SignWsseRaw(SignWsseRawDto dto) => SignWsseRaw(dto.Envelope, dto.MessageId);

    public string SignWsseRaw(string envelope, string messageId)
        => _crypto.SignWsseRaw(envelope, messageId);

    public VerifyResultDto Verify(VerifyDto dto)
    {
        var xml = HttpUtility.HtmlDecode(dto.Xml);
        return Map(SafeVerify(xml, dto.ValidateOcsp));
    }

    public VerifyResultDto VerifyBase64(VerifyBase64Dto dto)
    {
        var xml = Encoding.UTF8.GetString(dto.XmlData);
        return Map(SafeVerify(xml, dto.ValidateOcsp));
    }

    private VerifyResult SafeVerify(string xml, bool checkRevocation)
    {
        try
        {
            return _crypto.VerifyXml(xml, checkRevocation);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Ошибка при проверке подписи XML (CryptCore).");
            return new VerifyResult { Valid = false, Error = ex.Message };
        }
    }

    private static VerifyResultDto Map(VerifyResult result)
    {
        var dto = new VerifyResultDto { IsValid = result.Valid };
        var signer = result.Signers.FirstOrDefault();
        if (signer != null)
        {
            dto.CertInfo = new CertificateInfoDto
            {
                NotBefore = signer.NotBefore,
                NotAfter = signer.NotAfter,
                SerialNumber = signer.SerialNumber,
                SubjectInfo = new CertificationSubjectInfoDto
                {
                    Iin = signer.SubjectInfo.Iin,
                    Bin = signer.SubjectInfo.Bin,
                    FirstName = signer.SubjectInfo.FirstName,
                    MiddleName = signer.SubjectInfo.MiddleName,
                    LastName = signer.SubjectInfo.LastName,
                    Email = signer.SubjectInfo.Email,
                    OrganizationName = signer.SubjectInfo.OrganizationName
                }
            };
        }
        return dto;
    }
}
