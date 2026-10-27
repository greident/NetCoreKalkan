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
    private readonly bool _requireRevocation;

    // Shared client for OCSP requests; bounded timeout so verification never blocks long.
    private static readonly HttpClient OcspHttp = new() { Timeout = TimeSpan.FromSeconds(10) };

    // CRLs: the end-entity CRL is ~20 MB, but it is fetched at most once per publication (cached).
    private static readonly HttpClient CrlHttp = new() { Timeout = TimeSpan.FromSeconds(60) };

    public CryptCoreCryptService(IOptions<KalkanOption> options, ILogger<CryptCoreCryptService> logger)
    {
        _logger = logger;
        var opt = options.Value;

        ChainValidator? trust = null;
        if (!string.IsNullOrWhiteSpace(opt.CaCertsPath) && Directory.Exists(opt.CaCertsPath))
        {
            // Revocation is consulted when the caller passes ValidateOcsp=true or the server
            // enforces it (RequireRevocationCheck, see Revocation). OCSP first; CRL covers the
            // issuing CAs (no OCSP responder) and OCSP outages.
            var revocation = new CompositeRevocationChecker(
                new OcspRevocationChecker(OcspHttp, opt.OcspResponderUrl),
                new CrlRevocationChecker(CrlHttp));
            trust = ChainValidator.FromPemDirectory(opt.CaCertsPath, revocation);
            _requireRevocation = opt.RequireRevocationCheck;
            _logger.LogInformation(
                "Загружен trust-store НУЦ РК из {Path}; проверка цепочки включена, отзыв: OCSP ({Url}) → CRL, {Mode}.",
                opt.CaCertsPath, opt.OcspResponderUrl ?? "из AIA сертификата",
                _requireRevocation ? "всегда" : "по флагу ValidateOcsp запроса");
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
        return Map(SafeVerify("XML", () => _crypto.VerifyXml(xml, Revocation(dto.ValidateOcsp))));
    }

    public VerifyResultDto VerifyBase64(VerifyBase64Dto dto)
    {
        var xml = Encoding.UTF8.GetString(dto.XmlData);
        return Map(SafeVerify("XML", () => _crypto.VerifyXml(xml, Revocation(dto.ValidateOcsp))));
    }

    public VerifyResultDto VerifyWsse(VerifyWsseDto dto)
        => Map(SafeVerify("WSSE", () => _crypto.VerifyWsse(dto.Envelope, Revocation(dto.ValidateOcsp))));

    public byte[] SignCms(SignCmsDto dto) => _crypto.SignCms(dto.Data, dto.Detached);

    public VerifyResultDto VerifyCms(VerifyCmsDto dto)
        => Map(SafeVerify("CMS", () => _crypto.VerifyCms(dto.Cms, dto.Data, Revocation(dto.ValidateOcsp))));

    // The request's ValidateOcsp flag can turn revocation on, never off when the server requires it.
    private bool Revocation(bool requested) => requested || _requireRevocation;

    private VerifyResult SafeVerify(string format, Func<VerifyResult> verify)
    {
        try
        {
            return verify();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Ошибка при проверке подписи {Format} (CryptCore).", format);
            return new VerifyResult { Valid = false, Error = ex.Message };
        }
    }

    private static VerifyResultDto Map(VerifyResult result)
    {
        var dto = new VerifyResultDto { IsValid = result.Valid, Error = result.Error };
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
