using System.Text;
using CryptCore;
using CryptCore.Models;
using CryptCore.Pki;
using CryptCore.Signing;
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
    private readonly SigningKey _key;
    private readonly TspClient _tsa;
    private readonly bool _requireRevocation;

    // TSA requests are small and quick; keep the wait bounded.
    private static readonly HttpClient TspHttp = new() { Timeout = TimeSpan.FromSeconds(20) };

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
                new OcspRevocationChecker(OcspHttp, opt.OcspResponderUrl)
                {
                    CacheTtl = TimeSpan.FromMinutes(opt.OcspCacheMinutes),
                },
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

        _key = Pkcs12Loader.Load(opt.Path, opt.Key);
        _crypto = new KzCryptoService(_key, trust);
        _tsa = new TspClient(TspHttp, opt.TspUrl);
    }

    // XML is taken exactly as sent (raw, as NCANode does). It used to be HTML-decoded first,
    // which turned &amp;/&lt; in the data into broken XML and escaped text into real elements.
    public string SignXml(string messageBody)
        => _crypto.SignXml(messageBody);

    public string SignXml(SignXmlDto dto)
        // Each signer appends its ds:Signature over the document as signed so far.
        => Keys(dto.Signers).Aggregate(dto.Xml, (xml, key) => XmlDsigService.Sign(key, xml));

    public string SignWsse(SignWsseDto dto) => WsseService.Sign(Key(dto.Key), dto.MessageBody, dto.MessageId);

    public string SignWsse(string messageBody, string messageId)
        => _crypto.SignWsse(messageBody, messageId);

    public string SignWsseRaw(SignWsseRawDto dto) => WsseService.SignRaw(Key(dto.Key), dto.Envelope, dto.MessageId);

    public string SignWsseRaw(string envelope, string messageId)
        => _crypto.SignWsseRaw(envelope, messageId);

    public byte[] SignCms(SignCmsDto dto)
        => CmsService.Sign(Keys(dto.Signers), dto.Data, dto.Detached, dto.WithTsp ? _tsa : null);

    public byte[] AddCmsSigners(AddCmsSignersDto dto)
        => CmsService.AddSigners(dto.Cms, Keys(dto.Signers), dto.Data, dto.WithTsp ? _tsa : null);

    public List<string> Pkcs12Aliases(Pkcs12Dto dto)
        => Pkcs12Loader.List(dto.P12, dto.Password).Select(e => e.Alias).ToList();

    public List<Pkcs12KeyInfoDto> Pkcs12Info(Pkcs12Dto dto)
        => Pkcs12Loader.List(dto.P12, dto.Password)
            .Select(e =>
            {
                var info = Map(SafeVerify("PKCS12", () =>
                    _crypto.VerifyCertificate(e.Certificate.GetEncoded(), Revocation(dto.ValidateOcsp))), new Pkcs12KeyInfoDto());
                info.Alias = e.Alias;
                return info;
            })
            .ToList();

    /// <summary>The request's key if it carries one, else the service key.</summary>
    private SigningKey Key(SignerKeyDto? key) => key == null ? _key : Pkcs12Loader.Load(key.P12, key.Password, key.Alias);

    private IReadOnlyList<SigningKey> Keys(List<SignerKeyDto>? signers)
        => signers is { Count: > 0 } ? signers.Select(Key).ToList() : new[] { _key };

    public VerifyResultDto Verify(VerifyDto dto)
        => Map(SafeVerify("XML", () => _crypto.VerifyXml(dto.Xml, Revocation(dto.ValidateOcsp))));

    public VerifyResultDto VerifyBase64(VerifyBase64Dto dto)
    {
        var xml = Encoding.UTF8.GetString(dto.XmlData);
        return Map(SafeVerify("XML", () => _crypto.VerifyXml(xml, Revocation(dto.ValidateOcsp))));
    }

    public VerifyResultDto VerifyWsse(VerifyWsseDto dto)
        => Map(SafeVerify("WSSE", () => _crypto.VerifyWsse(dto.Envelope, Revocation(dto.ValidateOcsp))));

    public VerifyResultDto VerifyCms(VerifyCmsDto dto)
        => Map(SafeVerify("CMS", () => _crypto.VerifyCms(dto.Cms, dto.Data, Revocation(dto.ValidateOcsp))));

    public CmsExtractResultDto ExtractCms(VerifyCmsDto dto)
    {
        // Data comes back only together with the verdict on it, never on its own.
        var result = Map(SafeVerify("CMS", () => _crypto.VerifyCms(dto.Cms, dto.Data, Revocation(dto.ValidateOcsp))),
            new CmsExtractResultDto());
        try { result.Data = dto.Data ?? _crypto.ExtractCms(dto.Cms); }
        catch { /* malformed CMS: the verdict already says why */ }
        return result;
    }

    public VerifyResultDto VerifyCertificate(VerifyCertificateDto dto)
        => Map(SafeVerify("X.509", () => _crypto.VerifyCertificate(dto.Certificate, Revocation(dto.ValidateOcsp), dto.At)));

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

    private static VerifyResultDto Map(VerifyResult result) => Map(result, new VerifyResultDto());

    private static T Map<T>(VerifyResult result, T dto) where T : VerifyResultDto
    {
        dto.IsValid = result.Valid;
        dto.Error = result.Error;
        dto.Signers = result.Signers.Select(MapCert).ToList();
        dto.CertInfo = dto.Signers.FirstOrDefault()!;
        return dto;
    }

    private static CertificateInfoDto MapCert(CertificateInfo signer) => new()
    {
        NotBefore = signer.NotBefore,
        NotAfter = signer.NotAfter,
        SerialNumber = signer.SerialNumber,
        Issuer = signer.Issuer,
        KeyAlgorithm = signer.KeyAlgorithm,
        TimestampUtc = signer.TimestampUtc,
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
