namespace KalkanCore.DTO.Kalkan;

/// <summary>
/// Ключ подписи из запроса вместо ключа сервиса: .p12 (base64 в JSON), пароль и — если в
/// хранилище несколько ключей — алиас (см. crypt/pkcs12/aliases). Ключ живёт только в
/// памяти на время запроса и никуда не пишется.
/// </summary>
public record SignerKeyDto(byte[] P12, string Password, string? Alias = null);

/// <param name="Signers">Подписанты по порядку; пусто — ключ сервиса. Подпись уже подписанного
/// XML дописывает ещё одну ds:Signature (прежние сохраняются).</param>
public record SignXmlDto(string Xml, List<SignerKeyDto>? Signers = null);
public record SignWsseDto(string MessageBody, string MessageId, SignerKeyDto? Key = null);
public record SignWsseRawDto(string Envelope, string MessageId, SignerKeyDto? Key = null);
public record VerifyDto(string Xml, bool ValidateOcsp);
public record VerifyBase64Dto(byte[] XmlData, bool ValidateOcsp);
public record VerifyWsseDto(string Envelope, bool ValidateOcsp);

/// <param name="Signers">Подписанты; пусто — ключ сервиса.</param>
/// <param name="WithTsp">Добавить к каждой подписи метку времени НУЦ (RFC 3161).</param>
public record SignCmsDto(byte[] Data, bool Detached, List<SignerKeyDto>? Signers = null, bool WithTsp = false);

/// <param name="Data">Подписанные данные — обязательны для отсоединённой CMS.</param>
public record AddCmsSignersDto(byte[] Cms, byte[]? Data, List<SignerKeyDto>? Signers = null, bool WithTsp = false);
public record VerifyCmsDto(byte[] Cms, byte[]? Data, bool ValidateOcsp);

public record Pkcs12Dto(byte[] P12, string Password, bool ValidateOcsp = false);

/// <summary>Ключ из .p12: алиас + проверка его сертификата (как crypt/x509/info).</summary>
public class Pkcs12KeyInfoDto : VerifyResultDto
{
    public string Alias { get; set; }
}

/// <param name="Certificate">Сертификат: DER (base64 в JSON) или PEM-текст в байтах.</param>
/// <param name="At">Момент проверки срока действия (UTC); по умолчанию — сейчас.</param>
public record VerifyCertificateDto(byte[] Certificate, bool ValidateOcsp, DateTime? At = null);

public class VerifyResultDto
{
    public bool IsValid { get; set; }

    /// <summary>Причина отказа (крипто, цепочка, срок, отзыв); null при успехе.</summary>
    public string? Error { get; set; }

    /// <summary>Первый подписант (совместимость со старым контрактом).</summary>
    public CertificateInfoDto CertInfo { get; set; }

    /// <summary>Все подписанты (CMS может содержать несколько).</summary>
    public List<CertificateInfoDto> Signers { get; set; } = new();
}

public class CmsExtractResultDto : VerifyResultDto
{
    /// <summary>Подписанные данные; доверять им можно только при <see cref="VerifyResultDto.IsValid"/>.</summary>
    public byte[]? Data { get; set; }
}

public class CertificateInfoDto
{
    public bool IsArhive { get; set; }
    public DateTime NotBefore { get; set; }
    public DateTime NotAfter { get; set; }
    public string SerialNumber { get; set; }
    public string Issuer { get; set; }
    /// <summary>"RSA", "GOST-2004" или "GOST-2015".</summary>
    public string KeyAlgorithm { get; set; }
    /// <summary>Время подписи по проверенной метке TSA (только CMS); null — метки нет.</summary>
    public DateTime? TimestampUtc { get; set; }
    public CertificationSubjectInfoDto SubjectInfo { get; set; }
}

public class CertificationSubjectInfoDto
{
    public string Iin  { get; set; }
    public string Bin  { get; set; }
    public string FirstName { get; set; }
    public string MiddleName { get; set; }
    public string LastName { get; set; }
    public string Email { get; set; }
    public string OrganizationName { get; set; }
}