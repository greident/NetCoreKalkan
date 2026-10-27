namespace KalkanCore.DTO.Kalkan;

public record SignXmlDto(string Xml);
public record SignWsseDto(string MessageBody, string MessageId);
public record SignWsseRawDto(string Envelope, string MessageId);
public record VerifyDto(string Xml, bool ValidateOcsp);
public record VerifyBase64Dto(byte[] XmlData, bool ValidateOcsp);
public record VerifyWsseDto(string Envelope, bool ValidateOcsp);
public record SignCmsDto(byte[] Data, bool Detached);
public record VerifyCmsDto(byte[] Cms, byte[]? Data, bool ValidateOcsp);

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