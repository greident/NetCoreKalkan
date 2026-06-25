namespace CryptCore.Models;

/// <summary>Subject information extracted from a Kazakhstan NCA certificate.</summary>
public class CertSubjectInfo
{
    public string? Iin { get; set; }
    public string? Bin { get; set; }
    public string? FirstName { get; set; }
    public string? MiddleName { get; set; }
    public string? LastName { get; set; }
    public string? Email { get; set; }
    public string? OrganizationName { get; set; }
    /// <summary>Full common name (CN), e.g. "МАМЕТОВ ДАУЛЕТ".</summary>
    public string? CommonName { get; set; }
}

/// <summary>Parsed certificate metadata + KZ subject fields.</summary>
public class CertificateInfo
{
    public DateTime NotBefore { get; set; }
    public DateTime NotAfter { get; set; }
    public string SerialNumber { get; set; } = "";
    public string Issuer { get; set; } = "";
    public string Subject { get; set; } = "";
    /// <summary>Algorithm family: "RSA", "GOST-2004" or "GOST-2015".</summary>
    public string KeyAlgorithm { get; set; } = "";
    public CertSubjectInfo SubjectInfo { get; set; } = new();
}

/// <summary>Result of a signature verification.</summary>
public class VerifyResult
{
    public bool Valid { get; set; }
    public string? Error { get; set; }
    public List<CertificateInfo> Signers { get; set; } = new();
}

public enum DataFormat
{
    Der,
    Pem,
    Base64
}
