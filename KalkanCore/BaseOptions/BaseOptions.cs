namespace KalkanCore.BaseOptions;

public class AppOptions
{
    public string SenderId { get; set; }
    public string Password { get; set; }
    public string ConnectionUrl { get; set; }
    public string ConnectionWss { get; set; }
    public string ConnectionUrlProd { get; set; }
    public string ProxyConnectionWss { get; set; }
}

public class KalkanOption
{
    public string Path { get; init; }
    public string Key { get; init; }
    public string Url { get; set; }

    /// <summary>
    /// Directory of trusted NCA root/intermediate PEM certificates (pki.gov.kz).
    /// When set, incoming signatures are only accepted if the signer chains to one of
    /// these roots. Leave empty to disable chain validation (NOT recommended in prod).
    /// </summary>
    public string? CaCertsPath { get; init; }

    /// <summary>
    /// Fallback OCSP responder URL (e.g. "http://ocsp.pki.gov.kz") used when a certificate
    /// carries no AIA OCSP entry. Only consulted for requests with ValidateOcsp=true.
    /// </summary>
    public string? OcspResponderUrl { get; init; }
}