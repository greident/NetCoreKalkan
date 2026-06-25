using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.X509;
using BasicOcspResponseAsn1 = Org.BouncyCastle.Asn1.Ocsp.BasicOcspResponse;

namespace CryptCore.Pki;

/// <summary>
/// RFC 6960 OCSP revocation checker for Kazakhstan NCA certificates (responder at
/// http://ocsp.pki.gov.kz). It posts an OCSP request to the responder named in the
/// certificate's Authority Information Access extension (falling back to a configured
/// default) and reports good / revoked / unknown.
///
/// Two KZ-specific wrinkles are handled here:
///   * The OCSP response for a GOST certificate is itself GOST-signed, so its signature
///     is verified through the same <see cref="KzGost"/> primitives the rest of CryptCore
///     uses — BouncyCastle's <c>BasicOcspResp.Verify</c> only knows RSA/ECDSA OIDs.
///   * The CertID hash algorithm the responder expects is configurable
///     (<see cref="CertIdHashAlgorithm"/>); KZ deployments have used both SHA-256 and SHA-1.
///
/// Network/parse failures and untrusted responses return <see cref="RevocationStatus.Unknown"/>;
/// it is <see cref="ChainValidator"/> that decides whether "unknown" is fatal (fail-closed).
/// </summary>
public sealed class OcspRevocationChecker : IRevocationChecker
{
    public const string Sha256 = "2.16.840.1.101.3.4.2.1";
    private static readonly DerObjectIdentifier IdADOcsp = new("1.3.6.1.5.5.7.48.1");

    private readonly HttpClient _http;
    private readonly string? _defaultResponderUrl;

    /// <summary>OID of the digest used to build the OCSP CertID. Defaults to SHA-256.</summary>
    public string CertIdHashAlgorithm { get; init; } = Sha256;

    /// <param name="http">
    /// HTTP client used to reach the responder. Configure its <see cref="HttpClient.Timeout"/>
    /// to bound how long verification may block.
    /// </param>
    /// <param name="defaultResponderUrl">
    /// Responder URL to use when a certificate carries no AIA OCSP entry
    /// (e.g. "http://ocsp.pki.gov.kz").
    /// </param>
    public OcspRevocationChecker(HttpClient http, string? defaultResponderUrl = null)
    {
        _http = http;
        _defaultResponderUrl = defaultResponderUrl;
    }

    public RevocationStatus Check(X509Certificate cert, X509Certificate issuer)
    {
        try
        {
            var url = ResponderUrl(cert) ?? _defaultResponderUrl;
            if (string.IsNullOrEmpty(url)) return RevocationStatus.Unknown;

            var request = BuildRequest(cert, issuer);
            var responseBytes = Post(url!, request.GetEncoded());

            var resp = new OcspResp(responseBytes);
            if (resp.Status != OcspRespStatus.Successful) return RevocationStatus.Unknown;
            if (resp.GetResponseObject() is not BasicOcspResp basic) return RevocationStatus.Unknown;

            // Trust the response only if it is signed by the CA or by a responder the CA
            // certified. Without this an attacker who can answer HTTP could forge "good".
            if (!VerifyResponse(basic, issuer)) return RevocationStatus.Unknown;

            var single = basic.Responses.FirstOrDefault();
            if (single == null) return RevocationStatus.Unknown;

            var status = single.GetCertStatus();
            if (status == null) return RevocationStatus.Good;     // BouncyCastle: null == good
            if (status is RevokedStatus) return RevocationStatus.Revoked;
            return RevocationStatus.Unknown;                       // UnknownStatus or anything else
        }
        catch
        {
            return RevocationStatus.Unknown;
        }
    }

    // ---- request ------------------------------------------------------------

    private OcspReq BuildRequest(X509Certificate cert, X509Certificate issuer)
    {
        var gen = new OcspReqGenerator();
        gen.AddRequest(new CertificateID(CertIdHashAlgorithm, issuer, cert.SerialNumber));
        return gen.Generate();
    }

    private byte[] Post(string url, byte[] der)
    {
        using var content = new ByteArrayContent(der);
        content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/ocsp-request");
        using var resp = _http.PostAsync(url, content).GetAwaiter().GetResult();
        resp.EnsureSuccessStatusCode();
        return resp.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult();
    }

    // ---- response trust -----------------------------------------------------

    private static bool VerifyResponse(BasicOcspResp basic, X509Certificate issuer)
    {
        // The signer is either the issuing CA itself or a responder certificate the CA
        // signed and embedded in the response.
        var responder = basic.GetCerts().FirstOrDefault();

        if (responder != null && !IsIssuedBy(responder, issuer))
            return false; // embedded responder not vouched for by the CA
        var signerCert = responder ?? issuer;

        var asn1 = BasicOcspResponseAsn1.GetInstance(Asn1Object.FromByteArray(basic.GetEncoded()));
        if (KzGost.IsGostAny(asn1.SignatureAlgorithm.Algorithm))
            return VerifyGostResponse(asn1, signerCert);

        try { return basic.Verify(signerCert.GetPublicKey()); }
        catch { return false; }
    }

    private static bool VerifyGostResponse(BasicOcspResponseAsn1 asn1, X509Certificate signerCert)
    {
        try
        {
            var tbs = asn1.TbsResponseData.GetEncoded(Asn1Encodable.Der);
            var sig = asn1.Signature.GetBytes();
            var alg = asn1.SignatureAlgorithm.Algorithm;
            var pub = KzGost.DecodePublicKey(signerCert.CertificateStructure.SubjectPublicKeyInfo);

            return GostVerify(pub, tbs, sig, alg) || GostVerify(pub, tbs, Reversed(sig), alg);
        }
        catch
        {
            return false;
        }
    }

    private static bool GostVerify(ECPublicKeyParameters pub, byte[] data, byte[] sig, DerObjectIdentifier alg)
    {
        try
        {
            var signer = new Gost3410DigestSigner(KzGost.CreateSigner(alg), KzGost.CreateDigest(alg));
            signer.Init(false, pub);
            signer.BlockUpdate(data, 0, data.Length);
            return signer.VerifySignature(sig);
        }
        catch
        {
            return false;
        }
    }

    private static bool IsIssuedBy(X509Certificate subject, X509Certificate issuer)
    {
        if (!subject.IssuerDN.Equivalent(issuer.SubjectDN)) return false;
        var sigAlg = subject.CertificateStructure.SignatureAlgorithm.Algorithm;
        if (KzGost.IsGostAny(sigAlg))
        {
            try
            {
                var pub = KzGost.DecodePublicKey(issuer.CertificateStructure.SubjectPublicKeyInfo);
                var tbs = subject.GetTbsCertificate();
                var sig = subject.GetSignature();
                return GostVerify(pub, tbs, sig, sigAlg) || GostVerify(pub, tbs, Reversed(sig), sigAlg);
            }
            catch { return false; }
        }
        try { subject.Verify(issuer.GetPublicKey()); return true; }
        catch { return false; }
    }

    // ---- AIA ----------------------------------------------------------------

    private static string? ResponderUrl(X509Certificate cert)
    {
        var ext = cert.GetExtensionValue(X509Extensions.AuthorityInfoAccess);
        if (ext == null) return null;
        try
        {
            var aia = AuthorityInformationAccess.GetInstance(
                Asn1Object.FromByteArray(((Asn1OctetString)ext).GetOctets()));
            foreach (var ad in aia.GetAccessDescriptions())
            {
                if (!ad.AccessMethod.Equals(IdADOcsp)) continue;
                var loc = ad.AccessLocation;
                if (loc.TagNo == GeneralName.UniformResourceIdentifier)
                    return DerIA5String.GetInstance(loc.Name).GetString();
            }
        }
        catch { /* malformed AIA -> no URL */ }
        return null;
    }

    private static byte[] Reversed(byte[] b)
    {
        var r = (byte[])b.Clone();
        Array.Reverse(r);
        return r;
    }
}