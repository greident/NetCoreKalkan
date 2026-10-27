using System.Collections.Concurrent;
using System.Security.Cryptography;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.X509;
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
///     (<see cref="CertIdHashAlgorithm"/>); ocsp.pki.gov.kz accepts both SHA-256 and SHA-1.
///
/// OCSP runs over plain HTTP, so a response is only believed if it is signed by the CA or
/// by a delegated responder the CA certified for OCSP signing, is about the certificate
/// that was asked about, and is fresh — echoing the request nonce, or (if the responder
/// drops it) produced within <see cref="MaxResponseAge"/>. Definite answers are cached
/// for <see cref="CacheTtl"/> so verification does not hit the responder on every request.
///
/// Network/parse failures and untrusted responses return <see cref="RevocationStatus.Unknown"/>;
/// it is <see cref="ChainValidator"/> that decides whether "unknown" is fatal (fail-closed).
/// </summary>
public sealed class OcspRevocationChecker : IRevocationChecker
{
    public const string Sha256 = "2.16.840.1.101.3.4.2.1";
    private static readonly DerObjectIdentifier IdADOcsp = new("1.3.6.1.5.5.7.48.1");
    private static readonly TimeSpan ClockSkew = TimeSpan.FromMinutes(5);
    private const int MaxCacheEntries = 10_000;

    private readonly HttpClient _http;
    private readonly string? _defaultResponderUrl;
    private readonly TimeProvider _time;
    private readonly ConcurrentDictionary<string, (RevocationStatus Status, DateTime ExpiresUtc)> _cache = new();

    /// <summary>OID of the digest used to build the OCSP CertID. Defaults to SHA-256.</summary>
    public string CertIdHashAlgorithm { get; init; } = Sha256;

    /// <summary>
    /// How long a good/revoked answer is reused (capped by the response's nextUpdate, if any).
    /// The NCA responder sends no nextUpdate, so this is the effective revocation latency.
    /// Zero disables caching.
    /// </summary>
    public TimeSpan CacheTtl { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Oldest acceptable thisUpdate when the responder does not echo the request nonce —
    /// the replay window for a captured response.
    /// </summary>
    public TimeSpan MaxResponseAge { get; init; } = TimeSpan.FromMinutes(10);

    /// <param name="http">
    /// HTTP client used to reach the responder. Configure its <see cref="HttpClient.Timeout"/>
    /// to bound how long verification may block.
    /// </param>
    /// <param name="defaultResponderUrl">
    /// Responder URL to use when a certificate carries no AIA OCSP entry
    /// (e.g. "http://ocsp.pki.gov.kz").
    /// </param>
    /// <param name="time">Clock used for freshness and caching; defaults to the system clock.</param>
    public OcspRevocationChecker(HttpClient http, string? defaultResponderUrl = null, TimeProvider? time = null)
    {
        _http = http;
        _defaultResponderUrl = defaultResponderUrl;
        _time = time ?? TimeProvider.System;
    }

    public RevocationStatus Check(X509Certificate cert, X509Certificate issuer)
    {
        try
        {
            var url = ResponderUrl(cert);
            // NCA issuing CAs carry no AIA OCSP entry and ocsp.pki.gov.kz rejects queries for
            // them (malformedRequest); their status comes from the root's CRL instead, so don't
            // waste a round trip on the default responder.
            if (url == null && cert.GetBasicConstraints() >= 0) return RevocationStatus.Unknown;
            url ??= _defaultResponderUrl;
            if (string.IsNullOrEmpty(url)) return RevocationStatus.Unknown;

            var now = _time.GetUtcNow().UtcDateTime;
            var key = CacheKey(cert, issuer);
            if (_cache.TryGetValue(key, out var hit) && now < hit.ExpiresUtc) return hit.Status;

            var nonce = RandomNumberGenerator.GetBytes(16);
            var request = BuildRequest(cert, issuer, nonce);
            var responseBytes = Post(url!, request.GetEncoded());

            var resp = new OcspResp(responseBytes);
            if (resp.Status != OcspRespStatus.Successful) return RevocationStatus.Unknown;
            if (resp.GetResponseObject() is not BasicOcspResp basic) return RevocationStatus.Unknown;

            // Trust the response only if it is signed by the CA or by a responder the CA
            // certified. Without this an attacker who can answer HTTP could forge "good".
            if (!VerifyResponse(basic, issuer, now)) return RevocationStatus.Unknown;
            if (!IsFresh(basic, nonce, now)) return RevocationStatus.Unknown;

            // A validly signed response about some *other* certificate must not count.
            var single = basic.Responses.FirstOrDefault(r =>
                r.GetCertID().SerialNumber.Equals(cert.SerialNumber) && r.GetCertID().MatchesIssuer(issuer));
            if (single == null) return RevocationStatus.Unknown;
            if (single.ThisUpdate > now + ClockSkew) return RevocationStatus.Unknown;
            if (single.NextUpdate is { } next && next < now) return RevocationStatus.Unknown;

            var status = single.GetCertStatus() switch
            {
                null => RevocationStatus.Good,               // BouncyCastle: null == good
                RevokedStatus => RevocationStatus.Revoked,
                _ => RevocationStatus.Unknown,                // UnknownStatus or anything else
            };
            if (status != RevocationStatus.Unknown) Remember(key, status, now, single.NextUpdate);
            return status;
        }
        catch
        {
            return RevocationStatus.Unknown;
        }
    }

    // ---- request ------------------------------------------------------------

    private OcspReq BuildRequest(X509Certificate cert, X509Certificate issuer, byte[] nonce)
    {
        var gen = new OcspReqGenerator();
        gen.AddRequest(new CertificateID(CertIdHashAlgorithm, issuer, cert.SerialNumber));
        gen.SetRequestExtensions(new X509Extensions(new Dictionary<DerObjectIdentifier, X509Extension>
        {
            [OcspObjectIdentifiers.PkixOcspNonce] = new(false, new DerOctetString(new DerOctetString(nonce).GetEncoded())),
        }));
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

    // ---- freshness + cache ----------------------------------------------------

    /// <summary>
    /// The response must echo our nonce; a responder that drops it is tolerated (RFC 8954),
    /// but then the response must be recent, which bounds how long a captured one replays.
    /// </summary>
    private bool IsFresh(BasicOcspResp basic, byte[] nonce, DateTime now)
    {
        var echoed = basic.GetExtensionValue(OcspObjectIdentifiers.PkixOcspNonce);
        if (echoed != null)
            return Asn1OctetString.GetInstance(echoed.GetOctets()).GetOctets().AsSpan().SequenceEqual(nonce);
        return basic.ProducedAt >= now - MaxResponseAge && basic.ProducedAt <= now + ClockSkew;
    }

    private static string CacheKey(X509Certificate cert, X509Certificate issuer)
        => Convert.ToHexString(SHA256.HashData(issuer.GetEncoded())) + ":" + cert.SerialNumber.ToString(16);

    private void Remember(string key, RevocationStatus status, DateTime now, DateTime? nextUpdate)
    {
        if (CacheTtl <= TimeSpan.Zero) return;
        var expires = now + CacheTtl;
        if (nextUpdate is { } next && next < expires) expires = next;

        if (_cache.Count >= MaxCacheEntries)
            foreach (var (k, v) in _cache)
                if (v.ExpiresUtc <= now) _cache.TryRemove(k, out _);
        if (_cache.Count < MaxCacheEntries) _cache[key] = (status, expires);
    }

    // ---- response trust -----------------------------------------------------

    private static bool VerifyResponse(BasicOcspResp basic, X509Certificate issuer, DateTime now)
    {
        // The signer is either the issuing CA itself or a responder certificate the CA
        // signed and embedded in the response.
        var responder = basic.GetCerts().FirstOrDefault();

        if (responder != null && !IsAuthorizedResponder(responder, issuer, now))
            return false; // embedded responder not vouched for by the CA
        var signerCert = responder ?? issuer;

        var asn1 = BasicOcspResponseAsn1.GetInstance(Asn1Object.FromByteArray(basic.GetEncoded()));
        var alg = asn1.SignatureAlgorithm.Algorithm;
        if (KzGost.IsGostAny(alg))
            return KzGost.VerifyEitherOrientation(
                signerCert.CertificateStructure.SubjectPublicKeyInfo,
                asn1.TbsResponseData.GetEncoded(Asn1Encodable.Der), asn1.Signature.GetBytes(), alg);

        try { return basic.Verify(signerCert.GetPublicKey()); }
        catch { return false; }
    }

    /// <summary>
    /// RFC 6960 §4.2.2.2: a delegated responder must be issued by the CA *and* carry the
    /// id-kp-OCSPSigning EKU. Without the EKU check, the holder of any ordinary NCA
    /// certificate could sign a "good" answer for a revoked certificate.
    /// </summary>
    private static bool IsAuthorizedResponder(X509Certificate responder, X509Certificate issuer, DateTime now)
    {
        if (responder.Equals(issuer)) return true;
        if (now < responder.NotBefore.ToUniversalTime() || now > responder.NotAfter.ToUniversalTime()) return false;
        if (responder.GetExtendedKeyUsage()?.Contains(KeyPurposeID.id_kp_OCSPSigning) != true) return false;
        return IsIssuedBy(responder, issuer);
    }

    private static bool IsIssuedBy(X509Certificate subject, X509Certificate issuer)
    {
        if (!subject.IssuerDN.Equivalent(issuer.SubjectDN)) return false;
        var sigAlg = subject.CertificateStructure.SignatureAlgorithm.Algorithm;
        if (KzGost.IsGostAny(sigAlg))
            return KzGost.VerifyEitherOrientation(
                issuer.CertificateStructure.SubjectPublicKeyInfo, subject.GetTbsCertificate(), subject.GetSignature(), sigAlg);
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
}
