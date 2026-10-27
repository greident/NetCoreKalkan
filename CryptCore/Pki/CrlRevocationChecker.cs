using System.Collections.Concurrent;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;

namespace CryptCore.Pki;

/// <summary>
/// CRL revocation checker for Kazakhstan NCA certificates. Downloads the CRL named in
/// the certificate's CRL Distribution Points extension (e.g.
/// http://crl.pki.gov.kz/nca_gost_2022.crl), verifies that the issuer signed it and that
/// it is still current, and reports good / revoked / unknown.
///
/// Where it matters on the NCA hierarchy:
///   * Issuing CAs (nca_gost_2022, nca_rsa, ...) have no OCSP responder at all — their
///     status is published only in the root's CRL (crl.root.gov.kz, a few hundred bytes).
///   * End-entity CRLs are large (~20 MB, refreshed daily), so they serve as the fallback
///     when OCSP is unreachable; see <see cref="CompositeRevocationChecker"/>.
///
/// Each CRL is cached in memory until its nextUpdate, as a set of revoked serials, so a
/// download happens at most once per publication. A CRL past its nextUpdate, signed by
/// another key or not fetchable yields <see cref="RevocationStatus.Unknown"/>; it is
/// <see cref="ChainValidator"/> that decides whether "unknown" is fatal (fail-closed).
///
/// Delta CRLs (nca_d_*.crl) are not consulted: a revocation made after the base CRL was
/// published becomes visible here only with the next base CRL (up to ~1 day later).
/// </summary>
public sealed class CrlRevocationChecker : IRevocationChecker
{
    private readonly HttpClient _http;
    private readonly TimeProvider _time;
    private readonly ConcurrentDictionary<string, CachedCrl> _cache = new();
    private readonly ConcurrentDictionary<string, object> _locks = new();

    private sealed record CachedCrl(HashSet<BigInteger> Revoked, DateTime? NextUpdateUtc);

    /// <param name="http">
    /// HTTP client used to fetch CRLs. End-entity CRLs are large, so give it a timeout
    /// generous enough for a ~20 MB download.
    /// </param>
    /// <param name="time">Clock used for CRL freshness; defaults to the system clock.</param>
    public CrlRevocationChecker(HttpClient http, TimeProvider? time = null)
    {
        _http = http;
        _time = time ?? TimeProvider.System;
    }

    public RevocationStatus Check(X509Certificate cert, X509Certificate issuer)
    {
        foreach (var url in DistributionPoints(cert))
        {
            var crl = GetCrl(url, issuer);
            if (crl == null) continue; // try the next distribution point, if any
            return crl.Revoked.Contains(cert.SerialNumber) ? RevocationStatus.Revoked : RevocationStatus.Good;
        }
        return RevocationStatus.Unknown;
    }

    // ---- fetch + cache ------------------------------------------------------

    private CachedCrl? GetCrl(string url, X509Certificate issuer)
    {
        if (_cache.TryGetValue(url, out var cached) && IsCurrent(cached)) return cached;

        // One download per URL at a time: concurrent verifications wait for the same fetch
        // instead of each pulling the (large) CRL.
        lock (_locks.GetOrAdd(url, _ => new object()))
        {
            if (_cache.TryGetValue(url, out cached) && IsCurrent(cached)) return cached;
            _cache.TryRemove(url, out _);

            var fresh = Download(url, issuer);
            if (fresh != null && IsCurrent(fresh)) _cache[url] = fresh;
            return fresh != null && IsCurrent(fresh) ? fresh : null;
        }
    }

    private CachedCrl? Download(string url, X509Certificate issuer)
    {
        try
        {
            var bytes = _http.GetByteArrayAsync(url).GetAwaiter().GetResult();
            var crl = new X509CrlParser().ReadCrl(bytes);
            if (crl == null) return null;

            // Trust the CRL only if it comes from the certificate's issuer. Without this an
            // attacker who can answer HTTP could serve an empty list.
            if (!crl.IssuerDN.Equivalent(issuer.SubjectDN) || !IsSignedBy(crl, issuer)) return null;

            var revoked = new HashSet<BigInteger>();
            foreach (var entry in crl.GetRevokedCertificates() ?? new HashSet<X509CrlEntry>())
                revoked.Add(entry.SerialNumber);

            return new CachedCrl(revoked, crl.NextUpdate?.ToUniversalTime());
        }
        catch
        {
            return null;
        }
    }

    private bool IsCurrent(CachedCrl crl)
        => crl.NextUpdateUtc == null || _time.GetUtcNow().UtcDateTime <= crl.NextUpdateUtc;

    // ---- CRL trust ----------------------------------------------------------

    private static bool IsSignedBy(X509Crl crl, X509Certificate issuer)
    {
        var alg = new DerObjectIdentifier(crl.SigAlgOid);
        if (KzGost.IsGostAny(alg))
            return KzGost.VerifyEitherOrientation(
                issuer.CertificateStructure.SubjectPublicKeyInfo, crl.GetTbsCertList(), crl.GetSignature(), alg);

        try { crl.Verify(issuer.GetPublicKey()); return true; }
        catch { return false; }
    }

    // ---- CDP ----------------------------------------------------------------

    private static IEnumerable<string> DistributionPoints(X509Certificate cert)
    {
        var ext = cert.GetExtensionValue(X509Extensions.CrlDistributionPoints);
        if (ext == null) yield break;

        CrlDistPoint cdp;
        try { cdp = CrlDistPoint.GetInstance(X509ExtensionUtilities.FromExtensionValue(ext)); }
        catch { yield break; } // malformed CDP -> no URL

        foreach (var dp in cdp.GetDistributionPoints())
        {
            if (dp.DistributionPointName?.Type != DistributionPointName.FullName) continue;
            foreach (var name in GeneralNames.GetInstance(dp.DistributionPointName.Name).GetNames())
            {
                if (name.TagNo != GeneralName.UniformResourceIdentifier) continue;
                var url = DerIA5String.GetInstance(name.Name).GetString();
                if (url.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
                    url.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                    yield return url;
            }
        }
    }
}
