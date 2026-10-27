using CryptCore.Pki;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.X509;
using Xunit;

namespace CryptCore.Tests;

/// <summary>A [Fact] that only runs when KZ_LIVE_PKI=1 (it needs ocsp/crl.pki.gov.kz).</summary>
public sealed class LiveFactAttribute : FactAttribute
{
    public LiveFactAttribute()
    {
        if (Environment.GetEnvironmentVariable("KZ_LIVE_PKI") != "1")
            Skip = "Live NCA PKI test: set KZ_LIVE_PKI=1 to run against ocsp.pki.gov.kz / crl.pki.gov.kz.";
    }
}

/// <summary>
/// Integration tests against the real NCA responders. Not part of CI (network). Run:
/// <c>KZ_LIVE_PKI=1 dotnet test --filter LivePkiTests</c>
///
/// The МАМЕТОВ certificate is expired but was never revoked, and the NCA still answers
/// for it, so "good" is the expected status on both OCSP and CRL.
/// </summary>
public class LivePkiTests
{
    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(120) };

    private static X509Certificate Mametov() => Fixtures.LoadCert(Fixtures.MametovCertPath);
    private static X509Certificate NcaGost2022() => Fixtures.LoadCert(Path.Combine(Fixtures.CaCertsDir, "nca_gost_2022.pem"));
    private static X509Certificate RootGost2022() => Fixtures.LoadCert(Path.Combine(Fixtures.CaCertsDir, "root_gost_2022.pem"));

    [LiveFact]
    public void Ocsp_Leaf_IsGood_WithSha256CertId()
    {
        var ocsp = new OcspRevocationChecker(Http);

        Assert.Equal(RevocationStatus.Good, ocsp.Check(Mametov(), NcaGost2022()));
    }

    [LiveFact]
    public void Ocsp_Leaf_IsGood_WithSha1CertId()
    {
        var ocsp = new OcspRevocationChecker(Http) { CertIdHashAlgorithm = CertificateID.HashSha1 };

        Assert.Equal(RevocationStatus.Good, ocsp.Check(Mametov(), NcaGost2022()));
    }

    [LiveFact]
    public void Crl_IssuingCa_IsGood_FromRootCrl()
    {
        // Small (~0.5 KB) GOST-signed root CRL: exercises the GOST CRL signature check.
        var crl = new CrlRevocationChecker(Http);

        Assert.Equal(RevocationStatus.Good, crl.Check(NcaGost2022(), RootGost2022()));
    }

    [LiveFact]
    public void Crl_Leaf_IsGood_FromNcaCrl()
    {
        // ~20 MB end-entity CRL: the OCSP-outage fallback path.
        var crl = new CrlRevocationChecker(Http);

        Assert.Equal(RevocationStatus.Good, crl.Check(Mametov(), NcaGost2022()));
    }

    [LiveFact]
    public void FullChain_WithOcspThenCrl_IsTrusted()
    {
        var revocation = new CompositeRevocationChecker(
            new OcspRevocationChecker(Http, "http://ocsp.pki.gov.kz"),
            new CrlRevocationChecker(Http));
        var validator = ChainValidator.FromPemDirectory(Fixtures.CaCertsDir, revocation);

        var result = validator.Validate(Mametov(), atUtc: Fixtures.MametovValidInstant);

        Assert.True(result.Trusted, result.Error);
    }
}
