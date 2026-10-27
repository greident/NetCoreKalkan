using CryptCore.Pki;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.Security;
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

    // ---- revoked -------------------------------------------------------------
    // No revoked NCA certificate is at hand, but none is needed: OCSP asks about
    // (issuer, serial) and the CRL checker looks the serial up, so a stand-in certificate
    // carrying a serial taken from the real NCA CRL exercises the genuine "revoked" path.

    private const string NcaGost2022Crl = "http://crl.pki.gov.kz/nca_gost_2022.crl";

    // First entry of the real base CRL (held certificates are reported revoked by OCSP too).
    private static readonly Lazy<BigInteger> RevokedSerial = new(() =>
        new X509CrlParser().ReadCrl(Http.GetByteArrayAsync(NcaGost2022Crl).GetAwaiter().GetResult())
            .GetRevokedCertificates().First().SerialNumber);

    /// <summary>A non-CA certificate "issued" by NCA GOST 2022 with the given serial and CDP.</summary>
    private static X509Certificate StandIn(BigInteger serial)
    {
        var rsa = new RsaKeyPairGenerator();
        rsa.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
        var key = rsa.GenerateKeyPair();

        var gen = new X509V3CertificateGenerator();
        gen.SetSerialNumber(serial);
        gen.SetIssuerDN(NcaGost2022().SubjectDN);
        gen.SetSubjectDN(new X509Name("CN=STAND-IN,C=KZ"));
        gen.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        gen.SetNotAfter(DateTime.UtcNow.AddDays(1));
        gen.SetPublicKey(key.Public);
        gen.AddExtension(X509Extensions.CrlDistributionPoints, false, DistributionPoints(NcaGost2022Crl));
        gen.AddExtension(X509Extensions.FreshestCrl, false, DistributionPoints(NcaGost2022DeltaCrl));
        return gen.Generate(new Asn1SignatureFactory("SHA256WITHRSA", key.Private));
    }

    private static CrlDistPoint DistributionPoints(string url)
    {
        var uri = new GeneralName(GeneralName.UniformResourceIdentifier, url);
        return new CrlDistPoint(new[] { new DistributionPoint(new DistributionPointName(new GeneralNames(uri)), null, null) });
    }

    private const string NcaGost2022DeltaCrl = "http://crl.pki.gov.kz/nca_d_gost_2022.crl";

    // A serial revoked after the current base CRL was published: listed in the delta only.
    private static readonly Lazy<BigInteger> RevokedInDeltaOnlySerial = new(() =>
    {
        var delta = new X509CrlParser().ReadCrl(Http.GetByteArrayAsync(NcaGost2022DeltaCrl).GetAwaiter().GetResult());
        return delta.GetRevokedCertificates()
            .First(e => e.GetExtensionValue(X509Extensions.ReasonCode) is not { } r ||
                        Org.BouncyCastle.Asn1.DerEnumerated.GetInstance(
                            Org.BouncyCastle.X509.Extension.X509ExtensionUtilities.FromExtensionValue(r))
                            .IntValueExact != CrlReason.RemoveFromCrl)
            .SerialNumber;
    });

    [LiveFact]
    public void Crl_SerialRevokedInDeltaOnly_IsRevoked()
    {
        var crl = new CrlRevocationChecker(Http);

        Assert.Equal(RevocationStatus.Revoked, crl.Check(StandIn(RevokedInDeltaOnlySerial.Value), NcaGost2022()));
    }

    [LiveFact]
    public void Ocsp_RevokedSerial_IsRevoked()
    {
        var ocsp = new OcspRevocationChecker(Http, "http://ocsp.pki.gov.kz");

        Assert.Equal(RevocationStatus.Revoked, ocsp.Check(StandIn(RevokedSerial.Value), NcaGost2022()));
    }

    [LiveFact]
    public void Crl_RevokedSerial_IsRevoked()
    {
        var crl = new CrlRevocationChecker(Http);

        Assert.Equal(RevocationStatus.Revoked, crl.Check(StandIn(RevokedSerial.Value), NcaGost2022()));
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
