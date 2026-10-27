using Xunit;

namespace CryptCore.Tests;

/// <summary>
/// <see cref="KzCryptoService.VerifyCertificate"/> — the x509/info path: parse a
/// certificate and validate it against the NCA trust store (revocation is off here;
/// it is covered by the revocation tests).
/// </summary>
public class CertificateVerificationTests
{
    private static KzCryptoService WithTrust() => new(Fixtures.ForgedSelfSignedKey("000000000000"), Fixtures.ProductionTrust());

    [Fact]
    public void RealNcaCertificate_IsValid_AndParsed()
    {
        var pem = File.ReadAllBytes(Fixtures.MametovCertPath);

        var result = WithTrust().VerifyCertificate(pem, checkRevocation: false, atUtc: Fixtures.MametovValidInstant);

        Assert.True(result.Valid, result.Error);
        var info = Assert.Single(result.Signers);
        Assert.Equal("850717351069", info.SubjectInfo.Iin);
        Assert.Equal("161040017107", info.SubjectInfo.Bin);
        Assert.Equal("GOST-2015", info.KeyAlgorithm);
    }

    [Fact]
    public void DerInput_IsAccepted()
    {
        var der = Fixtures.LoadCert(Fixtures.BekbauovGostCertPath).GetEncoded();

        var result = WithTrust().VerifyCertificate(der, checkRevocation: false, atUtc: Fixtures.BekbauovValidInstant);

        Assert.True(result.Valid, result.Error);
        Assert.Equal("GOST-2004", Assert.Single(result.Signers).KeyAlgorithm);
    }

    [Fact]
    public void ExpiredCertificate_IsInvalid_ButStillParsed()
    {
        var pem = File.ReadAllBytes(Fixtures.MametovCertPath);

        var result = WithTrust().VerifyCertificate(pem, checkRevocation: false);

        Assert.False(result.Valid);
        Assert.Contains("validity window", result.Error);
        Assert.Single(result.Signers);
    }

    [Fact]
    public void ForgedSelfSigned_IsInvalid()
    {
        var forged = Fixtures.ForgedSelfSignedKey("850717351069").Certificate.GetEncoded();

        var result = WithTrust().VerifyCertificate(forged, checkRevocation: false);

        Assert.False(result.Valid);
        Assert.Contains("untrusted", result.Error);
    }

    [Fact]
    public void WithoutTrustStore_IsNotValid()
    {
        var svc = new KzCryptoService(Fixtures.ForgedSelfSignedKey("000000000000"));

        var result = svc.VerifyCertificate(File.ReadAllBytes(Fixtures.MametovCertPath));

        Assert.False(result.Valid);
        Assert.Contains("trust store", result.Error);
        Assert.Single(result.Signers);
    }

    [Fact]
    public void Garbage_IsInvalid()
    {
        var result = WithTrust().VerifyCertificate(Fixtures.Utf8("not a certificate"));

        Assert.False(result.Valid);
        Assert.NotNull(result.Error);
    }
}
