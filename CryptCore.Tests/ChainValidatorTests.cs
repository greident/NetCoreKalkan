using CryptCore.Pki;
using Xunit;

namespace CryptCore.Tests;

/// <summary>
/// Direct tests of <see cref="ChainValidator"/> against the real KZ NCA certificate
/// hierarchy. These are the heart of the trust fix: a genuine NCA certificate must be
/// accepted, while anything that does not chain to a configured root must be rejected.
/// </summary>
public class ChainValidatorTests
{
    // The positive case also exercises the GOST-2015 (Streebog-512) curve parameters in
    // KzGost: if the hardcoded curve set is wrong, the issuer signature on the cert will
    // not verify and the chain will (incorrectly) be rejected. So this test doubles as a
    // canary for the "curve params are best-known" caveat in KzGost.
    [Fact]
    public void TrustsRealNcaCert_WithinValidityWindow()
    {
        var validator = Fixtures.ProductionTrust();
        var mametov = Fixtures.LoadCert(Fixtures.MametovCertPath);

        var result = validator.ValidateChainOnly(mametov, atUtc: Fixtures.MametovValidInstant);

        Assert.True(result.Trusted, result.Error);
        // leaf -> intermediate (NCA GOST 2022) -> root
        Assert.Equal(3, result.Path.Count);
    }

    [Fact]
    public void RejectsRealNcaCert_WhenExpired()
    {
        var validator = Fixtures.ProductionTrust();
        var mametov = Fixtures.LoadCert(Fixtures.MametovCertPath);

        // "now" is well past the cert's Oct-2025 expiry.
        var result = validator.ValidateChainOnly(mametov, atUtc: new DateTime(2026, 5, 31, 0, 0, 0, DateTimeKind.Utc));

        Assert.False(result.Trusted);
        Assert.Contains("validity window", result.Error);
    }

    [Fact]
    public void RejectsCert_FromUntrustedHierarchy()
    {
        // The МАМЕТОВ cert chains to the production root, not the TEST root.
        var validator = Fixtures.TestHierarchyTrust();
        var mametov = Fixtures.LoadCert(Fixtures.MametovCertPath);

        var result = validator.ValidateChainOnly(mametov, atUtc: Fixtures.MametovValidInstant);

        Assert.False(result.Trusted);
    }

    [Fact]
    public void RejectsSelfSignedCert_WithForgedIin()
    {
        // The attack: a self-signed certificate carrying someone else's IIN.
        var validator = Fixtures.ProductionTrust();
        var forged = Fixtures.ForgedSelfSignedKey("850717351069").Certificate;

        var result = validator.ValidateChainOnly(forged);

        Assert.False(result.Trusted);
        Assert.Contains("untrusted", result.Error);
    }

    [Fact]
    public void EmptyTrustStore_IsRejectedAtConstruction()
    {
        // A trust store with no self-signed root cannot anchor anything; fail loudly
        // rather than silently trusting nothing/everything.
        Assert.Throws<ArgumentException>(() => new ChainValidator(Array.Empty<Org.BouncyCastle.X509.X509Certificate>()));
    }
}