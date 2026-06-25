using CryptCore.Pki;
using Org.BouncyCastle.X509;
using Xunit;

namespace CryptCore.Tests;

/// <summary>
/// Tests that <see cref="ChainValidator"/> enforces revocation correctly. A fake
/// <see cref="IRevocationChecker"/> is used so the behaviour is deterministic and
/// needs no network — the real OCSP wire format is covered by integration testing
/// against ocsp.pki.gov.kz, which cannot run in CI.
/// </summary>
public class RevocationTests
{
    private sealed class FakeChecker(RevocationStatus status) : IRevocationChecker
    {
        public int Calls { get; private set; }
        public RevocationStatus Check(X509Certificate cert, X509Certificate issuer)
        {
            Calls++;
            return status;
        }
    }

    private static ChainValidator TrustWith(IRevocationChecker checker, bool failOnUnknown = true)
        => ChainValidator.FromPemDirectory(Fixtures.CaCertsDir, checker, failOnUnknown);

    private static X509Certificate Mametov() => Fixtures.LoadCert(Fixtures.MametovCertPath);

    [Fact]
    public void RevokedCertificate_IsRejected()
    {
        var validator = TrustWith(new FakeChecker(RevocationStatus.Revoked));

        var result = validator.Validate(Mametov(), atUtc: Fixtures.MametovValidInstant);

        Assert.False(result.Trusted);
        Assert.Contains("revoked", result.Error);
    }

    [Fact]
    public void GoodCertificate_IsAccepted()
    {
        var validator = TrustWith(new FakeChecker(RevocationStatus.Good));

        var result = validator.Validate(Mametov(), atUtc: Fixtures.MametovValidInstant);

        Assert.True(result.Trusted, result.Error);
    }

    [Fact]
    public void UnknownStatus_IsRejected_WhenFailClosed()
    {
        var validator = TrustWith(new FakeChecker(RevocationStatus.Unknown), failOnUnknown: true);

        var result = validator.Validate(Mametov(), atUtc: Fixtures.MametovValidInstant);

        Assert.False(result.Trusted);
        Assert.Contains("could not be determined", result.Error);
    }

    [Fact]
    public void UnknownStatus_IsTolerated_WhenSoftFail()
    {
        var validator = TrustWith(new FakeChecker(RevocationStatus.Unknown), failOnUnknown: false);

        var result = validator.Validate(Mametov(), atUtc: Fixtures.MametovValidInstant);

        Assert.True(result.Trusted, result.Error);
    }

    [Fact]
    public void Revocation_IsSkipped_WhenCheckRevocationFalse()
    {
        var checker = new FakeChecker(RevocationStatus.Revoked);
        var validator = TrustWith(checker);

        // checkRevocation:false must short-circuit the (otherwise revoking) checker.
        var result = validator.Validate(Mametov(), atUtc: Fixtures.MametovValidInstant, checkRevocation: false);

        Assert.True(result.Trusted, result.Error);
        Assert.Equal(0, checker.Calls);
    }
}
