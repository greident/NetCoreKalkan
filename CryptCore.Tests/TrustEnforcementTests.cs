using Xunit;

namespace CryptCore.Tests;

/// <summary>
/// End-to-end tests proving the trust store actually gates <see cref="KzCryptoService"/>'s
/// Verify* path — and demonstrating the vulnerability it closes: without a trust store,
/// a self-signed certificate with a forged IIN verifies as valid.
/// </summary>
public class TrustEnforcementTests
{
    private const string Xml = "<doc><payload>hello</payload></doc>";

    [Fact]
    public void Vulnerability_ForgedSelfSignedSignature_VerifiesValid_WithoutTrustStore()
    {
        // Attacker signs with a self-signed cert carrying a forged IIN.
        var attacker = new KzCryptoService(Fixtures.ForgedSelfSignedKey("850717351069"));
        var signed = attacker.SignXml(Xml);

        // No trust store configured -> only the math is checked -> it passes. This is the
        // pre-fix behaviour and the reason ChainValidator exists.
        var result = attacker.VerifyXml(signed);

        Assert.True(result.Valid);
    }

    [Fact]
    public void Fix_ForgedSelfSignedSignature_IsRejected_WithTrustStore()
    {
        var attacker = new KzCryptoService(Fixtures.ForgedSelfSignedKey("850717351069"));
        var signed = attacker.SignXml(Xml);

        // A verifier configured with the NCA trust store rejects it: the signer does not
        // chain to any trusted root, even though the signature is cryptographically sound.
        var verifier = new KzCryptoService(Fixtures.ForgedSelfSignedKey("000000000000"), Fixtures.ProductionTrust());
        var result = verifier.VerifyXml(signed);

        Assert.False(result.Valid);
        // The signer info is still surfaced for diagnostics/logging.
        Assert.NotEmpty(result.Signers);
    }
}