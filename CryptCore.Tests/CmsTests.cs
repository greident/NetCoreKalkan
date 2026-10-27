using Xunit;

namespace CryptCore.Tests;

/// <summary>
/// CMS sign/verify/extract round trips (RSA key from <see cref="Fixtures"/>; the GOST
/// primitives are shared with XML/WSSE and covered there and by the chain tests).
/// </summary>
public class CmsTests
{
    private static readonly KzCryptoService Svc = new(Fixtures.ForgedSelfSignedKey("111111111111"));
    private static readonly byte[] Data = Fixtures.Utf8("pay 100 to 850717351069");

    [Fact]
    public void Attached_RoundTrip_IsValid()
    {
        Assert.True(Svc.VerifyCms(Svc.SignCms(Data)).Valid);
    }

    [Fact]
    public void Detached_WithData_IsValid()
    {
        var cms = Svc.SignCms(Data, detached: true);

        Assert.True(Svc.VerifyCms(cms, Data).Valid);
    }

    [Fact]
    public void Detached_WithOtherData_IsInvalid()
    {
        var cms = Svc.SignCms(Data, detached: true);

        var result = Svc.VerifyCms(cms, Fixtures.Utf8("pay 100 000 to 850717351069"));

        Assert.False(result.Valid);
        Assert.Contains("messageDigest", result.Error);
    }

    [Fact]
    public void Detached_WithoutData_IsInvalid()
    {
        // Without content only the signed attributes can be checked, which says nothing
        // about *what* was signed: stripping the content from any genuine CMS must not
        // turn it into a "valid" signature over whatever the caller has at hand.
        var cms = Svc.SignCms(Data, detached: true);

        var result = Svc.VerifyCms(cms);

        Assert.False(result.Valid);
        Assert.Contains("content", result.Error);
    }

    // ---- interop with Kalkan-produced CMS -----------------------------------
    // NCA timestamp tokens are CMS SignedData signed by the NCA's own Kalkan stack, so they
    // pin our byte conventions to the real thing (a self round trip cannot: it would pass
    // with any convention as long as sign and verify agree).

    [Fact]
    public void NcaGostCms_Verifies()
    {
        var result = CryptCore.Signing.CmsService.Verify(Fixtures.NcaTstGost2015, checkRevocation: false);

        Assert.True(result.Valid, result.Error);
        Assert.Equal("GOST-2015", Assert.Single(result.Signers).KeyAlgorithm);
    }

    [Fact]
    public void NcaRsaCms_Verifies()
    {
        var result = CryptCore.Signing.CmsService.Verify(Fixtures.NcaTstRsa2022, checkRevocation: false);

        Assert.True(result.Valid, result.Error);
        Assert.Equal("RSA", Assert.Single(result.Signers).KeyAlgorithm);
    }

    [Fact]
    public void Extract_Attached_ReturnsContent()
    {
        Assert.Equal(Data, Svc.ExtractCms(Svc.SignCms(Data)));
    }

    [Fact]
    public void Extract_Detached_ReturnsNull()
    {
        Assert.Null(Svc.ExtractCms(Svc.SignCms(Data, detached: true)));
    }
}
