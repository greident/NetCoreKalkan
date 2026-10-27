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
