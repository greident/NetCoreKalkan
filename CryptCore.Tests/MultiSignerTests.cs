using System.Xml;
using CryptCore.Signing;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Xunit;

namespace CryptCore.Tests;

/// <summary>Several signers on one CMS or XML document.</summary>
public class MultiSignerTests
{
    private static readonly CryptCore.Pki.SigningKey AliceKey = Fixtures.ForgedSelfSignedKey("111111111111");
    private static readonly CryptCore.Pki.SigningKey BobKey = Fixtures.ForgedSelfSignedKey("222222222222");
    private static readonly KzCryptoService Alice = new(AliceKey);
    private static readonly KzCryptoService Bob = new(BobKey);
    private static readonly byte[] Data = Fixtures.Utf8("contract #42");

    private static string[] Iins(CryptCore.Models.VerifyResult r) => r.Signers.Select(s => s.SubjectInfo.Iin!).ToArray();

    // ---- CMS -----------------------------------------------------------------

    [Fact]
    public void Cms_TwoKeysAtOnce_BothVerify()
    {
        var keys = new[] { AliceKey, BobKey };

        var result = CmsService.Verify(CmsService.Sign(keys, Data));

        Assert.True(result.Valid, result.Error);
        Assert.Equal(new[] { "111111111111", "222222222222" }, Iins(result).Order());
    }

    [Fact]
    public void Cms_AddSigner_KeepsTheFirstSignerUntouched()
    {
        var first = Alice.SignCms(Data);

        var both = Bob.AddCmsSigner(first);

        var result = Alice.VerifyCms(both);
        Assert.True(result.Valid, result.Error);
        // SignerInfos is a DER SET OF (sorted by encoding): compare as sets, not by position.
        Assert.Equal(new[] { "111111111111", "222222222222" }, Iins(result).Order());
        Assert.Contains(Assert.Single(SignerInfos(first)), SignerInfos(both));
    }

    [Fact]
    public void Cms_AddSigner_ToDetached_NeedsTheData()
    {
        var first = Alice.SignCms(Data, detached: true);

        Assert.Throws<ArgumentException>(() => Bob.AddCmsSigner(first));
        var both = Bob.AddCmsSigner(first, Data);
        Assert.True(Alice.VerifyCms(both, Data).Valid);
    }

    [Fact]
    public void Cms_AddSigner_WithOtherData_Throws()
    {
        Assert.Throws<ArgumentException>(() => Bob.AddCmsSigner(Alice.SignCms(Data), Fixtures.Utf8("contract #43")));
    }

    // ---- XML -----------------------------------------------------------------

    private const string Xml = "<doc><amount>100</amount></doc>";

    [Fact]
    public void Xml_SignedTwice_BothVerify_InSigningOrder()
    {
        var both = Bob.SignXml(Alice.SignXml(Xml));

        var result = Alice.VerifyXml(both);

        Assert.True(result.Valid, result.Error);
        Assert.Equal(new[] { "111111111111", "222222222222" }, Iins(result));
    }

    [Fact]
    public void Xml_SignedTwice_TamperedContent_IsInvalid()
    {
        var both = Bob.SignXml(Alice.SignXml(Xml)).Replace("<amount>100</amount>", "<amount>900</amount>");

        Assert.False(Alice.VerifyXml(both).Valid);
    }

    [Fact]
    public void Xml_SignedTwice_FirstSignatureRemoved_IsInvalid()
    {
        // The second signature covers the first; dropping the first must break the second.
        var doc = new XmlDocument { PreserveWhitespace = true };
        doc.LoadXml(Bob.SignXml(Alice.SignXml(Xml)));
        var first = doc.GetElementsByTagName("Signature", "http://www.w3.org/2000/09/xmldsig#")[0]!;
        first.ParentNode!.RemoveChild(first);

        var result = Alice.VerifyXml(doc.OuterXml);

        Assert.False(result.Valid);
    }

    // ---- helpers -------------------------------------------------------------

    private static string[] SignerInfos(byte[] cms)
        => SignedData.GetInstance(ContentInfo.GetInstance(Asn1Object.FromByteArray(cms)).Content).SignerInfos
            .Cast<Asn1Encodable>().Select(s => Convert.ToBase64String(s.GetEncoded())).ToArray();
}
