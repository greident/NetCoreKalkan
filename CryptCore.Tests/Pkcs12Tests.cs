using CryptCore.Pki;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Xunit;

namespace CryptCore.Tests;

/// <summary>
/// <see cref="Pkcs12Loader"/>: aliases and key selection (the pkcs12/aliases and
/// pkcs12/info paths, and signing with a key passed in a request). Stores are built with
/// BouncyCastle's standard writer, i.e. friendlyName + localKeyId bag attributes.
/// </summary>
public class Pkcs12Tests
{
    private const string Password = "Qwerty12";

    private static byte[] Store(params (string Alias, string Iin)[] entries)
    {
        var store = new Pkcs12StoreBuilder().Build();
        foreach (var (alias, iin) in entries)
        {
            var key = Fixtures.ForgedSelfSignedKey(iin);
            store.SetKeyEntry(alias, new AsymmetricKeyEntry(key.PrivateKey), new[] { new X509CertificateEntry(key.Certificate) });
        }
        using var ms = new MemoryStream();
        store.Save(ms, Password.ToCharArray(), new SecureRandom());
        return ms.ToArray();
    }

    [Fact]
    public void List_ReturnsEveryKeyWithItsCertificate()
    {
        var p12 = Store(("first", "111111111111"), ("second", "222222222222"));

        var entries = Pkcs12Loader.List(p12, Password);

        Assert.Equal(new[] { "first", "second" }, entries.Select(e => e.Alias).OrderBy(a => a));
        Assert.Equal("222222222222",
            CertificateInfoParser.Parse(entries.Single(e => e.Alias == "second").Certificate).SubjectInfo.Iin);
    }

    [Fact]
    public void Load_ByAlias_PicksThatKey()
    {
        var p12 = Store(("first", "111111111111"), ("second", "222222222222"));

        var key = Pkcs12Loader.Load(p12, Password, "second");

        Assert.Equal("222222222222", CertificateInfoParser.Parse(key.Certificate).SubjectInfo.Iin);
        // The private key really belongs to the certificate: a signature verifies against it.
        var svc = new KzCryptoService(key);
        Assert.True(svc.VerifyCms(svc.SignCms(Fixtures.Utf8("x"))).Valid);
    }

    [Fact]
    public void Load_SeveralKeysWithoutAlias_Throws()
    {
        var p12 = Store(("first", "111111111111"), ("second", "222222222222"));

        var e = Assert.Throws<InvalidOperationException>(() => Pkcs12Loader.Load(p12, Password));
        Assert.Contains("alias", e.Message);
    }

    [Fact]
    public void Load_SingleKey_NeedsNoAlias()
    {
        var key = Pkcs12Loader.Load(Store(("only", "333333333333")), Password);

        Assert.Equal("333333333333", CertificateInfoParser.Parse(key.Certificate).SubjectInfo.Iin);
    }

    [Fact]
    public void Load_UnknownAlias_Throws()
    {
        Assert.Throws<InvalidOperationException>(() => Pkcs12Loader.Load(Store(("only", "333333333333")), Password, "nope"));
    }

    [Fact]
    public void WrongPassword_Throws()
    {
        Assert.ThrowsAny<Exception>(() => Pkcs12Loader.List(Store(("only", "333333333333")), "wrong"));
    }
}
