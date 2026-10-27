using CryptCore.Pki;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Xunit;

namespace CryptCore.Tests;

/// <summary>
/// Tests that <see cref="ChainValidator"/> only lets CA certificates issue, and only lets
/// signing-capable keys sign. The attack it closes: anyone can obtain an ordinary NCA
/// certificate, use its key to issue a certificate with someone else's IIN/BIN, and embed
/// both in a CMS message — every signature in "forged → own NCA cert → NCA → root" is
/// mathematically sound, so without basicConstraints/keyUsage checks the forgery is trusted.
///
/// A synthetic RSA hierarchy stands in for the NCA (no NCA private key is available);
/// the checks are algorithm-independent.
/// </summary>
public class CaConstraintTests
{
    private static readonly SecureRandom Rng = new();
    private static readonly DateTime Now = DateTime.UtcNow;

    private sealed record Issued(X509Certificate Cert, AsymmetricCipherKeyPair Key);

    private static AsymmetricCipherKeyPair NewRsa()
    {
        var gen = new RsaKeyPairGenerator();
        gen.Init(new KeyGenerationParameters(Rng, 2048));
        return gen.GenerateKeyPair();
    }

    private static Issued Issue(string subject, Issued? issuer, BasicConstraints? bc, int? keyUsage)
    {
        var key = NewRsa();
        var subjectDn = new X509Name(subject);
        var gen = new X509V3CertificateGenerator();
        gen.SetSerialNumber(BigInteger.ValueOf(Rng.NextInt() & int.MaxValue));
        gen.SetIssuerDN(issuer?.Cert.SubjectDN ?? subjectDn);
        gen.SetSubjectDN(subjectDn);
        gen.SetNotBefore(Now.AddDays(-1));
        gen.SetNotAfter(Now.AddYears(1));
        gen.SetPublicKey(key.Public);
        if (bc != null) gen.AddExtension(X509Extensions.BasicConstraints, true, bc);
        if (keyUsage != null) gen.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(keyUsage.Value));
        var signer = (issuer?.Key ?? key).Private;
        return new Issued(gen.Generate(new Asn1SignatureFactory("SHA256WITHRSA", signer, Rng)), key);
    }

    private const int CaUsage = KeyUsage.KeyCertSign | KeyUsage.CrlSign;
    private const int SignUsage = KeyUsage.DigitalSignature | KeyUsage.NonRepudiation;

    private static Issued Root() => Issue("CN=Test Root,C=KZ", null, new BasicConstraints(true), CaUsage);

    /// <summary>The attacker's own, perfectly legitimate end-entity certificate.</summary>
    private static Issued OwnLeaf(Issued issuer) =>
        Issue("CN=ATTACKER,SERIALNUMBER=IIN111111111111,C=KZ", issuer, null, SignUsage);

    /// <summary>A certificate for the victim's IIN, issued with the attacker's leaf key.</summary>
    private static Issued Forged(Issued attackerLeaf) =>
        Issue("CN=VICTIM,SERIALNUMBER=IIN850717351069,C=KZ", attackerLeaf, null, SignUsage);

    private static ChainValidator Trust(Issued root) => new(new[] { root.Cert });

    [Fact]
    public void CertificateIssuedByEndEntity_IsRejected()
    {
        var root = Root();
        var attacker = OwnLeaf(root);
        var forged = Forged(attacker);

        var result = Trust(root).ValidateChainOnly(forged.Cert, extra: new[] { attacker.Cert });

        Assert.False(result.Trusted);
        Assert.Contains("not a CA", result.Error);
    }

    [Fact]
    public void Cms_ForgedSignerWithEmbeddedIssuer_IsRejected()
    {
        var root = Root();
        var attacker = OwnLeaf(root);
        var forged = Forged(attacker);
        var key = new SigningKey
        {
            Certificate = forged.Cert,
            PrivateKey = forged.Key.Private,
            Chain = new[] { forged.Cert, attacker.Cert }, // embedded in the CMS certificates set
        };

        var cms = new KzCryptoService(key).SignCms(Fixtures.Utf8("pay 1 000 000"));
        var result = new KzCryptoService(key, Trust(root)).VerifyCms(cms, checkRevocation: false);

        Assert.False(result.Valid);
    }

    [Fact]
    public void Cms_LegitimateEndEntitySigner_IsAccepted()
    {
        var root = Root();
        var signer = OwnLeaf(root);
        var key = new SigningKey
        {
            Certificate = signer.Cert,
            PrivateKey = signer.Key.Private,
            Chain = new[] { signer.Cert },
        };

        var cms = new KzCryptoService(key).SignCms(Fixtures.Utf8("hello"));
        var result = new KzCryptoService(key, Trust(root)).VerifyCms(cms, checkRevocation: false);

        Assert.True(result.Valid, result.Error);
    }

    [Fact]
    public void IssuerWithoutKeyCertSign_IsRejected()
    {
        var root = Root();
        var ca = Issue("CN=Sub CA,C=KZ", root, new BasicConstraints(true), KeyUsage.CrlSign);
        var leaf = OwnLeaf(ca);

        var result = Trust(root).ValidateChainOnly(leaf.Cert, extra: new[] { ca.Cert });

        Assert.False(result.Trusted);
        Assert.Contains("not a CA", result.Error);
    }

    [Fact]
    public void PathLengthConstraint_IsEnforced()
    {
        var root = Issue("CN=Test Root,C=KZ", null, new BasicConstraints(0), CaUsage); // no sub-CAs allowed
        var sub = Issue("CN=Sub CA,C=KZ", root, new BasicConstraints(true), CaUsage);
        var leaf = OwnLeaf(sub);

        var result = Trust(root).ValidateChainOnly(leaf.Cert, extra: new[] { sub.Cert });

        Assert.False(result.Trusted);
        Assert.Contains("path length", result.Error);
    }

    [Fact]
    public void SubCaWithinPathLength_IsAccepted()
    {
        var root = Issue("CN=Test Root,C=KZ", null, new BasicConstraints(1), CaUsage);
        var sub = Issue("CN=Sub CA,C=KZ", root, new BasicConstraints(true), CaUsage);
        var leaf = OwnLeaf(sub);

        var result = Trust(root).ValidateChainOnly(leaf.Cert, extra: new[] { sub.Cert });

        Assert.True(result.Trusted, result.Error);
    }

    [Fact]
    public void SignerWithoutSigningKeyUsage_IsRejected()
    {
        var root = Root();
        var encryptionOnly = Issue("CN=ENC,SERIALNUMBER=IIN111111111111,C=KZ", root, null, KeyUsage.KeyEncipherment);

        var result = Trust(root).ValidateChainOnly(encryptionOnly.Cert);

        Assert.False(result.Trusted);
        Assert.Contains("key usage", result.Error);
    }
}
