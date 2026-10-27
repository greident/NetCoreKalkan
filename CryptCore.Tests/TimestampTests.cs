using CryptCore.Pki;
using CryptCore.Signing;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509;
using Xunit;

namespace CryptCore.Tests;

/// <summary>
/// RFC 3161 timestamps on CMS signatures, offline: a synthetic RSA hierarchy with its own
/// TSA. The live NCA TSA (GOST and RSA) is covered by <see cref="LivePkiTests"/>, and
/// real NCA tokens by <see cref="CmsTests"/>.
/// </summary>
public class TimestampTests
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

    private static Issued Issue(string subject, Issued? issuer, DateTime from, DateTime to,
        bool ca = false, bool timeStamping = false)
    {
        var key = NewRsa();
        var dn = new X509Name(subject);
        var gen = new X509V3CertificateGenerator();
        gen.SetSerialNumber(BigInteger.ValueOf(Rng.NextInt() & int.MaxValue));
        gen.SetIssuerDN(issuer?.Cert.SubjectDN ?? dn);
        gen.SetSubjectDN(dn);
        gen.SetNotBefore(from);
        gen.SetNotAfter(to);
        gen.SetPublicKey(key.Public);
        if (ca) gen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(true));
        if (timeStamping)
            gen.AddExtension(X509Extensions.ExtendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeID.id_kp_timeStamping));
        return new Issued(gen.Generate(new Asn1SignatureFactory("SHA256WITHRSA", (issuer?.Key ?? key).Private, Rng)), key);
    }

    private static readonly Issued Root = Issue("CN=Test Root,C=KZ", null, Now.AddYears(-5), Now.AddYears(5), ca: true);
    private static readonly Issued Tsa = Issue("CN=TSA,C=KZ", Root, Now.AddYears(-1), Now.AddYears(1), timeStamping: true);
    private static readonly ChainValidator Trust = new(new[] { Root.Cert });

    /// <summary>A TSA answering with a fixed genTime; <paramref name="tamper"/> stamps other bytes.</summary>
    private sealed class FakeTsa(Issued tsa, DateTime genTime, bool tamper = false) : ITimestampAuthority
    {
        public byte[] Timestamp(byte[] data, SigningKey signer)
        {
            var hash = DigestUtilities.CalculateDigest("SHA-256", tamper ? Fixtures.Utf8("something else") : data);
            var reqGen = new TimeStampRequestGenerator();
            reqGen.SetCertReq(true); // as TspClient does; without it the token carries no TSA certificate
            var request = reqGen.Generate(NistObjectIdentifiers.IdSha256, hash);
            var gen = new TimeStampTokenGenerator(tsa.Key.Private, tsa.Cert, NistObjectIdentifiers.IdSha256.Id, "1.2.3.4");
            gen.SetCertificates(CollectionUtilities.CreateStore(new[] { tsa.Cert }));
            return gen.Generate(request, BigInteger.One, genTime).GetEncoded();
        }
    }

    private static SigningKey Signer(DateTime from, DateTime to)
    {
        var s = Issue("CN=SIGNER,SERIALNUMBER=IIN111111111111,C=KZ", Root, from, to);
        return new SigningKey { Certificate = s.Cert, PrivateKey = s.Key.Private, Chain = new[] { s.Cert } };
    }

    private static readonly byte[] Data = Fixtures.Utf8("contract #42");

    [Fact]
    public void Timestamped_IsValid_AndReportsGenTime()
    {
        var genTime = new DateTime(Now.Year, Now.Month, Now.Day, 8, 0, 0, DateTimeKind.Utc);
        var key = Signer(Now.AddDays(-30), Now.AddDays(30));

        var result = new KzCryptoService(key, Trust).VerifyCms(
            new KzCryptoService(key).SignCms(Data, tsa: new FakeTsa(Tsa, genTime)), checkRevocation: false);

        Assert.True(result.Valid, result.Error);
        Assert.Equal(genTime, Assert.Single(result.Signers).TimestampUtc);
    }

    [Fact]
    public void ExpiredSigner_TimestampedWhileValid_IsValid()
    {
        // The certificate expired yesterday, but the TSA proves the signature is a week old.
        var key = Signer(Now.AddDays(-30), Now.AddDays(-1));
        var cms = new KzCryptoService(key).SignCms(Data, tsa: new FakeTsa(Tsa, Now.AddDays(-7)));
        var verifier = new KzCryptoService(key, Trust);

        Assert.True(verifier.VerifyCms(cms, checkRevocation: false).Valid);
        // Without the timestamp the same certificate is simply expired.
        Assert.False(verifier.VerifyCms(new KzCryptoService(key).SignCms(Data), checkRevocation: false).Valid);
    }

    [Fact]
    public void ExpiredSigner_TimestampedAfterExpiry_IsInvalid()
    {
        var key = Signer(Now.AddDays(-30), Now.AddDays(-10));
        var cms = new KzCryptoService(key).SignCms(Data, tsa: new FakeTsa(Tsa, Now.AddDays(-2)));

        var result = new KzCryptoService(key, Trust).VerifyCms(cms, checkRevocation: false);

        Assert.False(result.Valid);
        Assert.Contains("validity window", result.Error);
    }

    [Fact]
    public void TokenOverOtherData_IsInvalid()
    {
        var key = Signer(Now.AddDays(-30), Now.AddDays(30));
        var cms = new KzCryptoService(key).SignCms(Data, tsa: new FakeTsa(Tsa, Now, tamper: true));

        var result = new KzCryptoService(key, Trust).VerifyCms(cms, checkRevocation: false);

        Assert.False(result.Valid);
        Assert.Contains("does not cover", result.Error);
    }

    [Fact]
    public void TokenFromUntrustedTsa_IsInvalid()
    {
        // A TSA outside the trust store could vouch for any time.
        var rogueRoot = Issue("CN=Rogue Root,C=KZ", null, Now.AddYears(-5), Now.AddYears(5), ca: true);
        var rogueTsa = Issue("CN=TSA,C=KZ", rogueRoot, Now.AddYears(-1), Now.AddYears(1), timeStamping: true);
        var key = Signer(Now.AddDays(-30), Now.AddDays(-1));
        var cms = new KzCryptoService(key).SignCms(Data, tsa: new FakeTsa(rogueTsa, Now.AddDays(-7)));

        var result = new KzCryptoService(key, Trust).VerifyCms(cms, checkRevocation: false);

        Assert.False(result.Valid);
        Assert.Contains("Timestamp invalid", result.Error);
    }

    [Fact]
    public void AddSigner_WithTimestamp_LeavesEarlierTimestampAlone()
    {
        var alice = Signer(Now.AddDays(-30), Now.AddDays(30));
        var bob = Signer(Now.AddDays(-30), Now.AddDays(30));
        var first = new KzCryptoService(alice).SignCms(Data, tsa: new FakeTsa(Tsa, Now.AddHours(-3)));

        var both = new KzCryptoService(bob).AddCmsSigner(first, tsa: new FakeTsa(Tsa, Now.AddHours(-1)));

        var result = new KzCryptoService(alice, Trust).VerifyCms(both, checkRevocation: false);
        Assert.True(result.Valid, result.Error);
        // SignerInfos is a DER SET OF (sorted), so compare as a set, not by position.
        Assert.Equal(
            new[] { Now.AddHours(-3), Now.AddHours(-1) }.Select(t => t.ToString("yyyyMMddHHmmss")).Order(),
            result.Signers.Select(s => s.TimestampUtc!.Value.ToString("yyyyMMddHHmmss")).Order());
    }
}
