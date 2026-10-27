using System.Net;
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
/// Offline tests for <see cref="CrlRevocationChecker"/> and <see cref="CompositeRevocationChecker"/>.
/// A throwaway RSA CA issues a leaf whose CDP points at a fake HTTP endpoint, so CRL
/// trust, freshness and caching are exercised without the network. The GOST CRL path
/// against the real NCA CRLs is covered by <see cref="LivePkiTests"/>.
/// </summary>
public class CrlRevocationTests
{
    private const string CrlUrl = "http://crl.test/ca.crl";
    private static readonly DateTime Now = new(2026, 1, 15, 12, 0, 0, DateTimeKind.Utc);

    private sealed class FixedTime(DateTime utc) : TimeProvider
    {
        public DateTime Utc { get; set; } = utc;
        public override DateTimeOffset GetUtcNow() => new(Utc);
    }

    private sealed class FakeHttp(Func<string, byte[]?> respond) : HttpMessageHandler
    {
        public int Calls { get; private set; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Calls++;
            var body = respond(request.RequestUri!.ToString());
            return Task.FromResult(body == null
                ? new HttpResponseMessage(HttpStatusCode.NotFound)
                : new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(body) });
        }
    }

    private sealed record Pki(AsymmetricCipherKeyPair CaKey, X509Certificate Ca, X509Certificate Leaf);

    private static readonly SecureRandom Rng = new();

    private static AsymmetricCipherKeyPair NewRsa()
    {
        var gen = new RsaKeyPairGenerator();
        gen.Init(new KeyGenerationParameters(Rng, 2048));
        return gen.GenerateKeyPair();
    }

    private static Pki NewPki(bool withCdp = true)
    {
        var caKey = NewRsa();
        var caDn = new X509Name("CN=Test CA,C=KZ");
        var caGen = new X509V3CertificateGenerator();
        caGen.SetSerialNumber(BigInteger.One);
        caGen.SetIssuerDN(caDn);
        caGen.SetSubjectDN(caDn);
        caGen.SetNotBefore(Now.AddYears(-1));
        caGen.SetNotAfter(Now.AddYears(1));
        caGen.SetPublicKey(caKey.Public);
        caGen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(true));
        var ca = caGen.Generate(new Asn1SignatureFactory("SHA256WITHRSA", caKey.Private, Rng));

        var leafGen = new X509V3CertificateGenerator();
        leafGen.SetSerialNumber(BigInteger.ValueOf(4242));
        leafGen.SetIssuerDN(caDn);
        leafGen.SetSubjectDN(new X509Name("CN=Leaf,SERIALNUMBER=IIN000000000000,C=KZ"));
        leafGen.SetNotBefore(Now.AddDays(-10));
        leafGen.SetNotAfter(Now.AddDays(300));
        leafGen.SetPublicKey(NewRsa().Public);
        if (withCdp)
        {
            var name = new GeneralNames(new GeneralName(GeneralName.UniformResourceIdentifier, CrlUrl));
            var dp = new DistributionPoint(new DistributionPointName(name), null, null);
            leafGen.AddExtension(X509Extensions.CrlDistributionPoints, false, new CrlDistPoint(new[] { dp }));
        }
        var leaf = leafGen.Generate(new Asn1SignatureFactory("SHA256WITHRSA", caKey.Private, Rng));

        return new Pki(caKey, ca, leaf);
    }

    private static byte[] NewCrl(Pki pki, DateTime nextUpdate, AsymmetricKeyParameter? signWith = null,
        params BigInteger[] revoked)
    {
        var gen = new X509V2CrlGenerator();
        gen.SetIssuerDN(pki.Ca.SubjectDN);
        gen.SetThisUpdate(Now.AddHours(-1));
        gen.SetNextUpdate(nextUpdate);
        foreach (var serial in revoked)
            gen.AddCrlEntry(serial, Now.AddDays(-1), CrlReason.KeyCompromise);
        return gen.Generate(new Asn1SignatureFactory("SHA256WITHRSA", signWith ?? pki.CaKey.Private, Rng)).GetEncoded();
    }

    private static (CrlRevocationChecker Checker, FakeHttp Http, FixedTime Time) CheckerServing(byte[]? crl)
    {
        var http = new FakeHttp(url => url == CrlUrl ? crl : null);
        var time = new FixedTime(Now);
        return (new CrlRevocationChecker(new HttpClient(http), time), http, time);
    }

    [Fact]
    public void ListedSerial_IsRevoked()
    {
        var pki = NewPki();
        var (checker, _, _) = CheckerServing(NewCrl(pki, Now.AddDays(1), revoked: pki.Leaf.SerialNumber));

        Assert.Equal(RevocationStatus.Revoked, checker.Check(pki.Leaf, pki.Ca));
    }

    [Fact]
    public void UnlistedSerial_IsGood()
    {
        var pki = NewPki();
        var (checker, _, _) = CheckerServing(NewCrl(pki, Now.AddDays(1), revoked: BigInteger.ValueOf(7)));

        Assert.Equal(RevocationStatus.Good, checker.Check(pki.Leaf, pki.Ca));
    }

    [Fact]
    public void CrlSignedByAnotherKey_IsUnknown()
    {
        // An attacker answering the CRL URL with an empty list must not turn into "good".
        var pki = NewPki();
        var (checker, _, _) = CheckerServing(NewCrl(pki, Now.AddDays(1), signWith: NewRsa().Private));

        Assert.Equal(RevocationStatus.Unknown, checker.Check(pki.Leaf, pki.Ca));
    }

    [Fact]
    public void ExpiredCrl_IsUnknown()
    {
        var pki = NewPki();
        var (checker, _, _) = CheckerServing(NewCrl(pki, Now.AddMinutes(-1)));

        Assert.Equal(RevocationStatus.Unknown, checker.Check(pki.Leaf, pki.Ca));
    }

    [Fact]
    public void Unreachable_IsUnknown()
    {
        var pki = NewPki();
        var (checker, _, _) = CheckerServing(null);

        Assert.Equal(RevocationStatus.Unknown, checker.Check(pki.Leaf, pki.Ca));
    }

    [Fact]
    public void NoDistributionPoint_IsUnknown_WithoutNetwork()
    {
        var pki = NewPki(withCdp: false);
        var (checker, http, _) = CheckerServing(NewCrl(pki, Now.AddDays(1)));

        Assert.Equal(RevocationStatus.Unknown, checker.Check(pki.Leaf, pki.Ca));
        Assert.Equal(0, http.Calls);
    }

    [Fact]
    public void Crl_IsCachedUntilNextUpdate_ThenRefetched()
    {
        var pki = NewPki();
        var (checker, http, time) = CheckerServing(NewCrl(pki, Now.AddHours(2)));

        checker.Check(pki.Leaf, pki.Ca);
        checker.Check(pki.Leaf, pki.Ca);
        Assert.Equal(1, http.Calls);

        time.Utc = Now.AddHours(3); // past nextUpdate -> cached copy is stale
        checker.Check(pki.Leaf, pki.Ca);
        Assert.Equal(2, http.Calls);
    }

    // ---- composite -----------------------------------------------------------

    private sealed class FakeChecker(RevocationStatus status) : IRevocationChecker
    {
        public int Calls { get; private set; }
        public RevocationStatus Check(X509Certificate cert, X509Certificate issuer)
        {
            Calls++;
            return status;
        }
    }

    [Fact]
    public void Composite_FallsBack_WhenFirstIsUnknown()
    {
        var pki = NewPki();
        var composite = new CompositeRevocationChecker(
            new FakeChecker(RevocationStatus.Unknown), new FakeChecker(RevocationStatus.Revoked));

        Assert.Equal(RevocationStatus.Revoked, composite.Check(pki.Leaf, pki.Ca));
    }

    [Fact]
    public void Composite_StopsAtFirstDefiniteAnswer()
    {
        var pki = NewPki();
        var second = new FakeChecker(RevocationStatus.Revoked);
        var composite = new CompositeRevocationChecker(new FakeChecker(RevocationStatus.Good), second);

        Assert.Equal(RevocationStatus.Good, composite.Check(pki.Leaf, pki.Ca));
        Assert.Equal(0, second.Calls);
    }

    [Fact]
    public void Composite_AllUnknown_IsUnknown()
    {
        var pki = NewPki();
        var composite = new CompositeRevocationChecker(
            new FakeChecker(RevocationStatus.Unknown), new FakeChecker(RevocationStatus.Unknown));

        Assert.Equal(RevocationStatus.Unknown, composite.Check(pki.Leaf, pki.Ca));
    }

    // ---- OCSP: issuing CAs ---------------------------------------------------

    [Fact]
    public void Ocsp_IssuingCaWithoutAia_IsNotSentToDefaultResponder()
    {
        // ocsp.pki.gov.kz answers malformedRequest for the NCA issuing CAs; they must be
        // left to the CRL checker instead of costing a failed round trip.
        var http = new FakeHttp(_ => throw new InvalidOperationException("no network expected"));
        var ocsp = new OcspRevocationChecker(new HttpClient(http), "http://ocsp.pki.gov.kz");
        var nca = Fixtures.LoadCert(Path.Combine(Fixtures.CaCertsDir, "nca_gost_2022.pem"));
        var root = Fixtures.LoadCert(Path.Combine(Fixtures.CaCertsDir, "root_gost_2022.pem"));

        Assert.Equal(RevocationStatus.Unknown, ocsp.Check(nca, root));
        Assert.Equal(0, http.Calls);
    }
}
