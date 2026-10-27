using System.Net;
using CryptCore.Pki;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Xunit;

namespace CryptCore.Tests;

/// <summary>
/// Offline tests for <see cref="OcspRevocationChecker"/>'s response trust, freshness and
/// caching. A throwaway RSA CA with a delegated responder answers over a fake HTTP handler,
/// so the attacks (forged responder, replayed or mismatched answers) are reproducible
/// without the network. The GOST wire format is covered by <see cref="LivePkiTests"/>.
/// </summary>
public class OcspRevocationTests
{
    private const string Url = "http://ocsp.test";
    private static readonly SecureRandom Rng = new();
    private static readonly DateTime Now = new(2026, 1, 15, 12, 0, 0, DateTimeKind.Utc);

    private sealed class FixedTime(DateTime utc) : TimeProvider
    {
        public DateTime Utc { get; set; } = utc;
        public override DateTimeOffset GetUtcNow() => new(Utc);
    }

    private sealed class FakeResponder(Func<OcspReq, byte[]> respond) : HttpMessageHandler
    {
        public int Calls { get; private set; }
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Calls++;
            var req = new OcspReq(await request.Content!.ReadAsByteArrayAsync(ct));
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(respond(req)) };
        }
    }

    private sealed record Issued(X509Certificate Cert, AsymmetricCipherKeyPair Key);

    private static AsymmetricCipherKeyPair NewRsa()
    {
        var gen = new RsaKeyPairGenerator();
        gen.Init(new KeyGenerationParameters(Rng, 2048));
        return gen.GenerateKeyPair();
    }

    private static Issued Issue(string subject, Issued? issuer, bool ca = false, bool ocspSigning = false)
    {
        var key = NewRsa();
        var dn = new X509Name(subject);
        var gen = new X509V3CertificateGenerator();
        gen.SetSerialNumber(BigInteger.ValueOf(Rng.NextInt() & int.MaxValue));
        gen.SetIssuerDN(issuer?.Cert.SubjectDN ?? dn);
        gen.SetSubjectDN(dn);
        gen.SetNotBefore(Now.AddDays(-30));
        gen.SetNotAfter(Now.AddDays(300));
        gen.SetPublicKey(key.Public);
        if (ca) gen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(true));
        if (ocspSigning)
            gen.AddExtension(X509Extensions.ExtendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeID.id_kp_OCSPSigning));
        return new Issued(gen.Generate(new Asn1SignatureFactory("SHA256WITHRSA", (issuer?.Key ?? key).Private, Rng)), key);
    }

    private static readonly Issued Ca = Issue("CN=Test CA,C=KZ", null, ca: true);
    private static readonly Issued Responder = Issue("CN=OCSP,C=KZ", Ca, ocspSigning: true);
    private static readonly Issued Leaf = Issue("CN=LEAF,SERIALNUMBER=IIN111111111111,C=KZ", Ca);

    /// <summary>Build a response to <paramref name="req"/> the way a responder would.</summary>
    private static byte[] Answer(OcspReq req, CertificateStatus? status, Issued? signer = null,
        BigInteger? aboutSerial = null, bool echoNonce = true, byte[]? nonce = null, DateTime? producedAt = null)
    {
        signer ??= Responder;
        var asked = req.GetRequestList()[0].GetCertID();
        var id = aboutSerial == null ? asked : CertificateID.DeriveCertificateID(asked, aboutSerial);

        var gen = new BasicOcspRespGenerator(new RespID(signer.Cert.SubjectDN));
        gen.AddResponse(id, status, producedAt ?? Now, null, null);
        var reqNonce = req.GetExtensionValue(OcspObjectIdentifiers.PkixOcspNonce);
        if (echoNonce && (reqNonce != null || nonce != null))
        {
            var value = nonce != null ? new DerOctetString(new DerOctetString(nonce).GetEncoded()) : reqNonce!;
            gen.SetResponseExtensions(new X509Extensions(new Dictionary<DerObjectIdentifier, X509Extension>
            {
                [OcspObjectIdentifiers.PkixOcspNonce] = new(false, (Asn1OctetString)value),
            }));
        }
        var chain = signer == Ca ? Array.Empty<X509Certificate>() : new[] { signer.Cert };
        var basic = gen.Generate(new Asn1SignatureFactory("SHA256WITHRSA", signer.Key.Private, Rng), chain, producedAt ?? Now);
        return new OCSPRespGenerator().Generate(OcspRespStatus.Successful, basic).GetEncoded();
    }

    private static (OcspRevocationChecker Checker, FakeResponder Http, FixedTime Time) Checker(Func<OcspReq, byte[]> respond)
    {
        var http = new FakeResponder(respond);
        var time = new FixedTime(Now);
        return (new OcspRevocationChecker(new HttpClient(http), Url, time), http, time);
    }

    [Fact]
    public void Good_FromDelegatedResponder()
    {
        var (ocsp, _, _) = Checker(req => Answer(req, CertificateStatus.Good));

        Assert.Equal(RevocationStatus.Good, ocsp.Check(Leaf.Cert, Ca.Cert));
    }

    [Fact]
    public void Good_SignedByCaItself()
    {
        var (ocsp, _, _) = Checker(req => Answer(req, CertificateStatus.Good, signer: Ca));

        Assert.Equal(RevocationStatus.Good, ocsp.Check(Leaf.Cert, Ca.Cert));
    }

    [Fact]
    public void Revoked_IsRevoked()
    {
        var (ocsp, _, _) = Checker(req => Answer(req, new RevokedStatus(Now.AddDays(-1), CrlReason.KeyCompromise)));

        Assert.Equal(RevocationStatus.Revoked, ocsp.Check(Leaf.Cert, Ca.Cert));
    }

    [Fact]
    public void ResponderWithoutOcspSigningEku_IsUnknown()
    {
        // The attack: the holder of an ordinary certificate from the same CA signs "good".
        var attacker = Issue("CN=ATTACKER,SERIALNUMBER=IIN222222222222,C=KZ", Ca);
        var (ocsp, _, _) = Checker(req => Answer(req, CertificateStatus.Good, signer: attacker));

        Assert.Equal(RevocationStatus.Unknown, ocsp.Check(Leaf.Cert, Ca.Cert));
    }

    [Fact]
    public void ResponseAboutAnotherSerial_IsUnknown()
    {
        // A genuine "good" for some other certificate must not vouch for this one.
        var (ocsp, _, _) = Checker(req => Answer(req, CertificateStatus.Good, aboutSerial: BigInteger.ValueOf(7)));

        Assert.Equal(RevocationStatus.Unknown, ocsp.Check(Leaf.Cert, Ca.Cert));
    }

    [Fact]
    public void WrongNonce_IsUnknown()
    {
        // A replayed response carries the nonce of the request it originally answered.
        var (ocsp, _, _) = Checker(req => Answer(req, CertificateStatus.Good, nonce: new byte[16]));

        Assert.Equal(RevocationStatus.Unknown, ocsp.Check(Leaf.Cert, Ca.Cert));
    }

    [Fact]
    public void NoNonce_RecentResponse_IsAccepted()
    {
        var (ocsp, _, _) = Checker(req => Answer(req, CertificateStatus.Good, echoNonce: false, producedAt: Now.AddMinutes(-2)));

        Assert.Equal(RevocationStatus.Good, ocsp.Check(Leaf.Cert, Ca.Cert));
    }

    [Fact]
    public void NoNonce_OldResponse_IsUnknown()
    {
        var (ocsp, _, _) = Checker(req => Answer(req, CertificateStatus.Good, echoNonce: false, producedAt: Now.AddHours(-1)));

        Assert.Equal(RevocationStatus.Unknown, ocsp.Check(Leaf.Cert, Ca.Cert));
    }

    [Fact]
    public void Answer_IsCachedForTtl_ThenRefetched()
    {
        var (ocsp, http, time) = Checker(req => Answer(req, CertificateStatus.Good));

        ocsp.Check(Leaf.Cert, Ca.Cert);
        ocsp.Check(Leaf.Cert, Ca.Cert);
        Assert.Equal(1, http.Calls);

        time.Utc = Now + ocsp.CacheTtl + TimeSpan.FromSeconds(1);
        Assert.Equal(RevocationStatus.Good, ocsp.Check(Leaf.Cert, Ca.Cert));
        Assert.Equal(2, http.Calls);
    }

    [Fact]
    public void UnknownAnswer_IsNotCached()
    {
        var (ocsp, http, _) = Checker(req => Answer(req, new UnknownStatus()));

        ocsp.Check(Leaf.Cert, Ca.Cert);
        ocsp.Check(Leaf.Cert, Ca.Cert);
        Assert.Equal(2, http.Calls);
    }
}
