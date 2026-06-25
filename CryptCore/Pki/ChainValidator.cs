using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.X509;

namespace CryptCore.Pki;

/// <summary>Outcome of validating a signer certificate against the trust store.</summary>
public sealed class ChainValidationResult
{
    public bool Trusted { get; init; }
    public string? Error { get; init; }
    /// <summary>The built path, leaf first, ending at a trusted root.</summary>
    public IReadOnlyList<X509Certificate> Path { get; init; } = Array.Empty<X509Certificate>();

    public static ChainValidationResult Ok(IReadOnlyList<X509Certificate> path) => new() { Trusted = true, Path = path };
    public static ChainValidationResult Fail(string error) => new() { Trusted = false, Error = error };
}

/// <summary>
/// Builds and validates an X.509 certification path for a signer certificate up to
/// a configured Kazakhstan NCA trust anchor (pki.gov.kz roots). This is the piece a
/// raw signature check is missing: <see cref="Signing.KzSignatures"/> only proves the
/// bytes were signed by <em>some</em> key, it does not prove the key belongs to a
/// certificate the NCA actually issued. Without this, a self-signed certificate
/// carrying an arbitrary IIN/BIN verifies as "valid".
///
/// BouncyCastle's PKIX validator is not used because it cannot verify the KZ GOST
/// certificate signatures (the 1.2.398.3.10.* OIDs are unknown to its SignerUtilities),
/// so the path is built by DN matching and each link's signature is checked here —
/// RSA the normal way, GOST through the same primitives as the rest of CryptCore.
///
/// Scope: trust anchoring + signature chaining + validity window. Revocation
/// (OCSP/CRL) is intentionally out of scope here — see <see cref="ValidateChainOnly"/>.
/// </summary>
public sealed class ChainValidator
{
    private const int MaxDepth = 10;

    private readonly List<X509Certificate> _anchors;       // trusted self-signed roots
    private readonly List<X509Certificate> _intermediates; // known sub-CAs (e.g. NCA issuing CAs)
    private readonly IRevocationChecker? _revocation;
    private readonly bool _failOnUnknownRevocation;

    /// <param name="trusted">
    /// All trusted certificates. Self-signed ones become trust anchors (roots);
    /// the rest are treated as known intermediates available for path building.
    /// </param>
    /// <param name="revocation">
    /// Optional revocation checker (e.g. <see cref="OcspRevocationChecker"/>). When supplied,
    /// <see cref="Validate"/> additionally rejects revoked certificates.
    /// </param>
    /// <param name="failOnUnknownRevocation">
    /// When true (default, fail-closed) an indeterminate revocation answer is treated as a
    /// failure; when false (soft-fail) it is tolerated. Only relevant if a checker is set.
    /// </param>
    public ChainValidator(
        IEnumerable<X509Certificate> trusted,
        IRevocationChecker? revocation = null,
        bool failOnUnknownRevocation = true)
    {
        var all = trusted.ToList();
        _anchors = all.Where(IsSelfIssued).ToList();
        _intermediates = all.Where(c => !IsSelfIssued(c)).ToList();
        _revocation = revocation;
        _failOnUnknownRevocation = failOnUnknownRevocation;
        if (_anchors.Count == 0)
            throw new ArgumentException("Trust store contains no self-signed root certificate to anchor on.");
    }

    /// <summary>Load every certificate found in the *.pem files under <paramref name="dir"/>.</summary>
    public static ChainValidator FromPemDirectory(
        string dir, IRevocationChecker? revocation = null, bool failOnUnknownRevocation = true)
        => new(Directory.EnumerateFiles(dir, "*.pem", SearchOption.AllDirectories).SelectMany(ReadPemCerts),
            revocation, failOnUnknownRevocation);

    public static ChainValidator FromPems(
        IEnumerable<string> pemPaths, IRevocationChecker? revocation = null, bool failOnUnknownRevocation = true)
        => new(pemPaths.SelectMany(ReadPemCerts), revocation, failOnUnknownRevocation);

    /// <summary>
    /// Validate <paramref name="leaf"/> at <paramref name="atUtc"/> (default: now).
    /// <paramref name="extra"/> carries certificates bundled with the message itself
    /// (CMS SignedData often ships the issuing chain) — they are candidate issuers but
    /// are never treated as trusted: only the configured anchors confer trust.
    /// </summary>
    /// <summary>
    /// Full validation: build and check the path (see <see cref="ValidateChainOnly"/>) and,
    /// when a revocation checker is configured and <paramref name="checkRevocation"/> is true,
    /// additionally reject any revoked certificate in the path.
    /// </summary>
    public ChainValidationResult Validate(
        X509Certificate leaf,
        IReadOnlyList<X509Certificate>? extra = null,
        DateTime? atUtc = null,
        bool checkRevocation = true)
    {
        var chain = ValidateChainOnly(leaf, extra, atUtc);
        if (!chain.Trusted || !checkRevocation || _revocation == null)
            return chain;

        // Check every non-root certificate against the certificate above it in the path.
        for (var i = 0; i < chain.Path.Count - 1; i++)
        {
            var subject = chain.Path[i];
            var issuer = chain.Path[i + 1];
            var status = _revocation.Check(subject, issuer);
            if (status == RevocationStatus.Revoked)
                return ChainValidationResult.Fail($"Certificate '{subject.SubjectDN}' is revoked (OCSP).");
            if (status == RevocationStatus.Unknown && _failOnUnknownRevocation)
                return ChainValidationResult.Fail(
                    $"Revocation status of '{subject.SubjectDN}' could not be determined (OCSP).");
        }
        return chain;
    }

    /// <summary>Path building + validity window only, without any revocation check.</summary>
    public ChainValidationResult ValidateChainOnly(
        X509Certificate leaf,
        IReadOnlyList<X509Certificate>? extra = null,
        DateTime? atUtc = null)
    {
        var now = (atUtc ?? DateTime.UtcNow).ToUniversalTime();

        // Issuer-candidate pool: message-supplied certs + known intermediates + roots.
        var pool = new List<X509Certificate>();
        if (extra != null) pool.AddRange(extra);
        pool.AddRange(_intermediates);
        pool.AddRange(_anchors);

        var path = new List<X509Certificate> { leaf };
        var current = leaf;

        for (var depth = 0; depth < MaxDepth; depth++)
        {
            if (!IsTimeValid(current, now))
                return ChainValidationResult.Fail(
                    $"Certificate '{current.SubjectDN}' is outside its validity window " +
                    $"({current.NotBefore:u} .. {current.NotAfter:u}).");

            if (IsAnchor(current))
                return ChainValidationResult.Ok(path);

            if (IsSelfIssued(current))
                return ChainValidationResult.Fail(
                    $"Chain terminates at an untrusted self-signed certificate '{current.SubjectDN}'.");

            var issuer = FindIssuer(current, pool);
            if (issuer == null)
                return ChainValidationResult.Fail(
                    $"No trusted issuer found for '{current.SubjectDN}' (issuer DN '{current.IssuerDN}').");

            path.Add(issuer);
            current = issuer;
        }

        return ChainValidationResult.Fail("Certification path exceeded the maximum depth.");
    }

    // ---- path building ------------------------------------------------------

    private X509Certificate? FindIssuer(X509Certificate cert, List<X509Certificate> pool)
        => pool.FirstOrDefault(c => c.SubjectDN.Equivalent(cert.IssuerDN) && VerifySignedBy(cert, c));

    /// <summary>True if <paramref name="issuer"/>'s key actually signed <paramref name="subject"/>.</summary>
    private static bool VerifySignedBy(X509Certificate subject, X509Certificate issuer)
    {
        var sigAlg = subject.CertificateStructure.SignatureAlgorithm.Algorithm;
        if (KzGost.IsGostAny(sigAlg))
        {
            ECPublicKeyParameters pub;
            try { pub = KzGost.DecodePublicKey(issuer.CertificateStructure.SubjectPublicKeyInfo); }
            catch { return false; } // issuer is not a GOST key -> cannot have signed a GOST cert
            var tbs = subject.GetTbsCertificate();
            var sig = subject.GetSignature();
            // KZ stores GOST signature values byte-reversed vs BouncyCastle in the XML/CMS
            // profiles; the certificate signature convention is not guaranteed, so accept
            // either orientation. The signature must still verify mathematically.
            return GostVerify(pub, tbs, sig, sigAlg) || GostVerify(pub, tbs, Reversed(sig), sigAlg);
        }

        try
        {
            subject.Verify(issuer.GetPublicKey()); // RSA (and anything BouncyCastle knows); throws on mismatch
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static bool GostVerify(ECPublicKeyParameters pub, byte[] data, byte[] sig, DerObjectIdentifier alg)
    {
        try
        {
            var signer = new Gost3410DigestSigner(KzGost.CreateSigner(alg), KzGost.CreateDigest(alg));
            signer.Init(false, pub);
            signer.BlockUpdate(data, 0, data.Length);
            return signer.VerifySignature(sig);
        }
        catch
        {
            return false;
        }
    }

    // ---- helpers ------------------------------------------------------------

    private bool IsAnchor(X509Certificate c)
    {
        var enc = c.GetEncoded();
        return _anchors.Any(a => a.GetEncoded().AsSpan().SequenceEqual(enc));
    }

    private static bool IsSelfIssued(X509Certificate c) => c.IssuerDN.Equivalent(c.SubjectDN);

    private static bool IsTimeValid(X509Certificate c, DateTime nowUtc)
        => nowUtc >= c.NotBefore.ToUniversalTime() && nowUtc <= c.NotAfter.ToUniversalTime();

    private static byte[] Reversed(byte[] b)
    {
        var r = (byte[])b.Clone();
        Array.Reverse(r);
        return r;
    }

    private static IEnumerable<X509Certificate> ReadPemCerts(string path)
    {
        using var reader = new StreamReader(path);
        var pem = new PemReader(reader);
        var list = new List<X509Certificate>();
        for (var o = pem.ReadObject(); o != null; o = pem.ReadObject())
            if (o is X509Certificate c)
                list.Add(c);
        return list;
    }
}