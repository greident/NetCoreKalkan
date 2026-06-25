using System.Text;
using CryptCore.Pki;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace CryptCore.Tests;

/// <summary>
/// Shared paths and helpers for the trust tests. Fixtures are the real NCA test
/// material already shipped under KalkanCore/Infra (the GOST chain) plus an
/// on-the-fly self-signed RSA certificate used to model the forgery attack.
/// </summary>
public static class Fixtures
{
    /// <summary>Repo path KalkanCore/Infra, found by walking up from the test binary.</summary>
    public static string InfraDir { get; } = LocateInfra();

    public static string CaCertsDir => Path.Combine(InfraDir, "Ca_Certs");
    public static string PemsDir => Path.Combine(InfraDir, "Certs", "Pems");

    /// <summary>End-entity test certificate "МАМЕТОВ ДАУЛЕТ" (IIN850717351069), GOST-2015.</summary>
    public static string MametovCertPath => Path.Combine(InfraDir, "Certs", "test_CERT_GOST.txt");

    /// <summary>The МАМЕТОВ certificate was valid Oct 2024 .. Oct 2025; pick an instant inside that.</summary>
    public static readonly DateTime MametovValidInstant = new(2025, 1, 15, 0, 0, 0, DateTimeKind.Utc);

    public static X509Certificate LoadCert(string path)
    {
        using var s = File.OpenRead(path);
        return new X509CertificateParser().ReadCertificate(s);
    }

    /// <summary>
    /// Validator trusting the production NCA roots (Ca_Certs): root + intermediate
    /// GOST/RSA. This is the set the МАМЕТОВ certificate chains to.
    /// </summary>
    public static ChainValidator ProductionTrust() => ChainValidator.FromPemDirectory(CaCertsDir);

    /// <summary>
    /// Validator trusting only the TEST hierarchy (root_test_gost_2022 + its sub-CA).
    /// The МАМЕТОВ certificate does NOT chain here, so it must be rejected.
    /// </summary>
    public static ChainValidator TestHierarchyTrust() => ChainValidator.FromPems(new[]
    {
        Path.Combine(PemsDir, "root_test_gost_2022.pem"),
        Path.Combine(PemsDir, "nca_gost2022_test.pem"),
    });

    /// <summary>
    /// Build a self-signed RSA signing identity carrying a forged subject (an arbitrary
    /// IIN), as an attacker would when they cannot obtain a real NCA certificate.
    /// </summary>
    public static SigningKey ForgedSelfSignedKey(string forgedIin)
    {
        var rng = new SecureRandom();
        var gen = new RsaKeyPairGenerator();
        gen.Init(new KeyGenerationParameters(rng, 2048));
        AsymmetricCipherKeyPair pair = gen.GenerateKeyPair();

        var dn = new X509Name($"SERIALNUMBER=IIN{forgedIin},CN=МАМЕТОВ ДАУЛЕТ,C=KZ");
        var certGen = new X509V3CertificateGenerator();
        certGen.SetSerialNumber(BigInteger.ValueOf(DateTime.UtcNow.Ticks));
        certGen.SetIssuerDN(dn);
        certGen.SetSubjectDN(dn);
        certGen.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        certGen.SetNotAfter(DateTime.UtcNow.AddYears(1));
        certGen.SetPublicKey(pair.Public);

        var sigFactory = new Asn1SignatureFactory("SHA256WITHRSA", pair.Private, rng);
        var cert = certGen.Generate(sigFactory);

        return new SigningKey
        {
            Certificate = cert,
            PrivateKey = pair.Private,
            Chain = new[] { cert },
        };
    }

    public static byte[] Utf8(string s) => Encoding.UTF8.GetBytes(s);

    private static string LocateInfra()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null)
        {
            var candidate = Path.Combine(dir.FullName, "KalkanCore", "Infra");
            if (Directory.Exists(candidate)) return candidate;
            dir = dir.Parent;
        }
        throw new DirectoryNotFoundException("Could not locate KalkanCore/Infra from the test binary.");
    }
}