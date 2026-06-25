using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace CryptCore.Pki;

/// <summary>A loaded signing identity: end-entity certificate, its chain and private key.</summary>
public sealed class SigningKey
{
    public required X509Certificate Certificate { get; init; }
    public required AsymmetricKeyParameter PrivateKey { get; init; }
    public required IReadOnlyList<X509Certificate> Chain { get; init; }

    /// <summary>Algorithm OID of the certificate's public key.</summary>
    public DerObjectIdentifier KeyAlgorithm =>
        Certificate.CertificateStructure.SubjectPublicKeyInfo.Algorithm.Algorithm;

    public bool IsGost => KzGost.IsGost(KeyAlgorithm);
}

/// <summary>
/// Loads PKCS#12 (.p12/.pfx) key stores by parsing the PFX structure directly.
/// BouncyCastle's high-level Pkcs12Store eagerly decodes the private key and
/// throws on Kazakhstan GOST keys (their OIDs are unknown to it), so we walk the
/// AuthenticatedSafe ourselves, decrypt the bags with the PKCS#12 PBE machinery,
/// and reconstruct RSA keys via PrivateKeyFactory or GOST keys by hand.
/// </summary>
public static class Pkcs12Loader
{
    public static SigningKey Load(string path, string password) => Load(File.ReadAllBytes(path), password);

    public static SigningKey Load(byte[] p12, string password)
    {
        var pw = password.ToCharArray();
        var pfx = Pfx.GetInstance(Asn1Object.FromByteArray(p12));

        PrivateKeyInfo? keyInfo = null;
        var certs = new List<X509Certificate>();

        var authSafe = Asn1Sequence.GetInstance(
            Asn1Object.FromByteArray(Asn1OctetString.GetInstance(pfx.AuthSafe.Content).GetOctets()));

        foreach (var entry in authSafe)
        {
            var ci = ContentInfo.GetInstance(entry);
            Asn1Sequence bags;
            if (ci.ContentType.Equals(PkcsObjectIdentifiers.Data))
            {
                bags = Asn1Sequence.GetInstance(
                    Asn1Object.FromByteArray(Asn1OctetString.GetInstance(ci.Content).GetOctets()));
            }
            else if (ci.ContentType.Equals(PkcsObjectIdentifiers.EncryptedData))
            {
                // EncryptedData ::= SEQ { version, EncryptedContentInfo }
                // EncryptedContentInfo ::= SEQ { contentType, contentEncryptionAlgorithm, [0] encryptedContent }
                var ed = Asn1Sequence.GetInstance(ci.Content);
                var eci = Asn1Sequence.GetInstance(ed[1]);
                var algId = AlgorithmIdentifier.GetInstance(eci[1]);
                var encContent = Asn1OctetString.GetInstance((Asn1TaggedObject)eci[2], false).GetOctets();
                var plain = Decrypt(algId, encContent, pw);
                bags = Asn1Sequence.GetInstance(Asn1Object.FromByteArray(plain));
            }
            else continue;

            foreach (var b in bags)
            {
                var bag = SafeBag.GetInstance(b);
                if (bag.BagID.Equals(PkcsObjectIdentifiers.Pkcs8ShroudedKeyBag))
                {
                    var epki = EncryptedPrivateKeyInfo.GetInstance(bag.BagValue);
                    var plain = Decrypt(epki.EncryptionAlgorithm, epki.GetEncryptedData(), pw);
                    keyInfo = PrivateKeyInfo.GetInstance(Asn1Object.FromByteArray(plain));
                }
                else if (bag.BagID.Equals(PkcsObjectIdentifiers.KeyBag))
                {
                    keyInfo = PrivateKeyInfo.GetInstance(bag.BagValue);
                }
                else if (bag.BagID.Equals(PkcsObjectIdentifiers.CertBag))
                {
                    var certBag = CertBag.GetInstance(bag.BagValue);
                    var der = Asn1OctetString.GetInstance(certBag.CertValue).GetOctets();
                    certs.Add(new X509CertificateParser().ReadCertificate(der));
                }
            }
        }

        if (certs.Count == 0)
            throw new InvalidOperationException("PKCS12 store contains no certificate.");
        if (keyInfo == null)
            throw new InvalidOperationException("PKCS12 store contains no private key.");

        // Order the chain so the key's certificate comes first.
        var leaf = MatchLeaf(certs, keyInfo) ?? certs[0];
        var chain = new List<X509Certificate> { leaf };
        chain.AddRange(certs.Where(c => c != leaf));

        return new SigningKey
        {
            Certificate = leaf,
            PrivateKey = BuildPrivateKey(keyInfo, leaf),
            Chain = chain
        };
    }

    private static byte[] Decrypt(AlgorithmIdentifier algId, byte[] data, char[] password)
    {
        var cipherParams = PbeUtilities.GenerateCipherParameters(algId, password);
        var cipher = (IBufferedCipher)PbeUtilities.CreateEngine(algId);
        cipher.Init(false, cipherParams);
        return cipher.DoFinal(data);
    }

    private static AsymmetricKeyParameter BuildPrivateKey(PrivateKeyInfo keyInfo, X509Certificate cert)
    {
        try
        {
            return PrivateKeyFactory.CreateKey(keyInfo); // RSA and any key BouncyCastle knows.
        }
        catch
        {
            return BuildGostPrivateKey(keyInfo, cert); // KZ GOST: reconstruct from the cert's curve.
        }
    }

    /// <summary>
    /// Reconstruct a GOST EC private key whose PKCS#8 wrapper uses a KZ OID.
    /// The private scalar D is stored little-endian inside an OCTET STRING.
    /// </summary>
    private static AsymmetricKeyParameter BuildGostPrivateKey(PrivateKeyInfo keyInfo, X509Certificate cert)
    {
        var spki = cert.CertificateStructure.SubjectPublicKeyInfo;
        var curveOid = (spki.Algorithm.Parameters as Asn1Sequence)?[0] is DerObjectIdentifier oid
            ? oid.Id
            : (KzGost.IsGost2015(spki.Algorithm.Algorithm) ? KzGost.CurveGost2015.Id : KzGost.CurveGost2004.Id);
        var domain = KzGost.GetCurve(curveOid);

        var inner = keyInfo.ParsePrivateKey().ToAsn1Object();
        byte[] dLe = inner switch
        {
            Asn1OctetString os => os.GetOctets(),
            DerInteger di => di.Value.ToByteArrayUnsigned(),
            _ => Asn1OctetString.GetInstance(inner).GetOctets()
        };
        var d = KzGost.LeToPositive(dLe, 0, dLe.Length);
        return new ECPrivateKeyParameters(d, domain);
    }

    private static X509Certificate? MatchLeaf(List<X509Certificate> certs, PrivateKeyInfo keyInfo)
    {
        // The leaf is the certificate whose public key OID matches the private key's.
        var keyAlg = keyInfo.PrivateKeyAlgorithm.Algorithm;
        return certs.FirstOrDefault(c =>
            c.CertificateStructure.SubjectPublicKeyInfo.Algorithm.Algorithm.Equals(keyAlg))
            ?? certs.FirstOrDefault(c => !IsSelfIssued(c));
    }

    private static bool IsSelfIssued(X509Certificate c) => c.IssuerDN.Equivalent(c.SubjectDN);
}
