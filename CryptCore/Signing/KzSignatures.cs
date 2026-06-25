using CryptCore.Pki;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace CryptCore.Signing;

/// <summary>
/// Low-level "sign / verify these bytes" primitive that transparently handles
/// both RSA and Kazakhstan GOST keys. Everything higher up (XMLDSig, WSSE, CMS)
/// builds on this so the algorithm split lives in exactly one place.
/// </summary>
public static class KzSignatures
{
    /// <summary>Sign raw bytes with the loaded key, returning the signature value.</summary>
    public static byte[] Sign(SigningKey key, byte[] data)
        => key.IsGost ? SignGost(key, data) : SignRsa(key.PrivateKey, data);

    public static byte[] SignRsa(AsymmetricKeyParameter privateKey, byte[] data, string algorithm = "SHA256withRSA")
    {
        var signer = SignerUtilities.GetSigner(algorithm);
        signer.Init(true, privateKey);
        signer.BlockUpdate(data, 0, data.Length);
        return signer.GenerateSignature();
    }

    public static byte[] SignGost(SigningKey key, byte[] data)
    {
        var signer = NewGostSigner(key.KeyAlgorithm);
        signer.Init(true, key.PrivateKey);
        signer.BlockUpdate(data, 0, data.Length);
        return signer.GenerateSignature();
    }

    /// <summary>Verify a signature against the certificate's public key.</summary>
    public static bool Verify(X509Certificate cert, byte[] data, byte[] signature, string rsaAlgorithm = "SHA256withRSA")
    {
        var algOid = cert.CertificateStructure.SubjectPublicKeyInfo.Algorithm.Algorithm;
        return KzGost.IsGost(algOid)
            ? VerifyGost(cert, data, signature)
            : VerifyRsa(cert.GetPublicKey(), data, signature, rsaAlgorithm);
    }

    public static bool VerifyRsa(AsymmetricKeyParameter publicKey, byte[] data, byte[] signature, string algorithm = "SHA256withRSA")
    {
        var signer = SignerUtilities.GetSigner(algorithm);
        signer.Init(false, publicKey);
        signer.BlockUpdate(data, 0, data.Length);
        return signer.VerifySignature(signature);
    }

    public static bool VerifyGost(X509Certificate cert, byte[] data, byte[] signature)
    {
        var spki = cert.CertificateStructure.SubjectPublicKeyInfo;
        var pub = KzGost.DecodePublicKey(spki);
        var signer = NewGostSigner(spki.Algorithm.Algorithm);
        signer.Init(false, pub);
        signer.BlockUpdate(data, 0, data.Length);
        return signer.VerifySignature(signature);
    }

    private static Gost3410DigestSigner NewGostSigner(DerObjectIdentifier algOid)
        => new(KzGost.CreateSigner(algOid), KzGost.CreateDigest(algOid));
}
