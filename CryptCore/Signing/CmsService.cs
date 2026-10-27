using CryptCore.Models;
using CryptCore.Pki;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using AttributeCms = Org.BouncyCastle.Asn1.Cms.Attribute;
using SignerInfo = Org.BouncyCastle.Asn1.Cms.SignerInfo;
using IssuerAndSerialNumber = Org.BouncyCastle.Asn1.Cms.IssuerAndSerialNumber;
using SignedData = Org.BouncyCastle.Asn1.Cms.SignedData;
using ContentInfo = Org.BouncyCastle.Asn1.Cms.ContentInfo;

namespace CryptCore.Signing;

/// <summary>
/// CMS (PKCS#7 / RFC 5652) signing and verification for RSA and Kazakhstan GOST.
/// The SignedData structure is assembled by hand on top of <see cref="KzSignatures"/>
/// so the KZ GOST OIDs — which BouncyCastle's high-level CMS helpers do not know —
/// are written and read uniformly with RSA.
/// </summary>
public static class CmsService
{
    private static readonly DerObjectIdentifier Sha256 = new("2.16.840.1.101.3.4.2.1");
    private static readonly DerObjectIdentifier Sha256WithRsa = PkcsObjectIdentifiers.Sha256WithRsaEncryption;

    /// <summary>
    /// Produce a CMS signature over <paramref name="data"/>.
    /// </summary>
    /// <param name="detached">If true the content is not embedded (signature only).</param>
    public static byte[] Sign(SigningKey key, byte[] data, bool detached = false) => Sign(new[] { key }, data, detached);

    /// <summary>
    /// Produce a CMS with one SignerInfo per key over <paramref name="data"/>; with
    /// <paramref name="tsa"/>, each signature gets an RFC 3161 timestamp (unsigned attribute
    /// id-aa-signatureTimeStampToken) proving when it was made.
    /// </summary>
    public static byte[] Sign(IReadOnlyList<SigningKey> keys, byte[] data, bool detached = false, ITimestampAuthority? tsa = null)
    {
        if (keys.Count == 0) throw new ArgumentException("At least one signing key is required.", nameof(keys));
        return Assemble(
            keys.Select(DigestAlgId),
            new ContentInfo(CmsObjectIdentifiers.Data, detached ? null : new DerOctetString(data)),
            keys.SelectMany(k => k.Chain).Select(c => c.CertificateStructure),
            null,
            keys.Select(k => BuildSignerInfo(k, data, tsa)));
    }

    /// <summary>
    /// Add signers to an existing CMS. Existing SignerInfos (and their timestamps) are kept
    /// byte for byte; nothing is re-signed. A detached CMS needs <paramref name="externalContent"/>.
    /// </summary>
    public static byte[] AddSigners(byte[] cms, IReadOnlyList<SigningKey> keys, byte[]? externalContent = null, ITimestampAuthority? tsa = null)
    {
        if (keys.Count == 0) throw new ArgumentException("At least one signing key is required.", nameof(keys));
        var signedData = SignedData.GetInstance(ContentInfo.GetInstance(Asn1Object.FromByteArray(cms)).Content);
        if (!signedData.EncapContentInfo.ContentType.Equals(CmsObjectIdentifiers.Data))
            throw new NotSupportedException($"Only id-data content can be co-signed (got {signedData.EncapContentInfo.ContentType}).");

        var embedded = signedData.EncapContentInfo.Content is Asn1OctetString os ? os.GetOctets() : null;
        if (embedded != null && externalContent != null && !embedded.AsSpan().SequenceEqual(externalContent))
            throw new ArgumentException("The data passed differs from the content embedded in the CMS.");
        var content = embedded ?? externalContent
                      ?? throw new ArgumentException("Detached CMS: pass the signed data to add a signer.");

        return Assemble(
            signedData.DigestAlgorithms.Cast<Asn1Encodable>().Select(AlgorithmIdentifier.GetInstance).Concat(keys.Select(DigestAlgId)),
            signedData.EncapContentInfo,
            (signedData.Certificates?.Cast<Asn1Encodable>().Select(X509CertificateStructure.GetInstance)
             ?? Enumerable.Empty<X509CertificateStructure>()).Concat(keys.SelectMany(k => k.Chain).Select(c => c.CertificateStructure)),
            signedData.CRLs,
            signedData.SignerInfos.Cast<Asn1Encodable>().Select(SignerInfo.GetInstance).Concat(keys.Select(k => BuildSignerInfo(k, content, tsa))));
    }

    private static SignerInfo BuildSignerInfo(SigningKey key, byte[] data, ITimestampAuthority? tsa)
    {
        // Signed attributes: contentType + messageDigest + signingTime (RFC 5652 §11).
        var signedAttrs = new Asn1EncodableVector
        {
            new AttributeCms(CmsAttributes.ContentType, new DerSet(CmsObjectIdentifiers.Data)),
            new AttributeCms(CmsAttributes.MessageDigest, new DerSet(new DerOctetString(Hash(key, data)))),
            new AttributeCms(CmsAttributes.SigningTime, new DerSet(new Org.BouncyCastle.Asn1.Cms.Time(DateTime.UtcNow)))
        };
        var attrSet = new DerSet(signedAttrs);
        var signature = KzSignatures.Sign(key, attrSet.GetEncoded(Asn1Encodable.Der));
        // Kalkan stores the GOST signature value byte-reversed relative to BouncyCastle's
        // r||s, in CMS just as in XML (confirmed on NCA TSA tokens). RSA is unaffected.
        if (key.IsGost) Array.Reverse(signature);

        // RFC 3161 Appendix A: the timestamp covers the signature value as stored.
        DerSet? unsignedAttrs = null;
        if (tsa != null)
        {
            var token = Asn1Object.FromByteArray(tsa.Timestamp(signature, key));
            unsignedAttrs = new DerSet(new AttributeCms(PkcsObjectIdentifiers.IdAASignatureTimeStampToken, new DerSet(token)));
        }

        return new SignerInfo(
            new SignerIdentifier(IssuerAndSerial(key.Certificate)),
            DigestAlgId(key),
            attrSet,
            SignatureAlgId(key),
            new DerOctetString(signature),
            unsignedAttrs);
    }

    private static byte[] Assemble(
        IEnumerable<AlgorithmIdentifier> digestAlgs, ContentInfo encap, IEnumerable<X509CertificateStructure> certs,
        Asn1Set? crls, IEnumerable<SignerInfo> signerInfos)
    {
        static Asn1Encodable[] Distinct(IEnumerable<Asn1Encodable> items)
            => items.DistinctBy(i => Convert.ToBase64String(i.GetEncoded(Asn1Encodable.Der))).ToArray();

        var signedData = new SignedData(
            new DerSet(Distinct(digestAlgs)),
            encap,
            new DerSet(Distinct(certs)),
            crls,
            new DerSet(signerInfos.Cast<Asn1Encodable>().ToArray()));
        return new ContentInfo(CmsObjectIdentifiers.SignedData, signedData).GetEncoded(Asn1Encodable.Der);
    }

    /// <summary>Verify a CMS blob. Pass <paramref name="externalContent"/> for detached signatures.</summary>
    public static VerifyResult Verify(byte[] cms, byte[]? externalContent = null, ChainValidator? trust = null, bool checkRevocation = true)
    {
        var result = new VerifyResult { Valid = true };
        try
        {
            var contentInfo = ContentInfo.GetInstance(Asn1Object.FromByteArray(cms));
            var signedData = SignedData.GetInstance(contentInfo.Content);

            var certs = LoadCerts(signedData);
            byte[]? content = externalContent
                ?? (signedData.EncapContentInfo.Content is Asn1OctetString os ? os.GetOctets() : null);

            foreach (var obj in signedData.SignerInfos)
            {
                var signer = SignerInfo.GetInstance(obj);
                if (!VerifySigner(signer, certs, content, result, trust, checkRevocation))
                    result.Valid = false;
            }
            if (!signedData.SignerInfos.Cast<object>().Any())
                result.Valid = false;
        }
        catch (Exception e)
        {
            result.Valid = false;
            result.Error = e.Message;
        }
        return result;
    }

    /// <summary>
    /// The content embedded in an attached CMS, or null for a detached one. Does not
    /// verify anything — pair it with <see cref="Verify"/> before trusting the bytes.
    /// </summary>
    public static byte[]? ExtractContent(byte[] cms)
    {
        var signedData = SignedData.GetInstance(ContentInfo.GetInstance(Asn1Object.FromByteArray(cms)).Content);
        return signedData.EncapContentInfo.Content is Asn1OctetString os ? os.GetOctets() : null;
    }

    private static bool VerifySigner(SignerInfo signer, List<X509Certificate> certs, byte[]? content, VerifyResult result, ChainValidator? trust, bool checkRevocation)
    {
        var cert = FindCert(certs, signer.SignerID);
        if (cert == null) { result.Error = "Signer certificate not found in CMS."; return false; }
        var info = CertificateInfoParser.Parse(cert);
        result.Signers.Add(info);
        // For RSA, verify with the signer's digest (SHA-256, -384, -512…); GOST picks its own.
        var rsaAlgorithm = (DigestUtilities.GetAlgorithmName(signer.DigestAlgorithm.Algorithm) ?? "SHA256").Replace("-", "") + "withRSA";

        var signature = signer.EncryptedDigest.GetOctets();
        // Kalkan byte order for GOST (see Sign).
        if (KzGost.IsGost(cert.CertificateStructure.SubjectPublicKeyInfo.Algorithm.Algorithm))
            signature = signature.Reverse().ToArray();
        var signedAttrs = signer.AuthenticatedAttributes;

        // Without content only the signed attributes could be checked, which proves nothing
        // about *what* was signed — a detached CMS needs the data passed alongside.
        if (content == null) { result.Error = "No content to verify (detached CMS: pass the signed data)."; return false; }

        bool cryptoOk;
        if (signedAttrs != null)
        {
            // messageDigest attribute must equal the digest of the content.
            var declared = MessageDigest(signedAttrs);
            var actual = HashWith(signer.DigestAlgorithm.Algorithm, content);
            if (declared == null || !declared.SequenceEqual(actual))
            {
                result.Error = "messageDigest mismatch.";
                return false;
            }
            // Signature is over the DER SET OF signed attributes.
            var signedBytes = new DerSet(signedAttrs.ToArray()).GetEncoded(Asn1Encodable.Der);
            cryptoOk = KzSignatures.Verify(cert, signedBytes, signature, rsaAlgorithm);
        }
        else
        {
            cryptoOk = KzSignatures.Verify(cert, content, signature, rsaAlgorithm);
        }

        if (!cryptoOk) { result.Error = "Signature invalid."; return false; }

        // A timestamp proves when the signature was made, so the certificate is judged at
        // that moment: a signature made while the certificate was valid stays valid after
        // it expires. Revocation is still checked as of now (conservative).
        DateTime? signedAt = null;
        if (TimestampToken(signer) is { } token)
        {
            var (genTime, error) = VerifyTimestamp(token, signer.EncryptedDigest.GetOctets(), trust, checkRevocation);
            if (error != null) { result.Error = $"Timestamp invalid: {error}"; return false; }
            signedAt = info.TimestampUtc = genTime;
        }

        // Trust: only accept the signer if it chains to a configured NCA root. The
        // certificates bundled in the CMS are offered as candidate issuers (not anchors).
        if (trust != null)
        {
            var chain = trust.Validate(cert, certs, atUtc: signedAt, checkRevocation: checkRevocation);
            if (!chain.Trusted) { result.Error = chain.Error; return false; }
        }
        return true;
    }

    // ---- timestamps -----------------------------------------------------------

    private static byte[]? TimestampToken(SignerInfo signer)
    {
        if (signer.UnauthenticatedAttributes == null) return null;
        foreach (var a in signer.UnauthenticatedAttributes)
        {
            var attr = AttributeCms.GetInstance(a);
            if (attr.AttrType.Equals(PkcsObjectIdentifiers.IdAASignatureTimeStampToken))
                return attr.AttrValues[0].ToAsn1Object().GetEncoded(Asn1Encodable.Der);
        }
        return null;
    }

    /// <summary>
    /// RFC 3161 token over <paramref name="signatureValue"/>: TSA signature valid (and, with
    /// a trust store, its certificate chaining to an NCA root), certificate marked for time
    /// stamping, imprint matching. Returns the proven time or the reason it is not.
    /// </summary>
    private static (DateTime GenTime, string? Error) VerifyTimestamp(
        byte[] token, byte[] signatureValue, ChainValidator? trust, bool checkRevocation)
    {
        var tokenResult = Verify(token, null, trust, checkRevocation);
        if (!tokenResult.Valid) return (default, tokenResult.Error);

        var signedData = SignedData.GetInstance(ContentInfo.GetInstance(Asn1Object.FromByteArray(token)).Content);
        if (!signedData.EncapContentInfo.ContentType.Equals(PkcsObjectIdentifiers.IdCTTstInfo))
            return (default, "not a TSTInfo token.");
        if (signedData.SignerInfos.Count != 1) return (default, "a timestamp token must have exactly one signer.");

        var tsa = FindCert(LoadCerts(signedData), SignerInfo.GetInstance(signedData.SignerInfos[0]).SignerID);
        if (tsa?.GetExtendedKeyUsage()?.Contains(KeyPurposeID.id_kp_timeStamping) != true)
            return (default, "token is not signed by a time-stamping certificate.");

        var tstInfo = Org.BouncyCastle.Asn1.Tsp.TstInfo.GetInstance(
            Asn1Object.FromByteArray(Asn1OctetString.GetInstance(signedData.EncapContentInfo.Content).GetOctets()));
        var imprint = tstInfo.MessageImprint;
        if (!HashWith(imprint.HashAlgorithm.Algorithm, signatureValue).AsSpan().SequenceEqual(imprint.GetHashedMessage()))
            return (default, "token does not cover this signature.");

        return (tstInfo.GenTime.ToDateTime().ToUniversalTime(), null);
    }

    // ---- helpers ------------------------------------------------------------

    private static AlgorithmIdentifier DigestAlgId(SigningKey key) => key.IsGost
        ? new AlgorithmIdentifier(KzGost.IsGost2015(key.KeyAlgorithm) ? KzGost.DigestGost2015 : KzGost.DigestGost2004)
        : new AlgorithmIdentifier(Sha256, DerNull.Instance);

    private static AlgorithmIdentifier SignatureAlgId(SigningKey key) => key.IsGost
        ? new AlgorithmIdentifier(KzGost.IsGost2015(key.KeyAlgorithm) ? KzGost.SignGost2015 : KzGost.SignGost2004)
        : new AlgorithmIdentifier(Sha256WithRsa, DerNull.Instance);

    private static byte[] Hash(SigningKey key, byte[] data) => key.IsGost
        ? HashWith(key.KeyAlgorithm, data)
        : DigestUtilities.CalculateDigest("SHA-256", data);

    internal static byte[] HashWith(DerObjectIdentifier algOid, byte[] data)
    {
        if (KzGost.IsGostAny(algOid))
        {
            var d = KzGost.CreateDigest(algOid);
            d.BlockUpdate(data, 0, data.Length);
            var outp = new byte[d.GetDigestSize()];
            d.DoFinal(outp, 0);
            return outp;
        }
        return DigestUtilities.CalculateDigest(algOid.Id, data);
    }

    private static IssuerAndSerialNumber IssuerAndSerial(X509Certificate cert) =>
        new(cert.IssuerDN, cert.SerialNumber);

    private static List<X509Certificate> LoadCerts(SignedData signedData)
    {
        var list = new List<X509Certificate>();
        if (signedData.Certificates != null)
            foreach (var c in signedData.Certificates)
                list.Add(new X509Certificate(X509CertificateStructure.GetInstance(c)));
        return list;
    }

    private static X509Certificate? FindCert(List<X509Certificate> certs, SignerIdentifier sid)
    {
        var ias = IssuerAndSerialNumber.GetInstance(sid.ID);
        return certs.FirstOrDefault(c =>
            c.SerialNumber.Equals(ias.SerialNumber.Value) && c.IssuerDN.Equivalent(ias.Name));
    }

    private static byte[]? MessageDigest(Asn1Set attrs)
    {
        foreach (var a in attrs)
        {
            var attr = AttributeCms.GetInstance(a);
            if (attr.AttrType.Equals(CmsAttributes.MessageDigest))
                return Asn1OctetString.GetInstance(attr.AttrValues[0]).GetOctets();
        }
        return null;
    }
}
