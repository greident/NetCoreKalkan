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
    public static byte[] Sign(SigningKey key, byte[] data, bool detached = false)
    {
        var digestAlg = DigestAlgId(key);
        var contentDigest = Hash(key, data);

        // Signed attributes: contentType + messageDigest + signingTime (RFC 5652 §11).
        var signedAttrs = new Asn1EncodableVector
        {
            new AttributeCms(CmsAttributes.ContentType, new DerSet(CmsObjectIdentifiers.Data)),
            new AttributeCms(CmsAttributes.MessageDigest, new DerSet(new DerOctetString(contentDigest))),
            new AttributeCms(CmsAttributes.SigningTime, new DerSet(new Org.BouncyCastle.Asn1.Cms.Time(DateTime.UtcNow)))
        };
        var attrSet = new DerSet(signedAttrs);
        var signature = KzSignatures.Sign(key, attrSet.GetEncoded(Asn1Encodable.Der));

        var signerInfo = new SignerInfo(
            new SignerIdentifier(IssuerAndSerial(key.Certificate)),
            digestAlg,
            attrSet,
            SignatureAlgId(key),
            new DerOctetString(signature),
            null);

        var certs = new DerSet(key.Chain.Select(c => c.CertificateStructure).Cast<Asn1Encodable>().ToArray());
        var encap = detached
            ? new ContentInfo(CmsObjectIdentifiers.Data, null)
            : new ContentInfo(CmsObjectIdentifiers.Data, new DerOctetString(data));

        var signedData = new SignedData(
            new DerSet(digestAlg),
            encap,
            new DerSet(certs.ToArray()),
            null,
            new DerSet(signerInfo));

        var contentInfo = new ContentInfo(CmsObjectIdentifiers.SignedData, signedData);
        return contentInfo.GetEncoded(Asn1Encodable.Der);
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

    private static bool VerifySigner(SignerInfo signer, List<X509Certificate> certs, byte[]? content, VerifyResult result, ChainValidator? trust, bool checkRevocation)
    {
        var cert = FindCert(certs, signer.SignerID);
        if (cert == null) { result.Error = "Signer certificate not found in CMS."; return false; }
        result.Signers.Add(CertificateInfoParser.Parse(cert));

        var signature = signer.EncryptedDigest.GetOctets();
        var signedAttrs = signer.AuthenticatedAttributes;

        bool cryptoOk;
        if (signedAttrs != null)
        {
            // messageDigest attribute must equal the digest of the content.
            if (content != null)
            {
                var declared = MessageDigest(signedAttrs);
                var actual = HashWith(signer.DigestAlgorithm.Algorithm, content);
                if (declared == null || !declared.SequenceEqual(actual))
                {
                    result.Error = "messageDigest mismatch.";
                    return false;
                }
            }
            // Signature is over the DER SET OF signed attributes.
            var signedBytes = new DerSet(signedAttrs.ToArray()).GetEncoded(Asn1Encodable.Der);
            cryptoOk = KzSignatures.Verify(cert, signedBytes, signature);
        }
        else
        {
            if (content == null) { result.Error = "No content to verify."; return false; }
            cryptoOk = KzSignatures.Verify(cert, content, signature);
        }

        if (!cryptoOk) { result.Error = "Signature invalid."; return false; }

        // Trust: only accept the signer if it chains to a configured NCA root. The
        // certificates bundled in the CMS are offered as candidate issuers (not anchors).
        if (trust != null)
        {
            var chain = trust.Validate(cert, certs, checkRevocation: checkRevocation);
            if (!chain.Trusted) { result.Error = chain.Error; return false; }
        }
        return true;
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

    private static byte[] HashWith(DerObjectIdentifier algOid, byte[] data)
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
