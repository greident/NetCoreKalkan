using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;
using CryptCore.Models;
using CryptCore.Pki;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace CryptCore.Signing;

/// <summary>
/// Enveloped XMLDSig signing and verification for RSA and Kazakhstan GOST,
/// matching the wire format produced by the native Kalkan provider
/// (inclusive C14N, enveloped + C14N#WithComments reference transforms).
/// </summary>
public static class XmlDsigService
{
    private const string Ds = SignedXml.XmlDsigNamespaceUrl; // http://www.w3.org/2000/09/xmldsig#
    private const string C14N = SignedXml.XmlDsigC14NTransformUrl;
    private const string C14NComments = SignedXml.XmlDsigC14NWithCommentsTransformUrl;
    private const string Enveloped = SignedXml.XmlDsigEnvelopedSignatureTransformUrl;

    public static string Sign(SigningKey key, string xml)
    {
        var doc = Load(xml);

        // 1. Reference digest over the document (no signature present yet).
        var digestValue = Convert.ToBase64String(Digest(key.KeyAlgorithm, Canonicalizer.Inclusive(doc, withComments: true)));

        // 2. Build the Signature element and append it to the root.
        var sig = doc.CreateElement("ds", "Signature", Ds);
        sig.AppendChild(BuildSignedInfo(doc, key, digestValue));
        var sigValueEl = doc.CreateElement("ds", "SignatureValue", Ds);
        sig.AppendChild(sigValueEl);
        sig.AppendChild(BuildKeyInfo(doc, key.Certificate));
        doc.DocumentElement!.AppendChild(sig);

        // 3. Sign the canonicalised SignedInfo (in document context).
        var signedInfo = (XmlElement)sig.GetElementsByTagName("SignedInfo", Ds)[0]!;
        var signature = KzSignatures.Sign(key, Canonicalizer.InclusiveInContext(signedInfo));
        // The pkigovkz/Kalkan XML profile stores the GOST signature byte-reversed
        // relative to BouncyCastle's r||s encoding. RSA is unaffected.
        if (key.IsGost) Array.Reverse(signature);
        sigValueEl.InnerText = Convert.ToBase64String(signature);

        return ToXmlString(doc);
    }

    /// <summary>
    /// Verify every signature on the document. Signing an already signed document appends
    /// another ds:Signature to the root whose digest covers the earlier ones (NCANode/Kalkan
    /// convention), so signatures are checked last to first, each against the document with
    /// itself and every later signature removed. All must be valid; <see cref="VerifyResult.Signers"/>
    /// lists the signers in signing order.
    /// </summary>
    public static VerifyResult Verify(string xml, ChainValidator? trust = null, bool checkRevocation = true)
    {
        var result = new VerifyResult { Valid = true };
        try
        {
            var working = Load(xml);
            var signatures = working.DocumentElement!.ChildNodes.OfType<XmlElement>()
                .Where(e => e.LocalName == "Signature" && e.NamespaceURI == Ds).ToList();
            // A signature elsewhere than at the root: verify it alone, as before.
            if (signatures.Count == 0 &&
                working.GetElementsByTagName("Signature", Ds).Cast<XmlElement>().FirstOrDefault() is { } nested)
                signatures.Add(nested);
            if (signatures.Count == 0) { result.Valid = false; result.Error = "No ds:Signature element."; return result; }

            for (var i = signatures.Count - 1; i >= 0; i--)
            {
                var error = VerifyOne(working, signatures[i], trust, checkRevocation, result);
                if (error == null) continue;
                result.Valid = false;
                result.Error ??= signatures.Count == 1 ? error : $"Signature #{i + 1}: {error}";
            }
        }
        catch (Exception e)
        {
            result.Valid = false;
            result.Error = e.Message;
        }
        return result;
    }

    /// <summary>Verify one signature and detach it from <paramref name="working"/>; null when valid.</summary>
    private static string? VerifyOne(XmlDocument working, XmlElement sig, ChainValidator? trust, bool checkRevocation, VerifyResult result)
    {
        var signedInfo = (XmlElement)sig.GetElementsByTagName("SignedInfo", Ds)[0]!;
        // SignedInfo is canonicalised in document context, so take it before detaching.
        var signedInfoC14N = Canonicalizer.InclusiveInContext(signedInfo);
        var sigValue = Convert.FromBase64String(Text(sig, "SignatureValue"));
        var declaredDigest = Text(sig, "DigestValue");
        var cert = new X509CertificateParser().ReadCertificate(Convert.FromBase64String(Text(sig, "X509Certificate")));
        var keyOid = cert.CertificateStructure.SubjectPublicKeyInfo.Algorithm.Algorithm;
        result.Signers.Insert(0, CertificateInfoParser.Parse(cert));

        // 1. Reference digest: remove the signature (enveloped transform) and canonicalise.
        sig.ParentNode!.RemoveChild(sig);
        var actualDigest = Convert.ToBase64String(Digest(keyOid, Canonicalizer.Inclusive(working, withComments: true)));
        if (actualDigest != declaredDigest) return "Reference digest mismatch.";

        // 2. Signature over the canonicalised SignedInfo (GOST value is byte-reversed).
        if (KzGost.IsGost(keyOid)) Array.Reverse(sigValue);
        if (!KzSignatures.Verify(cert, signedInfoC14N, sigValue)) return "SignedInfo signature invalid.";

        // 3. Trust: the signature is cryptographically sound, but only trust it if
        // the signer certificate chains to a configured NCA root and is in date.
        if (trust != null)
        {
            var chain = trust.Validate(cert, checkRevocation: checkRevocation);
            if (!chain.Trusted) return chain.Error;
        }
        return null;
    }

    // ---- structure builders -------------------------------------------------

    private static XmlElement BuildSignedInfo(XmlDocument doc, SigningKey key, string digestValue)
    {
        var si = doc.CreateElement("ds", "SignedInfo", Ds);
        si.AppendChild(Method(doc, "CanonicalizationMethod", C14N));
        si.AppendChild(Method(doc, "SignatureMethod", SignatureMethodUri(key.KeyAlgorithm)));

        var reference = doc.CreateElement("ds", "Reference", Ds);
        reference.SetAttribute("URI", "");
        var transforms = doc.CreateElement("ds", "Transforms", Ds);
        transforms.AppendChild(Method(doc, "Transform", Enveloped));
        transforms.AppendChild(Method(doc, "Transform", C14NComments));
        reference.AppendChild(transforms);
        reference.AppendChild(Method(doc, "DigestMethod", DigestMethodUri(key.KeyAlgorithm)));
        var dv = doc.CreateElement("ds", "DigestValue", Ds);
        dv.InnerText = digestValue;
        reference.AppendChild(dv);
        si.AppendChild(reference);
        return si;
    }

    private static XmlElement BuildKeyInfo(XmlDocument doc, X509Certificate cert)
    {
        var keyInfo = doc.CreateElement("ds", "KeyInfo", Ds);
        var x509Data = doc.CreateElement("ds", "X509Data", Ds);
        var x509Cert = doc.CreateElement("ds", "X509Certificate", Ds);
        x509Cert.InnerText = Convert.ToBase64String(cert.GetEncoded());
        x509Data.AppendChild(x509Cert);
        keyInfo.AppendChild(x509Data);
        return keyInfo;
    }

    private static XmlElement Method(XmlDocument doc, string name, string algorithm)
    {
        var el = doc.CreateElement("ds", name, Ds);
        el.SetAttribute("Algorithm", algorithm);
        return el;
    }

    // ---- algorithm mapping --------------------------------------------------

    private static string SignatureMethodUri(DerObjectIdentifier keyOid) =>
        KzGost.IsGost2015(keyOid) ? KzGost.XmlSigGost2015
        : KzGost.IsGost(keyOid) ? KzGost.XmlSigGost2004
        : KzGost.XmlSigRsaSha256;

    private static string DigestMethodUri(DerObjectIdentifier keyOid) =>
        KzGost.IsGost2015(keyOid) ? KzGost.XmlDigestGost2015
        : KzGost.IsGost(keyOid) ? KzGost.XmlDigestGost2004
        : KzGost.XmlDigestSha256;

    private static byte[] Digest(DerObjectIdentifier keyOid, byte[] data)
    {
        if (KzGost.IsGost(keyOid))
        {
            var d = KzGost.CreateDigest(keyOid);
            d.BlockUpdate(data, 0, data.Length);
            var outp = new byte[d.GetDigestSize()];
            d.DoFinal(outp, 0);
            return outp;
        }
        return DigestUtilities.CalculateDigest("SHA-256", data);
    }

    // ---- XML / canonicalisation helpers ------------------------------------

    private static XmlDocument Load(string xml)
    {
        var doc = new XmlDocument { PreserveWhitespace = true };
        doc.LoadXml(xml);
        return doc;
    }

    private static string ToXmlString(XmlDocument doc)
    {
        // Must declare UTF-8: a StringWriter is UTF-16, and a Java (Kalkan) parser
        // reading an encoding="utf-16" declaration on UTF-8 bytes mis-canonicalises
        // the document, breaking the reference digest.
        using var sw = new Utf8StringWriter();
        using var xw = XmlWriter.Create(sw, new XmlWriterSettings { OmitXmlDeclaration = false, Encoding = Encoding.UTF8 });
        doc.Save(xw);
        return sw.ToString();
    }

    private sealed class Utf8StringWriter : StringWriter
    {
        public override Encoding Encoding => Encoding.UTF8;
    }

    private static string Text(XmlElement scope, string localName)
    {
        var node = scope.GetElementsByTagName(localName, Ds)[0]
                   ?? throw new InvalidOperationException($"Missing ds:{localName}.");
        return node.InnerText.Replace("\r", "").Replace("\n", "").Trim();
    }
}
