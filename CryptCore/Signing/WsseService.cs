using System.Text;
using System.Xml;
using CryptCore.Pki;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Security;

namespace CryptCore.Signing;

/// <summary>
/// WS-Security (OASIS WSS X.509 Token Profile) SOAP signing, used by the
/// Kazakhstan SmartBridge / SHEP integrations. The SOAP Body is referenced by
/// wsu:Id and signed with exclusive C14N — the same wire shape the native
/// Kalkan provider produces. Supports RSA and KZ GOST keys.
/// </summary>
public static class WsseService
{
    private const string Soap11 = "http://schemas.xmlsoap.org/soap/envelope/";
    private const string Wsse = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
    private const string Wsu = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
    private const string ExcC14N = "http://www.w3.org/2001/10/xml-exc-c14n#";
    private const string C14NWithComments = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments";
    private const string Ds = "http://www.w3.org/2000/09/xmldsig#";
    private const string TokenType = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3";
    private const string Base64Encoding = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary";

    /// <summary>Wrap a message body in a SOAP 1.1 envelope and sign it.</summary>
    public static string Sign(SigningKey key, string messageBody, string messageId)
    {
        var doc = new XmlDocument { PreserveWhitespace = true };
        var env = doc.CreateElement("soap", "Envelope", Soap11);
        doc.AppendChild(env);
        env.AppendChild(doc.CreateElement("soap", "Header", Soap11));
        var body = doc.CreateElement("soap", "Body", Soap11);
        env.AppendChild(body);
        body.InnerXml = StripXmlDeclaration(messageBody);
        return SignEnvelope(doc, key, messageId);
    }

    /// <summary>Sign an existing SOAP envelope in place.</summary>
    public static string SignRaw(SigningKey key, string envelope, string messageId)
    {
        var doc = new XmlDocument { PreserveWhitespace = true };
        doc.LoadXml(envelope);
        return SignEnvelope(doc, key, messageId);
    }

    private static string SignEnvelope(XmlDocument doc, SigningKey key, string messageId)
    {
        var env = doc.DocumentElement ?? throw new InvalidOperationException("Empty envelope.");
        var soapNs = env.NamespaceURI;

        var header = FirstChild(env, "Header", soapNs);
        if (header == null)
        {
            header = doc.CreateElement(env.Prefix, "Header", soapNs);
            env.InsertBefore(header, env.FirstChild);
        }
        var body = FirstChild(env, "Body", soapNs)
                   ?? throw new InvalidOperationException("SOAP Body not found.");

        // Reference the Body by its existing Id (as SHEP envelopes carry one); only
        // mint a wsu:Id when the Body has none.
        var bodyId = ExistingId(body);
        if (bodyId == null)
        {
            bodyId = string.IsNullOrEmpty(messageId) ? "id-" + Guid.NewGuid().ToString("N") : messageId;
            SetWsuId(doc, body, bodyId);
        }

        var suffix = Guid.NewGuid().ToString();

        // <wsse:Security soapenv:mustUnderstand="1">
        var security = doc.CreateElement("wsse", "Security", Wsse);
        var mustUnderstand = doc.CreateAttribute(env.Prefix, "mustUnderstand", soapNs);
        mustUnderstand.Value = "1";
        security.Attributes.Append(mustUnderstand);
        header.InsertBefore(security, header.FirstChild);

        // Signature skeleton (DigestValue / SignatureValue filled after normalisation).
        var sig = doc.CreateElement("ds", "Signature", Ds);
        sig.SetAttribute("Id", "sig-" + suffix);
        sig.AppendChild(BuildSignedInfo(doc, key, bodyId));
        sig.AppendChild(doc.CreateElement("ds", "SignatureValue", Ds));
        sig.AppendChild(BuildKeyInfo(doc, key, "ki-" + suffix, "str-" + suffix));
        security.AppendChild(sig);

        // Normalise so that every namespace is a real, in-scope declaration: this
        // makes the canonical bytes computed here identical to those a verifier
        // computes after parsing the output string. Only text nodes are filled in
        // afterwards, so the canonical form stays stable.
        doc = Reparse(doc);
        var bodyN = FirstChild(doc.DocumentElement!, "Body", soapNs)!;
        var signedInfoN = doc.GetElementsByTagName("SignedInfo", Ds).Cast<XmlElement>().First();
        var digestN = signedInfoN.GetElementsByTagName("DigestValue", Ds).Cast<XmlElement>().First();
        var sigValueN = doc.GetElementsByTagName("SignatureValue", Ds).Cast<XmlElement>().First();

        // Body reference: inclusive C14N#WithComments (matches Kalkan's transform).
        digestN.InnerText = Convert.ToBase64String(
            Digest(key.KeyAlgorithm, Canonicalizer.InclusiveInContext(bodyN, withComments: true)));
        // SignedInfo: exclusive C14N with InclusiveNamespaces PrefixList="soap".
        var signature = KzSignatures.Sign(key, Canonicalizer.ExclusiveInContext(signedInfoN, "soap"));
        // pkigovkz/Kalkan stores the GOST SignatureValue byte-reversed vs BouncyCastle.
        if (key.IsGost) Array.Reverse(signature);
        sigValueN.InnerText = Convert.ToBase64String(signature);

        return ToXmlString(doc);
    }

    private static XmlElement BuildSignedInfo(XmlDocument doc, SigningKey key, string bodyId)
    {
        var si = doc.CreateElement("ds", "SignedInfo", Ds);

        var canon = Method(doc, "CanonicalizationMethod", ExcC14N);
        var inclusive = doc.CreateElement("InclusiveNamespaces", ExcC14N); // default xmlns, like Kalkan
        inclusive.SetAttribute("PrefixList", "soap");
        canon.AppendChild(inclusive);
        si.AppendChild(canon);
        si.AppendChild(Method(doc, "SignatureMethod", SignatureMethodUri(key.KeyAlgorithm)));

        var reference = doc.CreateElement("ds", "Reference", Ds);
        reference.SetAttribute("URI", "#" + bodyId);
        var transforms = doc.CreateElement("ds", "Transforms", Ds);
        transforms.AppendChild(Method(doc, "Transform", C14NWithComments));
        reference.AppendChild(transforms);
        reference.AppendChild(Method(doc, "DigestMethod", DigestMethodUri(key.KeyAlgorithm)));
        reference.AppendChild(doc.CreateElement("ds", "DigestValue", Ds));
        si.AppendChild(reference);
        return si;
    }

    private static XmlDocument Reparse(XmlDocument doc)
    {
        var copy = new XmlDocument { PreserveWhitespace = true };
        copy.LoadXml(ToXmlString(doc));
        return copy;
    }

    /// <summary>KeyInfo with the certificate carried as a wsse:KeyIdentifier (Kalkan style).</summary>
    private static XmlElement BuildKeyInfo(XmlDocument doc, SigningKey key, string keyInfoId, string strId)
    {
        var keyInfo = doc.CreateElement("ds", "KeyInfo", Ds);
        keyInfo.SetAttribute("Id", keyInfoId);
        var str = doc.CreateElement("wsse", "SecurityTokenReference", Wsse);
        SetWsuId(doc, str, strId);
        var keyId = doc.CreateElement("wsse", "KeyIdentifier", Wsse);
        keyId.SetAttribute("EncodingType", Base64Encoding);
        keyId.SetAttribute("ValueType", TokenType);
        keyId.InnerText = Convert.ToBase64String(key.Certificate.GetEncoded());
        str.AppendChild(keyId);
        keyInfo.AppendChild(str);
        return keyInfo;
    }

    private static string? ExistingId(XmlElement el)
        => el.Attributes.Cast<XmlAttribute>().FirstOrDefault(a => a.LocalName == "Id")?.Value;

    /// <summary>Verify a WSSE-signed envelope (Body reference + SignedInfo signature).</summary>
    public static Models.VerifyResult Verify(string envelope, ChainValidator? trust = null, bool checkRevocation = true)
    {
        var result = new Models.VerifyResult();
        try
        {
            var doc = new XmlDocument { PreserveWhitespace = true };
            doc.LoadXml(envelope);
            var sig = doc.GetElementsByTagName("Signature", Ds).Cast<XmlElement>().FirstOrDefault()
                      ?? throw new InvalidOperationException("No ds:Signature.");
            var signedInfo = (XmlElement)sig.GetElementsByTagName("SignedInfo", Ds)[0]!;
            var sigValue = Convert.FromBase64String(InnerText(sig, "SignatureValue"));
            var declaredDigest = InnerText(sig, "DigestValue");
            var cert = ExtractCertificate(doc, sig)
                       ?? throw new InvalidOperationException("No signer certificate in WSSE security header.");
            var keyOid = cert.CertificateStructure.SubjectPublicKeyInfo.Algorithm.Algorithm;
            result.Signers.Add(CertificateInfoParser.Parse(cert));

            // Resolve the referenced element and canonicalise it with the transform
            // the signature actually declares (Kalkan uses inclusive c14n#WithComments
            // for the Body, exclusive for SignedInfo — read it, don't assume).
            var reference = (XmlElement)sig.GetElementsByTagName("Reference", Ds)[0]!;
            var refUri = reference.GetAttribute("URI").TrimStart('#');
            var body = FindById(doc, refUri) ?? throw new InvalidOperationException("Referenced element not found.");
            var refTransform = reference.GetElementsByTagName("Transform", Ds).Cast<XmlElement>().LastOrDefault();
            var actualDigest = Convert.ToBase64String(Digest(keyOid, Canonicalize(body, refTransform)));
            if (actualDigest != declaredDigest) { result.Valid = false; result.Error = "Reference digest mismatch."; return result; }

            var canonMethod = (XmlElement)signedInfo.GetElementsByTagName("CanonicalizationMethod", Ds)[0]!;
            if (KzGost.IsGost(keyOid)) Array.Reverse(sigValue);
            result.Valid = KzSignatures.Verify(cert, Canonicalize(signedInfo, canonMethod), sigValue);
            if (!result.Valid) { result.Error = "SignedInfo signature invalid."; return result; }

            // Trust: chain the signer certificate to a configured NCA root before trusting it.
            if (trust != null)
            {
                var chain = trust.Validate(cert, checkRevocation: checkRevocation);
                if (!chain.Trusted) { result.Valid = false; result.Error = chain.Error; }
            }
        }
        catch (Exception e)
        {
            result.Valid = false;
            result.Error = e.Message;
        }
        return result;
    }

    // ---- helpers ------------------------------------------------------------

    /// <summary>
    /// Canonicalise <paramref name="target"/> using the C14N algorithm declared by
    /// <paramref name="algElement"/> (a ds:Transform or ds:CanonicalizationMethod).
    /// Honours the exc-c14n InclusiveNamespaces PrefixList when present.
    /// </summary>
    private static byte[] Canonicalize(XmlElement target, XmlElement? algElement)
    {
        var alg = algElement?.GetAttribute("Algorithm") ?? "";
        if (alg.StartsWith(ExcC14N, StringComparison.Ordinal))
            return Canonicalizer.ExclusiveInContext(target, InclusivePrefixes(algElement));
        if (alg.EndsWith("#WithComments", StringComparison.Ordinal))
            return Canonicalizer.InclusiveInContext(target, withComments: true);
        return Canonicalizer.InclusiveInContext(target);
    }

    /// <summary>
    /// Pull the signer certificate out of the signature's KeyInfo. The native
    /// Kalkan provider embeds it as a wsse:KeyIdentifier; other producers use a
    /// wsse:BinarySecurityToken or a plain ds:X509Certificate.
    /// </summary>
    private static Org.BouncyCastle.X509.X509Certificate? ExtractCertificate(XmlDocument doc, XmlElement sig)
    {
        var b64 = sig.GetElementsByTagName("KeyIdentifier", Wsse).Cast<XmlElement>().FirstOrDefault()?.InnerText
                  ?? sig.GetElementsByTagName("X509Certificate", Ds).Cast<XmlElement>().FirstOrDefault()?.InnerText
                  ?? doc.GetElementsByTagName("BinarySecurityToken", Wsse).Cast<XmlElement>().FirstOrDefault()?.InnerText;
        return b64 == null
            ? null
            : new Org.BouncyCastle.X509.X509CertificateParser().ReadCertificate(Convert.FromBase64String(CleanBase64(b64)));
    }

    private static string? InclusivePrefixes(XmlElement? algElement)
    {
        var inc = algElement?.GetElementsByTagName("InclusiveNamespaces", ExcC14N).Cast<XmlElement>().FirstOrDefault();
        var list = inc?.GetAttribute("PrefixList");
        return string.IsNullOrWhiteSpace(list) ? null : list;
    }

    private static XmlElement Method(XmlDocument doc, string name, string algorithm)
    {
        var el = doc.CreateElement("ds", name, Ds);
        el.SetAttribute("Algorithm", algorithm);
        return el;
    }

    private static void SetWsuId(XmlDocument doc, XmlElement el, string id)
    {
        // Materialise xmlns:wsu as a real declaration so C14N sees it in scope
        // consistently at sign time and after a serialize/parse round-trip.
        if (string.IsNullOrEmpty(el.GetAttribute("xmlns:wsu")))
            el.SetAttribute("xmlns:wsu", Wsu);
        var attr = doc.CreateAttribute("wsu", "Id", Wsu);
        attr.Value = id;
        el.Attributes.Append(attr);
    }

    private static XmlElement? FirstChild(XmlElement parent, string localName, string ns)
        => parent.ChildNodes.Cast<XmlNode>()
            .OfType<XmlElement>()
            .FirstOrDefault(e => e.LocalName == localName && e.NamespaceURI == ns);

    private static XmlElement? FindById(XmlDocument doc, string id)
        => doc.SelectNodes("//*")!.Cast<XmlElement>()
            .FirstOrDefault(e => e.Attributes.Cast<XmlAttribute>()
                .Any(a => a.LocalName == "Id" && a.Value == id));

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
        if (KzGost.IsGostAny(keyOid))
        {
            var d = KzGost.CreateDigest(keyOid);
            d.BlockUpdate(data, 0, data.Length);
            var outp = new byte[d.GetDigestSize()];
            d.DoFinal(outp, 0);
            return outp;
        }
        return DigestUtilities.CalculateDigest("SHA-256", data);
    }

    private static string StripXmlDeclaration(string xml)
    {
        xml = xml.TrimStart();
        if (xml.StartsWith("<?xml"))
        {
            var end = xml.IndexOf("?>", StringComparison.Ordinal);
            if (end >= 0) xml = xml[(end + 2)..].TrimStart();
        }
        return xml;
    }

    private static string InnerText(XmlElement scope, string localName)
        => CleanBase64(scope.GetElementsByTagName(localName, Ds)[0]!.InnerText);

    private static string CleanBase64(string s) => s.Replace("\r", "").Replace("\n", "").Replace(" ", "").Trim();

    private static string ToXmlString(XmlDocument doc)
    {
        // Declare UTF-8 (a StringWriter is UTF-16): a Java/Kalkan parser reading an
        // encoding="utf-16" declaration on UTF-8 bytes mis-canonicalises the document.
        using var sw = new Utf8StringWriter();
        using var xw = XmlWriter.Create(sw, new XmlWriterSettings { OmitXmlDeclaration = false, Encoding = Encoding.UTF8 });
        doc.Save(xw);
        return sw.ToString();
    }

    private sealed class Utf8StringWriter : StringWriter
    {
        public override Encoding Encoding => Encoding.UTF8;
    }
}
