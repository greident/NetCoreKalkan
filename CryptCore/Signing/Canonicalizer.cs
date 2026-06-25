using System.Security.Cryptography.Xml;
using System.Xml;

namespace CryptCore.Signing;

/// <summary>
/// Canonical XML helpers. We reuse .NET's proven C14N transforms (they are
/// algorithm-agnostic) and only do the crypto ourselves, so the canonical bytes
/// match any standard XMLDSig verifier (Apache Santuario / Kalkan included).
/// </summary>
public static class Canonicalizer
{
    /// <summary>Inclusive C14N (1.0) of a whole document.</summary>
    public static byte[] Inclusive(XmlDocument doc, bool withComments)
    {
        Transform t = withComments ? new XmlDsigC14NWithCommentsTransform() : new XmlDsigC14NTransform();
        t.LoadInput(doc);
        return Read((Stream)t.GetOutput(typeof(Stream)));
    }

    /// <summary>Inclusive C14N of an element as it sits in its document.</summary>
    public static byte[] InclusiveInContext(XmlElement element, bool withComments = false)
        => InContext(element, withComments ? new XmlDsigC14NWithCommentsTransform() : new XmlDsigC14NTransform());

    /// <summary>Exclusive C14N (xml-exc-c14n#) of an element as it sits in its document.</summary>
    public static byte[] ExclusiveInContext(XmlElement element, string? inclusivePrefixes = null)
        => InContext(element, inclusivePrefixes == null
            ? new XmlDsigExcC14NTransform()
            : new XmlDsigExcC14NTransform(inclusivePrefixes));

    /// <summary>
    /// Canonicalise <paramref name="element"/> with the given transform while
    /// preserving its document context: all in-scope ancestor namespace
    /// declarations are hoisted onto a standalone clone. Inclusive C14N keeps
    /// them all; exclusive C14N filters down to the visibly-used ones — both
    /// matching what an in-context canonicalisation would produce.
    /// </summary>
    private static byte[] InContext(XmlElement element, Transform transform)
    {
        var clone = (XmlElement)element.CloneNode(true);
        for (XmlNode? a = element.ParentNode; a is XmlElement ancestor; a = a.ParentNode)
            foreach (XmlAttribute at in ancestor.Attributes)
                if ((at.Name == "xmlns" || at.Prefix == "xmlns") && clone.GetAttributeNode(at.Name) == null)
                    clone.SetAttribute(at.Name, at.Value);

        var tmp = new XmlDocument { PreserveWhitespace = true };
        tmp.AppendChild(tmp.ImportNode(clone, true));
        transform.LoadInput(tmp);
        return Read((Stream)transform.GetOutput(typeof(Stream)));
    }

    private static byte[] Read(Stream s)
    {
        using var ms = new MemoryStream();
        s.CopyTo(ms);
        return ms.ToArray();
    }
}
