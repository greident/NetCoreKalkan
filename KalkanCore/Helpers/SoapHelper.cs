using System.Xml.Linq;
using System.Xml.Serialization;

namespace KalkanCore.Helpers;

public static class SoapHelper
{
    public static T DeserializeXml<T>(this string xml)
    {
        var doc = XDocument.Parse(xml);
        RemoveNamespaces(doc.Root);
        var serializer = new XmlSerializer(typeof(T));
        using var reader = new StringReader(doc.ToString());
        return (T)serializer.Deserialize(reader);
    }
    
    
    public static T DeserializeXml<T>(this Stream stream)
    {
        var doc = XDocument.Load(stream);
        RemoveNamespaces(doc.Root);
        
        var serializer = new XmlSerializer(typeof(T));
        using var reader = new StringReader(doc.ToString());
        return (T)serializer.Deserialize(reader);
    }
    
    public static T DeserializeXml<T>(this StreamReader stream)
    {
        var doc = XDocument.Load(stream);
        RemoveNamespaces(doc.Root);
        
        var serializer = new XmlSerializer(typeof(T));
        using var reader = new StringReader(doc.ToString());
        return (T)serializer.Deserialize(reader);
    }
    
    public static T DeserializeXmlToCamelCase<T>(this string xml)
    {
        var doc = XDocument.Parse(xml);
        RemoveNamespaces(doc.Root);
        NormalizeElementNames(doc.Root);
        
        var serializer = new XmlSerializer(typeof(T));
        using var reader = new StringReader(doc.ToString());
        return (T)serializer.Deserialize(reader);
    }
    
    private static void RemoveNamespaces(XElement element)
    {
        element.Name = element.Name.LocalName;
        
        foreach (var attr in element.Attributes().Where(a => a.IsNamespaceDeclaration || a.Name.Namespace != XNamespace.None).ToList())
            attr.Remove();

        foreach (var child in element.Elements())
            RemoveNamespaces(child);
    }
    
    private static void NormalizeElementNames(XElement element)
    {
        element.Name = element.Name.LocalName.ToCamelCase();
        foreach (var child in element.Elements())
            NormalizeElementNames(child);
    }
}