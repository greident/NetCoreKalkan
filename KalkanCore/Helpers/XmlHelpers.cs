using System.IO.Compression;
using System.Text;
using System.Xml;
using System.Xml.Serialization;

namespace KalkanCore.Helpers;

public sealed class NamespaceIgnorantXmlReader : XmlReader
{
    private readonly XmlReader _inner;

    public NamespaceIgnorantXmlReader(XmlReader inner)
        => _inner = inner ?? throw new ArgumentNullException(nameof(inner));

    public override string NamespaceURI => string.Empty;
    public override string Prefix => string.Empty;

    public override XmlNameTable NameTable => _inner.NameTable;
    public override ReadState ReadState => _inner.ReadState;

    public override bool Read() => _inner.Read();
    public override void Close() => _inner.Close();
    public override bool EOF => _inner.EOF;
    public override string BaseURI => _inner.BaseURI;
    public override int Depth => _inner.Depth;
    public override bool IsEmptyElement => _inner.IsEmptyElement;
    public override XmlNodeType NodeType => _inner.NodeType;
    public override string LocalName => _inner.LocalName;
    public override string Value => _inner.Value;

    public override int AttributeCount => _inner.AttributeCount;

    public override string GetAttribute(int i) => _inner.GetAttribute(i);
    public override string GetAttribute(string name) => _inner.GetAttribute(name);
    public override string GetAttribute(string name, string namespaceURI)
        => _inner.GetAttribute(name);

    public override bool MoveToAttribute(string name)
        => _inner.MoveToAttribute(name);

    public override bool MoveToAttribute(string name, string ns)
        => _inner.MoveToAttribute(name);

    public override bool MoveToFirstAttribute()
        => _inner.MoveToFirstAttribute();

    public override bool MoveToNextAttribute()
        => _inner.MoveToNextAttribute();

    public override bool MoveToElement()
        => _inner.MoveToElement();

    public override bool ReadAttributeValue()
        => _inner.ReadAttributeValue();

    public override void ResolveEntity()
        => _inner.ResolveEntity();

    public override string LookupNamespace(string prefix)
        => string.Empty;
}


public static class XmlHelpers
{
    
    public static string Compress(byte[] inputBytes)
    {
        using var outputStream = new MemoryStream();
        using (var gZipStream = new GZipStream(outputStream, CompressionMode.Compress))
            gZipStream.Write(inputBytes, 0, inputBytes.Length);

        var outputBytes = outputStream.ToArray();

        return Convert.ToBase64String(outputBytes);
    }
    
    public static string Compress<T>(T obj)
    {
        var xmlSerializer = new XmlSerializer(typeof(T));

        var settings = new XmlWriterSettings
        {
            Indent = true,
            Encoding = Encoding.UTF8,
            OmitXmlDeclaration = true
        };

        // Создаём пустые пространства имён (уберёт xmlns:xsi / xmlns:xsd)
        var emptyNamespaces = new XmlSerializerNamespaces();
        emptyNamespaces.Add(string.Empty, string.Empty);

        using var stringWriter = new StringWriter();
        using var xmlWriter = XmlWriter.Create(stringWriter, settings);

        xmlSerializer.Serialize(xmlWriter, obj, emptyNamespaces);

        var data = stringWriter.ToString();
        var bytes = Encoding.UTF8.GetBytes(data);
	    
        return Compress(bytes);
    }
    
    public static string SerializeToXml<T>(T obj)
    {
        var serializer = new XmlSerializer(typeof(T));

        using var stringWriter = new StringWriter();
        using var writer = new XmlTextWriter(stringWriter);
        
        writer.Formatting = Formatting.Indented;

        serializer.Serialize(writer, obj);
            
        writer.WriteEndElement(); // End of Envelope
        writer.WriteEndDocument();
        return stringWriter.ToString();
    }
    
    public static string SerializeToXmlWithoutDeclare<T>(T obj)
    {
        var serializer = new XmlSerializer(typeof(T));

        var namespaces = new XmlSerializerNamespaces();
        namespaces.Add(string.Empty, ((XmlRootAttribute)Attribute.GetCustomAttribute(typeof(T), typeof(XmlRootAttribute)))?.Namespace);

        var settings = new XmlWriterSettings
        {
            Encoding = Encoding.UTF8,
            Indent = true,
            OmitXmlDeclaration = true
        };

        using var stringWriter = new Utf8StringWriter();
        using var xmlWriter = XmlWriter.Create(stringWriter, settings);
        serializer.Serialize(xmlWriter, obj, namespaces);
        return stringWriter.ToString();
    }
    
    public static string SerializeWithoutDeclaration<T>(T obj)
    {
        var xmlSerializer = new XmlSerializer(typeof(T));

        var settings = new XmlWriterSettings
        {
            OmitXmlDeclaration = true,
            Indent = true,
            Encoding = Encoding.UTF8
        };

        var emptyNamespaces = new XmlSerializerNamespaces();
        emptyNamespaces.Add(string.Empty, string.Empty);

        using var stringWriter = new StringWriter();
        using var xmlWriter = XmlWriter.Create(stringWriter, settings);

        xmlSerializer.Serialize(xmlWriter, obj, emptyNamespaces);
        return stringWriter.ToString();
    }


    public static string EnbekSerialize<T>(T obj)
    {
        var serializer = new XmlSerializer(typeof(T));
        var namespaces = new XmlSerializerNamespaces();
        namespaces.Add("ns2", "http://enbek.kz/contract/ws/schemas");

        var settings = new XmlWriterSettings
        {
            OmitXmlDeclaration = true,
            Encoding = new UTF8Encoding(false),
            Indent = true
        };

        var sb = new StringBuilder();
        using var writer = XmlWriter.Create(sb, settings);
        serializer.Serialize(writer, obj, namespaces);

        return sb.ToString();
    }
    
    public static T DeserializeWithoutNamespaces<T>(this Stream stream)
    {
        var settings = new XmlReaderSettings
        {
            IgnoreComments = true,
            IgnoreWhitespace = true
        };

        using var xmlReader = XmlReader.Create(stream, settings);

        var serializer = new XmlSerializer(typeof(T));
        return (T)serializer.Deserialize(new NamespaceIgnorantXmlReader(xmlReader));
    }

    public static T DeserializeWithoutNamespaces<T>(this string xml)
    {
        using var stringReader = new StringReader(xml);
        var settings = new XmlReaderSettings
        {
            IgnoreComments = true,
            IgnoreWhitespace = true
        };

        using var xmlReader = XmlReader.Create(stringReader, settings);

        var serializer = new XmlSerializer(typeof(T));
        return (T)serializer.Deserialize(new NamespaceIgnorantXmlReader(xmlReader));
    }
}