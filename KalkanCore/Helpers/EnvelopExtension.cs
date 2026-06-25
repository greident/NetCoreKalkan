using System.Xml;
using System.Xml.Serialization;
using KalkanCore.DTO.Base;

namespace KalkanCore.Helpers;

public class XsiTypeIgnoringReader : XmlTextReader
{
    public XsiTypeIgnoringReader(TextReader reader) : base(reader) { }

    public override string GetAttribute(string name, string namespaceURI)
    {
        if (name == "type")
        {
            return null;
        }
        return base.GetAttribute(name, namespaceURI);
    }
}

public static class EnvelopExtension
{
    private const string DataElementName = "data";
    
    public static T? GetWrappedData<T>(this Stream stream) where T : class
    {
        using var textReader = new StreamReader(stream);

        using var xmlReader = new XsiTypeIgnoringReader(textReader);
        var serializer = new XmlSerializer(typeof(T), new XmlRootAttribute(DataElementName));

        while (xmlReader.Read())
        {
            if (xmlReader.NodeType == XmlNodeType.Element && xmlReader.LocalName == DataElementName)
            {
                return serializer.Deserialize(xmlReader) as T;
            }
        }
        return null;
    }
    
    public static T? GetInfoAndWrappedData<T>(this Stream stream) where T : class, ISoapInfo
    {
        using var textReader = new StreamReader(stream);

        using var xmlReader = new XsiTypeIgnoringReader(textReader);
        var serializer = new XmlSerializer(typeof(T), new XmlRootAttribute(DataElementName));

        var senderName = string.Empty;
        var correlationId = string.Empty;
        var messageId = string.Empty;
        
        while (xmlReader.Read())
        {
            if (xmlReader.NodeType == XmlNodeType.Element && xmlReader.LocalName == "senderId")
            {
                senderName = xmlReader.ReadString();
            }
            
            if (xmlReader.NodeType == XmlNodeType.Element && xmlReader.LocalName == "messageId")
            {
                messageId = xmlReader.ReadString();
            } 
            
            if (xmlReader.NodeType == XmlNodeType.Element && xmlReader.LocalName == "correlationId")
            {
                correlationId = xmlReader.ReadString();
            }
            
            
            if (xmlReader.NodeType == XmlNodeType.Element && xmlReader.LocalName == DataElementName)
            {
                var result = serializer.Deserialize(xmlReader) as T;
                
                result.SenderName = senderName;
                result.MessageId = messageId;
                result.СorrelationId = correlationId;
                
                return result;
            }
        }
        return null;
    }
}