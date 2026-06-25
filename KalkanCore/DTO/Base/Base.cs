using System.Xml.Serialization;

namespace KalkanCore.DTO.Base;


[XmlRoot(ElementName="sender")]
public class SenderV1 { 

	[XmlElement(ElementName="senderId")] 
	public string SenderId { get; set; } 

	[XmlElement(ElementName="password")] 
	public string Password { get; set; } 
}

[XmlRoot(ElementName="requestInfo")]
public class RequestInfoV1 { 

	[XmlElement(ElementName="messageId")] 
	public string MessageId { get; set; } 

	[XmlElement(ElementName="correlationId")] 
	public string CorrelationId { get; set; } 

	[XmlElement(ElementName="serviceId")] 
	public string ServiceId { get; set; } 

	[XmlElement(ElementName="messageDate")] 
	public DateTime MessageDate { get; set; } 

	[XmlElement(ElementName="routeId")] 
	public string RouteId { get; set; } 

	[XmlElement(ElementName="sender")] 
	public SenderV1 Sender { get; set; } 

	[XmlElement(ElementName="sessionId")] 
	public string SessionId { get; set; } 
}

[XmlRoot(ElementName="data")]
public class DataV1 { 

	[XmlElement(ElementName="identifier")] 
	public string Identifier { get; set; } 

	[XmlElement(ElementName="token")] 
	public string Token { get; set; } 
}

[XmlRoot(ElementName="requestData")]
public class RequestDataV1<T> where T : class { 

	[XmlElement(ElementName="data")] 
	public T Data { get; set; } 
}

[XmlRoot(ElementName="request")]
public class RequestV1<T> where T : class { 

	[XmlElement(ElementName="requestInfo")] 
	public RequestInfoV1 RequestInfo { get; set; } 

	[XmlElement(ElementName="requestData")] 
	public RequestDataV1<T> RequestData { get; set; } 
}

[XmlRoot(ElementName="SendMessage")]
public class SendMessageV1<T> where T : class { 

	[XmlElement(ElementName="request")] 
	public RequestV1<T> Request { get; set; } 

	[XmlAttribute(AttributeName="ns3")] 
	public string Ns3 { get; set; } 

	[XmlText] 
	public string Text { get; set; } 
}

[XmlRoot(ElementName="Body")]
public class BodyV1<T> where T : class { 

	[XmlElement(ElementName="SendMessage")] 
	public SendMessageV1<T> SendMessage { get; set; } 

	[XmlAttribute(AttributeName="wsu")] 
	public string Wsu { get; set; } 

	[XmlAttribute(AttributeName="Id")] 
	public string Id { get; set; } 

	[XmlText] 
	public string Text { get; set; } 
}

[XmlRoot(ElementName="Envelope")]
public class EnvelopeV1<T> where T : class  { 
	
	[XmlElement(ElementName="Body")] 
	public BodyV1<T> Body { get; set; } 

	[XmlAttribute(AttributeName="SOAP-ENV")]	
	public string SOAPENV { get; set; } 

	[XmlAttribute(AttributeName="typ")] 
	public string Typ { get; set; } 

	[XmlText] 
	public string Text { get; set; } 
}
