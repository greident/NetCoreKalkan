using System.Xml.Serialization;

// ReSharper disable InconsistentNaming
#pragma warning disable CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider declaring as nullable.

namespace KalkanCore.DTO;


[XmlRoot("Envelope")]
public class Envelope<T> where T : class
{
    [XmlElement("Header")]
    public Header Header { get; set; }
    [XmlElement("Body")]
    public Body<T> Body { get; set; }
}

[XmlRoot("Envelope")]
public class EnvelopeBase
{
    [XmlElement("Header")]
    public Header Header { get; set; }
    [XmlElement("Body")]
    public BodyBase Body { get; set; }

    public ApiResult GetResult()
    {
        var code = Body.SendMessageResponse.response.responseInfo.status.code;
        
        if (code != "SCSS001") // успешный код ответа
        {
            return new ApiResult
            {
                Success = ApiResultEnum.ErrorLogic,
                ErrorMessage = Body.SendMessageResponse.response.responseInfo.status.message
            };
        }
        
        return new ApiResult
        {
            Success = ApiResultEnum.Success,
            Data = Body.SendMessageResponse.response.responseInfo.status.message
        };
    }
}

public class Header
{
}

public class Body<T> where T : class
{
    [XmlElement("SendMessageResponse")]
    public SendMessageResponse<T> SendMessageResponse { get; set; }
}

public class BodyBase
{
    [XmlElement("SendMessageResponse")]
    public SendMessageResponseBase SendMessageResponse { get; set; }
}

public class SendMessageResponse<T> where T : class
{
    [XmlElement("response")]
    public Response<T> response { get; set; }
}

public class SendMessageResponseBase
{
    [XmlElement("response")]
    public ResponseBase response { get; set; }
}

public class ResponseBase 
{
    [XmlElement("responseInfo")]
    public ResponseInfo responseInfo { get; set; }
}

public class Response<T> where T : class
{
    [XmlElement("responseInfo")]
    public ResponseInfo responseInfo { get; set; }
    [XmlElement("responseData")]
    public ResponseData<T> responseData { get; set; }
}

public class ResponseInfo
{
    [XmlElement("messageId")]
    public string messageId { get; set; }
    [XmlElement("responseDate")]
    public DateTime responseDate { get; set; }
    [XmlElement("status")]
    public Status status { get; set; }
}

public class Status
{
    [XmlElement("code")]
    public string code { get; set; }
    [XmlElement("message")]
    public string message { get; set; }
    [XmlElement("nameRu")]
    public string nameRu { get; set; }
    [XmlElement("nameKz")]
    public string nameKz { get; set; } 
    [XmlElement("changeDate")]
    public DateTime changeDate { get; set; }
}

public class ResponseData<T> where T : class
{
    [XmlElement("data")]
    public T data { get; set; }
}