namespace KalkanCore.DTO.Base;

public interface ISoapInfo
{
    public int Sender { get; set; }
    public string SenderName { get; set; }
    public string SessionId { get; set; }
    public string СorrelationId { get; set; }
    public string MessageId { get; set; }
}