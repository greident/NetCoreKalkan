using System.Text.RegularExpressions;

namespace KalkanCore.Helpers;

public static class XmlParser
{
    public static readonly string SoapResponseMessageSuccess = "success";
    public static readonly Regex SoapResponseMessagePattern = new(@"<message>(.*?)<\/message>", RegexOptions.Compiled);
    
    public static readonly Regex OnlyDigitPattern = new(@"\D", RegexOptions.Compiled);
  
    public static readonly Regex XmlSingPattern = new(@"<\w+:X509Certificate>(.*?)<\/\w+:X509Certificate>", RegexOptions.Singleline | RegexOptions.Compiled);
}