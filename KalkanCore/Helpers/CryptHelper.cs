using System.Text.RegularExpressions;

namespace KalkanCore.Helpers;

public static class CryptHelper
{
    public static string OscpSuccessResult = "revoked";
    public static string SignatureSuccessResult = "OK";
    
    public static readonly Regex OscpStatusPattern = new(@"OCSP:\s*check certificate status:\s*(\w+)", RegexOptions.Singleline | RegexOptions.Compiled);
    public static readonly Regex SignatureStatusPattern = new(@"Signature\s+is\s+(\w+)", RegexOptions.Singleline | RegexOptions.Compiled);
}