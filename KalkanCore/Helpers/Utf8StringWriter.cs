using System.Text;

namespace KalkanCore.Helpers;

public class Utf8StringWriter : StringWriter
{
    public override Encoding Encoding => Encoding.UTF8;
}