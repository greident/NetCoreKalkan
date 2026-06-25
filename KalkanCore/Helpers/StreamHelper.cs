using System.IO.Compression;

namespace KalkanCore.Helpers;

public static class ZipFileHelper
{
    public static MemoryStream Create(string content)
    {
        var stream = new MemoryStream();
        using (var archive = new ZipArchive(stream, ZipArchiveMode.Create, true))
        {
            var fileName = "Application.xml";
            using var inZipFile = archive.CreateEntry(fileName).Open();
            using var fileStreamWriter = new StreamWriter(inZipFile);
            fileStreamWriter.Write(content);
        }
        _ = stream.Seek(0, SeekOrigin.Begin);
        return stream;
    }

    public static string ConvertToBase64(this Stream stream)
    {
        byte[] bytes;
        using (var memoryStream = new MemoryStream())
        {
            stream.CopyTo(memoryStream);
            bytes = memoryStream.ToArray();
        }

        return  Convert.ToBase64String(bytes);
    }
}
