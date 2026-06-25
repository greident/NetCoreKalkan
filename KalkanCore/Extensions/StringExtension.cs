using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;
using KalkanCore.DTO.Kalkan;
using KalkanCore.Helpers;

namespace KalkanCore.Extensions;

public static class StringExtension
{
    public static string ExtractDigits(this string input)
    {
        return XmlParser.OnlyDigitPattern.Replace(input, "");
    }

    public static CertificateInfoDto GetCertificateInfo(this string certificateBase64)
    {
        var bytes = Convert.FromBase64String(certificateBase64);
        var cert = new System.Security.Cryptography.X509Certificates.X509Certificate2(bytes);
        
        var certSubject = cert.Subject;
        var iinPosition = certSubject?.IndexOf("SERIALNUMBER=IIN", StringComparison.Ordinal) ?? -1;
        var binPosition = certSubject?.IndexOf("OU=BIN", StringComparison.Ordinal) ?? -1;
        
        var emailPosition = certSubject?.IndexOf("E=", StringComparison.Ordinal) ?? -1;
        int emailStartIndex = emailPosition + 2; 
        int emailEndIndex = certSubject.IndexOf(',', emailStartIndex);
        
        var iin = iinPosition > -1 ? certSubject.Substring(iinPosition + 16, 12): string.Empty;
        var bin = binPosition > -1 ? certSubject.Substring(binPosition + 6, 12) : string.Empty;
        
        string email = emailEndIndex == -1 
            ? certSubject.Substring(emailStartIndex) 
            : certSubject.Substring(emailStartIndex, emailEndIndex - emailStartIndex);
        
        var orgNamePosition = certSubject?.IndexOf("O=", StringComparison.Ordinal) ?? -1;
        var orgNameSub = orgNamePosition > -1 ? certSubject.Substring(orgNamePosition + 2) : string.Empty;
        var orgNameEndPosition = orgNameSub?.IndexOf(",", StringComparison.Ordinal) ?? 0;

        var organizationName = orgNamePosition > -1 ? orgNameSub.Substring(0, orgNameEndPosition) : string.Empty;
        
        var certFields = certSubject.Split(", ")
            .Select(field => field.Split('='))
            .Where(parts => parts.Length == 2)
            .ToDictionary(parts => parts[0], parts => parts[1]);

        var lastName = certFields.ContainsKey("SN") ? certFields["SN"] : string.Empty;
        var fullName = certFields.ContainsKey("CN") ? certFields["CN"] : string.Empty;
        var middleName = certFields.ContainsKey("G") ? certFields["G"] : string.Empty;

        var firstName = fullName.Replace(lastName, "").Trim();
        
        var result = new CertificateInfoDto
        {
            IsArhive = cert.Archived,
            NotBefore = cert.NotBefore,
            NotAfter = cert.NotAfter,
            SerialNumber = cert.SerialNumber,
            SubjectInfo = new CertificationSubjectInfoDto
            {
                Iin = iin,
                Bin = bin,
                FirstName = firstName,
                LastName = lastName,
                MiddleName = middleName,
                OrganizationName = organizationName,
                Email = email
            }
        };
        
        return result;
    }
    
    
    public static string CanonicalizeXml(this string xml)
    {
        var xmlDoc = new XmlDocument { PreserveWhitespace = true };
        xmlDoc.LoadXml(xml);

        var xmlCanonicalizer = new XmlDsigC14NTransform();
        xmlCanonicalizer.LoadInput(xmlDoc);

        using var canonicalizedStream = (Stream)xmlCanonicalizer.GetOutput(typeof(Stream));
        using var reader = new StreamReader(canonicalizedStream, Encoding.UTF8);
        return reader.ReadToEnd();
    }
}