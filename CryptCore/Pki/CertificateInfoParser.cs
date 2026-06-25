using CryptCore.Models;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.X509;

namespace CryptCore.Pki;

/// <summary>
/// Extracts Kazakhstan-specific subject fields (IIN/BIN, name parts, org, email)
/// from an NCA certificate's Distinguished Name. Mirrors the data the Kalkan
/// wrapper exposed (CertificateInfoDto).
/// </summary>
public static class CertificateInfoParser
{
    public static CertificateInfo Parse(X509Certificate cert)
    {
        var info = new CertificateInfo
        {
            NotBefore = cert.NotBefore.ToUniversalTime(),
            NotAfter = cert.NotAfter.ToUniversalTime(),
            SerialNumber = cert.SerialNumber.ToString(16),
            Issuer = cert.IssuerDN.ToString(),
            Subject = cert.SubjectDN.ToString(),
            KeyAlgorithm = ResolveAlgorithm(cert),
            SubjectInfo = ParseSubject(cert.SubjectDN)
        };
        return info;
    }

    private static string ResolveAlgorithm(X509Certificate cert)
    {
        var oid = cert.CertificateStructure.SubjectPublicKeyInfo.Algorithm.Algorithm;
        if (KzGost.IsGost2015(oid)) return "GOST-2015";
        if (KzGost.IsGost(oid)) return "GOST-2004";
        return "RSA";
    }

    private static CertSubjectInfo ParseSubject(X509Name dn)
    {
        var values = CollectValues(dn);
        var info = new CertSubjectInfo
        {
            CommonName = First(values, X509Name.CN),
            LastName = First(values, X509Name.Surname),
            MiddleName = First(values, X509Name.GivenName),
            OrganizationName = First(values, X509Name.O),
            Email = First(values, X509Name.EmailAddress) ?? First(values, X509Name.E)
        };

        // serialNumber carries "IINxxxxxxxxxxxx"; for legal entities it may carry "BIN...".
        var serial = First(values, X509Name.SerialNumber);
        AssignIinBin(info, serial);
        // OU commonly carries "BINxxxxxxxxxxxx".
        AssignIinBin(info, First(values, X509Name.OU));

        // First name = common name with the surname removed (CN = "SURNAME GIVENNAME").
        if (!string.IsNullOrEmpty(info.CommonName))
        {
            var cn = info.CommonName!;
            if (!string.IsNullOrEmpty(info.LastName) &&
                cn.StartsWith(info.LastName!, StringComparison.OrdinalIgnoreCase))
                info.FirstName = cn[info.LastName!.Length..].Trim();
            else
                info.FirstName = cn;
        }

        return info;
    }

    private static void AssignIinBin(CertSubjectInfo info, string? value)
    {
        if (string.IsNullOrEmpty(value)) return;
        if (value.StartsWith("IIN", StringComparison.OrdinalIgnoreCase))
            info.Iin ??= value[3..];
        else if (value.StartsWith("BIN", StringComparison.OrdinalIgnoreCase))
            info.Bin ??= value[3..];
    }

    private static Dictionary<DerObjectIdentifier, List<string>> CollectValues(X509Name dn)
    {
        var oids = dn.GetOidList();
        var vals = dn.GetValueList();
        var map = new Dictionary<DerObjectIdentifier, List<string>>();
        for (int i = 0; i < oids.Count; i++)
        {
            var oid = (DerObjectIdentifier)oids[i]!;
            var val = (string)vals[i]!;
            if (!map.TryGetValue(oid, out var list))
                map[oid] = list = new List<string>();
            list.Add(val);
        }
        return map;
    }

    private static string? First(Dictionary<DerObjectIdentifier, List<string>> map, DerObjectIdentifier oid)
        => map.TryGetValue(oid, out var list) && list.Count > 0 ? list[0] : null;
}
