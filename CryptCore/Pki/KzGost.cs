using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.Rosstandart;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;

namespace CryptCore.Pki;

/// <summary>
/// Central registry for the Kazakhstan-specific GOST algorithm identifiers
/// (arc 1.2.398.3.10.*) and the BouncyCastle primitives that implement them.
///
/// Kazakhstan certificates ("ҰЛТТЫҚ КУӘЛАНДЫРУШЫ ОРТАЛЫҚ", pki.gov.kz) come in
/// three flavours:
///   * RSA                       — handled directly by BouncyCastle, no registry needed.
///   * GOST 34.310-2004 (256-bit)— ECGOST3410 + GOST 34.311-95 hash.
///   * GOST 34.10-2015  (512-bit)— ECGOST3410-2012 + Streebog-512 hash.
///
/// The native Kalkan provider keeps the curve parameters closed-source, so the
/// curve domain parameters below are the *best known* mapping onto the published
/// CryptoPro / TC26 parameter sets. If signature verification of a real KZ GOST
/// certificate fails, override the mapping at startup via
/// <see cref="RegisterCurve"/> with the authentic parameters.
/// </summary>
public static class KzGost
{
    // ---- Public key algorithm OIDs ------------------------------------------
    /// <summary>GOST 34.310-2004 public key (256-bit).</summary>
    public static readonly DerObjectIdentifier PublicKeyGost2004 = new("1.2.398.3.10.1.1.1.1");
    /// <summary>GOST 34.10-2015 public key (512-bit).</summary>
    public static readonly DerObjectIdentifier PublicKeyGost2015 = new("1.2.398.3.10.1.1.2.2");

    // ---- Signature algorithm OIDs -------------------------------------------
    /// <summary>GOST 34.310-2004 signature (gost34310 + gost34311).</summary>
    public static readonly DerObjectIdentifier SignGost2004 = new("1.2.398.3.10.1.1.1.2");
    /// <summary>GOST 34.10-2015 / Streebog-512 signature.</summary>
    public static readonly DerObjectIdentifier SignGost2015 = new("1.2.398.3.10.1.1.2.3.2");

    // ---- Curve parameter set OIDs -------------------------------------------
    public static readonly DerObjectIdentifier CurveGost2004 = new("1.2.398.3.10.1.1.1.1.1");
    public static readonly DerObjectIdentifier CurveGost2015 = new("1.2.398.3.10.1.1.2.2.1");

    // ---- Digest OIDs --------------------------------------------------------
    public static readonly DerObjectIdentifier DigestGost2004 = new("1.2.398.3.10.1.3.1");
    public static readonly DerObjectIdentifier DigestGost2015 = new("1.2.398.3.10.1.3.3");

    /// <summary>
    /// XMLDSig URIs used by the Kalkan XML signer, kept here so XmlDsig code can
    /// pick the right algorithm purely from the certificate.
    /// </summary>
    public const string XmlSigGost2004 = "http://www.w3.org/2001/04/xmldsig-more#gost34310-gost34311";
    public const string XmlDigestGost2004 = "http://www.w3.org/2001/04/xmldsig-more#gost34311";
    public const string XmlSigGost2015 = "urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34102015-gostr34112015-512";
    public const string XmlDigestGost2015 = "urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34112015-512";
    public const string XmlSigRsaSha256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    public const string XmlDigestSha256 = "http://www.w3.org/2001/04/xmlenc#sha256";

    private static readonly Dictionary<string, ECDomainParameters> Curves = new();

    static KzGost()
    {
        // Default (unverified) curve mapping. The 512-bit KZ set is widely held to
        // coincide with TC26 paramSetA; the 256-bit set with CryptoPro-A.
        // Replace via RegisterCurve(...) if a real cert fails to verify.
        RegisterCurve(CurveGost2015.Id,
            ECGost3410NamedCurves.GetByOid(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512_paramSetA));
        RegisterCurve(CurveGost2004.Id,
            ECGost3410NamedCurves.GetByOid(CryptoProObjectIdentifiers.GostR3410x2001CryptoProA));
    }

    /// <summary>Register / override the curve parameters for a KZ curve OID.</summary>
    public static void RegisterCurve(string curveOid, Org.BouncyCastle.Asn1.X9.X9ECParameters x9)
        => Curves[curveOid] = new ECDomainParameters(x9);

    public static ECDomainParameters GetCurve(string curveOid)
        => Curves.TryGetValue(curveOid, out var c)
            ? c
            : throw new NotSupportedException($"Unknown KZ GOST curve OID {curveOid}. Register it via KzGost.RegisterCurve.");

    /// <summary>True if the algorithm OID belongs to the KZ GOST family.</summary>
    public static bool IsGost(DerObjectIdentifier oid) => oid.Id.StartsWith("1.2.398.3.10.1.1.1") || oid.Id.StartsWith("1.2.398.3.10.1.1.2");

    public static bool IsGost2015(DerObjectIdentifier oid) => oid.Id.StartsWith("1.2.398.3.10.1.1.2");

    /// <summary>True for any OID in the KZ GOST sub-arc (key, signature or digest).</summary>
    public static bool IsGostAny(DerObjectIdentifier oid) => oid.Id.StartsWith("1.2.398.3.10.1.");

    /// <summary>
    /// Fresh digest matching the GOST generation. Accepts a key, signature or
    /// digest OID (the 2015 digest 1.2.398.3.10.1.3.3 maps to Streebog-512,
    /// the 2004 digest 1.2.398.3.10.1.3.1 to GOST 34.311-95).
    /// </summary>
    public static IDigest CreateDigest(DerObjectIdentifier oid) =>
        IsGost2015(oid) || oid.Equals(DigestGost2015) ? new Gost3411_2012_512Digest() : new Gost3411Digest();

    /// <summary>
    /// Fresh DSA-style signer. BouncyCastle's <see cref="ECGost3410Signer"/> performs
    /// the same r/s computation for both GOST 34.10-2001 and 34.10-2012 EC keys —
    /// only the digest (and field size) differ, which is handled by CreateDigest.
    /// </summary>
    public static IDsa CreateSigner(DerObjectIdentifier sigOrKeyOid) => new ECGost3410Signer();

    /// <summary>
    /// Decode a GOST public key from a SubjectPublicKeyInfo whose algorithm OID is
    /// one of the KZ arcs (BouncyCastle's PublicKeyFactory does not know them).
    /// The key is an ASN.1 OCTET STRING holding X||Y as little-endian halves.
    /// </summary>
    public static ECPublicKeyParameters DecodePublicKey(SubjectPublicKeyInfo spki)
    {
        var algOid = spki.Algorithm.Algorithm;
        var curveOid = ResolveCurveOid(spki.Algorithm.Parameters, algOid);
        var domain = GetCurve(curveOid);

        byte[] raw = spki.PublicKey.GetBytes();
        // Strip the DER OCTET STRING wrapper if present.
        if (raw.Length > 2 && raw[0] == 0x04 && raw[1] == raw.Length - 2)
            raw = Asn1OctetString.GetInstance(raw).GetOctets();

        int half = raw.Length / 2;
        var x = LeToPositive(raw, 0, half);
        var y = LeToPositive(raw, half, half);
        var point = domain.Curve.CreatePoint(x, y);
        return new ECPublicKeyParameters(point, domain);
    }

    private static string ResolveCurveOid(Asn1Encodable? parameters, DerObjectIdentifier algOid)
    {
        // GOST params are a SEQUENCE { publicKeyParamSet OID, digestParamSet OID }.
        if (parameters is Asn1Sequence seq && seq.Count > 0 && seq[0] is DerObjectIdentifier oid)
            return oid.Id;
        return IsGost2015(algOid) ? CurveGost2015.Id : CurveGost2004.Id;
    }

    /// <summary>Interpret bytes [off, off+len) as a little-endian unsigned integer.</summary>
    public static BigInteger LeToPositive(byte[] data, int off, int len)
    {
        var be = new byte[len];
        for (int i = 0; i < len; i++)
            be[i] = data[off + len - 1 - i];
        return new BigInteger(1, be);
    }

    /// <summary>Encode a BigInteger as a fixed-length little-endian byte array.</summary>
    public static byte[] ToLeFixed(BigInteger v, int len)
    {
        var be = v.ToByteArrayUnsigned();
        var le = new byte[len];
        for (int i = 0; i < be.Length && i < len; i++)
            le[i] = be[be.Length - 1 - i];
        return le;
    }
}
