using System.Text;
using CryptCore.Models;
using CryptCore.Pki;
using CryptCore.Signing;

namespace CryptCore;

/// <summary>
/// High-level entry point that mirrors the Kalkan wrapper's surface but runs on
/// pure-managed BouncyCastle crypto, so it works on ARM (and anywhere else)
/// without the native libkalkancryptwr library. Supports RSA and Kazakhstan
/// GOST (34.310-2004 / 34.10-2015) NCA certificates.
///
/// Construct once from a PKCS#12 key (it is thread-safe for signing/verifying,
/// as every operation is stateless over the immutable key) and reuse it.
/// </summary>
public sealed class KzCryptoService
{
    private readonly SigningKey _key;
    private readonly ChainValidator? _trust;

    /// <param name="trust">
    /// Optional trust store. When supplied, every Verify* method additionally requires
    /// the signer certificate to chain to one of its NCA roots and be in date; without
    /// it, Verify* only checks that the signature is cryptographically sound (which a
    /// self-signed certificate with a forged IIN/BIN would also pass).
    /// </param>
    public KzCryptoService(SigningKey key, ChainValidator? trust = null)
    {
        _key = key;
        _trust = trust;
    }

    public static KzCryptoService FromPkcs12(string path, string password, ChainValidator? trust = null)
        => new(Pkcs12Loader.Load(path, password), trust);

    /// <param name="alias">Key to use when the store holds several (see <see cref="Pkcs12Loader.List"/>).</param>
    public static KzCryptoService FromPkcs12(byte[] p12, string password, ChainValidator? trust = null, string? alias = null)
        => new(Pkcs12Loader.Load(p12, password, alias), trust);

    /// <summary>The signing certificate this service signs with.</summary>
    public Org.BouncyCastle.X509.X509Certificate Certificate => _key.Certificate;

    /// <summary>Information about the loaded signing certificate (IIN/BIN, name, validity).</summary>
    public CertificateInfo CertificateInfo => CertificateInfoParser.Parse(_key.Certificate);

    // ---- XMLDSig ------------------------------------------------------------

    public string SignXml(string xml) => XmlDsigService.Sign(_key, xml);

    public VerifyResult VerifyXml(string signedXml, bool checkRevocation = true)
        => XmlDsigService.Verify(signedXml, _trust, checkRevocation);

    // ---- WSSE / SOAP --------------------------------------------------------

    public string SignWsse(string messageBody, string messageId) => WsseService.Sign(_key, messageBody, messageId);

    public string SignWsseRaw(string envelope, string messageId) => WsseService.SignRaw(_key, envelope, messageId);

    public VerifyResult VerifyWsse(string signedEnvelope, bool checkRevocation = true)
        => WsseService.Verify(signedEnvelope, _trust, checkRevocation);

    // ---- CMS / PKCS#7 -------------------------------------------------------

    /// <param name="tsa">When set, the signature carries an RFC 3161 timestamp from it.</param>
    public byte[] SignCms(byte[] data, bool detached = false, ITimestampAuthority? tsa = null)
        => CmsService.Sign(new[] { _key }, data, detached, tsa);

    /// <summary>Co-sign an existing CMS (earlier signers are kept untouched).</summary>
    public byte[] AddCmsSigner(byte[] cms, byte[]? externalContent = null, ITimestampAuthority? tsa = null)
        => CmsService.AddSigners(cms, new[] { _key }, externalContent, tsa);

    public VerifyResult VerifyCms(byte[] cms, byte[]? externalContent = null, bool checkRevocation = true)
        => CmsService.Verify(cms, externalContent, _trust, checkRevocation);

    /// <summary>Content of an attached CMS (null if detached). Not verified — see <see cref="VerifyCms"/>.</summary>
    public byte[]? ExtractCms(byte[] cms) => CmsService.ExtractContent(cms);

    // ---- X.509 --------------------------------------------------------------

    /// <summary>
    /// Parse a certificate (DER or PEM) and check it against the trust store: chains to an
    /// NCA root, in date at <paramref name="atUtc"/> (default: now), key usage, and — with
    /// <paramref name="checkRevocation"/> — not revoked. <see cref="VerifyResult.Signers"/>
    /// carries the parsed certificate even when it is rejected. Without a trust store the
    /// certificate is only parsed and reported as not valid.
    /// </summary>
    public VerifyResult VerifyCertificate(byte[] certificate, bool checkRevocation = true, DateTime? atUtc = null)
    {
        var result = new VerifyResult();
        try
        {
            var cert = new Org.BouncyCastle.X509.X509CertificateParser().ReadCertificate(certificate)
                       ?? throw new ArgumentException("No certificate found in the input.");
            result.Signers.Add(CertificateInfoParser.Parse(cert));

            if (_trust == null)
            {
                result.Error = "No trust store configured: the certificate was parsed but not validated.";
                return result;
            }
            var chain = _trust.Validate(cert, atUtc: atUtc, checkRevocation: checkRevocation);
            result.Valid = chain.Trusted;
            result.Error = chain.Error;
        }
        catch (Exception e)
        {
            result.Valid = false;
            result.Error = e.Message;
        }
        return result;
    }
}
