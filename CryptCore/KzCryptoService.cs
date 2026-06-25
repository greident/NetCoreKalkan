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

    public static KzCryptoService FromPkcs12(byte[] p12, string password, ChainValidator? trust = null)
        => new(Pkcs12Loader.Load(p12, password), trust);

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

    public byte[] SignCms(byte[] data, bool detached = false) => CmsService.Sign(_key, data, detached);

    public VerifyResult VerifyCms(byte[] cms, byte[]? externalContent = null, bool checkRevocation = true)
        => CmsService.Verify(cms, externalContent, _trust, checkRevocation);
}
