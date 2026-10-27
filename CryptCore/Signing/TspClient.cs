using CryptCore.Pki;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tsp;

namespace CryptCore.Signing;

/// <summary>Issues RFC 3161 timestamp tokens over arbitrary data (for CMS: the signature value).</summary>
public interface ITimestampAuthority
{
    /// <summary>
    /// A DER-encoded TimeStampToken (CMS ContentInfo) over <paramref name="data"/>, using a
    /// hash and policy fitting <paramref name="signer"/>'s key.
    /// </summary>
    byte[] Timestamp(byte[] data, SigningKey signer);
}

/// <summary>
/// RFC 3161 client for the NCA time-stamping authority (http://tsp.pki.gov.kz). Observed
/// behaviour of the live TSA (2026-10-27): it accepts SHA-256 and both KZ GOST message
/// imprints; policy 1.2.398.3.3.2.6.4 is answered by the GOST-2015 TSA certificate (under
/// NCA GOST 2022), 1.2.398.3.3.2.6.2 — also the default — by the RSA one (under NCA RSA
/// 2022); 1.2.398.3.3.2.6.1 (GOST-2004) is no longer served.
///
/// The token is checked before it is returned: granted status, matching nonce/imprint/
/// policy, and a cryptographically valid TSA signature. Trust in the TSA certificate is
/// established when the signature carrying the token is verified (see <see cref="CmsService.Verify"/>).
/// </summary>
public sealed class TspClient : ITimestampAuthority
{
    public const string DefaultUrl = "http://tsp.pki.gov.kz";
    public const string GostPolicy = "1.2.398.3.3.2.6.4";
    public const string RsaPolicy = "1.2.398.3.3.2.6.2";

    private static readonly SecureRandom Rng = new();
    private readonly HttpClient _http;
    private readonly string _url;

    public TspClient(HttpClient http, string? url = null)
    {
        _http = http;
        _url = string.IsNullOrWhiteSpace(url) ? DefaultUrl : url;
    }

    public byte[] Timestamp(byte[] data, SigningKey signer)
    {
        var hashAlg = signer.IsGost
            ? (KzGost.IsGost2015(signer.KeyAlgorithm) ? KzGost.DigestGost2015 : KzGost.DigestGost2004)
            : NistObjectIdentifiers.IdSha256;
        var policy = new DerObjectIdentifier(signer.IsGost ? GostPolicy : RsaPolicy);
        var hash = CmsService.HashWith(hashAlg, data);
        var nonce = new BigInteger(63, Rng);

        var gen = new TimeStampRequestGenerator();
        gen.SetCertReq(true);
        gen.SetReqPolicy(policy);
        var request = gen.Generate(hashAlg, hash, nonce);

        using var content = new ByteArrayContent(request.GetEncoded());
        content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/timestamp-query");
        using var http = _http.PostAsync(_url, content).GetAwaiter().GetResult();
        http.EnsureSuccessStatusCode();
        var response = new TimeStampResponse(http.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult());

        if (response.Status is not (0 or 1)) // granted / grantedWithMods
            throw new InvalidOperationException(
                $"TSA refused the request: {response.GetStatusString()} (failInfo {response.GetFailInfo()?.IntValue}).");
        var token = response.TimeStampToken ?? throw new InvalidOperationException("TSA response carries no token.");

        // BouncyCastle's TimeStampResponse.Validate does not know the KZ GOST digests, so check by hand.
        var info = token.TimeStampInfo;
        if (!nonce.Equals(info.Nonce) || info.MessageImprintAlgOid != hashAlg.Id ||
            !info.GetMessageImprintDigest().AsSpan().SequenceEqual(hash) || info.Policy != policy.Id)
            throw new InvalidOperationException("TSA response does not match the request.");

        var encoded = token.GetEncoded();
        var check = CmsService.Verify(encoded, checkRevocation: false);
        if (!check.Valid) throw new InvalidOperationException($"TSA token signature invalid: {check.Error}");
        return encoded;
    }
}
