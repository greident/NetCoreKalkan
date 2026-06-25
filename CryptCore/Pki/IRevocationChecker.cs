using Org.BouncyCastle.X509;

namespace CryptCore.Pki;

/// <summary>Revocation status of a certificate as reported by a responder.</summary>
public enum RevocationStatus
{
    /// <summary>The responder affirmatively says the certificate is not revoked.</summary>
    Good,
    /// <summary>The responder says the certificate is revoked.</summary>
    Revoked,
    /// <summary>No usable answer (no responder URL, network error, bad/untrusted response).</summary>
    Unknown,
}

/// <summary>
/// Checks whether a certificate has been revoked by its issuer. Abstracted so that
/// <see cref="ChainValidator"/> stays free of any network dependency and can be unit
/// tested deterministically; the production implementation is
/// <see cref="OcspRevocationChecker"/>.
/// </summary>
public interface IRevocationChecker
{
    /// <param name="cert">The certificate whose status is being queried.</param>
    /// <param name="issuer">The certificate that issued <paramref name="cert"/>.</param>
    RevocationStatus Check(X509Certificate cert, X509Certificate issuer);
}