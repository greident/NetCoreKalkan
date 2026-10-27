using Org.BouncyCastle.X509;

namespace CryptCore.Pki;

/// <summary>
/// Asks each checker in turn and returns the first definite answer (good or revoked);
/// only when every checker is indeterminate is the result <see cref="RevocationStatus.Unknown"/>.
/// The usual NCA setup is OCSP first (fast, per certificate), then CRL — which covers the
/// issuing CAs that have no OCSP responder and end-entity certificates while OCSP is down.
/// </summary>
public sealed class CompositeRevocationChecker : IRevocationChecker
{
    private readonly IReadOnlyList<IRevocationChecker> _checkers;

    public CompositeRevocationChecker(params IRevocationChecker[] checkers) => _checkers = checkers;

    public RevocationStatus Check(X509Certificate cert, X509Certificate issuer)
    {
        foreach (var checker in _checkers)
        {
            var status = checker.Check(cert, issuer);
            if (status != RevocationStatus.Unknown) return status;
        }
        return RevocationStatus.Unknown;
    }
}
