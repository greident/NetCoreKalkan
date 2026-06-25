# CryptCore

Pure-managed analogue of the Kalkan-based signing in `KalkanCore`, built on
**BouncyCastle.NET**. No native `libkalkancryptwr` — so it runs on **ARM** (and
anywhere .NET runs). Supports Kazakhstan NCA certificates: **RSA** and
**GOST** (34.310-2004 / 256-bit and 34.10-2015 / 512-bit).

## Why this exists

`KalkanCore` uses `NKalkan`, which P/Invokes the native `libkalkancryptwr-64.so`
— compiled for **x86_64 only**, so it fails to load on ARM servers. The Java
`NCANode` "works on ARM" only because it ships the Kalkan provider as a
platform-independent JAR; it does not reimplement the crypto. CryptCore instead
reimplements the Kazakhstan GOST identifiers on BouncyCastle's GOST primitives.

## Usage

```csharp
using CryptCore;

var svc = KzCryptoService.FromPkcs12("cert.p12", "password");

// Certificate info (IIN/BIN, name, validity, algorithm)
var info = svc.CertificateInfo;

// Enveloped XMLDSig
string signedXml = svc.SignXml(xml);
bool ok = svc.VerifyXml(signedXml).Valid;

// SOAP WS-Security (SmartBridge / SHEP)
string soap   = svc.SignWsse(messageBody, messageId);
string soap2  = svc.SignWsseRaw(existingEnvelope, messageId);
bool wsseOk   = svc.VerifyWsse(soap).Valid;

// CMS / PKCS#7
byte[] cms    = svc.SignCms(data);                 // attached
byte[] cmsDet = svc.SignCms(data, detached: true); // detached
bool cmsOk    = svc.VerifyCms(cms).Valid;
```

## Layout

| Area | File | Purpose |
|------|------|---------|
| OID/curve registry | `Pki/KzGost.cs` | KZ GOST OIDs, BC algorithm mapping, curve registration, GOST public-key decode |
| Key loading | `Pki/Pkcs12Loader.cs` | Manual PFX parsing (BC's high-level store rejects KZ GOST keys) |
| Cert parsing | `Pki/CertificateInfoParser.cs` | KZ subject DN → IIN/BIN/name/email/org |
| Signature primitive | `Signing/KzSignatures.cs` | RSA + GOST raw sign/verify (single algorithm switch) |
| Canonicalisation | `Signing/Canonicalizer.cs` | Inclusive / exclusive C14N (reuses .NET transforms) |
| CMS | `Signing/CmsService.cs` | Hand-built SignedData (RSA + GOST) |
| XMLDSig | `Signing/XmlDsigService.cs` | Enveloped signature |
| WSSE | `Signing/WsseService.cs` | OASIS WSS X.509 SOAP signature |
| Facade | `KzCryptoService.cs` | High-level entry point |

## Validation status

Verified end-to-end against the **real GOST-512 key** in
`KalkanCore/Infra/Certs` (RAW, CMS, XML and WSSE sign→verify all pass), and
XMLDSig interop is confirmed **both directions** against .NET's standard
`SignedXml` (so the canonical bytes match Apache Santuario / Kalkan verifiers).

The Kazakhstan GOST curve parameters are not published openly; they were
recovered by confirming that the public keys of real NCA certificates lie on
known parameter sets:

* GOST 34.10-2015 (512-bit) → TC26 `paramSetA`
* GOST 34.310-2004 (256-bit) → CryptoPro-A

Both are validated by signing/verifying with the certificate's own key pair. If
a certificate from a different curve ever appears, override the mapping at
startup:

```csharp
KzGost.RegisterCurve(KzGost.CurveGost2015.Id, x9Parameters);
```

> Note: interop with an external **Kalkan/SmartBridge** endpoint should still be
> smoke-tested against the live service, since the WSSE byte format there cannot
> be reproduced offline.
