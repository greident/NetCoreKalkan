# Проверка подписи входящих запросов: доверие, цепочка, отзыв

Статус ИБ по верификации подписей в `CryptCore`. `Verify*` используется для
**аутентификации входящих запросов** (SHEP/SmartBridge), поэтому проверка доверия —
не опциональная фича, а часть контракта безопасности.

> Контекст проблемы: до этих изменений `Verify*` проверял только криптоматематику и брал
> сертификат подписанта прямо из документа. Самоподписанный сертификат с поддельным
> IIN/BIN проходил как `Valid`. Это закрыто `ChainValidator` (fail-closed).

---

## Что сделано

### `CryptCore/Pki/ChainValidator.cs` — ✅ ядро доверия
- Строит путь от сертификата подписанта до доверенного корня НУЦ РК по DN и проверяет
  подпись каждого звена самостоятельно (стандартный PKIX BouncyCastle падает на KZ GOST
  OID `1.2.398.3.10.*`). RSA — через `cert.Verify`, GOST — через `KzGost` (обе ориентации байт).
- Проверяет срок действия каждого сертификата в цепочке.
- Самоподписанные сертификаты из стора → trust anchors; остальные → промежуточные.
- `Validate(...)` = цепочка + срок + отзыв; `ValidateChainOnly(...)` = без отзыва.
- Fail-closed: `failOnUnknownRevocation = true` по умолчанию.
- **Ограничения CA** (RFC 5280): каждый издатель в пути обязан иметь `basicConstraints cA=TRUE`
  и (если есть keyUsage) `keyCertSign`; соблюдается `pathLenConstraint`. У подписанта keyUsage
  (если есть) должен содержать `digitalSignature` или `nonRepudiation`.
  Закрывает атаку через CMS: владелец любого обычного сертификата НУЦ выпускал своим ключом
  сертификат на чужой ИИН/БИН, вкладывал оба в CMS — цепочка «подделка → свой серт НУЦ →
  NCA → root» сходилась по подписям и принималась как доверенная. XML/WSSE не были
  уязвимы (там издатели берутся только из trust-store).
- Параметры ГОСТ подтверждены тестами на боевых иерархиях: GOST-2015 (2022) и **GOST-2004**
  (2015/2018, сертификат БЕКБАУОВ) + RSA (2018).

### `CryptCore/Pki/KzGost.cs` — ✅ ГОСТ-2004 исправлен
- Хэш ГОСТ 34.311-95 был с S-box BouncyCastle по умолчанию (CryptoPro `D-A`); НУЦ использует
  **тестовый набор `D-TEST`** (параметр хэша `1.2.398.3.10.1.3.1.1.0`). С `D-A` не сходилась ни
  одна ГОСТ-2004 подпись НУЦ — проверка цепочки отклоняла все ГОСТ-2004 сертификаты, а подписи
  ГОСТ-2004 ключами (XML/CMS/WSSE) и `DigestValue` `gost34311` были несовместимы с Kalkan.
  Кривая (CryptoPro-A) и порядок байт подписи были верными.

### `CryptCore/Pki/IRevocationChecker.cs` — ✅ абстракция отзыва
- Enum `RevocationStatus { Good, Revoked, Unknown }` + интерфейс. Развязывает `ChainValidator`
  от сети, делает revocation тестируемым.

### `CryptCore/Pki/OcspRevocationChecker.cs` — ✅ OCSP (RFC 6960), проверен вживую
- Запрос строится через `CertificateID`, POST на ответчик из AIA сертификата
  (fallback — `OcspResponderUrl` из конфига).
- ГОСТ-aware проверка подписи ответа (через `KzGost.VerifyEitherOrientation`, обе ориентации байт).
- Не доверяет ответу вслепую: вшитый responder-сертификат должен быть выпущен тем же CA.
- Сеть/парс-ошибка/недоверенный ответ → `Unknown`.
- Промежуточные CA НУЦ (`nca_gost_2022`, `nca_rsa`, …) **не имеют OCSP в AIA**, а
  `ocsp.pki.gov.kz` отвечает на них `malformedRequest`. Для CA-сертификатов без AIA OCSP
  запрос на fallback-ответчик не шлётся → `Unknown` сразу, их статус даёт CRL корня.
  (До этого фикса `ValidateOcsp=true` + fail-closed отклонял **любую** подпись.)
- Живой `ocsp.pki.gov.kz` (проверено 2026-10-27): CertID и с **SHA-256**, и с **SHA-1** → `good`;
  ответ подписан ГОСТ-2015 сертификатом «OCSP GOST», выпущенным `nca_gost_2022`;
  **nonce поддерживается** (возвращается в ответе).

### `CryptCore/Pki/CrlRevocationChecker.cs` — ✅ CRL, проверен вживую
- URL из CDP-расширения сертификата (только http/https), скачивание, проверка, что CRL выпущен
  издателем сертификата (DN + подпись, ГОСТ — через `KzGost`, RSA — через BouncyCastle).
- CRL с истёкшим `nextUpdate`, чужой подписью или недоступный → `Unknown`.
- Кэш в памяти до `nextUpdate` (набор отозванных серийников); одна загрузка на URL одновременно.
- Размеры НУЦ: CRL корня на промежуточные CA ~0.5 КБ (обновление раз в месяц), CRL НУЦ на
  конечные сертификаты **~20 МБ** (раз в сутки; загрузка + разбор ≈ 9 с).
- ⚠️ Delta-CRL (`nca_d_gost_2022.crl`, обновляется каждые ~6 ч) **не читается**: отзыв,
  сделанный после выпуска базового CRL, виден через CRL только со следующим базовым (до ~1 сут).
  Для конечных сертификатов это fallback — основной путь OCSP, он актуален.

### `CryptCore/Pki/CompositeRevocationChecker.cs` — ✅ OCSP → CRL
- Первый определённый ответ (`Good`/`Revoked`) выигрывает; `Unknown` только если все `Unknown`.

### `CryptCore/Signing/{XmlDsigService,WsseService,CmsService}.cs` — ✅ интеграция
- Каждый `Verify` принимает `ChainValidator? trust` и `bool checkRevocation`.
- Логика: сначала криптопроверка → если ОК и `trust != null` → `trust.Validate(...)`.
  При недоверии `Valid = false` с причиной в `Error`. `Signers` сохраняются для логов.
- CMS: вшитые в сообщение сертификаты передаются как кандидаты-издатели (но не как анкоры).

### `CryptCore/KzCryptoService.cs` — ✅ проброс
- Опциональный `ChainValidator` в конструкторе/фабриках `FromPkcs12`.
- `VerifyXml/VerifyWsse/VerifyCms(..., bool checkRevocation = true)`.
- Без trust-стора поведение прежнее (обратная совместимость).

### `KalkanCore/Services/CryptCoreCryptService.cs` — ✅ DI-обвязка
- Строит `CompositeRevocationChecker(OCSP → CRL)` (OCSP: `HttpClient` timeout 10с,
  CRL: 60с) + `ChainValidator` из `CaCertsPath`. При отсутствии пути — **WARNING**, что
  проверка цепочки отключена.
- `VerifyDto.ValidateOcsp` → `checkRevocation` через весь стек (флаг больше не игнорируется;
  несмотря на имя, включает и CRL). При `RequireRevocationCheck = true` отзыв проверяется
  всегда — флаг запроса может только включить проверку, но не выключить.
- HTTP API: `crypt/verify/xml`, `crypt/verify/xml/base64`, `crypt/verify/wsse`,
  `crypt/cms/sign`, `crypt/cms/verify`; ответ проверки содержит `Error` с причиной отказа.

### `KalkanCore/BaseOptions/BaseOptions.cs` + `appsettings.json` — ✅ конфиг
- `KalkanOption.CaCertsPath` — папка PEM-корней; в `appsettings.json` = `/app/Infra/Ca_Certs`.
- `KalkanOption.OcspResponderUrl` — fallback-URL ответчика; = `http://ocsp.pki.gov.kz`.
- `KalkanOption.RequireRevocationCheck` — отзыв проверяется всегда; = `true`.

### `CryptCore.Tests/` — ✅ 32 офлайн-теста + 7 live, все зелёные (в `KalkanCore.slnx`)
- `ChainValidatorTests` (7): боевой NCA-сертификат GOST-2015, GOST-2004 и RSA → trusted;
  истёкший → reject; чужая иерархия → reject; самоподписанный с поддельным IIN → reject;
  пустой стор → throw.
- `CaConstraintTests` (7): серт, выпущенный не-CA → reject (и end-to-end через CMS с вложенным
  издателем); CA без keyCertSign → reject; pathLen; ключ без digitalSignature/nonRepudiation → reject.
- `TrustEnforcementTests` (2): демонстрация уязвимости (без стора подделка проходит) и фикса.
- `RevocationTests` (5): Revoked/Good/Unknown(fail-closed)/Unknown(soft)/skip — через фейковый
  `IRevocationChecker`, без сети.
- `CrlRevocationTests` (11): CRL revoked/good/чужая подпись/истёкший/недоступен/нет CDP/кэш;
  композит OCSP→CRL; OCSP не шлёт запрос для промежуточного CA.
- `LivePkiTests` (7, только при `KZ_LIVE_PKI=1`): OCSP SHA-256 и SHA-1, CRL корня (ГОСТ-подпись),
  CRL НУЦ (20 МБ), **отозванный серийник из CRL НУЦ → `Revoked` по OCSP и по CRL**,
  полная цепочка с OCSP→CRL. Запуск:
  `KZ_LIVE_PKI=1 dotnet test --filter LivePkiTests`.

---

## Что нужно сделать (вернуться к фичам)

### 🟡 P1 — подпись ГОСТ-2004 ключом против Kalkan
- После исправления S-box проверка ГОСТ-2004 подтверждена на боевых сертификатах, но
  **подпись** ГОСТ-2004 ключом (XML/CMS/WSSE) не проверена: в фикстурах нет приватного
  ключа ГОСТ-2004 (`gost_private_key.pem` пустой — только заголовок). Нужен `.p12` и сверка
  с Kalkan/SmartBridge. (`test_CMS_GOST.txt` — не CMS, а тот же сертификат БЕКБАУОВ.)

### 🟢 P2 — delta-CRL
Файл: `CrlRevocationChecker.cs`.
- Читать `FreshestCRL` / `nca_d_*.crl` поверх базового CRL, чтобы CRL-fallback был актуален
  до ~6 ч, а не до ~1 сут.

### 🟢 P2 — EKU / политика сертификата
Файл: `ChainValidator.cs`.
- keyUsage проверяется, EKU — нет. НУЦ кладёт в EKU свои OID (`1.2.398.3.3.4.*`: физлицо,
  сотрудник организации, первый руководитель…). Если сервису важно, *кто* подписал (например,
  только первый руководитель юрлица), это бизнес-правило поверх `Signers`, а не проверка цепочки.

### 🟢 P2 — кэш OCSP-ответов
Файл: `OcspRevocationChecker.cs`.
- Каждый Verify с `ValidateOcsp=true` = сетевой запрос. Закэшировать ответ по
  (issuer, serial). Живой ответчик отдаёт только `thisUpdate` без `nextUpdate`, так что
  TTL придётся задавать конфигом (например, 5–15 мин).

### 🟢 P2 — nonce в OCSP-запросе
Файл: `OcspRevocationChecker.cs` (`BuildRequest`).
- Сейчас nonce не добавляется (защита от replay). Ответчик НУЦ nonce **поддерживает**
  (проверено) — можно добавлять и сверять. Несовместимо с кэшем ответов: при кэше
  nonce имеет смысл только на промахе.

### ⚪ Прочее
- `OcspRevocationChecker` и `CrlRevocationChecker` используют синхронный `.GetAwaiter().GetResult()`
  поверх `HttpClient` внутри синхронного `IRevocationChecker.Check`. Если верификация уйдёт в
  async-путь — пересмотреть на async-интерфейс.
- Первая проверка конечного сертификата при недоступном OCSP блокирует запрос на загрузку
  20 МБ CRL (~9 с). Можно прогревать CRL фоном при старте.
