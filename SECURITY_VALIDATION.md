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
- Не доверяет ответу вслепую (OCSP идёт по голому HTTP):
  - делегированный ответчик должен быть выпущен тем же CA, действовать сейчас **и иметь EKU
    `id-kp-OCSPSigning`** (RFC 6960 §4.2.2.2). Раньше EKU не проверялся — владелец любого
    обычного сертификата НУЦ мог подписать «good» для отозванного сертификата (MITM);
  - ответ должен быть **про запрошенный сертификат** (сверка серийника и хэшей издателя
    в CertID). Раньше брался первый ответ — валидный «good» про чужой сертификат проходил;
  - **nonce**: в запрос кладётся случайный nonce, в ответе он обязан совпасть. Если ответчик
    его не вернул — ответ должен быть не старше `MaxResponseAge` (10 мин);
  - `thisUpdate` не из будущего (допуск 5 мин), `nextUpdate` (если есть) не в прошлом.
- **Кэш**: `Good`/`Revoked` переиспользуются `CacheTtl` (5 мин; ограничено `nextUpdate`, которого
  у НУЦ нет), до 10 000 записей. `Unknown` не кэшируется. Это и есть задержка, с которой
  видна новая отозванность.
- Сеть/парс-ошибка/недоверенный ответ → `Unknown`.
- Промежуточные CA НУЦ (`nca_gost_2022`, `nca_rsa`, …) **не имеют OCSP в AIA**, а
  `ocsp.pki.gov.kz` отвечает на них `malformedRequest`. Для CA-сертификатов без AIA OCSP
  запрос на fallback-ответчик не шлётся → `Unknown` сразу, их статус даёт CRL корня.
  (До этого фикса `ValidateOcsp=true` + fail-closed отклонял **любую** подпись.)
- Живой `ocsp.pki.gov.kz` (проверено 2026-10-27): CertID и с **SHA-256**, и с **SHA-1** → `good`;
  ответ подписан ГОСТ-2015 сертификатом «OCSP GOST» (EKU OCSP Signing, действует
  07.2026–07.2027), выпущенным `nca_gost_2022`; **nonce возвращается**; `nextUpdate` нет.

### `CryptCore/Pki/CrlRevocationChecker.cs` — ✅ CRL, проверен вживую
- URL из CDP-расширения сертификата (только http/https), скачивание, проверка, что CRL выпущен
  издателем сертификата (DN + подпись, ГОСТ — через `KzGost`, RSA — через BouncyCastle).
- CRL с истёкшим `nextUpdate`, чужой подписью или недоступный → `Unknown`.
- Кэш в памяти до `nextUpdate` (набор отозванных серийников); одна загрузка на URL одновременно.
- Размеры НУЦ: CRL корня на промежуточные CA ~0.5 КБ (обновление раз в месяц), CRL НУЦ на
  конечные сертификаты **~20 МБ** (раз в сутки; загрузка + разбор ≈ 9 с).
- **Delta-CRL** из расширения `Freshest CRL` (`nca_d_gost_2022.crl`, ~5 КБ, раз в ~6 ч)
  накладывается на базовый: отзыв из delta → `Revoked`, `removeFromCRL` снимает удержание.
  Delta применяется, только если номер базового CRL ≥ её `BaseCRLNumber` (RFC 5280 §5.2.4);
  недоступная/неподходящая delta не ломает проверку — отвечает базовый CRL.
  Базовый CRL с `DeltaCRLIndicator` (подмена базового на короткую delta) отвергается.

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

### `CryptCore.Tests/` — ✅ 47 офлайн-тестов + 8 live, все зелёные (в `KalkanCore.slnx`)
- `ChainValidatorTests` (7): боевой NCA-сертификат GOST-2015, GOST-2004 и RSA → trusted;
  истёкший → reject; чужая иерархия → reject; самоподписанный с поддельным IIN → reject;
  пустой стор → throw.
- `CaConstraintTests` (7): серт, выпущенный не-CA → reject (и end-to-end через CMS с вложенным
  издателем); CA без keyCertSign → reject; pathLen; ключ без digitalSignature/nonRepudiation → reject.
- `TrustEnforcementTests` (2): демонстрация уязвимости (без стора подделка проходит) и фикса.
- `RevocationTests` (5): Revoked/Good/Unknown(fail-closed)/Unknown(soft)/skip — через фейковый
  `IRevocationChecker`, без сети.
- `CrlRevocationTests` (16): CRL revoked/good/чужая подпись/истёкший/недоступен/нет CDP/кэш;
  delta: отзыв только в delta, снятие удержания, delta к более новому базовому, delta недоступна,
  delta по адресу базового; композит OCSP→CRL; OCSP не шлёт запрос для промежуточного CA.
- `OcspRevocationTests` (10): good от делегированного ответчика и от CA, revoked; ответчик без
  EKU OCSPSigning, ответ про чужой серийник, чужой nonce, старый ответ без nonce → `Unknown`;
  кэш на TTL, `Unknown` не кэшируется.
- `LivePkiTests` (8, только при `KZ_LIVE_PKI=1`): OCSP SHA-256 и SHA-1, CRL корня (ГОСТ-подпись),
  CRL НУЦ (20 МБ), **отозванный серийник из CRL НУЦ → `Revoked` по OCSP и по CRL**,
  серийник, отозванный только в delta → `Revoked` по CRL, полная цепочка с OCSP→CRL. Запуск:
  `KZ_LIVE_PKI=1 dotnet test --filter LivePkiTests`.

---

## Что нужно сделать (вернуться к фичам)

### 🟡 P1 — подпись ГОСТ-2004 ключом против Kalkan
- После исправления S-box проверка ГОСТ-2004 подтверждена на боевых сертификатах, но
  **подпись** ГОСТ-2004 ключом (XML/CMS/WSSE) не проверена: в фикстурах нет приватного
  ключа ГОСТ-2004 (`gost_private_key.pem` пустой — только заголовок). Нужен `.p12` и сверка
  с Kalkan/SmartBridge. (`test_CMS_GOST.txt` — не CMS, а тот же сертификат БЕКБАУОВ.)

### 🟢 P2 — EKU / политика сертификата
Файл: `ChainValidator.cs`.
- keyUsage проверяется, EKU — нет. НУЦ кладёт в EKU свои OID (`1.2.398.3.3.4.*`: физлицо,
  сотрудник организации, первый руководитель…). Если сервису важно, *кто* подписал (например,
  только первый руководитель юрлица), это бизнес-правило поверх `Signers`, а не проверка цепочки.

### 🟢 P2 — TTL кэша OCSP в конфиг
- `CacheTtl`/`MaxResponseAge` — свойства `OcspRevocationChecker` с дефолтами 5/10 мин; в
  `KalkanOption` не вынесены. Вынести, если понадобится другая задержка видимости отзыва.

### ⚪ Прочее
- `OcspRevocationChecker` и `CrlRevocationChecker` используют синхронный `.GetAwaiter().GetResult()`
  поверх `HttpClient` внутри синхронного `IRevocationChecker.Check`. Если верификация уйдёт в
  async-путь — пересмотреть на async-интерфейс.
- Первая проверка конечного сертификата при недоступном OCSP блокирует запрос на загрузку
  20 МБ CRL (~9 с). Можно прогревать CRL фоном при старте.
