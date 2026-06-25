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
- ⚠️ Curve-параметры GOST-2015 подтверждены тестом на боевой иерархии. **GOST-2004 не проверен**
  (нет фикстуры) — см. ниже.

### `CryptCore/Pki/IRevocationChecker.cs` — ✅ абстракция отзыва
- Enum `RevocationStatus { Good, Revoked, Unknown }` + интерфейс. Развязывает `ChainValidator`
  от сети, делает revocation тестируемым.

### `CryptCore/Pki/OcspRevocationChecker.cs` — ✅ OCSP (RFC 6960), ⚠️ wire не проверен вживую
- Запрос строится через `CertificateID`, POST на ответчик из AIA сертификата
  (fallback — `OcspResponderUrl` из конфига).
- ГОСТ-aware проверка подписи ответа (вручную через `KzGost`, обе ориентации байт).
- Не доверяет ответу вслепую: вшитый responder-сертификат должен быть выпущен тем же CA.
- Сеть/парс-ошибка/недоверенный ответ → `Unknown`.
- ⚠️ **Hash-алгоритм CertID = SHA-256 по умолчанию** (`CertIdHashAlgorithm`). НУЦ РК может
  ждать SHA-1 — не подтверждено против живого ответчика. См. раздел «Что нужно сделать».

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
- Строит `OcspRevocationChecker` (общий `HttpClient`, timeout 10с) + `ChainValidator`
  из `CaCertsPath`. При отсутствии пути — **WARNING**, что проверка цепочки отключена.
- `VerifyDto.ValidateOcsp` → `checkRevocation` через весь стек (флаг больше не игнорируется).

### `KalkanCore/BaseOptions/BaseOptions.cs` — ✅ конфиг
- `KalkanOption.CaCertsPath` — папка PEM-корней (по умолч. отключено = небезопасно).
- `KalkanOption.OcspResponderUrl` — fallback-URL ответчика.

### `CryptCore.Tests/` — ✅ 12 тестов, все зелёные
- `ChainValidatorTests` (5): боевой NCA-сертификат → trusted; истёкший → reject;
  чужая иерархия → reject; самоподписанный с поддельным IIN → reject; пустой стор → throw.
- `TrustEnforcementTests` (2): демонстрация уязвимости (без стора подделка проходит) и фикса.
- `RevocationTests` (5): Revoked/Good/Unknown(fail-closed)/Unknown(soft)/skip — через фейковый
  `IRevocationChecker`, без сети.

---

## Что нужно сделать (вернуться к фичам)

### 🔴 P0 — включить в проде (`appsettings*.json`)
Без этого вся проверка доверия **выключена** (приём подписи от любого сертификата):
```json
"Kalkan": {
  "Path": "...", "Key": "...",
  "CaCertsPath": "Infra/Ca_Certs",
  "OcspResponderUrl": "http://ocsp.pki.gov.kz"
}
```
И на стороне вызова входящих запросов передавать `ValidateOcsp = true`.

### 🔴 P0 — интеграционный тест OCSP против живого `ocsp.pki.gov.kz`
Файл: `OcspRevocationChecker.cs` (поле `CertIdHashAlgorithm`).
- Подтвердить hash-алгоритм CertID (SHA-256 vs SHA-1). Если ответчик возвращает `Unknown`
  на заведомо валидный сертификат — переключить на `CertificateID.HashSha1`.
- Прогнать на **отозванном** тестовом сертификате → ожидаем `Revoked`, а не `Unknown`
  (иначе fail-closed отклонит всё подряд, но по неверной причине).
- Этого нет в CI (нужна сеть) — оформить как ручной/опциональный integration-тест.

### 🟡 P1 — GOST-2004 (старые сертификаты)
Файлы: `CryptCore/Pki/KzGost.cs` (curve-параметры), `CryptCore.Tests`.
- Curve-параметры GOST-2004 помечены как «best known» и **не проверены тестом** (нет фикстуры).
- Если в проде встречаются GOST-2004 сертификаты: добавить такой `.p12`/`.pem` в фикстуры
  и тест «chains to root». Если подпись CA не сойдётся — задать подлинные параметры через
  `KzGost.RegisterCurve`.

### 🟡 P1 — CRL как fallback к OCSP
Файлы: новый `CryptCore/Pki/CrlRevocationChecker.cs`, `ChainValidator`.
- Сейчас при `Unknown` от OCSP (ответчик недоступен) и fail-closed всё отклоняется.
- Реализовать `IRevocationChecker` поверх CRL (из CDP-расширения сертификата) и
  композитный чекер «OCSP → при Unknown CRL». ГОСТ-подпись CRL — та же история, что и с OCSP.

### 🟢 P2 — KeyUsage / EKU
Файл: `ChainValidator.cs`.
- Не проверяется назначение ключа (digitalSignature/nonRepudiation) и EKU.
- Низкий приоритет: НУЦ РК выдаёт сертификаты с корректным usage, но для строгого
  соответствия стоит добавить проверку.

### 🟢 P2 — кэш OCSP-ответов
Файл: `OcspRevocationChecker.cs`.
- Каждый Verify с `ValidateOcsp=true` = сетевой запрос. Закэшировать ответ по
  (issuer, serial) с учётом `nextUpdate` из ответа, чтобы не бить ответчик на каждый запрос.

### 🟢 P2 — nonce в OCSP-запросе
Файл: `OcspRevocationChecker.cs` (`BuildRequest`).
- Сейчас nonce не добавляется (защита от replay). Опционально: НУЦ РК ответчик может его
  не поддерживать — проверить при интеграционном тесте.

### ⚪ Прочее
- `OcspRevocationChecker` использует синхронный `.GetAwaiter().GetResult()` поверх `HttpClient`
  внутри синхронного `IRevocationChecker.Check`. Если верификация уйдёт в async-путь —
  пересмотреть на async-интерфейс.
