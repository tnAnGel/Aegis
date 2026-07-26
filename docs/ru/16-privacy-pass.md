# Privacy Pass

Privacy Pass — это механизм приёма анонимных одноразовых токенов доверия, выпущенных сторонним issuer (Cloudflare Research, Apple Private Access Tokens, Fastly), которые позволяют уже доверенному клиенту пройти challenge ladder без раскрытия своей личности. AEGIS криптографически проверяет токен (Ed25519, RFC 9578 Type-1) и, если он валиден, выдаёт временный bypass через [chained trust](#chained-trust--цепочка-доверия). Этот документ описывает то, что **реально** делает код в [src/privacy_pass.rs](../../src/privacy_pass.rs) и [src/chained_trust.rs](../../src/chained_trust.rs).

> 🟡 **Статус честности (читать до внедрения).** Verifier полностью реализован и покрыт тестами, реестр issuers управляется через Admin API в рантайме, но **проверка токена ещё не подключена к request-path в Pingora-обработчике** ([src/proxy/pingora_http.rs](../../src/proxy/pingora_http.rs) не вызывает `parse_token`/`verify`). На данный момент это: рабочий verifier + рантайм-реестр + Admin API + счётчики/панель, но не сквозной фильтр в data plane. Подробнее — раздел [Что реально работает, а что нет](#что-реально-работает-а-что-нет).

---

## 1. Зачем это нужно

Privacy Pass (RFC 9576 по семантике, RFC 9578 по формату токена) решает компромисс между UX и защитой: доверенный браузер, уже прошедший аттестацию у крупного issuer (например, Apple device attestation или Cloudflare), может предъявить **анонимный** токен вместо повторного решения CAPTCHA/PoW. AEGIS:

1. Проверяет подпись токена публичным ключом issuer из локального реестра.
2. Помечает `nonce` токена как использованный (защита от replay).
3. Выдаёт временный bypass challenge ladder на `trust_duration`, заданный issuer.

Это снижает трение для доверенных клиентов и одновременно не требует от AEGIS ничего знать о клиенте — токен анонимен по конструкции (Type-1 — публично проверяемый, без идентификатора пользователя).

См. также: [Challenge ladder, PoW и captcha](./15-challenge-ladder.md), Defence Arsenal.

---

## 2. Формат токена на проводе (RFC 9578 Type-1)

Клиент присылает заголовок (документировано в docstring [src/privacy_pass.rs:14](../../src/privacy_pass.rs)):

```text
Authorization: PrivateToken token=<base64url(token_bytes)>,
                            issuer-name=cloudflare-research.com
```

Сырые байты токена (`token_bytes`) имеют фиксированную раскладку. AEGIS принимает упрощённую raw-форму (НЕ полное HTTP-семантическое кодирование RFC 9578 — см. оговорки):

| Смещение | Поле | Размер | Описание |
|---|---|---|---|
| `0..2` | `token_type` | 2 байта (u16 BE) | `0x0002` для публично проверяемых токенов |
| `2..34` | `nonce` | 32 байта | Уникальный одноразовый идентификатор (anti-replay) |
| `34..66` | `challenge_digest` | 32 байта | Дайджест challenge, к которому привязан токен |
| `66..98` | `token_key_id` | 32 байта | Селектор issuer (RFC 9578 `token_key_id`) |
| `98..end` | `signature` | зависит от семейства ключа | Для Ed25519 — ровно 64 байта |

Разбор выполняет `PrivacyPassVerifier::parse_token` ([src/privacy_pass.rs:178](../../src/privacy_pass.rs)). Любой вход короче 98 байт → `None` (malformed). Подпись забирается как «всё, что после 98 байта», длина проверяется уже на этапе verify.

### Подписываемое сообщение

Подпись покрывает конкатенацию **четырёх** полей (но НЕ саму подпись), реконструируемую в `verify` ([src/privacy_pass.rs:204](../../src/privacy_pass.rs)):

```text
msg = token_type (BE) || nonce || challenge_digest || token_key_id   // ровно 98 байт
```

То есть любое изменение `nonce`, `challenge_digest` или `key_id` инвалидирует подпись — это проверяется тестом `tampered_message_fails_verification` ([src/privacy_pass.rs:565](../../src/privacy_pass.rs)).

---

## 3. Алгоритмы подписи

Тип `SignatureAlgorithm` ([src/privacy_pass.rs:61](../../src/privacy_pass.rs)) знает два варианта:

| Вариант | Wire/admin имя | Назначение | Статус |
|---|---|---|---|
| `Ed25519` | `ed25519` | RFC 8032 Ed25519 — **боевой** алгоритм (V242) | ✅ Production |
| `HmacSha256` | `hmac_sha256` | SHA-256 HMAC (RFC 2104) | 🟡 **Только для тестов** |

> 🔴 **HmacSha256 не для production.** В docstring алгоритма прямо написано: «NOT FOR PRODUCTION». HMAC использует **общий секрет**, что разрушает саму идею Privacy Pass — анонимной проверки по **публичному** ключу. Этот вариант оставлен только чтобы прогонять обвязку verifier без генерации Ed25519-ключа. В бою используйте `ed25519` ([src/privacy_pass.rs:66](../../src/privacy_pass.rs)).

### 3.1. Ed25519 и `verify_strict` (защита от malleable-подписей)

Боевая проверка живёт в `verify_ed25519` ([src/privacy_pass.rs:300](../../src/privacy_pass.rs)) и использует крейт `ed25519_dalek`. Ключевой момент — **используется `VerifyingKey::verify_strict`, а не обычный `verify`**:

```rust
key.verify_strict(msg, &signature)
    .map_err(|_| Ed25519Error::BadSignature)
```

`verify_strict` отвергает подписи, эксплуатирующие malleability точек — small-order / torsion-компоненты кривой Curve25519. Для примитива, который **выдаёт bypass challenge ladder**, это правильный дефолт по умолчанию: строгая проверка гарантирует, что подпись привязана ровно к одному публичному ключу, и атакующий не может подменить ключ через малопорядковую точку ([src/privacy_pass.rs:293-299](../../src/privacy_pass.rs)).

Дополнительные строгие проверки в этом же пути:

- Публичный ключ обязан быть **ровно 32 байта** и валидной канонической сжатой точкой на кривой (`VerifyingKey::from_bytes`). Иначе → `Ed25519Error::InvalidKey`.
- Подпись обязана быть **ровно 64 байта**. Неверная длина — это контролируемое атакующим поле токена, поэтому она трактуется как `BadSignature`, а не как ошибка конфигурации ([src/privacy_pass.rs:307-311](../../src/privacy_pass.rs)).

### 3.2. Различение «плохой ключ» vs «плохая подпись»

Тип `Ed25519Error` ([src/privacy_pass.rs:283](../../src/privacy_pass.rs)) намеренно разделяет два случая, и это **security-relevant**:

| Ошибка | Причина | Внешний исход (`VerifyOutcome`) | Почему так |
|---|---|---|---|
| `InvalidKey` | Зарегистрированный публичный ключ issuer невалиден (не та длина / не на кривой) | `UnsupportedAlgorithm` | Это **ошибка оператора** — она диагностируема, а не выглядит как форджинг |
| `BadSignature` | Подпись не сходится с сообщением + ключом, либо не 64 байта / не каноническая | `BadSignature` | Это **настоящий отказ верификации / попытка подделки** — читается как любой другой плохой токен |

Оба случая **fail closed** (доверие не выдаётся), но `UnsupportedAlgorithm` позволяет оператору, зарегистрировавшему Ed25519-issuer с битым ключом, увидеть конфиг-ошибку, а не «все токены молча отвергаются как подделки».

### 3.3. HMAC-SHA256: история length-extension фикса

> 🟡 Контекст безопасности (даже хотя HMAC — тестовый алгоритм). В V233 функция `verify_hmac_sha256` ([src/privacy_pass.rs:338](../../src/privacy_pass.rs)) была переписана. Раньше она вычисляла `SHA256(key || msg)` — наивный prefix-MAC, уязвимый к **length-extension**: атакующий, наблюдавший один валидный `(msg, tag)` (а токены едут в заголовке запроса, то есть не секретны), мог подделать tag для `msg || pad || suffix` без ключа и получить 24-часовой bypass. Сейчас используется настоящий `Hmac::<Sha256>` (RFC 2104) с **constant-time** сравнением tag через `mac.verify_slice(sig)` (никогда `==`). Регрессионный тест — `length_extended_token_is_rejected` ([src/privacy_pass.rs:526](../../src/privacy_pass.rs)).

Оставшаяся функция `constant_time_eq` ([src/privacy_pass.rs:368](../../src/privacy_pass.rs)) больше не на пути HMAC (его заменил `verify_slice`), но сохранена как корректный dependency-free constant-time примитив для будущих вызывающих, помечена `#[allow(dead_code)]`.

---

## 4. Исходы проверки (`VerifyOutcome`)

`PrivacyPassVerifier::verify` ([src/privacy_pass.rs:199](../../src/privacy_pass.rs)) возвращает один из исходов ([src/privacy_pass.rs:109](../../src/privacy_pass.rs)):

| Исход | Когда | Доверие выдано? |
|---|---|---|
| `Valid` | Подпись валидна И nonce ранее не виден | ✅ Да |
| `UnknownIssuer` | `token_key_id` не найден в реестре | ❌ |
| `BadSignature` | Подпись не сходится / неверная длина | ❌ |
| `Replayed` | nonce уже в replay-кэше | ❌ |
| `Malformed` | (на уровне `parse_token` → `None`) | ❌ |
| `UnsupportedAlgorithm` | Алгоритм распознан, но ключ невалиден / алгоритм не реализован | ❌ (fail closed, но наблюдаемо) |

Порядок проверок в `verify`: **issuer lookup → реконструкция сообщения → проверка подписи → replay-проверка**. Replay помечается только **после** успешной проверки подписи, поэтому неваliдная подпись не «травит» replay-кэш чужими nonce.

---

## 5. Реестр trusted issuers

### 5.1. Структуры

`TrustedIssuer` ([src/privacy_pass.rs:50](../../src/privacy_pass.rs)):

| Поле | Тип | Описание |
|---|---|---|
| `key_id` | `[u8; 32]` | RFC 9578 `token_key_id`, ключ поиска в реестре |
| `name` | `String` | Человекочитаемое имя (напр. `cloudflare-research.com`) |
| `public_key` | `Vec<u8>` | Публичный ключ issuer (для Ed25519 — 32 байта) |
| `algorithm` | `SignatureAlgorithm` | `Ed25519` или `HmacSha256` |
| `trust_duration` | `Duration` | Сколько верифицированный токен даёт доверие до ре-challenge |

Реестр хранится в `PrivacyPassVerifier` ([src/privacy_pass.rs:125](../../src/privacy_pass.rs)) как `RwLock<HashMap<[u8;32], TrustedIssuer>>`. Регистрация **идемпотентна по `key_id`** — повторный `register_issuer` с тем же `key_id` перезаписывает запись (тест `issuer_registration_idempotent_per_key_id`, [src/privacy_pass.rs:505](../../src/privacy_pass.rs)).

### 5.2. Панель-безопасный просмотр (`IssuerInfo`)

`list_issuers` ([src/privacy_pass.rs:159](../../src/privacy_pass.rs)) возвращает `Vec<IssuerInfo>` ([src/privacy_pass.rs:87](../../src/privacy_pass.rs)) — форму, безопасную для сериализации в админ-панель:

| Поле | Описание |
|---|---|
| `name` | Имя issuer |
| `key_id_hex` | `token_key_id` в полном hex (это on-wire селектор, не секрет) |
| `algorithm` | `ed25519` \| `hmac_sha256` |
| `public_key_fingerprint` | `sha256:<первые 16 hex>` от байт ключа — **отпечаток, не сам ключ** |
| `trust_duration_secs` | Окно доверия в секундах |

> 🟡 Хотя Type-1 issuer-ключи — это **публичные** ключи верификации (не секреты), панель всё равно получает только fingerprint, а не сырые байты. Это сохраняет корректность контракта, если будущий алгоритм будет нести приватный материал. Тест `list_issuers_never_leaks_key_bytes` ([src/privacy_pass.rs:728](../../src/privacy_pass.rs)) проверяет, что сырой ключ не попадает в сериализованный JSON. Список отсортирован по `key_id_hex` для стабильного порядка строк в панели.

### 5.3. Ротация ключей

Ротация реализована как **статический реестр**, который Admin API может менять в рантайме (docstring [src/privacy_pass.rs:41](../../src/privacy_pass.rs)). Отдельного механизма автоматической ротации/подтягивания ключей issuer **нет** — оператор регистрирует/перезаписывает issuers вручную через API.

---

## 6. Защита от replay (nonce cache)

`try_mark_seen` ([src/privacy_pass.rs:236](../../src/privacy_pass.rs)) хранит увиденные nonce в `RwLock<HashMap<[u8;32], Instant>>`, где `Instant` — это **момент истечения** (`now + trust_duration`):

- Если nonce уже в кэше → `false` → `VerifyOutcome::Replayed`.
- При переполнении (`cache_capacity`, дефолт **100 000** через `PrivacyPassVerifier::default()`, [src/privacy_pass.rs:270](../../src/privacy_pass.rs)) вытесняется **один самый старый** элемент (`min_by_key` по времени).
- `gc()` ([src/privacy_pass.rs:257](../../src/privacy_pass.rs)) дропает все протухшие nonce; вызывать из того же тика, что обслуживает actuator wheel.
- `nonce_cache_size()` отдаёт текущий размер для метрик/панели.

Тест `gc_drops_expired_nonces` ([src/privacy_pass.rs:486](../../src/privacy_pass.rs)) подтверждает истечение и сборку мусора.

---

## 7. Chained trust — цепочка доверия

Реализация: [src/chained_trust.rs](../../src/chained_trust.rs) (V202). Идея: **более сильный пройденный challenge даёт более длинное окно доверия**, и пройденный сильный challenge освобождает клиента от пере-решения слабых на это окно (docstring [src/chained_trust.rs:1](../../src/chained_trust.rs)).

### 7.1. Уровни (`TrustTier`) и окна

`TrustTier` ([src/chained_trust.rs:50](../../src/chained_trust.rs)) — упорядоченное перечисление; окна задаёт `default_duration` ([src/chained_trust.rs:63](../../src/chained_trust.rs)):

| Tier | `as_str` | Окно доверия | Покрывает |
|---|---|---|---|
| `None` | `none` | 0 | — |
| `Cookie` | `cookie` | 5 минут | L1+L2 |
| `Reload` | `reload` | 15 минут | L1..L3 |
| `Interaction` | `interaction` | 30 минут | — |
| `Pow` | `pow` | 1 час | L1..L4 |
| `Captcha` | `captcha` | 24 часа | L1..L5 |
| `WebAuthn` | `webauthn` | **7 дней** | L1..L6 |
| `PrivacyPass` | `privacy_pass` | 24 часа (issuer-specified) | — |

Privacy Pass входит в эту лестницу как отдельный tier `PrivacyPass`. Заметьте: `default_duration` для него — 24 часа, но реальный `trust_duration` задаёт issuer в `TrustedIssuer`, а replay-окно nonce равно как минимум одному `trust_duration`.

### 7.2. Привязка гранта к подписанному nonce (V233 auth_bypass fix)

> 🔴 Это был критический фикс. Раньше грант доверия был привязан к **голому IP**. Любой за общим CGNAT / корпоративным NAT-выходом мог «прокатиться» на 24-часовом гранте в момент, когда **один** пир за тем же IP прошёл challenge.

Теперь каждый грант привязан к серверному случайному nonce, доставляемому конкретному клиенту как cookie. Реализация ([src/chained_trust.rs:21-32](../../src/chained_trust.rs)):

- Грант хранится по ключу `(IpAddr, RouteClass, nonce)` ([src/chained_trust.rs:119](../../src/chained_trust.rs)).
- `mint_nonce` ([src/chained_trust.rs:162](../../src/chained_trust.rs)) генерирует 16 случайных байт и подписывает их.
- `sign_nonce` ([src/chained_trust.rs:171](../../src/chained_trust.rs)) выдаёт cookie вида `base64(nonce).base64(hmac)`, где HMAC берётся над `ip:nonce` — cookie, выпущенная для одного IP, **не верифицируется под другим**.
- `verify_nonce` ([src/chained_trust.rs:186](../../src/chained_trust.rs)) — constant-time (`Mac::verify_slice`); любой malformed/bad-base64/wrong-IP/forged → `None`.
- `current()`/`covers()` ([src/chained_trust.rs:253](../../src/chained_trust.rs), [src/chained_trust.rs:287](../../src/chained_trust.rs)) требуют, чтобы клиент предъявил совпадающую подписанную cookie. **Отсутствующая или несовпадающая cookie → `TrustTier::None`.** Голого IP никогда не достаточно.

Регрессионный тест `grant_not_honoured_for_same_ip_with_different_or_absent_nonce` ([src/chained_trust.rs:447](../../src/chained_trust.rs)) закрывает именно shared-CGNAT bypass.

### 7.3. HMAC-ключ и переживание рестарта

`ChainedTrustStore::new()` ([src/chained_trust.rs:130](../../src/chained_trust.rs)) генерирует **случайный 32-байтный per-process** HMAC-ключ. Следствие: подписанные nonce не подделать без чтения памяти процесса, но и **рестарт инвалидирует** все выданные cookie. Для переживания рестарта / работы во флоте используйте `with_secret(...)` ([src/chained_trust.rs:146](../../src/chained_trust.rs)) с явным оператор-секретом (тест `cookie_from_other_secret_rejected`, [src/chained_trust.rs:518](../../src/chained_trust.rs)).

### 7.4. Классы маршрутов (`RouteClass`)

`RouteClass` ([src/chained_trust.rs:102](../../src/chained_trust.rs)):

| Класс | Маршруты | Поведение |
|---|---|---|
| `Generic` | всё, кроме auth | Доверие авто-выдаётся |
| `Auth` | `/login`, `/signup`, password-reset | Доверие **никогда** не авто-выдаётся; нужен явный opt-in `with_allow_for_auth(true)` |
| `Api` | `/api/*` | Отдельно настраивается (напр. API-потребители могут аутентифицироваться через mTLS и обходить ladder целиком) |

Гранты по классам **независимы** (тест `route_classes_are_independent`, [src/chained_trust.rs:426](../../src/chained_trust.rs)). `record` на auth-маршруте без opt-in возвращает `None`, и оператор знает, что cookie ставить не нужно ([src/chained_trust.rs:203-244](../../src/chained_trust.rs)).

### 7.5. Анти-даунгрейд

Если у `(ip, route_class)` уже есть живой **более сильный** грант, `record` слабого tier не понижает доверие — он возвращает существующую cookie сильного гранта, и клиент сохраняет более длинное окно ([src/chained_trust.rs:221-232](../../src/chained_trust.rs); тест `stronger_grant_not_downgraded_by_weaker`).

### 7.6. Отзыв и GC

- `revoke(ip)` ([src/chained_trust.rs:300](../../src/chained_trust.rs)) — дропает **все** per-nonce гранты для IP по всем классам (напр. при tamper cookie `aegis_fp` или после deny-решения).
- `gc()` ([src/chained_trust.rs:305](../../src/chained_trust.rs)) — дропает протухшие гранты.

---

## 8. Интеграция и переключатели

### 8.1. Arsenal

Verifier и trust-store живут в `Arsenal` как `Arc`-обёрнутые синглтоны ([src/arsenal.rs:422-507](../../src/arsenal.rs)):

```rust
pub chained_trust: Arc<ChainedTrustStore>,   // ::new()  (process-random secret)
pub privacy_pass:  Arc<PrivacyPassVerifier>, // ::default() (cache_capacity = 100_000)
```

Переключатели в `DomainChallengeConfig` ([src/arsenal.rs:52-58](../../src/arsenal.rs)) — **per-host, оба выключены по умолчанию** (`#[serde(default)]` на `bool` → `false`):

| Поле | Дефолт | Назначение |
|---|---|---|
| `privacy_pass` | `false` | Включить Privacy Pass bypass на этом хосте |
| `chained_trust` | `false` | Включить цепочку прогрессии доверия |
| `trust_for_auth` | `false` | Разрешить прогрессию доверия на auth-маршрутах |

Счётчики (`ShardedCounter`, [src/arsenal.rs:166-169](../../src/arsenal.rs)): `privacy_pass_accepts`, `privacy_pass_rejects`, `chained_trust_grants`, `chained_trust_bypasses`.

### 8.2. Admin API

Обработчики в [src/proxy/pingora_admin.rs](../../src/proxy/pingora_admin.rs):

| Метод | Путь | Действие |
|---|---|---|
| `GET` | `/admin/api/privacy-pass` | Сводка: `issuer_count`, `nonce_cache_size`, `wired` ([:2392](../../src/proxy/pingora_admin.rs)) |
| `GET` | `/admin/api/privacy-pass/issuers` | Полный список issuers (`IssuerInfo`) для панели ([:2412](../../src/proxy/pingora_admin.rs)) |
| `POST` | `/admin/api/privacy-pass/issuers` | Регистрация issuer в рантайме ([:2427](../../src/proxy/pingora_admin.rs)) |

Тело POST-запроса (`Payload`, [src/proxy/pingora_admin.rs:2428](../../src/proxy/pingora_admin.rs)):

```json
{
  "name": "cloudflare-research.com",
  "key_id_hex": "<64 hex символа = 32 байта>",
  "public_key_hex": "<hex публичного ключа>",
  "algorithm": "ed25519",
  "trust_duration_secs": 86400
}
```

Валидация на сервере:
- `key_id_hex` обязан быть **64 hex-символа** (32 байта), иначе `400`.
- `algorithm` обязан быть `ed25519` или `hmac_sha256`, иначе `400`.
- `trust_duration_secs` принудительно поднимается до **минимум 60 секунд** (`.max(60)`, [src/proxy/pingora_admin.rs:2466](../../src/proxy/pingora_admin.rs)).

Пример регистрации Ed25519-issuer:

```bash
curl -sS -X POST http://127.0.0.1:6280/admin/api/privacy-pass/issuers \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "cloudflare-research.com",
    "key_id_hex": "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
    "public_key_hex": "<32-байтный Ed25519 pubkey в hex>",
    "algorithm": "ed25519",
    "trust_duration_secs": 86400
  }'
# → {"ok":true,"name":"cloudflare-research.com"}
```

Сводка также доступна в общем admin-снапшоте: `trust_grants_active` и `privacy_pass_issuers` ([src/proxy/pingora_admin.rs:1334-1335](../../src/proxy/pingora_admin.rs)). Подробнее об API — Admin API — справочник.

---

## 9. Что реально работает, а что нет

> Соблюдение модели безопасности и честных оговорок брифинга обязательно.

**✅ Реализовано и протестировано:**
- Парсинг RFC 9578 Type-1 токена (raw-форма) и реконструкция подписываемого сообщения.
- Боевая Ed25519-верификация через `verify_strict` (защита от malleable/torsion-подписей).
- Различение `InvalidKey` (конфиг-ошибка → `UnsupportedAlgorithm`) и `BadSignature` (подделка), fail-closed.
- Replay-кэш nonce с capacity-эвикцией и GC.
- Рантайм-реестр issuers + панель-безопасный `IssuerInfo` (fingerprint, не сырой ключ).
- Admin API (GET сводка/список, POST регистрация) с валидацией.
- Chained trust с per-nonce HMAC-cookie (закрыт shared-CGNAT auth_bypass, V233).

**🟡 Частично / не реализовано (по docstring [src/privacy_pass.rs:35-44](../../src/privacy_pass.rs)):**
- **Verifier НЕ вызывается из request-path.** В [src/proxy/pingora_http.rs](../../src/proxy/pingora_http.rs) нет вызовов `parse_token`/`privacy_pass.verify`. Заголовок `PrivateToken` сейчас не парсится в боевом обработчике — bypass через Privacy Pass в data plane ещё не подключён. Это foundation (verifier + реестр + API + счётчики), а не сквозной фильтр.
- **Type-2 (Blind Signature Scheme) приватные токены НЕ реализованы.** Поддерживается только Type-1 публичная верификация, потому что каждый крупный issuer публикует ключ. Для Type-2 операторам нужен отдельный issuer-client.
- **HTTP-семантическое кодирование RFC 9578 НЕ реализовано** — принимается упрощённая raw-форма байт токена.
- **`HmacSha256` — только для тестов**, не для production (общий секрет ломает анонимность публичной верификации).
- **Автоматической ротации ключей issuer нет** — статический реестр, ключи меняются вручную через Admin API.

**Замечания по эксплуатации:**
- При `ChainedTrustStore::new()` (дефолт) HMAC-ключ per-process случайный → все выданные trust-cookie инвалидируются на рестарте. Для устойчивости задавайте общий секрет через `with_secret`.
- Оба переключателя (`privacy_pass`, `chained_trust`) выключены по умолчанию — включение per-host через `DomainChallengeConfig` (см. Картография и per-domain политики).

---

## 10. Связанные документы

- [Challenge ladder, PoW и captcha](./15-challenge-ladder.md) — лестница, в которую встраивается Privacy Pass tier.
- Defence Arsenal, сценарии и актуаторы — где живут verifier и trust-store.
- Admin API — справочник — полный справочник по `/admin/api/privacy-pass/*`.
- Модель безопасности и харднинг — общая модель угроз.
- Картография и per-domain политики — per-host переключатели.
- Глоссарий — термины Privacy Pass, replay, TrustTier.
