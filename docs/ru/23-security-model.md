# Модель безопасности и харднинг

Документ описывает модель угроз AEGIS, аутентификацию и авторизацию админ-плоскости (токены/сессии/роли, принудительная смена кредов), единый канонический формат записи решений безопасности (`SecurityEvent` — Allow/Challenge/Deny/Throttle/Observed), харднинг бинаря и systemd-юнитов, цепочку firewall-бэкендов (XDP → nftables → iptables → userspace), выводы внутреннего аудита (что закрыто, что отложено) и практические рекомендации по безопасному развёртыванию. Все утверждения привязаны к реальному коду с указанием путей файлов.

> Связанные документы: [02-architecture.md](02-architecture.md), [06-workers.md](06-workers.md), [13-xdp-ebpf.md](13-xdp-ebpf.md), [25-metrics-telemetry.md](25-metrics-telemetry.md), [29-admin-panel.md](29-admin-panel.md), [30-admin-api.md](30-admin-api.md), 42-текущее-состояние-STATUS.md, [47-faq-troubleshooting.md](47-faq-troubleshooting.md).

---

## 1. Модель угроз

AEGIS — самохостинг реверс-прокси с WAF и анти-DDoS. Он стоит на периметре, разбирает каждый запрос и принимает решение Allow/Challenge/Deny. Соответственно у системы две принципиально разные поверхности атаки: **трафик data plane** (запросы посетителей сайта) и **control plane** (админ-API + панель).

### 1.1. Что AEGIS защищает

| Слой | Защита | Документ |
|---|---|---|
| L3/L4 volumetric | Kernel fast-path XDP/eBPF + nftables/iptables deny-set; rate-drop SYN/пакетов | [13-xdp-ebpf.md](13-xdp-ebpf.md) |
| L7 application | WAF (Aho-Corasick + Sigma + compound + webshell), challenge ladder, PoW, ML risk engine | [10-waf.md](10-waf.md), [15-challenge-ladder.md](15-challenge-ladder.md), [18-ml-risk-engine.md](18-ml-risk-engine.md) |
| Идентификация клиента | TLS-фингерпринтинг JA3/JA4/JA4H/JA4T, репутация JA4/ASN/CIDR | [11-tls-fingerprinting.md](11-tls-fingerprinting.md), [12-reputation.md](12-reputation.md) |
| Control plane | Токены ролей, сессии панели, аудит-лог, harden-юниты | этот документ |

### 1.2. Модель доверия к источнику IP

Решения принимаются по client IP, полученному из TCP-peer или PROXY-protocol — он **не спуфится** для внутренних решений (подтверждено аудитом, раздел 6 `SECURITY-AUDIT-CONSOLIDATED-2026-06-07.md`). Прокси-цепочка upstream берётся из config-карты по `Host`, разрешён только `http://` — поверхность SSRF ограничена.

### 1.3. Честные оговорки модели угроз

Внутренний аудит (`SECURITY-AUDIT-CONSOLIDATED-2026-06-07.md`, объединённый отчёт Claude + Codex от 2026-06-07) даёт согласованную оценку «защита людей сейчас» **5–6/10**, с потенциалом 7.5–8/10 после закрытия критических находок. Ключевые честные ограничения:

- **Боевой data plane — `aegis-pingora`** (cutover V71), а часть защиты исторически жила только в legacy hyper-бинаре `aegis`. Это требует постоянной проверки паритета фич между двумя бинарями.
- **Volumetric L3/L4 в одиночку реверс-прокси не закрывает** — нужен upstream-провайдер/CDN + edge-фильтрация (XDP/nftables). XDP-фундамент есть, но требует корректных capabilities и поддержки ядром.
- Ряд находок аудита **отложен по объективным причинам**: h2-abuse-лимиты (C3) ждут апгрейда Pingora (0.8.0 не даёт нужного API), iframe-ступень без PoW (H8) сохранена ради no-JS UX, bearer-токен без IP-bind (M7) сделан намеренно под CDN с переключением IP.

См. полный статус находок в разделе 6.

---

## 2. Аутентификация и авторизация админ-плоскости

Control plane (`/admin/*`, `/admin/api/*`, `/metrics`) имеет **два независимых механизма аутентификации**, которые сходятся в единой функции авторизации `authorise()` в `src/proxy/pingora_admin.rs`.

### 2.1. Два источника учётных данных

```
                  ┌─────────────────────────────────────────────┐
   x-admin-token  │ 1) TokenRegistry  (config + AEGIS_ADMIN_TOKEN)│ → роль из конфига
   ───────────────┤    src/admin_auth.rs                          │
                  │ 2) WebAdminStore  (сессии React-панели)       │ → роль Admin
   cookie ────────┤    src/web_admin.rs                           │
   aegis_admin_   └─────────────────────────────────────────────┘
   session
```

**(1) Статические токены ролей** — `src/admin_auth.rs`, тип `TokenRegistry`. Собираются при старте из двух мест (`TokenRegistry::from_sources`):

- переменная окружения `AEGIS_ADMIN_TOKEN` → неявная роль `Admin` (обратная совместимость);
- записи `[[admin.tokens]]` / DSL `token <role> <value>;` с явной ролью (`AdminTokenEntry { token, role }` в `src/config.rs`).

Дубликаты одного токена резолвятся в **сильнейшую** роль (`authenticate` берёт `prev >= entry.role`). Эти токены дают CLI/curl-доступ к `/admin/reload`, `/admin/health` и т.п. — нужны для `systemctl reload` и ops-автоматизации.

**(2) Сессии React-панели** — `src/web_admin.rs`, тип `WebAdminStore`. Учётные данные (email + argon2id-хэш пароля) и активные сессии хранятся в одном JSON-файле (`DEFAULT_STATE_PATH = /var/lib/aegis/web.json`). Файл — единый источник правды для CLI (`aegis web reset-admin`, `aegis web stop`) и демона; демон делает `stat` на каждом аутентифицированном запросе и **перечитывает по изменению mtime** (`refresh()`), поэтому правки CLI вступают в силу без SIGHUP.

### 2.2. Роли (`AdminRole`)

`src/config.rs`, упорядоченный enum (`PartialOrd`/`Ord`):

| Роль | Права | Примеры эндпоинтов |
|---|---|---|
| `Read` | только чтение: метрики, health, threats, xdp-счётчики, GET `/admin/api/*` | `GET /admin/threats`, `GET /admin/api/metrics/series` |
| `Write` | чтение + мутация рантайма | `POST /admin/xdp/deny/<ip>`, `PUT /admin/api/sites/*`, `POST /admin/api/restart` |
| `Admin` | полный контроль | `POST /admin/reload`, `POST /admin/stop` |

Упорядочивание (`Admin > Write > Read`) — основа проверки `role >= required`.

### 2.3. Карта требуемых ролей (`required_role_for`)

Функция `required_role_for(method, path)` в `src/admin_auth.rs` возвращает минимальную роль для каждого эндпоинта. Ключевые свойства:

| Категория | Требуемая роль | Примечание |
|---|---|---|
| `GET /metrics` | `None` (публично) | метрики Prometheus |
| Статические ассеты `/`, `/admin/ui*` | `None` | JSON-API под ними сам энфорсит auth |
| `POST /admin/api/login`, `/logout`, `/change-credentials`, `GET /admin/api/me` | `None` | handler делает собственную валидацию |
| `GET /admin/api/*` (catch-all) | `Read` | внутри handler ре-проверяет write-операции |
| `POST/PUT/DELETE /admin/api/sites*`, `/config/*` apply, `/env`, `/restart`, `/honeypots` | `Write` | мутации |
| `POST /admin/reload`, `/admin/stop` | `Admin` | управление жизненным циклом |
| **любой `POST`/`PUT`/`DELETE` под `/admin/api/`, не перечисленный явно** | `Write` (**fail-closed**) | см. ниже |

**Fail-closed дефолт (V232).** До V232 неперечисленные мутации проваливались в `_ => None` и обслуживались **без аутентификации** — так были открыты `PUT /admin/api/topology` и `POST /admin/api/challenge/attack-mode`. Теперь любой `POST|PUT|DELETE` под `/admin/api/`, не являющийся явным публичным эндпоинтом (login/logout/change-credentials), требует роль `Write`. Регрессия зафиксирована тестом `v232_admin_api_mutations_fail_closed`.

### 2.4. Единый шлюз авторизации (`authorise`)

`src/proxy/pingora_admin.rs::authorise()` — единственная точка решения о доступе. Порядок резолюции:

1. Заголовок `x-admin-token` → сначала как config-token (`tokens.authenticate`), затем (если None и есть `web_admin`) как session-token (`store.validate` → роль `Admin`). React-панель кладёт session-token в localStorage и шлёт через этот же заголовок.
2. Cookie `aegis_admin_session` → `store.validate` → роль `Admin`.

```rust
let required = required_role_for(method, path);
// public endpoint → Ok(None)
// если tokens.is_empty() && web_admin.is_none() → Err((503, "admin auth not configured"))
match granted {
    Some(role) if role >= required => Ok(Some(role)),
    Some(_) => Err((403, "insufficient role")),
    None    => Err((401, "invalid or missing token")),
}
```

Важная деталь: если **ни один** механизм auth не сконфигурирован, control plane возвращает `503 "admin auth not configured"` — он не открывается «по умолчанию».

### 2.5. Сессии панели

`src/web_admin.rs`:

- **Токен сессии** — 256 случайных бит (`new_session_token`, `rand::thread_rng().fill_bytes([0u8;32])`), base64 url-safe без паддинга. TTL `SESSION_TTL_SECS = 24*3600` (24 ч).
- **Хранение пароля** — argon2id с per-record солью (`hash_password` через `SaltString::generate(&mut OsRng)`), PHC-строка.
- **Сравнение токенов — constant-time** (V233). Раньше сессионные токены сравнивались через `String ==` (короткое замыкание на первом несовпавшем байте) — это удалённый timing-oracle, дающий побайтовое восстановление 256-битного токена и угон панели. Теперь `validate`/`logout`/`change_credentials` используют `constant_time_eq` из `src/admin_auth.rs`.
- **Cookie панели** — `aegis_admin_session=<token>; Path=/admin; HttpOnly; SameSite=Strict; Max-Age=86400` (`pingora_admin.rs:4381`). Флаги `HttpOnly` + `SameSite=Strict` ограничивают XSS-кражу и CSRF.
- Сессии прунятся при каждом сохранении (`file.sessions.retain(|s| s.expires_at > now)`); запись файла атомарна (`write_atomic`: tmp + rename).

### 2.6. Принудительная смена учётных данных (force-change creds)

Дефолтный пароль больше **не** шипается (находка M8 закрыта):

- На **первом запуске** (`WebAdminStore::open`, файла нет) AEGIS генерирует **уникальный случайный пароль** (`generate_password`, ~108 бит энтропии), хэширует его, а plaintext выводит **ровно один раз** через `tracing::warn!("Generated initial admin password: …")` и нигде в открытом виде не хранит. Email — `DEFAULT_EMAIL = admin@local.lcl`, флаг `must_change = true`.
- Константа `DEFAULT_PASSWORD = "adminPassw0rd"` оставлена в коде, но **намеренно не используется** для провижининга. Тест `first_run_provisions_random_password_not_static_default` проверяет, что статический дефолт не пускает на свежей установке.
- Уже существующий файл **загружается verbatim** и не мигрируется (тест `existing_file_is_loaded_verbatim_not_migrated`) — старые инсталляции продолжают работать.
- Пока `must_change = true`, React показывает красный баннер, форсирующий смену. `change_credentials` проверяет старый пароль (argon2 verify), валидирует email/пароль (`validate_email`, `validate_password`: длина 8..=256), снимает `must_change`, **инвалидирует все прочие сессии** и переиздаёт токен текущей.
- CLI-восстановление: `reset_admin()` ставит свежий случайный пароль, `must_change = true`, чистит сессии, сбрасывает email на дефолт — оператор не может заблокировать себя навсегда.

### 2.7. HMAC-токены challenge-ладдера (отдельный механизм)

`src/security/token.rs` (НЕ путать с админ-токенами) — HMAC-SHA256-токены для challenge ladder: подпись `payload = "{ip}:{nonce}:{exp}"`. Проверка `verify_token` — **constant-time** (V233): base64-сигнатура декодируется в сырые байты, сравнение через `Mac::verify_slice` (никогда не сравниваются base64-строки), проверяется привязка к IP и срок. Cookie-хелперы (`src/security/cookie.rs`) читают `aegis_token`/`aegis_fp`; `secure_suffix(on)` добавляет `; Secure`. Подробнее: [15-challenge-ladder.md](15-challenge-ladder.md).

---

## 3. Аудит-лог админ-действий

`src/admin_auth.rs`, тип `AuditLog`. Каждое решение `authorise()` (включая отказы) логируется:

- **Всегда** — структурное tracing-событие `target: "aegis::audit"` с полями `ts, peer, method, path, role, status`.
- **Опционально** — JSON-строка в файл, если путь сконфигурирован (append-only, `OpenOptions::new().create(true).append(true)`).

Шумоподавление (`is_audit_worthy`): пропускаются ассеты `/admin/ui` и `/`, а также **все `GET`** (read-only телеметрия — панель опрашивает `/metrics`, `/admin/api/*` каждые несколько секунд). Записываются только мутации (`POST`/`PUT`/`DELETE`) и auth-события (login/logout/change-credentials — это POST). В `request_filter` запись делается и для **отказов** auth (`self.audit.record(&peer, …, None, status)` при `Err`).

---

## 4. SecurityEvent — канонический формат решений Allow/Challenge/Deny

`src/security_event.rs` (V116) заменяет N ad-hoc `tracing!()`-вызовов по фильтрам **одной канонической формой** на каждое решение безопасности — для SIEM-ингеста, Grafana и пост-инцидентного разбора.

### 4.1. Категории решений (`DecisionKind`)

| Значение | Смысл |
|---|---|
| `Allow` | запрос пропущен |
| `Challenge` | выдан челлендж (PoW/captcha/…) |
| `Deny` | заблокирован |
| `Throttle` | ограничен по скорости |
| `Observed` | «сматчилось, но не действуем» — shadow-mode WAF / observe-mode Risk Engine; отделяет «заблокировал бы» от «заблокировал» |

### 4.2. Структура события (`SecurityEvent`)

Поля намеренно малые и **без PII в метках**: `action`, `reason: &'static str`, `request_id`, `host`, `client_ip`, `method`, `path`, опционально `risk_score: Option<u8>` (0..=255 из ML Risk Engine), `extra_reasons: Vec<&'static str>`, `waf_rule_id: Option<String>`, `ja4_prefix: Option<String>` (обрезается до первых 12 символов — семейство JA4_a — чтобы лог не пух от 36-символьных отпечатков). Билдеры: `.with_risk()`, `.with_waf_rule()`, `.with_ja4()`.

### 4.3. Эмиттер (`SecurityEventEmitter`)

Два синка (`emit`, hot-path-safe):

1. Структурный лог `target: "aegis::security_event"` (одно событие с типизированными полями `action, reason, request_id, host, client_ip, method, path, risk_score, waf_rule_id, ja4_prefix`).
2. Счётчики Prometheus с **ограниченной кардинальностью** — ключ `(action, reason)`, где `reason` всегда `&'static str` (карта не может вырасти за статический набор ~30 значений). Рендер `render_prometheus()`:

```
aegis_security_decisions_total{action="deny",reason="waf_critical"} <n>
aegis_security_events_total <total>
```

Дашборды оператора:

```promql
sum(rate(aegis_security_decisions_total{action="deny"}[5m]))
topk(10, sum by (reason)(rate(aegis_security_decisions_total[5m])))
```

`snapshot()` отдаёт срез счётчиков для JSON-эндпоинтов `/admin/api/*`. Кардинальность гарантированно ограничена типом `&'static str` (тест `cardinality_bounded_by_static_reasons`). Поток событий наружу для SIEM — через EventBridge NDJSON (`src/event_bridge.rs`), см. [25-metrics-telemetry.md](25-metrics-telemetry.md).

> Честная оговорка: набор reason-строк и точки эмиссии должны совпадать между pingora- и hyper-путями; аудит отмечал, что ряд сигналов (RiskEngine, FP-enforcement) исторически был «наблюдательным» — см. раздел 6.

---

## 5. Харднинг

### 5.1. Сборка бинаря (`Cargo.toml`, `[profile.release]`)

| Опция | Значение | Цель безопасности/производительности |
|---|---|---|
| `panic = "abort"` | abort, не unwind | убирает unwind-таблицы из пролога каждой функции (экономия icache на Allow hot-path); безопасно — прокси и так трактует panic как краш воркера, pingora перезапускает воркер, REUSEPORT держит листенер живым |
| `strip = "symbols"` | срезаны символы | ~30% размера бинаря; debug-символы достаются из split-debug при необходимости |
| `lto = "thin"` | thin-LTO | параллельный кросс-крейтовый LTO |
| `codegen-units = 16` | — | параллельный codegen по ядрам |
| `incremental = true` | — | `install.sh --update` перекомпилирует только изменённое |
| `opt-level = 3`, `debug = false` | — | |

Скомпилированно отключены `debug!`/`trace!`-макросы в release (V229) — служебные логи не попадают в боевой бинарь. Для максимума: `AEGIS_BUILD_OPT=max` экспортирует `CARGO_PROFILE_RELEASE_{LTO=fat,CODEGEN_UNITS=1,INCREMENTAL=false}`. Профиль `[profile.profiling]` сохраняет символы только для perf/flamegraph и никогда не шипается.

### 5.2. Capabilities (least privilege)

`install.sh` выдаёт бинарю минимальный набор привилегий через `setcap` и systemd-ambient:

```
setcap 'cap_net_bind_service,cap_net_admin,cap_sys_resource=+ep' <binary>
```

В обычном режиме юнит имеет только `CAP_NET_BIND_SERVICE`. При **включённом XDP** (`AEGIS_ENABLE_XDP=1`) набор расширяется до:

```
CAP_NET_BIND_SERVICE CAP_NET_ADMIN CAP_SYS_RESOURCE CAP_BPF CAP_PERFMON
```

`CAP_PERFMON` критичен: на ядрах 6.x verifier гейтит операции с указателями/packet-data за `perfmon_capable()`, поэтому без него `BPF_PROG_LOAD` падает с `EACCES` (os err 13) даже при наличии `CAP_BPF` (находка из аудита, раздел 10 отчёта — исправлено). Для XDP также добавляется `AF_NETLINK` в `RestrictAddressFamilies` (attach идёт через rtnetlink). См. [13-xdp-ebpf.md](13-xdp-ebpf.md).

### 5.3. Sandboxing systemd-юнитов

Оба юнита (`aegis.service` и шаблон `aegis-pingora@.service`) запускаются от непривилегированного `$AEGIS_USER` со следующим харднингом (`install.sh`):

```ini
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX   # (+ AF_NETLINK при XDP)
RestrictNamespaces=true
LockPersonality=true
ReadOnlyPaths=$AEGIS_ETC                            # конфиг доступен только на чтение
ReadWritePaths=$AEGIS_LOG_DIR $AEGIS_HOME
AmbientCapabilities=$svc_cap
CapabilityBoundingSet=$svc_cap                      # жёсткий потолок привилегий
```

Особенности pingora-шаблона: `CPUAffinity=%i` (worker N → CPU N, thread-per-core), `LimitMEMLOCK=infinity` (для BPF-карт и locked ring buffers), `Nice=-10`, `LimitNOFILE=1048576`. Sandboxing относительно hyper-юнита намеренно ослаблен в двух местах: `MemoryDenyWriteExecute=false` (openssl-путь pingora использует JIT-able регионы на некоторых архитектурах) и +`CAP_NET_ADMIN` под XDP.

> Побочный эффект харднинга, замеченный на стенде: `/etc/aegis/tls_ticket.key` на read-only FS (`ProtectSystem=strict` + `ReadOnlyPaths`) → cross-worker TLS-resumption деградирует (безопасно — это компромисс в пользу неизменяемости конфига).

### 5.4. Изоляция воркеров

Многопроцессность через `SO_REUSEPORT` (`aegis-pingora@0..N`): краш одного воркера не валит соседей. Target использует `Wants=` (не `Requires=`) — рестарт одного воркера не делает зависимость target неудовлетворённой и не каскадит остановку сиблингов, что и даёт rolling-restart с почти нулевым даунтаймом (см. коммит и [06-workers.md](06-workers.md)).

---

## 6. Firewall-бэкенды (цепочка fallback)

AEGIS реализует деградирующую цепочку блокировки на edge:

```
XDP/eBPF  →  nftables  →  iptables  →  userspace (NoopXdp + IpAclFilter)
```

Выбор управляется `AEGIS_FW_BACKEND=auto|xdp|nftables|iptables|noop` (дефолт `auto`). Все бэкенды реализуют общий трейт `XdpHandle`, поэтому встают в конвейер как пиры без правок остального кода.

### 6.1. nftables (`src/nftables_backend.rs`, V128)

Работает на любом Linux ≥3.13, требует только `CAP_NET_ADMIN`. `NftablesXdp::open` создаёт inet-таблицу (`aegis` по умолчанию) и два set-а — `aegis-deny-v4` / `aegis-deny-v6` (`flags interval` — поддержка CIDR), плюс цепочку `input` (hook input, priority 0) с правилами `ip[6] saddr @aegis-deny-vN counter drop`. Все операции идемпотентны (`add table`/`add set` — no-op при наличии; правила добавляются только если отсутствуют в `list chain`). Блокировка — `nft add element`, разблокировка — `nft delete element`. Счётчики парсятся из `nft -j list table inet aegis`.

### 6.2. iptables (`src/iptables_backend.rs`, V130)

4-й рубеж — для legacy/embedded/минимальных контейнеров. `IptablesXdp` создаёт цепочки `AEGIS-DENY-V4` (iptables) / `AEGIS-DENY-V6` (ip6tables), джампы из `INPUT` (`-I INPUT 1 -j <chain>`). Deny/undeny — `-I <chain> 1 -s <ip> -j DROP` / `-D … -j DROP` с предварительной дедупликацией через `-C`. Счётчики — из `iptables -L <chain> -nvx`. **Не авто-устанавливается**: оператор включает явно (`AEGIS_FW_BACKEND=iptables` или через fallback).

### 6.3. Ограничения бэкендов nft/ipt (честно)

Оба бэкенда — **deny-only**. Не реализованы (возвращают `Err`):

| Метод трейта | nftables | iptables |
|---|---|---|
| `allow_v4`/`allow_v6`/`unallow` | не реализовано (allow-list требует отдельной accept-цепочки) | не реализовано |
| `set_rate_config` | не реализовано (per-IP rate требует иной формы ruleset; используйте XDP или userspace `RateLimitFilter`) | не реализовано |

Kernel-side rate-limiting и allow-list доступны только через XDP. eBPF-XDP-загрузчик живёт за cargo-фичей `bpf` и подключается в `aegis-pingora` как высший рубеж **перед** nftables (`open_full_fallback`). При недоступности всех бэкендов — `NoopXdp`, блокировка идёт userspace-`IpAclFilter`.

> Замечание по многопроцессности XDP: NIC держит одну XDP-программу, поэтому из N REUSEPORT-воркеров attach выигрывает один (владелец энфорсит kernel deny/allow карты для всего трафика), остальные получают `EEXIST` и фильтруют в userspace — enforcement-эквивалентно (раздел 10 отчёта).

---

## 7. Выводы аудита: что закрыто, что отложено

Источник — `SECURITY-AUDIT-CONSOLIDATED-2026-06-07.md` (раздел 8, пере-верификация на коде стенда `f48409c`; ветка фиксов `security-fixes-2026-06-07`).

### 7.1. Закрыто / исправлено

| ID | Находка | Статус |
|---|---|---|
| **C1** | captcha/verify выдавал 24-ч trust без proof | **уже исправлено**: verify требует валидный PoW/Turnstile до `aegis_fp`, fail-closed |
| **M8** | дефолтный admin-пароль `adminPassw0rd` | **исправлено**: первый запуск генерирует случайный пароль, статический дефолт не пускает (`src/web_admin.rs`) |
| **V233** | session-token сравнивался `String ==` (timing-oracle) | **исправлено**: `constant_time_eq` в `validate`/`logout`/`change_credentials` и в HMAC-`verify_token` |
| **V232** | неперечисленные `/admin/api/` мутации были публичны | **исправлено**: fail-closed дефолт → `Write` |
| **M11** | `cookie_secure=false` по умолчанию | **исправлено**: дефолт `true`, DSL-парсер тоже (`src/dsl/lower.rs`); challenge-cookie получает `; Secure` |
| **H1** | body на HEAD в h2 → `PROTOCOL_ERROR` | **исправлено** на стенде: deny/challenge не пишут тело на HEAD |
| **XDP** | `BPF_PROG_LOAD: Permission denied` | **исправлено**: добавлен `CAP_PERFMON` (+`AF_NETLINK`) |
| **HTTP/3** | не биндился на N воркеров | **исправлено**: `SO_REUSEPORT` через socket2 |

Также проверено как работающее правильно (раздел 6 отчёта): WAF реально блокирует SQLi/XSS/traversal → 403 (двойное/тройное URL-кодирование, MySQL-комменты, null-байты); client IP не спуфится; HMAC-токены constant-time + IP-bound + expiry, weak-secret denylist на старте; PoW constant-time; captcha-провайдеры fail-closed; TLS FP-извлечение корректно; admin на loopback; оверсайз-тело → 413.

### 7.2. Отложено (честно, с причиной)

| ID | Находка | Причина отсрочки |
|---|---|---|
| **C3** | h2-abuse-слой (rapid-reset/CONTINUATION/SETTINGS/PING) | Pingora 0.8.0 не даёт API для `max_header_list_size`/concurrent-streams — нужен апгрейд фреймворка |
| **H8** | iframe-ступень даёт free trust | форсировать PoW на iframe сломает no-JS UX |
| **M7** | bearer-токен без IP-bind | by-design под CDN с переключением IP; опционально — spent-nonce cache |

> Остальные находки (C2/C4/H2–H9, M1–M6 и др.) — в работе на ветке фиксов; актуальный статус сверяйте с 42-текущее-состояние-STATUS.md.

---

## 8. Рекомендации по безопасному развёртыванию

Эти рекомендации прямо вытекают из эксплуатационных находок аудита (раздел 9 отчёта: на одном из ранних стендов были обнаружены SSH с парольным входом + 11k брутфорс-попыток/сутки, отсутствие fail2ban/firewall, админка в интернете по HTTP).

### 8.1. SSH

- **Отключить парольную аутентификацию** — только ключи:
  ```
  # /etc/ssh/sshd_config
  PasswordAuthentication no
  PubkeyAuthentication yes
  PermitRootLogin no
  ```
- Установить **fail2ban** (jail `sshd`) против брутфорса.

### 8.2. Хостовый firewall

- Закрыть всё лишнее на edge (nftables/iptables на хосте, в дополнение к AEGIS-бэкендам): открыть только 80/443 (и порт SSH с ограничением по источнику).
- Для volumetric L3/L4 — это **обязательный** слой: реверс-прокси сам по себе не закрывает объёмные атаки (см. 1.3). XDP rate-drop на edge + upstream-провайдер/CDN.

### 8.3. Админ-панель и control plane

- **Не биндить админ-порт на `0.0.0.0` без защиты.** Дефолтный `AEGIS_PORT_ADMIN=6280`. ВНИМАНИЕ: в шаблоне nginx из `install.sh` есть `listen 0.0.0.0:$AEGIS_PORT_ADMIN;` — это нужно либо ограничить firewall-ом/VPN, либо переключить bind на loopback (`AEGIS_ADMIN_LISTEN`/`admin.listen`), либо поставить за TLS + аутентифицирующий reverse-proxy. Внутренние curl-вызовы (`ExecReload`, health) ходят через `127.0.0.1`.
- **Сразу сменить сгенерированный пароль** при первом логине (баннер `must_change`). Plaintext выводится один раз в лог — не оставлять его в логах надолго.
- Выдавать **минимальные роли** токенов: дашбордам — `Read`, автоматизации мутаций — `Write`, `Admin` — только для reload/stop.
- Держать панель за **HTTPS** (cookie `Secure`; дефолт `cookie_secure=true` после V-фикса M11). `HttpOnly` + `SameSite=Strict` уже стоят на сессионной cookie.

### 8.4. Capabilities и харднинг

- Если XDP не нужен — не давать `CAP_BPF`/`CAP_PERFMON`/`CAP_NET_ADMIN`; держать только `CAP_NET_BIND_SERVICE`.
- Не ослаблять systemd-sandbox (`NoNewPrivileges`, `ProtectSystem=strict`, `ReadOnlyPaths=$AEGIS_ETC`) без необходимости.

### 8.5. Наблюдаемость безопасности

- Подключить `aegis::security_event` и `aegis::audit` к лог-агрегатору/SIEM; настроить дашборды по `aegis_security_decisions_total` (раздел 4). См. [25-metrics-telemetry.md](25-metrics-telemetry.md) и [24-request-log.md](24-request-log.md).
- Включить файловый аудит-лог (`AuditLog` с путём) для несбрасываемой записи всех мутаций control plane.

---

## 9. Сводка ключевых файлов

| Файл | Ответственность |
|---|---|
| `src/admin_auth.rs` | `TokenRegistry` (статические токены/роли), `required_role_for`, `AuditLog`, `constant_time_eq` |
| `src/web_admin.rs` | `WebAdminStore` (argon2id креды, сессии, force-change, mtime-poll), генерация первого пароля |
| `src/proxy/pingora_admin.rs` | `authorise()` — единый шлюз auth, login/logout/me/change-credentials |
| `src/security_event.rs` | `SecurityEvent`/`DecisionKind`/`SecurityEventEmitter` — канонический формат решений + Prometheus |
| `src/security/token.rs` | HMAC-SHA256 challenge-токены (constant-time verify) |
| `src/security/cookie.rs` | чтение cookie + `secure_suffix` |
| `src/nftables_backend.rs` | firewall-бэкенд nftables (deny-only) |
| `src/iptables_backend.rs` | firewall-бэкенд iptables (deny-only) |
| `Cargo.toml` `[profile.release]` | харднинг сборки (panic=abort, strip, thin-LTO) |
| `install.sh` | capabilities (`setcap`/ambient), systemd-sandbox, порты |
| `SECURITY-AUDIT-CONSOLIDATED-2026-06-07.md` | объединённый аудит, статус находок |
