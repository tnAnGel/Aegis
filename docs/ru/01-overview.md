# Обзор продукта

**AEGIS** — высоконагруженный reverse proxy / edge gateway на Rust, который ставится перед вашим веб-сервисом и берёт на себя DDoS-митигацию и L7-фильтрацию: WAF, детекцию ботов и скрейперов, challenge-лестницу и kernel fast-path. Production data plane работает на [Cloudflare Pingora](../../src/bin/aegis-pingora.rs); legacy-бинарь на Hyper остаётся для HTTP/3 и dev-сред.

---

## 1. Что такое AEGIS

AEGIS — это «броневик» перед вашим origin: он принимает весь входящий HTTP/HTTPS-трафик, прогоняет его через многоуровневый конвейер защиты и форвардит на апстрим только то, что прошло проверку. Написан на Rust (`edition = "2024"`, см. [Cargo.toml](../../Cargo.toml)), поддерживает HTTP/1.1, HTTP/2 и HTTP/3 (QUIC), eBPF/XDP fast-path в ядре Linux и challenge-систему в стиле vDDoS.

Ключевая позиция в брифинге документации (соблюдается во всех docs): **AEGIS — это не «ещё один быстрый форвардер», а security-edge.** Голый nginx как dumb-прокси быстрее (см. бенчмаркинг), но у него нет встроенной L7-защиты. AEGIS обеспечивает полный per-request security-конвейер ценой лишь ~4% throughput на легитимном трафике, а под атакой — единственный из сравниваемых прокси, кто реально фильтрует трафик и закрывает origin.

> 🟡 Текущая версия по [README.md](../../README.md): `V237` (production data plane на Pingora). Изменения нумеруются спринтами `V2XX`; в этой документации версия фичи указывается там, где это важно.

---

## 2. Какие задачи решает

| Класс угрозы | Что делает AEGIS | Ключевые модули |
|---|---|---|
| **DDoS L3/L4 (волюметрика)** | XDP/eBPF fast-path в ядре дропает пакеты до userspace; per-IP rate + SYN-flood guard. ⚠️ **Частично:** полноценная L3/L4-защита от крупных флудов требует upstream (BGP RTBH / CDN) — см. оговорки ниже | [src/xdp.rs](../../src/xdp.rs), [src/bgp_rtbh.rs](../../src/bgp_rtbh.rs), [docs/13-xdp-ebpf.md](./13-xdp-ebpf.md) |
| **DDoS L7 (HTTP-флуд, low-rate)** | Per-IP / per-endpoint rate-limit, token-bucket, HTTP/2 frame-budgets (Rapid Reset / Settings / Ping / CONTINUATION flood), challenge-лестница, adaptive escalation | [src/filters/rate_limit.rs](../../src/filters/rate_limit.rs), [src/h2_budget.rs](../../src/h2_budget.rs), [docs/14-rate-limiting.md](./14-rate-limiting.md), [docs/15-challenge-ladder.md](./15-challenge-ladder.md) |
| **WAF (payload-атаки)** | Сигнатуры + regex + JIT-скомпилированные правила; детекция SQLi, XSS, path-traversal; SafeLine-style нормализация; семантический SQLi-детектор; импорт Sigma-правил | [src/filters/waf.rs](../../src/filters/waf.rs), [src/normalisation.rs](../../src/normalisation.rs), [src/sql_semantic.rs](../../src/sql_semantic.rs), [docs/10-waf.md](./10-waf.md) |
| **Боты** | TLS-фингерпринтинг (JA3/JA4/JA4H), cross-fingerprint correlation (Chrome JA4 + curl UA = бот), CreepJS-style client consistency, passive OS classification (p0f), GREASE-аномалия | [src/ja4.rs](../../src/ja4.rs), [src/fp_correlation.rs](../../src/fp_correlation.rs), [src/client_consistency.rs](../../src/client_consistency.rs), [docs/11-tls-fingerprinting.md](./11-tls-fingerprinting.md) |
| **Скрейперы / AI-краулеры** | Honeypot-приманки, Markov-chain poisoned tarpit (бесконечный лабиринт для AI), robots.txt auto-labeling, per-route PoW-сложность (GPTBot/CCBot +4 бита), LLM-honeypot | [src/poisoned_tarpit.rs](../../src/poisoned_tarpit.rs), [src/robots_honeypot.rs](../../src/robots_honeypot.rs), [src/llm_honeypot.rs](../../src/llm_honeypot.rs) |

---

## 3. Ключевые возможности (списком)

**Сетевой стек и транспорт:**
- HTTP/1.1, HTTP/2 (через openssl на Pingora-пути), HTTP/3 / QUIC (через quinn, sidecar)
- SO_REUSEPORT multi-process: несколько worker-процессов слушают один порт, ядро балансирует соединения (см. [docs/06-workers.md](./06-workers.md))
- PROXY protocol parser ([src/proxy_proto.rs](../../src/proxy_proto.rs)) и trusted-proxy real-IP resolver (`CF-Connecting-IP` / `X-Forwarded-For`, только для доверенных пиров — [src/real_ip.rs](../../src/real_ip.rs))
- TLS termination с per-SNI сертификатами и ALPN-h2; ACME / Let's Encrypt (HTTP-01) для авто-сертификатов ([src/acme.rs](../../src/acme.rs), [src/acme_instant.rs](../../src/acme_instant.rs), [docs/08-tls-certificates.md](./08-tls-certificates.md))

**Защита L7:**
- WAF: сигнатуры, regex, wirefilter-выражения, Coraza-style phase-indexed compiled rule plan, импорт SigmaHQ-правил
- Многоуровневая нормализация (SafeLine-style: URL → HTML entity → NFKC → confusable folding → null-strip → lowercase до fixed-point)
- ML-скорер: логистическая регрессия (23 фичи) + GBM (gradient-boosted trees) + anomaly-детектор + threat-scoring engine (`src/threat_analytics.rs`, `src/anomaly.rs`)
- Полный фингерпринт-стек: JA3/JA4/JA4H/JA4T/JA4S/JA4X/JA4TS + H2FP + H3FP + mTLS_FP ([docs/11-tls-fingerprinting.md](./11-tls-fingerprinting.md))
- Репутационные фиды: JA4-reputation, JA4-corpus, ASN/CIDR-reputation, GeoIP (MaxMind), CrowdSec LAPI ([docs/12-reputation.md](./12-reputation.md), `src/geoip.rs`)

**Challenge и доверие:**
- Challenge ladder: cookie → JS → PoW (SHA-256 hashcash) → Argon2id memory-hard PoW → iframe/full CAPTCHA ([docs/15-challenge-ladder.md](./15-challenge-ladder.md))
- Pluggable CAPTCHA-провайдеры: hCaptcha / Turnstile / reCAPTCHA
- Privacy Pass (RFC 9576 / 9578) — анонимные токены доверенных issuer'ов проходят ladder молча ([docs/16-privacy-pass.md](./16-privacy-pass.md))
- Chained trust: TrustTier-прогрессия (Cookie 5 мин → CAPTCHA 24ч → WebAuthn 7 дней) per-(IP, RouteClass)
- ⚠️ ChallengeConfig по умолчанию `enabled = false` (V231) — challenge-ladder opt-in per-domain

**Deception (обман):**
- Honeypot core + tarpit, LLM-honeypot (Galah-style), YAML-машины (Beelzebub-style), poisoned tarpit (Markov-chain), decoy-headers (impersonation Cloudflare/Akamai/Fastly/CloudFront), latency jitter (`src/poisoned_tarpit.rs`, `src/llm_honeypot.rs`)

**Инфраструктура и enforcement:**
- Firewall fallback-цепь: XDP → nftables → iptables → userspace (автовыбор по доступности)
- BGP RTBH / FlowSpec upstream-анонс (`src/bgp_rtbh.rs`)
- Actuator framework — единый реестр активных мер (XdpDeny / NftDrop / BgpAnnounce / ChallengeFloorRaise) с revert-TTL (`src/arsenal.rs`)
- ClamAV-сканер для upload-тел (⚠️ выключен по умолчанию, включается `AEGIS_CLAMAV_ADDR`)
- Response-cache (HIT отдаётся из памяти worker'а). ⚠️ Кэш не кэширует credentialed-запросы (auth header / session cookie)

**Observability и управление:**
- Структурированный SecurityEvent-поток + Prometheus-метрики (cardinality-bounded), NDJSON SIEM-export, T-Pot Sicherheitstacho export (`src/event_store.rs`, `src/metrics/`)
- Persistent request/event log (SQLite per-worker shard, WAL) — [src/event_store.rs](../../src/event_store.rs)
- Admin API + RBAC + audit log; встроенная React-панель на `:6280/admin/ui` (бандл вшит в бинарь через `include_dir!`, Node.js в runtime не нужен) (`src/web_admin.rs`, `src/admin_ui.rs`, [docs/admin-api.md](../en/reference/admin-api.md))
- Terminal TUI (Ratatui) для ssh-only деплоев

> 🟡 **Плагины (Lua/WASM):** в зависимостях присутствуют `mlua` (Lua 5.4) и `wasmi` (см. [Cargo.toml](../../Cargo.toml)). Состояние интеграции и модель доверия следует сверять напрямую по коду; не считайте это полностью готовой подсистемой без такой сверки.

---

## 4. Для кого

| Роль | Что даёт AEGIS |
|---|---|
| **Операторы / SRE** | Drop-in edge перед существующим сервисом; установка одной командой (`install.sh`); управление через web-панель без правки конфига и рестарта (runtime toggles, per-domain policy) |
| **Владельцы сайтов / VPS** | DDoS-защита и WAF «из коробки» без вынесения трафика в сторонний CDN; self-hosted, данные не покидают сервер |
| **Разработчики** | Открытый Rust-код, библиотечная поверхность (`src/lib.rs`) для интеграционных тестов, конфигурируемый DSL ([docs/04-configuration.md](./04-configuration.md)) |
| **Security-команды** | Полный фингерпринт-стек, ML risk engine, SIEM-export, CrowdSec-совместимые решения для существующих bouncer'ов |

---

## 5. Как встаёт перед сервисом / VPS

AEGIS — это reverse proxy: вы направляете публичный трафик (порты 80/443) на AEGIS, а он форвардит на ваш внутренний апстрим (origin) по сконфигурированному URL.

```
                  ┌────────────────────────────────────────────┐
  Клиенты   →     │  AEGIS edge (порты 80/443, SO_REUSEPORT)    │   →   origin (ваш сервис)
  (HTTP/1.1,      │  · XDP fast-path (ядро) — early DROP/PASS   │       (nginx / app / VPS)
   H2, H3/QUIC)   │  · TLS termination + фингерпринт            │
                  │  · WAF + bot-детекция + challenge + ML      │
                  │  · форвардинг разрешённого трафика          │
                  └────────────────────────────────────────────┘
                         :6280/admin/ui  (web-панель, RBAC)
```

Установка идемпотентна и автоматизирована: `sudo bash install.sh` определяет ОС (Debian/Ubuntu/Fedora/Alpine) и архитектуру (amd64/arm64), ставит зависимости и rustup, собирает релиз-бинарь, создаёт системного пользователя `aegis` и каталоги (`/etc/aegis/...`, `/var/lib/aegis/...`), генерирует self-signed cert + admin token + HMAC secret, пишет hardened systemd-юнит (`NoNewPrivileges`, `ProtectSystem=strict`, ambient `CAP_NET_BIND_SERVICE`), открывает порты в ufw/firewalld, стартует сервис и печатает URL панели. Подробности и переменные окружения — в шапке [install.sh](../../install.sh) и в [docs/03-installation.md](./03-installation.md).

> 🟡 По умолчанию запускается N = `nproc` worker'ов: один systemd-инстанс `aegis-pingora@N.service` на ядро, CPU-pinned через `CPUAffinity=%i`, поверх SO_REUSEPORT. Число воркеров меняется на странице **Workers** в панели; состояние хранится в `/var/lib/aegis/topology.json`. См. [docs/06-workers.md](./06-workers.md).

---

## 6. Бинарники: `aegis` (hyper) vs `aegis-pingora`

В репозитории два развёртываемых HTTP-бинаря (плюс служебные — bench, importer и т.д., см. секцию `[[bin]]` в [Cargo.toml](../../Cargo.toml)).

| Бинарь | Сборка | Роль | Transport | Защита |
|---|---|---|---|---|
| **`aegis-pingora`** | `--features pingora` (требует `[[bin]]` `required-features = ["pingora"]`) | ✅ **Production data plane** (V71+) | TCP H1/H2 (TLS через openssl) + h3-сайдкар | Полная: WAF + ML + фингерпринт + XDP + Arsenal |
| **`aegis`** (hyper, default) | сборка по умолчанию (фича `pingora` опциональна) | Legacy / HTTP/3 dev / compat | TCP H1/H2 (TLS через rustls) + QUIC native | Тот же набор фильтров и тот же threat-state, отдельный transport |

Почему два: `aegis-pingora` строится на [Cloudflare Pingora](../../src/bin/aegis-pingora.rs) — это «полная production data plane, не preview» (комментарий в шапке файла). Hyper-путь (`src/main.rs`, `src/server.rs`) остаётся для HTTP/3 и dev-сред; он использует **те же фильтры и тот же threat-state**, отличается только транспортным слоем (rustls + quinn вместо openssl + Pingora I/O).

Важная деталь сборки (из [Cargo.toml](../../Cargo.toml)): Pingora-зависимости и openssl собираются **только** под фичей `pingora`, чтобы дефолтная сборка оставалась лёгкой. Pingora-rustls не даёт хука для `ResolvesServerCert` / ClientHello-байтов, поэтому используется **openssl-бэкенд** Pingora — он открывает per-SNI cert routing и JA3/JA4 capture. Сборочные зависимости: `libssl-dev` (Debian/Ubuntu) / `openssl@3` (macOS).

### Feature flags

| Флаг | Что включает | Требования |
|---|---|---|
| `pingora` | компиляцию бинаря `aegis-pingora` (production-путь) | `openssl-dev` / `libssl-dev`; на macOS `openssl@3` |
| `xdp` | Linux-only eBPF/XDP fast-path (loader через `aya`, attach XDP-программы к NIC, зеркалирование IP deny-списков в kernel BPF map) | kernel 5.8+; `CAP_BPF` + `CAP_NET_ADMIN` в runtime; предкомпилированный BPF-объект. ⚠️ На ARM без PMU (PERFMON) XDP не загрузится — graceful fallback на nftables |

> ⚠️ XDP eBPF-объект (`xdp/aegis-xdp-ebpf`) намеренно исключён из workspace и собирается отдельным nightly-тулчейном под `bpfel-unknown-none` (см. комментарий в [Cargo.toml](../../Cargo.toml)). Подробнее — [docs/13-xdp-ebpf.md](./13-xdp-ebpf.md).

### Выбор транспортного пути (pingora / hyper / both)

Исторически hyper-путь выбирался флагом `AEGIS_PINGORA=1` в рамках одного бинаря-`aegis` (см. комментарии в [src/proxy/pingora_http.rs](../../src/proxy/pingora_http.rs#L34) и [src/server.rs](../../src/server.rs)). В текущей production-схеме AEGIS деплоится как **отдельный бинарь `aegis-pingora`** через [install.sh](../../install.sh) — именно его ставит установщик в `/usr/local/bin/aegis-pingora` и запускает systemd-юнит. Hyper-бинарь `aegis` остаётся доступным для HTTP/3 и dev/compat-режимов. Практически:

- **pingora-режим** — штатный production (запускается `aegis-pingora`), полная защита, TCP H1/H2 + h3-сайдкар.
- **hyper-режим** — `aegis` для HTTP/3-через-нативный-QUIC и dev/compat; те же фильтры, другой transport.
- **both** — оба пути разделяют общий threat-state и набор фильтров; на практике это означает «pingora для основного TCP-трафика, hyper/quinn для h3», а не два независимых прокси.

Тонкая настройка pingora-рантайма — через переменные `AEGIS_PINGORA_THREADS`, `AEGIS_PINGORA_REUSEPORT`, `AEGIS_PINGORA_WORK_STEALING`, `AEGIS_PINGORA_UPSTREAM_POOL`, `AEGIS_PINGORA_GRACE_SECS` и др. (см. [src/bin/aegis-pingora.rs](../../src/bin/aegis-pingora.rs) и [docs/07-protocols.md](./07-protocols.md)).

---

## 7. Режимы работы (для понимания производительности)

Эти режимы — не флаги запуска, а профили нагрузки/конфигурации, в которых меряется и эксплуатируется AEGIS (см. [README.md](../../README.md) и [docs/PERFORMANCE.md](../en/reference/performance.md)):

| Режим | Что происходит | Назначение |
|---|---|---|
| **no-cache (forwarding)** | каждый запрос форвардится на апстрим | baseline throughput |
| **cache-mode (HIT)** | ответ отдаётся из памяти worker'а, апстрим не трогается | максимальный RPS (на GET + простых условиях) |
| **protected** | WAF + bot-фингерпринт + JA4H + движок фильтров на **каждом** запросе | полная L7-защита (~4% overhead vs plain на легитимном трафике) |
| **plain-proxy** | все фильтры выключены, чистый форвардинг | только для бенчмарка-сравнения |

---

## 8. Честные оговорки (обязательны во всей документации)

Эти ограничения зафиксированы в каноническом брифинге и авторитетном SECURITY-AUDIT-CONSOLIDATED-2026-06-07.md; по бенчмаркам — [docs/PERFORMANCE.md](../en/reference/performance.md).

1. **Бенчмарк-числа — не догма.** Internal-relay-бенчи (`src/bin/aegis-distbench.rs`, `bench/`) мерят in-process filter engine без реального I/O. Полный `aegis-pingora` под боевой нагрузкой даёт ↓15–30% vs synthetic bench (Pingora I/O, syscalls, TCP/TLS handshake). Никогда не цитируйте абсолютный RPS без пояснения «in-process filter relay, не real deployment».

2. **Hardware-зависимость PoW/HMAC.** PoW/HMAC-тесты в VM без AES-NI/SHA-NI в ×2–3 медленнее bare-metal Intel с SHA-расширениями. Всегда уточняйте контекст железа.

3. **AEGIS не «быстрее nginx».** Как голый форвардер AEGIS медленнее вылизанных C-форвардеров (изолированный V237-замер: разрыв ~13%, nginx ~590k vs AEGIS ~513k RPS plain). Честная формулировка: «полная L7-защита с лишь ~13% overhead vs C-форвардера; с защитой nginx+ModSecurity теряет −95% throughput, AEGIS — доли этого». С кэшем AEGIS ~1.7× vs nginx-форвардинг.

4. **Что реально работает vs что частично.** Работает: WAF (SQLi/XSS/traversal), JA3/JA4-фингерпринтинг, PoW/CAPTCHA, rate-limit, IP-based tarpit. **Не полная защита силами AEGIS:** DDoS L3/L4 (нужен upstream BGP/CDN), часть IPv6-механик (опции). Авторитет — аудит, а не маркетинг.

5. **Кэш не универсален.** Кэшируются только GET + простые условия (без auth header / session-specific cookie). Под волюметрическим L3-флудом даже кэшированный ответ требует входящего соединения — без upstream BGP-drop бэкенд/канал всё равно под давлением. Формулировка: «AEGIS отражает ~0% атак на origin за счёт WAF + challenge, но L3-флуды требуют upstream-защиты».

---

## 9. Куда дальше

- Как устроен запрос внутри — [docs/02-architecture.md](./02-architecture.md)
- Установка и эксплуатация — [docs/03-installation.md](./03-installation.md)
- Конфигурация (DSL/TOML) — [docs/04-configuration.md](./04-configuration.md)
- Системные требования — [docs/05-requirements.md](./05-requirements.md)
