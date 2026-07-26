# Глоссарий

Алфавитный справочник терминов, протоколов и подсистем AEGIS. Каждое определение привязано к реальным модулям кода (`src/lib.rs`) и честно отмечает, что включено по умолчанию, а что — opt-in. Сокращения подсистем приводятся в форме, в которой они встречаются в коде (имена модулей, директивы, переменные окружения, маршруты).

---

## Как пользоваться

- Термины отсортированы по латинскому/кириллическому алфавиту (латиница идёт первой).
- В колонке «Где в коде» указан модуль из `src/lib.rs` (`pub mod …`) или иной файл репозитория.
- Метка **opt-in** означает, что фича выключена по умолчанию и требует явного включения (переменная окружения, конфиг, `.with_arsenal()` и т. п.).
- Метка **default-on** означает, что подсистема активна без дополнительной настройки.
- Подробности по каждой теме — в соседних доках; ссылки даны относительным путём.

---

## A

### ALPN (Application-Layer Protocol Negotiation)
Расширение TLS, которым клиент в `ClientHello` объявляет список прикладных протоколов (`h2`, `http/1.1`, `h3`). AEGIS читает ALPN при захвате ClientHello и использует его как один из входов фингерпринтинга и согласования протокола. Подробности: [11-tls-fingerprinting.md](11-tls-fingerprinting.md), [07-protocols.md](07-protocols.md).

### Argon2id PoW
Память-затратная (memory-hard) альтернатива SHA-256 Proof-of-Work. По задумке в 100–1000× дороже на GPU-фермах, потому что нижняя граница RAM на попытку (по умолчанию 64 МБ) ограничивает параллелизм. Модуль `argon2_pow` (V200). См. [15-challenge-ladder.md](15-challenge-ladder.md).

### ASN (Autonomous System Number)
Номер автономной системы — идентификатор сети-оператора в BGP. AEGIS использует ASN двумя путями: (1) обогащение GeoIP по базе db-ip (страна + ASN), модуль `geoip`; (2) репутация по ASN, модуль `asn_reputation` (V142) — фид «плохих» ASN/CIDR с lookup-трейтом `AsnLookup`, питающий ML-фичу `asn_reputation`. См. [20-geoip.md](20-geoip.md), [12-reputation.md](12-reputation.md).

### Adversarial (состязательное обучение)
Цикл генерации семантически-эквивалентных мутаций SQLi-нагрузок и прогона их через WAF/скорер; обходы возвращаются в `MlTrainer` как hard-negative-образцы для следующего переобучения. Модуль `ml_adversarial` (V146, стиль WAF-A-MoLE). См. [18-ml-risk-engine.md](18-ml-risk-engine.md).

### Aho-Corasick
Алгоритм одновременного многошаблонного поиска подстрок. Основа WAF-движка сигнатур AEGIS: один проход по нормализованному запросу матчит весь корпус сигнатур. См. [10-waf.md](10-waf.md).

---

## B

### BGP RTBH (Remotely-Triggered Black Hole)
Remotely-Triggered Black Hole — подавление атаки на сетевом уровне через анонс маршрута апстриму, чтобы трафик к жертве отбрасывался ещё до прокси. AEGIS отдаёт L7-решения о блокировке вверх как BGP-анонсы /32 (по умолчанию через pipe ExaBGP; трейт-абстракция допускает goBGP/FRR) с TTL и авто-отзывом. Модуль `bgp_rtbh` (V187, FlowSpec/RTBH-диспетчер), **opt-in**. См. [19-bgp-rtbh.md](19-bgp-rtbh.md).

---

## C

### CIDR (Classless Inter-Domain Routing)
Нотация диапазона адресов вида `203.0.113.0/24`. AEGIS применяет CIDR в rate-limit по подсети и в репутации (`asn_reputation` умеет работать по CIDR без ASN-БД). Дефолтные списки Tor/Spamhaus поставляются как **default-on** репутация. См. [14-rate-limiting.md](14-rate-limiting.md), [12-reputation.md](12-reputation.md).

### Challenge ladder (лестница испытаний)
Эскалирующая последовательность проверок клиента: cookie → reload → PoW → CAPTCHA → WebAuthn. Связана с цепочечным доверием (`chained_trust`, V202: cookie 5 мин → captcha 24 ч → WebAuthn 7 дней), адаптивностью (`adaptive_ladder`, V204: бамп битов PoW в anomaly-режиме, рандомизация стартового уровня per-IP) и слоем обмана (`challenge_deception`, V203: decoy-CAPTCHA, honeypot-поля формы). См. [15-challenge-ladder.md](15-challenge-ladder.md).

### CrowdSec LAPI (Local API)
Локальный API CrowdSec — формат провода для решений о блокировке, который понимают «баунсеры» CrowdSec (nginx, HAProxy, Cloudflare worker, iptables, Caddy, k8s ingress). AEGIS эмитит решения в этом формате (`crowdsec_api`, V157), чтобы существующие баунсеры применяли вердикты AEGIS без переделки энфорсмента. Также CrowdSec используется как источник репутации (**opt-in**). См. [12-reputation.md](12-reputation.md), [21-arsenal-scenarios.md](21-arsenal-scenarios.md).

### Compound rules (составные правила)
WAF-правила, срабатывающие по комбинации условий, а не по одной сигнатуре. Часть WAF-корпуса наряду с Aho-Corasick-сигнатурами, Sigma-корпусом и webshell-детектами. См. [10-waf.md](10-waf.md).

### CAPTCHA-провайдеры
Подключаемые внешние провайдеры CAPTCHA: hCaptcha, Cloudflare Turnstile, Google reCAPTCHA. Трейт `CaptchaProvider` абстрагирует вызов siteverify, `HttpPoster` — транспорт. Модуль `captcha_providers` (V132), **opt-in**. См. [15-challenge-ladder.md](15-challenge-ladder.md).

---

## D

### Defence Arsenal
Зонтичная подсистема, объединяющая модули V176–V190 (`arsenal`, V192) под `ArsenalState` с покомпонентными счётчиками активности. Подключается к `AegisPingoraProxy` через `.with_arsenal()` и **по умолчанию отсутствует** — продакшен-бинарь включает арсенал явно. См. [21-arsenal-scenarios.md](21-arsenal-scenarios.md).

### Decoy headers (декой-заголовки)
Имитация формы ответа Cloudflare / Akamai / Fastly / CloudFront на подозрительных запросах, чтобы обходное инструментарий атакующего выбрал неверный playbook. Модуль `decoy_headers` (V188, инверсия Scrapling), **opt-in** (часть арсенала). См. [21-arsenal-scenarios.md](21-arsenal-scenarios.md).

---

## E

### eBPF (extended Berkeley Packet Filter)
Технология исполнения программ в ядре Linux. AEGIS использует её для XDP-программы быстрого пути дропа пакетов. См. [13-xdp-ebpf.md](13-xdp-ebpf.md).

### Ed25519
Алгоритм цифровой подписи на эллиптической кривой. Используется AEGIS для верификации токенов Privacy Pass. См. [16-privacy-pass.md](16-privacy-pass.md).

### EventBridge
NDJSON-стример событий безопасности (V116 `SecurityEvent`) поверх Unix-сокета для SIEM. Best-effort и потеря-терпимый: медленные подписчики теряют события, но горячий путь прокси никогда не блокируется. Модуль `event_bridge` (V127). См. [25-metrics-telemetry.md](25-metrics-telemetry.md).

### Event-store
Персистентный лог запросов/событий. Per-worker SQLite-шард (`shard-<slot>.db`, WAL, один писатель на процесс) пишется из фонового потока через ограниченный канал, чтобы `record()` на горячем пути не блокировался; read-сторона админки делает `ATTACH` всех шардов и `UNION ALL`. Питает поиск по логу запросов, аналитику по доменам и «bots/DDoS за любой период». Модуль `event_store` (V243). См. [24-request-log.md](24-request-log.md).

---

## G

### GeoIP
Гео-обогащение по базе db-ip: страна + ASN. Модуль `geoip`. См. [20-geoip.md](20-geoip.md).

### GREASE (Generate Random Extensions And Sustain Extensibility)
Механизм RFC 8701: браузеры подмешивают случайные «мусорные» значения в cipher/extension-списки TLS, чтобы серверы не «закостеневали» на фиксированном наборе. AEGIS детектирует аномалии позиции GREASE: настоящий Chrome кладёт GREASE в `cipher[0]`, `ext[0]` и `supported_versions[0]`, а спуферы хардкодят одну перестановку. Модуль `grease_anomaly` (V178, стиль utls), выдаёт скор аномалии в [0,1]. См. [11-tls-fingerprinting.md](11-tls-fingerprinting.md).

---

## H

### Honeypot
Ловушка: ресурсы и пути-приманки, обращение к которым автоматически помечает клиента как вредоносного. В AEGIS: базовый `honeypot` (`HoneypotStore`), YAML-дескрипторы сервисов с детерминированными многошаговыми сценариями engagement (`honeypot_yaml`, V184, стиль Beelzebub), LLM-honeypot (см. ниже), robots.txt-honeypot (`robots_honeypot`, V149 — визиты на Disallow-пути пушат Malicious-образцы в `MlTrainer`). См. [17-honeypot-tarpit.md](17-honeypot-tarpit.md).

### LLM-honeypot
Honeypot, отвечающий правдоподобными ответами от LLM с кешем по семантическому хешу формы запроса (метод, шаблон пути, имена заголовков, форма тела), чтобы один сканер получал когерентные ответы без LLM-стоимости на каждый запрос. Трейт `LlmClient`. Модуль `llm_honeypot` (V183, стиль Galah), **opt-in**. См. [17-honeypot-tarpit.md](17-honeypot-tarpit.md).

### Honeypot self-learn (JA4 self-learn)
Само-обучение репутации JA4: «плохие» JA4-хеши майнятся из honeypot/WAF/tarpit-решений и подаются в фид репутации. См. `ja4_reputation`, `online_signature_miner`. См. [12-reputation.md](12-reputation.md).

---

## J

### JA3
Хеш TLS-фингерпринта `ClientHello` (версия, cipher-suites, extensions, эллиптические кривые, форматы точек). Модуль `ja3`. Захват — в callback `set_client_hello_callback`, под гейтом fingerprinting. См. [11-tls-fingerprinting.md](11-tls-fingerprinting.md).

### JA4
Современный TLS-фингерпринт семейства JA4+ (FoxIO): человекочитаемая структура по `ClientHello`. Базовый модуль `ja4`. Производные:

| Термин | Что фингерпринтит | Модуль / примечание |
|---|---|---|
| **JA4** | TLS ClientHello (клиент) | `ja4` |
| **JA4H** | HTTP-запрос (метод, версия, заголовки, cookie) | в составе фингерпринтинга, кросс-сверка с JA4 |
| **JA4T** | TCP SYN клиента (window, опции) | `tcp_info` / `p0f`-смежно |
| **JA4L** | латентность TLS-handshake (client-leg) | измерение латентности |
| **JA4S** | TLS ServerHello (сервер) | `ja4_server` (V126) |
| **JA4X** | X.509-сертификат | `ja4_server` (V126) |
| **JA4TS** | TCP SYN-ACK сервера | `ja4_server` (V126) |
| **JA4LS** | латентность server-leg | `ja4_server` (V126) |

Серверное семейство (`ja4_server`) операторы используют для детекта скомпрометированных апстримов и мониторинга стабильности цепочки сертификатов. См. [11-tls-fingerprinting.md](11-tls-fingerprinting.md).

### JA4 corpus
Курируемый корпус JA4 (seed от FoxIO): `Verdict::Allow` для известных браузеров, `Verdict::Deny` для известного инструментария. Консультируется до фида репутации; операторский файл расширяет корпус. Модуль `ja4_corpus` (V176). См. [12-reputation.md](12-reputation.md).

### JA4 churn
Скор «текучести» JA4 per-IP по скользящему окну. Высокий churn = ротация TLS-фингерпринта (utls / curl-impersonate). Питает ML-фичу `ja4_churn`. Модуль `ja4_churn` (V177). См. [18-ml-risk-engine.md](18-ml-risk-engine.md).

### JA4 reputation feed
Фид репутации JA4: оператор кладёт в файл список плохих JA4-хешей (community CTI, внутренний IR, майнинг из honeypot), модуль даёт O(1) lookup + горячую перезагрузку. Два вида матча: полный JA4 (сильнейший) и только по cipher-префиксу (слабее, шире). Модуль `ja4_reputation` (V138). См. [12-reputation.md](12-reputation.md).

---

## L

### LAPI
См. **CrowdSec LAPI**.

### Latency jitter (джиттер латентности)
Шейпинг задержек ответа по лог-нормальному или бимодальному (CDN-подобному) распределению для tarpit/honeypot/decoy-ответов, чтобы сорвать фингерпринтинг по времени ответа. Модуль `latency_jitter` (V190, стиль LLMHoney), **opt-in**. См. [17-honeypot-tarpit.md](17-honeypot-tarpit.md).

---

## M

### ML risk engine (движок риска)
Подсистема скоринга риска на основе ML. Режимы энфорсмента: **Observe** (только наблюдение), **HighConfidenceEnforce** (энфорс только при высокой уверенности), **FullEnforce** (полный энфорс). Модели версий v1/v2 (logistic/gbm). Связанные модули: `anomaly`, `fp_correlation` (V137, кросс-фингерпринт-корреляция: «Chrome JA4 + curl UA»), `client_consistency` (V145, CreepJS-стиль), `ml_adversarial` (V146), `timing_entropy` (V189), `signature_mine`/`online_signature_miner` (майнинг сигнатур). См. [18-ml-risk-engine.md](18-ml-risk-engine.md).

### ModSecurity
Классический WAF-движок-движок правил (контекст: OWASP CRS изначально писался для него). AEGIS не использует ModSecurity напрямую, но совместим по духу с подходом «фазы + правила»: фазо-индексированный план правил реализован в `rule_planner` (V181, стиль Coraza) — бакетирование ID правил по `Phase` (uri/headers/body/response) с severity-сортированной диспетчеризацией. См. [10-waf.md](10-waf.md).

### mTLS (mutual TLS)
Взаимная TLS-аутентификация — клиент тоже предъявляет сертификат. AEGIS фингерпринтит клиентский сертификат при mTLS. Модуль `mtls_fp`. См. [08-tls-certificates.md](08-tls-certificates.md), [11-tls-fingerprinting.md](11-tls-fingerprinting.md).

---

## N

### Normalisation (нормализация)
Многопроходная цепочка нормализации запроса перед матчингом WAF (стиль SafeLine): URL-декод → HTML-сущности → NFKC full-width → unicode-конфузаблы → strip null → lowercase. Прогоняется до фиксированной точки с ограниченным числом проходов. Модуль `normalisation` (V179). См. [10-waf.md](10-waf.md).

---

## O

### OWASP CRS (Core Rule Set)
OWASP Core Rule Set — открытый набор правил WAF. В AEGIS прямого импорта CRS нет; вместо него — собственный корпус сигнатур + импорт Sigma-правил (`sigma`, V196) и фазо-индексированный планировщик (`rule_planner`). Совместимость по концепции «фаз обработки». См. [10-waf.md](10-waf.md).

---

## P

### p0f
Пассивный фингерпринтинг ОС / TCP-стека по наблюдениям SYN (window, MSS, wscale, опции, TTL), которые AEGIS уже захватывает, с классификацией в семейство ОС для кросс-проверки «UA против стека». Модуль `p0f` (V155). См. [11-tls-fingerprinting.md](11-tls-fingerprinting.md).

### PoW (Proof-of-Work)
Доказательство работы — асимметричная задача: клиент тратит секунды CPU, сервер проверяет за микросекунды. SHA-256-hashcash реализован в `pow_captcha` (V131); память-затратная альтернатива — `argon2_pow` (V200). Цель — задавить одиночного атакующего, проксирующего много сессий. См. [15-challenge-ladder.md](15-challenge-ladder.md).

### Privacy Pass
Анонимные токены доказательства доверия (форма RFC 9576), выпускаемые Cloudflare/Apple/Fastly и др.; верифицированные браузеры молча проходят лестницу испытаний. Верификатор на Ed25519. Модуль `privacy_pass` (V201). См. [16-privacy-pass.md](16-privacy-pass.md).

### Param profile (профиль параметров)
Обучаемый per-endpoint профиль параметров (стиль open-appsec): скользящая статистика (длина / charset / энтропия) по `(host, endpoint, param)`; скор аномалии после `learn_threshold` наблюдений. Модуль `param_profile` (V180). См. [10-waf.md](10-waf.md).

### Poisoned tarpit (отравленный tarpit)
Tarpit с генератором текста на цепях Маркова + бесконечными внутренними ссылками HTML, чтобы AI-скраперы, игнорирующие robots.txt, увязали в лабиринте и жгли CPU, рекурсивно обходя фейковые страницы. Детерминированный per-deployment seed держит корпус трудным для фингерпринтинга. Модуль `poisoned_tarpit` (V147, линия Iocaine/Nepenthes/HellPot). См. [17-honeypot-tarpit.md](17-honeypot-tarpit.md).

---

## R

### Rate limiting (ограничение частоты)
Ограничение частоты запросов per-IP / по подсети / по URI, с бэкендом Redis для cross-worker-состояния. См. [14-rate-limiting.md](14-rate-limiting.md).

### Risk engine
См. **ML risk engine**.

### Reputation (репутация)
Сводный фид доверия к источнику. Слагаемые: JA4 self-learn (honeypot/WAF/tarpit), ASN/CIDR-репутация (Tor/Spamhaus **default-on**), CrowdSec LAPI (**opt-in**), threat-intel. Реализация: `ja4_reputation`, `ja4_corpus`, `asn_reputation`, `crowdsec_api`, `enrichment`. См. [12-reputation.md](12-reputation.md).

### Route difficulty (сложность по маршруту)
Per-(host,path) переопределение сложности испытания + пресет под AI-скраперов (+4 бита для GPTBot и т. п.) + пресет под auth-эндпоинты (+6 бит, форс JS-PoW на `*/login`). Модуль `route_difficulty` (V186, стиль Anubis). См. [15-challenge-ladder.md](15-challenge-ladder.md).

---

## S

### Scenarios (сценарии)
YAML-DSL поведенческого rate-limit в стиле leaky-bucket CrowdSec: грамматика `filter / groupby / distinct / capacity / leak_speed / blackhole` покрывает детект поведенческих аномалий без кода. Модуль `scenarios` (V199), часть Arsenal + актуаторы. См. [21-arsenal-scenarios.md](21-arsenal-scenarios.md).

### Sigma
Открытый формат правил детектирования. AEGIS импортирует SigmaHQ-YAML-правила (`logsource.category: webserver`) в значения `crate::config::WafRule` через CLI `aegis-sigma-import`. Поддержан общий набор модификаторов (contains/startswith/endswith/re), list-значения, условия одиночного блока + «1 of selection_*» + «selection and not filter». Модуль `sigma` (V196). См. [10-waf.md](10-waf.md).

### SNI (Server Name Indication)
Расширение TLS, которым клиент в `ClientHello` объявляет запрашиваемое имя хоста — позволяет одному IP обслуживать много TLS-сайтов и маршрутизировать по домену. Модуль `tls_sni`. См. [08-tls-certificates.md](08-tls-certificates.md), [26-sites-and-domains.md](26-sites-and-domains.md).

### SO_REUSEPORT
Сокет-опция, позволяющая нескольким процессам слушать один порт с распределением соединений ядром. Основа многопроцессности AEGIS: воркеры `aegis-pingora@0..N` слушают один порт, cross-worker-состояние — через диск + опрос по mtime. См. [06-workers.md](06-workers.md).

### Site map (картография)
Авто-обнаружение эндпоинтов из живого трафика с генерализацией путей (`/users/12345` → `/users/:id`) и per-host ограниченным LRU. Поверхность для страницы per-domain-редактирования в админке. Модуль `site_map` (V119); per-domain политика — `domain_policy` (V162). См. [26-sites-and-domains.md](26-sites-and-domains.md).

### SQL semantic detector
Семантический детектор SQL-инъекций (стиль SafeLine): токенизирует нагрузку (URL-декод + учёт комментариев/кавычек/hex/операторов) и распознаёт «форму инъекции» (тавтология, UNION после значения, stacked DDL, time-blind, комментарий после кавычки). По задумке устойчив к мутаторам V146/V148. Модуль `sql_semantic` (V156). См. [10-waf.md](10-waf.md).

---

## T

### Tarpit
Замедляющая ловушка: подозрительные соединения удерживаются/тянутся, чтобы изматывать ресурсы атакующего. В AEGIS — `poisoned_tarpit` (см. выше), а также источник для майнинга сигнатур (`online_signature_miner`, V107: tarpit-решения логируют payload, фоновый майнер периодически выделяет ранжированных кандидатов и отдаёт их через `/admin/api/mined_signatures`). См. [17-honeypot-tarpit.md](17-honeypot-tarpit.md).

> Замечание о слоулорис: реакция AEGIS — это реакция AEGIS — пожинание (reaping) медленных соединений считается защитой, а не перегрузкой (см. логику вердикта в `benchmark_flood`). См. [28-benchmarking.md](28-benchmarking.md).

### Threat intel / enrichment
Кешируемый фасад над всеми источниками разведки (`ja4_reputation`, `asn_reputation`, `threat_intel`, `geoip`, `ja4_corpus`) с per-source TTL и провенансом. Модуль `enrichment` (V198, стиль WISE). Аналитика угроз (`threat_analytics`, V121) разделяет per-IP бот-детекты и распределённый DDoS (ботнет). См. [22-enrichment.md](22-enrichment.md), [12-reputation.md](12-reputation.md).

### Timing entropy
ML-фичи по тайминговой энтропии: серверный анализатор дрожания мыши / каденса скролла, собранных клиентским `client_consistency` (V145). Детекторы равномерного таймера выдают скор аномалии ∈ [0,1]. Модуль `timing_entropy` (V189). См. [18-ml-risk-engine.md](18-ml-risk-engine.md).

---

## W

### WAF (Web Application Firewall)
Брандмауэр веб-приложений — фильтрация HTTP-запросов на прикладном уровне. WAF AEGIS: Aho-Corasick-сигнатуры + Sigma-корпус + compound-правила + webshell-детекты, поверх многопроходной нормализации (`normalisation`), с семантическим SQLi-детектором (`sql_semantic`), фазо-планировщиком (`rule_planner`) и профилем параметров (`param_profile`). Базовые модули: `filters`, `dsl`, `config::WafRule`. См. [10-waf.md](10-waf.md).

### Webshell signatures
Сигнатуры детектирования веб-шеллов (в т. ч. PHP-webshell) в составе WAF-корпуса. См. [10-waf.md](10-waf.md).

### WebAuthn
Сильнейший тир лестницы испытаний (аппаратный/платформенный аутентификатор). В цепочечном доверии (`chained_trust`) даёт самое длинное окно доверия (7 дней). См. [15-challenge-ladder.md](15-challenge-ladder.md).

---

## X

### XDP (eXpress Data Path)
Быстрый путь в ядре Linux (на eBPF) для дропа/перенаправления пакетов до сетевого стека. AEGIS использует XDP как kernel fast-path; цепочка фолбэков энфорсмента: **XDP → nftables → iptables → userspace** (`xdp`, `nftables_backend` V128, `iptables_backend` V130; `open_with_fallback()` возвращает первый успешно инициализированный бэкенд, все реализуют общий `XdpHandle`). См. [13-xdp-ebpf.md](13-xdp-ebpf.md).

---

## Прочие термины

### Actuator (актуатор)
Фреймворк активного ответа: реестр `(kind, target) → Actuator` с TTL отката и timer-wheel. Заменяет разрозненные паттерны «XDP-дроп, который никогда не истекает». Модуль `actuator` (V197). См. [21-arsenal-scenarios.md](21-arsenal-scenarios.md).

### Admin API
Около 86 маршрутов `/admin/api/*`; авторизация по `x-admin-token` / сессии / ролям. Модули `admin_auth`, `web_admin`, `server`. См. [30-admin-api.md](30-admin-api.md).

### Admin-панель
React-панель на 37 страниц поверх Admin API. Модуль `admin_ui`. См. [29-admin-panel.md](29-admin-panel.md).

### ACME
Авто-выпуск сертификатов (Let's Encrypt): HTTP-01-челлендж-респондер + раскладка cert-on-disk + оркестратор продления. Драйвер протокола инъектируется трейтом `AcmeClient`; конкретная реализация — на `instant-acme` (`acme` V134, `acme_instant` V234), с записью ключа аккаунта `O_CREAT|O_EXCL` + chmod 0600. См. [08-tls-certificates.md](08-tls-certificates.md).

### Benchmark / capacity projection
Микро-бенчмарки CPU integer / SHA-256 / memory-bandwidth + проекция RPS (forwarding/TLS/WAF) калиброванной линейной моделью (`benchmark`, V240); флуд-тесты на loopback (`benchmark_flood`, V241); сравнение vs nginx + матрица безопасности (`benchmark_compare`, V245).

> Честные оговорки: бенч-лейны AEGIS — это **in-process-движок**, а не полный pingora-бинарь. Аппаратный SHA-бенч — per-core и внутри VM без аппаратного SHA-ускорения низкий, тогда прогноз ёмкости пессимистичен. Матрица безопасности — честный сильный аргумент; AEGIS **не** заявляется быстрее реальных проксей по голой скорости. См. [28-benchmarking.md](28-benchmarking.md), [27-performance-tuning.md](27-performance-tuning.md).

### ClamAV scanner
TCP-сканер ClamAV для тела (multipart/octet-stream uploads) через протокол INSTREAM. **Выключен по умолчанию**; включается `AEGIS_CLAMAV_ADDR=host:3310`. Модуль `clamav_scanner` (V129).

### ClientHello callback
Точка захвата TLS-фингерпринтов — `set_client_hello_callback`, под гейтом fingerprinting. Здесь читаются cipher/extensions/ALPN/SNI/GREASE. См. [11-tls-fingerprinting.md](11-tls-fingerprinting.md).

### H2 budget (HTTP/2 control-frame budgets)
Per-connection token-bucket на каждый `FrameKind` (стиль Tempesta). Закрывает класс атак Rapid Reset / Settings flood / Ping flood / CONTINUATION flood. Модуль `h2_budget` (V182). Смежно — фингерпринтинг H2 (`h2_fp`) и HTTP/3 (`h3_fp`). См. [07-protocols.md](07-protocols.md).

### Real-IP resolver
Резолвер реального клиентского IP из `CF-Connecting-IP` / `X-Forwarded-For`, **только** если TCP-пир входит в доверенный proxy-set оператора. Нулевое изменение поведения, если `AEGIS_BEHIND_CLOUDFLARE` и `AEGIS_TRUSTED_PROXIES` не заданы. Модуль `real_ip`. См. [04-configuration.md](04-configuration.md).

### SecurityEvent
Структурированное событие безопасности (V116) + per-decision Prometheus-счётчики. Единая точка эмита для каждого решения Allow/Challenge/Deny/Throttle/Observed; метки ограничены по кардинальности (`&'static str`-причины). Модуль `security_event`. См. [25-metrics-telemetry.md](25-metrics-telemetry.md).

### Sicherheitstacho
Схема экспорта событий T-Pot Sicherheitstacho: рендер событий безопасности AEGIS в Sicherheitstacho-совместимый NDJSON для интеропа с deception-экосистемой. Модуль `sicherheitstacho` (V185). См. [25-metrics-telemetry.md](25-metrics-telemetry.md).

### TUI
Терминальный дашборд (Ratatui): чистые render-функции над значением `DashboardSnapshot`. Бинарь `aegis-tui` кормит его снапшотами из Admin API. Модуль `tui` (V133).

### Topology
Runtime-интроспекция топологии воркеров для страницы Workers в админке (факты о CPU хоста + живой скан процессов `aegis-pingora`). Модуль `topology` (V232). См. [06-workers.md](06-workers.md).

### Updates
Phase 1: проверка обновлений — опрос Gitea/GitHub-совместимого Releases API, классификация тегов на каналы stable/beta/nightly, показ «update available + changelog» в админке. **Не применяет** обновления (operator-driven). Phase 2/3: снапшот/восстановление конфига (`update_snapshot`), раскладка `releases/<version>/` + атомарный swap симлинка (`update_layout`), брокер apply-status (`update_apply`). Модули `updates` (V208), `update_snapshot` (V209), `update_layout` (V210), `update_apply` (V211). См. [44-updates-migration.md](44-updates-migration.md).

---

## Бинарники и сборка (справочно)

| Имя | Роль |
|---|---|
| `aegis` | hyper + CLI |
| `aegis-pingora` | основной data plane (фичи `pingora`+`xdp`), многопроцессно `aegis-pingora@0..N` |
| `aegis-tui` | терминальный дашборд |
| `aegis-sigma-import` | импорт Sigma-правил в `WafRule` |
| `aegis-updater` | применение обновлений (Phase 3) |

Установка: `install.sh` (`curl | bash`) + systemd target + template-юнит. Профиль сборки: thin-LTO / cgu16 / incremental + `AEGIS_BUILD_OPT=max` + `mold`. См. [03-installation.md](03-installation.md), [27-performance-tuning.md](27-performance-tuning.md).

---

## См. также

- [01-overview.md](01-overview.md) — общий обзор AEGIS
- [02-architecture.md](02-architecture.md) — архитектура подсистем
- [23-security-model.md](23-security-model.md) — модель безопасности и матрица
- 42-текущее-состояние-STATUS.md — что реализовано на сегодня
- [47-faq-troubleshooting.md](47-faq-troubleshooting.md) — FAQ и устранение неполадок
