/* ============================================================
   AEGIS landing — i18n, charts, interactions
   ============================================================ */

/* ---------- i18n dictionary ---------- */
const I18N = {
  ru: {
    // nav
    nav_features: "Возможности", nav_how: "Как работает", nav_bench: "Бенчмарки",
    nav_compare: "Сравнение", nav_pricing: "Установка", nav_faq: "FAQ", nav_cta: "Начать",
    // hero
    hero_badge: "Open-source · Rust · Pingora + Hyper",
    hero_title_1: "Защита от DDoS и L7-атак",
    hero_title_2: "для вашего VPS, на Rust",
    hero_sub: "Самостоятельно размещаемый реверс-прокси, который поглощает атаки L3-L7 перед вашим сервисом: WAF, отпечатки TLS (JA3/JA4), ядро-фильтр XDP/eBPF и ML-движок риска — в одном бинарнике.",
    hero_cta1: "Развернуть за 5 минут", hero_cta2: "Документация",
    hero_stat_rps: "RPS форвардинга", hero_stat_rules: "Sigma-правил WAF", hero_stat_lat: "Накладные задержки", unit_ms: "мс",
    // trust
    trust_tls: "RPS с TLS", trust_waf: "RPS + WAF", trust_hs: "TLS-рукопожатий/с",
    trust_layers: "Защита уровней", trust_self: "Self-hosted",
    // problem
    prob_kicker: "Угрозы", prob_title: "Ваш сервер атакуют каждый день",
    prob_sub: "Боты, флуды и эксплойты не спят. Без выделенного слоя защиты один скрипт-кидди может уронить ваш VPS.",
    prob_1_t: "DDoS L3/L4", prob_1_d: "SYN-флуды и объёмные атаки забивают канал и исчерпывают сокеты ещё до приложения.",
    prob_2_t: "L7-флуды", prob_2_d: "HTTP/2-флуды и медленные slowloris-соединения выглядят легитимно, но кладут бэкенд.",
    prob_3_t: "Боты и скрейперы", prob_3_d: "Автоматизация выкачивает контент, цены и данные, маскируясь под обычные браузеры.",
    prob_4_t: "Credential stuffing", prob_4_d: "Перебор украденных паролей по формам входа взламывает аккаунты пользователей.",
    prob_5_t: "Инъекции и эксплойты", prob_5_d: "SQLi, XSS, RCE, Log4Shell, path traversal — один пропущенный запрос компрометирует всё.",
    prob_6_t: "Веб-шеллы", prob_6_d: "c99, r57, wso, b374k, eval($_POST) — загруженный бэкдор даёт злоумышленнику ваш сервер.",
    // solution
    sol_kicker: "Решение", sol_title: "Один щит для всего стека",
    sol_p1: "AEGIS ставится перед любым веб-сервисом или VPS и фильтрует трафик сверху донизу: от пакетов в ядре до тела HTTP-запроса. Атаки отбиваются как можно раньше — самые дешёвые дропаются прямо в ядре через XDP, остальные проходят через WAF, отпечатки TLS и ML-оценку риска.",
    sol_p2: "Никаких облачных посредников: трафик никогда не покидает ваш сервер, нет оплаты за каждый запрос. Один бинарник, install.sh, systemd — и вы под защитой.",
    sol_li1: "Фильтрация в ядре до userspace — минимальные накладные расходы",
    sol_li2: "Самообучаемая репутация JA4 и адаптивная лестница challenge",
    sol_li3: "Авто-TLS (ACME / Let's Encrypt), HTTP/1.1, HTTP/2 и HTTP/3 (QUIC)",
    sol_code_c1: "фильтрация в ядре", sol_code_c2: "легитимный трафик проходит",
    // features
    feat_kicker: "Возможности", feat_title: "Полный арсенал защиты",
    feat_sub: "Каждый слой работает независимо и усиливает остальные. Всё включено, ничего докупать не нужно.",
    // how
    how_kicker: "Конвейер", how_title: "Путь запроса сквозь AEGIS",
    how_sub: "Каждый запрос проходит каскад проверок. Чем дешевле фильтр — тем раньше он стоит.",
    how_s1_t: "Клиент", how_s1_d: "Входящий трафик",
    how_s2_t: "XDP / eBPF", how_s2_d: "Дроп в ядре: SYN-флуд, deny-листы",
    how_s3_t: "TLS / JA4", how_s3_d: "Отпечатки JA3/JA4 + репутация",
    how_s4_t: "WAF", how_s4_d: "Aho-Corasick сигнатуры + тело",
    how_s5_t: "Challenge / ML", how_s5_d: "PoW-challenge + оценка риска",
    how_s6_t: "Rate limit", how_s6_d: "IP / подсеть /64 / URI · Redis",
    how_s7_t: "Upstream", how_s7_d: "Только чистый трафик",
    how_note: "Параллельно: репутация ASN/CIDR, GeoIP, honeypot + tarpit, CrowdSec LAPI и BGP RTBH для blackhole /32 апстриму при атаках высокой уверенности.",
    // bench
    bench_kicker: "Производительность", bench_title: "Бенчмарки и сравнение с nginx",
    bench_sub: "Честно: «голый» nginx быстрее на статике без защиты. Ценность AEGIS — интегрированная защита L7 с конкурентной пропускной способностью. Все цифры зависят от железа, измерены на базовых 8 ядрах.",
    bench_c1_t: "RPS по режимам", bench_c1_s: "raw nginx (без защиты) vs AEGIS (полная DDoS+WAF защита)",
    bench_c2_t: "TLS-рукопожатий в секунду", bench_c2_s: "полные рукопожатия; HTTP/2-мультиплексирование поднимает реальную пропускную способность",
    bench_c3_t: "Задержка p99 под нагрузкой", bench_c3_s: "мс, при росте конкурентности запросов",
    bench_c4_t: "Митигация атак", bench_c4_s: "nginx «из коробки» закрывает мало векторов L7",
    bench_disclaimer: "Цифры — репрезентативные оценки на 8-ядерном базовом сервере и масштабируются с железом. Ваши результаты зависят от CPU, NIC, конфигурации и профиля трафика.",
    // tiers
    tier_kicker: "Масштабирование", tier_title: "VPS, выделенный или облако",
    tier_sub: "AEGIS использует SO_REUSEPORT и мультипроцессность — пропускная способность растёт почти линейно с ядрами.",
    tier_1_tag: "Малый VPS", tier_1_core: "2 ядра", tier_1_d: "Идеально для индивидуальных проектов, блогов и небольших API под защитой.",
    tier_2_tag: "VPS · популярный", tier_2_core: "8 ядер", tier_2_d: "Базовая конфигурация бенчмарков: SaaS, e-commerce, продакшен-нагрузки.",
    tier_3_tag: "Выделенный", tier_3_core: "32 ядра", tier_3_d: "Высоконагруженные платформы и точки агрегации трафика на грани сети.",
    tier_rps: "RPS",
    tier_chart_t: "Масштабирование RPS по ядрам", tier_chart_s: "режим plain-форвардинга, оценка",
    tier_th_tier: "Тир", tier_th_cores: "Ядра", tier_th_rps: "RPS (plain)", tier_th_waf: "RPS + WAF", tier_th_eff: "Эфф.",
    tier_r1: "Малый VPS", tier_r2: "VPS 8-ядер", tier_r3: "Выделенный", tier_r4: "Облако (авто-масштаб)",
    tier_eff_high: "Высокая", tier_eff_best: "Лучшая цена/RPS", tier_eff_max: "Макс. throughput", tier_eff_payg: "платишь за инстансы",
    tier_flex: "гибко", tier_elastic: "эластично",
    // use cases
    uc_kicker: "Кому подходит", uc_title: "Один продукт — два мира",
    uc_b_t: "Бизнес", uc_b_sub: "SaaS и e-commerce, где простой стоит денег, а данные — под регламентом.",
    uc_b_1: "Аптайм и соответствие требованиям — трафик не покидает периметр",
    uc_b_2: "Интеграции SIEM и CrowdSec LAPI, threat-intel фиды",
    uc_b_3: "Аналитика ботов и DDoS за любой период из SQLite-лога",
    uc_b_4: "Админ-панель: дашборды, конфиг по доменам, restart без даунтайма",
    uc_v_t: "Свой VPS", uc_v_sub: "Indie-разработчики, которым нужна серьёзная защита без облачных счетов.",
    uc_v_1: "Установка одной командой — один бинарник и install.sh",
    uc_v_2: "Бесплатно и open-source — никаких лимитов по запросам",
    uc_v_3: "Полный контроль: ваши правила, ваши данные, ваше железо",
    uc_v_4: "Никакой оплаты за запрос и облачного посредника в трафике",
    // compare
    cmp_kicker: "Сравнение", cmp_title: "AEGIS против альтернатив",
    cmp_th_feat: "Возможность", cmp_th_nginx: "nginx + ModSecurity", cmp_th_cf: "Cloudflare / cloud WAF",
    // why
    why_kicker: "Приватность", why_title: "Зачем self-host",
    why_p: "С облачным WAF весь ваш трафик проходит через чужую инфраструктуру, а счёт растёт с каждым запросом. AEGIS работает на вашем железе: данные пользователей не покидают ваш сервер, нет per-request биллинга, нет вендор-лока. Вы видите каждое решение движка и владеете всеми логами.",
    why_s1: "за запрос", why_s2: "данных уходит наружу", why_s3: "контроля над правилами", why_s4: "запросов без доплат",
    // pricing
    price_kicker: "Установка", price_title: "Разверните за пять минут",
    price_sub: "Open-source и бесплатно для self-host. Опциональная поддержка — для команд, которым нужен SLA.",
    price_install: "установка в один шаг", price_copy: "Копировать",
    price_popular: "Рекомендуем",
    price_oss_t: "Self-host (Open Source)", price_free: "Бесплатно",
    price_oss_d: "Полный функционал. Навсегда. Ваше железо, ваши правила.",
    price_oss_1: "Все возможности WAF, XDP, ML и challenge",
    price_oss_2: "Неограниченные домены и запросы",
    price_oss_3: "Поддержка сообщества и обновления",
    price_oss_cta: "Скачать на GitHub",
    price_mgd_t: "Managed / Поддержка", price_custom: "По запросу",
    price_mgd_d: "Для команд, которым нужны SLA, приоритетная помощь и сопровождение.",
    price_mgd_1: "Приоритетная поддержка с SLA",
    price_mgd_2: "Помощь с настройкой правил и тюнингом",
    price_mgd_3: "Кастомные интеграции и обучение команды",
    price_mgd_cta: "Связаться",
    // faq
    faq_kicker: "FAQ", faq_title: "Частые вопросы",
    // footer
    foot_tag: "Self-hosted DDoS & WAF реверс-прокси на Rust.",
    foot_product: "Продукт", foot_res: "Ресурсы", foot_docs: "Документация",
    foot_start: "Начать", foot_cta_d: "Разверните защиту прямо сейчас.",
    foot_rights: "Open-source. Все права защищены.", foot_built: "Собрано на Rust · Pingora + Hyper",
    // dynamic: toasts
    toast_copied: "Скопировано в буфер обмена",
  },
  en: {
    nav_features: "Features", nav_how: "How it works", nav_bench: "Benchmarks",
    nav_compare: "Comparison", nav_pricing: "Install", nav_faq: "FAQ", nav_cta: "Get started",
    hero_badge: "Open-source · Rust · Pingora + Hyper",
    hero_title_1: "DDoS & L7 attack protection",
    hero_title_2: "for your VPS, built in Rust",
    hero_sub: "A self-hostable reverse proxy that absorbs L3-L7 attacks in front of your service: WAF, TLS fingerprinting (JA3/JA4), an XDP/eBPF kernel fast-path and an ML risk engine — in a single binary.",
    hero_cta1: "Deploy in 5 minutes", hero_cta2: "Documentation",
    hero_stat_rps: "Forwarding RPS", hero_stat_rules: "Sigma WAF rules", hero_stat_lat: "Added latency", unit_ms: "ms",
    trust_tls: "RPS with TLS", trust_waf: "RPS + WAF", trust_hs: "TLS handshakes/s",
    trust_layers: "Layers protected", trust_self: "Self-hosted",
    prob_kicker: "The threats", prob_title: "Your server is attacked every day",
    prob_sub: "Bots, floods and exploits never sleep. Without a dedicated defense layer, a single script kiddie can take your VPS down.",
    prob_1_t: "DDoS L3/L4", prob_1_d: "SYN floods and volumetric attacks saturate your pipe and exhaust sockets before traffic ever reaches the app.",
    prob_2_t: "L7 floods", prob_2_d: "HTTP/2 floods and slow slowloris connections look legitimate, yet they bring the backend to its knees.",
    prob_3_t: "Bots & scrapers", prob_3_d: "Automation siphons your content, prices and data while masquerading as ordinary browsers.",
    prob_4_t: "Credential stuffing", prob_4_d: "Stolen-password replay against login forms quietly takes over user accounts.",
    prob_5_t: "Injections & exploits", prob_5_d: "SQLi, XSS, RCE, Log4Shell, path traversal — one missed request compromises everything.",
    prob_6_t: "Web shells", prob_6_d: "c99, r57, wso, b374k, eval($_POST) — one uploaded backdoor hands an attacker your whole server.",
    sol_kicker: "The solution", sol_title: "One shield for the whole stack",
    sol_p1: "AEGIS sits in front of any web service or VPS and filters traffic top to bottom: from kernel packets to the HTTP request body. Attacks are stopped as early as possible — the cheapest are dropped right in the kernel via XDP, the rest flow through the WAF, TLS fingerprinting and ML risk scoring.",
    sol_p2: "No cloud middleman: traffic never leaves your server, and there's no per-request bill. One binary, install.sh, systemd — and you're protected.",
    sol_li1: "In-kernel filtering before userspace — minimal overhead",
    sol_li2: "Self-learning JA4 reputation and an adaptive challenge ladder",
    sol_li3: "Auto-TLS (ACME / Let's Encrypt), HTTP/1.1, HTTP/2 and HTTP/3 (QUIC)",
    sol_code_c1: "kernel-level filtering", sol_code_c2: "legitimate traffic passes through",
    feat_kicker: "Capabilities", feat_title: "A complete defense arsenal",
    feat_sub: "Every layer works independently and reinforces the rest. Everything's included — nothing to buy on top.",
    how_kicker: "Pipeline", how_title: "A request's path through AEGIS",
    how_sub: "Every request runs a cascade of checks. The cheaper the filter, the earlier it sits.",
    how_s1_t: "Client", how_s1_d: "Incoming traffic",
    how_s2_t: "XDP / eBPF", how_s2_d: "Kernel drop: SYN flood, deny lists",
    how_s3_t: "TLS / JA4", how_s3_d: "JA3/JA4 fingerprints + reputation",
    how_s4_t: "WAF", how_s4_d: "Aho-Corasick signatures + body",
    how_s5_t: "Challenge / ML", how_s5_d: "PoW challenge + risk scoring",
    how_s6_t: "Rate limit", how_s6_d: "IP / subnet /64 / URI · Redis",
    how_s7_t: "Upstream", how_s7_d: "Clean traffic only",
    how_note: "In parallel: ASN/CIDR reputation, GeoIP, honeypot + tarpit, CrowdSec LAPI and BGP RTBH to blackhole /32s upstream on high-confidence attacks.",
    bench_kicker: "Performance", bench_title: "Benchmarks & comparison vs nginx",
    bench_sub: "Honestly: raw nginx is faster at unprotected static serving. AEGIS's value is integrated L7 security with competitive throughput. All figures are hardware-dependent, measured on an 8-core baseline.",
    bench_c1_t: "RPS by mode", bench_c1_s: "raw nginx (no protection) vs AEGIS (full DDoS+WAF protection)",
    bench_c2_t: "TLS handshakes per second", bench_c2_s: "full handshakes; HTTP/2 multiplexing pushes effective throughput much higher",
    bench_c3_t: "p99 latency under load", bench_c3_s: "ms, as request concurrency grows",
    bench_c4_t: "Attack mitigation", bench_c4_s: "nginx out-of-the-box covers few L7 vectors",
    bench_disclaimer: "Figures are representative estimates on an 8-core baseline server and scale with hardware. Your results depend on CPU, NIC, configuration and traffic profile.",
    tier_kicker: "Scaling", tier_title: "VPS, dedicated or cloud",
    tier_sub: "AEGIS uses SO_REUSEPORT and multi-process workers — throughput scales near-linearly with cores.",
    tier_1_tag: "Small VPS", tier_1_core: "2 cores", tier_1_d: "Perfect for solo projects, blogs and small APIs under protection.",
    tier_2_tag: "VPS · popular", tier_2_core: "8 cores", tier_2_d: "The benchmark baseline: SaaS, e-commerce, production workloads.",
    tier_3_tag: "Dedicated", tier_3_core: "32 cores", tier_3_d: "High-load platforms and traffic-aggregation points at the network edge.",
    tier_rps: "RPS",
    tier_chart_t: "RPS scaling by cores", tier_chart_s: "plain-forwarding mode, estimate",
    tier_th_tier: "Tier", tier_th_cores: "Cores", tier_th_rps: "RPS (plain)", tier_th_waf: "RPS + WAF", tier_th_eff: "Efficiency",
    tier_r1: "Small VPS", tier_r2: "VPS 8-core", tier_r3: "Dedicated", tier_r4: "Cloud (auto-scale)",
    tier_eff_high: "High", tier_eff_best: "Best price/RPS", tier_eff_max: "Max throughput", tier_eff_payg: "pay per instance",
    tier_flex: "flexible", tier_elastic: "elastic",
    uc_kicker: "Who it's for", uc_title: "One product, two worlds",
    uc_b_t: "Business", uc_b_sub: "SaaS and e-commerce where downtime costs money and data is regulated.",
    uc_b_1: "Uptime and compliance — traffic never leaves your perimeter",
    uc_b_2: "SIEM and CrowdSec LAPI integrations, threat-intel feeds",
    uc_b_3: "Bot and DDoS analytics over any period from the SQLite log",
    uc_b_4: "Admin panel: dashboards, per-domain config, zero-downtime restart",
    uc_v_t: "Your own VPS", uc_v_sub: "Indie developers who want serious protection without cloud bills.",
    uc_v_1: "One-command install — a single binary and install.sh",
    uc_v_2: "Free and open-source — no per-request limits",
    uc_v_3: "Full control: your rules, your data, your hardware",
    uc_v_4: "No per-request fees and no cloud middleman in your traffic",
    cmp_kicker: "Comparison", cmp_title: "AEGIS vs the alternatives",
    cmp_th_feat: "Capability", cmp_th_nginx: "nginx + ModSecurity", cmp_th_cf: "Cloudflare / cloud WAF",
    why_kicker: "Privacy", why_title: "Why self-host",
    why_p: "With a cloud WAF, all your traffic flows through someone else's infrastructure and the bill grows with every request. AEGIS runs on your own hardware: user data never leaves your server, there's no per-request billing and no vendor lock-in. You see every engine decision and own every log.",
    why_s1: "per request", why_s2: "data leaves your server", why_s3: "control over rules", why_s4: "requests, no surcharge",
    price_kicker: "Install", price_title: "Deploy in five minutes",
    price_sub: "Open-source and free for self-hosting. Optional support — for teams that need an SLA.",
    price_install: "one-step install", price_copy: "Copy",
    price_popular: "Recommended",
    price_oss_t: "Self-host (Open Source)", price_free: "Free",
    price_oss_d: "Full feature set. Forever. Your hardware, your rules.",
    price_oss_1: "All WAF, XDP, ML and challenge capabilities",
    price_oss_2: "Unlimited domains and requests",
    price_oss_3: "Community support and updates",
    price_oss_cta: "Download on GitHub",
    price_mgd_t: "Managed / Support", price_custom: "Custom",
    price_mgd_d: "For teams that need SLAs, priority help and hands-on support.",
    price_mgd_1: "Priority support with an SLA",
    price_mgd_2: "Help with rule tuning and configuration",
    price_mgd_3: "Custom integrations and team training",
    price_mgd_cta: "Contact us",
    faq_kicker: "FAQ", faq_title: "Frequently asked questions",
    foot_tag: "Self-hosted DDoS & WAF reverse proxy in Rust.",
    foot_product: "Product", foot_res: "Resources", foot_docs: "Documentation",
    foot_start: "Get started", foot_cta_d: "Deploy protection right now.",
    foot_rights: "Open-source. All rights reserved.", foot_built: "Built in Rust · Pingora + Hyper",
    toast_copied: "Copied to clipboard",
  },
};

/* ---------- feature cards data ---------- */
const FEATURES = [
  { ic: "shield", ru: ["WAF-движок", "Aho-Corasick сигнатуры с нормализацией запросов и инспекцией тела (gzip/deflate): SQLi, XSS, RCE, SSRF, XXE, path traversal."],
    en: ["WAF engine", "Aho-Corasick signatures with request normalization and body inspection (gzip/deflate): SQLi, XSS, RCE, SSRF, XXE, path traversal."] },
  { ic: "bug", ru: ["Детект веб-шеллов", "PHP-бэкдоры: eval($_POST), c99/r57/wso/b374k, цепочки packer-обфускации — ловятся до загрузки."],
    en: ["Web-shell detection", "PHP backdoors: eval($_POST), c99/r57/wso/b374k, packer-obfuscation chains — caught before they land."] },
  { ic: "rules", ru: ["Sigma-корпус", "Импортёр 562-правил Sigma плюс compound-правила для сложных многошаговых сигнатур атак."],
    en: ["Sigma corpus", "Importer for a 562-rule Sigma corpus plus compound rules for complex multi-step attack signatures."] },
  { ic: "finger", ru: ["TLS-фингерпринтинг", "JA3 / JA4 / JA4H / JA4T + детект JA4-churn для TLS-ротирующих библиотек (utls, curl-impersonate)."],
    en: ["TLS fingerprinting", "JA3 / JA4 / JA4H / JA4T + JA4-churn detection for TLS-rotating libraries (utls, curl-impersonate)."] },
  { ic: "brain", ru: ["Самообучаемая репутация JA4", "Автоматически выучивает вредоносные отпечатки из попаданий в honeypot, WAF и tarpit."],
    en: ["Self-learning JA4 reputation", "Automatically learns malicious fingerprints from honeypot, WAF and tarpit hits."] },
  { ic: "chip", ru: ["XDP / eBPF в ядре", "Дроп атакующих пакетов прямо в ядре до userspace: SYN-флуд, IP-deny, rate. Multi-process SO_REUSEPORT."],
    en: ["XDP / eBPF kernel path", "Drops attack packets in-kernel before userspace: SYN flood, IP deny, rate. Multi-process SO_REUSEPORT."] },
  { ic: "ladder", ru: ["Адаптивный challenge", "Эскалирующая лестница JS / proof-of-work для подозрительных клиентов. Поддержка Privacy Pass (Ed25519)."],
    en: ["Adaptive challenge ladder", "Escalating JS / proof-of-work challenges for suspicious clients. Privacy Pass (Ed25519) token support."] },
  { ic: "risk", ru: ["ML-движок риска", "Сводит сигналы WAF, JA4, rate, репутации, honeypot и GeoIP в один риск-скор. Logistic + GBM, adversarial self-training."],
    en: ["ML risk engine", "Fuses WAF, JA4, rate, reputation, honeypot and GeoIP signals into one risk score. Logistic + GBM, adversarial self-training."] },
  { ic: "gauge", ru: ["Rate limiting", "Лимиты per-IP / per-subnet (IPv6 /64) / per-URI, распределённо через Redis для нескольких узлов."],
    en: ["Rate limiting", "Per-IP / per-subnet (IPv6 /64) / per-URI limits, distributed via Redis across nodes."] },
  { ic: "trap", ru: ["Honeypot + tarpit", "Ловушки, медленно «капающие» сканерам, плюс LLM-honeypot респондеры для дезинформации ботов."],
    en: ["Honeypot + tarpit", "Traps that slow-drip scanners, plus LLM-honeypot responders to mislead bots."] },
  { ic: "globe", ru: ["Репутационные фиды", "ASN/CIDR (Tor exit + Spamhaus DROP, ежедневно), GeoIP по странам, CrowdSec LAPI, threat-intel."],
    en: ["Reputation feeds", "ASN/CIDR (Tor exit + Spamhaus DROP, daily), GeoIP by country, CrowdSec LAPI, threat-intel."] },
  { ic: "route", ru: ["BGP RTBH", "Анонсирует /32 blackhole апстриму при атаках высокой уверенности — отсекает трафик до вашего канала."],
    en: ["BGP RTBH", "Announces /32 blackholes upstream on high-confidence attacks — cuts traffic before your pipe."] },
  { ic: "db", ru: ["Persistent request-лог", "SQLite-история запросов по доменам и эндпоинтам с time-range запросами и статистикой ботов/DDoS."],
    en: ["Persistent request log", "SQLite-backed per-domain/endpoint request history with time-range queries and bot/DDoS stats."] },
  { ic: "panel", ru: ["Админ-панель", "Real-time дашборды, конфиг по доменам, тумблеры, rolling-restart почти без даунтайма, бенчмарк железа."],
    en: ["Admin panel", "Real-time dashboards, per-domain config, toggles, near-zero-downtime rolling restart, hardware benchmark."] },
  { ic: "box", ru: ["Простой деплой", "Единый бинарник, install.sh, systemd, multi-worker, авто-TLS (ACME), HTTP/1.1 + HTTP/2 + HTTP/3 (QUIC)."],
    en: ["Simple deployment", "Single binary, install.sh, systemd, multi-worker, auto-TLS (ACME), HTTP/1.1 + HTTP/2 + HTTP/3 (QUIC)."] },
];

const ICONS = {
  shield: '<path d="M12 2 4 5v6c0 5 3.4 8.6 8 11 4.6-2.4 8-6 8-11V5l-8-3Z"/>',
  bug: '<path d="M8 6V4a4 4 0 0 1 8 0v2M5 10h14M6 10v5a6 6 0 0 0 12 0v-5M3 13h3m12 0h3M4 19l3-2m13 2-3-2"/>',
  rules: '<path d="M9 5h11M9 12h11M9 19h11M4 5h.01M4 12h.01M4 19h.01"/>',
  finger: '<path d="M12 11v3m0-9a7 7 0 0 1 7 7M5 12a7 7 0 0 1 7-7M8 14a4 4 0 0 1 8 0v3"/>',
  brain: '<path d="M9 3a3 3 0 0 0-3 3 3 3 0 0 0-1 5.8A3 3 0 0 0 9 21a3 3 0 0 0 3-1.5M15 3a3 3 0 0 1 3 3 3 3 0 0 1 1 5.8A3 3 0 0 1 15 21a3 3 0 0 1-3-1.5V4.5"/>',
  chip: '<rect x="6" y="6" width="12" height="12" rx="1"/><path d="M9 1v3m6-3v3M9 20v3m6-3v3M1 9h3m-3 6h3m16-6h3m-3 6h3"/>',
  ladder: '<path d="M8 21V3m8 18V3M8 8h8M8 13h8M8 18h8"/>',
  risk: '<path d="M12 9v4m0 4h.01M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z"/>',
  gauge: '<path d="M12 14a2 2 0 1 0 0-4 2 2 0 0 0 0 4Zm0 0 4-4M3 12a9 9 0 0 1 18 0"/>',
  trap: '<path d="m3 11 18-5v12L3 14v-3Zm0 0v6m9-7v9"/>',
  globe: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/>',
  route: '<circle cx="6" cy="6" r="3"/><circle cx="18" cy="18" r="3"/><path d="M6 9v6a3 3 0 0 0 3 3h6"/>',
  db: '<ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v6c0 1.7 3.6 3 8 3s8-1.3 8-3V5M4 11v6c0 1.7 3.6 3 8 3s8-1.3 8-3v-6"/>',
  panel: '<rect x="3" y="3" width="18" height="18" rx="2"/><path d="M3 9h18M9 21V9"/>',
  box: '<path d="m21 8-9-5-9 5 9 5 9-5Zm0 0v8l-9 5-9-5V8"/>',
};

/* ---------- comparison rows ---------- */
const COMPARE = [
  { ru: "L7 WAF (SQLi/XSS/RCE)", en: "L7 WAF (SQLi/XSS/RCE)", a: 2, n: 1, c: 2, nn: { ru: "только с ModSecurity", en: "only with ModSecurity" } },
  { ru: "JA3 / JA4 фингерпринтинг", en: "JA3 / JA4 fingerprinting", a: 2, n: 0, c: 2 },
  { ru: "XDP/eBPF дроп в ядре", en: "XDP/eBPF kernel-level drop", a: 2, n: 0, c: 1, cc: { ru: "на их edge", en: "on their edge" } },
  { ru: "ML-движок риска", en: "ML risk engine", a: 2, n: 0, c: 2 },
  { ru: "Детект веб-шеллов", en: "Web-shell detection", a: 2, n: 1, c: 1 },
  { ru: "Self-host / данные не уходят", en: "Self-host / data stays on your server", a: 2, n: 2, c: 0 },
  { ru: "BGP RTBH блэкхол", en: "BGP RTBH blackhole", a: 2, n: 0, c: 2 },
  { ru: "Модель цены", en: "Pricing model", a: { ru: "бесплатно", en: "free" }, n: { ru: "бесплатно", en: "free" }, c: { ru: "подписка", en: "subscription" } },
  { ru: "Стоимость за запрос", en: "Per-request cost", a: { ru: "нет", en: "none" }, n: { ru: "нет", en: "none" }, c: { ru: "часто да", en: "often yes" } },
];

/* ---------- FAQ ---------- */
const FAQ = [
  { ru: ["Что такое AEGIS?", "Это самостоятельно размещаемый DDoS / WAF реверс-прокси на Rust (Pingora + Hyper). Он ставится перед любым веб-сервисом или VPS и поглощает атаки на уровнях L3-L7."],
    en: ["What is AEGIS?", "It's a self-hostable DDoS / WAF reverse proxy written in Rust (Pingora + Hyper). It sits in front of any web service or VPS and absorbs L3-L7 attacks."] },
  { ru: ["Это правда быстрее nginx?", "Честно — нет, на «голой» статике без защиты nginx быстрее. Ценность AEGIS в том, что с полной защитой WAF + challenge он держит десятки тысяч RPS. Цифры зависят от железа (база — 8 ядер)."],
    en: ["Is it really faster than nginx?", "Honestly, no — for unprotected static serving nginx is faster. AEGIS's value is sustaining tens of thousands of RPS with full WAF + challenge protection on. Figures are hardware-dependent (8-core baseline)."] },
  { ru: ["Как устанавливается?", "Одной командой: curl -fsSL https://get.aegis.sh | sudo bash. Единый бинарник, install.sh, systemd, авто-TLS через ACME / Let's Encrypt."],
    en: ["How is it installed?", "With one command: curl -fsSL https://get.aegis.sh | sudo bash. A single binary, install.sh, systemd, and auto-TLS via ACME / Let's Encrypt."] },
  { ru: ["Мои данные куда-то уходят?", "Нет. AEGIS работает на вашем железе, трафик никогда не покидает ваш сервер. Нет облачного посредника и нет оплаты за каждый запрос."],
    en: ["Does my data go anywhere?", "No. AEGIS runs on your own hardware and traffic never leaves your server. There's no cloud middleman and no per-request billing."] },
  { ru: ["Поддерживает ли HTTP/3?", "Да — HTTP/1.1, HTTP/2 и HTTP/3 (QUIC). HTTP/2-мультиплексирование заметно повышает реальную пропускную способность."],
    en: ["Does it support HTTP/3?", "Yes — HTTP/1.1, HTTP/2 and HTTP/3 (QUIC). HTTP/2 multiplexing significantly raises effective throughput."] },
  { ru: ["Как обновляются правила и фиды?", "Sigma-корпус из 562 правил импортируется, репутационные фиды ASN/CIDR (Tor exit + Spamhaus DROP) обновляются ежедневно, плюс интеграция с CrowdSec LAPI."],
    en: ["How are rules and feeds updated?", "A 562-rule Sigma corpus is imported, ASN/CIDR reputation feeds (Tor exit + Spamhaus DROP) refresh daily, plus CrowdSec LAPI integration."] },
  { ru: ["Будет ли даунтайм при перезапуске?", "Почти нет: rolling-restart перезапускает воркеры поочерёдно прямо из админ-панели, без ручного systemctl и без обрыва сиблингов."],
    en: ["Is there downtime on restart?", "Almost none: a rolling restart cycles workers one by one straight from the admin panel — no manual systemctl and no cascading sibling stops."] },
  { ru: ["Сколько это стоит?", "Self-host версия бесплатна и open-source, со всеми возможностями и без лимитов. Опционально доступна managed-поддержка с SLA для команд."],
    en: ["How much does it cost?", "The self-host edition is free and open-source, with every feature and no limits. Managed support with an SLA is optionally available for teams."] },
];

/* ============================================================
   Rendering
   ============================================================ */
let currentLang = localStorage.getItem('aegis_lang') || 'ru';
let charts = {};

function svgIcon(name) {
  return `<svg class="h-6 w-6" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24">${ICONS[name] || ICONS.shield}</svg>`;
}

function renderFeatures() {
  const grid = document.getElementById('featGrid');
  grid.innerHTML = FEATURES.map((f) => {
    const [title, desc] = f[currentLang];
    return `<div class="reveal in grad-border glass rounded-2xl p-6">
      <div class="mb-4 flex h-11 w-11 items-center justify-center rounded-xl bg-brand-500/10 text-brand-400">${svgIcon(f.ic)}</div>
      <h3 class="text-lg font-bold text-white">${title}</h3>
      <p class="mt-2 text-sm leading-relaxed text-slate-400">${desc}</p>
    </div>`;
  }).join('');
}

function mark(v) {
  // v: 2 = yes, 1 = partial, 0 = no
  if (v === 2) return '<span class="inline-flex h-7 w-7 items-center justify-center rounded-full bg-brand-500/15 text-brand-400"><svg class="h-4 w-4" fill="none" stroke="currentColor" stroke-width="3" viewBox="0 0 24 24"><path d="m5 13 4 4L19 7"/></svg></span>';
  if (v === 1) return '<span class="inline-flex h-7 w-7 items-center justify-center rounded-full bg-amber-500/15 text-amber-400"><svg class="h-4 w-4" fill="none" stroke="currentColor" stroke-width="3" viewBox="0 0 24 24"><path d="M5 12h14"/></svg></span>';
  return '<span class="inline-flex h-7 w-7 items-center justify-center rounded-full bg-red-500/10 text-red-400/80"><svg class="h-4 w-4" fill="none" stroke="currentColor" stroke-width="3" viewBox="0 0 24 24"><path d="M6 6l12 12M18 6 6 18"/></svg></span>';
}

function cell(val, note) {
  if (typeof val === 'object' && val !== null && (val.ru || val.en)) {
    return `<span class="text-sm font-medium text-slate-300">${val[currentLang]}</span>`;
  }
  const m = mark(val);
  const n = note ? `<div class="mt-1 text-[11px] text-slate-500">${note[currentLang]}</div>` : '';
  return `<div class="flex flex-col items-center">${m}${n}</div>`;
}

function renderCompare() {
  const body = document.getElementById('cmpBody');
  body.innerHTML = COMPARE.map((r) => `
    <tr class="transition hover:bg-white/[0.03]">
      <td class="px-5 py-4 font-medium text-white">${r[currentLang]}</td>
      <td class="px-5 py-4 text-center">${cell(r.a, r.aa)}</td>
      <td class="px-5 py-4 text-center">${cell(r.n, r.nn)}</td>
      <td class="px-5 py-4 text-center">${cell(r.c, r.cc)}</td>
    </tr>`).join('');
}

function renderFaq() {
  const list = document.getElementById('faqList');
  list.innerHTML = FAQ.map((f) => {
    const [q, a] = f[currentLang];
    return `<details class="grad-border glass rounded-xl px-5 py-4">
      <summary class="flex items-center justify-between gap-4">
        <span class="text-base font-semibold text-white">${q}</span>
        <svg class="faq-chevron h-5 w-5 flex-none text-brand-400" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="m6 9 6 6 6-6"/></svg>
      </summary>
      <p class="mt-3 text-sm leading-relaxed text-slate-400">${a}</p>
    </details>`;
  }).join('');
}

/* ---------- apply i18n to [data-i18n] ---------- */
function applyI18n() {
  const dict = I18N[currentLang];
  document.querySelectorAll('[data-i18n]').forEach((el) => {
    const key = el.getAttribute('data-i18n');
    if (dict[key] !== undefined) el.innerHTML = dict[key];
  });
  document.documentElement.lang = currentLang;
  document.getElementById('langLabel').textContent = currentLang === 'ru' ? 'EN' : 'RU';
  renderFeatures();
  renderCompare();
  renderFaq();
}

/* ============================================================
   Charts
   ============================================================ */
const GRID = 'rgba(148,163,184,0.12)';
const TICK = 'rgba(148,163,184,0.8)';
const TEAL = '#2dd4bf';
const CYAN = '#22d3ee';
const SLATE = '#64748b';

function chartLabels() {
  return currentLang === 'ru'
    ? { plain: 'Plain', tls: 'TLS', waf: 'WAF + rate', aegis: 'AEGIS (полная защита)', nginx: 'nginx (без защиты)',
        ms: 'мс', conc: 'Конкурентность', dims: ['SYN-флуд', 'HTTP-флуд', 'Slowloris', 'Боты', 'Веб-шеллы'],
        rps: 'RPS' }
    : { plain: 'Plain', tls: 'TLS', waf: 'WAF + rate', aegis: 'AEGIS (full protection)', nginx: 'nginx (no protection)',
        ms: 'ms', conc: 'Concurrency', dims: ['SYN flood', 'HTTP flood', 'Slowloris', 'Bots', 'Web shells'],
        rps: 'RPS' };
}

function baseOpts(extra = {}) {
  return Object.assign({
    responsive: true, maintainAspectRatio: false,
    plugins: {
      legend: { labels: { color: TICK, font: { family: 'Inter', size: 12 }, usePointStyle: true, padding: 16 } },
      tooltip: { backgroundColor: '#0a0e14', borderColor: 'rgba(45,212,191,0.3)', borderWidth: 1, titleColor: '#fff', bodyColor: '#cbd5e1', padding: 10 },
    },
    scales: {
      x: { grid: { color: GRID }, ticks: { color: TICK, font: { family: 'Inter' } } },
      y: { grid: { color: GRID }, ticks: { color: TICK, font: { family: 'Inter' } }, beginAtZero: true },
    },
  }, extra);
}

function destroyCharts() {
  Object.values(charts).forEach((c) => c && c.destroy());
  charts = {};
}

function renderCharts() {
  if (typeof Chart === 'undefined') return;
  destroyCharts();
  const L = chartLabels();

  // (a) RPS by mode — grouped bars
  charts.rps = new Chart(document.getElementById('chartRps'), {
    type: 'bar',
    data: {
      labels: [L.plain, L.tls, L.waf],
      datasets: [
        { label: L.nginx, data: [150, 52, 18], backgroundColor: SLATE, borderRadius: 6, maxBarThickness: 46 },
        { label: L.aegis, data: [120, 45, 28], backgroundColor: TEAL, borderRadius: 6, maxBarThickness: 46 },
      ],
    },
    options: baseOpts({ scales: { x: { grid: { color: GRID }, ticks: { color: TICK } }, y: { grid: { color: GRID }, ticks: { color: TICK, callback: (v) => v + 'K' }, beginAtZero: true } } }),
  });

  // (b) TLS handshakes/s
  charts.tls = new Chart(document.getElementById('chartTls'), {
    type: 'bar',
    data: {
      labels: ['nginx', 'AEGIS'],
      datasets: [{ label: L.rps, data: [11.5, 8.8], backgroundColor: [SLATE, TEAL], borderRadius: 8, maxBarThickness: 90 }],
    },
    options: baseOpts({
      plugins: { legend: { display: false }, tooltip: { callbacks: { label: (c) => c.parsed.y + 'K/s' } } },
      scales: { x: { grid: { display: false }, ticks: { color: TICK } }, y: { grid: { color: GRID }, ticks: { color: TICK, callback: (v) => v + 'K' }, beginAtZero: true } },
    }),
  });

  // (c) latency p99 line
  charts.lat = new Chart(document.getElementById('chartLat'), {
    type: 'line',
    data: {
      labels: ['100', '500', '1K', '5K', '10K', '25K'],
      datasets: [
        { label: L.nginx, data: [0.4, 0.7, 1.1, 2.6, 5.2, 14], borderColor: SLATE, backgroundColor: 'rgba(100,116,139,0.1)', tension: 0.35, fill: true, pointRadius: 3 },
        { label: L.aegis, data: [0.6, 0.9, 1.4, 3.1, 6.0, 16], borderColor: TEAL, backgroundColor: 'rgba(45,212,191,0.12)', tension: 0.35, fill: true, pointRadius: 3 },
      ],
    },
    options: baseOpts({
      scales: {
        x: { grid: { color: GRID }, ticks: { color: TICK }, title: { display: true, text: L.conc, color: SLATE } },
        y: { grid: { color: GRID }, ticks: { color: TICK, callback: (v) => v + ' ' + L.ms }, beginAtZero: true },
      },
    }),
  });

  // (d) attack-mitigation radar
  charts.radar = new Chart(document.getElementById('chartRadar'), {
    type: 'radar',
    data: {
      labels: L.dims,
      datasets: [
        { label: L.nginx, data: [2, 2, 3, 1, 1], borderColor: SLATE, backgroundColor: 'rgba(100,116,139,0.18)', pointBackgroundColor: SLATE },
        { label: L.aegis, data: [10, 9, 9, 9, 10], borderColor: TEAL, backgroundColor: 'rgba(45,212,191,0.22)', pointBackgroundColor: TEAL },
      ],
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { labels: { color: TICK, usePointStyle: true, padding: 16 } } },
      scales: {
        r: {
          min: 0, max: 10,
          angleLines: { color: GRID }, grid: { color: GRID },
          pointLabels: { color: TICK, font: { family: 'Inter', size: 11 } },
          ticks: { display: false, stepSize: 2 },
        },
      },
    },
  });

  // scaling by cores
  charts.scale = new Chart(document.getElementById('chartScale'), {
    type: 'bar',
    data: {
      labels: ['2', '4', '8', '16', '32'],
      datasets: [{ label: L.rps, data: [30, 62, 120, 235, 450], backgroundColor: ['#0d9488', '#0d9488', TEAL, '#22d3ee', CYAN], borderRadius: 6, maxBarThickness: 60 }],
    },
    options: baseOpts({
      plugins: { legend: { display: false }, tooltip: { callbacks: { label: (c) => '~' + c.parsed.y + 'K ' + L.rps } } },
      scales: {
        x: { grid: { display: false }, ticks: { color: TICK }, title: { display: true, text: currentLang === 'ru' ? 'Ядра CPU' : 'CPU cores', color: SLATE } },
        y: { grid: { color: GRID }, ticks: { color: TICK, callback: (v) => v + 'K' }, beginAtZero: true },
      },
    }),
  });
}

/* ============================================================
   Counters (count-up)
   ============================================================ */
function animateCounter(el) {
  const target = parseFloat(el.getAttribute('data-target'));
  const decimals = parseInt(el.getAttribute('data-decimals') || '0', 10);
  const dur = 1400;
  const start = performance.now();
  function tick(now) {
    const p = Math.min((now - start) / dur, 1);
    const eased = 1 - Math.pow(1 - p, 3);
    const val = target * eased;
    el.textContent = decimals ? val.toFixed(decimals) : Math.round(val).toString();
    if (p < 1) requestAnimationFrame(tick);
    else el.textContent = decimals ? target.toFixed(decimals) : Math.round(target).toString();
  }
  requestAnimationFrame(tick);
}

/* ============================================================
   Scroll reveal + counters via IntersectionObserver
   ============================================================ */
function initObservers() {
  const revObs = new IntersectionObserver((entries) => {
    entries.forEach((e) => { if (e.isIntersecting) { e.target.classList.add('in'); revObs.unobserve(e.target); } });
  }, { threshold: 0.12 });
  document.querySelectorAll('.reveal').forEach((el) => revObs.observe(el));

  const cntObs = new IntersectionObserver((entries) => {
    entries.forEach((e) => { if (e.isIntersecting) { animateCounter(e.target); cntObs.unobserve(e.target); } });
  }, { threshold: 0.5 });
  document.querySelectorAll('.counter').forEach((el) => cntObs.observe(el));
}

/* ============================================================
   Misc interactions
   ============================================================ */
function showToast(msg) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.classList.remove('translate-y-20', 'opacity-0');
  setTimeout(() => t.classList.add('translate-y-20', 'opacity-0'), 2000);
}

function initNav() {
  const nav = document.getElementById('nav');
  const onScroll = () => {
    if (window.scrollY > 20) nav.querySelector('.glass').classList.add('shadow-2xl', 'shadow-black/40');
    else nav.querySelector('.glass').classList.remove('shadow-2xl', 'shadow-black/40');
  };
  window.addEventListener('scroll', onScroll, { passive: true });
  onScroll();
}

function initCopy() {
  const btn = document.getElementById('copyBtn');
  const cmd = document.getElementById('installCmd');
  if (!btn) return;
  btn.addEventListener('click', async () => {
    const text = cmd.textContent.trim();
    try {
      await navigator.clipboard.writeText(text);
    } catch (e) {
      const ta = document.createElement('textarea');
      ta.value = text; document.body.appendChild(ta); ta.select();
      try { document.execCommand('copy'); } catch (_) {}
      document.body.removeChild(ta);
    }
    showToast(I18N[currentLang].toast_copied);
  });
}

function initLangToggle() {
  document.getElementById('langToggle').addEventListener('click', () => {
    currentLang = currentLang === 'ru' ? 'en' : 'ru';
    localStorage.setItem('aegis_lang', currentLang);
    applyI18n();
    renderCharts();
  });
}

/* ============================================================
   Init
   ============================================================ */
document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('year').textContent = new Date().getFullYear();
  applyI18n();
  renderCharts();
  initObservers();
  initNav();
  initCopy();
  initLangToggle();
});
