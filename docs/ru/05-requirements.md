# Системные требования и совместимость

Документ описывает поддерживаемые операционные системы, процессорные архитектуры, требования ядра для XDP/eBPF, а также реалистичные ожидания по CPU/памяти и режим деградации (что именно перестаёт работать без XDP, без аппаратного SHA, без ASN-базы, без Redis). Все утверждения сверены с реальным кодом: [install.sh](../../install.sh), [Cargo.toml](../../Cargo.toml), [src/xdp.rs](../../src/xdp.rs).

> AEGIS собирается из исходников **на самой целевой машине** (`install.sh` клонирует репозиторий, ставит Rust/Node, компилирует release-бинарь и стартует systemd-юнит). Это означает, что «системные требования» — это одновременно требования к сборке и к runtime. Готовые бинарные пакеты не поставляются.

---

## 1. Поддерживаемые операционные системы

AEGIS — **Linux-only продукт в production**. На macOS/Windows код компилируется (XDP-слой превращается в no-op, см. §5), но это только dev-сценарий: production data plane и все защитные слои рассчитаны на Linux.

Установщик [install.sh](../../install.sh) определяет ОС из `/etc/os-release` (функция `detect_os`, строки 105–129) и выбирает пакетный менеджер:

| Семейство ОС | `ID` из os-release | Пакетный менеджер | Статус |
|---|---|---|---|
| Debian / Ubuntu | `debian`, `ubuntu` | `apt` | Основная цель (основной стенд — Debian 12) |
| RHEL-семейство | `fedora`, `rhel`, `centos`, `rocky`, `almalinux` | `dnf` | Поддерживается |
| Alpine | `alpine` | `apk` | Поддерживается |
| Любая другая | `unknown` | `unknown` | ⚠️ `warn "untested OS … proceeding optimistically"` — установка не падает, но пакеты придётся ставить вручную |

**Важные нюансы по дистрибутивам (из реального кода установщика):**

- **Debian 12** — это эталонная цель. Все вспомогательные бенчмарк-прокси (`nginx`, `HAProxy 2.6`, `Caddy 2.6`, `nginx+ModSecurity v3+CRS`, `Envoy 1.38.1`) ставятся через `apt` именно с расчётом на Debian 12 (см. `ensure_benchmark_proxies`, строки 610–761). На RHEL/Alpine часть этих опциональных бенчмарк-таргетов может оказаться недоступной — это влияет ТОЛЬКО на страницу сравнительного бенчмарка, не на саму защиту.
- **Alpine (musl)** — устанавливается через `apk` (`build-base pkgconfig openssl-dev …`). Учтите, что Alpine использует musl libc; сборка тяжёлого дерева зависимостей (pingora + openssl) на musl возможна, но компилируется дольше и менее протестирована, чем на glibc-системах.
- **RHEL/Alpine + ModSecurity** — установщик честно помечает, что коннектор ModSecurity на RHEL «not always packaged» (строка 688), а ABI-smoke-тест (`nginx -t`) может выдать `WARN … 'unavailable'`. Это не ошибка установки AEGIS.
- **Неизвестная ОС** — установщик продолжит, но пропустит установку пакетов и выведет требуемый список вручную: `gcc, cmake, git, pkg-config, openssl-dev, ca-certificates, clang, llvm` (строка 267).

Установка идемпотентна: повторный запуск обновляет до текущего tip ветки и не трогает `/etc/aegis`. Подробности процесса — в [03-installation.md](./03-installation.md). Авторитетный источник по переменным окружения и флагам — шапка [install.sh](../../install.sh) (строки 13–57).

---

## 2. Процессорные архитектуры

Установщик нормализует `uname -m` (строки 122–126):

| `uname -m` | Внутреннее имя `ARCH` | Поддержка |
|---|---|---|
| `x86_64`, `amd64` | `amd64` | ✅ полная |
| `aarch64`, `arm64` | `arm64` | ✅ полная |
| любое другое | — | 🔴 `fatal "unsupported architecture"` — установка прерывается |

То есть поддерживаются **ровно две архитектуры: amd64 и arm64**. Всё остальное (32-бит ARM, RISC-V, ppc64le и т. д.) явно не поддерживается и установщик завершится с ошибкой.

### 2.1. CPU-специфичная оптимизация при сборке

Поскольку бинарь компилируется на целевой машине, по умолчанию используется `AEGIS_TARGET_CPU=native` (строки 406–435). Это включает все инструкции конкретного CPU без риска `SIGILL`, потому что бинарь больше нигде не запускается:

- на современном **x86** — AVX2/BMI;
- на современном **ARM** (Graviton2+, Ampere, Apple, Neoverse) — LSE-атомики в одну инструкцию.

Опции тюнинга:

| Значение `AEGIS_TARGET_CPU` | Назначение |
|---|---|
| `native` (по умолчанию) | оптимально для ЭТОЙ машины |
| `generic` | портативный бинарь для модели build-once-deploy-many |
| `neoverse-n1`, `x86-64-v3`, … | пин конкретной микроархитектуры |

⚠️ Если вы собираете на одной машине, а запускаете на другой (build-once-deploy-many), обязательно используйте `AEGIS_TARGET_CPU=generic` или конкретную микроархитектуру — иначе на более старом CPU возможен `SIGILL`.

SIMD используется и в горячем пути WAF: `memchr` даёт NEON на aarch64 и AVX2 на x86_64 для побайтового поиска ([Cargo.toml](../../Cargo.toml), строки 107–110).

---

## 3. Требования к ядру Linux для XDP/eBPF

XDP — это **опциональный** kernel fast-path. Он включается фичей `xdp` при сборке и по умолчанию (`AEGIS_ENABLE_XDP=auto`) автоматически активируется, если ядро это позволяет. Без него AEGIS полностью работоспособен (см. §5 о деградации).

### 3.1. Версия ядра

Логика в `resolve_xdp_enable` ([install.sh](../../install.sh), строки 131–154):

- В режиме `--mode hyper` XDP **всегда отключается** — fast-path подключён только к pingora-data-plane (строки 137–141).
- При `AEGIS_ENABLE_XDP=auto` XDP включается, если ядро **≥ 4.18** (минимум, с которого aya поддерживает XDP). Иначе — `warn "linux … < 4.18 — XDP disabled (need ≥ 4.18 for aya)"`.

> ⚠️ Расхождение в документации vs код: комментарий к фиче в [Cargo.toml](../../Cargo.toml) (строка 18) версию ядра не называет вовсе — там сказано лишь «Requires CAP_BPF + CAP_NET_ADMIN at runtime and a precompiled BPF object», а установщик гейтит по 4.18+. На практике 4.18 — это **минимально достаточный** порог для самого attach через aya, но ряд продвинутых eBPF-возможностей появился позже. Брифинг проекта называет целевой средой **ядро 6.x** — именно на нём проверены capability-требования ниже. Для production рекомендуется ядро 6.x.

### 3.2. Capabilities (привилегии) для загрузки eBPF

Это самый тонкий момент. Установщик прописывает в systemd-юнит pingora-воркера (`write_systemd_unit_pingora`, строки 1221–1232) расширенный набор capabilities, когда XDP включён:

```
CAP_NET_BIND_SERVICE CAP_NET_ADMIN CAP_SYS_RESOURCE CAP_BPF CAP_PERFMON
```

и расширяет `RestrictAddressFamilies` до `AF_INET AF_INET6 AF_UNIX AF_NETLINK`.

Назначение каждой capability (прямые комментарии из кода, строки 1223–1231):

| Capability | Зачем нужна |
|---|---|
| `CAP_BPF` | загрузка/верификация eBPF-программы (`BPF_PROG_LOAD`) |
| `CAP_PERFMON` | 🔴 **критично на ядре 6.x**: верификатор гейтит операции с указателями/`packet-data` за `perfmon_capable()`. Без `CAP_PERFMON` загрузка падает с `EACCES` (os error 13), **даже если `CAP_BPF` присутствует** |
| `CAP_NET_ADMIN` | attach программы к NIC |
| `CAP_SYS_RESOURCE` | поднятие rlimit (для BPF-карт и locked-памяти) |
| `AF_NETLINK` (address family) | сам attach XDP идёт через rtnetlink |
| `CAP_NET_BIND_SERVICE` | bind на привилегированные порты :80/:443 без root |

Без XDP набор capability сужается до одного `CAP_NET_BIND_SERVICE` (строка 1221).

### 3.3. Locked-память (MEMLOCK)

В XDP-юните задаётся `LimitMEMLOCK=infinity` (строки 1262–1266), потому что BPF-карты и locked ring-буферы должны расти за пределы дефолтного rlimit в 64 КиБ. Без этого карты не выделятся.

### 3.4. Сборочные требования для eBPF-объекта

eBPF-объект собирается отдельно (`build_xdp_object`, строки 469–484) и требует особого тулчейна (`install_rust`, строки 296–318):

- **Rust nightly** + компонент `rust-src` (для `-Z build-std=core`);
- **`bpf-linker`** (`cargo install bpf-linker`, умеет эмитить BPF ELF, который принимает верификатор ядра);
- цель сборки — `bpfel-unknown-none` (отдельный workspace `xdp/aegis-xdp-ebpf` с собственным `.cargo/config.toml`, см. [Cargo.toml](../../Cargo.toml), строки 1–9);
- LLVM/clang — ставятся в `install_packages` (строки 254, 259, 264).

eBPF-крейт **намеренно исключён из основного workspace** ([Cargo.toml](../../Cargo.toml), строка 8), так что обычная сборка `aegis-pingora` его не трогает. Готовый объект кладётся в `/var/lib/aegis/aegis-xdp.o` (`AEGIS_XDP_OBJ`).

Если `bpf-linker` не установился, установщик предупреждает: «eBPF build will fail; retry with `--no-xdp`» (строка 314). То есть **можно полностью отказаться от nightly-тулчейна** флагом `--no-xdp` (или `AEGIS_ENABLE_XDP=0`) — тогда AEGIS собирается только на stable Rust.

### 3.5. Native (DRV) vs SKB (generic) режим attach

В runtime XDP-загрузчик ([src/xdp.rs](../../src/xdp.rs), строки 218–252) сначала пытается **native DRV-режим** (line-rate, требует поддержки XDP драйвером NIC), и при неудаче откатывается на **SKB (generic) mode**:

> «SKB mode is slower (packets are reinjected after sk_buff allocation) but works on every Linux NIC including virtio-net under hypervisors.» ([src/xdp.rs](../../src/xdp.rs), строки 219–224)

Это означает, что даже в облачных VM без native-XDP драйвера fast-path всё равно подключится — медленнее, но подключится. Подробнее об XDP — в [13-xdp-ebpf.md](./13-xdp-ebpf.md).

### 3.6. Один владелец XDP на NIC при REUSEPORT

NIC может нести ровно одну XDP-программу. При `N` SO_REUSEPORT-воркерах attach выиграет только один — остальные получат `EEXIST` (os error 17), который загрузчик распознаёт и возвращает как информационный маркер `XDP_ALREADY_OWNED_MARKER`, а не как ошибку ([src/xdp.rs](../../src/xdp.rs), строки 12–17, 160–178, 225–245). Воркер-владелец применяет deny/allow-карты в ядре для **всего** трафика, остальные воркеры фильтруют в userspace. Про многопроцессность — [06-workers.md](./06-workers.md).

---

## 4. Требования к CPU и памяти

### 4.1. CPU и топология воркеров

AEGIS использует модель **thread-per-core** (V230). По умолчанию (`resolve_workers`, строки 156–191):

- число воркеров = `nproc` (по одному воркеру на ядро), каждый с **1 потоком**;
- каждый воркер пинится 1:1 к своему CPU через `CPUAffinity=%i` в systemd-юните (строка 1265);
- воркеры нумеруются `0..N-1`, чтобы `%i` соответствовал индексу CPU.

Можно переопределить количество воркеров: `--workers N` или через панель (она пишет `topology.json`, который установщик читает на `--update`). CLI `--workers` всегда побеждает.

Минимум: код корректно работает и на 1 CPU (`nproc` → 1 воркер). Для рекомендованной production-конфигурации с XDP и полной L7-защитой целевой стенд — многоядерная машина (брифинг приводит цифры на 16 ядрах). Рантайм по умолчанию — **NoSteal thread-per-core** (`AEGIS_PINGORA_WORK_STEALING` не задан), это V81+ дефолт (строки 1328–1333). Подробности тюнинга — [docs/PERFORMANCE.md](../en/reference/performance.md).

`Nice=-10` (строка 1267) нудит проксю вперёд под нагрузкой, но без перехода в RT-FIFO, чтобы не заморить systemd/journald/sshd.

### 4.2. Память

Жёсткого порога RAM код не задаёт, но архитектурные потребители памяти известны:

- **Аллокатор `mimalloc`** включён всегда ([Cargo.toml](../../Cargo.toml), строка 143) — основной аллокатор бинаря.
- **Response cache** (`AEGIS_RESPONSE_CACHE_ENABLE=1` по умолчанию, строка 1325) — кэш ответов держится в памяти воркера. Объём зависит от настроек кэша.
- **Per-worker SQLite-шарды** журнала запросов/событий — каждый SO_REUSEPORT-воркер владеет своим `shard-<slot>.db` в WAL-режиме ([Cargo.toml](../../Cargo.toml), строки 159–166). Подробности — [src/event_store.rs](../../src/event_store.rs).
- **BPF-карты** (при XDP) — locked-память, см. §3.3.
- **GeoIP/ASN mmdb** — читаются через `maxminddb` (mmap), см. §5.3.

### 4.3. Лимит файловых дескрипторов

В обоих systemd-юнитах задан `LimitNOFILE=1048576` (строки 1185, 1257). Это нужно для большого числа одновременных соединений на edge. Если вы запускаете AEGIS вне systemd, выставьте аналогичный ulimit вручную.

### 4.4. Привилегированные порты без root

Бинарю `aegis-pingora` после сборки выдаётся file-capability (`build_aegis_pingora`, строки 463–465):

```
setcap 'cap_net_bind_service,cap_net_admin,cap_sys_resource=+ep' /usr/local/bin/aegis-pingora
```

Это позволяет воркерам слушать :80/:443, оставаясь под непривилегированным пользователем `aegis`. Если `setcap` недоступен — установщик предупреждает, что воркеры придётся запускать от root. Модель безопасности — SECURITY-AUDIT-CONSOLIDATED-2026-06-07.md.

---

## 5. Что деградирует без чего (режимы graceful-degradation)

AEGIS спроектирован так, чтобы отсутствие опционального компонента **не валило сервис**, а лишь отключало соответствующую функцию. Ниже — честная карта деградации, сверенная с кодом.

### 5.1. Без XDP

| Условие | Что происходит |
|---|---|
| Ядро < 4.18, или `--no-xdp`, или `--mode hyper`, или non-Linux | XDP отключён; loader возвращает `NoopXdp` ([src/xdp.rs](../../src/xdp.rs), строки 100–143) — все операции deny/allow/rate — no-op |
| ARM/любая платформа без PMU (нет `CAP_PERFMON`/`perfmon_capable`) | загрузка eBPF падает с `EACCES`; XDP не поднимается |
| NIC без native-XDP драйвера | откат на SKB (generic) mode — медленнее, но работает ([src/xdp.rs](../../src/xdp.rs), строки 218–251) |

**Что теряется без XDP:** kernel fast-path для дропа пакетов (deny-list, per-IP rate-limit, SYN-flood guard, inline kernel-WAF на scanner-префиксы — счётчики `drop_deny/drop_rate/drop_syn/drop_waf`, см. `XdpCounters` в [src/xdp.rs](../../src/xdp.rs), строки 80–98). Без XDP эти меры всё равно выполняются, но **в userspace** (и/или через nftables/iptables-бэкенд) — это медленнее под volumetric-нагрузкой. Вся L7-защита (WAF, fingerprinting, challenge, ML) от XDP не зависит и работает в полном объёме.

> 🔴 Honesty caveat: XDP не делает AEGIS защитой от L3/L4 volumetric DDoS. Под объёмным флудом даже kernel-drop требует, чтобы пакет дошёл до NIC; для крупнейших атак нужен upstream BGP/CDN (см. [src/bgp_rtbh.rs](../../src/bgp_rtbh.rs)). Авторитетный список ограничений — SECURITY-AUDIT-CONSOLIDATED-2026-06-07.md.

### 5.2. Без аппаратного SHA (PoW / HMAC)

PoW-challenge (`pow_captcha`, SHA-256 hashcash) и HMAC-токены используют `sha2` ([Cargo.toml](../../Cargo.toml), строка 83), который сам подхватывает аппаратное ускорение (SHA-NI на Intel/AMD, ARMv8 crypto extensions), если CPU его имеет.

> 🟡 Honesty caveat: на виртуальных ядрах AWS t4 / GCP e2 (часто без выставленного SHA-NI/AES-NI) PoW и HMAC считаются в **2–3× медленнее**, чем на bare-metal Intel/ARM с crypto-расширениями. Это влияет на стоимость проверки challenge на сервере и на абсолютные цифры бенчмарка. **Функционально всё работает; деградирует только скорость.** Всегда уточняйте: «в тестовой VM; bare-metal даст ×2–3 лучше». Подробности challenge — [15-challenge-ladder.md](./15-challenge-ladder.md).

### 5.3. Без ASN/GeoIP-базы

GeoIP-страновая база (`dbip-country-lite.mmdb`) поставляется в репозитории и сидируется установщиком в `/var/lib/aegis/geoip/` (`ensure_geoip_db`, строки 768–777). ASN-lite база (`dbip-asn-lite.mmdb`) подтягивается ежемесячно фоновым `aegis-refresh-feeds` (строки 821–827).

| Отсутствует | Деградация |
|---|---|
| Страновая mmdb | `warn "… map will be empty until Update is run"` (строка 771) — карта мира и страновые правила не работают до ручного Update в панели |
| ASN-lite mmdb | записи репутации, ключёванные по `AS<n>`, не резолвятся; CIDR-репутация (Tor/Spamhaus) при этом продолжает работать |

Все фид-загрузки — **best-effort**: неудача оставляет модуль инертным (ноль ложных срабатываний), но не валит установку (строки 786–787, 876–878). Демон **горячо перечитывает** изменившиеся файлы по mtime — рестарт не нужен. Подробности — [src/geoip.rs](../../src/geoip.rs) и [12-reputation.md](./12-reputation.md).

> ⚠️ Известная проблема безопасности зафиксирована честно: `maxminddb` держится на 0.24 из-за RUSTSEC-2025-0132 (unsound `Reader::open_mmap`); апгрейд до ≥0.27 — breaking change для [src/geoip.rs](../../src/geoip.rs) и отложен (см. [Cargo.toml](../../Cargo.toml), строки 59–64).

### 5.4. Без Redis

`redis` присутствует как зависимость ([Cargo.toml](../../Cargo.toml), строка 72, фича `tokio-comp`), но **не является обязательным компонентом runtime**: установщик [install.sh](../../install.sh) **нигде не устанавливает, не настраивает и не требует Redis-сервер**. Дефолтный конфиг и systemd-юниты Redis не упоминают.

Распределённый threat-scoring между воркерами реализован **не через Redis**, а через cross-worker mmap-arena (`ddos/shared_score.rs`, V91+, см. брифинг §3) и per-worker SQLite-шарды. То есть кластеризация скоринга работает **локально, без внешнего стора**.

> 🟡 Вывод: Redis — опциональный/вспомогательный путь, а не зависимость. Отсутствие Redis-сервера не деградирует основную защиту: межворкерный обмен скорингом идёт через shared-memory arena. Если в вашей инсталляции Redis не поднят — это штатно.

### 5.5. Без Node.js в runtime

Node.js (точнее Node 20 + pnpm 10) нужен **только на этапе сборки** — для компиляции React-админки, которая затем **встраивается в бинарь** (`build_frontend`, строки 382–396; `include_dir` в [Cargo.toml](../../Cargo.toml), строка 53). В runtime Node.js не требуется. Пропустить установку Node можно через `AEGIS_SKIP_NODE_INSTALL=1` (если node+pnpm уже на PATH).

### 5.6. Сводная таблица зависимостей сборки vs runtime

| Компонент | На этапе сборки | В runtime | Как отключить/пропустить |
|---|---|---|---|
| Rust stable + cargo | ✅ обязателен | — | `AEGIS_SKIP_RUST_INSTALL=1` (если уже на PATH) |
| Rust nightly + `bpf-linker` | ✅ только для XDP | — | `--no-xdp` / `AEGIS_ENABLE_XDP=0` |
| clang/llvm, cmake, openssl-dev, build-essential | ✅ обязательны | — | — |
| `mold` (линкер) | ✅ best-effort (ускоряет линковку) | — | отсутствие = откат на дефолтный линкер (строки 270–277) |
| Node 20 + pnpm 10 | ✅ для admin UI | ❌ | `AEGIS_SKIP_NODE_INSTALL=1` |
| XDP/eBPF (ядро ≥4.18, CAP_BPF/PERFMON) | nightly-тулчейн | опционально | деградирует в userspace-фильтрацию |
| GeoIP country mmdb | bundled | опционально | карта/страновые правила отключаются |
| ASN-lite mmdb | — (фоновый refresh) | опционально | AS-репутация не резолвится |
| Redis | — | опционально/неиспользуем по умолчанию | не требуется |
| nginx/HAProxy/Caddy/Envoy/ModSecurity | best-effort | только для бенчмарка | таргет покажет `unavailable` |

---

## 6. Сетевые требования

- Открытые порты по умолчанию: **80/tcp** (HTTP), **443/tcp** + **443/udp** (HTTPS + HTTP/3 QUIC), **6280/tcp** (admin UI). Установщик открывает их в `ufw`/`firewalld`, если те активны (`setup_firewall`, строки 1355–1374). Пропустить — `AEGIS_SKIP_FIREWALL=1`.
- Перед стартом установщик предупреждает (не падает) о конфликте портов с уже запущенными nginx/apache (`detect_port_conflict`, строки 1376–1389).
- Для первичной загрузки нужен outbound-доступ к git-репозиторию, crates.io, npm-registry и (для XDP) к источнику `bpf-linker`. Фид-рефреши ходят на `check.torproject.org`, `spamhaus.org`, `download.db-ip.com` (строки 810–826) — все best-effort.

Подробнее про слушатели и протоколы — [07-protocols.md](./07-protocols.md), про TLS/ACME — [08-tls-certificates.md](./08-tls-certificates.md).

---

## 7. Минимальная и рекомендованная конфигурация (резюме)

| Параметр | Минимум | Рекомендовано (production) |
|---|---|---|
| ОС | Linux (Debian/RHEL/Alpine), либо non-Linux только для dev | Debian 12 (эталон) |
| Архитектура | amd64 или arm64 | amd64/arm64 с crypto-расширениями (SHA-NI / ARMv8 crypto) |
| Ядро | ≥ 4.18 для XDP (иначе без XDP) | 6.x (проверены capability-требования) |
| CPU | 1 ядро | многоядерная (1 воркер на ядро, thread-per-core) |
| RAM | зависит от кэша/журнала; жёсткого порога нет | с запасом под response-cache + per-worker SQLite + BPF-карты |
| Capabilities (XDP) | — | `CAP_BPF CAP_PERFMON CAP_NET_ADMIN CAP_SYS_RESOURCE CAP_NET_BIND_SERVICE` |
| ulimit nofile | — | 1048576 (задаётся юнитом автоматически) |
| MEMLOCK (XDP) | — | infinity (задаётся юнитом автоматически) |

---

## 8. Связанные документы

- [03-installation.md](./03-installation.md) — пошаговая установка и флаги `install.sh`
- [06-workers.md](./06-workers.md) — REUSEPORT, CPU-pinning, топология
- [13-xdp-ebpf.md](./13-xdp-ebpf.md) — XDP/eBPF fast-path в деталях
- [12-reputation.md](./12-reputation.md) — фиды и GeoIP/ASN (см. также [src/geoip.rs](../../src/geoip.rs))
- [docs/PERFORMANCE.md](../en/reference/performance.md) — рантайм-тюнинг
- SECURITY-AUDIT-CONSOLIDATED-2026-06-07.md — авторитетный список найденных проблем и статус фиксов
