# Почему Aegis проиграл nginx в throughput и как победить

Бенч от 2026-05-18: 108k RPS у Aegis против 239k RPS у nginx (×2.2).
p99 у Aegis при этом ниже (1.88 ms vs 2.88 ms) — то есть мы быстрее
*на одном запросе*, но просаживаемся *в среднем*. Это характерный
профиль системы со «жирным» хот-патом: каждая отдельная просьба
выполняется ок, но на запрос тратится больше CPU-такта чем у nginx,
поэтому в насыщении мы упираемся в CPU раньше.

Ниже — где именно мы их тратим (со ссылками на код) и план как закрыть
разрыв.

---

## 1. Где честный проигрыш — структурный

nginx это event-loop на C с zero-copy `sendfile`, ноль аллокаций
на запрос, готовый upstream keep-alive pool. Мы — Rust на `hyper` +
`tokio`. Базовый теоретический потолок у такой связки **~70–80%** от
nginx на чистом проксировании (так же как Pingora у Cloudflare:
заявленный паритет получили только после написания собственного HTTP
стека вместо hyper).

То есть **полностью догнать на голом проксировании невозможно без
ухода с hyper**. Но довести с 45% до 75–85% реально — текущий зазор
почти весь это «жир», а не фундамент.

---

## 2. Реальные узкие места в нашем коде

### 2.1. Полный сбор тела до начала фильтров — [`http.rs:708-742`](src/proxy/http.rs:708)

```rust
let collect_fut = body.collect();
...
let body_bytes = body_result.map(|c| c.to_bytes()).unwrap_or_else(...);
```

Мы буферим **весь** body перед тем как принять любое решение, даже
для GET-запросов где body нулевой. Для streaming-uploads это полный
блокер throughput'а: nginx начинает отдавать первые байты к бэкенду
сразу.

**Цена:** одна большая аллокация и одно копирование на каждый запрос
с body. На GET — ноль, но мы всё равно платим за `await` и
переключение task'а.

### 2.2. Клон HeaderMap + Vec<(String,String)> на каждый запрос — [`http.rs:870-892`](src/proxy/http.rs:870)

```rust
let header_pairs: Vec<(String, String)> = parts.headers.iter()
    .filter_map(|(n,v)| v.to_str().ok().map(|s| (n.as_str().to_string(), s.to_string())))
    .collect();
...
let ja4h = crate::ja4::compute_ja4h(...);
...
let ctx = RequestContext {
    ...
    headers: parts.headers.clone(),   // ← полный клон HeaderMap
    ...
};
```

Аллокации на запрос:
1. `host.to_string()`
2. `ua.to_string()`
3. `path.to_string()`
4. `header_pairs` — `Vec` плюс 2 `String` на каждый заголовок (для
   типичного браузерного запроса это ~20 строк)
5. `parts.headers.clone()` — ещё один полный обход + аллокация
6. `uuid::Uuid::new_v4()` — RNG syscall + форматирование в строку
7. `ja4h.full` — ещё одна строка

**Цена:** при ~15 заголовках это ~30+ малых аллокаций на запрос.
malloc/free под нагрузкой бьёт в jemalloc/scudo тяжелее чем сам байт
работы.

### 2.3. WAF `canon()` — четыре прохода нормализации на каждое поле — [`waf.rs:224-266`](src/filters/waf.rs:224)

```rust
fn canon(v: &str) -> String {
    const MAX_PASSES: usize = 4;
    let mut cur = v.to_string();
    for _ in 0..MAX_PASSES {
        let next = canon_once(&cur);
        ...
    }
}

fn canon_once(v: &str) -> String {
    let decoded = urlencoding::decode(v)...;   // alloc
    let mut s = decoded.to_ascii_lowercase();  // alloc
    s = s.replace("%2f","/")                   // alloc
         .replace("%5c","\\")                  // alloc
         .replace("\\u002f","/")               // alloc
         .replace("\\x2f","/");                // alloc
    s = s.replace("/*!"," ");                  // alloc
    s = s.replace("*/", " ");                  // alloc
    s = s.replace('+', " ");                   // alloc
    let collapsed: String = s.split_whitespace().collect::<Vec<_>>().join(" ");
    collapsed
}
```

Это **~9 аллокаций × до 4 проходов = до 36 аллокаций на одно
проверяемое поле**, а полей у нас несколько (path, query, ua,
каждый header), да ещё с самим body. На запрос без атаки мы прогоняем
этот код впустую — payload'а нет, но цикл нормализации отрабатывает
полностью.

### 2.4. Async-цепочка с (опциональной) сетью внутри хот-пата

В [`http.rs:806-868`](src/proxy/http.rs:806) последовательно:

- `challenge_verified().await` — async, может ходить в кеш
- `distributed_rate_exceeded().await` — async, **может ходить в Redis**
- `distributed_bot_score().await` — async, **может ходить в Redis**

Когда Redis-репутация включена, это **сетевые RTT перед каждым
запросом**. Даже без неё мы платим за `.await` × N — переключение
task'ов в tokio не бесплатное (lockfree atomic + потенциальный
wake_by_ref).

### 2.5. Метрики — атомики в горячем цикле

В каждой ветке (allow, deny, challenge, tarpit, upstream-error) три-
четыре `AtomicU64::fetch_add(_, Relaxed)`. На 100k+ RPS на одном
адресе это контест за cache-line между ядрами, видный в `perf`.

### 2.6. Hyper `legacy::Client` без явного пула — [`http.rs:108-109`](src/proxy/http.rs:108)

```rust
let client: Client<HttpConnector, Full<Bytes>> =
    Client::builder(TokioExecutor::new()).build_http();
```

Дефолтный пул `hyper_util` маленький (по 90 keep-alive). Под флудом
500 коннекций он усыхает в bottleneck — каждый воркер ждёт
свободного слота. У nginx по дефолту `keepalive 32` *на воркер*, и
воркеров 8 — то есть 256, плюс upstream_keepalive_requests = бесконечно.

### 2.7. Уpstream URI собирается с двумя `.clone()` и одним `.parse()`

```rust
let mut uri_parts = parts.uri.clone().into_parts();
uri_parts.authority = Some(target.authority.parse().expect("authority parse"));
let new_uri = Uri::from_parts(uri_parts).unwrap_or_else(...);
```

`authority.parse()` парсит строку **на каждый запрос** хотя authority
у upstream фиксирована и могла бы быть `Arc<Authority>`, готовая.

---

## 3. План — быстрые победы (≤1 спринт, без переписывания)

Цель: **поднять с 108k до 180k+** (=75% nginx) без слома фич.

### Q1. Перестать буферить тело для запросов без него
- Если `Content-Length: 0` или метод `GET/HEAD/DELETE/OPTIONS` — пропустить
  `body.collect()` целиком, гонять `Empty<Bytes>` в upstream.
- Если тело есть и WAF не нуждается в его инспекции для данного host —
  стримить.
- **Ожидаемый эффект:** +15–25% RPS на голом GET-тесте (наш бенч).

### Q2. Убить лишние клоны в `handle_collected`
- `host`, `ua`, `path` → `&str`, держать в `RequestContext` как `Cow<'_, str>`.
- `headers` — передавать `&HeaderMap` в фильтры вместо клона.
- `header_pairs` — заменить на итератор-by-ref (`compute_ja4h` принимает
  `&[(&str,&str)]`).
- `Uuid` — генерить ленивo (только если включён structured-log с
  request_id; для прод-конфига без него — `()`).
- **Ожидаемый эффект:** −30…−40% malloc-нагрузки, +10% RPS.

### Q3. Кешировать `canon()` и сделать его аллокейшен-фри для горячего пути
- Path/query на этом запросе — нормализовать **один раз**, передать всем
  фильтрам.
- Переписать `canon_once` через `Cow<'_, str>`: если декодировать нечего
  и заглавных нет — вернуть тот же срез без аллокации.
- 4 прохода нужны только для случая когда после первого прохода что-то
  изменилось — у 99% запросов он один.
- **Ожидаемый эффект:** −80% аллокаций в WAF на чистых запросах, +8% RPS.

### Q4. Слить атомики метрик в per-CPU счётчики
- `requests_total / requests_denied / requests_challenged` — сделать
  `[AtomicU64; NUM_CPUS]`, агрегировать на читалке.
- **Ожидаемый эффект:** убирает cache-line contention, +5–10% RPS на
  многоядерках.

### Q5. Увеличить keep-alive пул к upstream
- `Client::builder().pool_idle_timeout(Some(Duration::from_secs(60)))`
- `.pool_max_idle_per_host(1024)` или выше
- HTTP/2 к upstream когда он его поддерживает (`http2_only(true)`) —
  одно соединение, multiplex.
- **Ожидаемый эффект:** +20–40% под `-c500` флудом (наш текущий 103k).

### Q6. Закешировать `target.authority` как готовый `http::uri::Authority`
- `Upstream { authority_parsed: http::uri::Authority }` — парсим один
  раз при build_handler.
- **Ожидаемый эффект:** −1 alloc/parse per request, мелочь, но
  бесплатная.

### Q7. Опциональный fast-path для bypass
- Если `bypass.matches(&ctx)` true — мы всё равно делаем WAF body
  inspect *и* graphql check *и* evaluate_with_attribution. По
  определению bypass это «пропусти всё». Должен быть **один** ранний
  `if bypass.matches { goto upstream }`.
- **Ожидаемый эффект:** для webhooks и internal вызовов — почти как
  голый nginx.

---

## 4. План — средняя дистанция (1 квартал)

### M1. Условная активация фильтров по host/path
Сейчас все фильтры бегут для каждого запроса. Если на host'е нет
GraphQL, его check_body не нужно вообще *компилировать в путь*.
Сделать `Vec<Box<dyn TrafficFilter>>` per-host из конфига.

### M2. WAF — Aho-Corasick вместо линейного поиска подстрок
Сейчас match_signature линейно прогоняет 30+ `s.contains(p)`. Заменить
на `aho_corasick::AhoCorasick` build-time, single-pass O(n) сканирование.
Это даст не только скорость но и возможность держать сотни сигнатур
бесплатно.

### M3. Параллелизация независимых проверок
`distributed_rate` и `distributed_bot` — независимые. Сейчас
sequential await. Можно `tokio::join!`. Будет видно только при
включённом Redis.

### M4. Per-worker shard для anomaly/scorer/honeypot counters
DashMap/Mutex замены на shard-by-thread, агрегация на чтении. Текущий
ddos scorer — горячая точка под флудом, видна в perf.

### M5. Перевести admin/control endpoints в отдельный listener
Сейчас `handle_ui_route`/`handle_api_route` живут в том же handler'е.
Их `if path.starts_with(...)` на каждом запросе — это branch + два
strcmp. Вынести в отдельный server на отдельном порту.

---

## 5. План — амбициозная цель (за-квартальная)

### L1. Перейти на `pingora` или собственный HTTP/1.1 парсер на picohttp
Это **единственный способ догнать nginx по чистому RPS**. Hyper
делает много "правильных" аллокаций для безопасности типов; nginx +
pingora работают на буферах. Цена — потеря части ergonomics hyper и
заметная переработка proxy слоя.

### L2. eBPF-ускоренный WAF
Часть простых сигнатур (длина URI, известные scanner UA, IP в deny)
можно проверять прямо в XDP-программе до того как пакет дошёл до
userspace. Мы уже грузим XDP для deny-set — есть инфраструктура,
расширить.

### L3. io_uring socket setup
Для accept() заменить epoll-based tokio reactor на tokio-uring. По
бенчмаркам даёт +15–25% на коротких HTTP/1.1 запросах.

### L4. Совместный upstream pool h2 multiplexing
Сейчас каждый client.request() это один stream. При h2 к бэкенду
можно гонять тысячи параллельных запросов через одно соединение —
это режет syscall'ы accept/connect почти в ноль.

---

## 6. Приоритетный roadmap

| # | Изменение                                          | Effort | RPS gain | Risk |
|---|----------------------------------------------------|--------|----------|------|
| 1 | Q1 пропускать `body.collect` для GET               | S      | +15–25%  | low  |
| 2 | Q5 раздуть upstream pool + h2 keepalive            | XS     | +20–40%* | low  |
| 3 | Q3 `canon` → Cow, один проход                      | S      | +8%      | low  |
| 4 | Q2 убрать клоны headers/host/path                  | M      | +10%     | med  |
| 5 | Q6 закешировать `Authority`                        | XS     | +1%      | none |
| 6 | Q7 ранний bypass                                   | XS     | +0–5%    | low  |
| 7 | Q4 per-CPU метрики                                 | M      | +5–10%   | low  |
| 8 | M2 Aho-Corasick для WAF                            | M      | +5%      | med  |
| 9 | M1 per-host фильтр-конфигурация                    | L      | +5–15%   | med  |
|10 | L1 pingora migration                               | XL     | +30–50%  | high |

\* — измеряется на `-c500` флуде, не на `-c100`.

После Q1+Q2+Q3+Q5 (≈неделя работы) ожидаемый baseline: **~180–200k RPS,
75–85% от nginx**, с сохранением всех фильтров. Это уже комфортная
позиция «платим −20% throughput, получаем WAF + honeypot + escalation».

L1 (pingora) — это уже разговор «обогнать ванильный nginx», требует
отдельного решения.

---

## 7. Чего НЕ делать

- Не «отключать защиты для скорости» в проде. Бенч в setup_fair.sh
  ослабляет их **только** для измерения базового потолка прокси-слоя.
  Под реальным трафиком rate_limit + bot_fingerprint + adaptive
  должны быть включены.
- Не оптимизировать tarpit-путь. По дизайну он медленный — это его
  фича, не баг.
- Не вкладываться в L3 (io_uring) пока не закрыты Q1–Q7. Это будет
  +10% поверх уже-оптимизированной системы; на текущей системе это
  +10% поверх жирного хот-пата = заметно меньше.
