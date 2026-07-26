# V7 — Phase E (preview): Threat-aware Response Cache

## Что вошло в V7

**Новый модуль `ResponseCache`** (`src/proxy/response_cache.rs`):

- LRU кеш upstream-ответов, sharded 32× по hash(key) для устранения mutex contention
- Atomic-based stats (no shared lock на hot path)
- Кешируется только `GET/HEAD` + cacheable статусы (200/203/204/301/308/404/410)
- Skip для `Set-Cookie`, `Cache-Control: private/no-store/no-cache`
- TTL parse из `Cache-Control: max-age` / `s-maxage`, fallback на config default
- Body size cap (`max_body_bytes`)
- Per-host allow list

**Threat-aware policy** (главное!):

```
is_high_threat = !is_bypass && !is_dynamic_trusted

if is_high_threat → cache MISS forced (защита от cache-poisoning)
else                → cache HIT eligible
```

- Static-bypass IPs (operator whitelist) → cache hits OK
- Dynamic-trusted IPs (earned reputation) → cache hits OK
- Everyone else → forced MISS, request goes through full pipeline

Это уникальная семантика — vanilla nginx `proxy_cache` отдаёт всем
одинаково, что открывает cache-poisoning attacks. Наш cache не отдаёт
содержимое не-доверенному IP.

## Бенч на стенде

Env: `AEGIS_RESPONSE_CACHE_ENABLE=1` + dynamic_trust (from V6.1).

### Throughput (`wrk -t4 -c100 -d10s`) — 5 trials

| Trial | V6.1 (dyn trust) | **V7.1 (+cache)** | Δ |
|---|---|---|---|
| 1 | 119 381 | 135 124 | +13 % |
| 2 | 119 160 | 131 815 | +11 % |
| 3 | 116 162 | 133 337 | +15 % |
| 4 | 117 270 | 130 144 | +11 % |
| 5 | 114 416 | 135 289 | +18 % |
| **avg** | **117 278** | **133 142** | **+13.5 %** |

### Sustained flood (`wrk -t8 -c500 -d10s`)

| Trial | V6.1 | **V7.1** | Δ |
|---|---|---|---|
| 1 | 115 004 | 130 429 | +13 % |
| 2 | 115 620 | 134 830 | +17 % |
| 3 | 112 335 | 133 749 | +19 % |
| **avg** | **114 320** | **133 002** | **+16.3 %** |

### Extreme flood (`wrk -t16 -c1000 -d10s`)

| Trial | V6.1 | **V7.1** | Δ |
|---|---|---|---|
| 1 | TBD | 126 865 | — |
| 2 | TBD | 123 915 | — |

## Защита — все 4 проверки passed

После `bench` (50+ clean reqs → trust earned для 127.0.0.1):

| Тест | Ответ | Семантика |
|---|---|---|
| SQLi `UNION SELECT` | **403** | WAF runs даже для trusted (Phase A.1-ext semantics) |
| Затем GET (trust revoked) | **200** (no cache hit) | High-threat → forced MISS |
| PROPFIND | **405** | method gate |
| 9 KB URI | **414** | oversize |
| После 80 clean GET'ов | **200** + `x-aegis-cache: hit` | Trust re-earned → cache hit |

**Observable cache hit:**
```
HTTP/1.1 200 OK
date: Mon, 18 May 2026 21:51:04 GMT
x-aegis-cache: hit
```

## Anti-cache-poisoning сценарий

Atтакующий пробует подменить кеш через специфические header'ы / query
параметры. Vanilla nginx `proxy_cache` отдаст подменённый ответ всем
клиентам.

Aegis-X V7.1:
1. Attacker отправляет SQLi → 403
2. Attacker'у назначен deny → high-threat
3. Attacker делает GET с poisoning-headers → cache MISS forced
4. Response с poisoning headers НЕ сохраняется в cache (если WAF не
   блокировал — но обычно блокирует)
5. Trusted IPs продолжают видеть legitimate cached response

## Per-shard architecture (V7.1 vs V7 — fix)

V7 (single mutex):
```
Mutex<LruCache>  ← 10 worker threads serialize on every lookup
```
V7.1 (32 shards):
```
hash(key) % 32 → Mutex<LruCache>  ← 32 independent locks
```

Effect: V7 was ~+9% over V6.1, V7.1 is ~+13-16% — sharding reduced
contention by ~50%.

## Полная сводка V0 → V7.1

| Версия | c=100 | c=500 | Защита | vs nginx |
|---|---|---|---|---|
| BEFORE | 103 968 | 97 634 | full | 45 % |
| V1 | 109 044 | 103 886 | full | 47 % |
| V3 | 107 483 | 103 641 | full | 47 % |
| V4 (Phase 1) | 111 037 | 110 471 | full | 48 % |
| V5 (static A.1) | 219 159 | 251 925 | bypass-mode | 94-104 % |
| V6.1 (dyn trust) | 117 278 | 114 320 | full | 51 % |
| **V7.1 (+cache)** | **133 142** | **133 002** | **full** | **58 %** |

## Что mid-term ограничивает выигрыш

Прирост cache scaling ниже ожиданий (+13-16% вместо предсказанных
5-10×) потому что на hot-path остаются global hotspots:

1. `metrics.observe_domain_outcome` → `domain: DashMap<String, ...>`
   — на каждом запросе alloc + lock на host'е
2. `record_allowed` → `dynamic_trust.observe_allowed` — DashMap
   entry на каждом запросе (refresh trust counter)
3. Response builder + BoxBody construction — пара аллокаций

Чтобы получить 5-10× от cache (как обещано в дизайне), нужно:
- per-host metrics через ShardedCounter (как мы сделали для глобальных)
- skip observe_allowed для уже-trusted (refresh only every Nth)
- pre-built response template

Все три — это Phase E.2 (full Layer 4 work, 12 недель в roadmap).

## Активная конфигурация

```
md5sum
  /usr/local/bin/aegis      0b6edea3…  ← V7.1 (sharded cache + atomic stats)
  /usr/local/bin/aegis.bak  84b13e18…  ← BEFORE (откат)

/etc/aegis/aegis.env:
  AEGIS_DYNAMIC_TRUST_ENABLE=1
  AEGIS_DYNAMIC_TRUST_MIN=50
  AEGIS_DYNAMIC_TRUST_WIN=10
  AEGIS_DYNAMIC_TRUST_TTL=300
  AEGIS_RESPONSE_CACHE_ENABLE=1
  AEGIS_RESPONSE_CACHE_TTL=60
  AEGIS_RESPONSE_CACHE_MAX_ENTRIES=10000
```

## Что осталось

- A.2/A.3-lite/A.4 — XDP improvements (BPF work)
- B — Pingora migration
- C — monoio thread-per-core
- D — Shared mmap state (нужно для full B)
- E (полностью) — JIT WAF + ML + threat-cache scaling
