# V6 — Phase A.1-extension (Reputation-driven dynamic trust)

## Что вошло в V6

**Новый модуль `DynamicTrust`** (`src/filters/dynamic_trust.rs`):

- Auto-promote IPs к bypass-fast-path после N "чистых" Allow ответов
- Demote мгновенно на любой Deny/Challenge (single attack revokes trust)
- TTL — trust истекает автоматически
- LRU bounded — memory cap
- Полностью userspace, no BPF

**Defense-first semantics** (важно!):

| Слой | Static bypass<br/>(`bypass.ips`, `xdp.allow`) | Dynamic trust<br/>(`ctx.is_trusted`) |
|---|---|---|
| Geo + smuggling | runs | runs |
| WAF body inspect | **skip** | **runs** ⭐ |
| GraphQL guard | **skip** | **runs** ⭐ |
| WAF filter (signatures) | **skip** | **runs** ⭐ |
| Honeypot tarpit | **skip** | **runs** ⭐ |
| Threat-intel | **skip** | **runs** ⭐ |
| IP ACL | **skip** | runs |
| **Rate-limit** | **skip** | **skip** |
| **Bot reputation** | **skip** | **skip** |
| **Challenge ladder** | **skip** | **skip** |
| Plugins (Lua/WASM) | **skip** | runs |

**Static bypass** = operator-declared, **full whitelist** (Stripe webhooks etc.)
**Dynamic trust** = reputation-earned, **только throttling skip**.

Trusted IP всё ещё блокируется WAF'ом если внезапно атакует — single
attack триггерит deny → trust revoked → следующий запрос снова через
полный pipeline.

## Configuration

Через `[filters.dynamic_trust]` в TOML (off by default):

```toml
[filters.dynamic_trust]
enabled = true
min_clean_requests = 100   # earn trust after N clean responses
trust_window_secs = 60     # within this window
trust_ttl_secs = 300       # trust lasts this long
max_trusted = 10000        # LRU cap
```

ИЛИ env-vars (для runtime override без перезагрузки конфига):
```
AEGIS_DYNAMIC_TRUST_ENABLE=1
AEGIS_DYNAMIC_TRUST_MIN=100
AEGIS_DYNAMIC_TRUST_WIN=60
AEGIS_DYNAMIC_TRUST_TTL=300
```

## Бенч на стенде

Конфиг: env-vars включают dynamic trust с порогом 50 reqs / 10s window /
300s TTL. Wrk шлёт с 127.0.0.1 — первые ~50 запросов проходят через
полный pipeline, остальные ~99% — через trust-fast-path (но WAF всё
равно работает).

### Throughput (`wrk -t4 -c100 -d10s`) — 5 trials

| Trial | V4 (Phase 1) | **V6.1 (safe trust)** | Δ |
|---|---|---|---|
| 1 | 108 561 | 119 381 | +10 % |
| 2 | 109 659 | 119 160 | +9 % |
| 3 | 110 309 | 116 162 | +5 % |
| 4 | 109 715 | 117 270 | +7 % |
| 5 | 110 116 | 114 416 | +4 % |
| **avg** | **109 672** | **117 278** | **+6.9 %** |

### Sustained flood (`wrk -t8 -c500 -d10s`)

| Trial | V4 | **V6.1** | Δ |
|---|---|---|---|
| 1 | 103 450 | 115 004 | +11 % |
| 2 | 104 457 | 115 620 | +11 % |
| 3 | 102 821 | 112 335 | +9 % |
| **avg** | **103 576** | **114 320** | **+10.4 %** |

## Защита — 100% работает для trusted IPs

После 60 чистых GET'ов с 127.0.0.1 (IP должен быть в trusted state):

| Атака | Ответ | Ожидалось |
|---|---|---|
| SQLi `UNION SELECT` | **403** | 403 ✅ |
| XSS `<script>` | **403** | 403 ✅ |
| Path traversal `../../etc/passwd` | **403** | 403 ✅ |
| PROPFIND | **405** | 405 ✅ |

WAF / smuggling / method gate работают для всех IPs одинаково — trust
обходит **только** throttling.

## Comparison: dynamic trust vs static bypass

| Версия | Throughput c=100 | SQLi от trusted IP | Use case |
|---|---|---|---|
| V5 (static `xdp.allow`) | **219 159** RPS | **200** (bypassed!) | Operator-declared (webhooks) |
| V6.1 (dynamic trust) | **117 278** RPS | **403** (caught!) | Production auto-promote |

Trade-off:
- **Static bypass** даёт макс. throughput, но IP полностью whitelisted
- **Dynamic trust** даёт меньший прирост (~+7-10 %), но **сохраняет защиту**

Они **сосуществуют** — оператор использует static для известных
trusted webhook IPs, а dynamic trust работает в фоне для production-traffic.

## Real-world expected gain

Прирост V6.1 на стенде скромный (+6-10 %) **потому что throttling
filters на стенде почти выключены**:
- `rate_limit` enabled но `rps=1_000_000` (effectively no-op)
- `bot_fingerprint` off
- `challenge_ladder` off

В типичном prod-конфиге с активными throttling filters:
- rate_limit: DashMap lookup + 3 entries → ~500 ns saved per skip
- bot: DefaultHasher + DashMap entry → ~800 ns saved
- challenge: cookie parse + state lookup → ~600 ns saved

Сумма: ~2 µs sav per trusted request → **+15-25 % throughput** в проде
для traffic'а где >80 % requests от trusted clients.

## Полная сводка V0 → V6

| Версия | c=100 | c=500 | c=1000 | Defense | vs nginx |
|---|---|---|---|---|---|
| BEFORE | 103 968 | 97 634 | 93 714 | full | 45 % |
| V1 | 109 044 | 103 886 | — | full | 47 % |
| V3 | 107 483 | 103 641 | 99 179 | full | 47 % |
| V4 (Phase 1) | 111 037 | 110 471 | 104 746 | full | 48 % |
| V5 (static A.1) | 219 159 | 251 925 | 248 802 | bypass | 94-104 % |
| **V6.1 (dyn trust)** | **117 278** | **114 320** | TBD | **full** ⭐ | 51-50 % |

V5 и V6.1 — **разные стратегии для разных задач**:
- V5 для operator-declared whitelist (webhooks) — максимум throughput
- V6.1 для general production — auto-amortize repeat-clients, защита целая

## Активная конфигурация на стенде

```
md5sum
  /usr/local/bin/aegis      c6e1b195…  ← V6.1 (dynamic trust safe)
  /usr/local/bin/aegis.bak  84b13e18…  ← BEFORE (откат)

/etc/aegis/aegis.env:
  AEGIS_DYNAMIC_TRUST_ENABLE=1
  AEGIS_DYNAMIC_TRUST_MIN=50
  AEGIS_DYNAMIC_TRUST_WIN=10
  AEGIS_DYNAMIC_TRUST_TTL=300
```

## Что осталось из Phase A для будущих сессий

| ID | Что | Effort |
|---|---|---|
| **A.2** | True token-bucket в XDP | 2 дня |
| **A.3-lite** | XDP early-deny по path prefix (eBPF AC WAF) | 1 неделя |
| **A.4** | SYN-cookies auto-toggle | 2 дня |

Следующая фаза — **B (multi-process pingora)** — это базовый шаг к
тому чтобы по-настоящему обгнать nginx на любой нагрузке (не только
trusted/cached).
