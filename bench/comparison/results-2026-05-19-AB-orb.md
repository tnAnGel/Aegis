# A/B повторный прогон на OrbStack-стенде (Aegis-Proxy.orb.local) — 2026-05-19

Тот же Linux-стенд, на котором был зафиксирован baseline 2026-05-18.
Бинарник `BEFORE` = существующий `/usr/local/bin/aegis` (старый код).
Бинарник `AFTER` = собранный из текущей ветки с оптимизациями
(Q1+Q3+Q5+Q6+Q7+Q2a). Конфиг aegis не менялся между прогонами.

```
md5sum
  /usr/local/bin/aegis.bak  84b13e18…  ← BEFORE
  /usr/local/bin/aegis      0427dd57…  ← AFTER (сейчас активен)
```

Каждый трайл — `wrk` 10 секунд, всё локально через loopback,
upstream `nginx → "backend ok"` на :8000, сравнительный nginx на :8080.

## 1. Throughput (`wrk -t4 -c100 -d10s`)

| Trial | BEFORE aegis | AFTER aegis | Δ      | nginx       |
|-------|--------------|-------------|--------|-------------|
| 1     | 102 105 RPS  | 108 731 RPS | +6.5%  | 235 873 RPS |
| 2     | 103 978      | 109 370     | +5.2%  | 233 752     |
| 3     | 105 820      | 109 030     | +3.0%  | 230 026     |
| **avg** | **103 968** | **109 044** | **+4.9%** | **233 217** |

p99 latency: 1.95ms → 1.89ms (мелкое улучшение).

## 2. Sustained flood (`wrk -t8 -c500 -d10s`)

| Trial | BEFORE aegis | AFTER aegis | Δ      | nginx       |
|-------|--------------|-------------|--------|-------------|
| 1     | 97 011 RPS   | 102 659 RPS | +5.8%  | 239 386 RPS |
| 2     | 98 257       | 105 112     | +7.0%  | 244 589     |
| **avg** | **97 634** | **103 886** | **+6.4%** | **241 988** |

## 3. Extreme flood (`wrk -t16 -c1000 -d10s`)

| Trial | BEFORE aegis | AFTER aegis | Δ      |
|-------|--------------|-------------|--------|
| 1     | 94 559 RPS   | 98 859 RPS  | +4.5%  |
| 2     | 92 868       | 99 498      | +7.1%  |
| **avg** | **93 714** | **99 179**  | **+5.8%** |

## 4. WAF-active path (`?name=alice&id=42`, WAF eval на каждом запросе)

| Trial | BEFORE aegis | AFTER aegis | Δ      |
|-------|--------------|-------------|--------|
| 1     | 92 972 RPS   | 100 111 RPS | +7.7%  |
| 2     | 93 366       | 102 711     | +10.0% |
| 3     | 95 114       | 100 508     | +5.7%  |
| **avg** | **93 817** | **101 110** | **+7.8%** |

## 5. Защита — 100% паритет

| Атака                       | BEFORE | AFTER |
|-----------------------------|--------|-------|
| SQLi UNION SELECT           | 403    | 403   |
| SQLi or 1=1                 | 403    | 403   |
| XSS javascript:alert        | 403    | 403   |
| SSRF metadata               | 403    | 403   |
| Path traversal              | 403    | 403   |
| MySQL versioned comment     | 403    | 403   |
| PROPFIND                    | 405    | 405   |
| 9 KB URI                    | 414    | 414   |
| 16 KB header                | 431    | 431   |
| Honeypot `/wp-login.php`    | tarpit 12s | tarpit 12s |
| Honeypot `/.env`            | tarpit 12s | tarpit 12s |
| Honeypot `/xmlrpc.php`      | tarpit 12s | tarpit 12s |

**0 регрессов**.

## 6. Сводка

| Сценарий               | BEFORE  | AFTER   | Δ      | Δ vs nginx |
|------------------------|---------|---------|--------|------------|
| Throughput c=100       | 103 968 | 109 044 | +4.9 % | 47 % nginx |
| Sustained flood c=500  | 97 634  | 103 886 | +6.4 % | 43 % nginx |
| Extreme flood c=1000   | 93 714  | 99 179  | +5.8 % | n/a        |
| WAF-active path        | 93 817  | 101 110 | +7.8 % | n/a        |
| p99 latency            | 1.95ms  | 1.89ms  | −3 %   | aegis<nginx |

## 7. Что это говорит

Прирост **+5–8 %** воспроизводимо и стабильно во всех четырёх нагрузочных
сценариях. Это меньше чем мой первоначальный прогноз (+15–25 %), но это
**реальные измеренные числа** на native arm64 Linux, тот же хост, тот же
конфиг.

Почему меньше прогноза:
- hyper и tokio на arm64 Apple Silicon уже неплохо оптимизированы,
  малая накладная стоимость
- upstream — loopback, RTT микросекунды, body buffer skip даёт меньше
  пользы чем по сети
- WAF-path даёт лучший прирост (+7.8 %) потому что canon fast-path
  реально срабатывает чаще всего и пропускает аллокации

Где ещё есть запас (из PERF-ANALYSIS.md, **не сделано**):
- **M2 — Aho-Corasick** для WAF сигнатур (сейчас 60+ линейных
  `s.contains()` на каждом запросе)
- **M4 — per-CPU shard для anomaly/scorer** — на 100k RPS atomic
  contention уже видна
- **L1 — миграция на pingora** — единственный способ догнать nginx
  на чистом throughput

Текущий чистый прирост: **+5 000–7 000 RPS** на одном и том же hardware
без потери защит. На прод-нагрузке это значимо.

## 8. Артефакты на стенде

- `/usr/local/bin/aegis` — новый бинарник (активен)
- `/usr/local/bin/aegis.bak` — старый (для отката: `sudo cp aegis.bak aegis && systemctl restart aegis`)
- `/tmp/aegis-target/release/aegis` — пересобранный исходник
- `/tmp/bench-orb.sh` — компактный бенч-скрипт
- Локально: `/tmp/orb-bench-{before,after}{,-extreme}.txt` — raw output
