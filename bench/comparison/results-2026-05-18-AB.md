# A/B повторный прогон — 2026-05-18 (после оптимизаций)

## Что прогонялось

Два бинарника на одной машине, с идентичным конфигом:

- `/tmp/aegis-before` — собран с `git stash`'нутыми моими изменениями
  (= тот же код что давал baseline 108k RPS на Linux-стенде)
- `/tmp/aegis-after` — собран с применёнными Q1+Q5+Q6+Q7+Q3+Q2a

Обе версии одновременно поднимались на `:9001` и `:9002` соответственно,
бэкенд (`hashicorp/http-echo`) и сравнительный nginx (`:8081`) — в Docker.

## 1. Тесты корректности

| Проверка | aegis-before | aegis-after |
|---|---|---|
| 269 unit-тестов | **✓ passed** | **✓ passed** |
| clippy `-D warnings` | clean | clean |

## 2. Параллельность защит — 10/10 идентично

Все WAF/method/oversize гейты возвращают тот же статус. Защита не
просела ни в одной точке.

| Атака | before | after |
|---|---|---|
| baseline GET | 200 | 200 |
| SQLi `UNION SELECT` | **403** | **403** |
| XSS `<script>` | **403** | **403** |
| SSRF `169.254.169.254` | **403** | **403** |
| Path traversal `../../etc/passwd` | **403** | **403** |
| Cmd injection `;cat /etc/passwd` | **403** | **403** |
| MySQL versioned comment `/*!UNION*/` | **403** | **403** |
| Method `PROPFIND` | **405** | **405** |
| 9 KB URI | **414** | **414** |
| 16 KB header | **431** | **431** |

## 3. Throughput на macOS-host

| Тест | nginx :8081 | before :9001 | after :9002 |
|---|---|---|---|
| `wrk -t4 -c100 -d10s` (idle GET) | 35 430 RPS | 21 234 | 21 246 |
| `wrk -t8 -c500 -d10s` flood | 37 950 | 20 080 | 20 116 |
| `wrk -t8 -c200 -d10s` WAF-active path | — | 20 909 / 20 910 / 20 948 | 20 899 / 20 814 / 20 845 |

**Дельта before→after = в пределах шума (±0.5%).**

## 4. Почему дельта не видна — это не значит что её нет

На macOS-стенде upstream и nginx живут в Docker, aegis на хосте.
- Сеть host↔docker идёт через Docker Desktop VM (Linux в HyperKit). У
  неё фиксированная per-packet задержка ~2 ms которую не убрать.
- 4.7 ms средняя latency при c=100 → потолок **100 / 4.7 ms ≈ 21 300 RPS**.
  Этот потолок задан хостовой сетью, а не кодом прокси.
- Те же 21k мы видим и для bypass'а (WAF deny), и для прохода в
  upstream — потому что не код упирается, а планировщик/VM.

Linux-стенд из прошлой сессии давал 108k RPS aegis vs 239k nginx
потому что весь стек жил в одном Linux-пользовательском пространстве
без VM-границы.

## 5. Что показала эта прогонка

✅ **Регресса нет** — same hardware, same conditions, same RPS.
✅ **Защита целая** — 10/10 атак блокируются идентично.
✅ **Код корректен** — 269/269 unit-тестов + clippy clean.

❌ **Throughput-прирост на этом стенде не измерим** — VM-граница macOS↔Docker
   маскирует любые ускорения < ~2ms на запрос.

## 6. Где проверять реальную дельту

Прогнать `bench/comparison/bench2.sh` на том же Linux-контейнере, где
получали baseline 108k:

```bash
# на Linux-стенде (где /etc/aegis/aegis.conf уже стоит):
bash setup_stand.sh
bash setup_fair.sh
bash bench2.sh | tee results-after.txt

# затем diff:
diff results-2026-05-18.md results-after.txt
```

Ожидание (из PERF-ANALYSIS.md):
- Q1 (skip body collect for GET) → +15–25 % → ~125–135k RPS
- Q5 (upstream pool) → +20–40 % на `-c500` floode → 125–145k vs текущих 103k
- Q3+Q6+Q7+Q2a → +10–15 % суммарно

Итог ожидаемо **~150–180k RPS** против nginx 239k, то есть 63–75 %
вместо текущих 45 %.

## 7. Артефакты

- `/tmp/aegis-before` — бинарник без оптимизаций (можно сравнивать)
- `/tmp/aegis-after` — бинарник с оптимизациями
- `/tmp/aegis-bench-before.toml`, `/tmp/aegis-bench-after.toml` — конфиги
- Логи: `/tmp/aegis-before.log`, `/tmp/aegis-after.log`
