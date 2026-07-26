# Aegis vs Nginx — стенд сравнения

Скрипты и зафиксированные результаты сравнительного бенчмарка проксирующего
слоя Aegis против ванильного nginx. Бэкенд один и тот же
(`nginx → :8000` отдаёт статическую строку `"backend ok"`), измеряется
исключительно работа прокси.

## Топология стенда

```
client (wrk/curl/nc/slowhttptest)
        │
        ├─► :80    aegis  ──┐
        │                   ├─► :8000  nginx-backend  "backend ok"
        └─► :8080  nginx   ──┘
```

## Файлы

- `setup_stand.sh` — устанавливает nginx как сравнительный прокси на :8080,
  выключает в Aegis `challenge_ladder` (у nginx нет JS-гейта, иначе нечестно).
- `setup_fair.sh` — заменяет python `http.server` на nginx-as-backend на :8000
  (python однопоточный, упирается ~4k RPS и искажает throughput),
  и временно ослабляет в Aegis `rate_limit / adaptive / bot_fingerprint`,
  чтобы получить baseline без срабатываний на нагрузочный тест.
- `bench.sh` — первая версия (T1…T17), оставлена для воспроизводимости.
- `bench2.sh` — расширенный набор: throughput, WAF, smuggling, methods,
  oversize, honeypot tarpit, slowloris, sustained flood, sustained SQLi,
  scanner sweep.
- `results-2026-05-18.md` — снятые цифры и итоговая таблица.

## Запуск

```bash
# на чистой машине (тестировалось на Debian/Ubuntu контейнере)
bash setup_stand.sh
bash setup_fair.sh
bash bench2.sh | tee results.txt
```
