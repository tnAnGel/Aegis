# Документация Aegis

**Языки:** [English](../en/README.md) · **Русский** · [中文](../zh/README.md)

> Русский набор — источник истины: документы пишутся здесь, английский и
> китайский переведены с него.

Aegis — высокопроизводительный защитный обратный прокси (anti-DDoS / WAF), сочетающий
XDP/eBPF-фильтрацию на уровне ядра, TLS-фингерпринтинг, репутацию, rate-limiting,
лестницу испытаний (challenge ladder) и ML-движок оценки риска. Система рассчитана на
многопроцессное развёртывание с воркерами, богатой наблюдаемостью и единой
админ-панелью с REST API. Этот документ — оглавление всей документации проекта.

## Оглавление

### Начало работы

- [Обзор](01-overview.md)
- [Установка и эксплуатация](03-installation.md)
- [Конфигурация](04-configuration.md)
- [Системные требования](05-requirements.md)

### Архитектура и развёртывание

- [Архитектура](02-architecture.md)
- [Многопроцессность и воркеры](06-workers.md)
- [Протоколы и слушатели](07-protocols.md)
- [TLS и сертификаты](08-tls-certificates.md)
- [Обновление и миграция](44-updates-migration.md)

### Подсистемы защиты

- [WAF](10-waf.md)
- [TLS-фингерпринтинг](11-tls-fingerprinting.md)
- [Репутация](12-reputation.md)
- [XDP / eBPF](13-xdp-ebpf.md)
- [Rate Limiting](14-rate-limiting.md)
- [Challenge Ladder (лестница испытаний)](15-challenge-ladder.md)
- [Privacy Pass](16-privacy-pass.md)
- [Honeypot и Tarpit](17-honeypot-tarpit.md)
- [ML Risk Engine (движок оценки риска)](18-ml-risk-engine.md)
- [BGP RTBH](19-bgp-rtbh.md)
- [GeoIP](20-geoip.md)
- [Arsenal-сценарии](21-arsenal-scenarios.md)
- [Enrichment (обогащение данных)](22-enrichment.md)
- [Модель безопасности](23-security-model.md)

### Наблюдаемость и эксплуатация

- [Журнал запросов](24-request-log.md)
- [Метрики и телеметрия](25-metrics-telemetry.md)
- [Картография и домены](26-sites-and-domains.md)
- [Производительность и тюнинг](27-performance-tuning.md)
- [Бенчмаркинг](28-benchmarking.md)

### Панель и API

- [Админ-панель](29-admin-panel.md)
- [Admin API](30-admin-api.md)
- [Плагины](31-plugins.md)

### Проект

- [Дорожная карта](40-roadmap.md)
- [План развития](41-development-plan.md)
- [Тестирование](43-testing.md)
- [История версий V97 → V245](45-changelog-history.md) — подробный инженерный журнал
  внутренних ревизий до публичного релиза
- [Глоссарий](46-glossary.md)
- [FAQ и troubleshooting](47-faq-troubleshooting.md)

## Дополнительно (англоязычные технические заметки)

- [Производительность — полное исследование](../en/reference/performance.md)
- [ML-пайплайн](../en/reference/ml-pipeline.md)
- [Admin API (детально)](../en/reference/admin-api.md)
- [Развёртывание на Pingora](../en/reference/pingora-deployment.md)
- [Многопроцессное развёртывание](../en/reference/multi-process-deployment.md)
- [Политика по доменам (per-domain policy)](../en/reference/per-domain-policy.md)
- [Консистентность клиента](../en/reference/client-consistency.md)
