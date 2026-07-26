# AEGIS — Landing Page

A polished, self-contained, bilingual (RU / EN) marketing landing page for **AEGIS**, the self-hostable DDoS / WAF reverse proxy.

No build step. No npm. No bundler. Just static files.

## Files

| File | Purpose |
| --- | --- |
| `index.html` | All markup + styles. Pulls Tailwind and Chart.js from CDNs. |
| `app.js` | i18n dictionary, dynamic content (features / comparison / FAQ), Chart.js charts, counters, scroll-reveal, language toggle. |
| `README.md` | This file. |

## Running it

**Option 1 — open directly.** Double-click `index.html` (or open it in a browser).
> Note: the clipboard "Copy" button and some browsers' module/CDN behavior work best over `http://`. If anything looks off, use Option 2.

**Option 2 — serve statically** (recommended; any static server works):

```bash
# Python
python3 -m http.server 8080
# or Node
npx serve .
# then visit http://localhost:8080
```

An internet connection is required the first time so the CDNs load:
- Tailwind CSS — `https://cdn.tailwindcss.com`
- Chart.js — `https://cdn.jsdelivr.net/npm/chart.js`
- Google Fonts (Inter, JetBrains Mono)

## Language toggle (RU / EN)

- RU is the default. The choice is persisted in `localStorage` under the key `aegis_lang`.
- The toggle button is in the top-right of the nav.
- All visible copy switches instantly, and the Chart.js charts re-render with localized labels.

### Editing / adding translations

All copy lives in **one place**: the `I18N` object near the top of `app.js`:

```js
const I18N = {
  ru: { hero_title_1: "Защита от DDoS и L7-атак", /* ... */ },
  en: { hero_title_1: "DDoS & L7 attack protection", /* ... */ },
};
```

To change text:

1. **Static text** is tagged in `index.html` with a `data-i18n="some_key"` attribute. Edit the matching `some_key` in **both** `ru` and `en` blocks of `I18N`.
2. **Generated lists** (feature cards, comparison table rows, FAQ) live in the `FEATURES`, `COMPARE`, and `FAQ` arrays in `app.js`, each with `ru` / `en` fields.
3. **Chart labels** are in the `chartLabels()` function in `app.js`.

> Keep the `ru` and `en` key sets identical. If a `data-i18n` key has no entry in the active language, that element simply keeps its hardcoded HTML fallback.

## Editing the charts / numbers

The benchmark figures are representative estimates measured on an 8-core baseline and scale with hardware. They live in `renderCharts()` in `app.js` (datasets for RPS-by-mode, TLS handshakes, p99 latency, attack-mitigation radar, and RPS-by-cores). Framing is intentionally honest: raw nginx is shown as the unprotected throughput ceiling, AEGIS as full DDoS + WAF protection.

## Theme

Dark, glassmorphism, teal/emerald + cyan accents (matching the AEGIS admin panel). Tailwind theme tokens and custom CSS (aurora background, gradient borders, reveal animations) are defined inline in `index.html`.
