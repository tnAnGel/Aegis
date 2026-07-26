# i18n convention — READ THIS before translating a page

The Aegis admin panel ships **Russian-first** (`ru`) with **English** (`en`) as
the fallback. All translation lives under `src/i18n/locales/<lang>/<ns>.json`.

`src/i18n/index.ts` auto-loads **every** JSON file under `locales/` via a Vite
glob. You never register namespaces by hand.

---

## TL;DR for adding a page

1. Pick a namespace `<ns>` — usually the route/page name, lowercase, one word
   (e.g. `dashboard`, `sites`, `security`, `bots`).
2. Create **both** files:
   ```
   src/i18n/locales/ru/<ns>.json
   src/i18n/locales/en/<ns>.json
   ```
   They MUST have the **same keys** — `ru` is the primary language, `en` is the
   fallback. Every key present in one must exist in the other.
3. In your page component:
   ```tsx
   import { useTranslation } from "react-i18next";

   function MyPage() {
       const { t } = useTranslation("<ns>");          // single namespace
       // or, to also use shared keys:
       // const { t } = useTranslation(["<ns>", "common"]);
       return <h1>{t("title")}</h1>;
   }
   ```
4. Replace every literal JSX string / aria-label / placeholder with `t("key")`.

That's it. The glob in `index.ts` picks the new files up automatically on the
next build/dev reload.

---

## Hard rules — DO NOT BREAK

- **NEVER edit `src/i18n/index.ts`.** The glob auto-loads namespaces; touching
  it risks breaking every other page. There is no manual registration step.
- **NEVER edit another page's JSON files** (or their components). Stay inside
  your own `<ns>` namespace. Shared strings go in `common` (already exists) —
  add to `common.json` only if the string is genuinely cross-page and obvious.
- **NEVER hardcode user-visible text.** No literal English/Russian strings in
  JSX, `aria-label`, `title`, `placeholder`, toast messages, etc.
- **Keep both languages in sync.** Same key set in `ru` and `en`.

---

## Key format

- **Flat and lowercase.** Prefer `camelCase` for multi-word keys:
  `"rateLimit"`, `"viewAll"`, `"emptyState"`.
- **One level of dot-grouping is allowed** for logical sections, e.g.
  `"status.connecting"`, `"table.header.name"`. Do not nest JSON objects —
  keep the JSON one level deep with dotted string keys. (i18next treats the
  dot as a separator, so `"status.offline"` resolves fine.)
- Keys describe **meaning**, not the English wording, so the RU text can change
  freely: use `"save"` not `"saveButton"`, `"emptyState"` not `"noDataYet"`.

Example `src/i18n/locales/en/sites.json`:
```json
{
  "title": "Sites",
  "addSite": "Add site",
  "empty": "No sites configured yet.",
  "col.host": "Host",
  "col.upstream": "Upstream"
}
```
The matching `ru/sites.json` has the **same keys**, Russian values.

---

## Interpolation & plurals

- Interpolation uses `{{name}}`:
  ```json
  { "welcome": "Добро пожаловать, {{name}}" }
  ```
  ```tsx
  t("welcome", { name: user })
  ```
- Plurals use i18next suffix keys. Russian needs `_one` / `_few` / `_many`;
  English needs `_one` / `_other`. Call with `{ count }`:
  ```json
  // ru
  { "site_one": "{{count}} сайт", "site_few": "{{count}} сайта", "site_many": "{{count}} сайтов" }
  // en
  { "site_one": "{{count}} site", "site_other": "{{count}} sites" }
  ```
  ```tsx
  t("site", { count: n })
  ```

---

## Shared namespaces already present (do not duplicate)

| namespace | purpose                                   | owner             |
|-----------|-------------------------------------------|-------------------|
| `common`  | save / cancel / loading / status words…   | shared — append only if truly common |
| `nav`     | sidebar group + item labels, page titles  | nav/sidebar/topbar — do not touch |
| `topbar`  | top-bar strings (welcome, status pill…)   | topbar — do not touch |

For your page, **create a new namespace.** Use `common` for the obvious shared
verbs (`t("save", { ns: "common" })` or `useTranslation(["<ns>", "common"])`).

---

## How the language is chosen (FYI — you don't configure this)

- Default language is **`ru`** when nothing is stored.
- The user's choice is persisted to `localStorage["aegis-lang"]` and `<html lang>`
  is kept in sync.
- The globe switcher in the top bar calls `i18n.changeLanguage(lng)`.
- `fallbackLng` is `en`, so a missing RU key falls back to the EN value, and a
  missing key in both shows the `defaultValue`/key.
