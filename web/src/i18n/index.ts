/**
 * i18n bootstrap for the Aegis admin panel.
 *
 * This module is the SINGLE source of i18next configuration. It is imported
 * for its side effect (i18next.init) from src/main.tsx before the app renders.
 *
 * ───────────────────────────────────────────────────────────────────────────
 *  HOW TRANSLATIONS ARE LOADED — page agents NEVER edit this file.
 * ───────────────────────────────────────────────────────────────────────────
 *  Every JSON file under ./locales is auto-registered via Vite's glob import.
 *  A path like  ./locales/ru/dashboard.json  becomes:
 *      resources.ru.dashboard = { ...the JSON... }
 *  i.e. the directory after `locales/` is the LANGUAGE and the filename
 *  (without .json) is the NAMESPACE.
 *
 *  To add a page namespace, just drop:
 *      src/i18n/locales/ru/<ns>.json
 *      src/i18n/locales/en/<ns>.json
 *  The glob picks them up automatically — see CONVENTION.md.
 */

import i18n from "i18next";
import { initReactI18next } from "react-i18next";
import LanguageDetector from "i18next-browser-languagedetector";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

export const SUPPORTED_LNGS = ["ru", "en"] as const;
export type SupportedLng = (typeof SUPPORTED_LNGS)[number];

export const DEFAULT_LNG: SupportedLng = "ru";
export const FALLBACK_LNG: SupportedLng = "en";

/** localStorage key holding the user's chosen language. */
export const LANG_STORAGE_KEY = "aegis-lang";

// ---------------------------------------------------------------------------
// Auto-register every namespace JSON via Vite glob.
// ---------------------------------------------------------------------------
//
// `eager: true`           → modules are bundled synchronously (no async chunk).
// `import: 'default'`      → we get the parsed JSON object directly.
//
const mods = import.meta.glob("./locales/**/*.json", {
    eager: true,
    import: "default",
}) as Record<string, Record<string, string>>;

type Resources = Record<string, Record<string, Record<string, string>>>;

const resources: Resources = {};

for (const [filePath, json] of Object.entries(mods)) {
    // filePath looks like "./locales/ru/dashboard.json"
    const match = filePath.match(/\.\/locales\/([^/]+)\/(.+)\.json$/);
    if (!match) continue;
    const [, lng, ns] = match;
    if (!lng || !ns) continue;
    (resources[lng] ??= {})[ns] = json;
}

// ---------------------------------------------------------------------------
// Resolve the initial language.
// ---------------------------------------------------------------------------
//
// LanguageDetector reads localStorage first, then navigator. We deliberately
// FORCE the default to RU when nothing has been stored yet, regardless of the
// browser's navigator language — the panel ships RU-first.
//
function readStoredLng(): SupportedLng | null {
    try {
        const raw = localStorage.getItem(LANG_STORAGE_KEY);
        if (raw && (SUPPORTED_LNGS as readonly string[]).includes(raw)) {
            return raw as SupportedLng;
        }
    } catch {
        /* localStorage unavailable (private mode / SSR) — ignore. */
    }
    return null;
}

const storedLng = readStoredLng();
const initialLng: SupportedLng = storedLng ?? DEFAULT_LNG;

void i18n
    .use(LanguageDetector)
    .use(initReactI18next)
    .init({
        resources,
        // Force RU when no stored preference; otherwise honour the stored one.
        lng: initialLng,
        fallbackLng: FALLBACK_LNG,
        supportedLngs: SUPPORTED_LNGS as unknown as string[],
        defaultNS: "common",
        fallbackNS: "common",
        detection: {
            order: ["localStorage", "navigator"],
            lookupLocalStorage: LANG_STORAGE_KEY,
            caches: ["localStorage"],
        },
        interpolation: {
            // React already escapes output.
            escapeValue: false,
        },
        react: {
            useSuspense: false,
        },
    });

// ---------------------------------------------------------------------------
// Keep <html lang> in sync + persist the chosen language.
// ---------------------------------------------------------------------------

function syncHtmlLang(lng: string) {
    if (typeof document !== "undefined") {
        document.documentElement.setAttribute("lang", lng);
    }
}

syncHtmlLang(i18n.language || initialLng);

i18n.on("languageChanged", (lng) => {
    syncHtmlLang(lng);
    try {
        localStorage.setItem(LANG_STORAGE_KEY, lng);
    } catch {
        /* ignore persistence failures */
    }
});

export default i18n;
