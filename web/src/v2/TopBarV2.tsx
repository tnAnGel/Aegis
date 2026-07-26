/**
 * TopBarV2
 *
 * V2-styled top application bar. Layout (left → right):
 *
 *   [Hamburger]  [Page title / Welcome]  ─── spacer ───
 *   [Bell + badge]  [System status pill]  [Avatar + name + role + chevron]
 *
 * Data sources:
 *   - useAuth()       → email + auth type (username / role display)
 *   - runtimeApi      → queried every 10 s; drives the status pill colour
 *
 * The hamburger triggers the `onToggleSidebar` callback owned by
 * AppLayoutV2 so that sidebar collapsed state stays in the parent.
 *
 * The avatar dropdown is cosmetic only for now (logout button via the
 * existing useAuth().logout() API).
 */

import { useState, useRef, useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import {
    Bell,
    ChevronDown,
    LogOut,
    CheckCircle2,
    AlertTriangle,
    AlertCircle,
    Globe,
    Check,
} from "lucide-react";
import { cn } from "@/lib/cn";
import { useAuth } from "@/hooks/useAuth";
import { runtimeApi } from "@/api/client";
import { SUPPORTED_LNGS } from "@/i18n";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Derive a display-friendly username from an email address.
 * "alice@example.com" → "Alice"
 *
 * NULL-SAFE: the auth state types `email` as a non-optional string, but the
 * backend's /me (and login) responses can transiently omit it — e.g. right
 * after a deploy/rolling-restart when the browser's existing session hits a
 * just-restarted worker. A missing display name must NEVER crash the whole
 * admin (the old `email.split(...)` threw "undefined is not an object").
 */
function displayName(email: string | null | undefined): string {
    const e = email ?? "";
    const local = e.split("@")[0] || e || "user";
    return local.charAt(0).toUpperCase() + local.slice(1);
}

/** Initials for the avatar circle — up to 2 chars. NULL-SAFE (see displayName). */
function initials(email: string | null | undefined): string {
    const e = email ?? "";
    const local = e.split("@")[0] ?? "";
    const parts = local.split(/[._\-]/).filter(Boolean);
    if (parts.length >= 2 && parts[0] && parts[1]) {
        return (parts[0][0]! + parts[1][0]!).toUpperCase();
    }
    return (e.slice(0, 2) || "U").toUpperCase();
}

// ---------------------------------------------------------------------------
// System-status pill
// ---------------------------------------------------------------------------

type SystemStatus = "ok" | "warn" | "error" | "loading";

interface StatusPillProps {
    status: SystemStatus;
    sitesCount?: number;
    uptimeSec?: number;
}

function StatusPill({ status, sitesCount, uptimeSec }: StatusPillProps) {
    const { t } = useTranslation("topbar");
    const uptimeMin = Math.floor((uptimeSec ?? 0) / 60);

    if (status === "loading") {
        return (
            <span className="v2-status-pill-warn">
                <span className="inline-block h-1.5 w-1.5 rounded-full bg-current animate-pulse" />
                {t("status.connecting")}
            </span>
        );
    }

    if (status === "error") {
        return (
            <span className="v2-status-pill-error">
                <AlertCircle className="h-3 w-3" />
                {t("status.offline")}
            </span>
        );
    }

    if (status === "warn") {
        return (
            <span className="v2-status-pill-warn">
                <AlertTriangle className="h-3 w-3" />
                {t("status.degraded")}
            </span>
        );
    }

    return (
        <span className="v2-status-pill-ok">
            <CheckCircle2 className="h-3 w-3" />
            {t("status.operational")}
            {sitesCount !== undefined && (
                <span className="opacity-70">
                    {" "}· {t("status.site", { count: sitesCount })}
                    {uptimeMin > 0 ? ` · ${t("status.uptime", { minutes: uptimeMin })}` : ""}
                </span>
            )}
        </span>
    );
}

// ---------------------------------------------------------------------------
// Avatar dropdown
// ---------------------------------------------------------------------------

interface AvatarMenuProps {
    // May be absent at runtime even when logged in (see displayName) — null-safe.
    email: string | null | undefined;
    onLogout: () => void;
}

function AvatarMenu({ email, onLogout }: AvatarMenuProps) {
    const { t } = useTranslation("topbar");
    const [open, setOpen] = useState(false);
    const ref = useRef<HTMLDivElement>(null);

    // Close on outside click
    useEffect(() => {
        function handler(e: MouseEvent) {
            if (ref.current && !ref.current.contains(e.target as Node)) {
                setOpen(false);
            }
        }
        if (open) document.addEventListener("mousedown", handler);
        return () => document.removeEventListener("mousedown", handler);
    }, [open]);

    const name = displayName(email);
    const abbr = initials(email);

    return (
        <div ref={ref} className="relative">
            <button
                onClick={() => setOpen((v) => !v)}
                aria-haspopup="true"
                aria-expanded={open}
                className={cn(
                    "flex items-center gap-2 rounded-lg px-2.5 py-1.5",
                    "hover:bg-accent/60 transition-colors duration-150",
                    "text-sm text-foreground",
                )}
            >
                {/* Avatar circle */}
                <span
                    className={cn(
                        "inline-flex h-7 w-7 rounded-full items-center justify-center",
                        "bg-primary/20 text-primary text-[0.65rem] font-semibold shrink-0 ring-1 ring-primary/30",
                    )}
                    aria-hidden="true"
                >
                    {abbr}
                </span>

                <span className="hidden sm:flex flex-col items-start leading-tight min-w-0">
                    <span className="font-medium text-xs text-foreground truncate max-w-[8rem]">
                        {name}
                    </span>
                    <span className="text-[0.6rem] text-muted-foreground uppercase tracking-wider">
                        admin
                    </span>
                </span>

                <ChevronDown
                    className={cn(
                        "h-3.5 w-3.5 text-muted-foreground transition-transform duration-150 hidden sm:block",
                        open ? "rotate-180" : "",
                    )}
                />
            </button>

            {/* Dropdown panel */}
            {open && (
                <div
                    className={cn(
                        "absolute right-0 top-full mt-1 z-50",
                        "w-52 rounded-xl border border-border bg-popover",
                        "shadow-lg py-1",
                    )}
                    style={{ boxShadow: "var(--v2-card-shadow)" }}
                >
                    {/* User info header */}
                    <div className="px-3 py-2.5 border-b border-border">
                        <div className="flex items-center gap-2.5">
                            <span
                                className={cn(
                                    "inline-flex h-8 w-8 rounded-full items-center justify-center",
                                    "bg-primary/20 text-primary text-[0.7rem] font-semibold shrink-0",
                                )}
                            >
                                {abbr}
                            </span>
                            <div className="min-w-0">
                                <div className="text-sm font-medium text-foreground truncate">
                                    {name}
                                </div>
                                <div className="text-[0.65rem] text-muted-foreground truncate">
                                    {email ?? ""}
                                </div>
                            </div>
                        </div>
                    </div>

                    {/* Actions */}
                    <button
                        onClick={() => {
                            setOpen(false);
                            onLogout();
                        }}
                        className={cn(
                            "flex w-full items-center gap-2.5 px-3 py-2 text-sm",
                            "text-muted-foreground hover:text-foreground hover:bg-accent/60",
                            "transition-colors duration-150",
                        )}
                    >
                        <LogOut className="h-4 w-4 shrink-0" />
                        {t("signOut")}
                    </button>
                </div>
            )}
        </div>
    );
}

// ---------------------------------------------------------------------------
// Language switcher (globe dropdown)
// ---------------------------------------------------------------------------

const LANG_LABELS: Record<string, string> = {
    ru: "Русский",
    en: "English",
};

function LanguageSwitcher() {
    const { t, i18n } = useTranslation("topbar");
    const [open, setOpen] = useState(false);
    const ref = useRef<HTMLDivElement>(null);

    // Close on outside click.
    useEffect(() => {
        function handler(e: MouseEvent) {
            if (ref.current && !ref.current.contains(e.target as Node)) {
                setOpen(false);
            }
        }
        if (open) document.addEventListener("mousedown", handler);
        return () => document.removeEventListener("mousedown", handler);
    }, [open]);

    // Normalise e.g. "en-US" → "en" for the active-check.
    const current = (i18n.resolvedLanguage || i18n.language || "ru").split("-")[0];

    function choose(lng: string) {
        setOpen(false);
        // changeLanguage triggers the languageChanged handler in i18n/index.ts,
        // which persists to localStorage and syncs <html lang>.
        void i18n.changeLanguage(lng);
    }

    return (
        <div ref={ref} className="relative">
            <button
                onClick={() => setOpen((v) => !v)}
                aria-haspopup="true"
                aria-expanded={open}
                aria-label={t("switchLanguage")}
                title={t("switchLanguage")}
                className={cn(
                    "relative h-8 w-8 flex items-center justify-center rounded-md shrink-0",
                    "text-muted-foreground hover:text-foreground hover:bg-accent/60",
                    "transition-colors duration-150",
                )}
            >
                <Globe className="h-4 w-4" />
            </button>

            {open && (
                <div
                    className={cn(
                        "absolute right-0 top-full mt-1 z-50",
                        "w-40 rounded-xl border border-border bg-popover",
                        "shadow-lg py-1",
                    )}
                    style={{ boxShadow: "var(--v2-card-shadow)" }}
                >
                    {SUPPORTED_LNGS.map((lng) => {
                        const active = lng === current;
                        return (
                            <button
                                key={lng}
                                onClick={() => choose(lng)}
                                aria-current={active ? "true" : undefined}
                                className={cn(
                                    "flex w-full items-center justify-between gap-2.5 px-3 py-2 text-sm",
                                    "transition-colors duration-150",
                                    active
                                        ? "text-foreground bg-accent/40"
                                        : "text-muted-foreground hover:text-foreground hover:bg-accent/60",
                                )}
                            >
                                <span className="flex items-center gap-2">
                                    <span className="uppercase text-[0.6rem] font-semibold tracking-wider opacity-70">
                                        {lng}
                                    </span>
                                    {LANG_LABELS[lng] ?? lng}
                                </span>
                                {active && <Check className="h-3.5 w-3.5 text-primary shrink-0" />}
                            </button>
                        );
                    })}
                </div>
            )}
        </div>
    );
}

// ---------------------------------------------------------------------------
// TopBarV2
// ---------------------------------------------------------------------------

interface TopBarV2Props {
    /**
     * Key into the `nav` namespace for the current page title (e.g.
     * "item.security"). Empty string means "no key — use the fallback".
     */
    pageTitleKey?: string;
    /** Plain-English fallback when {@link pageTitleKey} has no translation. */
    pageTitleFallback?: string;
}

export function TopBarV2({ pageTitleKey, pageTitleFallback }: TopBarV2Props) {
    const { t } = useTranslation("topbar");
    const { t: tNav } = useTranslation("nav");
    const { state: auth, logout } = useAuth();

    const pageTitle = pageTitleKey
        ? tNav(pageTitleKey, { defaultValue: pageTitleFallback ?? pageTitleKey })
        : pageTitleFallback;

    const runtimeStatus = useQuery({
        queryKey: ["runtime", "status"],
        queryFn: () => runtimeApi.status(),
        refetchInterval: 10_000,
        retry: 0,
    });

    const systemStatus: SystemStatus = runtimeStatus.isError
        ? "error"
        : runtimeStatus.isLoading
          ? "loading"
          : "ok";

    // Notification badge — placeholder count (replace with a real query
    // once an /admin/api/alerts endpoint is available).
    const notifCount = 0;

    const email = auth.status === "logged_in" ? auth.email : "";
    const welcomeName = email ? displayName(email) : "";

    return (
        <header
            className={cn(
                "h-14 shrink-0 flex items-center px-4 gap-3",
                "border-b border-border",
                "bg-[hsl(var(--v2-topbar-bg,var(--card)))]",
            )}
        >
            {/* Page title + welcome */}
            <div className="flex flex-col leading-tight min-w-0">
                {pageTitle && (
                    <span className="font-semibold text-sm text-foreground leading-tight truncate">
                        {pageTitle}
                    </span>
                )}
                {welcomeName && (
                    <span className="text-[0.65rem] text-muted-foreground leading-tight">
                        {t("welcomeBack", { name: welcomeName })}
                    </span>
                )}
            </div>

            {/* Spacer */}
            <div className="flex-1" />

            {/* Language switcher (globe) — top-right */}
            <LanguageSwitcher />

            {/* Bell icon with notification badge */}
            <button
                aria-label={
                    notifCount > 0
                        ? t("notificationsUnread", { count: notifCount })
                        : t("notifications")
                }
                className={cn(
                    "relative h-8 w-8 flex items-center justify-center rounded-md shrink-0",
                    "text-muted-foreground hover:text-foreground hover:bg-accent/60",
                    "transition-colors duration-150",
                )}
            >
                <Bell className="h-4 w-4" />
                {notifCount > 0 && (
                    <span
                        className={cn(
                            "absolute -top-0.5 -right-0.5",
                            "h-4 min-w-4 px-0.5 rounded-full",
                            "bg-destructive text-destructive-foreground",
                            "text-[0.55rem] font-bold flex items-center justify-center",
                        )}
                    >
                        {notifCount > 99 ? "99+" : notifCount}
                    </span>
                )}
            </button>

            {/* System status pill */}
            <StatusPill
                status={systemStatus}
                sitesCount={runtimeStatus.data?.sites_count}
                uptimeSec={runtimeStatus.data?.uptime_sec}
            />

            {/* Avatar + name + role dropdown */}
            {auth.status === "logged_in" && (
                <AvatarMenu email={auth.email} onLogout={() => void logout()} />
            )}
        </header>
    );
}
