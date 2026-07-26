/**
 * SidebarV2
 *
 * V2-restyled sidebar. Consumes the same nav-config.ts as V1 so that
 * adding a route in V1 automatically appears here too. Visual differences
 * vs V1:
 *
 *   - Brand block: shield icon in a green-tinted rounded square +
 *     "Aegis" wordmark + "SECURE PROXY" tagline.
 *   - Group labels: small-caps, uppercase, wide-tracked — rendered as a
 *     static label rather than a toggle button (groups are always expanded
 *     but still individually collapsible via chevron for power users).
 *   - Active link: 3 px green left rail + hsl(primary / 8) tint background.
 *   - All icon / spacing tokens derived from the V2 CSS custom properties
 *     declared in tokens.css.
 *
 * Routes in the sidebar point to the V2 equivalents (/v2/*) so that
 * navigation stays inside the V2 shell. The V1 nav-config `to` values
 * are prefixed with "/v2" at render time.
 */

import { useEffect, useState } from "react";
import { Link, useRouterState } from "@tanstack/react-router";
import { useTranslation } from "react-i18next";
import { Shield } from "lucide-react";
import { cn } from "@/lib/cn";
import {
    NAV_GROUPS,
    SETTINGS_ITEM,
    Settings,
    ChevronDown,
    getInitialOpen,
    toggleGroup,
} from "@/components/layout/nav-config";
import type { NavGroup, NavItem } from "@/components/layout/nav-config";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// V2 is the default UI mounted at the router root (basepath /admin/ui), so
// nav links use the nav-config paths AS-IS ("/", "/metrics", ...). The old
// "/v2" prefixing is gone — it 404'd now that there is no /v2 subtree.
const V2_GROUPS: NavGroup[] = NAV_GROUPS;

/** Derive the V2 equivalent of getInitialOpen — uses the V2-prefixed paths. */
function getInitialOpenV2(pathname: string): Set<string> {
    return getInitialOpen(V2_GROUPS, pathname);
}

/** Match the active nav item against the current router pathname. */
function isActive(to: string, pathname: string): boolean {
    if (to === "/") return pathname === "/" || pathname === "";
    return pathname === to || pathname.startsWith(to + "/");
}

// ---------------------------------------------------------------------------
// Sub-component: one collapsible group
// ---------------------------------------------------------------------------

interface V2NavGroupProps {
    group: NavGroup;
    isOpen: boolean;
    onToggle: () => void;
    pathname: string;
    /** Translator bound to the `nav` namespace. */
    t: (key: string, opts?: { defaultValue?: string }) => string;
}

function V2NavGroup({ group, isOpen, onToggle, pathname, t }: V2NavGroupProps) {
    const GroupIcon = group.icon;

    return (
        <div>
            {/* Group header — small-caps label + collapse chevron */}
            <button
                onClick={onToggle}
                aria-expanded={isOpen}
                className={cn(
                    "flex w-full items-center gap-2 px-3 py-1.5 mt-3",
                    "text-[0.62rem] font-semibold uppercase tracking-[0.1em]",
                    "text-muted-foreground hover:text-foreground",
                    "transition-colors duration-150 select-none",
                )}
            >
                <GroupIcon className="h-3 w-3 shrink-0 opacity-70" />
                <span className="flex-1 text-left">
                    {t(group.i18nKey, { defaultValue: group.label })}
                </span>
                <ChevronDown
                    className={cn(
                        "h-3 w-3 transition-transform duration-200",
                        isOpen ? "rotate-180" : "",
                    )}
                />
            </button>

            {/* Animated item list */}
            <div
                className={cn(
                    "overflow-hidden transition-all duration-200",
                    isOpen ? "max-h-[1200px]" : "max-h-0",
                )}
            >
                <div className="mt-0.5 space-y-px pb-1">
                    {group.items.map((item: NavItem) => {
                        const Icon = item.icon;
                        const active = isActive(item.to, pathname);
                        return (
                            <Link
                                key={item.to}
                                to={item.to}
                                aria-current={active ? "page" : undefined}
                                className={cn(
                                    // Base layout
                                    "relative flex items-center gap-2.5 rounded-md px-3 py-1.5 text-sm",
                                    "transition-colors duration-150",
                                    active
                                        ? "v2-nav-active"
                                        : "text-muted-foreground hover:bg-accent/60 hover:text-foreground",
                                )}
                            >
                                <Icon
                                    className={cn(
                                        "h-4 w-4 shrink-0",
                                        active ? "text-primary" : "opacity-60",
                                    )}
                                />
                                <span>{t(item.i18nKey, { defaultValue: item.label })}</span>
                            </Link>
                        );
                    })}
                </div>
            </div>
        </div>
    );
}

// ---------------------------------------------------------------------------
// SidebarV2
// ---------------------------------------------------------------------------

interface SidebarV2Props {
    /** Whether the sidebar is currently visible (controlled by TopBarV2 hamburger). */
    collapsed: boolean;
}

export function SidebarV2({ collapsed }: SidebarV2Props) {
    const { t } = useTranslation("nav");
    const { location } = useRouterState();
    const pathname = location.pathname;

    const [openGroups, setOpenGroups] = useState<Set<string>>(() =>
        getInitialOpenV2(pathname),
    );

    // Force-open the group containing the active route on navigation.
    useEffect(() => {
        setOpenGroups((prev) => {
            const merged = getInitialOpenV2(pathname);
            return new Set([...prev, ...merged]);
        });
    }, [pathname]);

    function handleToggle(id: string) {
        setOpenGroups((prev) => toggleGroup(id, prev));
    }

    const v2SettingsTo = SETTINGS_ITEM.to;
    const settingsActive = isActive(v2SettingsTo, pathname);
    const SettingsIcon = Settings;

    return (
        <aside
            style={{ width: "var(--v2-sidebar-width, 15rem)" }}
            className={cn(
                "shrink-0 flex flex-col overflow-hidden",
                "border-r border-border transition-all duration-300",
                // background uses the V2-specific sidebar token if set,
                // otherwise falls back to bg-card/50
                "bg-[hsl(var(--v2-sidebar-bg,var(--card)))]",
                collapsed ? "w-0 border-r-0" : "",
            )}
        >
            {/* ── Brand block ──────────────────────────────────────────── */}
            <div className="px-4 py-5 border-b border-border flex items-center gap-3 shrink-0">
                {/* Shield icon in green-tinted rounded square */}
                <div
                    className={cn(
                        "h-9 w-9 rounded-lg flex items-center justify-center shrink-0",
                        "bg-primary/15 ring-1 ring-primary/25",
                    )}
                >
                    <Shield className="h-5 w-5 text-primary" />
                </div>

                <div className="leading-tight min-w-0">
                    <div className="font-semibold text-sm text-foreground tracking-tight">
                        Aegis
                    </div>
                    <div
                        className={cn(
                            "text-[0.6rem] font-semibold uppercase tracking-[0.12em]",
                            "text-muted-foreground",
                        )}
                    >
                        Secure Proxy
                    </div>
                </div>
            </div>

            {/* ── Scrollable grouped nav ───────────────────────────────── */}
            <nav className="flex-1 overflow-y-auto px-2 pb-2">
                {V2_GROUPS.map((group) => (
                    <V2NavGroup
                        key={group.id}
                        group={group}
                        isOpen={openGroups.has(group.id)}
                        onToggle={() => handleToggle(group.id)}
                        pathname={pathname}
                        t={t}
                    />
                ))}
            </nav>

            {/* ── Pinned Settings + footer ─────────────────────────────── */}
            <div className="shrink-0">
                <div className="border-t border-border" />
                <div className="px-2 py-2">
                    <Link
                        to={v2SettingsTo}
                        aria-current={settingsActive ? "page" : undefined}
                        className={cn(
                            "relative flex items-center gap-2.5 rounded-md px-3 py-1.5 text-sm",
                            "transition-colors duration-150",
                            settingsActive
                                ? "v2-nav-active"
                                : "text-muted-foreground hover:bg-accent/60 hover:text-foreground",
                        )}
                    >
                        <SettingsIcon
                            className={cn(
                                "h-4 w-4 shrink-0",
                                settingsActive ? "text-primary" : "opacity-60",
                            )}
                        />
                        {t(SETTINGS_ITEM.i18nKey, { defaultValue: SETTINGS_ITEM.label })}
                    </Link>
                </div>

                <div className="border-t border-border px-4 py-3 text-[10px] text-muted-foreground/60 font-mono">
                    <div>aegis admin · v2 preview</div>
                    <div>{import.meta.env.MODE}</div>
                </div>
            </div>
        </aside>
    );
}
