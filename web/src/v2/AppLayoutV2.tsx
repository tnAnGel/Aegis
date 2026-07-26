/**
 * AppLayoutV2
 *
 * Root shell for all /v2/* pages. Responsibilities:
 *
 *   1. Applies data-theme="v2" to <html> on mount and removes it on unmount
 *      so V2 tokens activate exactly while any /v2 route is active.
 *
 *   2. Imports the V2 token stylesheet (tokens.css) once — side-effect import.
 *
 *   3. Lays out the page as a two-column grid:
 *        [SidebarV2 | { TopBarV2 / <Outlet> }]
 *      The sidebar can be collapsed by the hamburger in TopBarV2; the
 *      collapsed state lives here so both components share it.
 *
 *   4. Renders a floating "V2 PREVIEW" pill in the bottom-right corner with
 *      a link back to "/" (the V1 shell) so the operator can compare both
 *      designs side-by-side in separate tabs.
 *
 *   5. Shows the "must change credentials" warning banner (same as V1) so
 *      the security message is never silently suppressed in V2 mode.
 *
 * Usage (set in router.tsx as the parent route component for /v2/*):
 *
 *   const v2Root = createRootRoute({
 *     component: () => <AppLayoutV2><Outlet /></AppLayoutV2>,
 *   });
 *
 * Or via <Outlet /> directly (TanStack Router pattern):
 *
 *   component: AppLayoutV2          ← component renders <Outlet /> internally
 */

import { useEffect } from "react";
import { Link, Outlet, useRouterState } from "@tanstack/react-router";
import { cn } from "@/lib/cn";
import { useAuth } from "@/hooks/useAuth";
import { SidebarV2 } from "./SidebarV2";
import { TopBarV2 } from "./TopBarV2";

// Side-effect import — injects :root[data-theme="v2"] { … } into the document.
import "./styles/tokens.css";

// ---------------------------------------------------------------------------
// Page-title resolution
// ---------------------------------------------------------------------------

/**
 * Map the current pathname's first segment to a key in the `nav` namespace.
 * The TopBar resolves this through t() so the page title is localised. The
 * returned value is the bare key (e.g. "item.security"); the second element is
 * a plain-English fallback used if no translation matches.
 */
function navKeyFromPathname(pathname: string): { key: string; fallback: string } {
    // First path segment after the leading slash (router pathname excludes the
    // /admin/ui basepath), e.g. "/security" -> "security", "/" -> "".
    const seg = pathname.replace(/^\//, "").split("/")[0] ?? "";

    // segment -> { nav-namespace key, English fallback }
    const MAP: Record<string, { key: string; fallback: string }> = {
        "":             { key: "item.dashboard",    fallback: "Dashboard" },
        "metrics":      { key: "item.metrics",      fallback: "Metrics" },
        "sites":        { key: "item.sites",        fallback: "Sites" },
        "site-map":     { key: "item.siteMap",      fallback: "Site map" },
        "upstreams":    { key: "item.upstreams",    fallback: "Upstreams" },
        "certificates": { key: "item.certificates", fallback: "Certificates" },
        "security":     { key: "item.security",     fallback: "Security" },
        "bots":         { key: "item.bots",         fallback: "Bots" },
        "ddos":         { key: "item.ddos",         fallback: "DDoS" },
        "rate-limits":  { key: "item.rateLimits",   fallback: "Rate limits" },
        "reputation":   { key: "item.reputation",   fallback: "Reputation" },
        "geoip":        { key: "item.geoip",        fallback: "GeoIP" },
        "sigma":        { key: "item.sigma",        fallback: "Sigma rules" },
        "arsenal":      { key: "item.arsenal",      fallback: "Defence Arsenal" },
        "challenge":    { key: "item.challenge",    fallback: "Challenge Ladder" },
        "scenarios":    { key: "item.scenarios",    fallback: "Scenarios" },
        "actuators":    { key: "item.actuators",    fallback: "Active actions" },
        "honeypots":    { key: "item.honeypots",    fallback: "Honeypots" },
        "tarpit":       { key: "item.tarpit",       fallback: "Tarpit" },
        "bgp":          { key: "item.bgp",          fallback: "BGP RTBH" },
        "privacy-pass": { key: "item.privacyPass",  fallback: "Privacy Pass" },
        "enrichment":   { key: "item.enrichment",   fallback: "Enrichment" },
        "ml":           { key: "item.ml",           fallback: "ML" },
        "signatures":   { key: "item.signatures",   fallback: "Signature miner" },
        "crowdsec":     { key: "item.crowdsec",     fallback: "CrowdSec" },
        "workers":      { key: "item.workers",      fallback: "Workers" },
        "cluster":      { key: "item.cluster",      fallback: "Cluster" },
        "benchmark":    { key: "item.benchmark",    fallback: "Benchmark" },
        "telemetry":    { key: "item.telemetry",    fallback: "Telemetry" },
        "updates":      { key: "item.updates",      fallback: "Updates" },
        "config":       { key: "item.config",       fallback: "Config editor" },
        "logs":         { key: "item.logs",         fallback: "Audit log" },
        "settings":     { key: "item.settings",     fallback: "Settings" },
    };

    return (
        MAP[seg] ?? {
            key: "",
            fallback: seg.charAt(0).toUpperCase() + seg.slice(1).replace(/-/g, " "),
        }
    );
}

// ---------------------------------------------------------------------------
// AppLayoutV2
// ---------------------------------------------------------------------------

export function AppLayoutV2() {
    const { state } = useAuth();
    const mustChange = state.status === "logged_in" && state.mustChange;

    const { location } = useRouterState();
    const pageTitle = navKeyFromPathname(location.pathname);

    // ── Apply / remove the V2 theme attribute ────────────────────────────
    useEffect(() => {
        const html = document.documentElement;
        html.setAttribute("data-theme", "v2");
        return () => {
            // Only remove if still set to "v2" (another route may have changed it)
            if (html.getAttribute("data-theme") === "v2") {
                html.removeAttribute("data-theme");
            }
        };
    }, []);

    return (
        <div className="flex h-screen overflow-hidden bg-background">
            {/* ── Left: sidebar (always visible) ─────────────────────────── */}
            <SidebarV2 collapsed={false} />

            {/* ── Right: top bar + scrollable content ───────────────────── */}
            <div className="flex-1 flex flex-col overflow-hidden min-w-0">
                <TopBarV2
                    pageTitleKey={pageTitle.key}
                    pageTitleFallback={pageTitle.fallback}
                />

                {/* Credentials-must-change warning — same as V1 */}
                {mustChange && (
                    <div
                        className={cn(
                            "border-b border-destructive/40 bg-destructive/10",
                            "px-4 py-2 text-sm flex items-center justify-between gap-3",
                        )}
                    >
                        <span className="text-destructive-foreground">
                            <strong className="text-destructive">Security warning:</strong>{" "}
                            you are logged in with default installer credentials.
                            Change your email and password immediately.
                        </span>
                        <Link
                            to="/settings"
                            className="underline font-medium text-destructive whitespace-nowrap"
                        >
                            Go to Settings →
                        </Link>
                    </div>
                )}

                {/* Page content */}
                <main className="flex-1 overflow-auto">
                    <div className="container max-w-screen-2xl py-6">
                        <Outlet />
                    </div>
                </main>
            </div>
        </div>
    );
}
