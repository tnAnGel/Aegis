/**
 * V2 SiteMap pages — /v2/site-map and /v2/site-map/:host
 *
 * Host list cross-references sitesApi.list() to tag each observed host as
 * either "Configured" (matches a site in /admin/api/sites) or "Referring"
 * (an external domain/IP that resolves to this proxy but is NOT configured
 * as a site — shown with an amber "referring · unconfigured" badge).
 *
 * Exports two named components (matching V1 pattern):
 *   SiteMapHostsV2Page  — host list (/v2/site-map)
 *   SiteMapHostV2Page   — endpoint table (/v2/site-map/:host)
 */

import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import { Link, useRouterState } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import {
    ChevronLeft,
    ChevronRight,
    Globe2,
    Map as MapIcon,
    RefreshCw,
    Search,
    ShieldCheck,
    AlertTriangle,
    ArrowUpDown,
    ArrowDown,
    ArrowUp,
    ScrollText,
} from "lucide-react";
import {
    siteMapApi,
    sitesApi,
    type SiteMapEndpoint,
    type SiteMapHostEntry,
} from "@/api/client";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { ErrorState } from "@/components/ErrorState";
import { EmptyState } from "@/components/EmptyState";
import { MetricCard } from "@/v2/components/MetricCard";
import { cn } from "@/lib/cn";

// ─── Helpers ─────────────────────────────────────────────────────────────────

function relativeTime(unixSecs: number, t: TFunction): string {
    if (unixSecs === 0) return t("time.never");
    const now = Math.floor(Date.now() / 1000);
    const delta = now - unixSecs;
    if (delta < 60) return t("time.secondsAgo", { count: delta });
    if (delta < 3600) return t("time.minutesAgo", { count: Math.floor(delta / 60) });
    if (delta < 86400) return t("time.hoursAgo", { count: Math.floor(delta / 3600) });
    return t("time.daysAgo", { count: Math.floor(delta / 86400) });
}

// V2-flavoured method badge colours (dark-teal palette)
function methodBadgeClass(method: string): string {
    switch (method.toUpperCase()) {
        case "GET":    return "bg-blue-500/15 text-blue-400 border-blue-500/30";
        case "POST":   return "bg-green-500/15 text-green-400 border-green-500/30";
        case "PUT":
        case "PATCH":  return "bg-amber-500/15 text-amber-400 border-amber-500/30";
        case "DELETE": return "bg-red-500/15 text-red-400 border-red-500/30";
        default:       return "bg-muted/40 text-muted-foreground border-border/60";
    }
}

function MethodBadge({ method }: { method: string }) {
    return (
        <span
            className={cn(
                "inline-flex items-center rounded-md px-1.5 py-0.5 text-[0.65rem]",
                "font-mono font-bold uppercase tracking-wider border",
                methodBadgeClass(method),
            )}
        >
            {method.toUpperCase()}
        </span>
    );
}

// Segmented status bar (2xx/3xx/4xx/5xx)
function StatusBar({ e, t }: { e: SiteMapEndpoint; t: TFunction }) {
    const total = e.status_2xx + e.status_3xx + e.status_4xx + e.status_5xx;
    if (total === 0) {
        return <span className="text-xs text-muted-foreground/60 italic">{t("statusBar.noData")}</span>;
    }
    const segments: Array<{ label: string; count: number; color: string }> = [
        { label: "2xx", count: e.status_2xx, color: "bg-green-500" },
        { label: "3xx", count: e.status_3xx, color: "bg-blue-500" },
        { label: "4xx", count: e.status_4xx, color: "bg-amber-500" },
        { label: "5xx", count: e.status_5xx, color: "bg-red-500" },
    ];
    return (
        <div className="flex h-2 w-28 rounded overflow-hidden border border-border/50">
            {segments.map(({ label, count, color }) => {
                const pct = (count / total) * 100;
                if (pct < 0.5) return null;
                return (
                    <div
                        key={label}
                        className={color}
                        style={{ width: `${pct}%` }}
                        title={`${label}: ${count} (${pct.toFixed(1)}%)`}
                    />
                );
            })}
        </div>
    );
}

// Badge for configured vs referring/discovered hosts
function HostTypeBadge({ configured, t }: { configured: boolean; t: TFunction }) {
    if (configured) {
        return (
            <span
                className={cn(
                    "inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-[0.65rem]",
                    "font-semibold uppercase tracking-wider border",
                    "bg-green-500/15 text-green-400 border-green-500/30",
                )}
                title={t("badge.configuredTitle")}
            >
                <ShieldCheck className="h-2.5 w-2.5" />
                {t("badge.configured")}
            </span>
        );
    }
    return (
        <span
            className={cn(
                "inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-[0.65rem]",
                "font-semibold uppercase tracking-wider border",
                "bg-amber-500/15 text-amber-400 border-amber-500/30",
            )}
            title={t("badge.referringTitle")}
        >
            <AlertTriangle className="h-2.5 w-2.5" />
            {t("badge.referring")}
        </span>
    );
}

type SortField = "host" | "hits" | "last_seen";
type SortDir = "asc" | "desc";

function SortButton({
    field,
    current,
    dir,
    onClick,
    children,
}: {
    field: SortField;
    current: SortField;
    dir: SortDir;
    onClick: () => void;
    children: React.ReactNode;
}) {
    const active = field === current;
    return (
        <button
            onClick={onClick}
            className={cn(
                "inline-flex items-center gap-1 text-[0.65rem] uppercase tracking-wider",
                "transition-colors hover:text-foreground",
                active ? "text-foreground" : "text-muted-foreground",
            )}
        >
            {children}
            {active ? (
                dir === "asc" ? (
                    <ArrowUp className="h-3 w-3" />
                ) : (
                    <ArrowDown className="h-3 w-3" />
                )
            ) : (
                <ArrowUpDown className="h-3 w-3 opacity-40" />
            )}
        </button>
    );
}

// Normalise the host-entries list — if the backend is the legacy shape
// (no host_entries), synthesise minimal entries from the flat hosts[].
function normaliseEntries(
    hosts: string[],
    host_entries?: SiteMapHostEntry[],
): SiteMapHostEntry[] {
    if (host_entries && host_entries.length > 0) return host_entries;
    return hosts.map((h) => ({ host: h, total_hits: 0, last_seen_unix_secs: 0 }));
}

// ─── Host-list page ──────────────────────────────────────────────────────────

export function SiteMapHostsV2Page() {
    const { t } = useTranslation(["sitemap", "common"]);
    const mapQ = useQuery({
        queryKey: ["site_map", "hosts"],
        queryFn: siteMapApi.hosts,
        refetchInterval: 10_000,
    });

    const sitesQ = useQuery({
        queryKey: ["sites"],
        queryFn: sitesApi.list,
        // Stable reference — we don't need to refetch aggressively
        staleTime: 30_000,
    });

    const [search, setSearch] = useState("");
    const [sortField, setSortField] = useState<SortField>("hits");
    const [sortDir, setSortDir] = useState<SortDir>("desc");

    // Build the set of configured host names for O(1) lookup
    const configuredHosts = useMemo(() => {
        const s = new Set<string>();
        for (const site of sitesQ.data ?? []) s.add(site.host);
        return s;
    }, [sitesQ.data]);

    // Normalise to host entries with the new fields
    const entries = useMemo(() => {
        if (!mapQ.data) return [];
        return normaliseEntries(mapQ.data.hosts, mapQ.data.host_entries);
    }, [mapQ.data]);

    // Filter + sort
    const processed = useMemo(() => {
        let rows = entries;
        if (search.trim()) {
            const needle = search.toLowerCase();
            rows = rows.filter((e) => e.host.toLowerCase().includes(needle));
        }
        return rows.slice().sort((a, b) => {
            let cmp = 0;
            if (sortField === "host") cmp = a.host.localeCompare(b.host);
            else if (sortField === "hits") cmp = a.total_hits - b.total_hits;
            else if (sortField === "last_seen") cmp = a.last_seen_unix_secs - b.last_seen_unix_secs;
            return sortDir === "asc" ? cmp : -cmp;
        });
    }, [entries, search, sortField, sortDir]);

    function toggleSort(field: SortField) {
        if (sortField === field) {
            setSortDir((d) => (d === "asc" ? "desc" : "asc"));
        } else {
            setSortField(field);
            setSortDir("desc");
        }
    }

    const configuredCount = processed.filter((e) => configuredHosts.has(e.host)).length;
    const referringCount  = processed.length - configuredCount;

    return (
        <div className="space-y-6">
            {/* Page heading */}
            <div>
                <h1 className="text-2xl font-bold tracking-tight text-foreground flex items-center gap-2.5">
                    <MapIcon className="h-6 w-6 text-primary" />
                    {t("title")}
                </h1>
                <p className="text-sm text-muted-foreground mt-1 max-w-2xl">
                    {t("hosts.description", { example: "/users/12345", pattern: "/users/:id" })}
                </p>
            </div>

            {/* Loading skeleton */}
            {mapQ.isLoading && (
                <div className="space-y-3">
                    <Skeleton className="h-12 w-full rounded-xl" />
                    <Skeleton className="h-12 w-full rounded-xl" />
                    <Skeleton className="h-12 w-full rounded-xl" />
                </div>
            )}

            {/* Error */}
            {mapQ.error && (
                <ErrorState title={t("loadError")} error={mapQ.error} />
            )}

            {/* Empty state */}
            {mapQ.data && mapQ.data.hosts.length === 0 && (
                <MetricCard title={t("discoveredHosts")}>
                    <EmptyState
                        icon={<MapIcon className="h-8 w-8" />}
                        title={t("empty.title")}
                        description={t("empty.description")}
                    />
                </MetricCard>
            )}

            {/* Host list */}
            {mapQ.data && mapQ.data.hosts.length > 0 && (
                <>
                    {/* Summary callout */}
                    <div className="flex flex-wrap gap-3 items-start">
                        <div className="flex-1 min-w-0 rounded-lg border border-border/60 bg-card/40 px-4 py-3 space-y-1">
                            <p className="text-xs text-muted-foreground uppercase tracking-wider font-semibold">
                                {t("summary.heading")}
                            </p>
                            <p className="text-sm text-muted-foreground leading-snug max-w-2xl">
                                <span className="text-foreground font-medium">{t("summary.configured", { count: configuredCount })}</span>{" "}
                                {t("summary.site", { count: configuredCount })}{" "}
                                {t("summary.areProxied")}
                                {referringCount > 0 && (
                                    <>
                                        {" "}
                                        <span className="text-amber-400 font-medium">{t("summary.referring", { count: referringCount })}</span>{" "}
                                        {t("summary.host", { count: referringCount })}{" "}
                                        {t("summary.referringTail")}
                                    </>
                                )}
                            </p>
                        </div>
                    </div>

                    <MetricCard
                        title={t("discoveredHosts")}
                        description={`${t("hostsCount", { count: entries.length, shown: processed.length, total: entries.length })} · ${t("endpointsTotal", { count: mapQ.data.total_endpoints })}`}
                        noPadding
                        action={
                            <Button
                                variant="ghost"
                                size="sm"
                                onClick={() => mapQ.refetch()}
                                disabled={mapQ.isFetching}
                                className="flex items-center gap-1.5 h-7 text-xs"
                            >
                                <RefreshCw
                                    className={cn("h-3.5 w-3.5", mapQ.isFetching && "animate-spin")}
                                />
                                {t("refresh", { ns: "common" })}
                            </Button>
                        }
                    >
                        {/* Search */}
                        <div className="px-5 pt-3 pb-2 border-b border-border/40">
                            <div className="relative max-w-sm">
                                <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground/60" />
                                <Input
                                    placeholder={t("filterHosts")}
                                    value={search}
                                    onChange={(e) => setSearch(e.target.value)}
                                    className="pl-8 font-mono text-xs bg-background/60 border-border/60 h-8"
                                    aria-label={t("filterHostsAria")}
                                />
                            </div>
                        </div>

                        {/* Table */}
                        <Table className="text-xs">
                            <TableHeader>
                                <TableRow className="border-b border-border/60 hover:bg-transparent">
                                    <TableHead className="px-5 py-2 text-muted-foreground">
                                        <SortButton
                                            field="host"
                                            current={sortField}
                                            dir={sortDir}
                                            onClick={() => toggleSort("host")}
                                        >
                                            {t("col.host")}
                                        </SortButton>
                                    </TableHead>
                                    <TableHead className="px-3 py-2 w-36 text-muted-foreground">
                                        {t("col.status")}
                                    </TableHead>
                                    <TableHead className="px-3 py-2 w-24 text-right text-muted-foreground">
                                        <SortButton
                                            field="hits"
                                            current={sortField}
                                            dir={sortDir}
                                            onClick={() => toggleSort("hits")}
                                        >
                                            {t("col.totalHits")}
                                        </SortButton>
                                    </TableHead>
                                    <TableHead className="px-5 py-2 w-28 text-muted-foreground">
                                        <SortButton
                                            field="last_seen"
                                            current={sortField}
                                            dir={sortDir}
                                            onClick={() => toggleSort("last_seen")}
                                        >
                                            {t("col.lastSeen")}
                                        </SortButton>
                                    </TableHead>
                                    <TableHead className="px-5 py-2 w-10 text-muted-foreground" />
                                </TableRow>
                            </TableHeader>
                            <TableBody>
                                {processed.length === 0 && (
                                    <TableRow>
                                        <TableCell
                                            colSpan={5}
                                            className="px-5 py-10 text-center text-muted-foreground"
                                        >
                                            {t("noHostsMatch")}
                                        </TableCell>
                                    </TableRow>
                                )}
                                {processed.map((entry) => {
                                    const isConfigured = configuredHosts.has(entry.host);
                                    return (
                                        <TableRow key={entry.host} className="v2-table-row group">
                                            <TableCell className="px-5 py-3">
                                                <Link
                                                    to="/site-map/$host"
                                                    params={{ host: entry.host }}
                                                    className="flex items-center gap-2 hover:text-primary transition-colors"
                                                >
                                                    <Globe2 className="h-3.5 w-3.5 text-muted-foreground group-hover:text-primary transition-colors shrink-0" />
                                                    <span className="font-mono text-sm text-foreground group-hover:text-primary transition-colors">
                                                        {entry.host}
                                                    </span>
                                                </Link>
                                            </TableCell>
                                            <TableCell className="px-3 py-3">
                                                <HostTypeBadge configured={isConfigured} t={t} />
                                            </TableCell>
                                            <TableCell className="px-3 py-3 text-right v2-table-num font-mono">
                                                {entry.total_hits > 0
                                                    ? entry.total_hits.toLocaleString()
                                                    : <span className="text-muted-foreground/50 text-xs">—</span>
                                                }
                                            </TableCell>
                                            <TableCell className="px-5 py-3 text-muted-foreground">
                                                {entry.last_seen_unix_secs > 0
                                                    ? relativeTime(entry.last_seen_unix_secs, t)
                                                    : <span className="text-muted-foreground/50 text-xs italic">{t("time.never")}</span>
                                                }
                                            </TableCell>
                                            <TableCell className="px-5 py-3">
                                                <Link
                                                    to="/site-map/$host"
                                                    params={{ host: entry.host }}
                                                    aria-label={t("viewEndpointsAria", { host: entry.host })}
                                                >
                                                    <ChevronRight className="h-4 w-4 text-muted-foreground/40 group-hover:text-primary transition-colors" />
                                                </Link>
                                            </TableCell>
                                        </TableRow>
                                    );
                                })}
                            </TableBody>
                        </Table>
                    </MetricCard>

                    <p className="text-[0.7rem] text-muted-foreground/60 italic px-1">
                        {t("hosts.footnote")}
                    </p>
                </>
            )}
        </div>
    );
}

// ─── Per-host endpoint table ──────────────────────────────────────────────────

export function SiteMapHostV2Page() {
    const { t } = useTranslation(["sitemap", "common"]);
    const state = useRouterState();
    const host =
        (state.location.pathname.match(/\/site-map\/(.+)$/)?.[1]) ?? "";
    const [filter, setFilter] = useState("");

    const q = useQuery({
        queryKey: ["site_map", "host", host],
        queryFn: () => siteMapApi.forHost(host),
        refetchInterval: 10_000,
    });

    // Cross-reference with configured sites to show appropriate badge
    const sitesQ = useQuery({
        queryKey: ["sites"],
        queryFn: sitesApi.list,
        staleTime: 30_000,
    });

    const isConfigured = useMemo(
        () => (sitesQ.data ?? []).some((s) => s.host === host),
        [sitesQ.data, host],
    );

    const filtered = useMemo(() => {
        const eps = q.data?.endpoints ?? [];
        if (!filter.trim()) return eps;
        const needle = filter.toLowerCase();
        return eps.filter(
            (e) =>
                e.method.toLowerCase().includes(needle) ||
                e.path_pattern.toLowerCase().includes(needle),
        );
    }, [q.data, filter]);

    // Sort endpoints by hits descending by default
    const sorted = useMemo(
        () => filtered.slice().sort((a, b) => b.hits - a.hits),
        [filtered],
    );

    return (
        <div className="space-y-6">
            {/* Back link */}
            <div>
                <Link
                    to="/site-map"
                    className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground transition-colors"
                >
                    <ChevronLeft className="h-4 w-4" />
                    {t("allHosts")}
                </Link>
            </div>

            {/* Page heading */}
            <div className="flex items-start justify-between gap-4 flex-wrap">
                <div>
                    <h1 className="text-2xl font-bold tracking-tight text-foreground flex items-center gap-2.5 flex-wrap">
                        <Globe2 className="h-6 w-6 text-primary" />
                        {host || t("title")}
                        {sitesQ.data && (
                            <HostTypeBadge configured={isConfigured} t={t} />
                        )}
                    </h1>
                    <p className="text-sm text-muted-foreground mt-1 max-w-xl">
                        {isConfigured
                            ? t("host.descConfigured", { host })
                            : t("host.descReferring", { host })}
                    </p>
                </div>

                <Button
                    variant="outline"
                    size="sm"
                    onClick={() => q.refetch()}
                    disabled={q.isFetching}
                    className="shrink-0 flex items-center gap-1.5"
                >
                    <RefreshCw
                        className={cn(
                            "h-3.5 w-3.5",
                            q.isFetching && "animate-spin",
                        )}
                    />
                    {t("refresh", { ns: "common" })}
                </Button>
            </div>

            {/* Filter bar */}
            <MetricCard title={t("filterEndpoints.title")} contentClassName="py-3">
                <div className="flex items-center gap-2 max-w-sm">
                    <div className="relative flex-1">
                        <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground/60" />
                        <Input
                            placeholder={t("filterEndpoints.placeholder")}
                            value={filter}
                            onChange={(e) => setFilter(e.target.value)}
                            className="pl-8 font-mono text-xs bg-background/60 border-border/60"
                            aria-label={t("filterEndpoints.aria")}
                        />
                    </div>
                </div>
            </MetricCard>

            {/* Loading */}
            {q.isLoading && <Skeleton className="h-48 rounded-xl" />}

            {/* Error */}
            {q.error && (
                <ErrorState title={t("loadEndpointsError")} error={q.error} />
            )}

            {/* Empty state — no endpoints at all for this host */}
            {q.data && q.data.endpoints.length === 0 && (
                <MetricCard title={t("endpointMap.title")}>
                    <EmptyState
                        icon={<Globe2 className="h-8 w-8" />}
                        title={t("endpointMap.emptyTitle")}
                        description={t("endpointMap.emptyDesc")}
                    />
                </MetricCard>
            )}

            {/* Endpoint table */}
            {q.data && q.data.endpoints.length > 0 && (
                <MetricCard
                    title={t("endpointMap.title")}
                    description={
                        filtered.length !== (q.data.endpoints?.length ?? 0)
                            ? t("endpointMap.filtered", { shown: filtered.length, total: q.data.endpoints?.length ?? 0 })
                            : t("endpointMap.discovered", { count: filtered.length })
                    }
                    noPadding
                >
                    <Table className="text-xs">
                        <TableHeader>
                            <TableRow className="border-b border-border/60 hover:bg-transparent">
                                <TableHead className="px-5 py-2.5 w-24 text-muted-foreground text-[0.65rem] uppercase tracking-wider">
                                    {t("col.method")}
                                </TableHead>
                                <TableHead className="px-3 py-2.5 text-muted-foreground text-[0.65rem] uppercase tracking-wider">
                                    {t("col.pathPattern")}
                                </TableHead>
                                <TableHead className="px-3 py-2.5 w-20 text-right text-muted-foreground text-[0.65rem] uppercase tracking-wider">
                                    {t("col.hits")}
                                </TableHead>
                                <TableHead className="px-3 py-2.5 w-36 text-muted-foreground text-[0.65rem] uppercase tracking-wider">
                                    {t("col.statusMix")}
                                </TableHead>
                                <TableHead className="px-5 py-2.5 w-28 text-muted-foreground text-[0.65rem] uppercase tracking-wider">
                                    {t("col.lastSeen")}
                                </TableHead>
                                <TableHead className="px-5 py-2.5 w-20 text-right text-muted-foreground text-[0.65rem] uppercase tracking-wider">
                                    {t("col.logs", { defaultValue: "Логи" })}
                                </TableHead>
                            </TableRow>
                        </TableHeader>
                        <TableBody>
                            {sorted.length === 0 && (
                                <TableRow>
                                    <TableCell
                                        colSpan={6}
                                        className="px-5 py-10 text-center text-muted-foreground"
                                    >
                                        {t("noEndpointsMatch")}
                                    </TableCell>
                                </TableRow>
                            )}
                            {sorted.map((e) => (
                                <TableRow
                                    key={`${e.method}-${e.path_pattern}`}
                                    className="v2-table-row"
                                >
                                    <TableCell className="px-5 py-2.5">
                                        <MethodBadge method={e.method} />
                                    </TableCell>
                                    <TableCell className="px-3 py-2.5 font-mono break-all text-foreground/90">
                                        {e.path_pattern || "/"}
                                    </TableCell>
                                    <TableCell className="px-3 py-2.5 text-right v2-table-num font-mono">
                                        {e.hits.toLocaleString()}
                                    </TableCell>
                                    <TableCell className="px-3 py-2.5">
                                        <StatusBar e={e} t={t} />
                                    </TableCell>
                                    <TableCell className="px-5 py-2.5 text-muted-foreground">
                                        {relativeTime(e.last_seen_unix_secs, t)}
                                    </TableCell>
                                    <TableCell className="px-5 py-2.5 text-right">
                                        <Button
                                            asChild
                                            variant="ghost"
                                            size="sm"
                                            className="h-7 text-[0.65rem] gap-1.5 text-muted-foreground hover:text-primary"
                                        >
                                            <Link
                                                to="/logs"
                                                search={{ host, endpoint: e.path_pattern }}
                                                aria-label={t("viewLogsAria", {
                                                    defaultValue: "Логи для {{endpoint}}",
                                                    endpoint: e.path_pattern || "/",
                                                })}
                                            >
                                                <ScrollText className="h-3.5 w-3.5" />
                                                {t("col.logs", { defaultValue: "Логи" })}
                                            </Link>
                                        </Button>
                                    </TableCell>
                                </TableRow>
                            ))}
                        </TableBody>
                    </Table>
                </MetricCard>
            )}
        </div>
    );
}
