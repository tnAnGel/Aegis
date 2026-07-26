/**
 * V2 DDoS page — /v2/ddos
 *
 * Displays distributed attack targets in the V2 visual language:
 *   - V2-styled page header (ShieldAlert icon + title)
 *   - Summary KPI tiles
 *   - MetricCard wrapping the attack targets table
 *   - SeverityChip (C/H/M/L) from the V2 primitives
 *   - Tabular-nums throughout for numeric columns
 *   - v2-table-row hover styling from tokens.css
 *
 * Two data sources, toggled by the mode switch:
 *   - "Live"       → threatAnalyticsApi.ddos() — real-time, in-memory 5-min window
 *                    (host + path + distinct IPs + total hits per target).
 *   - "Historical" → logsApi.stats({from,to}).top_endpoints — persistent store,
 *                    any selected time range. Distinct-IP attribution is not
 *                    stored per endpoint, so historical rows rank by request
 *                    volume on the busiest path patterns.
 * V1 files are NOT imported.
 */

import * as React from "react";
import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import {
    Activity,
    Clock,
    Globe,
    Network,
    ShieldAlert,
    Radio,
    History,
    Hash,
} from "lucide-react";
import {
    threatAnalyticsApi,
    logsApi,
    type DdosTarget,
    type LogStatBucket,
} from "@/api/client";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState } from "@/components/ErrorState";
import { MetricCard } from "@/v2/components/MetricCard";
import { SeverityChip, type Severity } from "@/v2/components/SeverityChip";
import { SectionHeader } from "@/v2/components/SectionHeader";
import {
    Select,
    SelectContent,
    SelectItem,
    SelectTrigger,
    SelectValue,
} from "@/components/ui/select";
import { Input } from "@/components/ui/input";

// ─── Time range model (shared shape with the Bots page) ────────────────────────

type RangeKey = "1h" | "6h" | "24h" | "7d" | "30d" | "custom";

const RANGE_MS: Record<Exclude<RangeKey, "custom">, number> = {
    "1h": 3_600_000,
    "6h": 6 * 3_600_000,
    "24h": 24 * 3_600_000,
    "7d": 7 * 24 * 3_600_000,
    "30d": 30 * 24 * 3_600_000,
};

const DEFAULT_RANGE: RangeKey = "24h";

function toLocalInput(ms: number): string {
    const d = new Date(ms - new Date().getTimezoneOffset() * 60_000);
    return d.toISOString().slice(0, 16);
}
function fromLocalInput(v: string): number | undefined {
    if (!v) return undefined;
    const ms = new Date(v).getTime();
    return Number.isNaN(ms) ? undefined : ms;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function relativeTime(unixSecs: number, t: TFunction): string {
    if (unixSecs === 0) return t("time.never");
    const delta = Math.floor(Date.now() / 1000) - unixSecs;
    if (delta < 60) return t("time.secondsAgo", { n: delta });
    if (delta < 3600) return t("time.minutesAgo", { n: Math.floor(delta / 60) });
    if (delta < 86400) return t("time.hoursAgo", { n: Math.floor(delta / 3600) });
    return t("time.daysAgo", { n: Math.floor(delta / 86400) });
}

function severityFromIps(n: number): Severity {
    if (n >= 500) return "critical";
    if (n >= 100) return "high";
    if (n >= 30) return "medium";
    return "low";
}

/** Maps severity → V2 border-left accent color (used on table rows). */
function severityBorderColor(sev: Severity): string {
    switch (sev) {
        case "critical": return "var(--v2-severity-critical, #ef4444)";
        case "high":     return "var(--v2-severity-high, #f59e0b)";
        case "medium":   return "var(--v2-severity-medium, #eab308)";
        case "low":      return "var(--v2-severity-low, #60a5fa)";
    }
}

// ─── Live table row ────────────────────────────────────────────────────────────

function DdosTableRow({ target, t }: { target: DdosTarget; t: TFunction }) {
    const sev = severityFromIps(target.distinct_ips);
    const accentColor = severityBorderColor(sev);

    return (
        <tr
            className="v2-table-row text-sm"
            style={{ borderLeft: `3px solid ${accentColor}` }}
        >
            {/* Severity chip */}
            <td className="py-3 px-4">
                <SeverityChip severity={sev} showLabel />
            </td>
            {/* Host */}
            <td className="py-3 px-4 font-mono text-xs font-medium text-foreground truncate max-w-[180px]">
                {target.host}
            </td>
            {/* Path pattern */}
            <td className="py-3 px-4 font-mono text-xs text-muted-foreground break-all max-w-[240px]">
                {target.path_pattern || "/"}
            </td>
            {/* Distinct IPs */}
            <td className="v2-table-num py-3 px-4 font-semibold"
                style={{ color: accentColor }}>
                {target.distinct_ips.toLocaleString()}
            </td>
            {/* Total hits */}
            <td className="v2-table-num py-3 px-4 text-muted-foreground">
                {target.total_hits.toLocaleString()}
            </td>
            {/* Last seen */}
            <td className="py-3 px-4 text-xs text-muted-foreground whitespace-nowrap">
                {relativeTime(target.last_seen_unix_secs, t)}
            </td>
        </tr>
    );
}

// ─── Historical table row (logsApi.stats top_endpoints) ────────────────────────

function HistDdosTableRow({ bucket }: { bucket: LogStatBucket }) {
    return (
        <tr className="v2-table-row text-sm">
            {/* Path pattern */}
            <td className="py-3 px-4 font-mono text-xs font-medium text-foreground break-all max-w-[420px]">
                {bucket.key || "/"}
            </td>
            {/* Total hits */}
            <td className="v2-table-num py-3 px-4 font-semibold text-foreground">
                {bucket.count.toLocaleString()}
            </td>
        </tr>
    );
}

// ─── Mode + range toolbar ──────────────────────────────────────────────────────

function Toolbar({
    mode,
    setMode,
    range,
    setRange,
    from,
    to,
    setFrom,
    setTo,
    tLogs,
}: {
    mode: "live" | "historical";
    setMode: (m: "live" | "historical") => void;
    range: RangeKey;
    setRange: (r: RangeKey) => void;
    from: number;
    to: number;
    setFrom: (ms: number) => void;
    setTo: (ms: number) => void;
    tLogs: TFunction;
}) {
    return (
        <div className="flex flex-wrap items-center gap-2">
            {/* Mode toggle */}
            <div className="inline-flex rounded-lg border border-border/60 p-0.5 bg-muted/30">
                <button
                    type="button"
                    onClick={() => setMode("live")}
                    className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-semibold transition-colors ${
                        mode === "live"
                            ? "bg-background text-foreground shadow-sm"
                            : "text-muted-foreground hover:text-foreground"
                    }`}
                    aria-pressed={mode === "live"}
                >
                    <Radio className="h-3.5 w-3.5" />
                    {tLogs("range.live")}
                </button>
                <button
                    type="button"
                    onClick={() => setMode("historical")}
                    className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-semibold transition-colors ${
                        mode === "historical"
                            ? "bg-background text-foreground shadow-sm"
                            : "text-muted-foreground hover:text-foreground"
                    }`}
                    aria-pressed={mode === "historical"}
                >
                    <History className="h-3.5 w-3.5" />
                    {tLogs("range.historical")}
                </button>
            </div>

            {/* Range selector — historical only */}
            {mode === "historical" && (
                <>
                    <Select value={range} onValueChange={(v) => setRange(v as RangeKey)}>
                        <SelectTrigger className="h-9 w-[150px] text-xs">
                            <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                            <SelectItem value="1h">{tLogs("period.1h")}</SelectItem>
                            <SelectItem value="6h">{tLogs("period.6h")}</SelectItem>
                            <SelectItem value="24h">{tLogs("period.24h")}</SelectItem>
                            <SelectItem value="7d">{tLogs("period.7d")}</SelectItem>
                            <SelectItem value="30d">{tLogs("period.30d")}</SelectItem>
                            <SelectItem value="custom">{tLogs("range.custom")}</SelectItem>
                        </SelectContent>
                    </Select>

                    {range === "custom" && (
                        <div className="flex items-center gap-1.5">
                            <Input
                                type="datetime-local"
                                value={toLocalInput(from)}
                                onChange={(e) => {
                                    const ms = fromLocalInput(e.target.value);
                                    if (ms !== undefined) setFrom(ms);
                                }}
                                className="h-9 w-[190px] text-xs"
                                aria-label={tLogs("range.from")}
                            />
                            <span className="text-xs text-muted-foreground">–</span>
                            <Input
                                type="datetime-local"
                                value={toLocalInput(to)}
                                onChange={(e) => {
                                    const ms = fromLocalInput(e.target.value);
                                    if (ms !== undefined) setTo(ms);
                                }}
                                className="h-9 w-[190px] text-xs"
                                aria-label={tLogs("range.to")}
                            />
                        </div>
                    )}
                </>
            )}
        </div>
    );
}

// ─── Page ────────────────────────────────────────────────────────────────────

export function DdosV2Page() {
    const { t } = useTranslation(["ddos", "common"]);
    const { t: tLogs } = useTranslation("logs");

    const [mode, setMode] = React.useState<"live" | "historical">("historical");
    const [range, setRange] = React.useState<RangeKey>(DEFAULT_RANGE);
    const now = Date.now();
    const [customFrom, setCustomFrom] = React.useState<number>(now - RANGE_MS["24h"]);
    const [customTo, setCustomTo] = React.useState<number>(now);

    const histWindow = React.useMemo(() => {
        if (range === "custom") return { from: customFrom, to: customTo };
        const end = Date.now();
        return { from: end - RANGE_MS[range], to: end };
    }, [range, customFrom, customTo]);

    // Live data source.
    const liveQ = useQuery({
        queryKey: ["analytics", "ddos"],
        queryFn: threatAnalyticsApi.ddos,
        refetchInterval: 5_000,
        enabled: mode === "live",
    });

    // Historical data source (persistent store).
    const histQ = useQuery({
        queryKey: ["logs", "stats", "ddos", histWindow.from, histWindow.to],
        queryFn: () => logsApi.stats({ from: histWindow.from, to: histWindow.to }),
        enabled: mode === "historical",
    });

    const isLive = mode === "live";
    const q = isLive ? liveQ : histQ;

    const targets = liveQ.data?.targets ?? [];
    const tracked = liveQ.data?.summary.tracked_endpoints ?? 0;
    const histEndpoints: LogStatBucket[] = histQ.data?.top_endpoints ?? [];

    // Derived live summary stats.
    const maxIps = targets.length > 0 ? Math.max(...targets.map((tg) => tg.distinct_ips)) : 0;
    const maxHits = targets.length > 0 ? Math.max(...targets.map((tg) => tg.total_hits)) : 0;
    const criticalCount = targets.filter((tg) => severityFromIps(tg.distinct_ips) === "critical").length;

    // Derived historical summary stats.
    const histTotalHits = histEndpoints.reduce((sum, b) => sum + b.count, 0);
    const histPeakHits = histEndpoints.length > 0 ? Math.max(...histEndpoints.map((b) => b.count)) : 0;

    const hasRows = isLive ? targets.length > 0 : histEndpoints.length > 0;
    const hasData = isLive ? !!liveQ.data : !!histQ.data;

    return (
        <div className="space-y-6">
            {/* ── Page heading ──────────────────────────────────────────────── */}
            <div className="flex flex-wrap items-start justify-between gap-3">
                <div className="flex items-center gap-3">
                    <div className="h-10 w-10 rounded-xl bg-destructive/10 border border-destructive/20 grid place-items-center shrink-0">
                        <ShieldAlert className="h-5 w-5 text-destructive" />
                    </div>
                    <div>
                        <h1 className="text-xl font-bold text-foreground leading-snug">{t("title")}</h1>
                        <p className="text-xs text-muted-foreground mt-0.5">
                            {isLive ? t("subtitle") : t("subtitleHistorical")}
                        </p>
                    </div>
                </div>
                <Toolbar
                    mode={mode}
                    setMode={setMode}
                    range={range}
                    setRange={setRange}
                    from={customFrom}
                    to={customTo}
                    setFrom={setCustomFrom}
                    setTo={setCustomTo}
                    tLogs={tLogs}
                />
            </div>

            {/* ── Summary KPI strip ─────────────────────────────────────────── */}
            {hasData && (
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                    <div className="v2-card px-5 py-4 flex items-center gap-3" style={{ boxShadow: "var(--v2-card-shadow)" }}>
                        <Globe className="h-5 w-5 text-muted-foreground/60 shrink-0" />
                        <div>
                            <p className="v2-section-label">{t("kpi.targetedEndpoints")}</p>
                            <p className="v2-kpi-number text-2xl font-bold tabular-nums text-foreground leading-none mt-1">
                                {(isLive ? targets.length : histEndpoints.length).toLocaleString()}
                            </p>
                        </div>
                    </div>

                    {isLive ? (
                        <div className="v2-card px-5 py-4 flex items-center gap-3" style={{ boxShadow: "var(--v2-card-shadow)" }}>
                            <ShieldAlert className="h-5 w-5 text-destructive/60 shrink-0" />
                            <div>
                                <p className="v2-section-label">{t("kpi.critical")}</p>
                                <p
                                    className="v2-kpi-number text-2xl font-bold tabular-nums leading-none mt-1"
                                    style={{ color: criticalCount > 0 ? "var(--v2-severity-critical, #ef4444)" : "var(--foreground)" }}
                                >
                                    {criticalCount}
                                </p>
                            </div>
                        </div>
                    ) : (
                        <div className="v2-card px-5 py-4 flex items-center gap-3" style={{ boxShadow: "var(--v2-card-shadow)" }}>
                            <Activity className="h-5 w-5 text-muted-foreground/60 shrink-0" />
                            <div>
                                <p className="v2-section-label">{t("kpi.totalHits")}</p>
                                <p className="v2-kpi-number text-2xl font-bold tabular-nums text-foreground leading-none mt-1">
                                    {histTotalHits.toLocaleString()}
                                </p>
                            </div>
                        </div>
                    )}

                    {isLive ? (
                        <div className="v2-card px-5 py-4 flex items-center gap-3" style={{ boxShadow: "var(--v2-card-shadow)" }}>
                            <Network className="h-5 w-5 text-muted-foreground/60 shrink-0" />
                            <div>
                                <p className="v2-section-label">{t("kpi.peakDistinctIps")}</p>
                                <p className="v2-kpi-number text-2xl font-bold tabular-nums text-foreground leading-none mt-1">
                                    {maxIps > 0 ? maxIps.toLocaleString() : "—"}
                                </p>
                            </div>
                        </div>
                    ) : (
                        <div className="v2-card px-5 py-4 flex items-center gap-3" style={{ boxShadow: "var(--v2-card-shadow)" }}>
                            <Hash className="h-5 w-5 text-muted-foreground/60 shrink-0" />
                            <div>
                                <p className="v2-section-label">{t("kpi.peakEndpointHits")}</p>
                                <p className="v2-kpi-number text-2xl font-bold tabular-nums text-foreground leading-none mt-1">
                                    {histPeakHits > 0 ? histPeakHits.toLocaleString() : "—"}
                                </p>
                            </div>
                        </div>
                    )}

                    <div className="v2-card px-5 py-4 flex items-center gap-3" style={{ boxShadow: "var(--v2-card-shadow)" }}>
                        <Clock className="h-5 w-5 text-muted-foreground/60 shrink-0" />
                        <div>
                            <p className="v2-section-label">{isLive ? t("kpi.peakTotalHits") : t("kpi.window")}</p>
                            {isLive ? (
                                <p className="v2-kpi-number text-2xl font-bold tabular-nums text-foreground leading-none mt-1">
                                    {maxHits > 0 ? maxHits.toLocaleString() : "—"}
                                </p>
                            ) : (
                                <p className="v2-kpi-number text-2xl font-bold text-foreground leading-none mt-1">
                                    {range === "custom" ? tLogs("range.custom") : tLogs(`period.${range}`)}
                                </p>
                            )}
                        </div>
                    </div>
                </div>
            )}

            {/* ── Loading ───────────────────────────────────────────────────── */}
            {q.isLoading && (
                <div className="space-y-3">
                    <Skeleton className="h-10 w-64" />
                    <Skeleton className="h-72" />
                </div>
            )}

            {/* ── Error ─────────────────────────────────────────────────────── */}
            {q.error && (
                <ErrorState
                    title={t("error.title")}
                    error={q.error}
                    onRetry={() => q.refetch()}
                />
            )}

            {/* ── Empty state ───────────────────────────────────────────────── */}
            {hasData && !hasRows && (
                <MetricCard
                    title={t("empty.cardTitle")}
                    description={isLive ? t("empty.cardDescription") : t("empty.cardDescriptionHistorical")}
                >
                    <div className="py-12 flex flex-col items-center text-center gap-3">
                        <div className="h-14 w-14 rounded-full bg-primary/10 border border-primary/20 grid place-items-center">
                            <ShieldAlert className="h-7 w-7 text-primary/60" />
                        </div>
                        <div>
                            <p className="text-sm font-semibold text-foreground">{t("empty.heading")}</p>
                            <p className="text-xs text-muted-foreground mt-1 max-w-sm">
                                {isLive ? t("empty.body") : t("empty.bodyHistorical")}
                            </p>
                        </div>
                    </div>
                </MetricCard>
            )}

            {/* ── Live data table ───────────────────────────────────────────── */}
            {isLive && hasData && hasRows && (
                <MetricCard
                    title={t("table.title")}
                    description={t("table.description", { count: targets.length })}
                    noPadding
                >
                    <div className="overflow-x-auto">
                        <table className="w-full">
                            <thead>
                                <tr className="border-b border-border/60 text-left">
                                    <th className="px-4 py-2.5 text-[0.65rem] font-semibold uppercase tracking-wider text-muted-foreground w-24">
                                        {t("table.col.severity")}
                                    </th>
                                    <th className="px-4 py-2.5 text-[0.65rem] font-semibold uppercase tracking-wider text-muted-foreground">
                                        <div className="flex items-center gap-1.5">
                                            <Globe className="h-3 w-3" />
                                            {t("table.col.host")}
                                        </div>
                                    </th>
                                    <th className="px-4 py-2.5 text-[0.65rem] font-semibold uppercase tracking-wider text-muted-foreground">
                                        {t("table.col.path")}
                                    </th>
                                    <th className="px-4 py-2.5 text-[0.65rem] font-semibold uppercase tracking-wider text-muted-foreground text-right">
                                        <div className="flex items-center justify-end gap-1.5">
                                            <Network className="h-3 w-3" />
                                            {t("table.col.distinctIps")}
                                        </div>
                                    </th>
                                    <th className="px-4 py-2.5 text-[0.65rem] font-semibold uppercase tracking-wider text-muted-foreground text-right">
                                        {t("table.col.totalHits")}
                                    </th>
                                    <th className="px-4 py-2.5 text-[0.65rem] font-semibold uppercase tracking-wider text-muted-foreground">
                                        <div className="flex items-center gap-1.5">
                                            <Clock className="h-3 w-3" />
                                            {t("table.col.lastSeen")}
                                        </div>
                                    </th>
                                </tr>
                            </thead>
                            <tbody>
                                {targets.map((target: DdosTarget) => (
                                    <DdosTableRow
                                        key={`${target.host}-${target.path_pattern}`}
                                        target={target}
                                        t={t}
                                    />
                                ))}
                            </tbody>
                        </table>
                    </div>
                </MetricCard>
            )}

            {/* ── Historical data table ─────────────────────────────────────── */}
            {!isLive && hasData && hasRows && (
                <MetricCard
                    title={t("table.title")}
                    description={t("table.descriptionHistorical", { count: histEndpoints.length })}
                    noPadding
                >
                    <div className="overflow-x-auto">
                        <table className="w-full">
                            <thead>
                                <tr className="border-b border-border/60 text-left">
                                    <th className="px-4 py-2.5 text-[0.65rem] font-semibold uppercase tracking-wider text-muted-foreground">
                                        {t("table.col.path")}
                                    </th>
                                    <th className="px-4 py-2.5 text-[0.65rem] font-semibold uppercase tracking-wider text-muted-foreground text-right">
                                        <div className="flex items-center justify-end gap-1.5">
                                            <Hash className="h-3 w-3" />
                                            {t("table.col.totalHits")}
                                        </div>
                                    </th>
                                </tr>
                            </thead>
                            <tbody>
                                {histEndpoints.map((bucket: LogStatBucket) => (
                                    <HistDdosTableRow key={bucket.key} bucket={bucket} />
                                ))}
                            </tbody>
                        </table>
                    </div>
                </MetricCard>
            )}

            {/* ── Severity scale reference + remediation tips ───────────────── */}
            <div className="grid gap-4 sm:grid-cols-2">
                {/* Severity scale */}
                <MetricCard title={t("scale.title")} description={t("scale.description")}>
                    <div className="space-y-3">
                        {([
                            { sev: "critical" as const },
                            { sev: "high" as const },
                            { sev: "medium" as const },
                            { sev: "low" as const },
                        ]).map(({ sev }) => {
                            const threshold = t(`scale.${sev}.threshold`);
                            const desc = t(`scale.${sev}.desc`);
                            return (
                            <div key={sev} className="flex items-start gap-3">
                                <SeverityChip severity={sev} />
                                <div className="min-w-0">
                                    <p className="text-xs font-semibold text-foreground tabular-nums">{threshold}</p>
                                    <p className="text-xs text-muted-foreground mt-0.5 leading-snug">{desc}</p>
                                </div>
                            </div>
                            );
                        })}
                    </div>
                </MetricCard>

                {/* Remediation guidance */}
                <MetricCard
                    title={t("remediation.title")}
                    description={t("remediation.description")}
                >
                    <div className="space-y-3">
                        {(["rateLimits", "geoFilter", "challenge", "rtbh"]).map((key) => (
                            <div key={key}>
                                <SectionHeader label={t(`remediation.${key}.title`)} />
                                <p className="text-xs text-muted-foreground mt-1 leading-relaxed">
                                    {t(`remediation.${key}.desc`)}
                                </p>
                            </div>
                        ))}
                    </div>
                </MetricCard>
            </div>

            {/* ── Tracker note (live only) ─────────────────────────────────── */}
            {isLive && hasData && (
                <p className="text-[0.65rem] text-muted-foreground/60 text-right tabular-nums">
                    {t("trackerNote", { count: tracked })}
                </p>
            )}
        </div>
    );
}
