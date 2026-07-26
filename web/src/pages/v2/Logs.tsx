/**
 * V2 Logs page — /v2/logs  ("Журнал")
 *
 * The per-request decision log. Every proxied request is shown alongside how
 * Aegis acted on it — action, reason / WAF rule, status, latency and client
 * fingerprint. Restyled in the V2 visual language (MetricCard chrome, severity
 * chips, dark-palette table rows).
 *
 * Data sources:
 *   logsApi.list()  — GET /admin/api/logs        → paginated rows for the window
 *   logsApi.stats() — GET /admin/api/logs/stats  → by-action / total aggregations
 *
 * Filter trio (host/from/to) is shared between both endpoints; `list` additionally
 * honours endpoint / action / ip / free-text plus limit+offset pagination.
 */

import * as React from "react";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import {
    CalendarRange,
    Filter,
    Globe,
    Pause,
    Play,
    RotateCcw,
    Search,
} from "lucide-react";
import {
    logsApi,
    type LogEntry,
    type LogQuery,
    type LogStats,
    type LogStatBucket,
} from "@/api/client";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import {
    Select,
    SelectContent,
    SelectItem,
    SelectTrigger,
    SelectValue,
} from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { EmptyState } from "@/components/EmptyState";
import { ErrorState } from "@/components/ErrorState";
import { MetricCard } from "@/v2/components/MetricCard";
import { SectionHeader } from "@/v2/components/SectionHeader";
import { StatusBadge } from "@/v2/components/StatusBadge";
import type { Severity } from "@/v2/components/SeverityChip";

// ─── Constants ───────────────────────────────────────────────────────────────

const PAGE_SIZE = 50;
const REFRESH_MS = 5_000;

/** Period presets → window length in milliseconds. */
const PERIOD_MS: Record<string, number> = {
    "1h": 3_600_000,
    "6h": 6 * 3_600_000,
    "24h": 24 * 3_600_000,
    "7d": 7 * 24 * 3_600_000,
    "30d": 30 * 24 * 3_600_000,
};

const PERIOD_KEYS = ["1h", "6h", "24h", "7d", "30d"] as const;
type PeriodPreset = (typeof PERIOD_KEYS)[number];

/** Terminal actions the filter can pin to (matches backend dispositions). */
const ACTION_VALUES = ["pass", "deny", "challenge", "tarpit", "rate", "rtbh"] as const;

// ─── Helpers ─────────────────────────────────────────────────────────────────

type ChipVariant = "success" | "warn" | "error" | "neutral";

const CHIP_CLASS: Record<ChipVariant, string> = {
    success: "bg-emerald-500/15 border border-emerald-500/30 text-emerald-300",
    warn: "bg-amber-500/15 border border-amber-500/30 text-amber-300",
    error: "bg-red-500/15 border border-red-500/30 text-red-300",
    neutral: "bg-muted/30 border border-border/50 text-muted-foreground",
};

function Chip({ label, variant = "neutral", title }: { label: string; variant?: ChipVariant; title?: string }) {
    return (
        <span
            title={title}
            className={`inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-mono font-semibold uppercase tracking-wider ${CHIP_CLASS[variant]}`}
        >
            {label}
        </span>
    );
}

/** HTTP status code → colour class. */
function statusVariant(code: number): ChipVariant {
    if (code >= 500) return "error";
    if (code >= 400) return "warn";
    if (code >= 300) return "neutral";
    if (code >= 200) return "success";
    return "neutral";
}

function methodVariant(method: string): ChipVariant {
    if (method === "POST" || method === "PUT" || method === "PATCH") return "warn";
    if (method === "DELETE") return "error";
    return "neutral";
}

/** Terminal action → severity colour, mirroring how the proxy ranks dispositions. */
function actionSeverity(action: string): Severity {
    switch (action) {
        case "deny":
        case "rtbh":
            return "critical";
        case "tarpit":
        case "challenge":
            return "high";
        case "rate":
            return "medium";
        default:
            return "low";
    }
}

const SEVERITY_CHIP_CLASS: Record<Severity, string> = {
    critical: "v2-chip-critical",
    high: "v2-chip-high",
    medium: "v2-chip-medium",
    low: "v2-chip-low",
};

/** Action severity chip. The action token itself is machine data, rendered raw. */
function ActionChip({ action }: { action: string }) {
    const sev = actionSeverity(action);
    return (
        <span
            className={`inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-mono font-semibold uppercase tracking-wider ${SEVERITY_CHIP_CLASS[sev]}`}
            title={action}
        >
            {action || "—"}
        </span>
    );
}

/** ISO-3166 alpha-2 → flag emoji via regional-indicator code points. */
function countryFlag(cc: string): string {
    if (!cc || cc.length !== 2) return "";
    const A = 0x1f1e6;
    const up = cc.toUpperCase();
    const a = up.charCodeAt(0) - 65;
    const b = up.charCodeAt(1) - 65;
    if (a < 0 || a > 25 || b < 0 || b > 25) return "";
    return String.fromCodePoint(A + a) + String.fromCodePoint(A + b);
}

function fmtTime(tsMs: number): string {
    const d = new Date(tsMs);
    if (isNaN(d.getTime())) return "—";
    return d.toLocaleString(undefined, {
        month: "short",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
    });
}

function fmtLatency(ms: number): string {
    if (ms == null || isNaN(ms)) return "—";
    if (ms < 1000) return `${Math.round(ms)} ms`;
    return `${(ms / 1000).toFixed(2)} s`;
}

/** Convert a `datetime-local` value (local time) → epoch ms, or undefined. */
function localToMs(v: string): number | undefined {
    if (!v) return undefined;
    const ms = new Date(v).getTime();
    return isNaN(ms) ? undefined : ms;
}

// ─── Table header cell ───────────────────────────────────────────────────────

function TH({ children, className }: { children: React.ReactNode; className?: string }) {
    return (
        <th
            className={`px-4 py-2.5 text-left text-[10px] font-semibold uppercase tracking-wider text-muted-foreground border-b border-border/50 ${className ?? ""}`}
        >
            {children}
        </th>
    );
}

// ─── Summary strip ───────────────────────────────────────────────────────────

function SummaryStrip({ stats, total, t }: { stats: LogStats; total: number; t: TFunction }) {
    return (
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-3">
            {/* Total in window */}
            <div className="v2-card px-5 py-4" style={{ boxShadow: "var(--v2-card-shadow)" }}>
                <p className="v2-section-label">{t("entriesTitle")}</p>
                <p className="v2-kpi-number text-2xl font-bold tabular-nums text-foreground leading-none mt-1">
                    {total.toLocaleString()}
                </p>
            </div>
            {/* Per-action counts */}
            {stats.by_action.slice(0, 7).map((b: LogStatBucket) => {
                const sev = actionSeverity(b.key);
                return (
                    <div key={b.key} className="v2-card px-5 py-4" style={{ boxShadow: "var(--v2-card-shadow)" }}>
                        <div className="flex items-center gap-1.5">
                            <span
                                className={`inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-mono font-semibold uppercase tracking-wider ${SEVERITY_CHIP_CLASS[sev]}`}
                                title={b.key}
                            >
                                {b.key || "—"}
                            </span>
                        </div>
                        <p className="v2-kpi-number text-2xl font-bold tabular-nums text-foreground leading-none mt-1">
                            {b.count.toLocaleString()}
                        </p>
                    </div>
                );
            })}
        </div>
    );
}

// ─── Results table ───────────────────────────────────────────────────────────

function LogRow({ e }: { e: LogEntry }) {
    const flag = countryFlag(e.country);
    return (
        <tr className="v2-table-row">
            <td className="px-4 py-3 text-[11px] text-muted-foreground border-b border-border/20 v2-table-num whitespace-nowrap">
                {fmtTime(e.ts)}
            </td>
            <td className="px-4 py-3 font-mono text-[11px] text-foreground/80 border-b border-border/20 truncate max-w-[160px]" title={e.host}>
                {e.host || "—"}
            </td>
            <td className="px-4 py-3 border-b border-border/20">
                <Chip label={e.method || "—"} variant={methodVariant(e.method)} />
            </td>
            <td className="px-4 py-3 font-mono text-[11px] text-foreground/80 border-b border-border/20 truncate max-w-[260px]" title={e.path}>
                {e.path || "—"}
            </td>
            <td className="px-4 py-3 border-b border-border/20">
                <Chip label={String(e.status)} variant={statusVariant(e.status)} />
            </td>
            <td className="px-4 py-3 border-b border-border/20">
                <ActionChip action={e.action} />
            </td>
            <td className="px-4 py-3 text-[11px] text-muted-foreground border-b border-border/20 truncate max-w-[200px]" title={e.waf_rule || e.reason}>
                {e.waf_rule ? (
                    <span className="font-mono text-foreground/70">{e.waf_rule}</span>
                ) : (
                    e.reason || "—"
                )}
            </td>
            <td className="px-4 py-3 font-mono text-[11px] text-muted-foreground border-b border-border/20 whitespace-nowrap">
                {flag && <span className="mr-1.5 not-italic" aria-hidden>{flag}</span>}
                {e.client_ip || "—"}
            </td>
            <td className="px-4 py-3 text-[11px] text-muted-foreground border-b border-border/20 v2-table-num whitespace-nowrap text-right">
                {fmtLatency(e.latency_ms)}
            </td>
        </tr>
    );
}

// ─── Page ────────────────────────────────────────────────────────────────────

export function LogsV2Page() {
    const { t } = useTranslation(["logs", "common"]);

    // Draft filter state (the form), committed via Apply.
    const [host, setHost] = React.useState("");
    const [endpoint, setEndpoint] = React.useState("");
    const [action, setAction] = React.useState<string>("");
    const [clientIp, setClientIp] = React.useState("");
    const [q, setQ] = React.useState("");
    const [period, setPeriod] = React.useState<PeriodPreset | "custom">("24h");
    const [customFrom, setCustomFrom] = React.useState("");
    const [customTo, setCustomTo] = React.useState("");

    const [page, setPage] = React.useState(0);
    const [paused, setPaused] = React.useState(false);

    // Bumped on Apply / Reset / period change so the committed query re-derives
    // from the draft fields without refetching on every keystroke.
    const [appliedToken, setAppliedToken] = React.useState(0);
    const bumpApplied = React.useCallback(() => setAppliedToken((n) => n + 1), []);

    // Resolve the active time window from the period selection.
    const { from, to } = React.useMemo<{ from?: number; to?: number }>(() => {
        if (period === "custom") {
            return { from: localToMs(customFrom), to: localToMs(customTo) };
        }
        const span = PERIOD_MS[period] ?? 24 * 3_600_000;
        const now = Date.now();
        return { from: now - span, to: now };
    }, [period, customFrom, customTo]);

    // Committed query — only changes on Apply / Reset / pagination / period.
    const baseQuery = React.useMemo<LogQuery>(
        () => ({
            host: host || undefined,
            endpoint: endpoint || undefined,
            action: action || undefined,
            client_ip: clientIp || undefined,
            q: q || undefined,
            from,
            to,
        }),
        // eslint-disable-next-line react-hooks/exhaustive-deps
        [appliedToken, from, to],
    );

    const listQuery = useQuery({
        queryKey: ["logs", "list", baseQuery, page],
        queryFn: () => logsApi.list({ ...baseQuery, limit: PAGE_SIZE, offset: page * PAGE_SIZE }),
        refetchInterval: paused ? false : REFRESH_MS,
        placeholderData: keepPreviousData,
    });

    const statsQuery = useQuery({
        queryKey: ["logs", "stats", baseQuery.host ?? "", from ?? 0, to ?? 0],
        queryFn: () => logsApi.stats({ host: baseQuery.host, from, to }),
        refetchInterval: paused ? false : REFRESH_MS,
        placeholderData: keepPreviousData,
    });

    const entries = listQuery.data?.entries ?? [];
    const total = listQuery.data?.total ?? 0;
    const rangeFrom = total === 0 ? 0 : page * PAGE_SIZE + 1;
    const rangeTo = Math.min(total, (page + 1) * PAGE_SIZE);
    const hasPrev = page > 0;
    const hasNext = rangeTo < total;

    const applyFilters = () => {
        setPage(0);
        bumpApplied();
    };

    const resetFilters = () => {
        setHost("");
        setEndpoint("");
        setAction("");
        setClientIp("");
        setQ("");
        setPeriod("24h");
        setCustomFrom("");
        setCustomTo("");
        setPage(0);
        bumpApplied();
    };

    return (
        <div className="space-y-5">
            {/* ── Page header ───────────────────────────────────────────────── */}
            <div className="flex items-start justify-between gap-4 flex-wrap">
                <div>
                    <SectionHeader label={t("title")} />
                    <p className="text-xs text-muted-foreground mt-1.5 leading-snug max-w-2xl">
                        {t("description")}
                    </p>
                </div>
                <div className="flex items-center gap-3 shrink-0">
                    <StatusBadge
                        state={paused ? "standby" : "active"}
                        label={paused ? t("paused") : t("live")}
                    />
                    <Button
                        variant="outline"
                        size="sm"
                        className="h-8 text-xs"
                        onClick={() => setPaused((p) => !p)}
                    >
                        {paused ? <Play className="h-3.5 w-3.5 mr-1" /> : <Pause className="h-3.5 w-3.5 mr-1" />}
                        {paused ? t("resume") : t("pause")}
                    </Button>
                </div>
            </div>

            {/* ── Filter bar ────────────────────────────────────────────────── */}
            <MetricCard title={t("filterTitle")} noPadding>
                <div className="px-5 py-4 space-y-4">
                    {/* Row 1: domain / endpoint / action / ip */}
                    <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
                        <div className="space-y-1">
                            <Label htmlFor="log-host" className="text-[11px] text-muted-foreground">
                                {t("filters.domain")}
                            </Label>
                            <Input
                                id="log-host"
                                value={host}
                                onChange={(e) => setHost(e.target.value)}
                                onKeyDown={(e) => e.key === "Enter" && applyFilters()}
                                placeholder={t("filters.domainPlaceholder")}
                                className="h-8 text-xs bg-background/50"
                            />
                        </div>
                        <div className="space-y-1">
                            <Label htmlFor="log-endpoint" className="text-[11px] text-muted-foreground">
                                {t("filters.endpoint")}
                            </Label>
                            <Input
                                id="log-endpoint"
                                value={endpoint}
                                onChange={(e) => setEndpoint(e.target.value)}
                                onKeyDown={(e) => e.key === "Enter" && applyFilters()}
                                placeholder={t("filters.endpointPlaceholder")}
                                className="h-8 text-xs bg-background/50 font-mono"
                            />
                        </div>
                        <div className="space-y-1">
                            <Label htmlFor="log-action" className="text-[11px] text-muted-foreground">
                                {t("filters.action")}
                            </Label>
                            <Select
                                value={action || "__all__"}
                                onValueChange={(v) => setAction(v === "__all__" ? "" : v)}
                            >
                                <SelectTrigger id="log-action" className="h-8 text-xs">
                                    <SelectValue placeholder={t("filters.actionPlaceholder")} />
                                </SelectTrigger>
                                <SelectContent>
                                    <SelectItem value="__all__">{t("filters.actionPlaceholder")}</SelectItem>
                                    {ACTION_VALUES.map((a) => (
                                        <SelectItem key={a} value={a} className="font-mono uppercase">
                                            {a}
                                        </SelectItem>
                                    ))}
                                </SelectContent>
                            </Select>
                        </div>
                        <div className="space-y-1">
                            <Label htmlFor="log-ip" className="text-[11px] text-muted-foreground">
                                {t("filters.ip")}
                            </Label>
                            <Input
                                id="log-ip"
                                value={clientIp}
                                onChange={(e) => setClientIp(e.target.value)}
                                onKeyDown={(e) => e.key === "Enter" && applyFilters()}
                                placeholder={t("filters.ipPlaceholder")}
                                className="h-8 text-xs bg-background/50 font-mono"
                            />
                        </div>
                    </div>

                    {/* Row 2: free-text search + time range */}
                    <div className="grid gap-3 lg:grid-cols-[1fr_auto] items-end">
                        <div className="space-y-1">
                            <Label htmlFor="log-q" className="text-[11px] text-muted-foreground">
                                {t("filters.search")}
                            </Label>
                            <div className="relative">
                                <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
                                <Input
                                    id="log-q"
                                    value={q}
                                    onChange={(e) => setQ(e.target.value)}
                                    onKeyDown={(e) => e.key === "Enter" && applyFilters()}
                                    placeholder={t("filters.searchPlaceholder")}
                                    className="pl-8 h-8 text-xs bg-background/50"
                                />
                            </div>
                        </div>
                        <div className="space-y-1">
                            <Label htmlFor="log-period" className="text-[11px] text-muted-foreground flex items-center gap-1.5">
                                <CalendarRange className="h-3 w-3" />
                                {t("filters.period")}
                            </Label>
                            <Select
                                value={period}
                                onValueChange={(v) => {
                                    setPeriod(v as PeriodPreset | "custom");
                                    if (v !== "custom") {
                                        setPage(0);
                                        bumpApplied();
                                    }
                                }}
                            >
                                <SelectTrigger id="log-period" className="h-8 text-xs min-w-[10rem]">
                                    <SelectValue />
                                </SelectTrigger>
                                <SelectContent>
                                    {PERIOD_KEYS.map((p) => (
                                        <SelectItem key={p} value={p}>
                                            {t(`period.${p}`)}
                                        </SelectItem>
                                    ))}
                                    <SelectItem value="custom">
                                        <span className="flex items-center gap-1.5">
                                            <CalendarRange className="h-3 w-3" />
                                            {t("filters.period")}
                                        </span>
                                    </SelectItem>
                                </SelectContent>
                            </Select>
                        </div>
                    </div>

                    {/* Custom range inputs */}
                    {period === "custom" && (
                        <div className="flex items-end gap-2 flex-wrap">
                            <CalendarRange className="h-3.5 w-3.5 text-muted-foreground mb-2.5" aria-hidden />
                            <div className="space-y-1">
                                <Label htmlFor="log-from" className="sr-only">
                                    {t("filters.period")}
                                </Label>
                                <Input
                                    id="log-from"
                                    type="datetime-local"
                                    value={customFrom}
                                    onChange={(e) => setCustomFrom(e.target.value)}
                                    aria-label={t("filters.period")}
                                    className="h-8 text-xs bg-background/50 w-auto"
                                />
                            </div>
                            <span className="text-muted-foreground mb-2">–</span>
                            <div className="space-y-1">
                                <Label htmlFor="log-to" className="sr-only">
                                    {t("filters.period")}
                                </Label>
                                <Input
                                    id="log-to"
                                    type="datetime-local"
                                    value={customTo}
                                    onChange={(e) => setCustomTo(e.target.value)}
                                    aria-label={t("filters.period")}
                                    className="h-8 text-xs bg-background/50 w-auto"
                                />
                            </div>
                        </div>
                    )}

                    {/* Actions */}
                    <div className="flex items-center gap-2 pt-1">
                        <Button size="sm" className="h-8 text-xs" onClick={applyFilters}>
                            <Filter className="h-3.5 w-3.5 mr-1.5" />
                            {t("actions.apply")}
                        </Button>
                        <Button variant="outline" size="sm" className="h-8 text-xs" onClick={resetFilters}>
                            <RotateCcw className="h-3.5 w-3.5 mr-1.5" />
                            {t("actions.reset")}
                        </Button>
                    </div>
                </div>
            </MetricCard>

            {/* ── Summary strip ─────────────────────────────────────────────── */}
            {statsQuery.data && <SummaryStrip stats={statsQuery.data} total={total} t={t} />}

            {/* ── Results ───────────────────────────────────────────────────── */}
            <MetricCard
                title={t("entriesTitle")}
                description={t("entriesDescription")}
                noPadding
                action={
                    total > 0 ? (
                        <span className="text-[11px] text-muted-foreground tabular-nums">
                            {t("entriesCount", { count: total })}
                        </span>
                    ) : undefined
                }
            >
                {listQuery.isLoading ? (
                    <div className="px-5 py-4 space-y-2">
                        {Array.from({ length: 8 }).map((_, i) => (
                            <Skeleton key={i} className="h-9 w-full" />
                        ))}
                    </div>
                ) : listQuery.error ? (
                    <div className="px-5 py-6">
                        <ErrorState
                            title={t("common:error")}
                            error={listQuery.error}
                            onRetry={() => listQuery.refetch()}
                        />
                    </div>
                ) : entries.length === 0 ? (
                    <div className="px-5 py-10">
                        <EmptyState
                            icon={<Globe />}
                            title={t("emptyTitle")}
                            description={t("emptyDescription")}
                        />
                    </div>
                ) : (
                    <>
                        <div className="overflow-x-auto">
                            <table className="w-full">
                                <thead>
                                    <tr>
                                        <TH className="w-28">{t("columns.time")}</TH>
                                        <TH>{t("columns.host")}</TH>
                                        <TH className="w-20">{t("columns.method")}</TH>
                                        <TH>{t("columns.path")}</TH>
                                        <TH className="w-20">{t("columns.status")}</TH>
                                        <TH className="w-24">{t("columns.action")}</TH>
                                        <TH>{t("columns.reason")}</TH>
                                        <TH className="w-44">{t("columns.ip")}</TH>
                                        <TH className="w-24 text-right">{t("columns.latency")}</TH>
                                    </tr>
                                </thead>
                                <tbody>
                                    {entries.map((e: LogEntry, i: number) => (
                                        <LogRow key={`${e.ts}-${e.client_ip}-${i}`} e={e} />
                                    ))}
                                </tbody>
                            </table>
                        </div>

                        {/* Pager */}
                        <div className="flex items-center justify-between gap-3 px-5 py-3 border-t border-border/40">
                            <span className="text-[11px] text-muted-foreground tabular-nums">
                                {t("pagination.showing", { from: rangeFrom, to: rangeTo, total })}
                            </span>
                            <div className="flex items-center gap-2">
                                <span className="text-[11px] text-muted-foreground">
                                    {t("pagination.page", { page: page + 1 })}
                                </span>
                                <Button
                                    variant="outline"
                                    size="sm"
                                    className="h-7 text-xs"
                                    disabled={!hasPrev}
                                    onClick={() => setPage((p) => Math.max(0, p - 1))}
                                >
                                    {t("pagination.prev")}
                                </Button>
                                <Button
                                    variant="outline"
                                    size="sm"
                                    className="h-7 text-xs"
                                    disabled={!hasNext}
                                    onClick={() => setPage((p) => p + 1)}
                                >
                                    {t("pagination.next")}
                                </Button>
                            </div>
                        </div>
                    </>
                )}
            </MetricCard>
        </div>
    );
}
