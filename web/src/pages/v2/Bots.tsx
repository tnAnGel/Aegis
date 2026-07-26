/**
 * V2 Bots page — /v2/bots
 *
 * Displays per-IP bot detections in the V2 visual language:
 *   - V2-styled page header (Bot icon + title)
 *   - MetricCard wrapping the detections table or empty/loading states
 *   - Detection reason chips using SeverityChip colours
 *   - Tabular-nums for hit counts + last-seen timestamps
 *   - v2-table-row hover styling from tokens.css
 *
 * Two data sources, toggled by the mode switch:
 *   - "Live"       → threatAnalyticsApi.bots() — real-time, in-memory 5-min window.
 *   - "Historical" → logsApi.stats({from,to}).top_client_ips — persistent store,
 *                    any selected time range (1h/6h/24h/7d/30d/custom).
 * V1 files are NOT imported.
 */

import * as React from "react";
import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import {
    Bot,
    Clock,
    Hash,
    Network,
    Radio,
    History,
    ShieldX,
    ShieldQuestion,
} from "lucide-react";
import {
    threatAnalyticsApi,
    logsApi,
    type BotEntry,
    type LogClientIpStat,
} from "@/api/client";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState } from "@/components/ErrorState";
import { MetricCard } from "@/v2/components/MetricCard";
import { SectionHeader } from "@/v2/components/SectionHeader";
import {
    Select,
    SelectContent,
    SelectItem,
    SelectTrigger,
    SelectValue,
} from "@/components/ui/select";
import { Input } from "@/components/ui/input";

// ─── Time range model (shared shape with the DDoS page) ────────────────────────

type RangeKey = "1h" | "6h" | "24h" | "7d" | "30d" | "custom";

const RANGE_MS: Record<Exclude<RangeKey, "custom">, number> = {
    "1h": 3_600_000,
    "6h": 6 * 3_600_000,
    "24h": 24 * 3_600_000,
    "7d": 7 * 24 * 3_600_000,
    "30d": 30 * 24 * 3_600_000,
};

const DEFAULT_RANGE: RangeKey = "24h";

/** epoch-ms value for a `<input type="datetime-local">` field. */
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

/** Maps a reason string → V2 chip colours (bg / text / border inline styles). */
function reasonStyle(reason: string): { background: string; color: string; borderColor: string } {
    switch (reason) {
        case "honeypot_hit":
            return {
                background: "color-mix(in srgb, var(--v2-severity-critical, #ef4444) 15%, transparent)",
                color: "var(--v2-severity-critical, #ef4444)",
                borderColor: "color-mix(in srgb, var(--v2-severity-critical, #ef4444) 30%, transparent)",
            };
        case "waf_signature":
            return {
                background: "color-mix(in srgb, var(--v2-severity-high, #f59e0b) 15%, transparent)",
                color: "var(--v2-severity-high, #f59e0b)",
                borderColor: "color-mix(in srgb, var(--v2-severity-high, #f59e0b) 30%, transparent)",
            };
        case "ua_fp_mismatch":
            return {
                background: "color-mix(in srgb, var(--v2-severity-medium, #eab308) 15%, transparent)",
                color: "var(--v2-severity-medium, #eab308)",
                borderColor: "color-mix(in srgb, var(--v2-severity-medium, #eab308) 30%, transparent)",
            };
        case "compound":
            return {
                background: "color-mix(in srgb, #a855f7 15%, transparent)",
                color: "#a855f7",
                borderColor: "color-mix(in srgb, #a855f7 30%, transparent)",
            };
        case "high_threat_score":
        case "high_ml_score":
            return {
                background: "color-mix(in srgb, var(--v2-severity-critical, #ef4444) 15%, transparent)",
                color: "var(--v2-severity-critical, #ef4444)",
                borderColor: "color-mix(in srgb, var(--v2-severity-critical, #ef4444) 30%, transparent)",
            };
        default:
            return {
                background: "var(--muted)",
                color: "var(--muted-foreground)",
                borderColor: "var(--border)",
            };
    }
}

const KNOWN_REASONS = new Set([
    "honeypot_hit",
    "waf_signature",
    "ua_fp_mismatch",
    "compound",
    "high_threat_score",
    "high_ml_score",
    "no_user_agent",
]);

function reasonLabel(reason: string, t: TFunction): string {
    if (KNOWN_REASONS.has(reason)) return t(`reason.${reason}`);
    return reason;
}

// ─── Live table row ────────────────────────────────────────────────────────────

function BotTableRow({ b, t }: { b: BotEntry; t: TFunction }) {
    const style = reasonStyle(b.primary_reason);

    return (
        <tr className="v2-table-row text-sm">
            {/* IP */}
            <td className="py-2.5 px-4 font-mono text-xs font-medium text-foreground">
                {b.client_ip}
            </td>
            {/* Reason chip */}
            <td className="py-2.5 px-4">
                <span
                    className="inline-flex items-center px-2 py-0.5 rounded text-[0.65rem] font-semibold border"
                    style={style}
                >
                    {reasonLabel(b.primary_reason, t)}
                </span>
            </td>
            {/* Hits */}
            <td className="v2-table-num py-2.5 px-4 text-right">
                {b.hits.toLocaleString()}
            </td>
            {/* Last seen */}
            <td className="py-2.5 px-4 text-xs text-muted-foreground whitespace-nowrap">
                {relativeTime(b.last_seen_unix_secs, t)}
            </td>
        </tr>
    );
}

// ─── Historical table row (logsApi.stats top_client_ips) ───────────────────────

function HistBotTableRow({ s }: { s: LogClientIpStat }) {
    return (
        <tr className="v2-table-row text-sm">
            {/* IP */}
            <td className="py-2.5 px-4 font-mono text-xs font-medium text-foreground">
                {s.client_ip}
            </td>
            {/* Total requests */}
            <td className="v2-table-num py-2.5 px-4 text-right">
                {s.count.toLocaleString()}
            </td>
            {/* Denied */}
            <td className="v2-table-num py-2.5 px-4 text-right">
                <span
                    className="font-semibold"
                    style={{ color: s.deny > 0 ? "var(--v2-severity-critical, #ef4444)" : "var(--muted-foreground)" }}
                >
                    {s.deny.toLocaleString()}
                </span>
            </td>
            {/* Challenged */}
            <td className="v2-table-num py-2.5 px-4 text-right">
                <span
                    className="font-semibold"
                    style={{ color: s.challenge > 0 ? "var(--v2-severity-medium, #eab308)" : "var(--muted-foreground)" }}
                >
                    {s.challenge.toLocaleString()}
                </span>
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

export function BotsV2Page() {
    const { t } = useTranslation(["bots", "common"]);
    const { t: tLogs } = useTranslation("logs");

    const [mode, setMode] = React.useState<"live" | "historical">("historical");
    const [range, setRange] = React.useState<RangeKey>(DEFAULT_RANGE);
    const now = Date.now();
    const [customFrom, setCustomFrom] = React.useState<number>(now - RANGE_MS["24h"]);
    const [customTo, setCustomTo] = React.useState<number>(now);

    // Resolve from/to for the active historical window.
    const histWindow = React.useMemo(() => {
        if (range === "custom") return { from: customFrom, to: customTo };
        const end = Date.now();
        return { from: end - RANGE_MS[range], to: end };
    }, [range, customFrom, customTo]);

    // Live data source.
    const liveQ = useQuery({
        queryKey: ["analytics", "bots"],
        queryFn: threatAnalyticsApi.bots,
        refetchInterval: 5_000,
        enabled: mode === "live",
    });

    // Historical data source (persistent store).
    const histQ = useQuery({
        queryKey: ["logs", "stats", "bots", histWindow.from, histWindow.to],
        queryFn: () => logsApi.stats({ from: histWindow.from, to: histWindow.to }),
        enabled: mode === "historical",
    });

    const isLive = mode === "live";
    const q = isLive ? liveQ : histQ;

    const liveBots = liveQ.data?.bots ?? [];
    const tracked = liveQ.data?.summary.tracked_bots ?? 0;
    const histIps: LogClientIpStat[] = histQ.data?.top_client_ips ?? [];

    // KPI values per mode.
    const flaggedCount = isLive ? liveBots.length : histIps.length;
    const histDenied = histIps.reduce((sum, s) => sum + s.deny, 0);
    const histChallenged = histIps.reduce((sum, s) => sum + s.challenge, 0);

    const hasRows = isLive ? liveBots.length > 0 : histIps.length > 0;
    const hasData = isLive ? !!liveQ.data : !!histQ.data;

    return (
        <div className="space-y-6">
            {/* ── Page heading ──────────────────────────────────────────────── */}
            <div className="flex flex-wrap items-start justify-between gap-3">
                <div className="flex items-center gap-3">
                    <div className="h-10 w-10 rounded-xl bg-primary/10 border border-primary/20 grid place-items-center shrink-0">
                        <Bot className="h-5 w-5 text-primary" />
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
                <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
                    <div className="v2-card px-5 py-4 flex items-center gap-3" style={{ boxShadow: "var(--v2-card-shadow)" }}>
                        <Bot className="h-5 w-5 text-muted-foreground/60 shrink-0" />
                        <div>
                            <p className="v2-section-label">{t("kpi.flaggedIps")}</p>
                            <p className="v2-kpi-number text-2xl font-bold tabular-nums text-foreground leading-none mt-1">
                                {flaggedCount.toLocaleString()}
                            </p>
                        </div>
                    </div>

                    {isLive ? (
                        <div className="v2-card px-5 py-4 flex items-center gap-3" style={{ boxShadow: "var(--v2-card-shadow)" }}>
                            <Hash className="h-5 w-5 text-muted-foreground/60 shrink-0" />
                            <div>
                                <p className="v2-section-label">{t("kpi.trackedBots")}</p>
                                <p className="v2-kpi-number text-2xl font-bold tabular-nums text-foreground leading-none mt-1">
                                    {tracked.toLocaleString()}
                                </p>
                            </div>
                        </div>
                    ) : (
                        <div className="v2-card px-5 py-4 flex items-center gap-3" style={{ boxShadow: "var(--v2-card-shadow)" }}>
                            <ShieldX className="h-5 w-5 text-muted-foreground/60 shrink-0" />
                            <div>
                                <p className="v2-section-label">{t("kpi.denied")}</p>
                                <p className="v2-kpi-number text-2xl font-bold tabular-nums text-foreground leading-none mt-1">
                                    {histDenied.toLocaleString()}
                                </p>
                            </div>
                        </div>
                    )}

                    {isLive ? (
                        <div className="v2-card px-5 py-4 flex items-center gap-3" style={{ boxShadow: "var(--v2-card-shadow)" }}>
                            <Clock className="h-5 w-5 text-muted-foreground/60 shrink-0" />
                            <div>
                                <p className="v2-section-label">{t("kpi.window")}</p>
                                <p className="v2-kpi-number text-2xl font-bold text-foreground leading-none mt-1">
                                    {t("kpi.windowValue")}
                                </p>
                            </div>
                        </div>
                    ) : (
                        <div className="v2-card px-5 py-4 flex items-center gap-3" style={{ boxShadow: "var(--v2-card-shadow)" }}>
                            <ShieldQuestion className="h-5 w-5 text-muted-foreground/60 shrink-0" />
                            <div>
                                <p className="v2-section-label">{t("kpi.challenged")}</p>
                                <p className="v2-kpi-number text-2xl font-bold tabular-nums text-foreground leading-none mt-1">
                                    {histChallenged.toLocaleString()}
                                </p>
                            </div>
                        </div>
                    )}
                </div>
            )}

            {/* ── Loading ───────────────────────────────────────────────────── */}
            {q.isLoading && (
                <div className="space-y-3">
                    <Skeleton className="h-10 w-56" />
                    <Skeleton className="h-72" />
                </div>
            )}

            {/* ── Error ─────────────────────────────────────────────────────── */}
            {q.error && (
                <ErrorState title={t("error.title")} error={q.error} onRetry={() => q.refetch()} />
            )}

            {/* ── Empty ─────────────────────────────────────────────────────── */}
            {hasData && !hasRows && (
                <MetricCard title={t("emptyCard.title")} description={t("emptyCard.description")}>
                    <div className="py-12 flex flex-col items-center text-center gap-3">
                        <div className="h-14 w-14 rounded-full bg-primary/10 border border-primary/20 grid place-items-center">
                            <Bot className="h-7 w-7 text-primary/60" />
                        </div>
                        <div>
                            <p className="text-sm font-semibold text-foreground">{t("empty.title")}</p>
                            <p className="text-xs text-muted-foreground mt-1 max-w-sm">
                                {isLive ? t("empty.desc") : t("empty.descHistorical")}
                            </p>
                        </div>
                    </div>
                </MetricCard>
            )}

            {/* ── Live data table ───────────────────────────────────────────── */}
            {isLive && hasData && hasRows && (
                <MetricCard
                    title={t("table.title")}
                    description={t("table.description", { count: liveBots.length })}
                    noPadding
                >
                    <div className="overflow-x-auto">
                        <table className="w-full">
                            <thead>
                                <tr className="border-b border-border/60 text-left">
                                    <th className="px-4 py-2.5 text-[0.65rem] font-semibold uppercase tracking-wider text-muted-foreground">
                                        <div className="flex items-center gap-1.5">
                                            <Network className="h-3 w-3" />
                                            {t("col.ip")}
                                        </div>
                                    </th>
                                    <th className="px-4 py-2.5 text-[0.65rem] font-semibold uppercase tracking-wider text-muted-foreground">
                                        {t("col.reason")}
                                    </th>
                                    <th className="px-4 py-2.5 text-[0.65rem] font-semibold uppercase tracking-wider text-muted-foreground text-right">
                                        <div className="flex items-center justify-end gap-1.5">
                                            <Hash className="h-3 w-3" />
                                            {t("col.hits")}
                                        </div>
                                    </th>
                                    <th className="px-4 py-2.5 text-[0.65rem] font-semibold uppercase tracking-wider text-muted-foreground">
                                        <div className="flex items-center gap-1.5">
                                            <Clock className="h-3 w-3" />
                                            {t("col.lastSeen")}
                                        </div>
                                    </th>
                                </tr>
                            </thead>
                            <tbody>
                                {liveBots.map((b: BotEntry) => (
                                    <BotTableRow key={b.client_ip} b={b} t={t} />
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
                    description={t("table.descriptionHistorical", { count: histIps.length })}
                    noPadding
                >
                    <div className="overflow-x-auto">
                        <table className="w-full">
                            <thead>
                                <tr className="border-b border-border/60 text-left">
                                    <th className="px-4 py-2.5 text-[0.65rem] font-semibold uppercase tracking-wider text-muted-foreground">
                                        <div className="flex items-center gap-1.5">
                                            <Network className="h-3 w-3" />
                                            {t("col.ip")}
                                        </div>
                                    </th>
                                    <th className="px-4 py-2.5 text-[0.65rem] font-semibold uppercase tracking-wider text-muted-foreground text-right">
                                        <div className="flex items-center justify-end gap-1.5">
                                            <Hash className="h-3 w-3" />
                                            {t("col.requests")}
                                        </div>
                                    </th>
                                    <th className="px-4 py-2.5 text-[0.65rem] font-semibold uppercase tracking-wider text-muted-foreground text-right">
                                        {t("col.denied")}
                                    </th>
                                    <th className="px-4 py-2.5 text-[0.65rem] font-semibold uppercase tracking-wider text-muted-foreground text-right">
                                        {t("col.challenged")}
                                    </th>
                                </tr>
                            </thead>
                            <tbody>
                                {histIps.map((s: LogClientIpStat) => (
                                    <HistBotTableRow key={s.client_ip} s={s} />
                                ))}
                            </tbody>
                        </table>
                    </div>
                </MetricCard>
            )}

            {/* ── Explanation footer ────────────────────────────────────────── */}
            <MetricCard
                title={t("about.title")}
                description={t("about.description")}
            >
                <div className="grid gap-4 sm:grid-cols-2">
                    {[
                        {
                            title: t("about.waf.title"),
                            desc: t("about.waf.desc"),
                        },
                        {
                            title: t("about.honeypot.title"),
                            desc: t("about.honeypot.desc"),
                        },
                        {
                            title: t("about.uafp.title"),
                            desc: t("about.uafp.desc"),
                        },
                        {
                            title: t("about.coordinated.title"),
                            desc: t("about.coordinated.desc"),
                        },
                    ].map(({ title, desc }) => (
                        <div key={title} className="space-y-1">
                            <SectionHeader label={title} />
                            <p className="text-xs text-muted-foreground leading-relaxed">{desc}</p>
                        </div>
                    ))}
                </div>
            </MetricCard>
        </div>
    );
}
