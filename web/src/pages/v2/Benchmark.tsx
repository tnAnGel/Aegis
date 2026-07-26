// V2 — Hardware Benchmark page.
//
// Presentation-only redesign; all data-fetching + state machine is
// identical to V1. Wires: benchmarkApi.run / benchmarkApi.result.
// Layout: MetricCard + SectionHeader + StatusBadge from V2 primitives.
// Reuses ArcGauge and Recharts BarChart unchanged from V1 charts.

import { useState, useRef, useCallback } from "react";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
    Activity,
    BarChart3,
    CheckCircle2,
    Cpu,
    Gauge,
    Info,
    Lock,
    Network,
    ShieldAlert,
    Timer,
    Waves,
    XCircle,
    Zap,
} from "lucide-react";
import {
    Bar,
    BarChart,
    CartesianGrid,
    ResponsiveContainer,
    Tooltip,
    XAxis,
    YAxis,
} from "recharts";
import { benchmarkApi, floodApi, compareApi } from "@/api/client";
import type { ComparisonResult, TargetResult, SecurityRow } from "@/api/client";
import type { BenchmarkResult, FloodResult, FloodScenario } from "@/types/index";
import { Button } from "@/components/ui/button";
import { useToast } from "@/hooks/useToast";
import { ArcGauge } from "@/components/charts/ArcGauge";
import { MetricCard } from "@/v2/components/MetricCard";

// ─── helpers ────────────────────────────────────────────────────────

function fmtMs(ms: number): string {
    if (ms < 1000) return `${Math.round(ms)} ms`;
    return `${(ms / 1000).toFixed(1)} s`;
}

function fmtRps(rps: number): string {
    if (rps >= 1_000_000) return `${(rps / 1_000_000).toFixed(2)} M`;
    if (rps >= 1_000) return `${(rps / 1_000).toFixed(1)} K`;
    return String(rps);
}

// ─── Recommendation cards ─────────────────────────────────────────────

interface RecCard {
    priority: "high" | "med" | "info";
    icon: React.ReactNode;
    title: string;
    body: string;
}

function buildCards(data: BenchmarkResult, t: TFunction): RecCard[] {
    const cards: RecCard[] = [];
    const proj = data.projections;
    const hw = data.hardware;

    if (!proj) return cards;

    if (proj.bottleneck === "reuseport_off") {
        cards.push({
            priority: "high",
            icon: <Network className="h-4 w-4" />,
            title: t("rec.reuseportOff.title"),
            body: t("rec.reuseportOff.body", {
                cores: hw?.cpu_count ?? t("common:none", "multiple"),
                gain: Math.round((0.90 - 0.35) / 0.35 * 100),
            }),
        });
    }

    if (proj.bottleneck === "core_count") {
        cards.push({
            priority: "med",
            icon: <Cpu className="h-4 w-4" />,
            title: t("rec.coreCount.title"),
            body: t("rec.coreCount.body", { cores: hw?.cpu_count ?? "?" }),
        });
    }

    if (proj.bottleneck === "clock_bound") {
        cards.push({
            priority: "high",
            icon: <Zap className="h-4 w-4" />,
            title: t("rec.clockBound.title"),
            body: t("rec.clockBound.body", {
                score: data.scores?.sha256_mhash_per_sec?.toFixed(1),
            }),
        });
    }

    if (proj.est_tls_rps < 10_000) {
        cards.push({
            priority: "med",
            icon: <Lock className="h-4 w-4" />,
            title: t("rec.tlsModerate.title"),
            body: t("rec.tlsModerate.body", { rps: fmtRps(proj.est_tls_rps) }),
        });
    }

    cards.push({
        priority: "info",
        icon: <Network className="h-4 w-4" />,
        title: t("rec.http2.title"),
        body: t("rec.http2.body"),
    });

    cards.push({
        priority: "info",
        icon: <Info className="h-4 w-4" />,
        title: t("rec.calibration.title"),
        body: data.calibration_note ?? t("rec.calibration.fallback"),
    });

    return cards;
}

const PRIORITY_META: Record<
    RecCard["priority"],
    { color: string; borderColor: string; bgClass: string; labelKey: string }
> = {
    high: {
        color: "text-destructive",
        borderColor: "border-l-destructive",
        bgClass: "bg-destructive/5",
        labelKey: "priority.high",
    },
    med: {
        color: "text-amber-400",
        borderColor: "border-l-amber-500",
        bgClass: "bg-amber-500/5",
        labelKey: "priority.med",
    },
    info: {
        color: "text-sky-400",
        borderColor: "border-l-sky-500",
        bgClass: "bg-sky-500/5",
        labelKey: "priority.info",
    },
};

// ─── Capacity chart (horizontal bar) ────────────────────────────────

interface CapRow {
    name: string;
    estMax: number;
    sustained: number;
}

function CapacityChart({ data, t }: { data: BenchmarkResult; t: TFunction }) {
    const proj = data.projections;
    if (!proj) return null;

    const estMaxLabel = t("chart.estMax");
    const sustainedLabel = t("chart.sustained");

    const rows: CapRow[] = [
        {
            name: t("chart.plainForwarding"),
            estMax: proj.est_fwd_rps,
            sustained: Math.round(proj.est_fwd_rps * 0.85),
        },
        {
            name: t("chart.tlsTerminated"),
            estMax: proj.est_tls_rps,
            sustained: Math.round(proj.est_tls_rps * 0.85),
        },
        {
            name: t("chart.wafRateLimit"),
            estMax: proj.est_waf_rps,
            sustained: Math.round(proj.est_waf_rps * 0.85),
        },
    ];

    return (
        <div className="w-full" style={{ height: 220 }}>
            <ResponsiveContainer width="100%" height="100%">
                <BarChart
                    data={rows}
                    layout="vertical"
                    margin={{ top: 4, right: 20, bottom: 4, left: 0 }}
                    barCategoryGap="30%"
                    barGap={3}
                >
                    <CartesianGrid
                        strokeDasharray="3 3"
                        horizontal={false}
                        opacity={0.1}
                    />
                    <XAxis
                        type="number"
                        tick={{ fontSize: 10, fill: "currentColor", opacity: 0.55 }}
                        axisLine={false}
                        tickLine={false}
                        tickFormatter={(v: number) => fmtRps(v)}
                    />
                    <YAxis
                        type="category"
                        dataKey="name"
                        tick={{ fontSize: 11, fill: "currentColor" }}
                        width={130}
                        axisLine={false}
                        tickLine={false}
                    />
                    <Tooltip
                        contentStyle={{
                            background: "hsl(210 26% 9%)",
                            border: "1px solid hsl(210 22% 16%)",
                            borderRadius: 10,
                            fontSize: 11,
                        }}
                        cursor={{ fill: "rgba(255,255,255,0.03)" }}
                        formatter={(v: number, name: string) => [
                            `${fmtRps(v)} ${t("chart.rpsSuffix")}`,
                            name,
                        ]}
                    />
                    <Bar
                        name={estMaxLabel}
                        dataKey="estMax"
                        fill="#22d362"
                        fillOpacity={0.18}
                        radius={[0, 4, 4, 0]}
                        isAnimationActive={false}
                    />
                    <Bar
                        name={sustainedLabel}
                        dataKey="sustained"
                        fill="#22d362"
                        fillOpacity={0.85}
                        radius={[0, 4, 4, 0]}
                        isAnimationActive={false}
                    />
                </BarChart>
            </ResponsiveContainer>
        </div>
    );
}

// ─── Small stat tile ──────────────────────────────────────────────────

function StatTile({
    label,
    value,
    unit,
}: {
    label: string;
    value: string;
    unit?: string;
}) {
    return (
        <div className="rounded-xl border border-border/50 bg-card px-4 py-3 flex flex-col gap-1">
            <span className="text-[10px] uppercase tracking-widest text-muted-foreground font-medium">
                {label}
            </span>
            <span className="text-base font-semibold tabular-nums text-foreground leading-snug">
                {value}
                {unit && (
                    <span className="text-xs font-normal text-muted-foreground ml-1">
                        {unit}
                    </span>
                )}
            </span>
        </div>
    );
}

// ─── Spec row (hardware) ──────────────────────────────────────────────

function SpecRow({
    icon,
    label,
    value,
}: {
    icon: React.ReactNode;
    label: string;
    value: string;
}) {
    return (
        <div className="flex items-center justify-between gap-4 px-4 py-2.5">
            <span className="flex items-center gap-2 text-xs text-muted-foreground min-w-0">
                <span className="text-muted-foreground/60 shrink-0">{icon}</span>
                <span className="truncate">{label}</span>
            </span>
            <span className="text-sm font-semibold tabular-nums text-foreground text-right truncate">
                {value}
            </span>
        </div>
    );
}

// ─── Flood-capacity tests ─────────────────────────────────────────────

const FLOOD_ICON: Record<string, React.ReactNode> = {
    syn: <Network className="h-4 w-4" />,
    http: <Waves className="h-4 w-4" />,
    tls: <Lock className="h-4 w-4" />,
    slowloris: <Timer className="h-4 w-4" />,
    cache: <Zap className="h-4 w-4" />,
};

const VERDICT_META: Record<
    FloodScenario["verdict"],
    { labelKey: string; color: string; bg: string; border: string; icon: React.ReactNode }
> = {
    pass: {
        labelKey: "verdict.pass",
        color: "text-emerald-400",
        bg: "bg-emerald-500/5",
        border: "border-l-emerald-500",
        icon: <CheckCircle2 className="h-4 w-4" />,
    },
    degraded: {
        labelKey: "verdict.degraded",
        color: "text-amber-400",
        bg: "bg-amber-500/5",
        border: "border-l-amber-500",
        icon: <ShieldAlert className="h-4 w-4" />,
    },
    fail: {
        labelKey: "verdict.fail",
        color: "text-destructive",
        bg: "bg-destructive/5",
        border: "border-l-destructive",
        icon: <XCircle className="h-4 w-4" />,
    },
};

function fmtNum(n: number): string {
    if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(2)}M`;
    if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
    return String(n);
}

function FloodCard({ s, t }: { s: FloodScenario; t: TFunction }) {
    const meta = VERDICT_META[s.verdict] ?? VERDICT_META.fail;
    return (
        <div
            className={`rounded-xl border border-l-4 ${meta.border} ${meta.bg} border-border/40 p-4 flex flex-col gap-3`}
        >
            <div className="flex items-start justify-between gap-2">
                <div className="flex items-center gap-2 min-w-0">
                    <span className="text-muted-foreground shrink-0">
                        {FLOOD_ICON[s.id] ?? <Gauge className="h-4 w-4" />}
                    </span>
                    <span className="text-sm font-semibold text-foreground truncate">
                        {s.label}
                    </span>
                </div>
                <span
                    className={`shrink-0 flex items-center gap-1 text-[10px] uppercase tracking-widest font-semibold ${meta.color}`}
                >
                    {meta.icon}
                    {t(meta.labelKey)}
                </span>
            </div>

            <div className="flex items-baseline gap-1">
                <span className="text-2xl font-bold tabular-nums text-foreground">
                    {fmtNum(s.achieved_rps)}
                </span>
                <span className="text-xs text-muted-foreground">{s.unit}</span>
            </div>

            <div className="grid grid-cols-3 gap-2 text-center">
                <div className="rounded-lg bg-card/60 border border-border/40 px-2 py-1.5">
                    <div className="text-[9px] uppercase tracking-widest text-muted-foreground">
                        {t("flood.col.served")}
                    </div>
                    <div className="text-xs font-semibold tabular-nums text-foreground">
                        {fmtNum(s.served)}
                    </div>
                </div>
                <div className="rounded-lg bg-card/60 border border-border/40 px-2 py-1.5">
                    <div className="text-[9px] uppercase tracking-widest text-muted-foreground">
                        {t("flood.col.dropped")}
                    </div>
                    <div
                        className={`text-xs font-semibold tabular-nums ${s.dropped > 0 ? "text-amber-400" : "text-foreground"}`}
                    >
                        {fmtNum(s.dropped)}
                    </div>
                </div>
                <div className="rounded-lg bg-card/60 border border-border/40 px-2 py-1.5">
                    <div className="text-[9px] uppercase tracking-widest text-muted-foreground">
                        {t("flood.col.p99")}
                    </div>
                    <div className="text-xs font-semibold tabular-nums text-foreground">
                        {s.p99_ms.toFixed(1)}ms
                    </div>
                </div>
            </div>

            <p className="text-xs text-muted-foreground leading-relaxed">{s.detail}</p>
        </div>
    );
}

function FloodTable({ scenarios, t }: { scenarios: FloodScenario[]; t: TFunction }) {
    return (
        <div className="overflow-x-auto">
            <table className="w-full text-sm border-collapse">
                <thead>
                    <tr className="text-[10px] uppercase tracking-widest text-muted-foreground border-b border-border/50">
                        <th className="text-left font-medium py-2 pr-3">{t("flood.col.flood")}</th>
                        <th className="text-right font-medium py-2 px-3">{t("flood.col.sustained")}</th>
                        <th className="text-right font-medium py-2 px-3">{t("flood.col.served")}</th>
                        <th className="text-right font-medium py-2 px-3">{t("flood.col.dropped")}</th>
                        <th className="text-right font-medium py-2 px-3">{t("flood.col.p50")}</th>
                        <th className="text-right font-medium py-2 px-3">{t("flood.col.p99")}</th>
                        <th className="text-right font-medium py-2 pl-3">{t("flood.col.verdict")}</th>
                    </tr>
                </thead>
                <tbody>
                    {scenarios.map((s) => {
                        const meta = VERDICT_META[s.verdict] ?? VERDICT_META.fail;
                        return (
                            <tr
                                key={s.id}
                                className="border-b border-border/30 last:border-0"
                            >
                                <td className="py-2.5 pr-3">
                                    <div className="flex items-center gap-2">
                                        <span className="text-muted-foreground">
                                            {FLOOD_ICON[s.id] ?? <Gauge className="h-4 w-4" />}
                                        </span>
                                        <span className="text-foreground">{s.label}</span>
                                    </div>
                                </td>
                                <td className="py-2.5 px-3 text-right tabular-nums text-foreground font-semibold">
                                    {fmtNum(s.achieved_rps)}{" "}
                                    <span className="text-[10px] text-muted-foreground font-normal">
                                        {s.unit}
                                    </span>
                                </td>
                                <td className="py-2.5 px-3 text-right tabular-nums text-muted-foreground">
                                    {fmtNum(s.served)}
                                </td>
                                <td
                                    className={`py-2.5 px-3 text-right tabular-nums ${s.dropped > 0 ? "text-amber-400" : "text-muted-foreground"}`}
                                >
                                    {fmtNum(s.dropped)}
                                </td>
                                <td className="py-2.5 px-3 text-right tabular-nums text-muted-foreground">
                                    {s.p50_ms.toFixed(1)}ms
                                </td>
                                <td className="py-2.5 px-3 text-right tabular-nums text-muted-foreground">
                                    {s.p99_ms.toFixed(1)}ms
                                </td>
                                <td className="py-2.5 pl-3 text-right">
                                    <span
                                        className={`inline-flex items-center gap-1 text-[10px] uppercase tracking-widest font-semibold ${meta.color}`}
                                    >
                                        {meta.icon}
                                        {t(meta.labelKey)}
                                    </span>
                                </td>
                            </tr>
                        );
                    })}
                </tbody>
            </table>
        </div>
    );
}

// ─── multi-target ordering + helpers ──────────────────────────────────

// Fixed left→right display order. Targets returned by the backend are
// re-sorted into this order; any target not in the list is appended after.
const TARGET_DISPLAY_ORDER = [
    "AEGIS (raw)",
    "AEGIS + WAF",
    "nginx",
    "nginx+ModSec+CRS",
    "HAProxy",
    "Caddy",
    "Envoy",
] as const;

// A target paired with its original column index in the unsorted
// targets[]/verdicts[] arrays, so callers can read verdicts[origIdx]
// without an unchecked array lookup.
type OrderedTarget = TargetResult & { origIdx: number };

// Stable-sort the targets[] into the canonical display order, keeping the
// verdicts[] columns aligned: each returned target carries its origIdx so
// the security matrix can read verdicts[origIdx] per column.
function orderTargets(targets: TargetResult[]): { ordered: OrderedTarget[] } {
    const withIdx: OrderedTarget[] = targets.map((t, i) => ({ ...t, origIdx: i }));
    const rank = (name: string) => {
        const r = TARGET_DISPLAY_ORDER.indexOf(name as (typeof TARGET_DISPLAY_ORDER)[number]);
        return r === -1 ? TARGET_DISPLAY_ORDER.length : r;
    };
    withIdx.sort((a, b) => rank(a.name) - rank(b.name));
    return { ordered: withIdx };
}

// ─── Section sub-header (uppercase label inside the report) ────────────

function ReportSection({
    icon,
    label,
    badge,
    children,
}: {
    icon: React.ReactNode;
    label: string;
    badge?: React.ReactNode;
    children: React.ReactNode;
}) {
    return (
        <section className="space-y-4">
            <div className="flex items-center gap-2">
                <span className="text-emerald-400/80">{icon}</span>
                <h3 className="text-[11px] uppercase tracking-[0.18em] text-muted-foreground font-semibold">
                    {label}
                </h3>
                {badge && <span className="ml-auto">{badge}</span>}
            </div>
            {children}
        </section>
    );
}

const ESTIMATE_BADGE_CLS =
    "text-[10px] text-amber-400 bg-amber-500/10 border border-amber-500/30 rounded px-1.5 py-0.5 tracking-wide uppercase font-medium";

// ─── HERO: throughput bars (AEGIS vs the field) ────────────────────────

function isAegis(tg: TargetResult): boolean {
    return tg.kind === "aegis";
}

function ThroughputHero({ compare, t }: { compare: ComparisonResult; t: TFunction }) {
    const { ordered } = orderTargets(compare.targets);

    // Winner = single highest throughput across every available target.
    const winnerRps = Math.max(
        0,
        ...ordered.filter((tg) => tg.available).map((tg) => tg.throughput_rps),
    );
    // Normalise bar widths to the fastest available target.
    const maxRps = Math.max(1, winnerRps);

    // Honest headline: lead with AEGIS + WAF (the real protected config — what
    // you actually run), NOT the raw lane. Prefer comparing it against the only
    // OTHER WAF-protected proxy (nginx+ModSec+CRS) — apples-to-apples on the
    // "protected reverse proxy" axis. Fall back to the fastest plain proxy
    // (framed as parity + protection, since AEGIS+WAF may be slower than a
    // bare proxy). All targets now reverse-proxy to the same upstream.
    const aegisWafTg = ordered.find((tg) => isAegis(tg) && tg.has_waf && tg.available);
    const aegisRps = aegisWafTg?.throughput_rps
        ?? Math.max(0, ...ordered.filter((tg) => isAegis(tg) && tg.available).map((tg) => tg.throughput_rps));
    const otherWafTg = ordered.find((tg) => !isAegis(tg) && tg.has_waf && tg.available);
    const fieldProxies = ordered.filter((tg) => !isAegis(tg) && tg.available);
    const fieldBestProxy = fieldProxies.length
        ? fieldProxies.reduce((a, b) => (b.throughput_rps > a.throughput_rps ? b : a))
        : null;

    let takeaway: string;
    if (otherWafTg && otherWafTg.throughput_rps > 0 && aegisRps > 0) {
        const ratio = aegisRps / otherWafTg.throughput_rps;
        takeaway = t("report.takeawayWaf", {
            aegis: fmtRps(aegisRps),
            rival: otherWafTg.name,
            rivalRps: fmtRps(otherWafTg.throughput_rps),
            ratio: ratio >= 10 ? `${Math.round(ratio)}` : ratio.toFixed(1),
        });
    } else if (fieldBestProxy && fieldBestProxy.throughput_rps > 0 && aegisRps > 0) {
        takeaway = t("report.takeawayPlain", {
            aegis: fmtRps(aegisRps),
            rival: fieldBestProxy.name,
            rivalRps: fmtRps(fieldBestProxy.throughput_rps),
        });
    } else {
        takeaway = t("report.takeawayNoField", { aegis: fmtRps(aegisRps) });
    }

    return (
        <div className="space-y-4">
            <div className="text-[10px] uppercase tracking-widest text-muted-foreground font-medium">
                {t("report.throughputTitle")}
            </div>

            <div className="space-y-3">
                {ordered.map((tg) => {
                    const aegis = isAegis(tg);
                    const isWinner =
                        tg.available && tg.throughput_rps === winnerRps && winnerRps > 0;
                    const pct = tg.available
                        ? Math.max(2, (tg.throughput_rps / maxRps) * 100)
                        : 0;
                    return (
                        <div
                            key={tg.name}
                            className="space-y-1.5 group"
                            title={
                                tg.available
                                    ? t("report.barTooltip", {
                                          name: tg.name,
                                          p50: tg.p50_ms.toFixed(1),
                                          p99: tg.p99_ms.toFixed(1),
                                      })
                                    : undefined
                            }
                        >
                            <div className="flex items-baseline justify-between gap-2">
                                <span className="flex items-center gap-1.5 text-sm font-semibold text-foreground min-w-0">
                                    <span
                                        className={`truncate ${aegis ? "text-emerald-300" : ""}`}
                                    >
                                        {tg.name}
                                    </span>
                                    {tg.has_waf && (
                                        <span className="shrink-0 flex items-center gap-0.5 text-[9px] uppercase tracking-widest font-semibold text-emerald-400/70">
                                            <ShieldAlert className="h-3 w-3" />
                                            {t("report.wafTag")}
                                        </span>
                                    )}
                                    {isWinner && (
                                        <span className="shrink-0 flex items-center gap-0.5 text-[9px] uppercase tracking-widest font-semibold text-emerald-400">
                                            <CheckCircle2 className="h-3 w-3" />
                                            {t("compare.best")}
                                        </span>
                                    )}
                                </span>
                                <span className="shrink-0 tabular-nums text-sm font-bold text-foreground">
                                    {tg.available ? (
                                        <>
                                            {fmtRps(tg.throughput_rps)}{" "}
                                            <span className="text-[10px] font-normal text-muted-foreground">
                                                req/s
                                            </span>
                                        </>
                                    ) : (
                                        <span className="text-[10px] font-medium text-muted-foreground bg-muted/40 border border-border/40 rounded px-1.5 py-0.5">
                                            {t("compare.notInstalled")}
                                        </span>
                                    )}
                                </span>
                            </div>
                            <div className="h-3 w-full rounded-full bg-muted/40 overflow-hidden">
                                <div
                                    className={`h-full rounded-full transition-all ${
                                        !tg.available
                                            ? "bg-muted-foreground/15"
                                            : isWinner
                                              ? "bg-gradient-to-r from-emerald-500 to-teal-400"
                                              : aegis
                                                ? "bg-emerald-500/70"
                                                : "bg-sky-500/40"
                                    }`}
                                    style={{ width: `${pct}%` }}
                                />
                            </div>
                            {/* compact p50/p99 — always visible, subtle */}
                            {tg.available && (
                                <p className="text-[10px] text-muted-foreground/70 tabular-nums">
                                    {t("report.barLatency", {
                                        p50: tg.p50_ms.toFixed(1),
                                        p99: tg.p99_ms.toFixed(1),
                                    })}
                                </p>
                            )}
                        </div>
                    );
                })}
            </div>

            {/* punchy takeaway */}
            <div className="rounded-xl border border-emerald-500/30 bg-gradient-to-br from-emerald-500/[0.08] to-teal-500/[0.03] p-4">
                <p className="text-sm text-emerald-100/90 leading-relaxed font-medium">
                    {takeaway}
                </p>
            </div>

            <p className="text-[11px] text-muted-foreground leading-relaxed">
                {t("compare.protectedNote")}
            </p>
        </div>
    );
}

// ─── HERO: security stat (AEGIS+WAF N/N vs plain proxies 0/N) ──────────

// Count blocked attacks for the column at ordered-index `col`, but only
// over rows where that column's verdict is applicable.
function blockedFor(security: SecurityRow[], origIdx: number): { blocked: number; applicable: number } {
    let blocked = 0;
    let applicable = 0;
    for (const row of security) {
        const v = row.verdicts[origIdx];
        if (!v || !v.applicable) continue;
        applicable += 1;
        if (v.blocked) blocked += 1;
    }
    return { blocked, applicable };
}

function SecurityHero({ compare, t }: { compare: ComparisonResult; t: TFunction }) {
    const total = compare.security.length;
    const { ordered } = orderTargets(compare.targets);

    // Best AEGIS column (highest blocked) vs the strongest plain-proxy
    // column (no WAF) — the honest contrast. Unavailable targets ignored.
    let aegisBlocked = 0;
    let plainBlocked = 0;
    ordered.forEach((tg) => {
        if (!tg.available) return;
        const { blocked } = blockedFor(compare.security, tg.origIdx);
        if (isAegis(tg)) {
            aegisBlocked = Math.max(aegisBlocked, blocked);
        } else if (!tg.has_waf) {
            plainBlocked = Math.max(plainBlocked, blocked);
        }
    });

    return (
        <div className="space-y-4">
            <div className="text-[10px] uppercase tracking-widest text-muted-foreground font-medium">
                {t("report.securityTitle")}
            </div>
            <div className="grid grid-cols-2 gap-3">
                {/* AEGIS — emerald */}
                <div className="rounded-xl border border-emerald-500/40 bg-gradient-to-br from-emerald-500/[0.12] to-emerald-500/[0.03] p-4 flex flex-col items-center justify-center gap-1 text-center">
                    <ShieldAlert className="h-5 w-5 text-emerald-400 mb-1" />
                    <div className="flex items-baseline gap-1">
                        <span className="text-3xl font-bold tabular-nums text-emerald-400">
                            {aegisBlocked}
                        </span>
                        <span className="text-base text-emerald-400/60 font-semibold">/ {total}</span>
                    </div>
                    <span className="text-[10px] uppercase tracking-widest text-muted-foreground font-medium">
                        {t("report.secAegisLabel")}
                    </span>
                </div>
                {/* plain proxies — red */}
                <div className="rounded-xl border border-rose-500/40 bg-gradient-to-br from-rose-500/[0.10] to-rose-500/[0.02] p-4 flex flex-col items-center justify-center gap-1 text-center">
                    <XCircle className="h-5 w-5 text-rose-400 mb-1" />
                    <div className="flex items-baseline gap-1">
                        <span className="text-3xl font-bold tabular-nums text-rose-400">
                            {plainBlocked}
                        </span>
                        <span className="text-base text-rose-400/60 font-semibold">/ {total}</span>
                    </div>
                    <span className="text-[10px] uppercase tracking-widest text-muted-foreground font-medium">
                        {t("report.secPlainLabel")}
                    </span>
                </div>
            </div>
            <p className="text-[11px] text-muted-foreground leading-relaxed">
                {t("report.secPlainNote")}
            </p>
        </div>
    );
}

// ─── Security coverage matrix (section B) ──────────────────────────────

function SecurityMatrix({ compare, t }: { compare: ComparisonResult; t: TFunction }) {
    const total = compare.security.length;
    const { ordered } = orderTargets(compare.targets);

    // Per-column blocked tallies (over applicable rows) for the footer.
    const colTally = ordered.map((tg) => blockedFor(compare.security, tg.origIdx));

    // Summary line: best AEGIS, best nginx+ModSec (has_waf, non-aegis), and
    // the constant 0 for plain proxies.
    let aegisBlocked = 0;
    let modsecBlocked: number | null = null;
    ordered.forEach((tg, i) => {
        if (!tg.available) return;
        const tally = colTally[i];
        if (!tally) return;
        const { blocked } = tally;
        if (isAegis(tg)) {
            if (blocked > aegisBlocked) aegisBlocked = blocked;
        } else if (tg.has_waf) {
            modsecBlocked = Math.max(modsecBlocked ?? 0, blocked);
        }
    });

    return (
        <div className="rounded-xl border border-border/40 bg-card/40 p-4 space-y-3">
            {/* availability chips */}
            <div className="flex items-center gap-2 text-xs flex-wrap">
                {ordered.map((tg) =>
                    tg.available ? (
                        <span
                            key={tg.name}
                            className={`rounded px-2 py-0.5 border ${
                                isAegis(tg)
                                    ? "text-emerald-400 bg-emerald-500/10 border-emerald-500/30"
                                    : "text-sky-300/80 bg-sky-500/10 border-sky-500/25"
                            }`}
                        >
                            {tg.name}
                            {tg.version ? ` ${tg.version}` : ""} ✓
                        </span>
                    ) : (
                        <span
                            key={tg.name}
                            className="rounded px-2 py-0.5 border text-muted-foreground bg-muted/30 border-border/40"
                        >
                            {tg.name} · {t("compare.notInstalled")}
                        </span>
                    ),
                )}
            </div>

            <div className="overflow-x-auto">
                <table className="w-full text-xs border-collapse">
                    <thead>
                        <tr className="text-muted-foreground border-b border-border/40">
                            <th className="text-left py-1.5 pr-3 font-medium sticky left-0 bg-card/40">
                                {t("compare.col.attack")}
                            </th>
                            <th className="text-left py-1.5 pr-3 font-medium">
                                {t("compare.col.category")}
                            </th>
                            {ordered.map((tg) => (
                                <th
                                    key={tg.name}
                                    className={`text-center py-1.5 px-2 font-medium whitespace-nowrap ${
                                        isAegis(tg) ? "text-emerald-300" : ""
                                    }`}
                                >
                                    {tg.name}
                                </th>
                            ))}
                        </tr>
                    </thead>
                    <tbody>
                        {compare.security.map((s) => (
                            <tr key={s.attack} className="border-b border-border/20">
                                <td className="py-1.5 pr-3 text-foreground sticky left-0 bg-card/40">
                                    {s.attack}
                                </td>
                                <td className="py-1.5 pr-3 text-muted-foreground font-mono">
                                    {s.category}
                                </td>
                                {ordered.map((tg) => {
                                    const v = s.verdicts[tg.origIdx];
                                    return (
                                        <td key={tg.name} className="py-1.5 px-2 text-center">
                                            {!v || !v.applicable ? (
                                                <span
                                                    className="text-muted-foreground/50 font-medium"
                                                    title={t("compare.naTitle")}
                                                >
                                                    –
                                                </span>
                                            ) : v.blocked ? (
                                                <CheckCircle2 className="h-4 w-4 text-emerald-400 inline" />
                                            ) : (
                                                <XCircle className="h-4 w-4 text-rose-400 inline" />
                                            )}
                                        </td>
                                    );
                                })}
                            </tr>
                        ))}
                    </tbody>
                    <tfoot>
                        <tr className="border-t border-border/40 text-[10px] uppercase tracking-widest text-muted-foreground">
                            <td className="py-1.5 pr-3 font-medium sticky left-0 bg-card/40">
                                {t("compare.col.blocked")}
                            </td>
                            <td />
                            {ordered.map((tg, i) => (
                                <td
                                    key={tg.name}
                                    className={`py-1.5 px-2 text-center tabular-nums font-semibold ${
                                        isAegis(tg) ? "text-emerald-400" : "text-foreground/80"
                                    }`}
                                >
                                    {tg.available ? `${colTally[i]?.blocked ?? 0}/${total}` : "–"}
                                </td>
                            ))}
                        </tr>
                    </tfoot>
                </table>
            </div>

            {/* summary line */}
            <p className="text-[11px] text-emerald-100/80 leading-relaxed font-medium">
                {t("compare.summaryLine", {
                    aegis: aegisBlocked,
                    total,
                    modsec: modsecBlocked ?? 0,
                    hasModsec: modsecBlocked != null,
                })}
                {modsecBlocked != null
                    ? " " + t("compare.summaryModsec", { modsec: modsecBlocked, total })
                    : ""}
                {" " + t("compare.summaryPlain")}
            </p>
            <p className="text-[11px] text-muted-foreground">{t("compare.securityNote")}</p>
            {compare.caveat && (
                <p className="text-[11px] text-muted-foreground/70 italic leading-relaxed">
                    {compare.caveat}
                </p>
            )}
        </div>
    );
}

// ─── The monolithic report ─────────────────────────────────────────────

function MonolithicReport({
    bench,
    flood,
    compare,
    busy,
    onRerun,
    t,
}: {
    bench: BenchmarkResult;
    flood: FloodResult;
    compare: ComparisonResult;
    busy: boolean;
    onRerun: () => void;
    t: TFunction;
}) {
    const scenarios = flood.scenarios ?? [];
    const totalDurationMs =
        (bench.duration_ms ?? 0) +
        (flood.duration_ms ?? 0) +
        (compare.duration_ms ?? 0);

    return (
        <div
            className="v2-card overflow-hidden"
            style={{ boxShadow: "var(--v2-card-shadow)" }}
        >
            {/* Report header */}
            <div className="flex items-start justify-between gap-4 px-6 pt-6 pb-5 border-b border-border/50 bg-gradient-to-br from-emerald-500/[0.05] to-transparent">
                <div className="min-w-0">
                    <h2 className="text-lg font-bold text-foreground flex items-center gap-2">
                        <BarChart3 className="h-5 w-5 text-emerald-400" />
                        {t("report.title")}
                    </h2>
                    <p className="text-xs text-muted-foreground mt-1 leading-snug max-w-2xl">
                        {t("report.subtitle")}
                    </p>
                    {totalDurationMs > 0 && (
                        <p className="text-[11px] text-muted-foreground/80 mt-1.5 tabular-nums">
                            {t("report.completedIn", { duration: fmtMs(totalDurationMs) })}
                        </p>
                    )}
                </div>
                <Button
                    size="sm"
                    onClick={onRerun}
                    disabled={busy}
                    className="shrink-0 gap-1.5 bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white border-0"
                >
                    <Activity className="h-3.5 w-3.5" />
                    {t("report.rerun")}
                </Button>
            </div>

            <div className="px-6 py-6 space-y-8">
                {/* ── A. HERO: AEGIS vs nginx ─────────────────────────── */}
                <ReportSection
                    icon={<Gauge className="h-4 w-4" />}
                    label={t("report.vsTitle")}
                >
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                        <ThroughputHero compare={compare} t={t} />
                        <SecurityHero compare={compare} t={t} />
                    </div>
                </ReportSection>

                <div className="border-t border-border/40" />

                {/* ── B. SECURITY COVERAGE matrix ─────────────────────── */}
                <ReportSection
                    icon={<ShieldAlert className="h-4 w-4" />}
                    label={t("report.coverageTitle")}
                >
                    <SecurityMatrix compare={compare} t={t} />
                </ReportSection>

                <div className="border-t border-border/40" />

                {/* ── C. FLOOD RESILIENCE ─────────────────────────────── */}
                <ReportSection
                    icon={<Waves className="h-4 w-4" />}
                    label={t("report.floodTitle")}
                    badge={
                        <span className="text-[10px] text-sky-400 bg-sky-500/10 border border-sky-500/30 rounded px-1.5 py-0.5 tracking-wide uppercase">
                            {t("flood.badge.loopback")}
                        </span>
                    }
                >
                    {scenarios.length > 0 && (
                        <div className="space-y-5">
                            <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-3">
                                {scenarios.map((s) => (
                                    <FloodCard key={s.id} s={s} t={t} />
                                ))}
                            </div>

                            <div className="rounded-xl border border-border/40 bg-card/40 p-4">
                                <div className="text-[10px] uppercase tracking-widest text-muted-foreground font-medium mb-2">
                                    {t("flood.summary")}
                                </div>
                                <FloodTable scenarios={scenarios} t={t} />
                            </div>

                            <div className="rounded-xl border border-sky-500/20 bg-sky-500/5 p-4 flex gap-3">
                                <Info className="h-4 w-4 text-sky-400 mt-0.5 shrink-0" />
                                <p className="text-xs text-muted-foreground leading-relaxed">
                                    {flood.caveat}
                                    {flood.duration_ms !== undefined && (
                                        <>
                                            {" "}
                                            {t("flood.suiteCompleted", {
                                                duration: fmtMs(flood.duration_ms),
                                            })}
                                        </>
                                    )}
                                </p>
                            </div>
                        </div>
                    )}
                </ReportSection>

                <div className="border-t border-border/40" />

                {/* ── D. HARDWARE & CAPACITY (supporting footer) ──────── */}
                <ReportSection
                    icon={<Cpu className="h-4 w-4" />}
                    label={t("report.hwTitle")}
                    badge={<span className={ESTIMATE_BADGE_CLS}>{t("badge.estimate")}</span>}
                >
                    <div className="space-y-5">
                        {/* Scores — gauges */}
                        {bench.scores && (
                            <div>
                                <div className="text-[10px] uppercase tracking-widest text-muted-foreground font-medium mb-2">
                                    {t("report.scoresLabel")}
                                </div>
                                <div className="flex flex-wrap justify-around gap-6 py-2">
                                    <ArcGauge
                                        value={bench.scores.cpu_integer_gops}
                                        max={Math.max(bench.scores.cpu_integer_gops * 1.5, 10)}
                                        label={t("scores.cpuInteger")}
                                        unit="Gops"
                                        color="cyan"
                                    />
                                    <ArcGauge
                                        value={bench.scores.sha256_mhash_per_sec}
                                        max={Math.max(bench.scores.sha256_mhash_per_sec * 1.5, 60)}
                                        label={t("scores.sha256")}
                                        unit="MH/s"
                                        color="violet"
                                    />
                                    <ArcGauge
                                        value={bench.scores.mem_bw_gbps}
                                        max={Math.max(bench.scores.mem_bw_gbps * 1.5, 20)}
                                        label={t("scores.memBw")}
                                        unit="GB/s"
                                        color="amber"
                                    />
                                </div>
                            </div>
                        )}

                        {/* Hardware spec + capacity chart side by side */}
                        <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
                            {bench.hardware && (
                                <div>
                                    <div className="text-[10px] uppercase tracking-widest text-muted-foreground font-medium mb-2">
                                        {t("report.specLabel")}
                                    </div>
                                    <div className="rounded-xl border border-border/40 bg-card/40 divide-y divide-border/30">
                                        <SpecRow icon={<Cpu className="h-3.5 w-3.5" />} label={t("hw.cpuModel")} value={bench.hardware.cpu_model} />
                                        <SpecRow icon={<Cpu className="h-3.5 w-3.5" />} label={t("hw.cores")} value={String(bench.hardware.cpu_count)} />
                                        <SpecRow icon={<Cpu className="h-3.5 w-3.5" />} label={t("hw.arch")} value={bench.hardware.arch} />
                                        <SpecRow
                                            icon={<Activity className="h-3.5 w-3.5" />}
                                            label={t("hw.ramTotal")}
                                            value={`${(bench.hardware.ram_total_mb / 1024).toFixed(1)} ${t("unit.gib")}`}
                                        />
                                        <SpecRow
                                            icon={<Activity className="h-3.5 w-3.5" />}
                                            label={t("hw.ramAvailable")}
                                            value={`${(bench.hardware.ram_available_mb / 1024).toFixed(1)} ${t("unit.gib")}`}
                                        />
                                    </div>
                                </div>
                            )}

                            {bench.projections && (
                                <div>
                                    <div className="flex items-center gap-2 mb-2">
                                        <span className="text-[10px] uppercase tracking-widest text-muted-foreground font-medium">
                                            {t("report.capacityLabel")}
                                        </span>
                                        <span className={`${ESTIMATE_BADGE_CLS} ml-auto`}>
                                            {t("badge.estimate")}
                                        </span>
                                    </div>
                                    <CapacityChart data={bench} t={t} />
                                    <div className="mt-3 grid grid-cols-1 sm:grid-cols-3 gap-2">
                                        <StatTile
                                            label={t("tile.plainForwarding")}
                                            value={fmtRps(bench.projections.est_fwd_rps)}
                                            unit={t("unit.rps")}
                                        />
                                        <StatTile
                                            label={t("tile.tlsTerminated")}
                                            value={fmtRps(bench.projections.est_tls_rps)}
                                            unit={t("unit.hs")}
                                        />
                                        <StatTile
                                            label={t("tile.wafRateLimit")}
                                            value={fmtRps(bench.projections.est_waf_rps)}
                                            unit={t("unit.rps")}
                                        />
                                    </div>
                                </div>
                            )}
                        </div>

                        {/* Recommendations (condensed) */}
                        <div>
                            <div className="flex items-center gap-2 mb-2">
                                <span className="text-[10px] uppercase tracking-widest text-muted-foreground font-medium">
                                    {t("report.recommendationsLabel")}
                                </span>
                                <span className={`${ESTIMATE_BADGE_CLS} ml-auto`}>
                                    {t("badge.estimate")}
                                </span>
                            </div>
                            <div className="space-y-2.5">
                                {buildCards(bench, t).map((card, i) => {
                                    const meta = PRIORITY_META[card.priority];
                                    return (
                                        <div
                                            key={i}
                                            className={`rounded-xl border border-l-4 ${meta.borderColor} ${meta.bgClass} border-border/40 p-3.5 flex gap-3`}
                                        >
                                            <div className={`mt-0.5 shrink-0 ${meta.color}`}>
                                                {card.icon}
                                            </div>
                                            <div className="min-w-0 space-y-1">
                                                <div className="flex items-center gap-2 flex-wrap">
                                                    <span className="text-sm font-semibold text-foreground">
                                                        {card.title}
                                                    </span>
                                                    <span
                                                        className={`text-[10px] uppercase tracking-widest font-semibold ${meta.color}`}
                                                    >
                                                        {t(meta.labelKey)}
                                                    </span>
                                                </div>
                                                <p className="text-xs text-muted-foreground leading-relaxed">
                                                    {card.body}
                                                </p>
                                            </div>
                                        </div>
                                    );
                                })}
                            </div>
                        </div>
                    </div>
                </ReportSection>
            </div>
        </div>
    );
}

// ─── Main page ───────────────────────────────────────────────────────

type StageId = "hardware" | "flood" | "nginx";
const STAGE_ORDER: StageId[] = ["hardware", "flood", "nginx"];

interface StageDef {
    id: StageId;
    key: string;
    labelKey: string;
    runFn: () => Promise<{ ok: boolean; queued: boolean }>;
    resultFn: () => Promise<{ status: string }>;
}

// ─── Stage-progress strip ────────────────────────────────────────────

function StageStrip({
    current,
    done,
    t,
}: {
    current: StageId | null;
    done: Set<StageId>;
    t: TFunction;
}) {
    const LABEL: Record<StageId, string> = {
        hardware: t("all.stage.hardware"),
        flood: t("all.stage.flood"),
        nginx: t("all.stage.nginx"),
    };
    return (
        <div className="rounded-xl border border-blue-500/25 bg-blue-500/5 px-4 py-3 flex items-center gap-3 flex-wrap">
            <span className="text-sm text-blue-300 shrink-0">{t("all.running")}</span>
            <div className="flex items-center gap-2 flex-wrap">
                {STAGE_ORDER.map((id, i) => {
                    const isActive = current === id;
                    const isDone = done.has(id);
                    return (
                        <div key={id} className="flex items-center gap-2">
                            {i > 0 && (
                                <span className="text-muted-foreground/50 text-xs">→</span>
                            )}
                            <span
                                className={`inline-flex items-center gap-1.5 text-xs font-medium rounded-lg px-2.5 py-1 border ${
                                    isActive
                                        ? "text-blue-300 border-blue-500/40 bg-blue-500/10"
                                        : isDone
                                          ? "text-emerald-400 border-emerald-500/30 bg-emerald-500/5"
                                          : "text-muted-foreground border-border/40"
                                }`}
                            >
                                {isDone ? (
                                    <CheckCircle2 className="h-3.5 w-3.5" />
                                ) : isActive ? (
                                    <span className="h-2 w-2 rounded-full bg-blue-400 animate-pulse" />
                                ) : (
                                    <span className="h-2 w-2 rounded-full bg-muted-foreground/30" />
                                )}
                                {LABEL[id]}
                            </span>
                        </div>
                    );
                })}
            </div>
        </div>
    );
}

export function BenchmarkPage() {
    const { t } = useTranslation(["benchmark", "common"]);
    const { toast } = useToast();
    const queryClient = useQueryClient();

    const [started, setStarted] = useState(false);
    const [busy, setBusy] = useState(false);
    const [currentStage, setCurrentStage] = useState<StageId | null>(null);
    const [doneStages, setDoneStages] = useState<Set<StageId>>(new Set());
    // single in-flight guard so concurrent runOne/runAll never overlap
    const inFlight = useRef(false);

    // Three result queries — driven by the imperative poller via setQueryData.
    const benchQ = useQuery<BenchmarkResult>({
        queryKey: ["bench-result"],
        queryFn: benchmarkApi.result,
        enabled: started,
        refetchInterval: false,
    });
    const floodQ = useQuery<FloodResult>({
        queryKey: ["flood-result"],
        queryFn: floodApi.result,
        enabled: started,
        refetchInterval: false,
    });
    const compareQ = useQuery<ComparisonResult>({
        queryKey: ["compare-result"],
        queryFn: compareApi.result,
        enabled: started,
        refetchInterval: false,
    });

    const stages: Record<StageId, StageDef> = {
        hardware: {
            id: "hardware",
            key: "bench-result",
            labelKey: "all.stage.hardware",
            runFn: benchmarkApi.run,
            resultFn: benchmarkApi.result,
        },
        flood: {
            id: "flood",
            key: "flood-result",
            labelKey: "all.stage.flood",
            runFn: floodApi.run,
            resultFn: floodApi.result,
        },
        nginx: {
            id: "nginx",
            key: "compare-result",
            labelKey: "all.stage.nginx",
            runFn: compareApi.run,
            resultFn: compareApi.result,
        },
    };

    const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

    // Run one stage: kick it off (409 = already running → just poll), then
    // poll its result endpoint every 1s, writing each snapshot into the
    // react-query cache, until status is "done" or "error".
    const runStage = useCallback(
        async (stage: StageDef) => {
            setCurrentStage(stage.id);
            try {
                await stage.runFn();
            } catch {
                // 409 already-running (or any start error) → fall through to poll
            }
            for (let i = 0; i < 180; i++) {
                let r: { status: string };
                try {
                    r = await stage.resultFn();
                } catch {
                    await sleep(1_000);
                    continue;
                }
                queryClient.setQueryData([stage.key], r);
                if (r.status === "done" || r.status === "error") {
                    if (r.status === "error") {
                        toast({
                            title: t("errorToast.title"),
                            description:
                                (r as { error?: string | null }).error ??
                                t("unknownError"),
                            variant: "destructive",
                        });
                    }
                    return;
                }
                await sleep(1_000);
            }
        },
        [queryClient, toast, t],
    );

    const runAll = useCallback(async () => {
        if (inFlight.current) return;
        inFlight.current = true;
        setBusy(true);
        setStarted(true);
        setDoneStages(new Set());
        try {
            for (const id of STAGE_ORDER) {
                await runStage(stages[id]);
                setDoneStages((prev) => new Set(prev).add(id));
            }
        } finally {
            setBusy(false);
            setCurrentStage(null);
            inFlight.current = false;
        }
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [runStage]);

    const runOne = useCallback(
        async (id: StageId) => {
            if (inFlight.current) return;
            inFlight.current = true;
            setBusy(true);
            setStarted(true);
            try {
                await runStage(stages[id]);
                setDoneStages((prev) => new Set(prev).add(id));
            } finally {
                setBusy(false);
                setCurrentStage(null);
                inFlight.current = false;
            }
        },
        // eslint-disable-next-line react-hooks/exhaustive-deps
        [runStage],
    );

    const data = benchQ.data;
    const floodData = floodQ.data;
    const compareData = compareQ.data;

    // Per-stage re-run remains available for programmatic callers; the
    // monolithic report drives a full re-run via runAll. Reference runOne so
    // the orchestration helper is retained without an unused-symbol error.
    void runOne;

    // The full report renders ONLY when all three stages are done.
    const allDone =
        data?.status === "done" &&
        floodData?.status === "done" &&
        compareData?.status === "done";

    const anyError =
        data?.status === "error" ||
        floodData?.status === "error" ||
        compareData?.status === "error";

    return (
        <div className="space-y-6">
            {/* Page header */}
            <div className="flex items-start justify-between gap-4">
                <div>
                    <h1 className="text-xl font-bold text-foreground flex items-center gap-2">
                        <BarChart3 className="h-5 w-5 text-primary" />
                        {t("title")}
                    </h1>
                    <p className="text-sm text-muted-foreground mt-1">
                        {t("pageDescription")}
                    </p>
                </div>
                <Button
                    onClick={runAll}
                    disabled={busy}
                    className="shrink-0 gap-1.5 bg-gradient-to-r from-blue-600 to-violet-600 hover:from-blue-500 hover:to-violet-500 text-white border-0"
                >
                    <Activity className="h-3.5 w-3.5" />
                    {started ? t("all.rerun") : t("all.run")}
                </Button>
            </div>

            {/* Stage-progress strip — visible only while running */}
            {busy && (
                <StageStrip current={currentStage} done={doneStages} t={t} />
            )}

            {/* RUNNING — tasteful panel for the WHOLE run. NOTE: gated on `busy`
                ONLY (not `!allDone`). Between stages the react-query caches still
                hold the PREVIOUS run's "done" results until the next poll
                overwrites them, so `allDone` flickers true mid-run — which used
                to flash the finished report for a frame on every stage
                transition. Keeping this on pure `busy` (and the report on
                `!busy`) makes the running state stable. */}
            {busy && (
                <MetricCard title={t("report.title")}>
                    <div className="py-10 flex flex-col items-center gap-4 text-center">
                        <div className="w-14 h-14 rounded-2xl bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center">
                            <Activity className="h-7 w-7 text-emerald-400 animate-pulse" />
                        </div>
                        <div className="space-y-1">
                            <p className="text-sm font-medium text-foreground">
                                {t("report.running.heading")}
                            </p>
                            <p className="text-xs text-muted-foreground max-w-md">
                                {t("report.running.body")}
                            </p>
                        </div>
                    </div>
                </MetricCard>
            )}

            {/* THE MONOLITHIC REPORT — only once the run is fully finished
                (`!busy`) AND all three are done. The `!busy` guard is what
                prevents the mid-run flicker from stale "done" caches. */}
            {!busy && allDone && data && floodData && compareData && (
                <MonolithicReport
                    bench={data}
                    flood={floodData}
                    compare={compareData}
                    busy={busy}
                    onRerun={runAll}
                    t={t}
                />
            )}

            {/* Error state — surfaced only when not busy and report can't show */}
            {!busy && !allDone && anyError && (
                <MetricCard title={t("errorCard.title")}>
                    <p className="text-sm text-destructive">
                        {t("errorCard.failed", {
                            error:
                                data?.error ??
                                floodData?.error ??
                                compareData?.error ??
                                t("fallbackError"),
                        })}
                    </p>
                </MetricCard>
            )}

            {/* Idle / not-yet-run placeholder */}
            {!started && !data && !floodData && !compareData && (
                <MetricCard title={t("empty.title")}>
                    <div className="py-12 flex flex-col items-center gap-4 text-center">
                        <div className="w-14 h-14 rounded-2xl bg-muted/30 border border-border/40 flex items-center justify-center">
                            <Zap className="h-7 w-7 text-muted-foreground/30" />
                        </div>
                        <div className="space-y-1">
                            <p className="text-sm font-medium text-foreground">
                                {t("empty.heading")}
                            </p>
                            <p className="text-xs text-muted-foreground max-w-xs">
                                {t("empty.bodyPrefix")}{" "}
                                <strong className="text-foreground">
                                    {t("empty.bodyButton")}
                                </strong>{" "}
                                {t("empty.bodySuffix")}
                            </p>
                        </div>
                    </div>
                </MetricCard>
            )}
        </div>
    );
}
