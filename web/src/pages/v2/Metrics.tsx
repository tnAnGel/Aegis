/**
 * V2 Metrics — /v2/metrics
 *
 * Restyle of the V1 MetricsPage using V2 primitives (MetricCard, KPITile,
 * SectionHeader) and the mockup's dark-teal design language.
 *
 * Data sources:
 *   - metricsApi.series(range) — persisted, time-bucketed fleet history
 *       (/admin/api/metrics/series). Drives ALL rate/area charts + KPI
 *       sparklines so charts are populated on first load instead of waiting
 *       for an in-memory ring buffer to fill.
 *   - metricsApi.raw — 3 s poll, Prometheus text → cumulative KPI numbers,
 *       donuts, top-hosts, raw dump.
 *   - runtimeInfoApi.get — 15 s poll → filter toggle counts.
 *
 * Layout:
 *   1. Page title bar + time-range selector
 *   2. 4 KPI tiles (Requests / Denied / Challenged / Filter toggles)
 *   3. Range-driven historical panels: Traffic / Upstream / Cache
 *   4. XDP fast-path live panel (no persisted history source)
 *   5. 3-col cumulative donuts: Decision mix / Upstream status mix / Top hosts
 *   6. Raw Prometheus dump card
 */

import * as React from "react";
import { useTranslation } from "react-i18next";
import { useQuery } from "@tanstack/react-query";
import {
    Activity,
    AlertOctagon,
    Download,
    Search,
    ShieldOff,
    Zap,
} from "lucide-react";
import { metricsApi, runtimeInfoApi } from "@/api/client";
import { DonutChart } from "@/components/charts/DonutChart";
import { LiveAreaChart } from "@/components/charts/LiveAreaChart";
import { HistoricalAreaChart } from "@/components/charts/HistoricalAreaChart";
import type { MetricPoint as HistMetricPoint } from "@/components/charts/HistoricalAreaChart";
import { useTimeSeriesMulti } from "@/components/charts/useTimeSeries";
import { useMetricsSeries } from "@/hooks/useMetricsSeries";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { compact, pct } from "@/lib/format";
import { KPITile } from "@/v2/components/KPITile";
import { MetricCard } from "@/v2/components/MetricCard";
import { SectionHeader } from "@/v2/components/SectionHeader";
import { TimeRangeSelector } from "@/v2/components/TimeRangeSelector";
import type { MetricsRange } from "@/types";

// ─── Helpers ────────────────────────────────────────────────────────────────

function parsePromText(text: string): Record<string, number> {
    const out: Record<string, number> = {};
    for (const line of text.split("\n")) {
        if (!line || line.startsWith("#")) continue;
        const idx = line.lastIndexOf(" ");
        if (idx <= 0) continue;
        const name = line.slice(0, idx);
        const v = parseFloat(line.slice(idx + 1));
        if (!Number.isNaN(v)) out[name] = v;
    }
    return out;
}

const CHART_COLORS = {
    allowed:   "#22d362", // --v2-chart-allow
    challenged: "#3b82f6", // --v2-chart-challenge
    denied:    "#ef4444", // --v2-chart-deny
    rateLimit: "#f59e0b",
    tarpit:    "#a855f7",
    rtbh:      "#06b6d4",
    s2xx:      "#22d362",
    s4xx:      "#f59e0b",
    s5xx:      "#ef4444",
    cacheHit:  "#06b6d4",
    cacheMiss: "#64748b",
    xdpPass:   "#22d362",
    xdpDrop:   "#ef4444",
    xdpRate:   "#f59e0b",
    xdpSyn:    "#a855f7",
};

/** Convert the persisted series MetricPoint[] into HistoricalAreaChart rows.
 *  Each per-bucket delta is mapped 1:1; charts pick the keys they need. */
function toHistPoints(points: import("@/types").MetricPoint[]): HistMetricPoint[] {
    return points.map((p) => ({
        t:            p.t_unix * 1000, // epoch ms for recharts XAxis
        allowed:      p.allow,
        challenged:   p.challenged,
        denied:       p.denied,
        rate_limited: p.rate_limited,
        tarpit:       p.tarpit,
        rtbh:         p.rtbh,
        s2xx:         p.upstream_2xx,
        s4xx:         p.upstream_4xx,
        s5xx:         p.upstream_5xx,
        cacheHit:     p.cache_hits,
        cacheMiss:    p.cache_misses,
    }));
}

// ─── Sub-components ──────────────────────────────────────────────────────────

/**
 * Historical area panel — range-driven, sourced from persisted series.
 * Shows a loading placeholder while the first fetch resolves and an
 * empty-state when the selected window has no buckets yet.
 */
function HistPanel({
    title,
    description,
    data,
    series,
    loading,
    stacked = true,
}: {
    title: string;
    description?: string;
    data: HistMetricPoint[];
    series: { key: string; label: string; color: string; stacked?: boolean }[];
    loading: boolean;
    stacked?: boolean;
}) {
    const { t } = useTranslation(["metrics", "common"]);
    return (
        <MetricCard title={title} description={description}>
            {loading ? (
                <div className="h-52 grid place-items-center text-sm text-muted-foreground border border-dashed border-border rounded-lg">
                    {t("loadingSeries")}
                </div>
            ) : data.length === 0 ? (
                <div className="h-52 grid place-items-center text-sm text-muted-foreground border border-dashed border-border rounded-lg">
                    {t("noDataInWindow")}
                </div>
            ) : (
                <HistoricalAreaChart
                    data={data}
                    series={series}
                    height={208}
                    stacked={stacked}
                />
            )}
        </MetricCard>
    );
}

/**
 * Live rate panel — wraps LiveAreaChart in a MetricCard. Used only for the
 * XDP fast-path, which has no persisted historical source (kernel counters).
 */
function LiveRatePanel({
    title,
    description,
    rows,
    series,
    stacked = false,
}: {
    title: string;
    description?: string;
    rows: Array<{ t: number } & Record<string, number>>;
    series: { key: string; label: string; color: string }[];
    stacked?: boolean;
}) {
    const { t } = useTranslation(["metrics", "common"]);
    return (
        <MetricCard title={title} description={description}>
            {rows.length < 2 ? (
                <div className="h-52 grid place-items-center text-sm text-muted-foreground border border-dashed border-border rounded-lg">
                    {t("collectingData")}
                </div>
            ) : (
                <LiveAreaChart
                    rows={rows}
                    series={series}
                    height={208}
                    stacked={stacked}
                />
            )}
        </MetricCard>
    );
}

/**
 * Host bar list — top domains by cumulative request volume.
 * Used inside the "Top hosts" cumulative donut panel.
 */
function HostBarList({
    hosts,
}: {
    hosts: Array<{ host: string; total: number }>;
}) {
    const { t } = useTranslation(["metrics", "common"]);
    if (hosts.length === 0) {
        return (
            <div className="h-48 grid place-items-center text-xs text-muted-foreground">
                {t("noDomainCounters")}
            </div>
        );
    }
    const max = hosts[0]?.total ?? 1;
    return (
        <ul className="space-y-2.5 mt-1">
            {hosts.map((d) => {
                const pctWidth = ((d.total / Math.max(max, 1)) * 100).toFixed(1);
                return (
                    <li key={d.host} className="space-y-1">
                        <div className="flex justify-between text-xs">
                            <span className="font-mono truncate text-foreground">{d.host}</span>
                            <span className="tabular-nums text-muted-foreground ml-2">
                                {compact(d.total)}
                            </span>
                        </div>
                        <div className="h-1 rounded-full overflow-hidden bg-muted/40">
                            <div
                                className="h-full rounded-full transition-[width] duration-500"
                                style={{
                                    width: `${pctWidth}%`,
                                    background: "var(--v2-chart-allow, #22d362)",
                                }}
                            />
                        </div>
                    </li>
                );
            })}
        </ul>
    );
}

// ─── Page ───────────────────────────────────────────────────────────────────

export function MetricsV2Page() {
    const { t } = useTranslation(["metrics", "common"]);
    // ── Time range — drives all historical panels + sparklines ───────────
    const [range, setRange] = React.useState<MetricsRange>("1h");
    const seriesQ = useMetricsSeries(range);

    // ── Queries ─────────────────────────────────────────────────────────
    const metrics = useQuery({
        queryKey: ["metrics", "raw"],
        queryFn: metricsApi.raw,
        refetchInterval: 3_000,
    });
    const info = useQuery({
        queryKey: ["runtime", "info"],
        queryFn: runtimeInfoApi.get,
        refetchInterval: 15_000,
    });

    // ── Search filter for raw dump ───────────────────────────────────────
    const [search, setSearch] = React.useState("");

    // ── Derive cumulative counters from Prometheus text ──────────────────
    const parsed = metrics.data ? parsePromText(metrics.data) : {};
    const total      = parsed["aegis_requests_total"]      ?? 0;
    const denied     = parsed["aegis_requests_denied"]     ?? 0;
    const challenged = parsed["aegis_requests_challenged"] ?? 0;
    const allowed    = Math.max(0, total - denied - challenged);
    const s2xx       = parsed["aegis_upstream_2xx"]        ?? 0;
    const s4xx       = parsed["aegis_upstream_4xx"]        ?? 0;
    const s5xx       = parsed["aegis_upstream_5xx"]        ?? 0;
    // XDP fast-path counters are kernel-lifetime CUMULATIVE values fed to a
    // rate-computing hook (delta/elapsed). They MUST stay `undefined` until the
    // first real /metrics fetch lands — otherwise the hook anchors its baseline
    // on a `?? 0` placeholder and the first real sample emits
    // delta = (lifetime_total − 0) = a giant spike that then decays to zero
    // (the "starts at the top, slides to 0" chart artifact). Anchoring on the
    // real cumulative makes the first emitted point a true per-second rate.
    const xdpDeny    = metrics.data ? (parsed["aegis_xdp_drop_deny"] ?? 0) : undefined;
    const xdpRate    = metrics.data ? (parsed["aegis_xdp_drop_rate"] ?? 0) : undefined;
    const xdpSyn     = metrics.data ? (parsed["aegis_xdp_drop_syn"]  ?? 0) : undefined;
    const xdpPass    = metrics.data ? (parsed["aegis_xdp_pass"]      ?? 0) : undefined;

    const filterToggles = info.data?.filter_toggles_count ?? 0;
    const domainOverrides = info.data?.domain_policy_count ?? 0;

    // ── Historical series → chart rows + KPI sparklines ──────────────────
    // Sourced from persisted buckets so they are populated on first load
    // (the previous in-memory ring buffer started empty → "graphs vanish").
    const histPoints = React.useMemo(
        () => (seriesQ.data ? toHistPoints(seriesQ.data.points) : []),
        [seriesQ.data],
    );
    const sparkPoints = seriesQ.data?.points ?? [];
    const totalSeries      = sparkPoints.map((p) => ({ t: p.t_unix * 1000, v: p.requests }));
    const deniedSeries     = sparkPoints.map((p) => ({ t: p.t_unix * 1000, v: p.denied }));
    const challengedSeries = sparkPoints.map((p) => ({ t: p.t_unix * 1000, v: p.challenged }));

    // ── XDP fast-path — live ring (no persisted history source) ──────────
    const xdpStack = useTimeSeriesMulti({
        deny: xdpDeny,
        rate: xdpRate,
        syn: xdpSyn,
        pass: xdpPass,
    });

    // ── Per-domain breakdown for "top hosts" ─────────────────────────────
    const perDomain = Object.keys(parsed)
        .filter((k) => k.startsWith("aegis_domain_total{"))
        .map((k) => {
            const m = k.match(/host="([^"]+)"/);
            const host = m?.[1] ?? "?";
            return { host, total: parsed[k] ?? 0 };
        })
        .sort((a, b) => b.total - a.total)
        .slice(0, 10);

    // ── Donut slices ─────────────────────────────────────────────────────
    const decisionSlices = [
        { name: t("slice.allowed"),    value: allowed,    color: CHART_COLORS.allowed },
        { name: t("slice.challenged"), value: challenged, color: CHART_COLORS.challenged },
        { name: t("slice.denied"),     value: denied,     color: CHART_COLORS.denied },
    ].filter((s) => s.value > 0);

    const statusSlices = [
        { name: "2xx", value: s2xx, color: CHART_COLORS.s2xx },
        { name: "4xx", value: s4xx, color: CHART_COLORS.s4xx },
        { name: "5xx", value: s5xx, color: CHART_COLORS.s5xx },
    ].filter((s) => s.value > 0);

    // ── Filtered raw dump ────────────────────────────────────────────────
    const filteredRaw = (metrics.data ?? "")
        .split("\n")
        .filter((l) => !search || l.toLowerCase().includes(search.toLowerCase()))
        .slice(0, 400)
        .join("\n");

    // ── Export snapshot ──────────────────────────────────────────────────
    function exportSnapshot() {
        const blob = new Blob([metrics.data ?? ""], { type: "text/plain" });
        const url  = URL.createObjectURL(blob);
        const a    = document.createElement("a");
        a.href     = url;
        a.download = "aegis-metrics.txt";
        a.click();
        URL.revokeObjectURL(url);
    }

    // ── Derived delta labels (denial rate, challenge rate) ───────────────
    const deniedPct     = total > 0 ? pct(denied, total)     : "0%";
    const challengedPct = total > 0 ? pct(challenged, total) : "0%";

    const histLoading = seriesQ.isLoading;

    // ── Render ───────────────────────────────────────────────────────────
    return (
        <div className="space-y-5">

            {/* ── Page title bar ─────────────────────────────────────────────── */}
            <div className="flex items-center justify-between gap-4">
                <div>
                    <h1 className="text-xl font-semibold text-foreground tracking-tight">{t("title")}</h1>
                    <p className="text-xs text-muted-foreground mt-1">
                        {t("subtitle", { range })}
                    </p>
                </div>
                <div className="flex items-center gap-3 shrink-0">
                    <TimeRangeSelector
                        value={range}
                        onChange={setRange}
                        label={t("timeRangeLabel")}
                    />
                    <Button
                        variant="outline"
                        size="sm"
                        onClick={exportSnapshot}
                    >
                        <Download className="h-3.5 w-3.5" />
                        {t("exportSnapshot")}
                    </Button>
                </div>
            </div>

            {/* ══ 1. KPI TILES ═════════════════════════════════════════════════ */}
            <div className="grid gap-3 grid-cols-2 lg:grid-cols-4">
                <KPITile
                    label={t("kpi.totalRequests")}
                    value={compact(total)}
                    icon={<Activity className="h-4 w-4" />}
                    sparklineData={totalSeries}
                    sparklineColor={CHART_COLORS.allowed}
                    deltaLabel={t("kpi.cumulativeCounter")}
                />
                <KPITile
                    label={t("kpi.denied")}
                    value={compact(denied)}
                    icon={<ShieldOff className="h-4 w-4" />}
                    sparklineData={deniedSeries}
                    sparklineColor={CHART_COLORS.denied}
                    deltaLabel={t("kpi.ofTotal", { pct: deniedPct })}
                    valueColor={denied > 0 ? "text-destructive" : undefined}
                />
                <KPITile
                    label={t("kpi.challenged")}
                    value={compact(challenged)}
                    icon={<AlertOctagon className="h-4 w-4" />}
                    sparklineData={challengedSeries}
                    sparklineColor={CHART_COLORS.challenged}
                    deltaLabel={t("kpi.ofTotal", { pct: challengedPct })}
                />
                <KPITile
                    label={t("kpi.filterToggles")}
                    value={filterToggles.toLocaleString()}
                    icon={<Zap className="h-4 w-4" />}
                    deltaLabel={t("kpi.perDomainOverrides", { count: domainOverrides })}
                />
            </div>

            {/* ══ 2. HISTORICAL RANGE PANELS ══════════════════════════════════ */}
            <div>
                <SectionHeader label={t("section.historical")} className="mb-3" />
                <p className="text-xs text-muted-foreground mb-4 -mt-2">
                    {t("historical.subtitle", { range })}
                </p>
                <div className="grid gap-4 grid-cols-1 lg:grid-cols-2">
                    <HistPanel
                        title={t("panel.traffic.title")}
                        description={t("panel.traffic.desc")}
                        data={histPoints}
                        loading={histLoading}
                        stacked
                        series={[
                            { key: "allowed",      label: t("series.allowed"),     color: CHART_COLORS.allowed,    stacked: true },
                            { key: "challenged",   label: t("series.challenged"),  color: CHART_COLORS.challenged, stacked: true },
                            { key: "rate_limited", label: t("series.rateLimited"), color: CHART_COLORS.rateLimit, stacked: true },
                            { key: "tarpit",       label: t("series.tarpit"),      color: CHART_COLORS.tarpit,     stacked: true },
                            { key: "denied",       label: t("series.denied"),      color: CHART_COLORS.denied,     stacked: true },
                            { key: "rtbh",         label: t("series.rtbh"),        color: CHART_COLORS.rtbh,       stacked: true },
                        ]}
                    />
                    <HistPanel
                        title={t("panel.upstream.title")}
                        description={t("panel.upstream.desc")}
                        data={histPoints}
                        loading={histLoading}
                        stacked={false}
                        series={[
                            { key: "s2xx", label: t("series.s2xx"), color: CHART_COLORS.s2xx },
                            { key: "s4xx", label: t("series.s4xx"), color: CHART_COLORS.s4xx },
                            { key: "s5xx", label: t("series.s5xx"), color: CHART_COLORS.s5xx },
                        ]}
                    />
                    <HistPanel
                        title={t("panel.cache.title")}
                        description={t("panel.cache.desc")}
                        data={histPoints}
                        loading={histLoading}
                        stacked={false}
                        series={[
                            { key: "cacheHit",  label: t("series.hits"),   color: CHART_COLORS.cacheHit },
                            { key: "cacheMiss", label: t("series.misses"), color: CHART_COLORS.cacheMiss },
                        ]}
                    />
                    <LiveRatePanel
                        title={t("panel.xdp.title")}
                        description={t("panel.xdp.desc")}
                        rows={xdpStack}
                        series={[
                            { key: "pass", label: t("series.pass"),        color: CHART_COLORS.xdpPass },
                            { key: "deny", label: t("series.deny"),        color: CHART_COLORS.xdpDrop },
                            { key: "rate", label: t("series.rateLimited"), color: CHART_COLORS.xdpRate },
                            { key: "syn",  label: t("series.synFlood"),    color: CHART_COLORS.xdpSyn },
                        ]}
                    />
                </div>
            </div>

            {/* ══ 3. CUMULATIVE TOTALS — DONUTS + TOP HOSTS ═══════════════════ */}
            <div>
                <SectionHeader label={t("section.cumulative")} className="mb-3" />
                <div className="grid gap-4 grid-cols-1 sm:grid-cols-2 lg:grid-cols-3">
                    {/* Decision mix donut */}
                    <MetricCard title={t("donut.decision.title")} description={t("donut.decision.desc")}>
                        {decisionSlices.length === 0 ? (
                            <div className="h-52 grid place-items-center text-sm text-muted-foreground">
                                {t("donut.decision.noData")}
                            </div>
                        ) : (
                            <DonutChart
                                slices={decisionSlices}
                                centerValue={compact(total)}
                                centerLabel={t("donut.decision.center")}
                                height={200}
                            />
                        )}
                    </MetricCard>

                    {/* Upstream status mix donut */}
                    <MetricCard title={t("donut.upstream.title")} description={t("donut.upstream.desc")}>
                        {statusSlices.length === 0 ? (
                            <div className="h-52 grid place-items-center text-sm text-muted-foreground">
                                {t("donut.upstream.noData")}
                            </div>
                        ) : (
                            <DonutChart
                                slices={statusSlices}
                                centerValue={compact(s2xx + s4xx + s5xx)}
                                centerLabel={t("donut.upstream.center")}
                                height={200}
                            />
                        )}
                    </MetricCard>

                    {/* Top hosts by volume */}
                    <MetricCard
                        title={t("topHosts.title")}
                        description={t("topHosts.desc")}
                    >
                        <HostBarList hosts={perDomain} />
                    </MetricCard>
                </div>
            </div>

            {/* ══ 4. RAW PROMETHEUS DUMP ══════════════════════════════════════ */}
            <MetricCard
                title={t("raw.title")}
                description={t("raw.desc")}
                action={
                    <div className="relative">
                        <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground pointer-events-none" />
                        <Input
                            value={search}
                            onChange={(e) => setSearch(e.target.value)}
                            placeholder={t("raw.filterPlaceholder")}
                            className="h-8 w-44 pl-7 text-xs font-mono bg-background border-border"
                        />
                    </div>
                }
            >
                {metrics.isLoading ? (
                    <Skeleton className="h-72 w-full" />
                ) : (
                    <pre
                        className="rounded-lg p-3 text-[10px] font-mono leading-tight max-h-96 overflow-auto"
                        style={{
                            background: "hsl(var(--background) / 0.6)",
                            border: "1px solid hsl(var(--border))",
                        }}
                    >
                        {filteredRaw || t("raw.noMatch")}
                    </pre>
                )}
            </MetricCard>
        </div>
    );
}
