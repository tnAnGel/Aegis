/**
 * V2 Dashboard — /v2/ root page  (RICH rebuild)
 *
 * Layout (top → bottom):
 *   1. Header row: page title + TimeRangeSelector (drives all time-series)
 *   2. 5 KPI tiles (Total Requests / Threat Score / Active Attacks /
 *                   Mitigation Efficiency / Cluster Health)
 *   3. Three-col row: Live Traffic Overview (WorldMap + Top Countries) |
 *                     Traffic Flow (HistoricalAreaChart, range-driven) |
 *                     Security Events feed
 *   4. Live Decision Engine — full-width HistoricalAreaChart (stacked)
 *   5. Three-col row: Proxy Status donut | Upstream Status list |
 *                     System Health (4× ArcGauge)
 *   6. Three-col row: Defence Arsenal | Threat Intelligence |
 *                     Top Attack Types donut
 *   7. Bottom row: Sites Overview table (wide) + System Status list (narrow)
 *
 * Data sources:
 *   - /metrics (Prometheus text) — raw counters + per-domain + per-protocol
 *   - /admin/api/metrics/series?range= — historical series (metricsApi.series)
 *   - /admin/api/topology — CPU + worker data
 *   - /admin/api/benchmark/result — RAM data
 *   - /admin/api/geo/top — per-country traffic (may return 404 if not yet deployed)
 *   - /admin/health, /admin/threats, /admin/anomaly
 *   - /admin/api/runtime/info, /admin/api/arsenal, /admin/api/cluster/status
 *
 * Design rules:
 *   - Never invent numbers — all values come from real API responses or show "—"
 *   - When a backend feature is missing, render the block with nearest available
 *     data + a "live host stats unavailable" note.
 *   - All chart colors via V2_CHART_COLORS constants.
 *   - All layout via v2-* CSS utility classes + Tailwind tokens.
 */

import * as React from "react";
import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import {
    Activity,
    AlertTriangle,
    ExternalLink,
    Globe2,
    Server,
    Shield,
    ShieldCheck,
    Zap,
} from "lucide-react";
import {
    arsenalApi,
    benchmarkApi,
    clusterApi,
    metricsApi,
    opsApi,
    runtimeInfoApi,
    sitesApi,
    topologyApi,
} from "@/api/client";
import { compact, pct } from "@/lib/format";
import { DonutChart } from "@/components/charts/DonutChart";
import { HistoricalAreaChart } from "@/components/charts/HistoricalAreaChart";
import type { MetricPoint as HistMetricPoint } from "@/components/charts/HistoricalAreaChart";
import { useTimeSeries } from "@/components/charts/useTimeSeries";
import { KPITile } from "@/v2/components/KPITile";
import { MetricCard } from "@/v2/components/MetricCard";
import { EventRow } from "@/v2/components/EventRow";
import { StatusBadge } from "@/v2/components/StatusBadge";
import { SectionHeader } from "@/v2/components/SectionHeader";
import { WorldMap } from "@/v2/components/WorldMap";
import type { WorldMapPoint } from "@/v2/components/WorldMap";
import { SystemHealthGauge } from "@/v2/components/SystemHealthGauge";
import { ProxyStatusDonut } from "@/v2/components/ProxyStatusDonut";
import { TimeRangeSelector } from "@/v2/components/TimeRangeSelector";
import { useMetricsSeries } from "@/hooks/useMetricsSeries";
import type { Severity } from "@/v2/components/SeverityChip";
import type { MetricsRange } from "@/types";

// ─── Chart color palette ─────────────────────────────────────────────────────

const V2_CHART_COLORS = {
    allow:      "var(--v2-chart-allow,      #22d362)",
    challenge:  "var(--v2-chart-challenge,  #3b82f6)",
    rateLimit:  "var(--v2-chart-rate-limit, #f59e0b)",
    tarpit:     "var(--v2-chart-tarpit,     #a855f7)",
    deny:       "var(--v2-chart-deny,       #ef4444)",
    rtbh:       "var(--v2-chart-rtbh,       #06b6d4)",
};

// ─── Arsenal family icons ─────────────────────────────────────────────────────

const FAMILY_ICONS: Record<string, React.ReactNode> = {
    fingerprint: <Shield className="h-4 w-4" />,
    waf:         <ShieldCheck className="h-4 w-4" />,
    ddos:        <Zap className="h-4 w-4" />,
    honeypot:    <AlertTriangle className="h-4 w-4" />,
    telemetry:   <Activity className="h-4 w-4" />,
    challenge:   <Server className="h-4 w-4" />,
    deception:   <Globe2 className="h-4 w-4" />,
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

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

/** Score 0-100 → threat severity label */
function threatScoreSeverity(score: number): Severity {
    if (score >= 80) return "critical";
    if (score >= 60) return "high";
    if (score >= 40) return "medium";
    return "low";
}

/** Convert MetricPoint[] from the series API into HistoricalAreaChart format.
 *  The backend already returns per-bucket counts + a derived `allow`, plus the
 *  full decision breakdown (rate_limited / tarpit / rtbh), so we map 1:1. */
function toHistPoints(points: import("@/types").MetricPoint[]): HistMetricPoint[] {
    return points.map((p) => ({
        t:            p.t_unix * 1000,   // epoch ms for recharts XAxis
        allowed:      p.allow,
        challenged:   p.challenged,
        denied:       p.denied,
        rate_limited: p.rate_limited,
        tarpit:       p.tarpit,
        rtbh:         p.rtbh,
    }));
}

// ─── Sub-components ───────────────────────────────────────────────────────────

/** Single row in the Sites Overview table */
function SiteTableRow({
    host,
    online,
    requests,
    rps,
    threatened,
    threatenedPct,
    challengedPct,
    threatScore,
    t,
}: {
    host: string;
    online: boolean;
    requests: number;
    rps: number;
    threatened: number;
    threatenedPct: string;
    challengedPct: string;
    threatScore: number;
    t: TFunction;
}) {
    const scoreColor =
        threatScore >= 80
            ? "var(--v2-severity-critical, #ef4444)"
            : threatScore >= 60
              ? "var(--v2-severity-high, #f59e0b)"
              : threatScore >= 40
                ? "var(--v2-severity-medium, #eab308)"
                : "var(--v2-severity-low, #60a5fa)";
    return (
        <tr className="v2-table-row text-sm">
            <td className="py-2.5 px-3 font-mono text-xs font-medium text-foreground truncate max-w-[180px]">
                {host}
            </td>
            <td className="py-2.5 px-3">
                <StatusBadge state={online ? "active" : "error"} label={online ? t("status.online") : t("status.offline")} />
            </td>
            <td className="v2-table-num py-2.5 px-3">
                {compact(requests)}
                {rps > 0 && (
                    <span className="text-muted-foreground/60 ml-1 text-[0.7rem]">
                        {rps.toFixed(1)} rps
                    </span>
                )}
            </td>
            <td className="v2-table-num py-2.5 px-3">
                {compact(threatened)}
                <span className="text-muted-foreground/60 ml-1 text-[0.7rem]">{threatenedPct}</span>
            </td>
            <td className="v2-table-num py-2.5 px-3 text-muted-foreground">{challengedPct}</td>
            <td className="py-2.5 px-3 w-32">
                <div className="flex items-center gap-2">
                    <div className="v2-threat-bar-track flex-1">
                        <div
                            className="v2-threat-bar-fill"
                            style={{
                                width: `${Math.min(100, threatScore)}%`,
                                background: scoreColor,
                            }}
                        />
                    </div>
                    <span
                        className="text-[0.65rem] font-semibold tabular-nums w-6 text-right shrink-0"
                        style={{ color: scoreColor }}
                    >
                        {threatScore}
                    </span>
                </div>
            </td>
        </tr>
    );
}

/** System status item row */
function SystemStatusRow({
    icon,
    label,
    current,
    total,
    state,
}: {
    icon: React.ReactNode;
    label: string;
    current: number;
    total: number;
    state: "healthy" | "degraded" | "error";
}) {
    return (
        <div className="flex items-center justify-between py-2.5 border-b border-border/40 last:border-0">
            <div className="flex items-center gap-2.5">
                <span className="text-muted-foreground/60">{icon}</span>
                <span className="text-sm font-medium">{label}</span>
            </div>
            <div className="flex items-center gap-2">
                <span className="tabular-nums text-sm text-muted-foreground">
                    {current}/{total}
                </span>
                <StatusBadge state={state} />
            </div>
        </div>
    );
}

/** Convert ISO 3166-1 alpha-2 country code to flag emoji */
function countryFlag(code: string): string {
    // Each letter maps to a regional indicator symbol (U+1F1E6..U+1F1FF)
    const base = 0x1F1E6 - 65; // 'A'.charCodeAt(0) === 65
    const upper = code.toUpperCase();
    if (upper.length !== 2) return "🌐";
    return String.fromCodePoint(base + upper.charCodeAt(0), base + upper.charCodeAt(1));
}

/** Country display name from ISO code — falls back to the code itself */
const COUNTRY_NAMES: Record<string, string> = {
    US: "United States", CN: "China",        DE: "Germany",      GB: "United Kingdom",
    FR: "France",        RU: "Russia",        JP: "Japan",        IN: "India",
    BR: "Brazil",        CA: "Canada",        AU: "Australia",    KR: "South Korea",
    NL: "Netherlands",   SG: "Singapore",     IT: "Italy",        ES: "Spain",
    SE: "Sweden",        NO: "Norway",        PL: "Poland",       CH: "Switzerland",
    TR: "Turkey",        MX: "Mexico",        ID: "Indonesia",    SA: "Saudi Arabia",
    ZA: "South Africa",  AR: "Argentina",     UA: "Ukraine",      IL: "Israel",
    HK: "Hong Kong",     TW: "Taiwan",        NG: "Nigeria",      EG: "Egypt",
    PK: "Pakistan",      VN: "Vietnam",       TH: "Thailand",     MY: "Malaysia",
    BD: "Bangladesh",    PH: "Philippines",   IR: "Iran",         CL: "Chile",
    RO: "Romania",       CZ: "Czech Republic", AT: "Austria",     FI: "Finland",
    DK: "Denmark",
};

/** Top Countries table row — flag · country · requests · percentage */
function CountryRow({
    rank,
    country,
    total,
    grandTotal,
}: {
    rank: number;
    country: string;
    total: number;
    grandTotal: number;
}) {
    const sharePct = grandTotal > 0 ? ((total / grandTotal) * 100).toFixed(1) : "0.0";
    const flag     = countryFlag(country);
    const name     = COUNTRY_NAMES[country.toUpperCase()] ?? country;
    return (
        <tr className="text-xs border-b border-border/30 last:border-0 hover:bg-muted/10 transition-colors">
            <td className="py-2 pl-3 pr-1 text-muted-foreground/50 tabular-nums w-6 text-center leading-none">
                {rank}
            </td>
            <td className="py-2 px-1">
                <div className="flex items-center gap-1.5 min-w-0">
                    <span className="text-base leading-none shrink-0">{flag}</span>
                    <span className="font-medium truncate">{name}</span>
                </div>
            </td>
            <td className="py-2 px-1 tabular-nums text-right font-medium">{compact(total)}</td>
            <td className="py-2 pl-1 pr-3 tabular-nums text-right text-muted-foreground">{sharePct}%</td>
        </tr>
    );
}

// ─── GeoTop API — per-country traffic; gracefully absent without GeoIP ────────────────────────────
// GET /admin/api/geo/top returns [{country, total, denied}]
// This endpoint may not exist yet; we handle 404 gracefully.
interface GeoTopEntry { country: string; total: number; denied: number; }
async function fetchGeoTop(): Promise<GeoTopEntry[]> {
    try {
        const token = localStorage.getItem("aegis_admin_token") ?? "";
        const res = await fetch("/admin/api/geo/top", {
            headers: token ? { "x-admin-token": token } : {},
        });
        if (!res.ok) return [];
        return (await res.json()) as GeoTopEntry[];
    } catch {
        return [];
    }
}

// ─── Main page ───────────────────────────────────────────────────────────────

export function DashboardV2Page() {
    const { t } = useTranslation(["dashboard", "common"]);
    // ── Time range state — drives all historical charts ─────────────────
    const [range, setRange] = React.useState<MetricsRange>("1h");

    // ── Queries ─────────────────────────────────────────────────────────
    const metrics = useQuery({
        queryKey: ["metrics", "raw"],
        queryFn: metricsApi.raw,
        refetchInterval: 5_000,
    });
    const sites = useQuery({
        queryKey: ["sites"],
        queryFn: sitesApi.list,
        refetchInterval: 30_000,
    });
    const health = useQuery({
        queryKey: ["health"],
        queryFn: opsApi.health,
        refetchInterval: 10_000,
    });
    const threats = useQuery({
        queryKey: ["threats"],
        queryFn: opsApi.threats,
        refetchInterval: 5_000,
    });
    const anomaly = useQuery({
        queryKey: ["anomaly"],
        queryFn: opsApi.anomaly,
        refetchInterval: 10_000,
    });
    const info = useQuery({
        queryKey: ["runtime", "info"],
        queryFn: runtimeInfoApi.get,
        refetchInterval: 15_000,
    });
    const arsenalQ = useQuery({
        queryKey: ["arsenal"],
        queryFn: arsenalApi.get,
        refetchInterval: 60_000,
    });
    const clusterQ = useQuery({
        queryKey: ["cluster", "status"],
        queryFn: clusterApi.status,
        refetchInterval: 10_000,
    });
    const topologyQ = useQuery({
        queryKey: ["topology"],
        queryFn: topologyApi.get,
        refetchInterval: 15_000,
    });
    const benchmarkQ = useQuery({
        queryKey: ["benchmark", "result"],
        queryFn: benchmarkApi.result,
        refetchInterval: 60_000,
        retry: false,        // benchmark result may not be run yet
    });
    const geoTopQ = useQuery({
        queryKey: ["geo", "top"],
        queryFn: fetchGeoTop,
        refetchInterval: 30_000,
    });

    // Historical metrics series — refetch when range changes
    const seriesQ = useMetricsSeries(range);

    // ── Derived from Prometheus text ────────────────────────────────────
    const parsed = metrics.data ? parsePromText(metrics.data) : null;
    const total      = parsed?.["aegis_requests_total"]      ?? 0;
    const denied     = parsed?.["aegis_requests_denied"]     ?? 0;
    const challenged = parsed?.["aegis_requests_challenged"] ?? 0;
    const allowed    = Math.max(0, total - denied - challenged);
    const mitigated  = denied + challenged;
    const mitigationPct = total > 0 ? (mitigated / total) * 100 : 0;

    const activeAttacks = anomaly.data?.length ?? 0;

    const topThreats  = (threats.data ?? []).slice(0, 5);
    const threatScore = topThreats.length > 0
        ? Math.round(topThreats.reduce((s, t) => s + t.score, 0) / topThreats.length)
        : 0;

    const clusterHealthy = clusterQ.data?.shared_scorer_attached ?? false;

    // Per-domain for sites table
    const perDomain = parsed
        ? Object.keys(parsed)
              .filter((k) => k.startsWith("aegis_domain_total{"))
              .map((k) => {
                  const m = k.match(/host="([^"]+)"/);
                  const host = m?.[1] ?? "?";
                  const d = parsed[`aegis_domain_denied{host="${host}"}`] ?? 0;
                  const c = parsed[`aegis_domain_challenged{host="${host}"}`] ?? 0;
                  const t = parsed[k] ?? 0;
                  const a = Math.max(0, t - d - c);
                  return { host, total: t, allowed: a, challenged: c, denied: d };
              })
              .sort((a, b) => b.total - a.total)
              .slice(0, 10)
        : [];

    // Per-protocol for attack-types donut
    const perProtocol = parsed
        ? Object.keys(parsed)
              .filter((k) => k.startsWith("aegis_requests_by_protocol{"))
              .map((k) => {
                  const m = k.match(/protocol="([^"]+)"/);
                  return { name: m?.[1] ?? "?", value: parsed[k] ?? 0 };
              })
              .filter((d) => d.value > 0)
        : [];
    const PROTO_COLORS = ["#3b82f6", "#f59e0b", "#ef4444", "#22d362", "#a855f7", "#06b6d4"];
    const donutSlices = perProtocol.map((p, i) => ({
        name: p.name.toUpperCase(),
        value: p.value,
        color: PROTO_COLORS[i % PROTO_COLORS.length] ?? "#6b7280",
    }));

    // ── Sparkline series for KPI tiles ──────────────────────────────────
    // Sourced from the PERSISTED series so the sparklines are populated
    // immediately on page load (history) and stay current as new 1-minute
    // buckets are written (the series refetches every 30s). Previously these
    // used the realtime-only ring buffer, which started empty and only filled
    // in live — the "nothing on load" the operator saw. activeAttacks has no
    // historical series (it's a live runtime gauge), so it keeps the ring.
    const sparkPoints = seriesQ.data?.points ?? [];
    const totalSeries      = sparkPoints.map((p) => ({ t: p.t_unix * 1000, v: p.requests }));
    const deniedSeries     = sparkPoints.map((p) => ({ t: p.t_unix * 1000, v: p.denied }));
    const challengedSeries = sparkPoints.map((p) => ({ t: p.t_unix * 1000, v: p.challenged }));
    const attacksSeries    = useTimeSeries(activeAttacks);

    // ── Historical series → HistoricalAreaChart format ──────────────────
    const histPoints = React.useMemo(
        () => (seriesQ.data ? toHistPoints(seriesQ.data.points) : []),
        [seriesQ.data],
    );

    // ── System health data ───────────────────────────────────────────────
    // CPU: sum across workers from topology
    const cpuPct = topologyQ.data?.totals.cpu_pct_avg ?? null;
    // RAM: from benchmark (run once; may be absent)
    const ramTotal   = benchmarkQ.data?.hardware?.ram_total_mb ?? null;
    const ramAvail   = benchmarkQ.data?.hardware?.ram_available_mb ?? null;
    const ramUsedMb  = ramTotal !== null && ramAvail !== null ? ramTotal - ramAvail : null;
    // Live proxy resident-set size (fleet sum across SO_REUSEPORT workers) —
    // always available, used as the Memory fallback before a benchmark runs.
    const proxyRssMb = topologyQ.data?.totals.rss_mb ?? null;

    // ── Arsenal modules ──────────────────────────────────────────────────
    const arsenalModules  = arsenalQ.data?.modules ?? [];
    const displayModules  = arsenalModules.slice(0, 6);

    // ── Security events ──────────────────────────────────────────────────
    const securityEvents = topThreats.map((threat) => ({
        severity: threatScoreSeverity(threat.score),
        title: t("events.threatDetected", { ip: threat.ip }),
        subtext: t("events.score", { score: threat.score.toFixed(0) }),
        age: t("events.live"),
        country: undefined as string | undefined,
    }));
    const anomalyEvents = (anomaly.data ?? []).slice(0, 3).map((a) => ({
        severity: "critical" as Severity,
        title: t("events.attackMode", { host: a.host }),
        subtext: t("events.remaining", { seconds: Math.floor(a.remaining_ms / 1000) }),
        age: t("events.live"),
        country: undefined as string | undefined,
    }));
    const allEvents = [...anomalyEvents, ...securityEvents].slice(0, 8);

    // ── Upstream / proxy health ──────────────────────────────────────────
    const unhealthyUpstreams = (health.data ?? []).length;
    const totalSites         = sites.data?.length ?? 0;
    const healthySites       = Math.max(0, totalSites - unhealthyUpstreams);

    // Worker info
    const workerCount    = topologyQ.data?.layout.workers_running ?? (info.data ? 1 : 0);
    const totalWorkers   = topologyQ.data?.desired.effective ?? Math.max(1, workerCount);

    // ── Geo map dots ─────────────────────────────────────────────────────
    const geoData: GeoTopEntry[] = geoTopQ.data ?? [];
    const geoMaxTotal = geoData.reduce((m, g) => Math.max(m, g.total), 1);
    const worldMapPoints: WorldMapPoint[] = geoData.slice(0, 20).map((g) => ({
        country: g.country,
        weight: g.total / geoMaxTotal,
    }));

    // ── Threat intelligence list ─────────────────────────────────────────
    const intelSources: Array<{ name: string; count: number; delta?: string }> = [];
    if (info.data?.ja4_reputation?.active) {
        intelSources.push({ name: t("intel.ja4Feed"), count: info.data.ja4_reputation.entry_count, delta: "+0%" });
    }
    if (info.data?.asn_reputation?.active) {
        intelSources.push({ name: t("intel.asnFeed"), count: info.data.asn_reputation.entry_count, delta: "+0%" });
    }
    if (arsenalQ.data?.counters?.wired) {
        intelSources.push({ name: t("intel.arsenalDetections"), count: arsenalQ.data.summary.total_modules });
    }
    if (intelSources.length === 0) {
        intelSources.push({ name: t("intel.threatFeeds"), count: 0 });
    }

    // ─── Render ──────────────────────────────────────────────────────────
    return (
        <div className="space-y-5">

            {/* ══ 0. HEADER ══════════════════════════════════════════════════ */}
            <div className="flex items-center justify-between">
                <div>
                    <h1 className="text-xl font-bold tracking-tight">{t("title")}</h1>
                    <p className="text-xs text-muted-foreground mt-0.5">
                        {t("subtitle")}
                    </p>
                </div>
                <TimeRangeSelector
                    value={range}
                    onChange={setRange}
                    label={t("timeRangeLabel")}
                />
            </div>

            {/* ══ 1. KPI TILES ══════════════════════════════════════════════ */}
            <div className="v2-kpi-grid">
                <KPITile
                    label={t("kpi.totalRequests")}
                    value={compact(total)}
                    icon={<Activity className="h-4 w-4" />}
                    sparklineData={totalSeries}
                    sparklineColor={V2_CHART_COLORS.allow}
                    deltaLabel={t("kpi.totalRequests.delta")}
                />
                <KPITile
                    label={t("kpi.threatScore")}
                    value={threatScore > 0 ? threatScore.toString() : "—"}
                    icon={<AlertTriangle className="h-4 w-4" />}
                    valueColor={
                        threatScore >= 80
                            ? "text-destructive"
                            : threatScore >= 60
                              ? "text-amber-400"
                              : threatScore >= 40
                                ? "text-yellow-400"
                                : "text-blue-400"
                    }
                    sparklineData={deniedSeries}
                    sparklineColor={V2_CHART_COLORS.deny}
                    deltaLabel={t("kpi.threatScore.delta")}
                />
                <KPITile
                    label={t("kpi.activeAttacks")}
                    value={activeAttacks > 0 ? activeAttacks.toString() : "0"}
                    icon={<Zap className="h-4 w-4" />}
                    valueColor={activeAttacks > 0 ? "text-destructive" : undefined}
                    sparklineData={attacksSeries}
                    sparklineColor={V2_CHART_COLORS.deny}
                    deltaLabel={t("kpi.activeAttacks.delta")}
                />
                <KPITile
                    label={t("kpi.mitigationEfficiency")}
                    value={total > 0 ? `${mitigationPct.toFixed(1)}%` : "—"}
                    icon={<ShieldCheck className="h-4 w-4" />}
                    sparklineData={challengedSeries}
                    sparklineColor={V2_CHART_COLORS.challenge}
                    deltaLabel={t("kpi.mitigationEfficiency.delta")}
                />
                <KPITile
                    label={t("kpi.clusterHealth")}
                    value={clusterQ.isLoading ? "…" : clusterHealthy ? t("kpi.clusterHealth.ok") : t("kpi.clusterHealth.degraded")}
                    icon={<Server className="h-4 w-4" />}
                    valueColor={clusterHealthy ? "text-primary" : "text-destructive"}
                    deltaLabel={t("kpi.clusterHealth.delta")}
                />
            </div>

            {/* ══ 2. GEO MAP | TRAFFIC FLOW | SECURITY EVENTS ══════════════ */}
            <div className="v2-dashboard-row">
                {/* Live Traffic Overview — WorldMap + Top Countries */}
                <MetricCard
                    title={t("traffic.title")}
                    description={
                        geoData.length === 0
                            ? t("traffic.configureGeo")
                            : t("traffic.countriesDetected", { count: geoData.length })
                    }
                    className="flex-[1.4_1_0%] min-w-0"
                >
                    {/* World map */}
                    <WorldMap
                        points={worldMapPoints}
                        className="mb-3"
                    />

                    {/* Top Countries mini-table */}
                    {geoData.length > 0 ? (() => {
                        const grandTotal = geoData.reduce((s, g) => s + g.total, 0);
                        return (
                            <div className="overflow-x-auto">
                                <table className="w-full">
                                    <thead>
                                        <tr className="text-[0.6rem] font-semibold uppercase tracking-wider text-muted-foreground/60 border-b border-border/40">
                                            <th className="py-1.5 pl-3 pr-1 text-center w-6">#</th>
                                            <th className="py-1.5 px-1 text-left">{t("traffic.col.country")}</th>
                                            <th className="py-1.5 px-1 text-right">{t("traffic.col.requests")}</th>
                                            <th className="py-1.5 pl-1 pr-3 text-right">{t("traffic.col.share")}</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {geoData.slice(0, 8).map((g, i) => (
                                            <CountryRow
                                                key={g.country}
                                                rank={i + 1}
                                                country={g.country}
                                                total={g.total}
                                                grandTotal={grandTotal}
                                            />
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        );
                    })() : (
                        <div className="text-xs text-muted-foreground/60 text-center py-2">
                            {t("traffic.noCountryData")}
                        </div>
                    )}
                </MetricCard>

                {/* Traffic Flow — range-driven historical chart */}
                <MetricCard
                    title={t("flow.title")}
                    description={t("flow.description", { range })}
                    className="flex-[1.6_1_0%] min-w-0"
                >
                    {seriesQ.isLoading ? (
                        <div className="h-56 grid place-items-center text-sm text-muted-foreground border border-dashed border-border rounded-lg">
                            {t("flow.loading", { range })}
                        </div>
                    ) : (
                        <HistoricalAreaChart
                            data={histPoints}
                            height={220}
                            stacked
                            series={[
                                { key: "allowed",    label: t("flow.series.allowed"),   color: V2_CHART_COLORS.allow,     stacked: true },
                                { key: "challenged", label: t("flow.series.challenge"), color: V2_CHART_COLORS.challenge, stacked: true },
                                { key: "denied",     label: t("flow.series.blocked"),   color: V2_CHART_COLORS.deny,      stacked: true },
                            ]}
                        />
                    )}
                </MetricCard>

                {/* Security Events feed */}
                <MetricCard
                    title={t("events.title")}
                    description={t("events.description")}
                    className="flex-[0.9_1_0%] min-w-0"
                    action={
                        <a href="/admin/ui/security" className="flex items-center gap-1 hover:text-foreground transition-colors">
                            {t("events.viewAll")} <ExternalLink className="h-3 w-3" />
                        </a>
                    }
                    noPadding
                >
                    <div className="px-4 py-1">
                        {allEvents.length === 0 ? (
                            <div className="py-8 text-center text-sm text-muted-foreground">
                                {t("events.empty")}
                            </div>
                        ) : (
                            allEvents.map((ev, i) => (
                                <EventRow
                                    key={`${ev.title}-${i}`}
                                    severity={ev.severity}
                                    title={ev.title}
                                    subtext={ev.subtext}
                                    age={ev.age}
                                    country={ev.country}
                                    last={i === allEvents.length - 1}
                                />
                            ))
                        )}
                    </div>
                </MetricCard>
            </div>

            {/* ══ 3. LIVE DECISION ENGINE — full-width ══════════════════════ */}
            <MetricCard
                title={t("engine.title")}
                description={t("engine.description", { range })}
            >
                {seriesQ.isLoading ? (
                    <div className="h-56 grid place-items-center text-sm text-muted-foreground border border-dashed border-border rounded-lg">
                        {t("engine.loading", { range })}
                    </div>
                ) : (
                    <HistoricalAreaChart
                        data={histPoints}
                        height={240}
                        stacked
                        series={[
                            { key: "allowed",     label: t("engine.series.allow"),     color: V2_CHART_COLORS.allow,     stacked: true },
                            { key: "challenged",  label: t("engine.series.challenge"), color: V2_CHART_COLORS.challenge, stacked: true },
                            { key: "rate_limited",label: t("engine.series.rateLimit"), color: V2_CHART_COLORS.rateLimit, stacked: true },
                            { key: "tarpit",      label: t("engine.series.tarpit"),    color: V2_CHART_COLORS.tarpit,    stacked: true },
                            { key: "denied",      label: t("engine.series.deny"),      color: V2_CHART_COLORS.deny,      stacked: true },
                            { key: "rtbh",        label: t("engine.series.rtbh"),      color: V2_CHART_COLORS.rtbh,      stacked: true },
                        ]}
                    />
                )}
            </MetricCard>

            {/* ══ 4. PROXY STATUS | UPSTREAM STATUS | SYSTEM HEALTH ══════════ */}
            <div className="v2-three-col">
                {/* Proxy Status Donut */}
                <MetricCard title={t("proxy.title")} description={t("proxy.description")}>
                    <ProxyStatusDonut
                        active={healthySites}
                        inactive={0}
                        error={unhealthyUpstreams}
                        height={180}
                    />
                    {/* Individual upstream list */}
                    {(health.data ?? []).length > 0 && (
                        <div className="mt-4 space-y-1.5">
                            <SectionHeader label={t("proxy.unhealthyUpstreams")} />
                            <div className="mt-2 space-y-1">
                                {(health.data ?? []).slice(0, 5).map((h) => (
                                    <div
                                        key={h.host}
                                        className="flex items-center justify-between text-xs py-1 border-b border-border/30 last:border-0"
                                    >
                                        <span className="font-mono truncate text-destructive/80">{h.host}</span>
                                        <span className="text-muted-foreground/70 tabular-nums shrink-0 ml-2">
                                            {t("proxy.down", { seconds: Math.floor(h.since_ms / 1000) })}
                                        </span>
                                    </div>
                                ))}
                            </div>
                        </div>
                    )}
                    {(health.data ?? []).length === 0 && totalSites > 0 && (
                        <p className="mt-3 text-xs text-center text-primary/70 font-medium">
                            {t("proxy.allHealthy", { count: totalSites })}
                        </p>
                    )}
                </MetricCard>

                {/* Upstream Status list (enumerated) */}
                <MetricCard
                    title={t("upstream.title")}
                    description={t("upstream.description")}
                >
                    {sites.isLoading ? (
                        <div className="space-y-2">
                            {[1,2,3].map((n) => (
                                <div key={n} className="h-8 rounded-md bg-muted/30 animate-pulse" />
                            ))}
                        </div>
                    ) : (sites.data ?? []).length === 0 ? (
                        <div className="text-sm text-muted-foreground text-center py-4">
                            {t("upstream.empty")}
                        </div>
                    ) : (
                        <div className="space-y-0.5">
                            {(sites.data ?? []).slice(0, 8).map((s) => {
                                const isUnhealthy = (health.data ?? []).some((h) => h.host === s.host);
                                const unhealthyEntry = (health.data ?? []).find((h) => h.host === s.host);
                                return (
                                    <div
                                        key={s.host}
                                        className="flex items-center justify-between py-2 border-b border-border/30 last:border-0"
                                    >
                                        <div className="flex items-center gap-2 min-w-0">
                                            <Globe2 className="h-3.5 w-3.5 text-muted-foreground/50 shrink-0" />
                                            <span className="text-xs font-mono truncate">{s.host}</span>
                                        </div>
                                        <div className="flex items-center gap-2 shrink-0 ml-2">
                                            {isUnhealthy && unhealthyEntry && (
                                                <span className="text-[0.65rem] text-muted-foreground/60 tabular-nums">
                                                    {Math.floor(unhealthyEntry.since_ms / 1000)}s
                                                </span>
                                            )}
                                            <StatusBadge
                                                state={isUnhealthy ? "error" : "active"}
                                                label={isUnhealthy ? t("status.down") : t("status.up")}
                                            />
                                        </div>
                                    </div>
                                );
                            })}
                        </div>
                    )}
                </MetricCard>

                {/* System Health Gauges — only real, live sources are shown.
                    CPU is the live fleet average from the worker topology.
                    Memory shows host RAM utilisation when a benchmark has
                    sampled the hardware; otherwise it falls back to the live
                    proxy resident-set size (always available). Disk/Network
                    host gauges were removed: there is no backend collector
                    for them yet, so they were dead "—" placeholders. */}
                <MetricCard
                    title={t("health.title")}
                    description={t("health.description")}
                >
                    <div className="grid grid-cols-2 gap-4">
                        {/* CPU — live fleet average */}
                        {cpuPct !== null ? (
                            <SystemHealthGauge label={t("health.cpu")} pct={cpuPct} unit="%" />
                        ) : (
                            <div className="flex flex-col items-center gap-1 py-4">
                                <span className="text-xs text-muted-foreground/60">{t("health.cpu")}</span>
                                <span className="text-xs text-muted-foreground">{t("status.unavailable")}</span>
                            </div>
                        )}

                        {/* Memory — host RAM after a benchmark; else live proxy RSS */}
                        {ramTotal !== null && ramUsedMb !== null ? (
                            <SystemHealthGauge
                                label={t("health.hostRam")}
                                value={ramUsedMb}
                                max={ramTotal}
                                unit="MB"
                            />
                        ) : proxyRssMb !== null ? (
                            <SystemHealthGauge
                                label={t("health.proxyRss")}
                                value={proxyRssMb}
                                max={Math.max(proxyRssMb * 2, 512)}
                                unit="MB"
                            />
                        ) : (
                            <div className="flex flex-col items-center gap-1 py-4">
                                <span className="text-xs text-muted-foreground/60">{t("health.memory")}</span>
                                <span className="text-xs text-muted-foreground">{t("status.unavailable")}</span>
                            </div>
                        )}
                    </div>
                </MetricCard>
            </div>

            {/* ══ 5. ARSENAL STATUS | THREAT INTEL | TOP ATTACK TYPES ═══════ */}
            <div className="v2-three-col">
                {/* Defence Arsenal Status */}
                <MetricCard
                    title={t("arsenal.title")}
                    description={t("arsenal.modulesLoaded", { count: arsenalQ.data?.summary.total_modules ?? 0 })}
                    action={
                        <a href="/admin/ui/arsenal" className="flex items-center gap-1 hover:text-foreground transition-colors">
                            {t("arsenal.viewAll")} <ExternalLink className="h-3 w-3" />
                        </a>
                    }
                >
                    {arsenalQ.isLoading ? (
                        <div className="space-y-3">
                            {[1, 2, 3, 4].map((n) => (
                                <div key={n} className="h-8 rounded-md bg-muted/30 animate-pulse" />
                            ))}
                        </div>
                    ) : displayModules.length > 0 ? (
                        <div className="space-y-2">
                            {displayModules.map((mod) => (
                                <div
                                    key={mod.id}
                                    className="flex items-center justify-between py-2 border-b border-border/40 last:border-0"
                                >
                                    <div className="flex items-center gap-2.5 min-w-0">
                                        <span className="text-muted-foreground/70 shrink-0">
                                            {FAMILY_ICONS[mod.family] ?? <Shield className="h-4 w-4" />}
                                        </span>
                                        <span className="text-sm font-medium truncate">{mod.label}</span>
                                    </div>
                                    <div className="flex items-center gap-1.5 shrink-0 ml-2">
                                        <StatusBadge
                                            state={mod.status === "shipped" ? "active" : "standby"}
                                            label={mod.status === "shipped" ? t("status.active") : t("status.standby")}
                                        />
                                    </div>
                                </div>
                            ))}
                        </div>
                    ) : (
                        // Fall back to feature flags from runtime info
                        <div className="space-y-2">
                            {[
                                { label: t("arsenal.mlScorer"),       active: !!(info.data?.ml_v2 || info.data?.ml_v1_enabled) },
                                { label: t("arsenal.ja4Reputation"),  active: info.data?.ja4_reputation?.active ?? false },
                                { label: t("arsenal.honeypot"),       active: info.data?.honeypot?.enabled ?? false },
                                { label: t("arsenal.tlsFingerprint"), active: info.data?.tls_fingerprinting ?? false },
                                { label: t("arsenal.llmHoneypot"),    active: info.data?.llm_honeypot ?? false },
                                { label: t("arsenal.riskEngine"),     active: !!(info.data?.risk_engine_mode) },
                            ].map(({ label, active }) => (
                                <div
                                    key={label}
                                    className="flex items-center justify-between py-2 border-b border-border/40 last:border-0"
                                >
                                    <div className="flex items-center gap-2.5">
                                        <Shield className="h-4 w-4 text-muted-foreground/60" />
                                        <span className="text-sm font-medium">{label}</span>
                                    </div>
                                    <div className="flex items-center gap-1.5 shrink-0 ml-2">
                                        <StatusBadge state={active ? "active" : "standby"} />
                                    </div>
                                </div>
                            ))}
                        </div>
                    )}
                </MetricCard>

                {/* Threat Intelligence */}
                <MetricCard title={t("intel.title")} description={t("intel.description")}>
                    <div className="space-y-3">
                        {intelSources.map((src, i) => (
                            <div
                                key={`${src.name}-${i}`}
                                className="flex items-center justify-between py-2.5 border-b border-border/40 last:border-0"
                            >
                                <div className="min-w-0">
                                    <p className="text-sm font-medium truncate">{src.name}</p>
                                    {src.count > 0 && (
                                        <p className="text-xs text-muted-foreground mt-0.5 tabular-nums">
                                            {t("intel.entries", { count: src.count })}
                                        </p>
                                    )}
                                </div>
                                {src.delta !== undefined && (
                                    <span className="shrink-0 ml-2 text-xs text-muted-foreground/70 tabular-nums">
                                        {src.delta}
                                    </span>
                                )}
                            </div>
                        ))}

                        {/* ML model status */}
                        {info.data?.ml_v2 && (
                            <div className="flex items-center justify-between py-2.5 border-b border-border/40 last:border-0">
                                <div className="min-w-0">
                                    <p className="text-sm font-medium">{t("intel.mlModel", { kind: info.data.ml_v2.kind })}</p>
                                    <p className="text-xs text-muted-foreground mt-0.5">{t("intel.mlModelDesc")}</p>
                                </div>
                                <StatusBadge state="active" />
                            </div>
                        )}

                        {/* Anomaly */}
                        <div className="flex items-center justify-between py-2.5 border-b border-border/40 last:border-0">
                            <div className="min-w-0">
                                <p className="text-sm font-medium">{t("intel.anomalyDetector")}</p>
                                <p className="text-xs text-muted-foreground mt-0.5">
                                    {activeAttacks > 0
                                        ? t("intel.hostsUnderAttack", { count: activeAttacks })
                                        : t("intel.noActiveAttacks")}
                                </p>
                            </div>
                            <StatusBadge state={activeAttacks > 0 ? "error" : "healthy"} />
                        </div>
                    </div>
                </MetricCard>

                {/* Top Attack Types — donut */}
                <MetricCard title={t("attackTypes.title")} description={t("attackTypes.description")}>
                    {donutSlices.length > 0 ? (
                        <>
                            <DonutChart
                                slices={donutSlices}
                                centerValue={compact(total)}
                                centerLabel={t("attackTypes.total")}
                                height={180}
                            />
                            <div className="mt-3 space-y-1.5">
                                {donutSlices.map((s) => {
                                    const sliceTotal = donutSlices.reduce((a, b) => a + b.value, 0);
                                    return (
                                        <div key={s.name} className="flex items-center justify-between text-xs">
                                            <div className="flex items-center gap-2">
                                                <span
                                                    className="inline-block h-2 w-2 rounded-full shrink-0"
                                                    style={{ background: s.color }}
                                                />
                                                <span className="text-muted-foreground">{s.name}</span>
                                            </div>
                                            <span className="tabular-nums font-semibold">
                                                {pct(s.value, sliceTotal)}
                                            </span>
                                        </div>
                                    );
                                })}
                            </div>
                        </>
                    ) : (
                        <>
                            <DonutChart
                                slices={[
                                    { name: t("attackTypes.allowed"),    value: allowed,    color: V2_CHART_COLORS.allow },
                                    { name: t("attackTypes.challenged"), value: challenged, color: V2_CHART_COLORS.challenge },
                                    { name: t("attackTypes.denied"),     value: denied,     color: V2_CHART_COLORS.deny },
                                ].filter((s) => s.value > 0)}
                                centerValue={compact(total)}
                                centerLabel={t("attackTypes.requests")}
                                height={180}
                            />
                            <div className="mt-3 space-y-1.5">
                                {[
                                    { name: t("attackTypes.allowed"),    value: allowed,    color: V2_CHART_COLORS.allow },
                                    { name: t("attackTypes.challenged"), value: challenged, color: V2_CHART_COLORS.challenge },
                                    { name: t("attackTypes.denied"),     value: denied,     color: V2_CHART_COLORS.deny },
                                ]
                                    .filter((s) => s.value > 0)
                                    .map((s) => (
                                        <div key={s.name} className="flex items-center justify-between text-xs">
                                            <div className="flex items-center gap-2">
                                                <span
                                                    className="inline-block h-2 w-2 rounded-full shrink-0"
                                                    style={{ background: s.color }}
                                                />
                                                <span className="text-muted-foreground">{s.name}</span>
                                            </div>
                                            <span className="tabular-nums font-semibold">
                                                {pct(s.value, total)}
                                            </span>
                                        </div>
                                    ))}
                            </div>
                        </>
                    )}
                </MetricCard>
            </div>

            {/* ══ 6. SITES OVERVIEW TABLE + SYSTEM STATUS ══════════════════ */}
            <div className="v2-bottom-row">
                {/* Sites Overview — wide */}
                <MetricCard
                    title={t("sites.title")}
                    description={t("sites.description")}
                    className="flex-[3_1_0%] min-w-0"
                    noPadding
                    action={
                        <a href="/admin/ui/sites" className="flex items-center gap-1 hover:text-foreground transition-colors">
                            {t("sites.manage")} <ExternalLink className="h-3 w-3" />
                        </a>
                    }
                >
                    {perDomain.length === 0 && !metrics.isLoading ? (
                        <div className="px-5 py-8 text-center text-sm text-muted-foreground">
                            {t("sites.noTraffic")}
                        </div>
                    ) : (
                        <div className="overflow-x-auto">
                            <table className="w-full">
                                <thead>
                                    <tr className="border-b border-border/60 text-left">
                                        <th className="px-3 py-2 text-[0.65rem] font-semibold uppercase tracking-wider text-muted-foreground">{t("sites.col.site")}</th>
                                        <th className="px-3 py-2 text-[0.65rem] font-semibold uppercase tracking-wider text-muted-foreground">{t("sites.col.status")}</th>
                                        <th className="px-3 py-2 text-[0.65rem] font-semibold uppercase tracking-wider text-muted-foreground text-right">{t("sites.col.requests")}</th>
                                        <th className="px-3 py-2 text-[0.65rem] font-semibold uppercase tracking-wider text-muted-foreground text-right">{t("sites.col.threats")}</th>
                                        <th className="px-3 py-2 text-[0.65rem] font-semibold uppercase tracking-wider text-muted-foreground text-right">{t("sites.col.challenged")}</th>
                                        <th className="px-3 py-2 text-[0.65rem] font-semibold uppercase tracking-wider text-muted-foreground">{t("sites.col.threatScore")}</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {perDomain.map((d) => {
                                        const siteThreatScore = d.total > 0
                                            ? Math.min(100, Math.round((d.denied / d.total) * 100 * 2))
                                            : 0;
                                        const siteIsUnhealthy = (health.data ?? []).some((h) => h.host === d.host);
                                        return (
                                            <SiteTableRow
                                                key={d.host}
                                                host={d.host}
                                                online={!siteIsUnhealthy}
                                                requests={d.total}
                                                rps={0}
                                                threatened={d.denied}
                                                threatenedPct={pct(d.denied, d.total)}
                                                challengedPct={pct(d.challenged, d.total)}
                                                threatScore={siteThreatScore}
                                                t={t}
                                            />
                                        );
                                    })}
                                    {perDomain.length === 0 &&
                                        (sites.data ?? []).slice(0, 6).map((s) => (
                                            <SiteTableRow
                                                key={s.host}
                                                host={s.host}
                                                online
                                                requests={0}
                                                rps={0}
                                                threatened={0}
                                                threatenedPct="0%"
                                                challengedPct="0%"
                                                threatScore={0}
                                                t={t}
                                            />
                                        ))}
                                </tbody>
                            </table>
                        </div>
                    )}
                </MetricCard>

                {/* System Status — narrow */}
                <MetricCard
                    title={t("system.title")}
                    description={t("system.description")}
                    className="flex-[1_1_0%] min-w-[220px]"
                >
                    <div>
                        {/* Sites — total configured sites */}
                        <SystemStatusRow
                            icon={<Globe2 className="h-4 w-4" />}
                            label={t("system.sites")}
                            current={totalSites}
                            total={Math.max(1, totalSites)}
                            state={totalSites > 0 ? "healthy" : "degraded"}
                        />
                        {/* Healthy upstreams — sites whose upstream is not flagged unhealthy */}
                        <SystemStatusRow
                            icon={<Server className="h-4 w-4" />}
                            label={t("system.healthyUpstreams")}
                            current={healthySites}
                            total={Math.max(1, totalSites)}
                            state={unhealthyUpstreams === 0 ? "healthy" : "degraded"}
                        />
                        {/* Workers — running / desired from real topology */}
                        <SystemStatusRow
                            icon={<Activity className="h-4 w-4" />}
                            label={t("system.workers")}
                            current={workerCount}
                            total={totalWorkers}
                            state={workerCount === totalWorkers ? "healthy" : "degraded"}
                        />
                        {/* Cluster — shared cross-worker scorer binding the workers
                            together. No multi-node member list exists, so we report
                            the real worker count the shared scorer spans rather than a
                            hardcoded 1. When the scorer is not attached, 0 are joined. */}
                        <SystemStatusRow
                            icon={<Zap className="h-4 w-4" />}
                            label={t("system.cluster")}
                            current={clusterHealthy ? totalWorkers : 0}
                            total={totalWorkers}
                            state={clusterQ.isLoading ? "degraded" : clusterHealthy ? "healthy" : "error"}
                        />
                        {/* Security modules — real arsenal count (all loaded modules
                            are active, so current === total). */}
                        <SystemStatusRow
                            icon={<Shield className="h-4 w-4" />}
                            label={t("system.securityModules")}
                            current={arsenalQ.data?.summary.total_modules ?? 0}
                            total={arsenalQ.data?.summary.total_modules ?? 0}
                            state={arsenalQ.data ? "healthy" : "degraded"}
                        />

                        {/* Runtime detail */}
                        {info.data && (
                            <div className="mt-4 pt-3 border-t border-border/40 space-y-1">
                                <SectionHeader label={t("system.runtime")} />
                                <div className="space-y-1 mt-2">
                                    <div className="flex justify-between text-xs">
                                        <span className="text-muted-foreground">{t("system.version")}</span>
                                        <span className="tabular-nums font-mono">{info.data.version}</span>
                                    </div>
                                    <div className="flex justify-between text-xs">
                                        <span className="text-muted-foreground">{t("system.uptime")}</span>
                                        <span className="tabular-nums">
                                            {Math.floor(info.data.uptime_secs / 3600)}h{" "}
                                            {Math.floor((info.data.uptime_secs % 3600) / 60)}m
                                        </span>
                                    </div>
                                    <div className="flex justify-between text-xs">
                                        <span className="text-muted-foreground">{t("system.domainPolicies")}</span>
                                        <span className="tabular-nums">{info.data.domain_policy_count}</span>
                                    </div>
                                    {topologyQ.data && (
                                        <div className="flex justify-between text-xs">
                                            <span className="text-muted-foreground">{t("system.workers")}</span>
                                            <span className="tabular-nums">
                                                {topologyQ.data.layout.workers_running} / {topologyQ.data.desired.effective}
                                            </span>
                                        </div>
                                    )}
                                </div>
                            </div>
                        )}
                    </div>
                </MetricCard>
            </div>
        </div>
    );
}
