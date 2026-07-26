/**
 * V2 SiteDetail page — /v2/sites/:host
 *
 * Same query/mutation wiring as V1 SiteDetail.tsx:
 *   sitesApi.list, sitesApi.update
 *   siteMapApi.forHost
 *   metricsApi.raw
 *   sitePolicyApi.get / put / remove
 *   honeypotApi.builtin, honeypotApi.get, honeypotApi.toggleHost
 *
 * Visual treatment: MetricCard + KPITile for the stats row, V2 table
 * classes throughout, StatusBadge for filter states, SeverityChip-style
 * button groups. Tabs are preserved (same logic, V2 styling).
 */

import * as React from "react";
import { useTranslation } from "react-i18next";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useParams, Link } from "@tanstack/react-router";
import {
    ArrowLeft,
    Activity,
    FlaskConical,
    Gauge,
    Globe,
    Network,
    RotateCcw,
    Save,
    ScrollText,
    ShieldCheck,
    ShieldQuestion,
} from "lucide-react";
import {
    sitesApi,
    siteMapApi,
    honeypotApi,
    sitePolicyApi,
    challengeApi,
    metricsApi,
} from "@/api/client";
import type { DomainChallengeConfig } from "@/api/client";
import { LiveAreaChart } from "@/components/charts/LiveAreaChart";
import { useTimeSeries, useTimeSeriesMulti } from "@/components/charts/useTimeSeries";
import type { Site } from "@/types";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { EmptyState } from "@/components/EmptyState";
import { ErrorState } from "@/components/ErrorState";
import { useToast } from "@/hooks/useToast";
import { MetricCard } from "@/v2/components/MetricCard";
import { KPITile } from "@/v2/components/KPITile";
import { StatusBadge } from "@/v2/components/StatusBadge";
import { cn } from "@/lib/cn";

// ─── Helpers ─────────────────────────────────────────────────────────────────

function parsePromTextMini(text: string): Record<string, number> {
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
            {method}
        </span>
    );
}

// Compact inline pill (TLS / managed badges)
function InlinePill({
    children,
    variant = "default",
}: {
    children: React.ReactNode;
    variant?: "default" | "success" | "warning" | "muted";
}) {
    const cls: Record<string, string> = {
        default: "bg-primary/15 text-primary border-primary/30",
        success: "bg-green-500/15 text-green-400 border-green-500/30",
        warning: "bg-amber-500/15 text-amber-400 border-amber-500/30",
        muted:   "bg-muted/40 text-muted-foreground border-border/60",
    };
    return (
        <span
            className={cn(
                "inline-flex items-center rounded-md px-1.5 py-0.5 text-[0.65rem]",
                "font-semibold uppercase tracking-wider border",
                cls[variant],
            )}
        >
            {children}
        </span>
    );
}

// ─── Page root ────────────────────────────────────────────────────────────────

export function SiteDetailV2Page() {
    const { t } = useTranslation(["sitedetail", "common"]);
    const { host } = useParams({ from: "/sites/$host" }) as { host: string };
    const sites = useQuery({ queryKey: ["sites"], queryFn: sitesApi.list });
    const map = useQuery({
        queryKey: ["site_map", host],
        queryFn: () => siteMapApi.forHost(host),
    });

    const site = sites.data?.find((s) => s.host === host);

    if (!sites.data) {
        return (
            <div className="p-6 text-sm text-muted-foreground animate-pulse">
                {t("loadingSite")}
            </div>
        );
    }

    if (!site) {
        return (
            <div className="space-y-4 p-6">
                <h1 className="text-xl font-bold text-foreground">{host}</h1>
                <p className="text-sm text-muted-foreground">
                    {t("noMatchingSite")}
                </p>
                <Link to="/sites">
                    <Button variant="ghost" size="sm">
                        <ArrowLeft className="h-4 w-4" />
                        {t("backToSites")}
                    </Button>
                </Link>
            </div>
        );
    }

    return (
        <div className="space-y-6">
            {/* ── Back link ─────────────────────────────────────────────── */}
            <div>
                <Link
                    to="/sites"
                    className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground transition-colors"
                >
                    <ArrowLeft className="h-4 w-4" />
                    {t("allSites")}
                </Link>
            </div>

            {/* ── Page heading ──────────────────────────────────────────── */}
            <div className="flex items-start gap-3 flex-wrap">
                <Globe className="h-7 w-7 text-primary mt-0.5 shrink-0" />
                <div className="min-w-0">
                    <h1 className="text-2xl font-bold tracking-tight text-foreground flex items-center gap-2 flex-wrap">
                        {site.host}
                        <StatusBadge state={site.managed ? "active" : "standby"} label={site.managed ? t("managedUI") : t("managedOps")} />
                        {site.tls && (
                            <InlinePill variant="success">
                                <ShieldCheck className="h-3 w-3 mr-0.5" /> TLS
                            </InlinePill>
                        )}
                    </h1>
                    <p className="text-sm text-muted-foreground mt-1">
                        {t("upstreamArrow")}{" "}
                        <span className="font-mono text-foreground/80">
                            {site.upstream ?? "—"}
                        </span>
                    </p>
                </div>
            </div>

            {/* ── Tabs ──────────────────────────────────────────────────── */}
            <Tabs defaultValue="overview">
                <TabsList className="border border-border/60 bg-background/60 h-auto p-1 gap-0.5 flex-wrap">
                    <TabsTrigger value="overview" className="flex items-center gap-1.5 data-[state=active]:bg-primary/15 data-[state=active]:text-primary">
                        <Activity className="h-3.5 w-3.5" />
                        {t("tab.overview")}
                    </TabsTrigger>
                    <TabsTrigger value="security" className="flex items-center gap-1.5 data-[state=active]:bg-primary/15 data-[state=active]:text-primary">
                        <ShieldCheck className="h-3.5 w-3.5" />
                        {t("tab.security")}
                    </TabsTrigger>
                    <TabsTrigger value="endpoints" className="flex items-center gap-1.5 data-[state=active]:bg-primary/15 data-[state=active]:text-primary">
                        <Network className="h-3.5 w-3.5" />
                        {t("tab.endpoints")}
                    </TabsTrigger>
                    <TabsTrigger value="challenge" className="flex items-center gap-1.5 data-[state=active]:bg-primary/15 data-[state=active]:text-primary">
                        <ShieldQuestion className="h-3.5 w-3.5" />
                        {t("tab.challenge", { defaultValue: "Challenge" })}
                    </TabsTrigger>
                    <TabsTrigger value="rate" className="flex items-center gap-1.5 data-[state=active]:bg-primary/15 data-[state=active]:text-primary">
                        <Gauge className="h-3.5 w-3.5" />
                        {t("tab.rate")}
                    </TabsTrigger>
                    <TabsTrigger value="honeypots" className="flex items-center gap-1.5 data-[state=active]:bg-primary/15 data-[state=active]:text-primary">
                        <FlaskConical className="h-3.5 w-3.5" />
                        {t("tab.honeypots")}
                    </TabsTrigger>
                </TabsList>

                <TabsContent value="overview" className="mt-4">
                    <OverviewTab site={site} mapData={map.data?.endpoints ?? []} />
                </TabsContent>

                <TabsContent value="security" className="mt-4">
                    <SecurityTab host={site.host} />
                </TabsContent>

                <TabsContent value="endpoints" className="mt-4">
                    <EndpointsTab
                        host={site.host}
                        endpoints={map.data?.endpoints ?? []}
                    />
                </TabsContent>

                <TabsContent value="challenge" className="mt-4">
                    <ChallengeTab host={site.host} />
                </TabsContent>

                <TabsContent value="rate" className="mt-4">
                    <RateLimitTab site={site} />
                </TabsContent>

                <TabsContent value="honeypots" className="mt-4">
                    <HoneypotsTab host={site.host} />
                </TabsContent>
            </Tabs>
        </div>
    );
}

// ─── Overview tab ─────────────────────────────────────────────────────────────

function OverviewTab({
    site,
    mapData,
}: {
    site: Site;
    mapData: Array<{ method: string; path_pattern: string; hits: number }>;
}) {
    const { t } = useTranslation(["sitedetail", "common"]);
    const total = mapData.reduce((s, e) => s + e.hits, 0);

    const metrics = useQuery({
        queryKey: ["metrics", "raw"],
        queryFn: metricsApi.raw,
        refetchInterval: 3_000,
    });
    const parsed = parsePromTextMini(metrics.data ?? "");
    const domainTotal    = parsed[`aegis_domain_total{host="${site.host}"}`] ?? 0;
    const domainDenied   = parsed[`aegis_domain_denied{host="${site.host}"}`] ?? 0;
    const domainChallenged = parsed[`aegis_domain_challenged{host="${site.host}"}`] ?? 0;
    const domainAllowed  = Math.max(0, domainTotal - domainDenied - domainChallenged);

    const totalSeries     = useTimeSeries(domainTotal);
    const deniedSeries    = useTimeSeries(domainDenied);
    const challengedSeries = useTimeSeries(domainChallenged);
    const trafficStack    = useTimeSeriesMulti({
        allowed:   domainAllowed,
        challenged: domainChallenged,
        denied:    domainDenied,
    });

    return (
        <div className="space-y-4">
            {/* KPI row */}
            <div className="grid gap-4 grid-cols-2 lg:grid-cols-4">
                <KPITile
                    label={t("kpi.totalRequests")}
                    value={domainTotal.toLocaleString()}
                    sparklineData={totalSeries}
                    sparklineColor="var(--v2-chart-allow, #22d362)"
                />
                <KPITile
                    label={t("kpi.denied")}
                    value={domainDenied.toLocaleString()}
                    sparklineData={deniedSeries}
                    sparklineColor="var(--v2-chart-deny, #ef4444)"
                    valueColor={domainDenied > 0 ? "text-destructive" : undefined}
                />
                <KPITile
                    label={t("kpi.challenged")}
                    value={domainChallenged.toLocaleString()}
                    sparklineData={challengedSeries}
                    sparklineColor="var(--v2-chart-challenge, #3b82f6)"
                />
                <KPITile
                    label={t("kpi.endpointsFound")}
                    value={mapData.length.toString()}
                />
            </div>

            {/* Live chart + site config */}
            <div className="grid gap-4 grid-cols-1 lg:grid-cols-3">
                <MetricCard
                    title={t("liveTraffic.title", { host: site.host })}
                    description={t("liveTraffic.description")}
                    className="lg:col-span-2"
                >
                    {trafficStack.length < 2 ? (
                        <div className="h-48 grid place-items-center text-sm text-muted-foreground">
                            {t("collectingData")}
                        </div>
                    ) : (
                        <LiveAreaChart
                            rows={trafficStack}
                            height={192}
                            series={[
                                { key: "allowed",   label: t("series.allowed"),   color: "#22c55e" },
                                { key: "challenged",label: t("series.challenged"), color: "#3b82f6" },
                                { key: "denied",    label: t("series.denied"),    color: "#ef4444" },
                            ]}
                        />
                    )}
                </MetricCard>

                <MetricCard title={t("config.title")}>
                    <dl className="grid grid-cols-2 gap-y-3 text-sm">
                        <dt className="text-muted-foreground text-xs uppercase tracking-wider self-center">
                            {t("config.upstream")}
                        </dt>
                        <dd className="font-mono text-xs truncate text-foreground/90">
                            {site.upstream ?? "—"}
                        </dd>
                        <dt className="text-muted-foreground text-xs uppercase tracking-wider self-center">
                            {t("config.rateLimit")}
                        </dt>
                        <dd className="font-mono text-xs text-foreground/90">
                            {site.rate_limit
                                ? t("config.rateLimitValue", { rps: site.rate_limit.rps, burst: site.rate_limit.burst })
                                : t("config.rateLimitDefault")}
                        </dd>
                        <dt className="text-muted-foreground text-xs uppercase tracking-wider self-center">
                            {t("config.tls")}
                        </dt>
                        <dd>
                            {site.tls ? (
                                <InlinePill variant="success">{t("config.on")}</InlinePill>
                            ) : (
                                <InlinePill variant="muted">{t("config.off")}</InlinePill>
                            )}
                        </dd>
                        <dt className="text-muted-foreground text-xs uppercase tracking-wider self-center">
                            {t("config.managedBy")}
                        </dt>
                        <dd>
                            <StatusBadge
                                state={site.managed ? "active" : "standby"}
                                label={site.managed ? t("managedUI") : t("managedOps")}
                            />
                        </dd>
                    </dl>
                </MetricCard>
            </div>

            {/* Top endpoints */}
            <MetricCard
                title={t("topEndpoints.title")}
                noPadding
            >
                {mapData.length === 0 ? (
                    <div className="p-6">
                        <EmptyState
                            title={t("topEndpoints.emptyTitle")}
                            description={t("topEndpoints.emptyDesc")}
                        />
                    </div>
                ) : (
                    <Table>
                        <TableHeader>
                            <TableRow className="border-b border-border/60 hover:bg-transparent">
                                <TableHead className="px-5 w-20 text-muted-foreground text-[0.65rem] uppercase tracking-wider">
                                    {t("table.method")}
                                </TableHead>
                                <TableHead className="text-muted-foreground text-[0.65rem] uppercase tracking-wider">
                                    {t("table.path")}
                                </TableHead>
                                <TableHead className="text-right text-muted-foreground text-[0.65rem] uppercase tracking-wider">
                                    {t("table.hits")}
                                </TableHead>
                                <TableHead className="w-32 text-muted-foreground text-[0.65rem] uppercase tracking-wider">
                                    {t("table.share")}
                                </TableHead>
                            </TableRow>
                        </TableHeader>
                        <TableBody>
                            {mapData
                                .slice()
                                .sort((a, b) => b.hits - a.hits)
                                .slice(0, 10)
                                .map((e) => {
                                    const max = mapData[0]?.hits ?? 1;
                                    const pct = (e.hits / Math.max(max, 1)) * 100;
                                    return (
                                        <TableRow
                                            key={`${e.method}:${e.path_pattern}`}
                                            className="v2-table-row"
                                        >
                                            <TableCell className="px-5">
                                                <MethodBadge method={e.method} />
                                            </TableCell>
                                            <TableCell className="font-mono text-xs text-foreground/90">
                                                {e.path_pattern}
                                            </TableCell>
                                            <TableCell className="text-right v2-table-num font-mono text-xs">
                                                {e.hits.toLocaleString()}
                                            </TableCell>
                                            <TableCell>
                                                <div className="h-1.5 rounded-full bg-muted/40 overflow-hidden">
                                                    <div
                                                        className="h-full bg-primary rounded-full"
                                                        style={{ width: `${pct}%` }}
                                                    />
                                                </div>
                                            </TableCell>
                                        </TableRow>
                                    );
                                })}
                        </TableBody>
                    </Table>
                )}
            </MetricCard>

            <p className="text-[0.7rem] text-muted-foreground/60 italic px-1">
                {t("overview.footnote", { total: total.toLocaleString() })}
            </p>
        </div>
    );
}

// ─── Security tab ─────────────────────────────────────────────────────────────

function SecurityTab({ host }: { host: string }) {
    const { t } = useTranslation(["sitedetail", "common"]);
    const qc = useQueryClient();
    const { toast } = useToast();

    const data = useQuery({
        queryKey: ["site-policy", host],
        queryFn: () => sitePolicyApi.get(host),
    });

    const save = useMutation({
        mutationFn: (next: { name: string; override: boolean | null }) => {
            const current = data.data?.policy.filter_enabled ?? {};
            const updated: Record<string, boolean> = { ...current };
            if (next.override === null) {
                delete updated[next.name];
            } else {
                updated[next.name] = next.override;
            }
            return sitePolicyApi.put(host, {
                filter_enabled: updated,
                endpoint_policies: data.data?.policy.endpoint_policies ?? {},
            });
        },
        onSuccess: () => {
            qc.invalidateQueries({ queryKey: ["site-policy", host] });
            toast({ title: t("security.overrideSaved"), variant: "success" });
        },
        onError: (e: unknown) =>
            toast({ title: t("security.saveFailed"), description: String(e), variant: "destructive" }),
    });

    const clearAll = useMutation({
        mutationFn: () => sitePolicyApi.remove(host),
        onSuccess: () => {
            qc.invalidateQueries({ queryKey: ["site-policy", host] });
            toast({ title: t("security.allCleared"), variant: "success" });
        },
    });

    if (data.isError) {
        return (
            <ErrorState
                title={t("security.loadError")}
                error={data.error}
                onRetry={() => data.refetch()}
            />
        );
    }
    if (!data.data) {
        return (
            <p className="text-sm text-muted-foreground p-4 animate-pulse">
                {t("loading", { ns: "common" })}
            </p>
        );
    }

    const overrides = data.data.policy.filter_enabled;
    const overrideCount = Object.keys(overrides).length;

    return (
        <div className="space-y-4">
            <MetricCard
                title={t("security.overridesTitle")}
                description={`${t("security.overridesDescBase")} ${overrideCount > 0 ? t("security.activeOverrides", { count: overrideCount }) : t("security.noActiveOverrides")}`}
                action={
                    overrideCount > 0 ? (
                        <Button
                            variant="outline"
                            size="sm"
                            onClick={() => clearAll.mutate()}
                            disabled={clearAll.isPending}
                            className="text-xs"
                        >
                            {t("security.clearAll", { count: overrideCount })}
                        </Button>
                    ) : undefined
                }
            >
                <div className="space-y-2">
                    {data.data.global_filters.map((f) => {
                        const override = overrides[f.name];
                        const effective = override === undefined ? f.enabled : override;
                        const choice: "inherit" | "on" | "off" =
                            override === undefined
                                ? "inherit"
                                : override
                                    ? "on"
                                    : "off";
                        return (
                            <div
                                key={f.name}
                                className={cn(
                                    "flex items-center justify-between gap-3",
                                    "border border-border/60 rounded-lg px-4 py-3",
                                    "bg-card/40 hover:bg-accent/20 transition-colors",
                                )}
                            >
                                <div className="flex-1 min-w-0">
                                    <p className="text-sm font-medium font-mono text-foreground/90">
                                        {f.name}
                                    </p>
                                    <p className="text-[0.65rem] text-muted-foreground mt-0.5">
                                        {t("security.global")}{" "}
                                        <strong className={f.enabled ? "text-green-400" : "text-muted-foreground"}>
                                            {f.enabled ? t("security.statusOn") : t("security.statusOff")}
                                        </strong>
                                        {override !== undefined && (
                                            <>
                                                {" · "}{t("security.override")}{" "}
                                                <strong className={override ? "text-green-400" : "text-destructive"}>
                                                    {override ? t("security.forceOn") : t("security.forceOff")}
                                                </strong>
                                            </>
                                        )}
                                        {" · "}{t("security.effectiveFor", { host })}{" "}
                                        <StatusBadge
                                            state={effective ? "active" : "standby"}
                                            label={effective ? t("security.statusOn") : t("security.statusOff")}
                                        />
                                    </p>
                                </div>
                                <div className="flex items-center gap-1 shrink-0">
                                    {(["inherit", "on", "off"] as const).map((label) => (
                                        <Button
                                            key={label}
                                            variant={choice === label ? "default" : "ghost"}
                                            size="sm"
                                            className={cn(
                                                "h-7 text-[0.65rem] px-2.5 uppercase tracking-wider",
                                                choice === label &&
                                                    "bg-primary/20 text-primary hover:bg-primary/30",
                                            )}
                                            onClick={() =>
                                                save.mutate({
                                                    name: f.name,
                                                    override:
                                                        label === "inherit"
                                                            ? null
                                                            : label === "on",
                                                })
                                            }
                                        >
                                            {t(`security.choice.${label}`)}
                                        </Button>
                                    ))}
                                </div>
                            </div>
                        );
                    })}
                </div>
            </MetricCard>
            <p className="text-[0.7rem] text-muted-foreground/60 italic px-1">
                {t("security.footnote")}
            </p>
        </div>
    );
}

// ─── Endpoints tab ────────────────────────────────────────────────────────────

function EndpointsTab({
    host,
    endpoints,
}: {
    host: string;
    endpoints: Array<{
        method: string;
        path_pattern: string;
        hits: number;
        status_2xx: number;
        status_4xx: number;
        status_5xx: number;
    }>;
}) {
    const { t } = useTranslation(["sitedetail", "common"]);
    const qc = useQueryClient();
    const { toast } = useToast();

    const policyQ = useQuery({
        queryKey: ["site-policy", host],
        queryFn: () => sitePolicyApi.get(host),
    });

    const save = useMutation({
        mutationFn: (next: { path: string; action: string | null }) => {
            const cur = policyQ.data?.policy ?? {
                filter_enabled: {},
                endpoint_policies: {},
            };
            const updated: Record<string, string> = { ...cur.endpoint_policies };
            if (next.action === null) {
                delete updated[next.path];
            } else {
                updated[next.path] = next.action;
            }
            return sitePolicyApi.put(host, {
                ...cur,
                endpoint_policies: updated as Record<
                    string,
                    "allow" | "block" | "challenge" | "tarpit"
                >,
            });
        },
        onSuccess: () => {
            qc.invalidateQueries({ queryKey: ["site-policy", host] });
            toast({ title: t("endpoints.policyUpdated"), variant: "success" });
        },
        onError: (e: unknown) =>
            toast({ title: t("endpoints.saveFailed"), description: String(e), variant: "destructive" }),
    });

    const endpointPolicies = policyQ.data?.policy.endpoint_policies ?? {};

    return (
        <MetricCard
            title={t("endpoints.title", { host })}
            description={t("endpoints.description")}
            noPadding
        >
            {endpoints.length === 0 ? (
                <div className="p-6">
                    <EmptyState
                        title={t("endpoints.emptyTitle")}
                        description={t("endpoints.emptyDesc")}
                    />
                </div>
            ) : (
                <Table className="text-xs">
                    <TableHeader>
                        <TableRow className="border-b border-border/60 hover:bg-transparent">
                            <TableHead className="px-5 w-16 text-muted-foreground text-[0.65rem] uppercase tracking-wider">
                                {t("table.method")}
                            </TableHead>
                            <TableHead className="text-muted-foreground text-[0.65rem] uppercase tracking-wider">
                                {t("endpoints.pathPattern")}
                            </TableHead>
                            <TableHead className="text-right text-muted-foreground text-[0.65rem] uppercase tracking-wider">
                                {t("table.hits")}
                            </TableHead>
                            <TableHead className="text-right text-green-500/70 text-[0.65rem] uppercase tracking-wider">
                                2xx
                            </TableHead>
                            <TableHead className="text-right text-amber-500/70 text-[0.65rem] uppercase tracking-wider">
                                4xx
                            </TableHead>
                            <TableHead className="text-right text-red-500/70 text-[0.65rem] uppercase tracking-wider">
                                5xx
                            </TableHead>
                            <TableHead className="w-60 text-muted-foreground text-[0.65rem] uppercase tracking-wider pr-5">
                                {t("endpoints.action")}
                            </TableHead>
                        </TableRow>
                    </TableHeader>
                    <TableBody>
                        {endpoints.map((e) => {
                            const current = endpointPolicies[e.path_pattern] ?? null;
                            return (
                                <TableRow
                                    key={`${e.method}:${e.path_pattern}`}
                                    className="v2-table-row"
                                >
                                    <TableCell className="px-5">
                                        <MethodBadge method={e.method} />
                                    </TableCell>
                                    <TableCell className="font-mono text-xs text-foreground/90">
                                        {e.path_pattern}
                                    </TableCell>
                                    <TableCell className="text-right v2-table-num">
                                        {e.hits.toLocaleString()}
                                    </TableCell>
                                    <TableCell className="text-right v2-table-num text-green-400/80">
                                        {e.status_2xx}
                                    </TableCell>
                                    <TableCell className="text-right v2-table-num text-amber-400/80">
                                        {e.status_4xx}
                                    </TableCell>
                                    <TableCell className="text-right v2-table-num text-red-400/80">
                                        {e.status_5xx}
                                    </TableCell>
                                    <TableCell className="pr-5">
                                        <div className="flex items-center gap-1 flex-wrap">
                                            {(
                                                [
                                                    "inherit",
                                                    "allow",
                                                    "challenge",
                                                    "tarpit",
                                                    "block",
                                                ] as const
                                            ).map((a) => (
                                                <Button
                                                    key={a}
                                                    size="sm"
                                                    variant={
                                                        (current ?? "inherit") === a
                                                            ? "default"
                                                            : "ghost"
                                                    }
                                                    className={cn(
                                                        "h-6 text-[0.6rem] px-2 uppercase tracking-wider",
                                                        (current ?? "inherit") === a &&
                                                            "bg-primary/20 text-primary hover:bg-primary/30",
                                                    )}
                                                    aria-pressed={(current ?? "inherit") === a}
                                                    onClick={() =>
                                                        save.mutate({
                                                            path: e.path_pattern,
                                                            action:
                                                                a === "inherit" ? null : a,
                                                        })
                                                    }
                                                >
                                                    {t(`endpoints.act.${a}`)}
                                                </Button>
                                            ))}
                                            <Button
                                                asChild
                                                size="sm"
                                                variant="ghost"
                                                className="h-6 text-[0.6rem] px-2 uppercase tracking-wider gap-1 text-muted-foreground hover:text-primary"
                                            >
                                                <Link
                                                    to="/logs"
                                                    search={{ host, endpoint: e.path_pattern }}
                                                    aria-label={t("endpoints.viewLogsAria", {
                                                        defaultValue: "Логи для {{endpoint}}",
                                                        endpoint: e.path_pattern,
                                                    })}
                                                >
                                                    <ScrollText className="h-3 w-3" />
                                                    {t("endpoints.act.logs", { defaultValue: "Логи" })}
                                                </Link>
                                            </Button>
                                        </div>
                                    </TableCell>
                                </TableRow>
                            );
                        })}
                    </TableBody>
                </Table>
            )}
        </MetricCard>
    );
}

// ─── Rate limit tab ───────────────────────────────────────────────────────────

// ─── Challenge tab ──────────────────────────────────────────────────────────

/** Per-host challenge controls: master on/off (runtime policy overlay) plus
 *  the individual challenge behaviours (DomainChallengeConfig). Works for
 *  ops-managed sites too — everything is a runtime overlay, no .conf edit. */
/** Challenge behaviours, grouped. `label`/`desc` are i18n keys in the
 *  `sitedetail` namespace, resolved with t() inside the component. `groupKey`
 *  is the i18n key for the group heading. */
type ChallengeOption = {
    key: keyof DomainChallengeConfig;
    label: string;
    desc: string;
};
const CHALLENGE_GROUPS: Array<{ groupKey: string; options: ChallengeOption[] }> = [
    {
        groupKey: "challenge.group.behaviours",
        options: [
            { key: "adaptive",        label: "challenge.opt.adaptive.label",       desc: "challenge.opt.adaptive.desc" },
            { key: "argon2_pow",      label: "challenge.opt.argon2_pow.label",     desc: "challenge.opt.argon2_pow.desc" },
            { key: "privacy_pass",    label: "challenge.opt.privacy_pass.label",   desc: "challenge.opt.privacy_pass.desc" },
            { key: "chained_trust",   label: "challenge.opt.chained_trust.label",  desc: "challenge.opt.chained_trust.desc" },
            { key: "decoy_captcha",   label: "challenge.opt.decoy_captcha.label",  desc: "challenge.opt.decoy_captcha.desc" },
            { key: "honeypot_fields", label: "challenge.opt.honeypot_fields.label", desc: "challenge.opt.honeypot_fields.desc" },
            { key: "varied_errors",   label: "challenge.opt.varied_errors.label",  desc: "challenge.opt.varied_errors.desc" },
            { key: "trust_for_auth",  label: "challenge.opt.trust_for_auth.label", desc: "challenge.opt.trust_for_auth.desc" },
        ],
    },
    {
        groupKey: "challenge.group.passive",
        options: [
            { key: "ja4_ua_consistency",      label: "challenge.opt.ja4_ua_consistency.label",      desc: "challenge.opt.ja4_ua_consistency.desc" },
            { key: "header_fingerprint",      label: "challenge.opt.header_fingerprint.label",      desc: "challenge.opt.header_fingerprint.desc" },
            { key: "h2_fingerprint",          label: "challenge.opt.h2_fingerprint.label",          desc: "challenge.opt.h2_fingerprint.desc" },
            { key: "datacenter_asn_challenge", label: "challenge.opt.datacenter_asn_challenge.label", desc: "challenge.opt.datacenter_asn_challenge.desc" },
        ],
    },
    {
        groupKey: "challenge.group.browser",
        options: [
            { key: "headless_detection", label: "challenge.opt.headless_detection.label", desc: "challenge.opt.headless_detection.desc" },
            { key: "webgl_audio_fp",     label: "challenge.opt.webgl_audio_fp.label",     desc: "challenge.opt.webgl_audio_fp.desc" },
            { key: "dom_timing_entropy", label: "challenge.opt.dom_timing_entropy.label", desc: "challenge.opt.dom_timing_entropy.desc" },
            { key: "proof_of_click",     label: "challenge.opt.proof_of_click.label",     desc: "challenge.opt.proof_of_click.desc" },
        ],
    },
    {
        groupKey: "challenge.group.enforcement",
        options: [
            { key: "reputation_difficulty", label: "challenge.opt.reputation_difficulty.label", desc: "challenge.opt.reputation_difficulty.desc" },
            { key: "fail_to_xdp_deny",      label: "challenge.opt.fail_to_xdp_deny.label",      desc: "challenge.opt.fail_to_xdp_deny.desc" },
            { key: "turnstile",             label: "challenge.opt.turnstile.label",             desc: "challenge.opt.turnstile.desc" },
        ],
    },
];

function ChallengeTab({ host }: { host: string }) {
    const { t } = useTranslation(["sitedetail", "common"]);
    const qc = useQueryClient();
    const { toast } = useToast();

    const policyQ = useQuery({
        queryKey: ["site-policy", host],
        queryFn: () => sitePolicyApi.get(host),
    });
    const challengeQ = useQuery({
        queryKey: ["site-challenge", host],
        queryFn: () => challengeApi.getHost(host),
    });

    const challengeEnabled = policyQ.data?.policy.filter_enabled?.challenge;
    const globalChallenge =
        policyQ.data?.global_filters.find((f) => f.name === "challenge")?.enabled ?? false;
    const effectiveOn = challengeEnabled ?? globalChallenge;
    const cfg = challengeQ.data?.config ?? {};

    // Master toggle → per-host challenge filter override in the policy overlay.
    const setMaster = useMutation({
        mutationFn: (on: boolean) => {
            const cur = policyQ.data?.policy ?? { filter_enabled: {}, endpoint_policies: {} };
            return sitePolicyApi.put(host, {
                ...cur,
                filter_enabled: { ...cur.filter_enabled, challenge: on },
            });
        },
        onSuccess: () => {
            qc.invalidateQueries({ queryKey: ["site-policy", host] });
            toast({ title: t("challenge.saved"), variant: "success" });
        },
        onError: (e: unknown) =>
            toast({ title: t("challenge.saveFailed"), description: String(e), variant: "destructive" }),
    });

    // Per-behaviour toggle → merge into the DomainChallengeConfig overlay.
    const setOption = useMutation({
        mutationFn: (next: Partial<DomainChallengeConfig>) =>
            challengeApi.putHost(host, { ...cfg, ...next }),
        onSuccess: () => {
            qc.invalidateQueries({ queryKey: ["site-challenge", host] });
            toast({ title: t("challenge.saved"), variant: "success" });
        },
        onError: (e: unknown) =>
            toast({ title: t("challenge.saveFailed"), description: String(e), variant: "destructive" }),
    });

    const reset = useMutation({
        mutationFn: () => challengeApi.deleteHost(host),
        onSuccess: () => {
            qc.invalidateQueries({ queryKey: ["site-challenge", host] });
            toast({ title: t("challenge.resetDone"), variant: "success" });
        },
        onError: (e: unknown) =>
            toast({ title: t("challenge.resetFailed"), description: String(e), variant: "destructive" }),
    });

    return (
        <div className="space-y-4">
            {/* Master switch */}
            <MetricCard
                title={t("challenge.title", { host })}
                description={t("challenge.description")}
            >
                <div className="flex items-center justify-between gap-4 py-1">
                    <div className="min-w-0">
                        <p className="text-sm font-medium text-foreground">{t("challenge.masterLabel")}</p>
                        <p className="text-xs text-muted-foreground mt-0.5">
                            {t("challenge.masterDescPrefix")}{" "}
                            <span className={globalChallenge ? "text-green-400" : "text-muted-foreground"}>
                                {globalChallenge ? t("challenge.on") : t("challenge.off")}
                            </span>
                            {t("challenge.masterDescSuffix")}
                        </p>
                    </div>
                    <Switch
                        checked={effectiveOn}
                        disabled={setMaster.isPending || policyQ.isLoading}
                        onCheckedChange={(v) => setMaster.mutate(v)}
                        aria-label={t("challenge.masterAria")}
                    />
                </div>
            </MetricCard>

            {/* Per-behaviour toggles */}
            <MetricCard
                title={t("challenge.behavioursTitle")}
                description={t("challenge.behavioursDescription")}
                action={
                    Object.keys(cfg).length > 0 ? (
                        <button
                            onClick={() => reset.mutate()}
                            disabled={reset.isPending}
                            className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-colors"
                        >
                            <RotateCcw className="h-3 w-3" /> {t("challenge.reset")}
                        </button>
                    ) : undefined
                }
            >
                <div className="space-y-5">
                    {CHALLENGE_GROUPS.map((group) => (
                        <div key={group.groupKey}>
                            <p className="text-[11px] font-semibold uppercase tracking-wide text-muted-foreground/80 mb-1">
                                {t(group.groupKey)}
                            </p>
                            <div className="divide-y divide-border/40">
                                {group.options.map((opt) => (
                                    <div key={opt.key} className="flex items-start justify-between gap-4 py-3">
                                        <div className="min-w-0">
                                            <p className="text-sm font-medium text-foreground/90">{t(opt.label)}</p>
                                            <p className="text-xs text-muted-foreground mt-0.5">{t(opt.desc)}</p>
                                        </div>
                                        <Switch
                                            checked={!!cfg[opt.key]}
                                            disabled={setOption.isPending || challengeQ.isLoading}
                                            onCheckedChange={(v) => setOption.mutate({ [opt.key]: v })}
                                            aria-label={t(opt.label)}
                                        />
                                    </div>
                                ))}
                            </div>
                        </div>
                    ))}
                </div>
                {!effectiveOn && (
                    <p className="text-xs text-muted-foreground/70 italic mt-3">
                        {t("challenge.offNote")}
                    </p>
                )}
            </MetricCard>
        </div>
    );
}

function RateLimitTab({ site }: { site: Site }) {
    const { t } = useTranslation(["sitedetail", "common"]);
    const qc = useQueryClient();
    const { toast } = useToast();

    // V234 — the per-host rate limit lives in the runtime policy overlay
    // (PUT /admin/api/sites/<host>/policy), NOT the site `.conf`. The
    // overlay is disk-backed + cross-worker and editable through the
    // admin API, so this works for ops-managed sites too (their config
    // files are read-only). The rate-limit filter consults this override
    // before the global/static limits at request time.
    const policyQ = useQuery({
        queryKey: ["site-policy", site.host],
        queryFn: () => sitePolicyApi.get(site.host),
    });
    const override = policyQ.data?.policy.rate_limit ?? null;

    const [rps, setRps] = React.useState("");
    const [burst, setBurst] = React.useState("");

    // Seed inputs once the overlay loads; fall back to any static `.conf`
    // limit reported on the site object purely for initial display.
    React.useEffect(() => {
        const r = override?.rps ?? site.rate_limit?.rps;
        const b = override?.burst ?? site.rate_limit?.burst;
        setRps(r != null ? String(r) : "");
        setBurst(b != null ? String(b) : "");
    }, [override?.rps, override?.burst, site.rate_limit?.rps, site.rate_limit?.burst]);

    const save = useMutation({
        mutationFn: (rl: { rps: number; burst: number } | null) => {
            // Merge into the existing policy so we don't wipe filter or
            // endpoint overrides. null clears just the rate-limit field.
            const cur = policyQ.data?.policy ?? {
                filter_enabled: {},
                endpoint_policies: {},
            };
            return sitePolicyApi.put(site.host, { ...cur, rate_limit: rl });
        },
        onSuccess: () => {
            qc.invalidateQueries({ queryKey: ["site-policy", site.host] });
            qc.invalidateQueries({ queryKey: ["sites"] });
            toast({ title: t("rate.saved"), variant: "success" });
        },
        onError: (e: unknown) =>
            toast({ title: t("rate.saveFailed"), description: String(e), variant: "destructive" }),
    });

    return (
        <MetricCard
            title={t("rate.title")}
            description={t("rate.description")}
        >
            <div className="space-y-4 max-w-sm">
                <div className="grid gap-3 sm:grid-cols-2">
                    <div className="space-y-1.5">
                        <Label htmlFor="v2-rps" className="text-xs uppercase tracking-wider text-muted-foreground">
                            {t("rate.rps")}
                        </Label>
                        <Input
                            id="v2-rps"
                            type="number"
                            min={1}
                            value={rps}
                            onChange={(e) => setRps(e.target.value)}
                            placeholder={t("rate.rpsPlaceholder")}
                            className="bg-background/60 border-border/60 font-mono"
                        />
                    </div>
                    <div className="space-y-1.5">
                        <Label htmlFor="v2-burst" className="text-xs uppercase tracking-wider text-muted-foreground">
                            {t("rate.burst")}
                        </Label>
                        <Input
                            id="v2-burst"
                            type="number"
                            min={1}
                            value={burst}
                            onChange={(e) => setBurst(e.target.value)}
                            placeholder={t("rate.burstPlaceholder")}
                            className="bg-background/60 border-border/60 font-mono"
                        />
                    </div>
                </div>

                <div className="flex gap-2">
                    <Button
                        disabled={save.isPending}
                        onClick={() => {
                            const r = Number.parseInt(rps, 10);
                            const b = Number.parseInt(burst, 10);
                            if (
                                !Number.isFinite(r) ||
                                !Number.isFinite(b) ||
                                r < 1 ||
                                b < 1
                            ) {
                                toast({
                                    title: t("rate.invalid"),
                                    variant: "destructive",
                                });
                                return;
                            }
                            save.mutate({ rps: r, burst: b });
                        }}
                        className="flex items-center gap-1.5"
                    >
                        <Save className="h-3.5 w-3.5" />
                        {t("save", { ns: "common" })}
                    </Button>
                    {override && (
                        <Button
                            variant="outline"
                            disabled={save.isPending}
                            onClick={() => save.mutate(null)}
                        >
                            {t("rate.clearOverride")}
                        </Button>
                    )}
                </div>

                <p className="text-xs text-muted-foreground/70">
                    {override
                        ? t("rate.activeOverride", { rps: override.rps, burst: override.burst })
                        : t("rate.noOverride")}
                    {site.managed === false && (
                        <>
                            {" "}{t("rate.opsManaged")}{" "}
                            <code className="font-mono">
                                /etc/aegis/sites-enabled/{site.host}.conf
                            </code>
                            .
                        </>
                    )}
                </p>
            </div>
        </MetricCard>
    );
}

// ─── Honeypots tab ────────────────────────────────────────────────────────────

function HoneypotsTab({ host }: { host: string }) {
    const { t } = useTranslation(["sitedetail", "common"]);
    const builtin = useQuery({
        queryKey: ["honeypots", "builtin"],
        queryFn: honeypotApi.builtin,
    });
    const state = useQuery({
        queryKey: ["honeypots", "state"],
        queryFn: honeypotApi.get,
    });
    const qc = useQueryClient();

    const toggleHost = useMutation({
        mutationFn: (args: { pack_id: string; enabled: boolean }) =>
            honeypotApi.toggleHost(host, args.pack_id, args.enabled),
        onSuccess: () => qc.invalidateQueries({ queryKey: ["honeypots", "state"] }),
    });

    if (!builtin.data || !state.data) {
        return (
            <p className="text-sm text-muted-foreground p-4 animate-pulse">
                {t("loading", { ns: "common" })}
            </p>
        );
    }

    const hostOverrides = state.data.per_host[host] ?? {};

    return (
        <MetricCard
            title={t("honeypots.title", { host })}
            description={t("honeypots.description")}
        >
            <div className="space-y-2">
                {builtin.data.map((p) => {
                    const globalOn =
                        state.data.packs[p.id] ?? p.enabled ?? true;
                    const overridden =
                        host in (hostOverrides ?? {})
                            ? hostOverrides[p.id] !== undefined
                            : false;
                    const effective = overridden ? hostOverrides[p.id] : globalOn;

                    return (
                        <div
                            key={p.id}
                            className={cn(
                                "flex items-start justify-between gap-4",
                                "border border-border/60 rounded-lg px-4 py-3",
                                "bg-card/40 hover:bg-accent/20 transition-colors",
                            )}
                        >
                            <div className="min-w-0">
                                <p className="text-sm font-medium text-foreground/90 flex items-center gap-2">
                                    <FlaskConical className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
                                    {p.name}
                                    <span className="text-[0.65rem] text-muted-foreground font-mono">
                                        {p.id}
                                    </span>
                                </p>
                                <p className="text-xs text-muted-foreground mt-0.5 line-clamp-2">
                                    {p.description}
                                </p>
                                <p className="text-[0.65rem] text-muted-foreground/60 mt-1">
                                    {t("honeypots.baitPaths", { count: p.path_count })}{" "}
                                    <span className={globalOn ? "text-green-400" : "text-muted-foreground"}>
                                        {globalOn ? t("honeypots.on") : t("honeypots.off")}
                                    </span>
                                    {overridden && (
                                        <>
                                            {t("honeypots.override")}
                                            <span className={effective ? "text-green-400" : "text-destructive"}>
                                                {effective ? t("honeypots.on") : t("honeypots.off")}
                                            </span>
                                        </>
                                    )}
                                </p>
                            </div>
                            <Switch
                                checked={Boolean(effective)}
                                onCheckedChange={(v) =>
                                    toggleHost.mutate({ pack_id: p.id, enabled: v })
                                }
                                aria-label={t("honeypots.packAria", { name: p.name })}
                                className="shrink-0 mt-0.5"
                            />
                        </div>
                    );
                })}
            </div>
        </MetricCard>
    );
}
