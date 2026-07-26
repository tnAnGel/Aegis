/**
 * V2 Upstreams page — /v2/upstreams
 *
 * Identical data layer to V1 (sitesApi.list + opsApi.health, 10s poll).
 * Presentation rebuilt with V2 primitives: MetricCard wraps a bespoke
 * table, StatusBadge from v2/components, host chips styled with Tailwind
 * tokens rather than V1 Badge.
 *
 * V1 file at /pages/Upstreams.tsx is NOT touched.
 */

import { useQuery } from "@tanstack/react-query";
import { Server } from "lucide-react";
import { useTranslation } from "react-i18next";
import { opsApi, sitesApi } from "@/api/client";
import { cn } from "@/lib/cn";
import { MetricCard } from "@/v2/components/MetricCard";
import { StatusBadge } from "@/v2/components/StatusBadge";

// ─── Empty state ──────────────────────────────────────────────────────────────

function V2EmptyUpstreams() {
    const { t } = useTranslation(["upstreams", "common"]);
    return (
        <div className="flex flex-col items-center justify-center gap-3 py-16 text-center">
            <span className="rounded-xl bg-muted/30 p-4 text-muted-foreground">
                <Server className="h-7 w-7" />
            </span>
            <p className="text-sm font-medium text-foreground">{t("empty.title")}</p>
            <p className="max-w-xs text-xs text-muted-foreground leading-relaxed">
                {t("empty.hint")}
            </p>
        </div>
    );
}

// ─── Host chip ────────────────────────────────────────────────────────────────

function HostChip({ host }: { host: string }) {
    return (
        <span
            className={cn(
                "inline-flex items-center rounded px-2 py-0.5",
                "bg-muted/40 border border-border/50",
                "font-mono text-[0.72rem] text-foreground/80 leading-none",
                "tabular-nums",
            )}
        >
            {host}
        </span>
    );
}

// ─── Table row ────────────────────────────────────────────────────────────────

function UpstreamRow({
    url,
    hosts,
    isDown,
}: {
    url: string;
    hosts: string[];
    isDown: boolean;
}) {
    return (
        <div
            className={cn(
                "v2-table-row grid items-center gap-4 px-5 py-3",
            )}
            style={{ gridTemplateColumns: "2fr 3fr auto" }}
        >
            {/* Upstream URL */}
            <span className="font-mono text-xs text-foreground/90 truncate tabular-nums">
                {url}
            </span>

            {/* Host chips */}
            <div className="flex flex-wrap gap-1.5">
                {hosts.map((h) => (
                    <HostChip key={h} host={h} />
                ))}
            </div>

            {/* Health badge */}
            <StatusBadge state={isDown ? "degraded" : "healthy"} />
        </div>
    );
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export function UpstreamsV2Page() {
    const { t } = useTranslation(["upstreams", "common"]);
    const sites = useQuery({
        queryKey: ["sites"],
        queryFn: sitesApi.list,
    });

    const health = useQuery({
        queryKey: ["health"],
        queryFn: opsApi.health,
        refetchInterval: 10_000,
    });

    // Build upstream → [hosts] map from configured sites (same logic as V1)
    const upstreams = new Map<string, string[]>();
    for (const s of sites.data ?? []) {
        if (!s.upstream) continue;
        const list = upstreams.get(s.upstream) ?? [];
        list.push(s.host);
        upstreams.set(s.upstream, list);
    }

    const downKeys = new Set((health.data ?? []).map((h) => h.host));

    const loading = sites.isLoading;
    const empty = !loading && upstreams.size === 0;

    // Derive aggregate summary counts for the subtitle
    const total = upstreams.size;
    const degraded = [...upstreams.entries()].filter(([, hosts]) =>
        hosts.some((h) => downKeys.has(h)),
    ).length;
    const healthy = total - degraded;

    const subtitle =
        total > 0
            ? t("summary.line", {
                  total: t("upstream", { count: total }),
                  healthy,
                  degraded,
              })
            : t("summary.fallback");

    return (
        <div className="space-y-6">
            {/* Page title area — V2 style (no PageHeader import from V1) */}
            <div className="space-y-0.5">
                <h1 className="text-xl font-semibold tracking-tight text-foreground">
                    {t("title")}
                </h1>
                <p className="text-sm text-muted-foreground">
                    {t("subtitle")}
                </p>
            </div>

            {/* Summary KPI strip — only shown when data is available */}
            {total > 0 && (
                <div
                    className="grid gap-4"
                    style={{ gridTemplateColumns: "repeat(3, minmax(0, 1fr))" }}
                >
                    <div
                        className="v2-card flex flex-col gap-1 px-5 py-4"
                        style={{ boxShadow: "var(--v2-card-shadow)" }}
                    >
                        <p className="v2-section-label">{t("kpi.total")}</p>
                        <p className="v2-kpi-number text-2xl font-bold tabular-nums">
                            {total}
                        </p>
                    </div>
                    <div
                        className="v2-card flex flex-col gap-1 px-5 py-4"
                        style={{ boxShadow: "var(--v2-card-shadow)" }}
                    >
                        <p className="v2-section-label">{t("kpi.healthy")}</p>
                        <p className="v2-kpi-number text-2xl font-bold tabular-nums text-green-400">
                            {healthy}
                        </p>
                    </div>
                    <div
                        className="v2-card flex flex-col gap-1 px-5 py-4"
                        style={{ boxShadow: "var(--v2-card-shadow)" }}
                    >
                        <p className="v2-section-label">{t("kpi.degraded")}</p>
                        <p
                            className={cn(
                                "v2-kpi-number text-2xl font-bold tabular-nums",
                                degraded > 0 ? "text-destructive" : "text-muted-foreground",
                            )}
                        >
                            {degraded}
                        </p>
                    </div>
                </div>
            )}

            {/* Main table card */}
            <MetricCard
                title={t("pools.title")}
                description={subtitle}
                noPadding
            >
                {loading && (
                    <div className="px-5 py-8 text-sm text-muted-foreground">
                        {t("loading")}
                    </div>
                )}

                {empty && <V2EmptyUpstreams />}

                {!loading && !empty && (
                    <>
                        {/* Column headings */}
                        <div
                            className="grid items-center gap-4 border-b border-border/40 px-5 py-2"
                            style={{ gridTemplateColumns: "2fr 3fr auto" }}
                        >
                            <span className="text-[0.7rem] font-semibold uppercase tracking-widest text-muted-foreground">
                                {t("col.upstream")}
                            </span>
                            <span className="text-[0.7rem] font-semibold uppercase tracking-widest text-muted-foreground">
                                {t("col.usedBy")}
                            </span>
                            <span className="text-[0.7rem] font-semibold uppercase tracking-widest text-muted-foreground">
                                {t("col.health")}
                            </span>
                        </div>

                        {/* Data rows */}
                        {[...upstreams.entries()].map(([url, hosts]) => {
                            const isDown = hosts.some((h) => downKeys.has(h));
                            return (
                                <UpstreamRow
                                    key={url}
                                    url={url}
                                    hosts={hosts}
                                    isDown={isDown}
                                />
                            );
                        })}
                    </>
                )}
            </MetricCard>
        </div>
    );
}
