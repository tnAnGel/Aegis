/**
 * V2 Cluster page — /v2/cluster
 *
 * Shared-mmap cluster threat-state view, restyled with V2 primitives.
 * All data-fetching logic is identical to V1 ClusterPage.
 * Presentation changes: MetricCard, StatusBadge, V2 table styling,
 * KPITile for the active-slots counter.
 */

import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { Activity, Network, Server } from "lucide-react";
import { clusterApi } from "@/api/client";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState } from "@/components/ErrorState";
import { MetricCard } from "@/v2/components/MetricCard";
import { SectionHeader } from "@/v2/components/SectionHeader";
import { StatusBadge } from "@/v2/components/StatusBadge";

// ─── Page ────────────────────────────────────────────────────────────────────

export function ClusterPageV2() {
    const { t } = useTranslation(["cluster", "common"]);
    const q = useQuery({
        queryKey: ["cluster"],
        queryFn: clusterApi.status,
        refetchInterval: 5_000,
    });

    const top = q.data?.counts.top ?? [];
    const ipv4Active = q.data?.counts.ipv4_slots_active ?? 0;
    const sharedAttached = q.data?.shared_scorer_attached ?? false;

    return (
        <div className="space-y-6">
            {/* ── Page header ──────────────────────────────────────────── */}
            <div className="flex items-center gap-3">
                <span className="inline-flex items-center justify-center rounded-lg w-9 h-9 bg-primary/10 text-primary">
                    <Network className="h-5 w-5" />
                </span>
                <div>
                    <h1 className="text-xl font-semibold tracking-tight text-foreground">
                        {t("title")}
                    </h1>
                    <p className="text-xs text-muted-foreground mt-0.5">
                        {t("subtitle")}
                    </p>
                </div>
            </div>

            {/* ── Loading / error states ────────────────────────────────── */}
            {q.isLoading && <Skeleton className="h-32 rounded-xl" />}
            {q.error && (
                <ErrorState
                    title={t("loadError")}
                    error={q.error}
                />
            )}

            {/* ── Summary tiles ─────────────────────────────────────────── */}
            <SectionHeader label={t("overview")} />

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                {/* Shared scorer status */}
                <MetricCard
                    title={t("sharedScorer")}
                    action={<Server className="h-4 w-4 text-muted-foreground/60" />}
                >
                    <div className="space-y-3">
                        <StatusBadge
                            state={sharedAttached ? "active" : "standby"}
                            label={sharedAttached ? t("attached") : t("perWorkerOnly")}
                        />
                        {q.data?.note && (
                            <p className="text-xs text-muted-foreground leading-snug">
                                {q.data.note}
                            </p>
                        )}
                    </div>
                </MetricCard>

                {/* Active IPv4 slots */}
                <MetricCard
                    title={t("activeSlots")}
                    action={
                        <Activity className="h-4 w-4 text-muted-foreground/60" />
                    }
                >
                    <p
                        className="v2-kpi-number text-4xl font-bold leading-none tracking-tight text-foreground tabular-nums"
                        aria-label={t("activeSlotsAria", { count: ipv4Active })}
                    >
                        {ipv4Active.toLocaleString()}
                    </p>
                    <p className="text-xs text-muted-foreground mt-2">
                        {t("activeSlotsHint")}
                    </p>
                </MetricCard>
            </div>

            {/* ── Top 10 threat scores ──────────────────────────────────── */}
            <MetricCard
                title={t("topScores.title")}
                description={t("topScores.description")}
            >
                {top.length === 0 ? (
                    <p className="text-sm text-muted-foreground py-2">
                        {t("topScores.empty")}
                    </p>
                ) : (
                    <div className="overflow-x-auto -mx-5 px-5">
                        <table className="w-full text-xs min-w-[280px]">
                            <thead>
                                <tr className="border-b border-border/40">
                                    <th className="text-left py-2 pr-4 font-medium text-muted-foreground">
                                        {t("topScores.col.rank")}
                                    </th>
                                    <th className="text-left py-2 pr-4 font-medium text-muted-foreground">
                                        {t("topScores.col.ip")}
                                    </th>
                                    <th className="text-right py-2 font-medium text-muted-foreground">
                                        {t("topScores.col.score")}
                                    </th>
                                </tr>
                            </thead>
                            <tbody>
                                {top.map((entry, idx) => {
                                    // Colour score by severity
                                    const scoreClass =
                                        entry.score >= 80
                                            ? "text-red-400"
                                            : entry.score >= 50
                                              ? "text-amber-400"
                                              : "text-foreground";

                                    // Severity badge state
                                    const badgeState =
                                        entry.score >= 80
                                            ? "error"
                                            : entry.score >= 50
                                              ? "degraded"
                                              : "standby";

                                    return (
                                        <tr
                                            key={entry.ip}
                                            className="v2-table-row"
                                        >
                                            <td className="py-2 pr-4 text-muted-foreground/60 tabular-nums">
                                                {idx + 1}
                                            </td>
                                            <td className="py-2 pr-4">
                                                <code className="font-mono text-foreground">
                                                    {entry.ip}
                                                </code>
                                            </td>
                                            <td className="py-2 text-right">
                                                <span className="inline-flex items-center justify-end gap-2">
                                                    <StatusBadge
                                                        state={badgeState}
                                                        label={entry.score.toFixed(
                                                            1,
                                                        )}
                                                        className={scoreClass}
                                                    />
                                                </span>
                                            </td>
                                        </tr>
                                    );
                                })}
                            </tbody>
                        </table>
                    </div>
                )}
            </MetricCard>
        </div>
    );
}
