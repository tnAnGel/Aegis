/**
 * V2 Actuators page — /v2/actuators
 *
 * Presentation layer only change. Data fetching is identical to V1:
 *   - actuatorsApi.list (poll 5 s)
 *   - actuatorsApi.revert (mutation)
 *
 * V2 visual changes:
 *   - MetricCard replaces Card for all sections
 *   - SectionHeader for page-level titles
 *   - Lifetime-counters grid uses a plain stat layout with V2 tokens
 *   - Active-actions table styled with v2-table-* CSS classes
 *   - StatusBadge shows "wired" state of the arsenal
 */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { Clock, Undo2, Zap } from "lucide-react";
import { actuatorsApi } from "@/api/client";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState } from "@/components/ErrorState";
import { useToast } from "@/hooks/useToast";
import { MetricCard } from "@/v2/components/MetricCard";
import { SectionHeader } from "@/v2/components/SectionHeader";
import { StatusBadge } from "@/v2/components/StatusBadge";

// ─── Helpers ────────────────────────────────────────────────────────────────

interface StatTileProps {
    label: string;
    value: number;
    accent?: "red" | "amber";
}

function StatTile({ label, value, accent }: StatTileProps) {
    const numClass =
        accent === "red"
            ? "text-destructive"
            : accent === "amber"
                ? "text-amber-300"
                : "text-foreground";
    return (
        <div className="v2-card px-4 py-3 flex flex-col gap-1" style={{ boxShadow: "var(--v2-card-shadow)" }}>
            <p className="v2-section-label">{label}</p>
            <p className={`text-2xl font-bold tabular-nums leading-none ${numClass}`}>{value}</p>
        </div>
    );
}

// ─── Page ────────────────────────────────────────────────────────────────────

export function ActuatorsPage() {
    const { t } = useTranslation(["actuators", "common"]);
    const { toast } = useToast();
    const qc = useQueryClient();

    const q = useQuery({
        queryKey: ["actuators"],
        queryFn: actuatorsApi.list,
        refetchInterval: 5_000,
    });

    const revert = useMutation({
        mutationFn: (args: { kind: string; target_kind: string; target_value: string }) =>
            actuatorsApi.revert(args.kind, args.target_kind, args.target_value),
        onSuccess: (res) => {
            toast({ title: t("revertToast.title"), description: res.outcome });
            qc.invalidateQueries({ queryKey: ["actuators"] });
        },
    });

    const stats = q.data?.stats;
    const active = q.data?.active ?? [];
    const kinds = q.data?.kinds ?? [];
    const wired = q.data?.wired;

    return (
        <div className="space-y-6">
            {/* Page heading */}
            <div className="flex items-center gap-3">
                <div className="flex items-center justify-center w-8 h-8 rounded-lg bg-primary/10">
                    <Zap className="h-4 w-4 text-primary" />
                </div>
                <div>
                    <h1 className="text-lg font-semibold leading-tight text-foreground">
                        {t("title")}
                    </h1>
                    <p className="text-xs text-muted-foreground mt-0.5">
                        {t("subtitle")}
                    </p>
                </div>
            </div>

            {/* Loading / error */}
            {q.isLoading && <Skeleton className="h-32" />}
            {q.error && <ErrorState title={t("loadError")} error={q.error} />}

            {/* Arsenal wired state */}
            {!wired && !q.isLoading && (
                <div
                    className="v2-card border-amber-500/40 px-5 py-3 flex items-center gap-3"
                    style={{ boxShadow: "var(--v2-card-shadow)" }}
                >
                    <StatusBadge state="standby" label={t("notAttached")} />
                    <p className="text-sm text-amber-200">
                        {t("notWired")}
                    </p>
                </div>
            )}

            {/* Lifetime counters */}
            {stats && (
                <div className="space-y-2">
                    <SectionHeader label={t("lifetimeCounters")} />
                    <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
                        <StatTile label={t("stat.applied")} value={stats.applied ?? 0} />
                        <StatTile label={t("stat.alreadyApplied")} value={stats.already_applied ?? 0} />
                        <StatTile label={t("stat.failed")} value={stats.failed ?? 0} accent="red" />
                        <StatTile label={t("stat.revertedExpiry")} value={stats.reverted_on_expiry ?? 0} />
                        <StatTile label={t("stat.revertedManual")} value={stats.reverted_manually ?? 0} />
                    </div>
                </div>
            )}

            {/* Active actions table */}
            <MetricCard
                title={t("activeActions", { count: active.length })}
                description={kinds.length > 0 ? t("registeredKinds", { kinds: kinds.join(", ") }) : t("noRegisteredKinds")}
            >
                {active.length === 0 ? (
                    <p className="text-sm text-muted-foreground py-2">
                        {t("empty")}
                    </p>
                ) : (
                    <div className="overflow-x-auto -mx-5 px-5">
                        <table className="w-full text-xs">
                            <thead>
                                <tr className="border-b border-border/50">
                                    <th className="text-left py-2 pr-4 font-medium text-muted-foreground">{t("col.kind")}</th>
                                    <th className="text-left py-2 pr-4 font-medium text-muted-foreground">{t("col.target")}</th>
                                    <th className="text-left py-2 pr-4 font-medium text-muted-foreground">{t("col.source")}</th>
                                    <th className="text-left py-2 pr-4 font-medium text-muted-foreground">{t("col.age")}</th>
                                    <th className="text-left py-2 pr-4 font-medium text-muted-foreground">{t("col.remaining")}</th>
                                    <th className="text-right py-2 font-medium text-muted-foreground">{t("col.action")}</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-border/30">
                                {active.map((a, i) => (
                                    <tr key={i} className="v2-table-row">
                                        <td className="py-2 pr-4">
                                            <code className="text-primary/80 bg-primary/5 px-1.5 py-0.5 rounded text-[0.7rem]">
                                                {a.kind}
                                            </code>
                                        </td>
                                        <td className="py-2 pr-4">
                                            <code className="text-foreground/80 text-[0.7rem]">
                                                {a.target}
                                            </code>
                                        </td>
                                        <td className="py-2 pr-4 text-muted-foreground">
                                            {a.source_module ?? "—"}
                                            {a.reason && (
                                                <span className="ml-2 italic opacity-70">{a.reason}</span>
                                            )}
                                        </td>
                                        <td className="py-2 pr-4 v2-table-num text-muted-foreground">
                                            {a.applied_at}s
                                        </td>
                                        <td className="py-2 pr-4">
                                            {a.remaining_secs === null ? (
                                                <span className="v2-status-pill-ok text-[0.65rem] px-1.5 py-0.5">
                                                    {t("permanent")}
                                                </span>
                                            ) : (
                                                <span className="flex items-center gap-1 text-amber-300 tabular-nums">
                                                    <Clock className="h-3 w-3 shrink-0" />
                                                    {a.remaining_secs}s
                                                </span>
                                            )}
                                        </td>
                                        <td className="py-2 text-right">
                                            <Button
                                                size="sm"
                                                variant="outline"
                                                className="h-6 text-xs px-2 border-border/50 hover:border-destructive/50 hover:text-destructive"
                                                onClick={() => {
                                                    const target_kind = a.target.includes(":")
                                                        ? (a.target.split(":")[0] ?? "ip")
                                                        : "ip";
                                                    const target_value = a.target.includes(":")
                                                        ? a.target.substring(a.target.indexOf(":") + 1)
                                                        : a.target;
                                                    revert.mutate({
                                                        kind: a.kind,
                                                        target_kind,
                                                        target_value,
                                                    });
                                                }}
                                                disabled={revert.isPending}
                                            >
                                                <Undo2 className="h-3 w-3 mr-1" />
                                                {t("revert")}
                                            </Button>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}
            </MetricCard>
        </div>
    );
}
