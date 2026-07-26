/**
 * V2 Security page — /v2/security
 *
 * Presents the global filter chain in the V2 visual language:
 *   - Page header with shield icon + title (V2 styled, no V1 PageHeader import)
 *   - Grid of MetricCard-wrapped filter cards, each with icon + title + description + Switch
 *   - "Persisting changes" MetricCard at the bottom with DSL snippet
 *
 * Data: identical react-query hooks + mutations to V1 Security.tsx.
 * Presentation: MetricCard / SectionHeader / StatusBadge from V2 primitives.
 * V1 files are NOT imported.
 */

import * as React from "react";
import { Trans, useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
    Bot,
    CircleAlert,
    Cpu,
    Globe,
    ShieldAlert,
    ShieldCheck,
    Zap,
} from "lucide-react";
import { defaultsApi, filterActivityApi } from "@/api/client";
import { Switch } from "@/components/ui/switch";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState } from "@/components/ErrorState";
import { useToast } from "@/hooks/useToast";
import { MetricCard } from "@/v2/components/MetricCard";
import { SectionHeader } from "@/v2/components/SectionHeader";
import { StatusBadge } from "@/v2/components/StatusBadge";

// ─── Filter metadata ─────────────────────────────────────────────────────────

interface FilterMeta {
    name: string;
    title: string;
    icon: React.ComponentType<{ className?: string }>;
    description: string;
}

// Icon per filter name. Titles + descriptions are resolved from translations.
const ICONS: Record<string, React.ComponentType<{ className?: string }>> = {
    waf: ShieldCheck,
    bot: Bot,
    adaptive: Zap,
    challenge: ShieldAlert,
    ip_acl: Globe,
    rate_limit: Cpu,
    honeypot: ShieldAlert,
    threat_intel: ShieldCheck,
    wirefilter: ShieldCheck,
};

function metaFor(name: string, t: TFunction): FilterMeta {
    const icon = ICONS[name] ?? ShieldCheck;
    return {
        name,
        icon,
        title: t(`filter.${name}.title`, { defaultValue: name }),
        description: t(`filter.${name}.description`, {
            defaultValue: t("fallback.description"),
        }),
    };
}

// ─── Filter card ─────────────────────────────────────────────────────────────

function FilterCard({
    name,
    enabled,
    onToggle,
    isPending,
}: {
    name: string;
    enabled: boolean;
    onToggle: (enabled: boolean) => void;
    isPending: boolean;
}) {
    const { t } = useTranslation(["security", "common"]);
    const m = metaFor(name, t);
    const Icon = m.icon;

    return (
        <div
            className="v2-card flex flex-col gap-3 p-5"
            style={{ boxShadow: "var(--v2-card-shadow)" }}
        >
            {/* Header row: icon + title + switch */}
            <div className="flex items-start justify-between gap-3">
                <div className="flex items-center gap-3 min-w-0">
                    <div className="h-9 w-9 rounded-lg bg-primary/10 border border-primary/20 grid place-items-center shrink-0">
                        <Icon className="h-4 w-4 text-primary" />
                    </div>
                    <div className="min-w-0">
                        <p className="text-sm font-semibold text-foreground leading-snug truncate">
                            {m.title}
                        </p>
                        <p className="text-[0.65rem] font-mono text-muted-foreground/60 mt-0.5">
                            {m.name}
                        </p>
                    </div>
                </div>
                <div className="shrink-0 flex items-center gap-2 mt-0.5">
                    <StatusBadge
                        state={enabled ? "active" : "standby"}
                        label={enabled ? t("badge.active") : t("badge.standby")}
                    />
                    <Switch
                        checked={enabled}
                        onCheckedChange={onToggle}
                        disabled={isPending}
                        aria-label={t("card.enableAria", { name: m.title })}
                    />
                </div>
            </div>

            {/* Description */}
            <p className="text-xs text-muted-foreground leading-relaxed">
                {m.description}
            </p>
        </div>
    );
}

// ─── Filter Activity card ────────────────────────────────────────────────────

function FilterActivityCard() {
    const { t } = useTranslation(["security", "common"]);
    const activity = useQuery({
        queryKey: ["filter-activity"],
        queryFn: filterActivityApi.get,
        refetchInterval: 10_000,
    });

    const sorted = React.useMemo(
        () =>
            [...(activity.data ?? [])].sort((a, b) => b.blocks - a.blocks),
        [activity.data],
    );

    return (
        <MetricCard
            title={t("activity.title")}
            description={t("activity.description")}
        >
            {activity.isError ? (
                <ErrorState error={activity.error} onRetry={() => activity.refetch()} />
            ) : activity.isLoading ? (
                <div className="space-y-2">
                    {Array.from({ length: 4 }).map((_, i) => (
                        <Skeleton key={i} className="h-9 w-full" />
                    ))}
                </div>
            ) : sorted.length === 0 ? (
                <p className="text-sm text-muted-foreground py-4 text-center">
                    {t("activity.empty")}
                </p>
            ) : (
                <div className="overflow-x-auto">
                    <SectionHeader label={t("activity.countersHeading")} className="mb-3" />
                    <table className="w-full text-sm border-separate border-spacing-0">
                        <thead>
                            <tr>
                                {([
                                    { key: "filter", label: t("activity.col.filter") },
                                    { key: "blocks", label: t("activity.col.blocks") },
                                    { key: "challenges", label: t("activity.col.challenges") },
                                ] as const).map((col) => (
                                    <th
                                        key={col.key}
                                        className={[
                                            "py-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground border-b border-border/60",
                                            col.key === "filter" ? "text-left pr-4" : "text-right pl-4 tabular-nums",
                                        ].join(" ")}
                                    >
                                        {col.label}
                                    </th>
                                ))}
                            </tr>
                        </thead>
                        <tbody>
                            {sorted.map((row, idx) => (
                                <tr
                                    key={row.name}
                                    className={idx % 2 === 0 ? "bg-muted/10" : "bg-transparent"}
                                >
                                    <td className="py-2 pr-4 font-mono text-[0.75rem] text-foreground">
                                        {row.name}
                                    </td>
                                    <td className="py-2 pl-4 text-right tabular-nums font-semibold text-foreground">
                                        {row.blocks.toLocaleString()}
                                    </td>
                                    <td className="py-2 pl-4 text-right tabular-nums text-muted-foreground">
                                        {row.challenges.toLocaleString()}
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            )}
        </MetricCard>
    );
}

// ─── Page ────────────────────────────────────────────────────────────────────

export function SecurityV2Page() {
    const { t } = useTranslation(["security", "common"]);
    const { toast } = useToast();
    const qc = useQueryClient();

    const list = useQuery({
        queryKey: ["defaults", "filters"],
        queryFn: defaultsApi.list,
        refetchInterval: 15_000,
    });

    const flip = useMutation({
        mutationFn: (u: { name: string; enabled: boolean }) =>
            defaultsApi.update([u]),
        onMutate: async (u) => {
            await qc.cancelQueries({ queryKey: ["defaults", "filters"] });
            const prev = qc.getQueryData<{
                filters: { name: string; enabled: boolean }[];
                note: string;
            }>(["defaults", "filters"]);
            qc.setQueryData<typeof prev>(["defaults", "filters"], (old) =>
                old
                    ? {
                          ...old,
                          filters: old.filters.map((f) =>
                              f.name === u.name ? { ...f, enabled: u.enabled } : f,
                          ),
                      }
                    : old,
            );
            return { prev };
        },
        onError: (_e, _vars, ctx) => {
            if (ctx?.prev) qc.setQueryData(["defaults", "filters"], ctx.prev);
            toast({ title: t("toast.toggleFailed"), variant: "destructive" });
        },
        onSuccess: (_d, vars) => {
            toast({
                title: vars.enabled ? t("toast.filterEnabled") : t("toast.filterDisabled"),
                description: t("toast.flipDesc", {
                    name: vars.name,
                    state: vars.enabled ? t("state.on") : t("state.off"),
                }),
                variant: "success",
            });
        },
    });

    const isPending = flip.isPending;

    return (
        <div className="space-y-6">
            {/* ── Page heading (V2 style — no V1 PageHeader) ──────────────── */}
            <div className="flex items-center gap-3">
                <div className="h-10 w-10 rounded-xl bg-primary/10 border border-primary/20 grid place-items-center shrink-0">
                    <ShieldCheck className="h-5 w-5 text-primary" />
                </div>
                <div>
                    <h1 className="text-xl font-bold text-foreground leading-snug">{t("title")}</h1>
                    <p className="text-xs text-muted-foreground mt-0.5">
                        {t("subtitle")}
                    </p>
                </div>
            </div>

            {/* ── Filter chain ─────────────────────────────────────────────── */}
            <MetricCard
                title={t("chain.title")}
                description={t("chain.description")}
            >
                {list.isError ? (
                    <ErrorState error={list.error} onRetry={() => list.refetch()} />
                ) : list.isLoading ? (
                    <div className="grid gap-4 grid-cols-1 sm:grid-cols-2 lg:grid-cols-3">
                        {Array.from({ length: 6 }).map((_, i) => (
                            <Skeleton key={i} className="h-32" />
                        ))}
                    </div>
                ) : (
                    <div className="grid gap-4 grid-cols-1 sm:grid-cols-2 lg:grid-cols-3">
                        {(list.data?.filters ?? []).map((f) => (
                            <FilterCard
                                key={f.name}
                                name={f.name}
                                enabled={f.enabled}
                                onToggle={(v) => flip.mutate({ name: f.name, enabled: v })}
                                isPending={isPending}
                            />
                        ))}
                    </div>
                )}
            </MetricCard>

            {/* ── Filter Activity ──────────────────────────────────────────── */}
            <FilterActivityCard />

            {/* ── Persisting changes ───────────────────────────────────────── */}
            <MetricCard
                title={t("persist.title")}
                description={t("persist.description")}
            >
                <div className="space-y-4">
                    <p className="text-sm text-muted-foreground leading-relaxed">
                        <Trans
                            t={t}
                            i18nKey="persist.body"
                            components={[<strong className="text-foreground font-medium" />]}
                        />
                    </p>

                    <pre className="bg-muted/30 border border-border/60 rounded-xl p-4 text-xs font-mono leading-relaxed overflow-x-auto">
{`defaults {
    filters {
        waf                       on;
        bot_fingerprint           off;
        adaptive_spike_detection  on;
        challenge_ladder          on;
    }
}`}
                    </pre>

                    <div className="flex items-start gap-2 text-xs text-muted-foreground bg-muted/20 rounded-lg px-4 py-3 border border-border/40">
                        <CircleAlert className="h-3.5 w-3.5 mt-0.5 shrink-0 text-amber-400" />
                        <span>
                            <Trans
                                t={t}
                                i18nKey="persist.note"
                                values={{ cmd: "aegis-pingora --upgrade" }}
                                components={[
                                    <strong className="text-foreground font-medium" />,
                                    <code className="font-mono bg-muted/60 px-1 rounded text-[0.7rem]" />,
                                ]}
                            />
                        </span>
                    </div>

                    {/* Summary of current state */}
                    {list.data && (
                        <div className="pt-2">
                            <SectionHeader label={t("persist.stateHeading")} className="mb-3" />
                            <div className="flex flex-wrap gap-2">
                                {list.data.filters.map((f) => (
                                    <div
                                        key={f.name}
                                        className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-[0.7rem] font-mono border"
                                        style={{
                                            background: f.enabled
                                                ? "var(--v2-nav-active-bg, color-mix(in srgb, var(--primary) 10%, transparent))"
                                                : "var(--muted)",
                                            borderColor: f.enabled
                                                ? "color-mix(in srgb, var(--primary) 30%, transparent)"
                                                : "var(--border)",
                                            color: f.enabled ? "var(--primary)" : "var(--muted-foreground)",
                                        }}
                                    >
                                        <span
                                            className="h-1.5 w-1.5 rounded-full shrink-0"
                                            style={{
                                                background: f.enabled ? "var(--primary)" : "var(--muted-foreground)",
                                            }}
                                        />
                                        {f.name}
                                        <span className="opacity-60">{f.enabled ? t("state.on") : t("state.off")}</span>
                                    </div>
                                ))}
                            </div>
                        </div>
                    )}
                </div>
            </MetricCard>
        </div>
    );
}
