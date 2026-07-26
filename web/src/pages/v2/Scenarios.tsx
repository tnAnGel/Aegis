/**
 * V2 Scenarios page — /v2/scenarios
 *
 * Identical data-fetching and mutations as V1 Scenarios.tsx.
 * Presentation rebuilt with V2 primitives: MetricCard, SectionHeader,
 * KPITile and the v2-card CSS classes from tokens.css.
 *
 * The Monaco editor is reused unchanged (presentation-agnostic).
 */

import { useState } from "react";
import { useTranslation } from "react-i18next";
import Editor from "@monaco-editor/react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
    CheckCircle2,
    AlertCircle,
    Zap,
    Activity,
    Target,
    GitBranch,
    Flame,
} from "lucide-react";
import { scenariosApi } from "@/api/client";
import { Button } from "@/components/ui/button";
import { useToast } from "@/hooks/useToast";
import { MetricCard } from "@/v2/components/MetricCard";
import { SectionHeader } from "@/v2/components/SectionHeader";
import { StatusBadge } from "@/v2/components/StatusBadge";

// ─── YAML template (same as V1) ───────────────────────────────────────────────

const TEMPLATE = `# Leaky-bucket scenario rule.
# Fires the configured action when capacity is reached within the
# leak window.

name: http_login_brute
description: "Many 401s to /login from one IP"
filter:
  path_prefix: /login
  status_min: 400
  status_max: 499
groupby: client_ip       # client_ip | host | host_path | user_agent | asn
distinct: path           # optional dedup field
capacity: 10             # tokens before fire
leak_speed: 10s          # one token leaks every 10s
blackhole: 5m            # block target for this long
action: block            # block | challenge | tarpit | log
`;

// ─── Stat tile ─────────────────────────────────────────────────────────────────

function StatTile({
    icon,
    label,
    value,
    accent,
}: {
    icon: React.ReactNode;
    label: string;
    value: number;
    accent?: "emerald";
}) {
    const iconClass =
        accent === "emerald"
            ? "text-emerald-300 border-emerald-500/30 bg-emerald-500/10"
            : "text-muted-foreground border-border/40 bg-muted/20";

    return (
        <div
            className="v2-card flex items-center gap-3 p-4"
            style={{ boxShadow: "var(--v2-card-shadow)" }}
        >
            <div className={`h-9 w-9 rounded-lg grid place-items-center border shrink-0 ${iconClass}`}>
                {icon}
            </div>
            <div className="min-w-0">
                <p className="text-[10px] uppercase tracking-wider text-muted-foreground truncate">
                    {label}
                </p>
                <p className="text-xl font-bold tabular-nums text-foreground leading-tight">{value}</p>
            </div>
        </div>
    );
}

// ─── Loaded scenario row ──────────────────────────────────────────────────────

function ScenarioRow({
    name,
    action,
    description,
    groupby,
    distinct,
    capacity,
    labels,
}: {
    name: string;
    action: string;
    description?: string;
    groupby: string;
    distinct?: string;
    capacity: number;
    labels: { groupby: string; distinct: string; capacity: string };
}) {
    const actionColor: Record<string, string> = {
        block: "border-destructive/30 text-destructive bg-destructive/10",
        challenge: "border-amber-500/30 text-amber-300 bg-amber-500/10",
        tarpit: "border-orange-500/30 text-orange-300 bg-orange-500/10",
        log: "border-border/40 text-muted-foreground bg-muted/20",
    };

    const chipClass =
        actionColor[action] ??
        "border-border/40 text-muted-foreground bg-muted/20";

    return (
        <div
            className="v2-card p-4 flex items-start justify-between gap-4"
            style={{ boxShadow: "var(--v2-card-shadow)" }}
        >
            <div className="min-w-0 space-y-1">
                <div className="flex items-center gap-2 flex-wrap">
                    <code className="font-mono text-sm font-semibold text-foreground">{name}</code>
                    <span
                        className={`inline-flex items-center rounded-md border px-2 py-0.5 text-[10px] font-medium uppercase tracking-wider ${chipClass}`}
                    >
                        {action}
                    </span>
                </div>
                {description && (
                    <p className="text-xs text-muted-foreground">{description}</p>
                )}
                <p className="text-xs text-muted-foreground/70 font-mono">
                    {labels.groupby} <span className="text-foreground/60">{groupby}</span>
                    {distinct && (
                        <>
                            {" "}
                            · {labels.distinct} <span className="text-foreground/60">{distinct}</span>
                        </>
                    )}{" "}
                    · {labels.capacity}{" "}
                    <span className="text-foreground/60 tabular-nums">{capacity}</span>
                </p>
            </div>
        </div>
    );
}

// ─── Main page ────────────────────────────────────────────────────────────────

export function ScenariosPage() {
    const { t } = useTranslation(["scenarios", "common"]);
    const { toast } = useToast();
    const qc = useQueryClient();
    const [yaml, setYaml] = useState(TEMPLATE);

    const list = useQuery({
        queryKey: ["scenarios"],
        queryFn: scenariosApi.list,
        refetchInterval: 5_000,
    });

    const testM = useMutation({
        mutationFn: () => scenariosApi.test(yaml),
        onSuccess: (res) => {
            if (res.ok) {
                toast({
                    title: t("toast.yamlValid"),
                    description: t("toast.yamlValidDesc", { count: res.parsed?.length ?? 0 }),
                });
            } else {
                toast({ title: t("toast.parseFailed"), description: res.error, variant: "destructive" });
            }
        },
    });

    const loadM = useMutation({
        mutationFn: () => scenariosApi.load(yaml),
        onSuccess: (res) => {
            if (res.ok) {
                toast({ title: t("toast.loaded", { count: res.loaded ?? 0 }) });
                qc.invalidateQueries({ queryKey: ["scenarios"] });
            } else {
                toast({ title: t("toast.loadFailed"), description: res.error, variant: "destructive" });
            }
        },
    });

    const stats = list.data?.stats;
    const scenarios = list.data?.scenarios ?? [];
    const wired = list.data?.wired ?? false;

    return (
        <div className="space-y-8">
            {/* Page header */}
            <div>
                <h1 className="text-2xl font-bold text-foreground tracking-tight">{t("title")}</h1>
                <p className="mt-1 text-sm text-muted-foreground">
                    {t("subtitle")}
                </p>
            </div>

            {/* Arsenal not attached */}
            {!wired && (
                <div className="v2-card border-amber-500/30 p-4 text-sm text-amber-200">
                    {t("arsenalNotAttached")}
                </div>
            )}

            {/* Engine stats */}
            {stats && (
                <div className="space-y-3">
                    <SectionHeader label={t("stats.heading")} />
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                        <StatTile
                            icon={<Activity className="h-4 w-4" />}
                            label={t("stats.observed")}
                            value={stats.events_observed ?? 0}
                        />
                        <StatTile
                            icon={<Target className="h-4 w-4" />}
                            label={t("stats.matched")}
                            value={stats.events_matched ?? 0}
                        />
                        <StatTile
                            icon={<GitBranch className="h-4 w-4" />}
                            label={t("stats.bucketed")}
                            value={stats.events_bucketed ?? 0}
                        />
                        <StatTile
                            icon={<Flame className="h-4 w-4" />}
                            label={t("stats.fired")}
                            value={stats.buckets_fired ?? 0}
                            accent="emerald"
                        />
                    </div>
                </div>
            )}

            {/* YAML editor */}
            <MetricCard
                title={t("editor.title")}
                description={t("editor.description")}
            >
                <div className="space-y-4">
                    <div className="rounded-lg border border-border/40 overflow-hidden">
                        <Editor
                            height="320px"
                            defaultLanguage="yaml"
                            value={yaml}
                            onChange={(v) => setYaml(v ?? "")}
                            theme="vs-dark"
                            options={{ minimap: { enabled: false }, fontSize: 12 }}
                        />
                    </div>
                    <div className="flex items-center gap-2">
                        <Button
                            variant="outline"
                            onClick={() => testM.mutate()}
                            disabled={testM.isPending}
                            className="gap-1.5"
                        >
                            {testM.isPending ? (
                                <Activity className="h-3.5 w-3.5 animate-spin" />
                            ) : (
                                <CheckCircle2 className="h-3.5 w-3.5" />
                            )}
                            {t("editor.testParse")}
                        </Button>
                        <Button
                            onClick={() => loadM.mutate()}
                            disabled={loadM.isPending}
                            className="gap-1.5"
                        >
                            <Zap className="h-3.5 w-3.5" />
                            {t("editor.loadActive")}
                        </Button>
                        {testM.isSuccess && testM.data?.ok && (
                            <span className="text-xs text-emerald-300 flex items-center gap-1">
                                <CheckCircle2 className="h-3 w-3" />
                                {t("editor.parsedOk", { count: testM.data.parsed?.length ?? 0 })}
                            </span>
                        )}
                        {testM.isSuccess && !testM.data?.ok && (
                            <span className="text-xs text-destructive flex items-center gap-1">
                                <AlertCircle className="h-3 w-3" />
                                {testM.data?.error ?? t("editor.parseFailed")}
                            </span>
                        )}
                    </div>
                </div>
            </MetricCard>

            {/* Loaded scenarios */}
            <MetricCard
                title={t("loaded.title")}
                description={
                    scenarios.length > 0
                        ? t("loaded.activeCount", { count: scenarios.length })
                        : undefined
                }
                action={
                    scenarios.length > 0 ? (
                        <StatusBadge state="active" label={t("loaded.activeBadge", { count: scenarios.length })} />
                    ) : undefined
                }
            >
                {scenarios.length === 0 ? (
                    <p className="text-sm text-muted-foreground py-2">
                        {t("loaded.empty")}
                    </p>
                ) : (
                    <div className="space-y-3">
                        {scenarios.map((s, i) => (
                            <ScenarioRow
                                key={i}
                                name={s.name}
                                action={s.action}
                                description={s.description}
                                groupby={s.groupby}
                                distinct={s.distinct ?? undefined}
                                capacity={s.capacity}
                                labels={{
                                    groupby: t("row.groupby"),
                                    distinct: t("row.distinct"),
                                    capacity: t("row.capacity"),
                                }}
                            />
                        ))}
                    </div>
                )}
            </MetricCard>
        </div>
    );
}
