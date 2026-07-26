import { useState } from "react";
import { useTranslation } from "react-i18next";
import Editor from "@monaco-editor/react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Hourglass, Bot, CircuitBoard, Clock } from "lucide-react";
import { tarpitApi, honeypotYamlApi } from "@/api/client";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState } from "@/components/ErrorState";
import { useToast } from "@/hooks/useToast";
import { MetricCard } from "@/v2/components/MetricCard";
import { KPITile } from "@/v2/components/KPITile";
import { StatusBadge } from "@/v2/components/StatusBadge";
import { SectionHeader } from "@/v2/components/SectionHeader";
import { cn } from "@/lib/cn";

// ---------------------------------------------------------------------------
// YAML sample (same as V1)
// ---------------------------------------------------------------------------

const YAML_SAMPLE = `# Multi-turn honeypot descriptor example.
# Each descriptor binds a path pattern to N conversation turns; per-IP
# state tracks progress through the sequence.

- name: fake-phpmyadmin
  path: /phpmyadmin/*
  turns:
    - on: login_view
      response:
        status: 200
        headers:
          server: Apache/2.4.41
        body: "<title>phpMyAdmin login</title>"
    - on: login_submit
      trigger_body_contains: pma_password=
      response:
        status: 200
        body: "<title>Login error</title>"
    - on: brute_attempt
      trigger_body_contains: pma_password=
      response:
        status: 429
        body: "Too many requests"
`;

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export function TarpitPage() {
    const { t } = useTranslation(["tarpit", "common"]);
    const { toast } = useToast();
    const tarpit = useQuery({
        queryKey: ["tarpit"],
        queryFn: tarpitApi.status,
        refetchInterval: 30_000,
    });
    const yamlState = useQuery({
        queryKey: ["honeypot-yaml"],
        queryFn: honeypotYamlApi.list,
        refetchInterval: 10_000,
    });
    const [yaml, setYaml] = useState(YAML_SAMPLE);

    const parse = useMutation({
        mutationFn: () => honeypotYamlApi.parse(yaml),
        onSuccess: (res) => {
            if (res.ok) {
                toast({
                    title: t("toast.validTitle"),
                    description: t("toast.validDescription", { count: res.parsed?.length ?? 0 }),
                });
            } else {
                toast({ title: t("toast.parseFailedTitle"), description: res.error, variant: "destructive" });
            }
        },
    });

    return (
        <div className="space-y-6">
            {/* ── Page header ────────────────────────────────────────────── */}
            <div>
                <h1 className="text-2xl font-bold text-foreground flex items-center gap-2.5">
                    <Hourglass className="h-6 w-6 text-primary" />
                    {t("title")}
                </h1>
                <p className="text-sm text-muted-foreground mt-1 max-w-2xl">
                    {t("subtitle")}
                </p>
            </div>

            {tarpit.isLoading && <Skeleton className="h-32" />}
            {tarpit.error && (
                <ErrorState title={t("loadError")} error={tarpit.error} />
            )}

            {/* ── KPI row ────────────────────────────────────────────────── */}
            {tarpit.data && (
                <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                    <KPITile
                        label={t("kpi.duration")}
                        value={`${tarpit.data.tarpit_seconds}s`}
                        icon={<Hourglass className="h-4 w-4" />}
                    />
                    <KPITile
                        label={t("kpi.chunkBytes")}
                        value={tarpit.data.tarpit_chunk_bytes.toLocaleString()}
                        icon={<CircuitBoard className="h-4 w-4" />}
                    />
                    <KPITile
                        label={t("kpi.autoDeny")}
                        value={tarpit.data.auto_xdp_deny_threshold}
                        deltaLabel={t("kpi.autoDenyHint")}
                        icon={<Clock className="h-4 w-4" />}
                    />
                </div>
            )}

            {/* ── Poisoned Markov info ─────────────────────────────────────── */}
            {tarpit.data && (
                <MetricCard
                    title={t("markov.title")}
                    description={t("markov.description")}
                >
                    <div className="space-y-2 text-sm text-muted-foreground">
                        <div className="flex items-center gap-2">
                            <Bot className="h-4 w-4 shrink-0 text-primary/70" />
                            <span>
                                {t("markov.defaultDelay")}{" "}
                                <code className="font-mono text-xs text-foreground">
                                    {tarpit.data.poisoned_tarpit_default_delay_ms}ms
                                </code>{" "}
                                {t("markov.jitter")}
                            </span>
                        </div>
                        <p className="text-xs pl-6">
                            {t("markov.tuneHint")}{" "}
                            <code className="font-mono">/__aegis/tarpit/&lt;slug&gt;</code>
                        </p>
                    </div>
                </MetricCard>
            )}

            {/* ── Active YAML descriptors ──────────────────────────────────── */}
            <MetricCard
                title={t("yaml.activeTitle")}
                action={
                    yamlState.data?.active_sessions !== undefined ? (
                        <span className="text-xs tabular-nums text-muted-foreground">
                            {t("yaml.activeSessions", { count: yamlState.data.active_sessions })}
                        </span>
                    ) : undefined
                }
            >
                {!yamlState.data?.wired ? (
                    <div className="flex items-center gap-2 py-2">
                        <StatusBadge state="standby" label={t("yaml.notAttached")} />
                    </div>
                ) : yamlState.data.descriptors.length === 0 ? (
                    <p className="text-sm text-muted-foreground py-2">
                        {t("yaml.noDescriptors")}{" "}
                        <code className="font-mono tabular-nums">
                            {yamlState.data.active_sessions ?? 0}
                        </code>
                    </p>
                ) : (
                    <div className="space-y-2">
                        {yamlState.data.descriptors.map((d) => (
                            <DescriptorRow
                                key={d.name}
                                name={d.name}
                                pathPattern={d.path_pattern}
                                turns={d.turns}
                            />
                        ))}
                    </div>
                )}
            </MetricCard>

            {/* ── YAML editor ─────────────────────────────────────────────── */}
            <MetricCard
                title={t("yaml.editorTitle")}
                description={t("yaml.editorDescription")}
                noPadding
            >
                {/* Editor flush to card edges with a bottom-padded action row */}
                <div className="border-b border-border/40 overflow-hidden">
                    <Editor
                        height="320px"
                        defaultLanguage="yaml"
                        value={yaml}
                        onChange={(v) => setYaml(v ?? "")}
                        theme="vs-dark"
                        options={{ minimap: { enabled: false }, fontSize: 12 }}
                    />
                </div>
                <div className="px-5 py-4 space-y-3">
                    <Button onClick={() => parse.mutate()} disabled={parse.isPending}>
                        {t("yaml.parsePreview")}
                    </Button>
                    {parse.data?.ok && (
                        <ParseResult data={parse.data} />
                    )}
                </div>
            </MetricCard>
        </div>
    );
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

function DescriptorRow({
    name,
    pathPattern,
    turns,
}: {
    name: string;
    pathPattern: string;
    turns: number;
}) {
    const { t } = useTranslation(["tarpit", "common"]);
    return (
        <div className="flex items-center justify-between rounded-lg border border-border/40 bg-muted/10 px-3 py-2.5">
            <div className="min-w-0">
                <span className="font-mono text-sm font-semibold text-foreground">{name}</span>
                <code className="block text-xs text-muted-foreground mt-0.5">{pathPattern}</code>
            </div>
            <span className={cn(
                "shrink-0 ml-3 text-xs font-semibold tabular-nums px-2 py-0.5 rounded-full",
                "border border-border/40 text-muted-foreground",
            )}>
                {t("descriptor.turns", { count: turns })}
            </span>
        </div>
    );
}

function ParseResult({
    data,
}: {
    data: { ok: boolean; parsed?: Array<{ name: string; path_pattern: string; turns: number }>; note?: string };
}) {
    const { t } = useTranslation(["tarpit", "common"]);
    return (
        <div className="rounded-lg border border-primary/30 bg-primary/5 p-4 text-xs">
            <div className="flex items-center gap-2 mb-2">
                <StatusBadge state="active" label={t("yaml.valid")} />
                <SectionHeader
                    label={t("yaml.parsedCount", { count: data.parsed?.length ?? 0 })}
                    className="text-[10px]"
                />
            </div>
            <pre className="whitespace-pre-wrap overflow-x-auto text-foreground/80 leading-relaxed">
                {JSON.stringify(data.parsed, null, 2)}
            </pre>
            {data.note && (
                <p className="text-muted-foreground mt-2">{data.note}</p>
            )}
        </div>
    );
}

