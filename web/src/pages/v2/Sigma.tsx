/**
 * V2 Sigma — /v2/sigma
 *
 * Convert SigmaHQ community detection rules into Aegis WAF rules.
 * Mirrors V1 SigmaPage data-fetching exactly; only the presentation
 * layer changes.
 *
 * Data sources:
 *   sigmaApi.status()      — corpus file status
 *   sigmaApi.importRule()  — single-rule import mutation
 *   sigmaApi.list()        — every bundled rule + enabled state
 *   sigmaApi.toggle()      — per-rule enable/disable (disk overlay)
 */

import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import Editor from "@monaco-editor/react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Database, FileCode2, FileText, Search, Upload } from "lucide-react";
import { sigmaApi } from "@/api/client";
import type { SigmaRule } from "@/api/client";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { MetricCard } from "@/v2/components/MetricCard";
import { SectionHeader } from "@/v2/components/SectionHeader";
import { StatusBadge } from "@/v2/components/StatusBadge";
import { useToast } from "@/hooks/useToast";
import { cn } from "@/lib/cn";

const SAMPLE = `title: Suspicious user-agent
id: 00000000-0000-0000-0000-000000000001
status: stable
description: nikto / sqlmap UA
logsource:
  category: webserver
detection:
  selection:
    c-useragent|contains:
      - nikto
      - sqlmap
  condition: selection
level: high
`;

export function SigmaV2Page() {
    const { t } = useTranslation(["sigma", "common"]);
    const { toast } = useToast();
    const qc = useQueryClient();
    const [yaml, setYaml] = useState(SAMPLE);

    const status = useQuery({
        queryKey: ["sigma", "status"],
        queryFn: sigmaApi.status,
        refetchInterval: 30_000,
    });

    const importM = useMutation({
        mutationFn: () => sigmaApi.importRule(yaml),
        onSuccess: (res) => {
            if (res.ok) {
                toast({
                    title: t("toast.imported.title", { title: res.title }),
                    description: t("toast.imported.desc", { count: res.emitted ?? 0 }),
                });
                qc.invalidateQueries({ queryKey: ["sigma"] });
            } else {
                toast({
                    title: t("toast.importFailed"),
                    description: res.error,
                    variant: "destructive",
                });
            }
        },
    });

    return (
        <div className="space-y-6">
            {/* Page header */}
            <div>
                <SectionHeader label={t("section")} />
                <h1 className="text-2xl font-bold tracking-tight mt-1">{t("title")}</h1>
                <p className="text-sm text-muted-foreground mt-1">
                    {t("subtitle.before")}
                    (<code className="font-mono text-[0.7rem]">logsource.category: webserver</code>)
                    {t("subtitle.after")}
                </p>
            </div>

            {/* ── Corpus status ─────────────────────────────────────────── */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <MetricCard
                    title={t("corpus.title")}
                    action={
                        <StatusBadge
                            state={status.data?.exists ? "active" : "standby"}
                            label={status.data?.exists ? t("corpus.present") : t("corpus.missing")}
                        />
                    }
                >
                    <div className="space-y-2">
                        <div className="flex items-baseline gap-2">
                            <Database className="h-4 w-4 text-muted-foreground/70 shrink-0 mb-0.5" />
                            <span className="v2-kpi-number text-3xl font-bold tabular-nums">
                                {(status.data?.rule_count ?? 0).toLocaleString()}
                            </span>
                            <span className="text-sm text-muted-foreground">{t("corpus.rules")}</span>
                        </div>
                        <p className="text-xs text-muted-foreground font-mono break-all">
                            {status.data?.path ?? "—"}
                        </p>
                    </div>
                </MetricCard>

                <MetricCard
                    title={t("regen.title")}
                    className="md:col-span-2"
                >
                    <div className="rounded-lg overflow-hidden border border-border/40">
                        <div className="px-3 py-1.5 bg-muted/40 border-b border-border/40">
                            <span className="text-[0.65rem] font-semibold uppercase tracking-wider text-muted-foreground">
                                {t("regen.shell")}
                            </span>
                        </div>
                        <pre className="text-xs bg-muted/20 p-4 overflow-x-auto font-mono leading-relaxed text-foreground/90">{`git clone --depth=1 --filter=blob:none --sparse \\
    https://github.com/SigmaHQ/sigma.git /tmp/sigma
cd /tmp/sigma
git sparse-checkout set \\
    rules/web rules-emerging-threats rules-threat-hunting

aegis-sigma-import \\
    --input /tmp/sigma \\
    --output ${status.data?.path ?? "rules/sigma/sigma-webserver.toml"} \\
    --verbose

# Point WAF at it:
#   [filters.waf]
#   rule_files = ["rules/sigma/sigma-webserver.toml"]`}</pre>
                    </div>
                </MetricCard>
            </div>

            {/* ── Manage bundled rules ─────────────────────────────────── */}
            <SigmaRuleManager />

            {/* ── Single rule import ────────────────────────────────────── */}
            <MetricCard
                title={t("single.title")}
                description={t("single.description")}
            >
                <div className="space-y-4">
                    <div className="flex items-center gap-2 text-sm text-muted-foreground">
                        <Upload className="h-4 w-4" />
                        <span>
                            {t("single.hint")}
                        </span>
                    </div>

                    <div className="rounded-lg overflow-hidden border border-border/40">
                        <Editor
                            height="300px"
                            defaultLanguage="yaml"
                            value={yaml}
                            onChange={(v) => setYaml(v ?? "")}
                            theme="vs-dark"
                            options={{
                                minimap: { enabled: false },
                                fontSize: 12,
                                lineNumbersMinChars: 3,
                                scrollBeyondLastLine: false,
                            }}
                        />
                    </div>

                    <Button
                        onClick={() => importM.mutate()}
                        disabled={importM.isPending}
                    >
                        <Upload className="h-3.5 w-3.5 mr-1.5" />
                        {t("single.convert")}
                    </Button>

                    {/* Success result */}
                    {importM.data?.ok && (
                        <div className="rounded-lg overflow-hidden border border-green-500/30 bg-green-500/5">
                            <div className="px-4 py-2.5 border-b border-green-500/20 flex items-center gap-2">
                                <FileText className="h-3.5 w-3.5 text-green-400" />
                                <span className="text-sm font-semibold text-green-400">
                                    {t("single.converted", { title: importM.data.title, count: importM.data.emitted })}
                                </span>
                            </div>
                            <pre className="text-xs font-mono p-4 overflow-x-auto text-foreground/80 whitespace-pre-wrap leading-relaxed">
                                {JSON.stringify(importM.data.rules, null, 2)}
                            </pre>
                        </div>
                    )}

                    {/* Import error from API */}
                    {importM.data && !importM.data.ok && (
                        <div className="rounded-lg border border-destructive/30 bg-destructive/5 px-4 py-3">
                            <p className="text-sm text-destructive font-semibold">{t("single.importFailed")}</p>
                            <p className="text-xs text-muted-foreground mt-1">
                                {importM.data.error ?? t("single.unknownError")}
                            </p>
                        </div>
                    )}
                </div>
            </MetricCard>

            {/* ── File size detail ─────────────────────────────────────── */}
            {status.data && (
                <div className="flex items-center gap-4 text-xs text-muted-foreground">
                    <div className="flex items-center gap-1.5">
                        <FileCode2 className="h-3.5 w-3.5" />
                        <span>
                            {t("fileSize.label")}{" "}
                            <span className="tabular-nums text-foreground">
                                {status.data.size_bytes > 0
                                    ? `${(status.data.size_bytes / 1024).toFixed(1)} KB`
                                    : "—"}
                            </span>
                        </span>
                    </div>
                    {status.data.note && (
                        <span className="text-muted-foreground/70">{status.data.note}</span>
                    )}
                </div>
            )}
        </div>
    );
}

// ---------------------------------------------------------------------------
// Per-rule enable/disable manager
// ---------------------------------------------------------------------------

const SEVERITY_ORDER = ["critical", "high", "medium", "low"] as const;
type Severity = (typeof SEVERITY_ORDER)[number];

const SEVERITY_META: Record<Severity, { dot: string; text: string }> = {
    critical: { dot: "bg-red-500", text: "text-red-400" },
    high: { dot: "bg-orange-500", text: "text-orange-400" },
    medium: { dot: "bg-amber-500", text: "text-amber-400" },
    low: { dot: "bg-sky-500", text: "text-sky-400" },
};

function normSeverity(s: string): Severity {
    const v = s.toLowerCase();
    return (SEVERITY_ORDER as readonly string[]).includes(v) ? (v as Severity) : "medium";
}

function SigmaRuleManager() {
    const { t } = useTranslation(["sigma", "common"]);
    const { toast } = useToast();
    const qc = useQueryClient();
    const [search, setSearch] = useState("");
    const [onlyDisabled, setOnlyDisabled] = useState(false);

    const list = useQuery({
        queryKey: ["sigma", "list"],
        queryFn: sigmaApi.list,
        refetchInterval: 30_000,
    });

    const toggle = useMutation({
        mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
            sigmaApi.toggle(id, enabled),
        // Optimistic update so the Switch responds instantly across 562 rows.
        onMutate: async ({ id, enabled }) => {
            await qc.cancelQueries({ queryKey: ["sigma", "list"] });
            const prev = qc.getQueryData<Awaited<ReturnType<typeof sigmaApi.list>>>([
                "sigma",
                "list",
            ]);
            if (prev) {
                qc.setQueryData(["sigma", "list"], {
                    ...prev,
                    disabled_count: prev.disabled_count + (enabled ? -1 : 1),
                    rules: prev.rules.map((r) =>
                        r.id === id ? { ...r, enabled } : r,
                    ),
                });
            }
            return { prev };
        },
        onError: (e, _vars, ctx) => {
            if (ctx?.prev) qc.setQueryData(["sigma", "list"], ctx.prev);
            toast({ title: t("toast.toggleFailed"), description: String(e), variant: "destructive" });
        },
        onSettled: () => void qc.invalidateQueries({ queryKey: ["sigma", "list"] }),
    });

    const rules = list.data?.rules ?? [];

    // Filter by search (id / value / field / tags) and the disabled-only toggle.
    const filtered = useMemo(() => {
        const q = search.trim().toLowerCase();
        return rules.filter((r) => {
            if (onlyDisabled && r.enabled) return false;
            if (!q) return true;
            return (
                r.id.toLowerCase().includes(q) ||
                r.value.toLowerCase().includes(q) ||
                r.field.toLowerCase().includes(q) ||
                r.op.toLowerCase().includes(q) ||
                r.tags.some((t) => t.toLowerCase().includes(q))
            );
        });
    }, [rules, search, onlyDisabled]);

    // Group filtered rules by severity, in fixed severity order.
    const grouped = useMemo(() => {
        const m = new Map<Severity, SigmaRule[]>();
        for (const sev of SEVERITY_ORDER) m.set(sev, []);
        for (const r of filtered) m.get(normSeverity(r.severity))!.push(r);
        return SEVERITY_ORDER.map((sev) => ({ sev, items: m.get(sev)! })).filter(
            (g) => g.items.length > 0,
        );
    }, [filtered]);

    const total = list.data?.total ?? 0;
    const disabledCount = list.data?.disabled_count ?? 0;
    const enabledCount = total - disabledCount;

    return (
        <MetricCard
            title={t("manager.title", { total: total.toLocaleString() })}
            description={t("manager.description")}
            action={
                <StatusBadge
                    state={disabledCount > 0 ? "standby" : "active"}
                    label={t("manager.onOff", { on: enabledCount.toLocaleString(), off: disabledCount.toLocaleString() })}
                />
            }
        >
            <div className="space-y-4">
                {/* Search + filter row */}
                <div className="flex flex-wrap items-center gap-3">
                    <div className="relative flex-1 min-w-[220px]">
                        <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground/60" />
                        <Input
                            className="pl-9"
                            placeholder={t("manager.searchPlaceholder")}
                            value={search}
                            onChange={(e) => setSearch(e.target.value)}
                            aria-label={t("manager.searchAria")}
                        />
                    </div>
                    <label className="flex items-center gap-2 text-xs text-muted-foreground cursor-pointer shrink-0">
                        <Switch checked={onlyDisabled} onCheckedChange={setOnlyDisabled} />
                        {t("manager.disabledOnly")}
                    </label>
                </div>

                {/* States */}
                {list.isLoading ? (
                    <p className="text-sm text-muted-foreground">{t("manager.loading")}</p>
                ) : list.isError ? (
                    <p className="text-sm text-destructive">
                        {t("manager.loadError")}
                    </p>
                ) : filtered.length === 0 ? (
                    <p className="text-sm text-muted-foreground">
                        {t("manager.noMatch.before")}
                        <code className="font-mono text-[10px]">{search || t("manager.noMatch.fallback")}</code>
                        {t("manager.noMatch.after")}
                    </p>
                ) : (
                    <div className="space-y-5">
                        {grouped.map(({ sev, items }) => (
                            <div key={sev} className="space-y-2">
                                <div className="flex items-center gap-2">
                                    <span className={cn("h-2 w-2 rounded-full", SEVERITY_META[sev].dot)} />
                                    <span className={cn("text-xs font-semibold uppercase tracking-wider", SEVERITY_META[sev].text)}>
                                        {t(`severity.${sev}`)}
                                    </span>
                                    <span className="text-[10px] text-muted-foreground tabular-nums">
                                        {items.length}
                                    </span>
                                </div>
                                <div className="grid gap-2 grid-cols-1 lg:grid-cols-2">
                                    {items.map((r) => (
                                        <RuleRow
                                            key={r.id}
                                            rule={r}
                                            pending={toggle.isPending}
                                            onToggle={(enabled) =>
                                                toggle.mutate({ id: r.id, enabled })
                                            }
                                        />
                                    ))}
                                </div>
                            </div>
                        ))}
                    </div>
                )}
            </div>
        </MetricCard>
    );
}

function RuleRow({
    rule,
    pending,
    onToggle,
}: {
    rule: SigmaRule;
    pending: boolean;
    onToggle: (enabled: boolean) => void;
}) {
    const { t } = useTranslation("sigma");
    return (
        <div
            className={cn(
                "flex items-start gap-3 rounded-lg border p-3 transition-colors",
                rule.enabled
                    ? "border-primary/20 bg-primary/5"
                    : "border-border/40 bg-muted/10 opacity-70",
            )}
        >
            <Switch
                checked={rule.enabled}
                disabled={pending}
                onCheckedChange={onToggle}
                aria-label={t("row.toggleAria", { id: rule.id })}
            />
            <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2 flex-wrap">
                    <code className="text-xs font-mono text-foreground break-all">{rule.field}</code>
                    <span className="text-[10px] text-muted-foreground uppercase">{rule.op}</span>
                    <code className="text-[10px] font-mono text-muted-foreground bg-muted/30 px-1.5 py-0.5 rounded break-all">
                        {rule.value || "—"}
                    </code>
                    <span className="text-[10px] text-muted-foreground uppercase tracking-wide">
                        {rule.action}
                    </span>
                </div>
                <div className="flex items-center gap-1.5 flex-wrap mt-1">
                    <code className="text-[9px] font-mono text-muted-foreground/70 break-all">
                        {rule.id}
                    </code>
                    {rule.tags.slice(0, 4).map((t) => (
                        <span
                            key={t}
                            className="text-[9px] text-muted-foreground bg-muted/20 px-1 py-0.5 rounded"
                        >
                            {t}
                        </span>
                    ))}
                </div>
            </div>
        </div>
    );
}
