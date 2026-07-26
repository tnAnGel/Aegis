/**
 * V2 Enrichment page — /v2/enrichment
 *
 * Presentation layer only change. Data fetching is identical to V1:
 *   - enrichmentApi.status (poll 10 s)
 *   - enrichmentApi.lookup (mutation, manual trigger)
 *
 * V2 visual changes:
 *   - MetricCard replaces Card for all panels
 *   - KPITile for the three overview counters
 *   - Per-source stats table uses v2-table-* CSS classes
 *   - Lookup tester result panel uses V2 card chrome
 *   - SeverityChip-style verdict badges (inline styles match the V2 palette)
 */

import { useState } from "react";
import { useTranslation } from "react-i18next";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Database, Search } from "lucide-react";
import { enrichmentApi } from "@/api/client";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import {
    Select,
    SelectContent,
    SelectItem,
    SelectTrigger,
    SelectValue,
} from "@/components/ui/select";
import { ErrorState } from "@/components/ErrorState";
import { useToast } from "@/hooks/useToast";
import { KPITile } from "@/v2/components/KPITile";
import { MetricCard } from "@/v2/components/MetricCard";
import { SectionHeader } from "@/v2/components/SectionHeader";
import { StatusBadge } from "@/v2/components/StatusBadge";

// ─── Helpers ────────────────────────────────────────────────────────────────

/** Coloured verdict badge matching V2 palette — no new libs needed. */
function VerdictBadge({ verdict }: { verdict: string }) {
    const { t } = useTranslation("enrichment");
    const lower = verdict.toLowerCase();
    const style =
        lower === "deny"
            ? "border-destructive/40 bg-destructive/10 text-destructive"
            : lower === "allow"
                ? "border-green-500/40 bg-green-500/10 text-green-400"
                : "border-border/40 bg-muted/20 text-muted-foreground";
    // Translate the known verdicts; fall back to the raw value for anything else.
    const known = lower === "deny" || lower === "allow" || lower === "unknown";
    const labelText = known ? t(`verdict.${lower}`) : verdict;
    return (
        <span
            className={`inline-flex items-center px-2 py-0.5 rounded text-[0.65rem] font-semibold uppercase tracking-wider border ${style}`}
        >
            {labelText}
        </span>
    );
}

// ─── Page ────────────────────────────────────────────────────────────────────

type LookupKind = "ip" | "ja4" | "asn" | "user_agent";

export function EnrichmentPage() {
    const { t } = useTranslation(["enrichment", "common"]);
    const { toast } = useToast();
    const [kind, setKind] = useState<LookupKind>("ip");
    const [value, setValue] = useState("");

    const status = useQuery({
        queryKey: ["enrichment"],
        queryFn: enrichmentApi.status,
        refetchInterval: 10_000,
    });

    const lookup = useMutation({
        mutationFn: () => enrichmentApi.lookup(kind, value),
        onError: (e) =>
            toast({ title: t("lookupFailed"), description: String(e), variant: "destructive" }),
    });

    const sources = status.data?.sources ?? [];
    const totalQueries = sources.reduce((acc, s) => acc + s.queries, 0);
    const wired = status.data?.wired;

    const placeholderByKind: Record<LookupKind, string> = {
        ip: "203.0.113.5",
        ja4: "t13d1516h2_8daaf6152771_...",
        asn: "12345",
        user_agent: "Mozilla/5.0 ...",
    };

    return (
        <div className="space-y-6">
            {/* Page heading */}
            <div className="flex items-center gap-3">
                <div className="flex items-center justify-center w-8 h-8 rounded-lg bg-primary/10">
                    <Database className="h-4 w-4 text-primary" />
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
            {status.isLoading && <Skeleton className="h-32" />}
            {status.error && (
                <ErrorState title={t("loadError")} error={status.error} />
            )}

            {/* Arsenal wired state */}
            {!wired && !status.isLoading && (
                <div
                    className="v2-card border-amber-500/40 px-5 py-3 flex items-center gap-3"
                    style={{ boxShadow: "var(--v2-card-shadow)" }}
                >
                    <StatusBadge state="standby" label={t("arsenalNotAttached")} />
                    <p className="text-sm text-amber-200">
                        {t("arsenalNotWired")}
                    </p>
                </div>
            )}

            {/* Overview KPI tiles */}
            <div>
                <SectionHeader label={t("overview")} className="mb-3" />
                <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                    <KPITile
                        label={t("registeredSources")}
                        value={sources.length}
                        icon={<Database className="h-4 w-4" />}
                    />
                    <KPITile
                        label={t("cacheHits")}
                        value={status.data?.cache?.hits ?? 0}
                        deltaLabel={t("cacheDelta", {
                            misses: status.data?.cache?.misses ?? 0,
                            size: status.data?.cache?.size ?? 0,
                        })}
                    />
                    <KPITile
                        label={t("totalQueries")}
                        value={totalQueries}
                    />
                </div>
            </div>

            {/* Per-source stats */}
            <MetricCard title={t("perSourceStats")}>
                {sources.length === 0 ? (
                    <p className="text-sm text-muted-foreground py-2">
                        {t("noSourcesPrefix")}{" "}
                        <code className="text-primary/80 bg-primary/5 px-1 py-0.5 rounded text-[0.7rem]">
                            arsenal.enrichment.write().register(...)
                        </code>
                        .
                    </p>
                ) : (
                    <div className="overflow-x-auto -mx-5 px-5">
                        <table className="w-full text-xs">
                            <thead>
                                <tr className="border-b border-border/50">
                                    <th className="text-left py-2 pr-4 font-medium text-muted-foreground">{t("table.source")}</th>
                                    <th className="text-right py-2 pr-4 font-medium text-muted-foreground">{t("table.queries")}</th>
                                    <th className="text-right py-2 pr-4 font-medium text-muted-foreground">{t("table.hits")}</th>
                                    <th className="text-right py-2 pr-4 font-medium text-muted-foreground">{t("table.misses")}</th>
                                    <th className="text-right py-2 font-medium text-muted-foreground">{t("table.hitRate")}</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-border/30">
                                {sources.map((s) => {
                                    const hitRate =
                                        s.queries > 0
                                            ? `${((s.hits / s.queries) * 100).toFixed(0)}%`
                                            : "—";
                                    return (
                                        <tr key={s.name} className="v2-table-row">
                                            <td className="py-2 pr-4">
                                                <code className="text-primary/80 bg-primary/5 px-1.5 py-0.5 rounded text-[0.7rem]">
                                                    {s.name}
                                                </code>
                                            </td>
                                            <td className="py-2 pr-4 v2-table-num">{s.queries}</td>
                                            <td className="py-2 pr-4 v2-table-num text-green-400">{s.hits}</td>
                                            <td className="py-2 pr-4 v2-table-num text-muted-foreground">{s.misses}</td>
                                            <td className="py-2 v2-table-num">
                                                <span
                                                    className={
                                                        s.queries > 0 && s.hits / s.queries >= 0.8
                                                            ? "text-green-400"
                                                            : "text-muted-foreground"
                                                    }
                                                >
                                                    {hitRate}
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

            {/* Lookup tester */}
            <MetricCard
                title={t("lookupTester")}
                description={t("lookupTesterDesc")}
            >
                <div className="space-y-4">
                    <div className="grid grid-cols-1 md:grid-cols-4 gap-3 items-end">
                        <div>
                            <Label htmlFor="kind" className="text-xs text-muted-foreground mb-1.5 block">
                                {t("keyKind")}
                            </Label>
                            <Select value={kind} onValueChange={(v) => setKind(v as LookupKind)}>
                                <SelectTrigger id="kind" className="h-8 text-xs">
                                    <SelectValue />
                                </SelectTrigger>
                                <SelectContent>
                                    <SelectItem value="ip">{t("kind.ip")}</SelectItem>
                                    <SelectItem value="ja4">{t("kind.ja4")}</SelectItem>
                                    <SelectItem value="asn">{t("kind.asn")}</SelectItem>
                                    <SelectItem value="user_agent">{t("kind.userAgent")}</SelectItem>
                                </SelectContent>
                            </Select>
                        </div>
                        <div className="md:col-span-2">
                            <Label htmlFor="lookup-value" className="text-xs text-muted-foreground mb-1.5 block">
                                {t("value")}
                            </Label>
                            <Input
                                id="lookup-value"
                                value={value}
                                onChange={(e) => setValue(e.target.value)}
                                placeholder={placeholderByKind[kind]}
                                className="h-8 font-mono text-xs"
                                onKeyDown={(e) => {
                                    if (e.key === "Enter" && value && !lookup.isPending) {
                                        lookup.mutate();
                                    }
                                }}
                            />
                        </div>
                        <div>
                            <Button
                                onClick={() => lookup.mutate()}
                                disabled={!value || lookup.isPending}
                                size="sm"
                                className="h-8 w-full text-xs"
                            >
                                <Search className="h-3 w-3 mr-1.5" />
                                {lookup.isPending ? t("querying") : t("lookup")}
                            </Button>
                        </div>
                    </div>

                    {lookup.data && (
                        <div
                            className="rounded-lg border border-border/50 bg-muted/10 p-4 space-y-3"
                        >
                            {/* Aggregate verdict */}
                            <div className="flex items-center gap-3">
                                <p className="v2-section-label">{t("aggregateVerdict")}</p>
                                <VerdictBadge verdict={lookup.data.aggregate} />
                            </div>

                            {/* Per-source breakdown */}
                            {lookup.data.sources.length === 0 ? (
                                <p className="text-xs text-muted-foreground">
                                    {t("noSourceMatched")}
                                </p>
                            ) : (
                                <table className="w-full text-xs">
                                    <tbody className="divide-y divide-border/20">
                                        {lookup.data.sources.map((s, i) => (
                                            <tr key={i} className="v2-table-row">
                                                <td className="py-1.5 pr-4">
                                                    <code className="text-primary/80 bg-primary/5 px-1 py-0.5 rounded text-[0.7rem]">
                                                        {s.source}
                                                    </code>
                                                </td>
                                                <td className="py-1.5 pr-4">
                                                    <VerdictBadge verdict={s.verdict} />
                                                </td>
                                                <td className="py-1.5 text-muted-foreground">
                                                    {s.label}
                                                </td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            )}
                        </div>
                    )}
                </div>
            </MetricCard>
        </div>
    );
}
