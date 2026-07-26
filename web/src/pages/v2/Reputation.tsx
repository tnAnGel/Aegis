/**
 * V2 Reputation — /v2/reputation
 *
 * JA4 fingerprint reputation, ASN/CIDR reputation, and the built-in JA4
 * corpus. Mirrors V1 ReputationPage data-fetching exactly; only the
 * presentation layer changes.
 *
 * Data sources:
 *   reputationApi.ja4()          — JA4 feed status
 *   reputationApi.asn()          — ASN feed status
 *   envApi.get()                 — env-var list (feed paths)
 *   reputationApi.ja4Lookup()    — per-hash lookup mutation
 *   reputationApi.asnLookup()    — per-IP lookup mutation
 *   envApi.set()                 — save feed path mutation
 */

import { useState } from "react";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
    Fingerprint,
    Network,
    Save,
    Search,
    X,
} from "lucide-react";
import { reputationApi, envApi } from "@/api/client";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState } from "@/components/ErrorState";
import { useToast } from "@/hooks/useToast";
import type { EnvVarEntry } from "@/types";
import { MetricCard } from "@/v2/components/MetricCard";
import { SectionHeader } from "@/v2/components/SectionHeader";
import { StatusBadge } from "@/v2/components/StatusBadge";

// ── helpers ──────────────────────────────────────────────────────────

function splitPaths(value: string | null | undefined): string[] {
    if (!value) return [];
    return value
        .split(":")
        .map((p) => p.trim())
        .filter(Boolean);
}

function joinPaths(paths: string[]): string {
    return paths.filter((p) => p.trim()).join(":");
}

// ── PathListEditor ────────────────────────────────────────────────────

interface PathListEditorProps {
    envKey: string;
    entry: EnvVarEntry | null | undefined;
    onSaved: () => void;
    t: TFunction;
}

function PathListEditor({ envKey, entry, onSaved, t }: PathListEditorProps) {
    const { toast } = useToast();
    const currentPaths = splitPaths(entry?.value);
    const [paths, setPaths] = useState<string[]>(
        currentPaths.length > 0 ? [...currentPaths, ""] : [""],
    );

    const save = useMutation({
        mutationFn: () => {
            const joined = joinPaths(paths);
            return envApi.set(envKey, joined || null);
        },
        onSuccess: (res) => {
            toast({
                title: t("toast.savedTitle"),
                description: res.restart_required
                    ? t("toast.savedDescRestart")
                    : t("toast.savedDescApplied"),
                variant: "success",
            });
            onSaved();
        },
        onError: (e: unknown) => {
            toast({
                title: t("toast.failedTitle"),
                description: String(e),
                variant: "destructive",
            });
        },
    });

    function updatePath(idx: number, val: string) {
        setPaths((prev) => {
            const next = [...prev];
            next[idx] = val;
            if (idx === next.length - 1 && val.trim()) {
                next.push("");
            }
            return next;
        });
    }

    function removePath(idx: number) {
        setPaths((prev) => {
            const next = prev.filter((_, i) => i !== idx);
            return next.length > 0 ? next : [""];
        });
    }

    const stored = entry?.value ?? null;
    const edited = joinPaths(paths) || null;
    const isDirty = edited !== stored;

    return (
        <div className="space-y-2">
            {paths.map((p, idx) => (
                <div key={idx} className="flex items-center gap-2">
                    <Input
                        value={p}
                        onChange={(e) => updatePath(idx, e.target.value)}
                        placeholder={t("editor.placeholder")}
                        className="font-mono text-xs flex-1"
                        aria-label={t("editor.feedPathAria", { index: idx + 1 })}
                    />
                    {(paths.length > 1 || p.trim()) && (
                        <Button
                            variant="ghost"
                            size="icon"
                            className="h-8 w-8 shrink-0"
                            onClick={() => removePath(idx)}
                            aria-label={t("editor.removePath")}
                        >
                            <X className="h-3.5 w-3.5" />
                        </Button>
                    )}
                </div>
            ))}
            <div className="flex items-center gap-2 pt-1">
                <Button
                    size="sm"
                    onClick={() => save.mutate()}
                    disabled={!isDirty || save.isPending}
                >
                    <Save className="h-3.5 w-3.5 mr-1.5" />
                    {t("editor.save")}
                </Button>
                {isDirty && (
                    <span className="text-xs text-muted-foreground">{t("editor.unsaved")}</span>
                )}
                {save.data?.restart_required && (
                    <span className="inline-flex items-center px-2 py-0.5 rounded text-[0.65rem] font-semibold bg-amber-500/15 text-amber-400 border border-amber-500/30">
                        {t("editor.restartRequired")}
                    </span>
                )}
            </div>
            <p className="text-xs text-muted-foreground leading-relaxed">
                {t("editor.help")}
            </p>
        </div>
    );
}

// ── LookupResult ─────────────────────────────────────────────────────

function LookupResult({ children }: { children: React.ReactNode }) {
    return (
        <div className="rounded-lg border border-border/40 bg-muted/20 p-3 text-xs font-mono">
            {children}
        </div>
    );
}

// ── Main page ─────────────────────────────────────────────────────────

export function ReputationV2Page() {
    const { t } = useTranslation(["reputation", "common"]);
    const { toast } = useToast();
    const qc = useQueryClient();

    const ja4Status = useQuery({
        queryKey: ["rep", "ja4"],
        queryFn: reputationApi.ja4,
        refetchInterval: 30_000,
    });
    const asnStatus = useQuery({
        queryKey: ["rep", "asn"],
        queryFn: reputationApi.asn,
        refetchInterval: 30_000,
    });
    const envVars = useQuery({
        queryKey: ["env", "vars"],
        queryFn: envApi.get,
        refetchInterval: 60_000,
    });

    const [ja4, setJa4] = useState("");
    const [ip, setIp] = useState("");

    const ja4Lookup = useMutation({
        mutationFn: () => reputationApi.ja4Lookup(ja4),
        onError: (e) =>
            toast({ title: t("toast.ja4FailedTitle"), description: String(e), variant: "destructive" }),
    });
    const asnLookup = useMutation({
        mutationFn: () => reputationApi.asnLookup(ip),
        onError: (e) =>
            toast({ title: t("toast.asnFailedTitle"), description: String(e), variant: "destructive" }),
    });

    function findEnvEntry(key: string): EnvVarEntry | null {
        return envVars.data?.vars.find((v) => v.key === key) ?? null;
    }

    function handleSaved() {
        void qc.invalidateQueries({ queryKey: ["env", "vars"] });
        void qc.invalidateQueries({ queryKey: ["rep"] });
    }

    return (
        <div className="space-y-6">
            {/* Page header */}
            <div>
                <SectionHeader label={t("header.section")} />
                <h1 className="text-2xl font-bold tracking-tight mt-1">{t("header.title")}</h1>
                <p className="text-sm text-muted-foreground mt-1">
                    {t("header.subtitle")}
                </p>
            </div>

            {ja4Status.isLoading && <Skeleton className="h-32" />}
            {ja4Status.error && (
                <ErrorState title={t("error.load")} error={ja4Status.error} />
            )}

            {/* ── Feed status ──────────────────────────────────────────── */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <MetricCard
                    title={t("card.ja4.title")}
                    action={
                        <StatusBadge
                            state={ja4Status.data?.active ? "active" : "standby"}
                        />
                    }
                >
                    <div className="space-y-3">
                        <div className="flex items-baseline gap-2">
                            <Fingerprint className="h-4 w-4 text-muted-foreground/70 shrink-0 mb-0.5" />
                            <span className="v2-kpi-number text-3xl font-bold tabular-nums">
                                {(ja4Status.data?.entry_count ?? 0).toLocaleString()}
                            </span>
                            <span className="text-sm text-muted-foreground">{t("feedEntries")}</span>
                        </div>
                        <div className="flex items-center gap-4 text-sm text-muted-foreground">
                            <span>
                                {t("builtInCorpus")}{" "}
                                <span className="tabular-nums font-semibold text-foreground">
                                    {(ja4Status.data?.corpus_count ?? 0).toLocaleString()}
                                </span>
                            </span>
                        </div>
                    </div>
                </MetricCard>

                <MetricCard
                    title={t("card.asn.title")}
                    action={
                        <StatusBadge
                            state={asnStatus.data?.active ? "active" : "standby"}
                        />
                    }
                >
                    <div className="flex items-baseline gap-2">
                        <Network className="h-4 w-4 text-muted-foreground/70 shrink-0 mb-0.5" />
                        <span className="v2-kpi-number text-3xl font-bold tabular-nums">
                            {(asnStatus.data?.entry_count ?? 0).toLocaleString()}
                        </span>
                        <span className="text-sm text-muted-foreground">{t("feedEntries")}</span>
                    </div>
                </MetricCard>
            </div>

            {/* ── Feed path editors ─────────────────────────────────────── */}
            <MetricCard
                title={t("card.paths.title")}
                description={t("card.paths.description")}
            >
                <div className="space-y-6">
                    {/* JA4 paths */}
                    <div className="space-y-3">
                        <div className="flex items-center gap-2">
                            <Fingerprint className="h-4 w-4 text-muted-foreground/70" />
                            <h3 className="text-sm font-semibold">{t("ja4.paths.heading")}</h3>
                        </div>
                        <p className="text-xs text-muted-foreground">
                            {t("ja4.paths.help")}
                        </p>
                        {envVars.isLoading ? (
                            <Skeleton className="h-10" />
                        ) : envVars.error ? (
                            <p className="text-xs text-destructive">
                                {t("paths.loadError", { error: String(envVars.error) })}
                            </p>
                        ) : (
                            <>
                                <Label className="sr-only">{t("paths.srLabel.ja4")}</Label>
                                <PathListEditor
                                    envKey="AEGIS_JA4_REPUTATION"
                                    entry={findEnvEntry("AEGIS_JA4_REPUTATION")}
                                    onSaved={handleSaved}
                                    t={t}
                                />
                            </>
                        )}
                    </div>

                    <div className="border-t border-border/40" />

                    {/* ASN paths */}
                    <div className="space-y-3">
                        <div className="flex items-center gap-2">
                            <Network className="h-4 w-4 text-muted-foreground/70" />
                            <h3 className="text-sm font-semibold">{t("asn.paths.heading")}</h3>
                        </div>
                        <p className="text-xs text-muted-foreground">
                            {t("asn.paths.help")}
                        </p>
                        {envVars.isLoading ? (
                            <Skeleton className="h-10" />
                        ) : envVars.error ? (
                            <p className="text-xs text-destructive">
                                {t("paths.loadError", { error: String(envVars.error) })}
                            </p>
                        ) : (
                            <>
                                <Label className="sr-only">{t("paths.srLabel.asn")}</Label>
                                <PathListEditor
                                    envKey="AEGIS_ASN_REPUTATION"
                                    entry={findEnvEntry("AEGIS_ASN_REPUTATION")}
                                    onSaved={handleSaved}
                                    t={t}
                                />
                            </>
                        )}
                    </div>
                </div>
            </MetricCard>

            {/* ── Lookups ───────────────────────────────────────────────── */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {/* JA4 lookup */}
                <MetricCard
                    title={t("card.ja4Lookup.title")}
                    description={t("card.ja4Lookup.description")}
                >
                    <div className="space-y-3">
                        <div className="flex gap-2 items-end">
                            <div className="flex-1">
                                <Label htmlFor="v2-ja4-val" className="text-xs text-muted-foreground mb-1.5 block">
                                    {t("ja4Lookup.label")}
                                </Label>
                                <Input
                                    id="v2-ja4-val"
                                    value={ja4}
                                    onChange={(e) => setJa4(e.target.value)}
                                    placeholder="t13d1516h2_8daaf6152771_b1ff8ab2d16f"
                                    className="font-mono text-xs"
                                />
                            </div>
                            <Button
                                onClick={() => ja4Lookup.mutate()}
                                disabled={!ja4 || ja4Lookup.isPending}
                            >
                                <Search className="h-3.5 w-3.5 mr-1.5" />
                                {t("lookup.button")}
                            </Button>
                        </div>

                        {ja4Lookup.data && (
                            <LookupResult>
                                <div className="space-y-2">
                                    <div>
                                        <span className="text-muted-foreground">{t("ja4Lookup.feedMatch")}</span>
                                        {ja4Lookup.data.feed ? (
                                            <span className="text-green-400">
                                                {JSON.stringify(ja4Lookup.data.feed)}
                                            </span>
                                        ) : (
                                            <span className="text-muted-foreground italic">{t("ja4Lookup.noMatch")}</span>
                                        )}
                                    </div>
                                    <div>
                                        <span className="text-muted-foreground">{t("ja4Lookup.corpusMatch")}</span>
                                        {ja4Lookup.data.corpus ? (
                                            <span className="text-blue-400">
                                                {JSON.stringify(ja4Lookup.data.corpus)}
                                            </span>
                                        ) : (
                                            <span className="text-muted-foreground italic">{t("ja4Lookup.unknown")}</span>
                                        )}
                                    </div>
                                </div>
                            </LookupResult>
                        )}
                    </div>
                </MetricCard>

                {/* ASN lookup */}
                <MetricCard
                    title={t("card.asnLookup.title")}
                    description={t("card.asnLookup.description")}
                >
                    <div className="space-y-3">
                        <div className="flex gap-2 items-end">
                            <div className="flex-1">
                                <Label htmlFor="v2-ip-val" className="text-xs text-muted-foreground mb-1.5 block">
                                    {t("asnLookup.label")}
                                </Label>
                                <Input
                                    id="v2-ip-val"
                                    value={ip}
                                    onChange={(e) => setIp(e.target.value)}
                                    placeholder="203.0.113.5"
                                    className="font-mono text-xs"
                                />
                            </div>
                            <Button
                                onClick={() => asnLookup.mutate()}
                                disabled={!ip || asnLookup.isPending}
                            >
                                <Search className="h-3.5 w-3.5 mr-1.5" />
                                {t("lookup.button")}
                            </Button>
                        </div>

                        {asnLookup.data && (
                            <LookupResult>
                                {asnLookup.data.matched ? (
                                    <div className="space-y-1.5">
                                        <div>
                                            <span className="text-muted-foreground">{t("asnLookup.tag")}</span>
                                            <span className="text-amber-400">{asnLookup.data.tag}</span>
                                        </div>
                                        <div>
                                            <span className="text-muted-foreground">{t("asnLookup.score")}</span>
                                            <span className="tabular-nums text-foreground font-semibold">
                                                {asnLookup.data.score}
                                            </span>
                                        </div>
                                        <div>
                                            <span className="text-muted-foreground">{t("asnLookup.matchKind")}</span>
                                            <span className="text-foreground">{asnLookup.data.match_kind}</span>
                                        </div>
                                    </div>
                                ) : (
                                    <span className="text-muted-foreground italic">{t("asnLookup.noMatch")}</span>
                                )}
                            </LookupResult>
                        )}
                    </div>
                </MetricCard>
            </div>
        </div>
    );
}
