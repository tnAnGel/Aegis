/**
 * V2 SignatureMine — /v2/signatures
 *
 * Mine attack n-grams from a corpus of suspicious payloads.
 * Approve candidates and copy them as WAF rule TOML.
 *
 * NO direct write-back to WAF config — operator pastes into their
 * rule file via the Config Editor page.
 *
 * Data sources:
 *   signatureMineApi.mine()  — POST mutation returning candidates
 */

import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { useMutation, useQuery } from "@tanstack/react-query";
import { ClipboardCopy, Loader2, ScanSearch, Cpu } from "lucide-react";
import { signatureMineApi, type SignatureCandidate, type MinedCandidate } from "@/api/client";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
import { ErrorState } from "@/components/ErrorState";
import { useToast } from "@/hooks/useToast";
import { MetricCard } from "@/v2/components/MetricCard";
import { SectionHeader } from "@/v2/components/SectionHeader";
import { SeverityChip } from "@/v2/components/SeverityChip";
import type { Severity } from "@/v2/components/SeverityChip";

// ── constants ────────────────────────────────────────────────────────

const DEFAULT_ATTACK_SAMPLE = `/api/users?id=1' union select 1,2,3--
/login?u=admin' UNION SELECT password FROM users--
/?q=foo' or 1=1--
/?id=' OR '1'='1`;

const DEFAULT_BENIGN_SAMPLE = `/api/users
/login
/index.html
/static/app.js
/favicon.ico`;

// ── helpers ──────────────────────────────────────────────────────────

/** Map attack category to a V2 SeverityChip severity */
function categoryToSeverity(cat: string): Severity {
    switch (cat) {
        case "sqli":
        case "cmdi":
        case "rce":
        case "webshell":
            return "critical";
        case "xss":
        case "ssrf":
        case "lfi":
        case "xxe":
            return "high";
        case "path_traversal":
            return "medium";
        default:
            return "low";
    }
}

/** Confidence number → severity for colour coding */
function confidenceToSeverity(c: number): Severity {
    if (c >= 0.8) return "low";      // green-ish: high confidence = good signal
    if (c >= 0.5) return "medium";   // yellow
    return "high";                   // amber: low confidence
}

function ruleToml(c: SignatureCandidate, idx: number): string {
    const safeId = `mined-${c.category}-${idx}`;
    const escaped = c.ngram.replace(/"/g, '\\"');
    return [
        `[[rules]]`,
        `id = "${safeId}"`,
        `field = "path"`,
        `op = "contains"`,
        `value = "${escaped}"`,
        `action = "deny"`,
        ``,
    ].join("\n");
}

// ── Sub-components ─────────────────────────────────────────────────────

/** Candidates table extracted to prevent TSC deep-inference limit */
function CandidatesTable({
    candidates,
    selected,
    allSelected,
    onToggle,
    onToggleAll,
}: {
    candidates: SignatureCandidate[];
    selected: Set<number>;
    allSelected: boolean;
    onToggle: (idx: number) => void;
    onToggleAll: () => void;
}) {
    const { t } = useTranslation("signaturemine");
    return (
        <div className="overflow-x-auto">
            <table className="w-full">
                <thead>
                    <tr className="border-b border-border/60 text-left">
                        <th className="px-3 py-2.5 w-10">
                            <Checkbox
                                checked={allSelected}
                                onCheckedChange={onToggleAll}
                                aria-label={t("table.selectAll")}
                            />
                        </th>
                        <th className="px-3 py-2.5 text-[0.65rem] font-semibold uppercase tracking-wider text-muted-foreground">{t("table.confidence")}</th>
                        <th className="px-3 py-2.5 text-[0.65rem] font-semibold uppercase tracking-wider text-muted-foreground text-right">{t("table.attack")}</th>
                        <th className="px-3 py-2.5 text-[0.65rem] font-semibold uppercase tracking-wider text-muted-foreground text-right">{t("table.benign")}</th>
                        <th className="px-3 py-2.5 text-[0.65rem] font-semibold uppercase tracking-wider text-muted-foreground">{t("table.category")}</th>
                        <th className="px-3 py-2.5 text-[0.65rem] font-semibold uppercase tracking-wider text-muted-foreground">{t("table.ngram")}</th>
                    </tr>
                </thead>
                <tbody>
                    {candidates.map((c, idx) => (
                        <tr
                            key={`${c.ngram}-${idx}`}
                            className="v2-table-row text-sm"
                            onClick={() => onToggle(idx)}
                            style={{ cursor: "pointer" }}
                        >
                            <td className="px-3 py-2.5">
                                <Checkbox
                                    checked={selected.has(idx)}
                                    onCheckedChange={(v) => {
                                        if (v === true || v === false) onToggle(idx);
                                    }}
                                    onClick={(e) => e.stopPropagation()}
                                    aria-label={t("table.selectRow", { index: idx + 1, ngram: c.ngram })}
                                />
                            </td>
                            <td className="px-3 py-2.5">
                                <div className="flex items-center gap-2">
                                    <SeverityChip severity={confidenceToSeverity(c.confidence)} />
                                    <span className="font-mono tabular-nums text-xs text-muted-foreground">
                                        {c.confidence.toFixed(2)}
                                    </span>
                                </div>
                            </td>
                            <td className="v2-table-num px-3 py-2.5 text-xs">{c.attack_support.toFixed(2)}</td>
                            <td className="v2-table-num px-3 py-2.5 text-xs text-muted-foreground">{c.benign_support.toFixed(2)}</td>
                            <td className="px-3 py-2.5">
                                <SeverityChip severity={categoryToSeverity(c.category)} showLabel />
                                <span className="sr-only">{c.category}</span>
                            </td>
                            <td className="px-3 py-2.5 font-mono text-xs break-all text-foreground/90">{c.ngram}</td>
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    );
}

// ── Auto-mined candidates helpers ────────────────────────────────────

/** Format a Unix timestamp (seconds) as a relative "X ago" string. */
function relativeTime(unixSecs: number, t: (key: string, opts?: Record<string, unknown>) => string): string {
    const diffSecs = Math.max(0, Math.floor(Date.now() / 1000) - unixSecs);
    if (diffSecs < 60) return t("time.secondsAgo", { n: diffSecs });
    if (diffSecs < 3600) return t("time.minutesAgo", { n: Math.floor(diffSecs / 60) });
    if (diffSecs < 86400) return t("time.hoursAgo", { n: Math.floor(diffSecs / 3600) });
    return t("time.daysAgo", { n: Math.floor(diffSecs / 86400) });
}

/** Read-only table of auto-mined candidates from the tarpit→miner pipeline. */
function AutoMinedCandidatesCard() {
    const { t } = useTranslation("signaturemine");
    const mined = useQuery({
        queryKey: ["mined-signatures"],
        queryFn: signatureMineApi.minedCandidates,
        refetchInterval: 30000,
    });

    if (mined.isLoading) {
        return (
            <MetricCard title={t("auto.title")} description={t("auto.description")}>
                <div className="flex items-center gap-2 py-4 text-sm text-muted-foreground">
                    <Loader2 className="h-4 w-4 animate-spin" />
                    {t("auto.loading")}
                </div>
            </MetricCard>
        );
    }

    if (mined.error) {
        return (
            <MetricCard title={t("auto.title")} description={t("auto.description")}>
                <ErrorState title={t("auto.loadError")} error={mined.error as Error} />
            </MetricCard>
        );
    }

    const data = mined.data;
    if (!data) return null;

    // Pipeline disabled — show note in muted empty state
    if (!data.enabled) {
        return (
            <MetricCard
                title={t("auto.title")}
                description={t("auto.description")}
            >
                <div className="py-8 text-center">
                    <Cpu className="h-8 w-8 text-muted-foreground/30 mx-auto mb-3" />
                    <p className="text-sm text-muted-foreground">
                        {data.note ?? t("auto.disabled")}
                    </p>
                    <p className="text-xs text-muted-foreground/50 mt-1">
                        {t("auto.disabledHint")}
                    </p>
                </div>
            </MetricCard>
        );
    }

    // Sort by confidence descending
    const sorted: MinedCandidate[] = [...data.candidates].sort(
        (a, b) => b.confidence - a.confidence,
    );

    const lastRun = data.last_run_unix_secs != null
        ? relativeTime(data.last_run_unix_secs, t)
        : null;

    const description =
        t("auto.summary", { count: sorted.length }) +
        (lastRun ? t("auto.lastRun", { time: lastRun }) : "");

    return (
        <MetricCard
            title={t("auto.title")}
            description={description}
            noPadding
        >
            {sorted.length === 0 ? (
                <div className="py-8 text-center px-4">
                    <Cpu className="h-8 w-8 text-muted-foreground/30 mx-auto mb-3" />
                    <p className="text-sm text-muted-foreground">{t("auto.empty")}</p>
                    <p className="text-xs text-muted-foreground/50 mt-1">
                        {t("auto.emptyHint")}
                    </p>
                </div>
            ) : (
                <div className="overflow-x-auto">
                    <table className="w-full">
                        <thead>
                            <tr className="border-b border-border/60 text-left">
                                <th className="px-3 py-2.5 text-[0.65rem] font-semibold uppercase tracking-wider text-muted-foreground">{t("table.ngram")}</th>
                                <th className="px-3 py-2.5 text-[0.65rem] font-semibold uppercase tracking-wider text-muted-foreground">{t("table.category")}</th>
                                <th className="px-3 py-2.5 text-[0.65rem] font-semibold uppercase tracking-wider text-muted-foreground text-right">{t("table.confidence")}</th>
                                <th className="px-3 py-2.5 text-[0.65rem] font-semibold uppercase tracking-wider text-muted-foreground text-right">{t("table.attackSupport")}</th>
                                <th className="px-3 py-2.5 text-[0.65rem] font-semibold uppercase tracking-wider text-muted-foreground text-right">{t("table.benignSupport")}</th>
                            </tr>
                        </thead>
                        <tbody>
                            {sorted.map((c, idx) => (
                                <tr key={`${c.ngram}-${idx}`} className="v2-table-row text-sm">
                                    <td className="px-3 py-2.5 font-mono text-xs break-all text-foreground/90">
                                        {c.ngram}
                                    </td>
                                    <td className="px-3 py-2.5">
                                        <SeverityChip severity={categoryToSeverity(c.category)} showLabel />
                                        <span className="sr-only">{c.category}</span>
                                    </td>
                                    <td className="v2-table-num px-3 py-2.5">
                                        <div className="flex items-center justify-end gap-2">
                                            <SeverityChip severity={confidenceToSeverity(c.confidence)} />
                                            <span className="font-mono tabular-nums text-xs">
                                                {(c.confidence * 100).toFixed(1)}%
                                            </span>
                                        </div>
                                    </td>
                                    <td className="v2-table-num px-3 py-2.5 font-mono tabular-nums text-xs">
                                        {c.attack_support.toFixed(2)}
                                    </td>
                                    <td className="v2-table-num px-3 py-2.5 font-mono tabular-nums text-xs text-muted-foreground">
                                        {c.benign_support.toFixed(2)}
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

// ── Main page ─────────────────────────────────────────────────────────

export function SignatureMineV2Page() {
    const { t } = useTranslation(["signaturemine", "common"]);
    const { toast } = useToast();
    const [attacks, setAttacks] = useState("");
    const [benign, setBenign] = useState(DEFAULT_BENIGN_SAMPLE);
    const [selected, setSelected] = useState<Set<number>>(new Set());

    const mine = useMutation<{ candidates: SignatureCandidate[]; raw: string }, Error>({
        mutationFn: () =>
            signatureMineApi.mine(
                attacks.split(/\r?\n/).filter((l) => l.trim()),
                benign.split(/\r?\n/).filter((l) => l.trim()),
            ),
        onSuccess: () => {
            setSelected(new Set());
        },
        onError: (e: unknown) => {
            toast({ title: t("toast.mineFailed"), description: String(e), variant: "destructive" });
        },
    });

    const candidates: SignatureCandidate[] = mine.data?.candidates ?? [];

    const toggleSelect = (idx: number) => {
        setSelected((prev) => {
            const next = new Set(prev);
            if (next.has(idx)) next.delete(idx);
            else next.add(idx);
            return next;
        });
    };

    const toggleAll = () => {
        if (selected.size === candidates.length) {
            setSelected(new Set());
        } else {
            setSelected(new Set(candidates.map((_, i) => i)));
        }
    };

    const selectedToml = useMemo(() => {
        return Array.from(selected)
            .sort((a, b) => a - b)
            .map((i) => {
                const c = candidates[i];
                return c ? ruleToml(c, i) : "";
            })
            .filter(Boolean)
            .join("\n");
    }, [selected, candidates]);

    const copySelected = async () => {
        if (!selectedToml) {
            toast({ title: t("toast.noRows"), variant: "destructive" });
            return;
        }
        try {
            await navigator.clipboard.writeText(selectedToml);
            toast({
                title: t("toast.copied", { n: selected.size }),
                description: t("toast.copiedDesc"),
                variant: "success",
            });
        } catch (e) {
            toast({ title: t("toast.clipboardFailed"), description: String(e), variant: "destructive" });
        }
    };

    const allSelected = candidates.length > 0 && selected.size === candidates.length;

    return (
        <div className="space-y-6">
            <div>
                <SectionHeader label={t("section")} />
                <h1 className="text-2xl font-bold tracking-tight mt-1">{t("title")}</h1>
                <p className="text-sm text-muted-foreground mt-1">
                    {t("subtitle")}
                </p>
            </div>

            <AutoMinedCandidatesCard />

            <div>
                <SectionHeader label={t("manual.section")} />
                <p className="text-xs text-muted-foreground mt-1 mb-3">
                    {t("manual.hint")}
                </p>
            </div>

            <div className="grid md:grid-cols-2 gap-4">
                <MetricCard title={t("attack.title")} description={t("attack.description")}>
                    <Label htmlFor="v2-atks" className="sr-only">{t("attack.aria")}</Label>
                    <textarea
                        id="v2-atks"
                        value={attacks}
                        onChange={(e) => setAttacks(e.target.value)}
                        placeholder={DEFAULT_ATTACK_SAMPLE}
                        className="font-mono text-xs w-full h-56 rounded-lg border border-input bg-background/50 p-3 focus:outline-none focus:ring-1 focus:ring-ring resize-none"
                        spellCheck={false}
                    />
                </MetricCard>
                <MetricCard title={t("benign.title")} description={t("benign.description")}>
                    <Label htmlFor="v2-bens" className="sr-only">{t("benign.aria")}</Label>
                    <textarea
                        id="v2-bens"
                        value={benign}
                        onChange={(e) => setBenign(e.target.value)}
                        className="font-mono text-xs w-full h-56 rounded-lg border border-input bg-background/50 p-3 focus:outline-none focus:ring-1 focus:ring-ring resize-none"
                        spellCheck={false}
                    />
                </MetricCard>
            </div>

            <div className="flex items-center gap-3">
                <Button onClick={() => mine.mutate()} disabled={mine.isPending}>
                    {mine.isPending
                        ? <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                        : <ScanSearch className="h-4 w-4 mr-2" />
                    }
                    {t("mine.button")}
                </Button>
                {candidates.length > 0 && (
                    <Button variant="outline" onClick={copySelected} disabled={selected.size === 0}>
                        <ClipboardCopy className="h-4 w-4 mr-2" />
                        {selected.size > 0 ? t("copy.button", { n: selected.size }) : t("copy.buttonEmpty")}
                    </Button>
                )}
            </div>

            {mine.error && <ErrorState title={t("mine.errorTitle")} error={mine.error} />}

            {candidates.length > 0 && (
                <MetricCard
                    title={t("candidates.title")}
                    description={t("candidates.description", { n: candidates.length })}
                    noPadding
                >
                    <CandidatesTable
                        candidates={candidates}
                        selected={selected}
                        allSelected={allSelected}
                        onToggle={toggleSelect}
                        onToggleAll={toggleAll}
                    />
                </MetricCard>
            )}

            {mine.data && candidates.length === 0 && (
                <MetricCard title={t("empty.title")}>
                    <div className="py-6 text-center">
                        <ScanSearch className="h-8 w-8 text-muted-foreground/40 mx-auto mb-3" />
                        <p className="text-sm text-muted-foreground">{t("empty.text")}</p>
                        <p className="text-xs text-muted-foreground/70 mt-1 max-w-sm mx-auto">
                            {t("empty.hint")}
                        </p>
                    </div>
                </MetricCard>
            )}
        </div>
    );
}
