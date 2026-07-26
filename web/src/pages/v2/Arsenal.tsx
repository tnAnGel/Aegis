/**
 * V2 Defence Arsenal page — /v2/arsenal
 *
 * Identical data-fetching and mutations as V1 Arsenal.tsx.
 * Presentation rebuilt with V2 primitives: MetricCard, SectionHeader,
 * StatusBadge and the v2-card / v2-chip-* / v2-status-pill-* CSS classes.
 *
 * Feature-gate controls use the same envApi / restartApi / runtimeInfoApi
 * calls. Module cards are v2-styled with family-colour icon squares.
 */

import * as React from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import {
    Fingerprint,
    ShieldAlert,
    Network,
    FlaskConical,
    Radio,
    Lock,
    Sparkles,
    CheckCircle2,
    Clock,
    AlertTriangle,
    RotateCcw,
} from "lucide-react";
import { arsenalApi, envApi, restartApi, runtimeInfoApi } from "@/api/client";
import type { ArsenalModule, ArsenalCounters } from "@/api/client";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import {
    Dialog,
    DialogContent,
    DialogHeader,
    DialogTitle,
    DialogDescription,
    DialogFooter,
    DialogClose,
} from "@/components/ui/dialog";
import {
    Select,
    SelectContent,
    SelectItem,
    SelectTrigger,
    SelectValue,
} from "@/components/ui/select";
import { useToast } from "@/hooks/useToast";
import { MetricCard } from "@/v2/components/MetricCard";
import { StatusBadge } from "@/v2/components/StatusBadge";

// ─── Types ───────────────────────────────────────────────────────────────────

type Family = ArsenalModule["family"];
type RiskMode = "off" | "observe" | "enforce";

// ─── Family metadata ─────────────────────────────────────────────────────────

const FAMILY_META: Record<
    Family,
    {
        labelKey: string;
        icon: React.ComponentType<{ className?: string }>;
        iconClass: string;
        blurbKey: string;
    }
> = {
    fingerprint: {
        labelKey: "family.fingerprint.label",
        icon: Fingerprint,
        iconClass: "text-violet-400 bg-violet-500/10 border-violet-500/30",
        blurbKey: "family.fingerprint.blurb",
    },
    waf: {
        labelKey: "family.waf.label",
        icon: ShieldAlert,
        iconClass: "text-amber-400 bg-amber-500/10 border-amber-500/30",
        blurbKey: "family.waf.blurb",
    },
    ddos: {
        labelKey: "family.ddos.label",
        icon: Network,
        iconClass: "text-red-400 bg-red-500/10 border-red-500/30",
        blurbKey: "family.ddos.blurb",
    },
    honeypot: {
        labelKey: "family.honeypot.label",
        icon: FlaskConical,
        iconClass: "text-emerald-400 bg-emerald-500/10 border-emerald-500/30",
        blurbKey: "family.honeypot.blurb",
    },
    telemetry: {
        labelKey: "family.telemetry.label",
        icon: Radio,
        iconClass: "text-sky-400 bg-sky-500/10 border-sky-500/30",
        blurbKey: "family.telemetry.blurb",
    },
    challenge: {
        labelKey: "family.challenge.label",
        icon: Lock,
        iconClass: "text-blue-400 bg-blue-500/10 border-blue-500/30",
        blurbKey: "family.challenge.blurb",
    },
    deception: {
        labelKey: "family.deception.label",
        icon: Sparkles,
        iconClass: "text-pink-400 bg-pink-500/10 border-pink-500/30",
        blurbKey: "family.deception.blurb",
    },
};

const FAMILY_ORDER: Family[] = [
    "fingerprint",
    "waf",
    "ddos",
    "challenge",
    "honeypot",
    "deception",
    "telemetry",
];

// ─── Helpers ──────────────────────────────────────────────────────────────────

function formatNum(n: number): string {
    if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
    if (n >= 1_000) return `${(n / 1_000).toFixed(1)}k`;
    return n.toString();
}

// ─── Restart-required banner ──────────────────────────────────────────────────

function RestartBanner({
    onRestart,
    isPending,
}: {
    onRestart: () => void;
    isPending: boolean;
}) {
    const { t } = useTranslation("arsenal");
    return (
        <div className="flex items-center gap-3 rounded-lg border border-amber-500/30 bg-amber-500/8 px-4 py-2.5 text-sm text-amber-300 mt-3">
            <AlertTriangle className="h-4 w-4 shrink-0" />
            <span className="flex-1">
                {t("restartPending")}
            </span>
            <Button
                size="sm"
                variant="outline"
                className="border-amber-500/40 text-amber-300 hover:bg-amber-500/15 h-7 text-xs"
                onClick={onRestart}
                disabled={isPending}
            >
                <RotateCcw className="h-3 w-3 mr-1.5" />
                {t("restartNow")}
            </Button>
        </div>
    );
}

// ─── Module status chip (Arsenal-specific, distinct from V2 StatusBadge) ──────

function ArsenalStatusChip({ status }: { status: ArsenalModule["status"] }) {
    const { t } = useTranslation("arsenal");
    if (status === "shipped") {
        return (
            <span className="inline-flex items-center gap-1 rounded-md border border-emerald-500/30 bg-emerald-500/10 px-2 py-0.5 text-[10px] font-medium text-emerald-300">
                <CheckCircle2 className="h-2.5 w-2.5" />
                {t("chip.shipped")}
            </span>
        );
    }
    if (status === "experimental") {
        return (
            <span className="inline-flex items-center gap-1 rounded-md border border-amber-500/30 bg-amber-500/10 px-2 py-0.5 text-[10px] font-medium text-amber-300">
                <Sparkles className="h-2.5 w-2.5" />
                {t("chip.experimental")}
            </span>
        );
    }
    return (
        <span className="inline-flex items-center gap-1 rounded-md border border-border/40 bg-muted/20 px-2 py-0.5 text-[10px] font-medium text-muted-foreground">
            <Clock className="h-2.5 w-2.5" />
            {t("chip.planned")}
        </span>
    );
}

// ─── Module card ──────────────────────────────────────────────────────────────

function ModuleCard({
    m,
    counters,
}: {
    m: ArsenalModule;
    counters?: ArsenalCounters;
}) {
    const meta = FAMILY_META[m.family];
    const Icon = meta.icon;
    const raw = counters?.[m.id];
    const stats =
        typeof raw === "object" ? (raw as Record<string, number>) : undefined;

    return (
        <div
            className="v2-card flex flex-col gap-3 p-4"
            style={{ boxShadow: "var(--v2-card-shadow)" }}
        >
            {/* Header row */}
            <div className="flex items-start justify-between gap-2">
                <div className="flex items-center gap-2.5 min-w-0">
                    <div
                        className={`h-7 w-7 rounded-md grid place-items-center border shrink-0 ${meta.iconClass}`}
                    >
                        <Icon className="h-3.5 w-3.5" />
                    </div>
                    <div className="min-w-0">
                        <p
                            className="text-sm font-semibold text-foreground truncate leading-tight"
                            title={m.label}
                        >
                            {m.label}
                        </p>
                        <p className="text-[10px] font-mono text-muted-foreground mt-0.5 truncate">
                            {m.v} · {m.id}
                        </p>
                    </div>
                </div>
                <ArsenalStatusChip status={m.status} />
            </div>

            {/* Description */}
            <p className="text-xs text-muted-foreground leading-relaxed">{m.desc}</p>

            {/* Counters */}
            {stats && Object.keys(stats).length > 0 && (
                <div className="flex flex-wrap gap-1 pt-2 border-t border-border/30">
                    {Object.entries(stats).map(([k, v]) => (
                        <span
                            key={k}
                            className="inline-flex items-center gap-1 rounded border border-border/40 bg-muted/20 px-1.5 py-0.5 text-[10px] font-mono"
                            title={k}
                        >
                            <span className="text-muted-foreground">{k}</span>
                            <span
                                className={`font-semibold tabular-nums ${
                                    v > 0 ? "text-emerald-300" : "text-muted-foreground/60"
                                }`}
                            >
                                {formatNum(v)}
                            </span>
                        </span>
                    ))}
                </div>
            )}
        </div>
    );
}

// ─── Arsenal master-switch ────────────────────────────────────────────────────

function ArsenalMasterSwitch() {
    const { t } = useTranslation("arsenal");
    const { toast } = useToast();
    const qc = useQueryClient();
    const [confirmOpen, setConfirmOpen] = React.useState(false);
    const [pendingRestart, setPendingRestart] = React.useState(false);

    const info = useQuery({
        queryKey: ["runtime", "info"],
        queryFn: runtimeInfoApi.get,
        refetchInterval: 15_000,
    });

    const setEnv = useMutation({
        mutationFn: ({ key, value }: { key: string; value: string | null }) =>
            envApi.set(key, value),
        onSuccess: (res) => {
            if (res.restart_required) setPendingRestart(true);
            qc.invalidateQueries({ queryKey: ["runtime", "info"] });
            toast({
                title: res.restart_required
                    ? t("envUpdatedRestart")
                    : t("envUpdated"),
                description: t("envWritten"),
                variant: "success",
            });
        },
        onError: (e) => {
            toast({ title: t("envFailed"), description: String(e), variant: "destructive" });
        },
    });

    const restart = useMutation({
        mutationFn: restartApi.run,
        onSuccess: (res) => {
            setPendingRestart(false);
            toast({ title: t("restartTriggered"), description: res.note });
        },
        onError: (e) => {
            toast({ title: t("restartFailed"), description: String(e), variant: "destructive" });
        },
    });

    const arsenalEnabled = info.data?.arsenal_enabled ?? true;

    function handleToggle(checked: boolean) {
        if (!checked) {
            setConfirmOpen(true);
        } else {
            setEnv.mutate({ key: "AEGIS_ARSENAL", value: "1" });
        }
    }

    return (
        <>
            <div
                className="v2-card p-5 flex flex-col gap-3"
                style={{ boxShadow: "var(--v2-card-shadow)" }}
            >
                <div className="flex items-start justify-between gap-4">
                    <div className="space-y-1 min-w-0">
                        <p className="text-sm font-semibold text-foreground">{t("master.title")}</p>
                        <p className="text-xs text-muted-foreground leading-relaxed">
                            {t("master.desc")}
                        </p>
                    </div>
                    <Switch
                        checked={arsenalEnabled}
                        onCheckedChange={handleToggle}
                        disabled={setEnv.isPending || info.isLoading}
                        aria-label={t("master.ariaLabel")}
                        className="shrink-0"
                    />
                </div>
                {pendingRestart && (
                    <RestartBanner onRestart={() => restart.mutate()} isPending={restart.isPending} />
                )}
            </div>

            <Dialog open={confirmOpen} onOpenChange={setConfirmOpen}>
                <DialogContent className="max-w-md">
                    <DialogHeader>
                        <DialogTitle className="flex items-center gap-2">
                            <AlertTriangle className="h-5 w-5 text-amber-400" />
                            {t("master.confirmTitle")}
                        </DialogTitle>
                        <DialogDescription>
                            {t("master.confirmDesc")}
                        </DialogDescription>
                    </DialogHeader>
                    <div className="text-sm text-muted-foreground space-y-2">
                        <p>
                            {t("master.confirmBody")}
                        </p>
                        <p className="text-amber-300 font-medium">
                            {t("master.confirmKeep")}
                        </p>
                    </div>
                    <DialogFooter>
                        <DialogClose asChild>
                            <Button variant="outline" size="sm">{t("cancel", { ns: "common" })}</Button>
                        </DialogClose>
                        <Button
                            variant="destructive"
                            size="sm"
                            onClick={() => {
                                setConfirmOpen(false);
                                setEnv.mutate({ key: "AEGIS_ARSENAL", value: "0" });
                            }}
                            disabled={setEnv.isPending}
                        >
                            {t("master.disable")}
                        </Button>
                    </DialogFooter>
                </DialogContent>
            </Dialog>
        </>
    );
}

// ─── TLS fingerprinting switch ────────────────────────────────────────────────

function TlsFingerprintSwitch() {
    const { t } = useTranslation("arsenal");
    const { toast } = useToast();
    const qc = useQueryClient();
    const [pendingRestart, setPendingRestart] = React.useState(false);

    const info = useQuery({
        queryKey: ["runtime", "info"],
        queryFn: runtimeInfoApi.get,
        refetchInterval: 15_000,
    });

    const setEnv = useMutation({
        mutationFn: ({ key, value }: { key: string; value: string | null }) =>
            envApi.set(key, value),
        onSuccess: (res) => {
            if (res.restart_required) setPendingRestart(true);
            qc.invalidateQueries({ queryKey: ["runtime", "info"] });
            toast({
                title: res.restart_required ? t("envUpdatedRestart") : t("envUpdated"),
                description: t("envWritten"),
                variant: "success",
            });
        },
        onError: (e) => {
            toast({ title: t("envFailed"), description: String(e), variant: "destructive" });
        },
    });

    const restart = useMutation({
        mutationFn: restartApi.run,
        onSuccess: (res) => {
            setPendingRestart(false);
            toast({ title: t("restartTriggered"), description: res.note });
        },
        onError: (e) => {
            toast({ title: t("restartFailed"), description: String(e), variant: "destructive" });
        },
    });

    const tlsEnabled = info.data?.tls_fingerprinting ?? false;

    return (
        <div
            className="v2-card p-5 flex flex-col gap-3"
            style={{ boxShadow: "var(--v2-card-shadow)" }}
        >
            <div className="flex items-start justify-between gap-4">
                <div className="space-y-1 min-w-0">
                    <p className="text-sm font-semibold text-foreground flex items-center gap-2">
                        <Fingerprint className="h-4 w-4 text-violet-400 shrink-0" />
                        {t("tls.title")}
                    </p>
                    <p className="text-xs text-muted-foreground leading-relaxed">
                        {t("tls.desc")}
                    </p>
                </div>
                <Switch
                    checked={tlsEnabled}
                    onCheckedChange={(v) =>
                        setEnv.mutate({ key: "AEGIS_TLS_FINGERPRINT", value: v ? "1" : "0" })
                    }
                    disabled={setEnv.isPending || info.isLoading}
                    aria-label={t("tls.ariaLabel")}
                    className="shrink-0"
                />
            </div>
            {pendingRestart && (
                <RestartBanner onRestart={() => restart.mutate()} isPending={restart.isPending} />
            )}
        </div>
    );
}

// ─── Risk Engine control ──────────────────────────────────────────────────────

function RiskEngineControl() {
    const { t } = useTranslation("arsenal");
    const { toast } = useToast();
    const qc = useQueryClient();
    const [pendingRestart, setPendingRestart] = React.useState(false);

    const info = useQuery({
        queryKey: ["runtime", "info"],
        queryFn: runtimeInfoApi.get,
        refetchInterval: 15_000,
    });

    const setEnv = useMutation({
        mutationFn: ({ key, value }: { key: string; value: string | null }) =>
            envApi.set(key, value),
        onSuccess: (res) => {
            if (res.restart_required) setPendingRestart(true);
            qc.invalidateQueries({ queryKey: ["runtime", "info"] });
            toast({
                title: res.restart_required
                    ? t("risk.modeUpdatedRestart")
                    : t("risk.modeUpdated"),
                description: t("envWritten"),
                variant: "success",
            });
        },
        onError: (e) => {
            toast({ title: t("envFailed"), description: String(e), variant: "destructive" });
        },
    });

    const restart = useMutation({
        mutationFn: restartApi.run,
        onSuccess: (res) => {
            setPendingRestart(false);
            toast({ title: t("restartTriggered"), description: res.note });
        },
        onError: (e) => {
            toast({ title: t("restartFailed"), description: String(e), variant: "destructive" });
        },
    });

    const rawMode = info.data?.risk_engine_mode;
    const currentMode: RiskMode =
        rawMode === "observe" ? "observe" : rawMode === "enforce" ? "enforce" : "off";

    function handleModeChange(value: string) {
        const mode = value as RiskMode;
        setEnv.mutate({
            key: "AEGIS_RISK_ENGINE_MODE",
            value: mode === "off" ? null : mode,
        });
    }

    const modeChipClass: Record<RiskMode, string> = {
        off: "text-muted-foreground border-border/40 bg-muted/20",
        observe: "text-amber-300 border-amber-500/30 bg-amber-500/10",
        enforce: "text-emerald-300 border-emerald-500/30 bg-emerald-500/10",
    };

    return (
        <div
            className="v2-card p-5 flex flex-col gap-3"
            style={{ boxShadow: "var(--v2-card-shadow)" }}
        >
            <div className="flex items-start justify-between gap-4">
                <div className="space-y-1 flex-1 min-w-0">
                    <p className="text-sm font-semibold text-foreground flex items-center gap-2">
                        <ShieldAlert className="h-4 w-4 text-amber-400 shrink-0" />
                        {t("risk.title")}
                    </p>
                    <p className="text-xs text-muted-foreground leading-relaxed">
                        {t("risk.desc")}
                    </p>
                </div>
                <div className="flex flex-col items-end gap-2 shrink-0">
                    <Select
                        value={currentMode}
                        onValueChange={handleModeChange}
                        disabled={setEnv.isPending || info.isLoading}
                    >
                        <SelectTrigger className="w-32 h-8 text-xs">
                            <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                            <SelectItem value="off">
                                <span className="text-muted-foreground">{t("risk.mode.off")}</span>
                            </SelectItem>
                            <SelectItem value="observe">
                                <span className="text-amber-300">{t("risk.mode.observe")}</span>
                            </SelectItem>
                            <SelectItem value="enforce">
                                <span className="text-emerald-300">{t("risk.mode.enforce")}</span>
                            </SelectItem>
                        </SelectContent>
                    </Select>
                    <span
                        className={`inline-flex items-center rounded-md border px-2 py-0.5 text-[10px] font-medium ${modeChipClass[currentMode]}`}
                    >
                        {t(`risk.mode.${currentMode}`)}
                    </span>
                </div>
            </div>
            {pendingRestart && (
                <RestartBanner onRestart={() => restart.mutate()} isPending={restart.isPending} />
            )}
        </div>
    );
}

// ─── Main page ────────────────────────────────────────────────────────────────

export function ArsenalPage() {
    const { t } = useTranslation(["arsenal", "common"]);
    const q = useQuery({
        queryKey: ["arsenal"],
        queryFn: arsenalApi.get,
        refetchInterval: 30_000,
    });

    const modules = q.data?.modules ?? [];
    const summary = q.data?.summary;
    const counters = q.data?.counters;
    const wired = counters?.wired === true;

    const grouped: Record<Family, ArsenalModule[]> = {
        fingerprint: [],
        waf: [],
        ddos: [],
        honeypot: [],
        telemetry: [],
        challenge: [],
        deception: [],
    };
    for (const m of modules) {
        grouped[m.family]?.push(m);
    }

    return (
        <div className="space-y-8">
            {/* Page header */}
            <div>
                <h1 className="text-2xl font-bold text-foreground tracking-tight">{t("title")}</h1>
                <p className="mt-1 text-sm text-muted-foreground">
                    {t("subtitle")}
                </p>
            </div>

            {/* Feature-gate controls */}
            <MetricCard title={t("featureGate")}>
                <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
                    <ArsenalMasterSwitch />
                    <TlsFingerprintSwitch />
                    <RiskEngineControl />
                </div>
            </MetricCard>

            {/* Summary / wired indicator */}
            {summary && (
                <div className="space-y-4">
                    {/* Wired status pill */}
                    <div className="flex items-center gap-2">
                        <StatusBadge
                            state={wired ? "active" : "standby"}
                            label={wired ? t("wired") : t("notWired")}
                        />
                    </div>

                    {/* Family summary tiles */}
                    <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-3">
                        {FAMILY_ORDER.map((fam) => {
                            const meta = FAMILY_META[fam];
                            const Icon = meta.icon;
                            const n = summary.families[fam] ?? 0;
                            return (
                                <div
                                    key={fam}
                                    className="v2-card flex items-center gap-2.5 p-3"
                                    style={{ boxShadow: "var(--v2-card-shadow)" }}
                                >
                                    <div
                                        className={`h-8 w-8 rounded-md grid place-items-center border shrink-0 ${meta.iconClass}`}
                                    >
                                        <Icon className="h-4 w-4" />
                                    </div>
                                    <div className="min-w-0">
                                        <p className="text-[10px] text-muted-foreground uppercase tracking-wide truncate" title={t(meta.labelKey)}>
                                            {t(meta.labelKey)}
                                        </p>
                                        <p className="text-lg font-bold tabular-nums leading-tight text-foreground">
                                            {n}
                                        </p>
                                    </div>
                                </div>
                            );
                        })}
                    </div>
                </div>
            )}

            {/* Loading state */}
            {q.isLoading && (
                <div className="v2-card px-5 py-8 text-center text-sm text-muted-foreground">
                    {t("loading")}
                </div>
            )}

            {/* Error state */}
            {q.isError && (
                <div className="v2-card border-destructive/40 px-5 py-4 text-sm text-destructive">
                    {t("catalogueError")}{" "}
                    <code className="font-mono text-xs">/admin/api/arsenal</code>.
                </div>
            )}

            {/* Module groups */}
            <div className="space-y-8">
                {FAMILY_ORDER.map((fam) => {
                    const items = grouped[fam];
                    if (!items?.length) return null;
                    const meta = FAMILY_META[fam];
                    const Icon = meta.icon;
                    return (
                        <section key={fam} className="space-y-4">
                            {/* Group header */}
                            <div className="flex items-center gap-3">
                                <div
                                    className={`h-8 w-8 rounded-md grid place-items-center border shrink-0 ${meta.iconClass}`}
                                >
                                    <Icon className="h-4 w-4" />
                                </div>
                                <div>
                                    <p className="text-sm font-semibold text-foreground leading-tight">
                                        {t(meta.labelKey)}
                                        <span className="ml-2 text-xs text-muted-foreground font-normal">
                                            {t("moduleCount", { count: items.length })}
                                        </span>
                                    </p>
                                    <p className="text-xs text-muted-foreground mt-0.5">{t(meta.blurbKey)}</p>
                                </div>
                            </div>

                            {/* Module cards */}
                            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                                {items.map((m) => (
                                    <ModuleCard key={m.id} m={m} counters={counters} />
                                ))}
                            </div>
                        </section>
                    );
                })}
            </div>
        </div>
    );
}
