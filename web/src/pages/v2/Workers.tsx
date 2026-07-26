// V2 — Workers page.
//
// Presentation-only redesign; all data-fetching is identical to V1.
// Wires: topologyApi, envApi, runtimeInfoApi, restartApi.
// Layout: MetricCard + StatusBadge + SectionHeader from V2 primitives.
// No Card/CardHeader/CardContent from V1 UI — do NOT import those here.

import { useState } from "react";
import { useTranslation } from "react-i18next";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
    Cpu,
    Server,
    Save,
    Layers,
    AlertTriangle,
    RotateCcw,
} from "lucide-react";
import { topologyApi, envApi, runtimeInfoApi, restartApi } from "@/api/client";
import type { WorkerProc } from "@/types/index";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { useToast } from "@/hooks/useToast";
import { MetricCard } from "@/v2/components/MetricCard";
import { SectionHeader } from "@/v2/components/SectionHeader";
import { StatusBadge } from "@/v2/components/StatusBadge";

// ─── helpers ────────────────────────────────────────────────────────

function humanizeUptime(secs: number): string {
    if (!Number.isFinite(secs) || secs < 0) return "—";
    const s = Math.floor(secs);
    if (s < 60) return `${s}s`;
    const m = Math.floor(s / 60);
    if (m < 60) return `${m}m`;
    const h = Math.floor(m / 60);
    if (h < 24) return `${h}h ${m % 60}m`;
    const d = Math.floor(h / 24);
    return `${d}d ${h % 24}h`;
}

// ─── Small stat tile ─────────────────────────────────────────────────

function StatTile({ label, value }: { label: string; value: string }) {
    return (
        <div className="rounded-xl border border-border/50 bg-card px-4 py-3 flex flex-col gap-1">
            <span className="text-[10px] uppercase tracking-widest text-muted-foreground font-medium">
                {label}
            </span>
            <span className="text-base font-semibold tabular-nums text-foreground leading-snug">
                {value}
            </span>
        </div>
    );
}

// ─── Worker process row ───────────────────────────────────────────────

function WorkerRow({ worker }: { worker: WorkerProc }) {
    const barPct = Math.min(100, Math.max(0, worker.cpu_pct_avg));
    const cpuColor =
        barPct > 80 ? "bg-destructive" : barPct > 50 ? "bg-amber-400" : "bg-primary";

    return (
        <tr className="v2-table-row border-b border-border/30 last:border-0">
            <td className="py-2.5 px-3">
                <span className="inline-flex items-center justify-center w-6 h-6 rounded-md border border-border/60 text-[11px] font-mono text-muted-foreground bg-muted/30">
                    {worker.instance}
                </span>
            </td>
            <td className="py-2.5 px-3">
                <code className="text-xs text-foreground/80 font-mono">{worker.pid}</code>
            </td>
            <td className="py-2.5 px-3 v2-table-num text-xs">
                {worker.rss_mb.toLocaleString()} MiB
            </td>
            <td className="py-2.5 px-3 v2-table-num text-xs">{worker.threads}</td>
            <td className="py-2.5 px-3 v2-table-num text-xs">
                {humanizeUptime(worker.uptime_secs)}
            </td>
            <td className="py-2.5 px-3 min-w-[140px]">
                <div className="flex items-center gap-2">
                    <div className="h-1.5 flex-1 rounded-full bg-muted overflow-hidden">
                        <div
                            className={`h-full rounded-full transition-all duration-500 ${cpuColor}`}
                            style={{ width: `${barPct}%` }}
                        />
                    </div>
                    <span className="text-xs tabular-nums w-10 text-right text-foreground/70">
                        {worker.cpu_pct_avg.toFixed(1)}%
                    </span>
                </div>
            </td>
        </tr>
    );
}

// ─── REUSEPORT toggle ─────────────────────────────────────────────────

function ReuseportToggle() {
    const { t } = useTranslation(["workers", "common"]);
    const { toast } = useToast();
    const qc = useQueryClient();
    const [pendingRestart, setPendingRestart] = useState(false);

    const runtimeInfo = useQuery({
        queryKey: ["runtime", "info"],
        queryFn: runtimeInfoApi.get,
        refetchInterval: 15_000,
    });

    const setEnv = useMutation({
        mutationFn: ({ key, value }: { key: string; value: string | null }) =>
            envApi.set(key, value),
        onSuccess: (res) => {
            if (res.restart_required) setPendingRestart(true);
            void qc.invalidateQueries({ queryKey: ["runtime", "info"] });
            toast({
                title: res.restart_required ? t("toast.savedRestart") : t("toast.saved"),
                description: t("toast.savedDesc", {
                    restart: res.restart_required ? t("toast.savedDescRestart") : "",
                }),
            });
        },
        onError: (e: unknown) => {
            toast({ title: t("toast.saveFailed"), description: String(e), variant: "destructive" });
        },
    });

    const restart = useMutation({
        mutationFn: restartApi.run,
        onSuccess: (res) => {
            setPendingRestart(false);
            toast({ title: t("toast.restartTriggered"), description: res.note });
        },
        onError: (e: unknown) => {
            toast({ title: t("toast.restartFailed"), description: String(e), variant: "destructive" });
        },
    });

    const reuseportOn = runtimeInfo.data?.reuseport ?? false;
    const busy = setEnv.isPending || runtimeInfo.isLoading;

    return (
        <MetricCard
            title={t("reuseport.title")}
            description={t("reuseport.desc")}
        >
            <div className="space-y-4">
                <div className="flex items-center gap-4">
                    <Switch
                        id="v2-reuseport-switch"
                        checked={reuseportOn}
                        disabled={busy}
                        onCheckedChange={(on) =>
                            setEnv.mutate({
                                key: "AEGIS_PINGORA_REUSEPORT",
                                value: on ? "1" : "0",
                            })
                        }
                    />
                    <Label htmlFor="v2-reuseport-switch" className="cursor-pointer flex items-center gap-2">
                        <StatusBadge state={reuseportOn ? "active" : "standby"} />
                        <span className="text-xs text-muted-foreground">{t("reuseport.label")}</span>
                    </Label>
                </div>

                {pendingRestart && (
                    <div className="flex items-center gap-3 rounded-xl border border-amber-500/30 bg-amber-500/8 px-4 py-3 text-sm text-amber-300">
                        <AlertTriangle className="h-4 w-4 shrink-0" />
                        <span className="flex-1">
                            {t("reuseport.restartBanner")}
                        </span>
                        <Button
                            size="sm"
                            variant="outline"
                            className="border-amber-500/40 text-amber-300 hover:bg-amber-500/15 text-xs"
                            onClick={() => restart.mutate()}
                            disabled={restart.isPending}
                        >
                            <RotateCcw className="h-3.5 w-3.5 mr-1.5" />
                            {t("apply", { ns: "common" })}
                        </Button>
                    </div>
                )}

                <p className="text-xs text-muted-foreground leading-relaxed">
                    <span className="text-amber-300 font-medium">{t("reuseport.expert")}</span>{" "}
                    {t("reuseport.expertHint")}
                </p>
            </div>
        </MetricCard>
    );
}

// ─── Desired worker count ─────────────────────────────────────────────

function DesiredWorkers({
    current,
    effective,
    onSaved,
    toastFn,
}: {
    current: string;
    effective: number;
    onSaved: () => void;
    toastFn: ReturnType<typeof useToast>["toast"];
}) {
    const { t } = useTranslation(["workers", "common"]);
    const startsAuto = current === "auto";
    const [mode, setMode] = useState<"auto" | "custom">(startsAuto ? "auto" : "custom");
    const [count, setCount] = useState(startsAuto ? String(effective) : current);

    const save = useMutation({
        mutationFn: () => topologyApi.put(mode === "auto" ? "auto" : count.trim()),
        onSuccess: (res) => {
            toastFn({
                title: t("toast.desiredSaved"),
                description: res.restart_required
                    ? t("toast.desiredSavedRestart")
                    : t("toast.desiredSavedApplied"),
            });
            onSaved();
        },
        onError: (e: unknown) => {
            toastFn({ title: t("toast.desiredSaveFailed"), description: String(e), variant: "destructive" });
        },
    });

    const customValid =
        mode === "auto" ||
        (() => {
            const n = Number.parseInt(count.trim(), 10);
            return Number.isInteger(n) && n >= 1;
        })();

    const result = save.data;

    return (
        <MetricCard
            title={t("desired.title")}
            description={t("desired.desc")}
        >
            <div className="space-y-5">
                <div className="flex flex-wrap items-end gap-3">
                    {/* Mode selector */}
                    <div className="space-y-1.5">
                        <Label className="text-xs text-muted-foreground uppercase tracking-wider">
                            {t("desired.mode")}
                        </Label>
                        <div className="flex gap-1 p-1 rounded-lg bg-muted/40 border border-border/40">
                            {(["auto", "custom"] as const).map((m) => (
                                <button
                                    key={m}
                                    onClick={() => setMode(m)}
                                    aria-pressed={mode === m}
                                    className={
                                        mode === m
                                            ? "px-3 py-1.5 rounded-md text-xs font-semibold bg-primary text-primary-foreground transition-colors"
                                            : "px-3 py-1.5 rounded-md text-xs font-medium text-muted-foreground hover:text-foreground transition-colors"
                                    }
                                >
                                    {m === "auto" ? t("desired.modeAuto") : t("desired.modeCustom")}
                                </button>
                            ))}
                        </div>
                    </div>

                    {mode === "custom" && (
                        <div className="space-y-1.5">
                            <Label htmlFor="v2-worker-count" className="text-xs text-muted-foreground uppercase tracking-wider">
                                {t("desired.workers")}
                            </Label>
                            <Input
                                id="v2-worker-count"
                                type="number"
                                min={1}
                                value={count}
                                onChange={(e) => setCount(e.target.value)}
                                placeholder={t("desired.placeholder")}
                                className="w-28 font-mono text-sm"
                            />
                        </div>
                    )}

                    <Button
                        onClick={() => save.mutate()}
                        disabled={!customValid || save.isPending}
                        className="gap-1.5"
                    >
                        <Save className="h-3.5 w-3.5" />
                        {t("save", { ns: "common" })}
                    </Button>
                </div>

                <p className="text-xs text-muted-foreground">
                    {t("desired.configured")}{" "}
                    <code className="bg-muted/60 px-1.5 py-0.5 rounded font-mono text-foreground/80">
                        {current}
                    </code>
                    {" · "}{t("desired.effective")}{" "}
                    <code className="bg-muted/60 px-1.5 py-0.5 rounded font-mono text-foreground/80">
                        {effective}
                    </code>
                </p>

                {result && (
                    <div className="space-y-3">
                        {result.restart_required && (
                            <div className="rounded-xl border border-amber-500/30 bg-amber-500/8 p-3 text-sm text-amber-200">
                                <strong>{t("desired.restartRequired")}</strong>{" "}
                                {t("desired.restartHint")}
                            </div>
                        )}
                        <div>
                            <p className="text-xs text-muted-foreground mb-1.5">{t("desired.applyCommand")}</p>
                            <pre className="rounded-xl border border-border/40 bg-muted/30 p-3 text-xs overflow-x-auto whitespace-pre-wrap select-all font-mono">
                                {result.apply_hint}
                            </pre>
                        </div>
                        <p className="text-xs text-muted-foreground">
                            {t("desired.savedDesired")}{" "}
                            <code className="bg-muted/60 px-1.5 py-0.5 rounded font-mono text-foreground/80">
                                {result.desired.workers}
                            </code>
                            {" · "}{t("desired.resolvesTo")}{" "}
                            <code className="bg-muted/60 px-1.5 py-0.5 rounded font-mono text-foreground/80">
                                {result.desired.effective}
                            </code>{" "}
                            {t("desired.workersOnStart")}
                        </p>
                    </div>
                )}
            </div>
        </MetricCard>
    );
}

// ─── Main page ───────────────────────────────────────────────────────

export function WorkersPage() {
    const { t } = useTranslation(["workers", "common"]);
    const { toast } = useToast();

    const topo = useQuery({
        queryKey: ["topology"],
        queryFn: topologyApi.get,
        refetchInterval: 5_000,
    });

    if (topo.isError) {
        return (
            <div className="space-y-6">
                {/* Page title */}
                <div>
                    <h1 className="text-xl font-bold text-foreground flex items-center gap-2">
                        <Server className="h-5 w-5 text-primary" />
                        {t("title")}
                    </h1>
                    <SectionHeader label={t("subtitle.short")} className="mt-1" />
                </div>
                <MetricCard title={t("error.title")}>
                    <p className="text-sm text-destructive">
                        {t("error.load", { path: "/admin/api/topology", error: String(topo.error) })}
                    </p>
                </MetricCard>
            </div>
        );
    }

    if (!topo.data) {
        return (
            <div className="space-y-6">
                <div>
                    <h1 className="text-xl font-bold text-foreground flex items-center gap-2">
                        <Server className="h-5 w-5 text-primary" />
                        {t("title")}
                    </h1>
                    <SectionHeader label={t("subtitle.short")} className="mt-1" />
                </div>
                <p className="text-sm text-muted-foreground animate-pulse">{t("loading")}</p>
            </div>
        );
    }

    const { host, layout, workers, totals, desired, recommendation } = topo.data;
    const optimal = recommendation.status === "optimal";

    return (
        <div className="space-y-6">
            {/* Page header */}
            <div>
                <h1 className="text-xl font-bold text-foreground flex items-center gap-2">
                    <Server className="h-5 w-5 text-primary" />
                    {t("title")}
                </h1>
                <p className="text-sm text-muted-foreground mt-1">
                    {t("subtitle.long")}
                </p>
            </div>

            {/* ── Host summary ─────────────────────────────────────────── */}
            <MetricCard
                title={t("host.title")}
                action={
                    <span className="flex items-center gap-1.5 text-muted-foreground">
                        <Cpu className="h-3.5 w-3.5" />
                        <span className="text-[11px]">{host.cpu_model}</span>
                    </span>
                }
            >
                <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
                    <StatTile label={t("host.cpuModel")} value={host.cpu_model} />
                    <StatTile label={t("host.cores")} value={host.cpu_count.toString()} />
                    <StatTile
                        label={t("host.loadAvg")}
                        value={host.load_avg.map((n) => n.toFixed(2)).join("  ")}
                    />
                </div>
            </MetricCard>

            {/* ── Runtime layout + recommendation ──────────────────────── */}
            <MetricCard
                title={t("layout.title")}
                description={t("layout.mode", { mode: layout.mode })}
            >
                <div className="space-y-4">
                    <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
                        <StatTile label={t("layout.workersRunning")} value={layout.workers_running.toString()} />
                        <StatTile label={t("layout.threadsPerWorker")} value={layout.threads_per_worker.toString()} />
                        <StatTile label={t("layout.totalThreads")} value={layout.total_runtime_threads.toString()} />
                        <div className="rounded-xl border border-border/50 bg-card px-4 py-3 flex flex-col gap-1">
                            <span className="text-[10px] uppercase tracking-widest text-muted-foreground font-medium">
                                {t("layout.reuseport")}
                            </span>
                            <StatusBadge state={layout.reuseport ? "active" : "standby"} label={layout.reuseport ? t("layout.on") : t("layout.off")} />
                        </div>
                        <StatTile label={t("layout.modeLabel")} value={layout.mode} />
                    </div>

                    {/* Recommendation banner */}
                    <div
                        className={
                            optimal
                                ? "rounded-xl border border-emerald-500/30 bg-emerald-500/5 px-4 py-3 text-sm text-emerald-300"
                                : "rounded-xl border border-amber-500/30 bg-amber-500/8 px-4 py-3 text-sm text-amber-200"
                        }
                    >
                        <div className="flex items-center gap-2 font-semibold mb-1">
                            <Layers className="h-4 w-4" />
                            <span>{t("rec.title")}</span>
                            <StatusBadge
                                state={optimal ? "healthy" : "degraded"}
                                label={optimal ? t("rec.optimal") : t("rec.suboptimal")}
                                className="ml-auto"
                            />
                        </div>
                        <p className="leading-relaxed">{recommendation.message}</p>
                    </div>
                </div>
            </MetricCard>

            {/* ── Per-worker process table ──────────────────────────────── */}
            <MetricCard
                title={t("table.title")}
                description={t("table.desc")}
                noPadding
            >
                {workers.length === 0 ? (
                    <p className="px-5 py-4 text-sm text-muted-foreground">
                        {t("table.empty")}
                    </p>
                ) : (
                    <div className="overflow-x-auto">
                        <table className="w-full text-xs">
                            <thead>
                                <tr className="border-b border-border/50">
                                    {[
                                        { key: "instance", label: t("table.col.instance") },
                                        { key: "pid", label: t("table.col.pid") },
                                        { key: "rss", label: t("table.col.rss") },
                                        { key: "threads", label: t("table.col.threads") },
                                        { key: "uptime", label: t("table.col.uptime") },
                                        { key: "cpu", label: t("table.col.cpu") },
                                    ].map(
                                        (col, i) => (
                                            <th
                                                key={col.key}
                                                className={`px-3 py-2.5 text-[10px] uppercase tracking-widest text-muted-foreground font-medium ${i >= 2 ? "text-right" : "text-left"} ${col.key === "cpu" ? "text-left" : ""}`}
                                            >
                                                {col.label}
                                            </th>
                                        ),
                                    )}
                                </tr>
                            </thead>
                            <tbody>
                                {workers
                                    .slice()
                                    .sort((a, b) => a.instance - b.instance)
                                    .map((w) => (
                                        <WorkerRow key={w.pid} worker={w} />
                                    ))}
                            </tbody>
                            <tfoot className="border-t border-border/50">
                                <tr>
                                    <td
                                        className="px-3 py-2.5 text-xs text-muted-foreground"
                                        colSpan={2}
                                    >
                                        {t("table.totals", { count: workers.length })}
                                    </td>
                                    <td className="px-3 py-2.5 text-right tabular-nums text-xs text-foreground/70">
                                        {totals.rss_mb.toLocaleString()} MiB
                                    </td>
                                    <td className="px-3 py-2.5 text-right tabular-nums text-xs text-foreground/70">
                                        {workers.reduce((s, w) => s + w.threads, 0)}
                                    </td>
                                    <td className="px-3 py-2.5" />
                                    <td className="px-3 py-2.5 tabular-nums text-xs text-foreground/70 flex items-center gap-2">
                                        <div className="h-1.5 flex-1 rounded-full bg-muted overflow-hidden">
                                            <div
                                                className="h-full bg-primary rounded-full"
                                                style={{
                                                    width: `${Math.min(100, totals.cpu_pct_avg)}%`,
                                                }}
                                            />
                                        </div>
                                        {totals.cpu_pct_avg.toFixed(1)}%
                                    </td>
                                </tr>
                            </tfoot>
                        </table>
                    </div>
                )}
            </MetricCard>

            {/* ── SO_REUSEPORT toggle ───────────────────────────────────── */}
            <ReuseportToggle />

            {/* ── Desired-count control ─────────────────────────────────── */}
            <DesiredWorkers
                current={desired.workers}
                effective={desired.effective}
                onSaved={() => topo.refetch()}
                toastFn={toast}
            />
        </div>
    );
}
