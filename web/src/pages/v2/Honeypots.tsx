import { useState } from "react";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
    Trash2,
    Plus,
    FlaskConical,
    AlertTriangle,
    ShieldCheck,
    Layers,
    Route,
    Timer,
} from "lucide-react";
import { honeypotApi, envApi, runtimeInfoApi } from "@/api/client";
import type { HoneypotState } from "@/api/client";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { useToast } from "@/hooks/useToast";
import { useRestartRequired } from "@/hooks/useRestartRequired";
import { Select, SelectTrigger, SelectValue, SelectContent, SelectItem } from "@/components/ui/select";
import { MetricCard } from "@/v2/components/MetricCard";
import { KPITile } from "@/v2/components/KPITile";
import { StatusBadge } from "@/v2/components/StatusBadge";
import { SectionHeader } from "@/v2/components/SectionHeader";
import { cn } from "@/lib/cn";

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export function HoneypotsPage() {
    const { t } = useTranslation(["honeypots", "common"]);
    const { toast } = useToast();
    const qc = useQueryClient();
    const { restartRequired, setRestartRequired, clearRestartRequired } =
        useRestartRequired();

    const runtimeInfo = useQuery({
        queryKey: ["runtime", "info"],
        queryFn: runtimeInfoApi.get,
        refetchInterval: 15_000,
    });

    const setEnv = useMutation({
        mutationFn: ({ key, value }: { key: string; value: string | null }) =>
            envApi.set(key, value),
        onSuccess: () => {
            setRestartRequired(true);
            void qc.invalidateQueries({ queryKey: ["runtime", "info"] });
            toast({
                title: t("toast.saved.title"),
                description: t("toast.saved.desc"),
            });
        },
        onError: (err: unknown) => {
            toast({ title: t("toast.saveFailed.title"), description: String(err), variant: "destructive" });
        },
    });

    const llmHoneypotOn = runtimeInfo.data?.llm_honeypot ?? false;

    const packsQuery = useQuery({
        queryKey: ["honeypots", "builtin"],
        queryFn: honeypotApi.builtin,
    });
    const stateQuery = useQuery({
        queryKey: ["honeypots", "state"],
        queryFn: honeypotApi.get,
        refetchInterval: 5_000,
    });

    const toggleGlobal = useMutation({
        mutationFn: (args: { pack_id: string; enabled: boolean }) =>
            honeypotApi.toggleGlobal(args.pack_id, args.enabled),
        onSuccess: () => {
            void qc.invalidateQueries({ queryKey: ["honeypots", "state"] });
            toast({ title: t("toast.packToggled"), variant: "success" });
        },
        onError: (e: unknown) =>
            toast({ title: t("toast.saveFailed"), description: String(e), variant: "destructive" }),
    });

    const toggleHost = useMutation({
        mutationFn: (args: { host: string; pack_id: string; enabled: boolean }) =>
            honeypotApi.toggleHost(args.host, args.pack_id, args.enabled),
        onSuccess: () => void qc.invalidateQueries({ queryKey: ["honeypots", "state"] }),
    });

    const clearHost = useMutation({
        mutationFn: (host: string) => honeypotApi.clearHost(host),
        onSuccess: () => {
            void qc.invalidateQueries({ queryKey: ["honeypots", "state"] });
            toast({ title: t("toast.overrideRemoved"), variant: "success" });
        },
    });

    const setHostEnabled = useMutation({
        mutationFn: ({ host, enabled }: { host: string; enabled: boolean }) =>
            honeypotApi.setHostEnabled(host, enabled),
        onSuccess: (_data, vars) => {
            void qc.invalidateQueries({ queryKey: ["honeypots", "state"] });
            toast({
                title: vars.enabled
                    ? t("toast.bypassRemoved")
                    : t("toast.bypassAdded"),
                variant: "success",
            });
        },
        onError: (e: unknown) =>
            toast({ title: t("toast.saveFailed"), description: String(e), variant: "destructive" }),
    });

    const saveState = useMutation({
        mutationFn: (s: HoneypotState) => honeypotApi.save(s),
        onSuccess: () => {
            void qc.invalidateQueries({ queryKey: ["honeypots", "state"] });
            toast({ title: t("toast.savedShort"), variant: "success" });
        },
    });

    // Loading skeleton
    if (!packsQuery.data || !stateQuery.data) {
        return (
            <div className="space-y-6">
                {/* Page heading */}
                <div>
                    <h1 className="text-2xl font-bold text-foreground flex items-center gap-2.5">
                        <FlaskConical className="h-6 w-6 text-primary" />
                        {t("title")}
                    </h1>
                    <p className="v2-section-label mt-1">{t("loading")}</p>
                </div>
            </div>
        );
    }

    const packs = packsQuery.data;
    const state = stateQuery.data;
    const enabledCount = packs.filter((p) => state.packs[p.id] !== false).length;
    const totalPaths = packs.reduce(
        (sum, p) => (state.packs[p.id] !== false ? sum + p.path_count : sum),
        0,
    );

    return (
        <div className="space-y-6">
            {/* ── Page header ────────────────────────────────────────────── */}
            <div>
                <h1 className="text-2xl font-bold text-foreground flex items-center gap-2.5">
                    <FlaskConical className="h-6 w-6 text-primary" />
                    {t("title")}
                </h1>
                <p className="text-sm text-muted-foreground mt-1 max-w-2xl">
                    {t("intro")}
                </p>
            </div>

            {/* ── Restart-required banner ─────────────────────────────────── */}
            {restartRequired && (
                <div className="rounded-xl border border-amber-500/40 bg-amber-500/10 p-4 flex items-start gap-3 text-sm text-amber-200">
                    <AlertTriangle className="h-4 w-4 mt-0.5 shrink-0 text-amber-400" />
                    <div className="flex-1">
                        <strong>{t("restart.title")}</strong> {t("restart.body")}{" "}
                        <code className="font-mono text-xs">
                            systemctl restart aegis-pingora.target
                        </code>{" "}
                        {t("restart.suffix")}
                    </div>
                    <Button
                        size="sm"
                        variant="ghost"
                        className="shrink-0 text-amber-200 hover:text-amber-100"
                        onClick={clearRestartRequired}
                    >
                        {t("restart.dismiss")}
                    </Button>
                </div>
            )}

            {/* ── KPI row ────────────────────────────────────────────────── */}
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
                <KPITile
                    label={t("kpi.masterSwitch")}
                    value={state.enabled ? t("kpi.on") : t("kpi.off")}
                    valueColor={state.enabled ? "text-green-400" : "text-amber-400"}
                    icon={<ShieldCheck className="h-4 w-4" />}
                />
                <KPITile
                    label={t("kpi.packsEnabled")}
                    value={`${enabledCount} / ${packs.length}`}
                    icon={<Layers className="h-4 w-4" />}
                />
                <KPITile
                    label={t("kpi.activePaths")}
                    value={totalPaths.toLocaleString()}
                    icon={<Route className="h-4 w-4" />}
                />
                <KPITile
                    label={t("kpi.tarpitDuration")}
                    value={`${state.tarpit_seconds}s`}
                    icon={<Timer className="h-4 w-4" />}
                />
            </div>

            {/* ── LLM honeypot ────────────────────────────────────────────── */}
            <MetricCard
                title={t("llm.title")}
                description={t("llm.description")}
                action={
                    <span className="text-[10px] uppercase tracking-wide text-muted-foreground">
                        {t("llm.tag")}
                    </span>
                }
            >
                <div className="flex items-center gap-3">
                    <Switch
                        id="llm-honeypot-switch"
                        checked={llmHoneypotOn}
                        disabled={setEnv.isPending}
                        onCheckedChange={(on) =>
                            setEnv.mutate({ key: "AEGIS_LLM_HONEYPOT", value: on ? "1" : null })
                        }
                    />
                    <Label htmlFor="llm-honeypot-switch" className="cursor-pointer">
                        <StatusBadge
                            state={llmHoneypotOn ? "active" : "standby"}
                            label={llmHoneypotOn ? t("llm.enabled") : t("llm.disabled")}
                        />
                    </Label>
                </div>
                <p className="text-xs text-muted-foreground mt-3">
                    {t("llm.note")}
                </p>
            </MetricCard>

            {/* ── Tarpit settings ─────────────────────────────────────────── */}
            <MetricCard
                title={t("tarpit.title")}
                description={t("tarpit.description")}
            >
                <SettingsForm
                    state={state}
                    onSave={(s) => saveState.mutate(s)}
                    saving={saveState.isPending}
                    t={t}
                />
            </MetricCard>

            {/* ── Built-in packs ──────────────────────────────────────────── */}
            <MetricCard
                title={t("packs.title", { count: packs.length })}
                description={t("packs.description")}
            >
                <div className="grid gap-2 grid-cols-1 lg:grid-cols-2">
                    {packs.map((p) => {
                        const enabled = state.packs[p.id] !== false;
                        return (
                            <div
                                key={p.id}
                                className={cn(
                                    "flex items-start gap-3 rounded-lg border p-3 transition-colors",
                                    enabled
                                        ? "border-primary/20 bg-primary/5"
                                        : "border-border/40 bg-muted/10",
                                )}
                            >
                                <Switch
                                    checked={enabled}
                                    onCheckedChange={(v) =>
                                        toggleGlobal.mutate({ pack_id: p.id, enabled: v })
                                    }
                                />
                                <div className="min-w-0 flex-1">
                                    <div className="flex items-center gap-2 flex-wrap">
                                        <span className="text-sm font-medium text-foreground">
                                            {p.name}
                                        </span>
                                        <code className="text-[10px] font-mono text-muted-foreground bg-muted/30 px-1.5 py-0.5 rounded">
                                            {p.id}
                                        </code>
                                        <span className="text-[10px] text-muted-foreground tabular-nums">
                                            {t("packs.paths", { count: p.path_count })}
                                        </span>
                                    </div>
                                    <p className="text-xs text-muted-foreground mt-1">
                                        {p.description}
                                    </p>
                                </div>
                            </div>
                        );
                    })}
                </div>
            </MetricCard>

            {/* ── Per-host overrides ──────────────────────────────────────── */}
            <MetricCard
                title={t("perHost.title")}
                description={t("perHost.description")}
            >
                <div className="space-y-3">
                    {Object.entries(state.per_host).length === 0 ? (
                        <p className="text-sm text-muted-foreground">
                            {t("perHost.empty")}
                        </p>
                    ) : (
                        Object.entries(state.per_host).map(([host, overrides]) => (
                            <div
                                key={host}
                                className="rounded-lg border border-border/40 bg-muted/10 p-3"
                            >
                                <div className="flex items-center justify-between">
                                    <span className="font-mono text-sm text-foreground">
                                        {host}
                                    </span>
                                    <Button
                                        variant="ghost"
                                        size="sm"
                                        onClick={() => clearHost.mutate(host)}
                                        title={t("perHost.removeAll")}
                                        className="text-muted-foreground hover:text-destructive"
                                    >
                                        <Trash2 className="h-4 w-4" />
                                    </Button>
                                </div>
                                <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 mt-2">
                                    {packs.map((p) => {
                                        const isOverridden = p.id in overrides;
                                        const enabled = isOverridden
                                            ? overrides[p.id]
                                            : state.packs[p.id] !== false;
                                        return (
                                            <label
                                                key={p.id}
                                                className="flex items-center gap-2 text-xs cursor-pointer"
                                            >
                                                <Switch
                                                    checked={enabled}
                                                    onCheckedChange={(v) =>
                                                        toggleHost.mutate({
                                                            host,
                                                            pack_id: p.id,
                                                            enabled: v,
                                                        })
                                                    }
                                                />
                                                <span
                                                    className={
                                                        isOverridden
                                                            ? "font-medium text-foreground"
                                                            : "text-muted-foreground"
                                                    }
                                                >
                                                    {p.name}
                                                </span>
                                            </label>
                                        );
                                    })}
                                </div>
                            </div>
                        ))
                    )}
                    <AddHostOverride
                        onAdd={(host, pack_id, enabled) =>
                            toggleHost.mutate({ host, pack_id, enabled })
                        }
                        packs={packs}
                        t={t}
                    />
                </div>
            </MetricCard>

            {/* ── Trusted operator sites ──────────────────────────────────── */}
            <MetricCard
                title={t("trusted.title")}
                description={
                    <>
                        {t("trusted.descPrefix")}{" "}
                        <code className="font-mono text-[10px]">/wp-admin/install.php</code>
                        {t("trusted.descSuffix")}
                    </>
                }
            >
                <TrustedHostsEditor
                    disabled={state.host_disabled ?? []}
                    pending={setHostEnabled.isPending}
                    onAdd={(host) => setHostEnabled.mutate({ host, enabled: false })}
                    onRemove={(host) => setHostEnabled.mutate({ host, enabled: true })}
                    t={t}
                />
            </MetricCard>

            {/* ── Custom probe paths ─────────────────────────────────────── */}
            <MetricCard
                title={t("custom.title")}
                description={
                    <>
                        {t("custom.descPrefix")}{" "}
                        <code className="font-mono mx-1">/exact</code>,
                        <code className="font-mono mx-1">/prefix/*</code>,
                        <code className="font-mono mx-1">*/suffix</code>.
                    </>
                }
            >
                <CustomPathsEditor
                    state={state}
                    onSave={(s) => saveState.mutate(s)}
                    t={t}
                />
            </MetricCard>
        </div>
    );
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

function SettingsForm({
    state,
    onSave,
    saving,
    t,
}: {
    state: HoneypotState;
    onSave: (s: HoneypotState) => void;
    saving: boolean;
    t: TFunction;
}) {
    const [draft, setDraft] = useState(state);
    const dirty = JSON.stringify(draft) !== JSON.stringify(state);

    return (
        <div className="space-y-4">
            <div className="flex items-center gap-3">
                <Switch
                    id="honeypot-master"
                    checked={draft.enabled}
                    onCheckedChange={(v) => setDraft({ ...draft, enabled: v })}
                />
                <Label htmlFor="honeypot-master" className="cursor-pointer text-sm">
                    {t("tarpit.master")}
                </Label>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-1.5">
                    <Label htmlFor="tarpit-secs" className="text-xs text-muted-foreground uppercase tracking-wide">
                        {t("tarpit.duration")}
                    </Label>
                    <Input
                        id="tarpit-secs"
                        type="number"
                        min={0}
                        max={600}
                        value={draft.tarpit_seconds}
                        onChange={(e) =>
                            setDraft({ ...draft, tarpit_seconds: parseInt(e.target.value, 10) || 0 })
                        }
                    />
                </div>
                <div className="space-y-1.5">
                    <Label htmlFor="chunk" className="text-xs text-muted-foreground uppercase tracking-wide">
                        {t("tarpit.chunkBytes")}
                    </Label>
                    <Input
                        id="chunk"
                        type="number"
                        min={1}
                        max={4096}
                        value={draft.tarpit_chunk_bytes}
                        onChange={(e) =>
                            setDraft({
                                ...draft,
                                tarpit_chunk_bytes: parseInt(e.target.value, 10) || 1,
                            })
                        }
                    />
                </div>
                <div className="space-y-1.5">
                    <Label htmlFor="score" className="text-xs text-muted-foreground uppercase tracking-wide">
                        {t("tarpit.scoreBump")}
                    </Label>
                    <Input
                        id="score"
                        type="number"
                        min={0}
                        max={1000}
                        value={draft.score_bump}
                        onChange={(e) =>
                            setDraft({ ...draft, score_bump: parseInt(e.target.value, 10) || 0 })
                        }
                    />
                </div>
                <div className="space-y-1.5">
                    <Label htmlFor="threshold" className="text-xs text-muted-foreground uppercase tracking-wide">
                        {t("tarpit.denyThreshold")}
                    </Label>
                    <Input
                        id="threshold"
                        type="number"
                        min={0}
                        max={100}
                        value={draft.auto_xdp_deny_threshold}
                        onChange={(e) =>
                            setDraft({
                                ...draft,
                                auto_xdp_deny_threshold: parseInt(e.target.value, 10) || 0,
                            })
                        }
                    />
                </div>
                <div className="md:col-span-2 space-y-1.5">
                    <Label htmlFor="banner" className="text-xs text-muted-foreground uppercase tracking-wide">
                        {t("tarpit.serverHeader")}
                    </Label>
                    <Input
                        id="banner"
                        value={draft.server_header}
                        onChange={(e) => setDraft({ ...draft, server_header: e.target.value })}
                    />
                </div>
            </div>
            <Button size="sm" disabled={!dirty || saving} onClick={() => onSave(draft)}>
                {saving ? t("saving") : dirty ? t("tarpit.save") : t("tarpit.noChanges")}
            </Button>
        </div>
    );
}

function AddHostOverride({
    onAdd,
    packs,
    t,
}: {
    onAdd: (host: string, pack_id: string, enabled: boolean) => void;
    packs: { id: string; name: string }[];
    t: TFunction;
}) {
    const [host, setHost] = useState("");
    const [packId, setPackId] = useState(packs[0]?.id ?? "");

    return (
        <div className="flex flex-wrap items-end gap-2 pt-3 border-t border-border/40 mt-2">
            <div className="flex-1 min-w-[200px] space-y-1.5">
                <Label htmlFor="new-host" className="text-xs text-muted-foreground uppercase tracking-wide">
                    {t("perHost.host")}
                </Label>
                <Input
                    id="new-host"
                    placeholder={t("perHost.hostPlaceholder")}
                    value={host}
                    onChange={(e) => setHost(e.target.value)}
                />
            </div>
            <div className="space-y-1.5">
                <Label htmlFor="new-pack" className="text-xs text-muted-foreground uppercase tracking-wide">
                    {t("perHost.pack")}
                </Label>
                <Select value={packId} onValueChange={setPackId}>
                    <SelectTrigger id="new-pack" className="min-w-[140px]">
                        <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                        {packs.map((p) => (
                            <SelectItem key={p.id} value={p.id}>
                                {p.name}
                            </SelectItem>
                        ))}
                    </SelectContent>
                </Select>
            </div>
            <Button
                size="sm"
                onClick={() => {
                    if (!host.trim()) return;
                    onAdd(host.trim(), packId, false);
                    setHost("");
                }}
                disabled={!host.trim()}
            >
                <Plus className="h-4 w-4 mr-1" />
                {t("perHost.disableForHost")}
            </Button>
        </div>
    );
}

function TrustedHostsEditor({
    disabled,
    pending,
    onAdd,
    onRemove,
    t,
}: {
    disabled: string[];
    pending: boolean;
    onAdd: (host: string) => void;
    onRemove: (host: string) => void;
    t: TFunction;
}) {
    const [draft, setDraft] = useState("");

    return (
        <div className="space-y-3">
            {disabled.length === 0 ? (
                <p className="text-sm text-muted-foreground">
                    {t("trusted.empty")}
                </p>
            ) : (
                <ul className="space-y-1.5">
                    {disabled.map((host) => (
                        <li
                            key={host}
                            className="flex items-center justify-between rounded-lg border border-border/40 bg-muted/10 px-3 py-2"
                        >
                            <span className="font-mono text-sm text-foreground">{host}</span>
                            <Button
                                variant="ghost"
                                size="sm"
                                disabled={pending}
                                onClick={() => onRemove(host)}
                                title={t("trusted.reEnable")}
                                className="text-muted-foreground hover:text-destructive"
                            >
                                <Trash2 className="h-4 w-4" />
                            </Button>
                        </li>
                    ))}
                </ul>
            )}
            <div className="flex flex-wrap items-end gap-2 pt-3 border-t border-border/40">
                <div className="flex-1 min-w-[220px] space-y-1.5">
                    <Label htmlFor="trusted-host-input" className="text-xs text-muted-foreground uppercase tracking-wide">
                        {t("trusted.add")}
                    </Label>
                    <Input
                        id="trusted-host-input"
                        placeholder={t("trusted.addPlaceholder")}
                        value={draft}
                        onChange={(e) => setDraft(e.target.value)}
                        onKeyDown={(e) => {
                            if (e.key === "Enter" && draft.trim()) {
                                onAdd(draft.trim());
                                setDraft("");
                            }
                        }}
                    />
                </div>
                <Button
                    size="sm"
                    disabled={!draft.trim() || pending}
                    onClick={() => {
                        if (!draft.trim()) return;
                        onAdd(draft.trim());
                        setDraft("");
                    }}
                >
                    <Plus className="h-4 w-4 mr-1" />
                    {t("common:save")}
                </Button>
            </div>
        </div>
    );
}

function CustomPathsEditor({
    state,
    onSave,
    t,
}: {
    state: HoneypotState;
    onSave: (s: HoneypotState) => void;
    t: TFunction;
}) {
    const [draft, setDraft] = useState(state.custom_paths.join("\n"));
    const dirty = draft !== state.custom_paths.join("\n");

    return (
        <div className="space-y-3">
            <SectionHeader label={t("custom.onePerLine")} className="text-[10px]" />
            <textarea
                className={cn(
                    "w-full min-h-[120px] font-mono text-xs rounded-lg",
                    "border border-border/50 bg-background/60 p-3",
                    "focus:outline-none focus:ring-1 focus:ring-primary/50",
                    "placeholder:text-muted-foreground/50 resize-y",
                )}
                value={draft}
                onChange={(e) => setDraft(e.target.value)}
                placeholder={"/admin-secret\n/internal/*\n*/.env.backup"}
                aria-label={t("custom.ariaLabel")}
            />
            <Button
                size="sm"
                disabled={!dirty}
                onClick={() => {
                    const lines = draft
                        .split("\n")
                        .map((s) => s.trim())
                        .filter(Boolean);
                    onSave({ ...state, custom_paths: lines });
                }}
            >
                {dirty ? t("custom.save") : t("custom.noChanges")}
            </Button>
        </div>
    );
}
