/**
 * V2 ML page — /v2/ml
 *
 * Machine-learning feature-flag controls + status, restyled with V2 primitives.
 * All data-fetching, mutations, and business logic are identical to V1 MLPage.
 * Presentation only changes: MetricCard instead of Card, V2 restart banner,
 * V2 typography tokens, StatusBadge for feature state.
 */

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import {
    AlertTriangle,
    Bot,
    Brain,
    RefreshCw,
    RotateCcw,
    Save,
} from "lucide-react";
import { envApi, mlApi, runtimeInfoApi } from "@/api/client";
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
import { Switch } from "@/components/ui/switch";
import { ErrorState } from "@/components/ErrorState";
import { useToast } from "@/hooks/useToast";
import { useRestartRequired } from "@/hooks/useRestartRequired";
import { MetricCard } from "@/v2/components/MetricCard";
import { SectionHeader } from "@/v2/components/SectionHeader";
import { StatusBadge } from "@/v2/components/StatusBadge";

// ─── Restart-required banner ─────────────────────────────────────────────────

function RestartBanner({ onDismiss }: { onDismiss: () => void }) {
    const { t } = useTranslation(["ml", "common"]);
    return (
        <div className="rounded-xl border border-amber-500/30 bg-amber-500/10 px-5 py-4 flex items-start gap-3">
            <AlertTriangle className="h-4 w-4 mt-0.5 shrink-0 text-amber-400" />
            <div className="flex-1 text-sm text-amber-200 leading-snug">
                <strong className="font-semibold">{t("restart.title")}</strong>{" "}
                {t("restart.body", {
                    command: "systemctl restart aegis-pingora.target",
                })}
            </div>
            <Button
                size="sm"
                variant="ghost"
                className="shrink-0 text-amber-300 hover:text-amber-100 hover:bg-amber-500/20 h-7 px-2"
                onClick={onDismiss}
            >
                {t("restart.dismiss")}
            </Button>
        </div>
    );
}

// ─── Feature toggle row ──────────────────────────────────────────────────────

function FeatureToggleRow({
    id,
    checked,
    disabled,
    onCheckedChange,
}: {
    id: string;
    checked: boolean;
    disabled: boolean;
    onCheckedChange: (on: boolean) => void;
}) {
    const { t } = useTranslation(["ml", "common"]);
    return (
        <div className="flex items-center gap-3">
            <Switch
                id={id}
                checked={checked}
                disabled={disabled}
                onCheckedChange={onCheckedChange}
            />
            <Label htmlFor={id} className="cursor-pointer">
                <StatusBadge
                    state={checked ? "active" : "standby"}
                    label={checked ? t("state.enabled") : t("state.disabled")}
                />
            </Label>
        </div>
    );
}

// ─── Page ────────────────────────────────────────────────────────────────────

export function MLPageV2() {
    const { t } = useTranslation(["ml", "common"]);
    const { toast } = useToast();
    const qc = useQueryClient();
    const { restartRequired, setRestartRequired, clearRestartRequired } =
        useRestartRequired();

    // ── Data sources ──────────────────────────────────────────────────
    const mlStatus = useQuery({
        queryKey: ["ml", "status"],
        queryFn: mlApi.status,
        refetchInterval: 15_000,
    });
    const runtimeInfo = useQuery({
        queryKey: ["runtime", "info"],
        queryFn: runtimeInfoApi.get,
        refetchInterval: 15_000,
    });
    const envVars = useQuery({
        queryKey: ["env", "vars"],
        queryFn: envApi.get,
        refetchInterval: 60_000,
    });

    // ── Mutations ─────────────────────────────────────────────────────
    const retrain = useMutation({
        mutationFn: mlApi.retrain,
        onSuccess: (res) => {
            if (res.ok) {
                toast({ title: t("toast.retrainTriggered") });
                void qc.invalidateQueries({ queryKey: ["ml"] });
            } else {
                toast({
                    title: t("toast.notAvailable"),
                    description: res.hint ?? res.error,
                    variant: "destructive",
                });
            }
        },
    });

    const adversarialProbe = useMutation({
        mutationFn: mlApi.adversarial,
        onSuccess: (res) => {
            toast({
                title: res.enabled
                    ? t("toast.adversarialRunning")
                    : t("toast.disabled"),
                description: res.hint,
            });
        },
    });

    const setEnv = useMutation({
        mutationFn: ({ key, value }: { key: string; value: string | null }) =>
            envApi.set(key, value),
        onSuccess: (res) => {
            if (res.restart_required) {
                setRestartRequired(true);
                toast({
                    title: t("toast.savedRestart"),
                    description: t("toast.settingsSavedRestartDesc"),
                });
            } else {
                toast({
                    title: t("toast.saved"),
                    description: t("toast.settingsSavedDesc"),
                });
            }
            void qc.invalidateQueries({ queryKey: ["runtime", "info"] });
            void qc.invalidateQueries({ queryKey: ["ml"] });
        },
        onError: (err: unknown) => {
            toast({
                title: t("toast.saveFailed"),
                description: String(err),
                variant: "destructive",
            });
        },
    });

    // ── Derived state ─────────────────────────────────────────────────
    const s = mlStatus.data;
    const info = runtimeInfo.data;

    const v2On = info?.ml_v2_enabled ?? s?.v2_wired ?? false;
    const v1On = info?.ml_v1_enabled ?? false;
    const adversarialOn =
        info?.ml_adversarial ?? s?.adversarial_loop_env ?? false;

    const currentKind =
        (info?.ml_v2 as { kind?: string } | null)?.kind ??
        s?.v2_kind ??
        "logistic";

    const busy = setEnv.isPending;

    // ── GBM file path local state ─────────────────────────────────────
    const gbmFileStored =
        envVars.data?.vars.find((v) => v.key === "AEGIS_ML_V2_GBM_FILE")
            ?.value ?? null;
    const [gbmFile, setGbmFile] = useState<string>("");
    const gbmFileSynced =
        gbmFile === "" && gbmFileStored !== null ? gbmFileStored : gbmFile;
    const gbmFileDirty = (gbmFileSynced || null) !== (gbmFileStored || null);

    const saveGbmFile = useMutation({
        mutationFn: () =>
            envApi.set("AEGIS_ML_V2_GBM_FILE", gbmFileSynced.trim() || null),
        onSuccess: (res) => {
            if (res.restart_required) {
                setRestartRequired(true);
                toast({
                    title: t("toast.savedRestart"),
                    description: t("toast.gbmSavedRestartDesc"),
                });
            } else {
                toast({
                    title: t("toast.saved"),
                    description: t("toast.gbmSavedDesc"),
                });
            }
            void qc.invalidateQueries({ queryKey: ["env", "vars"] });
        },
        onError: (err: unknown) => {
            toast({
                title: t("toast.saveFailed"),
                description: String(err),
                variant: "destructive",
            });
        },
    });

    return (
        <div className="space-y-6">
            {/* ── Page header ──────────────────────────────────────────── */}
            <div className="flex items-center gap-3">
                <span className="inline-flex items-center justify-center rounded-lg w-9 h-9 bg-primary/10 text-primary">
                    <Brain className="h-5 w-5" />
                </span>
                <div>
                    <h1 className="text-xl font-semibold tracking-tight text-foreground">
                        {t("title")}
                    </h1>
                    <p className="text-xs text-muted-foreground mt-0.5">
                        {t("subtitle")}
                    </p>
                </div>
            </div>

            {/* ── Loading / error states ────────────────────────────────── */}
            {(mlStatus.isLoading || runtimeInfo.isLoading) && (
                <Skeleton className="h-32 rounded-xl" />
            )}
            {mlStatus.error && (
                <ErrorState
                    title={t("loadErrorTitle")}
                    error={mlStatus.error}
                />
            )}

            {/* ── Restart-required banner ───────────────────────────────── */}
            {restartRequired && (
                <RestartBanner onDismiss={clearRestartRequired} />
            )}

            {/* ── Feature-flag controls ─────────────────────────────────── */}
            <SectionHeader label={t("sectionFeatureFlags")} />

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {/* ML V2 scorer */}
                <MetricCard
                    title={t("v2.title")}
                    description={t("v2.description")}
                    action={
                        <span className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground">
                            {t("v2.badge")}
                        </span>
                    }
                >
                    <div className="space-y-4">
                        <FeatureToggleRow
                            id="ml-v2-switch"
                            checked={v2On}
                            disabled={busy}
                            onCheckedChange={(on) =>
                                setEnv.mutate({
                                    key: "AEGIS_ML_V2",
                                    value: on ? "1" : null,
                                })
                            }
                        />

                        {/* Model kind — only visible when V2 is on */}
                        {v2On && (
                            <div className="space-y-1.5">
                                <Label className="text-xs text-muted-foreground">
                                    {t("v2.modelKind")}
                                </Label>
                                <Select
                                    value={currentKind}
                                    disabled={busy}
                                    onValueChange={(kind) =>
                                        setEnv.mutate({
                                            key: "AEGIS_ML_V2_KIND",
                                            value: kind,
                                        })
                                    }
                                >
                                    <SelectTrigger className="w-40 h-8 text-xs">
                                        <SelectValue />
                                    </SelectTrigger>
                                    <SelectContent>
                                        <SelectItem value="logistic">
                                            logistic
                                        </SelectItem>
                                        <SelectItem value="gbm">gbm</SelectItem>
                                    </SelectContent>
                                </Select>
                            </div>
                        )}

                        {/* GBM file path — only visible when V2 on + gbm kind */}
                        {v2On && currentKind === "gbm" && (
                            <div className="space-y-1.5 pt-1">
                                <Label
                                    htmlFor="gbm-file-input"
                                    className="text-xs text-muted-foreground"
                                >
                                    {t("v2.gbmFile")}
                                </Label>
                                <div className="flex items-center gap-2">
                                    <Input
                                        id="gbm-file-input"
                                        value={gbmFileSynced}
                                        onChange={(e) =>
                                            setGbmFile(e.target.value)
                                        }
                                        placeholder={t("v2.gbmPlaceholder")}
                                        className="font-mono text-xs flex-1 h-8"
                                        aria-label={t("v2.gbmAria")}
                                    />
                                    <Button
                                        size="sm"
                                        className="h-8 shrink-0"
                                        disabled={
                                            !gbmFileDirty ||
                                            saveGbmFile.isPending
                                        }
                                        onClick={() => saveGbmFile.mutate()}
                                    >
                                        <Save className="h-3.5 w-3.5 mr-1" />
                                        {t("save", { ns: "common" })}
                                    </Button>
                                </div>
                                {gbmFileDirty && (
                                    <p className="text-xs text-amber-400">
                                        {t("v2.unsaved")}
                                    </p>
                                )}
                                <p className="text-xs text-muted-foreground">
                                    {t("v2.gbmHint")}
                                </p>
                            </div>
                        )}
                    </div>
                </MetricCard>

                {/* ML V1 scorer */}
                <MetricCard
                    title={t("v1.title")}
                    description={t("v1.description")}
                    action={
                        <span className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground">
                            {t("v1.badge")}
                        </span>
                    }
                >
                    <FeatureToggleRow
                        id="ml-v1-switch"
                        checked={v1On}
                        disabled={busy}
                        onCheckedChange={(on) =>
                            setEnv.mutate({
                                key: "AEGIS_ML_SCORER",
                                value: on ? "1" : null,
                            })
                        }
                    />
                </MetricCard>

                {/* Adversarial loop */}
                <MetricCard
                    title={t("adversarial.title")}
                    description={t("adversarial.description")}
                    action={
                        <span className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground">
                            {t("adversarial.badge")}
                        </span>
                    }
                >
                    <FeatureToggleRow
                        id="ml-adversarial-switch"
                        checked={adversarialOn}
                        disabled={busy}
                        onCheckedChange={(on) =>
                            setEnv.mutate({
                                key: "AEGIS_ML_ADVERSARIAL",
                                value: on ? "1" : null,
                            })
                        }
                    />
                </MetricCard>

                {/* Actions / probes */}
                <MetricCard
                    title={t("actions.title")}
                    description={t("actions.description")}
                >
                    <div className="flex flex-col gap-2">
                        <Button
                            size="sm"
                            variant="outline"
                            onClick={() => retrain.mutate()}
                            disabled={retrain.isPending}
                            className="justify-start gap-2"
                        >
                            <RefreshCw className="h-3.5 w-3.5" />
                            {t("actions.retrain")}
                        </Button>
                        <Button
                            size="sm"
                            variant="outline"
                            onClick={() => adversarialProbe.mutate()}
                            disabled={adversarialProbe.isPending}
                            className="justify-start gap-2"
                        >
                            <Bot className="h-3.5 w-3.5" />
                            {t("actions.probe")}
                        </Button>
                    </div>
                </MetricCard>
            </div>

            {/* ── Notes ────────────────────────────────────────────────── */}
            <MetricCard
                title={t("notes.title")}
                action={
                    <RotateCcw className="h-3.5 w-3.5 text-muted-foreground" />
                }
            >
                <div className="space-y-2">
                    {s?.note && (
                        <p className="text-sm text-muted-foreground">
                            {s.note}
                        </p>
                    )}
                    <p className="text-xs text-muted-foreground leading-relaxed">
                        {t("notes.body")}
                    </p>
                </div>
            </MetricCard>
        </div>
    );
}
