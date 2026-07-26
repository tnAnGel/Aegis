/**
 * V2 Telemetry page — /v2/telemetry
 *
 * Mirrors all env-var controls and live-status panels from V1 Telemetry.tsx,
 * restyled with V2 MetricCard chrome, V2 StatusBadge pills, and dark-palette
 * form elements. All react-query hooks and mutations are identical to V1.
 */

import * as React from "react";
import { useTranslation } from "react-i18next";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
    AlertTriangle,
    Eye,
    EyeOff,
    FileText,
    Radio,
    RotateCcw,
    Shield,
} from "lucide-react";
import { telemetryApi, captchaApi, envApi, restartApi, runtimeInfoApi } from "@/api/client";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import {
    Select,
    SelectContent,
    SelectItem,
    SelectTrigger,
    SelectValue,
} from "@/components/ui/select";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState } from "@/components/ErrorState";
import { useToast } from "@/hooks/useToast";
import { useRestartRequired } from "@/hooks/useRestartRequired";
import { MetricCard } from "@/v2/components/MetricCard";
import { SectionHeader } from "@/v2/components/SectionHeader";
import { StatusBadge } from "@/v2/components/StatusBadge";
import type { EnvVarEntry } from "@/types";

// ─── Restart banner ───────────────────────────────────────────────────────────

function RestartBanner({
    onRestart,
    isPending,
    onDismiss,
}: {
    onRestart: () => void;
    isPending: boolean;
    onDismiss: () => void;
}) {
    const { t } = useTranslation(["telemetry", "common"]);
    return (
        <div className="rounded-xl border border-amber-500/40 bg-amber-500/10 px-5 py-4 flex items-start gap-3 text-sm text-amber-200">
            <AlertTriangle className="h-4 w-4 mt-0.5 shrink-0 text-amber-400" />
            <div className="flex-1 leading-snug">
                <strong className="text-amber-300">{t("restart.title")}</strong>{" "}
                {t("restart.body")}
            </div>
            <div className="flex items-center gap-2 shrink-0">
                <Button
                    size="sm"
                    variant="outline"
                    className="border-amber-500/50 text-amber-300 hover:bg-amber-500/20 h-8 text-xs"
                    onClick={onRestart}
                    disabled={isPending}
                >
                    <RotateCcw className="h-3.5 w-3.5 mr-1.5" />
                    {t("restart.apply")}
                </Button>
                <Button
                    size="sm"
                    variant="ghost"
                    className="text-amber-200 hover:text-amber-100 h-8 text-xs"
                    onClick={onDismiss}
                >
                    {t("restart.dismiss")}
                </Button>
            </div>
        </div>
    );
}

// ─── Configured badge (V2 styled) ─────────────────────────────────────────────

function ConfiguredBadge({ configured }: { configured: boolean }) {
    const { t } = useTranslation("telemetry");
    return configured ? (
        <StatusBadge state="active" label={t("configured")} className="text-[10px]" />
    ) : (
        <span className="inline-flex items-center rounded-full px-2 py-0.5 text-[10px] font-medium border border-border/50 text-muted-foreground bg-muted/30">
            {t("notSet")}
        </span>
    );
}

// ─── Addr control (host:port text input) ─────────────────────────────────────

function AddrControl({
    envKey,
    label,
    hint,
    description,
    placeholder,
    entry,
    onSaved,
}: {
    envKey: string;
    label: string;
    hint: string;
    description: string;
    placeholder: string;
    entry: EnvVarEntry | null | undefined;
    onSaved: () => void;
}) {
    const { t } = useTranslation("telemetry");
    const { toast } = useToast();
    const [draft, setDraft] = React.useState<string | null>(null);

    const current = entry?.value ?? "";
    const editValue = draft ?? current;

    const save = useMutation({
        mutationFn: () => envApi.set(envKey, editValue || null),
        onSuccess: (res) => {
            setDraft(null);
            toast({
                title: t("saved.title", { name: label }),
                description: res.restart_required
                    ? t("saved.restartRequired")
                    : t("saved.applied"),
                variant: "success",
            });
            onSaved();
        },
        onError: (e: unknown) => {
            toast({ title: t("saveFailed.title"), description: String(e), variant: "destructive" });
        },
    });

    const dirty = draft !== null && draft !== current;

    return (
        <div className="space-y-2">
            <Label className="text-xs text-muted-foreground">
                {label}{" "}
                <span className="text-[10px] text-muted-foreground/70">{hint}</span>
            </Label>
            <p className="text-[11px] text-muted-foreground/70 leading-snug">{description}</p>
            <div className="flex items-center gap-2 flex-wrap">
                <Input
                    className="h-8 text-xs font-mono max-w-56 bg-background/50"
                    placeholder={placeholder}
                    value={editValue}
                    onChange={(e) => setDraft(e.target.value)}
                />
                {dirty ? (
                    <>
                        <Button
                            size="sm"
                            variant="outline"
                            className="h-8 text-xs"
                            onClick={() => save.mutate()}
                            disabled={save.isPending}
                        >
                            {t("save")}
                        </Button>
                        <Button
                            size="sm"
                            variant="ghost"
                            className="h-8 text-xs"
                            onClick={() => setDraft(null)}
                        >
                            {t("cancel")}
                        </Button>
                    </>
                ) : (
                    <ConfiguredBadge configured={!!entry?.configured} />
                )}
            </div>
        </div>
    );
}

// ─── Secret write-only control ─────────────────────────────────────────────────

function SecretControl({
    envKey,
    label,
    hint,
    description,
    entry,
    onSaved,
}: {
    envKey: string;
    label: string;
    hint: string;
    description: string;
    entry: EnvVarEntry | null | undefined;
    onSaved: () => void;
}) {
    const { t } = useTranslation("telemetry");
    const { toast } = useToast();
    const [value, setValue] = React.useState("");
    const [show, setShow] = React.useState(false);

    const save = useMutation({
        mutationFn: () => envApi.set(envKey, value || null),
        onSuccess: (res) => {
            setValue("");
            toast({
                title: t("saved.title", { name: label }),
                description: res.restart_required
                    ? t("saved.restartRequired")
                    : t("saved.applied"),
                variant: "success",
            });
            onSaved();
        },
        onError: (e: unknown) => {
            toast({ title: t("saveFailed.title"), description: String(e), variant: "destructive" });
        },
    });

    return (
        <div className="space-y-2">
            <Label className="text-xs text-muted-foreground">
                {label}{" "}
                <span className="text-[10px] text-muted-foreground/70">{hint}</span>
            </Label>
            <p className="text-[11px] text-muted-foreground/70 leading-snug">{description}</p>
            <div className="flex items-center gap-2">
                <ConfiguredBadge configured={!!entry?.configured} />
            </div>
            <div className="flex items-center gap-2 mt-1">
                <div className="relative max-w-56 flex-1">
                    <Input
                        type={show ? "text" : "password"}
                        className="h-8 text-xs font-mono pr-8 bg-background/50"
                        placeholder={
                            entry?.configured
                                ? t("secret.placeholderReplace")
                                : t("secret.placeholderNew")
                        }
                        value={value}
                        onChange={(e) => setValue(e.target.value)}
                        autoComplete="new-password"
                    />
                    <button
                        type="button"
                        className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                        onClick={() => setShow((s) => !s)}
                        aria-label={show ? t("secret.hide") : t("secret.show")}
                    >
                        {show ? <EyeOff className="h-3 w-3" /> : <Eye className="h-3 w-3" />}
                    </button>
                </div>
                <Button
                    size="sm"
                    variant="outline"
                    className="h-8 text-xs"
                    onClick={() => save.mutate()}
                    disabled={save.isPending || !value}
                >
                    {t("save")}
                </Button>
            </div>
        </div>
    );
}

// ─── Status row helper ────────────────────────────────────────────────────────

function StatusRow({ label, children }: { label: string; children: React.ReactNode }) {
    return (
        <div className="flex items-center justify-between text-sm py-1.5 border-b border-border/30 last:border-0">
            <span className="text-muted-foreground text-xs">{label}</span>
            <span className="text-right">{children}</span>
        </div>
    );
}

// ─── Inline value badge ───────────────────────────────────────────────────────

function ValueBadge({
    value,
    active,
}: {
    value: string | null | undefined;
    active?: boolean;
}) {
    return (
        <span
            className={`inline-flex items-center rounded px-2 py-0.5 text-[11px] font-medium border ${
                active
                    ? "text-emerald-300 border-emerald-500/40 bg-emerald-500/10"
                    : "text-muted-foreground border-border/50 bg-muted/30"
            }`}
        >
            {value ?? "—"}
        </span>
    );
}

// ─── Main page ────────────────────────────────────────────────────────────────

export function TelemetryV2Page() {
    const { t } = useTranslation(["telemetry", "common"]);
    const { toast } = useToast();
    const qc = useQueryClient();
    const { restartRequired, setRestartRequired, clearRestartRequired } = useRestartRequired();

    const tel = useQuery({
        queryKey: ["telemetry"],
        queryFn: telemetryApi.status,
        refetchInterval: 30_000,
    });
    const capt = useQuery({
        queryKey: ["captcha"],
        queryFn: captchaApi.status,
        refetchInterval: 30_000,
    });
    const runtimeInfo = useQuery({
        queryKey: ["runtime", "info"],
        queryFn: runtimeInfoApi.get,
        refetchInterval: 15_000,
    });
    const envVars = useQuery({
        queryKey: ["env", "vars"],
        queryFn: envApi.get,
        refetchInterval: 30_000,
    });

    function envEntry(key: string): EnvVarEntry | null | undefined {
        return envVars.data?.vars.find((v) => v.key === key);
    }

    const restart = useMutation({
        mutationFn: restartApi.run,
        onSuccess: (res) => {
            clearRestartRequired();
            toast({ title: t("restart.triggered.title"), description: res.note });
        },
        onError: (e: unknown) => {
            toast({ title: t("restart.failed.title"), description: String(e), variant: "destructive" });
        },
    });

    const setEnv = useMutation({
        mutationFn: ({ key, value }: { key: string; value: string | null }) =>
            envApi.set(key, value),
        onSuccess: (res) => {
            if (res.restart_required) setRestartRequired(true);
            toast({
                title: res.restart_required ? t("setEnv.savedRestart") : t("setEnv.saved"),
                description: t("setEnv.description"),
                variant: "success",
            });
            void qc.invalidateQueries({ queryKey: ["runtime", "info"] });
            void qc.invalidateQueries({ queryKey: ["env", "vars"] });
            void qc.invalidateQueries({ queryKey: ["telemetry"] });
        },
        onError: (e: unknown) => {
            toast({ title: t("setEnv.failed"), description: String(e), variant: "destructive" });
        },
    });

    function invalidateAll() {
        void qc.invalidateQueries({ queryKey: ["runtime", "info"] });
        void qc.invalidateQueries({ queryKey: ["env", "vars"] });
        void qc.invalidateQueries({ queryKey: ["telemetry"] });
        void qc.invalidateQueries({ queryKey: ["captcha"] });
        setRestartRequired(true);
    }

    const logJsonOn = runtimeInfo.data?.log_json ?? false;

    const formatEntry = envEntry("AEGIS_EVENT_FORMAT");
    const allowedFormats: string[] =
        formatEntry?.allowed_values ??
        tel.data?.event_bridge.format_options ??
        ["native", "sicherheitstacho", "tpot"];
    const currentFormat =
        formatEntry?.value ?? tel.data?.event_bridge.format ?? "native";

    const busy = setEnv.isPending;

    return (
        <div className="space-y-6">
            {/* Page title */}
            <div>
                <SectionHeader label={t("pageTitle")} />
                <p className="text-xs text-muted-foreground mt-1.5 leading-snug">
                    {t("pageDescription")}
                </p>
            </div>

            {(tel.isLoading || runtimeInfo.isLoading) && (
                <Skeleton className="h-32 rounded-xl" />
            )}
            {tel.error && <ErrorState title={t("loadError")} error={tel.error} />}

            {restartRequired && (
                <RestartBanner
                    onRestart={() => restart.mutate()}
                    isPending={restart.isPending}
                    onDismiss={clearRestartRequired}
                />
            )}

            {/* ── Configuration grid ─────────────────────────────────────── */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {/* ClamAV scanner */}
                <MetricCard
                    title={t("clamav.title")}
                    description={t("clamav.description")}
                >
                    <div className="flex items-center gap-2 mb-4">
                        <Shield className="h-4 w-4 text-muted-foreground" />
                        <span className="text-xs text-muted-foreground font-medium">
                            {t("clamav.fieldLabel")}
                        </span>
                    </div>
                    <AddrControl
                        envKey="AEGIS_CLAMAV_ADDR"
                        label={t("clamav.fieldLabel")}
                        hint={t("clamav.fieldHint")}
                        description={t("clamav.fieldDescription")}
                        placeholder={t("clamav.addrPlaceholder")}
                        entry={envEntry("AEGIS_CLAMAV_ADDR")}
                        onSaved={invalidateAll}
                    />
                </MetricCard>

                {/* Event format */}
                <MetricCard
                    title={t("format.title")}
                    description={t("format.description")}
                >
                    <div className="flex items-center gap-2 mb-4">
                        <Radio className="h-4 w-4 text-muted-foreground" />
                        <span className="text-xs text-muted-foreground font-medium">
                            {t("format.label")}
                        </span>
                    </div>
                    <div className="space-y-2">
                        <Label className="text-xs text-muted-foreground">{t("format.fieldLabel")}</Label>
                        <Select
                            value={currentFormat}
                            disabled={busy || envVars.isLoading}
                            onValueChange={(fmt) =>
                                setEnv.mutate({ key: "AEGIS_EVENT_FORMAT", value: fmt })
                            }
                        >
                            <SelectTrigger className="w-52 h-8 text-xs bg-background/50">
                                <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                                {allowedFormats.map((fmt) => (
                                    <SelectItem key={fmt} value={fmt}>
                                        {fmt}
                                    </SelectItem>
                                ))}
                            </SelectContent>
                        </Select>
                    </div>
                </MetricCard>

                {/* JSON log format */}
                <MetricCard
                    title={t("logJson.title")}
                    description={t("logJson.description")}
                >
                    <div className="flex items-center gap-2 mb-4">
                        <FileText className="h-4 w-4 text-muted-foreground" />
                        <span className="text-xs text-muted-foreground font-medium">
                            {t("logJson.label")}
                        </span>
                    </div>
                    <div className="flex items-center gap-4">
                        <Switch
                            id="v2-log-json-switch"
                            checked={logJsonOn}
                            disabled={busy}
                            onCheckedChange={(on) =>
                                setEnv.mutate({ key: "AEGIS_LOG_JSON", value: on ? "1" : null })
                            }
                        />
                        <Label htmlFor="v2-log-json-switch" className="cursor-pointer">
                            <StatusBadge
                                state={logJsonOn ? "active" : "standby"}
                                label={logJsonOn ? t("logJson.enabled") : t("logJson.disabled")}
                            />
                        </Label>
                    </div>
                </MetricCard>

                {/* CAPTCHA secrets */}
                <MetricCard
                    title={t("captchaSecrets.title")}
                    description={t("captchaSecrets.description")}
                >
                    <div className="flex items-center gap-2 mb-4">
                        <Shield className="h-4 w-4 text-muted-foreground" />
                    </div>
                    <div className="space-y-5">
                        <SecretControl
                            envKey="AEGIS_HCAPTCHA_SECRET"
                            label={t("captchaSecrets.hcaptchaLabel")}
                            hint={t("captchaSecrets.hcaptchaHint")}
                            description={t("captchaSecrets.hcaptchaDescription")}
                            entry={envEntry("AEGIS_HCAPTCHA_SECRET")}
                            onSaved={invalidateAll}
                        />
                        <div className="border-t border-border/30 pt-4">
                            <SecretControl
                                envKey="AEGIS_TURNSTILE_SECRET"
                                label={t("captchaSecrets.turnstileLabel")}
                                hint={t("captchaSecrets.turnstileHint")}
                                description={t("captchaSecrets.turnstileDescription")}
                                entry={envEntry("AEGIS_TURNSTILE_SECRET")}
                                onSaved={invalidateAll}
                            />
                        </div>
                    </div>
                </MetricCard>
            </div>

            {/* ── Live status ─────────────────────────────────────────────── */}
            <SectionHeader label={t("liveStatus")} />

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {/* EventBridge status */}
                <MetricCard
                    title={t("eventBridge.title")}
                    description={t("eventBridge.description")}
                >
                    <div className="flex items-center gap-2 mb-3">
                        <Radio className="h-4 w-4 text-muted-foreground" />
                        <span className="text-xs text-muted-foreground font-medium">
                            {t("eventBridge.socketSink")}
                        </span>
                    </div>
                    <StatusRow label={t("eventBridge.format")}>
                        <ValueBadge
                            value={tel.data?.event_bridge.format}
                            active={tel.data?.event_bridge.format === "sicherheitstacho"}
                        />
                    </StatusRow>
                    <StatusRow label={t("eventBridge.socket")}>
                        <code className="text-[11px] font-mono text-foreground/80">
                            {tel.data?.event_bridge.socket_path ?? t("unset")}
                        </code>
                    </StatusRow>
                </MetricCard>

                {/* ClamAV status */}
                <MetricCard
                    title={t("clamavStatus.title")}
                    description={t("clamavStatus.description")}
                >
                    <div className="flex items-center gap-2 mb-3">
                        <Shield className="h-4 w-4 text-muted-foreground" />
                        <span className="text-xs text-muted-foreground font-medium">
                            {t("clamavStatus.bodyScanner")}
                        </span>
                    </div>
                    <StatusRow label={t("clamavStatus.status")}>
                        <StatusBadge
                            state={tel.data?.clamav.enabled ? "active" : "standby"}
                            label={tel.data?.clamav.enabled ? t("logJson.enabled") : t("logJson.disabled")}
                        />
                    </StatusRow>
                    <StatusRow label={t("clamavStatus.address")}>
                        <code className="text-[11px] font-mono text-foreground/80">
                            {tel.data?.clamav.addr ?? t("unset")}
                        </code>
                    </StatusRow>
                </MetricCard>
            </div>

            {/* Audit log + CAPTCHA providers */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <MetricCard title={t("auditLog.title")} description="">
                    <div className="flex items-center gap-2 mb-3">
                        <FileText className="h-4 w-4 text-muted-foreground" />
                        <span className="text-xs text-muted-foreground">{t("auditLog.logPath")}</span>
                    </div>
                    <code className="text-[11px] font-mono text-foreground/80 break-all leading-relaxed">
                        {tel.data?.audit_log_path ?? t("auditLog.inMemory")}
                    </code>
                </MetricCard>

                <MetricCard
                    title={t("captchaProviders.title")}
                    description={t("captchaProviders.description")}
                >
                    <div className="flex items-center gap-2 mb-3">
                        <Shield className="h-4 w-4 text-muted-foreground" />
                    </div>
                    <div className="space-y-0">
                        <StatusRow label={t("captchaProviders.pow")}>
                            <span className="flex items-center gap-2">
                                <StatusBadge state="active" label={t("logJson.enabled")} />
                                <span className="text-[11px] text-muted-foreground">
                                    {capt.data?.pow.algorithm}
                                </span>
                            </span>
                        </StatusRow>
                        <StatusRow label={t("captchaProviders.difficultyBits")}>
                            <code className="text-[11px] font-mono">
                                {capt.data?.pow.difficulty_bits ?? "—"}
                            </code>
                        </StatusRow>
                        <StatusRow label={t("captchaProviders.hcaptcha")}>
                            <StatusBadge
                                state={
                                    capt.data?.external_providers.hcaptcha ? "active" : "standby"
                                }
                                label={
                                    capt.data?.external_providers.hcaptcha
                                        ? t("captchaProviders.wired")
                                        : t("captchaProviders.notConfigured")
                                }
                            />
                        </StatusRow>
                        <StatusRow label={t("captchaProviders.turnstile")}>
                            <StatusBadge
                                state={
                                    capt.data?.external_providers.turnstile ? "active" : "standby"
                                }
                                label={
                                    capt.data?.external_providers.turnstile
                                        ? t("captchaProviders.wired")
                                        : t("captchaProviders.notConfigured")
                                }
                            />
                        </StatusRow>
                        <StatusRow label={t("captchaProviders.recaptcha")}>
                            <StatusBadge
                                state={
                                    capt.data?.external_providers.recaptcha ? "active" : "standby"
                                }
                                label={
                                    capt.data?.external_providers.recaptcha
                                        ? t("captchaProviders.wired")
                                        : t("captchaProviders.notConfigured")
                                }
                            />
                        </StatusRow>
                        {capt.data?.note && (
                            <p className="text-[10px] text-muted-foreground/70 pt-2 leading-snug">
                                {capt.data.note}
                            </p>
                        )}
                    </div>
                </MetricCard>
            </div>
        </div>
    );
}
