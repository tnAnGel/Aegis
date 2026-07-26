/**
 * V2 CrowdSec page — /v2/crowdsec
 *
 * CrowdSec LAPI adapter configuration + status, restyled with V2 primitives.
 * All data-fetching, mutations, and business logic are identical to V1 CrowdSecPage.
 * Presentation only changes: MetricCard, StatusBadge, V2 restart banner.
 */

import { useState } from "react";
import { useTranslation } from "react-i18next";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, Link2, Save, Shield, Users } from "lucide-react";
import { crowdsecApi, envApi } from "@/api/client";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState } from "@/components/ErrorState";
import { useToast } from "@/hooks/useToast";
import { useRestartRequired } from "@/hooks/useRestartRequired";
import { MetricCard } from "@/v2/components/MetricCard";
import { SectionHeader } from "@/v2/components/SectionHeader";
import { StatusBadge } from "@/v2/components/StatusBadge";

// ─── Restart-required banner ─────────────────────────────────────────────────

function RestartBanner({ onDismiss }: { onDismiss: () => void }) {
    const { t } = useTranslation(["crowdsec", "common"]);
    return (
        <div className="rounded-xl border border-amber-500/30 bg-amber-500/10 px-5 py-4 flex items-start gap-3">
            <AlertTriangle className="h-4 w-4 mt-0.5 shrink-0 text-amber-400" />
            <div className="flex-1 text-sm text-amber-200 leading-snug">
                <strong className="font-semibold">{t("restart.title")}</strong>{" "}
                {t("restart.body")}{" "}
                <code className="font-mono text-xs">
                    {t("restart.command")}
                </code>
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

// ─── Page ────────────────────────────────────────────────────────────────────

export function CrowdSecPageV2() {
    const { t } = useTranslation(["crowdsec", "common"]);
    const { toast } = useToast();
    const qc = useQueryClient();
    const { restartRequired, setRestartRequired, clearRestartRequired } =
        useRestartRequired();

    // ── Data sources ──────────────────────────────────────────────────
    const q = useQuery({
        queryKey: ["crowdsec"],
        queryFn: crowdsecApi.status,
        refetchInterval: 30_000,
    });

    // ── Local editor state ─────────────────────────────────────────────
    const [lapiUrl, setLapiUrl] = useState<string>("");
    const [lapiDirty, setLapiDirty] = useState(false);
    const [bouncerKey, setBouncerKey] = useState<string>("");

    // Sync LAPI URL from status once on first load.
    const liveLapiUrl = q.data?.lapi_url ?? "";
    const [lapiInitialised, setLapiInitialised] = useState(false);
    if (!lapiInitialised && q.data !== undefined) {
        setLapiInitialised(true);
        setLapiUrl(liveLapiUrl);
    }

    // ── Mutations ─────────────────────────────────────────────────────
    const setEnv = useMutation({
        mutationFn: ({ key, value }: { key: string; value: string | null }) =>
            envApi.set(key, value),
        onSuccess: () => {
            setRestartRequired(true);
            toast({
                title: t("toast.saved.title"),
                description: t("toast.saved.description"),
            });
            void qc.invalidateQueries({ queryKey: ["crowdsec"] });
        },
        onError: (err: unknown) => {
            toast({
                title: t("toast.saveFailed.title"),
                description: String(err),
                variant: "destructive",
            });
        },
    });

    const busy = setEnv.isPending;

    const saveLapiUrl = () => {
        const trimmed = lapiUrl.trim();
        setEnv.mutate({ key: "AEGIS_CROWDSEC_LAPI_URL", value: trimmed || null });
        setLapiDirty(false);
    };

    const saveBouncerKey = () => {
        const trimmed = bouncerKey.trim();
        if (!trimmed) return;
        setEnv.mutate({ key: "AEGIS_CROWDSEC_BOUNCER_KEY", value: trimmed });
        setBouncerKey("");
    };

    return (
        <div className="space-y-6">
            {/* ── Page header ──────────────────────────────────────────── */}
            <div className="flex items-center gap-3">
                <span className="inline-flex items-center justify-center rounded-lg w-9 h-9 bg-primary/10 text-primary">
                    <Shield className="h-5 w-5" />
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
            {q.isLoading && <Skeleton className="h-32 rounded-xl" />}
            {q.error && (
                <ErrorState
                    title={t("errorTitle")}
                    error={q.error}
                />
            )}

            {/* ── Restart-required banner ───────────────────────────────── */}
            {restartRequired && (
                <RestartBanner onDismiss={clearRestartRequired} />
            )}

            {/* ── Live status summary ───────────────────────────────────── */}
            {q.data && (
                <div className="flex items-center gap-4 px-1">
                    <div className="flex items-center gap-2 text-xs text-muted-foreground">
                        <span>{t("status.lapiUrl")}</span>
                        <StatusBadge
                            state={q.data.lapi_url ? "active" : "standby"}
                            label={q.data.lapi_url ? t("status.configured") : t("status.notSet")}
                        />
                    </div>
                    <div className="flex items-center gap-2 text-xs text-muted-foreground">
                        <span>{t("status.bouncerKey")}</span>
                        <StatusBadge
                            state={
                                q.data.bouncer_key_configured
                                    ? "active"
                                    : "standby"
                            }
                            label={
                                q.data.bouncer_key_configured
                                    ? t("status.configured")
                                    : t("status.notSet")
                            }
                        />
                    </div>
                </div>
            )}

            {/* ── Configuration inputs ──────────────────────────────────── */}
            <SectionHeader label={t("configuration")} />

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {/* LAPI URL */}
                <MetricCard
                    title={t("lapi.title")}
                    description={t("lapi.description")}
                    action={
                        <span className="text-[10px] text-muted-foreground">
                            {t("lapi.badge")}
                        </span>
                    }
                >
                    <div className="space-y-3">
                        <div className="flex items-center gap-2 text-xs text-muted-foreground">
                            <Link2 className="h-3.5 w-3.5 shrink-0" />
                            <span className="font-mono truncate">
                                {q.data?.lapi_url || (
                                    <em className="not-italic text-muted-foreground/60">
                                        {t("lapi.notConfigured")}
                                    </em>
                                )}
                            </span>
                        </div>
                        <div className="space-y-1.5">
                            <Label
                                htmlFor="crowdsec-lapi-url"
                                className="text-xs text-muted-foreground"
                            >
                                {t("lapi.newValue")}
                            </Label>
                            <Input
                                id="crowdsec-lapi-url"
                                value={lapiUrl}
                                placeholder="http://127.0.0.1:8080"
                                disabled={busy}
                                onChange={(e) => {
                                    setLapiUrl(e.target.value);
                                    setLapiDirty(true);
                                }}
                                className="h-8 text-xs font-mono"
                            />
                        </div>
                        <Button
                            size="sm"
                            variant="outline"
                            disabled={busy || !lapiDirty}
                            onClick={saveLapiUrl}
                            className="gap-1.5"
                        >
                            <Save className="h-3.5 w-3.5" />
                            {t("save")}
                        </Button>
                    </div>
                </MetricCard>

                {/* Bouncer key — write-only secret */}
                <MetricCard
                    title={t("bouncer.title")}
                    description={t("bouncer.description")}
                    action={
                        <span className="text-[10px] text-muted-foreground">
                            {t("bouncer.badge")}
                        </span>
                    }
                >
                    <div className="space-y-3">
                        <div className="flex items-center gap-2 text-xs text-muted-foreground">
                            <Users className="h-3.5 w-3.5 shrink-0" />
                            <StatusBadge
                                state={
                                    q.data?.bouncer_key_configured
                                        ? "active"
                                        : "standby"
                                }
                                label={
                                    q.data?.bouncer_key_configured
                                        ? t("bouncer.keyOnFile")
                                        : t("bouncer.notSet")
                                }
                            />
                        </div>
                        <div className="space-y-1.5">
                            <Label
                                htmlFor="crowdsec-bouncer-key"
                                className="text-xs text-muted-foreground"
                            >
                                {t("bouncer.newKey")}{" "}
                                <span className="text-muted-foreground/60">
                                    {t("bouncer.leaveBlank")}
                                </span>
                            </Label>
                            <Input
                                id="crowdsec-bouncer-key"
                                type="password"
                                value={bouncerKey}
                                placeholder={
                                    q.data?.bouncer_key_configured
                                        ? t("bouncer.placeholderSet")
                                        : t("bouncer.placeholderEmpty")
                                }
                                disabled={busy}
                                onChange={(e) => setBouncerKey(e.target.value)}
                                className="h-8 text-xs font-mono"
                                autoComplete="new-password"
                            />
                        </div>
                        <Button
                            size="sm"
                            variant="outline"
                            disabled={busy || !bouncerKey.trim()}
                            onClick={saveBouncerKey}
                            className="gap-1.5"
                        >
                            <Save className="h-3.5 w-3.5" />
                            {t("save")}
                        </Button>
                    </div>
                </MetricCard>
            </div>

            {/* ── Why CrowdSec integration ──────────────────────────────── */}
            <MetricCard title={t("about.title")}>
                <div className="space-y-3 text-sm text-muted-foreground leading-relaxed">
                    <p>{t("about.p1")}</p>
                    <p className="text-xs">
                        {t("about.p2.prefix")}{" "}
                        <code className="font-mono text-[10px]">
                            src/crowdsec_api.rs
                        </code>{" "}
                        {t("about.p2.suffix")}
                    </p>
                    {q.data?.note && (
                        <p className="text-xs italic text-muted-foreground/70">
                            {q.data.note}
                        </p>
                    )}
                </div>
            </MetricCard>
        </div>
    );
}
