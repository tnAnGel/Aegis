/**
 * V2 Settings — /v2/settings
 *
 * Restyle of the V1 SettingsPage using V2 primitives (MetricCard,
 * SectionHeader, StatusBadge) and the mockup's dark-teal design language.
 *
 * Four tabs — identical structure to V1 but with V2 card chrome:
 *   General       — Runtime info, session, change credentials, danger zone
 *   ML & Detection — ML scorer, adversarial loop, honeypot
 *   Reputation    — JA4 + ASN reputation feeds
 *   Infrastructure — Response cache, dynamic trust, fw backend, XDP, ACME,
 *                    CrowdSec, ClamAV (env-var driven; restart banner)
 *
 * Data: identical react-query / mutation calls as V1 SettingsPage.
 *   runtimeApi.status       — useQuery
 *   runtimeInfoApi.get      — useQuery, 15 s refetch
 *   envApi.set              — useMutation
 *   restartApi.run          — useMutation
 *   authApi.changeCredentials — via ChangeCredentialsCard (reused as-is)
 *
 * V2 changes:
 *   - No Card import from /components/ui/card — MetricCard only.
 *   - Tabs styled with basic Tailwind (no Radix TabsList) to avoid V1
 *     component assumptions; could be upgraded later.
 *   - StatusBadge replaces Badge for active/inactive state pills.
 *   - All spacing, typography, and borders follow the V2 token palette.
 */

import * as React from "react";
import { useTranslation } from "react-i18next";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
    AlertTriangle,
    Brain,
    Database,
    RotateCcw,
    Server,
    Settings as SettingsIcon,
    Trash2,
    User,
} from "lucide-react";
import {
    runtimeApi,
    runtimeInfoApi,
    envApi,
    restartApi,
    clearToken,
    type RuntimeInfo,
} from "@/api/client";
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
import { useAuth } from "@/hooks/useAuth";
import { useRestartRequired } from "@/hooks/useRestartRequired";
import { useToast } from "@/hooks/useToast";
import { authApi } from "@/api/client";
import { MetricCard } from "@/v2/components/MetricCard";
import { SectionHeader } from "@/v2/components/SectionHeader";
import { StatusBadge } from "@/v2/components/StatusBadge";
import { cn } from "@/lib/cn";

// ─── Tab types ───────────────────────────────────────────────────────────────

type Tab = "general" | "ml" | "feeds" | "infra";

const TABS: { id: Tab; labelKey: string; icon: React.ReactNode }[] = [
    { id: "general", labelKey: "tab.general", icon: <SettingsIcon className="h-3.5 w-3.5" /> },
    { id: "ml",      labelKey: "tab.ml",      icon: <Brain className="h-3.5 w-3.5" /> },
    { id: "feeds",   labelKey: "tab.feeds",   icon: <Database className="h-3.5 w-3.5" /> },
    { id: "infra",   labelKey: "tab.infra",   icon: <Server className="h-3.5 w-3.5" /> },
];

// ─── Shared primitives ───────────────────────────────────────────────────────

/** Mono-spaced definition list row: label on left, value on right. */
function DefRow({ label, children }: { label: string; children: React.ReactNode }) {
    return (
        <>
            <dt className="text-sm text-muted-foreground">{label}</dt>
            <dd className="text-sm font-mono text-right break-all">{children ?? "—"}</dd>
        </>
    );
}

/** "Not wired" placeholder used in cards for optional integrations. */
function NotWired({ module, hint }: { module: string; hint: string }) {
    const { t } = useTranslation(["settings", "common"]);
    return (
        <div className="space-y-2">
            <StatusBadge state="standby" label={t("notWired.badge")} />
            <p className="text-xs text-muted-foreground">{t("notWired.line", { module })}</p>
            <p className="text-xs text-muted-foreground">{hint}</p>
        </div>
    );
}

// ─── Change Credentials (V2 inline version) ───────────────────────────────

function ChangeCredentialsCardV2() {
    const { t } = useTranslation(["settings", "common"]);
    const { state, markCredentialsChanged } = useAuth();
    const { toast } = useToast();
    const mustChange = state.status === "logged_in" && state.mustChange;
    const currentEmail = state.status === "logged_in" ? state.email : "";

    const [currentPassword, setCurrentPassword] = React.useState("");
    const [newEmail, setNewEmail] = React.useState("");
    const [newPassword, setNewPassword] = React.useState("");
    const [confirmPassword, setConfirmPassword] = React.useState("");
    const [busy, setBusy] = React.useState(false);
    const [error, setError] = React.useState<string | null>(null);

    async function handleSubmit(e: React.FormEvent) {
        e.preventDefault();
        if (busy) return;
        setError(null);
        if (newPassword.length < 8) {
            setError(t("creds.err.tooShort"));
            return;
        }
        if (newPassword !== confirmPassword) {
            setError(t("creds.err.mismatch"));
            return;
        }
        setBusy(true);
        try {
            const r = await authApi.changeCredentials(currentPassword, newEmail.trim(), newPassword);
            markCredentialsChanged(r.token, r.email);
            toast({ title: t("creds.toast.updated"), variant: "success" });
            setCurrentPassword("");
            setNewPassword("");
            setConfirmPassword("");
        } catch (err) {
            const e = err as { status?: number; body?: string };
            try {
                const parsed = JSON.parse(e.body ?? "{}");
                setError(parsed.error ?? `HTTP ${e.status}`);
            } catch {
                setError(`HTTP ${e.status}`);
            }
        } finally {
            setBusy(false);
        }
    }

    return (
        <MetricCard
            title={mustChange ? t("creds.title.mustChange") : t("creds.title.normal")}
            description={
                mustChange
                    ? t("creds.desc.mustChange")
                    : t("creds.desc.normal")
            }
            className={mustChange ? "border-destructive/50" : undefined}
        >
            <form className="space-y-4" onSubmit={handleSubmit}>
                <div className="space-y-1.5">
                    <Label htmlFor="v2-cur-pwd" className="text-xs text-muted-foreground uppercase tracking-wider">
                        {t("creds.currentPassword")}
                    </Label>
                    <Input
                        id="v2-cur-pwd"
                        type="password"
                        autoComplete="current-password"
                        value={currentPassword}
                        onChange={(e) => setCurrentPassword(e.target.value)}
                        required
                        className="bg-background border-border"
                    />
                </div>
                <div className="space-y-1.5">
                    <Label htmlFor="v2-new-email" className="text-xs text-muted-foreground uppercase tracking-wider">
                        {t("creds.newEmail")}
                    </Label>
                    <Input
                        id="v2-new-email"
                        type="email"
                        autoComplete="username"
                        placeholder={currentEmail || undefined}
                        value={newEmail}
                        onChange={(e) => setNewEmail(e.target.value)}
                        required
                        className="bg-background border-border"
                    />
                </div>
                <div className="grid gap-3 sm:grid-cols-2">
                    <div className="space-y-1.5">
                        <Label htmlFor="v2-new-pwd" className="text-xs text-muted-foreground uppercase tracking-wider">
                            {t("creds.newPassword")}
                        </Label>
                        <Input
                            id="v2-new-pwd"
                            type="password"
                            autoComplete="new-password"
                            value={newPassword}
                            onChange={(e) => setNewPassword(e.target.value)}
                            required
                            minLength={8}
                            className="bg-background border-border"
                        />
                    </div>
                    <div className="space-y-1.5">
                        <Label htmlFor="v2-confirm-pwd" className="text-xs text-muted-foreground uppercase tracking-wider">
                            {t("creds.confirm")}
                        </Label>
                        <Input
                            id="v2-confirm-pwd"
                            type="password"
                            autoComplete="new-password"
                            value={confirmPassword}
                            onChange={(e) => setConfirmPassword(e.target.value)}
                            required
                            minLength={8}
                            className="bg-background border-border"
                        />
                    </div>
                </div>
                {error && (
                    <p role="alert" className="text-sm text-destructive border border-destructive/40 bg-destructive/10 rounded-lg px-3 py-2">
                        {error}
                    </p>
                )}
                <Button type="submit" disabled={busy} size="sm">
                    {busy ? t("creds.saving") : t("creds.save")}
                </Button>
            </form>
        </MetricCard>
    );
}

// ─── Tab panels ──────────────────────────────────────────────────────────────

function GeneralTab({
    status,
    info,
}: {
    status: { aegis_version?: string; config_path?: string; uptime_sec?: number; listeners?: string[] } | undefined;
    info: RuntimeInfo | undefined;
}) {
    const { t } = useTranslation(["settings", "common"]);
    const { toast } = useToast();
    const qc = useQueryClient();
    const { state: auth, logout } = useAuth();

    return (
        <div className="grid gap-4 grid-cols-1 lg:grid-cols-2">
            {/* Runtime info */}
            <MetricCard title={t("runtime.title")} description={t("runtime.desc")}>
                <dl className="grid grid-cols-2 gap-y-3">
                    <DefRow label={t("runtime.version")}>
                        <span className="text-xs">{info?.version ?? status?.aegis_version ?? "—"}</span>
                    </DefRow>
                    <DefRow label={t("runtime.configPath")}>
                        <span className="text-xs truncate block max-w-[200px]">
                            {info?.config_path ?? status?.config_path ?? "—"}
                        </span>
                    </DefRow>
                    <DefRow label={t("runtime.uptime")}>
                        {info?.uptime_secs
                            ? t("runtime.uptimeValue", {
                                  minutes: Math.floor(info.uptime_secs / 60),
                                  seconds: info.uptime_secs % 60,
                              })
                            : "—"}
                    </DefRow>
                    <DefRow label={t("runtime.filterToggles")}>
                        {info?.filter_toggles_count ?? "—"}
                    </DefRow>
                    <DefRow label={t("runtime.domainOverrides")}>
                        {info?.domain_policy_count ?? 0}
                    </DefRow>
                </dl>

                {/* Listeners list */}
                {((status?.listeners ?? []).length > 0) && (
                    <div className="mt-4 pt-3 border-t border-border/40">
                        <SectionHeader label={t("runtime.listeners")} className="mb-2" />
                        <ul className="space-y-1 font-mono text-xs">
                            {(status?.listeners ?? []).map((l) => (
                                <li key={l} className="text-foreground">{l}</li>
                            ))}
                        </ul>
                    </div>
                )}
            </MetricCard>

            {/* Session */}
            <MetricCard
                title={t("session.title")}
                description={t("session.desc")}
            >
                <div className="flex items-center gap-2 mb-4">
                    <span className="inline-flex items-center justify-center rounded-full h-8 w-8 bg-muted/60 text-muted-foreground">
                        <User className="h-4 w-4" />
                    </span>
                    <div>
                        <p className="text-sm font-medium">
                            {auth.status === "logged_in" ? auth.email : t("session.notLoggedIn")}
                        </p>
                        <p className="text-xs text-muted-foreground">
                            {auth.status === "logged_in" ? auth.auth : "—"}
                        </p>
                    </div>
                </div>
                <Button
                    variant="secondary"
                    size="sm"
                    onClick={() => void logout()}
                >
                    {t("session.signOut")}
                </Button>
            </MetricCard>

            {/* Change credentials */}
            <ChangeCredentialsCardV2 />

            {/* Danger zone */}
            <MetricCard
                title={t("danger.title")}
                description={t("danger.desc")}
                className="border-destructive/40"
            >
                <div className="space-y-3">
                    <p className="text-xs text-muted-foreground">
                        {t("danger.body")}
                    </p>
                    <Button
                        variant="destructive"
                        size="sm"
                        onClick={() => {
                            clearToken();
                            qc.invalidateQueries();
                            toast({ title: t("danger.toast.cleared"), variant: "success" });
                        }}
                    >
                        <Trash2 className="h-3.5 w-3.5" />
                        {t("danger.clearToken")}
                    </Button>
                </div>
            </MetricCard>
        </div>
    );
}

function MlTab({ info }: { info: RuntimeInfo | undefined }) {
    const { t } = useTranslation(["settings", "common"]);
    return (
        <div className="grid gap-4 grid-cols-1 lg:grid-cols-2">
            {/* ML scorer */}
            <MetricCard
                title={t("ml.scorer.title")}
                description={t("ml.scorer.desc")}
            >
                {info?.ml_v2 ? (
                    <dl className="grid grid-cols-2 gap-y-3">
                        <DefRow label={t("ml.scorer.kind")}>
                            <StatusBadge state="active" label={info.ml_v2.kind} />
                        </DefRow>
                        <DefRow label={t("ml.scorer.status")}>
                            {info.ml_v2.available
                                ? <StatusBadge state="active" label={t("ml.scorer.active")} />
                                : <StatusBadge state="standby" label={t("ml.scorer.loadedDisabled")} />}
                        </DefRow>
                    </dl>
                ) : (
                    <NotWired
                        module={t("ml.scorer.notWired.module")}
                        hint={t("ml.scorer.notWired.hint")}
                    />
                )}
            </MetricCard>

            {/* Adversarial mutation loop */}
            <MetricCard
                title={t("ml.adversarial.title")}
                description={t("ml.adversarial.desc")}
            >
                <dl className="grid grid-cols-2 gap-y-3">
                    <DefRow label={t("ml.adversarial.status")}>
                        <StatusBadge
                            state={info?.adversarial_loop ? "active" : "standby"}
                            label={info?.adversarial_loop ? t("ml.adversarial.running") : t("ml.adversarial.off")}
                        />
                    </DefRow>
                </dl>
            </MetricCard>

            {/* Honeypot */}
            <MetricCard title={t("ml.honeypot.title")} description={t("ml.honeypot.desc")}>
                {info?.honeypot ? (
                    <dl className="grid grid-cols-2 gap-y-3">
                        <DefRow label={t("ml.honeypot.master")}>
                            <StatusBadge
                                state={info.honeypot.enabled ? "active" : "standby"}
                                label={info.honeypot.enabled ? t("ml.honeypot.on") : t("ml.honeypot.off")}
                            />
                        </DefRow>
                        <DefRow label={t("ml.honeypot.packsEnabled")}>
                            {info.honeypot.packs_enabled} / {info.honeypot.packs_total}
                        </DefRow>
                        <DefRow label={t("ml.honeypot.customPaths")}>
                            {info.honeypot.custom_paths_count}
                        </DefRow>
                        <DefRow label={t("ml.honeypot.tarpit")}>
                            {t("ml.honeypot.tarpitValue", { seconds: info.honeypot.tarpit_seconds })}
                        </DefRow>
                        <DefRow label={t("ml.honeypot.autoXdpThreshold")}>
                            {info.honeypot.auto_xdp_deny_threshold}
                        </DefRow>
                    </dl>
                ) : (
                    <NotWired
                        module={t("ml.honeypot.notWired.module")}
                        hint={t("ml.honeypot.notWired.hint")}
                    />
                )}
            </MetricCard>
        </div>
    );
}

function FeedsTab({ info }: { info: RuntimeInfo | undefined }) {
    const { t } = useTranslation(["settings", "common"]);
    return (
        <div className="grid gap-4 grid-cols-1 lg:grid-cols-2">
            {/* JA4 reputation */}
            <MetricCard
                title={t("feeds.ja4.title")}
                description={t("feeds.ja4.desc")}
            >
                {info?.ja4_reputation ? (
                    <dl className="grid grid-cols-2 gap-y-3">
                        <DefRow label={t("feeds.ja4.status")}>
                            <StatusBadge
                                state={info.ja4_reputation.active ? "active" : "standby"}
                                label={info.ja4_reputation.active ? t("feeds.ja4.loaded") : t("feeds.ja4.inactive")}
                            />
                        </DefRow>
                        <DefRow label={t("feeds.ja4.entryCount")}>
                            <span className="tabular-nums">{info.ja4_reputation.entry_count.toLocaleString()}</span>
                        </DefRow>
                    </dl>
                ) : (
                    <NotWired
                        module={t("feeds.ja4.notWired.module")}
                        hint={t("feeds.ja4.notWired.hint")}
                    />
                )}
            </MetricCard>

            {/* ASN / CIDR reputation */}
            <MetricCard
                title={t("feeds.asn.title")}
                description={t("feeds.asn.desc")}
            >
                {info?.asn_reputation ? (
                    <dl className="grid grid-cols-2 gap-y-3">
                        <DefRow label={t("feeds.asn.status")}>
                            <StatusBadge
                                state={info.asn_reputation.active ? "active" : "standby"}
                                label={info.asn_reputation.active ? t("feeds.asn.loaded") : t("feeds.asn.inactive")}
                            />
                        </DefRow>
                        <DefRow label={t("feeds.asn.entryCount")}>
                            <span className="tabular-nums">{info.asn_reputation.entry_count.toLocaleString()}</span>
                        </DefRow>
                    </dl>
                ) : (
                    <NotWired
                        module={t("feeds.asn.notWired.module")}
                        hint={t("feeds.asn.notWired.hint")}
                    />
                )}
            </MetricCard>
        </div>
    );
}

type FwBackend = "auto" | "xdp" | "nftables" | "iptables" | "noop";

function InfraTab({ info }: { info: RuntimeInfo | undefined }) {
    const { t } = useTranslation(["settings", "common"]);
    const { toast } = useToast();
    const qc = useQueryClient();
    const { restartRequired, setRestartRequired, clearRestartRequired } =
        useRestartRequired();

    const setEnv = useMutation({
        mutationFn: ({ key, value }: { key: string; value: string | null }) =>
            envApi.set(key, value),
        onSuccess: (res) => {
            if (res.restart_required) setRestartRequired(true);
            void qc.invalidateQueries({ queryKey: ["runtime", "info"] });
            toast({
                title: res.restart_required
                    ? t("toast.envUpdated.restart")
                    : t("toast.envUpdated"),
                description: t("toast.envUpdated.desc"),
                variant: "success",
            });
        },
        onError: (e: unknown) => {
            toast({
                title: t("toast.envFailed"),
                description: String(e),
                variant: "destructive",
            });
        },
    });

    const restart = useMutation({
        mutationFn: restartApi.run,
        onSuccess: (res) => {
            clearRestartRequired();
            toast({ title: t("toast.restartTriggered"), description: res.note });
        },
        onError: (e: unknown) => {
            toast({
                title: t("toast.restartFailed"),
                description: String(e),
                variant: "destructive",
            });
        },
    });

    const busy = setEnv.isPending;
    const cacheOn        = info?.response_cache_enabled  ?? false;
    const dynamicTrustOn = info?.dynamic_trust_enabled   ?? false;
    const rawFw          = info?.fw_backend;
    const fwBackend: FwBackend =
        rawFw === "xdp"      ? "xdp"
        : rawFw === "nftables"  ? "nftables"
        : rawFw === "iptables"  ? "iptables"
        : rawFw === "noop"      ? "noop"
        : "auto";

    return (
        <div className="space-y-4">
            {/* Restart banner */}
            {restartRequired && (
                <div className="rounded-xl border border-amber-500/40 bg-amber-500/10 p-4 flex items-start gap-3">
                    <AlertTriangle className="h-4 w-4 mt-0.5 shrink-0 text-amber-400" />
                    <div className="flex-1 text-sm text-amber-200">
                        <strong className="text-amber-300">{t("infra.restart.title")}</strong>{" "}
                        {t("infra.restart.before")}
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                        <Button
                            size="sm"
                            variant="outline"
                            className="border-amber-500/50 text-amber-300 hover:bg-amber-500/20"
                            onClick={() => restart.mutate()}
                            disabled={restart.isPending}
                        >
                            <RotateCcw className="h-3.5 w-3.5" />
                            {t("infra.restart.apply")}
                        </Button>
                        <Button
                            size="sm"
                            variant="ghost"
                            className="text-amber-200 hover:text-amber-100"
                            onClick={clearRestartRequired}
                        >
                            {t("infra.restart.dismiss")}
                        </Button>
                    </div>
                </div>
            )}

            <div className="grid gap-4 grid-cols-1 lg:grid-cols-2">
                {/* Response cache */}
                <MetricCard
                    title={t("infra.cache.title")}
                    description={t("infra.cache.desc")}
                    action={
                        <div className="flex items-center gap-2">
                            <span className="text-[0.65rem] text-muted-foreground">
                                {t("infra.cache.label")}
                            </span>
                            <Switch
                                id="v2-cache-switch"
                                checked={cacheOn}
                                disabled={busy}
                                onCheckedChange={(on) =>
                                    setEnv.mutate({
                                        key: "AEGIS_RESPONSE_CACHE_ENABLE",
                                        value: on ? "1" : null,
                                    })
                                }
                                aria-label={t("infra.cache.aria")}
                            />
                        </div>
                    }
                >
                    <Label htmlFor="v2-cache-switch" className="cursor-pointer">
                        <StatusBadge
                            state={cacheOn ? "active" : "standby"}
                            label={cacheOn ? t("enabled", { ns: "common" }) : t("disabled", { ns: "common" })}
                        />
                    </Label>
                </MetricCard>

                {/* Dynamic trust */}
                <MetricCard
                    title={t("infra.trust.title")}
                    description={t("infra.trust.desc")}
                    action={
                        <div className="flex items-center gap-2">
                            <span className="text-[0.65rem] text-muted-foreground">
                                {t("infra.trust.label")}
                            </span>
                            <Switch
                                id="v2-trust-switch"
                                checked={dynamicTrustOn}
                                disabled={busy}
                                onCheckedChange={(on) =>
                                    setEnv.mutate({
                                        key: "AEGIS_DYNAMIC_TRUST_ENABLE",
                                        value: on ? "1" : null,
                                    })
                                }
                                aria-label={t("infra.trust.aria")}
                            />
                        </div>
                    }
                >
                    <Label htmlFor="v2-trust-switch" className="cursor-pointer">
                        <StatusBadge
                            state={dynamicTrustOn ? "active" : "standby"}
                            label={dynamicTrustOn ? t("enabled", { ns: "common" }) : t("disabled", { ns: "common" })}
                        />
                    </Label>
                </MetricCard>

                {/* Firewall backend */}
                <MetricCard
                    title={t("infra.fw.title")}
                    description={
                        <>
                            {t("infra.fw.desc.before")}
                            <strong>{t("infra.fw.desc.auto")}</strong>
                            {t("infra.fw.desc.after")}
                        </>
                    }
                    action={
                        <div className="flex flex-col items-end gap-1.5">
                            <span className="text-[0.65rem] text-muted-foreground">
                                {t("infra.fw.label")}
                            </span>
                            <Select
                                value={fwBackend}
                                disabled={busy}
                                onValueChange={(v) =>
                                    setEnv.mutate({
                                        key: "AEGIS_FW_BACKEND",
                                        value: v === "auto" ? null : v,
                                    })
                                }
                            >
                                <SelectTrigger className="w-32 h-8 text-xs">
                                    <SelectValue />
                                </SelectTrigger>
                                <SelectContent>
                                    <SelectItem value="auto">auto</SelectItem>
                                    <SelectItem value="xdp">xdp</SelectItem>
                                    <SelectItem value="nftables">nftables</SelectItem>
                                    <SelectItem value="iptables">iptables</SelectItem>
                                    <SelectItem value="noop">noop</SelectItem>
                                </SelectContent>
                            </Select>
                        </div>
                    }
                >
                    <StatusBadge
                        state="active"
                        label={t("infra.fw.current", { backend: fwBackend })}
                    />
                </MetricCard>

                {/* XDP fast-path (read-only status) */}
                <MetricCard
                    title={t("infra.xdp.title")}
                    description={t("infra.xdp.desc")}
                >
                    <p className="text-sm text-muted-foreground">
                        {t("infra.xdp.body.before")}
                        <code className="font-mono text-xs">GET /admin/xdp</code>
                        {t("infra.xdp.body.after")}
                    </p>
                </MetricCard>

                {/* ACME auto-cert */}
                <MetricCard title={t("infra.acme.title")} description={t("infra.acme.desc")}>
                    <NotWired
                        module={t("infra.acme.notWired.module")}
                        hint={t("infra.acme.notWired.hint")}
                    />
                </MetricCard>

                {/* CrowdSec LAPI */}
                <MetricCard
                    title={t("infra.crowdsec.title")}
                    description={t("infra.crowdsec.desc")}
                >
                    <NotWired
                        module={t("infra.crowdsec.notWired.module")}
                        hint={t("infra.crowdsec.notWired.hint")}
                    />
                </MetricCard>

                {/* ClamAV scanner */}
                <MetricCard title={t("infra.clamav.title")} description={t("infra.clamav.desc")}>
                    {info?.clamav_addr ? (
                        <dl className="grid grid-cols-2 gap-y-3">
                            <DefRow label={t("infra.clamav.addr")}>
                                <span className="text-xs">{info.clamav_addr}</span>
                            </DefRow>
                        </dl>
                    ) : (
                        <NotWired
                            module={t("infra.clamav.notWired.module")}
                            hint={t("infra.clamav.notWired.hint")}
                        />
                    )}
                </MetricCard>
            </div>
        </div>
    );
}

// ─── Page ────────────────────────────────────────────────────────────────────

export function SettingsV2Page() {
    const { t } = useTranslation(["settings", "common"]);
    const [activeTab, setActiveTab] = React.useState<Tab>("general");

    const status = useQuery({
        queryKey: ["runtime", "status"],
        queryFn: runtimeApi.status,
    });
    const info = useQuery({
        queryKey: ["runtime", "info"],
        queryFn: runtimeInfoApi.get,
        refetchInterval: 15_000,
    });

    return (
        <div className="space-y-6">
            {/* ── Page title bar ─────────────────────────────────────────── */}
            <div className="flex items-center gap-3">
                <span className="inline-flex items-center justify-center rounded-lg h-9 w-9 bg-muted/50 text-muted-foreground">
                    <SettingsIcon className="h-5 w-5" />
                </span>
                <div>
                    <h1 className="text-xl font-semibold text-foreground tracking-tight">{t("page.title")}</h1>
                    <p className="text-xs text-muted-foreground mt-0.5">
                        {t("page.subtitle")}
                    </p>
                </div>
            </div>

            {/* Loading / error states */}
            {(status.isLoading || info.isLoading) && (
                <Skeleton className="h-24 w-full rounded-xl" />
            )}

            {/* ── Tab nav ────────────────────────────────────────────────── */}
            <div
                className="flex gap-1 p-1 rounded-xl"
                style={{ background: "hsl(var(--card))", border: "1px solid hsl(var(--border))" }}
                role="tablist"
                aria-label={t("tablist.aria")}
            >
                {TABS.map((tab) => (
                    <button
                        key={tab.id}
                        role="tab"
                        aria-selected={activeTab === tab.id}
                        onClick={() => setActiveTab(tab.id)}
                        className={cn(
                            "flex items-center gap-1.5 px-3 py-2 rounded-lg text-sm font-medium transition-colors",
                            "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
                            activeTab === tab.id
                                ? "bg-background text-foreground shadow-sm"
                                : "text-muted-foreground hover:text-foreground hover:bg-accent/50",
                        )}
                    >
                        {tab.icon}
                        {t(tab.labelKey)}
                    </button>
                ))}
            </div>

            {/* ── Tab panels ─────────────────────────────────────────────── */}
            <div role="tabpanel">
                {activeTab === "general" && (
                    <GeneralTab
                        status={status.data as {
                            aegis_version?: string;
                            config_path?: string;
                            uptime_sec?: number;
                            listeners?: string[];
                        } | undefined}
                        info={info.data}
                    />
                )}
                {activeTab === "ml" && <MlTab info={info.data} />}
                {activeTab === "feeds" && <FeedsTab info={info.data} />}
                {activeTab === "infra" && <InfraTab info={info.data} />}
            </div>
        </div>
    );
}
