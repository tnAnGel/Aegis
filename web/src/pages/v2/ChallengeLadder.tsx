/**
 * V2 Challenge Ladder page — /v2/challenge
 *
 * Identical data-fetching and mutations as V1 ChallengeLadder.tsx.
 * Presentation rebuilt with V2 primitives: MetricCard, SectionHeader,
 * StatusBadge and the v2-card CSS classes from tokens.css.
 */

import { useState } from "react";
import { useTranslation } from "react-i18next";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
    Shield,
    Activity,
    AlertOctagon,
    Trash2,
    Save,
} from "lucide-react";
import { challengeApi, routeDifficultyApi } from "@/api/client";
import type { DomainChallengeConfig } from "@/api/client";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Skeleton } from "@/components/ui/skeleton";
import {
    Table,
    TableHeader,
    TableBody,
    TableRow,
    TableHead,
    TableCell,
} from "@/components/ui/table";
import { useToast } from "@/hooks/useToast";
import { MetricCard } from "@/v2/components/MetricCard";
import { StatusBadge } from "@/v2/components/StatusBadge";

// ─── Helpers ──────────────────────────────────────────────────────────────────

function fmt(n: number): string {
    if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
    if (n >= 1_000) return `${(n / 1_000).toFixed(1)}k`;
    return n.toString();
}

// ─── Stat tile (for the global stats grid) ────────────────────────────────────

function StatTile({
    icon,
    label,
    value,
    accent,
}: {
    icon: React.ReactNode;
    label: string;
    value: string;
    accent?: "amber" | "emerald";
}) {
    const iconClass =
        accent === "amber"
            ? "text-amber-300 border-amber-500/30 bg-amber-500/10"
            : accent === "emerald"
            ? "text-emerald-300 border-emerald-500/30 bg-emerald-500/10"
            : "text-muted-foreground border-border/40 bg-muted/20";

    return (
        <div
            className="v2-card flex items-center gap-3 p-4"
            style={{ boxShadow: "var(--v2-card-shadow)" }}
        >
            <div className={`h-9 w-9 rounded-lg grid place-items-center border shrink-0 ${iconClass}`}>
                {icon}
            </div>
            <div className="min-w-0">
                <p className="text-[10px] uppercase tracking-wider text-muted-foreground truncate">
                    {label}
                </p>
                <p className="text-xl font-bold tabular-nums text-foreground leading-tight">{value}</p>
            </div>
        </div>
    );
}

// ─── Toggle / Number field helpers ────────────────────────────────────────────

function ToggleField({
    label,
    value,
    onChange,
}: {
    label: string;
    value: boolean;
    onChange: (v: boolean) => void;
}) {
    return (
        <label className="flex items-center gap-2 cursor-pointer text-xs text-foreground select-none">
            <Switch checked={value} onCheckedChange={onChange} />
            <span>{label}</span>
        </label>
    );
}

function NumberField({
    label,
    value,
    onChange,
    placeholder,
    step,
}: {
    label: string;
    value: number | null;
    onChange: (v: number | null) => void;
    placeholder?: string;
    step?: string;
}) {
    return (
        <label className="flex flex-col gap-1">
            <span className="text-[10px] uppercase tracking-wider text-muted-foreground">{label}</span>
            <Input
                type="number"
                step={step ?? "1"}
                value={value ?? ""}
                placeholder={placeholder}
                onChange={(e) => {
                    const v = e.target.value;
                    onChange(v === "" ? null : Number(v));
                }}
                className="h-8 text-xs tabular-nums"
            />
        </label>
    );
}

// ─── Per-host config card ─────────────────────────────────────────────────────

function HostCard({
    host,
    initial,
    onSaved,
}: {
    host: string;
    initial: DomainChallengeConfig;
    onSaved: () => void;
}) {
    const { t } = useTranslation(["challengeladder", "common"]);
    const { toast } = useToast();
    const [cfg, setCfg] = useState<DomainChallengeConfig>(initial);
    const [dirty, setDirty] = useState(false);

    const update = <K extends keyof DomainChallengeConfig>(
        k: K,
        v: DomainChallengeConfig[K],
    ) => {
        setCfg((prev) => ({ ...prev, [k]: v }));
        setDirty(true);
    };

    const save = useMutation({
        mutationFn: () => challengeApi.putHost(host, cfg),
        onSuccess: () => {
            setDirty(false);
            toast({ title: t("saved", { host }) });
            onSaved();
        },
        onError: (e: unknown) => {
            toast({ title: t("saveFailed"), description: String(e), variant: "destructive" });
        },
    });

    const remove = useMutation({
        mutationFn: () => challengeApi.deleteHost(host),
        onSuccess: () => {
            toast({ title: t("cleared", { host }) });
            onSaved();
        },
    });

    return (
        <div
            className="v2-card p-4 space-y-4"
            style={{ boxShadow: "var(--v2-card-shadow)" }}
        >
            {/* Host name + action row */}
            <div className="flex items-center justify-between gap-2">
                <div className="flex items-center gap-2 min-w-0">
                    <code className="text-sm font-semibold text-foreground truncate">{host}</code>
                    {dirty && (
                        <span className="inline-flex items-center rounded border border-amber-500/30 bg-amber-500/10 px-1.5 py-0.5 text-[10px] font-medium text-amber-300">
                            {t("unsaved")}
                        </span>
                    )}
                </div>
                <div className="flex gap-1 shrink-0">
                    <Button
                        size="sm"
                        variant="default"
                        className="h-7 text-xs px-2.5"
                        onClick={() => save.mutate()}
                        disabled={!dirty || save.isPending}
                    >
                        <Save className="h-3 w-3 mr-1" />
                        {t("save")}
                    </Button>
                    <Button
                        size="sm"
                        variant="ghost"
                        className="h-7 w-7 p-0 text-muted-foreground hover:text-destructive"
                        onClick={() => remove.mutate()}
                        disabled={remove.isPending}
                        aria-label={t("removeOverride", { host })}
                    >
                        <Trash2 className="h-3.5 w-3.5" />
                    </Button>
                </div>
            </div>

            {/* Toggle grid */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-x-4 gap-y-3">
                <ToggleField
                    label={t("toggle.argon2Pow")}
                    value={cfg.argon2_pow ?? false}
                    onChange={(v) => update("argon2_pow", v)}
                />
                <ToggleField
                    label={t("toggle.privacyPass")}
                    value={cfg.privacy_pass ?? false}
                    onChange={(v) => update("privacy_pass", v)}
                />
                <ToggleField
                    label={t("toggle.chainedTrust")}
                    value={cfg.chained_trust ?? false}
                    onChange={(v) => update("chained_trust", v)}
                />
                <ToggleField
                    label={t("toggle.adaptive")}
                    value={cfg.adaptive ?? false}
                    onChange={(v) => update("adaptive", v)}
                />
                <ToggleField
                    label={t("toggle.variedErrors")}
                    value={cfg.varied_errors ?? false}
                    onChange={(v) => update("varied_errors", v)}
                />
                <ToggleField
                    label={t("toggle.decoyCaptcha")}
                    value={cfg.decoy_captcha ?? false}
                    onChange={(v) => update("decoy_captcha", v)}
                />
                <ToggleField
                    label={t("toggle.honeypotFields")}
                    value={cfg.honeypot_fields ?? false}
                    onChange={(v) => update("honeypot_fields", v)}
                />
                <ToggleField
                    label={t("toggle.trustForAuth")}
                    value={cfg.trust_for_auth ?? false}
                    onChange={(v) => update("trust_for_auth", v)}
                />
            </div>

            {/* Numeric fields */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 pt-3 border-t border-border/30">
                <NumberField
                    label={t("field.argon2Bits")}
                    value={cfg.argon2_bits ?? null}
                    onChange={(v) => update("argon2_bits", v)}
                    placeholder="18"
                />
                <NumberField
                    label={t("field.argon2MemKb")}
                    value={cfg.argon2_memory_kb ?? null}
                    onChange={(v) => update("argon2_memory_kb", v)}
                    placeholder="65536"
                />
                <NumberField
                    label={t("field.fastTrackThreshold")}
                    value={cfg.fast_track_threshold ?? null}
                    onChange={(v) => update("fast_track_threshold", v)}
                    placeholder="0.75"
                    step="0.05"
                />
                <NumberField
                    label={t("field.attackModeBits")}
                    value={cfg.attack_mode_bits ?? null}
                    onChange={(v) => update("attack_mode_bits", v)}
                    placeholder="4"
                />
            </div>
        </div>
    );
}

// ─── Reference table row ──────────────────────────────────────────────────────

function RefRow({ name, body }: { name: string; body: string }) {
    return (
        <TableRow>
            <TableCell className="py-2 font-mono text-xs text-foreground w-44">{name}</TableCell>
            <TableCell className="py-2 text-xs text-muted-foreground">{body}</TableCell>
        </TableRow>
    );
}

// ─── Per-route PoW difficulty card ───────────────────────────────────────────

function RouteDifficultyCard() {
    const { t } = useTranslation(["challengeladder", "common"]);
    const rd = useQuery({
        queryKey: ["route-difficulty"],
        queryFn: routeDifficultyApi.list,
        refetchInterval: 30_000,
    });

    const data = rd.data;
    const wired = data?.wired === true;

    return (
        <MetricCard
            title={t("routeDifficulty.title")}
            description={t("routeDifficulty.description")}
            noPadding
        >
            {rd.isLoading && (
                <div className="px-5 py-4">
                    <div className="h-20 animate-pulse rounded bg-muted/30" />
                </div>
            )}

            {!rd.isLoading && !wired && (
                <div className="px-5 py-6 flex items-center gap-3 text-sm text-muted-foreground">
                    <Shield className="h-4 w-4 shrink-0 opacity-40" />
                    <span>{t("routeDifficulty.notAttached")}</span>
                </div>
            )}

            {!rd.isLoading && wired && (
                <div className="px-5 py-4 space-y-4">
                    {/* Preset badges */}
                    {(data?.ai_scraper_preset || data?.auth_preset) && (
                        <div className="flex flex-wrap gap-2">
                            {data?.ai_scraper_preset && (
                                <span className="inline-flex items-center rounded border border-violet-500/30 bg-violet-500/10 px-2 py-0.5 text-[10px] font-medium text-violet-300 uppercase tracking-wider">
                                    {t("routeDifficulty.aiScraperPreset")}
                                </span>
                            )}
                            {data?.auth_preset && (
                                <span className="inline-flex items-center rounded border border-sky-500/30 bg-sky-500/10 px-2 py-0.5 text-[10px] font-medium text-sky-300 uppercase tracking-wider">
                                    {t("routeDifficulty.authPreset")}
                                </span>
                            )}
                        </div>
                    )}

                    {/* Empty overrides */}
                    {data?.overrides.length === 0 && (
                        <p className="text-sm text-muted-foreground py-2">
                            {t("routeDifficulty.empty")}
                        </p>
                    )}

                    {/* Overrides table */}
                    {data && data.overrides.length > 0 && (
                        <Table className="w-full">
                            <TableHeader>
                                <TableRow>
                                    <TableHead className="text-left py-2 text-xs uppercase tracking-wider text-muted-foreground">
                                        {t("routeDifficulty.col.host")}
                                    </TableHead>
                                    <TableHead className="text-left py-2 text-xs uppercase tracking-wider text-muted-foreground">
                                        {t("routeDifficulty.col.pathPattern")}
                                    </TableHead>
                                    <TableHead className="text-right py-2 text-xs uppercase tracking-wider text-muted-foreground">
                                        {t("routeDifficulty.col.difficultyBits")}
                                    </TableHead>
                                    <TableHead className="text-left py-2 text-xs uppercase tracking-wider text-muted-foreground">
                                        {t("routeDifficulty.col.forcedKind")}
                                    </TableHead>
                                </TableRow>
                            </TableHeader>
                            <TableBody className="divide-y divide-border/30">
                                {data.overrides.map((row, i) => (
                                    <TableRow key={i}>
                                        <TableCell className="py-2 font-mono text-xs text-foreground">
                                            {row.host}
                                        </TableCell>
                                        <TableCell className="py-2 font-mono text-xs text-muted-foreground">
                                            {row.path_pattern}
                                        </TableCell>
                                        <TableCell className="py-2 text-right tabular-nums text-xs font-semibold text-foreground">
                                            {row.difficulty_bits}
                                        </TableCell>
                                        <TableCell className="py-2 text-xs">
                                            {row.force_kind ? (
                                                <span className="inline-flex items-center rounded border border-amber-500/30 bg-amber-500/10 px-1.5 py-0.5 text-[10px] font-medium text-amber-300">
                                                    {row.force_kind}
                                                </span>
                                            ) : (
                                                <span className="text-muted-foreground">—</span>
                                            )}
                                        </TableCell>
                                    </TableRow>
                                ))}
                            </TableBody>
                        </Table>
                    )}
                </div>
            )}
        </MetricCard>
    );
}

// ─── Main page ────────────────────────────────────────────────────────────────

export function ChallengeLadderPage() {
    const { t } = useTranslation(["challengeladder", "common"]);
    const { toast } = useToast();
    const qc = useQueryClient();
    const [newHost, setNewHost] = useState("");

    const hostsQuery = useQuery({
        queryKey: ["challenge", "hosts"],
        queryFn: challengeApi.listHosts,
        refetchInterval: 10_000,
    });

    const attackMode = useMutation({
        mutationFn: (on: boolean) => challengeApi.setAttackMode(on),
        onSuccess: (res) => {
            qc.invalidateQueries({ queryKey: ["challenge", "hosts"] });
            toast({
                title: res.attack_mode ? t("attackMode.onTitle") : t("attackMode.offTitle"),
                description: res.attack_mode
                    ? t("attackMode.onDesc")
                    : t("attackMode.offDesc"),
            });
        },
        onError: (e: unknown) => {
            toast({ title: t("attackMode.failed"), description: String(e), variant: "destructive" });
        },
    });

    const global = hostsQuery.data?.global;
    const wired = hostsQuery.data?.wired === true;

    return (
        <div className="space-y-8">
            {/* Page header */}
            <div>
                <h1 className="text-2xl font-bold text-foreground tracking-tight">{t("title")}</h1>
                <p className="mt-1 text-sm text-muted-foreground">
                    {t("subtitle")}
                </p>
            </div>

            {/* Not-wired warning */}
            {!wired && (
                <div className="v2-card border-amber-500/30 p-4 text-sm text-amber-200">
                    {t("notWired", {
                        withArsenal: ".with_arsenal()",
                        file: "aegis-pingora.rs",
                    })}
                </div>
            )}

            {/* Loading state */}
            {hostsQuery.isLoading && <Skeleton className="h-32" />}

            {/* Global stat tiles */}
            {global && (
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                    <StatTile
                        icon={<AlertOctagon className="h-4 w-4" />}
                        label={t("stat.attackMode")}
                        value={global.attack_mode ? t("stat.on") : t("stat.off")}
                        accent={global.attack_mode ? "amber" : "emerald"}
                    />
                    <StatTile
                        icon={<Activity className="h-4 w-4" />}
                        label={t("stat.fastTrackHits")}
                        value={fmt(global.fast_track_hits)}
                    />
                    <StatTile
                        icon={<Shield className="h-4 w-4" />}
                        label={t("stat.trustGrants")}
                        value={fmt(global.trust_grants_active)}
                    />
                    <StatTile
                        icon={<Shield className="h-4 w-4" />}
                        label={t("stat.privacyPassIssuers")}
                        value={fmt(global.privacy_pass_issuers)}
                    />
                    <StatTile
                        icon={<Activity className="h-4 w-4" />}
                        label={t("stat.honeypotFills")}
                        value={fmt(global.honeypot_fills_detected)}
                    />
                    <StatTile
                        icon={<Activity className="h-4 w-4" />}
                        label={t("stat.decoyCaptchas")}
                        value={fmt(global.decoy_forms_rendered)}
                    />
                    <StatTile
                        icon={<Activity className="h-4 w-4" />}
                        label={t("stat.variedErrors")}
                        value={fmt(global.varied_errors_rendered)}
                    />
                    <StatTile
                        icon={<Activity className="h-4 w-4" />}
                        label={t("stat.attackModeBumps")}
                        value={fmt(global.attack_mode_bumps)}
                    />
                </div>
            )}

            {/* Attack mode lever */}
            <MetricCard
                title={t("attackMode.title")}
                description={t("attackMode.description")}
            >
                <div className="flex items-center gap-4">
                    <Switch
                        id="attack-mode"
                        aria-label={t("attackMode.ariaLabel")}
                        checked={global?.attack_mode ?? false}
                        onCheckedChange={(on) => attackMode.mutate(on)}
                        disabled={!wired || attackMode.isPending || hostsQuery.isLoading}
                    />
                    <Label htmlFor="attack-mode" className="text-sm text-muted-foreground cursor-pointer">
                        {global?.attack_mode
                            ? t("attackMode.inAttack")
                            : t("attackMode.baseline")}
                        {global?.attack_mode && (
                            <strong className="ml-1 text-amber-300">
                                {global.config.attack_mode_bits}
                            </strong>
                        )}
                    </Label>
                    {global?.attack_mode && (
                        <StatusBadge state="standby" label={t("attackMode.badgeOn")} className="ml-auto" />
                    )}
                    {!global?.attack_mode && global && (
                        <StatusBadge state="active" label={t("attackMode.badgeBaseline")} className="ml-auto" />
                    )}
                </div>
            </MetricCard>

            {/* Per-domain overrides */}
            <MetricCard
                title={t("overrides.title")}
                description={t("overrides.description")}
            >
                <div className="space-y-5">
                    {/* Add host input */}
                    <div className="flex gap-2 items-end">
                        <div className="flex-1">
                            <Label htmlFor="new-host" className="text-xs text-muted-foreground mb-1 block">
                                {t("overrides.addHost")}
                            </Label>
                            <Input
                                id="new-host"
                                value={newHost}
                                placeholder={t("overrides.hostPlaceholder")}
                                onChange={(e) => setNewHost(e.target.value)}
                                disabled={!wired}
                                className="h-9"
                            />
                        </div>
                        <Button
                            className="h-9"
                            onClick={async () => {
                                if (!newHost) return;
                                await challengeApi.putHost(newHost, {});
                                setNewHost("");
                                qc.invalidateQueries({ queryKey: ["challenge", "hosts"] });
                            }}
                            disabled={!wired || !newHost}
                        >
                            {t("overrides.add")}
                        </Button>
                    </div>

                    {/* Empty state */}
                    {hostsQuery.data?.hosts.length === 0 && (
                        <p className="text-sm text-muted-foreground py-2">
                            {t("overrides.empty")}
                        </p>
                    )}

                    {/* Host cards */}
                    <div className="space-y-3">
                        {hostsQuery.data?.hosts.map((entry) => (
                            <HostCard
                                key={entry.host}
                                host={entry.host}
                                initial={entry.config}
                                onSaved={() =>
                                    qc.invalidateQueries({ queryKey: ["challenge", "hosts"] })
                                }
                            />
                        ))}
                    </div>
                </div>
            </MetricCard>

            {/* Per-route PoW difficulty */}
            <RouteDifficultyCard />

            {/* Module reference */}
            <MetricCard
                title={t("reference.title")}
                description={t("reference.description")}
                noPadding
            >
                <div className="px-5 py-4">
                    <Table className="w-full">
                        <TableHeader>
                            <TableRow>
                                <TableHead className="text-left py-2 text-xs uppercase tracking-wider text-muted-foreground w-44">
                                    {t("reference.col.toggle")}
                                </TableHead>
                                <TableHead className="text-left py-2 text-xs uppercase tracking-wider text-muted-foreground">
                                    {t("reference.col.effect")}
                                </TableHead>
                            </TableRow>
                        </TableHeader>
                        <TableBody className="divide-y divide-border/30">
                            <RefRow
                                name={t("reference.argon2Pow.name")}
                                body={t("reference.argon2Pow.effect")}
                            />
                            <RefRow
                                name={t("reference.privacyPass.name")}
                                body={t("reference.privacyPass.effect")}
                            />
                            <RefRow
                                name={t("reference.chainedTrust.name")}
                                body={t("reference.chainedTrust.effect")}
                            />
                            <RefRow
                                name={t("reference.adaptive.name")}
                                body={t("reference.adaptive.effect")}
                            />
                            <RefRow
                                name={t("reference.variedErrors.name")}
                                body={t("reference.variedErrors.effect")}
                            />
                            <RefRow
                                name={t("reference.decoyCaptcha.name")}
                                body={t("reference.decoyCaptcha.effect")}
                            />
                            <RefRow
                                name={t("reference.honeypotFields.name")}
                                body={t("reference.honeypotFields.effect")}
                            />
                            <RefRow
                                name={t("reference.trustForAuth.name")}
                                body={t("reference.trustForAuth.effect")}
                            />
                        </TableBody>
                    </Table>
                </div>
            </MetricCard>
        </div>
    );
}
