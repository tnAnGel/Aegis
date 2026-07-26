// V2 — Updates page.
//
// Presentation-only redesign; all data-fetching + mutations are
// identical to V1. Wires: updatesApi.status / releases / check / setConfig.
// Layout: MetricCard + SectionHeader + StatusBadge from V2 primitives.
// No Card/CardHeader/CardContent from V1 UI — do NOT import those here.

import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
    RefreshCw,
    Download,
    AlertCircle,
    Clock,
    Tag,
    Package,
    ExternalLink,
} from "lucide-react";
import { updatesApi } from "@/api/client";
import type { UpdateChannel, UpdateConfig, UpdateStatus } from "@/api/client";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useToast } from "@/hooks/useToast";
import {
    Select,
    SelectTrigger,
    SelectValue,
    SelectContent,
    SelectItem,
} from "@/components/ui/select";
import { MetricCard } from "@/v2/components/MetricCard";
import { SectionHeader } from "@/v2/components/SectionHeader";
import { StatusBadge } from "@/v2/components/StatusBadge";

// ─── Types ────────────────────────────────────────────────────────────

type StatusData = (UpdateStatus & { wired?: boolean; note?: string }) | undefined;

// ─── Helper: format bytes ─────────────────────────────────────────────

function formatBytes(n: number): string {
    if (n > 1_000_000) return `${(n / 1_000_000).toFixed(1)} MB`;
    if (n > 1_000) return `${(n / 1_000).toFixed(1)} KB`;
    return `${n} B`;
}

// ─── Channel badge ─────────────────────────────────────────────────────

function ChannelPill({ channel }: { channel: string }) {
    const style =
        channel === "stable"
            ? "bg-emerald-500/10 text-emerald-300 border-emerald-500/30"
            : channel === "beta"
              ? "bg-amber-500/10 text-amber-300 border-amber-500/30"
              : "bg-violet-500/10 text-violet-300 border-violet-500/30";
    return (
        <span
            className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg border text-xs font-semibold uppercase tracking-wider ${style}`}
        >
            {channel}
        </span>
    );
}

// ─── Version tile ─────────────────────────────────────────────────────

function VersionTile({
    label,
    ver,
    isNew,
    lastChecked,
    onCheck,
    checking,
}: {
    label: string;
    ver: string;
    isNew?: boolean;
    lastChecked?: string;
    onCheck?: () => void;
    checking?: boolean;
}) {
    const { t } = useTranslation("updates");
    return (
        <div className="rounded-xl border border-border/50 bg-card px-5 py-4 flex flex-col gap-2">
            <div className="flex items-center justify-between gap-2">
                <SectionHeader label={label} />
                {onCheck && (
                    <Button
                        size="sm"
                        variant="outline"
                        onClick={onCheck}
                        disabled={checking}
                        className="h-7 text-xs gap-1"
                    >
                        <RefreshCw className={`h-3 w-3 ${checking ? "animate-spin" : ""}`} />
                        {t("checkNow")}
                    </Button>
                )}
            </div>
            <div className="flex items-baseline gap-2">
                <span className="text-2xl font-mono font-bold text-foreground tabular-nums">
                    {ver}
                </span>
                {isNew && (
                    <span className="text-xs bg-primary/15 text-primary border border-primary/30 rounded-md px-1.5 py-0.5 font-semibold uppercase tracking-wider">
                        {t("new")}
                    </span>
                )}
            </div>
            {lastChecked && (
                <p className="text-xs text-muted-foreground">
                    {t("lastCheck", { time: lastChecked })}
                </p>
            )}
        </div>
    );
}

// ─── Changelog body ───────────────────────────────────────────────────

function ChangelogBody({ body }: { body: string }) {
    const { t } = useTranslation("updates");
    return (
        <pre className="text-xs whitespace-pre-wrap font-sans bg-background/60 border border-border/30 rounded-xl p-4 max-h-80 overflow-y-auto text-muted-foreground">
            {body || t("noChangelog")}
        </pre>
    );
}

// ─── New version banner ───────────────────────────────────────────────

function NewVersionBanner({
    release,
    currentVersion,
}: {
    release: {
        tag_name: string;
        name: string;
        body: string;
        published_at: string;
        assets: { name: string; size: number; url: string }[];
    };
    currentVersion: string;
}) {
    const { t } = useTranslation("updates");
    return (
        <MetricCard
            title={t("updateAvailable")}
            description={t("updateAvailable.description", {
                date: new Date(release.published_at).toLocaleString(),
                version: currentVersion,
            })}
            action={
                <span className="flex items-center gap-1.5">
                    <Download className="h-3.5 w-3.5 text-primary" />
                    <span className="text-primary font-semibold">{release.tag_name}</span>
                </span>
            }
        >
            <div className="space-y-4">
                <ChangelogBody body={release.body} />
                {release.assets.length > 0 && (
                    <div className="space-y-1.5">
                        <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                            {t("downloads")}
                        </p>
                        {release.assets.map((a) => (
                            <a
                                key={a.name}
                                href={a.url}
                                className="flex items-center gap-2 text-xs text-primary hover:underline"
                                target="_blank"
                                rel="noreferrer"
                            >
                                <ExternalLink className="h-3 w-3 shrink-0" />
                                {a.name}
                                <span className="text-muted-foreground">({formatBytes(a.size)})</span>
                            </a>
                        ))}
                    </div>
                )}
            </div>
        </MetricCard>
    );
}

// ─── Manual install instructions ─────────────────────────────────────

function ManualInstallCard({ latestTag }: { latestTag?: string }) {
    const { t } = useTranslation("updates");
    return (
        <MetricCard
            title={t("howToUpdate")}
            description={t("howToUpdate.description")}
        >
            <div className="space-y-4 text-sm">
                <ol className="list-decimal list-inside space-y-1.5 text-muted-foreground">
                    <li>
                        {t("howToUpdate.step1")}
                        {latestTag ? (
                            <>
                                {t("howToUpdate.step1Latest.pre")}
                                <code className="font-mono bg-muted/60 px-1 rounded text-foreground/80">
                                    {latestTag}
                                </code>
                                {t("howToUpdate.step1Latest.post")}
                            </>
                        ) : null}
                        {t("howToUpdate.step1End")}
                    </li>
                    <li>{t("howToUpdate.step2")}</li>
                    <li>{t("howToUpdate.step3")}</li>
                </ol>
                <pre className="rounded-xl border border-border/40 bg-muted/30 p-3 font-mono text-xs overflow-x-auto select-all">
                    sudo bash install.sh
                </pre>
                <p className="text-xs text-muted-foreground">
                    {t("howToUpdate.note")}
                </p>
            </div>
        </MetricCard>
    );
}

// ─── Release row ──────────────────────────────────────────────────────

function ReleaseRow({
    release,
    isCurrent,
}: {
    release: {
        tag_name: string;
        name: string;
        body: string;
        published_at: string;
        prerelease: boolean;
    };
    isCurrent: boolean;
}) {
    const { t } = useTranslation("updates");
    const [expanded, setExpanded] = useState(false);
    const summary = useMemo(
        // null-safe: a release can have an empty/absent body.
        () => (release.body ?? "").split("\n").slice(0, 4).join("\n"),
        [release.body],
    );

    return (
        <div
            className={`rounded-xl border px-4 py-3 space-y-2 transition-colors ${
                isCurrent
                    ? "border-emerald-500/30 bg-emerald-500/5"
                    : "border-border/40 hover:border-border/60"
            }`}
        >
            <div className="flex items-center justify-between gap-2">
                <div className="flex items-center gap-2 min-w-0 flex-wrap">
                    <code className="font-mono font-semibold text-sm text-foreground">
                        {release.tag_name}
                    </code>
                    {isCurrent && (
                        <StatusBadge state="active" label={t("running")} />
                    )}
                    {release.prerelease && (
                        <span className="text-[10px] uppercase tracking-widest text-amber-400 bg-amber-500/10 border border-amber-500/30 rounded px-1.5 py-0.5 font-semibold">
                            {t("preRelease")}
                        </span>
                    )}
                </div>
                <div className="flex items-center gap-1.5 text-xs text-muted-foreground shrink-0">
                    <Clock className="h-3 w-3" />
                    {new Date(release.published_at).toLocaleDateString()}
                </div>
            </div>
            {release.body.length > 0 && (
                <>
                    <pre className="text-xs text-muted-foreground whitespace-pre-wrap font-sans leading-relaxed">
                        {expanded ? release.body : summary}
                    </pre>
                    {release.body.length > summary.length && (
                        <button
                            className="text-xs text-primary hover:underline"
                            onClick={() => setExpanded(!expanded)}
                        >
                            {expanded ? t("collapse") : t("showFullChangelog")}
                        </button>
                    )}
                </>
            )}
        </div>
    );
}

// ─── Config card ──────────────────────────────────────────────────────

function ConfigCard({ status }: { status: NonNullable<StatusData> }) {
    const { t } = useTranslation("updates");
    const { toast } = useToast();
    const qc = useQueryClient();
    const [cfg, setCfg] = useState<UpdateConfig>({
        repo_api_url: status.repo_api_url,
        channel: status.channel,
        current_version: status.current_version,
        poll_interval_secs: 3600,
    });

    const save = useMutation({
        mutationFn: () => updatesApi.setConfig(cfg),
        onSuccess: () => {
            toast({ title: t("config.saved") });
            qc.invalidateQueries({ queryKey: ["updates"] });
        },
    });

    return (
        <MetricCard
            title={t("config.title")}
            description={t("config.description")}
        >
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-1.5">
                    <Label htmlFor="v2-repo" className="text-xs text-muted-foreground uppercase tracking-wider">
                        {t("config.repoUrl")}
                    </Label>
                    <Input
                        id="v2-repo"
                        value={cfg.repo_api_url}
                        onChange={(e) => setCfg({ ...cfg, repo_api_url: e.target.value })}
                        className="font-mono text-xs"
                    />
                </div>
                <div className="space-y-1.5">
                    <Label htmlFor="v2-channel" className="text-xs text-muted-foreground uppercase tracking-wider">
                        {t("config.channel")}
                    </Label>
                    <Select
                        value={cfg.channel}
                        onValueChange={(v) => setCfg({ ...cfg, channel: v as UpdateChannel })}
                    >
                        <SelectTrigger id="v2-channel">
                            <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                            <SelectItem value="stable">{t("channel.stable")}</SelectItem>
                            <SelectItem value="beta">{t("channel.beta")}</SelectItem>
                            <SelectItem value="nightly">{t("channel.nightly")}</SelectItem>
                        </SelectContent>
                    </Select>
                </div>
                <div className="space-y-1.5">
                    <Label htmlFor="v2-interval" className="text-xs text-muted-foreground uppercase tracking-wider">
                        {t("config.pollInterval")}
                    </Label>
                    <Input
                        id="v2-interval"
                        type="number"
                        value={cfg.poll_interval_secs}
                        onChange={(e) =>
                            setCfg({ ...cfg, poll_interval_secs: Number(e.target.value) })
                        }
                    />
                    <p className="text-xs text-muted-foreground">
                        {t("config.pollHint")}
                    </p>
                </div>
                <div className="flex items-end">
                    <Button onClick={() => save.mutate()} disabled={save.isPending}>
                        {t("config.save")}
                    </Button>
                </div>
            </div>
        </MetricCard>
    );
}

// ─── Main page ───────────────────────────────────────────────────────

export function UpdatesPage() {
    const { t } = useTranslation(["updates", "common"]);
    const { toast } = useToast();
    const qc = useQueryClient();

    const statusQuery = useQuery({
        queryKey: ["updates", "status"],
        queryFn: updatesApi.status,
        refetchInterval: 60_000,
    });

    const releasesQuery = useQuery({
        queryKey: ["updates", "releases"],
        queryFn: updatesApi.releases,
    });

    const checkNow = useMutation({
        mutationFn: updatesApi.check,
        onSuccess: (res) => {
            qc.invalidateQueries({ queryKey: ["updates"] });
            if (res.ok) {
                toast({
                    title: t("check.completeTitle"),
                    description: res.status.update_available
                        ? t("check.newVersion", { tag: res.status.latest?.tag_name })
                        : t("check.upToDate", { channel: res.status.channel }),
                });
            } else {
                toast({
                    title: t("check.failedTitle"),
                    description: res.error ?? t("check.unknownError"),
                    variant: "destructive",
                });
            }
        },
        onError: (e: unknown) => {
            toast({ title: t("check.failed"), description: String(e), variant: "destructive" });
        },
    });

    const status = statusQuery.data;
    const wired = (status as { wired?: boolean })?.wired !== false;
    const updateAvailable = status?.update_available ?? false;
    const releases = releasesQuery.data ?? [];

    return (
        <div className="space-y-6">
            {/* Page header */}
            <div>
                <h1 className="text-xl font-bold text-foreground flex items-center gap-2">
                    <Package className="h-5 w-5 text-primary" />
                    {t("title")}
                </h1>
                <p className="text-sm text-muted-foreground mt-1">
                    {t("description")}
                </p>
            </div>

            {/* Not-wired warning */}
            {!wired && (
                <div className="flex items-start gap-3 rounded-xl border border-amber-500/30 bg-amber-500/8 px-4 py-3 text-sm text-amber-200">
                    <AlertCircle className="h-4 w-4 mt-0.5 shrink-0 text-amber-400" />
                    <div>{t("notWired.body")}</div>
                </div>
            )}

            {/* Version overview — 3-up */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                <VersionTile
                    label={t("runningVersion")}
                    ver={status?.current_version ?? "?"}
                />
                <VersionTile
                    label={t("latestAvailable")}
                    ver={status?.latest?.tag_name ?? "—"}
                    isNew={status?.update_available}
                    lastChecked={
                        status?.last_checked_at
                            ? new Date(status.last_checked_at * 1000).toLocaleString()
                            : t("never")
                    }
                    onCheck={() => checkNow.mutate()}
                    checking={checkNow.isPending}
                />
                <div className="rounded-xl border border-border/50 bg-card px-5 py-4 flex flex-col gap-2">
                    <SectionHeader label={t("releaseChannel")} />
                    <div className="mt-1">
                        <ChannelPill channel={status?.channel ?? "stable"} />
                    </div>
                    <p className="text-xs text-muted-foreground mt-1">
                        {status?.channel === "stable" && t("channelDesc.stable")}
                        {status?.channel === "beta" && t("channelDesc.beta")}
                        {status?.channel === "nightly" && t("channelDesc.nightly")}
                        {!status?.channel && t("channelDesc.none")}
                    </p>
                </div>
            </div>

            {/* Last error */}
            {status?.last_error && (
                <MetricCard title={t("lastCheckError")}>
                    <pre className="text-xs bg-muted/30 p-3 rounded-xl overflow-x-auto whitespace-pre-wrap text-destructive">
                        {status.last_error}
                    </pre>
                </MetricCard>
            )}

            {/* Update available banner */}
            {updateAvailable && status?.latest && (
                <NewVersionBanner
                    release={status.latest}
                    currentVersion={status.current_version}
                />
            )}

            {/* Manual install instructions */}
            <ManualInstallCard latestTag={status?.latest?.tag_name} />

            {/* Release history */}
            <MetricCard
                title={t("releaseHistory")}
                description={t("releaseHistory.description")}
                action={
                    <span className="flex items-center gap-1.5 text-muted-foreground">
                        <Tag className="h-3.5 w-3.5" />
                        {t("releaseHistory.count", { count: releases.length })}
                    </span>
                }
            >
                {releases.length === 0 ? (
                    <p className="text-sm text-muted-foreground py-2">
                        {t("releaseHistory.empty")}
                    </p>
                ) : (
                    <div className="space-y-2">
                        {releases.slice(0, 20).map((r) => (
                            <ReleaseRow
                                key={r.tag_name}
                                release={r}
                                isCurrent={
                                    r.tag_name.replace(/^v/, "") === status?.current_version
                                }
                            />
                        ))}
                    </div>
                )}
            </MetricCard>

            {/* Config card (only when wired) */}
            {wired && status && <ConfigCard status={status} />}
        </div>
    );
}
