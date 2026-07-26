/**
 * V2 RateLimits page — /v2/rate-limits
 *
 * Mirrors the rate-limits editor from V1 RateLimits.tsx, restyled with V2
 * MetricCard chrome and dark-palette table rows. All react-query hooks and
 * mutations are identical to V1 — only presentation changes.
 */

import * as React from "react";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Gauge, Pencil, Save, X } from "lucide-react";
import { opsApi, sitesApi } from "@/api/client";
import type { Site, NewSite } from "@/types";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { EmptyState } from "@/components/EmptyState";
import { useToast } from "@/hooks/useToast";
import { MetricCard } from "@/v2/components/MetricCard";
import { SectionHeader } from "@/v2/components/SectionHeader";
import { StatusBadge } from "@/v2/components/StatusBadge";
import { cn } from "@/lib/cn";

// ─── Helpers ──────────────────────────────────────────────────────────────────

/** Small ops-mode badge for unmanaged sites. */
function OpsBadge({ t }: { t: TFunction }) {
    return (
        <span className="ml-2 inline-flex items-center rounded px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-wider border border-border/50 text-muted-foreground bg-muted/30">
            {t("opsBadge")}
        </span>
    );
}

/** Styled inline value — muted italic for defaults, bold for overrides. */
function RateValue({
    value,
    isOverride,
    t,
}: {
    value: number | null | undefined;
    isOverride: boolean;
    t: TFunction;
}) {
    if (value == null || !isOverride) {
        return (
            <span className="text-xs text-muted-foreground italic tabular-nums">{t("value.default")}</span>
        );
    }
    return (
        <span className="text-xs font-semibold tabular-nums" style={{ fontVariantNumeric: "tabular-nums" }}>
            {value}
        </span>
    );
}

// ─── Table header ──────────────────────────────────────────────────────────────

function TableHead({ children, right }: { children: React.ReactNode; right?: boolean }) {
    return (
        <th
            className={cn(
                "px-4 py-2.5 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground border-b border-border/50",
                right && "text-right",
            )}
        >
            {children}
        </th>
    );
}

function TableCell({
    children,
    right,
    className,
}: {
    children: React.ReactNode;
    right?: boolean;
    className?: string;
}) {
    return (
        <td
            className={cn(
                "px-4 py-3 text-sm",
                right && "text-right",
                "border-b border-border/20 last:border-0",
                className,
            )}
        >
            {children}
        </td>
    );
}

// ─── Display row ──────────────────────────────────────────────────────────────

function DisplayRow({ site, onEdit, t }: { site: Site; onEdit: () => void; t: TFunction }) {
    const hasOverride = !!site.rate_limit;
    return (
        <tr className="v2-table-row">
            <TableCell>
                <span className="font-medium text-foreground text-xs">
                    {site.host}
                </span>
                {!site.managed && <OpsBadge t={t} />}
            </TableCell>
            <TableCell>
                <RateValue value={site.rate_limit?.rps} isOverride={hasOverride} t={t} />
            </TableCell>
            <TableCell>
                <RateValue value={site.rate_limit?.burst} isOverride={hasOverride} t={t} />
            </TableCell>
            <TableCell right>
                {site.managed ? (
                    <Button
                        variant="ghost"
                        size="sm"
                        className="h-7 text-xs text-muted-foreground hover:text-foreground"
                        onClick={onEdit}
                    >
                        <Pencil className="h-3 w-3 mr-1" />
                        {hasOverride ? t("action.edit") : t("action.set")}
                    </Button>
                ) : (
                    <span className="text-[10px] text-muted-foreground/60 font-mono">
                        {t("action.editConf")}
                    </span>
                )}
            </TableCell>
        </tr>
    );
}

// ─── Edit row ─────────────────────────────────────────────────────────────────

function EditRow({
    site,
    onCancel,
    onSave,
    busy,
    t,
}: {
    site: Site;
    onCancel: () => void;
    onSave: (rl: { rps: number; burst: number } | null) => void;
    busy: boolean;
    t: TFunction;
}) {
    const [rps, setRps] = React.useState(String(site.rate_limit?.rps ?? ""));
    const [burst, setBurst] = React.useState(String(site.rate_limit?.burst ?? ""));

    const submit = () => {
        if (busy) return;
        const rpsN = Number.parseInt(rps, 10);
        const burstN = Number.parseInt(burst, 10);
        if (!Number.isFinite(rpsN) || rpsN <= 0) return;
        if (!Number.isFinite(burstN) || burstN <= 0) return;
        onSave({ rps: rpsN, burst: burstN });
    };

    return (
        <tr className="bg-primary/5 border-b border-border/30">
            <TableCell>
                <span className="font-medium text-xs">{site.host}</span>
            </TableCell>
            <TableCell>
                <Input
                    type="number"
                    min={1}
                    value={rps}
                    onChange={(e) => setRps(e.target.value)}
                    onKeyDown={(e) => {
                        if (e.key === "Enter") submit();
                        if (e.key === "Escape") onCancel();
                    }}
                    placeholder={t("edit.placeholderRps")}
                    className="h-7 w-24 text-xs bg-background/60"
                    autoFocus
                />
            </TableCell>
            <TableCell>
                <Input
                    type="number"
                    min={1}
                    value={burst}
                    onChange={(e) => setBurst(e.target.value)}
                    onKeyDown={(e) => {
                        if (e.key === "Enter") submit();
                        if (e.key === "Escape") onCancel();
                    }}
                    placeholder={t("edit.placeholderBurst")}
                    className="h-7 w-24 text-xs bg-background/60"
                />
            </TableCell>
            <TableCell right>
                <div className="flex items-center justify-end gap-1.5">
                    {site.rate_limit && (
                        <Button
                            size="sm"
                            variant="ghost"
                            className="h-7 text-xs text-muted-foreground"
                            onClick={() => onSave(null)}
                            disabled={busy}
                            title={t("edit.clearTooltip")}
                        >
                            {t("edit.clear")}
                        </Button>
                    )}
                    <Button
                        size="sm"
                        variant="ghost"
                        className="h-7"
                        onClick={onCancel}
                        disabled={busy}
                        aria-label={t("edit.cancel")}
                    >
                        <X className="h-3.5 w-3.5" />
                    </Button>
                    <Button size="sm" className="h-7 text-xs" onClick={submit} disabled={busy}>
                        <Save className="h-3.5 w-3.5 mr-1" />
                        {busy ? t("edit.saving") : t("edit.save")}
                    </Button>
                </div>
            </TableCell>
        </tr>
    );
}

// ─── Sites rate table ─────────────────────────────────────────────────────────

function SitesRateTable({ sites, t }: { sites: Site[]; t: TFunction }) {
    const [editingHost, setEditingHost] = React.useState<string | null>(null);
    const qc = useQueryClient();
    const { toast } = useToast();

    const save = useMutation({
        mutationFn: (s: NewSite) => sitesApi.update(s),
        onSuccess: () => {
            qc.invalidateQueries({ queryKey: ["sites"] });
            setEditingHost(null);
            toast({
                title: t("toast.savedTitle"),
                description: t("toast.savedDesc"),
                variant: "success",
            });
        },
        onError: (e: unknown) => {
            toast({ title: t("toast.failedTitle"), description: String(e), variant: "destructive" });
        },
    });

    return (
        <div className="overflow-x-auto">
            <table className="w-full">
                <thead>
                    <tr>
                        <TableHead>{t("col.host")}</TableHead>
                        <TableHead>{t("col.rps")}</TableHead>
                        <TableHead>{t("col.burst")}</TableHead>
                        <TableHead right>{t("col.action")}</TableHead>
                    </tr>
                </thead>
                <tbody>
                    {sites.map((s) =>
                        editingHost === s.host ? (
                            <EditRow
                                key={s.host}
                                site={s}
                                onCancel={() => setEditingHost(null)}
                                onSave={(rl) =>
                                    save.mutate({
                                        host: s.host,
                                        upstream: s.upstream ?? "",
                                        tls: s.tls,
                                        h3: false,
                                        ssl_cert: null,
                                        ssl_key: null,
                                        rate_limit: rl,
                                    })
                                }
                                busy={save.isPending}
                                t={t}
                            />
                        ) : (
                            <DisplayRow
                                key={s.host}
                                site={s}
                                onEdit={() => setEditingHost(s.host)}
                                t={t}
                            />
                        ),
                    )}
                </tbody>
            </table>
        </div>
    );
}

// ─── Main page ────────────────────────────────────────────────────────────────

export function RateLimitsV2Page() {
    const { t } = useTranslation(["ratelimits", "common"]);
    const sites = useQuery({ queryKey: ["sites"], queryFn: sitesApi.list });
    const hotUris = useQuery({
        queryKey: ["hot_uris"],
        queryFn: opsApi.hotUris,
        refetchInterval: 15_000,
    });

    const siteList = sites.data ?? [];
    const hotList = (hotUris.data ?? []).slice(0, 12);

    return (
        <div className="space-y-6">
            {/* Page title */}
            <div>
                <SectionHeader label={t("title")} />
                <p className="text-xs text-muted-foreground mt-1.5 leading-snug">
                    {t("subtitle")}
                </p>
            </div>

            <div className="grid gap-4 grid-cols-1 lg:grid-cols-3">
                {/* Sites table — 2/3 width */}
                <div className="lg:col-span-2">
                    <MetricCard
                        title={t("card.sites.title")}
                        description={t("card.sites.description")}
                        noPadding
                    >
                        {siteList.length === 0 ? (
                            <div className="px-5 py-8">
                                <EmptyState
                                    icon={<Gauge />}
                                    title={t("empty.title")}
                                    description={t("empty.description")}
                                />
                            </div>
                        ) : (
                            <SitesRateTable sites={siteList} t={t} />
                        )}
                    </MetricCard>
                </div>

                {/* Hot URIs — 1/3 width */}
                <MetricCard
                    title={t("card.hot.title")}
                    description={t("card.hot.description")}
                    noPadding
                >
                    {hotList.length === 0 ? (
                        <div className="px-5 py-8 text-xs text-muted-foreground">
                            {t("hot.empty")}
                        </div>
                    ) : (
                        <div className="overflow-x-auto">
                            <table className="w-full">
                                <thead>
                                    <tr>
                                        <th className="px-4 py-2.5 text-left text-[10px] font-semibold uppercase tracking-wider text-muted-foreground border-b border-border/50">
                                            {t("hot.col.uri")}
                                        </th>
                                        <th className="px-4 py-2.5 text-right text-[10px] font-semibold uppercase tracking-wider text-muted-foreground border-b border-border/50">
                                            {t("hot.col.hits")}
                                        </th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {hotList.map((u) => (
                                        <tr key={u.uri} className="v2-table-row">
                                            <td className="px-4 py-2.5 font-mono text-[11px] text-foreground/80 border-b border-border/20 truncate max-w-[160px]">
                                                {u.uri}
                                            </td>
                                            <td className="px-4 py-2.5 text-right text-xs border-b border-border/20 v2-table-num">
                                                {u.hits}
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    )}
                </MetricCard>
            </div>

            {/* Legend / info row */}
            <div className="flex items-center gap-6 text-[11px] text-muted-foreground">
                <span className="flex items-center gap-1.5">
                    <span className="inline-block w-3 h-0.5 bg-primary/60 rounded" />
                    {t("legend.override")}
                </span>
                <span className="flex items-center gap-1.5">
                    <span className="inline-block w-3 h-0.5 bg-muted-foreground/30 rounded" />
                    {t("legend.default")}
                </span>
                <span className="flex items-center gap-1.5">
                    <StatusBadge state="standby" label={t("opsBadge")} />
                    {t("legend.unmanaged")}
                </span>
            </div>
        </div>
    );
}
