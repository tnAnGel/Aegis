/**
 * V2 Sites page — /v2/sites
 *
 * Same data and mutations as V1 Sites.tsx (sitesApi.list + sitesApi.remove).
 * Visual treatment: MetricCard wrapper, V2 table styling, StatusBadge for
 * source, SeverityChip-inspired inline badges for TLS. The AddSiteWizard is
 * shared from V1 (it is presentation-agnostic).
 */

import * as React from "react";
import { Trans, useTranslation } from "react-i18next";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Globe2, Plus, Trash2, ShieldCheck } from "lucide-react";
import { sitesApi } from "@/api/client";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import {
    Table,
    TableBody,
    TableCell,
    TableHead,
    TableHeader,
    TableRow,
} from "@/components/ui/table";
import { EmptyState } from "@/components/EmptyState";
import { ErrorState } from "@/components/ErrorState";
import { AddSiteWizard } from "@/components/wizard/AddSiteWizard";
import { useToast } from "@/hooks/useToast";
import { MetricCard } from "@/v2/components/MetricCard";
import { StatusBadge } from "@/v2/components/StatusBadge";
import { cn } from "@/lib/cn";

// ─── Small inline badge for TLS / rate-limit ────────────────────────────────

function InlinePill({
    children,
    variant = "default",
}: {
    children: React.ReactNode;
    variant?: "default" | "success" | "warning" | "muted";
}) {
    const cls: Record<string, string> = {
        default: "bg-primary/15 text-primary border-primary/30",
        success: "bg-green-500/15 text-green-400 border-green-500/30",
        warning: "bg-amber-500/15 text-amber-400 border-amber-500/30",
        muted:   "bg-muted/40 text-muted-foreground border-border/60",
    };
    return (
        <span
            className={cn(
                "inline-flex items-center rounded-md px-1.5 py-0.5 text-[0.65rem]",
                "font-semibold uppercase tracking-wider border",
                cls[variant],
            )}
        >
            {children}
        </span>
    );
}

// ─── Page ────────────────────────────────────────────────────────────────────

export function SitesV2Page() {
    const { t } = useTranslation(["sites", "common"]);
    const [search, setSearch] = React.useState("");
    const [adding, setAdding] = React.useState(false);
    const qc = useQueryClient();
    const { toast } = useToast();

    const sites = useQuery({
        queryKey: ["sites"],
        queryFn: sitesApi.list,
    });

    const remove = useMutation({
        mutationFn: sitesApi.remove,
        onSuccess: (_, host) => {
            toast({
                title: t("toast.deletedTitle", { host }),
                description: t("toast.deletedDescription"),
                variant: "success",
            });
            qc.invalidateQueries({ queryKey: ["sites"] });
        },
        onError: (e) => {
            toast({
                title: t("toast.deleteFailedTitle"),
                description: e instanceof Error ? e.message : String(e),
                variant: "destructive",
            });
        },
    });

    const filtered = (sites.data ?? []).filter((s) =>
        search
            ? s.host.includes(search) || (s.upstream ?? "").includes(search)
            : true,
    );

    return (
        <div className="space-y-6">
            {/* ── Page heading ──────────────────────────────────────────── */}
            <div className="flex items-start justify-between gap-4">
                <div>
                    <h1 className="text-2xl font-bold tracking-tight text-foreground flex items-center gap-2.5">
                        <Globe2 className="h-6 w-6 text-primary" />
                        {t("title")}
                    </h1>
                    <p className="text-sm text-muted-foreground mt-1 max-w-xl">
                        <Trans
                            t={t}
                            i18nKey="subtitle"
                            values={{
                                uiPath: "/var/lib/aegis/sites.d",
                                opsPath: "/etc/aegis/sites-enabled",
                            }}
                            components={[
                                <code className="font-mono text-[0.7rem]" />,
                                <code className="font-mono text-[0.7rem]" />,
                            ]}
                        />
                    </p>
                </div>
                <Button
                    onClick={() => setAdding(true)}
                    className="shrink-0 flex items-center gap-1.5"
                >
                    <Plus className="h-4 w-4" />
                    {t("addSite")}
                </Button>
            </div>

            {/* ── Search bar ────────────────────────────────────────────── */}
            <MetricCard
                title={t("filterTitle")}
                contentClassName="py-3"
            >
                <Input
                    placeholder={t("searchPlaceholder")}
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                    className="max-w-sm bg-background/60 border-border/60"
                />
            </MetricCard>

            {/* ── Sites table ───────────────────────────────────────────── */}
            <MetricCard
                title={t("allSitesTitle")}
                description={
                    sites.data
                        ? t("summary", {
                              count: sites.data.length,
                              managed: sites.data.filter((s) => s.managed).length,
                          })
                        : undefined
                }
                noPadding
            >
                {sites.isLoading ? (
                    <div className="px-5 py-4 space-y-3">
                        <Skeleton className="h-8 w-full" />
                        <Skeleton className="h-8 w-full" />
                        <Skeleton className="h-8 w-3/4" />
                    </div>
                ) : sites.isError ? (
                    <div className="p-6">
                        <ErrorState
                            error={sites.error}
                            onRetry={() => sites.refetch()}
                        />
                    </div>
                ) : filtered.length === 0 ? (
                    <div className="p-8">
                        <EmptyState
                            icon={<Globe2 />}
                            title={t("empty.title")}
                            description={t("empty.description", {
                                path: "/etc/aegis/sites-enabled/",
                            })}
                            action={
                                <Button onClick={() => setAdding(true)}>
                                    <Plus className="h-4 w-4" />
                                    {t("addSite")}
                                </Button>
                            }
                        />
                    </div>
                ) : (
                    <Table>
                        <TableHeader>
                            <TableRow className="border-b border-border/60 hover:bg-transparent">
                                <TableHead className="text-muted-foreground text-xs uppercase tracking-wider font-medium px-5">
                                    {t("col.host")}
                                </TableHead>
                                <TableHead className="text-muted-foreground text-xs uppercase tracking-wider font-medium">
                                    {t("col.upstream")}
                                </TableHead>
                                <TableHead className="text-muted-foreground text-xs uppercase tracking-wider font-medium">
                                    {t("col.tls")}
                                </TableHead>
                                <TableHead className="text-muted-foreground text-xs uppercase tracking-wider font-medium">
                                    {t("col.rateLimit")}
                                </TableHead>
                                <TableHead className="text-muted-foreground text-xs uppercase tracking-wider font-medium">
                                    {t("col.source")}
                                </TableHead>
                                <TableHead className="text-right text-muted-foreground text-xs uppercase tracking-wider font-medium pr-5">
                                    {t("col.actions")}
                                </TableHead>
                            </TableRow>
                        </TableHeader>
                        <TableBody>
                            {filtered.map((s) => (
                                <TableRow
                                    key={s.host}
                                    className="v2-table-row cursor-pointer"
                                    onClick={() => {
                                        window.location.href = `/admin/ui/sites/${encodeURIComponent(s.host)}`;
                                    }}
                                >
                                    <TableCell className="px-5 py-3 font-medium">
                                        <a
                                            href={`/admin/ui/sites/${encodeURIComponent(s.host)}`}
                                            className="hover:text-primary transition-colors flex items-center gap-1.5"
                                            onClick={(e) => e.stopPropagation()}
                                        >
                                            <Globe2 className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
                                            {s.host}
                                        </a>
                                    </TableCell>
                                    <TableCell className="font-mono text-xs text-muted-foreground">
                                        {s.upstream ?? (
                                            <span className="text-muted-foreground/50 italic">
                                                {t("upstream.none")}
                                            </span>
                                        )}
                                    </TableCell>
                                    <TableCell>
                                        {s.tls ? (
                                            <span className="flex items-center gap-1">
                                                <ShieldCheck className="h-3.5 w-3.5 text-green-400" />
                                                <InlinePill variant="success">TLS</InlinePill>
                                            </span>
                                        ) : (
                                            <span className="text-xs text-muted-foreground/60 italic">
                                                {t("tls.plain")}
                                            </span>
                                        )}
                                    </TableCell>
                                    <TableCell className="text-xs v2-table-num">
                                        {s.rate_limit ? (
                                            <span className="font-mono">
                                                {t("rateLimit.value", {
                                                    rps: s.rate_limit.rps,
                                                    burst: s.rate_limit.burst,
                                                })}
                                            </span>
                                        ) : (
                                            <span className="text-muted-foreground/60 italic">
                                                {t("rateLimit.default")}
                                            </span>
                                        )}
                                    </TableCell>
                                    <TableCell>
                                        <StatusBadge
                                            state={s.managed ? "active" : "standby"}
                                            label={s.managed ? t("source.ui") : t("source.ops")}
                                        />
                                    </TableCell>
                                    <TableCell className="text-right pr-5">
                                        {s.managed ? (
                                            <Button
                                                variant="ghost"
                                                size="icon"
                                                className="h-7 w-7 hover:bg-destructive/15 hover:text-destructive transition-colors"
                                                onClick={(e) => {
                                                    e.stopPropagation();
                                                    if (confirm(t("confirmDelete", { host: s.host }))) {
                                                        remove.mutate(s.host);
                                                    }
                                                }}
                                                disabled={remove.isPending}
                                                aria-label={t("deleteAria", { host: s.host })}
                                            >
                                                <Trash2 className="h-3.5 w-3.5" />
                                            </Button>
                                        ) : (
                                            <span className="text-xs text-muted-foreground/50 italic">
                                                {t("readOnly")}
                                            </span>
                                        )}
                                    </TableCell>
                                </TableRow>
                            ))}
                        </TableBody>
                    </Table>
                )}
            </MetricCard>

            {/* ── Summary row ───────────────────────────────────────────── */}
            {sites.data && sites.data.length > 0 && (
                <div className="grid grid-cols-3 gap-4">
                    <MetricCard title={t("kpi.totalSites")}>
                        <p className="v2-kpi-number text-2xl font-bold tabular-nums text-foreground">
                            {sites.data.length}
                        </p>
                        <p className="text-xs text-muted-foreground mt-1">
                            {t("kpi.totalSitesHint")}
                        </p>
                    </MetricCard>
                    <MetricCard title={t("kpi.tlsEnabled")}>
                        <p className="v2-kpi-number text-2xl font-bold tabular-nums text-green-400">
                            {sites.data.filter((s) => s.tls).length}
                        </p>
                        <p className="text-xs text-muted-foreground mt-1">
                            {t("kpi.tlsEnabledHint")}
                        </p>
                    </MetricCard>
                    <MetricCard title={t("kpi.uiManaged")}>
                        <p className="v2-kpi-number text-2xl font-bold tabular-nums text-foreground">
                            {sites.data.filter((s) => s.managed).length}
                        </p>
                        <p className="text-xs text-muted-foreground mt-1">
                            {t("kpi.uiManagedHint")}
                        </p>
                    </MetricCard>
                </div>
            )}

            {/* ── Note ──────────────────────────────────────────────────── */}
            <p className="text-[0.7rem] text-muted-foreground/60 italic px-1">
                {t("note")}
            </p>

            <AddSiteWizard open={adding} onOpenChange={setAdding} />
        </div>
    );
}
