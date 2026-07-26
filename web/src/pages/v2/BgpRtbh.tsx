import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import { Radio, Undo2, AlertTriangle, Wifi } from "lucide-react";
import { bgpApi } from "@/api/client";
import type { BgpAnnounce } from "@/api/client";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState } from "@/components/ErrorState";
import { useToast } from "@/hooks/useToast";
import { MetricCard } from "@/v2/components/MetricCard";
import { KPITile } from "@/v2/components/KPITile";
import { StatusBadge } from "@/v2/components/StatusBadge";
import { cn } from "@/lib/cn";

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export function BgpRtbhPage() {
    const { t } = useTranslation(["bgprtbh", "common"]);
    const { toast } = useToast();
    const qc = useQueryClient();

    const q = useQuery({
        queryKey: ["bgp"],
        queryFn: bgpApi.list,
        refetchInterval: 10_000,
    });

    const withdraw = useMutation({
        mutationFn: (ip: string) => bgpApi.withdraw(ip),
        onSuccess: (res) => {
            if (res.ok) {
                toast({ title: t("withdrawn", { ip: res.ip }) });
                void qc.invalidateQueries({ queryKey: ["bgp"] });
            } else {
                toast({ title: t("withdrawFailed"), description: res.error, variant: "destructive" });
            }
        },
    });

    return (
        <div className="space-y-6">
            {/* ── Page header ────────────────────────────────────────────── */}
            <div>
                <h1 className="text-2xl font-bold text-foreground flex items-center gap-2.5">
                    <Radio className="h-6 w-6 text-primary" />
                    {t("title")}
                </h1>
                <p className="text-sm text-muted-foreground mt-1 max-w-2xl">
                    {t("pageDescription")}
                </p>
            </div>

            {q.isLoading && <Skeleton className="h-32" />}
            {q.error && (
                <ErrorState title={t("loadError")} error={q.error} />
            )}

            {/* ── Module not wired banner ─────────────────────────────────── */}
            {q.data && !q.data.wired && (
                <div className="rounded-xl border border-amber-500/40 bg-amber-500/10 p-4 flex items-start gap-3 text-sm text-amber-200">
                    <AlertTriangle className="h-4 w-4 mt-0.5 shrink-0 text-amber-400" />
                    <span>{t("notWired.banner")}</span>
                </div>
            )}

            {/* ── KPI row ────────────────────────────────────────────────── */}
            {q.data && (
                <div className="grid grid-cols-2 gap-3">
                    <KPITile
                        label={t("kpi.activeAnnouncements")}
                        value={q.data.active_count.toLocaleString()}
                        icon={<Wifi className="h-4 w-4" />}
                        valueColor={q.data.active_count > 0 ? "text-amber-400" : "text-foreground"}
                    />
                    <KPITile
                        label={t("kpi.moduleStatus")}
                        value={q.data.wired ? t("status.wired") : t("status.notWired")}
                        icon={<Radio className="h-4 w-4" />}
                        valueColor={q.data.wired ? "text-green-400" : "text-muted-foreground"}
                    />
                </div>
            )}

            {/* ── Active announcements table ───────────────────────────────── */}
            <MetricCard
                title={t("table.title")}
                description={t("table.description")}
                action={
                    q.data ? (
                        <StatusBadge
                            state={q.data.wired ? "active" : "standby"}
                            label={q.data.wired ? t("status.live") : t("status.offline")}
                        />
                    ) : undefined
                }
            >
                {(q.data?.active ?? []).length === 0 ? (
                    <p className="text-sm text-muted-foreground py-2">
                        {t("table.empty")}
                    </p>
                ) : (
                    <AnnouncementsTable
                        rows={q.data?.active ?? []}
                        withdrawing={withdraw.isPending}
                        onWithdraw={(ip) => withdraw.mutate(ip)}
                        t={t}
                    />
                )}
            </MetricCard>
        </div>
    );
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

function AnnouncementsTable({
    rows,
    withdrawing,
    onWithdraw,
    t,
}: {
    rows: BgpAnnounce[];
    withdrawing: boolean;
    onWithdraw: (ip: string) => void;
    t: TFunction;
}) {
    return (
        <div className="overflow-x-auto -mx-1">
            <table className="w-full text-xs min-w-[480px]">
                <thead>
                    <tr>
                        <Th>{t("col.ip")}</Th>
                        <Th>{t("col.community")}</Th>
                        <Th right>{t("col.age")}</Th>
                        <Th right>{t("col.action")}</Th>
                    </tr>
                </thead>
                <tbody className="divide-y divide-border/30">
                    {rows.map((a) => (
                        <AnnouncementRow
                            key={a.ip}
                            announce={a}
                            withdrawing={withdrawing}
                            onWithdraw={onWithdraw}
                            t={t}
                        />
                    ))}
                </tbody>
            </table>
        </div>
    );
}

function Th({
    children,
    right = false,
}: {
    children: React.ReactNode;
    right?: boolean;
}) {
    return (
        <th
            className={cn(
                "py-2 px-1 font-normal text-muted-foreground",
                "v2-section-label text-[9px] border-b border-border/40",
                right ? "text-right" : "text-left",
            )}
        >
            {children}
        </th>
    );
}

function AnnouncementRow({
    announce,
    withdrawing,
    onWithdraw,
    t,
}: {
    announce: BgpAnnounce;
    withdrawing: boolean;
    onWithdraw: (ip: string) => void;
    t: TFunction;
}) {
    return (
        <tr className="v2-table-row">
            <td className="py-2 px-1">
                <code className="font-mono text-xs text-foreground">{announce.ip}</code>
            </td>
            <td className="py-2 px-1">
                <code className="font-mono text-xs text-muted-foreground">
                    {announce.community}
                </code>
            </td>
            <td className="py-2 px-1 text-right v2-table-num text-muted-foreground">
                {t("ageSeconds", { count: announce.age_secs })}
            </td>
            <td className="py-2 px-1 text-right">
                <Button
                    size="sm"
                    variant="outline"
                    onClick={() => onWithdraw(announce.ip)}
                    disabled={withdrawing}
                    className="h-7 text-xs"
                >
                    <Undo2 className="h-3 w-3 mr-1" />
                    {t("withdraw")}
                </Button>
            </td>
        </tr>
    );
}
