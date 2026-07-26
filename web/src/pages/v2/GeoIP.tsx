/**
 * V2 GeoIP — /v2/geoip
 *
 * Country-based deny rules and ASN enrichment. Mirrors V1 GeoIPPage
 * data-fetching exactly; only the presentation layer changes.
 *
 * Data sources:
 *   geoipApi.status()   — database load state + paths
 *   geoipApi.lookup()   — per-IP lookup mutation
 */

import { useState } from "react";
import { useTranslation } from "react-i18next";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Globe2, Search, RefreshCw } from "lucide-react";
import { geoipApi } from "@/api/client";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState } from "@/components/ErrorState";
import { useToast } from "@/hooks/useToast";
import { MetricCard } from "@/v2/components/MetricCard";
import { SectionHeader } from "@/v2/components/SectionHeader";
import { StatusBadge } from "@/v2/components/StatusBadge";

export function GeoIPV2Page() {
    const { t } = useTranslation(["geoip", "common"]);
    const status = useQuery({
        queryKey: ["geoip"],
        queryFn: geoipApi.status,
        refetchInterval: 60_000,
    });
    const [ip, setIp] = useState("");
    const { toast } = useToast();
    const lookup = useMutation({
        mutationFn: () => geoipApi.lookup(ip),
        onError: (e) =>
            toast({ title: t("lookupFailed"), description: String(e), variant: "destructive" }),
    });
    const update = useMutation({
        mutationFn: () => geoipApi.update(),
        onSuccess: (r) =>
            toast({ title: t("updateStarted"), description: r.note, variant: "success" }),
        onError: (e) =>
            toast({ title: t("updateFailed"), description: String(e), variant: "destructive" }),
    });

    // Human-readable build date from the mmdb metadata epoch.
    const buildEpoch = status.data?.build_epoch ?? null;
    const buildDateLabel =
        buildEpoch && buildEpoch > 0
            ? new Date(buildEpoch * 1000).toLocaleDateString([], {
                  year: "numeric",
                  month: "short",
                  day: "numeric",
              })
            : null;

    return (
        <div className="space-y-6">
            {/* Page header */}
            <div>
                <SectionHeader label={t("sectionLabel")} />
                <h1 className="text-2xl font-bold tracking-tight mt-1">{t("title")}</h1>
                <p className="text-sm text-muted-foreground mt-1">
                    {t("subtitlePrefix")}{" "}
                    <code className="font-mono text-[0.7rem]">{t("countryLite")}</code>{" "}
                    {t("subtitleSuffix")}
                </p>
            </div>

            {status.isLoading && <Skeleton className="h-32" />}
            {status.error && (
                <ErrorState title={t("loadError")} error={status.error} />
            )}

            {/* ── Database status ──────────────────────────────────────── */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <MetricCard
                    title={t("geoipDatabase")}
                    description={
                        status.data?.database_type
                            ? buildDateLabel
                                ? t("builtOn", { type: status.data.database_type, date: buildDateLabel })
                                : status.data.database_type
                            : t("bundledDefault")
                    }
                    action={
                        <StatusBadge
                            state={status.data?.loaded ? "active" : "standby"}
                            label={status.data?.loaded ? t("loaded") : t("missing")}
                        />
                    }
                >
                    <div className="space-y-3">
                        <div className="flex items-center gap-3">
                            <Globe2 className="h-5 w-5 text-muted-foreground/60 shrink-0" />
                            <div className="min-w-0">
                                <p className="text-xs font-mono text-muted-foreground break-all">
                                    {status.data?.geoip_db_path ?? t("noDatabaseResolved")}
                                </p>
                            </div>
                        </div>
                        <div className="flex items-center gap-3">
                            <Button
                                size="sm"
                                variant="outline"
                                disabled={update.isPending}
                                onClick={() => update.mutate()}
                                className="flex items-center gap-1.5"
                            >
                                <RefreshCw className={`h-3.5 w-3.5 ${update.isPending ? "animate-spin" : ""}`} />
                                {update.isPending ? t("updating") : t("updateDatabase")}
                            </Button>
                            <span className="text-[0.7rem] text-muted-foreground/70">
                                {t("updateHint")}
                            </span>
                        </div>
                        {status.data?.attribution && (
                            <p className="text-[0.65rem] text-muted-foreground/60">
                                {status.data.attribution}
                            </p>
                        )}
                    </div>
                </MetricCard>

                <MetricCard
                    title={t("asnDatabase")}
                    description={t("asnDescription")}
                    action={
                        <StatusBadge
                            state={status.data?.asn_db_path ? "active" : "standby"}
                            label={status.data?.asn_db_path ? t("loaded") : t("notConfigured")}
                        />
                    }
                >
                    <div className="flex items-center gap-3">
                        <Globe2 className="h-5 w-5 text-muted-foreground/60 shrink-0" />
                        <div className="min-w-0">
                            <p className="text-xs font-mono text-muted-foreground break-all">
                                {status.data?.asn_db_path ?? t("asnNotConfigured")}
                            </p>
                        </div>
                    </div>
                </MetricCard>
            </div>

            {/* ── Configuration reference ──────────────────────────────── */}
            <MetricCard
                title={t("configReference")}
                description={t("configReferenceDesc")}
            >
                <div className="space-y-3">
                    {status.data?.note && (
                        <p className="text-xs text-muted-foreground">{status.data.note}</p>
                    )}
                    <div className="rounded-lg overflow-hidden border border-border/40">
                        <div className="px-3 py-1.5 bg-muted/40 border-b border-border/40">
                            <span className="text-[0.65rem] font-semibold uppercase tracking-wider text-muted-foreground">
                                aegis.conf
                            </span>
                        </div>
                        <pre className="text-xs bg-muted/20 p-4 overflow-x-auto font-mono leading-relaxed text-foreground/90">
{`# Deny countries block
geoip {
    db_path /var/lib/aegis/GeoLite2-Country.mmdb;
    deny_countries [ "CN", "RU", "KP" ];
    attack_mode_only true;   # only enforce during active attack mode
}`}
                        </pre>
                    </div>
                </div>
            </MetricCard>

            {/* ── IP lookup ─────────────────────────────────────────────── */}
            <MetricCard
                title={t("ipLookup")}
                description={t("ipLookupDesc")}
            >
                <div className="space-y-3">
                    <div className="flex gap-2 items-end">
                        <div className="flex-1">
                            <Label
                                htmlFor="v2-geoip-ip"
                                className="text-xs text-muted-foreground mb-1.5 block"
                            >
                                {t("ipAddress")}
                            </Label>
                            <Input
                                id="v2-geoip-ip"
                                value={ip}
                                onChange={(e) => setIp(e.target.value)}
                                placeholder="1.1.1.1"
                                className="font-mono"
                                onKeyDown={(e) => {
                                    if (e.key === "Enter" && ip && !lookup.isPending) {
                                        lookup.mutate();
                                    }
                                }}
                            />
                        </div>
                        <Button
                            onClick={() => lookup.mutate()}
                            disabled={!ip || lookup.isPending}
                        >
                            <Search className="h-3.5 w-3.5 mr-1.5" />
                            {t("lookup")}
                        </Button>
                    </div>

                    {lookup.data && (
                        <div className="rounded-lg border border-border/40 bg-muted/20 overflow-hidden">
                            <div className="px-3 py-1.5 bg-muted/40 border-b border-border/40">
                                <span className="text-[0.65rem] font-semibold uppercase tracking-wider text-muted-foreground">
                                    {t("result")}
                                </span>
                            </div>
                            <pre className="text-xs p-4 overflow-x-auto font-mono leading-relaxed text-foreground/90">
                                {JSON.stringify(lookup.data, null, 2)}
                            </pre>
                        </div>
                    )}
                </div>
            </MetricCard>
        </div>
    );
}
