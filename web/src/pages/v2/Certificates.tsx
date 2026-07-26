/**
 * V2 Certificates page — /v2/certificates
 *
 * Identical data layer and business logic to V1 (sitesApi, acmeApi,
 * all three mutations: saveConfig / createOrder / renewOrder).
 * Presentation rebuilt with V2 primitives: MetricCard, SeverityChip,
 * StatusBadge from v2/components. Dialog/Input/Switch/Label/Button come
 * from the shared ui/* primitives (unchanged from V1). No V1 Card import.
 *
 * V1 file at /pages/Certificates.tsx is NOT touched.
 */

import * as React from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import {
    AlertTriangle,
    FileLock2,
    Loader2,
    RefreshCw,
    ShieldCheck,
} from "lucide-react";
import { acmeApi, sitesApi } from "@/api/client";
import type { AcmeConfig, AcmeOrder, AcmeOrderStatus } from "@/types";
import { cn } from "@/lib/cn";
import {
    Dialog,
    DialogClose,
    DialogContent,
    DialogDescription,
    DialogFooter,
    DialogHeader,
    DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { useToast } from "@/hooks/useToast";
import { MetricCard } from "@/v2/components/MetricCard";
import { SeverityChip } from "@/v2/components/SeverityChip";
import type { Severity } from "@/v2/components/SeverityChip";

// ─── Severity mapping ─────────────────────────────────────────────────────────

function statusSeverity(status: AcmeOrderStatus): Severity | null {
    switch (status) {
        case "failed":   return "critical";
        case "expiring": return "high";
        case "pending":  return "medium";
        case "issued":   return "low";
        case "idle":     return null;
    }
}

// ─── Status chip ─────────────────────────────────────────────────────────────

function OrderStatusChip({ status }: { status: AcmeOrderStatus }) {
    const { t } = useTranslation("certificates");
    const severity = statusSeverity(status);

    if (severity) {
        return <SeverityChip severity={severity} showLabel />;
    }

    // "idle" — muted pill
    return (
        <span
            className={cn(
                "inline-flex items-center rounded px-2 py-0.5 gap-1",
                "bg-muted/40 border border-border/50",
                "text-[0.65rem] font-semibold uppercase tracking-wider text-muted-foreground",
            )}
        >
            {status === "pending" && <Loader2 className="h-3 w-3 animate-spin" />}
            {status === "pending" ? t("status.pending") : t("status.idle")}
        </span>
    );
}

// ─── Production confirm dialog ────────────────────────────────────────────────

function ProductionConfirmDialog({
    open,
    onConfirm,
    onCancel,
}: {
    open: boolean;
    onConfirm: () => void;
    onCancel: () => void;
}) {
    const { t } = useTranslation("certificates");
    return (
        <Dialog open={open} onOpenChange={(v) => { if (!v) onCancel(); }}>
            <DialogContent className="max-w-lg">
                <DialogHeader>
                    <DialogTitle className="flex items-center gap-2 text-destructive">
                        <AlertTriangle className="h-5 w-5" />
                        {t("prod.title")}
                    </DialogTitle>
                    <DialogDescription className="pt-1 leading-relaxed">
                        {t("prod.body1")}{" "}
                        <strong>{t("prod.rateLimitBold")}</strong>
                        {t("prod.body2")}
                        <br />
                        <br />
                        {t("prod.body3")}{" "}
                        <a
                            href="https://letsencrypt.org/repository/"
                            target="_blank"
                            rel="noreferrer"
                            className="underline text-primary"
                        >
                            {t("prod.agreementLink")}
                        </a>
                        .
                    </DialogDescription>
                </DialogHeader>
                <DialogFooter>
                    <DialogClose asChild>
                        <Button variant="outline" onClick={onCancel}>
                            {t("prod.cancel")}
                        </Button>
                    </DialogClose>
                    <Button variant="destructive" onClick={onConfirm}>
                        {t("prod.confirm")}
                    </Button>
                </DialogFooter>
            </DialogContent>
        </Dialog>
    );
}

// ─── Request cert dialog ──────────────────────────────────────────────────────

function RequestCertDialog({
    host,
    defaultEmail,
    open,
    onClose,
    onSubmit,
    submitting,
}: {
    host: string;
    defaultEmail: string;
    open: boolean;
    onClose: () => void;
    onSubmit: (host: string, email: string) => void;
    submitting: boolean;
}) {
    const { t } = useTranslation("certificates");
    const [email, setEmail] = React.useState(defaultEmail);

    React.useEffect(() => {
        setEmail(defaultEmail);
    }, [defaultEmail]);

    return (
        <Dialog open={open} onOpenChange={(v) => { if (!v) onClose(); }}>
            <DialogContent className="max-w-md">
                <DialogHeader>
                    <DialogTitle>{t("request.title")}</DialogTitle>
                    <DialogDescription>
                        {t("request.description")}
                    </DialogDescription>
                </DialogHeader>

                <div className="space-y-4 py-2">
                    <div className="space-y-1.5">
                        <Label>{t("request.host")}</Label>
                        <Input value={host} disabled />
                    </div>
                    <div className="space-y-1.5">
                        <Label htmlFor="cert-email-v2">
                            {t("request.contactEmail")}{" "}
                            <span className="font-normal text-muted-foreground">{t("request.optional")}</span>
                        </Label>
                        <Input
                            id="cert-email-v2"
                            type="email"
                            placeholder={t("request.emailPlaceholder")}
                            value={email}
                            onChange={(e) => setEmail(e.target.value)}
                        />
                        <p className="text-xs text-muted-foreground">
                            {t("request.emailHint")}
                        </p>
                    </div>
                </div>

                <DialogFooter>
                    <Button variant="outline" onClick={onClose} disabled={submitting}>
                        {t("request.cancel")}
                    </Button>
                    <Button onClick={() => onSubmit(host, email)} disabled={submitting}>
                        {submitting && <Loader2 className="h-4 w-4 animate-spin" />}
                        {t("request.submit")}
                    </Button>
                </DialogFooter>
            </DialogContent>
        </Dialog>
    );
}

// ─── ACME config card ─────────────────────────────────────────────────────────

function AcmeConfigCardV2({
    config,
    onSave,
    saving,
}: {
    config: AcmeConfig;
    onSave: (patch: Partial<AcmeConfig>) => void;
    saving: boolean;
}) {
    const { t } = useTranslation("certificates");
    const [email, setEmail] = React.useState(config.account_email ?? "");
    const [confirmProduction, setConfirmProduction] = React.useState(false);

    React.useEffect(() => {
        setEmail(config.account_email ?? "");
    }, [config.account_email]);

    function handleProductionToggle(checked: boolean) {
        if (checked) {
            setConfirmProduction(true);
        } else {
            onSave({ use_production: false });
        }
    }

    function handleProductionConfirmed() {
        setConfirmProduction(false);
        onSave({
            use_production: true,
            accepted_tos_at: Math.floor(Date.now() / 1000),
        });
    }

    return (
        <>
            <ProductionConfirmDialog
                open={confirmProduction}
                onConfirm={handleProductionConfirmed}
                onCancel={() => setConfirmProduction(false)}
            />

            <MetricCard
                title={t("acme.title")}
                description={t("acme.description")}
            >
                <div className="space-y-5">
                    {/* Account email */}
                    <div className="flex items-end gap-3">
                        <div className="flex-1 space-y-1.5">
                            <Label htmlFor="acme-email-v2">{t("acme.accountEmail")}</Label>
                            <Input
                                id="acme-email-v2"
                                type="email"
                                placeholder={t("request.emailPlaceholder")}
                                value={email}
                                onChange={(e) => setEmail(e.target.value)}
                            />
                            <p className="text-xs text-muted-foreground">
                                {t("acme.accountEmailHint")}
                            </p>
                        </div>
                        <Button
                            onClick={() => onSave({ account_email: email })}
                            disabled={saving || email === (config.account_email ?? "")}
                        >
                            {saving && <Loader2 className="h-4 w-4 animate-spin" />}
                            {t("acme.save")}
                        </Button>
                    </div>

                    {/* Production toggle */}
                    <div className="flex items-start gap-3 rounded-lg border border-border/60 bg-muted/20 p-4">
                        <Switch
                            id="production-switch-v2"
                            checked={config.use_production}
                            onCheckedChange={handleProductionToggle}
                            disabled={saving}
                        />
                        <div className="space-y-1">
                            <Label
                                htmlFor="production-switch-v2"
                                className="cursor-pointer"
                            >
                                {t("acme.useProduction")}
                            </Label>
                            <p className="text-xs text-muted-foreground leading-relaxed">
                                {config.use_production ? (
                                    <>
                                        <span className="font-medium text-amber-400">
                                            {t("acme.productionActive")}
                                        </span>{" "}
                                        {t("acme.productionRateLimit")}
                                        {config.accepted_tos_at && (
                                            <>
                                                {" "}
                                                {t("acme.tosAccepted", {
                                                    date: new Date(
                                                        config.accepted_tos_at * 1000,
                                                    ).toLocaleString("en-GB", {
                                                        dateStyle: "medium",
                                                        timeStyle: "short",
                                                    }),
                                                })}
                                            </>
                                        )}
                                    </>
                                ) : (
                                    t("acme.stagingNote")
                                )}
                            </p>
                        </div>
                    </div>

                    {/* Warning when production is on but TOS missing */}
                    {config.use_production && !config.accepted_tos_at && (
                        <div
                            className={cn(
                                "flex items-start gap-2 rounded-lg border border-destructive/40",
                                "bg-destructive/10 px-4 py-3 text-sm text-destructive",
                            )}
                        >
                            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
                            {t("acme.tosMissingWarning")}
                        </div>
                    )}
                </div>
            </MetricCard>
        </>
    );
}

// ─── Order table row ──────────────────────────────────────────────────────────

function OrderRow({
    row,
    expandedErrors,
    onToggleError,
    onRequest,
    onRenew,
    renewPending,
    renewTarget,
    createPending,
}: {
    row: AcmeOrder;
    expandedErrors: Set<string>;
    onToggleError: (host: string) => void;
    onRequest: (host: string) => void;
    onRenew: (host: string) => void;
    renewPending: boolean;
    renewTarget: string | undefined;
    createPending: boolean;
}) {
    const { t } = useTranslation("certificates");
    const isExpanded = expandedErrors.has(row.host);
    const isRenewing = renewPending && renewTarget === row.host;

    return (
        <React.Fragment>
            <div
                className="v2-table-row grid items-center gap-4 px-5 py-3"
                style={{ gridTemplateColumns: "2fr 1fr 1fr 2fr auto" }}
            >
                {/* Host */}
                <span className="font-mono text-sm font-medium text-foreground truncate tabular-nums">
                    {row.host}
                </span>

                {/* Status */}
                <span>
                    <OrderStatusChip status={row.status} />
                </span>

                {/* Expires */}
                <span className="text-sm tabular-nums text-muted-foreground">
                    {row.expires_in_days != null ? t("row.expiresInDays", { count: row.expires_in_days }) : "—"}
                </span>

                {/* Cert path */}
                <span
                    className="font-mono text-xs text-muted-foreground/70 truncate"
                    title={row.cert_path ?? undefined}
                >
                    {row.cert_path ?? "—"}
                </span>

                {/* Actions */}
                <div className="flex items-center justify-end gap-2 shrink-0">
                    {row.status === "idle" && (
                        <Button
                            size="sm"
                            onClick={() => onRequest(row.host)}
                            disabled={createPending}
                        >
                            {t("row.request")}
                        </Button>
                    )}

                    {(row.status === "issued" || row.status === "expiring") && (
                        <Button
                            size="sm"
                            variant="outline"
                            onClick={() => onRenew(row.host)}
                            disabled={isRenewing}
                        >
                            {isRenewing ? (
                                <Loader2 className="h-3.5 w-3.5 animate-spin" />
                            ) : (
                                <RefreshCw className="h-3.5 w-3.5" />
                            )}
                            {t("row.renewNow")}
                        </Button>
                    )}

                    {row.status === "failed" && (
                        <>
                            <Button
                                size="sm"
                                variant="outline"
                                onClick={() => onRequest(row.host)}
                                disabled={createPending}
                            >
                                {t("row.retry")}
                            </Button>
                            {row.error && (
                                <Button
                                    size="sm"
                                    variant="ghost"
                                    onClick={() => onToggleError(row.host)}
                                >
                                    {isExpanded ? t("row.hide") : t("row.details")}
                                </Button>
                            )}
                        </>
                    )}

                    {row.status === "pending" && (
                        <span className="text-xs text-muted-foreground whitespace-nowrap">
                            {t("row.inProgress")}
                        </span>
                    )}
                </div>
            </div>

            {/* Error expansion row */}
            {row.status === "failed" && row.error && isExpanded && (
                <div className="border-b border-border/30 bg-destructive/5 px-5 py-2">
                    <p className="font-mono text-xs text-destructive break-all">
                        {row.error}
                    </p>
                </div>
            )}
        </React.Fragment>
    );
}

// ─── Main page ────────────────────────────────────────────────────────────────

export function CertificatesV2Page() {
    const { t } = useTranslation("certificates");
    const { toast } = useToast();
    const qc = useQueryClient();

    // ── Data fetching ────────────────────────────────────────────────────

    const sitesQuery = useQuery({
        queryKey: ["sites"],
        queryFn: sitesApi.list,
    });

    const configQuery = useQuery({
        queryKey: ["acme", "config"],
        queryFn: acmeApi.config.get,
    });

    const [hasPending, setHasPending] = React.useState(false);

    const ordersQuery = useQuery({
        queryKey: ["acme", "orders"],
        queryFn: acmeApi.orders.list,
        refetchInterval: hasPending ? 5_000 : 30_000,
    });

    React.useEffect(() => {
        const orders = ordersQuery.data?.orders ?? [];
        setHasPending(orders.some((o) => o.status === "pending"));
    }, [ordersQuery.data]);

    // ── Mutations ────────────────────────────────────────────────────────

    const saveConfig = useMutation({
        mutationFn: (patch: Partial<AcmeConfig>) => acmeApi.config.set(patch),
        onSuccess: () => {
            toast({ title: t("toast.configSaved"), variant: "success" });
            void qc.invalidateQueries({ queryKey: ["acme", "config"] });
        },
        onError: (err: unknown) => {
            toast({
                title: t("toast.saveFailed"),
                description: String(err),
                variant: "destructive",
            });
        },
    });

    const createOrder = useMutation({
        mutationFn: ({ host, email }: { host: string; email: string }) =>
            acmeApi.orders.create(host, email),
        onSuccess: (_, vars) => {
            toast({
                title: t("toast.requestQueued", { host: vars.host }),
                description: t("toast.requestQueuedDesc"),
                variant: "success",
            });
            void qc.invalidateQueries({ queryKey: ["acme", "orders"] });
        },
        onError: (err: unknown) => {
            const msg = String(err);
            if (msg.includes("409")) {
                toast({
                    title: t("toast.orderInFlight"),
                    description: t("toast.orderInFlightDesc"),
                    variant: "destructive",
                });
            } else if (msg.includes("503")) {
                toast({
                    title: t("toast.clientNotInit"),
                    description: t("toast.clientNotInitDesc"),
                    variant: "destructive",
                });
            } else {
                toast({ title: t("toast.requestFailed"), description: msg, variant: "destructive" });
            }
        },
    });

    const renewOrder = useMutation({
        mutationFn: (host: string) => acmeApi.orders.renew(host),
        onSuccess: (_, host) => {
            toast({ title: t("toast.renewalQueued", { host }), variant: "success" });
            void qc.invalidateQueries({ queryKey: ["acme", "orders"] });
        },
        onError: (err: unknown) => {
            const msg = String(err);
            if (msg.includes("409")) {
                toast({
                    title: t("toast.alreadyRenewing"),
                    description: t("toast.alreadyRenewingDesc"),
                    variant: "destructive",
                });
            } else {
                toast({ title: t("toast.renewalFailed"), description: msg, variant: "destructive" });
            }
        },
    });

    // ── Local UI state ───────────────────────────────────────────────────

    const [requestHost, setRequestHost] = React.useState<string | null>(null);
    const [expandedErrors, setExpandedErrors] = React.useState<Set<string>>(
        new Set(),
    );

    function toggleError(host: string) {
        setExpandedErrors((prev) => {
            const next = new Set(prev);
            if (next.has(host)) next.delete(host);
            else next.add(host);
            return next;
        });
    }

    // ── Derived data ─────────────────────────────────────────────────────

    const tlsSites = (sitesQuery.data ?? []).filter((s) => s.tls);
    const ordersByHost = new Map<string, AcmeOrder>(
        (ordersQuery.data?.orders ?? []).map((o) => [o.host, o]),
    );

    const rows: AcmeOrder[] = tlsSites.map((s) => {
        const existing = ordersByHost.get(s.host);
        if (existing) return existing;
        return {
            host: s.host,
            status: "idle",
            not_after_unix: null,
            expires_in_days: null,
            cert_path: null,
            key_path: null,
            error: null,
        };
    });

    for (const [host, order] of ordersByHost) {
        if (!rows.find((r) => r.host === host)) rows.push(order);
    }

    const defaultEmail = configQuery.data?.account_email ?? "";

    // Summary counts for KPI strip
    const issued = rows.filter((r) => r.status === "issued").length;
    const expiring = rows.filter((r) => r.status === "expiring").length;
    const failed = rows.filter((r) => r.status === "failed").length;

    // ── Empty state ──────────────────────────────────────────────────────

    if (tlsSites.length === 0 && !ordersQuery.data?.orders.length) {
        return (
            <div className="space-y-6">
                <div className="flex items-start justify-between">
                    <div className="space-y-0.5">
                        <h1 className="flex items-center gap-2 text-xl font-semibold tracking-tight text-foreground">
                            <ShieldCheck className="h-5 w-5 text-primary" />
                            {t("title")}
                        </h1>
                        <p className="text-sm text-muted-foreground">
                            {t("subtitle")}
                        </p>
                    </div>
                </div>

                <MetricCard title={t("orders.title")} noPadding>
                    <div className="flex flex-col items-center justify-center gap-3 py-16 text-center">
                        <span className="rounded-xl bg-muted/30 p-4 text-muted-foreground">
                            <FileLock2 className="h-7 w-7" />
                        </span>
                        <p className="text-sm font-medium text-foreground">{t("empty.title")}</p>
                        <p className="max-w-xs text-xs text-muted-foreground leading-relaxed">
                            {t("empty.desc")}
                        </p>
                    </div>
                </MetricCard>
            </div>
        );
    }

    // ── Render ───────────────────────────────────────────────────────────

    return (
        <div className="space-y-6">
            {/* Page header */}
            <div className="flex items-start justify-between">
                <div className="space-y-0.5">
                    <h1 className="flex items-center gap-2 text-xl font-semibold tracking-tight text-foreground">
                        <ShieldCheck className="h-5 w-5 text-primary" />
                        {t("title")}
                    </h1>
                    <p className="text-sm text-muted-foreground">
                        {t("subtitle")}
                    </p>
                </div>
                <Button
                    variant="outline"
                    size="sm"
                    onClick={() => {
                        void qc.invalidateQueries({ queryKey: ["acme", "orders"] });
                    }}
                >
                    <RefreshCw className="h-3.5 w-3.5" />
                    {t("refresh")}
                </Button>
            </div>

            {/* KPI summary strip */}
            {rows.length > 0 && (
                <div
                    className="grid gap-4"
                    style={{ gridTemplateColumns: "repeat(4, minmax(0, 1fr))" }}
                >
                    <div
                        className="v2-card flex flex-col gap-1 px-5 py-4"
                        style={{ boxShadow: "var(--v2-card-shadow)" }}
                    >
                        <p className="v2-section-label">{t("kpi.totalSites")}</p>
                        <p className="v2-kpi-number text-2xl font-bold tabular-nums">
                            {rows.length}
                        </p>
                    </div>
                    <div
                        className="v2-card flex flex-col gap-1 px-5 py-4"
                        style={{ boxShadow: "var(--v2-card-shadow)" }}
                    >
                        <p className="v2-section-label">{t("kpi.issued")}</p>
                        <p className="v2-kpi-number text-2xl font-bold tabular-nums text-green-400">
                            {issued}
                        </p>
                    </div>
                    <div
                        className="v2-card flex flex-col gap-1 px-5 py-4"
                        style={{ boxShadow: "var(--v2-card-shadow)" }}
                    >
                        <p className="v2-section-label">{t("kpi.expiringSoon")}</p>
                        <p
                            className={cn(
                                "v2-kpi-number text-2xl font-bold tabular-nums",
                                expiring > 0 ? "text-amber-400" : "text-muted-foreground",
                            )}
                        >
                            {expiring}
                        </p>
                    </div>
                    <div
                        className="v2-card flex flex-col gap-1 px-5 py-4"
                        style={{ boxShadow: "var(--v2-card-shadow)" }}
                    >
                        <p className="v2-section-label">{t("kpi.failed")}</p>
                        <p
                            className={cn(
                                "v2-kpi-number text-2xl font-bold tabular-nums",
                                failed > 0 ? "text-destructive" : "text-muted-foreground",
                            )}
                        >
                            {failed}
                        </p>
                    </div>
                </div>
            )}

            {/* ACME configuration card */}
            {configQuery.data && (
                <AcmeConfigCardV2
                    config={configQuery.data}
                    onSave={(patch) => saveConfig.mutate(patch)}
                    saving={saveConfig.isPending}
                />
            )}

            {/* Certificate orders table */}
            <MetricCard
                title={t("orders.title")}
                description={t("orders.description")}
                noPadding
            >
                {/* Column headings */}
                <div
                    className="grid items-center gap-4 border-b border-border/40 px-5 py-2"
                    style={{ gridTemplateColumns: "2fr 1fr 1fr 2fr auto" }}
                >
                    {([
                        { key: "host", label: t("col.host") },
                        { key: "status", label: t("col.status") },
                        { key: "expires", label: t("col.expires") },
                        { key: "certPath", label: t("col.certPath") },
                        { key: "actions", label: t("col.actions") },
                    ] as const).map(
                        (col) => (
                            <span
                                key={col.key}
                                className={cn(
                                    "text-[0.7rem] font-semibold uppercase tracking-widest text-muted-foreground",
                                    col.key === "actions" && "text-right",
                                )}
                            >
                                {col.label}
                            </span>
                        ),
                    )}
                </div>

                {/* Data rows */}
                {rows.map((row) => (
                    <OrderRow
                        key={row.host}
                        row={row}
                        expandedErrors={expandedErrors}
                        onToggleError={toggleError}
                        onRequest={(h) => setRequestHost(h)}
                        onRenew={(h) => renewOrder.mutate(h)}
                        renewPending={renewOrder.isPending}
                        renewTarget={renewOrder.variables}
                        createPending={createOrder.isPending}
                    />
                ))}
            </MetricCard>

            {/* Request cert dialog */}
            {requestHost !== null && (
                <RequestCertDialog
                    host={requestHost}
                    defaultEmail={defaultEmail}
                    open={requestHost !== null}
                    onClose={() => setRequestHost(null)}
                    onSubmit={(host, email) => {
                        createOrder.mutate(
                            { host, email },
                            { onSettled: () => setRequestHost(null) },
                        );
                    }}
                    submitting={createOrder.isPending}
                />
            )}
        </div>
    );
}
