/**
 * V2 Privacy Pass page — /v2/privacy-pass
 *
 * Presentation layer only change. Data fetching is identical to V1:
 *   - privacyPassApi.status (poll 30 s)
 *   - privacyPassApi.addIssuer (mutation)
 *
 * V2 visual changes:
 *   - MetricCard + KPITile replace Card for all panels
 *   - Register-issuer form section uses MetricCard wrapper
 *   - Algorithm select styled consistently with V2 inputs
 *   - Status section uses KPITile for issuer count + nonce cache size
 *   - "Arsenal not attached" uses StatusBadge
 */

import { useState } from "react";
import { Trans, useTranslation } from "react-i18next";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { KeyRound, Plus, ShieldCheck } from "lucide-react";
import { privacyPassApi } from "@/api/client";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
    Select,
    SelectContent,
    SelectItem,
    SelectTrigger,
    SelectValue,
} from "@/components/ui/select";
import { useToast } from "@/hooks/useToast";
import { KPITile } from "@/v2/components/KPITile";
import { MetricCard } from "@/v2/components/MetricCard";
import { SectionHeader } from "@/v2/components/SectionHeader";
import { StatusBadge } from "@/v2/components/StatusBadge";

// ─── Page ────────────────────────────────────────────────────────────────────

export function PrivacyPassPage() {
    const { t } = useTranslation(["privacypass", "common"]);
    const { toast } = useToast();
    const qc = useQueryClient();

    const status = useQuery({
        queryKey: ["privacypass"],
        queryFn: privacyPassApi.status,
        refetchInterval: 30_000,
    });

    const [name, setName] = useState("");
    const [keyId, setKeyId] = useState("");
    const [pubKey, setPubKey] = useState("");
    const [algo, setAlgo] = useState<"ed25519" | "hmac_sha256">("ed25519");
    const [duration, setDuration] = useState(86_400);

    const add = useMutation({
        mutationFn: () =>
            privacyPassApi.addIssuer({
                name,
                key_id_hex: keyId,
                public_key_hex: pubKey,
                algorithm: algo,
                trust_duration_secs: duration,
            }),
        onSuccess: (res) => {
            if (res.ok) {
                toast({ title: t("toast.registered", { name: res.name }) });
                qc.invalidateQueries({ queryKey: ["privacypass"] });
                setName("");
                setKeyId("");
                setPubKey("");
            } else {
                toast({ title: t("toast.failed"), description: res.error, variant: "destructive" });
            }
        },
    });

    const wired = status.data?.wired;
    const canSubmit = name.length > 0 && keyId.length > 0 && pubKey.length > 0 && !add.isPending;

    return (
        <div className="space-y-6">
            {/* Page heading */}
            <div className="flex items-center gap-3">
                <div className="flex items-center justify-center w-8 h-8 rounded-lg bg-primary/10">
                    <ShieldCheck className="h-4 w-4 text-primary" />
                </div>
                <div>
                    <h1 className="text-lg font-semibold leading-tight text-foreground">
                        {t("title")}
                    </h1>
                    <p className="text-xs text-muted-foreground mt-0.5">
                        {t("subtitle")}
                    </p>
                </div>
            </div>

            {/* Arsenal wired state */}
            {!wired && !status.isLoading && (
                <div
                    className="v2-card border-amber-500/40 px-5 py-3 flex items-center gap-3"
                    style={{ boxShadow: "var(--v2-card-shadow)" }}
                >
                    <StatusBadge state="standby" label={t("notAttached.badge")} />
                    <p className="text-sm text-amber-200">
                        {t("notAttached.text")}
                    </p>
                </div>
            )}

            {/* Status overview */}
            <div>
                <SectionHeader label={t("section.status")} className="mb-3" />
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    <KPITile
                        label={t("status.trustedIssuers")}
                        value={status.data?.issuer_count ?? 0}
                        icon={<KeyRound className="h-4 w-4" />}
                        deltaLabel={t("status.registered")}
                    />
                    <KPITile
                        label={t("status.nonceCache")}
                        value={status.data?.nonce_cache_size ?? 0}
                        deltaLabel={t("status.seenNonces")}
                    />
                </div>
            </div>

            {/* Register issuer form */}
            <MetricCard
                title={t("register.title")}
                description={t("register.desc")}
            >
                <div className="space-y-4">
                    {/* Name + algorithm row */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                        <div>
                            <Label htmlFor="pp-name" className="text-xs text-muted-foreground mb-1.5 block">
                                {t("register.issuerName")}
                            </Label>
                            <Input
                                id="pp-name"
                                value={name}
                                onChange={(e) => setName(e.target.value)}
                                placeholder={t("register.issuerNamePlaceholder")}
                                className="h-8 text-sm"
                            />
                        </div>
                        <div>
                            <Label htmlFor="pp-algo" className="text-xs text-muted-foreground mb-1.5 block">
                                {t("register.algorithm")}
                            </Label>
                            <Select
                                value={algo}
                                onValueChange={(v) => setAlgo(v as typeof algo)}
                            >
                                <SelectTrigger id="pp-algo" className="h-8 text-xs">
                                    <SelectValue />
                                </SelectTrigger>
                                <SelectContent>
                                    <SelectItem value="ed25519">ed25519</SelectItem>
                                    <SelectItem value="hmac_sha256">
                                        hmac_sha256{" "}
                                        <span className="text-amber-400 ml-1">{t("register.testOnly")}</span>
                                    </SelectItem>
                                </SelectContent>
                            </Select>
                        </div>
                    </div>

                    {/* key_id */}
                    <div>
                        <Label htmlFor="pp-kid" className="text-xs text-muted-foreground mb-1.5 block">
                            key_id{" "}
                            <span className="text-muted-foreground/60">{t("register.keyIdHint")}</span>
                        </Label>
                        <Input
                            id="pp-kid"
                            value={keyId}
                            onChange={(e) => setKeyId(e.target.value)}
                            className="h-8 font-mono text-xs"
                            placeholder={t("register.keyIdPlaceholder")}
                        />
                    </div>

                    {/* public_key */}
                    <div>
                        <Label htmlFor="pp-pk" className="text-xs text-muted-foreground mb-1.5 block">
                            public_key{" "}
                            <span className="text-muted-foreground/60">{t("register.publicKeyHint")}</span>
                        </Label>
                        <Input
                            id="pp-pk"
                            value={pubKey}
                            onChange={(e) => setPubKey(e.target.value)}
                            className="h-8 font-mono text-xs"
                            placeholder={t("register.publicKeyPlaceholder")}
                        />
                    </div>

                    {/* Trust duration */}
                    <div>
                        <Label htmlFor="pp-dur" className="text-xs text-muted-foreground mb-1.5 block">
                            {t("register.trustDuration")}{" "}
                            <span className="text-muted-foreground/60">{t("register.seconds")}</span>
                        </Label>
                        <Input
                            id="pp-dur"
                            type="number"
                            value={duration}
                            onChange={(e) => setDuration(Number(e.target.value))}
                            className="h-8 text-sm tabular-nums w-48"
                            min={60}
                        />
                        <p className="text-xs text-muted-foreground/60 mt-1">
                            {duration >= 3600
                                ? t("register.hours", { count: (duration / 3600).toFixed(1) })
                                : t("register.durationSeconds", { count: duration })}
                        </p>
                    </div>

                    {/* Submit */}
                    <div className="pt-1">
                        <Button
                            onClick={() => add.mutate()}
                            disabled={!canSubmit}
                            size="sm"
                            className="h-8 text-xs"
                        >
                            <Plus className="h-3 w-3 mr-1.5" />
                            {add.isPending ? t("register.submitting") : t("register.submit")}
                        </Button>
                    </div>
                </div>
            </MetricCard>

            {/* Info card — algorithm notes */}
            <div
                className="v2-card px-5 py-4 border-primary/20"
                style={{ boxShadow: "var(--v2-card-shadow)" }}
            >
                <SectionHeader label={t("section.notes")} className="mb-2" />
                <ul className="text-xs text-muted-foreground space-y-1 list-disc list-inside leading-relaxed">
                    <li>
                        <Trans
                            ns="privacypass"
                            i18nKey="notes.production"
                            components={[<code className="text-primary/80 bg-primary/5 px-1 py-0.5 rounded" />]}
                        />
                    </li>
                    <li>
                        <Trans
                            ns="privacypass"
                            i18nKey="notes.hmac"
                            components={[<code className="text-amber-400/80 bg-amber-500/5 px-1 py-0.5 rounded" />]}
                        />
                    </li>
                    <li>
                        {t("notes.nonce")}
                    </li>
                </ul>
            </div>
        </div>
    );
}
