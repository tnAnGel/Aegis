/**
 * AddSiteWizard — installer-style 5-step guided wizard for adding a site.
 *
 * Steps:
 *   1. Site & Origin  — hostname, upstream URL(s), health-check
 *   2. TLS            — TLS mode radio cards + HTTPS redirect, HTTP/2, HTTP/3
 *   3. Protection     — preset selector cards + advanced filter overrides
 *   4. Traffic rules  — rate limit, GeoIP mode, IP allow/deny lists
 *   5. Review & Create — read-only summary, calls API on submit
 */
import * as React from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
    Check,
    ChevronRight,
    Globe,
    Loader2,
    Lock,
    Shield,
    ShieldCheck,
    Zap,
} from "lucide-react";
import { sitesApi, sitePolicyApi, defaultsApi } from "@/api/client";
import type { DefaultFilter } from "@/api/client";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import {
    Dialog,
    DialogContent,
    DialogFooter,
    DialogHeader,
    DialogTitle,
    DialogDescription,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import {
    Select,
    SelectContent,
    SelectItem,
    SelectTrigger,
    SelectValue,
} from "@/components/ui/select";
import { useToast } from "@/hooks/useToast";
import { cn } from "@/lib/cn";

// ─── Types ───────────────────────────────────────────────────────────────────

type TlsMode = "none" | "existing" | "acme";
type GeoMode = "off" | "allow" | "deny";
type Preset = "essential" | "balanced" | "maximum";

interface WizardState {
    // Step 1
    host: string;
    upstreams: string[];
    healthCheck: string;
    // Step 2
    tlsMode: TlsMode;
    httpsRedirect: boolean;
    http2: boolean;
    http3: boolean;
    sslCertPath: string;
    sslKeyPath: string;
    // Step 3
    preset: Preset;
    filterOverrides: Record<string, boolean>;
    // Step 4
    rateLimitEnabled: boolean;
    rps: number;
    burst: number;
    geoMode: GeoMode;
    countries: string;
    ipAllowList: string;
    ipDenyList: string;
}

const INITIAL: WizardState = {
    host: "",
    upstreams: [""],
    healthCheck: "",
    tlsMode: "none",
    httpsRedirect: false,
    http2: true,
    http3: false,
    sslCertPath: "",
    sslKeyPath: "",
    preset: "balanced",
    filterOverrides: {},
    rateLimitEnabled: false,
    rps: 100,
    burst: 200,
    geoMode: "off",
    countries: "",
    ipAllowList: "",
    ipDenyList: "",
};

const PRESETS: Record<Preset, Record<string, boolean>> = {
    essential: { waf: true, bot: false, rate_limit: false, challenge: false, honeypot: false },
    balanced: { waf: true, bot: true, rate_limit: false, challenge: true, honeypot: false },
    maximum: { waf: true, bot: true, rate_limit: true, challenge: true, honeypot: true },
};

const STEPS = [
    "Site & Origin",
    "TLS",
    "Protection",
    "Traffic rules",
    "Review",
] as const;

// ─── Validation ──────────────────────────────────────────────────────────────

const HOST_RE = /^[A-Za-z0-9.\-_*]+$/;
const URL_RE = /^https?:\/\//;

function validateStep(step: number, state: WizardState): string | null {
    if (step === 0) {
        if (!state.host) return "Hostname is required.";
        if (!HOST_RE.test(state.host)) return "Hostname may only contain letters, digits, '.', '-', '_', '*'.";
        if (state.host.length > 253) return "Hostname too long.";
        if (!state.upstreams[0]) return "Upstream URL is required.";
        if (!URL_RE.test(state.upstreams[0])) return "Upstream must start with http:// or https://";
        return null;
    }
    if (step === 1) {
        if (state.tlsMode === "existing") {
            if (!state.sslCertPath) return "Certificate path is required.";
            if (!state.sslKeyPath) return "Private key path is required.";
        }
        if (state.http3 && state.tlsMode === "none") return "HTTP/3 requires TLS.";
        return null;
    }
    return null;
}

// ─── Stepper ─────────────────────────────────────────────────────────────────

function Stepper({ current }: { current: number }) {
    return (
        <nav aria-label="Wizard steps" className="flex items-center gap-0 w-full">
            {STEPS.map((label, idx) => {
                const done = idx < current;
                const active = idx === current;
                return (
                    <React.Fragment key={label}>
                        <div className="flex flex-col items-center shrink-0">
                            <div
                                className={cn(
                                    "flex items-center justify-center w-7 h-7 rounded-full border-2 text-xs font-semibold transition-colors",
                                    done
                                        ? "bg-primary border-primary text-primary-foreground"
                                        : active
                                        ? "border-primary text-primary"
                                        : "border-muted-foreground/30 text-muted-foreground/50",
                                )}
                            >
                                {done ? <Check className="h-3.5 w-3.5" /> : idx + 1}
                            </div>
                            <span
                                className={cn(
                                    "mt-1 text-[10px] font-medium leading-tight text-center max-w-[56px]",
                                    active ? "text-primary" : "text-muted-foreground",
                                )}
                            >
                                {label}
                            </span>
                        </div>
                        {idx < STEPS.length - 1 && (
                            <div
                                className={cn(
                                    "flex-1 h-px mb-4 mx-1 transition-colors",
                                    idx < current ? "bg-primary" : "bg-muted-foreground/20",
                                )}
                            />
                        )}
                    </React.Fragment>
                );
            })}
        </nav>
    );
}

// ─── Step 1: Site & Origin ───────────────────────────────────────────────────

function Step1SiteOrigin({
    state,
    update,
}: {
    state: WizardState;
    update: (patch: Partial<WizardState>) => void;
}) {
    function setUpstream(idx: number, val: string) {
        const next = [...state.upstreams];
        next[idx] = val;
        update({ upstreams: next });
    }
    function addUpstream() {
        update({ upstreams: [...state.upstreams, ""] });
    }
    function removeUpstream(idx: number) {
        update({ upstreams: state.upstreams.filter((_, i) => i !== idx) });
    }

    return (
        <div className="space-y-4">
            <FieldRow label="Hostname">
                <Input
                    placeholder="api.example.com"
                    value={state.host}
                    onChange={(e) => update({ host: e.target.value })}
                    autoFocus
                />
                <p className="text-xs text-muted-foreground mt-1">
                    Wildcard prefix supported: <code className="font-mono">*.example.com</code>
                </p>
            </FieldRow>

            <div className="space-y-2">
                <Label className="block">Upstream URL{state.upstreams.length > 1 ? "s" : ""}</Label>
                {state.upstreams.map((u, idx) => (
                    <div key={idx} className="flex gap-2">
                        <Input
                            placeholder="http://127.0.0.1:3000"
                            value={u}
                            onChange={(e) => setUpstream(idx, e.target.value)}
                            className="flex-1"
                        />
                        {idx > 0 && (
                            <Button
                                type="button"
                                variant="outline"
                                size="sm"
                                onClick={() => removeUpstream(idx)}
                                className="shrink-0"
                            >
                                Remove
                            </Button>
                        )}
                    </div>
                ))}
                <button
                    type="button"
                    className="text-xs text-primary hover:underline"
                    onClick={addUpstream}
                >
                    + Add upstream
                </button>
                {state.upstreams.length > 1 && (
                    <p className="text-xs text-muted-foreground">
                        Only the first upstream is sent to the API — multi-upstream support requires manual config.
                    </p>
                )}
            </div>

            <FieldRow label="Health-check URL (optional)">
                <Input
                    placeholder="/health"
                    value={state.healthCheck}
                    onChange={(e) => update({ healthCheck: e.target.value })}
                />
                <p className="text-xs text-muted-foreground mt-1">
                    Leave blank to use the default upstream health probe.
                </p>
            </FieldRow>
        </div>
    );
}

// ─── Step 2: TLS ─────────────────────────────────────────────────────────────

const TLS_OPTIONS: {
    id: TlsMode;
    title: string;
    description: string;
    icon: React.ComponentType<{ className?: string }>;
}[] = [
    {
        id: "none",
        title: "No TLS",
        description: "HTTP only on port 80. Suitable for internal services or behind a TLS terminator.",
        icon: Globe,
    },
    {
        id: "existing",
        title: "Existing cert on disk",
        description: "Provide paths to a certificate and private key file already present on the server.",
        icon: Lock,
    },
    {
        id: "acme",
        title: "ACME / Let's Encrypt",
        description: "Aegis will provision and renew a certificate automatically via ACME (configure ACME in Settings first).",
        icon: ShieldCheck,
    },
];

function Step2Tls({
    state,
    update,
}: {
    state: WizardState;
    update: (patch: Partial<WizardState>) => void;
}) {
    return (
        <div className="space-y-4">
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                {TLS_OPTIONS.map((opt) => {
                    const Icon = opt.icon;
                    const selected = state.tlsMode === opt.id;
                    return (
                        <button
                            key={opt.id}
                            type="button"
                            onClick={() => update({ tlsMode: opt.id })}
                            className={cn(
                                "flex flex-col gap-2 rounded-lg border p-4 text-left transition-colors",
                                selected
                                    ? "border-primary bg-primary/5 ring-1 ring-primary"
                                    : "border-border hover:border-muted-foreground/40",
                            )}
                        >
                            <Icon
                                className={cn(
                                    "h-5 w-5",
                                    selected ? "text-primary" : "text-muted-foreground",
                                )}
                            />
                            <span className="text-sm font-semibold">{opt.title}</span>
                            <span className="text-xs text-muted-foreground leading-relaxed">
                                {opt.description}
                            </span>
                        </button>
                    );
                })}
            </div>

            {state.tlsMode === "existing" && (
                <div className="space-y-3 pt-1">
                    <FieldRow label="Certificate path">
                        <Input
                            placeholder="/etc/aegis/certs/example.crt"
                            value={state.sslCertPath}
                            onChange={(e) => update({ sslCertPath: e.target.value })}
                        />
                    </FieldRow>
                    <FieldRow label="Private key path">
                        <Input
                            placeholder="/etc/aegis/certs/example.key"
                            value={state.sslKeyPath}
                            onChange={(e) => update({ sslKeyPath: e.target.value })}
                        />
                    </FieldRow>
                </div>
            )}

            <div className="space-y-2 pt-1">
                <SwitchCard
                    label="HTTPS redirect"
                    description="Redirect all HTTP traffic to HTTPS (requires TLS)"
                    checked={state.httpsRedirect}
                    disabled={state.tlsMode === "none"}
                    onCheckedChange={(v) => update({ httpsRedirect: v })}
                />
                <SwitchCard
                    label="HTTP/2"
                    description="Enable HTTP/2 (recommended for all TLS sites)"
                    checked={state.http2}
                    disabled={state.tlsMode === "none"}
                    onCheckedChange={(v) => update({ http2: v })}
                />
                <SwitchCard
                    label="HTTP/3 (QUIC)"
                    description="Enable HTTP/3 over QUIC — requires TLS and HTTP/2"
                    checked={state.http3}
                    disabled={state.tlsMode === "none"}
                    onCheckedChange={(v) => update({ http3: v })}
                />
            </div>
        </div>
    );
}

// ─── Step 3: Protection ──────────────────────────────────────────────────────

const PRESET_CARDS: {
    id: Preset;
    title: string;
    icon: React.ComponentType<{ className?: string }>;
    bullets: string[];
}[] = [
    {
        id: "essential",
        title: "Essential",
        icon: Shield,
        bullets: ["WAF signatures", "IP allow/deny", "Rate limiting (global)"],
    },
    {
        id: "balanced",
        title: "Balanced",
        icon: ShieldCheck,
        bullets: ["WAF + bot fingerprinting", "Challenge ladder", "Rate limiting", "Threat intel"],
    },
    {
        id: "maximum",
        title: "Maximum",
        icon: Zap,
        bullets: ["All Balanced layers", "Honeypot traps", "GeoIP enforcement", "Adaptive spike detection"],
    },
];

const ADVANCED_FILTERS: { name: string; label: string; description: string }[] = [
    { name: "waf", label: "WAF", description: "Signature-based payload inspection" },
    { name: "bot", label: "Bot fingerprinting", description: "UA / header heuristic scoring" },
    { name: "challenge", label: "Challenge ladder", description: "JS PoW + reCAPTCHA progression" },
    { name: "rate_limit", label: "Rate limiter", description: "Per-IP token-bucket rate limiting" },
    { name: "honeypot", label: "Honeypot paths", description: "Bait URLs for scanner detection" },
];

function Step3Protection({
    state,
    update,
    globalFilters,
}: {
    state: WizardState;
    update: (patch: Partial<WizardState>) => void;
    globalFilters: DefaultFilter[];
}) {
    function selectPreset(preset: Preset) {
        update({ preset, filterOverrides: { ...PRESETS[preset] } });
    }

    function toggleOverride(name: string, val: boolean) {
        update({ filterOverrides: { ...state.filterOverrides, [name]: val } });
    }

    // Effective value: override wins, then global default
    function effectiveValue(name: string): boolean {
        if (name in state.filterOverrides) return state.filterOverrides[name] ?? false;
        const gf = globalFilters.find((f) => f.name === name);
        return gf?.enabled ?? false;
    }

    return (
        <div className="space-y-5">
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-3">
                {PRESET_CARDS.map((card) => {
                    const Icon = card.icon;
                    const selected = state.preset === card.id;
                    return (
                        <button
                            key={card.id}
                            type="button"
                            onClick={() => selectPreset(card.id)}
                            className={cn(
                                "flex flex-col gap-3 rounded-lg border p-4 text-left transition-colors",
                                selected
                                    ? "border-primary bg-primary/5 ring-1 ring-primary"
                                    : "border-border hover:border-muted-foreground/40",
                            )}
                        >
                            <div className="flex items-center gap-2">
                                <Icon
                                    className={cn(
                                        "h-5 w-5 shrink-0",
                                        selected ? "text-primary" : "text-muted-foreground",
                                    )}
                                />
                                <span className="font-semibold text-sm">{card.title}</span>
                            </div>
                            <ul className="space-y-1">
                                {card.bullets.map((b) => (
                                    <li key={b} className="text-xs text-muted-foreground flex items-start gap-1.5">
                                        <Check className="h-3 w-3 text-primary shrink-0 mt-0.5" />
                                        {b}
                                    </li>
                                ))}
                            </ul>
                        </button>
                    );
                })}
            </div>

            <details className="group">
                <summary className="cursor-pointer text-xs font-semibold text-muted-foreground uppercase tracking-wide select-none hover:text-foreground transition-colors flex items-center gap-1.5">
                    <ChevronRight className="h-3.5 w-3.5 transition-transform group-open:rotate-90" />
                    Advanced — per-filter overrides
                </summary>
                <div className="mt-3 space-y-2">
                    {ADVANCED_FILTERS.map((f) => (
                        <SwitchCard
                            key={f.name}
                            label={f.label}
                            description={f.description}
                            checked={effectiveValue(f.name)}
                            onCheckedChange={(v) => toggleOverride(f.name, v)}
                        />
                    ))}
                </div>
            </details>
        </div>
    );
}

// ─── Step 4: Traffic Rules ───────────────────────────────────────────────────

function Step4TrafficRules({
    state,
    update,
}: {
    state: WizardState;
    update: (patch: Partial<WizardState>) => void;
}) {
    return (
        <div className="space-y-4">
            <Card>
                <CardContent className="p-4 space-y-3">
                    <div className="flex items-center justify-between">
                        <span className="text-sm font-semibold">Per-host rate limit</span>
                        <Switch
                            checked={state.rateLimitEnabled}
                            onCheckedChange={(v) => update({ rateLimitEnabled: v })}
                        />
                    </div>
                    {state.rateLimitEnabled && (
                        <div className="grid grid-cols-2 gap-3 pt-1">
                            <FieldRow label="Requests / second">
                                <Input
                                    type="number"
                                    min={1}
                                    value={state.rps}
                                    onChange={(e) => update({ rps: Number(e.target.value) })}
                                />
                            </FieldRow>
                            <FieldRow label="Burst">
                                <Input
                                    type="number"
                                    min={1}
                                    value={state.burst}
                                    onChange={(e) => update({ burst: Number(e.target.value) })}
                                />
                            </FieldRow>
                        </div>
                    )}
                </CardContent>
            </Card>

            <Card>
                <CardContent className="p-4 space-y-3">
                    <span className="text-sm font-semibold">GeoIP</span>
                    <FieldRow label="Mode">
                        <Select
                            value={state.geoMode}
                            onValueChange={(v) => update({ geoMode: v as GeoMode })}
                        >
                            <SelectTrigger>
                                <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                                <SelectItem value="off">Off</SelectItem>
                                <SelectItem value="allow">Allow list — only these countries</SelectItem>
                                <SelectItem value="deny">Deny list — block these countries</SelectItem>
                            </SelectContent>
                        </Select>
                    </FieldRow>
                    {state.geoMode !== "off" && (
                        <FieldRow label="Country codes (comma-separated, e.g. US,CA,GB)">
                            <Input
                                placeholder="US,CA,GB"
                                value={state.countries}
                                onChange={(e) => update({ countries: e.target.value })}
                            />
                        </FieldRow>
                    )}
                    {state.geoMode !== "off" && (
                        <p className="text-xs text-muted-foreground">
                            Requires a GeoIP database configured in Settings. Saved to site policy after creation.
                        </p>
                    )}
                </CardContent>
            </Card>

            <Card>
                <CardContent className="p-4 space-y-3">
                    <span className="text-sm font-semibold">IP allow / deny lists</span>
                    <FieldRow label="Allow list (one CIDR or IP per line)">
                        <textarea
                            className="flex min-h-[72px] w-full rounded-md border border-input bg-background px-3 py-2 text-sm shadow-sm placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50 font-mono resize-y"
                            placeholder={"10.0.0.0/8\n192.168.1.100"}
                            value={state.ipAllowList}
                            onChange={(e) => update({ ipAllowList: e.target.value })}
                        />
                    </FieldRow>
                    <FieldRow label="Deny list (one CIDR or IP per line)">
                        <textarea
                            className="flex min-h-[72px] w-full rounded-md border border-input bg-background px-3 py-2 text-sm shadow-sm placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50 font-mono resize-y"
                            placeholder={"1.2.3.4\n5.6.7.0/24"}
                            value={state.ipDenyList}
                            onChange={(e) => update({ ipDenyList: e.target.value })}
                        />
                    </FieldRow>
                    <p className="text-xs text-muted-foreground">
                        IP lists are stored in the site policy and evaluated at request time.
                    </p>
                </CardContent>
            </Card>
        </div>
    );
}

// ─── Step 5: Review ──────────────────────────────────────────────────────────

function Step5Review({
    state,
    globalFilters,
}: {
    state: WizardState;
    globalFilters: DefaultFilter[];
}) {
    const tlsLabel: Record<TlsMode, string> = {
        none: "No TLS (HTTP only)",
        existing: `Existing cert — ${state.sslCertPath || "(path not set)"}`,
        acme: "ACME / Let's Encrypt",
    };

    const activeFilters = ADVANCED_FILTERS.filter((f) => {
        if (f.name in state.filterOverrides) return state.filterOverrides[f.name];
        return globalFilters.find((g) => g.name === f.name)?.enabled ?? false;
    }).map((f) => f.label);

    return (
        <div className="space-y-4">
            <ReviewCard title="Site & Origin">
                <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
                    <dt className="text-muted-foreground">Host</dt>
                    <dd className="font-mono font-medium">{state.host || "—"}</dd>
                    <dt className="text-muted-foreground">Upstream</dt>
                    <dd className="font-mono text-xs break-all">{state.upstreams[0] || "—"}</dd>
                    {state.upstreams.length > 1 && (
                        <>
                            <dt className="text-muted-foreground">Additional upstreams</dt>
                            <dd className="font-mono text-xs text-muted-foreground">
                                {state.upstreams.slice(1).join(", ")} (not sent to API)
                            </dd>
                        </>
                    )}
                    {state.healthCheck && (
                        <>
                            <dt className="text-muted-foreground">Health check</dt>
                            <dd className="font-mono text-xs">{state.healthCheck}</dd>
                        </>
                    )}
                </dl>
            </ReviewCard>

            <ReviewCard title="TLS">
                <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
                    <dt className="text-muted-foreground">Mode</dt>
                    <dd>{tlsLabel[state.tlsMode]}</dd>
                    <dt className="text-muted-foreground">HTTPS redirect</dt>
                    <dd>{state.httpsRedirect ? "Yes" : "No"}</dd>
                    <dt className="text-muted-foreground">HTTP/2</dt>
                    <dd>{state.http2 && state.tlsMode !== "none" ? "Yes" : "No"}</dd>
                    <dt className="text-muted-foreground">HTTP/3</dt>
                    <dd>{state.http3 && state.tlsMode !== "none" ? "Yes" : "No"}</dd>
                </dl>
            </ReviewCard>

            <ReviewCard title="Protection">
                <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
                    <dt className="text-muted-foreground">Preset</dt>
                    <dd className="capitalize">{state.preset}</dd>
                    <dt className="text-muted-foreground">Active filters</dt>
                    <dd>{activeFilters.length > 0 ? activeFilters.join(", ") : "None"}</dd>
                </dl>
            </ReviewCard>

            <ReviewCard title="Traffic rules">
                <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
                    <dt className="text-muted-foreground">Rate limit</dt>
                    <dd>
                        {state.rateLimitEnabled
                            ? `${state.rps} rps · burst ${state.burst}`
                            : "Global default"}
                    </dd>
                    <dt className="text-muted-foreground">GeoIP</dt>
                    <dd className="capitalize">{state.geoMode}</dd>
                    {state.geoMode !== "off" && state.countries && (
                        <>
                            <dt className="text-muted-foreground">Countries</dt>
                            <dd className="font-mono text-xs">{state.countries}</dd>
                        </>
                    )}
                    <dt className="text-muted-foreground">IP allow list</dt>
                    <dd className="text-xs text-muted-foreground">
                        {state.ipAllowList.trim() ? state.ipAllowList.trim().split("\n").length + " entries" : "None"}
                    </dd>
                    <dt className="text-muted-foreground">IP deny list</dt>
                    <dd className="text-xs text-muted-foreground">
                        {state.ipDenyList.trim() ? state.ipDenyList.trim().split("\n").length + " entries" : "None"}
                    </dd>
                </dl>
            </ReviewCard>
        </div>
    );
}

// ─── Main wizard component ───────────────────────────────────────────────────

export function AddSiteWizard({
    open,
    onOpenChange,
}: {
    open: boolean;
    onOpenChange: (o: boolean) => void;
}) {
    const [step, setStep] = React.useState(0);
    const [state, setState] = React.useState<WizardState>(INITIAL);
    const [error, setError] = React.useState<string | null>(null);
    const [submitting, setSubmitting] = React.useState(false);
    const qc = useQueryClient();
    const { toast } = useToast();

    const defaultsQuery = useQuery({
        queryKey: ["defaults-filters"],
        queryFn: defaultsApi.list,
        enabled: open,
    });
    const globalFilters: DefaultFilter[] = defaultsQuery.data?.filters ?? [];

    function update(patch: Partial<WizardState>) {
        setState((prev) => ({ ...prev, ...patch }));
        setError(null);
    }

    function reset() {
        setStep(0);
        setState(INITIAL);
        setError(null);
        setSubmitting(false);
    }

    function handleClose(o: boolean) {
        if (!o) reset();
        onOpenChange(o);
    }

    function next() {
        const err = validateStep(step, state);
        if (err) {
            setError(err);
            return;
        }
        setError(null);
        setStep((s) => Math.min(s + 1, STEPS.length - 1));
    }

    function back() {
        setError(null);
        setStep((s) => Math.max(s - 1, 0));
    }

    async function handleCreate() {
        setSubmitting(true);
        setError(null);
        try {
            const tls = state.tlsMode !== "none";
            await sitesApi.create({
                host: state.host,
                upstream: state.upstreams[0] ?? "",
                tls,
                h3: tls && state.http3,
                ssl_cert: state.tlsMode === "existing" ? state.sslCertPath : null,
                ssl_key: state.tlsMode === "existing" ? state.sslKeyPath : null,
                rate_limit:
                    state.rateLimitEnabled && state.rps > 0
                        ? { rps: state.rps, burst: state.burst }
                        : null,
            });

            // Compute overrides that differ from global defaults
            const globalMap: Record<string, boolean> = {};
            for (const f of globalFilters) {
                globalMap[f.name] = f.enabled;
            }
            const diffOverrides: Record<string, boolean> = {};
            for (const [k, v] of Object.entries(state.filterOverrides)) {
                if (globalMap[k] !== v) {
                    diffOverrides[k] = v;
                }
            }
            if (Object.keys(diffOverrides).length > 0) {
                await sitePolicyApi.put(state.host, {
                    filter_enabled: diffOverrides,
                    endpoint_policies: {},
                });
            }

            toast({
                title: `Site ${state.host} created`,
                description: "Aegis reloaded with the new configuration.",
                variant: "success",
            });
            qc.invalidateQueries({ queryKey: ["sites"] });
            handleClose(false);
            // Navigate to site detail
            window.location.href = `/admin/ui/sites/${encodeURIComponent(state.host)}`;
        } catch (e) {
            setError(e instanceof Error ? e.message : String(e));
        } finally {
            setSubmitting(false);
        }
    }

    const isLast = step === STEPS.length - 1;

    return (
        <Dialog open={open} onOpenChange={handleClose}>
            <DialogContent className="sm:max-w-4xl">
                <DialogHeader>
                    <DialogTitle>Add site</DialogTitle>
                    <DialogDescription>
                        Creates <code className="font-mono">/var/lib/aegis/sites.d/{state.host || "<host>"}.conf</code> and reloads Aegis.
                    </DialogDescription>
                </DialogHeader>

                <div className="pt-1">
                    <Stepper current={step} />
                </div>

                <div className="min-h-[300px] py-2">
                    {step === 0 && <Step1SiteOrigin state={state} update={update} />}
                    {step === 1 && <Step2Tls state={state} update={update} />}
                    {step === 2 && (
                        <Step3Protection
                            state={state}
                            update={update}
                            globalFilters={globalFilters}
                        />
                    )}
                    {step === 3 && <Step4TrafficRules state={state} update={update} />}
                    {step === 4 && <Step5Review state={state} globalFilters={globalFilters} />}
                </div>

                {error && (
                    <p className="text-sm text-destructive rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2">
                        {error}
                    </p>
                )}

                <DialogFooter className="flex items-center gap-2">
                    <Button
                        type="button"
                        variant="outline"
                        onClick={step === 0 ? () => handleClose(false) : back}
                        disabled={submitting}
                    >
                        {step === 0 ? "Cancel" : "Back"}
                    </Button>
                    <div className="flex-1" />
                    {isLast ? (
                        <Button type="button" onClick={handleCreate} disabled={submitting}>
                            {submitting && <Loader2 className="h-4 w-4 animate-spin" />}
                            Create site
                        </Button>
                    ) : (
                        <Button type="button" onClick={next}>
                            Next
                            <ChevronRight className="h-4 w-4" />
                        </Button>
                    )}
                </DialogFooter>
            </DialogContent>
        </Dialog>
    );
}

// ─── Small shared sub-components ────────────────────────────────────────────

function FieldRow({
    label,
    children,
}: {
    label: string;
    children: React.ReactNode;
}) {
    return (
        <div>
            <Label className="mb-1.5 block">{label}</Label>
            {children}
        </div>
    );
}

function SwitchCard({
    label,
    description,
    checked,
    disabled,
    onCheckedChange,
}: {
    label: string;
    description: string;
    checked: boolean;
    disabled?: boolean;
    onCheckedChange: (v: boolean) => void;
}) {
    return (
        <div
            className={cn(
                "flex items-center justify-between gap-3 rounded-md border border-input px-3 py-2.5",
                disabled && "opacity-50",
            )}
        >
            <div className="min-w-0">
                <p className="text-sm font-medium">{label}</p>
                <p className="text-xs text-muted-foreground">{description}</p>
            </div>
            <Switch
                checked={checked}
                onCheckedChange={onCheckedChange}
                disabled={disabled}
                className="shrink-0"
            />
        </div>
    );
}

function ReviewCard({
    title,
    children,
}: {
    title: string;
    children: React.ReactNode;
}) {
    return (
        <Card>
            <CardContent className="p-4">
                <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-2">
                    {title}
                </p>
                {children}
            </CardContent>
        </Card>
    );
}
