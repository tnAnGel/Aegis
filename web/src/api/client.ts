// Typed HTTP client for the Aegis admin API.
//
// Token is stored in localStorage under "aegis_admin_token" — kept the
// same key the legacy embedded UI used so an upgrade preserves logins.
// HttpOnly cookie auth is on the roadmap; until then we surface the
// limitation in Settings → API.
//
// Mock mode (VITE_USE_MOCKS=true) hands back synthetic data from
// `mocks.ts` so the UI is browsable without a running backend.

import * as mocks from "./mocks";
import type {
    AcmeConfig,
    AcmeOrder,
    AnomalyRow,
    ApplyResult,
    AuditEntry,
    BenchmarkResult,
    FloodResult,
    ConfigTestResult,
    EnvSetResult,
    EnvVarsResponse,
    HotUriRow,
    MetricsRange,
    MetricsSeriesResponse,
    NewSite,
    RestartResult,
    RuntimeStatus,
    Site,
    ThreatRow,
    TopologyPutResponse,
    TopologyResponse,
    UpstreamHealthEntry,
    XdpCounters,
} from "@/types";

const TOKEN_KEY = "aegis_admin_token";
const BASE = import.meta.env.VITE_AEGIS_API_BASE || "";
const USE_MOCKS = import.meta.env.VITE_USE_MOCKS === "true";

export function getToken(): string {
    return localStorage.getItem(TOKEN_KEY) ?? "";
}

export function setToken(value: string): void {
    // Aggressive normalise — trailing newline from terminal copy/paste
    // is the #1 cause of "401 unauthorized" reports.
    const clean = (value ?? "").replace(/[\s\r\n\t]+/g, "");
    localStorage.setItem(TOKEN_KEY, clean);
}

export function clearToken(): void {
    localStorage.removeItem(TOKEN_KEY);
}

export class ApiError extends Error {
    constructor(
        public status: number,
        public body: string,
        message?: string,
    ) {
        super(message ?? `${status}: ${body}`);
        this.name = "ApiError";
    }
}

async function request<T>(
    path: string,
    opts: RequestInit & { expect?: "json" | "text" } = {},
): Promise<T> {
    const { expect = "json", ...init } = opts;
    const headers = new Headers(init.headers);
    if (!headers.has("x-admin-token") && path.startsWith("/admin/")) {
        const token = getToken();
        if (token) headers.set("x-admin-token", token);
    }
    if (init.body && !headers.has("content-type")) {
        headers.set("content-type", "application/json");
    }
    const url = path.startsWith("http") ? path : `${BASE}${path}`;
    const res = await fetch(url, { ...init, headers });
    if (!res.ok) {
        const body = await res.text().catch(() => "");
        throw new ApiError(res.status, body);
    }
    if (expect === "text") {
        return (await res.text()) as unknown as T;
    }
    return (await res.json()) as T;
}

// ─── Sites ──────────────────────────────────────────────────────────
export const sitesApi = {
    list: async (): Promise<Site[]> => {
        if (USE_MOCKS) return mocks.sites();
        const data = await request<{ sites: Site[] }>("/admin/api/sites");
        return data.sites;
    },
    create: async (site: NewSite): Promise<{ ok: boolean; dsl_snippet: string }> => {
        if (USE_MOCKS) return mocks.createSite(site);
        return request("/admin/api/sites", {
            method: "POST",
            body: JSON.stringify(site),
        });
    },
    /** Upsert (same shape as create — POST is idempotent: same host overwrites the .conf). */
    update: async (site: NewSite): Promise<{ ok: boolean; dsl_snippet: string }> => {
        if (USE_MOCKS) return mocks.createSite(site);
        return request("/admin/api/sites", {
            method: "POST",
            body: JSON.stringify(site),
        });
    },
    remove: async (host: string): Promise<void> => {
        if (USE_MOCKS) return mocks.deleteSite(host);
        await request(`/admin/api/sites/${encodeURIComponent(host)}`, {
            method: "DELETE",
        });
    },
};

// ─── Filters ────────────────────────────────────────────────────────
/** Per-filter effectiveness counters from GET /admin/api/filters — how many
 *  requests each filter blocked / challenged. Distinct from defaultsApi
 *  (which is the on/off toggle state); this is the activity/analytics view. */
export interface FilterActivity {
    name: string;
    blocks: number;
    challenges: number;
}
export const filterActivityApi = {
    get: async (): Promise<FilterActivity[]> => {
        const data = await request<{ filters: FilterActivity[] }>("/admin/api/filters");
        return data.filters ?? [];
    },
};

// ─── V162/V164 — per-domain policy overrides ────────────────────────
/** V166 — per-endpoint short-circuit action. */
export type EndpointAction = "allow" | "block" | "challenge" | "tarpit";
export interface RateLimitOverride {
    rps: number;
    burst: number;
}
export interface DomainPolicy {
    /** Filter-name → enabled override. Missing key = fall through to global. */
    filter_enabled: Record<string, boolean>;
    /** V166 — path-pattern → action mapping. */
    endpoint_policies: Record<string, EndpointAction>;
    /** V234 — per-host rate-limit override (runtime overlay). Omitted/null =
     *  fall through to the global / static-config limits. Set through this
     *  runtime overlay so it works for ops-managed sites without editing
     *  the read-only `.conf`. */
    rate_limit?: RateLimitOverride | null;
}
export interface DomainPolicyResponse {
    host: string;
    policy: DomainPolicy;
    global_filters: Array<{ name: string; enabled: boolean }>;
    note: string;
}
export const sitePolicyApi = {
    /** GET /admin/api/sites/<host>/policy */
    get: async (host: string): Promise<DomainPolicyResponse> => {
        return request<DomainPolicyResponse>(
            `/admin/api/sites/${encodeURIComponent(host)}/policy`,
        );
    },
    /** PUT /admin/api/sites/<host>/policy — atomic replace */
    put: async (
        host: string,
        policy: DomainPolicy,
    ): Promise<{ ok: boolean; host: string; policy: DomainPolicy }> => {
        return request(`/admin/api/sites/${encodeURIComponent(host)}/policy`, {
            method: "PUT",
            body: JSON.stringify(policy),
        });
    },
    /** DELETE /admin/api/sites/<host>/policy — clear all overrides */
    remove: async (host: string): Promise<{ ok: boolean; host: string }> => {
        return request(`/admin/api/sites/${encodeURIComponent(host)}/policy`, {
            method: "DELETE",
        });
    },
};

// ─── V169 — runtime info (Settings page) ────────────────────────────
export interface RuntimeInfo {
    version: string;
    uptime_secs: number;
    config_path: string;
    ml_v2: { kind: "logistic" | "gbm"; available: boolean } | null;
    ja4_reputation: { active: boolean; entry_count: number } | null;
    asn_reputation: { active: boolean; entry_count: number } | null;
    honeypot: {
        enabled: boolean;
        packs_total: number;
        packs_enabled: number;
        custom_paths_count: number;
        tarpit_seconds: number;
        auto_xdp_deny_threshold: number;
    };
    filter_toggles_count: number;
    domain_policy_count: number;
    clamav_addr: string | null;
    adversarial_loop: boolean;
    // Extended env-gate status fields (added alongside /admin/api/env)
    ml_v2_enabled?: boolean;          // AEGIS_ML_V2=1
    ml_v1_enabled?: boolean;          // AEGIS_ML_SCORER=1
    ml_adversarial?: boolean;         // AEGIS_ML_ADVERSARIAL=1
    arsenal_enabled?: boolean;        // AEGIS_ARSENAL != "0"
    tls_fingerprinting?: boolean;     // AEGIS_TLS_FINGERPRINT=1
    llm_honeypot?: boolean;           // AEGIS_LLM_HONEYPOT=1
    upstream_healthcheck?: boolean;   // AEGIS_UPSTREAM_HEALTHCHECK=1
    risk_engine_mode?: string | null; // AEGIS_RISK_ENGINE_MODE
    dynamic_trust_enabled?: boolean;  // AEGIS_DYNAMIC_TRUST_ENABLE=1
    response_cache_enabled?: boolean; // AEGIS_RESPONSE_CACHE_ENABLE=1
    log_json?: boolean;               // AEGIS_LOG_JSON=1
    fw_backend?: string;              // AEGIS_FW_BACKEND, default "auto"
    reuseport?: boolean;              // AEGIS_PINGORA_REUSEPORT=1
}
export const runtimeInfoApi = {
    get: async (): Promise<RuntimeInfo> => {
        return request<RuntimeInfo>("/admin/api/runtime/info");
    },
};

// ─── Env-var feature flags (GET/PUT /admin/api/env) ─────────────────
// GET requires Read role; PUT requires Write role.
// Secrets are write-only: GET returns configured:true/false, value:null.
export const envApi = {
    /** GET /admin/api/env — list all allowlisted AEGIS_* feature flags and their status. */
    get: async (): Promise<EnvVarsResponse> => {
        return request<EnvVarsResponse>("/admin/api/env");
    },
    /** Alias for get() — convenience name used by components that follow the
     *  list/set convention of other panel APIs. */
    list: async (): Promise<EnvVarsResponse> => {
        return request<EnvVarsResponse>("/admin/api/env");
    },
    /** PUT /admin/api/env — set or unset one env-var feature flag.
     *  Pass value=null to remove the key from aegis.env.
     *  Returns restart_required=true for startup-gated vars. */
    set: async (key: string, value: string | null): Promise<EnvSetResult> => {
        return request<EnvSetResult>("/admin/api/env", {
            method: "PUT",
            body: JSON.stringify({ key, value }),
        });
    },
};

// ─── Service restart (POST /admin/api/restart) ───────────────────────
// Requires Write role. Spawns `systemctl restart aegis-pingora.target`;
// connection will drop within a couple of seconds.
export const restartApi = {
    run: async (): Promise<RestartResult> => {
        return request<RestartResult>("/admin/api/restart", {
            method: "POST",
            body: JSON.stringify({}),
        });
    },
};

// ─── V160 — runtime filter on/off toggles ───────────────────────────
export interface DefaultFilter {
    name: string;
    enabled: boolean;
}
export const defaultsApi = {
    /// GET /admin/api/defaults/filters — runtime toggle state for every
    /// registered filter. In-memory only; restart resets to config.
    list: async (): Promise<{ filters: DefaultFilter[]; note: string }> => {
        if (USE_MOCKS) {
            return {
                filters: [
                    { name: "waf", enabled: true },
                    { name: "bot_fingerprint", enabled: true },
                    { name: "challenge", enabled: true },
                    { name: "rate_limit", enabled: true },
                ],
                note: "mock",
            };
        }
        return request<{ filters: DefaultFilter[]; note: string }>(
            "/admin/api/defaults/filters",
        );
    },
    /// PUT /admin/api/defaults/filters — flip one or more filters.
    update: async (updates: DefaultFilter[]): Promise<{ ok: boolean; applied: number }> => {
        if (USE_MOCKS) return { ok: true, applied: updates.length };
        return request("/admin/api/defaults/filters", {
            method: "PUT",
            body: JSON.stringify({ updates }),
        });
    },
};

// ─── Metrics ────────────────────────────────────────────────────────
export const metricsApi = {
    raw: async (): Promise<string> => {
        if (USE_MOCKS) return mocks.metricsRaw();
        return request<string>("/metrics", { expect: "text" });
    },

    /**
     * GET /admin/api/metrics/series?range=<range>
     *
     * Returns a time-bucketed series of fleet-wide counters and derived rates.
     * The backend samples the mmap cluster counters (global.rs cluster_get)
     * and stores them in the PingoraBackground 30 s tick under AEGIS_HOME.
     * Only one worker writes (single-writer file lock); all workers read.
     *
     * In mock mode a synthetic 60-point series is returned so the UI is
     * browsable without a running backend.
     */
    series: async (range: MetricsRange): Promise<MetricsSeriesResponse> => {
        if (USE_MOCKS) return mockMetricsSeries(range);
        return request<MetricsSeriesResponse>(
            `/admin/api/metrics/series?range=${encodeURIComponent(range)}`,
        );
    },
};

// ─── Health / threats / hot URIs / anomaly ─────────────────────────
export const opsApi = {
    health: async (): Promise<UpstreamHealthEntry[]> => {
        if (USE_MOCKS) return mocks.health();
        const txt = await request<string>("/admin/health", { expect: "text" });
        return parseHealth(txt);
    },
    threats: async (): Promise<ThreatRow[]> => {
        if (USE_MOCKS) return mocks.threats();
        const txt = await request<string>("/admin/threats", { expect: "text" });
        return parseThreats(txt);
    },
    hotUris: async (): Promise<HotUriRow[]> => {
        if (USE_MOCKS) return mocks.hotUris();
        const txt = await request<string>("/admin/hot_uris", { expect: "text" });
        return parseHotUris(txt);
    },
    anomaly: async (): Promise<AnomalyRow[]> => {
        if (USE_MOCKS) return mocks.anomaly();
        const txt = await request<string>("/admin/anomaly", { expect: "text" });
        return parseAnomaly(txt);
    },
    xdp: async (): Promise<XdpCounters> => {
        if (USE_MOCKS) return mocks.xdp();
        const txt = await request<string>("/admin/xdp", { expect: "text" });
        return parseXdp(txt);
    },
    audit: async (): Promise<AuditEntry[]> => {
        if (USE_MOCKS) return mocks.audit();
        const txt = await request<string>("/admin/api/audit", { expect: "text" });
        return parseAudit(txt);
    },
};

// ─── V106: Signature miner (V99 backend) ────────────────────────────
export interface SignatureCandidate {
    confidence: number;
    attack_support: number;
    benign_support: number;
    category: string;
    ngram: string;
}

export const signatureMineApi = {
    /**
     * POST /admin/signature_mine — runs the V99 n-gram miner on
     * `attacks` against the `benign` contrast set. Body format expected
     * by the backend: attack lines, then a literal `---` separator,
     * then benign lines.
     */
    mine: async (
        attacks: string[],
        benign: string[],
    ): Promise<{ candidates: SignatureCandidate[]; raw: string }> => {
        const body =
            attacks.filter((s) => s.trim()).join("\n") +
            "\n---\n" +
            benign.filter((s) => s.trim()).join("\n");
        const txt = await request<string>("/admin/signature_mine", {
            method: "POST",
            body,
            headers: { "content-type": "text/plain" },
            expect: "text",
        });
        return { candidates: parseSignatureMineOutput(txt), raw: txt };
    },

    /**
     * GET /admin/api/mined_signatures — auto-mined attack-signature
     * candidates from the online tarpit→miner background pipeline
     * (separate from the manual `mine()` contrast run above). Read-only;
     * operators still approve candidates via the config editor.
     */
    minedCandidates: async (): Promise<MinedSignaturesResponse> => {
        return request<MinedSignaturesResponse>("/admin/api/mined_signatures");
    },
};

/** One auto-mined candidate from the online miner. */
export interface MinedCandidate {
    ngram: string;
    confidence: number;
    attack_support: number;
    benign_support: number;
    category: string;
}
export interface MinedSignaturesResponse {
    enabled: boolean;
    last_run_unix_secs?: number;
    note?: string;
    candidates: MinedCandidate[];
}

function parseSignatureMineOutput(txt: string): SignatureCandidate[] {
    // Lines look like: "0.950  1.000  0.050  sqli  union select"
    // Skipped: lines starting with '#' (header comments) or empty.
    const out: SignatureCandidate[] = [];
    for (const raw of txt.split(/\r?\n/)) {
        const line = raw.trim();
        if (!line || line.startsWith("#") || line.startsWith("no candidates")) continue;
        // Split on whitespace but cap to 5 fields so the ngram (which can
        // contain spaces) stays intact.
        const parts = line.split(/\s+/);
        if (parts.length < 5) continue;
        const [confStr, atkStr, benStr, category, ...rest] = parts;
        if (!confStr || !atkStr || !benStr || !category) continue;
        const confidence = Number.parseFloat(confStr);
        const attack_support = Number.parseFloat(atkStr);
        const benign_support = Number.parseFloat(benStr);
        if (!Number.isFinite(confidence)) continue;
        out.push({
            confidence,
            attack_support,
            benign_support,
            category,
            ngram: rest.join(" "),
        });
    }
    return out;
}

// ─── V120: Site cartography (V119 backend) ──────────────────────────
export interface SiteMapEndpoint {
    method: string;
    path_pattern: string;
    hits: number;
    last_seen_unix_secs: number;
    status_2xx: number;
    status_3xx: number;
    status_4xx: number;
    status_5xx: number;
}

/** One host entry in the aggregated site-map host list.
 *  The backend merges all shard-*.json files and returns per-host totals.
 *  Fields `total_hits` and `last_seen_unix_secs` are present in the new
 *  shard-based aggregated response; the legacy response only had `hosts[]`.
 */
export interface SiteMapHostEntry {
    host: string;
    /** Sum of all endpoint hits for this host across all shards. */
    total_hits: number;
    /** Unix seconds of the most-recently-seen request to this host. */
    last_seen_unix_secs: number;
}

export interface SiteMapHostsResponse {
    /** Flat host list (legacy compat — always present). */
    hosts: string[];
    /** Richer per-host rows (new shard-based backend).
     *  If the backend is old and omits this, we synthesise it from `hosts`. */
    host_entries?: SiteMapHostEntry[];
    total_endpoints: number;
}

export const siteMapApi = {
    /** GET /admin/api/site_map — list of hosts with discovered endpoints. */
    hosts: async (): Promise<SiteMapHostsResponse> => {
        if (USE_MOCKS) {
            return {
                hosts: ["example.com"],
                host_entries: [{ host: "example.com", total_hits: 0, last_seen_unix_secs: 0 }],
                total_endpoints: 0,
            };
        }
        return request<SiteMapHostsResponse>(
            "/admin/api/site_map",
            { expect: "json" },
        );
    },
    /** GET /admin/api/site_map/<host> — endpoints for one host. */
    forHost: async (host: string): Promise<{ host: string; endpoints: SiteMapEndpoint[] }> => {
        if (USE_MOCKS) return { host, endpoints: [] };
        return request<{ host: string; endpoints: SiteMapEndpoint[] }>(
            `/admin/api/site_map/${encodeURIComponent(host)}`,
            { expect: "json" },
        );
    },
};

// ─── V121: Bot vs DDoS analytics (V121 backend) ────────────────────
export interface BotEntry {
    client_ip: string;
    primary_reason: string;
    hits: number;
    last_seen_unix_secs: number;
}
export interface DdosTarget {
    host: string;
    path_pattern: string;
    total_hits: number;
    distinct_ips: number;
    last_seen_unix_secs: number;
}
export const threatAnalyticsApi = {
    bots: async (): Promise<{ bots: BotEntry[]; summary: { tracked_bots: number } }> => {
        if (USE_MOCKS) return { bots: [], summary: { tracked_bots: 0 } };
        return request<{ bots: BotEntry[]; summary: { tracked_bots: number } }>(
            "/admin/api/bots",
            { expect: "json" },
        );
    },
    ddos: async (): Promise<{ targets: DdosTarget[]; summary: { tracked_endpoints: number } }> => {
        if (USE_MOCKS) return { targets: [], summary: { tracked_endpoints: 0 } };
        return request<{ targets: DdosTarget[]; summary: { tracked_endpoints: number } }>(
            "/admin/api/ddos",
            { expect: "json" },
        );
    },
};

// ─── Config editor ──────────────────────────────────────────────────
export const configApi = {
    raw: async (): Promise<string> => {
        if (USE_MOCKS) return mocks.configRaw();
        return request<string>("/admin/api/config/raw", { expect: "text" });
    },
    save: async (text: string): Promise<ConfigTestResult> => {
        if (USE_MOCKS) return mocks.configSave();
        return request<ConfigTestResult>("/admin/api/config/raw", {
            method: "PUT",
            body: JSON.stringify({ content: text }),
        });
    },
    test: async (text: string): Promise<ConfigTestResult> => {
        if (USE_MOCKS) return mocks.configTest();
        return request<ConfigTestResult>("/admin/api/config/test", {
            method: "POST",
            body: JSON.stringify({ content: text }),
        });
    },
    apply: async (): Promise<ApplyResult> => {
        if (USE_MOCKS) return mocks.configApply();
        // POST /admin/api/config/apply — Write role required.
        // Same response shape as POST /admin/api/restart.
        const result = await request<RestartResult>("/admin/api/config/apply", {
            method: "POST",
            body: JSON.stringify({}),
        });
        return { ok: result.ok, message: result.note };
    },
};

// ─── Runtime ────────────────────────────────────────────────────────
export const runtimeApi = {
    status: async (): Promise<RuntimeStatus> => {
        if (USE_MOCKS) return mocks.runtimeStatus();
        return request<RuntimeStatus>("/admin/api/runtime/status");
    },
};

// ─── Honeypots ──────────────────────────────────────────────────────
export interface HoneypotPack {
    id: string;
    name: string;
    description: string;
    path_count: number;
    /// V158 — current enabled state merged with operator overrides.
    /// Defaults to `true` per packs.rs ("all packs are globally safe").
    enabled?: boolean;
}

export interface HoneypotState {
    enabled: boolean;
    packs: Record<string, boolean>;
    per_host: Record<string, Record<string, boolean>>;
    /** Hosts in this set bypass ALL honeypot matching — operator-trusted sites. */
    host_disabled: string[];
    custom_paths: string[];
    tarpit_seconds: number;
    tarpit_chunk_bytes: number;
    score_bump: number;
    auto_xdp_deny_threshold: number;
    server_header: string;
}

export const honeypotApi = {
    builtin: async (): Promise<HoneypotPack[]> => {
        const data = await request<{ packs: HoneypotPack[] }>("/admin/api/honeypots/builtin");
        return data.packs;
    },
    get: async (): Promise<HoneypotState> => {
        return request<HoneypotState>("/admin/api/honeypots");
    },
    save: async (state: HoneypotState): Promise<void> => {
        await request("/admin/api/honeypots", {
            method: "PUT",
            body: JSON.stringify(state),
        });
    },
    toggleGlobal: async (pack_id: string, enabled: boolean): Promise<void> => {
        await request("/admin/api/honeypots/global", {
            method: "PUT",
            body: JSON.stringify({ pack_id, enabled }),
        });
    },
    toggleHost: async (host: string, pack_id: string, enabled: boolean): Promise<void> => {
        await request("/admin/api/honeypots/host", {
            method: "PUT",
            body: JSON.stringify({ host, pack_id, enabled }),
        });
    },
    clearHost: async (host: string): Promise<void> => {
        await request(`/admin/api/honeypots/host/${encodeURIComponent(host)}`, {
            method: "DELETE",
        });
    },
    /**
     * PUT /admin/api/honeypots/host/enabled
     * Pass enabled=false to add a host to the bypass set (trusted operator site).
     * Pass enabled=true to remove it (re-enable honeypot matching for that host).
     */
    setHostEnabled: async (host: string, enabled: boolean): Promise<void> => {
        await request("/admin/api/honeypots/host/enabled", {
            method: "PUT",
            body: JSON.stringify({ host, enabled }),
        });
    },
};

// ─── Auth ───────────────────────────────────────────────────────────
export interface MeResponse {
    // May be absent at runtime during a rolling-restart window — readers must be
    // null-safe (see TopBarV2.displayName).
    email?: string;
    // The backend emits BOTH `must_change` and the legacy `must_change_credentials`.
    // Readers should accept either (see useAuth) so the forced credential-change
    // flow fires on both the login and the /me-refresh paths.
    must_change?: boolean;
    must_change_credentials?: boolean;
    auth: "session" | "config_token";
}

export const authApi = {
    me: async (): Promise<MeResponse> => {
        if (USE_MOCKS) return { email: "mock-user", must_change: false, auth: "session" };
        return request<MeResponse>("/admin/api/me");
    },
    login: async (
        email: string,
        password: string,
    ): Promise<{
        token: string;
        email?: string;
        must_change?: boolean;
        must_change_credentials?: boolean;
    }> => {
        if (USE_MOCKS)
            return { token: "mock-0000000000000000", email, must_change: false };
        return request("/admin/api/login", {
            method: "POST",
            body: JSON.stringify({ email, password }),
        });
    },
    logout: async (): Promise<void> => {
        if (USE_MOCKS) return;
        await request("/admin/api/logout", { method: "POST" });
    },
    changeCredentials: async (
        current_password: string,
        new_email: string,
        new_password: string,
    ): Promise<{ ok: boolean; token: string; email: string }> => {
        if (USE_MOCKS)
            return { ok: true, token: "mock-0000000000000000", email: new_email };
        return request("/admin/api/change-credentials", {
            method: "POST",
            body: JSON.stringify({ current_password, new_email, new_password }),
        });
    },
};

// ─── Parsers for plain-text endpoints ───────────────────────────────
function parseHealth(text: string): UpstreamHealthEntry[] {
    if (text.startsWith("all_upstreams_healthy")) return [];
    return text
        .split("\n")
        .map((line) => line.trim())
        .filter(Boolean)
        .flatMap((line) => {
            const m = line.match(/^unhealthy\s+(\S+)\s+since_ms=(\d+)/);
            return m ? [{ host: m[1]!, since_ms: parseInt(m[2]!, 10) }] : [];
        });
}

function parseThreats(text: string): ThreatRow[] {
    return text
        .split("\n")
        .map((l) => l.trim())
        .filter(Boolean)
        .flatMap((line) => {
            const m = line.match(/^(\S+)\s+([\d.]+)$/);
            return m ? [{ ip: m[1]!, score: parseFloat(m[2]!) }] : [];
        });
}

function parseHotUris(text: string): HotUriRow[] {
    if (text.startsWith("none")) return [];
    return text
        .split("\n")
        .map((l) => l.trim())
        .filter(Boolean)
        .flatMap((line) => {
            const idx = line.lastIndexOf(" ");
            if (idx <= 0) return [];
            const uri = line.slice(0, idx);
            const hits = parseInt(line.slice(idx + 1), 10);
            return Number.isFinite(hits) ? [{ uri, hits }] : [];
        });
}

function parseAnomaly(text: string): AnomalyRow[] {
    if (text.startsWith("no_active_attacks")) return [];
    return text
        .split("\n")
        .map((l) => l.trim())
        .filter(Boolean)
        .flatMap((line) => {
            const m = line.match(/^(\S+)\s+attack_remaining_ms=(\d+)/);
            return m ? [{ host: m[1]!, remaining_ms: parseInt(m[2]!, 10) }] : [];
        });
}

function parseXdp(text: string): XdpCounters {
    const lines = text.split("\n").map((l) => l.trim()).filter(Boolean);
    const grab = (key: string) => {
        const found = lines.find((l) => l.startsWith(key + " "));
        return found ? parseInt(found.split(" ")[1] ?? "0", 10) : 0;
    };
    return {
        pass: grab("xdp_pass"),
        drop_deny: grab("xdp_drop_deny"),
        drop_rate: grab("xdp_drop_rate"),
        drop_allowonly: grab("xdp_drop_allowonly"),
        drop_syn: grab("xdp_drop_syn"),
    };
}

function parseAudit(text: string): AuditEntry[] {
    return text
        .split("\n")
        .map((l) => l.trim())
        .filter(Boolean)
        .flatMap((line) => {
            try {
                const obj = JSON.parse(line);
                return [
                    {
                        ts: obj.ts ?? 0,
                        peer: obj.peer ?? "?",
                        method: obj.method ?? "?",
                        path: obj.path ?? "?",
                        role: obj.role ?? "anonymous",
                        status: obj.status ?? 0,
                    },
                ];
            } catch {
                return [];
            }
        })
        .reverse(); // newest first
}

// ─── Mock helpers ────────────────────────────────────────────────────────────

/** Generates a synthetic MetricsSeriesResponse for mock / dev mode. */
function mockMetricsSeries(range: MetricsRange): MetricsSeriesResponse {
    const RANGE_SECS: Record<MetricsRange, number> = {
        "1h":  3_600,
        "6h":  21_600,
        "24h": 86_400,
        "7d":  604_800,
        "30d": 2_592_000,
    };
    const totalSecs = RANGE_SECS[range];
    // aim for ~60 buckets; round to a clean bucket size
    const rawBucket = totalSecs / 60;
    const bucketSecs = [60, 300, 600, 1800, 3600, 7200, 14400, 43200, 86400]
        .find((b) => b >= rawBucket) ?? 86400;
    const buckets = Math.ceil(totalSecs / bucketSecs);

    const resolution = bucketSecs >= 3600
        ? `PT${bucketSecs / 3600}H`
        : `PT${bucketSecs / 60}M`;

    const nowSecs = Math.floor(Date.now() / 1000);
    const startSecs = nowSecs - totalSecs;

    let cumTotal = 180_000;
    let cumDenied = 4_000;
    let cumChallenged = 600;
    let cum2xx = 174_000;
    let cum4xx = 1_400;
    let cum5xx = 280;
    let cumCacheHits = 90_000;
    let cumCacheMisses = 84_000;

    const points = Array.from({ length: buckets }, (_, i) => {
        const ts = startSecs + i * bucketSecs;
        // Simulate a mid-range traffic spike at bucket 40 %
        const spikeFactor = i / buckets > 0.35 && i / buckets < 0.55 ? 2.5 : 1;
        const delta = Math.round(500 * spikeFactor * (0.8 + 0.4 * Math.random()));
        const denied = Math.round(delta * 0.023 * (0.8 + 0.4 * Math.random()));
        const challenged = Math.round(delta * 0.003 * (0.8 + 0.4 * Math.random()));
        const ok2xx = Math.round(delta * 0.96);
        const err4xx = Math.round(delta * 0.008);
        const err5xx = Math.round(delta * 0.002);
        const hits = Math.round(delta * 0.49);
        const misses = delta - hits;

        cumTotal += delta;
        cumDenied += denied;
        cumChallenged += challenged;
        cum2xx += ok2xx;
        cum4xx += err4xx;
        cum5xx += err5xx;
        cumCacheHits += hits;
        cumCacheMisses += misses;

        void cumTotal; void cumDenied; void cumChallenged; void cum2xx;
        void cum4xx; void cum5xx; void cumCacheHits; void cumCacheMisses;
        // Match the real /admin/api/metrics/series shape: per-bucket deltas
        // + backend-derived `allow`.
        return {
            t_unix: ts,
            requests: delta,
            denied,
            challenged,
            rate_limited: 0,
            tarpit: 0,
            rtbh: 0,
            allow: Math.max(0, delta - denied - challenged),
            cache_hits: hits,
            cache_misses: misses,
            upstream_2xx: ok2xx,
            upstream_4xx: err4xx,
            upstream_5xx: err5xx,
        };
    });

    return { resolution, points };
}

// Re-export for components that want the constants.
export const TOKEN_LOCAL_STORAGE_KEY = TOKEN_KEY;

// ─── V208 — Update checker ──────────────────────────────────────────
export type UpdateChannel = "stable" | "beta" | "nightly";
export interface ReleaseAsset {
    name: string;
    size: number;
    url: string;
}
export interface Release {
    tag_name: string;
    name: string;
    body: string;
    published_at: string;
    prerelease: boolean;
    draft: boolean;
    assets: ReleaseAsset[];
}
export interface UpdateStatus {
    current_version: string;
    channel: UpdateChannel;
    repo_api_url: string;
    latest: Release | null;
    update_available: boolean;
    last_checked_at: number | null;
    last_error: string | null;
}
export interface UpdateConfig {
    repo_api_url: string;
    channel: UpdateChannel;
    current_version: string;
    poll_interval_secs: number;
}
// V233 — REMOVED: the SnapshotEntry / InstalledRelease / ApplyStatus /
// ApplyPayload types and the updatesApi.apply / snapshots / createSnapshot
// / restoreSnapshot / deleteSnapshot / installedReleases / applyStatus
// methods. They drove the in-panel self-update *apply* mechanism, which
// downloaded and executed an attacker-controllable, signature-unverified
// binary as the service user (unauthenticated-RCE design). The backend
// routes are gone too. Only the read-only checker remains below.

export const updatesApi = {
    status: async (): Promise<UpdateStatus & { wired?: boolean; note?: string }> => {
        return request<UpdateStatus & { wired?: boolean; note?: string }>("/admin/api/updates/status");
    },
    check: async (): Promise<{ ok: boolean; releases_fetched?: number; status: UpdateStatus; error?: string }> => {
        return request("/admin/api/updates/check", { method: "POST" });
    },
    releases: async (): Promise<Release[]> => {
        return request<Release[]>("/admin/api/updates/releases");
    },
    setConfig: async (cfg: UpdateConfig): Promise<{ ok: boolean; config: UpdateConfig }> => {
        return request("/admin/api/updates/config", {
            method: "PUT",
            body: JSON.stringify(cfg),
            headers: { "content-type": "application/json" },
        });
    },
};

// ─── V205-V207 — Per-domain challenge config ────────────────────────
export interface DomainChallengeConfig {
    argon2_pow?: boolean;
    argon2_bits?: number | null;
    argon2_memory_kb?: number | null;
    privacy_pass?: boolean;
    chained_trust?: boolean;
    adaptive?: boolean;
    varied_errors?: boolean;
    decoy_captcha?: boolean;
    honeypot_fields?: boolean;
    trust_for_auth?: boolean;
    fast_track_threshold?: number | null;
    attack_mode_bits?: number | null;
    // ─── Challenge arsenal (passive signals) ─────────────────────────
    ja4_ua_consistency?: boolean;
    header_fingerprint?: boolean;
    h2_fingerprint?: boolean;
    datacenter_asn_challenge?: boolean;
    // ─── Challenge arsenal (browser checks) ──────────────────────────
    headless_detection?: boolean;
    webgl_audio_fp?: boolean;
    dom_timing_entropy?: boolean;
    proof_of_click?: boolean;
    // ─── Challenge arsenal (enforcement) ─────────────────────────────
    reputation_difficulty?: boolean;
    fail_to_xdp_deny?: boolean;
    turnstile?: boolean;
}
export interface AdaptiveLadderState {
    attack_mode_bits: number;
    randomize_order: boolean;
    fast_track_threshold: number;
}
export interface ChallengeGlobalState {
    attack_mode: boolean;
    config: AdaptiveLadderState;
    fast_track_hits: number;
    attack_mode_bumps: number;
    randomized_picks: number;
    decoy_forms_rendered: number;
    honeypot_fills_detected: number;
    varied_errors_rendered: number;
    trust_grants_active: number;
    privacy_pass_issuers: number;
}
export interface ChallengeHostsResponse {
    wired: boolean;
    hosts: Array<{ host: string; config: DomainChallengeConfig }>;
    global?: ChallengeGlobalState;
}
export const challengeApi = {
    listHosts: async (): Promise<ChallengeHostsResponse> => {
        return request<ChallengeHostsResponse>("/admin/api/challenge/hosts");
    },
    getHost: async (host: string): Promise<{ host: string; config: DomainChallengeConfig }> => {
        return request<{ host: string; config: DomainChallengeConfig }>(`/admin/api/sites/${encodeURIComponent(host)}/challenge`);
    },
    putHost: async (host: string, cfg: DomainChallengeConfig): Promise<{ host: string; config: DomainChallengeConfig; status: string }> => {
        return request<{ host: string; config: DomainChallengeConfig; status: string }>(
            `/admin/api/sites/${encodeURIComponent(host)}/challenge`,
            { method: "PUT", body: JSON.stringify(cfg), headers: { "content-type": "application/json" } },
        );
    },
    deleteHost: async (host: string): Promise<{ host: string; removed: boolean }> => {
        return request<{ host: string; removed: boolean }>(
            `/admin/api/sites/${encodeURIComponent(host)}/challenge`,
            { method: "DELETE" },
        );
    },
    setAttackMode: async (on: boolean): Promise<{ attack_mode: boolean }> => {
        return request<{ attack_mode: boolean }>(
            "/admin/api/challenge/attack-mode",
            { method: "POST", body: JSON.stringify({ on }), headers: { "content-type": "application/json" } },
        );
    },
};

// ─── V191 — Defence Arsenal ─────────────────────────────────────────
export interface ArsenalModule {
    id: string;
    v: string;
    family:
        | "fingerprint"
        | "waf"
        | "ddos"
        | "honeypot"
        | "telemetry"
        | "challenge"
        | "deception";
    label: string;
    desc: string;
    status: "shipped" | "planned" | "experimental";
}
export interface ArsenalSummary {
    total_modules: number;
    families: Record<string, number>;
    version_range: string;
}
export type ArsenalCounters = {
    wired: boolean;
    [moduleId: string]: { [key: string]: number } | boolean;
};
export interface ArsenalResponse {
    summary: ArsenalSummary;
    modules: ArsenalModule[];
    counters?: ArsenalCounters;
}
// ─── V213-V220 — Panel gap-fill APIs ────────────────────────────────

export interface ScenarioConfig {
    name: string;
    description?: string;
    filter: Record<string, unknown>;
    groupby: string;
    distinct?: string | null;
    capacity: number;
    leak_speed: { secs: number; nanos: number } | string;
    blackhole?: { secs: number; nanos: number } | string | null;
    action: string;
}
export const scenariosApi = {
    list: async (): Promise<{ wired: boolean; scenarios: ScenarioConfig[]; stats?: Record<string, number> }> => {
        return request("/admin/api/scenarios");
    },
    load: async (yaml: string): Promise<{ ok: boolean; loaded?: number; error?: string }> => {
        return request("/admin/api/scenarios/load", {
            method: "POST",
            body: yaml,
            headers: { "content-type": "text/yaml" },
        });
    },
    test: async (yaml: string): Promise<{ ok: boolean; parsed?: ScenarioConfig[]; error?: string }> => {
        return request("/admin/api/scenarios/test", {
            method: "POST",
            body: yaml,
            headers: { "content-type": "text/yaml" },
        });
    },
};

export interface ActiveAction {
    kind: string;
    target: string;
    reason: string | null;
    source_module: string | null;
    applied_at: number;
    remaining_secs: number | null;
}
export const actuatorsApi = {
    list: async (): Promise<{ wired: boolean; active: ActiveAction[]; kinds: string[]; stats: Record<string, number> }> => {
        return request("/admin/api/actuators");
    },
    revert: async (kind: string, target_kind: string, target_value: string): Promise<{ outcome: string }> => {
        return request("/admin/api/actuators/revert", {
            method: "POST",
            body: JSON.stringify({ kind, target_kind, target_value }),
            headers: { "content-type": "application/json" },
        });
    },
};

export interface SigmaRule {
    id: string;
    field: string;
    op: string;
    value: string;
    severity: string;
    action: string;
    tags: string[];
    enabled: boolean;
}
export const sigmaApi = {
    status: async (): Promise<{ path: string; exists: boolean; rule_count: number; size_bytes: number; note: string }> => {
        return request("/admin/api/sigma/rules");
    },
    importRule: async (yaml: string): Promise<{ ok: boolean; title?: string; emitted?: number; rules?: unknown[]; error?: string }> => {
        return request("/admin/api/sigma/import", {
            method: "POST",
            body: yaml,
            headers: { "content-type": "text/yaml" },
        });
    },
    // V237 — per-rule enable/disable for the bundled corpus.
    list: async (): Promise<{ path: string; total: number; disabled_count: number; rules: SigmaRule[] }> => {
        return request("/admin/api/sigma/rules/list");
    },
    toggle: async (id: string, enabled: boolean): Promise<{ ok: boolean; id: string; enabled: boolean }> => {
        return request("/admin/api/sigma/rules/toggle", {
            method: "PUT",
            body: JSON.stringify({ id, enabled }),
            headers: { "content-type": "application/json" },
        });
    },
};

export interface EnrichmentSourceStats {
    name: string;
    queries: number;
    hits: number;
    misses: number;
}
export const enrichmentApi = {
    status: async (): Promise<{ wired: boolean; sources: EnrichmentSourceStats[]; cache?: { hits: number; misses: number; size: number } }> => {
        return request("/admin/api/enrichment");
    },
    lookup: async (key_kind: "ip" | "ja4" | "asn" | "user_agent", value: string): Promise<{ aggregate: string; sources: Array<{ source: string; verdict: string; label: string }> }> => {
        return request("/admin/api/enrichment/lookup", {
            method: "POST",
            body: JSON.stringify({ key_kind, value }),
            headers: { "content-type": "application/json" },
        });
    },
};

export const reputationApi = {
    ja4: async (): Promise<{ wired: boolean; entry_count: number; active: boolean; corpus_count: number }> => {
        return request("/admin/api/reputation/ja4");
    },
    ja4Lookup: async (ja4: string): Promise<{ ja4: string; feed?: unknown; corpus?: unknown }> => {
        return request("/admin/api/reputation/ja4/lookup", {
            method: "POST",
            body: JSON.stringify({ ja4 }),
            headers: { "content-type": "application/json" },
        });
    },
    asn: async (): Promise<{ wired: boolean; entry_count: number; active: boolean }> => {
        return request("/admin/api/reputation/asn");
    },
    asnLookup: async (ip: string): Promise<{ ip: string; score: number | null; tag: string | null; match_kind: string | null; matched: boolean }> => {
        return request("/admin/api/reputation/asn/lookup", {
            method: "POST",
            body: JSON.stringify({ ip }),
            headers: { "content-type": "application/json" },
        });
    },
};

export const mlApi = {
    status: async (): Promise<{ v2_wired: boolean; v2_kind: string | null; adversarial_loop_env: boolean; note: string }> => {
        return request("/admin/api/ml/status");
    },
    retrain: async (): Promise<{ ok: boolean; error?: string; hint?: string }> => {
        return request("/admin/api/ml/retrain", { method: "POST" });
    },
    adversarial: async (): Promise<{ ok: boolean; enabled: boolean; hint: string }> => {
        return request("/admin/api/ml/adversarial", { method: "POST" });
    },
};

export interface PrivacyPassIssuerPayload {
    name: string;
    key_id_hex: string;
    public_key_hex: string;
    algorithm: "ed25519" | "hmac_sha256";
    trust_duration_secs: number;
}
export const privacyPassApi = {
    status: async (): Promise<{ wired: boolean; issuer_count: number; nonce_cache_size?: number; note?: string }> => {
        return request("/admin/api/privacy-pass");
    },
    addIssuer: async (issuer: PrivacyPassIssuerPayload): Promise<{ ok: boolean; name?: string; error?: string }> => {
        return request("/admin/api/privacy-pass/issuers", {
            method: "POST",
            body: JSON.stringify(issuer),
            headers: { "content-type": "application/json" },
        });
    },
};

export interface BgpAnnounce {
    ip: string;
    community: string;
    age_secs: number;
}
export const bgpApi = {
    list: async (): Promise<{ wired: boolean; active_count: number; active: BgpAnnounce[] }> => {
        return request("/admin/api/bgp/announces");
    },
    withdraw: async (ip: string): Promise<{ ok: boolean; ip?: string; error?: string }> => {
        return request("/admin/api/bgp/withdraw", {
            method: "POST",
            body: JSON.stringify({ ip }),
            headers: { "content-type": "application/json" },
        });
    },
};

// ─── V221-V227 — Final coverage APIs ────────────────────────────────

export const telemetryApi = {
    status: async (): Promise<{
        event_bridge: { format: string; format_options: string[]; socket_path: string | null };
        clamav: { enabled: boolean; addr: string | null; env_var: string };
        audit_log_path: string | null;
    }> => request("/admin/api/telemetry/status"),
};

export interface GeoipStatus {
    geoip_db_path: string | null;
    asn_db_path: string | null;
    loaded: boolean;
    database_type?: string | null;
    build_epoch?: number | null;
    bundled?: boolean;
    attribution?: string;
    note: string;
}
export const geoipApi = {
    status: async (): Promise<GeoipStatus> => request("/admin/api/geoip/status"),
    lookup: async (ip: string): Promise<{ ip: string; note: string }> =>
        request("/admin/api/geoip/lookup", {
            method: "POST",
            body: JSON.stringify({ ip }),
            headers: { "content-type": "application/json" },
        }),
    /** POST /admin/api/geoip/update — refresh the bundled db-ip Country Lite DB. */
    update: async (): Promise<{ ok: boolean; note: string }> =>
        request("/admin/api/geoip/update", {
            method: "POST",
            body: JSON.stringify({}),
            headers: { "content-type": "application/json" },
        }),
};

export const clusterApi = {
    status: async (): Promise<{
        shared_scorer_attached: boolean;
        counts: { ipv4_slots_active?: number; top?: Array<{ ip: string; score: number }> };
        note: string;
    }> => request("/admin/api/cluster/status"),
};

export const tarpitApi = {
    status: async (): Promise<{
        tarpit_seconds: number;
        tarpit_chunk_bytes: number;
        auto_xdp_deny_threshold: number;
        poisoned_tarpit_default_delay_ms: number;
        note: string;
    }> => request("/admin/api/tarpit/status"),
};

export const honeypotYamlApi = {
    list: async (): Promise<{ wired: boolean; descriptors: Array<{ name: string; path_pattern: string; turns: number }>; active_sessions?: number }> =>
        request("/admin/api/honeypot-yaml"),
    parse: async (yaml: string): Promise<{ ok: boolean; parsed?: Array<{ name: string; path_pattern: string; turns: number }>; error?: string; note?: string }> =>
        request("/admin/api/honeypot-yaml/load", {
            method: "POST",
            body: yaml,
            headers: { "content-type": "text/yaml" },
        }),
};

export const crowdsecApi = {
    status: async (): Promise<{ lapi_url: string | null; bouncer_key_configured: boolean; format_adapter_available: boolean; note: string }> =>
        request("/admin/api/crowdsec/status"),
};

export const captchaApi = {
    status: async (): Promise<{
        pow: { enabled: boolean; difficulty_bits: string; algorithm: string };
        external_providers: { hcaptcha: boolean; turnstile: boolean; recaptcha: boolean };
        note: string;
    }> => request("/admin/api/captcha/status"),
};

export const routeDifficultyApi = {
    list: async (): Promise<{
        wired: boolean;
        overrides: Array<{ host: string; path_pattern: string; difficulty_bits: number; force_kind: string | null }>;
        ai_scraper_preset?: boolean;
        auth_preset?: boolean;
    }> => request("/admin/api/route-difficulty"),
};

export const arsenalApi = {
    get: async (): Promise<ArsenalResponse> => {
        if (USE_MOCKS) {
            return {
                summary: {
                    total_modules: 15,
                    families: { fingerprint: 4, waf: 3, ddos: 2, honeypot: 2, telemetry: 1, challenge: 1, deception: 2 },
                    version_range: "176-190",
                },
                modules: [],
            };
        }
        return request<ArsenalResponse>("/admin/api/arsenal");
    },
};

// ─── V232 — Worker topology ─────────────────────────────────────────
export const topologyApi = {
    /** GET /admin/api/topology — host, layout, per-worker procs + recommendation. */
    get: async (): Promise<TopologyResponse> => {
        return request<TopologyResponse>("/admin/api/topology");
    },
    /** PUT /admin/api/topology — set desired worker count ("auto" or a numeric string). */
    put: async (workers: string): Promise<TopologyPutResponse> => {
        return request<TopologyPutResponse>("/admin/api/topology", {
            method: "PUT",
            body: JSON.stringify({ workers }),
            headers: { "content-type": "application/json" },
        });
    },
};

// ─── Hardware benchmark + capacity projection ────────────────────────
export const benchmarkApi = {
    run: async (): Promise<{ ok: boolean; queued: boolean }> => request("/admin/api/benchmark/run", { method: "POST" }),
    result: async (): Promise<BenchmarkResult> => request("/admin/api/benchmark/result"),
};

// ─── Flood-capacity tests (SYN / HTTP / TLS / slowloris / cache) ─────
// POST /admin/api/benchmark/flood/run     → fire-and-forget (202)
// GET  /admin/api/benchmark/flood/result  → poll until status === "done"
export const floodApi = {
    run: async (): Promise<{ ok: boolean; queued: boolean }> =>
        request("/admin/api/benchmark/flood/run", { method: "POST" }),
    result: async (): Promise<FloodResult> =>
        request("/admin/api/benchmark/flood/result"),
};

// ─── vs-nginx head-to-head comparison ────────────────────────────────
// POST /admin/api/benchmark/compare/run    → fire-and-forget (202)
// GET  /admin/api/benchmark/compare/result → poll until status === "done"
/**
 * One target column in the multi-target reverse-proxy comparison.
 * Targets are returned in fixed display order (left→right):
 *   AEGIS (raw), AEGIS + WAF, nginx, nginx+ModSec+CRS, HAProxy, Caddy, Envoy.
 */
export interface TargetResult {
    name: string;
    kind: "aegis" | "proxy";
    /** false when the binary is absent on the host. */
    available: boolean;
    version: string | null;
    /** 0.0 when unavailable. */
    throughput_rps: number;
    p50_ms: number;
    p99_ms: number;
    /** true for "AEGIS + WAF" and "nginx+ModSec+CRS". */
    has_waf: boolean;
}
/** One target's verdict on one attack sample. */
export interface SecVerdict {
    target: string;
    blocked: boolean;
    /** false when the target is unavailable. */
    applicable: boolean;
}
/** One attack row across all targets (verdicts in display order). */
export interface SecurityRow {
    attack: string;
    sample: string;
    category: string;
    verdicts: SecVerdict[];
}
export interface ComparisonResult {
    ok: boolean;
    status: "idle" | "running" | "done" | "error";
    error: string | null;
    started_at_unix: number | null;
    duration_ms: number | null;
    /** One entry per target, in fixed display order. */
    targets: TargetResult[];
    security: SecurityRow[];
    caveat: string;
}
export const compareApi = {
    run: async (): Promise<{ ok: boolean; queued: boolean }> =>
        request("/admin/api/benchmark/compare/run", { method: "POST" }),
    result: async (): Promise<ComparisonResult> =>
        request("/admin/api/benchmark/compare/result"),
};

// ─── Request log (Журнал) ───────────────────────────────────────────
// GET /admin/api/logs       → { entries: LogEntry[]; total: number }
// GET /admin/api/logs/stats → aggregations over the same filter window
//
// Both routes accept the same host/from/to filter trio; `list` additionally
// supports endpoint/action/ip/q free-text plus limit/offset pagination.

/** One decision-log row — a single proxied request and how Aegis acted on it. */
export interface LogEntry {
    /** Event time, epoch milliseconds. */
    ts: number;
    host: string;
    method: string;
    /** Raw request path (as received). */
    path: string;
    /** Normalised path template, e.g. `/users/{id}` — stable for grouping. */
    path_pattern: string;
    status: number;
    /** Terminal disposition: allow / deny / challenge / tarpit / rate_limited … */
    action: string;
    /** Why `action` fired (filter verdict / rule name / heuristic). */
    reason: string;
    /** WAF rule id that matched, if any. */
    waf_rule: string;
    client_ip: string;
    /** ISO-3166 alpha-2 country from GeoIP, or "" when unknown. */
    country: string;
    /** JA4 TLS-client fingerprint, or "" for plaintext / unknown. */
    ja4: string;
    latency_ms: number;
    bytes: number;
    /** "http/1.1" | "h2" | "h3" | … */
    protocol: string;
    user_agent: string;
}

/** Query params for `logsApi.list`. All fields optional; empty/undefined ones
 *  are omitted from the querystring. */
export interface LogQuery {
    host?: string;
    /** Match against `path_pattern`. */
    endpoint?: string;
    /** Filter by terminal action (allow / deny / challenge / …). */
    action?: string;
    client_ip?: string;
    /** Free-text search across path / UA / reason. */
    q?: string;
    /** Window start, epoch milliseconds. */
    from?: number;
    /** Window end, epoch milliseconds. */
    to?: number;
    limit?: number;
    offset?: number;
}

/** A `{ key, count }` aggregation bucket used throughout LogStats. */
export interface LogStatBucket {
    key: string;
    count: number;
}
/** Per-client-IP bucket carrying its deny/challenge breakdown. */
export interface LogClientIpStat {
    client_ip: string;
    count: number;
    deny: number;
    challenge: number;
}
/** One point in the time-bucketed request series. */
export interface LogSeriesPoint {
    /** Bucket start, epoch milliseconds. */
    t: number;
    count: number;
}
/** Aggregations from GET /admin/api/logs/stats over the active filter window. */
export interface LogStats {
    /** Request counts keyed by terminal action. */
    by_action: LogStatBucket[];
    /** Most-hit endpoints (path patterns) in the window. */
    top_endpoints: LogStatBucket[];
    /** Noisiest client IPs with their deny/challenge split. */
    top_client_ips: LogClientIpStat[];
    /** Most-common action reasons / rule names. */
    top_reasons: LogStatBucket[];
    /** HTTP status-code distribution (key is the status, e.g. "200", "403"). */
    status_distribution: LogStatBucket[];
    /** Time-bucketed request volume for the window. */
    series: LogSeriesPoint[];
}

/** Build a querystring from a LogQuery, dropping empty/undefined values. */
function logQueryString(query: LogQuery = {}): string {
    const params = new URLSearchParams();
    const put = (k: string, v: string | number | undefined) => {
        if (v === undefined || v === null) return;
        const s = String(v);
        if (s === "") return;
        params.set(k, s);
    };
    put("host", query.host);
    put("endpoint", query.endpoint);
    put("action", query.action);
    put("ip", query.client_ip);
    put("q", query.q);
    put("from", query.from);
    put("to", query.to);
    put("limit", query.limit);
    put("offset", query.offset);
    const qs = params.toString();
    return qs ? `?${qs}` : "";
}

export const logsApi = {
    /** GET /admin/api/logs — paginated decision-log rows for the filter window. */
    list: async (query: LogQuery = {}): Promise<{ entries: LogEntry[]; total: number }> => {
        if (USE_MOCKS) return { entries: [], total: 0 };
        return request<{ entries: LogEntry[]; total: number }>(
            `/admin/api/logs${logQueryString(query)}`,
        );
    },
    /** GET /admin/api/logs/stats — aggregations over the same window.
     *  Only host/from/to are honoured by the backend; other fields are ignored. */
    stats: async (query: LogQuery = {}): Promise<LogStats> => {
        if (USE_MOCKS) {
            return {
                by_action: [],
                top_endpoints: [],
                top_client_ips: [],
                top_reasons: [],
                status_distribution: [],
                series: [],
            };
        }
        const { host, from, to } = query;
        return request<LogStats>(
            `/admin/api/logs/stats${logQueryString({ host, from, to })}`,
        );
    },
};

// ─── ACME / Let's Encrypt cert management ───────────────────────────
// GET  /admin/api/acme/config                  → Read role
// PUT  /admin/api/acme/config                  → Write role
// GET  /admin/api/acme/orders                  → Read role
// GET  /admin/api/acme/orders/<host>           → Read role
// POST /admin/api/acme/orders                  → Write role
// POST /admin/api/acme/orders/<host>/renew     → Write role
export const acmeApi = {
    config: {
        get: async (): Promise<AcmeConfig> =>
            request<AcmeConfig>("/admin/api/acme/config"),

        set: async (patch: Partial<AcmeConfig>): Promise<AcmeConfig> =>
            request<AcmeConfig>("/admin/api/acme/config", {
                method: "PUT",
                body: JSON.stringify(patch),
            }),
    },

    orders: {
        list: async (): Promise<{ orders: AcmeOrder[] }> =>
            request<{ orders: AcmeOrder[] }>("/admin/api/acme/orders"),

        get: async (host: string): Promise<AcmeOrder> =>
            request<AcmeOrder>(`/admin/api/acme/orders/${encodeURIComponent(host)}`),

        create: async (host: string, email: string): Promise<{ host: string; status: string }> =>
            request<{ host: string; status: string }>("/admin/api/acme/orders", {
                method: "POST",
                body: JSON.stringify({ host, email }),
            }),

        renew: async (host: string): Promise<{ host: string; status: string }> =>
            request<{ host: string; status: string }>(
                `/admin/api/acme/orders/${encodeURIComponent(host)}/renew`,
                { method: "POST" },
            ),
    },
};

