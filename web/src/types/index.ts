// Shared types for Aegis admin panel. Hand-maintained — Aegis doesn't
// currently expose an OpenAPI document, so we keep these aligned with
// the JSON shapes returned by src/admin_ui.rs and src/server.rs.

export interface RateLimit {
    rps: number;
    burst: number;
}

export interface Site {
    host: string;
    upstream: string | null;
    tls: boolean;
    rate_limit: RateLimit | null;
    /** UI-managed sites live in /var/lib/aegis/sites.d (deletable);
     *  ops-managed live in /etc/aegis/sites-enabled (read-only). */
    managed: boolean;
}

export interface NewSite {
    host: string;
    upstream: string;
    tls: boolean;
    h3: boolean;
    ssl_cert: string | null;
    ssl_key: string | null;
    rate_limit: RateLimit | null;
}

export interface FilterState {
    enabled: boolean;
}

export type FilterName =
    | "waf"
    | "bot_fingerprint"
    | "adaptive_spike_detection"
    | "challenge_ladder"
    | "geoip"
    | "xdp";

export type FilterStates = Record<FilterName, FilterState>;

export interface PrometheusMetric {
    name: string;
    value: number;
    labels: Record<string, string>;
}

export interface MetricsSummary {
    requests_total: number;
    requests_denied: number;
    requests_challenged: number;
    upstream_2xx: number;
    upstream_4xx: number;
    upstream_5xx: number;
    upstream_errors: number;
    per_protocol: Record<string, number>;
    per_domain: Array<{ host: string; total: number; denied: number; challenged: number }>;
    raw_text: string;
}

export interface UpstreamHealthEntry {
    /** Either a domain host or the literal "_default" for the catch-all
     *  upstream the admin sees in `/admin/health`. */
    host: string;
    since_ms: number;
}

export interface ThreatRow {
    ip: string;
    score: number;
}

export interface HotUriRow {
    uri: string;
    hits: number;
}

export interface AnomalyRow {
    host: string;
    remaining_ms: number;
}

export interface XdpCounters {
    pass: number;
    drop_deny: number;
    drop_rate: number;
    drop_allowonly: number;
    drop_syn: number;
}

export interface AuditEntry {
    ts: number;
    peer: string;
    method: string;
    path: string;
    role: string;
    status: number;
}

export interface ConfigTestResult {
    ok: boolean;
    summary?: string;
    error?: string;
}

export interface ApplyResult {
    ok: boolean;
    message: string;
}

export interface RuntimeStatus {
    aegis_version: string;
    config_path: string;
    sites_count: number;
    listeners: string[];
    uptime_sec: number;
}

// ─── V232 — worker topology (GET/PUT /admin/api/topology) ───────────
/** One running worker process in the REUSEPORT pool. */
export interface WorkerProc {
    pid: number;
    instance: number;
    rss_mb: number;
    threads: number;
    uptime_secs: number;
    cpu_pct_avg: number;
}

export interface TopologyResponse {
    host: {
        cpu_count: number;
        cpu_model: string;
        /** 1m / 5m / 15m load average. */
        load_avg: [number, number, number];
    };
    layout: {
        workers_running: number;
        threads_per_worker: number;
        total_runtime_threads: number;
        reuseport: boolean;
        mode: string;
    };
    workers: WorkerProc[];
    totals: {
        rss_mb: number;
        cpu_pct_avg: number;
    };
    desired: {
        /** "auto" or a numeric string. */
        workers: string;
        effective: number;
    };
    recommendation: {
        status: "optimal" | "suboptimal";
        message: string;
    };
}

export interface TopologyPutResponse {
    ok: boolean;
    desired: {
        workers: string;
        effective: number;
    };
    restart_required: boolean;
    apply_hint: string;
}

// ─── Env-var feature flags (GET/PUT /admin/api/env) ─────────────────
/** Kind of a feature-flag env var, matching the backend allowlist. */
export type EnvVarKind = "Bool" | "Enum" | "Path" | "Uint" | "Secret";

/** One entry in the env-var feature-flag list. */
export interface EnvVarEntry {
    key: string;
    kind: EnvVarKind;
    is_secret: boolean;
    /** true when the key is present in aegis.env */
    configured: boolean;
    /** null for secrets and unconfigured entries */
    value: string | null;
    /** non-null only for Enum kind */
    allowed_values: string[] | null;
}

export interface EnvVarsResponse {
    vars: EnvVarEntry[];
}

export interface EnvSetResult {
    ok: boolean;
    key: string;
    restart_required: boolean;
}

export interface RestartResult {
    ok: boolean;
    estimated_downtime_ms: number;
    note: string;
}

// ─── ACME / Let's Encrypt ────────────────────────────────────────────

/** Shape returned by GET/PUT /admin/api/acme/config. */
export interface AcmeConfig {
    account_email: string | null;
    use_production: boolean;
    accepted_tos_at: number | null;
}

/**
 * Status of one host's certificate order.
 *   idle     - no cert, no order on record
 *   pending  - order in flight
 *   issued   - cert present, >30 days remaining
 *   expiring - cert present, <=30 days remaining
 *   failed   - last attempt errored
 */
export type AcmeOrderStatus = "idle" | "pending" | "issued" | "expiring" | "failed";

/** One element in the GET /admin/api/acme/orders response array. */
export interface AcmeOrder {
    host: string;
    status: AcmeOrderStatus;
    not_after_unix: number | null;
    expires_in_days: number | null;
    cert_path: string | null;
    key_path: string | null;
    error: string | null;
}

// ─── Benchmark feature ───────────────────────────────────────────────
export interface BenchmarkScores {
    cpu_integer_gops: number;
    sha256_mhash_per_sec: number;
    mem_bw_gbps: number;
}

export interface BenchmarkProjections {
    est_fwd_rps: number;
    est_tls_rps: number;
    est_waf_rps: number;
    bottleneck: "throughput_optimal" | "clock_bound" | "core_count" | "reuseport_off";
    bottleneck_detail: string;
    reuseport_factor: number;
}

export interface BenchmarkHardware {
    cpu_model: string;
    cpu_count: number;
    ram_total_mb: number;
    ram_available_mb: number;
    arch: string;
}

// ─── Flood-capacity tests (GET/POST /admin/api/benchmark/flood/*) ───────────

export interface FloodScenario {
    /** "syn" | "http" | "tls" | "slowloris" | "cache" */
    id: string;
    label: string;
    /** Achieved sustainable rate (or holder count for slowloris). */
    achieved_rps: number;
    /** Unit for achieved_rps: "conn/s" | "req/s" | "hs/s" | "conns". */
    unit: string;
    p99_ms: number;
    p50_ms: number;
    /** Operations the victim served (accepted + completed). */
    served: number;
    /** Operations dropped / denied / refused / timed out. */
    dropped: number;
    verdict: "pass" | "degraded" | "fail";
    detail: string;
}

export interface FloodResult {
    ok: boolean;
    status: "idle" | "running" | "done" | "error";
    error?: string;
    started_at_unix?: number;
    duration_ms?: number;
    scenarios: FloodScenario[];
    /** Always true — loopback, single-host measurement. */
    loopback: boolean;
    caveat: string;
}

// ─── Metrics time-series (GET /admin/api/metrics/series) ────────────────────

/** One data-point in a metrics time-series response. All counter fields are
 *  fleet-wide totals (sum across all SO_REUSEPORT workers via the mmap arena).
 *  Rates (rps, deny_rps, challenge_rps) are derived by the backend as
 *  delta-over-interval so the frontend can graph them directly without
 *  differencing. */
export interface MetricPoint {
    /** Unix epoch seconds for the start of this bucket. */
    t_unix: number;
    /** Total inbound requests in this bucket (per-bucket delta). */
    requests: number;
    /** Requests blocked in this bucket. */
    denied: number;
    /** Requests issued a challenge in this bucket. */
    challenged: number;
    /** Requests rate-limited in this bucket. */
    rate_limited: number;
    /** Requests tarpitted in this bucket. */
    tarpit: number;
    /** Requests RTBH-announced in this bucket. */
    rtbh: number;
    /** Allowed requests, derived by the backend = requests − (denied+challenged+rate_limited+tarpit+rtbh), floored at 0. */
    allow: number;
    /** Response cache hits in this bucket. */
    cache_hits: number;
    /** Response cache misses in this bucket. */
    cache_misses: number;
    /** 2xx upstream responses in this bucket. */
    upstream_2xx: number;
    /** 4xx upstream responses in this bucket. */
    upstream_4xx: number;
    /** 5xx upstream responses in this bucket. */
    upstream_5xx: number;
}

/** Valid time-range keys accepted by the series endpoint. */
export type MetricsRange = "1h" | "6h" | "24h" | "7d" | "30d";

/** Response shape for GET /admin/api/metrics/series?range=<MetricsRange>. */
export interface MetricsSeriesResponse {
    /** ISO-8601 duration string describing the bucket width, e.g. "PT1M". */
    resolution: string;
    points: MetricPoint[];
}

export interface BenchmarkResult {
    ok: boolean;
    status: "idle" | "running" | "done" | "error";
    error?: string;
    started_at_unix?: number;
    duration_ms?: number;
    hardware?: BenchmarkHardware;
    scores?: BenchmarkScores;
    projections?: BenchmarkProjections;
    calibration_note?: string;
    estimate: true;
}
