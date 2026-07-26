// Mock data for VITE_USE_MOCKS=true. Used during UI dev without a
// real Aegis running. Production build leaves these inert.

import type {
    AnomalyRow,
    AuditEntry,
    ConfigTestResult,
    FilterStates,
    HotUriRow,
    NewSite,
    RuntimeStatus,
    Site,
    ThreatRow,
    UpstreamHealthEntry,
    XdpCounters,
} from "@/types";

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

const mockSites: Site[] = [
    {
        host: "api.example.com",
        upstream: "http://127.0.0.1:3001",
        tls: true,
        rate_limit: { rps: 50, burst: 100 },
        managed: true,
    },
    {
        host: "app.example.com",
        upstream: "http://127.0.0.1:3002",
        tls: true,
        rate_limit: null,
        managed: true,
    },
    {
        host: "blog.example.com",
        upstream: "http://127.0.0.1:3003",
        tls: false,
        rate_limit: null,
        managed: false,
    },
];

export async function sites(): Promise<Site[]> {
    await sleep(200);
    return mockSites;
}

export async function createSite(s: NewSite) {
    await sleep(400);
    mockSites.push({
        host: s.host,
        upstream: s.upstream,
        tls: s.tls,
        rate_limit: s.rate_limit,
        managed: true,
    });
    return { ok: true, dsl_snippet: `server {\n    server_name ${s.host};\n    proxy_pass ${s.upstream};\n}` };
}

export async function deleteSite(host: string) {
    await sleep(200);
    const i = mockSites.findIndex((m) => m.host === host);
    if (i >= 0) mockSites.splice(i, 1);
}

export async function filters(): Promise<FilterStates> {
    await sleep(100);
    return {
        waf: { enabled: true },
        bot_fingerprint: { enabled: true },
        adaptive_spike_detection: { enabled: true },
        challenge_ladder: { enabled: true },
        geoip: { enabled: false },
        xdp: { enabled: false },
    };
}

export async function metricsRaw(): Promise<string> {
    await sleep(100);
    return [
        "# HELP aegis_requests_total Total inbound HTTP requests.",
        "# TYPE aegis_requests_total counter",
        "aegis_requests_total 184231",
        "aegis_requests_denied 4218",
        "aegis_requests_challenged 612",
        "aegis_upstream_2xx 178200",
        "aegis_upstream_4xx 1500",
        "aegis_upstream_5xx 311",
        "aegis_upstream_errors 0",
        'aegis_requests_by_protocol{protocol="h1"} 12000',
        'aegis_requests_by_protocol{protocol="h2"} 158000',
        'aegis_requests_by_protocol{protocol="h3"} 14231',
        'aegis_requests_by_protocol{protocol="other"} 0',
        'aegis_domain_total{host="api.example.com"} 102000',
        'aegis_domain_denied{host="api.example.com"} 2100',
        'aegis_domain_challenged{host="api.example.com"} 412',
        'aegis_domain_total{host="app.example.com"} 70000',
        'aegis_domain_denied{host="app.example.com"} 1900',
        'aegis_domain_challenged{host="app.example.com"} 180',
        'aegis_domain_total{host="blog.example.com"} 12231',
        'aegis_domain_denied{host="blog.example.com"} 218',
        'aegis_request_latency_ms_count 184231',
        'aegis_request_latency_ms_sum 6843244',
    ].join("\n");
}

export async function health(): Promise<UpstreamHealthEntry[]> {
    await sleep(80);
    return [];
}

export async function threats(): Promise<ThreatRow[]> {
    await sleep(100);
    return [
        { ip: "203.0.113.42", score: 87.5 },
        { ip: "198.51.100.7", score: 64.2 },
        { ip: "192.0.2.18", score: 30.0 },
    ];
}

export async function hotUris(): Promise<HotUriRow[]> {
    await sleep(80);
    return [
        { uri: "/api/login", hits: 412 },
        { uri: "/wp-admin", hits: 198 },
        { uri: "/.env", hits: 77 },
    ];
}

export async function anomaly(): Promise<AnomalyRow[]> {
    await sleep(80);
    return [];
}

export async function xdp(): Promise<XdpCounters> {
    return { pass: 0, drop_deny: 0, drop_rate: 0, drop_allowonly: 0, drop_syn: 0 };
}

export async function audit(): Promise<AuditEntry[]> {
    await sleep(60);
    const now = Math.floor(Date.now() / 1000);
    return [
        { ts: now - 5, peer: "127.0.0.1:42018", method: "GET", path: "/admin/api/sites", role: "admin", status: 200 },
        { ts: now - 20, peer: "127.0.0.1:42018", method: "POST", path: "/admin/api/sites", role: "admin", status: 200 },
        { ts: now - 60, peer: "192.168.1.42:55044", method: "GET", path: "/admin/health", role: "read", status: 200 },
    ];
}

export async function configRaw(): Promise<string> {
    return `admin {
    listen 0.0.0.0:6280;
    token admin REPLACE_ME;
}

defaults {
    request_timeout 10s;
    graceful_shutdown 10s;

    filters {
        waf                       on;
        bot_fingerprint           on;
        adaptive_spike_detection  on;
        challenge_ladder          on;
    }

    rate_limit {
        requests_per_second 100;
        burst 200;
    }
}

server {
    listen 0.0.0.0:80 default_server;
    proxy_pass http://127.0.0.1:8000;
}
`;
}

export async function configTest(): Promise<ConfigTestResult> {
    await sleep(150);
    return { ok: true, summary: "config ok\nservers: 1\nlisteners:\n  - 0.0.0.0:80\nroutes:\n  - default -> http://127.0.0.1:8000" };
}

export async function configSave(): Promise<ConfigTestResult> {
    await sleep(120);
    return { ok: true };
}

export async function configApply() {
    await sleep(300);
    return { ok: true, message: "reloaded" };
}

export async function runtimeStatus(): Promise<RuntimeStatus> {
    return {
        aegis_version: "0.1.0",
        config_path: "/etc/aegis/aegis.conf",
        sites_count: mockSites.length,
        listeners: ["0.0.0.0:80", "0.0.0.0:443 ssl http2 http3", "0.0.0.0:6280"],
        uptime_sec: 9420,
    };
}
