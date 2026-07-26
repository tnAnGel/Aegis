// Aegis admin UI — vanilla JS, no build step.
// All calls go through fetch() with x-admin-token from localStorage.
// Errors surface as toasts so failures aren't silent.

const TOKEN_KEY = "aegis_admin_token";

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

function token() { return localStorage.getItem(TOKEN_KEY) || ""; }
// Aggressively normalise — strips leading/trailing whitespace AND any
// internal control chars / newlines that sneak in via copy-paste.
function setToken(v) {
    const clean = (v || "").replace(/[\s\r\n\t]+/g, "");
    localStorage.setItem(TOKEN_KEY, clean);
}

// One-shot bootstrap: when the page is opened with
// `#token=<value>` the value is saved and the hash is cleaned out of
// the URL so it doesn't stay in browser history. Useful for the
// installer's printed URL.
(function bootstrapTokenFromHash() {
    if (!location.hash || !location.hash.includes("token=")) return;
    const params = new URLSearchParams(location.hash.replace(/^#/, ""));
    const t = params.get("token");
    if (t) {
        setToken(t);
        history.replaceState(null, "", location.pathname);
    }
})();

async function api(path, opts = {}) {
    if (!token() && path.startsWith("/admin/")) {
        throw new Error("admin token not set — paste it in the field at the top of the page, then Save");
    }
    const headers = Object.assign({ "x-admin-token": token() }, opts.headers || {});
    const res = await fetch(path, Object.assign({ headers }, opts));
    if (res.status === 401) {
        throw new Error("401 — token rejected. Check /etc/aegis/admin-token on the server matches the value above.");
    }
    if (!res.ok) {
        const body = await res.text().catch(() => "");
        throw new Error(`${res.status} ${res.statusText}: ${body.slice(0, 200)}`);
    }
    const ct = res.headers.get("content-type") || "";
    return ct.includes("application/json") ? res.json() : res.text();
}

function toast(msg, kind = "ok") {
    const t = $("#toast");
    t.className = `toast ${kind}`;
    t.textContent = msg;
    setTimeout(() => t.classList.add("hidden"), 3500);
}

/* ──────────────────────── tab switcher ──────────────────────── */
$$(".tab").forEach((b) => {
    b.addEventListener("click", () => {
        $$(".tab").forEach((x) => x.classList.remove("active"));
        $$(".tab-panel").forEach((x) => x.classList.remove("active"));
        b.classList.add("active");
        $(`#tab-${b.dataset.tab}`).classList.add("active");
        loadTab(b.dataset.tab);
    });
});

/* ──────────────────────── token ──────────────────────── */
$("#token").value = token();
const saveTokenAndReload = () => {
    setToken($("#token").value);
    $("#token").value = token(); // reflect normalised value back
    toast("token saved", "ok");
    const active = $(".tab.active").dataset.tab;
    loadTab(active);
};
$("#save-token").addEventListener("click", saveTokenAndReload);
$("#token").addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
        e.preventDefault();
        saveTokenAndReload();
    }
});

// Prominent warning when no token has been saved yet — most common
// 401 cause is forgetting the Save click after pasting.
function flagMissingToken() {
    if (token()) return;
    const tokenInput = $("#token");
    tokenInput.style.borderColor = "var(--red)";
    tokenInput.placeholder = "← paste admin token here, then click Save";
    toast(
        "Admin token missing. Paste it in the top-right field and click Save (or press Enter).",
        "error"
    );
}

/* ──────────────────────── sites tab ──────────────────────── */
const FILTER_DESCRIPTIONS = {
    waf: "Signature-based payload inspection: SQLi / XSS / cmd injection + custom rules",
    bot_fingerprint: "Per-IP scoring on UA / headers / path heuristics; challenges or denies known scanners",
    adaptive_spike_detection: "Per-IP 1-second window; spike above threshold → challenge",
    challenge_ladder: "Five-rung escalation: 307 → HTML → iframe → JS PoW → reCAPTCHA",
    geoip: "MaxMind GeoLite2 country deny list (configure under [geoip] in TOML legacy block)",
    xdp: "Linux-only kernel fast-path: L4 deny / allow / rate-limit / SYN-flood guard",
};

async function loadSites() {
    const body = $("#sites-rows");
    body.innerHTML = `<tr><td colspan="6" class="empty">Loading…</td></tr>`;
    try {
        const data = await api("/admin/api/sites");
        if (!data.sites || data.sites.length === 0) {
            body.innerHTML = `<tr><td colspan="6" class="empty">No sites configured yet. Click <b>+ Add site</b> to create one.</td></tr>`;
            return;
        }
        body.innerHTML = "";
        for (const s of data.sites) {
            const tr = document.createElement("tr");
            const tlsBadge = s.tls ? `<span class="badge tls">TLS</span>` : "";
            const srcBadge = s.managed
                ? `<span class="badge managed">UI</span>`
                : `<span class="badge ops">ops</span>`;
            tr.innerHTML = `
                <td>${esc(s.host)}</td>
                <td>${esc(s.upstream || "—")}</td>
                <td>${tlsBadge}</td>
                <td>${s.rate_limit ? `${s.rate_limit.rps}/s burst ${s.rate_limit.burst}` : "default"}</td>
                <td>${srcBadge}</td>
                <td class="actions">
                    ${s.managed
                        ? `<button class="delete-btn" data-host="${esc(s.host)}">Delete</button>`
                        : `<span class="ph">read-only</span>`}
                </td>`;
            body.appendChild(tr);
        }
        body.querySelectorAll(".delete-btn").forEach((b) => {
            b.addEventListener("click", () => deleteSite(b.dataset.host));
        });
    } catch (e) {
        body.innerHTML = `<tr><td colspan="6" class="empty">Error: ${esc(e.message)}</td></tr>`;
    }
}

async function deleteSite(host) {
    if (!confirm(`Delete site "${host}"? Aegis will reload after.`)) return;
    try {
        await api(`/admin/api/sites/${encodeURIComponent(host)}`, { method: "DELETE" });
        toast(`deleted ${host}; reloaded`, "ok");
        loadSites();
    } catch (e) {
        toast(e.message, "error");
    }
}

/* ─── add-site modal ─── */
$("#add-site-btn").addEventListener("click", () => {
    $("#site-form").reset();
    $("#modal-preview").textContent = "";
    $("#modal").classList.remove("hidden");
});
$("#cancel-btn").addEventListener("click", () => $("#modal").classList.add("hidden"));
$("#modal").addEventListener("click", (e) => {
    if (e.target === $("#modal")) $("#modal").classList.add("hidden");
});

$("#site-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const f = e.target;
    const payload = {
        host: f.host.value.trim(),
        upstream: f.upstream.value.trim(),
        tls: f.tls.value === "true",
        h3: f.h3.value === "true",
        ssl_cert: f.ssl_cert.value.trim() || null,
        ssl_key: f.ssl_key.value.trim() || null,
        rate_limit: (parseInt(f.rps.value) > 0 && parseInt(f.burst.value) > 0) ? {
            rps: parseInt(f.rps.value),
            burst: parseInt(f.burst.value),
        } : null,
    };
    try {
        const r = await api("/admin/api/sites", {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify(payload),
        });
        toast(`added ${payload.host}; reloaded`, "ok");
        $("#modal").classList.add("hidden");
        $("#modal-preview").textContent = r.dsl_snippet || "";
        loadSites();
    } catch (err) {
        toast(err.message, "error");
        $("#modal-preview").textContent = err.message;
    }
});

/* ──────────────────────── filters tab ──────────────────────── */
async function loadFilters() {
    const list = $("#filters-list");
    list.innerHTML = `<li class="ph">Loading…</li>`;
    try {
        const data = await api("/admin/api/filters");
        list.innerHTML = "";
        for (const [name, info] of Object.entries(data.filters)) {
            const li = document.createElement("li");
            const stateClass = info.enabled ? "on" : "off";
            const stateLabel = info.enabled ? "ON" : "OFF";
            li.innerHTML = `
                <div>
                    <div class="name">${esc(name)}</div>
                    <div class="desc">${esc(FILTER_DESCRIPTIONS[name] || "")}</div>
                </div>
                <span class="state ${stateClass}">${stateLabel}</span>`;
            list.appendChild(li);
        }
    } catch (e) {
        list.innerHTML = `<li class="ph">Error: ${esc(e.message)}</li>`;
    }
}

/* ──────────────────────── health tab ──────────────────────── */
async function loadHealth() {
    setText("#health-text", () => api("/admin/health"));
    setText("#threats-text", () => api("/admin/threats"));
    setText("#hot-uris-text", () => api("/admin/hot_uris"));
    setText("#anomaly-text", () => api("/admin/anomaly"));
}

async function setText(sel, fetcher) {
    const el = $(sel);
    el.textContent = "Loading…";
    try {
        const text = await fetcher();
        el.textContent = typeof text === "string" ? text : JSON.stringify(text, null, 2);
    } catch (e) {
        el.textContent = `Error: ${e.message}`;
    }
}

/* ──────────────────────── metrics tab ──────────────────────── */
async function loadMetrics() {
    try {
        const text = await api("/metrics");
        $("#raw-metrics").textContent = text;
        const parsed = parsePromText(text);
        $("#m-total").textContent = fmt(parsed["aegis_requests_total"]);
        $("#m-denied").textContent = fmt(parsed["aegis_requests_denied"]);
        $("#m-challenged").textContent = fmt(parsed["aegis_requests_challenged"]);
        $("#m-5xx").textContent = fmt(parsed["aegis_upstream_5xx"]);

        const proto = $("#m-proto");
        proto.innerHTML = "";
        for (const k of Object.keys(parsed)) {
            const m = k.match(/^aegis_requests_by_protocol\{protocol="([^"]+)"\}$/);
            if (m) {
                const li = document.createElement("li");
                li.innerHTML = `<span>${esc(m[1])}</span><span>${fmt(parsed[k])}</span>`;
                proto.appendChild(li);
            }
        }

        const domains = {};
        for (const [k, v] of Object.entries(parsed)) {
            const m = k.match(/^aegis_domain_(total|denied|challenged)\{host="([^"]+)"\}$/);
            if (m) {
                const [, kind, host] = m;
                (domains[host] ||= { host })[kind] = v;
            }
        }
        const list = Object.values(domains)
            .sort((a, b) => (b.total || 0) - (a.total || 0))
            .slice(0, 20);
        const dom = $("#m-domains");
        dom.innerHTML = "";
        for (const d of list) {
            const tr = document.createElement("tr");
            tr.innerHTML = `<td>${esc(d.host)}</td><td>${fmt(d.total)}</td><td>${fmt(d.denied)}</td><td>${fmt(d.challenged)}</td>`;
            dom.appendChild(tr);
        }
    } catch (e) {
        toast(e.message, "error");
    }
}

function parsePromText(text) {
    const out = {};
    for (const line of text.split("\n")) {
        if (!line || line.startsWith("#")) continue;
        const idx = line.lastIndexOf(" ");
        if (idx <= 0) continue;
        const name = line.slice(0, idx);
        const val = parseFloat(line.slice(idx + 1));
        if (!Number.isNaN(val)) out[name] = val;
    }
    return out;
}

/* ──────────────────────── audit log tab ──────────────────────── */
async function loadAudit() {
    try {
        const text = await api("/admin/api/audit");
        $("#audit-text").textContent = text || "(audit log is empty or unavailable)";
    } catch (e) {
        $("#audit-text").textContent = `Error: ${e.message}\n\nMake sure audit_log_path is set in your admin { ... } block.`;
    }
}

/* ──────────────────────── boot ──────────────────────── */
function loadTab(name) {
    if (name === "sites") loadSites();
    else if (name === "filters") loadFilters();
    else if (name === "health") loadHealth();
    else if (name === "metrics") loadMetrics();
    else if (name === "logs") loadAudit();
}

function esc(s) {
    return (s ?? "").toString().replace(/[&<>"']/g, (c) =>
        ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]
    );
}
function fmt(v) {
    if (v === undefined || v === null) return "0";
    return v.toLocaleString();
}

flagMissingToken();
loadTab("sites");
setInterval(() => {
    const active = $(".tab.active").dataset.tab;
    if (active === "metrics" || active === "health") loadTab(active);
}, 5000);
