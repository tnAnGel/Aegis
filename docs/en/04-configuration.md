# Configuration

**Languages:** **English** · [Русский](../ru/04-configuration.md)

Aegis reads a single main file, `/etc/aegis/aegis.conf`, written in an
nginx-style DSL. It is *nginx-like*, not nginx: there is no `rewrite`, no
`fastcgi`, no upstream groups. Everything Aegis-specific lives in its own
blocks (`filters { }`, `rate_limit { }`, `xdp { }`, …).

A TOML form is also accepted (`config/aegis.example.toml`); the DSL is the
recommended and better-supported format.

## Validate and reload

```bash
aegis -t                                  # syntax check, no restart
aegis -c /etc/aegis/aegis.conf config test
systemctl reload aegis-pingora.target     # apply live
```

`reload` is safe: the config is parsed and validated first, and a broken file
leaves the running workers untouched.

## Minimal config

```nginx
admin {
    listen 127.0.0.1:6280;
    token admin REPLACE_WITH_LONG_RANDOM;
    audit_log_path /var/log/aegis/audit.log;
}

defaults {
    request_timeout     10s;
    header_read_timeout 5s;
    graceful_shutdown   10s;

    filters {
        waf                      on;
        bot_fingerprint          on;
        adaptive_spike_detection on;
        challenge_ladder         off;   # opt-in per site
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
```

## Per-site blocks

```nginx
server {
    listen 0.0.0.0:80;
    listen 0.0.0.0:443 ssl http2 http3;

    server_name api.example.com;

    ssl_certificate     /etc/aegis/certs/api.crt;
    ssl_certificate_key /etc/aegis/certs/api.key;

    proxy_pass http://127.0.0.1:3001;

    # tighter limit than the global default
    rate_limit {
        requests_per_second 20;
        burst 50;
    }

    # browser verification for this site only
    filters {
        challenge_ladder on;
    }
}
```

Sites can also be split into separate files:

```nginx
include /etc/aegis/sites-enabled/*.conf;   # operator-managed
include /var/lib/aegis/sites.d/*.conf;     # written by the web panel
```

Both directories are scanned in deterministic alphabetical order; an empty glob
is a warning, not an error, so staging order does not matter.

## Key blocks

### `admin`

| Directive | Meaning |
|---|---|
| `listen` | Admin panel + API bind address. Keep it off the public internet. |
| `token <role> <secret>` | API token. Roles: `admin`, `operator`, `read`. |
| `audit_log_path` | Every mutating admin call is appended here. |
| `managed_sites_dir` | Where the web panel writes generated site files. |
| `ops_sites_dir` | Operator-managed site files (read-only in the panel). |
| `web_state_path` | Web panel credentials and sessions. |

### `defaults`

Global timeouts plus the default `filters` and `rate_limit` blocks that every
`server` inherits unless it overrides them.

### `filters`

| Filter | Default | What it does |
|---|---|---|
| `waf` | on | Signature + semantic request inspection |
| `bot_fingerprint` | on | UA / header / JA4 consistency scoring |
| `adaptive_spike_detection` | on | Per-IP and global rate anomaly detection |
| `challenge_ladder` | **off** | Browser verification (cookie → JS → PoW → CAPTCHA) |

`challenge_ladder` is deliberately off by default: turning it on globally would
challenge every client of every site, including APIs and non-browser traffic.
Enable it per `server` block.

### `rate_limit`

```nginx
rate_limit {
    requests_per_second 100;
    burst 200;
}
```

Buckets are per source IP. IPv6 sources are aggregated to a `/64` so a single
host cannot rotate through its own prefix to reset the counter.

### `xdp` (Linux, feature `xdp`)

```nginx
xdp {
    enabled true;
    interface eth0;
    bpf_object_path /var/lib/aegis/aegis-xdp.o;

    rate_window_ms 1000;   # per-IPv4 kernel rate limit window
    rate_burst 200;        # packets per window before dropping
    syn_burst 100;         # separate TCP SYN budget
}
```

The XDP program drops traffic in the kernel, before it reaches userspace. It
requires `CAP_BPF` + `CAP_NET_ADMIN` + `CAP_PERFMON` and a kernel that supports
XDP on your NIC driver (generic/SKB mode works on virtio).

## Runtime toggles vs config

Most filters can also be toggled at runtime from the admin panel or API, per
domain. Runtime toggles are the authoritative gate: a filter disabled at runtime
does not run even if the config says `on`. This lets you turn a noisy filter off
during an incident without editing files or reloading.

## Where to go next

- [WAF rules](10-waf.md)
- [Challenge ladder](15-challenge-ladder.md)
- [Admin API](30-admin-api.md)
- Full per-subsystem reference: [docs/ru](../ru/README.md)
