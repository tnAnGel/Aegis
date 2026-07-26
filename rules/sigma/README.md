# Sigma-imported WAF rules

**569 rules**, converted from the SigmaHQ `webserver` and `proxy` logsource
categories. `skipped.txt` lists every upstream rule that was not converted and
why — 513 of those are endpoint telemetry (process creation, registry, file
events) that carries no HTTP request to match against.

This directory holds WAF rules **auto-generated** from
[SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) community detection
rules. Do **not** hand-edit `sigma-webserver.toml` — re-run the
importer to refresh.

## Activating

Add the file to your `aegis.conf`:

```toml
[filters.waf]
rule_files = [
    "/etc/aegis/aegis-rules.toml",          # your own rules
    "/etc/aegis/rules/sigma/sigma-webserver.toml",  # community
]
```

Or via the DSL:

```
filters {
    waf {
        rule_files /etc/aegis/rules/sigma/sigma-webserver.toml;
    }
}
```

## Regenerating

```sh
# Sparse-clone the SigmaHQ repo (only the rule trees we need)
mkdir -p /tmp/sigma && cd /tmp/sigma
git clone --depth=1 --filter=blob:none --sparse https://github.com/SigmaHQ/sigma.git src
cd src
git sparse-checkout set rules/web rules-emerging-threats rules-threat-hunting

# Run the importer
aegis-sigma-import \
    --input /tmp/sigma/src \
    --output /etc/aegis/rules/sigma/sigma-webserver.toml \
    --skipped-log /tmp/sigma-skipped.txt \
    --verbose
```

Or, working in the Aegis repo:

```sh
cargo run --release --bin aegis-sigma-import -- \
    --input /tmp/sigma/src \
    --output rules/sigma/sigma-webserver.toml \
    --skipped-log rules/sigma/skipped.txt \
    --verbose
```

## What gets imported

Only Sigma rules with `logsource.category: webserver` (plus
`product: apache | nginx | iis | haproxy | caddy`) — endpoint /
sysmon / windows-eventlog rules are skipped (they target a stack
Aegis doesn't see).

Field mapping (Sigma → Aegis WafRule.field):

| Sigma                              | Aegis              |
|------------------------------------|--------------------|
| `c-uri`, `cs-uri`, `cs-uri-stem`   | `path`             |
| `cs-uri-query`, `c-uri-query`      | `query`            |
| `cs-method`                        | `method`           |
| `c-useragent`, `cs-user-agent`     | `user_agent`       |
| `cs(User-Agent)`                   | `user_agent`       |
| `cs(Host)`, `cs-host`              | `host`             |
| `cs(Referer)`                      | `header:referer`   |
| `cs(Cookie)`                       | `header:cookie`    |
| generic `cs(Some-Header)`          | `header:some-header` |
| `c-ip`, `src_ip`                   | `client_ip`        |

Modifier mapping (Sigma `field|modifier` → WafRule.op):

| Modifier      | Aegis op       |
|---------------|----------------|
| (none)        | `equals`       |
| `contains`    | `contains`     |
| `startswith`  | `starts_with`  |
| `endswith`    | `ends_with`    |
| `re` / `regex`| `regex`        |

Severity mapping (Sigma `level` → action + mode):

| Sigma           | Aegis severity | Action      | Mode    |
|-----------------|----------------|-------------|---------|
| `critical`      | critical       | `block`     | enforce |
| `high`          | high           | `block`     | enforce |
| `medium`        | medium         | `challenge` | enforce |
| `low` / `informational` | low    | `log`       | shadow  |

## Tagged metadata

Every emitted rule carries up to 8 of the Sigma rule's `tags`
(`attack.t1190`, `cve.2024-12345`, etc.) which surface in
`SecurityEvent.tags` so SIEM downstream can correlate.

## What gets skipped

Rules with conditions Aegis can't currently express in a flat
rule list:

* `all of selection_*` mixed with negations
* `selection or keywords or filter` complex 3+-way OR
* Selection blocks containing nested mappings (rare)

Each skipped rule logs to the `--skipped-log` file with title +
reason. Hand-port the high-value ones to your own rule file if
needed.

## Numbers (last import)

- **562 rules** converted (was 22 before parser improvements)
- 565 skipped — 559 are legitimately non-webserver rules (SigmaHQ
  has ~3000 rules total across all categories)
- Conversion rate: 49% of the full tree, ~95% of the webserver
  subset

## Caveats

- `|all` and `|any` modifiers are reduced to plain `contains` —
  the strict "all values must match" semantic isn't expressible
  in our flat rule list. Best-effort over-match; operator can
  hand-tighten.
- `not <block>` negations are dropped — we emit the affirmative
  rules and skip the filter. Watch for false positives in audit
  log; add bypass entries via `[filters.bypass]`.
- Sigma rules tagged `mitre.t1190` etc. are useful inside the WAF
  but their MITRE ATT&CK semantics aren't exposed yet; future
  work might cross-reference them with `/admin/api/threats`.
