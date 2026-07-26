# WAF

**Languages:** **English** · [Русский](../ru/10-waf.md)

The WAF inspects the request line, headers, query string, cookies and body, and
returns `Allow` or `Deny`. A `Deny` short-circuits the rest of the chain and
answers `403`.

## Detection layers

| Layer | What it catches |
|---|---|
| **Signature matching** | Known SQLi / XSS / traversal / RCE / webshell payloads, via Aho-Corasick multi-pattern search plus SIMD `memmem` prefix and suffix matchers |
| **Semantic SQL analysis** | SQL injections that no literal signature covers — the payload is tokenised and judged structurally |
| **Multi-pass normalisation** | URL decode → HTML entity decode → NFKC-ish folding → confusable folding → null-byte strip → lowercase, repeated to a fixed point, so `%2527`, full-width characters and mixed encodings collapse to the same canonical form before matching |
| **Parameter profiling** | Rolling per-parameter statistics (length, charset, entropy) flag values that look nothing like what that endpoint normally receives |
| **Protocol hygiene** | Duplicate `Transfer-Encoding` (request smuggling), malformed framing, oversized headers |
| **Compressed bodies** | `Content-Encoding: gzip`/`deflate` request bodies are decompressed (with a ratio cap) before inspection; unknown or stacked encodings are denied |
| **Sigma corpus** | Community detection rules converted from SigmaHQ (see below) |
| **GraphQL guards** | Query depth, introspection, batch-array limits |

## Rule files

```nginx
filters {
    waf on;
}
```

Rule sources are loaded from `rule_files`:

```toml
[filters.waf]
rule_files = [
    "/etc/aegis/aegis-rules.toml",                   # your own rules
    "/etc/aegis/rules/sigma/sigma-webserver.toml",   # community corpus
]
```

or in the DSL:

```nginx
filters {
    waf {
        rule_files /etc/aegis/rules/sigma/sigma-webserver.toml;
    }
}
```

## Rule format

```toml
[[rules]]
id          = "custom-1001"
description = "Block admin panel probing from non-office IPs"
severity    = "high"
action      = "deny"
field       = "path"          # path | query | header | cookie | body | ja4 | ja4h | ja3
match       = "regex"         # literal | prefix | suffix | regex
pattern     = "^/(wp-admin|phpmyadmin|\\.env)"
```

Fields available for matching include the request path, query, individual
headers, cookies, the body, and fingerprints (`ja4`, `ja4h`, `ja3`).

> Fingerprint fields that the production data plane does not populate match the
> empty string rather than failing loudly. Check the Arsenal page counters after
> deploying a fingerprint rule to confirm it actually fires.

## Sigma import

```bash
# sparse-clone the rule trees you want
git clone --depth=1 --filter=blob:none --sparse https://github.com/SigmaHQ/sigma.git
cd sigma && git sparse-checkout set rules/web rules-emerging-threats

# convert to the Aegis rule format
aegis-sigma-import --input rules/web --output /etc/aegis/rules/sigma/sigma-webserver.toml
```

The importer accepts the two Sigma logsource categories that describe HTTP
traffic — `webserver` (server access logs) and `proxy` (forward-proxy access
logs, which is where the hack-tool / exploit-framework / crypto-miner
User-Agent corpus lives). The corpus shipped in the repository holds **569**
converted WAF rules.

What it will not do is pretend: `process_creation`, `file_event`,
`registry_set`, `image_load` and friends are endpoint telemetry — they match
process command lines and registry keys, and there is no HTTP request in them
to match against. Those are recorded in `rules/sigma/skipped.txt` with the
reason, rather than emitted as rules that could never fire. Of the 535 skipped
upstream rules, 513 are endpoint telemetry; the remaining 22 are genuine
importer gaps (mostly conditions with `not 1 of filter_*` exclusions, which are
skipped on purpose — importing the match without its exclusion would turn a
precise detection into a false-positive generator).

Two things worth knowing before you rely on the corpus:

* **A `challenge` rule masks a `block` rule for the same payload.** Matching is
  first-match-wins, and roughly a fifth of the corpus carries `action =
  challenge` (medium-severity Sigma levels). If such a rule matches first and
  the challenge ladder is off for that site, the request passes — even when a
  later rule would have blocked it. Enable the ladder on browser-facing sites,
  or re-tag the rules you want to be hard blocks.
* **Rule order is the corpus order.** Re-running the importer can change which
  rule wins for a given payload. Pin the corpus you tested.

Imported rules are covered by the Sigma Detection Rule License; see
[NOTICE](../../NOTICE).

## Body inspection

The body is buffered only when it is actually needed — when ClamAV scanning is
enabled, when the path is a login endpoint, or when a rule targets the body.
Bodies are scanned whole up to a size limit (1 MiB by default); beyond that the
remainder is forwarded unscanned, so set the limit to match your threat model
rather than assuming full coverage of very large uploads.

## Tuning for false positives

1. Watch the **Security** and **Logs** pages — every `Deny` records the rule id
   and the matched field.
2. Disable a single noisy rule rather than the whole WAF: rule ids can be
   excluded per site.
3. Runtime toggles are authoritative — you can turn the WAF off for one domain
   from the panel during an incident without editing files.
4. For a new deployment, run with the challenge ladder off and watch the deny
   log for a day before tightening.

## See also

- [Challenge ladder](15-challenge-ladder.md)
- [Security model](23-security-model.md)
- Full Russian reference: [10-waf.md](../ru/10-waf.md)
