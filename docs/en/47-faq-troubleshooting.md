# FAQ and troubleshooting

**Languages:** **English** · [Русский](../ru/47-faq-troubleshooting.md)

## Installation

### Workers fail with `status=203/EXEC ... Operation not permitted`

The unit's `CapabilityBoundingSet` must be a **superset** of the file
capabilities set on the binary. The kernel refuses `execve()` when a file's
permitted capability set is not contained in the bounding set, and systemd
reports it as an opaque 203/EXEC.

```bash
getcap /usr/local/bin/aegis-pingora
grep CapabilityBoundingSet /etc/systemd/system/aegis-pingora@.service
```

Every capability from the first command must appear in the second. Fix the unit
(or re-run the installer, which keeps them in sync) and
`systemctl daemon-reload && systemctl restart aegis-pingora.target`.

### `git clone ... failed` during install

`AEGIS_REPO` points somewhere the machine cannot reach or authenticate to. Set
it explicitly, or unpack the source yourself and point `AEGIS_SRC` at the tree.

### The build runs out of memory

Release builds with LTO are memory-hungry. Use the default `AEGIS_BUILD_OPT=fast`
profile rather than `max`, or add swap. A 2 GB box will struggle; build
elsewhere and copy the binary.

## Startup

### `failed to bind 0.0.0.0:80`

Something else holds the port — usually a distro nginx or Apache:

```bash
ss -ltnp | grep ':80 '
systemctl disable --now nginx apache2
```

### XDP does not load: `BPF_PROG_LOAD ... Permission denied`

Kernel 6.x gates verifier operations on packet pointers behind
`perfmon_capable()`. `CAP_BPF` + `CAP_NET_ADMIN` are not enough — you also need
`CAP_PERFMON` in the unit. Without it Aegis falls back to userspace filtering:
still protected, just without the kernel fast path. Check the startup log rather
than assuming XDP is active.

With several REUSEPORT workers only one wins the XDP attach (a NIC holds one
program); the others log an informational "owned by a sibling worker". That is
expected — the owner enforces the kernel maps for all traffic.

### HTTP/3 does not bind

QUIC needs `SO_REUSEPORT` on the UDP socket for multi-worker layouts, and UDP/443
must be open in your firewall. Check `ss -lun | grep 443`.

## Traffic

### Legitimate users are being blocked

1. Open **Security** or **Log** in the panel — every deny records the rule and
   the matched field.
2. Disable the specific rule rather than the whole WAF.
3. If the challenge ladder is the cause, remember it is per-site: turn it off for
   API hosts and non-browser clients.
4. Runtime toggles are authoritative and take effect immediately — you do not
   have to edit files during an incident.

### An API client gets a challenge page

The challenge ladder is on for that site. It is off by default for exactly this
reason. Either turn it off for the host, or give the client a Privacy Pass token.

### Attacks are not being blocked

- Confirm the WAF is on for that domain (runtime toggles override the config).
- Check the **Defence arsenal** page: a module with a zero counter is not firing.
- Fingerprint fields that the data plane does not populate match the empty
  string, so a rule on those never fires as intended. Verify with a test request.
- Bot scoring is a *signal*, not an automatic deny. A scanner user agent raises a
  score; blocking comes from rules and thresholds.

### The origin sees the wrong client IP

Aegis overwrites `X-Forwarded-For` and `X-Real-IP` with the address it resolved
and drops `Forwarded`, so the origin always sees Aegis' view, never the client's
claim. If that view is wrong, Aegis is behind another hop it does not trust —
list it in `AEGIS_TRUSTED_PROXIES`. See the
[security model](23-security-model.md).

### GeoIP map is empty

The map plots the *resolved client IP*. If Aegis is behind another proxy or load
balancer you must tell it which sources to trust, otherwise every request looks
like it came from that hop:

```
AEGIS_TRUSTED_PROXIES=10.0.0.0/8,192.168.0.0/16
```

Private and unallocated ranges have no country, so a loopback test generator will
never populate the map.

## Performance

### Throughput is lower than expected

- Check **Workers**: are you running one worker per core? The benchmark page
  names the bottleneck explicitly.
- Response cache off means every request touches the origin — your ceiling is the
  origin's, not Aegis's.
- Build with `AEGIS_BUILD_OPT=max` for fat LTO and `codegen-units=1`.
- Apply the kernel tuning in [system requirements](05-requirements.md).

### Memory keeps growing

Thread-per-core means N full process images; 16 workers legitimately use several
hundred MB in total. Sustained growth *within* a worker is a bug — please report
it with `RSS` over time and your configuration.

## Operations

### Config change did not take effect

```bash
aegis -t                                  # does it even parse?
systemctl reload aegis-pingora.target     # apply
```

Some settings need a restart, not a reload — the panel shows a banner when that
is the case. Note that runtime toggles override the file: a filter disabled at
runtime stays off even if the config says `on`.

### I lost the panel password

```bash
sudo aegis web reset-admin
```

### How do I upgrade?

```bash
curl -fsSL https://raw.githubusercontent.com/tnAnGel/Aegis/main/install.sh | sudo bash -s -- --update
```

`/etc/aegis` is preserved. Aegis does **not** self-update from the panel: remote
update-and-apply was removed deliberately because it was an attacker-controlled
code execution path. Updates are an operator action.

## Getting help

- Documentation: [English](README.md) · [Русский](../ru/README.md) · [中文](../zh/README.md)
- Bugs and questions: [GitHub issues](https://github.com/tnAnGel/Aegis/issues)
- Security reports: privately, see [SECURITY.md](../../SECURITY.md)
