# Security policy

Aegis is a security product. If it has a hole, the people running it are the
ones who get hurt — so please tell us before you tell the internet.

## Reporting a vulnerability

**Do not open a public issue for a security problem.**

Report privately, by either route:

- GitHub → **Security** tab → **Report a vulnerability** (private advisory), or
- email **darkzeit00@gmail.com** with `[AEGIS SECURITY]` in the subject.

Please include:

- affected version or commit, and whether you tested `aegis-pingora` (the
  production data plane) or the legacy `aegis` binary — they are different code
  paths and a bug in one may not exist in the other;
- configuration relevant to the finding (filters enabled, challenge ladder on or
  off, XDP on or off);
- a reproduction: request, payload, expected vs actual behaviour;
- impact as you see it.

### What to expect

| Stage | Target |
|---|---|
| Acknowledgement | within 72 hours |
| Initial assessment (severity, affected versions) | within 7 days |
| Fix or documented mitigation for critical issues | within 30 days |
| Public advisory | after a fix ships, coordinated with you |

You will be credited in the advisory unless you ask otherwise.

## Safe harbour

We will not pursue or support legal action against anyone who:

- researches in good faith and reports privately through the channels above;
- tests only against their **own** installation — never against someone else's
  Aegis deployment;
- avoids privacy violations, data destruction and service degradation;
- gives us reasonable time to fix before disclosing.

There is no paid bounty programme at this time.

## Supported versions

| Version | Supported |
|---|---|
| `main` (latest) | ✅ |
| Older tags | ❌ — upgrade before reporting |

Fixes land on `main` first. `install.sh --update` is the upgrade path.

## Scope

**In scope**

- The proxy data planes: request parsing, filter chain, WAF, rate limiting,
  challenge ladder and its tokens, TLS handling, HTTP/2 and HTTP/3 framing.
- The admin plane: authentication, session handling, RBAC, the admin API,
  anything reachable at `/admin/*`.
- The eBPF/XDP loader and its maps.
- `install.sh` — privilege escalation, insecure defaults, unsafe file modes.
- Cryptographic use: token signing and verification, PoW issuance, Privacy Pass.

**Out of scope**

- Findings that require the operator to have already published the admin port to
  the internet with weak credentials — but *do* report anything that lets an
  unauthenticated request reach a privileged endpoint.
- Denial of service achieved by simply sending more traffic than the hardware
  can handle. Report resource exhaustion that is *disproportionate* — unbounded
  memory growth, an amplification factor, a single request that pins a core.
- Vulnerabilities in third-party dependencies without a demonstrated path
  through Aegis (report those upstream; tell us so we can bump the pin).
- Missing hardening that is documented as a deliberate trade-off in the
  [security model](docs/en/23-security-model.md) — unless you can show a
  concrete exploit that the documentation does not anticipate.

## Deploying safely

The single most important item: **do not expose the admin port (`:6280`) to the
internet.** Bind it to a management interface, put it behind a VPN or an SSH
tunnel, and change the generated password on first login.

The rest of the checklist lives in
[docs/en/23-security-model.md](docs/en/23-security-model.md). It lists the
trust boundaries and the known limitations honestly, including the ones we have
not closed yet — read it before you put Aegis in front of something critical.
