# Installation

**Languages:** **English** · [Русский](../ru/03-installation.md)

## One-line install

```bash
curl -fsSL https://raw.githubusercontent.com/tnAnGel/Aegis/main/install.sh | sudo bash
```

The installer is idempotent — re-running it upgrades an existing installation and
leaves `/etc/aegis` untouched. It will:

1. install a Rust toolchain, Node 20 and pnpm 10 if they are missing;
2. clone (or update) the source into `/usr/local/src/aegis`;
3. build the React admin UI, which gets embedded into the binary;
4. build `aegis-pingora` (the data plane) and `aegis` (CLI + legacy plane);
5. generate `/etc/aegis/aegis.conf`, a bootstrap self-signed certificate, an
   admin API token and a random web-panel password;
6. install a systemd template unit and start one CPU-pinned worker per core;
7. seed the GeoIP database and the reputation feeds.

At the end it prints the admin URL and the generated web-panel credentials.
**Write them down** — the password is shown once. If you lose it:

```bash
sudo aegis web reset-admin
```

## Installer options

```bash
sudo bash install.sh                 # install / update (pingora + XDP if available)
sudo bash install.sh --mode hyper    # legacy hyper-only mode
sudo bash install.sh --mode both     # both binaries (pingora primary)
sudo bash install.sh --no-xdp        # skip eBPF (no nightly toolchain needed)
sudo bash install.sh --workers 8     # override the REUSEPORT worker count
sudo bash install.sh --update        # pull + rebuild + restart
sudo bash install.sh --uninstall     # stop + remove, keep /etc/aegis
sudo bash install.sh --purge         # uninstall + delete state directories
sudo bash install.sh --version v1.0  # install a specific branch or tag
```

Environment overrides (set before piping into `bash`):

| Variable | Default | Meaning |
|---|---|---|
| `AEGIS_REPO` | `https://github.com/tnAnGel/Aegis.git` | Source repository |
| `AEGIS_VERSION` | `main` | Branch or tag to build |
| `AEGIS_PORT_HTTP` | `80` | Public HTTP port |
| `AEGIS_PORT_HTTPS` | `443` | Public HTTPS port |
| `AEGIS_PORT_ADMIN` | `6280` | Admin panel / API port |
| `AEGIS_WORKERS` | `auto` | Worker count (`auto` = one per core) |
| `AEGIS_ENABLE_XDP` | `auto` | `1` / `0` to force the eBPF fast path |
| `AEGIS_BUILD_OPT` | `fast` | `max` = fat LTO, `codegen-units=1` (slower build, faster binary) |
| `AEGIS_SKIP_FIREWALL` | `0` | `1` skips ufw/firewalld configuration |

## Layout after install

| Path | Contents |
|---|---|
| `/usr/local/bin/aegis-pingora` | Production data plane |
| `/usr/local/bin/aegis` | CLI + legacy data plane |
| `/etc/aegis/aegis.conf` | Main configuration |
| `/etc/aegis/sites-enabled/*.conf` | Operator-managed site files |
| `/var/lib/aegis/sites.d/*.conf` | Site files written by the web panel |
| `/etc/aegis/admin-token` | Admin API token |
| `/var/lib/aegis/` | State: web panel, honeypots, topology, GeoIP, feeds |
| `/var/log/aegis/` | Access, audit and error logs |
| `/etc/systemd/system/aegis-pingora@.service` | Worker template unit |

## Service management

```bash
systemctl status  aegis-pingora.target      # all workers
systemctl restart aegis-pingora.target      # restart the whole worker set
systemctl reload  aegis-pingora.target      # apply config without dropping traffic
journalctl -u 'aegis-pingora@*' -f          # follow logs from every worker
aegis -t                                    # validate the config, no restart
```

Workers run as the unprivileged `aegis` user. The binary carries file
capabilities (`cap_net_bind_service`, `cap_net_admin`, `cap_sys_resource`) so it
can bind ports 80/443 without root.

> **If workers fail with `status=203/EXEC ... Operation not permitted`:** the
> unit's `CapabilityBoundingSet` must be a superset of the file capabilities set
> on the binary — the kernel refuses `execve()` otherwise. The shipped installer
> keeps the two in sync; if you hand-edited the unit, check that first.

## Manual build

```bash
git clone https://github.com/tnAnGel/Aegis.git && cd Aegis

# admin UI (embedded into the binary at build time)
cd web && pnpm install && pnpm build && cd ..

# data plane
cargo build --release --bin aegis-pingora --features pingora

# with the eBPF/XDP fast path (Linux only)
cargo build --release --bin aegis-pingora --features "pingora xdp"

# the BPF object itself needs nightly + bpf-linker
cargo install bpf-linker
cargo +nightly build --release --manifest-path xdp/aegis-xdp-ebpf/Cargo.toml
```

Run it:

```bash
./target/release/aegis-pingora -c /etc/aegis/aegis.conf --log-level info
```

## First steps after install

1. Open `http://<host>:6280/admin/ui` and log in with the generated credentials.
   The panel forces an email and password change on first login.
2. Restrict the admin port — do not leave `:6280` open to the internet. Bind it
   to a management interface or put it behind a VPN. See the
   [security model](23-security-model.md).
3. Replace the bootstrap self-signed certificate with a real one (ACME is
   supported — see the Russian [TLS and certificates](../ru/08-tls-certificates.md) guide).
4. Point a site at your origin — see [Configuration](04-configuration.md).
