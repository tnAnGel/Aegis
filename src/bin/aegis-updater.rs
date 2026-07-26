//! V233 — aegis-updater is DISABLED.
//!
//! This binary previously implemented the in-panel self-update
//! applier: it read a launch manifest with an attacker-controllable
//! `download_url` + optional, self-supplied SHA256, downloaded a
//! tarball over the network, "verified" it only when a hash happened
//! to be present, unpacked it, installed the binary, atomically
//! activated the new release, and `systemctl restart`ed the daemon —
//! all as the service user, with NO cryptographic signature
//! verification anywhere in the chain.
//!
//! That is an unauthenticated-RCE-class design: anyone who could
//! reach `POST /admin/api/updates/apply` (or otherwise drop a launch
//! manifest) could make the host fetch and execute arbitrary code.
//!
//! The download / verify / install / activate / restart / snapshot /
//! rollback logic has been removed entirely. The panel keeps only the
//! read-only update *checker* ("a newer version is available" + a
//! download link). Operators install releases manually from the CLI.
//!
//! This stub remains so the `[[bin]]` target in Cargo.toml still
//! builds; it prints the manual-install instructions and exits with a
//! non-zero status so any lingering caller (e.g. an old systemd unit)
//! fails loudly instead of silently doing nothing.

fn main() -> std::process::ExitCode {
    eprintln!(
        "aegis-updater: automatic in-panel updates are DISABLED (V233).\n\
         \n\
         The self-update apply/download mechanism was removed because it\n\
         executed an unverified, attacker-controllable binary as the\n\
         service user (unauthenticated-RCE design — no signature check).\n\
         \n\
         To update Aegis, download the release for your platform and run\n\
         the installer manually on the host:\n\
         \n\
             sudo bash install.sh\n\
         \n\
         The admin panel still shows whether a newer version is available\n\
         and links to the release; it no longer downloads or installs it."
    );
    std::process::ExitCode::FAILURE
}
