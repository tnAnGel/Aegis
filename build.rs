// Ensure web/dist/ exists so the `include_dir!` macro in src/admin_ui.rs
// always finds a directory to embed. The installer (install.sh) and any
// developer building from a fresh checkout *should* run `pnpm build` in
// web/ first — this is just a safety net so `cargo build` doesn't fail
// outright with a confusing macro error when the assets are missing.
use std::{fs, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=web/dist");

    let dist = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("web/dist");
    let index = dist.join("index.html");
    if index.exists() {
        return;
    }
    let _ = fs::create_dir_all(&dist);
    let _ = fs::write(
        &index,
        "<!doctype html><meta charset=utf-8><title>Aegis admin UI</title>\
<body style=\"font-family:system-ui;max-width:42rem;margin:4rem auto;color:#333\">\
<h1>Admin UI not built</h1>\
<p>The React admin panel was not compiled. Run:</p>\
<pre>cd web &amp;&amp; pnpm install &amp;&amp; pnpm build</pre>\
<p>then rebuild Aegis. See the README for details.</p>",
    );
}
