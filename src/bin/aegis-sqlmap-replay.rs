//! V118 — sqlmap evasion replay harness.
//!
//! Operator points this at a running Aegis (or any URL), and it
//! fires a series of SQLi payloads through the WAF in their RAW form
//! AND after applying each sqlmap-equivalent tamper. The output is a
//! coverage matrix:
//!
//! ```text
//! TAMPER                     RAW    TAMPERED   STATUS
//! space2comment              403    403        OK
//! backticks                  403    403        OK
//! htmlencode                 403    403        OK
//! versionedkeywords          403    403        OK
//! space2dash                 403    200        ! BYPASSED
//! ...
//! ```
//!
//! Any line marked `! BYPASSED` is a WAF gap: the tamper variant
//! returned a non-403 (i.e. the WAF didn't catch it). Operator
//! ships the gap as a custom WAF rule or files an issue.
//!
//! NOTE: this is NOT a full sqlmap port (which has 50+ tampers
//! and combinations grow combinatorially). We ship the most-used
//! 12-15 tampers from sqlmap's tamper/ directory. Combinations:
//! pass `--chain space2comment,htmlencode,backticks` to apply
//! multiple in order — matches sqlmap's --tamper comma-separated
//! flag.

use anyhow::Result;
use clap::Parser;
use http_body_util::Empty;
use hyper::Request;
use hyper::body::Bytes;
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::TokioExecutor,
};
use std::time::Duration;

#[derive(Debug, Parser)]
#[command(
    name = "aegis-sqlmap-replay",
    about = "Replay sqlmap evasion tampers against an Aegis instance"
)]
struct Args {
    /// Target URL. Probe path will be appended as `?q=<payload>`.
    #[arg(long, default_value = "http://127.0.0.1/")]
    target: String,
    /// Base SQLi payload to tamper. Default catches the built-in
    /// signature `union select`.
    #[arg(long, default_value = "union select 1,2,3 from users")]
    payload: String,
    /// Optional comma-separated chain of tampers to apply on top
    /// of the iteration (matches sqlmap --tamper). Empty = apply
    /// each tamper individually.
    #[arg(long, default_value = "")]
    chain: String,
    /// Per-request timeout (seconds).
    #[arg(long, default_value_t = 5)]
    timeout_secs: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let chain: Vec<&str> = args
        .chain
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();
    let timeout = Duration::from_secs(args.timeout_secs);

    let mut client_conn = HttpConnector::new();
    client_conn.set_connect_timeout(Some(Duration::from_secs(2)));
    let client: Client<HttpConnector, Empty<Bytes>> = Client::builder(TokioExecutor::new())
        .pool_idle_timeout(Duration::from_secs(30))
        .build(client_conn);

    println!(
        "{:<28} {:>5} {:>10} {:>10}  notes",
        "TAMPER", "RAW", "TAMPERED", "STATUS"
    );

    // Reference probe: raw payload first.
    let raw_status = probe(&client, &args.target, &args.payload, timeout).await;

    let tampers: &[(&str, fn(&str) -> String)] = &[
        ("space2comment", space2comment),
        ("space2morecomments", space2morecomments),
        ("space2dash", space2dash),
        ("space2hash", space2hash),
        ("space2plus", space2plus),
        ("randomcase", randomcase),
        ("backticks", backticks),
        ("htmlencode_dec", htmlencode_dec),
        ("htmlencode_hex", htmlencode_hex),
        ("charencode", charencode),
        ("chardoubleencode", chardoubleencode),
        ("versionedkeywords", versionedkeywords),
        ("appendnullbyte", appendnullbyte),
        ("equaltolike", equaltolike),
        ("apostrophenullencode", apostrophenullencode),
    ];

    let mut bypassed = Vec::new();
    let mut ok = 0usize;

    for (name, f) in tampers {
        let mut tampered = f(&args.payload);
        // Apply optional chain on top.
        for ch in &chain {
            if let Some(extra) = tampers.iter().find(|(n, _)| n == ch).map(|(_, g)| g) {
                tampered = extra(&tampered);
            }
        }
        let status = probe(&client, &args.target, &tampered, timeout).await;
        let verdict = if status.is_some_and(|s| s == 403) {
            ok += 1;
            "OK"
        } else if let Some(s) = status {
            bypassed.push((name.to_string(), s));
            "! BYPASSED"
        } else {
            "! ERROR"
        };
        let notes = if tampered.len() < 80 {
            tampered.replace('\n', "\\n")
        } else {
            format!(
                "{}…(+{} chars)",
                tampered[..60].replace('\n', "\\n"),
                tampered.len() - 60
            )
        };
        println!(
            "{:<28} {:>5} {:>10} {:>10}  {}",
            name,
            raw_status
                .map(|s| s.to_string())
                .unwrap_or_else(|| "n/a".into()),
            status
                .map(|s| s.to_string())
                .unwrap_or_else(|| "n/a".into()),
            verdict,
            notes
        );
    }

    println!(
        "\n=== summary: {} OK / {} bypassed / {} total ===",
        ok,
        bypassed.len(),
        tampers.len()
    );
    if !bypassed.is_empty() {
        println!("\n=== BYPASSED ===");
        for (name, status) in &bypassed {
            println!("  - {name}: got status {status} (expected 403)");
        }
        std::process::exit(2);
    }
    Ok(())
}

async fn probe(
    client: &Client<HttpConnector, Empty<Bytes>>,
    base: &str,
    payload: &str,
    timeout: Duration,
) -> Option<u16> {
    let url = format!("{base}?q={}", urlencoding::encode(payload));
    let uri: hyper::Uri = url.parse().ok()?;
    let req = Request::builder()
        .method("GET")
        .uri(uri)
        .header("user-agent", "aegis-sqlmap-replay/0.1")
        .body(Empty::<Bytes>::new())
        .ok()?;
    match tokio::time::timeout(timeout, client.request(req)).await {
        Ok(Ok(resp)) => Some(resp.status().as_u16()),
        _ => None,
    }
}

// ── tamper implementations ────────────────────────────────────────
// Reference: https://github.com/sqlmapproject/sqlmap/tree/master/tamper

fn space2comment(s: &str) -> String {
    s.replace(' ', "/**/")
}

fn space2morecomments(s: &str) -> String {
    s.replace(' ', "/**//**/")
}

fn space2dash(s: &str) -> String {
    // sqlmap: replace each space with `-- <random>\n`. We use a fixed
    // marker so output is deterministic.
    s.replace(' ', "-- aegis\n")
}

fn space2hash(s: &str) -> String {
    s.replace(' ', "%23aegis%0a")
}

fn space2plus(s: &str) -> String {
    s.replace(' ', "+")
}

fn randomcase(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for (i, c) in s.chars().enumerate() {
        if c.is_ascii_alphabetic() {
            if i % 2 == 0 {
                out.push(c.to_ascii_uppercase());
            } else {
                out.push(c.to_ascii_lowercase());
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn backticks(s: &str) -> String {
    // Wrap each whitespace-delimited token in backticks if it looks
    // like an identifier (alphanumeric / underscore).
    s.split_whitespace()
        .map(|tok| {
            if tok.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                format!("`{tok}`")
            } else {
                tok.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn htmlencode_dec(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        if c.is_ascii_alphanumeric() {
            out.push_str(&format!("&#{};", c as u32));
        } else {
            out.push(c);
        }
    }
    out
}

fn htmlencode_hex(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        if c.is_ascii_alphanumeric() {
            out.push_str(&format!("&#x{:x};", c as u32));
        } else {
            out.push(c);
        }
    }
    out
}

fn charencode(s: &str) -> String {
    // urlencoding::encode encodes the same set as sqlmap's charencode
    // (every non-alphanumeric); for full equivalence we encode EVERY
    // char including alphanumerics.
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        out.push_str(&format!("%{:02X}", b));
    }
    out
}

fn chardoubleencode(s: &str) -> String {
    // First encode, then re-encode the `%` of each escape.
    let first = charencode(s);
    first.replace('%', "%25")
}

fn versionedkeywords(s: &str) -> String {
    // Wrap each SQL keyword in /*!50000KEYWORD*/.
    let kws = [
        "union", "select", "from", "where", "and", "or", "insert", "update", "delete", "drop",
        "table", "into", "values", "exec",
    ];
    let mut out = String::with_capacity(s.len() + 32);
    for tok in s.split_whitespace() {
        if !out.is_empty() {
            out.push(' ');
        }
        let lower = tok.to_ascii_lowercase();
        if kws.contains(&lower.as_str()) {
            out.push_str(&format!("/*!50000{tok}*/"));
        } else {
            out.push_str(tok);
        }
    }
    out
}

fn appendnullbyte(s: &str) -> String {
    format!("{s}%00")
}

fn equaltolike(s: &str) -> String {
    s.replace('=', " like ")
}

fn apostrophenullencode(s: &str) -> String {
    s.replace('\'', "%00%27")
}
