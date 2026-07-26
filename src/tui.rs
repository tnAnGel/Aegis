//! V133 — Terminal TUI live dashboard (Ratatui).
//!
//! Operator ssh's into a box running Aegis, runs `aegis-tui`, and gets
//! a real-time dashboard without leaving the terminal. Useful in three
//! cases the web admin can't cover:
//!
//! * **No GUI / no browser** — incident response from a jump host,
//!   embedded deployments, recovery-mode SSH.
//! * **Multi-host glance** — `tmux split` four panes, watch four
//!   regional Aegis nodes at once.
//! * **Pre-web-admin bootstrap** — admin UI not yet configured, but
//!   the proxy is up; need to see what it's doing.
//!
//! This module ships the rendering layer as pure functions over a
//! [DashboardSnapshot] value type. A binary (`aegis-tui`) feeds it
//! snapshots scraped from `/admin/api/runtime/status` and `/metrics`
//! on a polling interval. Decoupling the render from the data source
//! keeps the tests fast (no network) and lets the same renderer drive
//! a Unix-socket subscriber or a file replay later.
//!
//! Layout:
//!
//! ```text
//!   ┌─ Aegis  v0.1.0 ─ host: edge-01 ─ uptime: 4d 03:17 ──────────┐
//!   │ MODE  Normal              │ TLS  on        │ XDP backend xdp│
//!   ├──────────────── traffic ─────────────────── decisions ──────┤
//!   │ req/s 2,143  bps 31.2 Mb  │ allow 92.1% chal 5.8% deny 2.1% │
//!   │ p50 4ms  p95 21ms  p99 84 │ throttle 0.0%  observed 0.0%    │
//!   ├──────────────── top filters ────────── recent events ───────┤
//!   │ WAF        12,304 hits    │ 14:02 1.2.3.4 deny waf-sqli    │
//!   │ rate-limit  4,210 hits    │ 14:02 5.6.7.8 chal level=html  │
//!   │ ip-acl        887 hits    │ 14:01 9.9.9.9 deny acl-block   │
//!   └─────────────────────────────────────────────────────────────┘
//!     q quit · r refresh · f follow events
//! ```

use std::time::Duration;

use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Gauge, Paragraph, Row, Table},
};

/// Snapshot of everything the dashboard renders for one frame. The
/// binary builds this from polled HTTP responses; tests build it by
/// hand. All numeric fields are pre-aggregated.
#[derive(Debug, Clone)]
pub struct DashboardSnapshot {
    pub version: String,
    pub hostname: String,
    pub uptime: Duration,
    pub mode: String,
    pub tls_on: bool,
    pub xdp_backend: String,

    pub requests_per_sec: f64,
    pub bytes_per_sec: f64,
    pub p50_ms: u64,
    pub p95_ms: u64,
    pub p99_ms: u64,

    pub allow_pct: f32,
    pub challenge_pct: f32,
    pub deny_pct: f32,
    pub throttle_pct: f32,
    pub observed_pct: f32,

    pub top_filters: Vec<(String, u64)>,
    pub recent_events: Vec<RecentEvent>,
}

#[derive(Debug, Clone)]
pub struct RecentEvent {
    /// Wall clock for the event (HH:MM rendering done in TUI).
    pub hhmm: String,
    pub ip: String,
    pub decision: String,
    pub reason: String,
}

impl DashboardSnapshot {
    /// All-zero / no-data snapshot. Useful as a placeholder before
    /// the first poll completes.
    pub fn empty() -> Self {
        Self {
            version: env!("CARGO_PKG_VERSION").to_string(),
            hostname: String::from("?"),
            uptime: Duration::ZERO,
            mode: String::from("?"),
            tls_on: false,
            xdp_backend: String::from("?"),
            requests_per_sec: 0.0,
            bytes_per_sec: 0.0,
            p50_ms: 0,
            p95_ms: 0,
            p99_ms: 0,
            allow_pct: 0.0,
            challenge_pct: 0.0,
            deny_pct: 0.0,
            throttle_pct: 0.0,
            observed_pct: 0.0,
            top_filters: vec![],
            recent_events: vec![],
        }
    }
}

fn fmt_uptime(d: Duration) -> String {
    let secs = d.as_secs();
    let days = secs / 86_400;
    let h = (secs % 86_400) / 3600;
    let m = (secs % 3600) / 60;
    if days > 0 {
        format!("{days}d {h:02}:{m:02}")
    } else {
        let s = secs % 60;
        format!("{h:02}:{m:02}:{s:02}")
    }
}

fn fmt_bps(bps: f64) -> String {
    const KB: f64 = 1_000.0;
    const MB: f64 = 1_000_000.0;
    const GB: f64 = 1_000_000_000.0;
    if bps >= GB {
        format!("{:.1} Gb", bps / GB)
    } else if bps >= MB {
        format!("{:.1} Mb", bps / MB)
    } else if bps >= KB {
        format!("{:.1} Kb", bps / KB)
    } else {
        format!("{bps:.0} b")
    }
}

/// Mode → colour. Visual cue that an attack is in progress without
/// the operator parsing the mode name.
fn mode_style(mode: &str) -> Style {
    match mode.to_ascii_lowercase().as_str() {
        "normal" | "baseline" => Style::default().fg(Color::Green),
        "elevated" | "watch" => Style::default().fg(Color::Yellow),
        "attack" | "alert" => Style::default().fg(Color::Magenta),
        "critical" | "lockdown" => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        _ => Style::default().fg(Color::Gray),
    }
}

/// Render one full frame. Pure function over the snapshot — no I/O.
pub fn render(frame: &mut Frame, snap: &DashboardSnapshot) {
    let area = frame.area();
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // header
            Constraint::Length(4), // traffic + decisions
            Constraint::Length(3), // decision gauges
            Constraint::Min(5),    // top filters + events
            Constraint::Length(1), // help line
        ])
        .split(area);

    render_header(frame, rows[0], snap);
    render_traffic_decisions(frame, rows[1], snap);
    render_decision_gauges(frame, rows[2], snap);
    render_bottom(frame, rows[3], snap);
    render_help(frame, rows[4]);
}

fn render_header(frame: &mut Frame, area: Rect, snap: &DashboardSnapshot) {
    let title = format!(
        " Aegis v{} · host {} · uptime {} ",
        snap.version,
        snap.hostname,
        fmt_uptime(snap.uptime),
    );
    let block = Block::default().borders(Borders::ALL).title(title);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(34),
            Constraint::Percentage(33),
            Constraint::Percentage(33),
        ])
        .split(inner);

    let mode = Paragraph::new(Line::from(vec![
        Span::raw("MODE  "),
        Span::styled(snap.mode.clone(), mode_style(&snap.mode)),
    ]));
    let tls = Paragraph::new(Line::from(vec![
        Span::raw("TLS  "),
        Span::styled(
            if snap.tls_on { "on" } else { "off" },
            if snap.tls_on {
                Style::default().fg(Color::Green)
            } else {
                Style::default().fg(Color::Red)
            },
        ),
    ]));
    let xdp = Paragraph::new(Line::from(vec![
        Span::raw("XDP  "),
        Span::styled(snap.xdp_backend.clone(), Style::default().fg(Color::Cyan)),
    ]));
    frame.render_widget(mode, cols[0]);
    frame.render_widget(tls, cols[1]);
    frame.render_widget(xdp, cols[2]);
}

fn render_traffic_decisions(frame: &mut Frame, area: Rect, snap: &DashboardSnapshot) {
    let block = Block::default().borders(Borders::ALL).title(" traffic ");
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let lines = vec![
        Line::from(format!(
            "req/s {:>7.1}    bps {:>8}    p50 {:>3}ms  p95 {:>3}ms  p99 {:>4}ms",
            snap.requests_per_sec,
            fmt_bps(snap.bytes_per_sec),
            snap.p50_ms,
            snap.p95_ms,
            snap.p99_ms,
        )),
        Line::from(format!(
            "decisions  allow {:.1}%  chal {:.1}%  deny {:.1}%  throttle {:.1}%  observed {:.1}%",
            snap.allow_pct, snap.challenge_pct, snap.deny_pct, snap.throttle_pct, snap.observed_pct,
        )),
    ];
    frame.render_widget(Paragraph::new(lines), inner);
}

fn render_decision_gauges(frame: &mut Frame, area: Rect, snap: &DashboardSnapshot) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(33),
            Constraint::Percentage(33),
            Constraint::Percentage(34),
        ])
        .split(area);

    let allow = Gauge::default()
        .block(Block::default().borders(Borders::ALL).title("allow"))
        .gauge_style(Style::default().fg(Color::Green))
        .percent(snap.allow_pct.clamp(0.0, 100.0) as u16);
    let chal = Gauge::default()
        .block(Block::default().borders(Borders::ALL).title("challenge"))
        .gauge_style(Style::default().fg(Color::Yellow))
        .percent(snap.challenge_pct.clamp(0.0, 100.0) as u16);
    let deny = Gauge::default()
        .block(Block::default().borders(Borders::ALL).title("deny"))
        .gauge_style(Style::default().fg(Color::Red))
        .percent(snap.deny_pct.clamp(0.0, 100.0) as u16);
    frame.render_widget(allow, cols[0]);
    frame.render_widget(chal, cols[1]);
    frame.render_widget(deny, cols[2]);
}

fn render_bottom(frame: &mut Frame, area: Rect, snap: &DashboardSnapshot) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(area);

    let filter_rows: Vec<Row> = snap
        .top_filters
        .iter()
        .map(|(name, hits)| Row::new(vec![name.clone(), format!("{hits}")]))
        .collect();
    let filter_widths = [Constraint::Percentage(70), Constraint::Percentage(30)];
    let filters = Table::new(filter_rows, filter_widths)
        .header(
            Row::new(vec!["filter", "hits"]).style(Style::default().add_modifier(Modifier::BOLD)),
        )
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" top filters "),
        );
    frame.render_widget(filters, cols[0]);

    let event_rows: Vec<Row> = snap
        .recent_events
        .iter()
        .map(|e| {
            let decision_style = match e.decision.as_str() {
                "deny" => Style::default().fg(Color::Red),
                "challenge" => Style::default().fg(Color::Yellow),
                "throttle" => Style::default().fg(Color::Magenta),
                "allow" => Style::default().fg(Color::Green),
                _ => Style::default().fg(Color::Gray),
            };
            Row::new(vec![
                Cell::from(e.hhmm.clone()),
                Cell::from(e.ip.clone()),
                Cell::from(Span::styled(e.decision.clone(), decision_style)),
                Cell::from(e.reason.clone()),
            ])
        })
        .collect();
    let event_widths = [
        Constraint::Length(5),
        Constraint::Length(15),
        Constraint::Length(10),
        Constraint::Min(10),
    ];
    let events = Table::new(event_rows, event_widths)
        .header(
            Row::new(vec!["time", "ip", "decision", "reason"])
                .style(Style::default().add_modifier(Modifier::BOLD)),
        )
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" recent events "),
        );
    frame.render_widget(events, cols[1]);
}

fn render_help(frame: &mut Frame, area: Rect) {
    let help = Paragraph::new(Line::from(vec![
        Span::styled(" q ", Style::default().fg(Color::Black).bg(Color::Gray)),
        Span::raw(" quit  "),
        Span::styled(" r ", Style::default().fg(Color::Black).bg(Color::Gray)),
        Span::raw(" refresh  "),
        Span::styled(" f ", Style::default().fg(Color::Black).bg(Color::Gray)),
        Span::raw(" follow events  "),
    ]));
    frame.render_widget(help, area);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn sample_snap() -> DashboardSnapshot {
        DashboardSnapshot {
            version: "test".into(),
            hostname: "edge-01".into(),
            uptime: Duration::from_secs(4 * 86_400 + 3 * 3600 + 17 * 60),
            mode: "Attack".into(),
            tls_on: true,
            xdp_backend: "xdp".into(),
            requests_per_sec: 2143.0,
            bytes_per_sec: 31_200_000.0,
            p50_ms: 4,
            p95_ms: 21,
            p99_ms: 84,
            allow_pct: 92.1,
            challenge_pct: 5.8,
            deny_pct: 2.1,
            throttle_pct: 0.0,
            observed_pct: 0.0,
            top_filters: vec![
                ("waf".into(), 12_304),
                ("rate-limit".into(), 4_210),
                ("ip-acl".into(), 887),
            ],
            recent_events: vec![
                RecentEvent {
                    hhmm: "14:02".into(),
                    ip: "1.2.3.4".into(),
                    decision: "deny".into(),
                    reason: "waf-sqli".into(),
                },
                RecentEvent {
                    hhmm: "14:02".into(),
                    ip: "5.6.7.8".into(),
                    decision: "challenge".into(),
                    reason: "level=html".into(),
                },
            ],
        }
    }

    fn render_to_string(snap: &DashboardSnapshot, w: u16, h: u16) -> String {
        let backend = TestBackend::new(w, h);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| render(f, snap)).unwrap();
        let buf = term.backend().buffer().clone();
        let mut out = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                out.push_str(buf[(x, y)].symbol());
            }
            out.push('\n');
        }
        out
    }

    #[test]
    fn fmt_uptime_short_and_long() {
        assert_eq!(fmt_uptime(Duration::from_secs(0)), "00:00:00");
        assert_eq!(fmt_uptime(Duration::from_secs(3661)), "01:01:01");
        assert_eq!(
            fmt_uptime(Duration::from_secs(4 * 86_400 + 3 * 3600 + 17 * 60)),
            "4d 03:17"
        );
    }

    #[test]
    fn fmt_bps_scales_units() {
        assert_eq!(fmt_bps(500.0), "500 b");
        assert_eq!(fmt_bps(1_500.0), "1.5 Kb");
        assert_eq!(fmt_bps(2_500_000.0), "2.5 Mb");
        assert_eq!(fmt_bps(3_400_000_000.0), "3.4 Gb");
    }

    #[test]
    fn mode_colours_by_severity() {
        assert_eq!(mode_style("Normal").fg, Some(Color::Green));
        assert_eq!(mode_style("Elevated").fg, Some(Color::Yellow));
        assert_eq!(mode_style("Attack").fg, Some(Color::Magenta));
        assert_eq!(mode_style("Critical").fg, Some(Color::Red));
        assert_eq!(mode_style("whatever").fg, Some(Color::Gray));
    }

    #[test]
    fn renders_header_with_key_fields() {
        let s = sample_snap();
        let out = render_to_string(&s, 120, 24);
        assert!(out.contains("Aegis vtest"));
        assert!(out.contains("edge-01"));
        assert!(out.contains("4d 03:17"));
        assert!(out.contains("MODE"));
        assert!(out.contains("Attack"));
        assert!(out.contains("TLS"));
        assert!(out.contains("XDP"));
    }

    #[test]
    fn renders_traffic_and_decision_lines() {
        let s = sample_snap();
        let out = render_to_string(&s, 140, 24);
        assert!(out.contains("req/s"));
        assert!(out.contains("31.2 Mb"));
        assert!(out.contains("p50"));
        assert!(out.contains("p99"));
        assert!(out.contains("allow 92.1%"));
        assert!(out.contains("deny 2.1%"));
    }

    #[test]
    fn renders_top_filters_table_and_events() {
        let s = sample_snap();
        let out = render_to_string(&s, 140, 28);
        assert!(out.contains("top filters"));
        assert!(out.contains("waf"));
        assert!(out.contains("rate-limit"));
        assert!(out.contains("recent events"));
        assert!(out.contains("1.2.3.4"));
        assert!(out.contains("waf-sqli"));
    }

    #[test]
    fn renders_help_bar() {
        let s = sample_snap();
        let out = render_to_string(&s, 100, 24);
        assert!(out.contains("quit"));
        assert!(out.contains("refresh"));
    }

    #[test]
    fn empty_snapshot_renders_without_panic() {
        let s = DashboardSnapshot::empty();
        // Just exercising the render path — any panic would fail.
        let _ = render_to_string(&s, 100, 24);
    }
}
