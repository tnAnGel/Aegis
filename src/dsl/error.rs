//! Human-readable parse/validation errors with source location.
//!
//! Every error carries the file path + line + column so operators can
//! jump straight to the offending byte. Where reasonable we attach a
//! `did you mean X?` suggestion via edit-distance on a list of valid
//! identifiers.

use std::{fmt, path::PathBuf};

#[derive(Debug, Clone)]
pub struct DslError {
    pub message: String,
    pub file: PathBuf,
    pub line: u32,
    pub col: u32,
    pub suggestion: Option<String>,
    pub secondary: Option<Box<DslError>>,
}

impl DslError {
    pub fn new(message: impl Into<String>, file: PathBuf, line: u32, col: u32) -> Self {
        Self {
            message: message.into(),
            file,
            line,
            col,
            suggestion: None,
            secondary: None,
        }
    }

    pub fn with_suggestion(mut self, s: impl Into<String>) -> Self {
        self.suggestion = Some(s.into());
        self
    }

    pub fn with_secondary(mut self, e: DslError) -> Self {
        self.secondary = Some(Box::new(e));
        self
    }
}

impl fmt::Display for DslError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "config error: {}:{}:{}\n  {}",
            self.file.display(),
            self.line,
            self.col,
            self.message
        )?;
        if let Some(s) = &self.suggestion {
            write!(f, "\n  did you mean: {s}?")?;
        }
        if let Some(s) = &self.secondary {
            write!(f, "\n\nrelated:\n{s}")?;
        }
        Ok(())
    }
}

impl std::error::Error for DslError {}

/// Return the closest match from `candidates` to `input` by edit
/// distance, but only if the distance is ≤ 3 (otherwise the
/// suggestion is more confusing than helpful).
pub fn closest_match<'a>(input: &str, candidates: &[&'a str]) -> Option<&'a str> {
    let mut best: Option<(&str, usize)> = None;
    for c in candidates {
        let d = levenshtein(input, c);
        if d <= 3 && best.map(|(_, bd)| d < bd).unwrap_or(true) {
            best = Some((c, d));
        }
    }
    best.map(|(s, _)| s)
}

fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut cur = vec![0usize; b.len() + 1];
    for i in 1..=a.len() {
        cur[0] = i;
        for j in 1..=b.len() {
            let cost = if a[i - 1] == b[j - 1] { 0 } else { 1 };
            cur[j] = (cur[j - 1] + 1).min(prev[j] + 1).min(prev[j - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    prev[b.len()]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn levenshtein_basic() {
        assert_eq!(levenshtein("proxypass", "proxy_pass"), 1);
        assert_eq!(levenshtein("listen", "listen"), 0);
        assert_eq!(levenshtein("waf", "xdp"), 3);
    }

    #[test]
    fn closest_match_suggests_typo() {
        let candidates = ["proxy_pass", "listen", "server_name", "ssl_certificate"];
        assert_eq!(closest_match("proxypass", &candidates), Some("proxy_pass"));
        assert_eq!(closest_match("listn", &candidates), Some("listen"));
    }

    #[test]
    fn closest_match_skips_unrelated() {
        let candidates = ["proxy_pass", "listen"];
        assert_eq!(closest_match("xyzzy", &candidates), None);
    }
}
