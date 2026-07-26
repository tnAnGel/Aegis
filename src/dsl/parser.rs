//! Recursive-descent parser for the Aegis DSL.
//!
//! Public entry point is `parse_file(path)` — it loads the file,
//! tokenises it, walks the token stream, and recursively expands
//! `include <glob>;` directives. Cycle detection is by canonicalised
//! path so symlink loops are caught.

use std::{
    collections::HashSet,
    path::{Path, PathBuf},
    time::Duration,
};

use super::{
    ast::*,
    error::{DslError, closest_match},
    lexer::{Token, TokenKind, tokenize},
};

/// Top-level entry point. Parses the file at `path` plus any
/// transitively `include`d files into a single ConfigAst.
pub fn parse_file(path: &Path) -> Result<ConfigAst, DslError> {
    let mut ast = ConfigAst::default();
    let mut visited = HashSet::new();
    parse_file_into(path, &mut ast, &mut visited)?;
    Ok(ast)
}

fn parse_file_into(
    path: &Path,
    out: &mut ConfigAst,
    visited: &mut HashSet<PathBuf>,
) -> Result<(), DslError> {
    let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    if !visited.insert(canonical.clone()) {
        return Err(DslError::new(
            format!("recursive include of {}", path.display()),
            path.to_path_buf(),
            1,
            1,
        ));
    }
    let source = std::fs::read_to_string(path).map_err(|e| {
        DslError::new(
            format!("read {}: {e}", path.display()),
            path.to_path_buf(),
            1,
            1,
        )
    })?;
    let tokens = tokenize(&source, path)?;
    let mut p = Parser {
        file: path.to_path_buf(),
        tokens,
        pos: 0,
    };
    p.parse_top_level(out, visited)?;
    Ok(())
}

struct Parser {
    file: PathBuf,
    tokens: Vec<Token>,
    pos: usize,
}

const TOP_LEVEL_KEYWORDS: &[&str] = &["admin", "defaults", "server", "include", "xdp"];
const SERVER_DIRECTIVES: &[&str] = &[
    "listen",
    "server_name",
    "ssl_certificate",
    "ssl_certificate_key",
    "proxy_pass",
    "location",
    "filters",
    "rate_limit",
];
const ADMIN_DIRECTIVES: &[&str] = &[
    "listen",
    "audit_log_path",
    "managed_sites_dir",
    "ops_sites_dir",
    "web_state_path",
    "token",
];
const DEFAULTS_DIRECTIVES: &[&str] = &[
    "request_timeout",
    "graceful_shutdown",
    "header_read_timeout",
    "body_read_timeout",
    "filters",
    "rate_limit",
    "cache",
];
const FILTER_KEYS: &[&str] = &[
    "waf",
    "bot_fingerprint",
    "adaptive_spike_detection",
    "challenge_ladder",
    "geoip",
    "xdp",
    "plugins",
];

impl Parser {
    fn peek(&self) -> &Token {
        &self.tokens[self.pos]
    }

    fn advance(&mut self) -> Token {
        let t = self.tokens[self.pos].clone();
        if self.pos < self.tokens.len() - 1 {
            self.pos += 1;
        }
        t
    }

    fn span(&self, tok: &Token) -> Span {
        Span::new(self.file.clone(), tok.line, tok.col)
    }

    fn err(&self, msg: impl Into<String>, tok: &Token) -> DslError {
        DslError::new(msg, self.file.clone(), tok.line, tok.col)
    }

    fn expect(&mut self, kind: TokenKind, what: &str) -> Result<Token, DslError> {
        let t = self.peek().clone();
        if t.kind != kind {
            return Err(self.err(format!("expected {what}, found `{}`", t.value), &t));
        }
        Ok(self.advance())
    }

    fn parse_top_level(
        &mut self,
        out: &mut ConfigAst,
        visited: &mut HashSet<PathBuf>,
    ) -> Result<(), DslError> {
        while self.peek().kind != TokenKind::Eof {
            let head = self.advance();
            match head.value.as_str() {
                "admin" => {
                    let block = self.parse_admin_block(self.span(&head))?;
                    out.admin = Some(block);
                }
                "defaults" => {
                    let block = self.parse_defaults_block(self.span(&head))?;
                    out.defaults = Some(block);
                }
                "server" => {
                    let block = self.parse_server_block(self.span(&head))?;
                    out.servers.push(block);
                }
                "include" => {
                    let arg = self.expect(TokenKind::Word, "include path")?;
                    self.expect(TokenKind::Semicolon, "`;` after include")?;
                    self.expand_include(&arg.value, &head, out, visited)?;
                }
                "xdp" => {
                    let block = self.parse_xdp_block()?;
                    out.xdp = Some(block);
                }
                other => {
                    let suggestion = closest_match(other, TOP_LEVEL_KEYWORDS).map(String::from);
                    let mut e = self.err(format!("unknown top-level block: `{other}`"), &head);
                    e.suggestion = suggestion;
                    return Err(e);
                }
            }
        }
        Ok(())
    }

    fn expand_include(
        &mut self,
        pattern_raw: &str,
        head: &Token,
        out: &mut ConfigAst,
        visited: &mut HashSet<PathBuf>,
    ) -> Result<(), DslError> {
        let parent = self
            .file
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        let resolved = if Path::new(pattern_raw).is_absolute() {
            PathBuf::from(pattern_raw)
        } else {
            parent.join(pattern_raw)
        };
        let mut matched: Vec<PathBuf> = if resolved.to_string_lossy().contains('*') {
            simple_glob(&resolved).map_err(|e| self.err(e, head))?
        } else {
            vec![resolved.clone()]
        };
        matched.sort();
        if matched.is_empty() {
            // Soft warn (no fail) — operator likely staged sites-enabled
            // before any symlinks exist.
            tracing::warn!(pattern = pattern_raw, "include matched no files");
            return Ok(());
        }
        for path in matched {
            if !path.exists() {
                return Err(self.err(
                    format!("include path does not exist: {}", path.display()),
                    head,
                ));
            }
            parse_file_into(&path, out, visited)?;
        }
        Ok(())
    }

    fn parse_admin_block(&mut self, head_span: Span) -> Result<AdminBlock, DslError> {
        self.expect(TokenKind::LBrace, "`{` after admin")?;
        let mut block = AdminBlock {
            listen: None,
            audit_log_path: None,
            managed_sites_dir: None,
            ops_sites_dir: None,
            web_state_path: None,
            tokens: Vec::new(),
            span: head_span,
        };
        while self.peek().kind != TokenKind::RBrace {
            let tok = self.advance();
            if tok.kind == TokenKind::Eof {
                return Err(self.err("missing closing `}` for admin block", &tok));
            }
            match tok.value.as_str() {
                "listen" => {
                    let arg = self.expect(TokenKind::Word, "listen address")?;
                    self.expect(TokenKind::Semicolon, "`;` after listen")?;
                    block.listen = Some(arg.value);
                }
                "audit_log_path" => {
                    let arg = self.expect(TokenKind::Word, "audit_log_path")?;
                    self.expect(TokenKind::Semicolon, "`;` after audit_log_path")?;
                    block.audit_log_path = Some(arg.value);
                }
                "managed_sites_dir" => {
                    let arg = self.expect(TokenKind::Word, "managed_sites_dir path")?;
                    self.expect(TokenKind::Semicolon, "`;`")?;
                    block.managed_sites_dir = Some(arg.value);
                }
                "ops_sites_dir" => {
                    let arg = self.expect(TokenKind::Word, "ops_sites_dir path")?;
                    self.expect(TokenKind::Semicolon, "`;`")?;
                    block.ops_sites_dir = Some(arg.value);
                }
                "web_state_path" => {
                    let arg = self.expect(TokenKind::Word, "web_state_path")?;
                    self.expect(TokenKind::Semicolon, "`;`")?;
                    block.web_state_path = Some(arg.value);
                }
                "token" => {
                    let role = self.expect(TokenKind::Word, "token role")?;
                    let value = self.expect(TokenKind::Word, "token value")?;
                    self.expect(TokenKind::Semicolon, "`;` after token")?;
                    block.tokens.push(AdminTokenEntry {
                        token: value.value,
                        role: role.value,
                        span: self.span(&tok),
                    });
                }
                other => {
                    let mut e = self.err(format!("unknown admin directive: `{other}`"), &tok);
                    e.suggestion = closest_match(other, ADMIN_DIRECTIVES).map(String::from);
                    return Err(e);
                }
            }
        }
        self.expect(TokenKind::RBrace, "`}`")?;
        Ok(block)
    }

    fn parse_xdp_block(&mut self) -> Result<crate::dsl::ast::XdpBlock, DslError> {
        self.expect(TokenKind::LBrace, "`{` after xdp")?;
        let mut block = crate::dsl::ast::XdpBlock::default();
        while self.peek().kind != TokenKind::RBrace {
            let key = self.advance();
            if key.kind == TokenKind::Eof {
                return Err(self.err("missing closing `}` for xdp", &key));
            }
            let val = self.expect(TokenKind::Word, "value")?;
            self.expect(TokenKind::Semicolon, "`;`")?;
            match key.value.as_str() {
                "enabled" => {
                    block.enabled = matches!(val.value.as_str(), "on" | "true" | "1" | "yes")
                }
                "interface" => block.interface = Some(val.value),
                "bpf_object_path" => block.bpf_object_path = Some(val.value),
                "allow_only" => {
                    block.allow_only = matches!(val.value.as_str(), "on" | "true" | "1" | "yes")
                }
                "allow" => block.allow.push(val.value),
                "rate_window_ms" => {
                    block.rate_window_ms = val.value.parse().map_err(|_| {
                        self.err(
                            format!("rate_window_ms must be a number, got `{}`", val.value),
                            &val,
                        )
                    })?
                }
                "rate_burst" => {
                    block.rate_burst = val.value.parse().map_err(|_| {
                        self.err(
                            format!("rate_burst must be a number, got `{}`", val.value),
                            &val,
                        )
                    })?
                }
                "syn_burst" => {
                    block.syn_burst = val.value.parse().map_err(|_| {
                        self.err(
                            format!("syn_burst must be a number, got `{}`", val.value),
                            &val,
                        )
                    })?
                }
                other => {
                    return Err(self.err(format!("unknown xdp directive: `{other}`"), &key));
                }
            }
        }
        self.expect(TokenKind::RBrace, "`}`")?;
        Ok(block)
    }

    fn parse_defaults_block(&mut self, head_span: Span) -> Result<DefaultsBlock, DslError> {
        self.expect(TokenKind::LBrace, "`{` after defaults")?;
        let mut block = DefaultsBlock {
            span: Some(head_span),
            ..Default::default()
        };
        while self.peek().kind != TokenKind::RBrace {
            let tok = self.advance();
            if tok.kind == TokenKind::Eof {
                return Err(self.err("missing closing `}` for defaults block", &tok));
            }
            match tok.value.as_str() {
                "request_timeout" => {
                    let arg = self.expect(TokenKind::Word, "duration")?;
                    self.expect(TokenKind::Semicolon, "`;`")?;
                    block.request_timeout =
                        Some(parse_duration(&arg.value).map_err(|m| self.err(m, &arg))?);
                }
                "graceful_shutdown" => {
                    let arg = self.expect(TokenKind::Word, "duration")?;
                    self.expect(TokenKind::Semicolon, "`;`")?;
                    block.graceful_shutdown =
                        Some(parse_duration(&arg.value).map_err(|m| self.err(m, &arg))?);
                }
                "header_read_timeout" => {
                    let arg = self.expect(TokenKind::Word, "duration")?;
                    self.expect(TokenKind::Semicolon, "`;`")?;
                    block.header_read_timeout =
                        Some(parse_duration(&arg.value).map_err(|m| self.err(m, &arg))?);
                }
                "body_read_timeout" => {
                    let arg = self.expect(TokenKind::Word, "duration")?;
                    self.expect(TokenKind::Semicolon, "`;`")?;
                    block.body_read_timeout =
                        Some(parse_duration(&arg.value).map_err(|m| self.err(m, &arg))?);
                }
                "filters" => {
                    let f = self.parse_filters_block(self.span(&tok))?;
                    block.filters = Some(f);
                }
                "rate_limit" => {
                    let r = self.parse_rate_limit_block()?;
                    block.rate_limit = Some(r);
                }
                "cache" => {
                    let c = self.parse_cache_block()?;
                    block.cache = Some(c);
                }
                other => {
                    let mut e = self.err(format!("unknown defaults directive: `{other}`"), &tok);
                    e.suggestion = closest_match(other, DEFAULTS_DIRECTIVES).map(String::from);
                    return Err(e);
                }
            }
        }
        self.expect(TokenKind::RBrace, "`}`")?;
        Ok(block)
    }

    /// V103 — `cache { ... }` block inside defaults. Surface for
    /// [crate::config::ResponseCacheConfig] from the DSL.
    fn parse_cache_block(&mut self) -> Result<crate::dsl::ast::CacheBlock, DslError> {
        self.expect(TokenKind::LBrace, "`{` after cache")?;
        let mut block = crate::dsl::ast::CacheBlock::default();
        while self.peek().kind != TokenKind::RBrace {
            let tok = self.advance();
            if tok.kind == TokenKind::Eof {
                return Err(self.err("missing closing `}` for cache block", &tok));
            }
            match tok.value.as_str() {
                "default_ttl_secs" => {
                    let arg = self.expect(TokenKind::Word, "number")?;
                    self.expect(TokenKind::Semicolon, "`;`")?;
                    block.default_ttl_secs = Some(arg.value.parse::<u64>().map_err(|_| {
                        self.err(
                            format!("expected integer for default_ttl_secs, got `{}`", arg.value),
                            &arg,
                        )
                    })?);
                }
                "max_entries" => {
                    let arg = self.expect(TokenKind::Word, "number")?;
                    self.expect(TokenKind::Semicolon, "`;`")?;
                    block.max_entries = Some(arg.value.parse::<usize>().map_err(|_| {
                        self.err(
                            format!("expected integer for max_entries, got `{}`", arg.value),
                            &arg,
                        )
                    })?);
                }
                "max_body_bytes" => {
                    let arg = self.expect(TokenKind::Word, "number")?;
                    self.expect(TokenKind::Semicolon, "`;`")?;
                    block.max_body_bytes = Some(arg.value.parse::<usize>().map_err(|_| {
                        self.err(
                            format!("expected integer for max_body_bytes, got `{}`", arg.value),
                            &arg,
                        )
                    })?);
                }
                "host" => {
                    let arg = self.expect(TokenKind::Word, "hostname")?;
                    self.expect(TokenKind::Semicolon, "`;`")?;
                    block.hosts.push(arg.value);
                }
                other => {
                    return Err(self.err(
                        format!("unknown cache directive: `{other}` (expected default_ttl_secs / max_entries / max_body_bytes / host)"),
                        &tok,
                    ));
                }
            }
        }
        self.expect(TokenKind::RBrace, "`}`")?;
        Ok(block)
    }

    fn parse_server_block(&mut self, head_span: Span) -> Result<ServerBlock, DslError> {
        self.expect(TokenKind::LBrace, "`{` after server")?;
        let mut block = ServerBlock {
            listens: Vec::new(),
            server_names: Vec::new(),
            ssl_certificate: None,
            ssl_certificate_key: None,
            proxy_pass: None,
            filters: None,
            rate_limit: None,
            locations: Vec::new(),
            span: head_span,
        };
        while self.peek().kind != TokenKind::RBrace {
            let tok = self.advance();
            if tok.kind == TokenKind::Eof {
                return Err(self.err("missing closing `}` for server block", &tok));
            }
            match tok.value.as_str() {
                "listen" => {
                    block.listens.push(self.parse_listen(&tok)?);
                }
                "server_name" => {
                    let mut names = Vec::new();
                    while self.peek().kind == TokenKind::Word {
                        names.push(self.advance().value);
                    }
                    self.expect(TokenKind::Semicolon, "`;` after server_name")?;
                    if names.is_empty() {
                        return Err(self.err("server_name requires at least one name", &tok));
                    }
                    block.server_names.extend(names);
                }
                "ssl_certificate" => {
                    let arg = self.expect(TokenKind::Word, "certificate path")?;
                    self.expect(TokenKind::Semicolon, "`;`")?;
                    block.ssl_certificate = Some(arg.value);
                }
                "ssl_certificate_key" => {
                    let arg = self.expect(TokenKind::Word, "key path")?;
                    self.expect(TokenKind::Semicolon, "`;`")?;
                    block.ssl_certificate_key = Some(arg.value);
                }
                "proxy_pass" => {
                    let arg = self.expect(TokenKind::Word, "upstream URL")?;
                    self.expect(TokenKind::Semicolon, "`;`")?;
                    block.proxy_pass = Some(arg.value);
                }
                "filters" => {
                    block.filters = Some(self.parse_filters_block(self.span(&tok))?);
                }
                "rate_limit" => {
                    block.rate_limit = Some(self.parse_rate_limit_block()?);
                }
                "location" => {
                    block.locations.push(self.parse_location_block(&tok)?);
                }
                other => {
                    let mut e = self.err(format!("unknown server directive: `{other}`"), &tok);
                    e.suggestion = closest_match(other, SERVER_DIRECTIVES).map(String::from);
                    return Err(e);
                }
            }
        }
        self.expect(TokenKind::RBrace, "`}`")?;
        Ok(block)
    }

    fn parse_listen(&mut self, head: &Token) -> Result<Listen, DslError> {
        let addr_tok = self.expect(TokenKind::Word, "listen address")?;
        let mut listen = Listen {
            addr: addr_tok.value,
            ssl: false,
            http2: false,
            http3: false,
            default_server: false,
            span: self.span(head),
        };
        while self.peek().kind == TokenKind::Word {
            let modifier = self.advance();
            match modifier.value.as_str() {
                "ssl" => listen.ssl = true,
                "http2" => listen.http2 = true,
                "http3" => listen.http3 = true,
                "default_server" => listen.default_server = true,
                other => {
                    return Err(self.err(
                        format!(
                            "unknown listen modifier: `{other}` (allowed: ssl, http2, http3, default_server)"
                        ),
                        &modifier,
                    ));
                }
            }
        }
        self.expect(TokenKind::Semicolon, "`;` after listen")?;
        if listen.http3 && !listen.ssl {
            return Err(self.err("`http3` requires `ssl` on the same listen line", head));
        }
        Ok(listen)
    }

    fn parse_filters_block(&mut self, span: Span) -> Result<FiltersBlock, DslError> {
        self.expect(TokenKind::LBrace, "`{` after filters")?;
        let mut block = FiltersBlock {
            span: Some(span),
            ..Default::default()
        };
        while self.peek().kind != TokenKind::RBrace {
            let key = self.advance();
            if key.kind == TokenKind::Eof {
                return Err(self.err("missing closing `}` for filters", &key));
            }
            // `plugins { ... }` is a nested block, not an on/off knob.
            if key.value == "plugins" {
                block.plugins = Some(self.parse_plugins_block()?);
                continue;
            }
            let val = self.expect(TokenKind::Word, "`on` or `off`")?;
            self.expect(TokenKind::Semicolon, "`;`")?;
            let on = match val.value.as_str() {
                "on" | "true" | "yes" | "1" => true,
                "off" | "false" | "no" | "0" => false,
                other => {
                    return Err(self.err(
                        format!("filter value must be `on` or `off`, got `{other}`"),
                        &val,
                    ));
                }
            };
            match key.value.as_str() {
                "waf" => block.waf = Some(on),
                "bot_fingerprint" => block.bot_fingerprint = Some(on),
                "adaptive_spike_detection" => block.adaptive_spike_detection = Some(on),
                "challenge_ladder" => block.challenge_ladder = Some(on),
                "geoip" => block.geoip = Some(on),
                "xdp" => block.xdp = Some(on),
                other => {
                    let mut e = self.err(format!("unknown filter: `{other}`"), &key);
                    e.suggestion = closest_match(other, FILTER_KEYS).map(String::from);
                    return Err(e);
                }
            }
        }
        self.expect(TokenKind::RBrace, "`}`")?;
        Ok(block)
    }

    fn parse_plugins_block(&mut self) -> Result<crate::dsl::ast::PluginsBlock, DslError> {
        self.expect(TokenKind::LBrace, "`{` after plugins")?;
        let mut block = crate::dsl::ast::PluginsBlock::default();
        while self.peek().kind != TokenKind::RBrace {
            let key = self.advance();
            if key.kind == TokenKind::Eof {
                return Err(self.err("missing closing `}` for plugins", &key));
            }
            let path = self.expect(TokenKind::Word, "plugin path")?;
            self.expect(TokenKind::Semicolon, "`;`")?;
            match key.value.as_str() {
                "lua" => block.lua.push(path.value),
                "wasm" => block.wasm.push(path.value),
                other => {
                    return Err(self.err(
                        format!("unknown plugin kind `{other}` (allowed: lua, wasm)"),
                        &key,
                    ));
                }
            }
        }
        self.expect(TokenKind::RBrace, "`}`")?;
        Ok(block)
    }

    fn parse_rate_limit_block(&mut self) -> Result<RateLimitBlock, DslError> {
        self.expect(TokenKind::LBrace, "`{` after rate_limit")?;
        let mut block = RateLimitBlock::default();
        while self.peek().kind != TokenKind::RBrace {
            let key = self.advance();
            if key.kind == TokenKind::Eof {
                return Err(self.err("missing closing `}` for rate_limit", &key));
            }
            let val = self.expect(TokenKind::Word, "integer")?;
            self.expect(TokenKind::Semicolon, "`;`")?;
            let n: u64 = val.value.parse().map_err(|_| {
                self.err(
                    format!(
                        "rate_limit value must be a positive integer, got `{}`",
                        val.value
                    ),
                    &val,
                )
            })?;
            match key.value.as_str() {
                "requests_per_second" => block.requests_per_second = Some(n),
                "burst" => block.burst = Some(n),
                other => {
                    return Err(self.err(
                        format!(
                            "unknown rate_limit key: `{other}` (allowed: requests_per_second, burst)"
                        ),
                        &key,
                    ));
                }
            }
        }
        self.expect(TokenKind::RBrace, "`}`")?;
        Ok(block)
    }

    fn parse_location_block(&mut self, head: &Token) -> Result<LocationBlock, DslError> {
        // Two forms:
        //   location /path/ { ... }       — prefix
        //   location = /exact { ... }     — exact match
        let first = self.expect(TokenKind::Word, "location matcher")?;
        let matcher = if first.value == "=" {
            let path = self.expect(TokenKind::Word, "exact path")?;
            LocationMatcher::Exact(path.value)
        } else {
            LocationMatcher::Prefix(first.value)
        };
        self.expect(TokenKind::LBrace, "`{` after location")?;
        let mut block = LocationBlock {
            matcher,
            proxy_pass: None,
            rate_limit: None,
            span: self.span(head),
        };
        while self.peek().kind != TokenKind::RBrace {
            let tok = self.advance();
            if tok.kind == TokenKind::Eof {
                return Err(self.err("missing closing `}` for location", &tok));
            }
            match tok.value.as_str() {
                "proxy_pass" => {
                    let arg = self.expect(TokenKind::Word, "upstream URL")?;
                    self.expect(TokenKind::Semicolon, "`;`")?;
                    block.proxy_pass = Some(arg.value);
                }
                "rate_limit" => {
                    block.rate_limit = Some(self.parse_rate_limit_block()?);
                }
                other => {
                    return Err(self.err(
                        format!(
                            "unknown location directive: `{other}` (allowed: proxy_pass, rate_limit)"
                        ),
                        &tok,
                    ));
                }
            }
        }
        self.expect(TokenKind::RBrace, "`}`")?;
        Ok(block)
    }
}

/// Parse human duration: `10s`, `500ms`, `2m`. Unit is required.
pub fn parse_duration(s: &str) -> Result<Duration, String> {
    if let Some(rest) = s.strip_suffix("ms") {
        let n: u64 = rest
            .parse()
            .map_err(|_| format!("invalid duration: `{s}`"))?;
        Ok(Duration::from_millis(n))
    } else if let Some(rest) = s.strip_suffix('s') {
        let n: u64 = rest
            .parse()
            .map_err(|_| format!("invalid duration: `{s}`"))?;
        Ok(Duration::from_secs(n))
    } else if let Some(rest) = s.strip_suffix('m') {
        let n: u64 = rest
            .parse()
            .map_err(|_| format!("invalid duration: `{s}`"))?;
        Ok(Duration::from_secs(n * 60))
    } else {
        Err(format!("duration `{s}` needs a unit suffix (ms, s, m)"))
    }
}

/// Trivial glob: supports a single `*` wildcard inside the filename
/// component only (`sites-enabled/*.conf`). Anything fancier returns
/// no matches; operators can fall back to enumerating files
/// explicitly. Returned paths are not canonicalised — cycle detection
/// in parse_file_into does that.
fn simple_glob(pattern: &Path) -> Result<Vec<PathBuf>, String> {
    let parent = pattern.parent().unwrap_or(Path::new("."));
    let file_pat = pattern
        .file_name()
        .ok_or_else(|| format!("glob pattern missing filename: {}", pattern.display()))?
        .to_string_lossy()
        .to_string();
    let star_pos = file_pat.find('*');
    let entries =
        std::fs::read_dir(parent).map_err(|e| format!("read_dir {}: {e}", parent.display()))?;
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        let matches = match star_pos {
            Some(p) => {
                let prefix = &file_pat[..p];
                let suffix = &file_pat[p + 1..];
                name.starts_with(prefix) && name.ends_with(suffix)
            }
            None => name == file_pat,
        };
        if matches {
            out.push(entry.path());
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn parse_str(src: &str) -> Result<ConfigAst, DslError> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "aegis-dsl-{}-{}-{}.conf",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed),
            uniq()
        ));
        std::fs::File::create(&path)
            .unwrap()
            .write_all(src.as_bytes())
            .unwrap();
        let r = parse_file(&path);
        std::fs::remove_file(&path).ok();
        r
    }

    fn uniq() -> String {
        use std::time::SystemTime;
        format!(
            "{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        )
    }

    #[test]
    fn empty_config_is_valid() {
        let a = parse_str("").unwrap();
        assert!(a.servers.is_empty());
        assert!(a.admin.is_none());
    }

    #[test]
    fn simple_server_block() {
        let src = r#"
            server {
                listen 80;
                proxy_pass http://127.0.0.1:8000;
            }
        "#;
        let a = parse_str(src).unwrap();
        assert_eq!(a.servers.len(), 1);
        let s = &a.servers[0];
        assert_eq!(s.listens.len(), 1);
        assert_eq!(s.listens[0].addr, "80");
        assert_eq!(s.proxy_pass.as_deref(), Some("http://127.0.0.1:8000"));
    }

    #[test]
    fn listen_with_modifiers() {
        let src = r#"
            server {
                listen 0.0.0.0:443 ssl http2 http3 default_server;
                ssl_certificate /a;
                ssl_certificate_key /b;
                proxy_pass http://up;
            }
        "#;
        let a = parse_str(src).unwrap();
        let l = &a.servers[0].listens[0];
        assert!(l.ssl && l.http2 && l.http3 && l.default_server);
    }

    #[test]
    fn http3_requires_ssl() {
        let r = parse_str(r#"server { listen 0.0.0.0:443 http3; proxy_pass http://x; }"#);
        assert!(r.is_err());
        assert!(r.unwrap_err().message.contains("http3"));
    }

    #[test]
    fn defaults_block_parses_durations() {
        let a = parse_str(
            r#"
            defaults {
                request_timeout 10s;
                graceful_shutdown 500ms;
            }
        "#,
        )
        .unwrap();
        let d = a.defaults.unwrap();
        assert_eq!(d.request_timeout, Some(Duration::from_secs(10)));
        assert_eq!(d.graceful_shutdown, Some(Duration::from_millis(500)));
    }

    #[test]
    fn invalid_duration_errors() {
        let r = parse_str(r#"defaults { request_timeout 10x; }"#);
        assert!(r.is_err());
    }

    #[test]
    fn unknown_directive_suggests_typo() {
        let r = parse_str(r#"server { proxypass http://x; }"#);
        let e = r.unwrap_err();
        assert_eq!(e.suggestion.as_deref(), Some("proxy_pass"));
    }

    #[test]
    fn unknown_filter_suggests_typo() {
        let r = parse_str(r#"server { listen 80; proxy_pass http://x; filters { wf on; } }"#);
        let e = r.unwrap_err();
        assert_eq!(e.suggestion.as_deref(), Some("waf"));
    }

    #[test]
    fn filter_value_validated() {
        let r = parse_str(r#"server { listen 80; proxy_pass http://x; filters { waf maybe; } }"#);
        assert!(r.is_err());
    }

    #[test]
    fn rate_limit_integer_validated() {
        let r =
            parse_str(r#"server { listen 80; proxy_pass http://x; rate_limit { burst abc; } }"#);
        assert!(r.is_err());
    }

    #[test]
    fn unterminated_block_errors() {
        let r = parse_str(r#"server { listen 80;"#);
        assert!(r.is_err());
    }

    #[test]
    fn comments_are_skipped() {
        let a = parse_str(
            r#"
            # top-level comment
            server {
                # nested comment
                listen 80;
                proxy_pass http://x;
            }
        "#,
        )
        .unwrap();
        assert_eq!(a.servers.len(), 1);
    }

    #[test]
    fn quoted_paths_with_spaces() {
        let a = parse_str(
            r#"
            server {
                listen 80;
                ssl_certificate "/etc/aegis/certs/path with spaces.crt";
                ssl_certificate_key "/etc/aegis/certs/key.key";
                proxy_pass http://x;
            }
        "#,
        )
        .unwrap();
        assert_eq!(
            a.servers[0].ssl_certificate.as_deref(),
            Some("/etc/aegis/certs/path with spaces.crt")
        );
    }

    #[test]
    fn location_block_prefix() {
        let a = parse_str(
            r#"
            server {
                listen 80;
                proxy_pass http://default;
                location /api/ {
                    proxy_pass http://api;
                }
            }
        "#,
        )
        .unwrap();
        let loc = &a.servers[0].locations[0];
        assert!(matches!(&loc.matcher, LocationMatcher::Prefix(p) if p == "/api/"));
        assert_eq!(loc.proxy_pass.as_deref(), Some("http://api"));
    }

    #[test]
    fn location_exact_match() {
        let a = parse_str(
            r#"
            server {
                listen 80;
                proxy_pass http://x;
                location = /health { proxy_pass http://h; }
            }
        "#,
        )
        .unwrap();
        assert!(matches!(
            &a.servers[0].locations[0].matcher,
            LocationMatcher::Exact(p) if p == "/health"
        ));
    }

    #[test]
    fn admin_block_parses() {
        let a = parse_str(
            r#"
            admin {
                listen 127.0.0.1:9090;
                token admin SECRET-VALUE;
            }
        "#,
        )
        .unwrap();
        let admin = a.admin.unwrap();
        assert_eq!(admin.listen.as_deref(), Some("127.0.0.1:9090"));
        assert_eq!(admin.tokens[0].role, "admin");
        assert_eq!(admin.tokens[0].token, "SECRET-VALUE");
    }

    #[test]
    fn parse_duration_table() {
        assert_eq!(parse_duration("10s").unwrap(), Duration::from_secs(10));
        assert_eq!(parse_duration("500ms").unwrap(), Duration::from_millis(500));
        assert_eq!(parse_duration("2m").unwrap(), Duration::from_secs(120));
        assert!(parse_duration("10").is_err());
        assert!(parse_duration("xs").is_err());
    }
}
