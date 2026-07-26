//! Nginx-style tokenizer.
//!
//! Tokens are space-separated bare words, quoted strings, `{`, `}`,
//! and `;`. Anything from `#` to end-of-line is a comment. Whitespace
//! (incl. newlines) is insignificant beyond separation. Strings may be
//! double- or single-quoted; backslash escapes the quote character.

use std::path::Path;

use super::error::DslError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenKind {
    Word,
    LBrace,
    RBrace,
    Semicolon,
    Eof,
}

#[derive(Debug, Clone)]
pub struct Token {
    pub kind: TokenKind,
    pub value: String,
    pub line: u32,
    pub col: u32,
}

pub fn tokenize(source: &str, file: &Path) -> Result<Vec<Token>, DslError> {
    let mut tokens = Vec::new();
    let bytes = source.as_bytes();
    let mut i = 0;
    let mut line: u32 = 1;
    let mut line_start: usize = 0;

    while i < bytes.len() {
        let c = bytes[i];

        // Whitespace
        if c == b'\n' {
            line += 1;
            line_start = i + 1;
            i += 1;
            continue;
        }
        if c == b' ' || c == b'\t' || c == b'\r' {
            i += 1;
            continue;
        }

        // Comment to end of line
        if c == b'#' {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }

        let col = (i - line_start + 1) as u32;

        // Single-char punctuation
        if c == b';' {
            tokens.push(Token {
                kind: TokenKind::Semicolon,
                value: ";".to_string(),
                line,
                col,
            });
            i += 1;
            continue;
        }
        if c == b'{' {
            tokens.push(Token {
                kind: TokenKind::LBrace,
                value: "{".to_string(),
                line,
                col,
            });
            i += 1;
            continue;
        }
        if c == b'}' {
            tokens.push(Token {
                kind: TokenKind::RBrace,
                value: "}".to_string(),
                line,
                col,
            });
            i += 1;
            continue;
        }

        // Quoted string
        if c == b'"' || c == b'\'' {
            let quote = c;
            let start_line = line;
            let start_col = col;
            i += 1;
            let mut value = String::new();
            while i < bytes.len() && bytes[i] != quote {
                if bytes[i] == b'\\' && i + 1 < bytes.len() {
                    let next = bytes[i + 1];
                    match next {
                        b'n' => value.push('\n'),
                        b't' => value.push('\t'),
                        b'r' => value.push('\r'),
                        b'\\' => value.push('\\'),
                        c if c == quote => value.push(quote as char),
                        other => {
                            value.push('\\');
                            value.push(other as char);
                        }
                    }
                    i += 2;
                    continue;
                }
                if bytes[i] == b'\n' {
                    line += 1;
                    line_start = i + 1;
                }
                value.push(bytes[i] as char);
                i += 1;
            }
            if i >= bytes.len() {
                return Err(DslError::new(
                    "unterminated string literal",
                    file.to_path_buf(),
                    start_line,
                    start_col,
                ));
            }
            i += 1; // consume closing quote
            tokens.push(Token {
                kind: TokenKind::Word,
                value,
                line: start_line,
                col: start_col,
            });
            continue;
        }

        // Bare word: read until whitespace, `;`, `{`, `}`, `#`
        let start = i;
        while i < bytes.len() {
            let ch = bytes[i];
            if ch == b' '
                || ch == b'\t'
                || ch == b'\r'
                || ch == b'\n'
                || ch == b';'
                || ch == b'{'
                || ch == b'}'
                || ch == b'#'
            {
                break;
            }
            i += 1;
        }
        let value = std::str::from_utf8(&bytes[start..i])
            .map_err(|_| DslError::new("invalid utf-8 in word", file.to_path_buf(), line, col))?
            .to_string();
        tokens.push(Token {
            kind: TokenKind::Word,
            value,
            line,
            col,
        });
    }

    tokens.push(Token {
        kind: TokenKind::Eof,
        value: String::new(),
        line,
        col: 1,
    });
    Ok(tokens)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn toks(src: &str) -> Vec<(TokenKind, String)> {
        tokenize(src, &PathBuf::from("test.conf"))
            .unwrap()
            .into_iter()
            .filter(|t| t.kind != TokenKind::Eof)
            .map(|t| (t.kind, t.value))
            .collect()
    }

    #[test]
    fn simple_directive() {
        assert_eq!(
            toks("listen 80;"),
            vec![
                (TokenKind::Word, "listen".to_string()),
                (TokenKind::Word, "80".to_string()),
                (TokenKind::Semicolon, ";".to_string()),
            ]
        );
    }

    #[test]
    fn block_with_nested_directive() {
        let src = "server { listen 80; }";
        let v = toks(src);
        assert_eq!(v[0], (TokenKind::Word, "server".to_string()));
        assert_eq!(v[1], (TokenKind::LBrace, "{".to_string()));
        assert_eq!(v.last().unwrap().0, TokenKind::RBrace);
    }

    #[test]
    fn comment_to_eol_ignored() {
        let v = toks("# hello\nlisten 80;");
        assert_eq!(v[0].1, "listen");
    }

    #[test]
    fn quoted_string_keeps_spaces() {
        let v = toks(r#"include "path with spaces.conf";"#);
        assert_eq!(v[1].1, "path with spaces.conf");
    }

    #[test]
    fn single_quoted_string() {
        let v = toks("token 'sec ret';");
        assert_eq!(v[1].1, "sec ret");
    }

    #[test]
    fn escape_sequences_in_string() {
        let v = toks(r#"token "a\nb\"c";"#);
        assert_eq!(v[1].1, "a\nb\"c");
    }

    #[test]
    fn nginx_style_listen_args() {
        let v = toks("listen 0.0.0.0:443 ssl http2 http3 default_server;");
        let words: Vec<_> = v
            .iter()
            .filter(|(k, _)| *k == TokenKind::Word)
            .map(|(_, v)| v.as_str())
            .collect();
        assert_eq!(
            words,
            vec![
                "listen",
                "0.0.0.0:443",
                "ssl",
                "http2",
                "http3",
                "default_server"
            ]
        );
    }

    #[test]
    fn unterminated_string_errors() {
        let r = tokenize(r#"x "unfinished"#, &PathBuf::from("x.conf"));
        assert!(r.is_err());
    }

    #[test]
    fn line_column_tracked() {
        let toks = tokenize("server {\n    listen 80;\n}", &PathBuf::from("x")).unwrap();
        let listen = toks.iter().find(|t| t.value == "listen").unwrap();
        assert_eq!(listen.line, 2);
        assert_eq!(listen.col, 5);
    }
}
