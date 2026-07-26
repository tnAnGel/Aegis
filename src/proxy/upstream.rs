use std::{collections::HashMap, sync::Arc};

use anyhow::{Context, Result};
use hyper::http::{
    Uri,
    uri::{Authority, Scheme},
};

#[derive(Debug, Clone)]
pub struct Upstream {
    pub base_uri: Uri,
    pub authority: String,
    /// Pre-parsed authority — avoids re-parsing on every proxied
    /// request when rewriting `parts.uri` to the upstream.
    pub authority_parsed: Authority,
    /// Pre-cached scheme (defaults to http) — same reason as above.
    pub scheme: Scheme,
}

#[derive(Debug, Clone)]
pub struct UpstreamRouter {
    pub default_upstream: Upstream,
    pub domain_upstreams: HashMap<String, Upstream>,
}

impl Upstream {
    pub fn from_url(url: &str) -> Result<Self> {
        let uri: Uri = url.parse().context("invalid upstream url")?;
        let authority_obj = uri
            .authority()
            .cloned()
            .context("upstream URL missing authority")?;
        let authority = authority_obj.to_string();
        let scheme = uri.scheme().cloned().unwrap_or(Scheme::HTTP);
        Ok(Self {
            base_uri: uri,
            authority,
            authority_parsed: authority_obj,
            scheme,
        })
    }
}

impl UpstreamRouter {
    pub fn resolve(&self, host: &str) -> &Upstream {
        self.domain_upstreams
            .get(host)
            .unwrap_or(&self.default_upstream)
    }
}

pub type SharedUpstreamRouter = Arc<UpstreamRouter>;
