//! Built-in honeypot path packs.
//!
//! Each pack is a curated list of URL patterns that legitimate users
//! never visit — they're paths that exist exclusively in the lookup
//! tables of automated scanners. A hit on any of these is a clean,
//! zero-false-positive signal: it cannot be a real human.
//!
//! Patterns:
//!   `/foo`     → exact match
//!   `/foo/*`   → prefix match (anything under `/foo/`)
//!   `*/foo`    → suffix match (e.g. `*/.env` matches `/anything/.env`)
//!
//! Order doesn't matter; any single match triggers the tarpit response.
//!
//! Adding new packs: append a new `Pack { id, name, description,
//! paths }` entry to `BUILTIN_PACKS`. `id` must be `[a-z0-9_]+`, stable
//! across releases (the per-host overrides reference packs by id).

#[derive(Debug, Clone)]
pub struct Pack {
    pub id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub paths: &'static [&'static str],
}

impl Pack {
    /// Number of paths in this pack — surfaced in the admin UI so
    /// operators can see relative pack size at a glance.
    pub fn path_count(&self) -> usize {
        self.paths.len()
    }
}

/// All built-in packs. Operators toggle each one ON/OFF per host
/// through the admin panel. Default is "all on" — the patterns here
/// are chosen to be globally safe (nothing matches a real user
/// browsing a real site).
pub const BUILTIN_PACKS: &[Pack] = &[
    Pack {
        id: "wordpress",
        name: "WordPress",
        description: "wp-admin, xmlrpc, wp-config — anything a WordPress \
                      scanner pokes. Disable only if you actually run \
                      WordPress on this host.",
        paths: &[
            "/wp-admin/*",
            "/wp-login.php",
            "/wp-content/uploads/*.php",
            "/wp-config.php",
            "/wp-config.php.bak",
            "/wp-config.php~",
            "/xmlrpc.php",
            "/wp-cron.php",
            "/wp-includes/wlwmanifest.xml",
            "/wp-includes/*.php",
            "/wp-trackback.php",
            "/wp-mail.php",
            "/wordpress/wp-login.php",
            "/blog/wp-login.php",
            "/web/wp-login.php",
            "/site/wp-login.php",
            "/old/wp-login.php",
        ],
    },
    Pack {
        id: "secrets",
        name: "Secret files",
        description: "Credential dumps and source-control leftovers. \
                      .env, .git, AWS keys — universally bad to expose, \
                      never legitimate to request.",
        paths: &[
            "/.env",
            "/.env.local",
            "/.env.production",
            "/.env.dev",
            "/.env.backup",
            "/.env.save",
            "/.env.old",
            "/.git/config",
            "/.git/HEAD",
            "/.git/index",
            "/.gitconfig",
            "/.gitignore",
            "/.svn/entries",
            "/.svn/wc.db",
            "/.hg/store",
            "/.bzr/branch-format",
            "/.aws/credentials",
            "/.aws/config",
            "/.npmrc",
            "/.netrc",
            "/.ssh/id_rsa",
            "/.ssh/authorized_keys",
            "/.ssh/known_hosts",
            "/.docker/config.json",
            "/.kube/config",
            "/.dockercfg",
            "/.bash_history",
            "/.python_history",
            "/.mysql_history",
            "/.profile",
            "/.bashrc",
            "/.zshrc",
        ],
    },
    Pack {
        id: "php_admin",
        name: "PHP admin tooling",
        description: "phpMyAdmin / phpInfo and friends. Frequent scanner \
                      target; only legitimate if you run PHP admin tools.",
        paths: &[
            "/phpmyadmin/*",
            "/phpMyAdmin/*",
            "/pma/*",
            "/myadmin/*",
            "/PMA/*",
            "/phpinfo.php",
            "/info.php",
            "/test.php",
            "/php.php",
            "/_phpinfo.php",
            "/admin/phpmyadmin/",
            "/db/phpmyadmin/",
            "/databases/",
            "/sql/",
            "/mysqladmin/",
        ],
    },
    Pack {
        id: "drupal",
        name: "Drupal",
        description: "Drupal core paths (CHANGELOG, install, update).",
        paths: &[
            "/CHANGELOG.txt",
            "/core/CHANGELOG.txt",
            "/core/install.php",
            "/core/update.php",
            "/core/MAINTAINERS.txt",
            "/sites/default/settings.php",
            "/sites/default/files/.htaccess",
            "/sites/default/private/",
            // NOTE — the legacy `/?q=admin` / `/?q=user/register`
            // query-routing probes were removed in V234. The honeypot
            // matcher is path-only (`canonical_path` strips the query
            // string), so a `/?q=…` pattern collapses to the bare root
            // `/` and would tarpit every visitor to the site root. The
            // clean-URL forms below cover modern Drupal scanners.
            "/user/register",
            "/user/password",
        ],
    },
    Pack {
        id: "joomla",
        name: "Joomla",
        description: "Joomla admin + config probe paths.",
        paths: &[
            "/administrator/*",
            "/configuration.php",
            "/configuration.php-dist",
            "/components/com_jce/*",
            "/plugins/system/cache/cache.xml",
            "/htaccess.txt",
            "/joomla/administrator/",
            "/cms/administrator/",
        ],
    },
    Pack {
        id: "xenforo",
        name: "XenForo",
        description: "XenForo installer, internal_data, source-tree, and \
                      admin-ajax paths. Disable only if you actually run \
                      a XenForo forum on this host.",
        paths: &[
            // Installer — should never be world-reachable after setup.
            "/install/",
            "/install/index.php",
            "/install/upgrade/",
            "/install/upgrade/index.php",
            "/install/data/",
            // Internal data tree — Apache .htaccess normally blocks
            // these; if they reach Aegis it's a scanner.
            "/internal_data/install-lock.php",
            "/internal_data/keys/",
            "/internal_data/keys/encryption.key",
            "/internal_data/code_cache/",
            "/internal_data/cookie_consent_log/",
            "/internal_data/temp/",
            "/internal_data/sitemaps/",
            "/internal_data/file_check.php",
            // Source-tree probes (XF 2.x lives in /src/, XF 1.x in /library/).
            "/src/config.php",
            "/src/XF/Install/Bootstrap.php",
            "/src/addons/",
            "/library/config.php",
            "/library/XenForo/Application.php",
            "/library/XenForo/Helper/File.php",
            "/library/Zend/",
            // Common admin-AJAX probe paths under ?_xfRequestUri=
            "/admin.php?install",
            "/admin.php?cron-entries",
            "/admin.php?option-groups",
            "/admin.php?node-types",
            "/admin.php?addons",
            "/admin.php?import",
            "/admin.php?backup",
            // Frequently-scanned XF addon trees.
            "/data/install/",
            "/styles/default/xenforo/",
            "/styles/install/",
            // Test endpoints scanners look for after probing a XF site.
            "/test.php?xf",
            "/forum/install/index.php",
            "/forums/install/index.php",
            "/community/install/index.php",
        ],
    },
    Pack {
        id: "magento",
        name: "Magento",
        description: "Magento downloader + shell + connect paths.",
        paths: &[
            "/downloader/*",
            "/shell/*",
            "/Magento_Version",
            "/magento_version",
            "/skin/install.txt",
            "/RELEASE_NOTES.txt",
            "/index.php/admin/",
            "/index.php/rss/order/new/",
            "/customer/account/create/",
        ],
    },
    Pack {
        id: "shells",
        name: "Webshell drop spots",
        description: "Common webshell filenames that scanners check for \
                      after they think they've exploited a CMS.",
        paths: &[
            "/shell.php",
            "/webshell.php",
            "/c99.php",
            "/r57.php",
            "/cmd.php",
            "/cmd.jsp",
            "/cmd.asp",
            "/cmd.aspx",
            "/upload.php",
            "/up.php",
            "/sh.php",
            "/x.php",
            "/0.php",
            "/index.php?act=cmd",
            "/wso.php",
            "/alfa.php",
            "/marijuana.php",
            "/by.php",
            "/2017.php",
            "/2018.php",
            "/2019.php",
            "/2020.php",
            "/2021.php",
            "/2022.php",
            "/2023.php",
            "/2024.php",
            "/2025.php",
            "/2026.php",
            "/admin.php",
            "/eval.php",
            "/test.jsp",
            "/test.asp",
        ],
    },
    Pack {
        id: "backup_dumps",
        name: "Database / backup dumps",
        description: "SQL dumps and backup archives left behind by lazy ops.",
        paths: &[
            "/backup.zip",
            "/backup.tar",
            "/backup.tar.gz",
            "/backup.sql",
            "/backup.sql.gz",
            "/backup.sql.zip",
            "/db.sql",
            "/db.sql.gz",
            "/dump.sql",
            "/dump.sql.gz",
            "/database.sql",
            "/site.sql",
            "/wp.sql",
            "/wordpress.sql",
            "/mysqldump.sql",
            "/site.zip",
            "/site.tar.gz",
            "/www.zip",
            "/www.tar.gz",
            "/public_html.zip",
            "/htdocs.zip",
            "/old.zip",
            "/old.tar.gz",
            "/data.zip",
            "/data.tar.gz",
            "/web.zip",
            "/web.tar.gz",
        ],
    },
    Pack {
        id: "vendor_paths",
        name: "Vendor / dependency leaks",
        description: "Composer / npm install artefacts that should never \
                      be web-reachable.",
        paths: &[
            "/vendor/phpunit/*",
            "/vendor/laravel/*",
            "/vendor/composer/installed.json",
            "/vendor/autoload.php",
            "/composer.json",
            "/composer.lock",
            "/package.json",
            "/package-lock.json",
            "/yarn.lock",
            "/pnpm-lock.yaml",
            "/Gemfile",
            "/Gemfile.lock",
            "/Cargo.toml",
            "/Cargo.lock",
            "/go.mod",
            "/go.sum",
            "/requirements.txt",
            "/Pipfile",
            "/Pipfile.lock",
            "/node_modules/*",
        ],
    },
    Pack {
        id: "ci_cd",
        name: "CI/CD configs",
        description: "Pipeline + container configs that often leak \
                      tokens or topology details.",
        paths: &[
            "/.github/workflows/*",
            "/.gitlab-ci.yml",
            "/.travis.yml",
            "/.circleci/config.yml",
            "/Jenkinsfile",
            "/azure-pipelines.yml",
            "/bitbucket-pipelines.yml",
            "/.drone.yml",
            "/Dockerfile",
            "/docker-compose.yml",
            "/docker-compose.yaml",
            "/docker-compose.prod.yml",
            "/Makefile",
            "/CMakeLists.txt",
            "/.buildkite/pipeline.yml",
            "/cloudbuild.yaml",
        ],
    },
    Pack {
        id: "iot_default",
        name: "IoT / router defaults",
        description: "Mirai / Hajime / Gafgyt-style probes targeting \
                      consumer router default endpoints. Never legitimate \
                      on a server.",
        paths: &[
            "/HNAP1/",
            "/cgi-bin/luci",
            "/cgi-bin/luci/*",
            "/login.cgi",
            "/cgi-bin/login.cgi",
            "/cgi-bin/kerbynet",
            "/cgi-bin/admin.cgi",
            "/cgi-bin/aw-cgi/eaccess.cgi",
            "/setup.cgi",
            "/picsdesc.xml",
            "/wanipcn.xml",
            "/getuser",
            "/GponForm/diag_Form",
            "/jsonrpc",
            "/system/console",
            "/manager/html",
            "/host-manager/html",
            "/tmui/login.jsp",
            "/recordings/index.php",
            "/Mozi.m",
            "/Mozi.a",
            "/CmDuFqDZQqo",
        ],
    },
    Pack {
        id: "java_admin",
        name: "Java / Spring / Tomcat admin",
        description: "Spring Boot actuators, Tomcat manager, JMX consoles.",
        paths: &[
            "/actuator/*",
            "/actuator/env",
            "/actuator/heapdump",
            "/actuator/jolokia",
            "/actuator/mappings",
            "/actuator/trace",
            "/actuator/configprops",
            "/actuator/threaddump",
            "/manager/text/list",
            "/manager/jmxproxy",
            "/manager/status",
            "/jmx-console/",
            "/web-console/",
            "/struts/webconsole.html",
            "/console/login/LoginForm.jsp",
            "/auth/saml/login",
            "/_ah/admin",
        ],
    },
    Pack {
        id: "monitoring",
        name: "Monitoring / status pages",
        description: "Apache server-status, nginx status — usually \
                      restricted to localhost, never to the public.",
        paths: &[
            "/server-status",
            "/server-info",
            "/nginx_status",
            "/nginx-status",
            "/stub_status",
            "/haproxy?stats",
            "/metrics-admin",
            "/debug/pprof/*",
            "/debug/vars",
            "/varnish/status",
        ],
    },
    Pack {
        id: "git_repos",
        name: "Source code repositories",
        description: "Exposed git/hg/svn directories — high-severity \
                      info-leak target.",
        paths: &[
            "/.git/*",
            "/.git/refs/heads/master",
            "/.git/refs/heads/main",
            "/.git/logs/HEAD",
            "/.svn/*",
            "/.hg/*",
            "/.bzr/*",
            "/CVS/*",
        ],
    },
    Pack {
        id: "fuzzer_noise",
        name: "Common fuzzer wordlist",
        description: "Top hits from dirb / ffuf / gobuster default \
                      wordlists. High volume, near-zero false positive.",
        paths: &[
            "/secret/",
            "/secrets/",
            "/private/",
            "/internal/",
            "/staging/",
            "/dev/",
            "/test/",
            "/temp/",
            "/tmp/",
            "/old/",
            "/backup/",
            "/data/",
            "/files/",
            "/upload/",
            "/uploads/",
            "/.well-known/security.txt.bak",
            "/sitemap.xml.gz",
            "/robots.txt.bak",
            "/admin/",
            "/admin.html",
            "/login/",
            "/login.html",
            "/dashboard/",
            "/console/",
            "/cpanel/",
            "/whm/",
            "/webmail/",
            "/roundcube/",
            "/owa/",
            "/exchange/",
        ],
    },
    Pack {
        id: "windows_iis",
        name: "Windows / IIS",
        description: "Classic IIS / ASP / .NET probe paths.",
        paths: &[
            "/iisstart.htm",
            "/iis-85.png",
            "/welcome.png",
            "/Trace.axd",
            "/elmah.axd",
            "/WebResource.axd",
            "/_vti_inf.html",
            "/_vti_bin/*",
            "/web.config",
            "/web.config.bak",
            "/web.config.old",
            "/global.asax",
            "/global.asa",
            "/aspnet_client/*",
            "/MSOffice/*",
        ],
    },
    Pack {
        id: "node_npm",
        name: "Node.js / npm artefacts",
        description: "Node-specific leaks: source maps, dist folders, \
                      Express defaults.",
        paths: &[
            "/.npmrc",
            "/.nvmrc",
            "/server.js.map",
            "/index.js.map",
            "/app.js.map",
            "/main.js.map",
            "/bundle.js.map",
            "/build/main.js.map",
            "/dist/main.js.map",
            "/api/v1/__debug__",
            "/__debug__/",
            "/_next/static/chunks/*.js.map",
            "/socket.io/*",
        ],
    },
];

/// Look up a built-in pack by id. None when the id isn't a built-in
/// (e.g. the operator's state file references a pack that was removed
/// in a later release).
pub fn pack_by_id(id: &str) -> Option<&'static Pack> {
    BUILTIN_PACKS.iter().find(|p| p.id == id)
}

/// Total path count across every built-in pack. Useful for admin
/// dashboard headlines like "1,234 protected probe paths".
pub fn total_path_count() -> usize {
    BUILTIN_PACKS.iter().map(|p| p.paths.len()).sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_pack_id_is_unique() {
        use std::collections::HashSet;
        let ids: HashSet<&str> = BUILTIN_PACKS.iter().map(|p| p.id).collect();
        assert_eq!(ids.len(), BUILTIN_PACKS.len(), "duplicate pack id");
    }

    #[test]
    fn every_pack_has_paths() {
        for p in BUILTIN_PACKS {
            assert!(!p.paths.is_empty(), "{} has no paths", p.id);
            assert!(!p.name.is_empty());
            assert!(!p.description.is_empty());
        }
    }

    #[test]
    fn pack_ids_are_slug_form() {
        for p in BUILTIN_PACKS {
            for c in p.id.chars() {
                assert!(
                    c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_',
                    "pack id `{}` has invalid char `{c}`",
                    p.id
                );
            }
        }
    }

    #[test]
    fn we_ship_at_least_a_dozen_packs() {
        assert!(BUILTIN_PACKS.len() >= 12, "library is suspiciously small");
        assert!(total_path_count() >= 200);
    }
}
