//! Dedicated application paths and exact input files for a prepared policy.
//! Directory preparation happens before restriction; Linux pins opened objects
//! in a ruleset reused by workers. File replacement requires a new session.

use crate::config::NetwatchConfig;
use std::path::PathBuf;

/// Paths the sandbox needs to know about. All optional — empty entries
/// are skipped at apply time rather than treated as `/` allow-all.
#[derive(Debug, Clone, Default)]
pub struct SandboxPaths {
    /// `~/.cache/netwatch/` — log files + Flight Recorder bundles + any
    /// other transient output the TUI writes.
    pub cache_dir: Option<PathBuf>,
    /// `~/.config/netwatch/` — config.toml read at startup and on
    /// settings-overlay edits.
    pub config_dir: Option<PathBuf>,
    /// Exact City database file (legacy field name retained).
    pub geoip_db_dir: Option<PathBuf>,
    /// Exact ASN database file (legacy field name retained).
    pub geoip_asn_db_dir: Option<PathBuf>,
    /// Exact keylog file; no parent-directory grant. Missing files are not granted.
    pub keylog_dir: Option<PathBuf>,
    /// Dedicated cache/netwatch/exports directory (legacy field name retained).
    pub cwd: Option<PathBuf>,
    /// `~/.local/state/netwatch/` (Linux) — the learned egress baseline
    /// (`egress-profiles.json`) persists here on a rate-limited tick and
    /// at quit, both after the sandbox is applied. Read-only would lose
    /// the baseline every session.
    pub state_dir: Option<PathBuf>,
}

impl SandboxPaths {
    /// Derive the sandbox path set from runtime config and dirs.
    ///
    /// All filesystem ops here are read-only (existence checks via
    /// `dirs::*` + `parent()`). No directories are created — the
    /// sandbox just needs to *permit* the directory if the app later
    /// chooses to write there. Missing dirs are silently skipped.
    pub fn from_config(cfg: &NetwatchConfig) -> Self {
        let cache_dir = dirs::cache_dir().map(|c| c.join("netwatch"));
        let config_dir = dirs::config_dir().map(|c| c.join("netwatch"));

        let geoip_db_dir = file_if_set(&cfg.geoip_db);
        let geoip_asn_db_dir = file_if_set(&cfg.geoip_asn_db);
        let keylog_dir = file_if_set(&cfg.tls_keylog_path);

        let cwd = cache_dir.as_ref().map(|p| p.join("exports"));

        // Derive from the same helper that decides where the baseline is
        // written, so the sandbox rule can't drift from the writer.
        let state_dir = crate::collectors::egress::default_profiles_path()
            .and_then(|p| p.parent().map(|d| d.to_path_buf()));

        Self {
            cache_dir,
            config_dir,
            geoip_db_dir,
            geoip_asn_db_dir,
            keylog_dir,
            cwd,
            state_dir,
        }
    }
}

fn file_if_set(path: &str) -> Option<PathBuf> {
    (!path.trim().is_empty()).then(|| PathBuf::from(path))
}

impl SandboxPaths {
    /// Create owned application directories before restriction. Reject symlinks
    /// and broad existing directory targets rather than silently widening access.
    pub fn prepare(&self) -> std::io::Result<()> {
        for dir in [
            &self.cache_dir,
            &self.config_dir,
            &self.state_dir,
            &self.cwd,
        ]
        .into_iter()
        .flatten()
        {
            prepare_directory(dir)?;
        }
        if let Some(cache) = &self.cache_dir {
            prepare_directory(&cache.join("scratch"))?;
        }
        for file in [&self.geoip_db_dir, &self.geoip_asn_db_dir, &self.keylog_dir]
            .into_iter()
            .flatten()
        {
            if file.exists() && !file.is_file() {
                return Err(std::io::Error::other(format!(
                    "expected a file: {}",
                    file.display()
                )));
            }
        }
        Ok(())
    }
}
fn prepare_directory(path: &std::path::Path) -> std::io::Result<()> {
    if path.parent().is_none() || path.file_name().is_none() {
        return Err(std::io::Error::other("broad sandbox directory rejected"));
    }
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            return Err(std::io::Error::other("symlink sandbox directory rejected"));
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)?;
    }
    #[cfg(not(unix))]
    std::fs::create_dir_all(path)?;
    let canonical = path.canonicalize()?;
    if [
        "/", "/tmp", "/var/tmp", "/usr", "/etc", "/run", "/home", "/root",
    ]
    .iter()
    .any(|p| canonical == std::path::Path::new(p))
        || dirs::home_dir().is_some_and(|h| h == canonical)
    {
        return Err(std::io::Error::other("home/root sandbox grant rejected"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
        let directory = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW)
            .open(path)?;
        if directory.metadata()?.uid() != unsafe { nix::libc::geteuid() } {
            return Err(std::io::Error::other(
                "sandbox directory is owned by a different user",
            ));
        }
        directory.set_permissions(std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn shared_tmp_is_rejected_without_changing_its_permissions() {
        let before = std::fs::metadata("/tmp").unwrap().permissions();
        assert!(prepare_directory(std::path::Path::new("/tmp")).is_err());
        assert_eq!(std::fs::metadata("/tmp").unwrap().permissions(), before);
    }

    #[test]
    fn exports_use_the_dedicated_cache_directory() {
        let paths = SandboxPaths::from_config(&NetwatchConfig::default());
        assert_eq!(paths.cwd, paths.cache_dir.map(|p| p.join("exports")));
    }

    #[test]
    fn empty_geoip_paths_resolve_to_none() {
        let cfg = NetwatchConfig {
            geoip_db: String::new(),
            geoip_asn_db: String::new(),
            ..Default::default()
        };
        let paths = SandboxPaths::from_config(&cfg);
        assert!(paths.geoip_db_dir.is_none());
        assert!(paths.geoip_asn_db_dir.is_none());
    }

    #[test]
    fn absolute_geoip_path_extracts_parent() {
        let cfg = NetwatchConfig {
            geoip_db: "/usr/share/GeoIP/GeoLite2-City.mmdb".to_string(),
            ..Default::default()
        };
        let paths = SandboxPaths::from_config(&cfg);
        assert_eq!(
            paths.geoip_db_dir.as_deref(),
            Some(std::path::Path::new("/usr/share/GeoIP/GeoLite2-City.mmdb"))
        );
    }

    #[test]
    fn bare_filename_geoip_remains_an_exact_file() {
        let cfg = NetwatchConfig {
            geoip_db: "city.mmdb".to_string(),
            ..Default::default()
        };
        let paths = SandboxPaths::from_config(&cfg);
        assert_eq!(
            paths.geoip_db_dir.as_deref(),
            Some(std::path::Path::new("city.mmdb"))
        );
    }
}
